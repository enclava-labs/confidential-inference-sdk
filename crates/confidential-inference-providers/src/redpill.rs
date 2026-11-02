use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use confidential_inference_attestation::{
    sha256_digest, verify_redpill_aci_signature, NvidiaGpuAttestationEvidence,
};
use confidential_inference_openai::ChatCompletionResponse;
use serde_json::{json, Value};
use std::fmt;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

use crate::http::{checked_response_bytes, https_or_test_loopback, require_tls_peer, LiveTlsPeer};
use crate::provider::EvidenceStateStore;
use crate::tls::FETCH_REQUEST_TIMEOUT;
use crate::{
    EvidenceRequest, NvidiaNrasRemoteClient, ProviderAdapter, ProviderChatRequest, ProviderError,
    ProviderRequestConfidentiality, Result, RouteDefinition,
};

#[derive(Clone)]
struct ApiKey(Zeroizing<String>);
impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Clone, Debug)]
struct SessionState {
    tls: LiveTlsPeer,
    session_id: String,
    session: Value,
    gateway_report: Value,
    gpu_attestation: Option<NvidiaGpuAttestationEvidence>,
}

// Entries are populated only on dispatch of SDK-verified evidence; every
// later capture is independently reverified.
#[derive(Clone, Debug)]
struct CachedSession {
    session_id: String,
    session: Value,
    gpu_attestation: Option<NvidiaGpuAttestationEvidence>,
    // Earliest of the session expiry and the NRAS JWT `exp`; reuse beyond it
    // would replay a stale token into fresh captures.
    not_after: u64,
}

impl CachedSession {
    fn matches_listed(&self, entry: &Value, now: u64) -> bool {
        entry.get("session_id").and_then(Value::as_str) == Some(self.session_id.as_str())
            && entry
                .pointer("/evidence/digest")
                .and_then(Value::as_str)
                .is_some_and(|digest| {
                    self.session
                        .pointer("/evidence/digest")
                        .and_then(Value::as_str)
                        == Some(digest)
                })
            && self.not_after > now
    }
}

/// Reads `exp` from a compact JWT's claims without verifying the signature;
/// the token was already verified by NRAS verification before this is called.
fn jwt_exp(token: &str) -> Option<u64> {
    let claims = token.split('.').nth(1)?;
    let value: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).ok()?).ok()?;
    value.get("exp").and_then(Value::as_u64)
}

/// Cache reuse horizon: the earliest of the session expiry and the verified
/// NRAS JWT `exp`. Missing GPU evidence or a missing/malformed token or `exp`
/// returns `None` so the session is always refetched instead of replaying a
/// possibly-expired attestation.
fn cache_not_after(
    session: &Value,
    gpu_attestation: Option<&NvidiaGpuAttestationEvidence>,
) -> Option<u64> {
    let session_expiry = session.get("expires_at").and_then(Value::as_u64)?;
    let jwt_exp = jwt_exp(gpu_attestation?.nras_token.as_deref()?)?;
    Some(session_expiry.min(jwt_exp))
}

#[derive(Clone, Debug)]
pub struct RedpillHttpProvider {
    provider_id: String,
    routes: Vec<RouteDefinition>,
    api_key: ApiKey,
    client: reqwest::Client,
    nras_client: Option<NvidiaNrasRemoteClient>,
    state: Arc<Mutex<EvidenceStateStore<SessionState>>>,
    session_cache: Arc<Mutex<std::collections::BTreeMap<String, CachedSession>>>,
    pinned_clients: crate::tls::PinnedSpkiClientCache,
}

impl RedpillHttpProvider {
    pub fn new(
        provider_id: impl Into<String>,
        routes: Vec<RouteDefinition>,
        api_key: impl Into<String>,
    ) -> Result<Self> {
        Self::with_transport(
            provider_id,
            routes,
            api_key.into(),
            Default::default(),
            Some(NvidiaNrasRemoteClient::with_default_http()?),
        )
    }

    pub fn with_transport(
        provider_id: impl Into<String>,
        routes: Vec<RouteDefinition>,
        api_key: String,
        transport: crate::AttestedHttpTransport,
        nras_client: Option<NvidiaNrasRemoteClient>,
    ) -> Result<Self> {
        let client = transport.evidence_client()?;
        Ok(Self {
            provider_id: provider_id.into(),
            routes,
            api_key: ApiKey(Zeroizing::new(api_key)),
            client,
            nras_client,
            state: Arc::new(Mutex::new(EvidenceStateStore::new())),
            session_cache: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            pinned_clients: crate::tls::PinnedSpkiClientCache::new(transport),
        })
    }

    fn authorize(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder.bearer_auth(self.api_key.0.as_str())
    }

    async fn gpu_attestation(
        &self,
        session: &Value,
    ) -> Result<Option<NvidiaGpuAttestationEvidence>> {
        let data = session
            .pointer("/evidence/data")
            .and_then(Value::as_str)
            .and_then(|s| s.strip_prefix("data:application/json;base64,"))
            .ok_or_else(|| {
                ProviderError::Adapter("RedPill session evidence is not a JSON data URI".into())
            })?;
        let bytes = STANDARD.decode(data).map_err(|e| {
            ProviderError::Adapter(format!("RedPill session evidence is not base64: {e}"))
        })?;
        let value: Value = serde_json::from_slice(&bytes)?;
        let Some(payload) = value.get("nvidia_payload").and_then(Value::as_str) else {
            return Ok(None);
        };
        let nonce = value
            .get("request_nonce")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ProviderError::Adapter("RedPill GPU evidence has no nonce".into()))?;
        let payload_value: Value = serde_json::from_str(payload)?;
        let evidence = NvidiaGpuAttestationEvidence {
            schema: NvidiaGpuAttestationEvidence::SCHEMA.into(),
            attestation_format: NvidiaGpuAttestationEvidence::NRAS_GPU_EVIDENCE_V3.into(),
            nonce: nonce.into(),
            arch: payload_value
                .get("arch")
                .and_then(Value::as_str)
                .map(str::to_owned),
            payload_sha256: Some(sha256_digest(payload.as_bytes())),
            raw_payload_base64: Some(STANDARD.encode(payload.as_bytes())),
            nras_token: None,
        };
        match &self.nras_client {
            Some(client) => client.attest_gpu_evidence(&evidence).await.map(Some),
            None => Ok(Some(evidence)),
        }
    }
}

#[async_trait]
impl ProviderAdapter for RedpillHttpProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }
    fn routes(&self) -> Vec<RouteDefinition> {
        self.routes.clone()
    }

    async fn fetch_evidence(
        &self,
        route: &RouteDefinition,
        request: &EvidenceRequest,
    ) -> Result<Vec<u8>> {
        ensure_route(route, &self.provider_id)?;
        let nonce = request
            .nonce
            .as_deref()
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| {
                ProviderError::Compatibility(
                    "RedPill requires a fresh 32-byte hexadecimal nonce".into(),
                )
            })?;
        let response = self
            .authorize(
                self.client
                    .get(&route.evidence_endpoint)
                    .query(&[("nonce", nonce)])
                    .timeout(FETCH_REQUEST_TIMEOUT),
            )
            .send()
            .await
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        let tls = require_tls_peer(&response, "RedPill evidence")?;
        let report: Value =
            serde_json::from_slice(&checked_response_bytes(response, "RedPill evidence").await?)?;
        let client = self.pinned_clients.client(&tls.spki_sha256)?;
        let base = route.api_base_url.trim_end_matches('/');
        let response = self
            .authorize(
                client
                    .get(format!("{base}/aci/sessions"))
                    .query(&[("model", &route.provider_model)])
                    .timeout(FETCH_REQUEST_TIMEOUT),
            )
            .send()
            .await
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        let list: Value =
            serde_json::from_slice(&checked_response_bytes(response, "RedPill sessions").await?)?;
        if list.get("api_version").and_then(Value::as_str) != Some("aci/1") {
            return Err(ProviderError::Adapter(
                "RedPill sessions has invalid API version".into(),
            ));
        }
        let entry = newest_session(&list)?;
        let session_id = entry
            .get("session_id")
            .and_then(Value::as_str)
            .expect("filtered sessions carry an id")
            .to_owned();
        // Sessions are content-addressed and immutable; a cached document is
        // safe to reuse only while the gateway still lists the same id and
        // evidence digest. The verifier still re-checks every byte.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| ProviderError::Adapter(e.to_string()))?
            .as_secs();
        let cached = self
            .session_cache
            .lock()
            .map_err(|_| ProviderError::Adapter("RedPill state lock poisoned".into()))?
            .get(&route.route_id)
            .filter(|c| c.matches_listed(entry, now))
            .cloned();
        let (session, gpu_attestation) = match cached {
            Some(cached) => (cached.session, cached.gpu_attestation),
            None => {
                let response = self
                    .authorize(
                        client
                            .get(format!("{base}/aci/sessions/{session_id}"))
                            .timeout(FETCH_REQUEST_TIMEOUT),
                    )
                    .send()
                    .await
                    .map_err(|e| ProviderError::Http(e.to_string()))?;
                let session: Value = serde_json::from_slice(
                    &checked_response_bytes(response, "RedPill session").await?,
                )?;
                let gpu_attestation = self.gpu_attestation(&session).await?;
                (session, gpu_attestation)
            }
        };
        let capture = json!({
            "schema": "confidential-inference.redpill-aci-live.v1", "provider": route.provider,
            "route_id": route.route_id, "evidence_family": route.evidence_family,
            "requested_model": request.requested_model, "policy_digest": request.policy_digest,
            "request_nonce": nonce, "evidence_endpoint": route.evidence_endpoint,
            "live_tls_spki_sha256": tls.spki_sha256,
            "live_tls_leaf_certificate_der_base64": STANDARD.encode(&tls.leaf_certificate_der),
            "gateway_report": report, "session": session, "session_id": session_id,
            "gpu_attestation": gpu_attestation
        });
        let serialized = serde_json::to_vec(&capture)?;
        let state = SessionState {
            tls,
            session_id,
            session,
            gateway_report: report,
            gpu_attestation,
        };
        self.state
            .lock()
            .map_err(|_| ProviderError::Adapter("RedPill state lock poisoned".into()))?
            .insert(&route.route_id, &sha256_digest(&serialized), state);
        Ok(serialized)
    }

    async fn chat(
        &self,
        route: &RouteDefinition,
        request: ProviderChatRequest,
    ) -> Result<ChatCompletionResponse> {
        ensure_route(route, &self.provider_id)?;
        if request.confidentiality() != &ProviderRequestConfidentiality::Plaintext {
            return Err(ProviderError::Compatibility(
                "RedPill requires the attested TLS channel".into(),
            ));
        }
        if request.model() != Some(route.provider_model.as_str()) {
            return Err(ProviderError::Compatibility(
                "RedPill request model does not match verified route".into(),
            ));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| ProviderError::Adapter("RedPill state lock poisoned".into()))?
            .lookup_for_request(route, &request, "RedPill session")?
            .clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| ProviderError::Adapter(e.to_string()))?
            .as_secs();
        let valid_until = state
            .session
            .get("expires_at")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let key_until = state
            .gateway_report
            .pointer("/attestation/workload_keyset/not_after")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if now >= valid_until || now >= key_until {
            return Err(ProviderError::key_rotation(
                &route.route_id,
                "RedPill session or gateway keyset expired",
            ));
        }
        if let Some(not_after) = cache_not_after(&state.session, state.gpu_attestation.as_ref()) {
            self.session_cache
                .lock()
                .map_err(|_| ProviderError::Adapter("RedPill state lock poisoned".into()))?
                .insert(
                    route.route_id.clone(),
                    CachedSession {
                        session_id: state.session_id.clone(),
                        session: state.session.clone(),
                        gpu_attestation: state.gpu_attestation.clone(),
                        not_after,
                    },
                );
        }
        let body = constrain_request(request.into_body(), &state.session_id)?;
        let wire = serde_json::to_vec(&body)?;
        let client = self.pinned_clients.client(&state.tls.spki_sha256)?;
        let base = route.api_base_url.trim_end_matches('/');
        let response = self
            .authorize(
                client
                    .post(format!("{base}/chat/completions"))
                    .header("content-type", "application/json")
                    .body(wire.clone()),
            )
            .send()
            .await
            .map_err(|e| crate::http::map_send_error(&route.route_id, e))?;
        let observed = require_tls_peer(&response, "RedPill chat")
            .map_err(|e| ProviderError::Adapter(format!("RedPill chat TLS: {e}")))?;
        if observed.spki_sha256 != state.tls.spki_sha256 {
            return Err(ProviderError::Adapter(
                "RedPill chat TLS SPKI changed despite handshake pin".into(),
            ));
        }
        let receipt_id = response
            .headers()
            .get("x-receipt-id")
            .and_then(|v| v.to_str().ok())
            .filter(|id| {
                !id.is_empty()
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .map(str::to_owned);
        let response_body = checked_response_bytes(response, "RedPill chat")
            .await
            .map_err(|error| session_refusal(&route.route_id, error))?;
        let receipt_id = receipt_id.ok_or_else(|| {
            ProviderError::Adapter("RedPill response has no valid receipt ID".into())
        })?;
        let receipt_response = self
            .authorize(
                client
                    .get(format!("{base}/aci/receipts/{receipt_id}"))
                    .timeout(FETCH_REQUEST_TIMEOUT),
            )
            .send()
            .await
            .map_err(|e| {
                ProviderError::Adapter(format!("RedPill receipt fetch failed after dispatch: {e}"))
            })?;
        let receipt_bytes = checked_response_bytes(receipt_response, "RedPill receipt")
            .await
            .map_err(|e| {
                ProviderError::Adapter(format!("RedPill receipt fetch failed after dispatch: {e}"))
            })?;
        let receipt: Value = serde_json::from_slice(&receipt_bytes)?;
        verify_receipt(receipt, &receipt_id, &wire, &response_body, &state)?;
        serde_json::from_slice(&response_body).map_err(Into::into)
    }
}

/// Selects the most recently established session from a list response; the
/// newest entry has the best chance of still serving at dispatch.
fn newest_session(list: &Value) -> Result<&Value> {
    list.get("sessions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|s| {
            s.get("session_id")
                .and_then(Value::as_str)
                .is_some_and(|id| {
                    id.len() == 64
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
        })
        .max_by_key(|s| s.get("established_at").and_then(Value::as_u64).unwrap_or(0))
        .ok_or_else(|| ProviderError::Unavailable("RedPill has no current model session".into()))
}

fn session_refusal(route_id: &str, error: ProviderError) -> ProviderError {
    if let ProviderError::HttpStatus {
        status: 412,
        message,
    } = &error
    {
        let is_session_refusal = message
            .strip_prefix("RedPill chat: ")
            .and_then(|body| serde_json::from_str::<Value>(body).ok())
            .and_then(|body| {
                body.pointer("/error/type")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .as_deref()
            == Some("session_not_accepted");
        if is_session_refusal {
            return ProviderError::key_rotation(
                route_id,
                "RedPill session was superseded before dispatch",
            );
        }
    }
    error
}

fn ensure_route(route: &RouteDefinition, provider: &str) -> Result<()> {
    if route.provider != provider || route.evidence_family != "redpill_aci_verified_tls" {
        return Err(ProviderError::Compatibility(
            "route is not a RedPill ACI verified TLS route".into(),
        ));
    }
    if !https_or_test_loopback(&route.api_base_url)
        || !https_or_test_loopback(&route.evidence_endpoint)
    {
        return Err(ProviderError::Compatibility(
            "RedPill endpoints must use HTTPS".into(),
        ));
    }
    Ok(())
}

fn constrain_request(mut body: Value, session_id: &str) -> Result<Value> {
    let object = body
        .as_object_mut()
        .ok_or_else(|| ProviderError::Compatibility("RedPill request must be an object".into()))?;
    object.insert("provider".into(), json!({"aci_session_ids": [session_id]}));
    Ok(body)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hex = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            };
            Some(hex(pair[0])? * 16 + hex(pair[1])?)
        })
        .collect()
}

fn verify_receipt(
    mut receipt: Value,
    receipt_id: &str,
    wire: &[u8],
    response: &[u8],
    state: &SessionState,
) -> Result<()> {
    let invalid =
        || ProviderError::Adapter("RedPill receipt verification failed after dispatch".into());
    let object = receipt.as_object_mut().ok_or_else(invalid)?;
    let sig = object
        .remove("signature")
        .and_then(|v| v.as_str().and_then(decode_hex))
        .ok_or_else(invalid)?;
    let key_id = object
        .get("key_id")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?
        .to_owned();
    let keyset = state
        .gateway_report
        .pointer("/attestation/workload_keyset")
        .ok_or_else(invalid)?;
    let keys = keyset
        .get("receipt_signing_keys")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let matches: Vec<_> = keys
        .iter()
        .filter(|key| {
            key.get("key_id").and_then(Value::as_str) == Some(key_id.as_str())
                && key.get("algo").and_then(Value::as_str) == Some("ed25519")
        })
        .collect();
    if matches.len() != 1 {
        return Err(invalid());
    }
    let public_key = matches[0]
        .get("public_key")
        .and_then(Value::as_str)
        .and_then(decode_hex)
        .ok_or_else(invalid)?;
    verify_redpill_aci_signature(&receipt, &public_key, &sig).map_err(|_| invalid())?;
    let served = receipt
        .get("served_at")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let established = state
        .session
        .get("established_at")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let expires = state
        .session
        .get("expires_at")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let key_expiry = keyset
        .get("not_after")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    if receipt.get("api_version").and_then(Value::as_str) != Some("aci/1")
        || receipt.get("receipt_id").and_then(Value::as_str) != Some(receipt_id)
        || receipt.get("workload_keyset_digest")
            != state.gateway_report.get("workload_keyset_digest")
        || served < established
        || served >= expires
        || served >= key_expiry
    {
        return Err(invalid());
    }
    let events = receipt
        .get("event_log")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let matching = |kind: &str| {
        events
            .iter()
            .filter(|e| e.get("type").and_then(Value::as_str) == Some(kind))
            .collect::<Vec<_>>()
    };
    let received = matching("request.received");
    let returned = matching("response.returned");
    let upstream = matching("upstream.verified");
    if received.len() != 1
        || returned.len() != 1
        || events.first() != received.first().copied()
        || received[0].get("body_hash").and_then(Value::as_str)
            != Some(sha256_digest(wire).as_str())
        || returned[0].get("body_hash").and_then(Value::as_str)
            != Some(sha256_digest(response).as_str())
        || upstream.is_empty()
        || !upstream.iter().all(|event| {
            event.get("result").and_then(Value::as_str) == Some("verified")
                && event.get("required").and_then(Value::as_bool) == Some(true)
                && event.get("session_id").and_then(Value::as_str)
                    == Some(state.session_id.as_str())
        })
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_constraint_overwrites_caller_provider() {
        for provider in [
            json!({"zdr":true}),
            json!({"aci_session_ids":["other"]}),
            json!(null),
        ] {
            let body = constrain_request(json!({"model":"m","provider":provider}), "abc").unwrap();
            assert_eq!(body["provider"], json!({"aci_session_ids":["abc"]}));
        }
    }

    #[test]
    fn newest_session_prefers_latest_established_valid_id() {
        let id = |c: char| c.to_string().repeat(64);
        let list = json!({"sessions": [
            {"session_id": id('a'), "established_at": 100},
            {"session_id": "not-an-id", "established_at": 300},
            {"session_id": id('b'), "established_at": 200},
        ]});
        assert_eq!(
            newest_session(&list).unwrap()["session_id"],
            Value::String(id('b'))
        );
        assert!(newest_session(&json!({"sessions": [
            {"session_id": "not-an-id"}
        ]}))
        .is_err());
    }

    #[test]
    fn cached_session_requires_matching_current_id_digest_and_expiry() {
        let cache = CachedSession {
            session_id: "a".repeat(64),
            session: json!({"evidence": {"digest": "sha256:one"}}),
            gpu_attestation: None,
            not_after: 200,
        };
        let entry = json!({"session_id": "a".repeat(64), "evidence": {"digest": "sha256:one"}});
        assert!(cache.matches_listed(&entry, 199));
        assert!(!cache.matches_listed(&entry, 200));
        assert!(!cache.matches_listed(
            &json!({"session_id":"b".repeat(64),"evidence":{"digest":"sha256:one"}}),
            199
        ));
        assert!(!cache.matches_listed(
            &json!({"session_id":"a".repeat(64),"evidence":{"digest":"sha256:two"}}),
            199
        ));
        assert!(!cache.matches_listed(&json!({"session_id":"a".repeat(64)}), 199));
    }

    fn fake_jwt(claims: &Value) -> String {
        format!(
            "h.{}.s",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        )
    }

    #[test]
    fn jwt_exp_fails_closed_on_malformed_tokens() {
        assert_eq!(jwt_exp(&fake_jwt(&json!({"exp": 1000}))), Some(1000));
        assert_eq!(jwt_exp(&fake_jwt(&json!({"exp": 1000.5}))), None);
        assert_eq!(jwt_exp(&fake_jwt(&json!({"exp": "1000"}))), None);
        assert_eq!(jwt_exp(&fake_jwt(&json!({"sub": "x"}))), None);
        assert_eq!(jwt_exp(&fake_jwt(&json!("not claims"))), None);
        assert_eq!(jwt_exp("no-claims-segment"), None);
        assert_eq!(jwt_exp("a.%%%.b"), None);
        assert_eq!(jwt_exp("a.b"), None);
    }

    #[test]
    fn cache_reuse_is_bounded_by_earliest_session_and_nras_expiry() {
        let gpu = |token: Option<String>| NvidiaGpuAttestationEvidence {
            schema: NvidiaGpuAttestationEvidence::SCHEMA.into(),
            attestation_format: NvidiaGpuAttestationEvidence::NRAS_GPU_EVIDENCE_V3.into(),
            nonce: "n".into(),
            arch: None,
            payload_sha256: None,
            raw_payload_base64: None,
            nras_token: token,
        };
        let session = |expires_at: u64| json!({"expires_at": expires_at});
        let token = |exp: u64| fake_jwt(&json!({"exp": exp}));
        assert_eq!(
            cache_not_after(&session(300), Some(&gpu(Some(token(200))))),
            Some(200)
        );
        assert_eq!(
            cache_not_after(&session(300), Some(&gpu(Some(token(400))))),
            Some(300)
        );
        // Missing evidence, token or `exp` must fail closed: no cache reuse.
        assert_eq!(cache_not_after(&session(300), None), None);
        assert_eq!(cache_not_after(&session(300), Some(&gpu(None))), None);
        assert_eq!(
            cache_not_after(&session(300), Some(&gpu(Some("bad".into())))),
            None
        );
        assert_eq!(
            cache_not_after(&session(300), Some(&gpu(Some(fake_jwt(&json!({})))))),
            None
        );
        assert_eq!(
            cache_not_after(&json!({}), Some(&gpu(Some(token(200))))),
            None
        );
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn receipt_state() -> (
        ed25519_compact::KeyPair,
        SessionState,
        Vec<u8>,
        Vec<u8>,
        String,
    ) {
        let key_pair = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([7u8; 32]));
        let session_id = "a".repeat(64);
        let state = SessionState {
            tls: LiveTlsPeer {
                spki_sha256: "spki".into(),
                leaf_certificate_der: vec![],
            },
            session_id: session_id.clone(),
            session: json!({"established_at": 100, "expires_at": 2000}),
            gateway_report: json!({
                "workload_keyset_digest": "sha256:keyset",
                "attestation": {"workload_keyset": {
                    "not_after": 2000,
                    "receipt_signing_keys": [{
                        "key_id": "receipt-key",
                        "algo": "ed25519",
                        "public_key": to_hex(key_pair.pk.as_ref()),
                    }],
                }},
            }),
            gpu_attestation: None,
        };
        (
            key_pair,
            state,
            b"wire-body".to_vec(),
            b"response-body".to_vec(),
            session_id,
        )
    }

    fn signed_receipt(key_pair: &ed25519_compact::KeyPair, events: Vec<Value>) -> Value {
        let mut receipt = json!({
            "api_version": "aci/1",
            "receipt_id": "receipt-1",
            "workload_keyset_digest": "sha256:keyset",
            "served_at": 500,
            "key_id": "receipt-key",
            "event_log": events,
        });
        let signature = key_pair.sk.sign(
            confidential_inference_attestation::canonical_json(&receipt)
                .unwrap()
                .as_bytes(),
            None,
        );
        receipt["signature"] = json!(to_hex(signature.as_ref()));
        receipt
    }

    #[test]
    fn receipt_requires_every_upstream_event_verified_for_this_session() {
        let (key_pair, state, wire, response, session_id) = receipt_state();
        let upstream = |result: &str, required: bool, session: &str| {
            json!({
                "type": "upstream.verified",
                "result": result,
                "required": required,
                "session_id": session,
            })
        };
        let events = |upstream_events: Vec<Value>| {
            let mut events = vec![
                json!({"type": "request.received", "body_hash": sha256_digest(&wire)}),
                json!({"type": "response.returned", "body_hash": sha256_digest(&response)}),
            ];
            events.extend(upstream_events);
            events
        };
        let check = |events: Vec<Value>| {
            verify_receipt(
                signed_receipt(&key_pair, events),
                "receipt-1",
                &wire,
                &response,
                &state,
            )
        };
        let good = upstream("verified", true, &session_id);
        assert!(check(events(vec![good.clone()])).is_ok());
        assert!(check(events(vec![good.clone(), good.clone()])).is_ok());
        // At least one upstream.verified event is required.
        assert!(check(events(vec![])).is_err());
        // Every upstream event must be a required verification of this session.
        for extra in [
            upstream("failed", true, &session_id),
            upstream("verified", false, &session_id),
            upstream("verified", true, &"b".repeat(64)),
            json!({"type": "upstream.verified"}),
        ] {
            assert!(check(events(vec![extra.clone()])).is_err());
            assert!(check(events(vec![good.clone(), extra])).is_err());
        }
    }

    #[test]
    fn only_explicit_session_refusal_requests_reverification() {
        let response = |status, body: &str| ProviderError::HttpStatus {
            status,
            message: format!("RedPill chat: {body}"),
        };
        let refused = session_refusal(
            "route",
            response(412, r#"{"error":{"type":"session_not_accepted"}}"#),
        );
        assert!(refused.is_key_rotation());
        assert_eq!(
            refused.chat_dispatch_outcome(),
            crate::DispatchOutcome::NotDispatched
        );
        for error in [
            response(412, r#"{"error":{"type":"other"}}"#),
            response(412, "not JSON"),
            response(500, r#"{"error":{"type":"session_not_accepted"}}"#),
        ] {
            assert!(matches!(
                session_refusal("route", error),
                ProviderError::HttpStatus { .. }
            ));
        }
    }
}
