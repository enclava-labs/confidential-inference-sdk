use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use confidential_inference_attestation::{
    sha256_digest, NearLiveEvidence, NvidiaGpuAttestationEvidence,
};
use confidential_inference_openai::ChatCompletionResponse;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::http::{checked_response_bytes, require_tls_peer, LiveTlsPeer};
use crate::nvidia::NvidiaNrasRemoteClient;
use crate::{
    EvidenceRequest, ProviderAdapter, ProviderChatRequest, ProviderError,
    ProviderRequestConfidentiality, Result, RouteDefinition,
};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct NearApiKey(Zeroizing<String>);

impl NearApiKey {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for NearApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Clone, Debug)]
pub struct NearHttpProvider {
    provider_id: String,
    routes: Vec<RouteDefinition>,
    api_key: NearApiKey,
    client: reqwest::Client,
    nras_client: Option<NvidiaNrasRemoteClient>,
    attested_tls: Arc<Mutex<BTreeMap<String, LiveTlsPeer>>>,
}

impl NearHttpProvider {
    pub fn new(
        provider_id: impl Into<String>,
        routes: Vec<RouteDefinition>,
        api_key: impl Into<String>,
    ) -> Result<Self> {
        install_default_rustls_provider();
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_HTTP_TIMEOUT)
            .tls_info(true)
            .build()
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        Ok(Self::with_clients(
            provider_id,
            routes,
            api_key.into(),
            client,
            Some(NvidiaNrasRemoteClient::with_default_http()?),
        ))
    }

    pub fn with_clients(
        provider_id: impl Into<String>,
        routes: Vec<RouteDefinition>,
        api_key: String,
        client: reqwest::Client,
        nras_client: Option<NvidiaNrasRemoteClient>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            routes,
            api_key: NearApiKey::new(api_key),
            client,
            nras_client,
            attested_tls: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.bearer_auth(self.api_key.expose())
    }

    async fn gpu_attestation(
        &self,
        report: &NearAttestationResponse,
    ) -> Result<Option<NvidiaGpuAttestationEvidence>> {
        let Some(payload) = report.nvidia_payload.as_deref() else {
            return Ok(None);
        };
        let payload_value: Value = serde_json::from_str(payload).map_err(|error| {
            ProviderError::Adapter(format!("NEAR NVIDIA payload is invalid JSON: {error}"))
        })?;
        let payload_bytes = serde_json::to_vec(&payload_value)?;
        let arch = payload_value
            .get("arch")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let nonce = payload_value
            .get("nonce")
            .and_then(Value::as_str)
            .filter(|nonce| !nonce.trim().is_empty())
            .ok_or_else(|| ProviderError::Adapter("NEAR NVIDIA payload has no nonce".into()))?;
        let evidence = NvidiaGpuAttestationEvidence {
            schema: NvidiaGpuAttestationEvidence::SCHEMA.into(),
            attestation_format: NvidiaGpuAttestationEvidence::NRAS_GPU_EVIDENCE_V3.into(),
            nonce: nonce.to_owned(),
            arch,
            payload_sha256: Some(sha256_digest(&payload_bytes)),
            raw_payload_base64: Some(STANDARD.encode(payload_bytes)),
            nras_token: None,
        };
        match &self.nras_client {
            Some(client) => client.attest_gpu_evidence(&evidence).await.map(Some),
            None => Ok(Some(evidence)),
        }
    }
}

#[async_trait]
impl ProviderAdapter for NearHttpProvider {
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
        ensure_near_route(route, &self.provider_id)?;
        let nonce = request.nonce.as_deref().ok_or_else(|| {
            ProviderError::Compatibility(
                "NEAR live evidence requires a per-request 32-byte nonce".into(),
            )
        })?;
        validate_nonce(nonce)?;
        let response = self
            .authorize(self.client.get(&route.evidence_endpoint).query(&[
                ("signing_algo", "ecdsa"),
                ("nonce", nonce),
                ("include_tls_fingerprint", "true"),
            ]))
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        let tls_peer = require_tls_peer(&response, "NEAR evidence")?;
        let body = checked_response_bytes(response, "NEAR evidence").await?;
        let report: NearAttestationResponse = serde_json::from_slice(&body)?;
        let gpu_attestation = self.gpu_attestation(&report).await?;
        let capture = NearLiveEvidence {
            schema: NearLiveEvidence::SCHEMA.into(),
            provider: route.provider.clone(),
            route_id: route.route_id.clone(),
            evidence_family: route.evidence_family.clone(),
            requested_model: request.requested_model.clone(),
            policy_digest: request.policy_digest.clone(),
            request_nonce: nonce.to_owned(),
            evidence_endpoint: route.evidence_endpoint.clone(),
            live_tls_spki_sha256: tls_peer.spki_sha256.clone(),
            live_tls_leaf_certificate_der_base64: STANDARD.encode(&tls_peer.leaf_certificate_der),
            raw_attestation_body_base64: STANDARD.encode(body),
            gpu_attestation,
        };
        let serialized = serde_json::to_vec(&capture)?;
        self.attested_tls
            .lock()
            .map_err(|_| ProviderError::Adapter("NEAR TLS state lock is poisoned".into()))?
            .insert(route.route_id.clone(), tls_peer);
        Ok(serialized)
    }

    async fn chat(
        &self,
        route: &RouteDefinition,
        request: ProviderChatRequest,
    ) -> Result<ChatCompletionResponse> {
        ensure_near_route(route, &self.provider_id)?;
        if request.confidentiality() != &ProviderRequestConfidentiality::Plaintext {
            return Err(ProviderError::Compatibility(
                "NEAR direct-endpoint chat must use the attested TLS channel".into(),
            ));
        }
        let expected_tls = self
            .attested_tls
            .lock()
            .map_err(|_| ProviderError::Adapter("NEAR TLS state lock is poisoned".into()))?
            .get(&route.route_id)
            .cloned()
            .ok_or_else(|| {
                ProviderError::Compatibility(format!(
                    "route {} has no attested NEAR TLS identity; verify evidence before chat",
                    route.route_id
                ))
            })?;
        let url = format!(
            "{}/chat/completions",
            route.api_base_url.trim_end_matches('/')
        );
        let response = self
            .authorize(self.client.post(url).json(request.body()))
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        let observed_tls = require_tls_peer(&response, "NEAR chat")?;
        if observed_tls.spki_sha256 != expected_tls.spki_sha256 {
            return Err(ProviderError::key_rotation(
                route.route_id.clone(),
                "NEAR TLS SPKI changed between attestation and chat",
            ));
        }
        let body = checked_response_bytes(response, "NEAR chat completions").await?;
        serde_json::from_slice(&body).map_err(Into::into)
    }
}

fn ensure_near_route(route: &RouteDefinition, provider: &str) -> Result<()> {
    if route.provider != provider {
        return Err(ProviderError::Adapter(format!(
            "route {} belongs to provider {}, not {}",
            route.route_id, route.provider, provider
        )));
    }
    if route.evidence_family != "near_hw_verified_tls" {
        return Err(ProviderError::Compatibility(format!(
            "route {} is not a NEAR hardware-verified TLS route",
            route.route_id
        )));
    }
    for (field, url) in [
        ("api_base_url", route.api_base_url.as_str()),
        ("evidence_endpoint", route.evidence_endpoint.as_str()),
    ] {
        if !url.starts_with("https://") && !(cfg!(test) && url.starts_with("http://127.0.0.1")) {
            return Err(ProviderError::Compatibility(format!(
                "route {} {field} must use https",
                route.route_id
            )));
        }
    }
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<()> {
    if nonce.len() == 64 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ProviderError::Adapter(
            "NEAR evidence nonce must be exactly 32 bytes of hex".into(),
        ))
    }
}

fn install_default_rustls_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug, Deserialize)]
struct NearAttestationResponse {
    #[serde(default)]
    nvidia_payload: Option<String>,
}
