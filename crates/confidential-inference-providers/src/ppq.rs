use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use confidential_inference_attestation::{
    parse_ppq_ehbp_evidence, sha256_digest, PpqEhbpLiveEvidence,
};
use confidential_inference_openai::ChatCompletionResponse;
use zeroize::Zeroizing;

use crate::http::{checked_response_bytes, https_or_test_loopback};
use crate::provider::EvidenceStateStore;
use crate::tls::{reqwest_client_builder, CONNECT_TIMEOUT, FETCH_REQUEST_TIMEOUT, READ_TIMEOUT};
use crate::{
    EvidenceRequest, ProviderAdapter, ProviderChatRequest, ProviderError,
    ProviderRequestConfidentiality, Result, RouteDefinition,
};

#[derive(Clone)]
struct Enclave {
    key: [u8; 32],
    domain: String,
}

#[derive(Clone)]
pub struct PpqPrivateHttpProvider {
    routes: Vec<RouteDefinition>,
    api_key: Zeroizing<String>,
    client: reqwest::Client,
    state: Arc<Mutex<EvidenceStateStore<Enclave>>>,
}

impl PpqPrivateHttpProvider {
    pub fn new(routes: Vec<RouteDefinition>, api_key: impl Into<String>) -> Result<Self> {
        let client = reqwest_client_builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build()
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        Ok(Self {
            routes,
            api_key: Zeroizing::new(api_key.into()),
            client,
            state: Arc::new(Mutex::new(EvidenceStateStore::new())),
        })
    }
}

fn ensure_route(route: &RouteDefinition) -> Result<()> {
    if route.provider != "ppq"
        || route.evidence_family != "ppq_ehbp"
        || !https_or_test_loopback(&route.api_base_url)
        || !https_or_test_loopback(&route.evidence_endpoint)
    {
        return Err(ProviderError::Compatibility(
            "PPQ requires a ppq_ehbp route with HTTPS endpoints".into(),
        ));
    }
    Ok(())
}

#[async_trait]
impl ProviderAdapter for PpqPrivateHttpProvider {
    fn provider_id(&self) -> &str {
        "ppq"
    }
    fn routes(&self) -> Vec<RouteDefinition> {
        self.routes.clone()
    }

    async fn fetch_evidence(
        &self,
        route: &RouteDefinition,
        request: &EvidenceRequest,
    ) -> Result<Vec<u8>> {
        ensure_route(route)?;
        let response = self
            .client
            .get(&route.evidence_endpoint)
            .timeout(FETCH_REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        let bundle = checked_response_bytes(response, "PPQ attestation bundle").await?;
        let capture = PpqEhbpLiveEvidence {
            schema: PpqEhbpLiveEvidence::SCHEMA.into(),
            provider: route.provider.clone(),
            route_id: route.route_id.clone(),
            evidence_family: route.evidence_family.clone(),
            requested_model: request.requested_model.clone(),
            policy_digest: request.policy_digest.clone(),
            evidence_endpoint: route.evidence_endpoint.clone(),
            raw_bundle_base64: STANDARD.encode(bundle),
        };
        let parsed = parse_ppq_ehbp_evidence(&capture)
            .map_err(|error| ProviderError::Adapter(error.to_string()))?;
        let raw = serde_json::to_vec(&capture)?;
        self.state
            .lock()
            .map_err(|_| ProviderError::Adapter("PPQ evidence state lock poisoned".into()))?
            .insert(
                &route.route_id,
                &sha256_digest(&raw),
                Enclave {
                    key: parsed.hpke_public_key,
                    domain: parsed.domain,
                },
            );
        Ok(raw)
    }

    async fn chat(
        &self,
        route: &RouteDefinition,
        request: ProviderChatRequest,
    ) -> Result<ChatCompletionResponse> {
        ensure_route(route)?;
        if request.confidentiality() != &ProviderRequestConfidentiality::AdapterManagedEncrypted {
            return Err(ProviderError::Compatibility(
                "PPQ requires adapter-managed E2EE".into(),
            ));
        }
        let enclave = self
            .state
            .lock()
            .map_err(|_| ProviderError::Adapter("PPQ evidence state lock poisoned".into()))?
            .lookup_for_request(route, &request, "PPQ enclave key")?
            .clone();
        let mut body = request.body().clone();
        let model = route
            .provider_model
            .strip_prefix("private/")
            .unwrap_or(&route.provider_model);
        body["model"] = model.into();
        let encrypted = crate::ehbp::encrypt(&enclave.key, &serde_json::to_vec(&body)?)?;
        let response = self
            .client
            .post(format!(
                "{}/chat/completions",
                route.api_base_url.trim_end_matches('/')
            ))
            .bearer_auth(self.api_key.as_str())
            .header("Content-Type", "application/json")
            .header("Ehbp-Encapsulated-Key", hex_encode(&encrypted.enc))
            .header(
                "X-Tinfoil-Enclave-Url",
                format!("https://{}", enclave.domain),
            )
            .header("X-Private-Model", &route.provider_model)
            .header("x-query-source", "api")
            .body(encrypted.body)
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        let nonce = response
            .headers()
            .get("Ehbp-Response-Nonce")
            .or_else(|| response.headers().get("X-EHbp-Response-Nonce"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let ciphertext = checked_response_bytes(response, "PPQ chat").await?;
        let nonce = nonce
            .ok_or_else(|| ProviderError::Adapter("PPQ response missing EHBP nonce".into()))?;
        let nonce = decode_hex(&nonce)?;
        let plaintext = crate::ehbp::decrypt(
            &encrypted.exported_secret,
            &encrypted.enc,
            &nonce,
            &ciphertext,
        )?;
        serde_json::from_slice(&plaintext).map_err(Into::into)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a string");
    }
    out
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.is_ascii() {
        return Err(ProviderError::Adapter("invalid PPQ response nonce".into()));
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| ProviderError::Adapter("invalid PPQ response nonce".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn chat_rejects_unknown_evidence_digest_before_dispatch() {
        let mut route = crate::ProviderRegistry::phase2_fixtures()
            .unwrap()
            .find_route(Some("tinfoil-fixture"), "llama-3.3-70b")
            .unwrap()
            .1
            .clone();
        route.provider = "ppq".into();
        route.evidence_family = "ppq_ehbp".into();
        let provider = PpqPrivateHttpProvider::new(vec![route.clone()], "key").unwrap();
        provider.state.lock().unwrap().insert(
            &route.route_id,
            "verified",
            Enclave {
                key: [1; 32],
                domain: "example.com".into(),
            },
        );
        let request =
            ProviderChatRequest::adapter_managed_encrypt(serde_json::json!({"model":"test"}))
                .with_verified_evidence_digest("other");
        assert!(provider
            .chat(&route, request)
            .await
            .unwrap_err()
            .is_key_rotation());
    }
}
