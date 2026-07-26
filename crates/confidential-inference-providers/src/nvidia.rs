use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use confidential_inference_attestation::{
    GpuAttestationVerifier, GpuTeeKind, NvidiaGpuAttestationEvidence,
    NvidiaGpuAttestationVerificationRequest, NvidiaNrasJwtVerifier, VerifiedGpuAttestation,
};
use serde_json::{json, Value};
use std::time::Duration;

use crate::{ProviderError, Result};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
pub const NVIDIA_NRAS_ATTEST_GPU_V4_URL: &str = "https://nras.attestation.nvidia.com/v4/attest/gpu";
pub const NVIDIA_NRAS_CLAIMS_VERSION: &str = "3.0";
#[deprecated(
    since = "0.1.0",
    note = "NRAS v3 is superseded; use NVIDIA_NRAS_ATTEST_GPU_V4_URL"
)]
pub const NVIDIA_NRAS_ATTEST_GPU_V3_URL: &str = "https://nras.attestation.nvidia.com/v3/attest/gpu";
pub const NVIDIA_NRAS_JWKS_URL: &str = "https://nras.attestation.nvidia.com/.well-known/jwks.json";

#[derive(Clone, Debug)]
pub struct NvidiaNrasRemoteClient {
    client: reqwest::Client,
    attest_gpu_url: String,
    jwks_url: String,
}

impl NvidiaNrasRemoteClient {
    pub fn with_default_http() -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_HTTP_TIMEOUT)
            .build()
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        Ok(Self::with_client_and_urls(
            client,
            NVIDIA_NRAS_ATTEST_GPU_V4_URL,
            NVIDIA_NRAS_JWKS_URL,
        ))
    }

    pub fn with_client_and_urls(
        client: reqwest::Client,
        attest_gpu_url: impl Into<String>,
        jwks_url: impl Into<String>,
    ) -> Self {
        Self {
            client,
            attest_gpu_url: attest_gpu_url.into(),
            jwks_url: jwks_url.into(),
        }
    }

    pub async fn fetch_jwks_json(&self) -> Result<String> {
        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|error| ProviderError::Http(format!("NRAS JWKS fetch failed: {error}")))?;
        checked_text_response(response, "NRAS JWKS").await
    }

    pub async fn fetch_jwt_verifier(&self) -> Result<NvidiaNrasJwtVerifier> {
        let jwks_json = self.fetch_jwks_json().await?;
        NvidiaNrasJwtVerifier::from_jwks_json(&jwks_json)
            .map_err(|error| ProviderError::Adapter(error.to_string()))
    }

    pub async fn submit_gpu_evidence(
        &self,
        evidence: &NvidiaGpuAttestationEvidence,
    ) -> Result<String> {
        let request_body = nras_gpu_attestation_request(evidence)?;
        let response = self
            .client
            .post(&self.attest_gpu_url)
            .header("accept", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|error| {
                ProviderError::Http(format!("NRAS GPU attestation request failed: {error}"))
            })?;
        let body = checked_text_response(response, "NRAS GPU attestation").await?;
        let value: Value = serde_json::from_str(&body)?;
        extract_nras_token(&value)
            .ok_or_else(|| {
                ProviderError::Adapter(
                    "NRAS GPU attestation response did not contain a compact JWT".into(),
                )
            })
            .map(ToOwned::to_owned)
    }

    pub async fn attest_gpu_evidence(
        &self,
        evidence: &NvidiaGpuAttestationEvidence,
    ) -> Result<NvidiaGpuAttestationEvidence> {
        let nras_token = self.submit_gpu_evidence(evidence).await?;
        let mut enriched = evidence.clone();
        enriched.nras_token = Some(nras_token);
        Ok(enriched)
    }

    pub async fn attest_and_verify_gpu_evidence(
        &self,
        evidence: &NvidiaGpuAttestationEvidence,
    ) -> Result<VerifiedGpuAttestation> {
        let enriched = self.attest_gpu_evidence(evidence).await?;
        let verifier = self.fetch_jwt_verifier().await?;
        verifier
            .verify_nvidia_gpu_attestation(&NvidiaGpuAttestationVerificationRequest {
                evidence: &enriched,
                expected_nonce: &enriched.nonce,
                expected_tee: GpuTeeKind::NvidiaCc,
                provider: "nvidia-nras",
                route_id: "nvidia-nras:gpu",
            })
            .map_err(|error| ProviderError::Adapter(error.to_string()))
    }
}

fn nras_gpu_attestation_request(evidence: &NvidiaGpuAttestationEvidence) -> Result<Value> {
    if evidence.nonce.trim().is_empty() {
        return Err(ProviderError::Adapter(
            "NVIDIA GPU attestation evidence has an empty nonce".into(),
        ));
    }
    let raw_payload_base64 = evidence.raw_payload_base64.as_deref().ok_or_else(|| {
        ProviderError::Adapter("NVIDIA GPU attestation evidence is missing raw payload".into())
    })?;
    let raw_payload = STANDARD.decode(raw_payload_base64).map_err(|error| {
        ProviderError::Adapter(format!("NVIDIA GPU payload is not base64: {error}"))
    })?;
    if raw_payload.is_empty() {
        return Err(ProviderError::Adapter(
            "NVIDIA GPU attestation evidence has an empty raw payload".into(),
        ));
    }
    let payload = match serde_json::from_slice::<Value>(&raw_payload) {
        Ok(payload) => payload,
        Err(_) => Value::String(String::from_utf8(raw_payload).map_err(|error| {
            ProviderError::Adapter(format!(
                "NVIDIA GPU payload is neither JSON nor UTF-8 evidence: {error}"
            ))
        })?),
    };
    validate_provider_nonce(&payload, &evidence.nonce)?;
    let evidence_list = nras_evidence_list_from_payload(&payload)?;

    Ok(json!({
        "nonce": evidence.nonce,
        "arch": nras_arch(evidence.arch.as_deref(), &payload),
        "evidence_list": evidence_list,
        "claims_version": NVIDIA_NRAS_CLAIMS_VERSION,
    }))
}

fn validate_provider_nonce(payload: &Value, expected_nonce: &str) -> Result<()> {
    let Some(nonce) = payload.get("nonce") else {
        return Ok(());
    };
    let actual_nonce = nonce
        .as_str()
        .filter(|nonce| !nonce.trim().is_empty())
        .ok_or_else(|| {
            ProviderError::Adapter("NVIDIA provider nonce is empty or malformed".into())
        })?;
    if !actual_nonce.eq_ignore_ascii_case(expected_nonce) {
        return Err(ProviderError::Adapter(
            "NVIDIA provider nonce does not match the verifier nonce".into(),
        ));
    }
    Ok(())
}

fn nras_evidence_list_from_payload(payload: &Value) -> Result<Value> {
    let entries = if let Some(evidence_list) = payload.get("evidence_list") {
        evidence_list.as_array().cloned().ok_or_else(|| {
            ProviderError::Adapter("NVIDIA GPU evidence_list is not an array".into())
        })?
    } else if let Some(entries) = payload.as_array() {
        entries.clone()
    } else if payload.get("evidence").is_some() {
        vec![payload.clone()]
    } else if let Some(raw) = payload.as_str() {
        vec![json!({ "evidence": raw })]
    } else {
        return Err(ProviderError::Adapter(
            "NVIDIA provider payload contains no GPU evidence".into(),
        ));
    };

    if entries.is_empty()
        || entries.iter().any(|entry| {
            entry
                .get("evidence")
                .and_then(Value::as_str)
                .is_none_or(|evidence| evidence.trim().is_empty())
        })
    {
        return Err(ProviderError::Adapter(
            "NVIDIA provider payload contains empty or malformed GPU evidence".into(),
        ));
    }
    Ok(Value::Array(entries))
}

fn nras_arch(explicit_arch: Option<&str>, payload: &Value) -> &'static str {
    let arch = explicit_arch
        .or_else(|| payload.get("arch").and_then(Value::as_str))
        .or_else(|| {
            payload
                .get("evidence_list")
                .and_then(Value::as_array)
                .and_then(|entries| entries.first())
                .and_then(|entry| entry.get("arch"))
                .and_then(Value::as_str)
        })
        .unwrap_or_default()
        .to_ascii_lowercase();
    if arch.contains("blackwell") || arch.contains("b200") || arch.contains("gb200") {
        "BLACKWELL"
    } else {
        "HOPPER"
    }
}

pub fn extract_nras_token(value: &Value) -> Option<&str> {
    if let Some(token) = value.as_str().filter(|token| is_compact_jwt(token)) {
        return Some(token);
    }
    if let Some(object) = value.as_object() {
        for key in [
            "token",
            "jwt",
            "eat",
            "nras_token",
            "attestation_token",
            "REMOTE_GPU_CLAIMS",
        ] {
            if let Some(token) = object.get(key).and_then(extract_nras_token) {
                return Some(token);
            }
        }
        for nested in object.values() {
            if let Some(token) = extract_nras_token(nested) {
                return Some(token);
            }
        }
    }
    if let Some(array) = value.as_array() {
        if array.len() >= 2
            && array[0].as_str() == Some("JWT")
            && array[1].as_str().is_some_and(is_compact_jwt)
        {
            return array[1].as_str();
        }
        for item in array {
            if let Some(token) = extract_nras_token(item) {
                return Some(token);
            }
        }
    }
    None
}

fn is_compact_jwt(value: &str) -> bool {
    value.split('.').count() == 3
}

async fn checked_text_response(response: reqwest::Response, label: &str) -> Result<String> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| ProviderError::Http(format!("{label} response body failed: {error}")))?;
    if !status.is_success() {
        let preview: String = body.chars().take(500).collect();
        return Err(ProviderError::Http(format!(
            "{label} returned HTTP {status}: {preview}"
        )));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn builds_v4_request_from_evidence_list_payload() {
        let evidence = evidence_with_payload(json!({
            "nonce": "33".repeat(32),
            "evidence_list": [{
                "evidence": "gpu-evidence",
                "certificate": "gpu-cert",
                "arch": "gpu-blackwell-b200"
            }]
        }));

        let request = nras_gpu_attestation_request(&evidence).unwrap();

        assert_eq!(request["nonce"], evidence.nonce);
        assert_eq!(request["arch"], "BLACKWELL");
        assert_eq!(request["claims_version"], NVIDIA_NRAS_CLAIMS_VERSION);
        assert_eq!(request["evidence_list"][0]["evidence"], "gpu-evidence");
        assert_eq!(request["evidence_list"][0]["certificate"], "gpu-cert");
    }

    #[test]
    fn rejects_empty_or_malformed_gpu_evidence() {
        for payload in [
            json!({}),
            json!({ "evidence_list": [] }),
            json!({ "evidence_list": [{}] }),
            json!({ "evidence_list": [{ "evidence": " " }] }),
            json!({ "evidence_list": "not-an-array" }),
        ] {
            let error = nras_gpu_attestation_request(&evidence_with_payload(payload)).unwrap_err();
            assert!(error.to_string().contains("evidence"));
        }
    }

    #[test]
    fn rejects_provider_nonce_mismatch_before_submission() {
        let evidence = evidence_with_payload(json!({
            "nonce": "44".repeat(32),
            "evidence_list": [{ "evidence": "gpu-evidence" }]
        }));

        let error = nras_gpu_attestation_request(&evidence).unwrap_err();

        assert!(error.to_string().contains("nonce"));
    }

    #[test]
    fn extracts_token_from_detached_eat_bundle() {
        let response = json!([
            ["JWT", "header.claims.signature"],
            { "claim_details": { "GPU-0": { "x-nvidia-overall-att-result": true } } }
        ]);

        assert_eq!(
            extract_nras_token(&response),
            Some("header.claims.signature")
        );
    }

    #[tokio::test]
    async fn remote_client_submits_gpu_evidence_fetches_jwks_and_verifies_token() {
        let fixture = SignedNrasTokenFixture::new();
        let (base_url, server) =
            spawn_nras_server(fixture.token.clone(), fixture.jwks.clone()).await;
        let reqwest_client = reqwest::Client::builder().build().unwrap();
        let client = NvidiaNrasRemoteClient::with_client_and_urls(
            reqwest_client,
            format!("{base_url}/v4/attest/gpu"),
            format!("{base_url}/.well-known/jwks.json"),
        );
        let evidence = evidence_with_payload(json!({
            "evidence_list": [{ "evidence": "gpu-evidence", "certificate": "gpu-cert" }],
            "arch": "HOPPER"
        }));

        let verified = client
            .attest_and_verify_gpu_evidence(&evidence)
            .await
            .unwrap();

        assert_eq!(verified.tee, GpuTeeKind::NvidiaCc);
        assert_eq!(verified.nonce, evidence.nonce);
        assert_eq!(verified.verifier, "nvidia-nras-jwt:nras-test-key");
        server.await.unwrap().unwrap();
    }

    fn evidence_with_payload(payload: Value) -> NvidiaGpuAttestationEvidence {
        NvidiaGpuAttestationEvidence {
            schema: NvidiaGpuAttestationEvidence::SCHEMA.into(),
            attestation_format: NvidiaGpuAttestationEvidence::NRAS_GPU_EVIDENCE_V3.into(),
            nonce: "33".repeat(32),
            arch: None,
            payload_sha256: None,
            raw_payload_base64: Some(STANDARD.encode(serde_json::to_vec(&payload).unwrap())),
            nras_token: None,
        }
    }

    async fn spawn_nras_server(
        token: String,
        jwks: Value,
    ) -> (String, tokio::task::JoinHandle<std::io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await?;
                let mut request = vec![0_u8; 8192];
                let n = socket.read(&mut request).await?;
                let request = String::from_utf8_lossy(&request[..n]);
                let body = if request.starts_with("POST /v4/attest/gpu ")
                    && request.contains(r#""claims_version":"3.0""#)
                {
                    json!([["JWT", token]]).to_string()
                } else if request.starts_with("GET /.well-known/jwks.json ") {
                    jwks.to_string()
                } else {
                    json!({"error": "not found"}).to_string()
                };
                let status = if body.contains("not found") {
                    "HTTP/1.1 404 Not Found"
                } else {
                    "HTTP/1.1 200 OK"
                };
                let response = format!(
                    "{status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await?;
            }
            Ok(())
        });
        (base_url, server)
    }

    #[derive(Clone)]
    struct SignedNrasTokenFixture {
        token: String,
        jwks: Value,
    }

    impl SignedNrasTokenFixture {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
            let key_pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            let public_key = key_pair.public_key().as_ref();
            let jwks = json!({
                "keys": [{
                    "kty": "EC",
                    "crv": "P-384",
                    "alg": "ES384",
                    "kid": "nras-test-key",
                    "x": URL_SAFE_NO_PAD.encode(&public_key[1..49]),
                    "y": URL_SAFE_NO_PAD.encode(&public_key[49..97])
                }]
            });
            let header = json!({
                "alg": "ES384",
                "typ": "JWT",
                "kid": "nras-test-key"
            });
            let claims = json!({
                "iss": confidential_inference_attestation::NVIDIA_NRAS_ISSUER,
                "sub": "nvidia-gpu",
                "x-nvidia-ver": confidential_inference_attestation::NVIDIA_NRAS_CLAIMS_VERSION,
                "x-nvidia-overall-att-result": true,
                "eat_nonce": "33".repeat(32),
                "nbf": 0u64,
                "exp": 4_070_908_800u64
            });
            let signing_input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            );
            let signature = key_pair.sign(&rng, signing_input.as_bytes()).unwrap();
            let token = format!(
                "{}.{}",
                signing_input,
                URL_SAFE_NO_PAD.encode(signature.as_ref())
            );
            Self { token, jwks }
        }
    }
}
