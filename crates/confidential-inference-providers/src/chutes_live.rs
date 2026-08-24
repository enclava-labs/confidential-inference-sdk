use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use confidential_inference_attestation::{
    chutes_expected_report_data_prefix, sha256_digest, ChutesLiveEvidence,
    NvidiaGpuAttestationEvidence,
};
use confidential_inference_openai::ChatCompletionResponse;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit},
    MlKem768,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::nvidia::NvidiaNrasRemoteClient;
use crate::{
    EvidenceRequest, ProviderAdapter, ProviderChatRequest, ProviderError,
    ProviderRequestConfidentiality, Result, RouteDefinition,
};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1_184;
const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1_088;
const CHACHA_NONCE_BYTES: usize = 12;
const CHACHA_TAG_BYTES: usize = 16;
const MAX_DECRYPTED_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const E2EE_REQUEST_INFO: &[u8] = b"e2e-req-v1";
const E2EE_RESPONSE_INFO: &[u8] = b"e2e-resp-v1";

#[derive(Clone)]
struct ChutesApiKey(Zeroizing<String>);

impl ChutesApiKey {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ChutesApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Clone, Debug)]
struct AttestedChutesInstance {
    chute_id: String,
    instance_id: String,
    e2e_public_key_base64: String,
    invocation_nonces: VecDeque<String>,
}

#[derive(Clone, Debug)]
pub struct ChutesHttpProvider {
    provider_id: String,
    routes: Vec<RouteDefinition>,
    api_key: ChutesApiKey,
    client: reqwest::Client,
    nras_client: Option<NvidiaNrasRemoteClient>,
    attested_instances: Arc<Mutex<BTreeMap<String, AttestedChutesInstance>>>,
}

impl ChutesHttpProvider {
    pub fn new(
        provider_id: impl Into<String>,
        routes: Vec<RouteDefinition>,
        api_key: impl Into<String>,
    ) -> Result<Self> {
        install_default_rustls_provider();
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_HTTP_TIMEOUT)
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
            api_key: ChutesApiKey::new(api_key),
            client,
            nras_client,
            attested_instances: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.bearer_auth(self.api_key.expose())
    }

    async fn resolve_chute_id(&self, route: &RouteDefinition) -> Result<String> {
        let url = format!("{}/models", route.api_base_url.trim_end_matches('/'));
        let response = self
            .authorize(self.client.get(url))
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        let body = checked_response_bytes(response, "Chutes model discovery").await?;
        let model_list: ChutesModelList = serde_json::from_slice(&body)?;
        model_list
            .data
            .into_iter()
            .find(|model| model.id == route.provider_model)
            .and_then(|model| model.chute_id)
            .filter(|chute_id| !chute_id.trim().is_empty())
            .ok_or_else(|| {
                ProviderError::Adapter(format!(
                    "Chutes model {} did not resolve to a chute_id",
                    route.provider_model
                ))
            })
    }

    async fn discover_instance(
        &self,
        route: &RouteDefinition,
        chute_id: &str,
    ) -> Result<ChutesDiscoveredInstance> {
        let control_base = control_api_base(&route.evidence_endpoint)?;
        let url = format!(
            "{}/e2e/instances/{}",
            control_base.trim_end_matches('/'),
            chute_id
        );
        let response = self
            .authorize(self.client.get(url))
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        let body = checked_response_bytes(response, "Chutes E2EE instance discovery").await?;
        let discovery: ChutesInstanceDiscovery = serde_json::from_slice(&body)?;
        discovery
            .instances
            .into_iter()
            .find(|instance| {
                !instance.instance_id.trim().is_empty()
                    && !instance.nonces.is_empty()
                    && STANDARD
                        .decode(&instance.e2e_pubkey)
                        .is_ok_and(|key| key.len() == ML_KEM_768_PUBLIC_KEY_BYTES)
            })
            .ok_or_else(|| {
                ProviderError::Unavailable("Chutes has no active ML-KEM-768 E2EE instance".into())
            })
    }

    async fn fetch_instance_evidence(
        &self,
        route: &RouteDefinition,
        instance_id: &str,
        nonce: &str,
    ) -> Result<ChutesInstanceEvidence> {
        let control_base = control_api_base(&route.evidence_endpoint)?;
        let url = format!(
            "{}/instances/{}/evidence",
            control_base.trim_end_matches('/'),
            instance_id
        );
        let response = self
            .authorize(self.client.get(url).query(&[("nonce", nonce)]))
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        let body = checked_response_bytes(response, "Chutes instance evidence").await?;
        let evidence: ChutesInstanceEvidence = serde_json::from_slice(&body)?;
        if evidence
            .instance_id
            .as_deref()
            .is_some_and(|returned| returned != instance_id)
        {
            return Err(ProviderError::key_rotation(
                route.route_id.clone(),
                "Chutes evidence returned a different instance_id",
            ));
        }
        Ok(evidence)
    }

    async fn gpu_attestation(
        &self,
        gpu_evidence: &[Value],
        nonce: &str,
    ) -> Result<Option<NvidiaGpuAttestationEvidence>> {
        if gpu_evidence.is_empty() {
            return Ok(None);
        }
        let payload = serde_json::to_vec(gpu_evidence)?;
        let arch = gpu_evidence
            .first()
            .and_then(|entry| entry.get("arch"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let evidence = NvidiaGpuAttestationEvidence {
            schema: NvidiaGpuAttestationEvidence::SCHEMA.into(),
            attestation_format: NvidiaGpuAttestationEvidence::NRAS_GPU_EVIDENCE_V3.into(),
            nonce: nonce.to_owned(),
            arch,
            payload_sha256: Some(sha256_digest(&payload)),
            raw_payload_base64: Some(STANDARD.encode(payload)),
            nras_token: None,
        };
        match &self.nras_client {
            Some(client) => client.attest_gpu_evidence(&evidence).await.map(Some),
            None => Ok(Some(evidence)),
        }
    }

    fn take_attested_invocation(
        &self,
        route: &RouteDefinition,
    ) -> Result<(AttestedChutesInstance, String)> {
        let mut instances = self.attested_instances.lock().map_err(|_| {
            ProviderError::Adapter("Chutes attested-instance state lock is poisoned".into())
        })?;
        let instance = instances.get_mut(&route.route_id).ok_or_else(|| {
            ProviderError::Compatibility(format!(
                "route {} has no attested Chutes instance; verify evidence before chat",
                route.route_id
            ))
        })?;
        let nonce = instance.invocation_nonces.pop_front().ok_or_else(|| {
            ProviderError::key_rotation(
                route.route_id.clone(),
                "attested Chutes instance has no unused invocation nonces",
            )
        })?;
        Ok((instance.clone(), nonce))
    }
}

#[async_trait]
impl ProviderAdapter for ChutesHttpProvider {
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
        ensure_chutes_route(route, &self.provider_id)?;
        let request_nonce = request.nonce.as_deref().ok_or_else(|| {
            ProviderError::Compatibility(
                "Chutes live evidence requires a per-request 32-byte nonce".into(),
            )
        })?;
        validate_nonce(request_nonce, "Chutes evidence nonce")?;
        let chute_id = self.resolve_chute_id(route).await?;
        let instance = self.discover_instance(route, &chute_id).await?;
        let evidence = self
            .fetch_instance_evidence(route, &instance.instance_id, request_nonce)
            .await?;
        let gpu_nonce = chutes_expected_report_data_prefix(request_nonce, &instance.e2e_pubkey)
            .ok_or_else(|| {
                ProviderError::Adapter(
                    "Chutes evidence challenge or E2EE public key is malformed".into(),
                )
            })?;
        let gpu_attestation = self
            .gpu_attestation(&evidence.gpu_evidence, &gpu_nonce)
            .await?;

        let capture = ChutesLiveEvidence {
            schema: ChutesLiveEvidence::SCHEMA.into(),
            provider: route.provider.clone(),
            route_id: route.route_id.clone(),
            evidence_family: route.evidence_family.clone(),
            requested_model: request.requested_model.clone(),
            policy_digest: request.policy_digest.clone(),
            request_nonce: request_nonce.to_owned(),
            evidence_endpoint: route.evidence_endpoint.clone(),
            chute_id: chute_id.clone(),
            instance_id: instance.instance_id.clone(),
            e2e_public_key_base64: instance.e2e_pubkey.clone(),
            quote_base64: evidence.quote,
            certificate_der_base64: evidence.certificate,
            gpu_attestation,
        };
        let serialized = serde_json::to_vec(&capture)?;

        self.attested_instances
            .lock()
            .map_err(|_| {
                ProviderError::Adapter("Chutes attested-instance state lock is poisoned".into())
            })?
            .insert(
                route.route_id.clone(),
                AttestedChutesInstance {
                    chute_id,
                    instance_id: instance.instance_id,
                    e2e_public_key_base64: instance.e2e_pubkey,
                    invocation_nonces: instance.nonces.into(),
                },
            );
        Ok(serialized)
    }

    async fn chat(
        &self,
        route: &RouteDefinition,
        request: ProviderChatRequest,
    ) -> Result<ChatCompletionResponse> {
        ensure_chutes_route(route, &self.provider_id)?;
        if request.confidentiality() != &ProviderRequestConfidentiality::AdapterManagedEncrypted {
            return Err(ProviderError::Compatibility(
                "Chutes live chat requires adapter-managed E2EE".into(),
            ));
        }
        let (instance, invocation_nonce) = self.take_attested_invocation(route)?;
        let encrypted = encrypt_request(&instance.e2e_public_key_base64, request.body())?;
        let control_base = control_api_base(&route.evidence_endpoint)?;
        let response = self
            .authorize(
                self.client
                    .post(format!("{}/e2e/invoke", control_base.trim_end_matches('/')))
                    .header("X-Chute-Id", &instance.chute_id)
                    .header("X-Instance-Id", &instance.instance_id)
                    .header("X-E2E-Nonce", invocation_nonce)
                    .header("X-E2E-Stream", "false")
                    .header("X-E2E-Path", "/v1/chat/completions")
                    .header("Content-Type", "application/octet-stream")
                    .body(encrypted.blob),
            )
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        let body = checked_response_bytes(response, "Chutes E2EE invocation").await?;
        let plaintext = decrypt_response(&body, &encrypted.response_decapsulation_key)?;
        serde_json::from_slice(&plaintext).map_err(Into::into)
    }
}

struct EncryptedChutesRequest {
    blob: Vec<u8>,
    response_decapsulation_key: <MlKem768 as Kem>::DecapsulationKey,
}

fn encrypt_request(e2e_public_key_base64: &str, body: &Value) -> Result<EncryptedChutesRequest> {
    let public_key_bytes = STANDARD.decode(e2e_public_key_base64).map_err(|error| {
        ProviderError::Adapter(format!("Chutes E2EE public key is not base64: {error}"))
    })?;
    let public_key = <MlKem768 as Kem>::EncapsulationKey::new_from_slice(&public_key_bytes)
        .map_err(|_| ProviderError::Adapter("Chutes ML-KEM-768 public key is invalid".into()))?;
    let (request_ciphertext, shared_secret) = public_key.encapsulate();
    let request_key = derive_key(
        shared_secret.as_ref(),
        request_ciphertext.as_ref(),
        E2EE_REQUEST_INFO,
    )?;

    let (response_decapsulation_key, response_public_key) = MlKem768::generate_keypair();
    let mut payload = body.clone();
    let fields = payload
        .as_object_mut()
        .ok_or_else(|| ProviderError::Adapter("Chutes chat payload is not a JSON object".into()))?;
    fields.insert(
        "e2e_response_pk".into(),
        Value::String(STANDARD.encode(response_public_key.to_bytes())),
    );
    let plaintext = serde_json::to_vec(&payload)?;
    let compressed = gzip(&plaintext)?;
    let mut nonce = [0_u8; CHACHA_NONCE_BYTES];
    getrandom::fill(&mut nonce).expect("OS randomness unavailable");
    let encrypted = ChaCha20Poly1305::new_from_slice(&request_key)
        .map_err(|_| ProviderError::Adapter("invalid Chutes request key".into()))?
        .encrypt((&nonce).into(), compressed.as_ref())
        .map_err(|_| ProviderError::Adapter("Chutes request encryption failed".into()))?;

    let mut blob =
        Vec::with_capacity(ML_KEM_768_CIPHERTEXT_BYTES + CHACHA_NONCE_BYTES + encrypted.len());
    blob.extend_from_slice(request_ciphertext.as_ref());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&encrypted);
    Ok(EncryptedChutesRequest {
        blob,
        response_decapsulation_key,
    })
}

fn decrypt_response(
    blob: &[u8],
    response_decapsulation_key: &<MlKem768 as Kem>::DecapsulationKey,
) -> Result<Vec<u8>> {
    let minimum = ML_KEM_768_CIPHERTEXT_BYTES + CHACHA_NONCE_BYTES + CHACHA_TAG_BYTES;
    if blob.len() < minimum {
        return Err(ProviderError::Adapter(
            "Chutes E2EE response is truncated".into(),
        ));
    }
    let (ciphertext_bytes, rest) = blob.split_at(ML_KEM_768_CIPHERTEXT_BYTES);
    let (nonce, encrypted) = rest.split_at(CHACHA_NONCE_BYTES);
    let ciphertext = ciphertext_bytes.try_into().map_err(|_| {
        ProviderError::Adapter("Chutes response ML-KEM ciphertext has wrong size".into())
    })?;
    let shared_secret = response_decapsulation_key.decapsulate(&ciphertext);
    let response_key = derive_key(shared_secret.as_ref(), ciphertext_bytes, E2EE_RESPONSE_INFO)?;
    let compressed = ChaCha20Poly1305::new_from_slice(&response_key)
        .map_err(|_| ProviderError::Adapter("invalid Chutes response key".into()))?
        .decrypt(
            <&Nonce>::try_from(nonce).expect("validated Chutes nonce length"),
            encrypted,
        )
        .map_err(|_| ProviderError::Adapter("Chutes response authentication failed".into()))?;
    gunzip_bounded(&compressed)
}

fn derive_key(shared_secret: &[u8], ciphertext: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let salt = ciphertext.get(..16).ok_or_else(|| {
        ProviderError::Adapter("Chutes ML-KEM ciphertext is too short for HKDF salt".into())
    })?;
    let mut key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(salt), shared_secret)
        .expand(info, &mut key)
        .map_err(|_| ProviderError::Adapter("Chutes HKDF expansion failed".into()))?;
    Ok(key)
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bytes)
        .map_err(|error| ProviderError::Adapter(format!("Chutes gzip failed: {error}")))?;
    encoder
        .finish()
        .map_err(|error| ProviderError::Adapter(format!("Chutes gzip failed: {error}")))
}

fn gunzip_bounded(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder
        .by_ref()
        .take((MAX_DECRYPTED_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|error| ProviderError::Adapter(format!("Chutes gunzip failed: {error}")))?;
    if out.len() > MAX_DECRYPTED_RESPONSE_BYTES {
        return Err(ProviderError::Adapter(
            "Chutes decrypted response exceeds size limit".into(),
        ));
    }
    Ok(out)
}

fn ensure_chutes_route(route: &RouteDefinition, provider: &str) -> Result<()> {
    if route.provider != provider {
        return Err(ProviderError::Adapter(format!(
            "route {} belongs to provider {}, not {}",
            route.route_id, route.provider, provider
        )));
    }
    if route.evidence_family != "chutes_live_e2ee" {
        return Err(ProviderError::Compatibility(format!(
            "route {} is not a Chutes live-E2EE route",
            route.route_id
        )));
    }
    require_https(&route.api_base_url, "api_base_url", &route.route_id)?;
    require_https(
        &route.evidence_endpoint,
        "evidence_endpoint",
        &route.route_id,
    )
}

fn require_https(url: &str, field: &str, route_id: &str) -> Result<()> {
    if url.starts_with("https://") || cfg!(test) && url.starts_with("http://127.0.0.1") {
        Ok(())
    } else {
        Err(ProviderError::Compatibility(format!(
            "route {route_id} {field} must use https"
        )))
    }
}

fn control_api_base(evidence_endpoint: &str) -> Result<String> {
    let url = reqwest::Url::parse(evidence_endpoint).map_err(|error| {
        ProviderError::Compatibility(format!("invalid Chutes evidence endpoint: {error}"))
    })?;
    let host = url.host_str().ok_or_else(|| {
        ProviderError::Compatibility("Chutes evidence endpoint has no host".into())
    })?;
    let mut base = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        base.push_str(&format!(":{port}"));
    }
    Ok(base)
}

fn validate_nonce(nonce: &str, field: &str) -> Result<()> {
    if nonce.len() == 64 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ProviderError::Adapter(format!(
            "{field} must be exactly 32 bytes of hex"
        )))
    }
}

async fn checked_response_bytes(response: reqwest::Response, operation: &str) -> Result<Vec<u8>> {
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|error| ProviderError::Http(error.to_string()))?
        .to_vec();
    if status.is_success() {
        Ok(body)
    } else {
        Err(ProviderError::HttpStatus {
            status: status.as_u16(),
            message: format!("{operation} failed"),
        })
    }
}

fn install_default_rustls_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug, Deserialize)]
struct ChutesModelList {
    data: Vec<ChutesModel>,
}

#[derive(Debug, Deserialize)]
struct ChutesModel {
    id: String,
    #[serde(default)]
    chute_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChutesInstanceDiscovery {
    instances: Vec<ChutesDiscoveredInstance>,
}

#[derive(Clone, Debug, Deserialize)]
struct ChutesDiscoveredInstance {
    instance_id: String,
    e2e_pubkey: String,
    nonces: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ChutesInstanceEvidence {
    quote: String,
    gpu_evidence: Vec<Value>,
    certificate: String,
    #[serde(default)]
    instance_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chutes_crypto_round_trip_matches_wire_format() {
        let (server_secret, server_public) = MlKem768::generate_keypair();
        let request = encrypt_request(
            &STANDARD.encode(server_public.to_bytes()),
            &serde_json::json!({"model":"test","messages":[]}),
        )
        .unwrap();
        assert!(request.blob.len() > ML_KEM_768_CIPHERTEXT_BYTES + CHACHA_NONCE_BYTES);

        let request_ct: ml_kem::Ciphertext<MlKem768> = request.blob[..ML_KEM_768_CIPHERTEXT_BYTES]
            .try_into()
            .unwrap();
        let server_shared = server_secret.decapsulate(&request_ct);
        let server_key = derive_key(
            server_shared.as_ref(),
            request_ct.as_ref(),
            E2EE_REQUEST_INFO,
        )
        .unwrap();
        let compressed = ChaCha20Poly1305::new_from_slice(&server_key)
            .unwrap()
            .decrypt(
                <&Nonce>::try_from(
                    &request.blob[ML_KEM_768_CIPHERTEXT_BYTES
                        ..ML_KEM_768_CIPHERTEXT_BYTES + CHACHA_NONCE_BYTES],
                )
                .unwrap(),
                &request.blob[ML_KEM_768_CIPHERTEXT_BYTES + CHACHA_NONCE_BYTES..],
            )
            .unwrap();
        let plaintext = gunzip_bounded(&compressed).unwrap();
        let payload: Value = serde_json::from_slice(&plaintext).unwrap();
        let response_public = <MlKem768 as Kem>::EncapsulationKey::new_from_slice(
            &STANDARD
                .decode(payload["e2e_response_pk"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();

        let (response_ct, response_shared) = response_public.encapsulate();
        let response_key = derive_key(
            response_shared.as_ref(),
            response_ct.as_ref(),
            E2EE_RESPONSE_INFO,
        )
        .unwrap();
        let response_plaintext = br#"{"id":"chatcmpl-test","object":"chat.completion","created":1,"model":"test","choices":[]}"#;
        let response_compressed = gzip(response_plaintext).unwrap();
        let response_nonce = [7_u8; CHACHA_NONCE_BYTES];
        let response_encrypted = ChaCha20Poly1305::new_from_slice(&response_key)
            .unwrap()
            .encrypt((&response_nonce).into(), response_compressed.as_ref())
            .unwrap();
        let mut response_blob = response_ct.as_slice().to_vec();
        response_blob.extend_from_slice(&response_nonce);
        response_blob.extend_from_slice(&response_encrypted);

        assert_eq!(
            decrypt_response(&response_blob, &request.response_decapsulation_key).unwrap(),
            response_plaintext
        );
    }
}
