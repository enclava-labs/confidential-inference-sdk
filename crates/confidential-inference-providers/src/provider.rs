use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use confidential_inference_openai::{ChatCompletionRequest, ChatCompletionResponse};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::RouteDefinition;

const FIXTURE_ENCRYPTED_CHAT_SCHEMA: &str = "confidential-inference.fixture-encrypted-chat.v1";
const SDK_ENCRYPTED_CHAT_SCHEMA: &str = "confidential-inference.sdk-encrypted-chat.v1";
const SDK_ENCRYPTED_CHAT_RESPONSE_SCHEMA: &str =
    "confidential-inference.sdk-encrypted-chat-response.v1";
pub const SDK_APP_E2EE_ALG: &str = "x25519-hkdf-sha256-chacha20poly1305";

pub type Result<T> = std::result::Result<T, ProviderError>;

pub enum ProviderError {
    Unavailable(String),
    Adapter(String),
    Compatibility(String),
    KeyRotation {
        route_id: String,
        message: String,
    },
    /// A transport-level HTTP failure, such as a connection error or timeout.
    Http(String),
    /// A completed HTTP exchange whose status did not indicate success.
    HttpStatus {
        status: u16,
        message: String,
    },
    Json(serde_json::Error),
}

impl ProviderError {
    pub fn key_rotation(route_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::KeyRotation {
            route_id: route_id.into(),
            message: message.into(),
        }
    }

    pub fn is_key_rotation(&self) -> bool {
        matches!(self, ProviderError::KeyRotation { .. })
    }

    /// Returns true when retrying the request against another policy-compatible
    /// provider is appropriate. Authentication, compatibility, parsing, and
    /// cryptographic adapter failures deliberately remain fail-closed.
    pub fn is_retryable_outage(&self) -> bool {
        match self {
            ProviderError::Unavailable(_) | ProviderError::Http(_) => true,
            ProviderError::HttpStatus { status, .. } => {
                matches!(*status, 408 | 425 | 429 | 500 | 502 | 503 | 504)
            }
            ProviderError::Adapter(_)
            | ProviderError::Compatibility(_)
            | ProviderError::KeyRotation { .. }
            | ProviderError::Json(_) => false,
        }
    }
}

impl Display for ProviderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ProviderError::Unavailable(provider) => {
                write!(
                    formatter,
                    "provider {} is unavailable",
                    redact_sensitive(provider)
                )
            }
            ProviderError::Adapter(message) => {
                write!(
                    formatter,
                    "provider adapter failed: {}",
                    redact_sensitive(message)
                )
            }
            ProviderError::Compatibility(message) => {
                write!(
                    formatter,
                    "provider compatibility failed: {}",
                    redact_sensitive(message)
                )
            }
            ProviderError::KeyRotation { route_id, message } => {
                write!(
                    formatter,
                    "provider key rotation observed for route {}: {}",
                    redact_sensitive(route_id),
                    redact_sensitive(message)
                )
            }
            ProviderError::Http(message) => {
                write!(
                    formatter,
                    "provider HTTP request failed: {}",
                    redact_sensitive(message)
                )
            }
            ProviderError::HttpStatus { status, message } => {
                write!(
                    formatter,
                    "provider HTTP request returned status {status}: {}",
                    redact_sensitive(message)
                )
            }
            ProviderError::Json(error) => write!(formatter, "json failed: {error}"),
        }
    }
}

impl Debug for ProviderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, formatter)
    }
}

impl Error for ProviderError {}

impl From<serde_json::Error> for ProviderError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRequest {
    pub requested_model: String,
    pub policy_digest: String,
    pub nonce: Option<String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderChatRequest {
    pub body: Value,
    #[serde(default)]
    pub confidentiality: ProviderRequestConfidentiality,
    #[serde(skip)]
    sdk_app_e2ee_context: Option<SdkAppE2eeClientContext>,
}

impl Debug for ProviderChatRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderChatRequest")
            .field("body", &self.body)
            .field("confidentiality", &self.confidentiality)
            .field(
                "sdk_app_e2ee_context",
                &self
                    .sdk_app_e2ee_context
                    .as_ref()
                    .map(|context| RedactedSdkAppE2eeContext {
                        request_id: &context.request_id,
                    }),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SdkAppE2eeClientContext {
    request_id: String,
    response_key: [u8; 32],
}

struct RedactedSdkAppE2eeContext<'a> {
    request_id: &'a str,
}

impl Debug for RedactedSdkAppE2eeContext<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdkAppE2eeClientContext")
            .field("request_id", &self.request_id)
            .field("response_key", &"[REDACTED]")
            .finish()
    }
}

impl ProviderChatRequest {
    pub fn new(body: Value) -> Self {
        Self {
            body,
            confidentiality: ProviderRequestConfidentiality::Plaintext,
            sdk_app_e2ee_context: None,
        }
    }

    pub fn with_confidentiality(
        body: Value,
        confidentiality: ProviderRequestConfidentiality,
    ) -> Self {
        Self {
            body,
            confidentiality,
            sdk_app_e2ee_context: None,
        }
    }

    pub fn adapter_managed_encrypt(body: Value) -> Self {
        Self::with_confidentiality(
            body,
            ProviderRequestConfidentiality::AdapterManagedEncrypted,
        )
    }

    pub fn fixture_encrypt(route: &RouteDefinition, body: Value) -> Result<Self> {
        let plaintext = serde_json::to_vec(&body)?;
        let ciphertext = fixture_xor(route, &plaintext);
        let envelope = FixtureEncryptedChatEnvelope {
            schema: FIXTURE_ENCRYPTED_CHAT_SCHEMA.into(),
            route_id: route.route_id.clone(),
            provider: route.provider.clone(),
            provider_model: route.provider_model.clone(),
            plaintext_sha256: sha256_hex(&plaintext),
            ciphertext_base64: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        };

        Ok(Self::with_confidentiality(
            serde_json::to_value(envelope)?,
            ProviderRequestConfidentiality::FixtureEncrypted,
        ))
    }

    pub fn sdk_encrypt(
        route: &RouteDefinition,
        body: Value,
        config: &SdkAppE2eeConfig,
    ) -> Result<Self> {
        let recipient_public_key = config.recipient_public_key()?;
        let ephemeral_secret = EphemeralSecret::random();
        let ephemeral_public_key = PublicKey::from(&ephemeral_secret);
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public_key);
        let request_id = random_request_id();
        let (request_key, response_key) =
            derive_sdk_app_e2ee_keys(shared_secret.as_bytes(), route, &request_id, &config.key_id)?;
        let aad = sdk_app_e2ee_aad(route, &request_id, &config.key_id)?;
        let nonce = random_nonce();
        let plaintext = serde_json::to_vec(&body)?;
        let ciphertext = seal(&request_key, &nonce, &aad, &plaintext)?;
        let envelope = SdkEncryptedChatEnvelope {
            schema: SDK_ENCRYPTED_CHAT_SCHEMA.into(),
            route_id: route.route_id.clone(),
            provider: route.provider.clone(),
            provider_model: route.provider_model.clone(),
            request_id: request_id.clone(),
            key_id: config.key_id.clone(),
            alg: SDK_APP_E2EE_ALG.into(),
            ephemeral_public_key_base64: STANDARD.encode(ephemeral_public_key.as_bytes()),
            nonce_base64: STANDARD.encode(nonce),
            aad_sha256: sha256_hex(&aad),
            ciphertext_base64: STANDARD.encode(ciphertext),
        };

        Ok(Self {
            body: serde_json::to_value(envelope)?,
            confidentiality: ProviderRequestConfidentiality::SdkEncrypted,
            sdk_app_e2ee_context: Some(SdkAppE2eeClientContext {
                request_id,
                response_key,
            }),
        })
    }

    pub fn body(&self) -> &Value {
        &self.body
    }

    pub fn confidentiality(&self) -> &ProviderRequestConfidentiality {
        &self.confidentiality
    }

    pub fn into_body(self) -> Value {
        self.body
    }

    pub fn to_openai_request(&self) -> Result<ChatCompletionRequest> {
        if self.confidentiality != ProviderRequestConfidentiality::Plaintext {
            return Err(ProviderError::Adapter(format!(
                "{:?} request metadata must be decrypted before OpenAI request parsing",
                self.confidentiality
            )));
        }
        Ok(serde_json::from_value(self.body.clone())?)
    }

    pub fn fixture_decrypted_body(&self, route: &RouteDefinition) -> Result<Value> {
        if self.confidentiality != ProviderRequestConfidentiality::FixtureEncrypted {
            return Err(ProviderError::Adapter(
                "request is not fixture-encrypted".into(),
            ));
        }

        let envelope: FixtureEncryptedChatEnvelope = serde_json::from_value(self.body.clone())?;
        envelope.validate_route(route)?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&envelope.ciphertext_base64)
            .map_err(|error| {
                ProviderError::Adapter(format!("fixture ciphertext is not base64: {error}"))
            })?;
        let plaintext = fixture_xor(route, &ciphertext);
        let plaintext_sha256 = sha256_hex(&plaintext);
        if plaintext_sha256 != envelope.plaintext_sha256 {
            return Err(ProviderError::Adapter(
                "fixture ciphertext digest did not match envelope".into(),
            ));
        }

        Ok(serde_json::from_slice(&plaintext)?)
    }

    pub fn to_fixture_decrypted_openai_request(
        &self,
        route: &RouteDefinition,
    ) -> Result<ChatCompletionRequest> {
        Ok(serde_json::from_value(self.fixture_decrypted_body(route)?)?)
    }

    pub fn sdk_decrypted_body(
        &self,
        route: &RouteDefinition,
        secret_key: &SdkAppE2eeSecretKey,
    ) -> Result<(Value, SdkAppE2eeSession)> {
        if self.confidentiality != ProviderRequestConfidentiality::SdkEncrypted {
            return Err(ProviderError::Adapter(
                "request is not SDK-encrypted".into(),
            ));
        }

        let envelope: SdkEncryptedChatEnvelope = serde_json::from_value(self.body.clone())?;
        envelope.decrypt_body(route, secret_key)
    }

    pub fn to_sdk_decrypted_openai_request(
        &self,
        route: &RouteDefinition,
        secret_key: &SdkAppE2eeSecretKey,
    ) -> Result<(ChatCompletionRequest, SdkAppE2eeSession)> {
        let (body, session) = self.sdk_decrypted_body(route, secret_key)?;
        Ok((serde_json::from_value(body)?, session))
    }

    pub fn decrypt_sdk_response_body(
        &self,
        route: &RouteDefinition,
        response_body: &[u8],
    ) -> Result<Vec<u8>> {
        if self.confidentiality != ProviderRequestConfidentiality::SdkEncrypted {
            return Ok(response_body.to_vec());
        }
        let context = self.sdk_app_e2ee_context.as_ref().ok_or_else(|| {
            ProviderError::Adapter("SDK-encrypted request is missing response context".into())
        })?;
        let envelope: SdkEncryptedChatResponseEnvelope = serde_json::from_slice(response_body)?;
        envelope.decrypt_body(route, context)
    }

    pub fn model(&self) -> Option<&str> {
        self.body
            .get("model")
            .or_else(|| self.body.get("provider_model"))
            .and_then(Value::as_str)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRequestConfidentiality {
    #[default]
    Plaintext,
    FixtureEncrypted,
    SdkEncrypted,
    AdapterManagedEncrypted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FixtureEncryptedChatEnvelope {
    schema: String,
    route_id: String,
    provider: String,
    provider_model: String,
    plaintext_sha256: String,
    ciphertext_base64: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkAppE2eeConfig {
    pub key_id: String,
    pub public_key_base64: String,
}

impl SdkAppE2eeConfig {
    pub fn new(key_id: impl Into<String>, public_key_base64: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            public_key_base64: public_key_base64.into(),
        }
    }

    pub fn public_key_digest(&self) -> Result<String> {
        Ok(format!("sha256:{}", sha256_hex(&self.public_key_bytes()?)))
    }

    fn recipient_public_key(&self) -> Result<PublicKey> {
        Ok(PublicKey::from(self.public_key_bytes()?))
    }

    fn public_key_bytes(&self) -> Result<[u8; 32]> {
        decode_fixed_base64("SDK app-E2EE public key", &self.public_key_base64)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkAppE2eeSecretKey {
    pub key_id: String,
    pub private_key_base64: String,
}

impl Debug for SdkAppE2eeSecretKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdkAppE2eeSecretKey")
            .field("key_id", &self.key_id)
            .field("private_key_base64", &"[REDACTED]")
            .finish()
    }
}

impl SdkAppE2eeSecretKey {
    pub fn from_private_key_bytes(key_id: impl Into<String>, private_key: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            private_key_base64: STANDARD.encode(private_key),
        }
    }

    pub fn public_config(&self) -> Result<SdkAppE2eeConfig> {
        let secret = self.static_secret()?;
        let public_key = PublicKey::from(&secret);
        Ok(SdkAppE2eeConfig::new(
            self.key_id.clone(),
            STANDARD.encode(public_key.as_bytes()),
        ))
    }

    fn static_secret(&self) -> Result<StaticSecret> {
        Ok(StaticSecret::from(decode_fixed_base64(
            "SDK app-E2EE private key",
            &self.private_key_base64,
        )?))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SdkAppE2eeSession {
    request_id: String,
    response_key: [u8; 32],
}

impl Debug for SdkAppE2eeSession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdkAppE2eeSession")
            .field("request_id", &self.request_id)
            .field("response_key", &"[REDACTED]")
            .finish()
    }
}

impl SdkAppE2eeSession {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn encrypt_response_body(
        &self,
        route: &RouteDefinition,
        plaintext: &[u8],
    ) -> Result<SdkEncryptedChatResponseEnvelope> {
        let aad = sdk_app_e2ee_response_aad(route, &self.request_id)?;
        let nonce = random_nonce();
        let ciphertext = seal(&self.response_key, &nonce, &aad, plaintext)?;
        Ok(SdkEncryptedChatResponseEnvelope {
            schema: SDK_ENCRYPTED_CHAT_RESPONSE_SCHEMA.into(),
            route_id: route.route_id.clone(),
            provider: route.provider.clone(),
            provider_model: route.provider_model.clone(),
            request_id: self.request_id.clone(),
            alg: SDK_APP_E2EE_ALG.into(),
            nonce_base64: STANDARD.encode(nonce),
            aad_sha256: sha256_hex(&aad),
            ciphertext_base64: STANDARD.encode(ciphertext),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkEncryptedChatEnvelope {
    pub schema: String,
    pub route_id: String,
    pub provider: String,
    pub provider_model: String,
    pub request_id: String,
    pub key_id: String,
    pub alg: String,
    pub ephemeral_public_key_base64: String,
    pub nonce_base64: String,
    pub aad_sha256: String,
    pub ciphertext_base64: String,
}

impl SdkEncryptedChatEnvelope {
    pub fn decrypt_body(
        &self,
        route: &RouteDefinition,
        secret_key: &SdkAppE2eeSecretKey,
    ) -> Result<(Value, SdkAppE2eeSession)> {
        self.validate_route(route)?;
        if self.key_id != secret_key.key_id {
            return Err(ProviderError::Adapter(
                "SDK encrypted chat envelope key id does not match secret key".into(),
            ));
        }
        let ephemeral_public_key = PublicKey::from(decode_fixed_base64(
            "SDK app-E2EE ephemeral public key",
            &self.ephemeral_public_key_base64,
        )?);
        let shared_secret = secret_key
            .static_secret()?
            .diffie_hellman(&ephemeral_public_key);
        let (request_key, response_key) = derive_sdk_app_e2ee_keys(
            shared_secret.as_bytes(),
            route,
            &self.request_id,
            &self.key_id,
        )?;
        let aad = sdk_app_e2ee_aad(route, &self.request_id, &self.key_id)?;
        if self.aad_sha256 != sha256_hex(&aad) {
            return Err(ProviderError::Adapter(
                "SDK encrypted chat envelope AAD digest does not match route metadata".into(),
            ));
        }
        let nonce = decode_fixed_base64("SDK app-E2EE request nonce", &self.nonce_base64)?;
        let ciphertext = STANDARD.decode(&self.ciphertext_base64).map_err(|error| {
            ProviderError::Adapter(format!(
                "SDK encrypted chat ciphertext is not base64: {error}"
            ))
        })?;
        let plaintext = open(&request_key, &nonce, &aad, &ciphertext)?;
        let body = serde_json::from_slice(&plaintext)?;

        Ok((
            body,
            SdkAppE2eeSession {
                request_id: self.request_id.clone(),
                response_key,
            },
        ))
    }

    fn validate_route(&self, route: &RouteDefinition) -> Result<()> {
        if self.schema != SDK_ENCRYPTED_CHAT_SCHEMA {
            return Err(ProviderError::Adapter(format!(
                "unsupported SDK encrypted chat envelope schema {}",
                self.schema
            )));
        }
        if self.alg != SDK_APP_E2EE_ALG {
            return Err(ProviderError::Adapter(format!(
                "unsupported SDK app-E2EE algorithm {}",
                self.alg
            )));
        }
        if self.route_id != route.route_id
            || self.provider != route.provider
            || self.provider_model != route.provider_model
        {
            return Err(ProviderError::Adapter(
                "SDK encrypted chat envelope route metadata does not match route".into(),
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkEncryptedChatResponseEnvelope {
    pub schema: String,
    pub route_id: String,
    pub provider: String,
    pub provider_model: String,
    pub request_id: String,
    pub alg: String,
    pub nonce_base64: String,
    pub aad_sha256: String,
    pub ciphertext_base64: String,
}

impl SdkEncryptedChatResponseEnvelope {
    fn decrypt_body(
        &self,
        route: &RouteDefinition,
        context: &SdkAppE2eeClientContext,
    ) -> Result<Vec<u8>> {
        if self.schema != SDK_ENCRYPTED_CHAT_RESPONSE_SCHEMA {
            return Err(ProviderError::Adapter(format!(
                "unsupported SDK encrypted chat response envelope schema {}",
                self.schema
            )));
        }
        if self.alg != SDK_APP_E2EE_ALG {
            return Err(ProviderError::Adapter(format!(
                "unsupported SDK app-E2EE response algorithm {}",
                self.alg
            )));
        }
        if self.route_id != route.route_id
            || self.provider != route.provider
            || self.provider_model != route.provider_model
            || self.request_id != context.request_id
        {
            return Err(ProviderError::Adapter(
                "SDK encrypted chat response route metadata does not match request context".into(),
            ));
        }
        let aad = sdk_app_e2ee_response_aad(route, &self.request_id)?;
        if self.aad_sha256 != sha256_hex(&aad) {
            return Err(ProviderError::Adapter(
                "SDK encrypted chat response AAD digest does not match route metadata".into(),
            ));
        }
        let nonce = decode_fixed_base64("SDK app-E2EE response nonce", &self.nonce_base64)?;
        let ciphertext = STANDARD.decode(&self.ciphertext_base64).map_err(|error| {
            ProviderError::Adapter(format!(
                "SDK encrypted chat response is not base64: {error}"
            ))
        })?;
        open(&context.response_key, &nonce, &aad, &ciphertext)
    }
}

impl FixtureEncryptedChatEnvelope {
    fn validate_route(&self, route: &RouteDefinition) -> Result<()> {
        if self.schema != FIXTURE_ENCRYPTED_CHAT_SCHEMA {
            return Err(ProviderError::Adapter(format!(
                "unsupported fixture chat envelope schema {}",
                self.schema
            )));
        }
        if self.route_id != route.route_id
            || self.provider != route.provider
            || self.provider_model != route.provider_model
        {
            return Err(ProviderError::Adapter(
                "fixture chat envelope route metadata does not match route".into(),
            ));
        }

        Ok(())
    }
}

fn fixture_xor(route: &RouteDefinition, input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut counter = 0_u64;
    while output.len() < input.len() {
        let mut hasher = Sha256::new();
        hasher.update(b"confidential-inference.fixture-chat-encryption.v1");
        hasher.update(route.route_id.as_bytes());
        hasher.update(route.provider.as_bytes());
        hasher.update(route.provider_model.as_bytes());
        hasher.update(counter.to_le_bytes());
        let block = hasher.finalize();
        for byte in block {
            if output.len() == input.len() {
                break;
            }
            output.push(input[output.len()] ^ byte);
        }
        counter = counter.saturating_add(1);
    }
    output
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn random_request_id() -> String {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).expect("OS randomness unavailable");
    STANDARD.encode(bytes)
}

fn random_nonce() -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut nonce).expect("OS randomness unavailable");
    nonce
}

fn decode_fixed_base64<const N: usize>(field: &str, value: &str) -> Result<[u8; N]> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|error| ProviderError::Adapter(format!("{field} is not base64: {error}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        ProviderError::Adapter(format!("{field} must be {N} bytes, got {}", bytes.len()))
    })
}

fn sdk_app_e2ee_aad(route: &RouteDefinition, request_id: &str, key_id: &str) -> Result<Vec<u8>> {
    sdk_app_e2ee_context_json(SDK_ENCRYPTED_CHAT_SCHEMA, route, request_id, Some(key_id))
}

fn sdk_app_e2ee_response_aad(route: &RouteDefinition, request_id: &str) -> Result<Vec<u8>> {
    sdk_app_e2ee_context_json(SDK_ENCRYPTED_CHAT_RESPONSE_SCHEMA, route, request_id, None)
}

fn sdk_app_e2ee_context_json(
    schema: &str,
    route: &RouteDefinition,
    request_id: &str,
    key_id: Option<&str>,
) -> Result<Vec<u8>> {
    let mut context = serde_json::Map::new();
    context.insert("schema".into(), Value::String(schema.into()));
    context.insert("route_id".into(), Value::String(route.route_id.clone()));
    context.insert("provider".into(), Value::String(route.provider.clone()));
    context.insert(
        "provider_model".into(),
        Value::String(route.provider_model.clone()),
    );
    context.insert("request_id".into(), Value::String(request_id.into()));
    context.insert("alg".into(), Value::String(SDK_APP_E2EE_ALG.into()));
    if let Some(key_id) = key_id {
        context.insert("key_id".into(), Value::String(key_id.into()));
    }
    serde_json::to_vec(&Value::Object(context)).map_err(Into::into)
}

fn derive_sdk_app_e2ee_keys(
    shared_secret: &[u8],
    route: &RouteDefinition,
    request_id: &str,
    key_id: &str,
) -> Result<([u8; 32], [u8; 32])> {
    let mut salt = Sha256::new();
    salt.update(b"confidential-inference.sdk-app-e2ee.v1");
    salt.update(route.route_id.as_bytes());
    salt.update(route.provider.as_bytes());
    salt.update(route.provider_model.as_bytes());
    salt.update(request_id.as_bytes());
    salt.update(key_id.as_bytes());
    let salt = salt.finalize();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut request_key = [0_u8; 32];
    let mut response_key = [0_u8; 32];
    hkdf.expand(b"request-body", &mut request_key)
        .map_err(|_| ProviderError::Adapter("failed to derive SDK app-E2EE request key".into()))?;
    hkdf.expand(b"response-body", &mut response_key)
        .map_err(|_| ProviderError::Adapter("failed to derive SDK app-E2EE response key".into()))?;
    Ok((request_key, response_key))
}

fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ProviderError::Adapter("SDK app-E2EE encryption failed".into()))
}

fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ProviderError::Adapter("SDK app-E2EE ciphertext authentication failed".into()))
}

#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn provider_id(&self) -> &str;

    fn routes(&self) -> Vec<RouteDefinition>;

    async fn fetch_evidence(
        &self,
        route: &RouteDefinition,
        request: &EvidenceRequest,
    ) -> Result<Vec<u8>>;

    async fn chat(
        &self,
        route: &RouteDefinition,
        request: ProviderChatRequest,
    ) -> Result<ChatCompletionResponse>;
}

fn redact_sensitive(message: &str) -> String {
    let message = redact_json_string_values(message);
    let mut redacted = Vec::new();
    let mut redact_next = false;

    for token in message.split_whitespace() {
        let normalized = token
            .trim_matches(|character: char| {
                matches!(
                    character,
                    '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
                )
            })
            .to_ascii_lowercase();

        if redact_next {
            if normalized == "bearer" {
                redacted.push(token.to_owned());
            } else {
                redacted.push(redacted_token(token));
                redact_next = false;
            }
            continue;
        }

        if normalized == "bearer" || sensitive_label_without_value(&normalized) {
            redacted.push(token.to_owned());
            redact_next = true;
        } else if sensitive_assignment(&normalized).is_some() {
            redacted.push(redact_assignment_token(token));
        } else if normalized.starts_with("sk-") {
            redacted.push(redacted_token(token));
        } else {
            redacted.push(token.to_owned());
        }
    }

    redacted.join(" ")
}

fn redact_json_string_values(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut redacted = String::with_capacity(message.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'"' {
            if let Some((value_start, value_end)) = sensitive_json_string_value_range(bytes, index)
            {
                redacted.push_str(&message[index..value_start]);
                redacted.push_str("[REDACTED]");
                redacted.push('"');
                index = value_end + 1;
                continue;
            }
        }

        let character = message[index..]
            .chars()
            .next()
            .expect("index is within string bounds");
        redacted.push(character);
        index += character.len_utf8();
    }

    redacted
}

fn sensitive_json_string_value_range(bytes: &[u8], key_start: usize) -> Option<(usize, usize)> {
    let key_end = closing_json_quote(bytes, key_start + 1)?;
    let key = std::str::from_utf8(&bytes[key_start + 1..key_end]).ok()?;
    let normalized_key = key.to_ascii_lowercase();
    if !sensitive_json_key(&normalized_key) {
        return None;
    }

    let mut cursor = key_end + 1;
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b':') {
        return None;
    }
    cursor += 1;
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }

    let value_start = cursor + 1;
    let value_end = closing_json_quote(bytes, value_start)?;
    Some((value_start, value_end))
}

fn closing_json_quote(bytes: &[u8], mut cursor: usize) -> Option<usize> {
    let mut escaped = false;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn sensitive_label_without_value(token: &str) -> bool {
    matches!(
        token.trim_end_matches(':'),
        "authorization"
            | "api-key"
            | "api_key"
            | "apikey"
            | "x-api-key"
            | "token"
            | "access_token"
            | "password"
            | "secret"
            | "prompt"
            | "completion"
    )
}

fn sensitive_json_key(token: &str) -> bool {
    sensitive_label_without_value(token)
        || matches!(token, "bearer" | "content" | "input" | "output")
}

fn sensitive_assignment(token: &str) -> Option<usize> {
    let separator = token.find(['=', ':'])?;
    let label = &token[..separator];
    if sensitive_json_key(label) {
        Some(separator)
    } else {
        None
    }
}

fn redact_assignment_token(token: &str) -> String {
    let Some(separator) = token.find(['=', ':']) else {
        return redacted_token(token);
    };
    let (prefix, value) = token.split_at(separator + 1);
    format!("{prefix}{}", redacted_token(value))
}

fn redacted_token(token: &str) -> String {
    let trailing = token
        .chars()
        .rev()
        .take_while(|character| matches!(character, ',' | ';' | '.' | ')' | ']' | '}' | '"' | '\''))
        .collect::<Vec<_>>();
    let mut redacted = "[REDACTED]".to_owned();
    for character in trailing.into_iter().rev() {
        redacted.push(character);
    }
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_error_display_and_debug_redact_sensitive_values() {
        let error = ProviderError::Adapter(
            "Authorization: Bearer opaque-live-token api_key=demo-key prompt=plain completion=answer content=payload input=hidden output=result password=secret"
                .into(),
        );
        let display = error.to_string();
        let debug = format!("{error:?}");

        for rendered in [display, debug] {
            assert!(!rendered.contains("opaque-live-token"));
            assert!(!rendered.contains("demo-key"));
            assert!(!rendered.contains("plain"));
            assert!(!rendered.contains("answer"));
            assert!(!rendered.contains("payload"));
            assert!(!rendered.contains("hidden"));
            assert!(!rendered.contains("result"));
            assert!(!rendered.contains("secret"));
            assert!(rendered.contains("[REDACTED]"));
        }
    }

    #[test]
    fn provider_error_redacts_compact_json_error_bodies() {
        let error = ProviderError::Http(
            r#"{"error":{"authorization":"Bearer opaque-json-token","api_key":"json-key","prompt":"private","completion":"hidden","content":"payload","input":"secret-input","output":"secret-output","password":"secret-pass"}}"#
                .into(),
        );
        let rendered = error.to_string();

        for leaked in [
            "opaque-json-token",
            "json-key",
            "private",
            "hidden",
            "payload",
            "secret-input",
            "secret-output",
            "secret-pass",
        ] {
            assert!(!rendered.contains(leaked), "{leaked} leaked");
        }
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn retryable_outage_classification_is_conservative() {
        assert!(ProviderError::Unavailable("primary".into()).is_retryable_outage());
        assert!(ProviderError::Http("connection refused".into()).is_retryable_outage());
        for status in [408, 425, 429, 500, 502, 503, 504] {
            assert!(ProviderError::HttpStatus {
                status,
                message: "temporary failure".into(),
            }
            .is_retryable_outage());
        }

        for status in [400, 401, 403, 404, 409, 422, 501, 505] {
            assert!(!ProviderError::HttpStatus {
                status,
                message: "non-retryable failure".into(),
            }
            .is_retryable_outage());
        }
        assert!(!ProviderError::Adapter("invalid encrypted response".into()).is_retryable_outage());
        assert!(!ProviderError::Compatibility("route mismatch".into()).is_retryable_outage());
        assert!(!ProviderError::key_rotation("route", "rotated").is_retryable_outage());
    }

    #[test]
    fn fixture_encrypted_chat_request_round_trips_and_hides_plaintext() {
        let route = fixture_route();
        let body = serde_json::json!({
            "model": "e2ee-gpt-oss-120b-p",
            "messages": [{"role": "user", "content": "plaintext prompt"}]
        });

        let request = ProviderChatRequest::fixture_encrypt(&route, body.clone()).unwrap();

        assert_eq!(
            request.confidentiality(),
            &ProviderRequestConfidentiality::FixtureEncrypted
        );
        assert!(!request.body().to_string().contains("plaintext prompt"));
        assert_eq!(request.fixture_decrypted_body(&route).unwrap(), body);
    }

    #[test]
    fn sdk_encrypted_chat_request_and_response_round_trip_without_plaintext() {
        let route = fixture_route();
        let secret_key = SdkAppE2eeSecretKey::from_private_key_bytes("test-e2ee-key", [7_u8; 32]);
        let config = secret_key.public_config().unwrap();
        let body = serde_json::json!({
            "model": "e2ee-gpt-oss-120b-p",
            "messages": [{"role": "user", "content": "plaintext prompt"}]
        });

        let request = ProviderChatRequest::sdk_encrypt(&route, body.clone(), &config).unwrap();

        assert_eq!(
            request.confidentiality(),
            &ProviderRequestConfidentiality::SdkEncrypted
        );
        assert_eq!(request.model(), Some("e2ee-gpt-oss-120b-p"));
        assert!(!request.body().to_string().contains("plaintext prompt"));
        assert!(!format!("{request:?}").contains(&secret_key.private_key_base64));

        let (decrypted_body, session) = request.sdk_decrypted_body(&route, &secret_key).unwrap();
        assert_eq!(decrypted_body, body);
        let response_plaintext = br#"{"id":"chatcmpl-test","object":"chat.completion"}"#;
        let response = session
            .encrypt_response_body(&route, response_plaintext)
            .unwrap();
        let response_json = serde_json::to_vec(&response).unwrap();

        assert!(!String::from_utf8_lossy(&response_json).contains("chatcmpl-test"));
        assert_eq!(
            request
                .decrypt_sdk_response_body(&route, &response_json)
                .unwrap(),
            response_plaintext
        );
    }

    #[test]
    fn sdk_encrypted_chat_request_rejects_wrong_key_and_tampered_response() {
        let route = fixture_route();
        let secret_key = SdkAppE2eeSecretKey::from_private_key_bytes("test-e2ee-key", [7_u8; 32]);
        let config = secret_key.public_config().unwrap();
        let request = ProviderChatRequest::sdk_encrypt(
            &route,
            serde_json::json!({"model": "e2ee-gpt-oss-120b-p"}),
            &config,
        )
        .unwrap();
        let wrong_key = SdkAppE2eeSecretKey::from_private_key_bytes("test-e2ee-key", [8_u8; 32]);

        assert!(request.sdk_decrypted_body(&route, &wrong_key).is_err());

        let (_, session) = request.sdk_decrypted_body(&route, &secret_key).unwrap();
        let mut response = session
            .encrypt_response_body(&route, br#"{"ok":true}"#)
            .unwrap();
        response.ciphertext_base64.push('A');
        let response_json = serde_json::to_vec(&response).unwrap();

        assert!(request
            .decrypt_sdk_response_body(&route, &response_json)
            .is_err());
    }

    fn fixture_route() -> RouteDefinition {
        RouteDefinition {
            route_id: "fixture:gpt-oss-120b:e2ee-gpt-oss-120b-p".into(),
            route_status: crate::RouteLifecycle::Active,
            provider: "fixture".into(),
            provider_model: "e2ee-gpt-oss-120b-p".into(),
            evidence_family: "fixture_dstack".into(),
            api_base_url: "http://127.0.0.1/fixture/v1".into(),
            evidence_endpoint: "http://127.0.0.1/fixture/evidence".into(),
            adapter_version: "fixture/0.1.0".into(),
            freshness_class: confidential_inference_attestation::FreshnessClass::PerSession,
            channel_binding_kind:
                confidential_inference_attestation::ChannelBindingKind::AttestedAppE2ee,
            trust_tier: confidential_inference_attestation::TrustTier::AppE2ee,
            request_confidentiality_requirement:
                confidential_inference_attestation::BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement:
                confidential_inference_attestation::BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement:
                confidential_inference_attestation::ResponseIntegrityRequirement::AnyBound,
            accepted_gpu_tees: Vec::new(),
            request_encryption: crate::EncryptionRequirement::Required,
            response_decryption: crate::EncryptionRequirement::Required,
            streaming: crate::StreamingSupport::Unsupported,
            alias_confidence: confidential_inference_attestation::AliasConfidence::Curated,
        }
    }
}
