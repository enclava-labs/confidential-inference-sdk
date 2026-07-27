use async_trait::async_trait;
use base64::Engine;
use confidential_inference_attestation::{
    certificate_spki_sha256_hex, chutes_provider_nonce, TinfoilLiveCaptureEvidence,
};
use confidential_inference_openai::ChatCompletionResponse;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::{
    chutes::normalize_chutes_e2ee_evidence_bytes, dstack::normalize_dstack_evidence_bytes,
    EvidenceRequest, ProviderAdapter, ProviderChatRequest, ProviderError,
    ProviderRequestConfidentiality, Result, RouteDefinition,
};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct ProviderApiKey(Zeroizing<String>);

impl ProviderApiKey {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ProviderApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl From<String> for ProviderApiKey {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Debug)]
pub struct OpenAiHttpProvider {
    provider_id: String,
    routes: Vec<RouteDefinition>,
    api_key: Option<ProviderApiKey>,
    client: reqwest::Client,
}

impl OpenAiHttpProvider {
    pub fn new(provider_id: impl Into<String>, routes: Vec<RouteDefinition>) -> Result<Self> {
        Self::with_api_key(provider_id, routes, None::<String>)
    }

    pub fn with_api_key(
        provider_id: impl Into<String>,
        routes: Vec<RouteDefinition>,
        api_key: Option<impl Into<String>>,
    ) -> Result<Self> {
        install_default_rustls_provider();
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_HTTP_TIMEOUT)
            .build()
            .map_err(|error| ProviderError::Http(error.to_string()))?;

        Ok(Self::with_client(
            provider_id,
            routes,
            api_key.map(Into::into),
            client,
        ))
    }

    pub fn with_client(
        provider_id: impl Into<String>,
        routes: Vec<RouteDefinition>,
        api_key: Option<String>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            routes,
            api_key: api_key.map(ProviderApiKey::from),
            client,
        }
    }

    pub fn api_key_configured(&self) -> bool {
        self.api_key.is_some()
    }

    async fn fetch_evidence_bytes(&self, route: &RouteDefinition) -> Result<Vec<u8>> {
        self.fetch_evidence_bytes_with_query(route, &[]).await
    }

    async fn fetch_evidence_bytes_with_query(
        &self,
        route: &RouteDefinition,
        query: &[(&str, &str)],
    ) -> Result<Vec<u8>> {
        ensure_route_provider(route, &self.provider_id)?;
        let mut request = self.client.get(&route.evidence_endpoint);
        if !query.is_empty() {
            request = request.query(query);
        }
        let request = self.authorize(request);
        let response = request
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        checked_response_bytes(response, "evidence").await
    }

    async fn post_chat(
        &self,
        route: &RouteDefinition,
        request: &ProviderChatRequest,
    ) -> Result<HttpResponseCapture> {
        ensure_route_provider(route, &self.provider_id)?;
        if request.confidentiality() == &ProviderRequestConfidentiality::FixtureEncrypted {
            return Err(ProviderError::Adapter(
                "fixture-encrypted requests cannot be sent through live HTTP providers".into(),
            ));
        }
        let url = chat_completions_url(&route.api_base_url)?;
        let response = self
            .authorize(self.client.post(url).json(request.body()))
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        capture_response(response, "chat completions").await
    }

    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(api_key) => request.bearer_auth(api_key.as_str()),
            None => request,
        }
    }
}

#[async_trait]
impl ProviderAdapter for OpenAiHttpProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn routes(&self) -> Vec<RouteDefinition> {
        self.routes.clone()
    }

    async fn fetch_evidence(
        &self,
        route: &RouteDefinition,
        _request: &EvidenceRequest,
    ) -> Result<Vec<u8>> {
        self.fetch_evidence_bytes(route).await
    }

    async fn chat(
        &self,
        route: &RouteDefinition,
        request: ProviderChatRequest,
    ) -> Result<ChatCompletionResponse> {
        let capture = self.post_chat(route, &request).await?;
        let body = request.decrypt_sdk_response_body(route, &capture.body)?;
        serde_json::from_slice(&body).map_err(Into::into)
    }
}

#[derive(Clone, Debug)]
pub struct ConfidentialHttpProvider {
    inner: OpenAiHttpProvider,
}

impl ConfidentialHttpProvider {
    pub fn new(provider_id: impl Into<String>, routes: Vec<RouteDefinition>) -> Result<Self> {
        Self::with_api_key(provider_id, routes, None::<String>)
    }

    pub fn with_api_key(
        provider_id: impl Into<String>,
        routes: Vec<RouteDefinition>,
        api_key: Option<impl Into<String>>,
    ) -> Result<Self> {
        Ok(Self {
            inner: OpenAiHttpProvider::with_api_key(provider_id, routes, api_key)?,
        })
    }

    pub fn with_client(
        provider_id: impl Into<String>,
        routes: Vec<RouteDefinition>,
        api_key: Option<String>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            inner: OpenAiHttpProvider::with_client(provider_id, routes, api_key, client),
        }
    }
}

#[async_trait]
impl ProviderAdapter for ConfidentialHttpProvider {
    fn provider_id(&self) -> &str {
        self.inner.provider_id()
    }

    fn routes(&self) -> Vec<RouteDefinition> {
        self.inner.routes()
    }

    async fn fetch_evidence(
        &self,
        route: &RouteDefinition,
        request: &EvidenceRequest,
    ) -> Result<Vec<u8>> {
        let body = match route.evidence_family.as_str() {
            "chutes_e2ee" => {
                if let Some(request_nonce) = request.nonce.as_deref() {
                    let nonce = chutes_provider_nonce(request_nonce);
                    self.inner
                        .fetch_evidence_bytes_with_query(route, &[("nonce", nonce.as_str())])
                        .await?
                } else {
                    self.inner.fetch_evidence_bytes(route).await?
                }
            }
            _ => self.inner.fetch_evidence_bytes(route).await?,
        };
        match route.evidence_family.as_str() {
            "dstack_app_e2ee" => normalize_dstack_evidence_bytes(route, request, &body),
            "chutes_e2ee" => normalize_chutes_e2ee_evidence_bytes(route, request, &body),
            _ => Ok(body),
        }
    }

    async fn chat(
        &self,
        route: &RouteDefinition,
        request: ProviderChatRequest,
    ) -> Result<ChatCompletionResponse> {
        self.inner.chat(route, request).await
    }
}

pub type DstackHttpProvider = ConfidentialHttpProvider;
pub type PhalaHttpProvider = ConfidentialHttpProvider;

#[derive(Clone, Debug)]
pub struct TinfoilHttpProvider {
    inner: OpenAiHttpProvider,
    tls_state: Arc<Mutex<BTreeMap<String, LiveTlsPeer>>>,
}

impl TinfoilHttpProvider {
    pub fn new(routes: Vec<RouteDefinition>, api_key: Option<impl Into<String>>) -> Result<Self> {
        Self::with_provider_id("tinfoil", routes, api_key)
    }

    pub fn with_provider_id(
        provider_id: impl Into<String>,
        routes: Vec<RouteDefinition>,
        api_key: Option<impl Into<String>>,
    ) -> Result<Self> {
        install_default_rustls_provider();
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_HTTP_TIMEOUT)
            .tls_info(true)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|error| ProviderError::Http(error.to_string()))?;

        Ok(Self {
            inner: OpenAiHttpProvider::with_client(
                provider_id,
                routes,
                api_key.map(Into::into),
                client,
            ),
            tls_state: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    pub fn with_client(
        provider_id: impl Into<String>,
        routes: Vec<RouteDefinition>,
        api_key: Option<String>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            inner: OpenAiHttpProvider::with_client(provider_id, routes, api_key, client),
            tls_state: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl ProviderAdapter for TinfoilHttpProvider {
    fn provider_id(&self) -> &str {
        self.inner.provider_id()
    }

    fn routes(&self) -> Vec<RouteDefinition> {
        self.inner.routes()
    }

    async fn fetch_evidence(
        &self,
        route: &RouteDefinition,
        request: &EvidenceRequest,
    ) -> Result<Vec<u8>> {
        ensure_tinfoil_route(route, self.provider_id())?;
        let response = self
            .inner
            .authorize(self.inner.client.get(&route.evidence_endpoint))
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        let tls_peer = require_tls_peer(&response, "Tinfoil evidence")?;
        let body = checked_response_bytes(response, "Tinfoil evidence").await?;

        self.tls_state
            .lock()
            .map_err(|_| ProviderError::Adapter("Tinfoil TLS state lock is poisoned".into()))?
            .insert(route.route_id.clone(), tls_peer.clone());

        let capture = TinfoilLiveCaptureEvidence {
            schema: TinfoilLiveCaptureEvidence::SCHEMA.into(),
            provider: route.provider.clone(),
            route_id: route.route_id.clone(),
            evidence_family: route.evidence_family.clone(),
            requested_model: request.requested_model.clone(),
            policy_digest: request.policy_digest.clone(),
            nonce: request.nonce.clone(),
            evidence_endpoint: route.evidence_endpoint.clone(),
            live_tls_spki_sha256: tls_peer.spki_sha256,
            live_tls_leaf_certificate_der_base64: base64::engine::general_purpose::STANDARD
                .encode(&tls_peer.leaf_certificate_der),
            raw_attestation_body_base64: base64::engine::general_purpose::STANDARD.encode(body),
        };

        serde_json::to_vec(&capture).map_err(Into::into)
    }

    async fn chat(
        &self,
        route: &RouteDefinition,
        request: ProviderChatRequest,
    ) -> Result<ChatCompletionResponse> {
        ensure_tinfoil_route(route, self.provider_id())?;
        let expected_tls = self
            .tls_state
            .lock()
            .map_err(|_| ProviderError::Adapter("Tinfoil TLS state lock is poisoned".into()))?
            .get(&route.route_id)
            .cloned()
            .ok_or_else(|| {
                ProviderError::Compatibility(format!(
                    "route {} has no captured Tinfoil TLS identity; verify evidence before chat",
                    route.route_id
                ))
            })?;

        let capture = self.inner.post_chat(route, &request).await?;
        let observed_tls = capture.tls_peer.ok_or_else(|| {
            ProviderError::Compatibility(format!(
                "route {} chat response did not expose a live TLS certificate",
                route.route_id
            ))
        })?;
        if observed_tls.spki_sha256 != expected_tls.spki_sha256 {
            return Err(ProviderError::key_rotation(
                route.route_id.clone(),
                "live TLS SPKI changed between evidence and chat",
            ));
        }

        let body = request.decrypt_sdk_response_body(route, &capture.body)?;
        serde_json::from_slice(&body).map_err(Into::into)
    }
}

#[derive(Clone, Debug)]
struct HttpResponseCapture {
    body: Vec<u8>,
    tls_peer: Option<LiveTlsPeer>,
}

#[derive(Clone, Debug)]
struct LiveTlsPeer {
    spki_sha256: String,
    leaf_certificate_der: Vec<u8>,
}

fn ensure_route_provider(route: &RouteDefinition, provider: &str) -> Result<()> {
    if route.provider == provider {
        Ok(())
    } else {
        Err(ProviderError::Adapter(format!(
            "route {} belongs to provider {}, not {}",
            route.route_id, route.provider, provider
        )))
    }
}

fn ensure_tinfoil_route(route: &RouteDefinition, provider: &str) -> Result<()> {
    ensure_route_provider(route, provider)?;
    if route.evidence_family != "tinfoil_hw_verified_tls" {
        return Err(ProviderError::Compatibility(format!(
            "route {} uses evidence family {}, not tinfoil_hw_verified_tls",
            route.route_id, route.evidence_family
        )));
    }
    require_https_url(&route.api_base_url, "api_base_url", &route.route_id)?;
    require_https_url(
        &route.evidence_endpoint,
        "evidence_endpoint",
        &route.route_id,
    )?;
    Ok(())
}

fn require_https_url(url: &str, field: &str, route_id: &str) -> Result<()> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(ProviderError::Compatibility(format!(
            "route {route_id} {field} must use https for live Tinfoil"
        )))
    }
}

fn chat_completions_url(api_base_url: &str) -> Result<String> {
    if api_base_url.trim().is_empty() {
        return Err(ProviderError::Compatibility(
            "route api_base_url is empty".into(),
        ));
    }
    Ok(format!(
        "{}/chat/completions",
        api_base_url.trim_end_matches('/')
    ))
}

async fn capture_response(
    response: reqwest::Response,
    operation: &str,
) -> Result<HttpResponseCapture> {
    let tls_peer = response_tls_peer(&response)?;
    let body = checked_response_bytes(response, operation).await?;
    Ok(HttpResponseCapture { body, tls_peer })
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
            message: format!("{operation}: {}", response_body_preview(&body)),
        })
    }
}

fn response_tls_peer(response: &reqwest::Response) -> Result<Option<LiveTlsPeer>> {
    let Some(tls_info) = response.extensions().get::<reqwest::tls::TlsInfo>() else {
        return Ok(None);
    };
    let Some(der) = tls_info.peer_certificate() else {
        return Ok(None);
    };
    Ok(Some(LiveTlsPeer {
        spki_sha256: certificate_spki_sha256_hex(der)
            .map_err(|error| ProviderError::Adapter(error.to_string()))?,
        leaf_certificate_der: der.to_vec(),
    }))
}

fn require_tls_peer(response: &reqwest::Response, operation: &str) -> Result<LiveTlsPeer> {
    response_tls_peer(response)?.ok_or_else(|| {
        ProviderError::Compatibility(format!("{operation} did not expose a live TLS certificate"))
    })
}

fn response_body_preview(body: &[u8]) -> String {
    let preview = String::from_utf8_lossy(body);
    preview.chars().take(512).collect()
}

fn install_default_rustls_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProviderRegistry, SdkAppE2eeSecretKey};
    use confidential_inference_attestation::{
        chutes_expected_report_data_prefix, AliasConfidence, BoundDataRequirement,
        ChannelBindingKind, ChutesE2eeEvidence, FreshnessClass, GpuTeeKind,
        NvidiaGpuAttestationEvidence, ResponseIntegrityRequirement, TinfoilAttestationDoc,
        TrustTier, TINFOIL_TDX_GUEST_V2_FORMAT,
    };
    use confidential_inference_openai::{ChatChoice, ChatMessage};
    use flate2::{write::GzEncoder, Compression};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::ServerConfig;
    use serde_json::json;
    use std::io::Write;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    const TINFOIL_TEST_QUOTE_BYTES: [u8; 48] = [42_u8; 48];
    const TINFOIL_TEST_CERT_DER_BASE64: &str = concat!(
        "MIIDTTCCAjWgAwIBAgIUF0+ODWj0TBiZ451P+xEHiX4O2SUwDQYJKoZIhvcNAQELBQAw",
        "KDEmMCQGA1UEAwwdZW5jbGF2YS1sb2NhbC10aW5mb2lsLmludmFsaWQwHhcNMjYw",
        "NzA1MTY0NjU0WhcNMzYwNzAyMTY0NjU0WjAoMSYwJAYDVQQDDB1lbmNsYXZh",
        "LWxvY2FsLXRpbmZvaWwuaW52YWxpZDCCASIwDQYJKoZIhvcNAQEBBQADggEP",
        "ADCCAQoCggEBALY1+xYGvS1ORL0iyTP2QlYriI/EhyxMB2kzWUueYMI7w4UNoV",
        "TO3QwhXuZU8d/ziZabwvrB64OH8tV9fCtBqnPtJee7kEoAfmLjEyzEb7FPc3I",
        "QixuzTnRtrfqb3tbk9Enq09LpAuBkysNdSiMmT3UiJpU7G3Y4zZFjNQvYWr7go",
        "AwMvHzhXZRkAIxl7edr6dT9Sx8QZjMNb11Wv6ooTcKiC+v5c6Kgmat1gpEJ8v",
        "RaCYGHaAUyQ4b/k+TwrRPtGms4rCbYXMLE8S1haFVkGlJ0gKIu85Hh5wAuDrHC",
        "tRE+OI0yxbqEE+WPQd6/p+ArVqWya4D98YHE7/gLiObwcPMCAwEAAaNvMG0w",
        "HQYDVR0OBBYEFA1EBWbMUpCzcm8VFxhfa7odiCZUMB8GA1UdIwQYMBaAFA1E",
        "BWbMUpCzcm8VFxhfa7odiCZUMA8GA1UdEwEB/wQFMAMBAf8wGgYDVR0RBBMw",
        "EYIJbG9jYWxob3N0hwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQCNXb3vkwmR",
        "NnHubyUcZXD+l2Dqh0dGO/jSMStB88Tm4+SjsAGGMM9nhZHcVI7F/LZ4KwYA9",
        "xYTb9XHmUg8ZP/yszKr6QqCmErG9oN1LyhamjJLWMk8Q57L6PRF9/mQG7MKNK",
        "b1wsJ98EhaabQA88N43U6mU2vqWsuLZ7y7FsxbGUI57Qci+n2SmsX/GqupUUd",
        "mLGOIWHPI8ArjHzVUdZ8/JeW+rFv48oCPxPlyiLUkxNSuYwKkQ2to2cQlWrFv",
        "6WydJS7vPX6VKIu5rPnulEtSban2x2m1V0+/vHjJsxvXMEPrKGXx+Mxgb7xA",
        "Z9Qxj/btKwDPr8hVL6AYjnEm9I2A",
    );

    const TINFOIL_TEST_KEY_DER_BASE64: &str = concat!(
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2NfsWBr0tTkS9",
        "Iskz9kJWK4iPxIcsTAdpM1lLnmDCO8OFDaFUzt0MIV7mVPHf84mWm8L6weuDh/LV",
        "fXwrQapz7SXnu5BKAH5i4xMsxG+xT3NyEIsbs050ba36m97W5PRJ6tPS6QLgZMr",
        "DXUojJk91IiaVOxt2OM2RYzUL2Fq+4KAMDLx84V2UZACMZe3na+nU/UsfEGYzD",
        "W9dVr+qKE3Cogvr+XOioJmrdYKRCfL0WgmBh2gFMkOG/5Pk8K0T7RprOKwm2Fz",
        "CxPEtYWhVZBpSdICiLvOR4ecALg6xwrURPjiNMsW6hBPlj0Hev6fgK1alsmuA",
        "/fGBxO/4C4jm8HDzAgMBAAECggEACT5fQpZM0negvlGZ9ARGlnkTPN2t3vNeAf",
        "3AuBxMuDa3ndBRCaWMQ1lU7ongi57mFNIth8gbQCsiszUpNpzKJaMT+UKHRuHM",
        "+WFm6HWMspR0p3g5t0n6rVFKckNtR3dDOusxVM4wlFXG5KitE/4x8LxZgi3N",
        "9XVbQNbBo+Ncj50X6bgqeiDqW0txc7/P4Vw3cYp9uyZNGVvfIOzjV6Zd8wTH+",
        "KWJ8GUpjQxx7BE6MIdTkGwj7fNRWQnXY/R1kjVHiAtpV0IKbN9byrobnjRSWJ",
        "zTQm7Pq+YUdV1VnQdYWN7Yt9snTP89PPOvPJ2MrgsKejj+E2VsDG0SoE/AzEg",
        "ETQKBgQDyPt7C3ima02SFxMW9zNBz2BoU/9c3ugLQr7A0KfxENcorkKqhhYP0",
        "5l45QHMpmuHnQ9nViBaAvL9XFGqipA2J9zKQoBbU5nNeyoxpbAIiF4j+Ld5S",
        "bBEvsc9h14NL35IlWws06EdyuffXx1Ero3RYMH6gf37P+3AM4LmvFovQpwKB",
        "gQDAjnvLA1ImJLBABxLqNKJNoQ78WV9G35kFkIOFDjXY1w1vJwZcyiETQXHL",
        "7OcER/Ad2H1vAskBwrQLjQl9HkdezFZjQUPYhycxUWzWMq1u6XRqOhTLFUeYo",
        "6C6qKEeiADDPzPyOMmqOFUKJ0i93PDs7uAxJRmnqPRj/NU08ro61QKBgFp/O",
        "DLuUfagEEaU6xZrxFfynFPJ+/m6iMCzUY07Ph2xRpSd19C9kz1TLlIPDLa3Q",
        "LtnsqI908JGQOjkHK4jwVcQPRigZcclTGZWHrxneCiKSEhElHCQJJ9/uqyfm",
        "VIn9G32JCqgt8hZRwiaUm2OA7HKdBO7bYF/Oi3lahjJwHOzAoGBAJcaOIKi",
        "5IASIkzcQDeRfhu023GjIGUZaZc4RDzRXef/OgeTdCa0ZygZHxeLm+18Fi0V",
        "ibjnUp0TEP5Pera4YAFAEDprKLZtuI+2+dVMh1SV1kjVsyN6W2ioXqSbV3Q",
        "B/bc5jaXyci4lbnY9RZPYISeMfFmUZ4Ftz/n2mcinAQTRAoGBAIVs6j59tr",
        "qCVEKtTSpSKv182hIMgknTUaiyx0wODVJWzTE8eHJxSWkpGO6iQEALrodx/",
        "FCbanFofmIot+wvLfLqbMOW3XnISHGQdbbBGbN6WhmTGpi44eGmwhIMByIT",
        "jM0KeLi0TN4EGSarPlwybsSMpawHyhSXwM0yilS+Y70Y",
    );
    const TINFOIL_ALT_CERT_DER_BASE64: &str = concat!(
        "MIIDSTCCAjGgAwIBAgIUIAGtU3yqqw4a8Q898SGBiGi0Bw8wDQYJKoZIhvcNAQELBQAw",
        "JjEkMCIGA1UEAwwbZW5jbGF2YS1hbHQtdGluZm9pbC5pbnZhbGlkMB4XDTI2MDcw",
        "NTE4MjEyNVoXDTM2MDcwMjE4MjEyNVowJjEkMCIGA1UEAwwbZW5jbGF2YS1hbHQ",
        "tdGluZm9pbC5pbnZhbGlkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC",
        "AQEA7jqm3oRw3r/WCljP8/r3T/CkGGPM5xmnj515PIAkhdOIq7x9rGyaby94",
        "y2sFzChOYttri6sfJMuKe9JQQczXUQdxkyDNtsctIbVI2z0uscovW48rsm6S",
        "wFeQBrSczotSJrrqUwr/dLys5ius5u30FZ7I4gnxCtZNR+AEHqHDhaay/iNH",
        "VZHBvcINAAHzOI6Hl1LePb47HqnEYtWwXT148QclrhZgGwabr30RkodAsnFg",
        "6ZVq/egWxRJPPG0QWJA4LbIe641Rz8wQPipYCqn8IEjkXEBlMQsANSzGKTA6",
        "+zKOs5WzX1/PXKalL0KQvtQHm5zKHbpT2qYXQbUBkWFifQIDAQABo28wbTAd",
        "BgNVHQ4EFgQUp9prOk256MfqzSrLBc+EcDcV1/0wHwYDVR0jBBgwFoAUp9pr",
        "Ok256MfqzSrLBc+EcDcV1/0wDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzAR",
        "gglsb2NhbGhvc3SHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAOSk09ajJrLO",
        "Znsfgg8Vn5boldfGS72Xjgfl9ek0Mt1AAGKbZKQ/NTmUfIjq8j83AXtARXhZ",
        "D/FPErhX7yXxoF3AFwHGbTfYFAGegy06InhBvZOP70Y13ayVNngMa92Typil",
        "PYSkrF41CkGa0CpOLcgnmJwA9FSpW0b2ynZQhV36ZLGSK10BYq+RMsI2xEts",
        "HnT/WYzk8pDUKscdgwwkgVJsJ7FdM8UqT+uO+aMHxbFmfZ1HlppM9DpINN5c",
        "rI1fJHVBsN3S5paTpBpClBSkBMW+SToi7kbAnr1++JiHnpb8aP0lW1chzREN",
        "Fz9z1mYehM+gIL1AteApwShYf8LWDC0=",
    );
    const TINFOIL_ALT_KEY_DER_BASE64: &str = concat!(
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDuOqbehHDev9YK",
        "WM/z+vdP8KQYY8znGaePnXk8gCSF04irvH2sbJpvL3jLawXMKE5i22uLqx8ky4p7",
        "0lBBzNdRB3GTIM22xy0htUjbPS6xyi9bjyuybpLAV5AGtJzOi1ImuupTCv90vKzm",
        "K6zm7fQVnsjiCfEK1k1H4AQeocOFprL+I0dVkcG9wg0AAfM4joeXUt49vjseqcR",
        "i1bBdPXjxByWuFmAbBpuvfRGSh0CycWDplWr96BbFEk88bRBYkDgtsh7rjVHPzBA",
        "+KlgKqfwgSORcQGUxCwA1LMYpMDr7Mo6zlbNfX89cpqUvQpC+1AebnModulPaph",
        "dBtQGRYWJ9AgMBAAECggEAHSL4SMvbACtnUtGk8Xq258SPVVpTc8pr94EzlEY58",
        "VI7a4G8vytzQfkE5aA7z8n4OFgM0cLGptnsIJPK9BlJFmR6LBv9fQbkSrSg6guU",
        "G/OWEjUzC3pBoZu0BlXtvcdFb245/ZkhQFZZMTeTSJU+3qwSdq7vl7s5LXrFFjg",
        "DsWNDHVx03DhZae851cXmLeuGc3iuHYCHTON+LFYXugOB8PxJnsRga5js0kSuz/",
        "HtDVx/LMoxinpKk4QabT87lJXX3eSB4VUr4mlCAUK5bn/Le7iTzqb1h8B62mXVq",
        "Z0ZnVIl513eGcJEYTLwdUcyzoPkUYpNBpLXQ4A1GzaIT1n5YQKBgQD/G8fCwdHU",
        "yOlPydRJF6kO7OUcQsLngPTdKC3qT0odX4WI27vQvFnJP+oNW4Y9gEev/Zr91+H",
        "c59xGKcMOkJ5O2SLnhguzvMdaR7CUXZGztOuuq6mzCcfeCcflytdWFDqQKy1Fci",
        "gN5fUuhABlUzOgYJHAs8Zhn9xiaBAJOrjDzQKBgQDvD8Vu/0+D3vbtkOQg6YJW7",
        "FhGziLTDUHUBhe7EHtyjE8dc2LHMtAh2AMFWDZE9pzXw+6ZQ/zVoemHjXofCss8",
        "ZNHpEsjxv+EBtBW+do2j25OluK0srV69maueERCH8ue7B/nga7aDgTj86fbG54I",
        "ZamM3P8RU6FMZzyHhG3PJcQKBgCG/rReoyHeb9LGng7v/s0/UKyMn+dzihIJVdG",
        "2Q+78TCflnCFu+7ynemLoXp5SvScyQglaenrS4v71QfQuKOkc4FpQGebnXeZAJ9",
        "+RI1KOvhZZgA106KATJynYt9XrfxjeYXq7XQVFFYMA8mkjNTwEihWW24sG7gk5K",
        "cgSmjhbpAoGBAIxjAJhcSf+w8eU0zyMcvbP5+yUpbH3wLRYrtcfet//esZ8j4Y",
        "AFMQCO78c1tDjvcc+refR7XoC+Inu981dDaXI/6p0qsOJ2wdXUQWimCiuNiLkr",
        "KFcyQI6rLYMXllOfq8HDv1OxLW8wdZzgcFECJv5x4W3SfqM2A4cGgmjFTEuhAo",
        "GBAOXX43U10LdKc6NAM2HhTMRV54gr9/3aGlRUQkRPeB9IVyrrFnAjKYAEZND2",
        "QyB9GB4dKXjmy+26cOsABYkqDRzM3+8Dlv94G4NrRoEETL0x6hTaXo+JVI50WJ",
        "yzX2lRxy4DXVI28v+Ot5m6XEbczrZFa8bOP8iKi7P4Q2KOvg+g",
    );

    #[tokio::test]
    async fn openai_http_provider_posts_chat_completion_with_bearer_token() {
        let (base_url, request) = spawn_http_response(
            200,
            json!({
                "id": "chatcmpl-http-test",
                "object": "chat.completion",
                "created": 1,
                "model": "llama-3.3-70b",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop"
                }]
            })
            .to_string(),
        )
        .await;
        let route = http_route(&base_url);
        let provider = OpenAiHttpProvider::with_api_key(
            "tinfoil-http-test",
            vec![route.clone()],
            Some("sk-test-secret"),
        )
        .unwrap();
        let response = provider
            .chat(
                &route,
                ProviderChatRequest::new(json!({
                    "model": "llama-3.3-70b",
                    "messages": [{"role": "user", "content": "hello"}]
                })),
            )
            .await
            .unwrap();

        assert_eq!(response.model, "llama-3.3-70b");
        assert_eq!(
            response.choices,
            vec![ChatChoice {
                index: 0,
                message: ChatMessage::assistant("ok"),
                finish_reason: "stop".into(),
            }]
        );
        let request = request.await.unwrap().unwrap();
        assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1"));
        assert!(request.contains("authorization: Bearer sk-test-secret"));
        assert!(request.contains("\"model\":\"llama-3.3-70b\""));
    }

    #[test]
    fn http_provider_debug_redacts_configured_api_key() {
        let provider = OpenAiHttpProvider::with_client(
            "tinfoil-http-test",
            vec![],
            Some("sk-debug-secret".into()),
            reqwest::Client::new(),
        );

        let rendered = format!("{provider:?}");

        assert!(rendered.contains("api_key: Some(<redacted>)"));
        assert!(!rendered.contains("sk-debug-secret"));
    }

    #[tokio::test]
    async fn openai_http_provider_redacts_error_body() {
        let (base_url, _request) = spawn_http_response(
            401,
            "api_key=sk-test-secret prompt=private completion=hidden".into(),
        )
        .await;
        let route = http_route(&base_url);
        let provider = OpenAiHttpProvider::new("tinfoil-http-test", vec![route.clone()]).unwrap();

        let error = provider
            .chat(
                &route,
                ProviderChatRequest::new(json!({
                    "model": "llama-3.3-70b",
                    "messages": [{"role": "user", "content": "hello"}]
                })),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            &error,
            ProviderError::HttpStatus { status: 401, .. }
        ));
        assert!(!error.is_retryable_outage());
        let rendered = error.to_string();
        assert!(!rendered.contains("sk-test-secret"));
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("hidden"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn openai_http_provider_classifies_service_unavailable_as_retryable() {
        let (base_url, _request) = spawn_http_response(503, "temporarily unavailable".into()).await;
        let route = http_route(&base_url);
        let provider = OpenAiHttpProvider::new("tinfoil-http-test", vec![route.clone()]).unwrap();

        let error = provider
            .chat(
                &route,
                ProviderChatRequest::new(json!({
                    "model": "llama-3.3-70b",
                    "messages": [{"role": "user", "content": "hello"}]
                })),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            &error,
            ProviderError::HttpStatus { status: 503, .. }
        ));
        assert!(error.is_retryable_outage());
    }

    #[tokio::test]
    async fn openai_http_provider_classifies_transport_failure_as_retryable() {
        let route = http_route("http://127.0.0.1:9");
        let provider = OpenAiHttpProvider::new("tinfoil-http-test", vec![route.clone()]).unwrap();

        let error = provider
            .chat(
                &route,
                ProviderChatRequest::new(json!({
                    "model": "llama-3.3-70b",
                    "messages": [{"role": "user", "content": "hello"}]
                })),
            )
            .await
            .unwrap_err();

        assert!(matches!(&error, ProviderError::Http(_)));
        assert!(error.is_retryable_outage());
    }

    #[tokio::test]
    async fn openai_http_provider_rejects_fixture_encrypted_requests() {
        let route = http_route("http://127.0.0.1:9");
        let provider = OpenAiHttpProvider::new("tinfoil-http-test", vec![route.clone()]).unwrap();

        let error = provider
            .chat(
                &route,
                ProviderChatRequest::with_confidentiality(
                    json!({
                        "model": "llama-3.3-70b",
                        "messages": [{"role": "user", "content": "hello"}]
                    }),
                    ProviderRequestConfidentiality::FixtureEncrypted,
                ),
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("fixture-encrypted requests cannot be sent"));
    }

    #[tokio::test]
    async fn openai_http_provider_posts_sdk_encrypted_chat_and_decrypts_response() {
        let secret_key = SdkAppE2eeSecretKey::from_private_key_bytes("http-e2ee-key", [11_u8; 32]);
        let (base_url, request) = spawn_sdk_e2ee_response(secret_key.clone()).await;
        let route = http_route(&base_url);
        let provider = OpenAiHttpProvider::new("tinfoil-http-test", vec![route.clone()]).unwrap();
        let provider_request = ProviderChatRequest::sdk_encrypt(
            &route,
            json!({
                "model": "llama-3.3-70b",
                "messages": [{"role": "user", "content": "secret prompt"}]
            }),
            &secret_key.public_config().unwrap(),
        )
        .unwrap();

        let response = provider.chat(&route, provider_request).await.unwrap();

        assert_eq!(response.model, "llama-3.3-70b");
        assert_eq!(
            response.choices,
            vec![ChatChoice {
                index: 0,
                message: ChatMessage::assistant("encrypted ok"),
                finish_reason: "stop".into(),
            }]
        );
        let request = request.await.unwrap().unwrap();
        assert!(request.contains("POST /v1/chat/completions HTTP/1.1"));
        assert!(request.contains("\"schema\":\"confidential-inference.sdk-encrypted-chat.v1\""));
        assert!(!request.contains("secret prompt"));
    }

    #[tokio::test]
    async fn tinfoil_http_provider_rejects_non_https_routes() {
        let route = http_route("http://127.0.0.1:9");
        let provider = TinfoilHttpProvider::with_client(
            "tinfoil-http-test",
            vec![route.clone()],
            None,
            reqwest::Client::new(),
        );

        let error = provider
            .fetch_evidence(
                &route,
                &EvidenceRequest {
                    requested_model: "llama-3.3-70b".into(),
                    policy_digest: "sha256:policy".into(),
                    nonce: None,
                },
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("must use https"));
    }

    #[tokio::test]
    async fn tinfoil_http_provider_fails_closed_when_chat_tls_identity_changes() {
        let (base_url, server) = spawn_tinfoil_tls_identity_rotation().await;
        let route = http_route(&base_url);
        let provider = TinfoilHttpProvider::with_provider_id(
            "tinfoil-http-test",
            vec![route.clone()],
            Some("sk-tinfoil-test"),
        )
        .unwrap();
        let evidence_request = EvidenceRequest {
            requested_model: "llama-3.3-70b".into(),
            policy_digest: "sha256:policy".into(),
            nonce: None,
        };

        let raw = provider
            .fetch_evidence(&route, &evidence_request)
            .await
            .unwrap();
        let capture: TinfoilLiveCaptureEvidence = serde_json::from_slice(&raw).unwrap();
        let first_cert = decode_test_base64(TINFOIL_TEST_CERT_DER_BASE64).unwrap();
        assert_eq!(
            capture.live_tls_spki_sha256,
            certificate_spki_sha256_hex(&first_cert).unwrap()
        );

        let error = provider
            .chat(
                &route,
                ProviderChatRequest::new(json!({
                    "model": "llama-3.3-70b",
                    "messages": [{"role": "user", "content": "hello"}]
                })),
            )
            .await
            .unwrap_err();

        assert!(error.is_key_rotation());
        let error = error.to_string();
        assert!(error.contains("live TLS SPKI changed between evidence and chat"));
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn confidential_http_provider_normalizes_chutes_evidence() {
        let sdk_nonce = "11".repeat(16);
        let nonce = chutes_provider_nonce(&sdk_nonce);
        let e2e_pubkey = "chutes-test-public-key";
        let report_data = format!(
            "{}{}",
            chutes_expected_report_data_prefix(&nonce, e2e_pubkey).unwrap(),
            "00".repeat(32)
        );
        let (base_url, request) = spawn_http_response(
            200,
            json!({
                "attestation_type": "chutes",
                "tee_measurement": "sha256:chutes-tee-measurement",
                "all_attestations": [{
                    "model": "private/org/gpt-oss-120b:thinking-TEE",
                    "nonce": nonce,
                    "e2e_pubkey": e2e_pubkey,
                    "report_data": report_data,
                    "gpu_evidence": [{"kind": "nvidia_cc_fixture", "arch": "gpu-hopper-h100"}]
                }],
                "nras_token": "fixture.nras.jwt",
                "workload_image_digest": "sha256:chutes-workload-image",
                "model_artifacts": [{
                    "kind": "weights",
                    "name": "gpt-oss-120b",
                    "digest": "sha256:chutes-weights"
                }]
            })
            .to_string(),
        )
        .await;
        let route = chutes_http_route(&base_url);
        let provider = ConfidentialHttpProvider::with_api_key(
            "redpill-http-test",
            vec![route.clone()],
            Some("sk-redpill-test"),
        )
        .unwrap();

        let raw = provider
            .fetch_evidence(
                &route,
                &EvidenceRequest {
                    requested_model: "gpt-oss-120b".into(),
                    policy_digest: "sha256:policy".into(),
                    nonce: Some(sdk_nonce),
                },
            )
            .await
            .unwrap();
        let evidence: ChutesE2eeEvidence = serde_json::from_slice(&raw).unwrap();

        assert_eq!(evidence.schema, ChutesE2eeEvidence::SCHEMA);
        assert_eq!(evidence.provider, "redpill-http-test");
        assert_eq!(evidence.evidence_family, "chutes_e2ee");
        assert_eq!(evidence.report_data, report_data);
        assert_eq!(evidence.e2e_public_key, e2e_pubkey);
        assert!(evidence.hardware.gpu.is_some());
        let gpu_attestation = evidence.gpu_attestation.as_ref().unwrap();
        assert_eq!(gpu_attestation.schema, NvidiaGpuAttestationEvidence::SCHEMA);
        assert_eq!(gpu_attestation.nonce, nonce);
        assert_eq!(gpu_attestation.arch.as_deref(), Some("gpu-hopper-h100"));
        assert!(gpu_attestation.raw_payload_base64.is_some());
        assert_eq!(
            gpu_attestation.nras_token.as_deref(),
            Some("fixture.nras.jwt")
        );
        assert_eq!(evidence.attested_model.as_deref(), Some("gpt-oss-120b"));
        let request = request.await.unwrap().unwrap();
        assert!(request.contains("authorization: Bearer sk-redpill-test"));
        assert!(request.contains(&format!("GET /v1/attestation/report?nonce={nonce} ")));
    }

    fn http_route(base_url: &str) -> RouteDefinition {
        let mut route = ProviderRegistry::phase2_fixtures()
            .unwrap()
            .find_route(Some("tinfoil-fixture"), "llama-3.3-70b")
            .unwrap()
            .1
            .clone();
        route.provider = "tinfoil-http-test".into();
        route.route_id = "tinfoil-http-test:llama-3.3-70b:llama-3.3-70b".into();
        route.api_base_url = format!("{}/v1", base_url.trim_end_matches('/'));
        route.evidence_endpoint = format!(
            "{}/.well-known/tinfoil-attestation",
            base_url.trim_end_matches('/')
        );
        route
    }

    fn chutes_http_route(base_url: &str) -> RouteDefinition {
        RouteDefinition {
            route_id: "redpill-http-test:gpt-oss-120b:private/org/gpt-oss-120b:thinking-TEE".into(),
            route_status: crate::RouteLifecycle::Active,
            provider: "redpill-http-test".into(),
            provider_model: "private/org/gpt-oss-120b:thinking-TEE".into(),
            evidence_family: "chutes_e2ee".into(),
            api_base_url: format!("{}/v1", base_url.trim_end_matches('/')),
            evidence_endpoint: format!("{}/v1/attestation/report", base_url.trim_end_matches('/')),
            adapter_version: "redpill-http-chutes-adapter/0.1.0".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            accepted_gpu_tees: vec![GpuTeeKind::NvidiaCc],
            request_encryption: crate::EncryptionRequirement::Required,
            response_decryption: crate::EncryptionRequirement::Required,
            streaming: crate::StreamingSupport::Unsupported,
            alias_confidence: AliasConfidence::Curated,
        }
    }

    async fn spawn_http_response(
        status: u16,
        body: String,
    ) -> (String, tokio::task::JoinHandle<std::io::Result<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request_complete(&request) {
                    break;
                }
            }
            let reason = if status == 200 { "OK" } else { "ERROR" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            Ok(String::from_utf8_lossy(&request).into_owned())
        });

        (format!("http://{address}"), handle)
    }

    async fn spawn_sdk_e2ee_response(
        secret_key: SdkAppE2eeSecretKey,
    ) -> (String, tokio::task::JoinHandle<std::io::Result<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{address}");
        let route = http_route(&base_url);
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_http_request(&mut stream).await?;
            let body = http_request_body(&request);
            let request_value: serde_json::Value =
                serde_json::from_slice(body).map_err(std::io::Error::other)?;
            let provider_request = ProviderChatRequest::with_confidentiality(
                request_value,
                ProviderRequestConfidentiality::SdkEncrypted,
            );
            let (decrypted, session) = provider_request
                .sdk_decrypted_body(&route, &secret_key)
                .map_err(std::io::Error::other)?;
            assert_eq!(decrypted["model"], "llama-3.3-70b");
            assert_eq!(decrypted["messages"][0]["content"], "secret prompt");

            let response_plaintext = json!({
                "id": "chatcmpl-http-e2ee-test",
                "object": "chat.completion",
                "created": 1,
                "model": "llama-3.3-70b",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "encrypted ok"},
                    "finish_reason": "stop"
                }]
            });
            let response_plaintext =
                serde_json::to_vec(&response_plaintext).map_err(std::io::Error::other)?;
            let response_envelope = session
                .encrypt_response_body(&route, &response_plaintext)
                .map_err(std::io::Error::other)?;
            let body = serde_json::to_string(&response_envelope).map_err(std::io::Error::other)?;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            Ok(String::from_utf8_lossy(&request).into_owned())
        });

        (base_url, handle)
    }

    async fn spawn_tinfoil_tls_identity_rotation(
    ) -> (String, tokio::task::JoinHandle<std::io::Result<()>>) {
        install_default_rustls_provider();
        let first_acceptor = TlsAcceptor::from(Arc::new(
            test_tls_server_config(TINFOIL_TEST_CERT_DER_BASE64, TINFOIL_TEST_KEY_DER_BASE64)
                .unwrap(),
        ));
        let second_acceptor = TlsAcceptor::from(Arc::new(
            test_tls_server_config(TINFOIL_ALT_CERT_DER_BASE64, TINFOIL_ALT_KEY_DER_BASE64)
                .unwrap(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = first_acceptor
                .accept(stream)
                .await
                .map_err(std::io::Error::other)?;
            write_test_http_response(
                &mut stream,
                "GET /.well-known/tinfoil-attestation ",
                tinfoil_attestation_body()?,
            )
            .await?;

            let (stream, _) = listener.accept().await?;
            let mut stream = second_acceptor
                .accept(stream)
                .await
                .map_err(std::io::Error::other)?;
            write_test_http_response(
                &mut stream,
                "POST /v1/chat/completions ",
                json!({
                    "id": "chatcmpl-tinfoil-spki-rotation",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "llama-3.3-70b",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "should not be accepted"},
                        "finish_reason": "stop"
                    }]
                })
                .to_string(),
            )
            .await
        });

        (format!("https://{address}"), handle)
    }

    async fn read_http_request<S>(stream: &mut S) -> std::io::Result<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request_complete(&request) {
                break;
            }
        }
        Ok(request)
    }

    async fn write_test_http_response<S>(
        stream: &mut S,
        expected_request_prefix: &str,
        body: String,
    ) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let request = read_http_request(stream).await?;
        let request_text = String::from_utf8_lossy(&request);
        if !request_text.starts_with(expected_request_prefix) {
            return Err(std::io::Error::other(format!(
                "expected request prefix {expected_request_prefix:?}, got {:?}",
                request_text.lines().next().unwrap_or("")
            )));
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await
    }

    fn test_tls_server_config(
        cert_base64: &str,
        key_base64: &str,
    ) -> std::io::Result<ServerConfig> {
        let cert_der = decode_test_base64(cert_base64)?;
        let key_der = decode_test_base64(key_base64)?;
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der)],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der)),
            )
            .map_err(std::io::Error::other)
    }

    fn tinfoil_attestation_body() -> std::io::Result<String> {
        let attestation_doc = TinfoilAttestationDoc {
            format: TINFOIL_TDX_GUEST_V2_FORMAT.into(),
            body: gzip_base64(&TINFOIL_TEST_QUOTE_BYTES)?,
        };
        serde_json::to_string(&attestation_doc).map_err(std::io::Error::other)
    }

    fn gzip_base64(bytes: &[u8]) -> std::io::Result<String> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(encoder.finish()?))
    }

    fn decode_test_base64(value: &str) -> std::io::Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(std::io::Error::other)
    }

    fn http_request_body(request: &[u8]) -> &[u8] {
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
            .unwrap_or(request.len());
        &request[header_end..]
    }

    fn request_complete(request: &[u8]) -> bool {
        let Some(header_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        else {
            return false;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);

        request.len() >= header_end + content_length
    }
}
