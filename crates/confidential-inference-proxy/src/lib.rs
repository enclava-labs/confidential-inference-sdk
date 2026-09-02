//! Optional proxy crate.
//!
//! The proxy sits above `confidential-inference-sdk`. This crate enforces the proxy
//! security configuration contract and provides OpenAI-compatible route
//! handlers without reimplementing SDK routing or attestation logic.

use confidential_inference_openai::{
    ChatCompletionRequest, ChatCompletionResponse, ResponseCreateRequest,
};
use confidential_inference_sdk::{ClientError, ConfidentialInference, ConfidentialResponse};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyConfig {
    pub bind_addr: SocketAddr,
    pub auth: ProxyAuth,
    pub transport: ProxyTransportSecurity,
    pub cors: ProxyCors,
    pub allow_provider_credentials_from_unauthenticated_callers: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787),
            auth: ProxyAuth::LoopbackOnly,
            transport: ProxyTransportSecurity::PlainHttpLoopbackOnly,
            cors: ProxyCors::Disabled,
            allow_provider_credentials_from_unauthenticated_callers: false,
        }
    }
}

#[derive(Clone)]
pub struct ConfidentialInferenceProxy {
    client: ConfidentialInference,
    startup_plan: ProxyStartupPlan,
}

impl ConfidentialInferenceProxy {
    pub fn from_config(
        client: ConfidentialInference,
        config: ProxyConfig,
    ) -> Result<Self, ProxyConfigError> {
        let startup_plan = config.validate()?;
        Ok(Self {
            client,
            startup_plan,
        })
    }

    pub fn new(client: ConfidentialInference, startup_plan: ProxyStartupPlan) -> Self {
        Self {
            client,
            startup_plan,
        }
    }

    pub fn startup_plan(&self) -> &ProxyStartupPlan {
        &self.startup_plan
    }

    pub async fn handle(&self, request: ProxyHttpRequest) -> ProxyHttpResponse {
        let cors_origin = self.cors_allowed_origin(&request);
        let is_cors_preflight = self.is_cors_preflight(&request);
        let response = if let Some(response) =
            self.cors_origin_error(&request, cors_origin.is_some())
        {
            response
        } else if is_cors_preflight {
            self.handle_cors_preflight(&request)
        } else if let Some(response) = self.authorization_error(&request) {
            response
        } else {
            let path = normalized_path(&request.path);
            match (&request.method, path.as_str()) {
                (ProxyHttpMethod::Post, "/v1/chat/completions") => {
                    self.handle_chat_completions(request.body).await
                }
                (ProxyHttpMethod::Get, "/v1/models") => json_response(200, &self.client.models()),
                (ProxyHttpMethod::Get, "/v1/confidentiality") => {
                    json_response(200, &self.client.confidential_models())
                }
                (ProxyHttpMethod::Post, "/v1/responses") => {
                    self.handle_responses(request.body).await
                }
                (ProxyHttpMethod::Get, _) if path.starts_with("/v1/attestation/") => {
                    self.handle_attestation(&path).await
                }
                (ProxyHttpMethod::Options, _) => method_not_allowed_response("OPTIONS"),
                (ProxyHttpMethod::Other(method), _) => proxy_error_response(
                    405,
                    "method_not_allowed",
                    &format!("HTTP method {method} is not supported by the proxy"),
                ),
                _ => proxy_error_response(404, "not_found", "proxy route not found"),
            }
        };

        self.decorate_response(cors_origin, is_cors_preflight, response)
    }

    async fn handle_chat_completions(&self, body: Vec<u8>) -> ProxyHttpResponse {
        let request = match serde_json::from_slice::<ChatCompletionRequest>(&body) {
            Ok(request) => request,
            Err(error) => {
                return proxy_error_response(
                    400,
                    "invalid_request_json",
                    &format!("failed to parse OpenAI chat completion request JSON: {error}"),
                )
            }
        };

        match send_chat_request(self.client.clone(), request).await {
            Ok(response) => openai_chat_response(response),
            Err(error) => client_error_response(&error),
        }
    }

    async fn handle_responses(&self, body: Vec<u8>) -> ProxyHttpResponse {
        let request = match serde_json::from_slice::<ResponseCreateRequest>(&body) {
            Ok(request) => request,
            Err(error) => {
                return proxy_error_response(
                    400,
                    "invalid_request_json",
                    &format!("failed to parse OpenAI Responses request JSON: {error}"),
                )
            }
        };

        match self.client.create_response(request).await {
            Ok(response) => confidential_response_body(response),
            Err(error) => client_error_response(&error),
        }
    }

    async fn handle_attestation(&self, path: &str) -> ProxyHttpResponse {
        let Some((provider, model)) = attestation_path_parts(path) else {
            return proxy_error_response(
                400,
                "invalid_attestation_path",
                "expected /v1/attestation/{provider}/{model}",
            );
        };

        match self.client.verify_route(provider, model).await {
            Ok(verified) => json_response(200, verified.verdict()),
            Err(error) => client_error_response(&error),
        }
    }

    fn authorization_error(&self, request: &ProxyHttpRequest) -> Option<ProxyHttpResponse> {
        if self.startup_plan.auth.request_authorized(request) {
            return None;
        }

        Some(proxy_error_response_with_headers(
            401,
            "unauthorized",
            "proxy request is missing valid authentication",
            vec![("www-authenticate".into(), "Bearer".into())],
        ))
    }

    fn cors_origin_error(
        &self,
        request: &ProxyHttpRequest,
        cors_origin_allowed: bool,
    ) -> Option<ProxyHttpResponse> {
        if matches!(self.startup_plan.cors, ProxyCors::Disabled)
            || request.header("origin").is_none()
        {
            return None;
        }

        if cors_origin_allowed {
            None
        } else {
            Some(proxy_error_response(
                403,
                "cors_origin_not_allowed",
                "request Origin is not allowed by proxy CORS policy",
            ))
        }
    }

    fn is_cors_preflight(&self, request: &ProxyHttpRequest) -> bool {
        !matches!(self.startup_plan.cors, ProxyCors::Disabled)
            && matches!(request.method, ProxyHttpMethod::Options)
            && request.header("origin").is_some()
            && request.header("access-control-request-method").is_some()
    }

    fn handle_cors_preflight(&self, request: &ProxyHttpRequest) -> ProxyHttpResponse {
        let requested_method = request
            .header("access-control-request-method")
            .unwrap_or_default();
        if !cors_method_allowed(requested_method) {
            return method_not_allowed_response(requested_method);
        }
        if !cors_requested_headers_allowed(request.header("access-control-request-headers")) {
            return proxy_error_response(
                403,
                "cors_headers_not_allowed",
                "requested CORS headers are not allowed by proxy CORS policy",
            );
        }

        ProxyHttpResponse {
            status: 204,
            content_type: "text/plain".into(),
            headers: vec![
                (
                    "access-control-allow-methods".into(),
                    "GET, POST, OPTIONS".into(),
                ),
                (
                    "access-control-allow-headers".into(),
                    "authorization, content-type".into(),
                ),
                ("access-control-max-age".into(), "600".into()),
            ],
            body: String::new(),
            verdict_json: None,
            confidential_response_json: None,
        }
    }

    fn cors_allowed_origin(&self, request: &ProxyHttpRequest) -> Option<String> {
        let origin = request.header("origin")?;
        match &self.startup_plan.cors {
            ProxyCors::Disabled | ProxyCors::AllowAnyOrigin => None,
            ProxyCors::AllowOrigins(origins) => origins
                .iter()
                .find(|allowed| allowed.as_str() == origin)
                .cloned(),
        }
    }

    fn decorate_response(
        &self,
        cors_origin: Option<String>,
        is_cors_preflight: bool,
        mut response: ProxyHttpResponse,
    ) -> ProxyHttpResponse {
        if let Some(origin) = cors_origin {
            response
                .headers
                .push(("access-control-allow-origin".into(), origin));
            let vary = if is_cors_preflight {
                "origin, access-control-request-method, access-control-request-headers"
            } else {
                "origin"
            };
            response.headers.push(("vary".into(), vary.into()));
        }
        response
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyHttpMethod {
    Get,
    Post,
    Options,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyHttpRequest {
    pub method: ProxyHttpMethod,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ProxyHttpRequest {
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            method: ProxyHttpMethod::Get,
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn post_json(path: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method: ProxyHttpMethod::Post,
            path: path.into(),
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyHttpResponse {
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub verdict_json: Option<String>,
    pub confidential_response_json: Option<String>,
}

impl ProxyConfig {
    pub fn validate(&self) -> Result<ProxyStartupPlan, ProxyConfigError> {
        let exposed = !self.bind_addr.ip().is_loopback();
        if exposed && !self.auth.requires_authentication() {
            return Err(ProxyConfigError::NonLoopbackRequiresAuth {
                bind_addr: self.bind_addr,
            });
        }
        if exposed && !self.transport.protects_non_loopback() {
            return Err(ProxyConfigError::NonLoopbackRequiresTlsOrReverseProxy {
                bind_addr: self.bind_addr,
            });
        }
        if matches!(&self.auth, ProxyAuth::BearerToken { token, .. } if token.is_empty()) {
            return Err(ProxyConfigError::BearerTokenCannotBeEmpty);
        }
        if self.allow_provider_credentials_from_unauthenticated_callers
            && !self.auth.requires_authentication()
        {
            return Err(ProxyConfigError::UnauthenticatedProviderCredentialForwarding);
        }
        if matches!(self.cors, ProxyCors::AllowAnyOrigin) {
            return Err(ProxyConfigError::WildcardCorsRejected);
        }
        if let ProxyCors::AllowOrigins(origins) = &self.cors {
            if origins.is_empty() || origins.iter().any(|origin| origin.trim().is_empty()) {
                return Err(ProxyConfigError::CorsRequiresExplicitOrigins);
            }
            if origins.iter().any(|origin| origin == "*") {
                return Err(ProxyConfigError::WildcardCorsRejected);
            }
            if origins
                .iter()
                .any(|origin| origin.trim() != origin || origin.chars().any(char::is_control))
            {
                return Err(ProxyConfigError::CorsOriginMustBeHeaderSafe);
            }
        }

        Ok(ProxyStartupPlan {
            bind_addr: self.bind_addr,
            exposed,
            auth: self.auth.clone(),
            auth_enabled: self.auth.requires_authentication(),
            transport: self.transport.clone(),
            cors: self.cors.clone(),
            startup_warnings: startup_warnings(self),
        })
    }
}

pub struct ProxyServer {
    proxy: ConfidentialInferenceProxy,
    listener: TcpListener,
}

impl ProxyServer {
    pub async fn bind(
        client: ConfidentialInference,
        config: ProxyConfig,
    ) -> Result<Self, ProxyServerError> {
        let proxy = ConfidentialInferenceProxy::from_config(client, config)?;
        if proxy.startup_plan.exposed {
            return Err(ProxyServerError::UnsupportedTransport(
                "the built-in HTTP server only binds loopback addresses; use a secure reverse proxy or TLS server integration for exposed deployments"
                    .into(),
            ));
        }
        if proxy.startup_plan.transport != ProxyTransportSecurity::PlainHttpLoopbackOnly {
            return Err(ProxyServerError::UnsupportedTransport(
                "the built-in HTTP server currently supports plain HTTP loopback transport only"
                    .into(),
            ));
        }

        let listener = TcpListener::bind(proxy.startup_plan.bind_addr).await?;
        Ok(Self { proxy, listener })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve_once(&self) -> Result<(), ProxyServerError> {
        let (stream, _peer) = self.listener.accept().await?;
        handle_connection(self.proxy.clone(), stream).await
    }

    pub async fn serve_until<S>(self, shutdown: S) -> Result<(), ProxyServerError>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                accepted = self.listener.accept() => {
                    let (stream, _peer) = accepted?;
                    let proxy = self.proxy.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection(proxy, stream).await;
                    });
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum ProxyServerError {
    Config(ProxyConfigError),
    Io(std::io::Error),
    BadRequest(String),
    UnsupportedTransport(String),
}

impl std::fmt::Display for ProxyServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::BadRequest(message) => write!(formatter, "bad proxy HTTP request: {message}"),
            Self::UnsupportedTransport(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for ProxyServerError {}

impl From<ProxyConfigError> for ProxyServerError {
    fn from(error: ProxyConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<std::io::Error> for ProxyServerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ProxyAuth {
    LoopbackOnly,
    BearerToken {
        token: String,
        redacted_token_label: String,
    },
    StrongExternalAuth {
        description: String,
    },
}

impl ProxyAuth {
    pub fn bearer_token(token: impl Into<String>) -> Self {
        Self::BearerToken {
            token: token.into(),
            redacted_token_label: "configured-bearer-token".into(),
        }
    }

    fn requires_authentication(&self) -> bool {
        matches!(
            self,
            ProxyAuth::BearerToken { .. } | ProxyAuth::StrongExternalAuth { .. }
        )
    }

    fn request_authorized(&self, request: &ProxyHttpRequest) -> bool {
        match self {
            Self::LoopbackOnly | Self::StrongExternalAuth { .. } => true,
            Self::BearerToken { token, .. } => request
                .header("authorization")
                .and_then(|value| value.strip_prefix("Bearer "))
                .map(|candidate| constant_time_eq(candidate.as_bytes(), token.as_bytes()))
                .unwrap_or(false),
        }
    }
}

/// Fixed-time comparison so a remote caller cannot recover the configured
/// bearer token through timing. The length check leaks only the token length.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

impl std::fmt::Debug for ProxyAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoopbackOnly => formatter.write_str("LoopbackOnly"),
            Self::BearerToken {
                redacted_token_label,
                ..
            } => formatter
                .debug_struct("BearerToken")
                .field("token", &"[REDACTED]")
                .field("redacted_token_label", redacted_token_label)
                .finish(),
            Self::StrongExternalAuth { description } => formatter
                .debug_struct("StrongExternalAuth")
                .field("description", description)
                .finish(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyTransportSecurity {
    PlainHttpLoopbackOnly,
    Tls,
    MutualTls,
    SecureReverseProxy { description: String },
}

impl ProxyTransportSecurity {
    fn protects_non_loopback(&self) -> bool {
        matches!(
            self,
            ProxyTransportSecurity::Tls
                | ProxyTransportSecurity::MutualTls
                | ProxyTransportSecurity::SecureReverseProxy { .. }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyCors {
    Disabled,
    AllowOrigins(Vec<String>),
    AllowAnyOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyStartupPlan {
    pub bind_addr: SocketAddr,
    pub exposed: bool,
    pub auth: ProxyAuth,
    pub auth_enabled: bool,
    pub transport: ProxyTransportSecurity,
    pub cors: ProxyCors,
    pub startup_warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyConfigError {
    NonLoopbackRequiresAuth { bind_addr: SocketAddr },
    NonLoopbackRequiresTlsOrReverseProxy { bind_addr: SocketAddr },
    UnauthenticatedProviderCredentialForwarding,
    BearerTokenCannotBeEmpty,
    WildcardCorsRejected,
    CorsRequiresExplicitOrigins,
    CorsOriginMustBeHeaderSafe,
}

impl std::fmt::Display for ProxyConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonLoopbackRequiresAuth { bind_addr } => write!(
                formatter,
                "proxy bind address {bind_addr} is non-loopback and requires authentication"
            ),
            Self::NonLoopbackRequiresTlsOrReverseProxy { bind_addr } => write!(
                formatter,
                "proxy bind address {bind_addr} is non-loopback and requires TLS, mTLS, or a secure reverse proxy"
            ),
            Self::UnauthenticatedProviderCredentialForwarding => write!(
                formatter,
                "proxy must not forward provider credentials for unauthenticated callers"
            ),
            Self::BearerTokenCannotBeEmpty => write!(
                formatter,
                "proxy bearer token authentication requires a non-empty token"
            ),
            Self::WildcardCorsRejected => {
                write!(formatter, "proxy CORS must use explicit origins, not wildcard")
            }
            Self::CorsRequiresExplicitOrigins => {
                write!(formatter, "proxy CORS requires at least one explicit origin")
            }
            Self::CorsOriginMustBeHeaderSafe => {
                write!(formatter, "proxy CORS origins must be header-safe exact values")
            }
        }
    }
}

impl std::error::Error for ProxyConfigError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxySecurityDefaults {
    pub loopback_only: bool,
    pub cors_enabled: bool,
    pub requires_auth_for_non_loopback: bool,
    pub requires_tls_or_secure_reverse_proxy_for_non_loopback: bool,
}

impl Default for ProxySecurityDefaults {
    fn default() -> Self {
        Self {
            loopback_only: true,
            cors_enabled: false,
            requires_auth_for_non_loopback: true,
            requires_tls_or_secure_reverse_proxy_for_non_loopback: true,
        }
    }
}

fn startup_warnings(config: &ProxyConfig) -> Vec<String> {
    let mut warnings = Vec::new();
    if !config.bind_addr.ip().is_loopback() {
        warnings.push(format!(
            "proxy exposed on non-loopback address {}; auth_enabled={}",
            config.bind_addr,
            config.auth.requires_authentication()
        ));
    }
    if !matches!(config.cors, ProxyCors::Disabled) {
        warnings.push("proxy CORS is enabled with explicit origins".into());
    }
    warnings
}

fn cors_method_allowed(method: &str) -> bool {
    matches!(method, "GET" | "POST")
}

fn cors_requested_headers_allowed(headers: Option<&str>) -> bool {
    let Some(headers) = headers else {
        return true;
    };

    headers.split(',').all(|header| {
        matches!(
            header.trim().to_ascii_lowercase().as_str(),
            "" | "authorization" | "content-type"
        )
    })
}

async fn send_chat_request(
    client: ConfidentialInference,
    request: ChatCompletionRequest,
) -> confidential_inference_sdk::Result<ConfidentialResponse<ChatCompletionResponse>> {
    let mut builder = client
        .chat_completions()
        .model(request.model)
        .messages(request.messages);
    if let Some(stream) = request.stream {
        builder = builder.stream(stream);
    }
    if let Some(max_tokens) = request.max_tokens {
        builder = builder.max_tokens(max_tokens);
    }
    if let Some(temperature) = request.temperature {
        builder = builder.temperature(temperature);
    }
    builder.send().await
}

fn openai_chat_response(
    response: ConfidentialResponse<ChatCompletionResponse>,
) -> ProxyHttpResponse {
    confidential_response_body(response)
}

fn confidential_response_body<T: serde::Serialize>(
    response: ConfidentialResponse<T>,
) -> ProxyHttpResponse {
    let body = serde_json::to_string(&response.response).unwrap_or_else(|error| {
        proxy_error_body(
            "response_serialization_failed",
            &format!("failed to serialize OpenAI-compatible response JSON: {error}"),
        )
    });
    let verdict_json = serde_json::to_string(&response.verdict).ok();
    let confidential_response_json = serde_json::to_string(&response).ok();
    let headers = vec![
        (
            "x-confidential-inference-verdict-status".into(),
            format!("{:?}", response.verdict.status).to_ascii_lowercase(),
        ),
        (
            "x-confidential-inference-route-id".into(),
            response.verdict.route_id.clone(),
        ),
        (
            "x-confidential-inference-provider".into(),
            response.provider.clone(),
        ),
        (
            "x-confidential-inference-provider-model".into(),
            response.provider_model.clone(),
        ),
        (
            "x-confidential-inference-response-integrity".into(),
            json_enum_header_value(&response.response_integrity_result),
        ),
    ];

    ProxyHttpResponse {
        status: 200,
        content_type: "application/json".into(),
        headers,
        body,
        verdict_json,
        confidential_response_json,
    }
}

fn json_response<T: serde::Serialize>(status: u16, value: &T) -> ProxyHttpResponse {
    let body = serde_json::to_string(value).unwrap_or_else(|error| {
        proxy_error_body(
            "response_serialization_failed",
            &format!("failed to serialize proxy response JSON: {error}"),
        )
    });
    ProxyHttpResponse {
        status,
        content_type: "application/json".into(),
        headers: Vec::new(),
        body,
        verdict_json: None,
        confidential_response_json: None,
    }
}

fn client_error_response(error: &ClientError) -> ProxyHttpResponse {
    let (status, code) = match error {
        ClientError::RouteNotFound { .. } | ClientError::UnknownProvider(_) => {
            (404, "route_not_found")
        }
        ClientError::RouteSelectionFailed { .. }
        | ClientError::MissingModel
        | ClientError::MissingMessages
        | ClientError::ResponseCompatibility(_)
        | ClientError::StreamingNotSupported { .. }
        | ClientError::VerifiedRouteModelMismatch { .. }
        | ClientError::InvalidProviderRouting { .. } => (400, "invalid_request"),
        ClientError::PolicyDenied { .. } => (403, "policy_denied"),
        ClientError::VerifiedRouteExpired { .. } => (409, "verified_route_expired"),
        ClientError::InsecurePolicyRequiresOptIn { .. } => (500, "client_configuration_failed"),
        ClientError::ResponseJsonSerialization(_) => (500, "response_serialization_failed"),
        ClientError::RegistryCache(_) => (503, "registry_cache_failed"),
        ClientError::ReferenceValuesCache(_) => (503, "reference_values_cache_failed"),
        ClientError::Attestation(_)
        | ClientError::Provider(_)
        | ClientError::VerificationWaitQueueFull { .. }
        | ClientError::VerificationWaitTimeout { .. }
        | ClientError::RouteAttemptsFailed { .. } => (502, "upstream_verification_failed"),
    };
    proxy_error_response(status, code, &error.to_string())
}

fn proxy_error_response(status: u16, code: &str, message: &str) -> ProxyHttpResponse {
    proxy_error_response_with_headers(status, code, message, Vec::new())
}

fn method_not_allowed_response(method: &str) -> ProxyHttpResponse {
    proxy_error_response_with_headers(
        405,
        "method_not_allowed",
        &format!("HTTP method {method} is not supported by the proxy"),
        vec![("allow".into(), "GET, POST, OPTIONS".into())],
    )
}

fn proxy_error_response_with_headers(
    status: u16,
    code: &str,
    message: &str,
    headers: Vec<(String, String)>,
) -> ProxyHttpResponse {
    ProxyHttpResponse {
        status,
        content_type: "application/json".into(),
        headers,
        body: proxy_error_body(code, message),
        verdict_json: None,
        confidential_response_json: None,
    }
}

fn proxy_error_body(code: &str, message: &str) -> String {
    serde_json::json!({
        "error": {
            "type": "confidential_inference_proxy_error",
            "code": code,
            "message": redact_proxy_error_message(message),
        }
    })
    .to_string()
}

fn redact_proxy_error_message(message: &str) -> String {
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

fn json_enum_header_value<T>(value: &T) -> String
where
    T: serde::Serialize + std::fmt::Debug,
{
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(value)) => value,
        _ => format!("{value:?}").to_ascii_lowercase(),
    }
}

fn normalized_path(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".into()
    } else {
        trimmed.into()
    }
}

fn attestation_path_parts(path: &str) -> Option<(&str, String)> {
    let mut parts = path
        .trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty());
    if parts.next()? != "v1" || parts.next()? != "attestation" {
        return None;
    }
    let provider = parts.next()?;
    let model = parts.collect::<Vec<_>>().join("/");
    if provider.is_empty() || model.is_empty() {
        None
    } else {
        Some((provider, model))
    }
}

async fn handle_connection(
    proxy: ConfidentialInferenceProxy,
    mut stream: TcpStream,
) -> Result<(), ProxyServerError> {
    let response = match read_http_request(&mut stream).await {
        Ok(request) => proxy.handle(request).await,
        Err(ProxyServerError::BadRequest(message)) => {
            proxy_error_response(400, "bad_request", &message)
        }
        Err(error) => return Err(error),
    };
    write_http_response(&mut stream, response).await?;
    Ok(())
}

async fn read_http_request(stream: &mut TcpStream) -> Result<ProxyHttpRequest, ProxyServerError> {
    let mut buffer = Vec::new();
    let header_end = loop {
        if let Some(header_end) = header_end(&buffer) {
            break header_end;
        }
        if buffer.len() >= MAX_HTTP_HEADER_BYTES {
            return Err(ProxyServerError::BadRequest(
                "HTTP request headers exceed proxy limit".into(),
            ));
        }

        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(ProxyServerError::BadRequest(
                "connection closed before HTTP headers completed".into(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let headers = String::from_utf8(buffer[..header_end].to_vec()).map_err(|error| {
        ProxyServerError::BadRequest(format!("HTTP request headers are not UTF-8: {error}"))
    })?;
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| ProxyServerError::BadRequest("missing HTTP request line".into()))?;
    let (method, path) = parse_request_line(request_line)?;
    let headers = lines
        .filter(|line| !line.is_empty())
        .map(parse_header_line)
        .collect::<Result<Vec<_>, _>>()?;
    let content_length = content_length(&headers)?;
    if content_length > MAX_HTTP_BODY_BYTES {
        return Err(ProxyServerError::BadRequest(
            "HTTP request body exceeds proxy limit".into(),
        ));
    }

    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = vec![0_u8; (content_length - body.len()).min(8192)];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(ProxyServerError::BadRequest(
                "connection closed before HTTP body completed".into(),
            ));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Ok(ProxyHttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_request_line(line: &str) -> Result<(ProxyHttpMethod, String), ProxyServerError> {
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ProxyServerError::BadRequest("missing HTTP method".into()))?;
    let path = parts
        .next()
        .ok_or_else(|| ProxyServerError::BadRequest("missing HTTP request target".into()))?;
    let version = parts
        .next()
        .ok_or_else(|| ProxyServerError::BadRequest("missing HTTP version".into()))?;
    if !version.starts_with("HTTP/1.") {
        return Err(ProxyServerError::BadRequest(format!(
            "unsupported HTTP version {version}"
        )));
    }
    let method = match method {
        "GET" => ProxyHttpMethod::Get,
        "POST" => ProxyHttpMethod::Post,
        "OPTIONS" => ProxyHttpMethod::Options,
        other => ProxyHttpMethod::Other(other.to_owned()),
    };
    Ok((method, path.to_owned()))
}

fn parse_header_line(line: &str) -> Result<(String, String), ProxyServerError> {
    let Some((name, value)) = line.split_once(':') else {
        return Err(ProxyServerError::BadRequest(format!(
            "malformed HTTP header line {line:?}"
        )));
    };
    Ok((name.trim().to_owned(), value.trim().to_owned()))
}

fn content_length(headers: &[(String, String)]) -> Result<usize, ProxyServerError> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| {
            value.parse::<usize>().map_err(|error| {
                ProxyServerError::BadRequest(format!("invalid content-length header: {error}"))
            })
        })
        .transpose()
        .map(|length| length.unwrap_or(0))
}

async fn write_http_response(
    stream: &mut TcpStream,
    response: ProxyHttpResponse,
) -> std::io::Result<()> {
    let body = response.body.into_bytes();
    let mut head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        reason_phrase(response.status),
        sanitize_header_value(&response.content_type),
        body.len()
    );
    for (name, value) in response.headers {
        if valid_header_name(&name) {
            head.push_str(&format!(
                "{}: {}\r\n",
                name.to_ascii_lowercase(),
                sanitize_header_value(&value)
            ));
        }
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "OK",
    }
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn sanitize_header_value(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidential_inference_openai::ChatMessage;
    use confidential_inference_sdk::{VerdictRecord, VerdictStore};
    use serde_json::Value;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MemoryVerdictStore {
        records: Mutex<Vec<VerdictRecord>>,
    }

    impl VerdictStore for MemoryVerdictStore {
        fn persist(&self, record: &VerdictRecord) {
            self.records.lock().unwrap().push(record.clone());
        }
    }

    fn exposed_config() -> ProxyConfig {
        ProxyConfig {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 8787)),
            auth: ProxyAuth::BearerToken {
                token: "local-proxy-token-secret".into(),
                redacted_token_label: "local-proxy-token".into(),
            },
            transport: ProxyTransportSecurity::Tls,
            cors: ProxyCors::Disabled,
            allow_provider_credentials_from_unauthenticated_callers: false,
        }
    }

    #[test]
    fn default_proxy_config_is_loopback_only_without_cors() {
        let plan = ProxyConfig::default().validate().unwrap();

        assert_eq!(plan.bind_addr, SocketAddr::from(([127, 0, 0, 1], 8787)));
        assert!(!plan.exposed);
        assert!(!plan.auth_enabled);
        assert_eq!(plan.cors, ProxyCors::Disabled);
        assert!(plan.startup_warnings.is_empty());
    }

    #[test]
    fn non_loopback_bind_requires_authentication() {
        let mut config = exposed_config();
        config.auth = ProxyAuth::LoopbackOnly;

        assert!(matches!(
            config.validate(),
            Err(ProxyConfigError::NonLoopbackRequiresAuth { .. })
        ));
    }

    #[test]
    fn non_loopback_bind_requires_tls_or_secure_reverse_proxy() {
        let mut config = exposed_config();
        config.transport = ProxyTransportSecurity::PlainHttpLoopbackOnly;

        assert!(matches!(
            config.validate(),
            Err(ProxyConfigError::NonLoopbackRequiresTlsOrReverseProxy { .. })
        ));
    }

    #[test]
    fn exposed_proxy_emits_startup_warning_with_auth_state() {
        let plan = exposed_config().validate().unwrap();

        assert!(plan.exposed);
        assert!(plan.auth_enabled);
        assert!(plan.startup_warnings.iter().any(|warning| {
            warning.contains("0.0.0.0:8787") && warning.contains("auth_enabled=true")
        }));
    }

    #[test]
    fn unauthenticated_provider_credential_forwarding_is_rejected() {
        let config = ProxyConfig {
            allow_provider_credentials_from_unauthenticated_callers: true,
            ..ProxyConfig::default()
        };

        assert!(matches!(
            config.validate(),
            Err(ProxyConfigError::UnauthenticatedProviderCredentialForwarding)
        ));
    }

    #[test]
    fn cors_is_disabled_by_default_and_wildcard_is_rejected() {
        assert_eq!(ProxyConfig::default().cors, ProxyCors::Disabled);

        let config = ProxyConfig {
            cors: ProxyCors::AllowAnyOrigin,
            ..ProxyConfig::default()
        };

        assert!(matches!(
            config.validate(),
            Err(ProxyConfigError::WildcardCorsRejected)
        ));
    }

    #[test]
    fn cors_requires_explicit_origins_when_enabled() {
        let config = ProxyConfig {
            cors: ProxyCors::AllowOrigins(Vec::new()),
            ..ProxyConfig::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ProxyConfigError::CorsRequiresExplicitOrigins)
        ));

        let config = ProxyConfig {
            cors: ProxyCors::AllowOrigins(vec!["*".into()]),
            ..ProxyConfig::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ProxyConfigError::WildcardCorsRejected)
        ));

        let config = ProxyConfig {
            cors: ProxyCors::AllowOrigins(vec!["https://app.example\r\nx-leak: true".into()]),
            ..ProxyConfig::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ProxyConfigError::CorsOriginMustBeHeaderSafe)
        ));

        let config = ProxyConfig {
            cors: ProxyCors::AllowOrigins(vec!["https://app.example".into()]),
            ..ProxyConfig::default()
        };
        let plan = config.validate().unwrap();
        assert!(plan
            .startup_warnings
            .contains(&"proxy CORS is enabled with explicit origins".to_owned()));
    }

    #[test]
    fn bearer_proxy_auth_redacts_token_in_debug_and_rejects_empty_token() {
        let auth = ProxyAuth::BearerToken {
            token: "super-secret-proxy-token".into(),
            redacted_token_label: "operator-token".into(),
        };
        let rendered = format!("{auth:?}");

        assert!(!rendered.contains("super-secret-proxy-token"));
        assert!(rendered.contains("[REDACTED]"));

        let config = ProxyConfig {
            auth: ProxyAuth::BearerToken {
                token: String::new(),
                redacted_token_label: "empty".into(),
            },
            ..ProxyConfig::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ProxyConfigError::BearerTokenCannotBeEmpty)
        ));
    }

    async fn demo_proxy() -> ConfidentialInferenceProxy {
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .build()
            .await
            .unwrap();
        ConfidentialInferenceProxy::from_config(client, ProxyConfig::default()).unwrap()
    }

    async fn demo_client() -> ConfidentialInference {
        ConfidentialInference::builder()
            .with_demo_provider()
            .build()
            .await
            .unwrap()
    }

    async fn raw_http_request(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    fn response_header<'a>(response: &'a ProxyHttpResponse, name: &str) -> Option<&'a str> {
        response
            .headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[tokio::test]
    async fn proxy_bearer_auth_is_enforced_before_route_handling() {
        let client = demo_client().await;
        let proxy = ConfidentialInferenceProxy::from_config(
            client,
            ProxyConfig {
                auth: ProxyAuth::BearerToken {
                    token: "proxy-secret".into(),
                    redacted_token_label: "proxy-token".into(),
                },
                ..ProxyConfig::default()
            },
        )
        .unwrap();

        let unauthorized = proxy.handle(ProxyHttpRequest::get("/v1/models")).await;
        let authorized = proxy
            .handle(
                ProxyHttpRequest::get("/v1/models")
                    .with_header("authorization", "Bearer proxy-secret"),
            )
            .await;

        assert_eq!(unauthorized.status, 401);
        assert!(unauthorized.body.contains("unauthorized"));
        assert_eq!(authorized.status, 200);
        assert!(authorized.body.contains("gpt-oss-120b"));
    }

    #[tokio::test]
    async fn proxy_cors_reflects_only_matching_explicit_origin() {
        let client = demo_client().await;
        let proxy = ConfidentialInferenceProxy::from_config(
            client,
            ProxyConfig {
                cors: ProxyCors::AllowOrigins(vec![
                    "https://app.example".into(),
                    "https://admin.example".into(),
                ]),
                ..ProxyConfig::default()
            },
        )
        .unwrap();

        let allowed = proxy
            .handle(
                ProxyHttpRequest::get("/v1/models").with_header("origin", "https://admin.example"),
            )
            .await;
        let disallowed = proxy
            .handle(
                ProxyHttpRequest::get("/v1/models").with_header("origin", "https://evil.example"),
            )
            .await;
        let no_origin = proxy.handle(ProxyHttpRequest::get("/v1/models")).await;

        assert_eq!(allowed.status, 200);
        assert_eq!(
            response_header(&allowed, "access-control-allow-origin"),
            Some("https://admin.example")
        );
        assert_eq!(response_header(&allowed, "vary"), Some("origin"));
        assert_ne!(
            response_header(&allowed, "access-control-allow-origin"),
            Some("https://app.example")
        );
        assert_eq!(disallowed.status, 403);
        assert!(disallowed.body.contains("cors_origin_not_allowed"));
        assert!(!disallowed.body.contains("gpt-oss-120b"));
        assert_eq!(
            response_header(&disallowed, "access-control-allow-origin"),
            None
        );
        assert_eq!(no_origin.status, 200);
        assert_eq!(
            response_header(&no_origin, "access-control-allow-origin"),
            None
        );
    }

    #[tokio::test]
    async fn proxy_cors_preflight_is_static_and_fail_closed_before_auth() {
        let client = demo_client().await;
        let proxy = ConfidentialInferenceProxy::from_config(
            client,
            ProxyConfig {
                auth: ProxyAuth::BearerToken {
                    token: "proxy-secret".into(),
                    redacted_token_label: "proxy-token".into(),
                },
                cors: ProxyCors::AllowOrigins(vec!["https://app.example".into()]),
                ..ProxyConfig::default()
            },
        )
        .unwrap();

        let allowed = proxy
            .handle(ProxyHttpRequest {
                method: ProxyHttpMethod::Options,
                path: "/v1/chat/completions".into(),
                headers: vec![
                    ("origin".into(), "https://app.example".into()),
                    ("access-control-request-method".into(), "POST".into()),
                    (
                        "access-control-request-headers".into(),
                        "authorization, content-type".into(),
                    ),
                ],
                body: Vec::new(),
            })
            .await;
        let disallowed_header = proxy
            .handle(ProxyHttpRequest {
                method: ProxyHttpMethod::Options,
                path: "/v1/chat/completions".into(),
                headers: vec![
                    ("origin".into(), "https://app.example".into()),
                    ("access-control-request-method".into(), "POST".into()),
                    ("access-control-request-headers".into(), "x-api-key".into()),
                ],
                body: Vec::new(),
            })
            .await;
        let disallowed_origin = proxy
            .handle(ProxyHttpRequest {
                method: ProxyHttpMethod::Options,
                path: "/v1/chat/completions".into(),
                headers: vec![
                    ("origin".into(), "https://evil.example".into()),
                    ("access-control-request-method".into(), "POST".into()),
                    (
                        "access-control-request-headers".into(),
                        "authorization".into(),
                    ),
                ],
                body: Vec::new(),
            })
            .await;
        let cors_disabled = demo_proxy()
            .await
            .handle(ProxyHttpRequest {
                method: ProxyHttpMethod::Options,
                path: "/v1/chat/completions".into(),
                headers: vec![
                    ("origin".into(), "https://app.example".into()),
                    ("access-control-request-method".into(), "POST".into()),
                    (
                        "access-control-request-headers".into(),
                        "authorization".into(),
                    ),
                ],
                body: Vec::new(),
            })
            .await;

        assert_eq!(allowed.status, 204);
        assert!(allowed.body.is_empty());
        assert!(allowed.verdict_json.is_none());
        assert_eq!(
            response_header(&allowed, "access-control-allow-origin"),
            Some("https://app.example")
        );
        assert_eq!(
            response_header(&allowed, "access-control-allow-methods"),
            Some("GET, POST, OPTIONS")
        );
        assert_eq!(
            response_header(&allowed, "access-control-allow-headers"),
            Some("authorization, content-type")
        );
        assert_eq!(
            response_header(&allowed, "vary"),
            Some("origin, access-control-request-method, access-control-request-headers")
        );
        assert_eq!(disallowed_header.status, 403);
        assert!(disallowed_header.body.contains("cors_headers_not_allowed"));
        assert_eq!(
            response_header(&disallowed_header, "access-control-allow-origin"),
            Some("https://app.example")
        );
        assert_eq!(disallowed_origin.status, 403);
        assert!(disallowed_origin.body.contains("cors_origin_not_allowed"));
        assert_eq!(
            response_header(&disallowed_origin, "access-control-allow-origin"),
            None
        );
        assert_eq!(cors_disabled.status, 405);
        assert_eq!(
            response_header(&cors_disabled, "access-control-allow-origin"),
            None
        );
    }

    #[tokio::test]
    async fn proxy_rejects_unauthenticated_chat_before_sdk_verification() {
        let audit = Arc::new(MemoryVerdictStore::default());
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .verdict_store(audit.clone())
            .build()
            .await
            .unwrap();
        let proxy = ConfidentialInferenceProxy::from_config(
            client,
            ProxyConfig {
                auth: ProxyAuth::BearerToken {
                    token: "proxy-secret".into(),
                    redacted_token_label: "proxy-token".into(),
                },
                ..ProxyConfig::default()
            },
        )
        .unwrap();
        let body = serde_json::to_vec(&ChatCompletionRequest::new(
            "gpt-oss-120b",
            vec![ChatMessage::user("unauthenticated proxy spend guard")],
        ))
        .unwrap();

        let unauthorized = proxy
            .handle(ProxyHttpRequest::post_json("/v1/chat/completions", body))
            .await;

        assert_eq!(unauthorized.status, 401);
        assert!(unauthorized.body.contains("unauthorized"));
        assert!(unauthorized.verdict_json.is_none());
        assert!(audit.records.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn proxy_server_serves_loopback_http_with_verdict_headers() {
        let client = demo_client().await;
        let server = ProxyServer::bind(
            client,
            ProxyConfig {
                bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                ..ProxyConfig::default()
            },
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move { server.serve_once().await });
        let request_body = serde_json::json!({
            "model": "gpt-oss-120b",
            "messages": [{"role": "user", "content": "proxy server chat path"}]
        })
        .to_string();

        let response = raw_http_request(
            address,
            &format!(
                "POST /v1/chat/completions HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                request_body.len(),
                request_body
            ),
        )
        .await;
        server_task.await.unwrap().unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();

        assert!(head.starts_with("HTTP/1.1 200 OK"));
        assert!(head.contains("x-confidential-inference-verdict-status: verified"));
        assert!(head.contains("x-confidential-inference-response-integrity: channel_bound"));
        assert!(head.contains("x-confidential-inference-provider: demo"));
        assert!(!head.contains("proxy server chat path"));
        assert!(body.contains("\"object\":\"chat.completion\""));
        assert!(body.contains("proxy server chat path"));
    }

    #[tokio::test]
    async fn proxy_chat_completions_route_delegates_to_sdk_and_returns_verdict_sidecar() {
        let proxy = demo_proxy().await;
        let request =
            ChatCompletionRequest::new("gpt-oss-120b", vec![ChatMessage::user("proxy chat path")]);

        let response = proxy
            .handle(ProxyHttpRequest::post_json(
                "/v1/chat/completions",
                serde_json::to_vec(&request).unwrap(),
            ))
            .await;
        let body: Value = serde_json::from_str(&response.body).unwrap();
        let verdict: Value = serde_json::from_str(response.verdict_json.as_ref().unwrap()).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "application/json");
        assert_eq!(body["object"], "chat.completion");
        assert_eq!(body["model"], "e2ee-gpt-oss-120b-p");
        assert!(body.get("verdict").is_none());
        assert_eq!(verdict["status"], "verified");
        assert_eq!(verdict["request_allowed"], true);
        assert!(!response.verdict_json.unwrap().contains("proxy chat path"));
        assert!(response.confidential_response_json.is_some());
    }

    #[tokio::test]
    async fn proxy_models_and_confidentiality_routes_use_client_discovery() {
        let proxy = demo_proxy().await;

        let models = proxy.handle(ProxyHttpRequest::get("/v1/models")).await;
        let confidentiality = proxy
            .handle(ProxyHttpRequest::get("/v1/confidentiality"))
            .await;
        let model_body: Value = serde_json::from_str(&models.body).unwrap();
        let confidentiality_body: Value = serde_json::from_str(&confidentiality.body).unwrap();

        assert_eq!(models.status, 200);
        assert_eq!(model_body["object"], "list");
        assert_eq!(model_body["data"][0]["id"], "gpt-oss-120b");
        assert_eq!(confidentiality.status, 200);
        assert_eq!(confidentiality_body[0]["canonical_model"], "gpt-oss-120b");
        assert_eq!(confidentiality_body[0]["routes"][0]["provider"], "demo");
    }

    #[tokio::test]
    async fn proxy_attestation_route_verifies_without_chat_execution() {
        let proxy = demo_proxy().await;

        let response = proxy
            .handle(ProxyHttpRequest::get("/v1/attestation/demo/gpt-oss-120b"))
            .await;
        let verdict: Value = serde_json::from_str(&response.body).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(verdict["status"], "verified");
        assert_eq!(verdict["provider"], "demo");
        assert_eq!(verdict["route_id"], "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p");
    }

    #[tokio::test]
    async fn proxy_responses_route_uses_compatibility_shim_and_verdict_sidecar() {
        let proxy = demo_proxy().await;
        let request = serde_json::json!({
            "model": "gpt-oss-120b",
            "input": "proxy responses path",
            "max_output_tokens": 64
        });

        let response = proxy
            .handle(ProxyHttpRequest::post_json(
                "/v1/responses",
                serde_json::to_vec(&request).unwrap(),
            ))
            .await;
        let body: Value = serde_json::from_str(&response.body).unwrap();
        let verdict: Value = serde_json::from_str(response.verdict_json.as_ref().unwrap()).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(body["object"], "response");
        assert_eq!(body["status"], "completed");
        assert_eq!(
            body["metadata"]["confidential_inference_compatibility"],
            "responses_to_chat_shim"
        );
        assert_eq!(
            body["output_text"],
            "demo confidential response for e2ee-gpt-oss-120b-p: proxy responses path"
        );
        assert_eq!(verdict["status"], "verified");
        assert!(!response
            .verdict_json
            .unwrap()
            .contains("proxy responses path"));
        assert!(response.confidential_response_json.is_some());
    }

    #[tokio::test]
    async fn proxy_responses_route_fails_closed_for_unsupported_input_and_streaming() {
        let proxy = demo_proxy().await;

        let unsupported_input = proxy
            .handle(ProxyHttpRequest::post_json(
                "/v1/responses",
                serde_json::json!({
                    "model": "gpt-oss-120b",
                    "input": [{
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_image"}]
                    }]
                })
                .to_string(),
            ))
            .await;
        let streaming = proxy
            .handle(ProxyHttpRequest::post_json(
                "/v1/responses",
                serde_json::json!({
                    "model": "gpt-oss-120b",
                    "input": "streaming should fail",
                    "stream": true
                })
                .to_string(),
            ))
            .await;

        assert_eq!(unsupported_input.status, 400);
        assert!(unsupported_input
            .body
            .contains("input content type input_image"));
        assert_eq!(streaming.status, 400);
        assert!(streaming.body.contains("streaming is not supported"));
    }

    #[tokio::test]
    async fn proxy_rejects_invalid_json_and_unknown_routes_as_openai_style_errors() {
        let proxy = demo_proxy().await;

        let invalid_json = proxy
            .handle(ProxyHttpRequest::post_json(
                "/v1/chat/completions",
                b"{not-json".to_vec(),
            ))
            .await;
        let missing = proxy.handle(ProxyHttpRequest::get("/v1/not-a-route")).await;
        let invalid_responses = proxy
            .handle(ProxyHttpRequest::post_json(
                "/v1/responses",
                b"{not-json".to_vec(),
            ))
            .await;

        assert_eq!(invalid_json.status, 400);
        assert!(invalid_json.body.contains("invalid_request_json"));
        assert_eq!(missing.status, 404);
        assert!(missing.body.contains("not_found"));
        assert_eq!(invalid_responses.status, 400);
        assert!(invalid_responses.body.contains("invalid_request_json"));
    }

    #[test]
    fn proxy_maps_registry_cache_errors_to_service_unavailable() {
        let response = client_error_response(&ClientError::RegistryCache(
            "failed to replace cache file".into(),
        ));

        assert_eq!(response.status, 503);
        assert!(response.body.contains("registry_cache_failed"));

        let response = client_error_response(&ClientError::ReferenceValuesCache(
            "failed to replace cache file".into(),
        ));

        assert_eq!(response.status, 503);
        assert!(response.body.contains("reference_values_cache_failed"));
    }

    #[test]
    fn proxy_maps_client_response_json_errors_to_internal_error() {
        let response = client_error_response(&ClientError::ResponseJsonSerialization(
            "synthetic serializer failure".into(),
        ));

        assert_eq!(response.status, 500);
        assert!(response.body.contains("response_serialization_failed"));
    }

    #[test]
    fn proxy_error_responses_redact_sensitive_route_attempt_details() {
        let response = client_error_response(&ClientError::RouteAttemptsFailed {
            model: "gpt-oss-120b".into(),
            errors: vec![
                "provider failed with Authorization: Bearer opaque-proxy-secret api_key=demo-key prompt=private completion=hidden content=payload input=hidden output=answer".into(),
            ],
        });

        assert_eq!(response.status, 502);
        assert!(response.body.contains("upstream_verification_failed"));
        assert!(response.body.contains("[REDACTED]"));
        for leaked in [
            "opaque-proxy-secret",
            "demo-key",
            "private",
            "hidden",
            "payload",
            "answer",
        ] {
            assert!(!response.body.contains(leaked), "{leaked} leaked");
        }
    }

    #[test]
    fn proxy_error_redaction_preserves_non_secret_compatibility_messages() {
        let response = proxy_error_response(
            400,
            "invalid_request",
            "Responses input content type input_image is not supported",
        );

        assert_eq!(response.status, 400);
        assert!(response.body.contains("input content type input_image"));
        assert!(!response.body.contains("[REDACTED]"));
    }

    #[test]
    fn proxy_error_redaction_redacts_compact_json_error_bodies() {
        let response = proxy_error_response(
            502,
            "upstream_verification_failed",
            r#"{"error":{"authorization":"Bearer opaque-json-token","api_key":"json-key","prompt":"private","completion":"hidden","content":"payload","input":"secret-input","output":"secret-output","password":"secret-pass"}}"#,
        );

        assert_eq!(response.status, 502);
        assert!(response.body.contains("[REDACTED]"));
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
            assert!(!response.body.contains(leaked), "{leaked} leaked");
        }
    }

    #[tokio::test]
    async fn proxy_router_construction_validates_security_config() {
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .build()
            .await
            .unwrap();
        let config = ProxyConfig {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 8787)),
            ..ProxyConfig::default()
        };

        assert!(matches!(
            ConfidentialInferenceProxy::from_config(client, config),
            Err(ProxyConfigError::NonLoopbackRequiresAuth { .. })
        ));
    }
}
