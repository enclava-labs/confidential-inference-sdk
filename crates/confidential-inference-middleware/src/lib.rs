//! Middleware helpers that sit above `confidential-inference-sdk`.
//!
//! This crate does not reimplement routing, request adaptation, or attestation.
//! It adapts OpenAI-shaped chat and Responses requests into the native SDK path
//! and exposes verdict material beside OpenAI-compatible response JSON for
//! callers that already have HTTP or Tower-style integration points.

use confidential_inference_openai::{
    ChatCompletionRequest, ChatCompletionResponse, ResponseCreateRequest, ResponseObject,
};
use confidential_inference_sdk::{
    ClientError, ConfidentialInference, ConfidentialResponse, Result as ClientResult,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tower_layer::Layer;
use tower_service::Service;

pub type Result<T> = std::result::Result<T, MiddlewareError>;

#[derive(Debug, Error)]
pub enum MiddlewareError {
    #[error(transparent)]
    Client(#[from] ClientError),

    #[error("failed to parse OpenAI request JSON: {0}")]
    InvalidRequestJson(#[source] serde_json::Error),

    #[error("failed to serialize OpenAI response JSON: {0}")]
    ResponseJson(#[source] serde_json::Error),

    #[error("failed to serialize attestation verdict JSON: {0}")]
    VerdictJson(#[source] serde_json::Error),

    #[error("failed to serialize confidential response JSON: {0}")]
    ConfidentialResponseJson(#[source] serde_json::Error),

    #[error("unsupported reqwest request {method} {path}")]
    UnsupportedReqwestRequest { method: String, path: String },

    #[error("reqwest request body is missing")]
    MissingReqwestBody,

    #[error("reqwest request body must be buffered before middleware verification")]
    StreamingReqwestBody,
}

#[derive(Clone)]
pub struct VerifiedChatService {
    client: ConfidentialInference,
}

#[derive(Clone)]
pub struct VerifiedChatLayer {
    client: ConfidentialInference,
}

impl VerifiedChatLayer {
    pub fn new(client: ConfidentialInference) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &ConfidentialInference {
        &self.client
    }

    pub fn service(&self) -> VerifiedChatService {
        VerifiedChatService::new(self.client.clone())
    }
}

impl<S> Layer<S> for VerifiedChatLayer {
    type Service = VerifiedChatService;

    fn layer(&self, _inner: S) -> Self::Service {
        self.service()
    }
}

impl VerifiedChatService {
    pub fn new(client: ConfidentialInference) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &ConfidentialInference {
        &self.client
    }

    pub async fn chat(
        &self,
        request: ChatCompletionRequest,
    ) -> ClientResult<ConfidentialResponse<ChatCompletionResponse>> {
        send_chat_request(self.client.clone(), request).await
    }

    pub async fn chat_json(
        &self,
        request_body: impl AsRef<[u8]>,
    ) -> Result<VerifiedChatJsonResponse> {
        let request = serde_json::from_slice(request_body.as_ref())
            .map_err(MiddlewareError::InvalidRequestJson)?;
        let response = self.chat(request).await?;
        VerifiedChatJsonResponse::from_confidential_response(&response)
    }

    pub async fn response(
        &self,
        request: ResponseCreateRequest,
    ) -> ClientResult<ConfidentialResponse<ResponseObject>> {
        self.client.create_response(request).await
    }

    pub async fn response_json(
        &self,
        request_body: impl AsRef<[u8]>,
    ) -> Result<VerifiedResponseJsonResponse> {
        let request = serde_json::from_slice(request_body.as_ref())
            .map_err(MiddlewareError::InvalidRequestJson)?;
        let response = self.response(request).await?;
        VerifiedResponseJsonResponse::from_confidential_response(&response)
    }

    pub async fn reqwest_request(&self, request: reqwest::Request) -> Result<VerifiedHttpResponse> {
        if request.method() != reqwest::Method::POST {
            return Err(MiddlewareError::UnsupportedReqwestRequest {
                method: request.method().as_str().to_owned(),
                path: request.url().path().to_owned(),
            });
        }

        let body = request_body_bytes(&request)?;
        match request.url().path() {
            "/v1/chat/completions" => {
                let response = self.chat_json(body).await?;
                Ok(VerifiedHttpResponse::from_chat_json_response(response))
            }
            "/v1/responses" => {
                let response = self.response_json(body).await?;
                Ok(VerifiedHttpResponse::from_response_json_response(response))
            }
            path => Err(MiddlewareError::UnsupportedReqwestRequest {
                method: request.method().as_str().to_owned(),
                path: path.to_owned(),
            }),
        }
    }
}

impl Service<ChatCompletionRequest> for VerifiedChatService {
    type Response = ConfidentialResponse<ChatCompletionResponse>;
    type Error = ClientError;
    type Future = Pin<Box<dyn Future<Output = ClientResult<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<ClientResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: ChatCompletionRequest) -> Self::Future {
        let client = self.client.clone();
        Box::pin(async move { send_chat_request(client, request).await })
    }
}

impl Service<ResponseCreateRequest> for VerifiedChatService {
    type Response = ConfidentialResponse<ResponseObject>;
    type Error = ClientError;
    type Future = Pin<Box<dyn Future<Output = ClientResult<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<ClientResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: ResponseCreateRequest) -> Self::Future {
        let client = self.client.clone();
        Box::pin(async move { client.create_response(request).await })
    }
}

impl Service<reqwest::Request> for VerifiedChatService {
    type Response = VerifiedHttpResponse;
    type Error = MiddlewareError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: reqwest::Request) -> Self::Future {
        let service = self.clone();
        Box::pin(async move { service.reqwest_request(request).await })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedChatJsonResponse {
    pub openai_response_json: String,
    pub verdict_json: String,
    pub confidential_response_json: String,
    pub verdict_status: String,
    pub response_integrity_result: String,
    pub provider: String,
    pub provider_model: String,
    pub requested_model: String,
    pub route_id: String,
    pub response_channel_bound: bool,
    pub request_allowed: bool,
}

impl VerifiedChatJsonResponse {
    fn from_confidential_response(
        response: &ConfidentialResponse<ChatCompletionResponse>,
    ) -> Result<Self> {
        let openai_response_json =
            serde_json::to_string(&response.response).map_err(MiddlewareError::ResponseJson)?;
        let verdict_json =
            serde_json::to_string(&response.verdict).map_err(MiddlewareError::VerdictJson)?;
        let confidential_response_json =
            serde_json::to_string(response).map_err(MiddlewareError::ConfidentialResponseJson)?;

        Ok(Self {
            openai_response_json,
            verdict_json,
            confidential_response_json,
            verdict_status: json_enum_header_value(&response.verdict.status),
            response_integrity_result: json_enum_header_value(
                &response.verdict.response_integrity_result,
            ),
            provider: response.provider.clone(),
            provider_model: response.provider_model.clone(),
            requested_model: response.requested_model.clone(),
            route_id: response.route.route_id.clone(),
            response_channel_bound: response.response_channel_bound,
            request_allowed: response.verdict.request_allowed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedResponseJsonResponse {
    pub openai_response_json: String,
    pub verdict_json: String,
    pub confidential_response_json: String,
    pub verdict_status: String,
    pub response_integrity_result: String,
    pub provider: String,
    pub provider_model: String,
    pub requested_model: String,
    pub route_id: String,
    pub response_channel_bound: bool,
    pub request_allowed: bool,
}

impl VerifiedResponseJsonResponse {
    fn from_confidential_response(response: &ConfidentialResponse<ResponseObject>) -> Result<Self> {
        let openai_response_json =
            serde_json::to_string(&response.response).map_err(MiddlewareError::ResponseJson)?;
        let verdict_json =
            serde_json::to_string(&response.verdict).map_err(MiddlewareError::VerdictJson)?;
        let confidential_response_json =
            serde_json::to_string(response).map_err(MiddlewareError::ConfidentialResponseJson)?;

        Ok(Self {
            openai_response_json,
            verdict_json,
            confidential_response_json,
            verdict_status: json_enum_header_value(&response.verdict.status),
            response_integrity_result: json_enum_header_value(
                &response.verdict.response_integrity_result,
            ),
            provider: response.provider.clone(),
            provider_model: response.provider_model.clone(),
            requested_model: response.requested_model.clone(),
            route_id: response.route.route_id.clone(),
            response_channel_bound: response.response_channel_bound,
            request_allowed: response.verdict.request_allowed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body_json: String,
    pub verdict_json: String,
    pub confidential_response_json: String,
    pub provider: String,
    pub provider_model: String,
    pub requested_model: String,
    pub route_id: String,
    pub response_channel_bound: bool,
    pub request_allowed: bool,
}

impl VerifiedHttpResponse {
    fn from_chat_json_response(response: VerifiedChatJsonResponse) -> Self {
        Self {
            status: 200,
            headers: response_headers(&response),
            body_json: response.openai_response_json,
            verdict_json: response.verdict_json,
            confidential_response_json: response.confidential_response_json,
            provider: response.provider,
            provider_model: response.provider_model,
            requested_model: response.requested_model,
            route_id: response.route_id,
            response_channel_bound: response.response_channel_bound,
            request_allowed: response.request_allowed,
        }
    }

    fn from_response_json_response(response: VerifiedResponseJsonResponse) -> Self {
        Self {
            status: 200,
            headers: response_headers(&response),
            body_json: response.openai_response_json,
            verdict_json: response.verdict_json,
            confidential_response_json: response.confidential_response_json,
            provider: response.provider,
            provider_model: response.provider_model,
            requested_model: response.requested_model,
            route_id: response.route_id,
            response_channel_bound: response.response_channel_bound,
            request_allowed: response.request_allowed,
        }
    }
}

trait VerifiedJsonMetadata {
    fn provider(&self) -> &str;
    fn provider_model(&self) -> &str;
    fn requested_model(&self) -> &str;
    fn route_id(&self) -> &str;
    fn verdict_status(&self) -> &str;
    fn response_integrity_result(&self) -> &str;
}

impl VerifiedJsonMetadata for VerifiedChatJsonResponse {
    fn provider(&self) -> &str {
        &self.provider
    }

    fn provider_model(&self) -> &str {
        &self.provider_model
    }

    fn requested_model(&self) -> &str {
        &self.requested_model
    }

    fn route_id(&self) -> &str {
        &self.route_id
    }

    fn verdict_status(&self) -> &str {
        &self.verdict_status
    }

    fn response_integrity_result(&self) -> &str {
        &self.response_integrity_result
    }
}

impl VerifiedJsonMetadata for VerifiedResponseJsonResponse {
    fn provider(&self) -> &str {
        &self.provider
    }

    fn provider_model(&self) -> &str {
        &self.provider_model
    }

    fn requested_model(&self) -> &str {
        &self.requested_model
    }

    fn route_id(&self) -> &str {
        &self.route_id
    }

    fn verdict_status(&self) -> &str {
        &self.verdict_status
    }

    fn response_integrity_result(&self) -> &str {
        &self.response_integrity_result
    }
}

fn response_headers(response: &impl VerifiedJsonMetadata) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("content-type".to_owned(), "application/json".to_owned()),
        (
            "x-confidential-inference-provider".to_owned(),
            response.provider().to_owned(),
        ),
        (
            "x-confidential-inference-provider-model".to_owned(),
            response.provider_model().to_owned(),
        ),
        (
            "x-confidential-inference-requested-model".to_owned(),
            response.requested_model().to_owned(),
        ),
        (
            "x-confidential-inference-route-id".to_owned(),
            response.route_id().to_owned(),
        ),
        (
            "x-confidential-inference-verdict-status".to_owned(),
            response.verdict_status().to_owned(),
        ),
        (
            "x-confidential-inference-response-integrity".to_owned(),
            response.response_integrity_result().to_owned(),
        ),
    ])
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiddlewareStatus {
    pub implemented: bool,
    pub reason: &'static str,
}

pub fn status() -> MiddlewareStatus {
    MiddlewareStatus {
        implemented: true,
        reason: "verified chat/Responses service, reqwest wrapper, Tower layer/service, and JSON bridge delegate to confidential-inference-sdk",
    }
}

async fn send_chat_request(
    client: ConfidentialInference,
    request: ChatCompletionRequest,
) -> ClientResult<ConfidentialResponse<ChatCompletionResponse>> {
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

fn request_body_bytes(request: &reqwest::Request) -> Result<&[u8]> {
    let body = request.body().ok_or(MiddlewareError::MissingReqwestBody)?;
    body.as_bytes().ok_or(MiddlewareError::StreamingReqwestBody)
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidential_inference_openai::ChatMessage;
    use serde_json::Value;

    async fn demo_service() -> VerifiedChatService {
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .build()
            .await
            .unwrap();
        VerifiedChatService::new(client)
    }

    #[tokio::test]
    async fn verified_chat_service_delegates_to_sdk_client() {
        let service = demo_service().await;

        let response = service
            .chat(ChatCompletionRequest::new(
                "gpt-oss-120b",
                vec![ChatMessage::user("middleware native path")],
            ))
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(response.provider_model, "e2ee-gpt-oss-120b-p");
        assert!(response.verdict.request_allowed);
        assert!(response.response_channel_bound);
        assert_eq!(
            response.response.choices[0].message.content,
            "demo confidential response for e2ee-gpt-oss-120b-p: middleware native path"
        );
    }

    #[tokio::test]
    async fn tower_service_path_uses_same_verified_chat_flow() {
        let mut service = demo_service().await;

        let response = service
            .call(ChatCompletionRequest::new(
                "gpt-oss-120b",
                vec![ChatMessage::user("tower path")],
            ))
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert!(response.verdict.request_allowed);
        assert!(response.response_channel_bound);
        assert_eq!(
            response.response.choices[0].message.content,
            "demo confidential response for e2ee-gpt-oss-120b-p: tower path"
        );
    }

    #[tokio::test]
    async fn tower_layer_constructs_verified_service_from_sdk_client() {
        let service = demo_service().await;
        let layer = VerifiedChatLayer::new(service.client().clone());
        let mut layered = layer.layer(());

        let response = layered
            .call(ChatCompletionRequest::new(
                "gpt-oss-120b",
                vec![ChatMessage::user("tower layer path")],
            ))
            .await
            .unwrap();

        assert_eq!(layer.client().models().data[0].id, "gpt-oss-120b");
        assert_eq!(response.provider, "demo");
        assert!(response.verdict.request_allowed);
        assert!(response.response_channel_bound);
        assert_eq!(
            response.response.choices[0].message.content,
            "demo confidential response for e2ee-gpt-oss-120b-p: tower layer path"
        );
    }

    #[tokio::test]
    async fn verified_response_service_delegates_to_sdk_client() {
        let service = demo_service().await;

        let response = service
            .response(ResponseCreateRequest::text(
                "gpt-oss-120b",
                "middleware responses path",
            ))
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(response.provider_model, "e2ee-gpt-oss-120b-p");
        assert!(response.verdict.request_allowed);
        assert!(response.response_channel_bound);
        assert_eq!(response.response.object, "response");
        assert_eq!(
            response
                .response
                .metadata
                .get("confidential_inference_compatibility"),
            Some(&"responses_to_chat_shim".to_owned())
        );
        assert_eq!(
            response.response.output_text,
            "demo confidential response for e2ee-gpt-oss-120b-p: middleware responses path"
        );
    }

    #[tokio::test]
    async fn tower_service_path_uses_same_verified_responses_flow() {
        let mut service = demo_service().await;

        let response = Service::<ResponseCreateRequest>::call(
            &mut service,
            ResponseCreateRequest::text("gpt-oss-120b", "tower responses path"),
        )
        .await
        .unwrap();

        assert_eq!(response.provider, "demo");
        assert!(response.verdict.request_allowed);
        assert!(response.response_channel_bound);
        assert_eq!(
            response.response.output_text,
            "demo confidential response for e2ee-gpt-oss-120b-p: tower responses path"
        );
    }

    #[tokio::test]
    async fn json_bridge_returns_openai_body_and_verdict_sidecar() {
        let service = demo_service().await;
        let request =
            ChatCompletionRequest::new("gpt-oss-120b", vec![ChatMessage::user("json bridge path")]);
        let request_json = serde_json::to_vec(&request).unwrap();

        let response = service.chat_json(request_json).await.unwrap();
        let openai_response: Value = serde_json::from_str(&response.openai_response_json).unwrap();
        let verdict: Value = serde_json::from_str(&response.verdict_json).unwrap();
        let confidential: Value =
            serde_json::from_str(&response.confidential_response_json).unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(response.provider_model, "e2ee-gpt-oss-120b-p");
        assert_eq!(response.route_id, "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p");
        assert!(response.response_channel_bound);
        assert!(response.request_allowed);
        assert_eq!(openai_response["object"], "chat.completion");
        assert_eq!(openai_response["model"], "e2ee-gpt-oss-120b-p");
        assert!(openai_response.get("verdict").is_none());
        assert_eq!(verdict["status"], "verified");
        assert_eq!(verdict["request_allowed"], true);
        assert_eq!(confidential["verdict"]["status"], "verified");
        assert!(!response.verdict_json.contains("json bridge path"));
    }

    #[tokio::test]
    async fn response_json_bridge_returns_response_body_and_verdict_sidecar() {
        let service = demo_service().await;
        let request = ResponseCreateRequest::text("gpt-oss-120b", "response json bridge path");
        let request_json = serde_json::to_vec(&request).unwrap();

        let response = service.response_json(request_json).await.unwrap();
        let openai_response: Value = serde_json::from_str(&response.openai_response_json).unwrap();
        let verdict: Value = serde_json::from_str(&response.verdict_json).unwrap();
        let confidential: Value =
            serde_json::from_str(&response.confidential_response_json).unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(response.provider_model, "e2ee-gpt-oss-120b-p");
        assert_eq!(response.route_id, "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p");
        assert!(response.response_channel_bound);
        assert!(response.request_allowed);
        assert_eq!(openai_response["object"], "response");
        assert_eq!(
            openai_response["metadata"]["confidential_inference_compatibility"],
            "responses_to_chat_shim"
        );
        assert!(openai_response.get("verdict").is_none());
        assert_eq!(verdict["status"], "verified");
        assert_eq!(verdict["request_allowed"], true);
        assert_eq!(confidential["verdict"]["status"], "verified");
        assert!(!response.verdict_json.contains("response json bridge path"));
    }

    #[tokio::test]
    async fn reqwest_wrapper_handles_chat_completion_request() {
        let service = demo_service().await;
        let request =
            ChatCompletionRequest::new("gpt-oss-120b", vec![ChatMessage::user("reqwest path")]);
        let reqwest_request = reqwest_post(
            "/v1/chat/completions",
            serde_json::to_vec(&request).unwrap(),
        );

        let response = service.reqwest_request(reqwest_request).await.unwrap();
        let body: Value = serde_json::from_str(&response.body_json).unwrap();
        let verdict: Value = serde_json::from_str(&response.verdict_json).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.headers["content-type"], "application/json");
        assert_eq!(
            response.headers["x-confidential-inference-route-id"],
            response.route_id
        );
        assert_eq!(
            response.headers["x-confidential-inference-verdict-status"],
            "verified"
        );
        assert_eq!(
            response.headers["x-confidential-inference-response-integrity"],
            "channel_bound"
        );
        assert_eq!(body["object"], "chat.completion");
        assert!(body.get("verdict").is_none());
        assert_eq!(verdict["status"], "verified");
        assert!(!response.verdict_json.contains("reqwest path"));
    }

    #[tokio::test]
    async fn tower_service_handles_buffered_reqwest_request() {
        let mut service = demo_service().await;
        let request = ChatCompletionRequest::new(
            "gpt-oss-120b",
            vec![ChatMessage::user("tower reqwest path")],
        );
        let reqwest_request = reqwest_post(
            "/v1/chat/completions",
            serde_json::to_vec(&request).unwrap(),
        );

        let response = Service::<reqwest::Request>::call(&mut service, reqwest_request)
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&response.body_json).unwrap();
        let verdict: Value = serde_json::from_str(&response.verdict_json).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers["x-confidential-inference-verdict-status"],
            "verified"
        );
        assert_eq!(
            response.headers["x-confidential-inference-response-integrity"],
            "channel_bound"
        );
        assert_eq!(body["object"], "chat.completion");
        assert!(body.get("verdict").is_none());
        assert_eq!(verdict["status"], "verified");
        assert!(!response.verdict_json.contains("tower reqwest path"));
    }

    #[tokio::test]
    async fn reqwest_wrapper_handles_responses_request() {
        let service = demo_service().await;
        let request = ResponseCreateRequest::text("gpt-oss-120b", "reqwest responses path");
        let reqwest_request = reqwest_post("/v1/responses", serde_json::to_vec(&request).unwrap());

        let response = service.reqwest_request(reqwest_request).await.unwrap();
        let body: Value = serde_json::from_str(&response.body_json).unwrap();
        let verdict: Value = serde_json::from_str(&response.verdict_json).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers["x-confidential-inference-verdict-status"],
            "verified"
        );
        assert_eq!(
            response.headers["x-confidential-inference-response-integrity"],
            "channel_bound"
        );
        assert_eq!(body["object"], "response");
        assert_eq!(
            body["metadata"]["confidential_inference_compatibility"],
            "responses_to_chat_shim"
        );
        assert!(body.get("verdict").is_none());
        assert_eq!(verdict["status"], "verified");
        assert!(!response.verdict_json.contains("reqwest responses path"));
    }

    #[tokio::test]
    async fn reqwest_wrapper_rejects_unsupported_request_shape() {
        let service = demo_service().await;
        let request = reqwest_post("/v1/not-supported", b"{}".to_vec());

        let error = service.reqwest_request(request).await.unwrap_err();

        assert!(matches!(
            error,
            MiddlewareError::UnsupportedReqwestRequest { .. }
        ));
    }

    #[tokio::test]
    async fn json_bridge_rejects_invalid_openai_request_json() {
        let service = demo_service().await;

        let error = service.chat_json(b"{not-json").await.unwrap_err();

        assert!(matches!(error, MiddlewareError::InvalidRequestJson(_)));
    }

    #[test]
    fn status_reports_implemented_middleware_surface() {
        let status = status();

        assert!(status.implemented);
        assert!(status.reason.contains("confidential-inference-sdk"));
        assert!(status.reason.contains("Tower layer/service"));
    }

    fn reqwest_post(path: &str, body: Vec<u8>) -> reqwest::Request {
        let url = reqwest::Url::parse(&format!("http://localhost{path}")).unwrap();
        let mut request = reqwest::Request::new(reqwest::Method::POST, url);
        *request.body_mut() = Some(reqwest::Body::from(body));
        request
    }
}
