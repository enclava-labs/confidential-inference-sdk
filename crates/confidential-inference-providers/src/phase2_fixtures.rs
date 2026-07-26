use async_trait::async_trait;
use confidential_inference_openai::{ChatChoice, ChatCompletionResponse, ChatMessage, Usage};

use crate::{
    EvidenceRequest, ProviderAdapter, ProviderChatRequest, ProviderError, ProviderRegistry,
    ProviderRequestConfidentiality, Result, RouteDefinition,
};

#[derive(Clone, Debug, Default)]
pub struct TinfoilFixtureProvider;

impl TinfoilFixtureProvider {
    pub fn valid() -> Self {
        Self
    }
}

#[async_trait]
impl ProviderAdapter for TinfoilFixtureProvider {
    fn provider_id(&self) -> &str {
        "tinfoil-fixture"
    }

    fn routes(&self) -> Vec<RouteDefinition> {
        phase2_routes(self.provider_id())
    }

    async fn fetch_evidence(
        &self,
        route: &RouteDefinition,
        _request: &EvidenceRequest,
    ) -> Result<Vec<u8>> {
        ensure_route_provider(route, self.provider_id())?;
        Ok(include_bytes!("../assets/evidence/tinfoil-valid.json").to_vec())
    }

    async fn chat(
        &self,
        route: &RouteDefinition,
        request: ProviderChatRequest,
    ) -> Result<ChatCompletionResponse> {
        if request.confidentiality() != &ProviderRequestConfidentiality::Plaintext {
            return Err(ProviderError::Adapter(
                "tinfoil TLS fixture route expects plaintext-over-verified-TLS request metadata"
                    .into(),
            ));
        }

        let request = request.to_openai_request()?;
        if route.provider_model != request.model {
            return Err(ProviderError::Adapter(format!(
                "request model {} was not rewritten to provider model {}",
                request.model, route.provider_model
            )));
        }

        let content = format!(
            "tinfoil fixture response for {}: {}",
            route.provider_model,
            request.last_user_message().unwrap_or("")
        );
        let prompt_tokens = request
            .messages
            .iter()
            .map(|message| message.content.split_whitespace().count() as u32)
            .sum::<u32>();
        let completion_tokens = content.split_whitespace().count() as u32;

        Ok(ChatCompletionResponse {
            id: "chatcmpl-tinfoil-fixture".into(),
            object: "chat.completion".into(),
            created: 1_783_209_600,
            model: route.provider_model.clone(),
            choices: vec![ChatChoice {
                index: 0,
                message: ChatMessage::assistant(content),
                finish_reason: "stop".into(),
            }],
            usage: Some(Usage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens + completion_tokens,
            }),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct VeniceFixtureProvider;

impl VeniceFixtureProvider {
    pub fn valid() -> Self {
        Self
    }
}

#[async_trait]
impl ProviderAdapter for VeniceFixtureProvider {
    fn provider_id(&self) -> &str {
        "venice-fixture"
    }

    fn routes(&self) -> Vec<RouteDefinition> {
        phase2_routes(self.provider_id())
    }

    async fn fetch_evidence(
        &self,
        route: &RouteDefinition,
        _request: &EvidenceRequest,
    ) -> Result<Vec<u8>> {
        ensure_route_provider(route, self.provider_id())?;
        Ok(include_bytes!("../assets/evidence/venice-dstack-valid.json").to_vec())
    }

    async fn chat(
        &self,
        _route: &RouteDefinition,
        _request: ProviderChatRequest,
    ) -> Result<ChatCompletionResponse> {
        Err(ProviderError::Compatibility(
            "venice-fixture is verification-only until SDK-managed app encryption is implemented"
                .into(),
        ))
    }
}

fn phase2_routes(provider: &str) -> Vec<RouteDefinition> {
    ProviderRegistry::phase2_fixtures()
        .ok()
        .map(|registry| {
            registry
                .models
                .values()
                .flat_map(|model| model.routes.iter())
                .filter(|route| route.provider == provider)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn ensure_route_provider(route: &RouteDefinition, provider: &str) -> Result<()> {
    if route.provider == provider {
        Ok(())
    } else {
        Err(ProviderError::Adapter(format!(
            "route {} does not belong to provider {}",
            route.route_id, provider
        )))
    }
}
