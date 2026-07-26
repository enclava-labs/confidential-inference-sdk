use async_trait::async_trait;
use confidential_inference_openai::{ChatChoice, ChatCompletionResponse, ChatMessage, Usage};

use crate::{
    EvidenceRequest, ProviderAdapter, ProviderChatRequest, ProviderError, ProviderRegistry,
    ProviderRequestConfidentiality, Result, RouteDefinition,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DemoEvidenceMode {
    Valid,
    WrongModel,
    WrongKey,
}

#[derive(Clone, Debug)]
pub struct DemoProvider {
    evidence_mode: DemoEvidenceMode,
}

impl DemoProvider {
    pub fn valid() -> Self {
        Self {
            evidence_mode: DemoEvidenceMode::Valid,
        }
    }

    pub fn wrong_model() -> Self {
        Self {
            evidence_mode: DemoEvidenceMode::WrongModel,
        }
    }

    pub fn wrong_key() -> Self {
        Self {
            evidence_mode: DemoEvidenceMode::WrongKey,
        }
    }

    fn evidence_bytes(&self) -> &'static [u8] {
        match self.evidence_mode {
            DemoEvidenceMode::Valid => include_bytes!("../assets/evidence/demo-valid.json"),
            DemoEvidenceMode::WrongModel => {
                include_bytes!("../assets/evidence/demo-wrong-model.json")
            }
            DemoEvidenceMode::WrongKey => {
                include_bytes!("../assets/evidence/demo-wrong-key.json")
            }
        }
    }
}

impl Default for DemoProvider {
    fn default() -> Self {
        Self::valid()
    }
}

#[async_trait]
impl ProviderAdapter for DemoProvider {
    fn provider_id(&self) -> &str {
        "demo"
    }

    fn routes(&self) -> Vec<RouteDefinition> {
        ProviderRegistry::bundled_demo()
            .ok()
            .and_then(|registry| {
                registry
                    .find_route(Some("demo"), "gpt-oss-120b")
                    .map(|(_, route)| vec![route.clone()])
            })
            .unwrap_or_default()
    }

    async fn fetch_evidence(
        &self,
        route: &RouteDefinition,
        _request: &EvidenceRequest,
    ) -> Result<Vec<u8>> {
        if route.provider != self.provider_id() {
            return Err(ProviderError::Adapter(format!(
                "route {} does not belong to demo provider",
                route.route_id
            )));
        }
        Ok(self.evidence_bytes().to_vec())
    }

    async fn chat(
        &self,
        route: &RouteDefinition,
        request: ProviderChatRequest,
    ) -> Result<ChatCompletionResponse> {
        if request.confidentiality() != &ProviderRequestConfidentiality::FixtureEncrypted {
            return Err(ProviderError::Adapter(
                "demo app-E2EE fixture route requires fixture-encrypted request metadata".into(),
            ));
        }

        let request = request.to_fixture_decrypted_openai_request(route)?;
        if route.provider_model != request.model {
            return Err(ProviderError::Adapter(format!(
                "request model {} was not rewritten to provider model {}",
                request.model, route.provider_model
            )));
        }

        let content = format!(
            "demo confidential response for {}: {}",
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
            id: "chatcmpl-demo-fixture".into(),
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
