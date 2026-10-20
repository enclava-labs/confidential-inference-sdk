use async_trait::async_trait;
use confidential_inference_openai::{
    ChatChoice, ChatCompletionResponse, ChatMessage, EmbeddingsData, EmbeddingsRequest,
    EmbeddingsResponse, EmbeddingsUsage, Usage,
};

use crate::{
    EvidenceRequest, ProviderAdapter, ProviderChatRequest, ProviderEmbeddingsRequest,
    ProviderError, ProviderRegistry, ProviderRequestConfidentiality, Result, RouteDefinition,
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
            request.last_user_message().unwrap_or_default()
        );
        let prompt_tokens = request
            .messages
            .iter()
            .map(|message| {
                message
                    .content
                    .text()
                    .unwrap_or_default()
                    .split_whitespace()
                    .count() as u32
            })
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
                finish_reason: Some("stop".into()),
                extra: Default::default(),
            }],
            usage: Some(Usage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens + completion_tokens,
                extra: Default::default(),
            }),
            extra: Default::default(),
        })
    }

    async fn embeddings(
        &self,
        route: &RouteDefinition,
        request: ProviderEmbeddingsRequest,
    ) -> Result<EmbeddingsResponse> {
        if request.confidentiality() != &ProviderRequestConfidentiality::FixtureEncrypted {
            return Err(ProviderError::Adapter(
                "demo app-E2EE fixture route requires fixture-encrypted request metadata".into(),
            ));
        }
        let request: EmbeddingsRequest =
            serde_json::from_value(request.fixture_decrypted_body(route)?)?;
        if route.provider_model != request.model {
            return Err(ProviderError::Adapter(format!(
                "request model {} was not rewritten to provider model {}",
                request.model, route.provider_model
            )));
        }
        let count = match &request.input {
            confidential_inference_openai::EmbeddingInput::Text(_) => 1,
            confidential_inference_openai::EmbeddingInput::TextArray(values) => values.len(),
            confidential_inference_openai::EmbeddingInput::Tokens(_) => 1,
            confidential_inference_openai::EmbeddingInput::TokenArrays(values) => values.len(),
            confidential_inference_openai::EmbeddingInput::Parts(values) => values.len(),
        };
        Ok(EmbeddingsResponse {
            object: "list".into(),
            data: (0..count)
                .map(|index| EmbeddingsData {
                    object: "embedding".into(),
                    embedding: vec![index as f64, 1.0],
                    index: index as u32,
                    extra: Default::default(),
                })
                .collect(),
            model: route.provider_model.clone(),
            usage: EmbeddingsUsage {
                prompt_tokens: count as u32,
                total_tokens: count as u32,
                extra: Default::default(),
            },
            extra: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn embeddings_decrypts_token_input_and_returns_vectors() {
        let provider = DemoProvider::valid();
        let route = provider.routes().remove(0);
        let request = ProviderEmbeddingsRequest::fixture_encrypt(
            &route,
            json!({
                "model": route.provider_model.clone(),
                "input": [[7, 8], [9]],
                "vendor_option": true
            }),
        )
        .unwrap();
        let response = provider.embeddings(&route, request).await.unwrap();
        assert_eq!(response.data.len(), 2);
        assert_eq!(response.data[1].embedding, vec![1.0, 1.0]);
        assert_eq!(response.model, route.provider_model);
    }
}
