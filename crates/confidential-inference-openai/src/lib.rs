use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::System,
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::User,
            content: content.into(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: content.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

impl ChatCompletionRequest {
    pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Self {
        Self {
            model: model.into(),
            messages,
            stream: None,
            max_tokens: None,
            temperature: None,
        }
    }

    pub fn streaming(&self) -> bool {
        self.stream.unwrap_or(false)
    }

    pub fn with_model(&self, model: impl Into<String>) -> Self {
        let mut request = self.clone();
        request.model = model.into();
        request
    }

    pub fn last_user_message(&self) -> Option<&str> {
        self.messages
            .iter()
            .rev()
            .find(|message| message.role == ChatRole::User)
            .map(|message| message.content.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Model {
    pub id: String,
    pub object: String,
    pub owned_by: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelList {
    pub object: String,
    pub data: Vec<Model>,
}

impl ModelList {
    pub fn new(data: Vec<Model>) -> Self {
        Self {
            object: "list".into(),
            data,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseCreateRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<ResponseInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}

impl ResponseCreateRequest {
    pub fn text(model: impl Into<String>, input: impl Into<String>) -> Self {
        Self {
            model: Some(model.into()),
            input: Some(ResponseInput::Text(input.into())),
            instructions: None,
            stream: None,
            max_output_tokens: None,
            temperature: None,
            metadata: None,
        }
    }

    pub fn to_chat_completion_request(
        &self,
    ) -> Result<ChatCompletionRequest, ResponseCompatibilityError> {
        let model = self
            .model
            .clone()
            .ok_or(ResponseCompatibilityError::MissingModel)?;
        let input = self
            .input
            .as_ref()
            .ok_or(ResponseCompatibilityError::MissingInput)?;
        let mut messages = Vec::new();

        if let Some(instructions) = &self.instructions {
            if !instructions.trim().is_empty() {
                messages.push(ChatMessage::system(instructions.clone()));
            }
        }

        match input {
            ResponseInput::Text(text) => messages.push(ChatMessage::user(text.clone())),
            ResponseInput::Items(items) => {
                if items.is_empty() {
                    return Err(ResponseCompatibilityError::MissingInput);
                }
                for item in items {
                    messages.push(item.to_chat_message()?);
                }
            }
        }

        if messages.is_empty() {
            return Err(ResponseCompatibilityError::MissingInput);
        }

        Ok(ChatCompletionRequest {
            model,
            messages,
            stream: self.stream,
            max_tokens: self.max_output_tokens,
            temperature: self.temperature,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseInput {
    Text(String),
    Items(Vec<ResponseInputItem>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseInputItem {
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub item_type: Option<String>,
    pub role: ResponseInputRole,
    pub content: ResponseInputContent,
}

impl ResponseInputItem {
    pub fn message(role: ResponseInputRole, content: impl Into<String>) -> Self {
        Self {
            item_type: Some("message".into()),
            role,
            content: ResponseInputContent::Text(content.into()),
        }
    }

    fn to_chat_message(&self) -> Result<ChatMessage, ResponseCompatibilityError> {
        if self.item_type.as_deref().unwrap_or("message") != "message" {
            return Err(ResponseCompatibilityError::UnsupportedInputItemType(
                self.item_type
                    .clone()
                    .unwrap_or_else(|| "unknown".to_owned()),
            ));
        }
        let content = self.content.text()?;
        let role = match self.role {
            ResponseInputRole::System | ResponseInputRole::Developer => ChatRole::System,
            ResponseInputRole::User => ChatRole::User,
            ResponseInputRole::Assistant => ChatRole::Assistant,
        };
        Ok(ChatMessage { role, content })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseInputRole {
    System,
    Developer,
    User,
    Assistant,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseInputContent {
    Text(String),
    Parts(Vec<ResponseInputContentPart>),
}

impl ResponseInputContent {
    fn text(&self) -> Result<String, ResponseCompatibilityError> {
        match self {
            Self::Text(text) => Ok(text.clone()),
            Self::Parts(parts) => {
                let mut text = String::new();
                for part in parts {
                    if part.content_type != "input_text" {
                        return Err(ResponseCompatibilityError::UnsupportedInputContentType(
                            part.content_type.clone(),
                        ));
                    }
                    let Some(part_text) = &part.text else {
                        return Err(ResponseCompatibilityError::MissingInputText);
                    };
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(part_text);
                }
                if text.is_empty() {
                    Err(ResponseCompatibilityError::MissingInputText)
                } else {
                    Ok(text)
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseInputContentPart {
    #[serde(rename = "type")]
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseCompatibilityError {
    MissingModel,
    MissingInput,
    MissingInputText,
    UnsupportedInputItemType(String),
    UnsupportedInputContentType(String),
}

impl Display for ResponseCompatibilityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingModel => write!(formatter, "Responses compatibility requires a model"),
            Self::MissingInput => write!(formatter, "Responses compatibility requires input"),
            Self::MissingInputText => {
                write!(
                    formatter,
                    "Responses compatibility requires text input content"
                )
            }
            Self::UnsupportedInputItemType(item_type) => write!(
                formatter,
                "Responses-to-chat compatibility does not support input item type {item_type}"
            ),
            Self::UnsupportedInputContentType(content_type) => write!(
                formatter,
                "Responses-to-chat compatibility does not support input content type {content_type}"
            ),
        }
    }
}

impl std::error::Error for ResponseCompatibilityError {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseObject {
    pub id: String,
    pub object: String,
    pub created_at: u64,
    pub status: String,
    pub model: String,
    pub output: Vec<ResponseOutputItem>,
    pub output_text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl ResponseObject {
    pub fn from_chat_completion(response: ChatCompletionResponse) -> Self {
        let output = response
            .choices
            .iter()
            .map(|choice| {
                ResponseOutputItem::message(
                    format!("msg_{}_{}", response.id, choice.index),
                    choice.message.content.clone(),
                    choice.finish_reason.clone(),
                )
            })
            .collect::<Vec<_>>();
        let output_text = response
            .choices
            .first()
            .map(|choice| choice.message.content.clone())
            .unwrap_or_default();
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "confidential_inference_compatibility".into(),
            "responses_to_chat_shim".into(),
        );
        metadata.insert("native_provider_responses_api".into(), "false".into());

        Self {
            id: format!("resp_{}", response.id),
            object: "response".into(),
            created_at: response.created,
            status: "completed".into(),
            model: response.model,
            output,
            output_text,
            usage: response.usage,
            metadata,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseOutputItem {
    pub id: String,
    #[serde(rename = "type")]
    pub item_type: String,
    pub status: String,
    pub role: String,
    pub content: Vec<ResponseOutputContent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

impl ResponseOutputItem {
    pub fn message(id: String, text: String, finish_reason: String) -> Self {
        Self {
            id,
            item_type: "message".into(),
            status: "completed".into(),
            role: "assistant".into(),
            content: vec![ResponseOutputContent::output_text(text)],
            finish_reason: Some(finish_reason),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseOutputContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
    #[serde(default)]
    pub annotations: Vec<Value>,
}

impl ResponseOutputContent {
    pub fn output_text(text: String) -> Self {
        Self {
            content_type: "output_text".into(),
            text,
            annotations: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses_text_input_converts_to_chat_request() {
        let request = ResponseCreateRequest::text("gpt-oss-120b", "hello");

        let chat = request.to_chat_completion_request().unwrap();

        assert_eq!(chat.model, "gpt-oss-120b");
        assert_eq!(chat.messages, vec![ChatMessage::user("hello")]);
    }

    #[test]
    fn responses_message_parts_convert_to_chat_request_with_instructions() {
        let request = ResponseCreateRequest {
            model: Some("gpt-oss-120b".into()),
            input: Some(ResponseInput::Items(vec![ResponseInputItem {
                item_type: Some("message".into()),
                role: ResponseInputRole::User,
                content: ResponseInputContent::Parts(vec![
                    ResponseInputContentPart {
                        content_type: "input_text".into(),
                        text: Some("hello".into()),
                    },
                    ResponseInputContentPart {
                        content_type: "input_text".into(),
                        text: Some("world".into()),
                    },
                ]),
            }])),
            instructions: Some("be brief".into()),
            stream: Some(false),
            max_output_tokens: Some(32),
            temperature: Some(0.2),
            metadata: None,
        };

        let chat = request.to_chat_completion_request().unwrap();

        assert_eq!(chat.messages[0], ChatMessage::system("be brief"));
        assert_eq!(chat.messages[1], ChatMessage::user("hello\nworld"));
        assert_eq!(chat.max_tokens, Some(32));
        assert_eq!(chat.temperature, Some(0.2));
    }

    #[test]
    fn responses_non_text_content_fails_closed_for_shim() {
        let request = ResponseCreateRequest {
            model: Some("gpt-oss-120b".into()),
            input: Some(ResponseInput::Items(vec![ResponseInputItem {
                item_type: Some("message".into()),
                role: ResponseInputRole::User,
                content: ResponseInputContent::Parts(vec![ResponseInputContentPart {
                    content_type: "input_image".into(),
                    text: None,
                }]),
            }])),
            instructions: None,
            stream: None,
            max_output_tokens: None,
            temperature: None,
            metadata: None,
        };

        let error = request.to_chat_completion_request().unwrap_err();

        assert_eq!(
            error,
            ResponseCompatibilityError::UnsupportedInputContentType("input_image".into())
        );
    }

    #[test]
    fn response_object_marks_chat_shim_compatibility() {
        let response = ChatCompletionResponse {
            id: "chatcmpl-demo".into(),
            object: "chat.completion".into(),
            created: 1,
            model: "e2ee-gpt-oss-120b-p".into(),
            choices: vec![ChatChoice {
                index: 0,
                message: ChatMessage::assistant("ok"),
                finish_reason: "stop".into(),
            }],
            usage: Some(Usage {
                prompt_tokens: 1,
                completion_tokens: 1,
                total_tokens: 2,
            }),
        };

        let response = ResponseObject::from_chat_completion(response);

        assert_eq!(response.object, "response");
        assert_eq!(response.output_text, "ok");
        assert_eq!(
            response
                .metadata
                .get("confidential_inference_compatibility"),
            Some(&"responses_to_chat_shim".to_owned())
        );
    }
}
