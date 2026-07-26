use confidential_inference_attestation::{
    canonical_digest, verify_artifact_signature_with_keys, ArtifactSignature, FreshnessClass,
    TrustTier, TrustedSigningKey,
};
use confidential_inference_openai::ChatCompletionRequest;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    EncryptionRequirement, ProviderChatRequest, ProviderError, ProviderRegistry,
    ProviderRequestConfidentiality, RouteDefinition, SdkAppE2eeConfig, StreamingSupport,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCompatibilityMatrix {
    pub schema: String,
    pub providers: BTreeMap<String, ProviderCompatibility>,
}

impl ProviderCompatibilityMatrix {
    pub const SCHEMA: &'static str = "confidential-inference.provider-compatibility-matrix.v1";
    pub const SUPPORTED_SCHEMA_MAJOR: u32 = 1;

    pub fn bundled() -> crate::Result<Self> {
        ProviderCompatibilityMatrixEnvelope::bundled()?.into_verified_payload()
    }

    pub fn digest(&self) -> crate::Result<String> {
        validate_compatibility_matrix_schema_major("schema", &self.schema)?;
        canonical_digest(self).map_err(|error| ProviderError::Compatibility(error.to_string()))
    }

    #[cfg(test)]
    fn bundled_raw_fixture() -> crate::Result<Self> {
        let matrix = serde_json::from_str(include_str!(
            "../../../fixtures/providers/compatibility-matrix.json"
        ))?;
        Ok(matrix)
    }

    pub fn validate(&self) -> crate::Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(ProviderError::Compatibility(format!(
                "unsupported compatibility matrix schema {}",
                self.schema
            )));
        }

        let mut seen_api_bases = BTreeSet::new();
        for (provider_id, provider) in &self.providers {
            if provider_id != &provider.provider {
                return Err(ProviderError::Compatibility(format!(
                    "provider key {provider_id} does not match provider {}",
                    provider.provider
                )));
            }
            if provider.api_base_url.trim().is_empty() {
                return Err(ProviderError::Compatibility(format!(
                    "provider {provider_id} has an empty api_base_url"
                )));
            }
            reject_url_credentials(
                &provider.api_base_url,
                "provider",
                provider_id,
                "api_base_url",
            )?;
            if provider.supported_openai_endpoints.is_empty() {
                return Err(ProviderError::Compatibility(format!(
                    "provider {provider_id} has no supported OpenAI endpoints"
                )));
            }
            if !provider.supports_endpoint(OpenAiEndpoint::ChatCompletions) {
                return Err(ProviderError::Compatibility(format!(
                    "provider {provider_id} does not support chat completions"
                )));
            }
            seen_api_bases.insert(provider.api_base_url.clone());
        }

        Ok(())
    }

    pub fn provider(&self, provider: &str) -> crate::Result<&ProviderCompatibility> {
        self.providers.get(provider).ok_or_else(|| {
            ProviderError::Compatibility(format!(
                "provider {provider} is missing from compatibility matrix"
            ))
        })
    }

    pub fn validate_registry_routes(&self, registry: &ProviderRegistry) -> crate::Result<()> {
        for model in registry.models.values() {
            for route in model
                .routes
                .iter()
                .filter(|route| route.route_status.security_sensitive())
            {
                self.provider(&route.provider)?.validate_route(route)?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCompatibilityMatrixEnvelope {
    pub schema: String,
    pub payload: ProviderCompatibilityMatrix,
    pub signature: ArtifactSignature,
}

impl ProviderCompatibilityMatrixEnvelope {
    pub const SCHEMA: &'static str =
        "confidential-inference.provider-compatibility-matrix-envelope.v1";

    pub fn bundled() -> crate::Result<Self> {
        serde_json::from_str(include_str!(
            "../assets/providers/compatibility-matrix-envelope.json"
        ))
        .map_err(Into::into)
    }

    pub fn verify_signature(&self) -> crate::Result<()> {
        self.verify_signature_with_keys(
            &confidential_inference_attestation::default_trusted_signing_keys(),
        )
    }

    pub fn verify_signature_with_keys(
        &self,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> crate::Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(ProviderError::Compatibility(
                "compatibility matrix envelope schema mismatch".into(),
            ));
        }
        verify_artifact_signature_with_keys(&self.signature, &self.payload, trusted_signing_keys)
            .map_err(|error| ProviderError::Compatibility(error.to_string()))?;
        self.payload.validate()
    }

    pub fn into_verified_payload(self) -> crate::Result<ProviderCompatibilityMatrix> {
        self.verify_signature()?;
        Ok(self.payload)
    }
}

fn validate_compatibility_matrix_schema_major(field: &str, value: &str) -> crate::Result<()> {
    let Some(version) = value
        .strip_prefix("confidential-inference.provider-compatibility-matrix")
        .and_then(|rest| rest.strip_prefix(".v"))
    else {
        return Err(ProviderError::Compatibility(format!(
            "{field} must start with confidential-inference.provider-compatibility-matrix.v{}",
            ProviderCompatibilityMatrix::SUPPORTED_SCHEMA_MAJOR
        )));
    };
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or_default();
    if major.is_empty() || major.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(ProviderError::Compatibility(format!(
            "{field} has malformed schema version {value}"
        )));
    }
    for part in parts {
        if part.is_empty() || part.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(ProviderError::Compatibility(format!(
                "{field} has malformed schema version {value}"
            )));
        }
    }
    let parsed_major = major.parse::<u32>().map_err(|_| {
        ProviderError::Compatibility(format!("{field} has malformed schema version {value}"))
    })?;
    if parsed_major != ProviderCompatibilityMatrix::SUPPORTED_SCHEMA_MAJOR {
        return Err(ProviderError::Compatibility(format!(
            "{field} major version {parsed_major} is not supported"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCompatibility {
    pub provider: String,
    pub route_execution_status: RouteExecutionStatus,
    pub api_base_url: String,
    pub supported_openai_endpoints: Vec<OpenAiEndpoint>,
    pub model_listing: ModelListingBehavior,
    pub model_id_rewrite: ModelIdRewrite,
    pub token_parameter_rewrite: TokenParameterRewrite,
    pub streaming: StreamingSupport,
    pub request_encryption: EncryptionRequirement,
    pub response_decryption: EncryptionRequirement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk_app_e2ee: Option<SdkAppE2eeConfig>,
    pub attestation_endpoint_shape: String,
    pub required_credentials: Vec<CredentialKind>,
    pub freshness_class: FreshnessClass,
    pub cacheability_class: CacheabilityClass,
    pub expected_trust_tier: TrustTier,
    pub model_binding_support: ModelBindingSupport,
    pub known_unsupported_modes: Vec<String>,
}

impl ProviderCompatibility {
    pub fn validate_route(&self, route: &RouteDefinition) -> crate::Result<()> {
        reject_url_credentials(
            &self.api_base_url,
            "provider",
            &self.provider,
            "api_base_url",
        )?;
        reject_url_credentials(
            &route.api_base_url,
            "route",
            &route.route_id,
            "api_base_url",
        )?;
        reject_url_credentials(
            &route.evidence_endpoint,
            "route",
            &route.route_id,
            "evidence_endpoint",
        )?;
        if route.provider != self.provider {
            return Err(ProviderError::Compatibility(format!(
                "route {} belongs to provider {}, not {}",
                route.route_id, route.provider, self.provider
            )));
        }
        if route.api_base_url != self.api_base_url {
            return Err(ProviderError::Compatibility(format!(
                "route {} api_base_url {} does not match compatibility matrix {}",
                route.route_id, route.api_base_url, self.api_base_url
            )));
        }
        if route.freshness_class != self.freshness_class {
            return Err(ProviderError::Compatibility(format!(
                "route {} freshness {:?} does not match compatibility matrix {:?}",
                route.route_id, route.freshness_class, self.freshness_class
            )));
        }
        if route.trust_tier != self.expected_trust_tier {
            return Err(ProviderError::Compatibility(format!(
                "route {} trust tier {:?} does not match compatibility matrix {:?}",
                route.route_id, route.trust_tier, self.expected_trust_tier
            )));
        }
        if route.request_encryption != self.request_encryption {
            return Err(ProviderError::Compatibility(format!(
                "route {} request encryption {:?} does not match compatibility matrix {:?}",
                route.route_id, route.request_encryption, self.request_encryption
            )));
        }
        if route.response_decryption != self.response_decryption {
            return Err(ProviderError::Compatibility(format!(
                "route {} response decryption {:?} does not match compatibility matrix {:?}",
                route.route_id, route.response_decryption, self.response_decryption
            )));
        }
        if route.streaming != self.streaming {
            return Err(ProviderError::Compatibility(format!(
                "route {} streaming {:?} does not match compatibility matrix {:?}",
                route.route_id, route.streaming, self.streaming
            )));
        }

        Ok(())
    }

    pub fn adapt_chat_request(
        &self,
        route: &RouteDefinition,
        request: &ChatCompletionRequest,
    ) -> crate::Result<ProviderChatRequest> {
        if !self.supports_endpoint(OpenAiEndpoint::ChatCompletions) {
            return Err(ProviderError::Compatibility(format!(
                "provider {} does not support chat completions",
                self.provider
            )));
        }
        self.validate_streaming(request)?;

        let provider_request = match self.model_id_rewrite {
            ModelIdRewrite::UseRouteProviderModel => {
                request.with_model(route.provider_model.clone())
            }
        };
        let mut body = serde_json::to_value(provider_request)?;
        let Value::Object(ref mut fields) = body else {
            return Err(ProviderError::Compatibility(
                "chat request did not serialize to a JSON object".into(),
            ));
        };

        self.apply_token_parameter_rewrite(fields);
        match self.request_confidentiality_for_chat()? {
            ChatRequestConfidentiality::Plaintext => Ok(ProviderChatRequest::with_confidentiality(
                body,
                ProviderRequestConfidentiality::Plaintext,
            )),
            ChatRequestConfidentiality::FixtureEncrypted => {
                ProviderChatRequest::fixture_encrypt(route, body)
            }
            ChatRequestConfidentiality::SdkEncrypted(config) => {
                ProviderChatRequest::sdk_encrypt(route, body, config)
            }
        }
    }

    pub fn supports_endpoint(&self, endpoint: OpenAiEndpoint) -> bool {
        self.supported_openai_endpoints.contains(&endpoint)
    }

    pub fn validate_streaming(&self, request: &ChatCompletionRequest) -> crate::Result<()> {
        if request.streaming() && self.streaming == StreamingSupport::Unsupported {
            Err(ProviderError::Compatibility(format!(
                "provider {} does not support streaming under the selected compatibility profile",
                self.provider
            )))
        } else {
            Ok(())
        }
    }

    fn apply_token_parameter_rewrite(&self, fields: &mut Map<String, Value>) {
        match self.token_parameter_rewrite {
            TokenParameterRewrite::PreserveMaxTokens => {}
            TokenParameterRewrite::MaxTokensToMaxCompletionTokens => {
                if let Some(max_tokens) = fields.remove("max_tokens") {
                    fields.insert("max_completion_tokens".into(), max_tokens);
                }
            }
        }
    }

    fn request_confidentiality_for_chat(&self) -> crate::Result<ChatRequestConfidentiality<'_>> {
        let encryption_required = self.request_encryption == EncryptionRequirement::Required
            || self.response_decryption == EncryptionRequirement::Required;
        if !encryption_required {
            return Ok(ChatRequestConfidentiality::Plaintext);
        }

        match self.route_execution_status {
            RouteExecutionStatus::ExecutableFixture | RouteExecutionStatus::AdapterShapeFixture => {
                Ok(ChatRequestConfidentiality::FixtureEncrypted)
            }
            RouteExecutionStatus::VerificationOnly => Err(ProviderError::Compatibility(format!(
                "provider {} is verification-only until SDK-managed app encryption is implemented",
                self.provider
            ))),
            RouteExecutionStatus::Executable => self
                .sdk_app_e2ee
                .as_ref()
                .map(ChatRequestConfidentiality::SdkEncrypted)
                .ok_or_else(|| {
                    ProviderError::Compatibility(format!(
                        "provider {} requires an SDK-managed app encryption profile before encrypted chat execution",
                        self.provider
                    ))
                }),
        }
    }
}

enum ChatRequestConfidentiality<'a> {
    Plaintext,
    FixtureEncrypted,
    SdkEncrypted(&'a SdkAppE2eeConfig),
}

fn reject_url_credentials(
    url: &str,
    subject_kind: &str,
    subject_id: &str,
    field: &str,
) -> crate::Result<()> {
    if url_authority_has_credentials(url) {
        return Err(ProviderError::Compatibility(format!(
            "{subject_kind} {subject_id} {field} must not include URL credentials"
        )));
    }
    Ok(())
}

fn url_authority_has_credentials(url: &str) -> bool {
    let Some((authority_start, authority_end)) = url_authority_bounds(url) else {
        return false;
    };
    url[authority_start..authority_end].contains('@')
}

fn url_authority_bounds(url: &str) -> Option<(usize, usize)> {
    let scheme_end = url.find("://")?;
    let authority_start = scheme_end + 3;
    let rest = &url[authority_start..];
    let mut authority_end = rest.len();
    for separator in ['/', '?', '#'] {
        if let Some(index) = rest.find(separator) {
            authority_end = authority_end.min(index);
        }
    }
    Some((authority_start, authority_start + authority_end))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteExecutionStatus {
    ExecutableFixture,
    AdapterShapeFixture,
    VerificationOnly,
    Executable,
}

impl RouteExecutionStatus {
    pub fn allows_chat_execution(&self) -> bool {
        matches!(
            self,
            RouteExecutionStatus::Executable | RouteExecutionStatus::ExecutableFixture
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenAiEndpoint {
    ChatCompletions,
    Models,
    Confidentiality,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelListingBehavior {
    SignedRegistryOnly,
    LiveCatalog,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelIdRewrite {
    UseRouteProviderModel,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenParameterRewrite {
    PreserveMaxTokens,
    MaxTokensToMaxCompletionTokens,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    BearerToken,
    ApiKeyHeader,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheabilityClass {
    PerRequestOnly,
    PerSessionVerdict,
    StaticProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelBindingSupport {
    Unsupported,
    Partial,
    Verified,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptionRequirement, ProviderRegistry, RouteLifecycle, SdkAppE2eeSecretKey};
    use confidential_inference_attestation::{
        AliasConfidence, COMPATIBILITY_FIXTURE_SIGNING_KEY_ID,
    };
    use confidential_inference_openai::ChatMessage;

    const COMPATIBILITY_MATRIX_DIGEST: &str =
        "sha256:bc8b1b5e04436313caa368d19bc3c1b1ea9f944a94cdfd6ddc7dda9dd96f33ce";

    #[test]
    fn bundled_compatibility_matrix_validates() {
        let matrix = ProviderCompatibilityMatrix::bundled().unwrap();

        matrix.validate().unwrap();
        assert!(matrix.provider("demo").is_ok());
        assert!(matrix.provider("tinfoil-fixture").is_ok());
        assert!(matrix.provider("venice-fixture").is_ok());
        assert!(matrix.provider("phala-direct-fixture").is_ok());
        assert!(matrix.provider("ionet-confidential-fixture").is_ok());
        assert!(matrix.provider("redpill-fixture").is_ok());
        assert!(matrix.provider("ppq-private-fixture").is_ok());
    }

    #[test]
    fn bundled_compatibility_matrix_signature_verifies() {
        let envelope = ProviderCompatibilityMatrixEnvelope::bundled().unwrap();

        envelope.verify_signature().unwrap();
        assert_eq!(
            envelope.signature.key_id,
            COMPATIBILITY_FIXTURE_SIGNING_KEY_ID
        );
        assert_eq!(
            envelope.payload.digest().unwrap(),
            COMPATIBILITY_MATRIX_DIGEST
        );
    }

    #[test]
    fn compatibility_matrix_digest_accepts_same_major_schema_metadata() {
        let mut matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        matrix.schema = "confidential-inference.provider-compatibility-matrix.v1.1".into();

        assert!(matrix.digest().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn compatibility_matrix_digest_rejects_unknown_major_schema_metadata() {
        let mut matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        matrix.schema = "confidential-inference.provider-compatibility-matrix.v2".into();

        let error = matrix.digest().unwrap_err();

        assert!(matches!(
            error,
            ProviderError::Compatibility(message)
                if message.contains("schema major version 2 is not supported")
        ));
    }

    #[test]
    fn compatibility_matrix_digest_rejects_malformed_schema_metadata() {
        let mut matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        matrix.schema = "confidential-inference.provider-compatibility-matrix.v1.beta".into();

        let error = matrix.digest().unwrap_err();

        assert!(matches!(
            error,
            ProviderError::Compatibility(message)
                if message.contains("schema has malformed schema version")
        ));
    }

    #[test]
    fn tampered_compatibility_matrix_signature_fails() {
        let mut envelope = ProviderCompatibilityMatrixEnvelope::bundled().unwrap();
        envelope
            .payload
            .providers
            .get_mut("demo")
            .unwrap()
            .streaming = StreamingSupport::Supported;

        assert!(envelope.verify_signature().is_err());
    }

    #[test]
    fn raw_compatibility_matrix_matches_signed_envelope_payload() {
        let envelope = ProviderCompatibilityMatrixEnvelope::bundled().unwrap();
        let raw = ProviderCompatibilityMatrix::bundled_raw_fixture().unwrap();

        assert_eq!(raw, envelope.payload);
    }

    #[test]
    fn demo_compatibility_matches_signed_registry_route() {
        let matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let registry = ProviderRegistry::bundled_demo().unwrap();
        let (_, route) = registry.find_route(Some("demo"), "gpt-oss-120b").unwrap();

        matrix
            .provider("demo")
            .unwrap()
            .validate_route(route)
            .unwrap();
        matrix.validate_registry_routes(&registry).unwrap();
    }

    #[test]
    fn phase2_fixture_compatibility_matches_signed_registry_routes() {
        let matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let registry = ProviderRegistry::phase2_fixtures().unwrap();

        matrix.validate_registry_routes(&registry).unwrap();
        assert!(matrix
            .provider("tinfoil-fixture")
            .unwrap()
            .route_execution_status
            .allows_chat_execution());
        assert!(!matrix
            .provider("venice-fixture")
            .unwrap()
            .route_execution_status
            .allows_chat_execution());
    }

    #[test]
    fn registry_routes_missing_from_matrix_fail_validation() {
        let mut matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        matrix.providers.remove("demo");
        let registry = ProviderRegistry::bundled_demo().unwrap();

        assert!(matches!(
            matrix.validate_registry_routes(&registry),
            Err(ProviderError::Compatibility(_))
        ));
    }

    #[test]
    fn verification_only_registry_routes_are_compatibility_validated() {
        let matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        let route = &mut registry.models.get_mut("gpt-oss-120b").unwrap().routes[0];
        route.route_status = RouteLifecycle::VerificationOnly;
        route.api_base_url = "https://api.venice.ai/api/v1".into();

        let error = matrix.validate_registry_routes(&registry).unwrap_err();

        assert!(matches!(
            error,
            ProviderError::Compatibility(message)
                if message.contains("api_base_url")
                    && message.contains("does not match compatibility matrix")
        ));
    }

    #[test]
    fn compatibility_matrix_rejects_credentialed_api_base_without_leaking_credentials() {
        let mut matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        matrix.providers.get_mut("demo").unwrap().api_base_url =
            "https://token:secret@api.redpill.ai/v1".into();

        let error = matrix.validate().unwrap_err();
        let message = error.to_string();

        assert!(matches!(error, ProviderError::Compatibility(_)));
        assert!(message.contains("api_base_url must not include URL credentials"));
        assert!(!message.contains("token"));
        assert!(!message.contains("secret"));
        assert!(!message.contains("token:secret@api.redpill.ai"));
    }

    #[test]
    fn compatibility_route_rejects_credentialed_url_without_leaking_credentials() {
        let matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let mut route = fixture_route(
            "demo",
            "e2ee-gpt-oss-120b-p",
            "https://token:secret@api.redpill.ai/v1",
        );
        route.route_status = RouteLifecycle::Active;

        let error = matrix
            .provider("demo")
            .unwrap()
            .validate_route(&route)
            .unwrap_err();
        let message = error.to_string();

        assert!(matches!(error, ProviderError::Compatibility(_)));
        assert!(message.contains("api_base_url must not include URL credentials"));
        assert!(!message.contains("token"));
        assert!(!message.contains("secret"));
        assert!(!message.contains("token:secret@api.redpill.ai"));
    }

    #[test]
    fn compatibility_route_rejects_credentialed_evidence_without_leaking_credentials() {
        let matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let mut route = fixture_route(
            "demo",
            "e2ee-gpt-oss-120b-p",
            &matrix.provider("demo").unwrap().api_base_url,
        );
        route.evidence_endpoint =
            "https://token:secret@api.redpill.ai/v1/attestation/report".into();

        let error = matrix
            .provider("demo")
            .unwrap()
            .validate_route(&route)
            .unwrap_err();
        let message = error.to_string();

        assert!(matches!(error, ProviderError::Compatibility(_)));
        assert!(message.contains("evidence_endpoint must not include URL credentials"));
        assert!(!message.contains("token"));
        assert!(!message.contains("secret"));
        assert!(!message.contains("token:secret@api.redpill.ai"));
    }

    #[test]
    fn request_adaptation_rewrites_model_and_preserves_demo_token_parameter() {
        let matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let registry = ProviderRegistry::bundled_demo().unwrap();
        let (_, route) = registry.find_route(Some("demo"), "gpt-oss-120b").unwrap();
        let request = chat_request();

        let body = matrix
            .provider("demo")
            .unwrap()
            .adapt_chat_request(route, &request)
            .unwrap();

        assert!(!body.body().to_string().contains("matrix adaptation"));
        assert_eq!(
            body.confidentiality(),
            &ProviderRequestConfidentiality::FixtureEncrypted
        );
        let decrypted = body.fixture_decrypted_body(route).unwrap();
        assert_eq!(decrypted["model"], "e2ee-gpt-oss-120b-p");
        assert_eq!(decrypted["max_tokens"], 64);
        assert!(decrypted.get("max_completion_tokens").is_none());
    }

    #[test]
    fn redpill_fixture_maps_max_tokens_to_max_completion_tokens() {
        let matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let route = fixture_route(
            "redpill-fixture",
            "e2ee-gpt-oss-120b-p",
            "https://api.redpill.ai/v1",
        );
        let request = chat_request();

        let body = matrix
            .provider("redpill-fixture")
            .unwrap()
            .adapt_chat_request(&route, &request)
            .unwrap();

        assert_eq!(
            body.confidentiality(),
            &ProviderRequestConfidentiality::FixtureEncrypted
        );
        let decrypted = body.fixture_decrypted_body(&route).unwrap();
        assert_eq!(decrypted["model"], "e2ee-gpt-oss-120b-p");
        assert_eq!(decrypted["max_completion_tokens"], 64);
        assert!(decrypted.get("max_tokens").is_none());
    }

    #[test]
    fn executable_app_e2ee_route_without_sdk_crypto_fails_closed() {
        let mut matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let provider = matrix.providers.get_mut("demo").unwrap();
        provider.route_execution_status = RouteExecutionStatus::Executable;
        provider.request_encryption = EncryptionRequirement::Required;
        provider.response_decryption = EncryptionRequirement::Required;
        let registry = ProviderRegistry::bundled_demo().unwrap();
        let (_, route) = registry.find_route(Some("demo"), "gpt-oss-120b").unwrap();

        let error = matrix
            .provider("demo")
            .unwrap()
            .adapt_chat_request(route, &chat_request())
            .unwrap_err();

        assert!(matches!(error, ProviderError::Compatibility(_)));
        assert!(error.to_string().contains("SDK-managed app encryption"));
    }

    #[test]
    fn executable_app_e2ee_route_with_sdk_crypto_encrypts_request() {
        let mut matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let provider = matrix.providers.get_mut("demo").unwrap();
        provider.route_execution_status = RouteExecutionStatus::Executable;
        provider.request_encryption = EncryptionRequirement::Required;
        provider.response_decryption = EncryptionRequirement::Required;
        let secret_key = SdkAppE2eeSecretKey::from_private_key_bytes("test-e2ee-key", [9_u8; 32]);
        provider.sdk_app_e2ee = Some(secret_key.public_config().unwrap());
        let registry = ProviderRegistry::bundled_demo().unwrap();
        let (_, route) = registry.find_route(Some("demo"), "gpt-oss-120b").unwrap();

        let request = matrix
            .provider("demo")
            .unwrap()
            .adapt_chat_request(route, &chat_request())
            .unwrap();

        assert_eq!(
            request.confidentiality(),
            &ProviderRequestConfidentiality::SdkEncrypted
        );
        assert!(!request.body().to_string().contains("matrix adaptation"));
        let (decrypted, _) = request.sdk_decrypted_body(route, &secret_key).unwrap();
        assert_eq!(decrypted["model"], "e2ee-gpt-oss-120b-p");
        assert_eq!(decrypted["max_tokens"], 64);
    }

    #[test]
    fn matrix_streaming_rules_fail_closed_before_request_adaptation() {
        let matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let registry = ProviderRegistry::bundled_demo().unwrap();
        let (_, route) = registry.find_route(Some("demo"), "gpt-oss-120b").unwrap();
        let mut request = chat_request();
        request.stream = Some(true);

        assert!(matches!(
            matrix
                .provider("demo")
                .unwrap()
                .adapt_chat_request(route, &request),
            Err(ProviderError::Compatibility(_))
        ));
    }

    fn chat_request() -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "gpt-oss-120b".into(),
            messages: vec![ChatMessage::user("matrix adaptation")],
            stream: None,
            max_tokens: Some(64),
            temperature: Some(0.2),
        }
    }

    fn fixture_route(provider: &str, provider_model: &str, api_base_url: &str) -> RouteDefinition {
        let registry = ProviderRegistry::bundled_demo().unwrap();
        let (_, base) = registry.find_route(Some("demo"), "gpt-oss-120b").unwrap();
        let mut route = base.clone();
        route.route_id = format!("{provider}:gpt-oss-120b:{provider_model}");
        route.route_status = RouteLifecycle::VerificationOnly;
        route.provider = provider.into();
        route.provider_model = provider_model.into();
        route.api_base_url = api_base_url.into();
        route.evidence_endpoint = format!("{api_base_url}/confidentiality");
        route.adapter_version = format!("{provider}-adapter-shape/0.1.0");
        route.alias_confidence = AliasConfidence::Curated;
        route
    }
}
