use crate::{
    EncryptionRequirement, ProviderRegistry, ProviderRegistryEnvelope, RegistryModel,
    RouteDefinition, RouteLifecycle, SourceSyncRun, StreamingSupport,
};
use confidential_inference_attestation::{
    sha256_digest, AliasConfidence, ArtifactSignature, AttestationError, BoundDataRequirement,
    ChannelBindingKind, FreshnessClass, GpuTeeKind, ResponseIntegrityRequirement,
    Result as AttestationResult, TrustTier,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryGeneratorInput {
    pub schema: String,
    pub version: String,
    pub generated_at: String,
    pub source_sync_run: SourceSyncRun,
    pub models: Vec<RegistryGeneratorModel>,
}

impl RegistryGeneratorInput {
    pub const SCHEMA: &'static str = "confidential-inference.provider-registry-generator-input.v1";

    pub fn generate(self) -> AttestationResult<ProviderRegistry> {
        generate_provider_registry(self)
    }

    pub fn generate_signed(
        self,
        signature: ArtifactSignature,
    ) -> AttestationResult<ProviderRegistryEnvelope> {
        generate_signed_provider_registry(self, signature)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryGeneratorModel {
    pub canonical_model: String,
    pub display_name: String,
    pub family: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub routes: Vec<RegistryGeneratorRoute>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryGeneratorRoute {
    #[serde(default)]
    pub route_id: Option<String>,
    pub route_status: RouteLifecycle,
    pub provider: String,
    pub provider_model: String,
    pub evidence_family: String,
    pub api_base_url: String,
    pub evidence_endpoint: String,
    pub adapter_version: String,
    pub freshness_class: FreshnessClass,
    pub channel_binding_kind: ChannelBindingKind,
    pub trust_tier: TrustTier,
    pub request_confidentiality_requirement: BoundDataRequirement,
    pub response_confidentiality_requirement: BoundDataRequirement,
    pub response_integrity_requirement: ResponseIntegrityRequirement,
    #[serde(default)]
    pub accepted_gpu_tees: Vec<GpuTeeKind>,
    pub request_encryption: EncryptionRequirement,
    pub response_decryption: EncryptionRequirement,
    pub streaming: StreamingSupport,
    pub alias_confidence: AliasConfidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryLiveSyncInput {
    pub schema: String,
    pub version: String,
    pub generated_at: String,
    pub source_sync_run: SourceSyncRun,
    pub providers: Vec<RegistryLiveSyncProvider>,
}

impl RegistryLiveSyncInput {
    pub const SCHEMA: &'static str = "confidential-inference.provider-registry-live-sync-input.v1";

    pub fn ingest(self) -> AttestationResult<RegistryLiveSyncIngestion> {
        ingest_live_sync_registry(self)
    }

    pub fn generate(self) -> AttestationResult<ProviderRegistry> {
        generate_provider_registry_from_live_sync(self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryLiveSyncProvider {
    pub provider: String,
    pub api_base_url: String,
    pub evidence_endpoint: String,
    pub adapter_version: String,
    pub evidence_family: String,
    pub freshness_class: FreshnessClass,
    pub channel_binding_kind: ChannelBindingKind,
    pub trust_tier: TrustTier,
    pub request_confidentiality_requirement: BoundDataRequirement,
    pub response_confidentiality_requirement: BoundDataRequirement,
    pub response_integrity_requirement: ResponseIntegrityRequirement,
    #[serde(default)]
    pub accepted_gpu_tees: Vec<GpuTeeKind>,
    pub request_encryption: EncryptionRequirement,
    pub response_decryption: EncryptionRequirement,
    pub streaming: StreamingSupport,
    pub raw_models: Vec<RegistryLiveSyncRawModel>,
    #[serde(default)]
    pub enrichments: Vec<RegistryLiveSyncEnrichment>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryLiveSyncRawModel {
    pub provider_model: String,
    #[serde(default)]
    pub raw_payload: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryLiveSyncEnrichment {
    pub provider_model: String,
    #[serde(default)]
    pub canonical_model: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub route_status: Option<RouteLifecycle>,
    #[serde(default)]
    pub alias_confidence: Option<AliasConfidence>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegistryLiveSyncIngestion {
    pub generator_input: RegistryGeneratorInput,
    pub observations: Vec<RegistryLiveSyncObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryLiveSyncObservation {
    pub provider: String,
    pub provider_model: String,
    pub canonical_model: String,
    pub route_status: RouteLifecycle,
    pub alias_confidence: AliasConfidence,
    pub raw_payload_digest: String,
    pub enrichment_applied: bool,
}

pub fn parse_openai_model_list_raw_models(
    raw_response: &Value,
) -> AttestationResult<Vec<RegistryLiveSyncRawModel>> {
    let models = raw_response
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AttestationError::InvalidProviderRegistry(
                "live sync OpenAI model list must contain a data array".into(),
            )
        })?;

    let mut raw_models = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, raw_model) in models.iter().enumerate() {
        let provider_model = raw_model
            .get("id")
            .or_else(|| raw_model.get("model_id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AttestationError::InvalidProviderRegistry(format!(
                    "live sync OpenAI model list entry {index} is missing string id/model_id"
                ))
            })?
            .to_owned();
        if !seen.insert(provider_model.clone()) {
            return Err(AttestationError::InvalidProviderRegistry(format!(
                "live sync OpenAI model list repeats model id {provider_model}"
            )));
        }

        raw_models.push(RegistryLiveSyncRawModel {
            provider_model,
            raw_payload: raw_model.clone(),
        });
    }

    Ok(raw_models)
}

pub fn parse_provider_model_list_raw_models(
    raw_response: &Value,
) -> AttestationResult<Vec<RegistryLiveSyncRawModel>> {
    if raw_response.get("data").is_some() {
        return parse_openai_model_list_raw_models(raw_response);
    }

    let Some(models) = raw_response.get("models") else {
        return Err(AttestationError::InvalidProviderRegistry(
            "live sync provider model list must contain an OpenAI data array or provider models array"
                .into(),
        ));
    };
    let models = models.as_array().ok_or_else(|| {
        AttestationError::InvalidProviderRegistry(
            "live sync provider model list field models must be an array".into(),
        )
    })?;

    let mut raw_models = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, raw_model) in models.iter().enumerate() {
        let provider_model = provider_model_id(raw_model).ok_or_else(|| {
            AttestationError::InvalidProviderRegistry(format!(
                "live sync provider model list entry {index} is missing string model identifier"
            ))
        })?;
        if !seen.insert(provider_model.clone()) {
            return Err(AttestationError::InvalidProviderRegistry(format!(
                "live sync provider model list repeats model id {provider_model}"
            )));
        }

        raw_models.push(RegistryLiveSyncRawModel {
            provider_model,
            raw_payload: raw_model.clone(),
        });
    }

    Ok(raw_models)
}

pub fn generate_provider_registry(
    input: RegistryGeneratorInput,
) -> AttestationResult<ProviderRegistry> {
    if input.schema != RegistryGeneratorInput::SCHEMA {
        return Err(AttestationError::InvalidProviderRegistry(format!(
            "unsupported registry generator input schema {}",
            input.schema
        )));
    }

    let mut models = BTreeMap::new();
    let mut route_ids = BTreeSet::new();

    for model in input.models {
        let canonical_model = required_field("canonical_model", model.canonical_model)?;
        if models.contains_key(&canonical_model) {
            return Err(AttestationError::InvalidProviderRegistry(format!(
                "generator input repeats canonical model {canonical_model}"
            )));
        }

        let mut aliases = dedup_aliases(canonical_model.clone(), model.aliases)?;
        let mut routes = Vec::new();

        for route in model.routes {
            let provider = required_field("provider", route.provider)?;
            let provider_model = required_field("provider_model", route.provider_model)?;
            let route_id = route
                .route_id
                .unwrap_or_else(|| format!("{provider}:{canonical_model}:{provider_model}"));
            let route_id = required_field("route_id", route_id)?;
            if !route_ids.insert(route_id.clone()) {
                return Err(AttestationError::InvalidProviderRegistry(format!(
                    "generator input repeats route_id {route_id}"
                )));
            }

            routes.push(RouteDefinition {
                route_id,
                route_status: route.route_status,
                provider,
                provider_model,
                evidence_family: required_field("evidence_family", route.evidence_family)?,
                api_base_url: required_field("api_base_url", route.api_base_url)?,
                evidence_endpoint: required_field("evidence_endpoint", route.evidence_endpoint)?,
                adapter_version: required_field("adapter_version", route.adapter_version)?,
                freshness_class: route.freshness_class,
                channel_binding_kind: route.channel_binding_kind,
                trust_tier: route.trust_tier,
                request_confidentiality_requirement: route.request_confidentiality_requirement,
                response_confidentiality_requirement: route.response_confidentiality_requirement,
                response_integrity_requirement: route.response_integrity_requirement,
                accepted_gpu_tees: route.accepted_gpu_tees,
                request_encryption: route.request_encryption,
                response_decryption: route.response_decryption,
                streaming: route.streaming,
                alias_confidence: route.alias_confidence,
            });
        }

        routes.sort_by(|left, right| left.route_id.cmp(&right.route_id));
        aliases.shrink_to_fit();
        routes.shrink_to_fit();

        models.insert(
            canonical_model.clone(),
            RegistryModel {
                canonical_model,
                display_name: required_field("display_name", model.display_name)?,
                family: required_field("family", model.family)?,
                aliases,
                routes,
            },
        );
    }

    let registry = ProviderRegistry {
        schema: ProviderRegistry::SCHEMA.into(),
        version: required_field("version", input.version)?,
        generated_at: required_field("generated_at", input.generated_at)?,
        source_sync_run: input.source_sync_run,
        models,
    };
    registry.validate_security_invariants()?;
    Ok(registry)
}

pub fn generate_signed_provider_registry(
    input: RegistryGeneratorInput,
    signature: ArtifactSignature,
) -> AttestationResult<ProviderRegistryEnvelope> {
    let payload = generate_provider_registry(input)?;
    let envelope = ProviderRegistryEnvelope {
        schema: ProviderRegistryEnvelope::SCHEMA.into(),
        payload,
        signature,
    };
    envelope.verify_signature()?;
    Ok(envelope)
}

pub fn ingest_live_sync_registry(
    input: RegistryLiveSyncInput,
) -> AttestationResult<RegistryLiveSyncIngestion> {
    if input.schema != RegistryLiveSyncInput::SCHEMA {
        return Err(AttestationError::InvalidProviderRegistry(format!(
            "unsupported registry live sync input schema {}",
            input.schema
        )));
    }

    let mut models = BTreeMap::<String, RegistryGeneratorModel>::new();
    let mut observations = Vec::new();

    for provider_input in input.providers {
        let provider = required_field("provider", provider_input.provider)?;
        let mut enrichments = BTreeMap::<String, RegistryLiveSyncEnrichment>::new();
        for enrichment in provider_input.enrichments {
            let provider_model =
                required_field("enrichment.provider_model", enrichment.provider_model)?;
            if enrichments
                .insert(
                    provider_model.clone(),
                    RegistryLiveSyncEnrichment {
                        provider_model: provider_model.clone(),
                        ..enrichment
                    },
                )
                .is_some()
            {
                return Err(AttestationError::InvalidProviderRegistry(format!(
                    "live sync enrichment repeats provider_model {provider}/{provider_model}"
                )));
            }
        }

        let mut seen_provider_models = BTreeSet::new();
        for raw_model in provider_input.raw_models {
            let provider_model = required_field("raw.provider_model", raw_model.provider_model)?;
            if !seen_provider_models.insert(provider_model.clone()) {
                return Err(AttestationError::InvalidProviderRegistry(format!(
                    "live sync raw output repeats provider_model {provider}/{provider_model}"
                )));
            }

            let raw_payload_digest = raw_payload_digest(&raw_model.raw_payload)?;
            let enrichment = enrichments.get(&provider_model);
            let explicit_canonical = enrichment
                .and_then(|enrichment| enrichment.canonical_model.as_deref())
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let canonical_model = explicit_canonical
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| provisional_canonical_model(&provider_model));
            let enrichment_applied = explicit_canonical.is_some();
            let route_status = if enrichment_applied {
                enrichment
                    .and_then(|enrichment| enrichment.route_status.clone())
                    .unwrap_or(RouteLifecycle::NewUnverified)
            } else {
                RouteLifecycle::NewUnverified
            };
            let alias_confidence = if enrichment_applied {
                enrichment
                    .and_then(|enrichment| enrichment.alias_confidence.clone())
                    .unwrap_or(AliasConfidence::Curated)
            } else {
                AliasConfidence::Algorithmic
            };
            let display_name = enrichment
                .and_then(|enrichment| enrichment.display_name.clone())
                .unwrap_or_else(|| canonical_model.clone());
            let family = enrichment
                .and_then(|enrichment| enrichment.family.clone())
                .unwrap_or_else(|| "unknown".into());
            let aliases = enrichment
                .map(|enrichment| enrichment.aliases.clone())
                .unwrap_or_default();

            let route = RegistryGeneratorRoute {
                route_id: None,
                route_status: route_status.clone(),
                provider: provider.clone(),
                provider_model: provider_model.clone(),
                evidence_family: provider_input.evidence_family.clone(),
                api_base_url: provider_input.api_base_url.clone(),
                evidence_endpoint: provider_input.evidence_endpoint.clone(),
                adapter_version: provider_input.adapter_version.clone(),
                freshness_class: provider_input.freshness_class.clone(),
                channel_binding_kind: provider_input.channel_binding_kind.clone(),
                trust_tier: provider_input.trust_tier.clone(),
                request_confidentiality_requirement: provider_input
                    .request_confidentiality_requirement
                    .clone(),
                response_confidentiality_requirement: provider_input
                    .response_confidentiality_requirement
                    .clone(),
                response_integrity_requirement: provider_input
                    .response_integrity_requirement
                    .clone(),
                accepted_gpu_tees: provider_input.accepted_gpu_tees.clone(),
                request_encryption: provider_input.request_encryption.clone(),
                response_decryption: provider_input.response_decryption.clone(),
                streaming: provider_input.streaming.clone(),
                alias_confidence: alias_confidence.clone(),
            };

            merge_live_sync_model(
                &mut models,
                canonical_model.clone(),
                display_name,
                family,
                aliases,
                route,
            )?;

            observations.push(RegistryLiveSyncObservation {
                provider: provider.clone(),
                provider_model,
                canonical_model,
                route_status,
                alias_confidence,
                raw_payload_digest,
                enrichment_applied,
            });
        }
    }

    observations.sort_by(|left, right| {
        (&left.provider, &left.provider_model).cmp(&(&right.provider, &right.provider_model))
    });

    Ok(RegistryLiveSyncIngestion {
        generator_input: RegistryGeneratorInput {
            schema: RegistryGeneratorInput::SCHEMA.into(),
            version: required_field("version", input.version)?,
            generated_at: required_field("generated_at", input.generated_at)?,
            source_sync_run: input.source_sync_run,
            models: models.into_values().collect(),
        },
        observations,
    })
}

pub fn generate_provider_registry_from_live_sync(
    input: RegistryLiveSyncInput,
) -> AttestationResult<ProviderRegistry> {
    ingest_live_sync_registry(input)?.generator_input.generate()
}

fn merge_live_sync_model(
    models: &mut BTreeMap<String, RegistryGeneratorModel>,
    canonical_model: String,
    display_name: String,
    family: String,
    aliases: Vec<String>,
    route: RegistryGeneratorRoute,
) -> AttestationResult<()> {
    if let Some(model) = models.get_mut(&canonical_model) {
        if model.display_name != display_name || model.family != family {
            return Err(AttestationError::InvalidProviderRegistry(format!(
                "live sync enrichment for {canonical_model} has conflicting display metadata"
            )));
        }
        model.aliases.extend(aliases);
        model.routes.push(route);
    } else {
        models.insert(
            canonical_model.clone(),
            RegistryGeneratorModel {
                canonical_model,
                display_name,
                family,
                aliases,
                routes: vec![route],
            },
        );
    }
    Ok(())
}

fn raw_payload_digest(raw_payload: &Value) -> AttestationResult<String> {
    let bytes = serde_json::to_vec(raw_payload).map_err(AttestationError::Json)?;
    Ok(sha256_digest(&bytes))
}

fn provider_model_id(raw_model: &Value) -> Option<String> {
    if let Some(model_id) = raw_model.as_str() {
        return non_empty_model_id(model_id);
    }

    ["id", "model_id", "provider_model", "model", "name", "slug"]
        .into_iter()
        .find_map(|field| {
            raw_model
                .get(field)
                .and_then(Value::as_str)
                .and_then(non_empty_model_id)
        })
}

fn non_empty_model_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn provisional_canonical_model(provider_model: &str) -> String {
    let mut output = String::new();
    let mut previous_separator = false;
    for ch in provider_model.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            output.push(ch);
            previous_separator = false;
        } else if !previous_separator {
            output.push('-');
            previous_separator = true;
        }
    }
    let output = output.trim_matches('-').to_owned();
    if output.is_empty() {
        "unknown-model".into()
    } else {
        output
    }
}

fn dedup_aliases(canonical_model: String, aliases: Vec<String>) -> AttestationResult<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for alias in std::iter::once(canonical_model).chain(aliases) {
        let alias = required_field("alias", alias)?;
        if seen.insert(alias.clone()) {
            output.push(alias);
        }
    }
    Ok(output)
}

fn required_field(field: &'static str, value: String) -> AttestationResult<String> {
    if value.trim().is_empty() {
        Err(AttestationError::InvalidProviderRegistry(format!(
            "generator input field {field} must not be empty"
        )))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Deserialize)]
    struct ProviderLiveSyncCorpus {
        schema: String,
        cases: Vec<ProviderLiveSyncCorpusCase>,
    }

    #[derive(Debug, Deserialize)]
    struct ProviderLiveSyncCorpusCase {
        id: String,
        provider: String,
        #[serde(default)]
        api_base_url: Option<String>,
        #[serde(default)]
        evidence_endpoint: Option<String>,
        #[serde(default)]
        adapter_version: Option<String>,
        #[serde(default)]
        evidence_family: Option<String>,
        #[serde(default)]
        freshness_class: Option<FreshnessClass>,
        #[serde(default)]
        channel_binding_kind: Option<ChannelBindingKind>,
        #[serde(default)]
        trust_tier: Option<TrustTier>,
        #[serde(default)]
        request_confidentiality_requirement: Option<BoundDataRequirement>,
        #[serde(default)]
        response_confidentiality_requirement: Option<BoundDataRequirement>,
        #[serde(default)]
        response_integrity_requirement: Option<ResponseIntegrityRequirement>,
        #[serde(default)]
        accepted_gpu_tees: Vec<GpuTeeKind>,
        #[serde(default)]
        request_encryption: Option<EncryptionRequirement>,
        #[serde(default)]
        response_decryption: Option<EncryptionRequirement>,
        #[serde(default)]
        streaming: Option<StreamingSupport>,
        raw_model_list: Value,
        #[serde(default)]
        enrichments: Vec<RegistryLiveSyncEnrichment>,
        #[serde(default)]
        expected: Option<ExpectedProviderLiveSync>,
        #[serde(default)]
        expected_error_contains: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct ExpectedProviderLiveSync {
        raw_model_ids: Vec<String>,
        reviewed_routes: Vec<ExpectedProviderLiveSyncRoute>,
        unreviewed_routes: Vec<ExpectedProviderLiveSyncRoute>,
    }

    #[derive(Debug, Deserialize)]
    struct ExpectedProviderLiveSyncRoute {
        provider_model: String,
        canonical_model: String,
        route_status: RouteLifecycle,
        alias_confidence: AliasConfidence,
    }

    #[test]
    fn registry_generator_emits_signed_envelope_for_matching_external_signature() {
        let signed_fixture = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let generated = generate_signed_provider_registry(
            generator_input_from_registry(signed_fixture.payload.clone()),
            signed_fixture.signature.clone(),
        )
        .unwrap();

        generated.verify_signature().unwrap();
        assert_eq!(generated.schema, ProviderRegistryEnvelope::SCHEMA);
        assert_eq!(generated.payload, signed_fixture.payload);
        assert_eq!(
            generated.payload.digest().unwrap(),
            signed_fixture.payload.digest().unwrap()
        );
    }

    #[test]
    fn registry_generator_rejects_signature_that_does_not_match_generated_payload() {
        let signed_fixture = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let wrong_signature = ProviderRegistryEnvelope::phase2_fixtures()
            .unwrap()
            .signature;
        let error = generate_signed_provider_registry(
            generator_input_from_registry(signed_fixture.payload),
            wrong_signature,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidArtifactSignature(_)
        ));
    }

    #[test]
    fn registry_generator_preserves_provider_model_ids_and_derives_route_ids() {
        let registry = generate_provider_registry(generator_input(vec![generator_model(
            "gpt-oss-120b",
            vec![generator_route(
                RouteLifecycle::Active,
                "redpill",
                "private/org/gpt-oss-120b:thinking-TEE",
                AliasConfidence::Curated,
            )],
        )]))
        .unwrap();

        let (_, route) = registry
            .find_route(Some("redpill"), "private/org/gpt-oss-120b:thinking-TEE")
            .unwrap();

        assert_eq!(
            route.provider_model,
            "private/org/gpt-oss-120b:thinking-TEE"
        );
        assert_eq!(
            route.route_id,
            "redpill:gpt-oss-120b:private/org/gpt-oss-120b:thinking-TEE"
        );
        assert_eq!(
            registry.models["gpt-oss-120b"].aliases,
            vec!["gpt-oss-120b", "GPT-OSS 120B"]
        );
        assert_eq!(
            registry.source_sync_run.source,
            "confidential-inference-sdk-registry-generator"
        );
    }

    #[test]
    fn registry_generator_sorts_models_and_routes_for_stable_digests() {
        let registry = generate_provider_registry(generator_input(vec![
            generator_model(
                "llama-3.3-70b",
                vec![generator_route(
                    RouteLifecycle::VerificationOnly,
                    "tinfoil",
                    "llama-3.3-70b",
                    AliasConfidence::ProviderDeclared,
                )],
            ),
            generator_model(
                "gpt-oss-120b",
                vec![
                    generator_route(
                        RouteLifecycle::NewUnverified,
                        "venice",
                        "e2ee-gpt-oss-120b-p",
                        AliasConfidence::Algorithmic,
                    ),
                    generator_route(
                        RouteLifecycle::Active,
                        "demo",
                        "e2ee-gpt-oss-120b-p",
                        AliasConfidence::Curated,
                    ),
                ],
            ),
        ]))
        .unwrap();

        assert_eq!(
            registry.models.keys().cloned().collect::<Vec<_>>(),
            vec!["gpt-oss-120b", "llama-3.3-70b"]
        );
        let route_ids = registry.models["gpt-oss-120b"]
            .routes
            .iter()
            .map(|route| route.route_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            route_ids,
            vec![
                "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p",
                "venice:gpt-oss-120b:e2ee-gpt-oss-120b-p"
            ]
        );
    }

    #[test]
    fn registry_generator_keeps_algorithmic_routes_non_executable_until_reviewed() {
        let registry = generate_provider_registry(generator_input(vec![generator_model(
            "gpt-oss-120b",
            vec![generator_route(
                RouteLifecycle::NewUnverified,
                "venice",
                "e2ee-new-gpt-oss-120b-p",
                AliasConfidence::Algorithmic,
            )],
        )]))
        .unwrap();

        assert!(registry
            .find_route(None, "e2ee-new-gpt-oss-120b-p")
            .is_none());
        assert!(registry.find_route(None, "gpt-oss-120b").is_none());
    }

    #[test]
    fn registry_generator_rejects_active_algorithmic_routes() {
        let error = generate_provider_registry(generator_input(vec![generator_model(
            "gpt-oss-120b",
            vec![generator_route(
                RouteLifecycle::Active,
                "venice",
                "e2ee-gpt-oss-120b-p",
                AliasConfidence::Algorithmic,
            )],
        )]))
        .unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidProviderRegistry(_)
        ));
        assert!(error.to_string().contains("algorithmic alias confidence"));
    }

    #[test]
    fn registry_generator_rejects_duplicate_route_ids() {
        let mut left = generator_route(
            RouteLifecycle::VerificationOnly,
            "venice",
            "e2ee-gpt-oss-120b-p",
            AliasConfidence::Curated,
        );
        let mut right = generator_route(
            RouteLifecycle::VerificationOnly,
            "tinfoil",
            "llama-3.3-70b",
            AliasConfidence::Curated,
        );
        left.route_id = Some("duplicate-route".into());
        right.route_id = Some("duplicate-route".into());

        let error = generate_provider_registry(generator_input(vec![
            generator_model("gpt-oss-120b", vec![left]),
            generator_model("llama-3.3-70b", vec![right]),
        ]))
        .unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidProviderRegistry(_)
        ));
        assert!(error
            .to_string()
            .contains("repeats route_id duplicate-route"));
    }

    #[test]
    fn live_sync_ingestion_preserves_exact_provider_model_ids_for_enriched_active_routes() {
        let ingestion = ingest_live_sync_registry(live_sync_input(vec![live_provider(
            "redpill",
            vec![live_raw_model(
                "private/org/gpt-oss-120b:thinking-TEE",
                json!({
                    "id": "private/org/gpt-oss-120b:thinking-TEE",
                    "object": "model",
                    "owned_by": "redpill"
                }),
            )],
            vec![live_enrichment(
                "private/org/gpt-oss-120b:thinking-TEE",
                Some("gpt-oss-120b"),
                RouteLifecycle::Active,
                AliasConfidence::Curated,
            )],
        )]))
        .unwrap();
        let registry = ingestion.generator_input.clone().generate().unwrap();
        let (_, route) = registry
            .find_route(Some("redpill"), "private/org/gpt-oss-120b:thinking-TEE")
            .unwrap();

        assert_eq!(
            route.provider_model,
            "private/org/gpt-oss-120b:thinking-TEE"
        );
        assert_eq!(route.route_status, RouteLifecycle::Active);
        assert_eq!(route.alias_confidence, AliasConfidence::Curated);
        assert_eq!(
            registry.models["gpt-oss-120b"].aliases,
            vec!["gpt-oss-120b", "GPT-OSS 120B"]
        );
        assert_eq!(ingestion.observations.len(), 1);
        assert!(ingestion.observations[0].enrichment_applied);
        assert!(ingestion.observations[0]
            .raw_payload_digest
            .starts_with("sha256:"));
    }

    #[test]
    fn live_sync_ingestion_keeps_unenriched_raw_models_non_executable() {
        let ingestion = ingest_live_sync_registry(live_sync_input(vec![live_provider(
            "venice",
            vec![live_raw_model(
                "private/Gemma 4 31B:TEE",
                json!({"id": "private/Gemma 4 31B:TEE"}),
            )],
            Vec::new(),
        )]))
        .unwrap();
        let registry = ingestion.generator_input.clone().generate().unwrap();
        let model = registry.models.get("private-gemma-4-31b-tee").unwrap();
        let route = model.routes.first().unwrap();

        assert_eq!(route.provider_model, "private/Gemma 4 31B:TEE");
        assert_eq!(route.route_status, RouteLifecycle::NewUnverified);
        assert_eq!(route.alias_confidence, AliasConfidence::Algorithmic);
        assert!(registry
            .find_route(Some("venice"), "private/Gemma 4 31B:TEE")
            .is_none());
        assert!(!ingestion.observations[0].enrichment_applied);
    }

    #[test]
    fn live_sync_ingestion_rejects_duplicate_raw_provider_models() {
        let error = ingest_live_sync_registry(live_sync_input(vec![live_provider(
            "tinfoil",
            vec![
                live_raw_model("llama-3.3-70b", json!({"id": "llama-3.3-70b"})),
                live_raw_model("llama-3.3-70b", json!({"id": "llama-3.3-70b"})),
            ],
            Vec::new(),
        )]))
        .unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidProviderRegistry(_)
        ));
        assert!(error
            .to_string()
            .contains("repeats provider_model tinfoil/llama-3.3-70b"));
    }

    #[test]
    fn live_sync_ingestion_rejects_conflicting_enrichment_for_canonical_model() {
        let error = ingest_live_sync_registry(live_sync_input(vec![
            live_provider(
                "demo",
                vec![live_raw_model(
                    "e2ee-gpt-oss-120b-p",
                    json!({"id": "e2ee-gpt-oss-120b-p"}),
                )],
                vec![live_enrichment(
                    "e2ee-gpt-oss-120b-p",
                    Some("gpt-oss-120b"),
                    RouteLifecycle::Active,
                    AliasConfidence::Curated,
                )],
            ),
            live_provider(
                "venice",
                vec![live_raw_model(
                    "e2ee-gpt-oss-120b-p",
                    json!({"id": "e2ee-gpt-oss-120b-p"}),
                )],
                vec![RegistryLiveSyncEnrichment {
                    provider_model: "e2ee-gpt-oss-120b-p".into(),
                    canonical_model: Some("gpt-oss-120b".into()),
                    display_name: Some("Different GPT".into()),
                    family: Some("OpenAI GPT".into()),
                    aliases: Vec::new(),
                    route_status: Some(RouteLifecycle::VerificationOnly),
                    alias_confidence: Some(AliasConfidence::Curated),
                }],
            ),
        ]))
        .unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidProviderRegistry(_)
        ));
        assert!(error.to_string().contains("conflicting display metadata"));
    }

    #[test]
    fn provider_live_sync_corpus_matches_expected_registry_outcomes() {
        let corpus: ProviderLiveSyncCorpus = serde_json::from_str(include_str!(
            "../../../fixtures/providers/live-sync-corpus.json"
        ))
        .unwrap();
        assert_eq!(
            corpus.schema,
            "confidential-inference.provider-live-sync-corpus.v1"
        );

        for case in corpus.cases {
            let raw_models = parse_provider_model_list_raw_models(&case.raw_model_list);
            match (&case.expected, &case.expected_error_contains, raw_models) {
                (Some(expected), None, Ok(raw_models)) => {
                    assert_eq!(
                        raw_models
                            .iter()
                            .map(|model| model.provider_model.as_str())
                            .collect::<Vec<_>>(),
                        expected
                            .raw_model_ids
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>(),
                        "{}: raw model ids",
                        case.id
                    );

                    let ingestion = ingest_live_sync_registry(RegistryLiveSyncInput {
                        schema: RegistryLiveSyncInput::SCHEMA.into(),
                        version: format!("2026-07-05-{}", case.id),
                        generated_at: "2026-07-05T00:00:00Z".into(),
                        source_sync_run: SourceSyncRun {
                            completed_at: "2026-07-05T00:00:00Z".into(),
                            status: "success".into(),
                            source: format!("{}-live-sync-corpus", case.provider),
                        },
                        providers: vec![case.provider_input(raw_models)],
                    })
                    .unwrap();
                    let registry = ingestion.generator_input.generate().unwrap();
                    registry.validate_security_invariants().unwrap();

                    for expected_route in &expected.reviewed_routes {
                        assert_corpus_route(&case, &registry, expected_route);
                    }
                    for expected_route in &expected.unreviewed_routes {
                        assert_corpus_route(&case, &registry, expected_route);
                        assert!(
                            registry
                                .find_route(Some(&case.provider), &expected_route.provider_model)
                                .is_none(),
                            "{}: unreviewed route must not be executable",
                            case.id
                        );
                    }

                    assert_eq!(
                        ingestion.observations.len(),
                        expected.raw_model_ids.len(),
                        "{}: observation count",
                        case.id
                    );
                    for observation in ingestion.observations {
                        assert_eq!(observation.provider, case.provider, "{}: provider", case.id);
                        assert!(
                            observation.raw_payload_digest.starts_with("sha256:"),
                            "{}: raw payload digest",
                            case.id
                        );
                    }
                }
                (None, Some(expected_error), Err(error)) => {
                    let error = error.to_string();
                    assert!(
                        error.contains(expected_error),
                        "{}: expected error containing {:?}, got {error:?}",
                        case.id,
                        expected_error
                    );
                }
                (Some(_), None, Err(error)) => {
                    panic!("{}: expected live-sync parse success, got {error}", case.id);
                }
                (None, Some(_), Ok(raw_models)) => {
                    panic!(
                        "{}: expected live-sync parse failure, got {:?}",
                        case.id, raw_models
                    );
                }
                _ => panic!(
                    "{}: corpus case must define exactly one expected outcome",
                    case.id
                ),
            }
        }
    }

    fn generator_input(models: Vec<RegistryGeneratorModel>) -> RegistryGeneratorInput {
        RegistryGeneratorInput {
            schema: RegistryGeneratorInput::SCHEMA.into(),
            version: "2026-07-05-generated".into(),
            generated_at: "2026-07-05T00:00:00Z".into(),
            source_sync_run: SourceSyncRun {
                completed_at: "2026-07-05T00:00:00Z".into(),
                status: "success".into(),
                source: "confidential-inference-sdk-registry-generator".into(),
            },
            models,
        }
    }

    fn live_sync_input(providers: Vec<RegistryLiveSyncProvider>) -> RegistryLiveSyncInput {
        RegistryLiveSyncInput {
            schema: RegistryLiveSyncInput::SCHEMA.into(),
            version: "2026-07-05-live-sync".into(),
            generated_at: "2026-07-05T00:00:00Z".into(),
            source_sync_run: SourceSyncRun {
                completed_at: "2026-07-05T00:00:00Z".into(),
                status: "success".into(),
                source: "confidential-inference-sdk-registry-live-sync".into(),
            },
            providers,
        }
    }

    fn live_provider(
        provider: &str,
        raw_models: Vec<RegistryLiveSyncRawModel>,
        enrichments: Vec<RegistryLiveSyncEnrichment>,
    ) -> RegistryLiveSyncProvider {
        RegistryLiveSyncProvider {
            provider: provider.into(),
            api_base_url: format!("http://127.0.0.1/{provider}/v1"),
            evidence_endpoint: format!("http://127.0.0.1/{provider}/v1/confidentiality"),
            adapter_version: format!("{provider}-live-sync-adapter/0.1.0"),
            evidence_family: "fixture_dstack".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            accepted_gpu_tees: Vec::new(),
            request_encryption: EncryptionRequirement::Required,
            response_decryption: EncryptionRequirement::Required,
            streaming: StreamingSupport::Unsupported,
            raw_models,
            enrichments,
        }
    }

    fn live_raw_model(provider_model: &str, raw_payload: Value) -> RegistryLiveSyncRawModel {
        RegistryLiveSyncRawModel {
            provider_model: provider_model.into(),
            raw_payload,
        }
    }

    fn live_enrichment(
        provider_model: &str,
        canonical_model: Option<&str>,
        route_status: RouteLifecycle,
        alias_confidence: AliasConfidence,
    ) -> RegistryLiveSyncEnrichment {
        RegistryLiveSyncEnrichment {
            provider_model: provider_model.into(),
            canonical_model: canonical_model.map(Into::into),
            display_name: Some(
                match canonical_model {
                    Some("llama-3.3-70b") => "Llama 3.3 70B",
                    _ => "GPT-OSS 120B",
                }
                .into(),
            ),
            family: Some(
                match canonical_model {
                    Some("llama-3.3-70b") => "Llama",
                    _ => "OpenAI GPT",
                }
                .into(),
            ),
            aliases: match canonical_model {
                Some("llama-3.3-70b") => vec!["Llama 3.3 70B".into()],
                Some("gpt-oss-120b") => vec!["GPT-OSS 120B".into()],
                _ => Vec::new(),
            },
            route_status: Some(route_status),
            alias_confidence: Some(alias_confidence),
        }
    }

    fn generator_input_from_registry(registry: ProviderRegistry) -> RegistryGeneratorInput {
        let models = registry
            .models
            .into_values()
            .map(|model| RegistryGeneratorModel {
                canonical_model: model.canonical_model,
                display_name: model.display_name,
                family: model.family,
                aliases: model.aliases,
                routes: model
                    .routes
                    .into_iter()
                    .map(|route| RegistryGeneratorRoute {
                        route_id: Some(route.route_id),
                        route_status: route.route_status,
                        provider: route.provider,
                        provider_model: route.provider_model,
                        evidence_family: route.evidence_family,
                        api_base_url: route.api_base_url,
                        evidence_endpoint: route.evidence_endpoint,
                        adapter_version: route.adapter_version,
                        freshness_class: route.freshness_class,
                        channel_binding_kind: route.channel_binding_kind,
                        trust_tier: route.trust_tier,
                        request_confidentiality_requirement: route
                            .request_confidentiality_requirement,
                        response_confidentiality_requirement: route
                            .response_confidentiality_requirement,
                        response_integrity_requirement: route.response_integrity_requirement,
                        accepted_gpu_tees: route.accepted_gpu_tees,
                        request_encryption: route.request_encryption,
                        response_decryption: route.response_decryption,
                        streaming: route.streaming,
                        alias_confidence: route.alias_confidence,
                    })
                    .collect(),
            })
            .collect();

        RegistryGeneratorInput {
            schema: RegistryGeneratorInput::SCHEMA.into(),
            version: registry.version,
            generated_at: registry.generated_at,
            source_sync_run: registry.source_sync_run,
            models,
        }
    }

    fn generator_model(
        canonical_model: &str,
        routes: Vec<RegistryGeneratorRoute>,
    ) -> RegistryGeneratorModel {
        RegistryGeneratorModel {
            canonical_model: canonical_model.into(),
            display_name: match canonical_model {
                "llama-3.3-70b" => "Llama 3.3 70B",
                _ => "GPT-OSS 120B",
            }
            .into(),
            family: match canonical_model {
                "llama-3.3-70b" => "Llama",
                _ => "OpenAI GPT",
            }
            .into(),
            aliases: match canonical_model {
                "llama-3.3-70b" => vec!["Llama 3.3 70B".into()],
                _ => vec!["GPT-OSS 120B".into(), "gpt-oss-120b".into()],
            },
            routes,
        }
    }

    fn generator_route(
        route_status: RouteLifecycle,
        provider: &str,
        provider_model: &str,
        alias_confidence: AliasConfidence,
    ) -> RegistryGeneratorRoute {
        RegistryGeneratorRoute {
            route_id: None,
            route_status,
            provider: provider.into(),
            provider_model: provider_model.into(),
            evidence_family: "fixture_dstack".into(),
            api_base_url: format!("http://127.0.0.1/{provider}/v1"),
            evidence_endpoint: format!("http://127.0.0.1/{provider}/v1/confidentiality"),
            adapter_version: format!("{provider}-fixture-adapter/0.1.0"),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            accepted_gpu_tees: Vec::new(),
            request_encryption: EncryptionRequirement::Required,
            response_decryption: EncryptionRequirement::Required,
            streaming: StreamingSupport::Unsupported,
            alias_confidence,
        }
    }

    impl ProviderLiveSyncCorpusCase {
        fn provider_input(
            &self,
            raw_models: Vec<RegistryLiveSyncRawModel>,
        ) -> RegistryLiveSyncProvider {
            RegistryLiveSyncProvider {
                provider: self.provider.clone(),
                api_base_url: self.required("api_base_url", &self.api_base_url),
                evidence_endpoint: self.required("evidence_endpoint", &self.evidence_endpoint),
                adapter_version: self.required("adapter_version", &self.adapter_version),
                evidence_family: self.required("evidence_family", &self.evidence_family),
                freshness_class: self
                    .freshness_class
                    .clone()
                    .expect("valid corpus case missing freshness_class"),
                channel_binding_kind: self
                    .channel_binding_kind
                    .clone()
                    .expect("valid corpus case missing channel_binding_kind"),
                trust_tier: self
                    .trust_tier
                    .clone()
                    .expect("valid corpus case missing trust_tier"),
                request_confidentiality_requirement: self
                    .request_confidentiality_requirement
                    .clone()
                    .expect("valid corpus case missing request_confidentiality_requirement"),
                response_confidentiality_requirement: self
                    .response_confidentiality_requirement
                    .clone()
                    .expect("valid corpus case missing response_confidentiality_requirement"),
                response_integrity_requirement: self
                    .response_integrity_requirement
                    .clone()
                    .expect("valid corpus case missing response_integrity_requirement"),
                accepted_gpu_tees: self.accepted_gpu_tees.clone(),
                request_encryption: self
                    .request_encryption
                    .clone()
                    .expect("valid corpus case missing request_encryption"),
                response_decryption: self
                    .response_decryption
                    .clone()
                    .expect("valid corpus case missing response_decryption"),
                streaming: self
                    .streaming
                    .clone()
                    .expect("valid corpus case missing streaming"),
                raw_models,
                enrichments: self.enrichments.clone(),
            }
        }

        fn required(&self, field: &str, value: &Option<String>) -> String {
            value
                .clone()
                .unwrap_or_else(|| panic!("{}: valid corpus case missing {field}", self.id))
        }
    }

    fn assert_corpus_route(
        case: &ProviderLiveSyncCorpusCase,
        registry: &ProviderRegistry,
        expected: &ExpectedProviderLiveSyncRoute,
    ) {
        let (model, route) = registry
            .models
            .values()
            .find_map(|model| {
                model
                    .routes
                    .iter()
                    .find(|route| {
                        route.provider == case.provider
                            && route.provider_model == expected.provider_model
                    })
                    .map(|route| (model, route))
            })
            .unwrap_or_else(|| {
                panic!(
                    "{}: missing route {}/{}",
                    case.id, case.provider, expected.provider_model
                )
            });

        assert_eq!(
            model.canonical_model, expected.canonical_model,
            "{}: canonical model",
            case.id
        );
        assert_eq!(
            route.route_status, expected.route_status,
            "{}: route status",
            case.id
        );
        assert_eq!(
            route.alias_confidence, expected.alias_confidence,
            "{}: alias confidence",
            case.id
        );
    }
}
