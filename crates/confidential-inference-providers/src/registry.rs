use confidential_inference_attestation::{
    canonical_digest, parse_utc_timestamp_millis, verify_artifact_signature_with_keys,
    AliasConfidence, ArtifactSignature, AttestationError, AttestedRoute, BoundDataRequirement,
    ChannelBindingKind, FreshnessClass, GpuTeeKind, ResponseIntegrityRequirement,
    Result as AttestationResult, TrustTier, TrustedSigningKey,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRegistryEnvelope {
    pub schema: String,
    pub payload: ProviderRegistry,
    pub signature: ArtifactSignature,
}

impl ProviderRegistryEnvelope {
    pub const SCHEMA: &'static str = "confidential-inference.provider-registry-envelope.v1";

    pub fn bundled_demo() -> AttestationResult<Self> {
        serde_json::from_str(include_str!("../assets/registry/demo-registry.json"))
            .map_err(Into::into)
    }

    pub fn phase2_fixtures() -> AttestationResult<Self> {
        serde_json::from_str(include_str!(
            "../assets/registry/phase2-fixtures-registry.json"
        ))
        .map_err(Into::into)
    }

    pub fn verify_signature(&self) -> AttestationResult<()> {
        self.verify_signature_with_keys(
            &confidential_inference_attestation::default_trusted_signing_keys(),
        )
    }

    pub fn verify_signature_with_keys(
        &self,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> AttestationResult<()> {
        if self.schema != Self::SCHEMA {
            return Err(
                confidential_inference_attestation::AttestationError::InvalidArtifactSignature(
                    "provider registry envelope schema mismatch".into(),
                ),
            );
        }
        self.payload.validate_security_invariants()?;
        verify_artifact_signature_with_keys(&self.signature, &self.payload, trusted_signing_keys)
    }

    pub fn into_verified_payload(self) -> AttestationResult<ProviderRegistry> {
        self.verify_signature()?;
        self.payload.validate_security_invariants()?;
        Ok(self.payload)
    }

    pub fn into_verified_payload_with_keys(
        self,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> AttestationResult<ProviderRegistry> {
        self.verify_signature_with_keys(trusted_signing_keys)?;
        self.payload.validate_security_invariants()?;
        Ok(self.payload)
    }

    pub fn into_verified_update_from(
        self,
        current: &ProviderRegistry,
    ) -> AttestationResult<ProviderRegistry> {
        self.verify_signature()?;
        self.payload.validate_security_invariants()?;
        current.verify_update_to(&self.payload)?;
        Ok(self.payload)
    }

    pub fn into_verified_update_from_with_keys(
        self,
        current: &ProviderRegistry,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> AttestationResult<ProviderRegistry> {
        self.verify_signature_with_keys(trusted_signing_keys)?;
        self.payload.validate_security_invariants()?;
        current.verify_update_to(&self.payload)?;
        Ok(self.payload)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAliasMatrixEnvelope {
    pub schema: String,
    pub payload: ModelAliasMatrix,
    pub signature: ArtifactSignature,
}

impl ModelAliasMatrixEnvelope {
    pub const SCHEMA: &'static str = "confidential-inference.model-alias-matrix-envelope.v1";

    pub fn bundled() -> AttestationResult<Self> {
        serde_json::from_str(include_str!(
            "../assets/registry/model-alias-matrix-envelope.json"
        ))
        .map_err(Into::into)
    }

    pub fn verify_signature(&self) -> AttestationResult<()> {
        self.verify_signature_with_keys(
            &confidential_inference_attestation::default_trusted_signing_keys(),
        )
    }

    pub fn verify_signature_with_keys(
        &self,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> AttestationResult<()> {
        if self.schema != Self::SCHEMA {
            return Err(AttestationError::InvalidProviderRegistry(
                "model alias matrix envelope schema mismatch".into(),
            ));
        }
        verify_artifact_signature_with_keys(&self.signature, &self.payload, trusted_signing_keys)?;
        self.payload.validate()
    }

    pub fn into_verified_payload(self) -> AttestationResult<ModelAliasMatrix> {
        self.verify_signature()?;
        Ok(self.payload)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAliasMatrix {
    pub schema: String,
    pub models: Vec<ModelAliasCase>,
}

impl ModelAliasMatrix {
    pub const SCHEMA: &'static str = "confidential-inference.model-alias-matrix.v1";
    pub const SUPPORTED_SCHEMA_MAJOR: u32 = 1;

    pub fn bundled() -> AttestationResult<Self> {
        ModelAliasMatrixEnvelope::bundled()?.into_verified_payload()
    }

    #[cfg(test)]
    fn bundled_raw_fixture() -> AttestationResult<Self> {
        serde_json::from_str(include_str!(
            "../../../fixtures/registry/model-alias-matrix.json"
        ))
        .map_err(Into::into)
    }

    pub fn digest(&self) -> AttestationResult<String> {
        validate_model_alias_matrix_schema_major("schema", &self.schema)?;
        canonical_digest(self)
    }

    pub fn validate(&self) -> AttestationResult<()> {
        if self.schema != Self::SCHEMA {
            return Err(AttestationError::InvalidProviderRegistry(format!(
                "unsupported model alias matrix schema {}",
                self.schema
            )));
        }
        if self.models.is_empty() {
            return Err(AttestationError::InvalidProviderRegistry(
                "model alias matrix contains no models".into(),
            ));
        }

        let mut canonical_models = BTreeSet::new();
        for model in &self.models {
            model.validate()?;
            if !canonical_models.insert(model.canonical_model.clone()) {
                return Err(AttestationError::InvalidProviderRegistry(format!(
                    "model alias matrix repeats canonical model {}",
                    model.canonical_model
                )));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAliasCase {
    pub canonical_model: String,
    pub display_name: String,
    pub family: String,
    pub aliases: Vec<String>,
    pub provider_routes: Vec<ModelAliasProviderRoute>,
    pub must_not_match: Vec<String>,
}

impl ModelAliasCase {
    fn validate(&self) -> AttestationResult<()> {
        if self.canonical_model.trim().is_empty() {
            return Err(AttestationError::InvalidProviderRegistry(
                "model alias matrix has an empty canonical_model".into(),
            ));
        }
        for field in [
            ("display_name", &self.display_name),
            ("family", &self.family),
        ] {
            if field.1.trim().is_empty() {
                return Err(AttestationError::InvalidProviderRegistry(format!(
                    "model alias matrix {} {} must be non-empty",
                    self.canonical_model, field.0
                )));
            }
        }
        if self.aliases.is_empty() {
            return Err(AttestationError::InvalidProviderRegistry(format!(
                "model alias matrix {} has no aliases",
                self.canonical_model
            )));
        }
        if self.provider_routes.is_empty() {
            return Err(AttestationError::InvalidProviderRegistry(format!(
                "model alias matrix {} has no provider routes",
                self.canonical_model
            )));
        }

        let mut aliases = BTreeSet::new();
        for alias in &self.aliases {
            if alias.trim().is_empty() {
                return Err(AttestationError::InvalidProviderRegistry(format!(
                    "model alias matrix {} has an empty alias",
                    self.canonical_model
                )));
            }
            if !aliases.insert(alias.clone()) {
                return Err(AttestationError::InvalidProviderRegistry(format!(
                    "model alias matrix {} repeats alias {}",
                    self.canonical_model, alias
                )));
            }
        }
        if !aliases.contains(&self.canonical_model) {
            return Err(AttestationError::InvalidProviderRegistry(format!(
                "model alias matrix {} aliases must include the canonical model",
                self.canonical_model
            )));
        }

        let mut provider_routes = BTreeSet::new();
        for route in &self.provider_routes {
            route.validate(&self.canonical_model)?;
            if !provider_routes.insert((route.provider.clone(), route.provider_model.clone())) {
                return Err(AttestationError::InvalidProviderRegistry(format!(
                    "model alias matrix {} repeats provider route {}/{}",
                    self.canonical_model, route.provider, route.provider_model
                )));
            }
        }

        for rejected in &self.must_not_match {
            if rejected.trim().is_empty() {
                return Err(AttestationError::InvalidProviderRegistry(format!(
                    "model alias matrix {} has an empty must_not_match entry",
                    self.canonical_model
                )));
            }
            if aliases.contains(rejected) {
                return Err(AttestationError::InvalidProviderRegistry(format!(
                    "model alias matrix {} rejects explicit alias {}",
                    self.canonical_model, rejected
                )));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAliasProviderRoute {
    pub provider: String,
    pub provider_model: String,
}

impl ModelAliasProviderRoute {
    fn validate(&self, canonical_model: &str) -> AttestationResult<()> {
        if self.provider.trim().is_empty() {
            return Err(AttestationError::InvalidProviderRegistry(format!(
                "model alias matrix {canonical_model} has an empty provider route provider"
            )));
        }
        if self.provider_model.trim().is_empty() {
            return Err(AttestationError::InvalidProviderRegistry(format!(
                "model alias matrix {canonical_model} has an empty provider_model"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRegistry {
    pub schema: String,
    pub version: String,
    pub generated_at: String,
    pub source_sync_run: SourceSyncRun,
    pub models: BTreeMap<String, RegistryModel>,
}

impl ProviderRegistry {
    pub const SCHEMA: &'static str = "confidential-inference.provider-registry.v1";
    pub const SUPPORTED_SCHEMA_MAJOR: u32 = 1;

    pub fn bundled_demo() -> AttestationResult<Self> {
        ProviderRegistryEnvelope::bundled_demo()?.into_verified_payload()
    }

    pub fn phase2_fixtures() -> AttestationResult<Self> {
        ProviderRegistryEnvelope::phase2_fixtures()?.into_verified_payload()
    }

    pub fn digest(&self) -> AttestationResult<String> {
        validate_provider_registry_schema_major("schema", &self.schema)?;
        self.validate_timestamp_metadata()?;
        canonical_digest(self)
    }

    pub fn verify_update_to(&self, candidate: &ProviderRegistry) -> AttestationResult<()> {
        self.validate_security_invariants()?;
        candidate.validate_security_invariants()?;

        if candidate.schema != Self::SCHEMA {
            return Err(AttestationError::InvalidRegistryUpdate(format!(
                "unsupported registry schema {}",
                candidate.schema
            )));
        }

        if candidate.source_sync_run.status != "success" {
            return Err(AttestationError::InvalidRegistryUpdate(format!(
                "registry sync status is {}",
                candidate.source_sync_run.status
            )));
        }

        if candidate.version < self.version {
            return Err(AttestationError::InvalidRegistryUpdate(format!(
                "candidate registry version {} is older than current {}",
                candidate.version, self.version
            )));
        }

        for (model_id, current_model) in &self.models {
            let Some(candidate_model) = candidate.models.get(model_id) else {
                return Err(AttestationError::WeakeningRegistryUpdate(format!(
                    "model {model_id} was removed"
                )));
            };

            if candidate_model.canonical_model != current_model.canonical_model {
                return Err(AttestationError::WeakeningRegistryUpdate(format!(
                    "model {model_id} canonical identity changed from {} to {}",
                    current_model.canonical_model, candidate_model.canonical_model
                )));
            }

            for alias in &current_model.aliases {
                if !candidate_model
                    .aliases
                    .iter()
                    .any(|candidate| candidate == alias)
                {
                    return Err(AttestationError::WeakeningRegistryUpdate(format!(
                        "model {model_id} removed alias {alias}"
                    )));
                }
            }

            for current_route in current_model
                .routes
                .iter()
                .filter(|route| route.route_status.security_sensitive())
            {
                let Some(candidate_route) = candidate_model
                    .routes
                    .iter()
                    .find(|route| route.route_id == current_route.route_id)
                else {
                    return Err(AttestationError::WeakeningRegistryUpdate(format!(
                        "security-sensitive route {} was removed",
                        current_route.route_id
                    )));
                };

                current_route.verify_not_weakened_by(candidate_route)?;
            }
        }

        Ok(())
    }

    pub fn diff_to(
        &self,
        candidate: &ProviderRegistry,
    ) -> AttestationResult<ProviderRegistryDiffReport> {
        self.validate_security_invariants()?;
        candidate.validate_security_invariants()?;

        let mut changes = Vec::new();

        for (model_id, current_model) in &self.models {
            let Some(candidate_model) = candidate.models.get(model_id) else {
                changes.push(RegistryDiffChange::model(
                    RegistryDiffKind::ModelRemoved,
                    model_id,
                    Some(json_value(current_model)?),
                    None,
                    true,
                ));
                continue;
            };

            push_model_field_change(
                &mut changes,
                model_id,
                "display_name",
                &current_model.display_name,
                &candidate_model.display_name,
                false,
            )?;
            push_model_field_change(
                &mut changes,
                model_id,
                "family",
                &current_model.family,
                &candidate_model.family,
                false,
            )?;

            let current_aliases = current_model
                .aliases
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let candidate_aliases = candidate_model
                .aliases
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();

            for alias in candidate_aliases.difference(&current_aliases) {
                changes.push(RegistryDiffChange::alias(
                    RegistryDiffKind::AliasAdded,
                    model_id,
                    alias,
                ));
            }
            for alias in current_aliases.difference(&candidate_aliases) {
                changes.push(RegistryDiffChange::alias(
                    RegistryDiffKind::AliasRemoved,
                    model_id,
                    alias,
                ));
            }

            let current_routes = route_map(current_model);
            let candidate_routes = route_map(candidate_model);

            for (route_id, current_route) in &current_routes {
                let Some(candidate_route) = candidate_routes.get(route_id) else {
                    changes.push(RegistryDiffChange::route(
                        RegistryDiffKind::RouteRemoved,
                        model_id,
                        current_route,
                        Some(json_value(current_route)?),
                        None,
                        current_route.route_status.security_sensitive(),
                    ));
                    continue;
                };

                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "route_status",
                    &current_route.route_status,
                    &candidate_route.route_status,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "provider",
                    &current_route.provider,
                    &candidate_route.provider,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "provider_model",
                    &current_route.provider_model,
                    &candidate_route.provider_model,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "evidence_family",
                    &current_route.evidence_family,
                    &candidate_route.evidence_family,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "api_base_url",
                    &current_route.api_base_url,
                    &candidate_route.api_base_url,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "evidence_endpoint",
                    &current_route.evidence_endpoint,
                    &candidate_route.evidence_endpoint,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "adapter_version",
                    &current_route.adapter_version,
                    &candidate_route.adapter_version,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "freshness_class",
                    &current_route.freshness_class,
                    &candidate_route.freshness_class,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "channel_binding_kind",
                    &current_route.channel_binding_kind,
                    &candidate_route.channel_binding_kind,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "trust_tier",
                    &current_route.trust_tier,
                    &candidate_route.trust_tier,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "request_confidentiality_requirement",
                    &current_route.request_confidentiality_requirement,
                    &candidate_route.request_confidentiality_requirement,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "response_confidentiality_requirement",
                    &current_route.response_confidentiality_requirement,
                    &candidate_route.response_confidentiality_requirement,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "response_integrity_requirement",
                    &current_route.response_integrity_requirement,
                    &candidate_route.response_integrity_requirement,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "accepted_gpu_tees",
                    &current_route.accepted_gpu_tees,
                    &candidate_route.accepted_gpu_tees,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "request_encryption",
                    &current_route.request_encryption,
                    &candidate_route.request_encryption,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "response_decryption",
                    &current_route.response_decryption,
                    &candidate_route.response_decryption,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "streaming",
                    &current_route.streaming,
                    &candidate_route.streaming,
                    true,
                )?;
                push_route_field_change(
                    &mut changes,
                    model_id,
                    current_route,
                    "alias_confidence",
                    &current_route.alias_confidence,
                    &candidate_route.alias_confidence,
                    true,
                )?;
            }

            for (route_id, candidate_route) in &candidate_routes {
                if current_routes.contains_key(route_id) {
                    continue;
                }
                changes.push(RegistryDiffChange::route(
                    RegistryDiffKind::RouteAdded,
                    model_id,
                    candidate_route,
                    None,
                    Some(json_value(candidate_route)?),
                    candidate_route.route_status.security_sensitive(),
                ));
            }
        }

        for (model_id, candidate_model) in &candidate.models {
            if self.models.contains_key(model_id) {
                continue;
            }
            changes.push(RegistryDiffChange::model(
                RegistryDiffKind::ModelAdded,
                model_id,
                None,
                Some(json_value(candidate_model)?),
                candidate_model
                    .routes
                    .iter()
                    .any(|route| route.route_status.security_sensitive()),
            ));
        }

        Ok(ProviderRegistryDiffReport {
            from_version: self.version.clone(),
            to_version: candidate.version.clone(),
            from_digest: self.digest()?,
            to_digest: candidate.digest()?,
            changes,
        })
    }

    pub fn validate_security_invariants(&self) -> AttestationResult<()> {
        if self.schema != Self::SCHEMA {
            return Err(AttestationError::InvalidRegistryUpdate(format!(
                "unsupported registry schema {}",
                self.schema
            )));
        }

        self.validate_timestamp_metadata()?;

        if self.source_sync_run.status != "success" {
            return Err(AttestationError::InvalidRegistryUpdate(format!(
                "registry sync status is {}",
                self.source_sync_run.status
            )));
        }

        let mut alias_to_model = BTreeMap::<String, String>::new();
        let mut active_provider_models = BTreeMap::<(String, String), String>::new();

        for (model_id, model) in &self.models {
            if model_id != &model.canonical_model {
                return Err(AttestationError::InvalidProviderRegistry(format!(
                    "model key {model_id} does not match canonical model {}",
                    model.canonical_model
                )));
            }

            let mut model_aliases = BTreeSet::new();
            for alias in &model.aliases {
                if alias.trim().is_empty() {
                    return Err(AttestationError::InvalidProviderRegistry(format!(
                        "model {model_id} contains an empty alias"
                    )));
                }
                if !model_aliases.insert(alias) {
                    return Err(AttestationError::InvalidProviderRegistry(format!(
                        "model {model_id} repeats alias {alias}"
                    )));
                }
                if let Some(existing_model) =
                    alias_to_model.insert(alias.clone(), model.canonical_model.clone())
                {
                    if existing_model != model.canonical_model {
                        return Err(AttestationError::InvalidProviderRegistry(format!(
                            "alias {alias} maps to both {existing_model} and {}",
                            model.canonical_model
                        )));
                    }
                }
            }

            for route in &model.routes {
                if route.route_id.trim().is_empty() {
                    return Err(AttestationError::InvalidProviderRegistry(format!(
                        "model {model_id} contains a route with an empty route_id"
                    )));
                }
                reject_route_url_credentials(route, "api_base_url", &route.api_base_url)?;
                reject_route_url_credentials(route, "evidence_endpoint", &route.evidence_endpoint)?;
                if route.provider.trim().is_empty() || route.provider_model.trim().is_empty() {
                    return Err(AttestationError::InvalidProviderRegistry(format!(
                        "route {} has an empty provider or provider_model",
                        route.route_id
                    )));
                }

                if route.route_status.security_sensitive() {
                    if route.alias_confidence == AliasConfidence::Algorithmic {
                        return Err(AttestationError::InvalidProviderRegistry(format!(
                            "active route {} uses algorithmic alias confidence",
                            route.route_id
                        )));
                    }

                    let provider_model_key = (route.provider.clone(), route.provider_model.clone());
                    if let Some(existing_model) = active_provider_models
                        .insert(provider_model_key, model.canonical_model.clone())
                    {
                        if existing_model != model.canonical_model {
                            return Err(AttestationError::InvalidProviderRegistry(format!(
                                "active provider model {}/{} maps to both {existing_model} and {}",
                                route.provider, route.provider_model, model.canonical_model
                            )));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_timestamp_metadata(&self) -> AttestationResult<()> {
        parse_registry_timestamp("generated_at", &self.generated_at)?;
        parse_registry_timestamp(
            "source_sync_run.completed_at",
            &self.source_sync_run.completed_at,
        )?;
        Ok(())
    }

    pub fn find_route(
        &self,
        provider: Option<&str>,
        requested_model: &str,
    ) -> Option<(&RegistryModel, &RouteDefinition)> {
        self.matching_routes(provider, requested_model)
            .into_iter()
            .next()
    }

    pub fn matching_routes(
        &self,
        provider: Option<&str>,
        requested_model: &str,
    ) -> Vec<(&RegistryModel, &RouteDefinition)> {
        self.models
            .values()
            .flat_map(|model| {
                model.routes.iter().filter_map(move |route| {
                    if route.route_status.selectable_for_verification()
                        && provider.is_none_or(|provider| provider == route.provider)
                        && route.matches_request_model(model, requested_model)
                    {
                        Some((model, route))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRegistryPin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_signing_identities: Vec<ProviderRegistrySigningIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_millis: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRegistrySigningIdentity {
    pub signer: String,
    pub key_id: String,
    pub alg: String,
}

impl ProviderRegistrySigningIdentity {
    pub fn new(
        signer: impl Into<String>,
        key_id: impl Into<String>,
        alg: impl Into<String>,
    ) -> Self {
        Self {
            signer: signer.into(),
            key_id: key_id.into(),
            alg: alg.into(),
        }
    }

    pub fn ed25519(signer: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self::new(signer, key_id, "ed25519")
    }

    fn matches_signature(&self, signature: &ArtifactSignature) -> bool {
        self.signer == signature.signer
            && self.key_id == signature.key_id
            && self.alg == signature.alg
    }
}

impl ProviderRegistryPin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn digest(digest: impl Into<String>) -> Self {
        Self::new().with_digest(digest)
    }

    pub fn version(version: impl Into<String>) -> Self {
        Self::new().with_version(version)
    }

    pub fn minimum_version(version: impl Into<String>) -> Self {
        Self::new().with_minimum_version(version)
    }

    pub fn digest_and_version(digest: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new().with_digest(digest).with_version(version)
    }

    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn with_minimum_version(mut self, version: impl Into<String>) -> Self {
        self.minimum_version = Some(version.into());
        self
    }

    pub fn with_accepted_signing_identity(
        mut self,
        identity: ProviderRegistrySigningIdentity,
    ) -> Self {
        self.accepted_signing_identities.push(identity);
        self
    }

    pub fn with_accepted_ed25519_signing_identity(
        self,
        signer: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        self.with_accepted_signing_identity(ProviderRegistrySigningIdentity::ed25519(
            signer, key_id,
        ))
    }

    pub fn with_max_age_millis(mut self, millis: u64) -> Self {
        self.max_age_millis = Some(millis);
        self
    }

    pub fn verify(&self, registry: &ProviderRegistry) -> AttestationResult<()> {
        let digest = registry.digest()?;
        self.verify_with_digest(registry, &digest)
    }

    pub fn verify_with_digest(
        &self,
        registry: &ProviderRegistry,
        digest: &str,
    ) -> AttestationResult<()> {
        self.verify_with_digest_at(registry, digest, now_epoch_millis())
    }

    pub fn verify_with_digest_at(
        &self,
        registry: &ProviderRegistry,
        digest: &str,
        now_epoch_millis: u64,
    ) -> AttestationResult<()> {
        if let Some(expected_digest) = &self.digest {
            if digest != expected_digest {
                return Err(AttestationError::InvalidRegistryUpdate(format!(
                    "registry digest pin mismatch: expected {expected_digest}, got {digest}"
                )));
            }
        }

        if let Some(expected_version) = &self.version {
            if &registry.version != expected_version {
                return Err(AttestationError::InvalidRegistryUpdate(format!(
                    "registry version pin mismatch: expected {expected_version}, got {}",
                    registry.version
                )));
            }
        }

        if let Some(minimum_version) = &self.minimum_version {
            if &registry.version < minimum_version {
                return Err(AttestationError::InvalidRegistryUpdate(format!(
                    "registry version {} is older than pinned minimum {minimum_version}",
                    registry.version
                )));
            }
        }

        if let Some(max_age_millis) = self.max_age_millis {
            let completed_at = parse_utc_timestamp_millis(&registry.source_sync_run.completed_at)
                .map_err(|error| {
                AttestationError::InvalidRegistryUpdate(format!(
                    "registry source_sync_run.completed_at is invalid: {error}"
                ))
            })?;
            if completed_at > now_epoch_millis {
                return Err(AttestationError::InvalidRegistryUpdate(format!(
                    "registry source_sync_run.completed_at {} is in the future",
                    registry.source_sync_run.completed_at
                )));
            }
            let age_millis = now_epoch_millis.saturating_sub(completed_at);
            if age_millis > max_age_millis {
                return Err(AttestationError::InvalidRegistryUpdate(format!(
                    "registry age {age_millis}ms exceeds pinned maximum {max_age_millis}ms"
                )));
            }
        }

        Ok(())
    }

    pub fn verify_envelope_with_digest_at(
        &self,
        envelope: &ProviderRegistryEnvelope,
        digest: &str,
        now_epoch_millis: u64,
    ) -> AttestationResult<()> {
        if !self.accepted_signing_identities.is_empty()
            && !self
                .accepted_signing_identities
                .iter()
                .any(|identity| identity.matches_signature(&envelope.signature))
        {
            return Err(AttestationError::InvalidRegistryUpdate(format!(
                "registry signing identity pin mismatch: got {}/{}/{}",
                envelope.signature.signer, envelope.signature.key_id, envelope.signature.alg
            )));
        }

        self.verify_with_digest_at(&envelope.payload, digest, now_epoch_millis)
    }
}

fn parse_registry_timestamp(field: &str, value: &str) -> AttestationResult<u64> {
    parse_utc_timestamp_millis(value).map_err(|error| {
        AttestationError::InvalidRegistryUpdate(format!("registry {field} is invalid: {error}"))
    })
}

fn validate_model_alias_matrix_schema_major(field: &str, value: &str) -> AttestationResult<()> {
    let Some(version) = value
        .strip_prefix("confidential-inference.model-alias-matrix")
        .and_then(|rest| rest.strip_prefix(".v"))
    else {
        return Err(AttestationError::InvalidProviderRegistry(format!(
            "{field} must start with confidential-inference.model-alias-matrix.v{}",
            ModelAliasMatrix::SUPPORTED_SCHEMA_MAJOR
        )));
    };
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or_default();
    if major.is_empty() || major.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(AttestationError::InvalidProviderRegistry(format!(
            "{field} has malformed schema version {value}"
        )));
    }
    for part in parts {
        if part.is_empty() || part.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(AttestationError::InvalidProviderRegistry(format!(
                "{field} has malformed schema version {value}"
            )));
        }
    }
    let parsed_major = major.parse::<u32>().map_err(|_| {
        AttestationError::InvalidProviderRegistry(format!(
            "{field} has malformed schema version {value}"
        ))
    })?;
    if parsed_major != ModelAliasMatrix::SUPPORTED_SCHEMA_MAJOR {
        return Err(AttestationError::InvalidProviderRegistry(format!(
            "{field} major version {parsed_major} is not supported"
        )));
    }
    Ok(())
}

fn validate_provider_registry_schema_major(field: &str, value: &str) -> AttestationResult<()> {
    let Some(version) = value
        .strip_prefix("confidential-inference.provider-registry")
        .and_then(|rest| rest.strip_prefix(".v"))
    else {
        return Err(AttestationError::InvalidRegistryUpdate(format!(
            "{field} must start with confidential-inference.provider-registry.v{}",
            ProviderRegistry::SUPPORTED_SCHEMA_MAJOR
        )));
    };
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or_default();
    if major.is_empty() || major.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(AttestationError::InvalidRegistryUpdate(format!(
            "{field} has malformed schema version {value}"
        )));
    }
    for part in parts {
        if part.is_empty() || part.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(AttestationError::InvalidRegistryUpdate(format!(
                "{field} has malformed schema version {value}"
            )));
        }
    }
    let parsed_major = major.parse::<u32>().map_err(|_| {
        AttestationError::InvalidRegistryUpdate(format!(
            "{field} has malformed schema version {value}"
        ))
    })?;
    if parsed_major != ProviderRegistry::SUPPORTED_SCHEMA_MAJOR {
        return Err(AttestationError::InvalidRegistryUpdate(format!(
            "{field} major version {parsed_major} is not supported"
        )));
    }
    Ok(())
}

fn now_epoch_millis() -> u64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    millis.min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProviderRegistryDiffReport {
    pub from_version: String,
    pub to_version: String,
    pub from_digest: String,
    pub to_digest: String,
    pub changes: Vec<RegistryDiffChange>,
}

impl ProviderRegistryDiffReport {
    pub fn review_required(&self) -> bool {
        self.changes.iter().any(|change| change.review_required)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegistryDiffChange {
    pub kind: RegistryDiffKind,
    pub model: String,
    pub route_id: Option<String>,
    pub provider: Option<String>,
    pub provider_model: Option<String>,
    pub field: Option<String>,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub review_required: bool,
}

impl RegistryDiffChange {
    fn model(
        kind: RegistryDiffKind,
        model: &str,
        before: Option<Value>,
        after: Option<Value>,
        review_required: bool,
    ) -> Self {
        Self {
            kind,
            model: model.to_owned(),
            route_id: None,
            provider: None,
            provider_model: None,
            field: None,
            before,
            after,
            review_required,
        }
    }

    fn alias(kind: RegistryDiffKind, model: &str, alias: &str) -> Self {
        let (before, after) = match kind {
            RegistryDiffKind::AliasAdded => (None, Some(Value::String(alias.to_owned()))),
            RegistryDiffKind::AliasRemoved => (Some(Value::String(alias.to_owned())), None),
            _ => unreachable!("alias helper requires alias diff kind"),
        };
        Self {
            kind,
            model: model.to_owned(),
            route_id: None,
            provider: None,
            provider_model: None,
            field: Some("aliases".into()),
            before,
            after,
            review_required: true,
        }
    }

    fn route(
        kind: RegistryDiffKind,
        model: &str,
        route: &RouteDefinition,
        before: Option<Value>,
        after: Option<Value>,
        review_required: bool,
    ) -> Self {
        Self {
            kind,
            model: model.to_owned(),
            route_id: Some(route.route_id.clone()),
            provider: Some(route.provider.clone()),
            provider_model: Some(route.provider_model.clone()),
            field: None,
            before,
            after,
            review_required,
        }
    }

    fn route_field<T: Serialize>(
        model: &str,
        route: &RouteDefinition,
        field: &str,
        before: &T,
        after: &T,
        review_required: bool,
    ) -> AttestationResult<Self> {
        Ok(Self {
            kind: RegistryDiffKind::RouteFieldChanged,
            model: model.to_owned(),
            route_id: Some(route.route_id.clone()),
            provider: Some(route.provider.clone()),
            provider_model: Some(route.provider_model.clone()),
            field: Some(field.to_owned()),
            before: Some(json_value(before)?),
            after: Some(json_value(after)?),
            review_required,
        })
    }

    fn model_field<T: Serialize>(
        model: &str,
        field: &str,
        before: &T,
        after: &T,
        review_required: bool,
    ) -> AttestationResult<Self> {
        Ok(Self {
            kind: RegistryDiffKind::ModelFieldChanged,
            model: model.to_owned(),
            route_id: None,
            provider: None,
            provider_model: None,
            field: Some(field.to_owned()),
            before: Some(json_value(before)?),
            after: Some(json_value(after)?),
            review_required,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryDiffKind {
    ModelAdded,
    ModelRemoved,
    ModelFieldChanged,
    AliasAdded,
    AliasRemoved,
    RouteAdded,
    RouteRemoved,
    RouteFieldChanged,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSyncRun {
    pub completed_at: String,
    pub status: String,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryModel {
    pub canonical_model: String,
    pub display_name: String,
    pub family: String,
    pub aliases: Vec<String>,
    pub routes: Vec<RouteDefinition>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDefinition {
    pub route_id: String,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_gpu_tees: Vec<GpuTeeKind>,
    pub request_encryption: EncryptionRequirement,
    pub response_decryption: EncryptionRequirement,
    pub streaming: StreamingSupport,
    pub alias_confidence: AliasConfidence,
}

impl RouteDefinition {
    pub fn to_attested_route(
        &self,
        requested_model: impl Into<String>,
        canonical_model: impl Into<String>,
    ) -> AttestedRoute {
        AttestedRoute {
            provider: self.provider.clone(),
            route_id: self.route_id.clone(),
            evidence_family: self.evidence_family.clone(),
            requested_model: requested_model.into(),
            provider_model: self.provider_model.clone(),
            canonical_model: canonical_model.into(),
            api_endpoint: self.api_base_url.clone(),
            evidence_endpoint: self.evidence_endpoint.clone(),
            adapter_version: self.adapter_version.clone(),
            freshness_class: self.freshness_class.clone(),
            channel_binding_kind: self.channel_binding_kind.clone(),
            trust_tier: self.trust_tier.clone(),
            alias_confidence: self.alias_confidence.clone(),
            request_confidentiality_requirement: self.request_confidentiality_requirement.clone(),
            response_confidentiality_requirement: self.response_confidentiality_requirement.clone(),
            response_integrity_requirement: self.response_integrity_requirement.clone(),
            streaming_allowed: self.streaming.allows_streaming(),
        }
    }

    fn matches_request_model(&self, model: &RegistryModel, requested_model: &str) -> bool {
        self.provider_model == requested_model
            || model.canonical_model == requested_model
            || (alias_allowed_by_default(&self.alias_confidence)
                && model.aliases.iter().any(|alias| alias == requested_model))
    }

    fn verify_not_weakened_by(&self, candidate: &RouteDefinition) -> AttestationResult<()> {
        let route_id = &self.route_id;
        if route_lifecycle_security_rank(&candidate.route_status)
            < route_lifecycle_security_rank(&self.route_status)
        {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} changed status from {:?} to {:?}",
                self.route_status, candidate.route_status
            )));
        }

        fail_if_changed(route_id, "provider", &self.provider, &candidate.provider)?;
        fail_if_changed(
            route_id,
            "provider_model",
            &self.provider_model,
            &candidate.provider_model,
        )?;
        fail_if_changed(
            route_id,
            "evidence_family",
            &self.evidence_family,
            &candidate.evidence_family,
        )?;
        fail_if_changed(
            route_id,
            "api_base_url",
            &self.api_base_url,
            &candidate.api_base_url,
        )?;
        fail_if_changed(
            route_id,
            "evidence_endpoint",
            &self.evidence_endpoint,
            &candidate.evidence_endpoint,
        )?;
        fail_if_changed(
            route_id,
            "adapter_version",
            &self.adapter_version,
            &candidate.adapter_version,
        )?;

        if trust_tier_rank(&candidate.trust_tier) < trust_tier_rank(&self.trust_tier) {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} downgraded trust tier from {:?} to {:?}",
                self.trust_tier, candidate.trust_tier
            )));
        }

        if self.channel_binding_kind != candidate.channel_binding_kind {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} changed channel binding from {:?} to {:?}",
                self.channel_binding_kind, candidate.channel_binding_kind
            )));
        }

        if bound_data_rank(&candidate.request_confidentiality_requirement)
            < bound_data_rank(&self.request_confidentiality_requirement)
        {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} weakened request confidentiality requirement"
            )));
        }

        if bound_data_rank(&candidate.response_confidentiality_requirement)
            < bound_data_rank(&self.response_confidentiality_requirement)
        {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} weakened response confidentiality requirement"
            )));
        }

        if response_integrity_rank(&candidate.response_integrity_requirement)
            < response_integrity_rank(&self.response_integrity_requirement)
        {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} weakened response integrity requirement"
            )));
        }

        if self.response_integrity_requirement != candidate.response_integrity_requirement
            && response_integrity_rank(&self.response_integrity_requirement) >= 2
        {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} changed concrete response integrity requirement from {:?} to {:?}",
                self.response_integrity_requirement, candidate.response_integrity_requirement
            )));
        }

        fail_if_removed_values(
            route_id,
            "accepted_gpu_tees",
            &self.accepted_gpu_tees,
            &candidate.accepted_gpu_tees,
        )?;

        if self.request_encryption == EncryptionRequirement::Required
            && candidate.request_encryption != EncryptionRequirement::Required
        {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} removed request encryption"
            )));
        }

        if self.response_decryption == EncryptionRequirement::Required
            && candidate.response_decryption != EncryptionRequirement::Required
        {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} removed response decryption"
            )));
        }

        if alias_confidence_rank(&candidate.alias_confidence)
            < alias_confidence_rank(&self.alias_confidence)
        {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} weakened alias confidence from {:?} to {:?}",
                self.alias_confidence, candidate.alias_confidence
            )));
        }

        if self.streaming == StreamingSupport::Unsupported
            && candidate.streaming != StreamingSupport::Unsupported
        {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} enabled streaming without review"
            )));
        }

        Ok(())
    }
}

fn fail_if_changed<T>(
    route_id: &str,
    field: &str,
    current: &T,
    candidate: &T,
) -> AttestationResult<()>
where
    T: PartialEq + std::fmt::Debug,
{
    if current == candidate {
        Ok(())
    } else {
        Err(AttestationError::WeakeningRegistryUpdate(format!(
            "route {route_id} changed {field} from {current:?} to {candidate:?}"
        )))
    }
}

fn fail_if_removed_values<T>(
    route_id: &str,
    field: &str,
    current: &[T],
    candidate: &[T],
) -> AttestationResult<()>
where
    T: PartialEq + std::fmt::Debug,
{
    for value in current {
        if !candidate.iter().any(|candidate| candidate == value) {
            return Err(AttestationError::WeakeningRegistryUpdate(format!(
                "route {route_id} removed {field} value {value:?}"
            )));
        }
    }
    Ok(())
}

fn trust_tier_rank(value: &TrustTier) -> u8 {
    match value {
        TrustTier::None => 0,
        TrustTier::TeeOnly => 1,
        TrustTier::HwVerifiedTls | TrustTier::AppE2ee => 2,
    }
}

fn bound_data_rank(value: &BoundDataRequirement) -> u8 {
    match value {
        BoundDataRequirement::NotRequired => 0,
        BoundDataRequirement::BoundToAttestedWorkload => 1,
    }
}

fn response_integrity_rank(value: &ResponseIntegrityRequirement) -> u8 {
    match value {
        ResponseIntegrityRequirement::NotRequired => 0,
        ResponseIntegrityRequirement::AnyBound => 1,
        ResponseIntegrityRequirement::ChannelBound | ResponseIntegrityRequirement::ReceiptBound => {
            2
        }
    }
}

fn alias_confidence_rank(value: &AliasConfidence) -> u8 {
    match value {
        AliasConfidence::Algorithmic => 0,
        AliasConfidence::ProviderDeclared => 1,
        AliasConfidence::ManualOverride => 2,
        AliasConfidence::Curated => 3,
    }
}

fn route_lifecycle_security_rank(value: &RouteLifecycle) -> u8 {
    match value {
        RouteLifecycle::Active => 2,
        RouteLifecycle::VerificationOnly => 1,
        RouteLifecycle::NewUnverified
        | RouteLifecycle::Deprecated
        | RouteLifecycle::Removed
        | RouteLifecycle::Blocked => 0,
    }
}

fn alias_allowed_by_default(value: &AliasConfidence) -> bool {
    matches!(
        value,
        AliasConfidence::Curated | AliasConfidence::ManualOverride
    )
}

fn reject_route_url_credentials(
    route: &RouteDefinition,
    field: &str,
    url: &str,
) -> AttestationResult<()> {
    if url_authority_has_credentials(url) {
        return Err(AttestationError::InvalidProviderRegistry(format!(
            "route {} {field} must not include URL credentials",
            route.route_id
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

fn route_map(model: &RegistryModel) -> BTreeMap<&str, &RouteDefinition> {
    model
        .routes
        .iter()
        .map(|route| (route.route_id.as_str(), route))
        .collect()
}

fn push_model_field_change<T>(
    changes: &mut Vec<RegistryDiffChange>,
    model: &str,
    field: &str,
    current: &T,
    candidate: &T,
    review_required: bool,
) -> AttestationResult<()>
where
    T: PartialEq + Serialize,
{
    if current != candidate {
        changes.push(RegistryDiffChange::model_field(
            model,
            field,
            current,
            candidate,
            review_required,
        )?);
    }
    Ok(())
}

fn push_route_field_change<T>(
    changes: &mut Vec<RegistryDiffChange>,
    model: &str,
    current_route: &RouteDefinition,
    field: &str,
    current: &T,
    candidate: &T,
    review_required: bool,
) -> AttestationResult<()>
where
    T: PartialEq + Serialize,
{
    if current != candidate {
        changes.push(RegistryDiffChange::route_field(
            model,
            current_route,
            field,
            current,
            candidate,
            review_required,
        )?);
    }
    Ok(())
}

fn json_value<T: Serialize>(value: &T) -> AttestationResult<Value> {
    serde_json::to_value(value).map_err(Into::into)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLifecycle {
    Active,
    NewUnverified,
    VerificationOnly,
    Deprecated,
    Removed,
    Blocked,
}

impl RouteLifecycle {
    pub fn selectable_for_verification(&self) -> bool {
        matches!(
            self,
            RouteLifecycle::Active | RouteLifecycle::VerificationOnly
        )
    }

    pub fn selectable_for_chat(&self) -> bool {
        matches!(self, RouteLifecycle::Active)
    }

    pub fn security_sensitive(&self) -> bool {
        self.selectable_for_verification()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionRequirement {
    Required,
    NotRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamingSupport {
    Supported,
    SupportedIfEncryptionSupportsStreaming,
    Unsupported,
}

impl StreamingSupport {
    pub fn allows_streaming(&self) -> bool {
        matches!(
            self,
            StreamingSupport::Supported | StreamingSupport::SupportedIfEncryptionSupportsStreaming
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use confidential_inference_attestation::{
        canonical_json, AttestationError, ALIAS_MATRIX_FIXTURE_SIGNING_KEY_ID, DEMO_SIGNING_KEY_ID,
    };
    use ed25519_compact::{KeyPair, Seed};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};

    const ACCEPTED_UPDATE_SIGNATURE: &str = "base64url:dygz7DERJVKb07m0SKEFFplpuRMT0JYEiOdd4uF9-l6CAET157drxY-Lc_KQ2AFYyb33-rkqHqPWFOAJYm9WBg";
    const PARTIAL_UPDATE_SIGNATURE: &str = "base64url:iPf1VvB0cLUUOtObwf4DAKshTnWfXCH9g5aO6e8V4MfWQCE9dRg5zjn6FgZJQ8CyAcEZCHoVCqCtle7e2Y4rCg";
    const STALE_UPDATE_SIGNATURE: &str = "base64url:rT_L0d5vn_wqFJp6U8rtv9ZunHjCwdQlYwPdMY6yHwFxOCraqRt-p7xUxD5cdvKZafTdNWwu91Dye8vHnRxtDw";
    const WEAKENED_UPDATE_SIGNATURE: &str = "base64url:s3hQ2pF5Qf9Ph8fjNtQNLi1ng7Q07I8bGIlhFv-vKMg3Ryh9HKYpXTrInB_7N6C2u9RoOlt3RNjuHM-BSKqsAg";
    const REMOVED_ROUTE_UPDATE_SIGNATURE: &str = "base64url:5hWqmgDEmDWt1VuzGtZDhMEPA9UwunU4m-YBC7ERC_vXpdAHW_cxYHcU5-fcGZQ1Lok9O8DrQkGLNrCYOj6bAQ";
    const DEMO_REGISTRY_DIGEST: &str =
        "sha256:5f7d7f58d2198ccabbdd1c90e9d0ec0030d9934d80895007244971e3e61b7373";
    const MODEL_ALIAS_MATRIX_DIGEST: &str =
        "sha256:ec781dc92a5cfe4c2725c0b9301c1684c361e11cb52a9d8591d3bfbb94e95ffb";

    #[test]
    fn bundled_registry_preserves_provider_model_id() {
        let registry = ProviderRegistry::bundled_demo().unwrap();
        let (_, route) = registry.find_route(Some("demo"), "gpt-oss-120b").unwrap();

        assert_eq!(route.provider_model, "e2ee-gpt-oss-120b-p");
        assert_eq!(route.trust_tier, TrustTier::AppE2ee);
        assert!(!route.streaming.allows_streaming());
        assert_eq!(registry.digest().unwrap(), DEMO_REGISTRY_DIGEST);
    }

    #[test]
    fn registry_model_resolution_is_exact_and_preserves_provider_ids() {
        let registry = ProviderRegistry::bundled_demo().unwrap();

        assert!(registry.find_route(None, "gpt-oss-120b").is_some());
        assert!(registry.find_route(None, "GPT-OSS 120B").is_some());
        assert!(registry.find_route(None, "e2ee-gpt-oss-120b-p").is_some());
        assert!(registry.find_route(None, "GPT-OSS 120B v2").is_none());
        assert!(registry.find_route(None, "gpt-oss-20b").is_none());
    }

    #[test]
    fn registry_digest_accepts_same_major_schema_metadata() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        registry.schema = "confidential-inference.provider-registry.v1.1".into();

        assert!(registry.digest().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn registry_digest_rejects_unknown_major_schema_metadata() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        registry.schema = "confidential-inference.provider-registry.v2".into();

        let error = registry.digest().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("schema major version 2 is not supported")
        ));
    }

    #[test]
    fn registry_digest_rejects_malformed_schema_metadata() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        registry.schema = "confidential-inference.provider-registry.v1.beta".into();

        let error = registry.digest().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("schema has malformed schema version")
        ));
    }

    #[test]
    fn registry_digest_rejects_invalid_generated_at_metadata() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        registry.generated_at = "not-a-timestamp".into();

        let error = registry.digest().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("generated_at")
        ));
    }

    #[test]
    fn registry_digest_rejects_invalid_source_sync_completed_at_metadata() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        registry.source_sync_run.completed_at = "not-a-timestamp".into();

        let error = registry.digest().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("source_sync_run.completed_at")
        ));
    }

    #[test]
    fn non_active_provider_model_does_not_select_an_active_route() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        let model = registry.models.get_mut("gpt-oss-120b").unwrap();
        let mut new_route = model.routes[0].clone();
        new_route.route_id = "demo:gpt-oss-120b:e2ee-new-unverified".into();
        new_route.route_status = RouteLifecycle::NewUnverified;
        new_route.provider_model = "e2ee-new-unverified".into();
        new_route.alias_confidence = AliasConfidence::Algorithmic;
        model.routes.push(new_route);

        registry.validate_security_invariants().unwrap();

        assert!(registry.find_route(None, "e2ee-new-unverified").is_none());
        assert!(registry.find_route(None, "gpt-oss-120b").is_some());
    }

    #[test]
    fn verification_only_provider_model_can_be_selected_for_verification() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        let model = registry.models.get_mut("gpt-oss-120b").unwrap();
        let mut verification_only_route = model.routes[0].clone();
        verification_only_route.route_id = "demo:gpt-oss-120b:e2ee-verification-only".into();
        verification_only_route.route_status = RouteLifecycle::VerificationOnly;
        verification_only_route.provider_model = "e2ee-verification-only".into();
        model.routes.push(verification_only_route);

        registry.validate_security_invariants().unwrap();

        let (_, route) = registry
            .find_route(Some("demo"), "e2ee-verification-only")
            .unwrap();
        assert_eq!(route.route_status, RouteLifecycle::VerificationOnly);
    }

    #[test]
    fn verification_only_algorithmic_alias_registry_is_rejected() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        let route = &mut registry.models.get_mut("gpt-oss-120b").unwrap().routes[0];
        route.route_status = RouteLifecycle::VerificationOnly;
        route.alias_confidence = AliasConfidence::Algorithmic;

        assert!(matches!(
            registry.validate_security_invariants(),
            Err(AttestationError::InvalidProviderRegistry(_))
        ));
    }

    #[test]
    fn verification_only_route_removal_is_a_weakening_update() {
        let mut current = ProviderRegistry::bundled_demo().unwrap();
        current.models.get_mut("gpt-oss-120b").unwrap().routes[0].route_status =
            RouteLifecycle::VerificationOnly;
        let mut candidate = current.clone();
        candidate
            .models
            .get_mut("gpt-oss-120b")
            .unwrap()
            .routes
            .clear();

        let error = current.verify_update_to(&candidate).unwrap_err();

        assert!(matches!(
            error,
            AttestationError::WeakeningRegistryUpdate(message)
                if message.contains("security-sensitive route")
        ));
    }

    #[test]
    fn verification_only_route_can_be_promoted_to_active_without_weakening() {
        let mut current = ProviderRegistry::bundled_demo().unwrap();
        current.models.get_mut("gpt-oss-120b").unwrap().routes[0].route_status =
            RouteLifecycle::VerificationOnly;
        let mut candidate = current.clone();
        candidate.models.get_mut("gpt-oss-120b").unwrap().routes[0].route_status =
            RouteLifecycle::Active;

        current.verify_update_to(&candidate).unwrap();
    }

    #[test]
    fn active_algorithmic_alias_registry_is_rejected() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        registry.models.get_mut("gpt-oss-120b").unwrap().routes[0].alias_confidence =
            AliasConfidence::Algorithmic;

        assert!(matches!(
            registry.validate_security_invariants(),
            Err(AttestationError::InvalidProviderRegistry(_))
        ));
    }

    #[test]
    fn provider_declared_aliases_do_not_satisfy_default_strict_selection() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        registry.models.get_mut("gpt-oss-120b").unwrap().routes[0].alias_confidence =
            AliasConfidence::ProviderDeclared;

        registry.validate_security_invariants().unwrap();

        assert!(registry.find_route(None, "GPT-OSS 120B").is_none());
        assert!(registry.find_route(None, "gpt-oss-120b").is_some());
        assert!(registry.find_route(None, "e2ee-gpt-oss-120b-p").is_some());
    }

    #[test]
    fn manual_override_aliases_satisfy_default_selection_after_explicit_override() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        registry.models.get_mut("gpt-oss-120b").unwrap().routes[0].alias_confidence =
            AliasConfidence::ManualOverride;

        registry.validate_security_invariants().unwrap();

        assert!(registry.find_route(None, "GPT-OSS 120B").is_some());
    }

    #[test]
    fn alias_collision_registry_is_rejected() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        registry.models.insert(
            "gpt-oss-20b".into(),
            RegistryModel {
                canonical_model: "gpt-oss-20b".into(),
                display_name: "GPT-OSS 20B".into(),
                family: "OpenAI GPT".into(),
                aliases: vec!["GPT-OSS 120B".into()],
                routes: Vec::new(),
            },
        );

        assert!(matches!(
            registry.validate_security_invariants(),
            Err(AttestationError::InvalidProviderRegistry(_))
        ));
    }

    #[test]
    fn duplicate_active_provider_model_registry_is_rejected() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        let mut route = registry.models.get("gpt-oss-120b").unwrap().routes[0].clone();
        route.route_id = "demo:gpt-oss-20b:e2ee-gpt-oss-120b-p".into();
        registry.models.insert(
            "gpt-oss-20b".into(),
            RegistryModel {
                canonical_model: "gpt-oss-20b".into(),
                display_name: "GPT-OSS 20B".into(),
                family: "OpenAI GPT".into(),
                aliases: vec!["gpt-oss-20b".into()],
                routes: vec![route],
            },
        );

        assert!(matches!(
            registry.validate_security_invariants(),
            Err(AttestationError::InvalidProviderRegistry(_))
        ));
    }

    #[test]
    fn credentialed_route_api_base_url_is_rejected_without_leaking_credentials() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        registry.models.get_mut("gpt-oss-120b").unwrap().routes[0].api_base_url =
            "https://token:secret@api.redpill.ai/v1".into();

        let error = registry.validate_security_invariants().unwrap_err();
        let message = error.to_string();

        assert!(matches!(
            error,
            AttestationError::InvalidProviderRegistry(_)
        ));
        assert!(message.contains("api_base_url must not include URL credentials"));
        assert!(!message.contains("token"));
        assert!(!message.contains("secret"));
        assert!(!message.contains("token:secret@api.redpill.ai"));
    }

    #[test]
    fn credentialed_route_evidence_endpoint_is_rejected_without_leaking_credentials() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        registry.models.get_mut("gpt-oss-120b").unwrap().routes[0].evidence_endpoint =
            "https://token:secret@api.redpill.ai/v1/attestation/report".into();

        let error = registry.validate_security_invariants().unwrap_err();
        let message = error.to_string();

        assert!(matches!(
            error,
            AttestationError::InvalidProviderRegistry(_)
        ));
        assert!(message.contains("evidence_endpoint must not include URL credentials"));
        assert!(!message.contains("token"));
        assert!(!message.contains("secret"));
        assert!(!message.contains("token:secret@api.redpill.ai"));
    }

    #[test]
    fn route_url_at_signs_outside_authority_are_allowed() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        let route = &mut registry.models.get_mut("gpt-oss-120b").unwrap().routes[0];
        route.api_base_url = "http://127.0.0.1/fixture/v1/@metadata".into();
        route.evidence_endpoint =
            "https://api.redpill.ai/v1/attestation/report?contact=ops@confidential-inference.dev"
                .into();

        registry.validate_security_invariants().unwrap();
    }

    #[test]
    fn model_alias_matrix_preserves_required_roster() {
        let matrix = model_alias_matrix();
        let expected_roster = BTreeSet::from([
            "deepseek-v3.2",
            "gemma-3-27b",
            "gemma-4-31b",
            "glm-5",
            "glm-5.1",
            "glm-5.2",
            "gpt-oss-120b",
            "kimi-k2.5",
            "kimi-k2.6",
            "llama-3.3-70b",
            "minimax-m2.5",
            "mistral-nemo-instruct-2407",
            "nemotron-3-nano-omni-30b",
            "qwen3-235b-a22b-thinking-2507",
            "qwen3-32b",
            "qwen3-vl-30b-a3b",
            "qwen3.5-397b-a17b",
            "qwen3.6-27b",
        ]);
        let actual_roster = matrix
            .models
            .iter()
            .map(|model| model.canonical_model.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            matrix.schema,
            "confidential-inference.model-alias-matrix.v1"
        );
        assert_eq!(actual_roster, expected_roster);
    }

    #[test]
    fn model_alias_matrix_digest_accepts_same_major_schema_metadata() {
        let mut matrix = model_alias_matrix();
        matrix.schema = "confidential-inference.model-alias-matrix.v1.1".into();

        assert!(matrix.digest().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn model_alias_matrix_digest_rejects_unknown_major_schema_metadata() {
        let mut matrix = model_alias_matrix();
        matrix.schema = "confidential-inference.model-alias-matrix.v2".into();

        let error = matrix.digest().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidProviderRegistry(message)
                if message.contains("schema major version 2 is not supported")
        ));
    }

    #[test]
    fn bundled_model_alias_matrix_signature_verifies() {
        let envelope = ModelAliasMatrixEnvelope::bundled().unwrap();

        envelope.verify_signature().unwrap();
        assert_eq!(
            envelope.signature.key_id,
            ALIAS_MATRIX_FIXTURE_SIGNING_KEY_ID
        );
        assert_eq!(
            envelope.payload.digest().unwrap(),
            MODEL_ALIAS_MATRIX_DIGEST
        );
    }

    #[test]
    fn tampered_model_alias_matrix_signature_fails() {
        let mut envelope = ModelAliasMatrixEnvelope::bundled().unwrap();
        envelope.payload.models[0]
            .aliases
            .push("GPT OSS 120B".into());

        assert!(envelope.verify_signature().is_err());
    }

    #[test]
    fn raw_model_alias_matrix_matches_signed_envelope_payload() {
        let envelope = ModelAliasMatrixEnvelope::bundled().unwrap();
        let raw = ModelAliasMatrix::bundled_raw_fixture().unwrap();

        assert_eq!(raw, envelope.payload);
    }

    #[test]
    fn model_alias_matrix_resolves_only_explicit_aliases_and_routes() {
        let matrix = model_alias_matrix();
        let registry = registry_from_alias_matrix(&matrix);

        registry.validate_security_invariants().unwrap();

        for model_case in &matrix.models {
            for alias in &model_case.aliases {
                let (model, route) = registry
                    .find_route(None, alias)
                    .unwrap_or_else(|| panic!("alias {alias} did not resolve"));
                assert_eq!(model.canonical_model, model_case.canonical_model);
                assert_eq!(route.alias_confidence, AliasConfidence::Curated);
            }

            for provider_route in &model_case.provider_routes {
                let (model, route) = registry
                    .find_route(
                        Some(&provider_route.provider),
                        &provider_route.provider_model,
                    )
                    .unwrap_or_else(|| {
                        panic!(
                            "provider model {}/{} did not resolve",
                            provider_route.provider, provider_route.provider_model
                        )
                    });

                assert_eq!(model.canonical_model, model_case.canonical_model);
                assert_eq!(route.provider_model, provider_route.provider_model);
            }

            for rejected in &model_case.must_not_match {
                assert!(
                    registry.find_route(None, rejected).is_none(),
                    "{rejected} unexpectedly resolved"
                );
            }
        }
    }

    #[test]
    fn bundled_registry_signature_verifies() {
        let envelope = ProviderRegistryEnvelope::bundled_demo().unwrap();

        envelope.verify_signature().unwrap();
    }

    #[test]
    fn tampered_registry_signature_fails() {
        let mut envelope = ProviderRegistryEnvelope::bundled_demo().unwrap();
        envelope.payload.version = "tampered".into();

        assert!(envelope.verify_signature().is_err());
    }

    #[test]
    fn signed_non_weakening_registry_update_is_accepted() {
        let current = ProviderRegistry::bundled_demo().unwrap();
        let mut candidate = current.clone();
        candidate.version = "2026-07-06-demo".into();
        let update = signed_update(candidate, ACCEPTED_UPDATE_SIGNATURE);

        let accepted = update.into_verified_update_from(&current).unwrap();

        assert_eq!(accepted.version, "2026-07-06-demo");
    }

    #[test]
    fn signed_partial_registry_update_fails_closed() {
        let current = ProviderRegistry::bundled_demo().unwrap();
        let mut candidate = current.clone();
        candidate.version = "2026-07-06-demo".into();
        candidate.source_sync_run.status = "partial".into();
        let update = signed_update(candidate, PARTIAL_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::InvalidRegistryUpdate(_))
        ));
    }

    #[test]
    fn signed_stale_registry_update_fails_closed() {
        let current = ProviderRegistry::bundled_demo().unwrap();
        let mut candidate = current.clone();
        candidate.version = "2026-07-04-demo".into();
        let update = signed_update(candidate, STALE_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::InvalidRegistryUpdate(_))
        ));
    }

    #[test]
    fn registry_update_rejects_invalid_current_timestamp_metadata() {
        let mut current = ProviderRegistry::bundled_demo().unwrap();
        current.generated_at = "not-a-timestamp".into();
        let mut candidate = ProviderRegistry::bundled_demo().unwrap();
        candidate.version = "2026-07-06-demo".into();

        let error = current.verify_update_to(&candidate).unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("generated_at")
        ));
    }

    #[test]
    fn registry_update_rejects_invalid_candidate_timestamp_metadata() {
        let current = ProviderRegistry::bundled_demo().unwrap();
        let mut candidate = current.clone();
        candidate.version = "2026-07-06-demo".into();
        candidate.source_sync_run.completed_at = "not-a-timestamp".into();

        let error = current.verify_update_to(&candidate).unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("source_sync_run.completed_at")
        ));
    }

    #[test]
    fn signed_weakening_registry_update_fails_closed() {
        let current = ProviderRegistry::bundled_demo().unwrap();
        let mut candidate = current.clone();
        candidate.version = "2026-07-06-demo".into();
        let route = &mut candidate.models.get_mut("gpt-oss-120b").unwrap().routes[0];
        route.trust_tier = TrustTier::TeeOnly;
        route.channel_binding_kind = ChannelBindingKind::None;
        route.request_confidentiality_requirement = BoundDataRequirement::NotRequired;
        route.response_confidentiality_requirement = BoundDataRequirement::NotRequired;
        route.response_integrity_requirement = ResponseIntegrityRequirement::NotRequired;
        route.request_encryption = EncryptionRequirement::NotRequired;
        route.response_decryption = EncryptionRequirement::NotRequired;
        let update = signed_update(candidate, WEAKENED_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::WeakeningRegistryUpdate(_))
        ));
    }

    #[test]
    fn registry_update_removing_gpu_capability_fails_closed() {
        let mut current = ProviderRegistry::bundled_demo().unwrap();
        current.models.get_mut("gpt-oss-120b").unwrap().routes[0].accepted_gpu_tees =
            vec![GpuTeeKind::NvidiaCc];
        let mut candidate = current.clone();
        candidate.version = "2026-07-06-demo".into();
        candidate.models.get_mut("gpt-oss-120b").unwrap().routes[0]
            .accepted_gpu_tees
            .clear();

        let error = current.verify_update_to(&candidate).unwrap_err();

        assert!(matches!(
            error,
            AttestationError::WeakeningRegistryUpdate(_)
        ));
        assert!(error.to_string().contains("accepted_gpu_tees"));
    }

    #[test]
    fn signed_route_removal_registry_update_fails_closed() {
        let current = ProviderRegistry::bundled_demo().unwrap();
        let mut candidate = current.clone();
        candidate.version = "2026-07-06-demo".into();
        candidate
            .models
            .get_mut("gpt-oss-120b")
            .unwrap()
            .routes
            .clear();
        let update = signed_update(candidate, REMOVED_ROUTE_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::WeakeningRegistryUpdate(_))
        ));
    }

    #[test]
    fn unsigned_registry_update_fails_before_update_evaluation() {
        let current = ProviderRegistry::bundled_demo().unwrap();
        let mut candidate = current.clone();
        candidate.version = "2026-07-06-demo".into();
        let mut update = signed_update(candidate, ACCEPTED_UPDATE_SIGNATURE);
        update.signature.value =
            "base64url:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .into();

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::InvalidArtifactSignature(_))
        ));
    }

    #[test]
    fn registry_diff_report_calls_out_alias_route_and_security_changes() {
        let current = ProviderRegistry::bundled_demo().unwrap();
        let mut candidate = current.clone();
        candidate.version = "2026-07-06-demo".into();
        let model = candidate.models.get_mut("gpt-oss-120b").unwrap();
        model.aliases.retain(|alias| alias != "GPT-OSS 120B");
        model.aliases.push("GPT OSS 120B".into());

        let mut new_route = model.routes[0].clone();
        new_route.route_id = "demo:gpt-oss-120b:e2ee-new-gpt-oss-120b-p".into();
        new_route.route_status = RouteLifecycle::NewUnverified;
        new_route.provider_model = "e2ee-new-gpt-oss-120b-p".into();
        new_route.alias_confidence = AliasConfidence::Algorithmic;
        model.routes.push(new_route);

        let route = &mut model.routes[0];
        route.evidence_endpoint = "https://api.venice.ai/api/v1/changed/confidentiality".into();
        route.request_encryption = EncryptionRequirement::NotRequired;
        route.accepted_gpu_tees = vec![GpuTeeKind::NvidiaCc];

        let report = current.diff_to(&candidate).unwrap();

        assert_ne!(report.from_digest, report.to_digest);
        assert!(report.review_required());
        assert!(report.changes.iter().any(|change| {
            change.kind == RegistryDiffKind::AliasAdded
                && change.after == Some(json!("GPT OSS 120B"))
                && change.review_required
        }));
        assert!(report.changes.iter().any(|change| {
            change.kind == RegistryDiffKind::AliasRemoved
                && change.before == Some(json!("GPT-OSS 120B"))
                && change.review_required
        }));

        let added_route = find_change(
            &report,
            RegistryDiffKind::RouteAdded,
            Some("demo:gpt-oss-120b:e2ee-new-gpt-oss-120b-p"),
            None,
        );
        assert_eq!(
            added_route.provider_model.as_deref(),
            Some("e2ee-new-gpt-oss-120b-p")
        );
        assert!(!added_route.review_required);

        let endpoint_change = find_change(
            &report,
            RegistryDiffKind::RouteFieldChanged,
            Some("demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"),
            Some("evidence_endpoint"),
        );
        assert_eq!(
            endpoint_change.after,
            Some(json!(
                "https://api.venice.ai/api/v1/changed/confidentiality"
            ))
        );
        assert!(endpoint_change.review_required);

        let encryption_change = find_change(
            &report,
            RegistryDiffKind::RouteFieldChanged,
            Some("demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"),
            Some("request_encryption"),
        );
        assert_eq!(encryption_change.before, Some(json!("required")));
        assert_eq!(encryption_change.after, Some(json!("not_required")));
        assert!(encryption_change.review_required);

        let gpu_change = find_change(
            &report,
            RegistryDiffKind::RouteFieldChanged,
            Some("demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"),
            Some("accepted_gpu_tees"),
        );
        assert_eq!(gpu_change.before, Some(json!([])));
        assert_eq!(gpu_change.after, Some(json!(["nvidia_cc"])));
        assert!(gpu_change.review_required);
    }

    #[test]
    fn registry_diff_report_marks_removed_active_route_for_review() {
        let current = ProviderRegistry::bundled_demo().unwrap();
        let mut candidate = current.clone();
        candidate.version = "2026-07-06-demo".into();
        candidate
            .models
            .get_mut("gpt-oss-120b")
            .unwrap()
            .routes
            .clear();

        let report = current.diff_to(&candidate).unwrap();
        let removed = find_change(
            &report,
            RegistryDiffKind::RouteRemoved,
            Some("demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"),
            None,
        );

        assert!(removed.review_required);
        assert_eq!(removed.provider.as_deref(), Some("demo"));
        assert_eq!(
            removed.provider_model.as_deref(),
            Some("e2ee-gpt-oss-120b-p")
        );
    }

    #[test]
    fn registry_diff_report_is_empty_for_unchanged_registry() {
        let current = ProviderRegistry::bundled_demo().unwrap();
        let report = current.diff_to(&current).unwrap();

        assert_eq!(report.from_digest, report.to_digest);
        assert!(!report.review_required());
        assert!(report.changes.is_empty());
    }

    #[test]
    fn registry_pin_accepts_matching_digest_and_versions() {
        let registry = ProviderRegistry::bundled_demo().unwrap();
        let pin =
            ProviderRegistryPin::digest_and_version(DEMO_REGISTRY_DIGEST, registry.version.clone())
                .with_minimum_version("2026-07-01");

        pin.verify(&registry).unwrap();
    }

    #[test]
    fn registry_pin_accepts_matching_signing_identity_and_age() {
        let envelope = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let digest = envelope.payload.digest().unwrap();
        let now = parse_utc_timestamp_millis("2026-07-05T00:00:01Z").unwrap();
        let pin = ProviderRegistryPin::new()
            .with_accepted_ed25519_signing_identity("confidential-inference", DEMO_SIGNING_KEY_ID)
            .with_max_age_millis(1_000);

        pin.verify_envelope_with_digest_at(&envelope, &digest, now)
            .unwrap();
    }

    #[test]
    fn registry_pin_rejects_signing_identity_mismatch() {
        let envelope = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let digest = envelope.payload.digest().unwrap();
        let now = parse_utc_timestamp_millis("2026-07-05T00:00:01Z").unwrap();
        let pin = ProviderRegistryPin::new()
            .with_accepted_ed25519_signing_identity("confidential-inference", "other-key");
        let err = pin
            .verify_envelope_with_digest_at(&envelope, &digest, now)
            .unwrap_err();

        assert!(matches!(
            err,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("registry signing identity pin mismatch")
        ));
    }

    #[test]
    fn registry_pin_rejects_registry_over_maximum_age() {
        let envelope = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let digest = envelope.payload.digest().unwrap();
        let now = parse_utc_timestamp_millis("2026-07-05T00:00:02Z").unwrap();
        let pin = ProviderRegistryPin::new().with_max_age_millis(1_000);
        let err = pin
            .verify_envelope_with_digest_at(&envelope, &digest, now)
            .unwrap_err();

        assert!(matches!(
            err,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("exceeds pinned maximum")
        ));
    }

    #[test]
    fn registry_pin_rejects_registry_completed_in_the_future() {
        let envelope = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let digest = envelope.payload.digest().unwrap();
        let now = parse_utc_timestamp_millis("2026-07-04T23:59:59Z").unwrap();
        let pin = ProviderRegistryPin::new().with_max_age_millis(60_000);
        let err = pin
            .verify_envelope_with_digest_at(&envelope, &digest, now)
            .unwrap_err();

        assert!(matches!(
            err,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("is in the future")
        ));
    }

    #[test]
    fn registry_pin_rejects_digest_mismatch() {
        let registry = ProviderRegistry::bundled_demo().unwrap();
        let pin = ProviderRegistryPin::digest("sha256:wrong");
        let err = pin.verify(&registry).unwrap_err();

        assert!(matches!(
            err,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("registry digest pin mismatch")
        ));
    }

    #[test]
    fn registry_pin_rejects_exact_version_mismatch() {
        let registry = ProviderRegistry::bundled_demo().unwrap();
        let pin = ProviderRegistryPin::version("2026-07-06-demo");
        let err = pin.verify(&registry).unwrap_err();

        assert!(matches!(
            err,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("registry version pin mismatch")
        ));
    }

    #[test]
    fn registry_pin_rejects_minimum_version_downgrade() {
        let registry = ProviderRegistry::bundled_demo().unwrap();
        let pin = ProviderRegistryPin::minimum_version("2026-07-06-demo");
        let err = pin.verify(&registry).unwrap_err();

        assert!(matches!(
            err,
            AttestationError::InvalidRegistryUpdate(message)
                if message.contains("older than pinned minimum")
        ));
    }

    fn signed_update(
        payload: ProviderRegistry,
        _legacy_signature: &str,
    ) -> ProviderRegistryEnvelope {
        let canonical = canonical_json(&payload).unwrap();
        let key_pair = KeyPair::from_seed(Seed::new([71_u8; 32]));
        let signature = format!(
            "base64url:{}",
            URL_SAFE_NO_PAD.encode(key_pair.sk.sign(canonical.as_bytes(), None).as_ref())
        );
        ProviderRegistryEnvelope {
            schema: ProviderRegistryEnvelope::SCHEMA.into(),
            payload,
            signature: ArtifactSignature {
                signer: "confidential-inference".into(),
                key_id: DEMO_SIGNING_KEY_ID.into(),
                alg: "ed25519".into(),
                value: signature,
            },
        }
    }

    fn model_alias_matrix() -> ModelAliasMatrix {
        ModelAliasMatrix::bundled().unwrap()
    }

    fn find_change<'a>(
        report: &'a ProviderRegistryDiffReport,
        kind: RegistryDiffKind,
        route_id: Option<&str>,
        field: Option<&str>,
    ) -> &'a RegistryDiffChange {
        report
            .changes
            .iter()
            .find(|change| {
                change.kind == kind
                    && change.route_id.as_deref() == route_id
                    && change.field.as_deref() == field
            })
            .unwrap_or_else(|| panic!("missing change {kind:?} {route_id:?} {field:?}"))
    }

    fn registry_from_alias_matrix(matrix: &ModelAliasMatrix) -> ProviderRegistry {
        let demo_registry = ProviderRegistry::bundled_demo().unwrap();
        let base_route = demo_registry
            .models
            .get("gpt-oss-120b")
            .unwrap()
            .routes
            .first()
            .unwrap()
            .clone();

        let models = matrix
            .models
            .iter()
            .map(|model_case| {
                let routes = model_case
                    .provider_routes
                    .iter()
                    .map(|provider_route| {
                        let mut route = base_route.clone();
                        route.route_id = format!(
                            "{}:{}:{}",
                            provider_route.provider,
                            model_case.canonical_model,
                            provider_route.provider_model
                        );
                        route.provider = provider_route.provider.clone();
                        route.provider_model = provider_route.provider_model.clone();
                        route.alias_confidence = AliasConfidence::Curated;
                        route
                    })
                    .collect();

                (
                    model_case.canonical_model.clone(),
                    RegistryModel {
                        canonical_model: model_case.canonical_model.clone(),
                        display_name: model_case.display_name.clone(),
                        family: model_case.family.clone(),
                        aliases: model_case.aliases.clone(),
                        routes,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        ProviderRegistry {
            schema: ProviderRegistry::SCHEMA.into(),
            version: "2026-07-05-alias-matrix".into(),
            generated_at: "2026-07-05T00:00:00Z".into(),
            source_sync_run: SourceSyncRun {
                completed_at: "2026-07-05T00:00:00Z".into(),
                status: "success".into(),
                source: "confidential-inference-sdk-alias-matrix-fixture".into(),
            },
            models,
        }
    }
}
