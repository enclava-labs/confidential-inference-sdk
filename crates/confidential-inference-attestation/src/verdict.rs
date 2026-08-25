use crate::policy::{
    BoundDataRequirement, ChannelBindingRequirement, CpuTeeKind, EnforcementMode,
    ResponseIntegrityRequirement,
};
use crate::{parse_utc_timestamp_millis, AttestationError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    Partial,
    Failed,
    Unreachable,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustTier {
    #[serde(rename = "hw-verified-tls")]
    HwVerifiedTls,
    #[serde(rename = "app-e2ee")]
    AppE2ee,
    #[serde(rename = "tee-only")]
    TeeOnly,
    #[serde(rename = "none")]
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelBindingKind {
    NotRequired,
    TeeTerminatedTls,
    AttestedAppE2ee,
    AnyAttestedChannel,
    None,
}

impl ChannelBindingKind {
    pub fn satisfies(&self, requirement: &ChannelBindingRequirement) -> bool {
        match requirement {
            ChannelBindingRequirement::NotRequired => true,
            ChannelBindingRequirement::AnyAttestedChannel => matches!(
                self,
                ChannelBindingKind::TeeTerminatedTls | ChannelBindingKind::AttestedAppE2ee
            ),
            ChannelBindingRequirement::TeeTerminatedTls => {
                matches!(self, ChannelBindingKind::TeeTerminatedTls)
            }
            ChannelBindingRequirement::AttestedAppE2ee => {
                matches!(self, ChannelBindingKind::AttestedAppE2ee)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessClass {
    PerRequest,
    PerSession,
    CachedBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasConfidence {
    Curated,
    ProviderDeclared,
    Algorithmic,
    ManualOverride,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelBindingResult {
    Verified,
    Partial,
    NotSupported,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Verified,
    Failed,
    NotApplicable,
    NotSupported,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckOutcome {
    pub state: CheckResult,
    pub required: bool,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePartyRole {
    InferenceProvider,
    RegistryAuthority,
    ReferenceValuesAuthority,
    WorkloadOperator,
    TeePlatform,
    CloudHost,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionSource {
    SignedRegistry,
    SignedReferenceValues,
    AttestedEvidence,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePartyAttribution {
    pub role: RoutePartyRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party_id: Option<String>,
    pub source: AttributionSource,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAttribution {
    pub parties: Vec<RoutePartyAttribution>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialityResult {
    ChannelBound,
    EncryptedBound,
    NotBound,
    Unknown,
}

impl ConfidentialityResult {
    pub fn satisfies(&self, requirement: &BoundDataRequirement) -> bool {
        match requirement {
            BoundDataRequirement::NotRequired => true,
            BoundDataRequirement::BoundToAttestedWorkload => matches!(
                self,
                ConfidentialityResult::ChannelBound | ConfidentialityResult::EncryptedBound
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseIntegrityResult {
    ChannelBound,
    ReceiptBound,
    NotBound,
    Unknown,
}

impl ResponseIntegrityResult {
    pub fn satisfies(&self, requirement: &ResponseIntegrityRequirement) -> bool {
        match requirement {
            ResponseIntegrityRequirement::NotRequired => true,
            ResponseIntegrityRequirement::AnyBound => matches!(
                self,
                ResponseIntegrityResult::ChannelBound | ResponseIntegrityResult::ReceiptBound
            ),
            ResponseIntegrityRequirement::ChannelBound => {
                matches!(self, ResponseIntegrityResult::ChannelBound)
            }
            ResponseIntegrityRequirement::ReceiptBound => {
                matches!(self, ResponseIntegrityResult::ReceiptBound)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedRoute {
    pub provider: String,
    pub route_id: String,
    pub evidence_family: String,
    pub requested_model: String,
    pub provider_model: String,
    pub canonical_model: String,
    pub api_endpoint: String,
    pub evidence_endpoint: String,
    pub adapter_version: String,
    pub freshness_class: FreshnessClass,
    pub channel_binding_kind: ChannelBindingKind,
    pub trust_tier: TrustTier,
    pub alias_confidence: AliasConfidence,
    pub request_confidentiality_requirement: BoundDataRequirement,
    pub response_confidentiality_requirement: BoundDataRequirement,
    pub response_integrity_requirement: ResponseIntegrityRequirement,
    pub streaming_allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureMetadata {
    pub signer: String,
    pub key_id: String,
    pub alg: String,
}

impl SignatureMetadata {
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidityWindow {
    pub policy_ttl_until: String,
    pub collateral_valid_until: String,
    pub certificate_valid_until: String,
    pub quote_valid_until: String,
    pub tcb_valid_until: String,
    pub reference_values_valid_until: String,
    pub computed_expires_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictArtifacts {
    pub source_url: Option<String>,
    pub tee_measurement: Option<String>,
    pub report_data: Option<String>,
    pub signing_public_key: Option<String>,
    pub e2ee_capability: Option<String>,
    pub model_manifest: Option<String>,
    pub model_artifacts: Vec<crate::ArtifactDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationVerdict {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    pub policy_schema: String,
    pub reference_values_schema: String,
    pub provider_registry_schema: String,
    pub status: VerificationStatus,
    pub enforcement: crate::EnforcementMode,
    pub request_allowed: bool,
    pub would_block_under_enforce: bool,
    pub trust_tier: TrustTier,
    pub provider: String,
    pub requested_model: String,
    pub provider_model: String,
    pub canonical_model: String,
    pub route_id: String,
    pub evidence_family: String,
    pub alias_confidence: AliasConfidence,
    pub adapter_version: String,
    pub api_endpoint: String,
    pub evidence_endpoint: String,
    pub freshness_class: FreshnessClass,
    pub streaming_allowed: bool,
    #[serde(default)]
    pub route_execution_status: String,
    #[serde(default)]
    pub chat_executable: bool,
    #[serde(default)]
    pub known_unsupported_modes: Vec<String>,
    pub channel_binding_kind: ChannelBindingKind,
    pub model_binding_result: ModelBindingResult,
    pub request_channel_bound: bool,
    pub request_confidentiality_result: ConfidentialityResult,
    pub response_confidentiality_result: ConfidentialityResult,
    pub response_channel_bound: bool,
    pub response_integrity_result: ResponseIntegrityResult,
    pub policy_digest: String,
    pub provider_registry_digest: String,
    pub registry_version: String,
    pub registry_source: String,
    pub registry_sync_completed_at: String,
    pub registry_signature: SignatureMetadata,
    pub reference_values_digest: String,
    pub reference_values_version: String,
    pub reference_values_source: String,
    pub reference_values_signature: SignatureMetadata,
    pub raw_evidence_digest: String,
    pub evidence_digest: String,
    pub verified_at: String,
    pub expires_at: String,
    pub expires_at_epoch_ms: u64,
    pub validity: ValidityWindow,
    pub checks: BTreeMap<String, CheckResult>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub check_outcomes: BTreeMap<String, CheckOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_attribution: Option<RouteAttribution>,
    pub artifacts: VerdictArtifacts,
    pub errors: Vec<VerdictError>,
}

impl AttestationVerdict {
    pub const SCHEMA: &'static str = "confidential-inference.verdict.v1";
    const SUPPORTED_SCHEMA_MAJOR: u32 = 1;

    pub fn validate_summary_consistency(&self) -> Result<()> {
        self.validate_schema_metadata()?;
        self.validate_required_fields()?;
        self.validate_digest_metadata()?;
        self.validate_signature_metadata()?;
        self.validate_validity_summary()?;
        self.validate_structured_checks()?;
        self.validate_route_attribution()?;

        if self.model_binding_result == ModelBindingResult::Verified
            && self.checks.get("model_binding") != Some(&CheckResult::Verified)
        {
            return Err(AttestationError::MalformedVerdict(
                "model_binding_result=verified but model_binding check is not verified".into(),
            ));
        }

        if matches!(
            self.request_confidentiality_result,
            ConfidentialityResult::ChannelBound | ConfidentialityResult::EncryptedBound
        ) {
            if !self.request_channel_bound {
                return Err(AttestationError::MalformedVerdict(
                    "bound request_confidentiality_result conflicts with request_channel_bound=false"
                        .into(),
                ));
            }
            self.require_verified_check(
                "request_key_binding",
                "bound request_confidentiality_result",
            )?;
            self.require_verified_check(
                "request_encryption",
                "bound request_confidentiality_result",
            )?;
        }

        if self.request_channel_bound
            && !matches!(
                self.request_confidentiality_result,
                ConfidentialityResult::ChannelBound | ConfidentialityResult::EncryptedBound
            )
        {
            return Err(AttestationError::MalformedVerdict(
                "request_channel_bound conflicts with request_confidentiality_result".into(),
            ));
        }

        if matches!(
            self.response_confidentiality_result,
            ConfidentialityResult::ChannelBound | ConfidentialityResult::EncryptedBound
        ) {
            if !self.response_channel_bound {
                return Err(AttestationError::MalformedVerdict(
                    "bound response_confidentiality_result conflicts with response_channel_bound=false"
                        .into(),
                ));
            }
            self.require_verified_check(
                "response_key_binding",
                "bound response_confidentiality_result",
            )?;
            self.require_verified_check(
                "response_encryption",
                "bound response_confidentiality_result",
            )?;
        }

        if self.response_channel_bound
            && !matches!(
                self.response_confidentiality_result,
                ConfidentialityResult::ChannelBound | ConfidentialityResult::EncryptedBound
            )
        {
            return Err(AttestationError::MalformedVerdict(
                "response_channel_bound conflicts with response_confidentiality_result".into(),
            ));
        }

        if self.response_channel_bound
            && self.response_integrity_result != ResponseIntegrityResult::ChannelBound
        {
            return Err(AttestationError::MalformedVerdict(
                "response channel binding must mirror channel-bound response integrity".into(),
            ));
        }

        match self.response_integrity_result {
            ResponseIntegrityResult::ChannelBound => {
                if !self.response_channel_bound {
                    return Err(AttestationError::MalformedVerdict(
                        "channel-bound response integrity conflicts with response_channel_bound=false"
                            .into(),
                    ));
                }
                self.require_verified_check(
                    "response_channel_binding",
                    "channel-bound response_integrity_result",
                )?;
            }
            ResponseIntegrityResult::ReceiptBound => {
                self.require_verified_check(
                    "response_receipt",
                    "receipt-bound response_integrity_result",
                )?;
            }
            ResponseIntegrityResult::NotBound | ResponseIntegrityResult::Unknown => {}
        }

        self.validate_trust_tier_summary()?;
        self.validate_enforcement_summary()?;
        self.validate_status_summary()?;

        Ok(())
    }

    fn validate_schema_metadata(&self) -> Result<()> {
        validate_schema_major("schema", &self.schema, "confidential-inference.verdict")?;
        validate_schema_major(
            "policy_schema",
            &self.policy_schema,
            "confidential-inference.policy",
        )?;
        validate_schema_major(
            "reference_values_schema",
            &self.reference_values_schema,
            "confidential-inference.reference-values",
        )?;
        validate_schema_major(
            "provider_registry_schema",
            &self.provider_registry_schema,
            "confidential-inference.provider-registry",
        )
    }

    fn validate_digest_metadata(&self) -> Result<()> {
        validate_sha256_digest("policy_digest", &self.policy_digest)?;
        validate_sha256_digest("provider_registry_digest", &self.provider_registry_digest)?;
        validate_sha256_digest("reference_values_digest", &self.reference_values_digest)?;
        validate_sha256_digest("raw_evidence_digest", &self.raw_evidence_digest)?;
        validate_sha256_digest("evidence_digest", &self.evidence_digest)
    }

    fn validate_signature_metadata(&self) -> Result<()> {
        validate_signature_metadata("registry_signature", &self.registry_signature)?;
        validate_signature_metadata(
            "reference_values_signature",
            &self.reference_values_signature,
        )
    }

    fn validate_required_fields(&self) -> Result<()> {
        for field in &self.required {
            if field.is_empty() {
                return Err(AttestationError::MalformedVerdict(
                    "verdict required list must contain non-empty field names".into(),
                ));
            }
            if !VERDICT_KNOWN_FIELDS.contains(&field.as_str()) {
                return Err(AttestationError::MalformedVerdict(format!(
                    "verdict declares unsupported required field {field}"
                )));
            }
        }
        Ok(())
    }

    fn validate_validity_summary(&self) -> Result<()> {
        if self.expires_at != self.validity.computed_expires_at {
            return Err(AttestationError::MalformedVerdict(
                "expires_at must match validity.computed_expires_at".into(),
            ));
        }
        let expires_at_epoch_ms = parse_verdict_timestamp("expires_at", &self.expires_at)?;
        if expires_at_epoch_ms != self.expires_at_epoch_ms {
            return Err(AttestationError::MalformedVerdict(
                "expires_at_epoch_ms must match expires_at".into(),
            ));
        }

        let validity_bounds = [
            (
                "validity.policy_ttl_until",
                self.validity.policy_ttl_until.as_str(),
            ),
            (
                "validity.collateral_valid_until",
                self.validity.collateral_valid_until.as_str(),
            ),
            (
                "validity.certificate_valid_until",
                self.validity.certificate_valid_until.as_str(),
            ),
            (
                "validity.quote_valid_until",
                self.validity.quote_valid_until.as_str(),
            ),
            (
                "validity.tcb_valid_until",
                self.validity.tcb_valid_until.as_str(),
            ),
            (
                "validity.reference_values_valid_until",
                self.validity.reference_values_valid_until.as_str(),
            ),
        ];
        let expected_min = validity_bounds
            .iter()
            .map(|(field, value)| parse_verdict_timestamp(field, value))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .min()
            .ok_or_else(|| AttestationError::MalformedVerdict("validity is empty".into()))?;
        if expected_min != expires_at_epoch_ms {
            return Err(AttestationError::MalformedVerdict(
                "validity.computed_expires_at must be the minimum validity bound".into(),
            ));
        }
        Ok(())
    }

    fn validate_status_summary(&self) -> Result<()> {
        if self.status != VerificationStatus::Verified {
            return Ok(());
        }
        if self
            .checks
            .values()
            .any(|check| *check == CheckResult::Failed)
        {
            return Err(AttestationError::MalformedVerdict(
                "status=verified but at least one check is failed".into(),
            ));
        }
        if !self.errors.is_empty() {
            return Err(AttestationError::MalformedVerdict(
                "status=verified but verdict contains errors".into(),
            ));
        }
        if !self.request_allowed {
            return Err(AttestationError::MalformedVerdict(
                "status=verified conflicts with request_allowed=false".into(),
            ));
        }
        if self.would_block_under_enforce {
            return Err(AttestationError::MalformedVerdict(
                "status=verified conflicts with would_block_under_enforce=true".into(),
            ));
        }
        Ok(())
    }

    fn validate_structured_checks(&self) -> Result<()> {
        if self.check_outcomes.is_empty() {
            return Ok(());
        }
        if self.check_outcomes.len() != self.checks.len() {
            return Err(AttestationError::MalformedVerdict(
                "check_outcomes must contain exactly the legacy check keys".into(),
            ));
        }
        for (name, state) in &self.checks {
            let outcome = self.check_outcomes.get(name).ok_or_else(|| {
                AttestationError::MalformedVerdict(format!(
                    "check_outcomes is missing check {name}"
                ))
            })?;
            if &outcome.state != state {
                return Err(AttestationError::MalformedVerdict(format!(
                    "check_outcomes.{name}.state conflicts with checks.{name}"
                )));
            }
            if outcome.detail.trim().is_empty() {
                return Err(AttestationError::MalformedVerdict(format!(
                    "check_outcomes.{name}.detail must not be empty"
                )));
            }
            if outcome.required && outcome.state == CheckResult::NotApplicable {
                return Err(AttestationError::MalformedVerdict(format!(
                    "required check_outcomes.{name} cannot be not_applicable"
                )));
            }
            validate_evidence_refs(
                &format!("check_outcomes.{name}.evidence_refs"),
                &outcome.evidence_refs,
            )?;
        }
        Ok(())
    }

    fn validate_route_attribution(&self) -> Result<()> {
        let Some(attribution) = &self.route_attribution else {
            return Ok(());
        };
        let expected_roles = [
            RoutePartyRole::InferenceProvider,
            RoutePartyRole::RegistryAuthority,
            RoutePartyRole::ReferenceValuesAuthority,
            RoutePartyRole::WorkloadOperator,
            RoutePartyRole::TeePlatform,
            RoutePartyRole::CloudHost,
        ];
        if attribution.parties.len() != expected_roles.len() {
            return Err(AttestationError::MalformedVerdict(
                "route_attribution must explicitly cover every route-party role".into(),
            ));
        }
        let mut roles = attribution
            .parties
            .iter()
            .map(|party| party.role.clone())
            .collect::<Vec<_>>();
        roles.sort();
        roles.dedup();
        if roles != expected_roles {
            return Err(AttestationError::MalformedVerdict(
                "route_attribution roles are missing or duplicated".into(),
            ));
        }
        for party in &attribution.parties {
            if party.detail.trim().is_empty() {
                return Err(AttestationError::MalformedVerdict(format!(
                    "route_attribution {:?} detail must not be empty",
                    party.role
                )));
            }
            match (&party.source, &party.party_id) {
                (AttributionSource::Unknown, None) => {}
                (AttributionSource::Unknown, Some(_)) => {
                    return Err(AttestationError::MalformedVerdict(format!(
                        "route_attribution {:?} cannot name a party from an unknown source",
                        party.role
                    )));
                }
                (_, Some(party_id)) if !party_id.trim().is_empty() => {}
                _ => {
                    return Err(AttestationError::MalformedVerdict(format!(
                        "route_attribution {:?} requires a non-empty party_id",
                        party.role
                    )));
                }
            }
            validate_evidence_refs(
                &format!("route_attribution.{:?}.evidence_refs", party.role),
                &party.evidence_refs,
            )?;
        }
        let provider = attribution
            .parties
            .iter()
            .find(|party| party.role == RoutePartyRole::InferenceProvider)
            .expect("role coverage checked above");
        if provider.party_id.as_deref() != Some(self.provider.as_str())
            || provider.source != AttributionSource::SignedRegistry
        {
            return Err(AttestationError::MalformedVerdict(
                "inference-provider attribution must match the signed registry provider".into(),
            ));
        }
        Ok(())
    }

    fn validate_trust_tier_summary(&self) -> Result<()> {
        if self.status != VerificationStatus::Verified {
            return Ok(());
        }
        match self.trust_tier {
            TrustTier::AppE2ee => {
                if self.channel_binding_kind != ChannelBindingKind::AttestedAppE2ee {
                    return Err(AttestationError::MalformedVerdict(
                        "trust_tier=app-e2ee requires channel_binding_kind=attested_app_e2ee"
                            .into(),
                    ));
                }
                if !self.request_channel_bound || !self.response_channel_bound {
                    return Err(AttestationError::MalformedVerdict(
                        "trust_tier=app-e2ee requires request and response channel binding".into(),
                    ));
                }
            }
            TrustTier::HwVerifiedTls => {
                if self.channel_binding_kind != ChannelBindingKind::TeeTerminatedTls {
                    return Err(AttestationError::MalformedVerdict(
                        "trust_tier=hw-verified-tls requires channel_binding_kind=tee_terminated_tls"
                            .into(),
                    ));
                }
                self.require_verified_check("tls_binding", "trust_tier=hw-verified-tls")?;
                if !matches!(
                    self.request_confidentiality_result,
                    ConfidentialityResult::ChannelBound
                ) || !matches!(
                    self.response_confidentiality_result,
                    ConfidentialityResult::ChannelBound
                ) {
                    return Err(AttestationError::MalformedVerdict(
                        "trust_tier=hw-verified-tls requires channel-bound request and response confidentiality"
                            .into(),
                    ));
                }
            }
            TrustTier::TeeOnly => {
                if self.response_channel_bound {
                    return Err(AttestationError::MalformedVerdict(
                        "trust_tier=tee-only must not report response_channel_bound=true".into(),
                    ));
                }
            }
            TrustTier::None => {
                if self.request_channel_bound
                    || self.response_channel_bound
                    || matches!(
                        self.response_integrity_result,
                        ResponseIntegrityResult::ChannelBound
                            | ResponseIntegrityResult::ReceiptBound
                    )
                    || matches!(
                        self.request_confidentiality_result,
                        ConfidentialityResult::ChannelBound | ConfidentialityResult::EncryptedBound
                    )
                    || matches!(
                        self.response_confidentiality_result,
                        ConfidentialityResult::ChannelBound | ConfidentialityResult::EncryptedBound
                    )
                {
                    return Err(AttestationError::MalformedVerdict(
                        "trust_tier=none conflicts with bound channel or response integrity summaries"
                            .into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_enforcement_summary(&self) -> Result<()> {
        let has_failed_check = self
            .checks
            .values()
            .any(|check| *check == CheckResult::Failed);
        if has_failed_check && !self.would_block_under_enforce {
            return Err(AttestationError::MalformedVerdict(
                "failed checks conflict with would_block_under_enforce=false".into(),
            ));
        }
        if !has_failed_check && self.would_block_under_enforce {
            return Err(AttestationError::MalformedVerdict(
                "would_block_under_enforce=true but no check is failed".into(),
            ));
        }
        if self.status == VerificationStatus::Disabled
            && self.enforcement != EnforcementMode::Disabled
        {
            return Err(AttestationError::MalformedVerdict(
                "status=disabled requires disabled enforcement".into(),
            ));
        }
        match self.enforcement {
            EnforcementMode::Enforce if self.would_block_under_enforce && self.request_allowed => {
                Err(AttestationError::MalformedVerdict(
                    "enforce verdict would block but request_allowed=true".into(),
                ))
            }
            EnforcementMode::Enforce
                if !self.would_block_under_enforce && !self.request_allowed =>
            {
                Err(AttestationError::MalformedVerdict(
                    "enforce verdict allows policy but request_allowed=false".into(),
                ))
            }
            EnforcementMode::Observe | EnforcementMode::Disabled if !self.request_allowed => {
                Err(AttestationError::MalformedVerdict(
                    "non-enforcing verdict must not set request_allowed=false".into(),
                ))
            }
            EnforcementMode::Disabled if self.status != VerificationStatus::Disabled => {
                Err(AttestationError::MalformedVerdict(
                    "disabled enforcement must emit status=disabled".into(),
                ))
            }
            _ => Ok(()),
        }
    }

    pub fn check(&self, name: &str) -> Option<&CheckResult> {
        self.checks.get(name)
    }

    fn require_verified_check(&self, check_name: &str, summary: &str) -> Result<()> {
        if self.checks.get(check_name) == Some(&CheckResult::Verified) {
            return Ok(());
        }
        Err(AttestationError::MalformedVerdict(format!(
            "{summary} requires {check_name} check to be verified"
        )))
    }
}

const VERDICT_KNOWN_FIELDS: &[&str] = &[
    "schema",
    "required",
    "policy_schema",
    "reference_values_schema",
    "provider_registry_schema",
    "status",
    "enforcement",
    "request_allowed",
    "would_block_under_enforce",
    "trust_tier",
    "provider",
    "requested_model",
    "provider_model",
    "canonical_model",
    "route_id",
    "evidence_family",
    "alias_confidence",
    "adapter_version",
    "api_endpoint",
    "evidence_endpoint",
    "freshness_class",
    "streaming_allowed",
    "route_execution_status",
    "chat_executable",
    "known_unsupported_modes",
    "channel_binding_kind",
    "model_binding_result",
    "request_channel_bound",
    "request_confidentiality_result",
    "response_confidentiality_result",
    "response_channel_bound",
    "response_integrity_result",
    "policy_digest",
    "provider_registry_digest",
    "registry_version",
    "registry_source",
    "registry_sync_completed_at",
    "registry_signature",
    "reference_values_digest",
    "reference_values_version",
    "reference_values_source",
    "reference_values_signature",
    "raw_evidence_digest",
    "evidence_digest",
    "verified_at",
    "expires_at",
    "expires_at_epoch_ms",
    "validity",
    "checks",
    "check_outcomes",
    "route_attribution",
    "artifacts",
    "errors",
];

const VERDICT_EVIDENCE_REFS: &[&str] = &[
    "policy_digest",
    "provider_registry_digest",
    "reference_values_digest",
    "raw_evidence_digest",
    "evidence_digest",
];

fn validate_evidence_refs(field: &str, refs: &[String]) -> Result<()> {
    let mut canonical = refs.to_vec();
    canonical.sort();
    canonical.dedup();
    if canonical != refs {
        return Err(AttestationError::MalformedVerdict(format!(
            "{field} must be sorted and unique"
        )));
    }
    if let Some(unsupported) = refs
        .iter()
        .find(|reference| !VERDICT_EVIDENCE_REFS.contains(&reference.as_str()))
    {
        return Err(AttestationError::MalformedVerdict(format!(
            "{field} contains unsupported evidence reference {unsupported}"
        )));
    }
    Ok(())
}

fn validate_schema_major(field: &str, value: &str, prefix: &str) -> Result<()> {
    let Some(version) = value
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix(".v"))
    else {
        return Err(AttestationError::MalformedVerdict(format!(
            "{field} must start with {prefix}.v{}",
            AttestationVerdict::SUPPORTED_SCHEMA_MAJOR
        )));
    };
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or_default();
    if major.is_empty() || major.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(AttestationError::MalformedVerdict(format!(
            "{field} has malformed schema version {value}"
        )));
    }
    for part in parts {
        if part.is_empty() || part.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(AttestationError::MalformedVerdict(format!(
                "{field} has malformed schema version {value}"
            )));
        }
    }
    let parsed_major = major.parse::<u32>().map_err(|_| {
        AttestationError::MalformedVerdict(format!("{field} has malformed schema version {value}"))
    })?;
    if parsed_major != AttestationVerdict::SUPPORTED_SCHEMA_MAJOR {
        return Err(AttestationError::MalformedVerdict(format!(
            "{field} major version {parsed_major} is not supported"
        )));
    }
    Ok(())
}

fn validate_sha256_digest(field: &str, value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(AttestationError::MalformedVerdict(format!(
            "{field} must be a canonical sha256 digest"
        )));
    };
    if hex.len() != 64
        || hex
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(AttestationError::MalformedVerdict(format!(
            "{field} must be a canonical sha256 digest"
        )));
    }
    Ok(())
}

fn validate_signature_metadata(field: &str, signature: &SignatureMetadata) -> Result<()> {
    if signature.signer.is_empty() || signature.key_id.is_empty() {
        return Err(AttestationError::MalformedVerdict(format!(
            "{field} metadata is incomplete"
        )));
    }
    if signature.alg != "ed25519" {
        return Err(AttestationError::MalformedVerdict(format!(
            "{field} uses unsupported signature algorithm {}",
            signature.alg
        )));
    }
    Ok(())
}

fn parse_verdict_timestamp(field: &str, value: &str) -> Result<u64> {
    parse_utc_timestamp_millis(value).map_err(|error| {
        AttestationError::MalformedVerdict(format!(
            "{field} is not a canonical UTC timestamp: {error}"
        ))
    })
}

pub(crate) fn cpu_allowed(cpu: &CpuTeeKind, accepted: &[CpuTeeKind]) -> bool {
    accepted.iter().any(|candidate| candidate == cpu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn fixture_verdict() -> AttestationVerdict {
        serde_json::from_str(include_str!("../../../fixtures/verdict/demo-verified.json")).unwrap()
    }

    fn verdict_with(field: &str, value: Value) -> AttestationVerdict {
        let mut verdict: Value =
            serde_json::from_str(include_str!("../../../fixtures/verdict/demo-verified.json"))
                .unwrap();
        verdict[field] = value;
        serde_json::from_value(verdict).unwrap()
    }

    fn verdict_with_check(check_name: &str, result: &str) -> AttestationVerdict {
        let mut verdict: Value =
            serde_json::from_str(include_str!("../../../fixtures/verdict/demo-verified.json"))
                .unwrap();
        verdict["checks"][check_name] = json!(result);
        verdict["check_outcomes"][check_name]["state"] = json!(result);
        serde_json::from_value(verdict).unwrap()
    }

    fn attributed_party(
        role: RoutePartyRole,
        party_id: Option<&str>,
        source: AttributionSource,
    ) -> RoutePartyAttribution {
        RoutePartyAttribution {
            role,
            party_id: party_id.map(str::to_owned),
            source,
            detail: "fixture attribution detail".into(),
            evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn verdict_validation_accepts_known_major_schema_metadata() {
        let mut verdict = fixture_verdict();
        verdict.schema = "confidential-inference.verdict.v1.1".into();
        verdict.policy_schema = "confidential-inference.policy.v1.1".into();
        verdict.reference_values_schema = "confidential-inference.reference-values.v1.1".into();
        verdict.provider_registry_schema = "confidential-inference.provider-registry.v1.1".into();

        verdict.validate_summary_consistency().unwrap();
    }

    #[test]
    fn verdict_validation_accepts_same_major_optional_unknown_fields() {
        let mut value: Value =
            serde_json::from_str(include_str!("../../../fixtures/verdict/demo-verified.json"))
                .unwrap();
        value["schema"] = json!("confidential-inference.verdict.v1.1");
        value["future_optional_field"] = json!({"ignored": true});

        let verdict: AttestationVerdict = serde_json::from_value(value).unwrap();

        assert!(verdict.required.is_empty());
        verdict.validate_summary_consistency().unwrap();
    }

    #[test]
    fn verdict_validation_rejects_structured_check_state_mismatch() {
        let mut verdict = fixture_verdict();
        verdict.check_outcomes = verdict
            .checks
            .iter()
            .map(|(name, state)| {
                (
                    name.clone(),
                    CheckOutcome {
                        state: state.clone(),
                        required: false,
                        detail: "fixture check detail".into(),
                        evidence_refs: Vec::new(),
                    },
                )
            })
            .collect();
        verdict
            .check_outcomes
            .get_mut("model_binding")
            .unwrap()
            .state = CheckResult::Failed;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("check_outcomes.model_binding.state conflicts"));
    }

    #[test]
    fn verdict_validation_rejects_inferred_provider_attribution() {
        let mut verdict = fixture_verdict();
        verdict.route_attribution = Some(RouteAttribution {
            parties: vec![
                attributed_party(
                    RoutePartyRole::InferenceProvider,
                    Some("different-provider"),
                    AttributionSource::SignedRegistry,
                ),
                attributed_party(
                    RoutePartyRole::RegistryAuthority,
                    Some("confidential-inference"),
                    AttributionSource::SignedRegistry,
                ),
                attributed_party(
                    RoutePartyRole::ReferenceValuesAuthority,
                    Some("confidential-inference"),
                    AttributionSource::SignedReferenceValues,
                ),
                attributed_party(
                    RoutePartyRole::WorkloadOperator,
                    None,
                    AttributionSource::Unknown,
                ),
                attributed_party(
                    RoutePartyRole::TeePlatform,
                    Some("tdx"),
                    AttributionSource::AttestedEvidence,
                ),
                attributed_party(RoutePartyRole::CloudHost, None, AttributionSource::Unknown),
            ],
        });

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("must match the signed registry provider"));
    }

    #[test]
    fn verdict_validation_rejects_unknown_required_fields() {
        let mut value: Value =
            serde_json::from_str(include_str!("../../../fixtures/verdict/demo-verified.json"))
                .unwrap();
        value["schema"] = json!("confidential-inference.verdict.v1.1");
        value["required"] = json!(["future_required_field"]);
        value["future_required_field"] = json!(true);
        let verdict: AttestationVerdict = serde_json::from_value(value).unwrap();

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("unsupported required field future_required_field"));
    }

    #[test]
    fn verdict_validation_rejects_malformed_required_list() {
        let mut verdict = fixture_verdict();
        verdict.required = vec!["".into()];

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("required list must contain non-empty field names"));
    }

    #[test]
    fn verdict_deserialization_rejects_missing_declared_required_known_field() {
        let mut value: Value =
            serde_json::from_str(include_str!("../../../fixtures/verdict/demo-verified.json"))
                .unwrap();
        value["required"] = json!(["policy_digest"]);
        value.as_object_mut().unwrap().remove("policy_digest");

        let error = serde_json::from_value::<AttestationVerdict>(value).unwrap_err();

        assert!(error.to_string().contains("policy_digest"));
    }

    #[test]
    fn verdict_validation_rejects_unknown_major_schema_metadata() {
        let verdict = verdict_with("schema", json!("confidential-inference.verdict.v2"));
        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("schema major version 2 is not supported"));
    }

    #[test]
    fn verdict_validation_rejects_malformed_digest_metadata() {
        for field in [
            "policy_digest",
            "provider_registry_digest",
            "reference_values_digest",
            "raw_evidence_digest",
            "evidence_digest",
        ] {
            let verdict = verdict_with(field, json!("sha256:not-canonical"));
            let error = verdict.validate_summary_consistency().unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("{field} must be a canonical sha256 digest")),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn verdict_validation_rejects_incomplete_signature_metadata() {
        for field in ["registry_signature", "reference_values_signature"] {
            let mut verdict = fixture_verdict();
            match field {
                "registry_signature" => verdict.registry_signature.signer.clear(),
                "reference_values_signature" => verdict.reference_values_signature.key_id.clear(),
                _ => unreachable!(),
            }

            let error = verdict.validate_summary_consistency().unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains(&format!("{field} metadata is incomplete")),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn verdict_validation_rejects_unsupported_signature_algorithm() {
        for field in ["registry_signature", "reference_values_signature"] {
            let mut verdict = fixture_verdict();
            match field {
                "registry_signature" => verdict.registry_signature.alg = "rsa".into(),
                "reference_values_signature" => {
                    verdict.reference_values_signature.alg = "rsa".into()
                }
                _ => unreachable!(),
            }

            let error = verdict.validate_summary_consistency().unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains(&format!("{field} uses unsupported signature algorithm rsa")),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn verdict_validation_rejects_expires_at_computed_mismatch() {
        let mut verdict = fixture_verdict();
        verdict.expires_at = "2099-01-01T00:00:01Z".into();

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("expires_at must match validity.computed_expires_at"));
    }

    #[test]
    fn verdict_validation_rejects_expires_at_epoch_mismatch() {
        let mut verdict = fixture_verdict();
        verdict.expires_at_epoch_ms += 1;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("expires_at_epoch_ms must match expires_at"));
    }

    #[test]
    fn verdict_validation_rejects_computed_expiry_after_validity_bound() {
        let mut verdict = fixture_verdict();
        verdict.validity.policy_ttl_until = "2098-12-31T23:59:59Z".into();

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("validity.computed_expires_at must be the minimum validity bound"));
    }

    #[test]
    fn verdict_validation_rejects_verified_status_with_failed_check() {
        let mut verdict = verdict_with_check("image_provenance", "failed");
        verdict.enforcement = EnforcementMode::Observe;
        verdict.would_block_under_enforce = true;
        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("status=verified but at least one check is failed"));
    }

    #[test]
    fn verdict_validation_rejects_verified_status_with_errors() {
        let mut verdict = fixture_verdict();
        verdict.errors.push(VerdictError {
            code: "bad_check".into(),
            message: "check failed".into(),
        });

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("status=verified but verdict contains errors"));
    }

    #[test]
    fn verdict_validation_rejects_verified_status_that_would_block() {
        let mut verdict = fixture_verdict();
        verdict.enforcement = EnforcementMode::Observe;
        verdict.would_block_under_enforce = true;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("would_block_under_enforce=true but no check is failed"));
    }

    #[test]
    fn verdict_validation_rejects_failed_checks_without_would_block_flag() {
        let mut verdict = verdict_with_check("image_provenance", "failed");
        verdict.status = VerificationStatus::Failed;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("failed checks conflict with would_block_under_enforce=false"));
    }

    #[test]
    fn verdict_validation_rejects_would_block_without_failed_checks() {
        let mut verdict = fixture_verdict();
        verdict.status = VerificationStatus::Partial;
        verdict.enforcement = EnforcementMode::Observe;
        verdict.would_block_under_enforce = true;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("would_block_under_enforce=true but no check is failed"));
    }

    #[test]
    fn verdict_validation_rejects_enforcing_verdict_that_would_block_but_allows() {
        let mut verdict = verdict_with_check("image_provenance", "failed");
        verdict.status = VerificationStatus::Failed;
        verdict.would_block_under_enforce = true;
        verdict.request_allowed = true;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("enforce verdict would block but request_allowed=true"));
    }

    #[test]
    fn verdict_validation_rejects_enforcing_verdict_that_allows_but_denies() {
        let mut verdict = fixture_verdict();
        verdict.status = VerificationStatus::Partial;
        verdict.request_allowed = false;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("enforce verdict allows policy but request_allowed=false"));
    }

    #[test]
    fn verdict_validation_rejects_non_enforcing_verdict_that_denies() {
        for (enforcement, status) in [
            (EnforcementMode::Observe, VerificationStatus::Partial),
            (EnforcementMode::Disabled, VerificationStatus::Disabled),
        ] {
            let mut verdict = fixture_verdict();
            verdict.enforcement = enforcement;
            verdict.status = status;
            verdict.request_allowed = false;

            let error = verdict.validate_summary_consistency().unwrap_err();

            assert!(error
                .to_string()
                .contains("non-enforcing verdict must not set request_allowed=false"));
        }
    }

    #[test]
    fn verdict_validation_rejects_disabled_enforcement_without_disabled_status() {
        let mut verdict = fixture_verdict();
        verdict.enforcement = EnforcementMode::Disabled;
        verdict.status = VerificationStatus::Partial;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("disabled enforcement must emit status=disabled"));
    }

    #[test]
    fn verdict_validation_rejects_disabled_status_without_disabled_enforcement() {
        let mut verdict = fixture_verdict();
        verdict.enforcement = EnforcementMode::Observe;
        verdict.status = VerificationStatus::Disabled;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("status=disabled requires disabled enforcement"));
    }

    #[test]
    fn verdict_validation_rejects_verified_app_e2ee_with_wrong_channel_kind() {
        let mut verdict = fixture_verdict();
        verdict.channel_binding_kind = ChannelBindingKind::TeeTerminatedTls;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("trust_tier=app-e2ee requires channel_binding_kind"));
    }

    #[test]
    fn verdict_validation_rejects_verified_app_e2ee_without_bound_response() {
        let mut verdict = fixture_verdict();
        verdict.response_channel_bound = false;
        verdict.response_confidentiality_result = ConfidentialityResult::Unknown;
        verdict.response_integrity_result = ResponseIntegrityResult::Unknown;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("trust_tier=app-e2ee requires request and response channel binding"));
    }

    #[test]
    fn verdict_validation_rejects_verified_hw_tls_without_tls_check() {
        let mut verdict = fixture_verdict();
        verdict.trust_tier = TrustTier::HwVerifiedTls;
        verdict.channel_binding_kind = ChannelBindingKind::TeeTerminatedTls;
        verdict.request_confidentiality_result = ConfidentialityResult::ChannelBound;
        verdict.response_confidentiality_result = ConfidentialityResult::ChannelBound;
        verdict
            .checks
            .insert("tls_binding".into(), CheckResult::NotApplicable);

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error.to_string().contains("tls_binding"));
    }

    #[test]
    fn verdict_validation_rejects_verified_tee_only_with_response_channel_binding() {
        let mut verdict = fixture_verdict();
        verdict.trust_tier = TrustTier::TeeOnly;
        verdict.channel_binding_kind = ChannelBindingKind::None;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("trust_tier=tee-only must not report response_channel_bound=true"));
    }

    #[test]
    fn verdict_validation_rejects_verified_none_with_bound_summaries() {
        let mut verdict = fixture_verdict();
        verdict.trust_tier = TrustTier::None;
        verdict.channel_binding_kind = ChannelBindingKind::None;

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error
            .to_string()
            .contains("trust_tier=none conflicts with bound channel"));
    }

    #[test]
    fn verdict_validation_rejects_bound_request_summary_without_verified_checks() {
        for check_name in ["request_key_binding", "request_encryption"] {
            let verdict = verdict_with_check(check_name, "failed");
            let error = verdict.validate_summary_consistency().unwrap_err();
            assert!(
                error.to_string().contains(check_name),
                "{check_name}: {error}"
            );
        }
    }

    #[test]
    fn verdict_validation_rejects_bound_response_summary_without_verified_checks() {
        for check_name in [
            "response_key_binding",
            "response_encryption",
            "response_channel_binding",
        ] {
            let verdict = verdict_with_check(check_name, "failed");
            let error = verdict.validate_summary_consistency().unwrap_err();
            assert!(
                error.to_string().contains(check_name),
                "{check_name}: {error}"
            );
        }
    }

    #[test]
    fn verdict_validation_rejects_receipt_integrity_without_verified_receipt_check() {
        let mut verdict = fixture_verdict();
        verdict.response_channel_bound = false;
        verdict.response_confidentiality_result = ConfidentialityResult::Unknown;
        verdict.response_integrity_result = ResponseIntegrityResult::ReceiptBound;
        verdict
            .checks
            .insert("response_receipt".into(), CheckResult::Failed);

        let error = verdict.validate_summary_consistency().unwrap_err();

        assert!(error.to_string().contains("response_receipt"));
    }
}
