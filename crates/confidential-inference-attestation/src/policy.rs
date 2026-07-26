use crate::{canonical_digest, AttestationError, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Disabled,
    Observe,
    Enforce,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuTeeKind {
    Tdx,
    SevSnp,
    Nitro,
}

impl CpuTeeKind {
    pub fn as_policy_str(&self) -> &'static str {
        match self {
            CpuTeeKind::Tdx => "tdx",
            CpuTeeKind::SevSnp => "sev_snp",
            CpuTeeKind::Nitro => "nitro",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum CpuTeeRequirement {
    NotRequired,
    AnyCpuTee,
    OneOf { allowed: Vec<CpuTeeKind> },
}

impl CpuTeeRequirement {
    pub fn one_of(mut allowed: Vec<CpuTeeKind>) -> Self {
        allowed.sort_by(|left, right| left.as_policy_str().cmp(right.as_policy_str()));
        allowed.dedup();
        CpuTeeRequirement::OneOf { allowed }
    }

    fn normalize(&mut self) {
        if let CpuTeeRequirement::OneOf { allowed } = self {
            allowed.sort_by(|left, right| left.as_policy_str().cmp(right.as_policy_str()));
            allowed.dedup();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuTeeKind {
    NvidiaCc,
}

impl GpuTeeKind {
    pub fn as_policy_str(&self) -> &'static str {
        match self {
            GpuTeeKind::NvidiaCc => "nvidia_cc",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum GpuTeeRequirement {
    NotRequired,
    OneOf { allowed: Vec<GpuTeeKind> },
}

impl GpuTeeRequirement {
    pub fn one_of(mut allowed: Vec<GpuTeeKind>) -> Self {
        allowed.sort_by(|left, right| left.as_policy_str().cmp(right.as_policy_str()));
        allowed.dedup();
        GpuTeeRequirement::OneOf { allowed }
    }

    fn normalize(&mut self) {
        if let GpuTeeRequirement::OneOf { allowed } = self {
            allowed.sort_by(|left, right| left.as_policy_str().cmp(right.as_policy_str()));
            allowed.dedup();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareRequirement {
    pub cpu: CpuTeeRequirement,
    pub gpu: GpuTeeRequirement,
}

impl HardwareRequirement {
    pub fn any_cpu_tee() -> Self {
        Self {
            cpu: CpuTeeRequirement::AnyCpuTee,
            gpu: GpuTeeRequirement::NotRequired,
        }
    }

    pub fn not_required() -> Self {
        Self {
            cpu: CpuTeeRequirement::NotRequired,
            gpu: GpuTeeRequirement::NotRequired,
        }
    }

    fn normalize(&mut self) {
        self.cpu.normalize();
        self.gpu.normalize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelBindingRequirement {
    NotRequired,
    AnyAttestedChannel,
    TeeTerminatedTls,
    AttestedAppE2ee,
}

impl ChannelBindingRequirement {
    pub fn as_policy_str(&self) -> &'static str {
        match self {
            ChannelBindingRequirement::NotRequired => "not_required",
            ChannelBindingRequirement::AnyAttestedChannel => "any_attested_channel",
            ChannelBindingRequirement::TeeTerminatedTls => "tee_terminated_tls",
            ChannelBindingRequirement::AttestedAppE2ee => "attested_app_e2ee",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundDataRequirement {
    NotRequired,
    BoundToAttestedWorkload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseIntegrityRequirement {
    NotRequired,
    AnyBound,
    ChannelBound,
    ReceiptBound,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelBindingRequirement {
    NotRequired,
    IfProviderSupports,
    Required,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRequirement {
    pub workload_image: bool,
    pub model_artifacts: bool,
    pub reproducible_build: bool,
    pub source_attestation: bool,
    pub dependency_sbom: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Millis(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum StaleVerdictPolicy {
    FailClosed,
    AllowForMillis { millis: Millis },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum FreshnessPolicy {
    PerRequest,
    PerSession,
    AllowCachedBindingMillis { millis: Millis },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationPolicy {
    pub schema: String,
    pub enforcement: EnforcementMode,
    pub hardware: HardwareRequirement,
    pub channel_binding_requirement: ChannelBindingRequirement,
    pub request_confidentiality_requirement: BoundDataRequirement,
    pub response_confidentiality_requirement: BoundDataRequirement,
    pub response_integrity_requirement: ResponseIntegrityRequirement,
    pub model_binding_requirement: ModelBindingRequirement,
    pub provenance: ProvenanceRequirement,
    pub freshness: FreshnessPolicy,
    pub stale_verdicts: StaleVerdictPolicy,
    pub verdict_ttl_millis: Millis,
    pub provider_registry_digest: String,
    pub reference_values_digest: String,
}

impl VerificationPolicy {
    pub const SCHEMA: &'static str = "confidential-inference.policy.v1";
    pub const SUPPORTED_SCHEMA_MAJOR: u32 = 1;
    pub const UNRESOLVED_DIGEST: &'static str = "sha256:unresolved";

    pub fn disabled() -> Self {
        Self {
            schema: Self::SCHEMA.to_owned(),
            enforcement: EnforcementMode::Disabled,
            hardware: HardwareRequirement::not_required(),
            channel_binding_requirement: ChannelBindingRequirement::NotRequired,
            request_confidentiality_requirement: BoundDataRequirement::NotRequired,
            response_confidentiality_requirement: BoundDataRequirement::NotRequired,
            response_integrity_requirement: ResponseIntegrityRequirement::NotRequired,
            model_binding_requirement: ModelBindingRequirement::NotRequired,
            provenance: ProvenanceRequirement::default(),
            freshness: FreshnessPolicy::AllowCachedBindingMillis {
                millis: Millis(600_000),
            },
            stale_verdicts: StaleVerdictPolicy::AllowForMillis {
                millis: Millis(600_000),
            },
            verdict_ttl_millis: Millis(600_000),
            provider_registry_digest: Self::UNRESOLVED_DIGEST.to_owned(),
            reference_values_digest: Self::UNRESOLVED_DIGEST.to_owned(),
        }
    }

    pub fn observe() -> Self {
        let mut policy = Self::require_hardware();
        policy.enforcement = EnforcementMode::Observe;
        policy
    }

    pub fn require_hardware() -> Self {
        Self {
            schema: Self::SCHEMA.to_owned(),
            enforcement: EnforcementMode::Enforce,
            hardware: HardwareRequirement::any_cpu_tee(),
            channel_binding_requirement: ChannelBindingRequirement::NotRequired,
            request_confidentiality_requirement: BoundDataRequirement::NotRequired,
            response_confidentiality_requirement: BoundDataRequirement::NotRequired,
            response_integrity_requirement: ResponseIntegrityRequirement::NotRequired,
            model_binding_requirement: ModelBindingRequirement::NotRequired,
            provenance: ProvenanceRequirement::default(),
            freshness: FreshnessPolicy::PerSession,
            stale_verdicts: StaleVerdictPolicy::FailClosed,
            verdict_ttl_millis: Millis(600_000),
            provider_registry_digest: Self::UNRESOLVED_DIGEST.to_owned(),
            reference_values_digest: Self::UNRESOLVED_DIGEST.to_owned(),
        }
    }

    pub fn require_attested_e2ee() -> Self {
        let mut policy = Self::require_hardware();
        policy.channel_binding_requirement = ChannelBindingRequirement::AttestedAppE2ee;
        policy.request_confidentiality_requirement = BoundDataRequirement::BoundToAttestedWorkload;
        policy.response_confidentiality_requirement = BoundDataRequirement::BoundToAttestedWorkload;
        policy.response_integrity_requirement = ResponseIntegrityRequirement::AnyBound;
        policy.model_binding_requirement = ModelBindingRequirement::IfProviderSupports;
        policy
    }

    pub fn require_hw_verified_tls() -> Self {
        let mut policy = Self::require_hardware();
        policy.channel_binding_requirement = ChannelBindingRequirement::TeeTerminatedTls;
        policy.request_confidentiality_requirement = BoundDataRequirement::BoundToAttestedWorkload;
        policy.response_confidentiality_requirement = BoundDataRequirement::BoundToAttestedWorkload;
        policy.response_integrity_requirement = ResponseIntegrityRequirement::ChannelBound;
        policy
    }

    pub fn require_model_binding() -> Self {
        let mut policy = Self::require_hardware();
        policy.model_binding_requirement = ModelBindingRequirement::Required;
        policy
    }

    pub fn require_full_provenance(channel_binding: ChannelBindingRequirement) -> Result<Self> {
        let mut policy = Self::require_hardware();
        policy.apply_concrete_channel_binding(channel_binding, "require_full_provenance")?;
        policy.model_binding_requirement = ModelBindingRequirement::Required;
        policy.provenance = ProvenanceRequirement {
            workload_image: true,
            model_artifacts: true,
            reproducible_build: true,
            source_attestation: true,
            dependency_sbom: true,
        };
        Ok(policy)
    }

    pub fn require_confidential_gpu_inference(
        channel_binding: ChannelBindingRequirement,
    ) -> Result<Self> {
        let mut policy = Self::require_hardware();
        policy.apply_concrete_channel_binding(
            channel_binding,
            "require_confidential_gpu_inference",
        )?;
        policy.hardware.gpu = GpuTeeRequirement::one_of(vec![GpuTeeKind::NvidiaCc]);
        Ok(policy)
    }

    pub fn with_artifact_digests(
        mut self,
        provider_registry_digest: impl Into<String>,
        reference_values_digest: impl Into<String>,
    ) -> Self {
        self.provider_registry_digest = provider_registry_digest.into();
        self.reference_values_digest = reference_values_digest.into();
        self
    }

    pub fn digest(&self) -> Result<String> {
        validate_policy_schema_major("schema", &self.schema)?;
        canonical_digest(&self.normalized())
    }

    pub fn normalized(&self) -> Self {
        let mut policy = self.clone();
        policy.hardware.normalize();
        policy
    }

    fn apply_concrete_channel_binding(
        &mut self,
        channel_binding: ChannelBindingRequirement,
        helper: &str,
    ) -> Result<()> {
        self.request_confidentiality_requirement = BoundDataRequirement::BoundToAttestedWorkload;
        self.response_confidentiality_requirement = BoundDataRequirement::BoundToAttestedWorkload;
        match channel_binding {
            ChannelBindingRequirement::TeeTerminatedTls => {
                self.channel_binding_requirement = ChannelBindingRequirement::TeeTerminatedTls;
                self.response_integrity_requirement = ResponseIntegrityRequirement::ChannelBound;
                Ok(())
            }
            ChannelBindingRequirement::AttestedAppE2ee => {
                self.channel_binding_requirement = ChannelBindingRequirement::AttestedAppE2ee;
                self.response_integrity_requirement = ResponseIntegrityRequirement::AnyBound;
                self.model_binding_requirement = ModelBindingRequirement::IfProviderSupports;
                Ok(())
            }
            other => Err(AttestationError::InvalidPolicy(format!(
                "{helper} requires tee_terminated_tls or attested_app_e2ee, got {}",
                other.as_policy_str()
            ))),
        }
    }
}

fn validate_policy_schema_major(field: &str, value: &str) -> Result<()> {
    let Some(version) = value
        .strip_prefix("confidential-inference.policy")
        .and_then(|rest| rest.strip_prefix(".v"))
    else {
        return Err(AttestationError::InvalidPolicy(format!(
            "{field} must start with confidential-inference.policy.v{}",
            VerificationPolicy::SUPPORTED_SCHEMA_MAJOR
        )));
    };
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or_default();
    if major.is_empty() || major.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(AttestationError::InvalidPolicy(format!(
            "{field} has malformed schema version {value}"
        )));
    }
    for part in parts {
        if part.is_empty() || part.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(AttestationError::InvalidPolicy(format!(
                "{field} has malformed schema version {value}"
            )));
        }
    }
    let parsed_major = major.parse::<u32>().map_err(|_| {
        AttestationError::InvalidPolicy(format!("{field} has malformed schema version {value}"))
    })?;
    if parsed_major != VerificationPolicy::SUPPORTED_SCHEMA_MAJOR {
        return Err(AttestationError::InvalidPolicy(format!(
            "{field} major version {parsed_major} is not supported"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical_json, AttestationError, MAX_SAFE_JSON_INT};
    use serde::Deserialize;
    use std::collections::BTreeMap;

    const DEMO_REGISTRY_DIGEST: &str =
        "sha256:5f7d7f58d2198ccabbdd1c90e9d0ec0030d9934d80895007244971e3e61b7373";
    const DEMO_REFERENCE_VALUES_DIGEST: &str =
        "sha256:23e42367da27793fd4600dcc48ad51c2c8b7b3124f541c23cfcc7c7c8ef474b9";
    const DEMO_REQUIRE_ATTESTED_E2EE_POLICY_DIGEST: &str =
        "sha256:3e65bdb04377c5169296f258e37d8133fa6365df10259da31dbc4502c5aca783";

    #[test]
    fn cpu_one_of_is_sorted_for_canonical_digest() {
        let left = VerificationPolicy {
            hardware: HardwareRequirement {
                cpu: CpuTeeRequirement::one_of(vec![CpuTeeKind::Tdx, CpuTeeKind::SevSnp]),
                gpu: GpuTeeRequirement::NotRequired,
            },
            ..VerificationPolicy::require_hardware()
        };
        let right = VerificationPolicy {
            hardware: HardwareRequirement {
                cpu: CpuTeeRequirement::one_of(vec![CpuTeeKind::SevSnp, CpuTeeKind::Tdx]),
                gpu: GpuTeeRequirement::NotRequired,
            },
            ..VerificationPolicy::require_hardware()
        };

        assert_eq!(left.digest().unwrap(), right.digest().unwrap());
    }

    #[test]
    fn require_attested_e2ee_policy_digest_matches_demo_vector() {
        let policy = VerificationPolicy::require_attested_e2ee()
            .with_artifact_digests(DEMO_REGISTRY_DIGEST, DEMO_REFERENCE_VALUES_DIGEST);

        assert_eq!(
            policy.digest().unwrap(),
            DEMO_REQUIRE_ATTESTED_E2EE_POLICY_DIGEST
        );
    }

    #[test]
    fn require_attested_e2ee_policy_fixture_matches_constructor() {
        let fixture: VerificationPolicy = serde_json::from_str(include_str!(
            "../../../fixtures/policy/require_attested_e2ee.json"
        ))
        .unwrap();
        let constructed = VerificationPolicy::require_attested_e2ee()
            .with_artifact_digests(DEMO_REGISTRY_DIGEST, DEMO_REFERENCE_VALUES_DIGEST);

        assert_eq!(fixture, constructed);
        assert_eq!(
            fixture.digest().unwrap(),
            DEMO_REQUIRE_ATTESTED_E2EE_POLICY_DIGEST
        );
    }

    #[test]
    fn policy_digest_accepts_same_major_schema_metadata() {
        let mut policy = VerificationPolicy::require_attested_e2ee()
            .with_artifact_digests(DEMO_REGISTRY_DIGEST, DEMO_REFERENCE_VALUES_DIGEST);
        policy.schema = "confidential-inference.policy.v1.1".into();

        assert!(policy.digest().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn policy_digest_rejects_unknown_major_schema_metadata() {
        let mut policy = VerificationPolicy::require_attested_e2ee()
            .with_artifact_digests(DEMO_REGISTRY_DIGEST, DEMO_REFERENCE_VALUES_DIGEST);
        policy.schema = "confidential-inference.policy.v2".into();

        let error = policy.digest().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidPolicy(message)
                if message.contains("schema major version 2 is not supported")
        ));
    }

    #[test]
    fn policy_digest_rejects_malformed_schema_metadata() {
        let mut policy = VerificationPolicy::require_attested_e2ee()
            .with_artifact_digests(DEMO_REGISTRY_DIGEST, DEMO_REFERENCE_VALUES_DIGEST);
        policy.schema = "confidential-inference.policy.v1.beta".into();

        let error = policy.digest().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidPolicy(message)
                if message.contains("schema has malformed schema version")
        ));
    }

    #[test]
    fn security_axis_downgrades_change_policy_digest() {
        let mut base = VerificationPolicy::require_confidential_gpu_inference(
            ChannelBindingRequirement::AttestedAppE2ee,
        )
        .unwrap()
        .with_artifact_digests(DEMO_REGISTRY_DIGEST, DEMO_REFERENCE_VALUES_DIGEST);
        base.model_binding_requirement = ModelBindingRequirement::Required;
        base.provenance = ProvenanceRequirement {
            workload_image: true,
            model_artifacts: true,
            reproducible_build: true,
            source_attestation: true,
            dependency_sbom: true,
        };
        base.freshness = FreshnessPolicy::PerRequest;
        base.stale_verdicts = StaleVerdictPolicy::FailClosed;
        base.verdict_ttl_millis = Millis(60_000);
        let base_digest = base.digest().unwrap();

        let cases = [
            (
                "enforcement",
                VerificationPolicy {
                    enforcement: EnforcementMode::Observe,
                    ..base.clone()
                },
            ),
            (
                "cpu tee requirement",
                VerificationPolicy {
                    hardware: HardwareRequirement {
                        cpu: CpuTeeRequirement::NotRequired,
                        ..base.hardware.clone()
                    },
                    ..base.clone()
                },
            ),
            (
                "gpu tee requirement",
                VerificationPolicy {
                    hardware: HardwareRequirement {
                        gpu: GpuTeeRequirement::NotRequired,
                        ..base.hardware.clone()
                    },
                    ..base.clone()
                },
            ),
            (
                "channel binding",
                VerificationPolicy {
                    channel_binding_requirement: ChannelBindingRequirement::NotRequired,
                    ..base.clone()
                },
            ),
            (
                "request confidentiality",
                VerificationPolicy {
                    request_confidentiality_requirement: BoundDataRequirement::NotRequired,
                    ..base.clone()
                },
            ),
            (
                "response confidentiality",
                VerificationPolicy {
                    response_confidentiality_requirement: BoundDataRequirement::NotRequired,
                    ..base.clone()
                },
            ),
            (
                "response integrity",
                VerificationPolicy {
                    response_integrity_requirement: ResponseIntegrityRequirement::NotRequired,
                    ..base.clone()
                },
            ),
            (
                "model binding",
                VerificationPolicy {
                    model_binding_requirement: ModelBindingRequirement::NotRequired,
                    ..base.clone()
                },
            ),
            (
                "workload image provenance",
                VerificationPolicy {
                    provenance: ProvenanceRequirement {
                        workload_image: false,
                        ..base.provenance.clone()
                    },
                    ..base.clone()
                },
            ),
            (
                "freshness",
                VerificationPolicy {
                    freshness: FreshnessPolicy::PerSession,
                    ..base.clone()
                },
            ),
            (
                "stale verdicts",
                VerificationPolicy {
                    stale_verdicts: StaleVerdictPolicy::AllowForMillis {
                        millis: Millis(60_000),
                    },
                    ..base.clone()
                },
            ),
            (
                "verdict ttl",
                VerificationPolicy {
                    verdict_ttl_millis: Millis(600_000),
                    ..base.clone()
                },
            ),
            (
                "registry digest",
                VerificationPolicy {
                    provider_registry_digest:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    ..base.clone()
                },
            ),
            (
                "reference-values digest",
                VerificationPolicy {
                    reference_values_digest:
                        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                            .into(),
                    ..base.clone()
                },
            ),
        ];

        for (label, policy) in cases {
            assert_ne!(
                policy.digest().unwrap(),
                base_digest,
                "{label} downgrade did not change policy digest"
            );
        }
    }

    #[test]
    fn require_full_provenance_sets_all_supply_chain_requirements() {
        let app_e2ee =
            VerificationPolicy::require_full_provenance(ChannelBindingRequirement::AttestedAppE2ee)
                .unwrap();

        assert_eq!(
            app_e2ee.channel_binding_requirement,
            ChannelBindingRequirement::AttestedAppE2ee
        );
        assert_eq!(
            app_e2ee.request_confidentiality_requirement,
            BoundDataRequirement::BoundToAttestedWorkload
        );
        assert_eq!(
            app_e2ee.response_confidentiality_requirement,
            BoundDataRequirement::BoundToAttestedWorkload
        );
        assert_eq!(
            app_e2ee.response_integrity_requirement,
            ResponseIntegrityRequirement::AnyBound
        );
        assert_eq!(
            app_e2ee.model_binding_requirement,
            ModelBindingRequirement::Required
        );
        assert!(app_e2ee.provenance.workload_image);
        assert!(app_e2ee.provenance.model_artifacts);
        assert!(app_e2ee.provenance.reproducible_build);
        assert!(app_e2ee.provenance.source_attestation);
        assert!(app_e2ee.provenance.dependency_sbom);

        let tls = VerificationPolicy::require_full_provenance(
            ChannelBindingRequirement::TeeTerminatedTls,
        )
        .unwrap();
        assert_eq!(
            tls.channel_binding_requirement,
            ChannelBindingRequirement::TeeTerminatedTls
        );
        assert_eq!(
            tls.response_integrity_requirement,
            ResponseIntegrityRequirement::ChannelBound
        );
    }

    #[test]
    fn require_confidential_gpu_inference_requires_cpu_and_nvidia_gpu_tee() {
        let policy = VerificationPolicy::require_confidential_gpu_inference(
            ChannelBindingRequirement::AttestedAppE2ee,
        )
        .unwrap();

        assert_eq!(policy.hardware.cpu, CpuTeeRequirement::AnyCpuTee);
        assert!(matches!(
            policy.hardware.gpu,
            GpuTeeRequirement::OneOf { ref allowed }
                if allowed.as_slice() == [GpuTeeKind::NvidiaCc]
        ));
        assert_eq!(
            policy.channel_binding_requirement,
            ChannelBindingRequirement::AttestedAppE2ee
        );
        assert_eq!(
            policy.request_confidentiality_requirement,
            BoundDataRequirement::BoundToAttestedWorkload
        );
        assert_eq!(
            policy.response_confidentiality_requirement,
            BoundDataRequirement::BoundToAttestedWorkload
        );
        assert_eq!(
            policy.response_integrity_requirement,
            ResponseIntegrityRequirement::AnyBound
        );
    }

    #[test]
    fn strong_policy_helpers_reject_weak_or_ambiguous_channel_binding() {
        for channel_binding in [
            ChannelBindingRequirement::NotRequired,
            ChannelBindingRequirement::AnyAttestedChannel,
        ] {
            let full_provenance_error =
                VerificationPolicy::require_full_provenance(channel_binding.clone()).unwrap_err();
            assert!(matches!(
                full_provenance_error,
                AttestationError::InvalidPolicy(message)
                    if message.contains("requires tee_terminated_tls or attested_app_e2ee")
            ));

            let gpu_error = VerificationPolicy::require_confidential_gpu_inference(channel_binding)
                .unwrap_err();
            assert!(matches!(
                gpu_error,
                AttestationError::InvalidPolicy(message)
                    if message.contains("requires tee_terminated_tls or attested_app_e2ee")
            ));
        }
    }

    #[test]
    fn canonical_policy_vectors_match_fixture() {
        let vectors = policy_vectors();

        assert_eq!(
            vectors.schema,
            "confidential-inference.policy-canonical-vectors.v1"
        );
        for vector in &vectors.vectors {
            let normalized = vector.policy.normalized();

            assert_eq!(
                canonical_json(&normalized).unwrap(),
                vector.canonical_json,
                "{} canonical JSON changed",
                vector.id
            );
            assert_eq!(
                vector.policy.digest().unwrap(),
                vector.digest,
                "{} digest changed",
                vector.id
            );
        }

        let vector_by_id = vectors
            .vectors
            .iter()
            .map(|vector| (vector.id.as_str(), vector))
            .collect::<BTreeMap<_, _>>();

        for case in &vectors.equivalence_cases {
            let expected = vector_by_id
                .get(case.equivalent_to.as_str())
                .unwrap_or_else(|| panic!("{} references a missing vector", case.id));

            assert_eq!(
                case.policy.digest().unwrap(),
                expected.digest,
                "{} no longer normalizes to {}",
                case.id,
                case.equivalent_to
            );
            assert_eq!(
                canonical_json(&case.policy.normalized()).unwrap(),
                expected.canonical_json,
                "{} canonical form diverged from {}",
                case.id,
                case.equivalent_to
            );
        }
    }

    #[test]
    fn policy_json_rejects_unknown_structured_fields() {
        let with_extra_field = r#"{
          "schema": "confidential-inference.policy.v1",
          "enforcement": "enforce",
          "hardware": {
            "cpu": { "mode": "one_of", "allowed": ["tdx"], "unexpected": true },
            "gpu": { "mode": "not_required" }
          },
          "channel_binding_requirement": "not_required",
          "request_confidentiality_requirement": "not_required",
          "response_confidentiality_requirement": "not_required",
          "response_integrity_requirement": "not_required",
          "model_binding_requirement": "not_required",
          "provenance": {
            "workload_image": false,
            "model_artifacts": false,
            "reproducible_build": false,
            "source_attestation": false,
            "dependency_sbom": false
          },
          "freshness": { "mode": "per_session" },
          "stale_verdicts": { "mode": "fail_closed" },
          "verdict_ttl_millis": 600000,
          "provider_registry_digest": "sha256:unresolved",
          "reference_values_digest": "sha256:unresolved"
        }"#;

        assert!(serde_json::from_str::<VerificationPolicy>(with_extra_field).is_err());
    }

    #[test]
    fn policy_digest_rejects_verdict_ttl_above_json_safe_integer_range() {
        let policy = VerificationPolicy {
            verdict_ttl_millis: Millis(MAX_SAFE_JSON_INT + 1),
            ..VerificationPolicy::require_hardware()
        };

        assert!(matches!(
            policy.digest(),
            Err(AttestationError::UnsafeInteger(value)) if value == MAX_SAFE_JSON_INT + 1
        ));
    }

    #[test]
    fn policy_digest_rejects_freshness_millis_above_json_safe_integer_range() {
        let policy = VerificationPolicy {
            freshness: FreshnessPolicy::AllowCachedBindingMillis {
                millis: Millis(MAX_SAFE_JSON_INT + 1),
            },
            ..VerificationPolicy::require_hardware()
        };

        assert!(matches!(
            policy.digest(),
            Err(AttestationError::UnsafeInteger(value)) if value == MAX_SAFE_JSON_INT + 1
        ));
    }

    #[test]
    fn policy_digest_rejects_stale_verdict_millis_above_json_safe_integer_range() {
        let policy = VerificationPolicy {
            stale_verdicts: StaleVerdictPolicy::AllowForMillis {
                millis: Millis(MAX_SAFE_JSON_INT + 1),
            },
            ..VerificationPolicy::require_hardware()
        };

        assert!(matches!(
            policy.digest(),
            Err(AttestationError::UnsafeInteger(value)) if value == MAX_SAFE_JSON_INT + 1
        ));
    }

    fn policy_vectors() -> PolicyCanonicalVectors {
        serde_json::from_str(include_str!(
            "../../../fixtures/policy/canonical-vectors.json"
        ))
        .unwrap()
    }

    #[derive(Debug, Deserialize)]
    struct PolicyCanonicalVectors {
        schema: String,
        vectors: Vec<PolicyCanonicalVector>,
        equivalence_cases: Vec<PolicyEquivalenceCase>,
    }

    #[derive(Debug, Deserialize)]
    struct PolicyCanonicalVector {
        id: String,
        policy: VerificationPolicy,
        canonical_json: String,
        digest: String,
    }

    #[derive(Debug, Deserialize)]
    struct PolicyEquivalenceCase {
        id: String,
        equivalent_to: String,
        policy: VerificationPolicy,
    }
}
