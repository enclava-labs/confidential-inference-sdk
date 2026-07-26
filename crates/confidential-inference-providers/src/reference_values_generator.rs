use confidential_inference_attestation::{
    sha256_digest, verify_chutes_e2ee_report_data_binding, verify_tls_spki_report_data_binding,
    ChannelBindingKind, ChutesE2eeEvidence, ChutesE2eeReportDataBinding, DstackEvidence,
    EvidenceHardware, ProviderReference, ReferenceValuesPayload, RouteReference,
    TinfoilAttestationFormat, TrustTier, VerifiedTinfoilQuote,
};
use std::collections::BTreeMap;

use crate::{ProviderError, Result, RouteDefinition};

const NOT_APPLICABLE_KEY_DIGEST: &str = "sha256:not-applicable";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TinfoilLiveReferenceValuesInput {
    pub version: String,
    pub issuer: String,
    pub valid_from: String,
    pub revocation_epoch: u64,
    pub minimum_acceptable_version: String,
    pub canonical_model: String,
    pub route: RouteDefinition,
    pub verified_quote: VerifiedTinfoilQuote,
    pub live_tls_spki_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppE2eeReferenceValuesInput {
    pub version: String,
    pub issuer: String,
    pub valid_from: String,
    pub revocation_epoch: u64,
    pub minimum_acceptable_version: String,
    pub canonical_model: String,
    pub route: RouteDefinition,
    pub evidence: AppE2eeReferenceEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppE2eeReferenceEvidence {
    Dstack(DstackEvidence),
    Chutes(ChutesE2eeEvidence),
}

pub fn generate_app_e2ee_reference_values(
    input: AppE2eeReferenceValuesInput,
) -> Result<ReferenceValuesPayload> {
    require_app_e2ee_route(&input.route)?;
    let canonical_model = required_for(
        "app-E2EE reference values",
        "canonical_model",
        &input.canonical_model,
    )?;
    validate_app_e2ee_evidence(&input.route, canonical_model, &input.evidence)?;
    let e2ee_public_key_digest = input.evidence.e2ee_public_key_digest()?;

    let mut routes = BTreeMap::new();
    routes.insert(
        input.route.route_id.clone(),
        RouteReference {
            canonical_model: canonical_model.to_owned(),
            provider_model: input.route.provider_model.clone(),
            evidence_family: input.route.evidence_family.clone(),
            channel_binding_kind: input.route.channel_binding_kind.clone(),
            trust_tier: input.route.trust_tier.clone(),
            accepted_cpu_tees: vec![input.evidence.hardware().cpu.clone()],
            e2ee_public_key_digest,
            response_signing_key_digest: None,
            tls_spki_sha256: None,
            workload_images: input.evidence.workload_images().to_vec(),
            workload_image_digest: input.evidence.workload_image_digest().to_owned(),
            model_artifacts: input.evidence.model_artifacts().to_vec(),
            valid_until: input.evidence.expires_at().to_owned(),
            valid_until_epoch_ms: input.evidence.expires_at_epoch_ms(),
        },
    );

    let mut providers = BTreeMap::new();
    providers.insert(
        input.route.provider.clone(),
        ProviderReference {
            accepted_measurements: vec![input.evidence.tee_measurement().to_owned()],
            routes,
        },
    );

    Ok(ReferenceValuesPayload {
        schema: ReferenceValuesPayload::SCHEMA.into(),
        version: required_for("app-E2EE reference values", "version", &input.version)?.to_owned(),
        issuer: required_for("app-E2EE reference values", "issuer", &input.issuer)?.to_owned(),
        valid_from: required_for("app-E2EE reference values", "valid_from", &input.valid_from)?
            .to_owned(),
        valid_until: input.evidence.expires_at().to_owned(),
        valid_until_epoch_ms: input.evidence.expires_at_epoch_ms(),
        revocation_epoch: input.revocation_epoch,
        minimum_acceptable_version: required_for(
            "app-E2EE reference values",
            "minimum_acceptable_version",
            &input.minimum_acceptable_version,
        )?
        .to_owned(),
        providers,
    })
}

pub fn generate_tinfoil_live_reference_values(
    input: TinfoilLiveReferenceValuesInput,
) -> Result<ReferenceValuesPayload> {
    require_tinfoil_tls_route(&input.route)?;
    let canonical_model = required_for(
        "Tinfoil live reference values",
        "canonical_model",
        &input.canonical_model,
    )?;
    let format = TinfoilAttestationFormat::parse(input.verified_quote.attestation_format.as_str())
        .map_err(|error| ProviderError::Compatibility(error.to_string()))?;
    if input.verified_quote.hardware.cpu != format.cpu_kind() {
        return Err(ProviderError::Compatibility(
            "verified Tinfoil quote CPU kind does not match attestation format".into(),
        ));
    }
    if input.verified_quote.tee_measurement.trim().is_empty() {
        return Err(ProviderError::Compatibility(
            "verified Tinfoil quote did not expose a TEE measurement".into(),
        ));
    }

    let attested_model = input
        .verified_quote
        .attested_model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ProviderError::Compatibility(
                "verified Tinfoil quote did not expose an attested model".into(),
            )
        })?;
    if attested_model != canonical_model {
        return Err(ProviderError::Compatibility(format!(
            "verified Tinfoil quote model {attested_model} does not match canonical model {canonical_model}"
        )));
    }

    let workload_image_digest = input
        .verified_quote
        .workload_image_digest
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ProviderError::Compatibility(
                "verified Tinfoil quote did not expose workload image provenance".into(),
            )
        })?;
    if input.verified_quote.model_artifacts.is_empty() {
        return Err(ProviderError::Compatibility(
            "verified Tinfoil quote did not expose model artifact provenance".into(),
        ));
    }

    let spki_sha256 = normalize_sha256_hex(&input.live_tls_spki_sha256, "live_tls_spki_sha256")?;
    let binding =
        verify_tls_spki_report_data_binding(&input.verified_quote.report_data, &spki_sha256)
            .ok_or_else(|| {
                ProviderError::Compatibility(
                    "verified Tinfoil quote report_data or TLS SPKI is not canonical hex".into(),
                )
            })?;
    if !binding.matches {
        return Err(ProviderError::Compatibility(
            "verified Tinfoil quote report_data is not bound to the live TLS SPKI".into(),
        ));
    }

    let mut routes = BTreeMap::new();
    routes.insert(
        input.route.route_id.clone(),
        RouteReference {
            canonical_model: canonical_model.to_owned(),
            provider_model: input.route.provider_model.clone(),
            evidence_family: input.route.evidence_family.clone(),
            channel_binding_kind: input.route.channel_binding_kind.clone(),
            trust_tier: input.route.trust_tier.clone(),
            accepted_cpu_tees: vec![input.verified_quote.hardware.cpu.clone()],
            e2ee_public_key_digest: NOT_APPLICABLE_KEY_DIGEST.into(),
            response_signing_key_digest: None,
            tls_spki_sha256: Some(format!("sha256:{spki_sha256}")),
            workload_images: Vec::new(),
            workload_image_digest: workload_image_digest.to_owned(),
            model_artifacts: input.verified_quote.model_artifacts.clone(),
            valid_until: input.verified_quote.expires_at.clone(),
            valid_until_epoch_ms: input.verified_quote.expires_at_epoch_ms,
        },
    );

    let mut providers = BTreeMap::new();
    providers.insert(
        input.route.provider.clone(),
        ProviderReference {
            accepted_measurements: vec![input.verified_quote.tee_measurement.clone()],
            routes,
        },
    );

    Ok(ReferenceValuesPayload {
        schema: ReferenceValuesPayload::SCHEMA.into(),
        version: required_for("Tinfoil live reference values", "version", &input.version)?
            .to_owned(),
        issuer: required_for("Tinfoil live reference values", "issuer", &input.issuer)?.to_owned(),
        valid_from: required_for(
            "Tinfoil live reference values",
            "valid_from",
            &input.valid_from,
        )?
        .to_owned(),
        valid_until: input.verified_quote.expires_at,
        valid_until_epoch_ms: input.verified_quote.expires_at_epoch_ms,
        revocation_epoch: input.revocation_epoch,
        minimum_acceptable_version: required_for(
            "Tinfoil live reference values",
            "minimum_acceptable_version",
            &input.minimum_acceptable_version,
        )?
        .to_owned(),
        providers,
    })
}

fn require_app_e2ee_route(route: &RouteDefinition) -> Result<()> {
    if route.channel_binding_kind != ChannelBindingKind::AttestedAppE2ee {
        return Err(ProviderError::Compatibility(
            "app-E2EE reference values require an attested app-E2EE route".into(),
        ));
    }
    if route.trust_tier != TrustTier::AppE2ee {
        return Err(ProviderError::Compatibility(
            "app-E2EE reference values require an app-E2EE trust tier".into(),
        ));
    }
    if route.provider.trim().is_empty()
        || route.route_id.trim().is_empty()
        || route.provider_model.trim().is_empty()
        || route.evidence_family.trim().is_empty()
    {
        return Err(ProviderError::Compatibility(
            "app-E2EE reference values require complete route metadata".into(),
        ));
    }
    Ok(())
}

fn require_tinfoil_tls_route(route: &RouteDefinition) -> Result<()> {
    if route.channel_binding_kind != ChannelBindingKind::TeeTerminatedTls {
        return Err(ProviderError::Compatibility(
            "Tinfoil live reference values require a TEE-terminated TLS route".into(),
        ));
    }
    if route.trust_tier != TrustTier::HwVerifiedTls {
        return Err(ProviderError::Compatibility(
            "Tinfoil live reference values require a hardware-verified TLS trust tier".into(),
        ));
    }
    if route.provider.trim().is_empty()
        || route.route_id.trim().is_empty()
        || route.provider_model.trim().is_empty()
        || route.evidence_family.trim().is_empty()
    {
        return Err(ProviderError::Compatibility(
            "Tinfoil live reference values require complete route metadata".into(),
        ));
    }
    Ok(())
}

fn validate_app_e2ee_evidence(
    route: &RouteDefinition,
    canonical_model: &str,
    evidence: &AppE2eeReferenceEvidence,
) -> Result<()> {
    if evidence.provider() != route.provider {
        return Err(ProviderError::Compatibility(format!(
            "app-E2EE evidence provider {} does not match route provider {}",
            evidence.provider(),
            route.provider
        )));
    }
    if evidence.route_id() != route.route_id {
        return Err(ProviderError::Compatibility(format!(
            "app-E2EE evidence route {} does not match route {}",
            evidence.route_id(),
            route.route_id
        )));
    }
    if evidence.evidence_family() != route.evidence_family {
        return Err(ProviderError::Compatibility(format!(
            "app-E2EE evidence family {} does not match route family {}",
            evidence.evidence_family(),
            route.evidence_family
        )));
    }
    let attested_model = evidence.attested_model().ok_or_else(|| {
        ProviderError::Compatibility(
            "app-E2EE evidence did not expose a quote-bound model identity".into(),
        )
    })?;
    if attested_model != canonical_model {
        return Err(ProviderError::Compatibility(format!(
            "app-E2EE evidence model {attested_model} does not match canonical model {canonical_model}"
        )));
    }
    if evidence.tee_measurement().trim().is_empty() {
        return Err(ProviderError::Compatibility(
            "app-E2EE evidence did not expose a TEE measurement".into(),
        ));
    }
    if evidence.workload_image_digest().trim().is_empty() {
        return Err(ProviderError::Compatibility(
            "app-E2EE evidence did not expose workload image provenance".into(),
        ));
    }
    if matches!(evidence, AppE2eeReferenceEvidence::Dstack(_)) {
        if evidence.workload_images().is_empty() {
            return Err(ProviderError::Compatibility(
                "dstack evidence did not expose a complete workload image manifest".into(),
            ));
        }
        if evidence
            .workload_images()
            .iter()
            .any(|image| !image.is_digest_pinned())
        {
            return Err(ProviderError::Compatibility(
                "dstack evidence contains an unpinned workload image".into(),
            ));
        }
    }
    if evidence.model_artifacts().is_empty() {
        return Err(ProviderError::Compatibility(
            "app-E2EE evidence did not expose model artifact provenance".into(),
        ));
    }
    if let Some(gpu) = evidence.hardware().gpu.as_ref() {
        let accepted = route
            .accepted_gpu_tees
            .iter()
            .any(|accepted_gpu| accepted_gpu == gpu);
        if !accepted {
            return Err(ProviderError::Compatibility(
                "app-E2EE evidence GPU TEE is not accepted by the route".into(),
            ));
        }
    }
    Ok(())
}

fn required_for<'a>(context: &str, field: &str, value: &'a str) -> Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ProviderError::Compatibility(format!(
            "{context} require {field}"
        )));
    }
    Ok(value)
}

fn normalize_sha256_hex(value: &str, field: &str) -> Result<String> {
    let value = value.trim();
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(value.to_ascii_lowercase());
    }
    Err(ProviderError::Compatibility(format!(
        "Tinfoil live reference values require {field} as a SHA-256 hex digest"
    )))
}

impl AppE2eeReferenceEvidence {
    fn provider(&self) -> &str {
        match self {
            Self::Dstack(evidence) => &evidence.provider,
            Self::Chutes(evidence) => &evidence.provider,
        }
    }

    fn route_id(&self) -> &str {
        match self {
            Self::Dstack(evidence) => &evidence.route_id,
            Self::Chutes(evidence) => &evidence.route_id,
        }
    }

    fn evidence_family(&self) -> &str {
        match self {
            Self::Dstack(evidence) => &evidence.evidence_family,
            Self::Chutes(evidence) => &evidence.evidence_family,
        }
    }

    fn attested_model(&self) -> Option<&str> {
        match self {
            Self::Dstack(evidence) => evidence.attested_model.as_deref(),
            Self::Chutes(evidence) => evidence.attested_model.as_deref(),
        }
    }

    fn tee_measurement(&self) -> &str {
        match self {
            Self::Dstack(evidence) => &evidence.tee_measurement,
            Self::Chutes(evidence) => &evidence.tee_measurement,
        }
    }

    fn hardware(&self) -> &EvidenceHardware {
        match self {
            Self::Dstack(evidence) => &evidence.hardware,
            Self::Chutes(evidence) => &evidence.hardware,
        }
    }

    fn workload_image_digest(&self) -> &str {
        match self {
            Self::Dstack(evidence) => &evidence.workload_image_digest,
            Self::Chutes(evidence) => &evidence.workload_image_digest,
        }
    }

    fn workload_images(&self) -> &[confidential_inference_attestation::WorkloadImage] {
        match self {
            Self::Dstack(evidence) => &evidence.workload_images,
            Self::Chutes(_) => &[],
        }
    }

    fn model_artifacts(&self) -> &[confidential_inference_attestation::ArtifactDigest] {
        match self {
            Self::Dstack(evidence) => &evidence.model_artifacts,
            Self::Chutes(evidence) => &evidence.model_artifacts,
        }
    }

    fn expires_at(&self) -> &str {
        match self {
            Self::Dstack(evidence) => &evidence.expires_at,
            Self::Chutes(evidence) => &evidence.expires_at,
        }
    }

    fn expires_at_epoch_ms(&self) -> u64 {
        match self {
            Self::Dstack(evidence) => evidence.expires_at_epoch_ms,
            Self::Chutes(evidence) => evidence.expires_at_epoch_ms,
        }
    }

    fn e2ee_public_key_digest(&self) -> Result<String> {
        match self {
            Self::Dstack(evidence) => {
                if evidence.channel_binding.kind != ChannelBindingKind::AttestedAppE2ee {
                    return Err(ProviderError::Compatibility(
                        "dstack evidence channel binding is not app-E2EE".into(),
                    ));
                }
                if evidence.channel_binding.public_key_digest.trim().is_empty() {
                    return Err(ProviderError::Compatibility(
                        "dstack evidence did not expose an app-E2EE public key digest".into(),
                    ));
                }
                Ok(evidence.channel_binding.public_key_digest.clone())
            }
            Self::Chutes(evidence) => {
                if evidence.e2e_public_key.trim().is_empty() {
                    return Err(ProviderError::Compatibility(
                        "Chutes evidence did not expose an app-E2EE public key".into(),
                    ));
                }
                let binding = verify_chutes_e2ee_report_data_binding(
                    &evidence.report_data,
                    &evidence.nonce,
                    &evidence.e2e_public_key,
                );
                if binding != ChutesE2eeReportDataBinding::Verified {
                    return Err(ProviderError::Compatibility(
                        "Chutes evidence report_data is not bound to the app-E2EE key".into(),
                    ));
                }
                Ok(sha256_digest(evidence.e2e_public_key.as_bytes()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptionRequirement, RouteLifecycle, StreamingSupport};
    use base64::Engine;
    use confidential_inference_attestation::{
        canonical_json, AliasConfidence, ArtifactDigest, ArtifactSignature, BoundDataRequirement,
        CpuTeeKind, EvidenceHardware, FreshnessClass, ReferenceValuesEnvelope,
        ResponseIntegrityRequirement, TrustedSigningKey, TINFOIL_TDX_GUEST_V2_FORMAT,
    };
    use ed25519_compact::{KeyPair, Seed};
    use serde::Deserialize;

    const ROUTE_ID: &str = "tinfoil-live:llama-3.3-70b:llama-3.3-70b";
    const SPKI: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_SIGNER: &str = "confidential-inference-live-reference-corpus";
    const TEST_KEY_ID: &str = "tinfoil-live-reference-corpus-ed25519";

    #[derive(Debug, Deserialize)]
    struct TinfoilLiveReferenceCorpus {
        schema: String,
        cases: Vec<TinfoilLiveReferenceCorpusCase>,
    }

    #[derive(Debug, Deserialize)]
    struct TinfoilLiveReferenceCorpusCase {
        id: String,
        version: String,
        issuer: String,
        valid_from: String,
        revocation_epoch: u64,
        minimum_acceptable_version: String,
        canonical_model: String,
        route: RouteDefinition,
        verified_quote: VerifiedTinfoilQuote,
        live_tls_spki_sha256: String,
        expected: Option<ExpectedTinfoilLiveReferenceValues>,
        expected_error_contains: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct ExpectedTinfoilLiveReferenceValues {
        provider: String,
        route_id: String,
        reference_values_version: String,
        accepted_measurement: String,
        accepted_cpu_tee: CpuTeeKind,
        tls_spki_sha256: String,
        workload_image_digest: String,
        model_artifact_count: usize,
    }

    impl TinfoilLiveReferenceCorpusCase {
        fn input(&self) -> TinfoilLiveReferenceValuesInput {
            TinfoilLiveReferenceValuesInput {
                version: self.version.clone(),
                issuer: self.issuer.clone(),
                valid_from: self.valid_from.clone(),
                revocation_epoch: self.revocation_epoch,
                minimum_acceptable_version: self.minimum_acceptable_version.clone(),
                canonical_model: self.canonical_model.clone(),
                route: self.route.clone(),
                verified_quote: self.verified_quote.clone(),
                live_tls_spki_sha256: self.live_tls_spki_sha256.clone(),
            }
        }
    }

    #[test]
    fn tinfoil_live_reference_values_bind_verified_quote_to_route() {
        let payload = generate_tinfoil_live_reference_values(input()).unwrap();

        assert_eq!(payload.schema, ReferenceValuesPayload::SCHEMA);
        assert_eq!(payload.valid_until, "2099-01-01T00:00:00Z");
        let provider = payload.providers.get("tinfoil-live").unwrap();
        assert_eq!(
            provider.accepted_measurements,
            vec!["tdx:mr_td:live-measurement"]
        );
        let route = provider.routes.get(ROUTE_ID).unwrap();
        assert_eq!(route.canonical_model, "llama-3.3-70b");
        assert_eq!(route.provider_model, "llama-3.3-70b");
        assert_eq!(route.accepted_cpu_tees, vec![CpuTeeKind::Tdx]);
        let expected_spki = format!("sha256:{SPKI}");
        assert_eq!(
            route.tls_spki_sha256.as_deref(),
            Some(expected_spki.as_str())
        );
        assert_eq!(route.workload_image_digest, "sha256:workload");
        assert_eq!(route.model_artifacts.len(), 1);
    }

    #[test]
    fn tinfoil_live_reference_values_reject_model_mismatch() {
        let mut input = input();
        input.verified_quote.attested_model = Some("wrong-model".into());

        let error = generate_tinfoil_live_reference_values(input)
            .unwrap_err()
            .to_string();

        assert!(error.contains("does not match canonical model"));
    }

    #[test]
    fn tinfoil_live_reference_values_reject_unbound_tls_spki() {
        let mut input = input();
        input.verified_quote.report_data = format!("{}{}", "bb".repeat(32), "00".repeat(32));

        let error = generate_tinfoil_live_reference_values(input)
            .unwrap_err()
            .to_string();

        assert!(error.contains("not bound to the live TLS SPKI"));
    }

    #[test]
    fn tinfoil_live_reference_values_reject_missing_provenance() {
        let mut input = input();
        input.verified_quote.model_artifacts.clear();

        let error = generate_tinfoil_live_reference_values(input)
            .unwrap_err()
            .to_string();

        assert!(error.contains("model artifact provenance"));
    }

    #[test]
    fn tinfoil_live_reference_values_reject_wrong_route_trust_tier() {
        let mut input = input();
        input.route.trust_tier = TrustTier::AppE2ee;

        let error = generate_tinfoil_live_reference_values(input)
            .unwrap_err()
            .to_string();

        assert!(error.contains("hardware-verified TLS trust tier"));
    }

    #[test]
    fn tinfoil_live_reference_corpus_generates_signed_bundles_and_failures() {
        let corpus: TinfoilLiveReferenceCorpus = serde_json::from_str(include_str!(
            "../../../fixtures/providers/tinfoil-live-reference-corpus.json"
        ))
        .unwrap();
        assert_eq!(
            corpus.schema,
            "confidential-inference.tinfoil-live-reference-corpus.v1"
        );
        let trusted_key = tinfoil_live_reference_trusted_key();

        for case in corpus.cases {
            let result = generate_tinfoil_live_reference_values(case.input());
            match (
                case.expected.as_ref(),
                case.expected_error_contains.as_deref(),
                result,
            ) {
                (Some(expected), None, Ok(payload)) => {
                    assert_eq!(
                        payload.version, expected.reference_values_version,
                        "{}: version",
                        case.id
                    );
                    let provider = payload
                        .providers
                        .get(&expected.provider)
                        .unwrap_or_else(|| panic!("{}: missing expected provider", case.id));
                    assert_eq!(
                        provider.accepted_measurements,
                        vec![expected.accepted_measurement.clone()],
                        "{}: accepted measurements",
                        case.id
                    );
                    let route = provider
                        .routes
                        .get(&expected.route_id)
                        .unwrap_or_else(|| panic!("{}: missing expected route", case.id));
                    assert_eq!(
                        route.accepted_cpu_tees,
                        vec![expected.accepted_cpu_tee.clone()],
                        "{}: accepted CPU TEE",
                        case.id
                    );
                    assert_eq!(
                        route.tls_spki_sha256.as_deref(),
                        Some(expected.tls_spki_sha256.as_str()),
                        "{}: TLS SPKI",
                        case.id
                    );
                    assert_eq!(
                        route.workload_image_digest, expected.workload_image_digest,
                        "{}: workload image",
                        case.id
                    );
                    assert_eq!(
                        route.model_artifacts.len(),
                        expected.model_artifact_count,
                        "{}: model artifacts",
                        case.id
                    );

                    let envelope = signed_tinfoil_live_reference_envelope(payload);
                    envelope
                        .verify_signature_with_keys(std::slice::from_ref(&trusted_key))
                        .unwrap_or_else(|error| {
                            panic!("{}: signed reference bundle failed: {error}", case.id)
                        });
                    let verified = envelope
                        .clone()
                        .into_verified_payload_with_keys(std::slice::from_ref(&trusted_key))
                        .unwrap();
                    assert_eq!(
                        verified.digest().unwrap(),
                        envelope.payload.digest().unwrap()
                    );

                    let mut tampered = envelope;
                    tampered.payload.version.push_str("-tampered");
                    assert!(
                        tampered
                            .verify_signature_with_keys(std::slice::from_ref(&trusted_key))
                            .is_err(),
                        "{}: tampered signed reference bundle verified",
                        case.id
                    );
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
                    panic!("{}: expected live reference success, got {error}", case.id);
                }
                (None, Some(_), Ok(payload)) => {
                    panic!(
                        "{}: expected live reference failure, got {:?}",
                        case.id, payload
                    );
                }
                _ => panic!(
                    "{}: corpus case must define exactly one expected outcome",
                    case.id
                ),
            }
        }
    }

    fn input() -> TinfoilLiveReferenceValuesInput {
        TinfoilLiveReferenceValuesInput {
            version: "2026-07-05-live-tinfoil".into(),
            issuer: "confidential-inference-live-sync".into(),
            valid_from: "2026-07-05T00:00:00Z".into(),
            revocation_epoch: 1,
            minimum_acceptable_version: "2026-07-05-live-tinfoil".into(),
            canonical_model: "llama-3.3-70b".into(),
            route: route(),
            verified_quote: verified_quote(),
            live_tls_spki_sha256: format!("sha256:{SPKI}"),
        }
    }

    fn route() -> RouteDefinition {
        RouteDefinition {
            route_id: ROUTE_ID.into(),
            route_status: RouteLifecycle::Active,
            provider: "tinfoil-live".into(),
            provider_model: "llama-3.3-70b".into(),
            evidence_family: "tinfoil_hw_verified_tls".into(),
            api_base_url: "https://inference.tinfoil.sh/v1".into(),
            evidence_endpoint: "https://inference.tinfoil.sh/.well-known/tinfoil-attestation"
                .into(),
            adapter_version: "tinfoil-live-test/0.1.0".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::TeeTerminatedTls,
            trust_tier: TrustTier::HwVerifiedTls,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::ChannelBound,
            accepted_gpu_tees: Vec::new(),
            request_encryption: EncryptionRequirement::NotRequired,
            response_decryption: EncryptionRequirement::NotRequired,
            streaming: StreamingSupport::Unsupported,
            alias_confidence: AliasConfidence::Curated,
        }
    }

    fn verified_quote() -> VerifiedTinfoilQuote {
        let mut quote = VerifiedTinfoilQuote {
            attestation_format: TINFOIL_TDX_GUEST_V2_FORMAT.into(),
            hardware: EvidenceHardware {
                cpu: CpuTeeKind::Tdx,
                gpu: None,
            },
            tee_measurement: "tdx:mr_td:live-measurement".into(),
            report_data: format!("{SPKI}{}", "00".repeat(32)),
            issued_at: "2098-12-31T23:50:00Z".into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            expires_at_epoch_ms: 4_070_908_800_000,
            attested_model: Some("llama-3.3-70b".into()),
            workload_image_digest: Some("sha256:workload".into()),
            model_artifacts: Vec::new(),
        };
        quote.model_artifacts.push(ArtifactDigest {
            kind: "weights".into(),
            name: "llama-3.3-70b".into(),
            digest: "sha256:weights".into(),
        });
        quote
    }

    fn signed_tinfoil_live_reference_envelope(
        payload: ReferenceValuesPayload,
    ) -> ReferenceValuesEnvelope {
        ReferenceValuesEnvelope {
            schema: ReferenceValuesEnvelope::SCHEMA.into(),
            signature: tinfoil_live_reference_signature(&payload),
            payload,
        }
    }

    fn tinfoil_live_reference_signature(payload: &ReferenceValuesPayload) -> ArtifactSignature {
        let key_pair = tinfoil_live_reference_key_pair();
        let payload_json = canonical_json(payload).unwrap();
        let signature = key_pair.sk.sign(payload_json.as_bytes(), None);
        ArtifactSignature {
            signer: TEST_SIGNER.into(),
            key_id: TEST_KEY_ID.into(),
            alg: "ed25519".into(),
            value: format!(
                "base64url:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref())
            ),
        }
    }

    fn tinfoil_live_reference_trusted_key() -> TrustedSigningKey {
        let key_pair = tinfoil_live_reference_key_pair();
        TrustedSigningKey {
            signer: TEST_SIGNER.into(),
            key_id: TEST_KEY_ID.into(),
            public_key_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(key_pair.pk.as_ref()),
        }
    }

    fn tinfoil_live_reference_key_pair() -> KeyPair {
        KeyPair::from_seed(Seed::new([41_u8; 32]))
    }
}
