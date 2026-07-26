use crate::{
    chutes::normalize_chutes_e2ee_evidence_bytes, dstack::normalize_dstack_evidence_bytes,
    generate_app_e2ee_reference_values, AppE2eeReferenceEvidence, AppE2eeReferenceValuesInput,
    EncryptionRequirement, EvidenceRequest, RouteDefinition, RouteLifecycle, StreamingSupport,
};
use base64::Engine;
use confidential_inference_attestation::{
    canonical_json, sha256_digest, verify_evidence, AliasConfidence, ArtifactDigest,
    ArtifactSignature, AttestationVerdict, BoundDataRequirement, ChannelBindingKind, CheckResult,
    ChutesE2eeEvidence, CpuTeeKind, DstackEvidence, FreshnessClass, GpuTeeKind, ProviderReference,
    ReferenceValuesEnvelope, ReferenceValuesPayload, ResponseIntegrityRequirement,
    ResponseIntegrityResult, RouteReference, SignatureMetadata, TrustTier, TrustedSigningKey,
    VerificationPolicy, VerificationRequest, VerificationStatus,
};
use ed25519_compact::{KeyPair, Seed};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
struct ProviderEvidenceNormalizerCorpus {
    schema: String,
    cases: Vec<ProviderEvidenceNormalizerCase>,
}

#[derive(Debug, Deserialize)]
struct ProviderEvidenceNormalizerCase {
    id: String,
    evidence_family: String,
    provider: String,
    route_id: String,
    provider_model: String,
    requested_model: String,
    raw_payload: Value,
    expected: Option<ExpectedNormalizedEvidence>,
    expected_error_contains: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExpectedNormalizedEvidence {
    schema: String,
    attested_model: String,
    tee_measurement: String,
    #[serde(default)]
    public_key_digest: Option<String>,
    workload_image_digest: String,
    model_artifact_count: usize,
    #[serde(default)]
    gpu_arch: Option<String>,
    #[serde(default)]
    nras_token: Option<String>,
}

struct ActualCommonFields<'a> {
    provider: &'a str,
    route_id: &'a str,
    evidence_family: &'a str,
    attested_model: Option<&'a str>,
    tee_measurement: &'a str,
    workload_image_digest: &'a str,
    model_artifact_count: usize,
}

const APP_E2EE_TEST_SIGNER: &str = "confidential-inference-provider-app-e2ee-reference-corpus";
const APP_E2EE_TEST_KEY_ID: &str = "provider-app-e2ee-reference-corpus-ed25519";

#[test]
fn provider_evidence_normalizer_corpus_matches_expected_outcomes() {
    let corpus: ProviderEvidenceNormalizerCorpus = serde_json::from_str(include_str!(
        "../../../fixtures/providers/evidence-normalizer-corpus.json"
    ))
    .unwrap();
    assert_eq!(
        corpus.schema,
        "confidential-inference.provider-evidence-normalizer-corpus.v1"
    );

    for case in corpus.cases {
        let route = route_for_case(&case);
        let request = EvidenceRequest {
            requested_model: case.requested_model.clone(),
            policy_digest: "sha256:provider-normalizer-corpus".into(),
            nonce: None,
        };
        let raw = serde_json::to_vec(&case.raw_payload).unwrap();
        let result = match case.evidence_family.as_str() {
            "dstack_app_e2ee" => normalize_dstack_evidence_bytes(&route, &request, &raw),
            "chutes_e2ee" => normalize_chutes_e2ee_evidence_bytes(&route, &request, &raw),
            other => panic!("{}: unsupported evidence family {other}", case.id),
        };

        match (&case.expected, &case.expected_error_contains, result) {
            (Some(expected), None, Ok(normalized)) => {
                assert_normalized_evidence(&case, expected, &normalized);
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
                panic!("{}: expected normalization success, got {error}", case.id);
            }
            (None, Some(_), Ok(normalized)) => {
                panic!(
                    "{}: expected normalization failure, got {}",
                    case.id,
                    String::from_utf8_lossy(&normalized)
                );
            }
            _ => panic!(
                "{}: corpus case must define exactly one expected outcome",
                case.id
            ),
        }
    }
}

#[test]
fn provider_evidence_normalizer_corpus_verifies_normalized_evidence() {
    let corpus: ProviderEvidenceNormalizerCorpus = serde_json::from_str(include_str!(
        "../../../fixtures/providers/evidence-normalizer-corpus.json"
    ))
    .unwrap();

    for case in corpus
        .cases
        .into_iter()
        .filter(|case| case.expected.is_some())
    {
        let route = route_for_case(&case);
        let normalized = normalize_case(&case, &route).unwrap();
        let evidence = normalized_evidence_for_case(&case, &normalized);
        let request = verification_request_for_case(&case, &route, &normalized, &evidence, None);

        let verdict = verify_evidence(request).unwrap();

        if case.evidence_family == "dstack_app_e2ee" {
            assert_eq!(
                verdict.status,
                VerificationStatus::Failed,
                "{}: verifier status",
                case.id
            );
            assert!(!verdict.request_allowed, "{}: request allowed", case.id);
            assert_eq!(
                verdict.response_integrity_result,
                ResponseIntegrityResult::Unknown,
                "{}: response integrity",
                case.id
            );
            assert_eq!(
                verdict.check("e2ee_key_reference_match"),
                Some(&CheckResult::Verified),
                "{}: key reference match",
                case.id
            );
            assert_eq!(
                verdict.check("e2ee_key_binding"),
                Some(&CheckResult::NotSupported),
                "{}: request key binding",
                case.id
            );
        } else {
            assert_eq!(
                verdict.status,
                VerificationStatus::Verified,
                "{}: verifier status",
                case.id
            );
            assert!(verdict.request_allowed, "{}: request allowed", case.id);
            assert_eq!(
                verdict.response_integrity_result,
                ResponseIntegrityResult::ChannelBound,
                "{}: response integrity",
                case.id
            );
            assert!(
                verdict.errors.is_empty(),
                "{}: expected no verifier errors, got {:?}",
                case.id,
                verdict.errors
            );
        }

        let failed = verify_evidence(verification_request_for_case(
            &case,
            &route,
            &normalized,
            &evidence,
            Some(ReferenceMutation::WrongE2eeKey),
        ))
        .unwrap();
        assert_failed_check(
            &case,
            &failed,
            if case.evidence_family == "dstack_app_e2ee" {
                "e2ee_key_reference_match"
            } else {
                "e2ee_key_binding"
            },
        );

        let failed = verify_evidence(verification_request_for_case(
            &case,
            &route,
            &normalized,
            &evidence,
            Some(ReferenceMutation::WrongMeasurement),
        ))
        .unwrap();
        assert_failed_check(&case, &failed, "cpu_tee");
    }
}

#[test]
fn provider_evidence_normalizer_corpus_generates_signed_app_e2ee_reference_values() {
    let corpus: ProviderEvidenceNormalizerCorpus = serde_json::from_str(include_str!(
        "../../../fixtures/providers/evidence-normalizer-corpus.json"
    ))
    .unwrap();
    let trusted_key = app_e2ee_reference_trusted_key();

    for case in corpus
        .cases
        .into_iter()
        .filter(|case| case.expected.is_some())
    {
        let route = route_for_case(&case);
        let normalized = normalize_case(&case, &route).unwrap();
        let evidence = normalized_evidence_for_case(&case, &normalized);
        let payload =
            generate_app_e2ee_reference_values(app_e2ee_reference_input(&case, &route, &evidence))
                .unwrap_or_else(|error| {
                    panic!(
                        "{}: expected generated app-E2EE reference values: {error}",
                        case.id
                    )
                });

        assert_eq!(
            payload.version,
            format!("2026-07-05-provider-app-e2ee-{}", case.id),
            "{}: generated reference version",
            case.id
        );
        assert_eq!(
            payload.valid_until,
            evidence.expires_at(),
            "{}: generated reference validity",
            case.id
        );
        assert_eq!(
            payload.valid_until_epoch_ms,
            evidence.expires_at_epoch_ms(),
            "{}: generated reference epoch",
            case.id
        );
        let provider = payload
            .providers
            .get(&case.provider)
            .unwrap_or_else(|| panic!("{}: missing generated provider", case.id));
        assert_eq!(
            provider.accepted_measurements,
            vec![evidence.tee_measurement().to_owned()],
            "{}: generated accepted measurements",
            case.id
        );
        let route_reference = provider
            .routes
            .get(&case.route_id)
            .unwrap_or_else(|| panic!("{}: missing generated route reference", case.id));
        assert_eq!(
            route_reference.canonical_model, case.requested_model,
            "{}: generated canonical model",
            case.id
        );
        assert_eq!(
            route_reference.provider_model, case.provider_model,
            "{}: generated provider model",
            case.id
        );
        assert_eq!(
            route_reference.evidence_family, case.evidence_family,
            "{}: generated evidence family",
            case.id
        );
        assert_eq!(
            route_reference.channel_binding_kind,
            ChannelBindingKind::AttestedAppE2ee,
            "{}: generated channel binding kind",
            case.id
        );
        assert_eq!(
            route_reference.trust_tier,
            TrustTier::AppE2ee,
            "{}: generated trust tier",
            case.id
        );
        assert_eq!(
            route_reference.e2ee_public_key_digest,
            evidence.public_key_digest(),
            "{}: generated app-E2EE key digest",
            case.id
        );
        assert_eq!(
            route_reference.workload_image_digest,
            evidence.workload_image_digest(),
            "{}: generated workload image",
            case.id
        );
        assert_eq!(
            route_reference.model_artifacts,
            evidence.model_artifacts(),
            "{}: generated model artifacts",
            case.id
        );

        let envelope = signed_app_e2ee_reference_envelope(payload.clone());
        envelope
            .verify_signature_with_keys(std::slice::from_ref(&trusted_key))
            .unwrap_or_else(|error| {
                panic!(
                    "{}: signed app-E2EE reference bundle failed: {error}",
                    case.id
                )
            });
        let verified = envelope
            .clone()
            .into_verified_payload_with_keys(std::slice::from_ref(&trusted_key))
            .unwrap();
        assert_eq!(
            verified.digest().unwrap(),
            envelope.payload.digest().unwrap()
        );

        let verdict = verify_evidence(verification_request_from_reference_values_for_case(
            &case,
            &route,
            &normalized,
            payload,
        ))
        .unwrap();
        assert_eq!(
            verdict.status,
            if case.evidence_family == "dstack_app_e2ee" {
                VerificationStatus::Failed
            } else {
                VerificationStatus::Verified
            },
            "{}: generated reference verifier status",
            case.id
        );

        let mut tampered = envelope;
        tampered
            .payload
            .providers
            .get_mut(&case.provider)
            .unwrap()
            .routes
            .get_mut(&case.route_id)
            .unwrap()
            .e2ee_public_key_digest = "sha256:tampered-provider-e2ee-key".into();
        assert!(
            tampered
                .verify_signature_with_keys(std::slice::from_ref(&trusted_key))
                .is_err(),
            "{}: tampered signed app-E2EE reference bundle verified",
            case.id
        );

        let mut mismatch_input = app_e2ee_reference_input(&case, &route, &evidence);
        mismatch_input.canonical_model = "wrong-model".into();
        let error = generate_app_e2ee_reference_values(mismatch_input)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("does not match canonical model"),
            "{}: model mismatch error was {error:?}",
            case.id
        );

        let mut wrong_tier_input = app_e2ee_reference_input(&case, &route, &evidence);
        wrong_tier_input.route.trust_tier = TrustTier::HwVerifiedTls;
        let error = generate_app_e2ee_reference_values(wrong_tier_input)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("app-E2EE trust tier"),
            "{}: trust tier error was {error:?}",
            case.id
        );
    }
}

fn assert_normalized_evidence(
    case: &ProviderEvidenceNormalizerCase,
    expected: &ExpectedNormalizedEvidence,
    normalized: &[u8],
) {
    match case.evidence_family.as_str() {
        "dstack_app_e2ee" => {
            let evidence: DstackEvidence = serde_json::from_slice(normalized).unwrap();
            assert_eq!(evidence.schema, expected.schema, "{}: schema", case.id);
            assert_common_fields(
                case,
                expected,
                ActualCommonFields {
                    provider: &evidence.provider,
                    route_id: &evidence.route_id,
                    evidence_family: &evidence.evidence_family,
                    attested_model: evidence.attested_model.as_deref(),
                    tee_measurement: &evidence.tee_measurement,
                    workload_image_digest: &evidence.workload_image_digest,
                    model_artifact_count: evidence.model_artifacts.len(),
                },
            );
            assert_eq!(
                Some(evidence.channel_binding.public_key_digest.as_str()),
                expected.public_key_digest.as_deref(),
                "{}: public key digest",
                case.id
            );
        }
        "chutes_e2ee" => {
            let evidence: ChutesE2eeEvidence = serde_json::from_slice(normalized).unwrap();
            assert_eq!(evidence.schema, expected.schema, "{}: schema", case.id);
            assert_common_fields(
                case,
                expected,
                ActualCommonFields {
                    provider: &evidence.provider,
                    route_id: &evidence.route_id,
                    evidence_family: &evidence.evidence_family,
                    attested_model: evidence.attested_model.as_deref(),
                    tee_measurement: &evidence.tee_measurement,
                    workload_image_digest: &evidence.workload_image_digest,
                    model_artifact_count: evidence.model_artifacts.len(),
                },
            );
            let gpu_attestation = evidence.gpu_attestation.as_ref();
            assert_eq!(
                gpu_attestation.and_then(|gpu| gpu.arch.as_deref()),
                expected.gpu_arch.as_deref(),
                "{}: GPU architecture",
                case.id
            );
            assert_eq!(
                gpu_attestation.and_then(|gpu| gpu.nras_token.as_deref()),
                expected.nras_token.as_deref(),
                "{}: NRAS token",
                case.id
            );
        }
        other => panic!("{}: unsupported evidence family {other}", case.id),
    }
}

fn assert_common_fields(
    case: &ProviderEvidenceNormalizerCase,
    expected: &ExpectedNormalizedEvidence,
    actual: ActualCommonFields<'_>,
) {
    assert_eq!(actual.provider, case.provider, "{}: provider", case.id);
    assert_eq!(actual.route_id, case.route_id, "{}: route id", case.id);
    assert_eq!(
        actual.evidence_family, case.evidence_family,
        "{}: evidence family",
        case.id
    );
    assert_eq!(
        actual.attested_model,
        Some(expected.attested_model.as_str()),
        "{}: attested model",
        case.id
    );
    assert_eq!(
        actual.tee_measurement, expected.tee_measurement,
        "{}: TEE measurement",
        case.id
    );
    assert_eq!(
        actual.workload_image_digest, expected.workload_image_digest,
        "{}: workload image",
        case.id
    );
    assert_eq!(
        actual.model_artifact_count, expected.model_artifact_count,
        "{}: model artifact count",
        case.id
    );
}

fn normalize_case(
    case: &ProviderEvidenceNormalizerCase,
    route: &RouteDefinition,
) -> crate::Result<Vec<u8>> {
    let request = EvidenceRequest {
        requested_model: case.requested_model.clone(),
        policy_digest: "sha256:provider-normalizer-corpus".into(),
        nonce: None,
    };
    let raw = serde_json::to_vec(&case.raw_payload).unwrap();
    match case.evidence_family.as_str() {
        "dstack_app_e2ee" => normalize_dstack_evidence_bytes(route, &request, &raw),
        "chutes_e2ee" => normalize_chutes_e2ee_evidence_bytes(route, &request, &raw),
        other => panic!("{}: unsupported evidence family {other}", case.id),
    }
}

fn route_for_case(case: &ProviderEvidenceNormalizerCase) -> RouteDefinition {
    RouteDefinition {
        route_id: case.route_id.clone(),
        route_status: RouteLifecycle::Active,
        provider: case.provider.clone(),
        provider_model: case.provider_model.clone(),
        evidence_family: case.evidence_family.clone(),
        api_base_url: "http://127.0.0.1/v1".into(),
        evidence_endpoint: "http://127.0.0.1/v1/confidentiality".into(),
        adapter_version: "provider-evidence-corpus/0.1.0".into(),
        freshness_class: FreshnessClass::PerSession,
        channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
        trust_tier: TrustTier::AppE2ee,
        request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
        accepted_gpu_tees: if case.evidence_family == "chutes_e2ee" {
            vec![GpuTeeKind::NvidiaCc]
        } else {
            Vec::new()
        },
        request_encryption: EncryptionRequirement::Required,
        response_decryption: EncryptionRequirement::Required,
        streaming: StreamingSupport::Unsupported,
        alias_confidence: AliasConfidence::Curated,
    }
}

#[derive(Clone)]
enum NormalizedProviderEvidence {
    Dstack(DstackEvidence),
    Chutes(ChutesE2eeEvidence),
}

impl NormalizedProviderEvidence {
    fn tee_measurement(&self) -> &str {
        match self {
            Self::Dstack(evidence) => &evidence.tee_measurement,
            Self::Chutes(evidence) => &evidence.tee_measurement,
        }
    }

    fn public_key_digest(&self) -> String {
        match self {
            Self::Dstack(evidence) => evidence.channel_binding.public_key_digest.clone(),
            Self::Chutes(evidence) => sha256_digest(evidence.e2e_public_key.as_bytes()),
        }
    }

    fn workload_image_digest(&self) -> &str {
        match self {
            Self::Dstack(evidence) => &evidence.workload_image_digest,
            Self::Chutes(evidence) => &evidence.workload_image_digest,
        }
    }

    fn workload_images(&self) -> Vec<confidential_inference_attestation::WorkloadImage> {
        match self {
            Self::Dstack(evidence) => evidence.workload_images.clone(),
            Self::Chutes(_) => Vec::new(),
        }
    }

    fn model_artifacts(&self) -> Vec<ArtifactDigest> {
        match self {
            Self::Dstack(evidence) => evidence.model_artifacts.clone(),
            Self::Chutes(evidence) => evidence.model_artifacts.clone(),
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

    fn app_reference_evidence(&self) -> AppE2eeReferenceEvidence {
        match self {
            Self::Dstack(evidence) => AppE2eeReferenceEvidence::Dstack(evidence.clone()),
            Self::Chutes(evidence) => AppE2eeReferenceEvidence::Chutes(evidence.clone()),
        }
    }
}

#[derive(Clone, Copy)]
enum ReferenceMutation {
    WrongE2eeKey,
    WrongMeasurement,
}

fn normalized_evidence_for_case(
    case: &ProviderEvidenceNormalizerCase,
    normalized: &[u8],
) -> NormalizedProviderEvidence {
    match case.evidence_family.as_str() {
        "dstack_app_e2ee" => {
            NormalizedProviderEvidence::Dstack(serde_json::from_slice(normalized).unwrap())
        }
        "chutes_e2ee" => {
            NormalizedProviderEvidence::Chutes(serde_json::from_slice(normalized).unwrap())
        }
        other => panic!("{}: unsupported evidence family {other}", case.id),
    }
}

fn verification_request_for_case(
    case: &ProviderEvidenceNormalizerCase,
    route: &RouteDefinition,
    normalized: &[u8],
    evidence: &NormalizedProviderEvidence,
    mutation: Option<ReferenceMutation>,
) -> VerificationRequest {
    let mut accepted_measurement = evidence.tee_measurement().to_owned();
    let mut e2ee_public_key_digest = evidence.public_key_digest();
    match mutation {
        Some(ReferenceMutation::WrongE2eeKey) => {
            e2ee_public_key_digest = "sha256:wrong-provider-e2ee-key".into();
        }
        Some(ReferenceMutation::WrongMeasurement) => {
            accepted_measurement = "sha256:wrong-provider-tee-measurement".into();
        }
        None => {}
    }

    let attested_route = route.to_attested_route(&case.requested_model, &case.requested_model);
    let route_reference = RouteReference {
        canonical_model: case.requested_model.clone(),
        provider_model: case.provider_model.clone(),
        evidence_family: case.evidence_family.clone(),
        channel_binding_kind: route.channel_binding_kind.clone(),
        trust_tier: route.trust_tier.clone(),
        accepted_cpu_tees: vec![CpuTeeKind::Tdx],
        e2ee_public_key_digest,
        response_signing_key_digest: None,
        tls_spki_sha256: None,
        workload_images: evidence.workload_images(),
        workload_image_digest: evidence.workload_image_digest().to_owned(),
        model_artifacts: evidence.model_artifacts(),
        valid_until: "2099-01-01T00:00:00Z".into(),
        valid_until_epoch_ms: 4_070_908_800_000,
    };
    let reference_values = ReferenceValuesPayload {
        schema: ReferenceValuesPayload::SCHEMA.into(),
        version: format!("2026-07-05-provider-corpus-{}", case.id),
        issuer: "confidential-inference-provider-corpus".into(),
        valid_from: "2026-07-05T00:00:00Z".into(),
        valid_until: "2099-01-01T00:00:00Z".into(),
        valid_until_epoch_ms: 4_070_908_800_000,
        revocation_epoch: 1,
        minimum_acceptable_version: "2026-07-05-provider-corpus".into(),
        providers: BTreeMap::from([(
            case.provider.clone(),
            ProviderReference {
                accepted_measurements: vec![accepted_measurement],
                routes: BTreeMap::from([(case.route_id.clone(), route_reference)]),
            },
        )]),
    };
    let reference_values_digest = reference_values.digest().unwrap();
    let registry_digest = sha256_digest(format!("provider-corpus-registry-{}", case.id).as_bytes());

    VerificationRequest {
        route: attested_route,
        route_execution_status: "provider_corpus".into(),
        chat_executable: true,
        known_unsupported_modes: Vec::new(),
        expected_freshness_nonce: None,
        policy: VerificationPolicy::require_attested_e2ee()
            .with_artifact_digests(registry_digest.clone(), reference_values_digest.clone()),
        reference_values,
        reference_signature: SignatureMetadata {
            signer: "confidential-inference-provider-corpus".into(),
            key_id: "test".into(),
            alg: "ed25519".into(),
        },
        reference_values_digest,
        reference_values_source: "provider-corpus".into(),
        registry_digest,
        registry_version: "2026-07-05-provider-corpus".into(),
        registry_source: "test".into(),
        registry_sync_completed_at: "2026-07-05T00:00:00Z".into(),
        registry_signature: SignatureMetadata {
            signer: "confidential-inference-provider-corpus".into(),
            key_id: "test".into(),
            alg: "ed25519".into(),
        },
        raw_evidence: normalized.to_vec(),
    }
}

fn app_e2ee_reference_input(
    case: &ProviderEvidenceNormalizerCase,
    route: &RouteDefinition,
    evidence: &NormalizedProviderEvidence,
) -> AppE2eeReferenceValuesInput {
    AppE2eeReferenceValuesInput {
        version: format!("2026-07-05-provider-app-e2ee-{}", case.id),
        issuer: "confidential-inference-provider-corpus".into(),
        valid_from: "2026-07-05T00:00:00Z".into(),
        revocation_epoch: 1,
        minimum_acceptable_version: "2026-07-05-provider-app-e2ee".into(),
        canonical_model: case.requested_model.clone(),
        route: route.clone(),
        evidence: evidence.app_reference_evidence(),
    }
}

fn verification_request_from_reference_values_for_case(
    case: &ProviderEvidenceNormalizerCase,
    route: &RouteDefinition,
    normalized: &[u8],
    reference_values: ReferenceValuesPayload,
) -> VerificationRequest {
    let attested_route = route.to_attested_route(&case.requested_model, &case.requested_model);
    let reference_values_digest = reference_values.digest().unwrap();
    let registry_digest =
        sha256_digest(format!("provider-app-e2ee-reference-registry-{}", case.id).as_bytes());

    VerificationRequest {
        route: attested_route,
        route_execution_status: "provider_corpus".into(),
        chat_executable: true,
        known_unsupported_modes: Vec::new(),
        expected_freshness_nonce: None,
        policy: VerificationPolicy::require_attested_e2ee()
            .with_artifact_digests(registry_digest.clone(), reference_values_digest.clone()),
        reference_values,
        reference_signature: SignatureMetadata {
            signer: APP_E2EE_TEST_SIGNER.into(),
            key_id: APP_E2EE_TEST_KEY_ID.into(),
            alg: "ed25519".into(),
        },
        reference_values_digest,
        reference_values_source: "provider-corpus".into(),
        registry_digest,
        registry_version: "2026-07-05-provider-app-e2ee".into(),
        registry_source: "test".into(),
        registry_sync_completed_at: "2026-07-05T00:00:00Z".into(),
        registry_signature: SignatureMetadata {
            signer: APP_E2EE_TEST_SIGNER.into(),
            key_id: APP_E2EE_TEST_KEY_ID.into(),
            alg: "ed25519".into(),
        },
        raw_evidence: normalized.to_vec(),
    }
}

fn signed_app_e2ee_reference_envelope(payload: ReferenceValuesPayload) -> ReferenceValuesEnvelope {
    ReferenceValuesEnvelope {
        schema: ReferenceValuesEnvelope::SCHEMA.into(),
        signature: app_e2ee_reference_signature(&payload),
        payload,
    }
}

fn app_e2ee_reference_signature(payload: &ReferenceValuesPayload) -> ArtifactSignature {
    let key_pair = app_e2ee_reference_key_pair();
    let payload_json = canonical_json(payload).unwrap();
    let signature = key_pair.sk.sign(payload_json.as_bytes(), None);
    ArtifactSignature {
        signer: APP_E2EE_TEST_SIGNER.into(),
        key_id: APP_E2EE_TEST_KEY_ID.into(),
        alg: "ed25519".into(),
        value: format!(
            "base64url:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref())
        ),
    }
}

fn app_e2ee_reference_trusted_key() -> TrustedSigningKey {
    let key_pair = app_e2ee_reference_key_pair();
    TrustedSigningKey {
        signer: APP_E2EE_TEST_SIGNER.into(),
        key_id: APP_E2EE_TEST_KEY_ID.into(),
        public_key_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key_pair.pk.as_ref()),
    }
}

fn app_e2ee_reference_key_pair() -> KeyPair {
    KeyPair::from_seed(Seed::new([43_u8; 32]))
}

fn assert_failed_check(
    case: &ProviderEvidenceNormalizerCase,
    verdict: &AttestationVerdict,
    check: &str,
) {
    assert_eq!(
        verdict.status,
        VerificationStatus::Failed,
        "{}: failed mutation status",
        case.id
    );
    assert!(
        !verdict.request_allowed,
        "{}: failed mutation request allowed",
        case.id
    );
    assert_eq!(
        verdict.checks.get(check),
        Some(&CheckResult::Failed),
        "{}: expected failed check {check}, got {:?}",
        case.id,
        verdict.checks
    );
}
