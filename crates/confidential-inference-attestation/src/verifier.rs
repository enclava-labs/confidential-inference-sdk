use crate::policy::{
    ChannelBindingRequirement, CpuTeeRequirement, EnforcementMode, FreshnessPolicy, GpuTeeKind,
    GpuTeeRequirement, ModelBindingRequirement, VerificationPolicy,
};
use crate::verdict::cpu_allowed;
use crate::{
    canonical_digest, certificate_spki_sha256_hex, certificate_validity_epoch_millis,
    sha256_digest, verify_chutes_e2ee_report_data_binding, verify_chutes_live_report_data_binding,
    verify_dstack_tcb_compose_hash, verify_tls_spki_report_data_binding, AttestationError,
    AttestationVerdict, AttestedRoute, AttributionSource, CheckOutcome, CheckResult,
    ChutesE2eeEvidence, ChutesE2eeReportDataBinding, ChutesLiveEvidence,
    ChutesLiveReportDataBinding, ConfidentialityResult, CpuTeeKind, DstackEvidence,
    EvidenceHardware, FailClosedGpuAttestationVerifier, FailClosedTinfoilQuoteVerifier,
    FixtureEvidence, GpuAttestationVerifier, ModelBindingResult, NearLiveEvidence,
    NvidiaGpuAttestationEvidence, NvidiaGpuAttestationVerificationRequest,
    ParsedTinfoilLiveCapture, ReferenceValuesPayload, ResponseIntegrityResult, Result,
    RouteAttribution, RoutePartyAttribution, RoutePartyRole, SignatureMetadata,
    TcbComposeHashBinding, TinfoilLiveCaptureEvidence, TinfoilQuoteVerificationRequest,
    TinfoilQuoteVerifier, TinfoilTlsEvidence, TrustTier, ValidityWindow, VerdictArtifacts,
    VerdictError, VerificationStatus, VerifiedTdxQuote, VerifiedTinfoilQuote,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct VerificationRequest {
    pub route: AttestedRoute,
    pub route_execution_status: String,
    pub chat_executable: bool,
    pub known_unsupported_modes: Vec<String>,
    pub expected_freshness_nonce: Option<String>,
    pub policy: VerificationPolicy,
    pub reference_values: ReferenceValuesPayload,
    pub reference_signature: SignatureMetadata,
    pub reference_values_digest: String,
    pub registry_digest: String,
    pub registry_version: String,
    pub registry_source: String,
    pub registry_sync_completed_at: String,
    pub registry_signature: SignatureMetadata,
    pub reference_values_source: String,
    pub raw_evidence: Vec<u8>,
}

pub fn verify_evidence(request: VerificationRequest) -> Result<AttestationVerdict> {
    verify_evidence_with_attestation_verifiers(
        request,
        &FailClosedTinfoilQuoteVerifier,
        &FailClosedGpuAttestationVerifier,
    )
}

pub fn verify_evidence_with_tinfoil_quote_verifier(
    request: VerificationRequest,
    tinfoil_quote_verifier: &dyn TinfoilQuoteVerifier,
) -> Result<AttestationVerdict> {
    verify_evidence_with_attestation_verifiers(
        request,
        tinfoil_quote_verifier,
        &FailClosedGpuAttestationVerifier,
    )
}

pub fn verify_evidence_with_gpu_attestation_verifier(
    request: VerificationRequest,
    gpu_attestation_verifier: &dyn GpuAttestationVerifier,
) -> Result<AttestationVerdict> {
    verify_evidence_with_attestation_verifiers(
        request,
        &FailClosedTinfoilQuoteVerifier,
        gpu_attestation_verifier,
    )
}

pub fn verify_evidence_with_attestation_verifiers(
    request: VerificationRequest,
    tinfoil_quote_verifier: &dyn TinfoilQuoteVerifier,
    gpu_attestation_verifier: &dyn GpuAttestationVerifier,
) -> Result<AttestationVerdict> {
    let _span = tracing::info_span!(
        "confidential-inference.attestation.dispatch",
        provider = %request.route.provider,
        route_id = %request.route.route_id,
        evidence_family = %request.route.evidence_family,
        requested_model = %request.route.requested_model,
        provider_model = %request.route.provider_model,
        canonical_model = %request.route.canonical_model
    )
    .entered();
    match request.route.evidence_family.as_str() {
        "fixture_dstack" => verify_fixture_evidence(request),
        "dstack_app_e2ee" => verify_dstack_evidence(request),
        "chutes_e2ee" => verify_chutes_e2ee_evidence_with_gpu_attestation_verifier(
            request,
            gpu_attestation_verifier,
        ),
        "chutes_live_e2ee" => verify_chutes_live_evidence_with_attestation_verifiers(
            request,
            tinfoil_quote_verifier,
            gpu_attestation_verifier,
        ),
        "near_hw_verified_tls" => verify_near_live_evidence_with_attestation_verifiers(
            request,
            tinfoil_quote_verifier,
            gpu_attestation_verifier,
        ),
        "tinfoil_hw_verified_tls" => {
            verify_tinfoil_tls_evidence_with_quote_verifier(request, tinfoil_quote_verifier)
        }
        evidence_family => Err(AttestationError::InvalidEvidence(format!(
            "unsupported evidence family {evidence_family}"
        ))),
    }
}

#[derive(Debug, Deserialize)]
struct NearAttestationReport {
    intel_quote: String,
    request_nonce: String,
    signing_address: String,
    signing_algo: String,
    tls_cert_fingerprint: String,
    #[serde(default)]
    model_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifiedLiveEvidenceDigest<'a, T: Serialize> {
    schema: &'static str,
    capture: &'a T,
    verified_quote: &'a VerifiedTdxQuote,
}

#[derive(Clone, Debug)]
struct VerifiedProviderLiveEvidence {
    provider: String,
    route_id: String,
    evidence_family: String,
    tee_measurement: String,
    hardware: EvidenceHardware,
    gpu_attestation: Option<NvidiaGpuAttestationEvidence>,
    gpu_nonce: String,
    report_data: String,
    nonce_binding_verified: bool,
    channel_binding_verified: bool,
    channel_check: &'static str,
    channel_error: &'static str,
    confidentiality_result: ConfidentialityResult,
    attested_model: Option<String>,
    issued_at: String,
    expires_at: String,
    expires_at_epoch_ms: u64,
    evidence_digest: String,
    signing_public_key: Option<String>,
    e2ee_capability: Option<String>,
}

struct LiveCaptureMetadata<'a> {
    provider: &'a str,
    route_id: &'a str,
    evidence_family: &'a str,
    requested_model: &'a str,
    policy_digest: &'a str,
    evidence_endpoint: &'a str,
}

pub fn verify_chutes_live_evidence_with_attestation_verifiers(
    request: VerificationRequest,
    tdx_quote_verifier: &dyn TinfoilQuoteVerifier,
    gpu_attestation_verifier: &dyn GpuAttestationVerifier,
) -> Result<AttestationVerdict> {
    let capture: ChutesLiveEvidence = serde_json::from_slice(&request.raw_evidence)?;
    if capture.schema != ChutesLiveEvidence::SCHEMA {
        return Err(AttestationError::InvalidEvidence(format!(
            "unsupported schema {}",
            capture.schema
        )));
    }
    validate_live_capture_metadata(
        LiveCaptureMetadata {
            provider: &capture.provider,
            route_id: &capture.route_id,
            evidence_family: &capture.evidence_family,
            requested_model: &capture.requested_model,
            policy_digest: &capture.policy_digest,
            evidence_endpoint: &capture.evidence_endpoint,
        },
        &request,
        "Chutes",
    )?;
    validate_nonce_hex("Chutes request nonce", &capture.request_nonce)?;

    let e2e_public_key = decode_base64("Chutes ML-KEM public key", &capture.e2e_public_key_base64)?;
    if e2e_public_key.len() != 1_184 {
        return Err(AttestationError::InvalidEvidence(format!(
            "Chutes ML-KEM-768 public key has {} bytes, expected 1184",
            e2e_public_key.len()
        )));
    }
    let quote_bytes = decode_base64("Chutes TDX quote", &capture.quote_base64)?;
    let verified_quote = tdx_quote_verifier.verify_tdx_quote(&quote_bytes)?;
    let certificate_der = decode_base64(
        "Chutes instance certificate",
        &capture.certificate_der_base64,
    )?;
    let certificate_spki = certificate_spki_sha256_hex(&certificate_der)?;
    let certificate_expires_at =
        validate_live_certificate(&certificate_der, &verified_quote.issued_at, "Chutes")?;

    let report_data_binding = verify_chutes_live_report_data_binding(
        &verified_quote.report_data,
        &capture.request_nonce,
        &capture.e2e_public_key_base64,
        &certificate_spki,
    );
    let freshness_matches = freshness_nonce_matches_policy(
        &request.policy,
        request.expected_freshness_nonce.as_deref(),
        &capture.request_nonce,
    );
    let nonce_binding_verified =
        report_data_binding == ChutesLiveReportDataBinding::Verified && freshness_matches;
    let gpu_nonce = crate::chutes_expected_report_data_prefix(
        &capture.request_nonce,
        &capture.e2e_public_key_base64,
    )
    .ok_or_else(|| {
        AttestationError::InvalidEvidence(
            "Chutes request nonce or ML-KEM public key is malformed".into(),
        )
    })?;
    if capture
        .gpu_attestation
        .as_ref()
        .is_some_and(|gpu| !gpu.nonce.eq_ignore_ascii_case(&gpu_nonce))
    {
        return Err(AttestationError::InvalidEvidence(
            "Chutes GPU evidence nonce does not match the quote-bound E2EE key challenge".into(),
        ));
    }

    let tee_measurement = format!(
        "tdx:mr_td:{}:rtmr0:{}:rtmr1:{}:rtmr2:{}:rtmr3:{}",
        verified_quote.mr_td,
        verified_quote.rtmr0,
        verified_quote.rtmr1,
        verified_quote.rtmr2,
        verified_quote.rtmr3
    );
    let expires_at_epoch_ms = verified_quote
        .expires_at_epoch_ms
        .min(certificate_expires_at);
    let evidence_digest = canonical_digest(&VerifiedLiveEvidenceDigest {
        schema: "confidential-inference.chutes-live-verified-evidence.v1",
        capture: &capture,
        verified_quote: &verified_quote,
    })?;
    let channel_binding_verified = nonce_binding_verified;
    let evidence = VerifiedProviderLiveEvidence {
        provider: capture.provider,
        route_id: capture.route_id,
        evidence_family: capture.evidence_family,
        tee_measurement,
        hardware: EvidenceHardware {
            cpu: CpuTeeKind::Tdx,
            gpu: capture
                .gpu_attestation
                .as_ref()
                .map(|_| GpuTeeKind::NvidiaCc),
        },
        gpu_attestation: capture.gpu_attestation,
        gpu_nonce,
        report_data: verified_quote.report_data,
        nonce_binding_verified,
        channel_binding_verified,
        channel_check: "e2ee_key_binding",
        channel_error: "Chutes ML-KEM key and instance certificate are not bound to the fresh verified TDX quote",
        confidentiality_result: if channel_binding_verified {
            ConfidentialityResult::EncryptedBound
        } else {
            ConfidentialityResult::NotBound
        },
        attested_model: None,
        issued_at: verified_quote.issued_at,
        expires_at: format_utc_timestamp_millis(expires_at_epoch_ms),
        expires_at_epoch_ms,
        evidence_digest,
        signing_public_key: Some(sha256_digest(&e2e_public_key)),
        e2ee_capability: Some("chutes-ml-kem-768-e2ee".into()),
    };

    verify_provider_live_evidence(request, evidence, gpu_attestation_verifier)
}

pub fn verify_near_live_evidence_with_attestation_verifiers(
    request: VerificationRequest,
    tdx_quote_verifier: &dyn TinfoilQuoteVerifier,
    gpu_attestation_verifier: &dyn GpuAttestationVerifier,
) -> Result<AttestationVerdict> {
    let capture: NearLiveEvidence = serde_json::from_slice(&request.raw_evidence)?;
    if capture.schema != NearLiveEvidence::SCHEMA {
        return Err(AttestationError::InvalidEvidence(format!(
            "unsupported schema {}",
            capture.schema
        )));
    }
    validate_live_capture_metadata(
        LiveCaptureMetadata {
            provider: &capture.provider,
            route_id: &capture.route_id,
            evidence_family: &capture.evidence_family,
            requested_model: &capture.requested_model,
            policy_digest: &capture.policy_digest,
            evidence_endpoint: &capture.evidence_endpoint,
        },
        &request,
        "NEAR",
    )?;
    validate_nonce_hex("NEAR request nonce", &capture.request_nonce)?;

    let certificate_der = decode_base64(
        "NEAR live TLS certificate",
        &capture.live_tls_leaf_certificate_der_base64,
    )?;
    let certificate_spki = certificate_spki_sha256_hex(&certificate_der)?;
    if !certificate_spki.eq_ignore_ascii_case(&capture.live_tls_spki_sha256) {
        return Err(AttestationError::InvalidEvidence(
            "NEAR live TLS SPKI does not match the captured certificate".into(),
        ));
    }
    let raw_attestation = decode_base64(
        "NEAR raw attestation body",
        &capture.raw_attestation_body_base64,
    )?;
    let report: NearAttestationReport =
        serde_json::from_slice(&raw_attestation).map_err(|error| {
            AttestationError::InvalidEvidence(format!(
                "NEAR attestation response is not valid JSON: {error}"
            ))
        })?;
    if report.signing_algo != "ecdsa" {
        return Err(AttestationError::InvalidEvidence(format!(
            "NEAR attestation used unsupported signing algorithm {}",
            report.signing_algo
        )));
    }
    if !report
        .request_nonce
        .eq_ignore_ascii_case(&capture.request_nonce)
    {
        return Err(AttestationError::InvalidEvidence(
            "NEAR attestation request_nonce does not match the verifier challenge".into(),
        ));
    }

    let quote_bytes = decode_hex("NEAR TDX quote", &report.intel_quote)?;
    let verified_quote = tdx_quote_verifier.verify_tdx_quote(&quote_bytes)?;
    if verified_quote.mr_config_id.len() != 96 || !verified_quote.mr_config_id.starts_with("01") {
        return Err(AttestationError::InvalidEvidence(
            "NEAR TDX mr_config_id is not a v1 compose measurement".into(),
        ));
    }

    let attested_tls_fingerprint = normalize_sha256_hex(
        "NEAR attested TLS fingerprint",
        &report.tls_cert_fingerprint,
    )?;
    if !attested_tls_fingerprint.eq_ignore_ascii_case(&certificate_spki) {
        return Err(AttestationError::InvalidEvidence(
            "NEAR attested TLS fingerprint does not match the live TLS certificate".into(),
        ));
    }
    let signing_address = decode_hex(
        "NEAR ECDSA signing address",
        report.signing_address.trim_start_matches("0x"),
    )?;
    if signing_address.len() != 20 {
        return Err(AttestationError::InvalidEvidence(
            "NEAR ECDSA signing address is not 20 bytes".into(),
        ));
    }
    let mut report_binding_input = signing_address.clone();
    report_binding_input.extend_from_slice(&decode_hex(
        "NEAR TLS fingerprint",
        &attested_tls_fingerprint,
    )?);
    let expected_first32 = Sha256::digest(&report_binding_input);
    let report_data = decode_hex("NEAR TDX report_data", &verified_quote.report_data)?;
    let nonce_bytes = decode_hex("NEAR request nonce", &capture.request_nonce)?;
    let report_data_matches = report_data.len() == 64
        && report_data[..32] == expected_first32[..]
        && report_data[32..] == nonce_bytes;
    let freshness_matches = freshness_nonce_matches_policy(
        &request.policy,
        request.expected_freshness_nonce.as_deref(),
        &capture.request_nonce,
    );
    let nonce_binding_verified = report_data_matches && freshness_matches;
    if capture
        .gpu_attestation
        .as_ref()
        .is_some_and(|gpu| !gpu.nonce.eq_ignore_ascii_case(&capture.request_nonce))
    {
        return Err(AttestationError::InvalidEvidence(
            "NEAR GPU evidence nonce does not match the verifier challenge".into(),
        ));
    }
    let model_binding_verified = report.model_name.as_deref().is_some_and(|model| {
        model == request.route.provider_model || model == request.route.canonical_model
    });
    let attested_model = model_binding_verified.then(|| request.route.canonical_model.clone());

    let certificate_expires_at =
        validate_live_certificate(&certificate_der, &verified_quote.issued_at, "NEAR")?;
    let expires_at_epoch_ms = verified_quote
        .expires_at_epoch_ms
        .min(certificate_expires_at);
    let evidence_digest = canonical_digest(&VerifiedLiveEvidenceDigest {
        schema: "confidential-inference.near-live-verified-evidence.v1",
        capture: &capture,
        verified_quote: &verified_quote,
    })?;
    let channel_binding_verified = nonce_binding_verified;
    let evidence = VerifiedProviderLiveEvidence {
        provider: capture.provider,
        route_id: capture.route_id,
        evidence_family: capture.evidence_family,
        tee_measurement: format!("tdx:mr_config_id:{}", verified_quote.mr_config_id),
        hardware: EvidenceHardware {
            cpu: CpuTeeKind::Tdx,
            gpu: capture
                .gpu_attestation
                .as_ref()
                .map(|_| GpuTeeKind::NvidiaCc),
        },
        gpu_attestation: capture.gpu_attestation,
        gpu_nonce: capture.request_nonce,
        report_data: verified_quote.report_data,
        nonce_binding_verified,
        channel_binding_verified,
        channel_check: "tls_binding",
        channel_error:
            "NEAR live TLS certificate, signing address, and nonce are not bound to the verified TDX quote",
        confidentiality_result: if channel_binding_verified {
            ConfidentialityResult::ChannelBound
        } else {
            ConfidentialityResult::NotBound
        },
        attested_model,
        issued_at: verified_quote.issued_at,
        expires_at: format_utc_timestamp_millis(expires_at_epoch_ms),
        expires_at_epoch_ms,
        evidence_digest,
        signing_public_key: Some(format!("ecdsa:{}", report.signing_address)),
        e2ee_capability: None,
    };

    verify_provider_live_evidence(request, evidence, gpu_attestation_verifier)
}

fn verify_provider_live_evidence(
    request: VerificationRequest,
    evidence: VerifiedProviderLiveEvidence,
    gpu_attestation_verifier: &dyn GpuAttestationVerifier,
) -> Result<AttestationVerdict> {
    let provider_reference = request
        .reference_values
        .providers
        .get(&request.route.provider)
        .ok_or_else(|| AttestationError::MissingProviderReference {
            provider: request.route.provider.clone(),
        })?;
    let route_reference = provider_reference
        .routes
        .get(&request.route.route_id)
        .ok_or_else(|| AttestationError::MissingRouteReference {
            route_id: request.route.route_id.clone(),
        })?;
    let mut checks = BTreeMap::new();
    let mut errors = Vec::new();

    push_check(
        &mut checks,
        &mut errors,
        "route_metadata_binding",
        evidence.provider == request.route.provider
            && evidence.route_id == request.route.route_id
            && evidence.evidence_family == request.route.evidence_family
            && route_reference.provider_model == request.route.provider_model
            && route_reference.canonical_model == request.route.canonical_model
            && route_reference.evidence_family == request.route.evidence_family,
        "evidence route metadata does not match registry/reference route",
    );
    mark_request_route_unproven(&mut checks);

    let measurement_accepted = provider_reference
        .accepted_measurements
        .iter()
        .any(|measurement| measurement == &evidence.tee_measurement);
    let hardware_verified = match &request.policy.hardware.cpu {
        CpuTeeRequirement::NotRequired => {
            checks.insert("cpu_tee".into(), CheckResult::NotApplicable);
            true
        }
        CpuTeeRequirement::AnyCpuTee => {
            let ok = cpu_allowed(&evidence.hardware.cpu, &route_reference.accepted_cpu_tees)
                && measurement_accepted;
            push_check(
                &mut checks,
                &mut errors,
                "cpu_tee",
                ok,
                "verified TDX identity is not accepted by signed reference values",
            );
            ok
        }
        CpuTeeRequirement::OneOf { allowed } => {
            let ok = allowed.contains(&evidence.hardware.cpu)
                && cpu_allowed(&evidence.hardware.cpu, &route_reference.accepted_cpu_tees)
                && measurement_accepted;
            push_check(
                &mut checks,
                &mut errors,
                "cpu_tee",
                ok,
                "verified TDX identity is not accepted by policy and signed reference values",
            );
            ok
        }
    };

    let gpu_verified = match &request.policy.hardware.gpu {
        GpuTeeRequirement::NotRequired => {
            checks.insert("gpu_tee".into(), CheckResult::NotApplicable);
            true
        }
        GpuTeeRequirement::OneOf { allowed } => {
            let result = verify_live_nvidia_gpu_attestation(
                evidence.gpu_attestation.as_ref(),
                &evidence.gpu_nonce,
                allowed,
                gpu_attestation_verifier,
                &request.route.provider,
                &request.route.route_id,
            );
            let ok = result.is_ok();
            push_check(
                &mut checks,
                &mut errors,
                "gpu_tee",
                ok,
                &result
                    .err()
                    .unwrap_or_else(|| "NVIDIA GPU attestation verified".into()),
            );
            ok
        }
    };

    let route_channel_matches = request.route.channel_binding_kind
        == route_reference.channel_binding_kind
        && request
            .route
            .channel_binding_kind
            .satisfies(&request.policy.channel_binding_requirement)
        && route_reference
            .channel_binding_kind
            .satisfies(&request.policy.channel_binding_requirement);
    let channel_verified = evidence.channel_binding_verified && route_channel_matches;
    push_check(
        &mut checks,
        &mut errors,
        evidence.channel_check,
        channel_verified,
        evidence.channel_error,
    );
    let other_channel_check = if evidence.channel_check == "tls_binding" {
        "e2ee_key_binding"
    } else {
        "tls_binding"
    };
    checks.insert(other_channel_check.into(), CheckResult::NotApplicable);
    push_check(
        &mut checks,
        &mut errors,
        "nonce_binding",
        evidence.nonce_binding_verified,
        "fresh provider challenge is not bound to verified TDX report_data",
    );

    let confidentiality_result = if channel_verified {
        evidence.confidentiality_result.clone()
    } else {
        ConfidentialityResult::NotBound
    };
    let response_integrity_result = if channel_verified {
        ResponseIntegrityResult::ChannelBound
    } else {
        ResponseIntegrityResult::NotBound
    };
    push_check(
        &mut checks,
        &mut errors,
        "request_key_binding",
        confidentiality_result.satisfies(&request.policy.request_confidentiality_requirement),
        "request confidentiality is not bound to the attested workload",
    );
    checks.insert(
        "request_encryption".into(),
        if channel_verified {
            CheckResult::Verified
        } else {
            CheckResult::Failed
        },
    );
    push_check(
        &mut checks,
        &mut errors,
        "response_key_binding",
        confidentiality_result.satisfies(&request.policy.response_confidentiality_requirement),
        "response confidentiality is not bound to the attested workload",
    );
    checks.insert(
        "response_encryption".into(),
        if channel_verified {
            CheckResult::Verified
        } else {
            CheckResult::Failed
        },
    );
    push_check(
        &mut checks,
        &mut errors,
        "response_channel_binding",
        response_integrity_result.satisfies(&request.policy.response_integrity_requirement),
        "response bytes are not cryptographically bound as required by policy",
    );
    checks.insert("response_receipt".into(), CheckResult::NotApplicable);

    let model_binding_verified = evidence.attested_model.as_deref()
        == Some(request.route.canonical_model.as_str())
        && route_reference.canonical_model == request.route.canonical_model;
    let model_binding_result = push_model_binding_check(
        &mut checks,
        &mut errors,
        &request.policy.model_binding_requirement,
        evidence.attested_model.is_some(),
        model_binding_verified,
    );

    let provenance_required =
        request.policy.provenance.workload_image || request.policy.provenance.model_artifacts;
    if provenance_required {
        push_check(
            &mut checks,
            &mut errors,
            "image_provenance",
            false,
            "live provider evidence does not contain signed workload image provenance",
        );
        push_check(
            &mut checks,
            &mut errors,
            "model_artifact_provenance",
            false,
            "live provider evidence does not contain signed model artifact provenance",
        );
    } else {
        checks.insert("image_provenance".into(), CheckResult::NotApplicable);
        checks.insert(
            "model_artifact_provenance".into(),
            CheckResult::NotApplicable,
        );
    }
    push_unsupported_provenance_checks(&mut checks, &mut errors, &request.policy);
    push_per_request_freshness_check(&mut checks, &mut errors, &request.policy);

    let failed_required = checks.values().any(|check| *check == CheckResult::Failed);
    let request_allowed = match request.policy.enforcement {
        EnforcementMode::Disabled | EnforcementMode::Observe => true,
        EnforcementMode::Enforce => !failed_required,
    };
    let status = match request.policy.enforcement {
        EnforcementMode::Disabled => VerificationStatus::Disabled,
        _ if failed_required => VerificationStatus::Failed,
        _ if hardware_verified && gpu_verified && channel_verified => VerificationStatus::Verified,
        _ => VerificationStatus::Partial,
    };
    let policy_digest = request.policy.digest()?;
    let raw_evidence_digest = sha256_digest(&request.raw_evidence);
    let validity = compute_validity_bounds(
        &evidence.issued_at,
        request.policy.verdict_ttl_millis.0,
        [
            ValidityCandidate {
                epoch_ms: evidence.expires_at_epoch_ms,
                timestamp: &evidence.expires_at,
            },
            ValidityCandidate {
                epoch_ms: route_reference.valid_until_epoch_ms,
                timestamp: &route_reference.valid_until,
            },
            ValidityCandidate {
                epoch_ms: request.reference_values.valid_until_epoch_ms,
                timestamp: &request.reference_values.valid_until,
            },
        ],
    )?;

    let verdict = AttestationVerdict {
        schema: AttestationVerdict::SCHEMA.into(),
        required: Vec::new(),
        check_outcomes: build_check_outcomes(&checks, &errors, &request.policy),
        route_attribution: Some(build_route_attribution(
            &request,
            Some(evidence.hardware.cpu.as_policy_str()),
        )),
        policy_schema: VerificationPolicy::SCHEMA.into(),
        reference_values_schema: ReferenceValuesPayload::SCHEMA.into(),
        provider_registry_schema: "confidential-inference.provider-registry.v1".into(),
        status,
        enforcement: request.policy.enforcement.clone(),
        request_allowed,
        would_block_under_enforce: failed_required,
        trust_tier: request.route.trust_tier.clone(),
        provider: request.route.provider.clone(),
        requested_model: request.route.requested_model.clone(),
        provider_model: request.route.provider_model.clone(),
        canonical_model: request.route.canonical_model.clone(),
        route_id: request.route.route_id.clone(),
        evidence_family: request.route.evidence_family.clone(),
        alias_confidence: request.route.alias_confidence.clone(),
        adapter_version: request.route.adapter_version.clone(),
        api_endpoint: request.route.api_endpoint.clone(),
        evidence_endpoint: request.route.evidence_endpoint.clone(),
        freshness_class: request.route.freshness_class.clone(),
        streaming_allowed: request.route.streaming_allowed,
        route_execution_status: request.route_execution_status,
        chat_executable: request.chat_executable,
        known_unsupported_modes: request.known_unsupported_modes,
        channel_binding_kind: request.route.channel_binding_kind.clone(),
        model_binding_result,
        request_channel_bound: channel_verified,
        request_confidentiality_result: confidentiality_result.clone(),
        response_confidentiality_result: confidentiality_result,
        response_channel_bound: channel_verified,
        response_integrity_result,
        policy_digest,
        provider_registry_digest: request.registry_digest,
        registry_version: request.registry_version,
        registry_source: request.registry_source,
        registry_sync_completed_at: request.registry_sync_completed_at,
        registry_signature: request.registry_signature,
        reference_values_digest: request.reference_values_digest,
        reference_values_version: request.reference_values.version.clone(),
        reference_values_source: request.reference_values_source,
        reference_values_signature: request.reference_signature,
        raw_evidence_digest,
        evidence_digest: evidence.evidence_digest,
        verified_at: evidence.issued_at,
        expires_at: validity.expires_at.clone(),
        expires_at_epoch_ms: validity.expires_at_epoch_ms,
        validity: ValidityWindow {
            policy_ttl_until: validity.policy_ttl_until,
            collateral_valid_until: evidence.expires_at.clone(),
            certificate_valid_until: evidence.expires_at.clone(),
            quote_valid_until: evidence.expires_at.clone(),
            tcb_valid_until: evidence.expires_at.clone(),
            reference_values_valid_until: request.reference_values.valid_until,
            computed_expires_at: validity.expires_at,
        },
        checks,
        artifacts: VerdictArtifacts {
            source_url: Some(request.route.evidence_endpoint),
            tee_measurement: Some(evidence.tee_measurement),
            report_data: Some(evidence.report_data),
            signing_public_key: evidence.signing_public_key,
            e2ee_capability: evidence.e2ee_capability,
            model_manifest: evidence.attested_model,
            model_artifacts: Vec::new(),
        },
        errors,
    };
    verdict.validate_summary_consistency()?;
    trace_verdict_completed(&verdict);
    Ok(verdict)
}

fn verify_live_nvidia_gpu_attestation(
    evidence: Option<&NvidiaGpuAttestationEvidence>,
    expected_nonce: &str,
    allowed: &[GpuTeeKind],
    verifier: &dyn GpuAttestationVerifier,
    provider: &str,
    route_id: &str,
) -> std::result::Result<(), String> {
    if !allowed.contains(&GpuTeeKind::NvidiaCc) {
        return Err("NVIDIA confidential-computing GPU is not accepted by policy".into());
    }
    let evidence =
        evidence.ok_or_else(|| "NVIDIA GPU attestation evidence is missing".to_owned())?;
    if evidence.schema != NvidiaGpuAttestationEvidence::SCHEMA {
        return Err(format!(
            "unsupported NVIDIA GPU attestation schema {}",
            evidence.schema
        ));
    }
    if !evidence.nonce.eq_ignore_ascii_case(expected_nonce) {
        return Err("NVIDIA GPU evidence nonce does not match the TDX-bound challenge".into());
    }
    let verified = verifier
        .verify_nvidia_gpu_attestation(&NvidiaGpuAttestationVerificationRequest {
            evidence,
            expected_nonce,
            expected_tee: GpuTeeKind::NvidiaCc,
            provider,
            route_id,
        })
        .map_err(|error| format!("NVIDIA GPU attestation verification failed: {error}"))?;
    if verified.tee != GpuTeeKind::NvidiaCc
        || !verified.nonce.eq_ignore_ascii_case(expected_nonce)
        || verified.attestation_format != evidence.attestation_format
    {
        return Err("NVIDIA GPU verifier returned inconsistent verified claims".into());
    }
    Ok(())
}

fn validate_live_capture_metadata(
    metadata: LiveCaptureMetadata<'_>,
    request: &VerificationRequest,
    provider_name: &str,
) -> Result<()> {
    let expected_policy_digest = request.policy.digest()?;
    if metadata.provider != request.route.provider
        || metadata.route_id != request.route.route_id
        || metadata.evidence_family != request.route.evidence_family
        || metadata.requested_model != request.route.requested_model
        || metadata.policy_digest != expected_policy_digest
        || metadata.evidence_endpoint != request.route.evidence_endpoint
    {
        return Err(AttestationError::InvalidEvidence(format!(
            "{provider_name} live capture metadata does not match verification request"
        )));
    }
    Ok(())
}

fn validate_live_certificate(
    certificate_der: &[u8],
    verified_at: &str,
    provider_name: &str,
) -> Result<u64> {
    let (not_before, not_after) = certificate_validity_epoch_millis(certificate_der)?;
    let verified_at = parse_utc_timestamp_millis(verified_at)?;
    if verified_at < not_before || verified_at >= not_after {
        return Err(AttestationError::InvalidEvidence(format!(
            "{provider_name} certificate is not valid at quote verification time"
        )));
    }
    Ok(not_after)
}

fn validate_nonce_hex(field: &str, value: &str) -> Result<()> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AttestationError::InvalidEvidence(format!(
            "{field} must be exactly 32 bytes of hex"
        )))
    }
}

fn normalize_sha256_hex(field: &str, value: &str) -> Result<String> {
    validate_nonce_hex(field, value)?;
    Ok(value.to_ascii_lowercase())
}

fn decode_base64(field: &str, value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| {
            AttestationError::InvalidEvidence(format!("{field} is not valid base64: {error}"))
        })
}

fn decode_hex(field: &str, value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AttestationError::InvalidEvidence(format!(
            "{field} is not canonical hex"
        )));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).expect("hex was validated");
            let low = hex_nibble(pair[1]).expect("hex was validated");
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn verify_chutes_e2ee_evidence(request: VerificationRequest) -> Result<AttestationVerdict> {
    verify_chutes_e2ee_evidence_with_gpu_attestation_verifier(
        request,
        &FailClosedGpuAttestationVerifier,
    )
}

pub fn verify_chutes_e2ee_evidence_with_gpu_attestation_verifier(
    request: VerificationRequest,
    gpu_attestation_verifier: &dyn GpuAttestationVerifier,
) -> Result<AttestationVerdict> {
    let evidence: ChutesE2eeEvidence = serde_json::from_slice(&request.raw_evidence)?;
    if evidence.schema != ChutesE2eeEvidence::SCHEMA {
        return Err(AttestationError::InvalidEvidence(format!(
            "unsupported schema {}",
            evidence.schema
        )));
    }

    let provider_reference = request
        .reference_values
        .providers
        .get(&request.route.provider)
        .ok_or_else(|| AttestationError::MissingProviderReference {
            provider: request.route.provider.clone(),
        })?;
    let route_reference = provider_reference
        .routes
        .get(&request.route.route_id)
        .ok_or_else(|| AttestationError::MissingRouteReference {
            route_id: request.route.route_id.clone(),
        })?;

    let mut checks = BTreeMap::new();
    let mut errors = Vec::new();

    push_check(
        &mut checks,
        &mut errors,
        "route_metadata_binding",
        evidence.provider == request.route.provider
            && evidence.route_id == request.route.route_id
            && evidence.evidence_family == request.route.evidence_family
            && route_reference.provider_model == request.route.provider_model
            && route_reference.canonical_model == request.route.canonical_model
            && route_reference.evidence_family == request.route.evidence_family,
        "evidence route metadata does not match registry/reference route",
    );
    mark_request_route_unproven(&mut checks);

    let hardware_verified = match &request.policy.hardware.cpu {
        CpuTeeRequirement::NotRequired => {
            checks.insert("cpu_tee".into(), CheckResult::NotApplicable);
            true
        }
        CpuTeeRequirement::AnyCpuTee => {
            let ok = cpu_allowed(&evidence.hardware.cpu, &route_reference.accepted_cpu_tees)
                && provider_reference
                    .accepted_measurements
                    .iter()
                    .any(|measurement| measurement == &evidence.tee_measurement);
            push_check(
                &mut checks,
                &mut errors,
                "cpu_tee",
                ok,
                "CPU TEE or measurement is not accepted by reference values",
            );
            ok
        }
        CpuTeeRequirement::OneOf { allowed } => {
            let ok = allowed
                .iter()
                .any(|candidate| candidate == &evidence.hardware.cpu)
                && cpu_allowed(&evidence.hardware.cpu, &route_reference.accepted_cpu_tees)
                && provider_reference
                    .accepted_measurements
                    .iter()
                    .any(|measurement| measurement == &evidence.tee_measurement);
            push_check(
                &mut checks,
                &mut errors,
                "cpu_tee",
                ok,
                "CPU TEE kind or measurement is not accepted by policy/reference values",
            );
            ok
        }
    };

    let gpu_verified = match &request.policy.hardware.gpu {
        GpuTeeRequirement::NotRequired => {
            checks.insert("gpu_tee".into(), CheckResult::NotApplicable);
            true
        }
        GpuTeeRequirement::OneOf { allowed } => {
            let gpu_check = verify_chutes_gpu_tee(
                &evidence,
                allowed,
                gpu_attestation_verifier,
                &request.route.provider,
                &request.route.route_id,
            );
            let ok = gpu_check.is_ok();
            let message = gpu_check
                .err()
                .unwrap_or_else(|| "GPU TEE attestation verified".into());
            push_check(&mut checks, &mut errors, "gpu_tee", ok, &message);
            ok
        }
    };
    checks.insert("tls_binding".into(), CheckResult::NotApplicable);

    let report_data_binding = verify_chutes_e2ee_report_data_binding(
        &evidence.report_data,
        &evidence.nonce,
        &evidence.e2e_public_key,
    );
    let freshness_nonce_matches = freshness_nonce_matches_policy(
        &request.policy,
        request.expected_freshness_nonce.as_deref(),
        &evidence.nonce,
    );
    let nonce_binding_verified =
        report_data_binding == ChutesE2eeReportDataBinding::Verified && freshness_nonce_matches;
    let public_key_digest = sha256_digest(evidence.e2e_public_key.as_bytes());
    let reference_key_matches = public_key_digest == route_reference.e2ee_public_key_digest;
    let channel_verified = request
        .route
        .channel_binding_kind
        .satisfies(&request.policy.channel_binding_requirement)
        && route_reference.channel_binding_kind == request.route.channel_binding_kind
        && route_reference
            .channel_binding_kind
            .satisfies(&request.policy.channel_binding_requirement)
        && nonce_binding_verified
        && reference_key_matches;
    tracing::debug!(
        report_data_binding = ?report_data_binding,
        reference_key_matches,
        channel_verified,
        "Chutes E2EE binding checked"
    );

    match request.policy.channel_binding_requirement {
        ChannelBindingRequirement::NotRequired => {
            checks.insert("e2ee_key_binding".into(), CheckResult::NotApplicable);
        }
        _ => {
            push_check(
                &mut checks,
                &mut errors,
                "e2ee_key_binding",
                channel_verified,
                "Chutes E2EE key is not bound to report data and reference values",
            );
        }
    }
    push_check(
        &mut checks,
        &mut errors,
        "nonce_binding",
        nonce_binding_verified,
        if freshness_nonce_matches {
            chutes_e2ee_binding_error(&report_data_binding)
        } else {
            "Chutes E2EE nonce does not match expected per-request freshness nonce"
        },
    );

    let request_confidentiality_result = if channel_verified {
        ConfidentialityResult::EncryptedBound
    } else {
        ConfidentialityResult::NotBound
    };
    let response_confidentiality_result = if channel_verified {
        ConfidentialityResult::EncryptedBound
    } else {
        ConfidentialityResult::NotBound
    };
    let response_integrity_result = if channel_verified {
        ResponseIntegrityResult::ChannelBound
    } else {
        ResponseIntegrityResult::NotBound
    };

    push_check(
        &mut checks,
        &mut errors,
        "request_key_binding",
        request_confidentiality_result
            .satisfies(&request.policy.request_confidentiality_requirement),
        "request confidentiality is not bound to the attested workload",
    );
    checks.insert(
        "request_encryption".into(),
        if channel_verified {
            CheckResult::Verified
        } else {
            CheckResult::Failed
        },
    );

    push_check(
        &mut checks,
        &mut errors,
        "response_key_binding",
        response_confidentiality_result
            .satisfies(&request.policy.response_confidentiality_requirement),
        "response confidentiality is not bound to the attested workload",
    );
    checks.insert(
        "response_encryption".into(),
        if channel_verified {
            CheckResult::Verified
        } else {
            CheckResult::Failed
        },
    );

    push_check(
        &mut checks,
        &mut errors,
        "response_channel_binding",
        response_integrity_result.satisfies(&request.policy.response_integrity_requirement),
        "response bytes are not cryptographically bound as required by policy",
    );
    checks.insert("response_receipt".into(), CheckResult::NotApplicable);

    let model_binding_verified = evidence.attested_model.as_deref()
        == Some(request.route.canonical_model.as_str())
        && route_reference.canonical_model == request.route.canonical_model;
    let provider_supports_model_binding = evidence.attested_model.is_some();
    let model_binding_result = push_model_binding_check(
        &mut checks,
        &mut errors,
        &request.policy.model_binding_requirement,
        provider_supports_model_binding,
        model_binding_verified,
    );

    let provenance_required = request.policy.provenance.workload_image
        || request.policy.provenance.model_artifacts
        || request.policy.provenance.reproducible_build
        || request.policy.provenance.source_attestation
        || request.policy.provenance.dependency_sbom;
    if provenance_required {
        push_check(
            &mut checks,
            &mut errors,
            "image_provenance",
            evidence.workload_image_digest == route_reference.workload_image_digest,
            "workload image digest does not match reference values",
        );
        push_check(
            &mut checks,
            &mut errors,
            "model_artifact_provenance",
            route_reference.model_artifacts.iter().all(|expected| {
                evidence
                    .model_artifacts
                    .iter()
                    .any(|actual| actual == expected)
            }),
            "model artifact digests do not match reference values",
        );
    } else {
        checks.insert("image_provenance".into(), CheckResult::NotApplicable);
        checks.insert(
            "model_artifact_provenance".into(),
            CheckResult::NotApplicable,
        );
    }
    push_unsupported_provenance_checks(&mut checks, &mut errors, &request.policy);

    push_per_request_freshness_check(&mut checks, &mut errors, &request.policy);

    let failed_required = checks.values().any(|check| *check == CheckResult::Failed);
    let would_block_under_enforce = failed_required;
    let request_allowed = match request.policy.enforcement {
        EnforcementMode::Disabled | EnforcementMode::Observe => true,
        EnforcementMode::Enforce => !failed_required,
    };

    let status = match request.policy.enforcement {
        EnforcementMode::Disabled => VerificationStatus::Disabled,
        _ if failed_required => VerificationStatus::Failed,
        _ if hardware_verified && gpu_verified && channel_verified => VerificationStatus::Verified,
        _ => VerificationStatus::Partial,
    };

    let raw_evidence_digest = sha256_digest(&request.raw_evidence);
    let evidence_digest = canonical_digest(&evidence)?;
    let policy_digest = request.policy.digest()?;
    let validity = compute_validity_bounds(
        &evidence.issued_at,
        request.policy.verdict_ttl_millis.0,
        [
            ValidityCandidate {
                epoch_ms: evidence.expires_at_epoch_ms,
                timestamp: &evidence.expires_at,
            },
            ValidityCandidate {
                epoch_ms: route_reference.valid_until_epoch_ms,
                timestamp: &route_reference.valid_until,
            },
            ValidityCandidate {
                epoch_ms: request.reference_values.valid_until_epoch_ms,
                timestamp: &request.reference_values.valid_until,
            },
        ],
    )?;

    let verdict = AttestationVerdict {
        schema: AttestationVerdict::SCHEMA.into(),
        required: Vec::new(),
        check_outcomes: build_check_outcomes(&checks, &errors, &request.policy),
        route_attribution: Some(build_route_attribution(
            &request,
            Some(evidence.hardware.cpu.as_policy_str()),
        )),
        policy_schema: VerificationPolicy::SCHEMA.into(),
        reference_values_schema: ReferenceValuesPayload::SCHEMA.into(),
        provider_registry_schema: "confidential-inference.provider-registry.v1".into(),
        status,
        enforcement: request.policy.enforcement.clone(),
        request_allowed,
        would_block_under_enforce,
        trust_tier: request.route.trust_tier.clone(),
        provider: request.route.provider.clone(),
        requested_model: request.route.requested_model.clone(),
        provider_model: request.route.provider_model.clone(),
        canonical_model: request.route.canonical_model.clone(),
        route_id: request.route.route_id.clone(),
        evidence_family: request.route.evidence_family.clone(),
        alias_confidence: request.route.alias_confidence.clone(),
        adapter_version: request.route.adapter_version.clone(),
        api_endpoint: request.route.api_endpoint.clone(),
        evidence_endpoint: request.route.evidence_endpoint.clone(),
        freshness_class: request.route.freshness_class.clone(),
        streaming_allowed: request.route.streaming_allowed,
        route_execution_status: request.route_execution_status,
        chat_executable: request.chat_executable,
        known_unsupported_modes: request.known_unsupported_modes,
        channel_binding_kind: request.route.channel_binding_kind.clone(),
        model_binding_result,
        request_channel_bound: channel_verified,
        request_confidentiality_result,
        response_confidentiality_result,
        response_channel_bound: channel_verified,
        response_integrity_result,
        policy_digest,
        provider_registry_digest: request.registry_digest,
        registry_version: request.registry_version,
        registry_source: request.registry_source,
        registry_sync_completed_at: request.registry_sync_completed_at,
        registry_signature: request.registry_signature,
        reference_values_digest: request.reference_values_digest,
        reference_values_version: request.reference_values.version.clone(),
        reference_values_source: request.reference_values_source,
        reference_values_signature: request.reference_signature,
        raw_evidence_digest,
        evidence_digest,
        verified_at: evidence.issued_at,
        expires_at: validity.expires_at.clone(),
        expires_at_epoch_ms: validity.expires_at_epoch_ms,
        validity: ValidityWindow {
            policy_ttl_until: validity.policy_ttl_until,
            collateral_valid_until: validity.expires_at.clone(),
            certificate_valid_until: validity.expires_at.clone(),
            quote_valid_until: validity.expires_at.clone(),
            tcb_valid_until: validity.expires_at.clone(),
            reference_values_valid_until: request.reference_values.valid_until,
            computed_expires_at: validity.expires_at,
        },
        checks,
        artifacts: VerdictArtifacts {
            source_url: Some(request.route.evidence_endpoint),
            tee_measurement: Some(evidence.tee_measurement),
            report_data: Some(evidence.report_data),
            signing_public_key: Some(public_key_digest),
            e2ee_capability: Some("chutes-e2ee".into()),
            model_manifest: evidence.attested_model,
            model_artifacts: evidence.model_artifacts,
        },
        errors,
    };

    verdict.validate_summary_consistency()?;
    trace_verdict_completed(&verdict);
    Ok(verdict)
}

fn verify_chutes_gpu_tee(
    evidence: &ChutesE2eeEvidence,
    allowed: &[GpuTeeKind],
    gpu_attestation_verifier: &dyn GpuAttestationVerifier,
    provider: &str,
    route_id: &str,
) -> std::result::Result<(), String> {
    let actual = evidence
        .hardware
        .gpu
        .as_ref()
        .ok_or_else(|| "GPU TEE kind is not present".to_owned())?;
    if !allowed.iter().any(|candidate| candidate == actual) {
        return Err("GPU TEE kind is not accepted by policy".into());
    }

    match actual {
        GpuTeeKind::NvidiaCc => verify_chutes_nvidia_gpu_attestation(
            evidence,
            gpu_attestation_verifier,
            provider,
            route_id,
        ),
    }
}

fn verify_chutes_nvidia_gpu_attestation(
    evidence: &ChutesE2eeEvidence,
    gpu_attestation_verifier: &dyn GpuAttestationVerifier,
    provider: &str,
    route_id: &str,
) -> std::result::Result<(), String> {
    let gpu_attestation = evidence
        .gpu_attestation
        .as_ref()
        .ok_or_else(|| "NVIDIA GPU attestation evidence is missing".to_owned())?;
    if gpu_attestation.schema != NvidiaGpuAttestationEvidence::SCHEMA {
        return Err(format!(
            "unsupported NVIDIA GPU attestation schema {}",
            gpu_attestation.schema
        ));
    }
    if gpu_attestation.nonce != evidence.nonce {
        return Err("NVIDIA GPU attestation nonce does not match Chutes E2EE nonce".into());
    }

    let verified = gpu_attestation_verifier
        .verify_nvidia_gpu_attestation(&NvidiaGpuAttestationVerificationRequest {
            evidence: gpu_attestation,
            expected_nonce: &evidence.nonce,
            expected_tee: GpuTeeKind::NvidiaCc,
            provider,
            route_id,
        })
        .map_err(|error| format!("NVIDIA GPU attestation verification failed: {error}"))?;
    if verified.tee != GpuTeeKind::NvidiaCc {
        return Err("NVIDIA GPU attestation verified a different GPU TEE kind".into());
    }
    if verified.nonce != evidence.nonce {
        return Err("NVIDIA GPU attestation verified a different nonce".into());
    }
    if verified.attestation_format != gpu_attestation.attestation_format {
        return Err("NVIDIA GPU attestation format changed during verification".into());
    }

    Ok(())
}

fn chutes_e2ee_binding_error(binding: &ChutesE2eeReportDataBinding) -> &'static str {
    match binding {
        ChutesE2eeReportDataBinding::Verified => {
            "Chutes E2EE report data is bound to nonce and public key"
        }
        ChutesE2eeReportDataBinding::InvalidNonce => "Chutes E2EE nonce is not canonical hex",
        ChutesE2eeReportDataBinding::MissingPublicKey => "Chutes E2EE public key is missing",
        ChutesE2eeReportDataBinding::ReportDataMismatch => {
            "Chutes E2EE report data does not bind nonce and public key"
        }
    }
}

pub fn verify_dstack_evidence(request: VerificationRequest) -> Result<AttestationVerdict> {
    let evidence: DstackEvidence = serde_json::from_slice(&request.raw_evidence)?;
    if evidence.schema != DstackEvidence::SCHEMA {
        return Err(AttestationError::InvalidEvidence(format!(
            "unsupported schema {}",
            evidence.schema
        )));
    }

    let provider_reference = request
        .reference_values
        .providers
        .get(&request.route.provider)
        .ok_or_else(|| AttestationError::MissingProviderReference {
            provider: request.route.provider.clone(),
        })?;
    let route_reference = provider_reference
        .routes
        .get(&request.route.route_id)
        .ok_or_else(|| AttestationError::MissingRouteReference {
            route_id: request.route.route_id.clone(),
        })?;

    let mut checks = BTreeMap::new();
    let mut errors = Vec::new();

    push_check(
        &mut checks,
        &mut errors,
        "route_metadata_binding",
        evidence.provider == request.route.provider
            && evidence.route_id == request.route.route_id
            && evidence.evidence_family == request.route.evidence_family
            && route_reference.provider_model == request.route.provider_model
            && route_reference.canonical_model == request.route.canonical_model
            && route_reference.evidence_family == request.route.evidence_family,
        "evidence route metadata does not match registry/reference route",
    );
    mark_request_route_unproven(&mut checks);

    let cpu_verified = match &request.policy.hardware.cpu {
        CpuTeeRequirement::NotRequired => {
            checks.insert("cpu_tee".into(), CheckResult::NotApplicable);
            true
        }
        CpuTeeRequirement::AnyCpuTee => {
            let ok = cpu_allowed(&evidence.hardware.cpu, &route_reference.accepted_cpu_tees)
                && provider_reference
                    .accepted_measurements
                    .iter()
                    .any(|measurement| measurement == &evidence.tee_measurement);
            push_check(
                &mut checks,
                &mut errors,
                "cpu_tee",
                ok,
                "CPU TEE or measurement is not accepted by reference values",
            );
            ok
        }
        CpuTeeRequirement::OneOf { allowed } => {
            let ok = allowed
                .iter()
                .any(|candidate| candidate == &evidence.hardware.cpu)
                && cpu_allowed(&evidence.hardware.cpu, &route_reference.accepted_cpu_tees)
                && provider_reference
                    .accepted_measurements
                    .iter()
                    .any(|measurement| measurement == &evidence.tee_measurement);
            push_check(
                &mut checks,
                &mut errors,
                "cpu_tee",
                ok,
                "CPU TEE kind or measurement is not accepted by policy/reference values",
            );
            ok
        }
    };

    let tcb_binding = verify_dstack_tcb_compose_hash(
        Some(&evidence.tcb_info),
        Some(&evidence.quote_measurements),
    );
    let tcb_verified = tcb_binding == TcbComposeHashBinding::Verified;
    tracing::debug!(
        tcb_binding = ?tcb_binding,
        tcb_verified,
        "dstack TCB compose hash checked"
    );
    push_check(
        &mut checks,
        &mut errors,
        "tcb_compose_hash",
        tcb_verified,
        "dstack tcb_info is not bound to quote measurements or compose_hash",
    );
    let hardware_verified = cpu_verified && tcb_verified;

    checks.insert("gpu_tee".into(), CheckResult::NotApplicable);
    checks.insert("tls_binding".into(), CheckResult::NotApplicable);

    let channel_reference_matches = request
        .route
        .channel_binding_kind
        .satisfies(&request.policy.channel_binding_requirement)
        && evidence
            .channel_binding
            .kind
            .satisfies(&request.policy.channel_binding_requirement)
        && evidence.channel_binding.kind == route_reference.channel_binding_kind
        && evidence.channel_binding.public_key_digest == route_reference.e2ee_public_key_digest;
    tracing::debug!(
        channel_reference_matches,
        "dstack E2EE channel reference checked"
    );
    push_check(
        &mut checks,
        &mut errors,
        "e2ee_key_reference_match",
        channel_reference_matches,
        "channel key metadata does not match signed reference values",
    );
    let channel_verified = matches!(
        request.policy.channel_binding_requirement,
        ChannelBindingRequirement::NotRequired
    );
    match request.policy.channel_binding_requirement {
        ChannelBindingRequirement::NotRequired => {
            checks.insert("e2ee_key_binding".into(), CheckResult::NotApplicable);
        }
        _ => {
            checks.insert("e2ee_key_binding".into(), CheckResult::NotSupported);
        }
    }

    // The provider response can declare request_bound/response_bound, but this
    // verifier has no request ciphertext or response receipt to prove either
    // claim. Keep the result unknown until the execution layer supplies proof.
    let request_confidentiality_result = ConfidentialityResult::Unknown;
    let response_confidentiality_result = ConfidentialityResult::Unknown;
    let response_integrity_result = ResponseIntegrityResult::Unknown;

    if request.policy.request_confidentiality_requirement
        == crate::BoundDataRequirement::NotRequired
    {
        checks.insert("request_key_binding".into(), CheckResult::NotApplicable);
    } else {
        push_check(
            &mut checks,
            &mut errors,
            "request_key_binding",
            false,
            "request confidentiality is not bound to the attested workload",
        );
    }
    checks.insert(
        "request_encryption".into(),
        if request.policy.request_confidentiality_requirement
            == crate::BoundDataRequirement::NotRequired
        {
            CheckResult::NotApplicable
        } else {
            CheckResult::Unknown
        },
    );

    if request.policy.response_confidentiality_requirement
        == crate::BoundDataRequirement::NotRequired
    {
        checks.insert("response_key_binding".into(), CheckResult::NotApplicable);
    } else {
        push_check(
            &mut checks,
            &mut errors,
            "response_key_binding",
            false,
            "response confidentiality is not bound to the attested workload",
        );
    }
    checks.insert(
        "response_encryption".into(),
        if request.policy.response_confidentiality_requirement
            == crate::BoundDataRequirement::NotRequired
        {
            CheckResult::NotApplicable
        } else {
            CheckResult::Unknown
        },
    );

    if request.policy.response_integrity_requirement
        == crate::ResponseIntegrityRequirement::NotRequired
    {
        checks.insert(
            "response_channel_binding".into(),
            CheckResult::NotApplicable,
        );
    } else {
        push_check(
            &mut checks,
            &mut errors,
            "response_channel_binding",
            false,
            "response bytes are not cryptographically bound as required by policy",
        );
    }
    checks.insert("response_receipt".into(), CheckResult::NotApplicable);
    checks.insert("nonce_binding".into(), CheckResult::NotApplicable);

    let model_binding_verified = evidence.attested_model.as_deref()
        == Some(request.route.canonical_model.as_str())
        && route_reference.canonical_model == request.route.canonical_model;
    let provider_supports_model_binding = evidence.attested_model.is_some();
    let model_binding_result = push_model_binding_check(
        &mut checks,
        &mut errors,
        &request.policy.model_binding_requirement,
        provider_supports_model_binding,
        model_binding_verified,
    );

    let provenance_required = request.policy.provenance.workload_image
        || request.policy.provenance.model_artifacts
        || request.policy.provenance.reproducible_build
        || request.policy.provenance.source_attestation
        || request.policy.provenance.dependency_sbom;
    if provenance_required {
        let workload_manifest_bound =
            crate::parse_dstack_workload_images(&evidence.tcb_info.app_compose)
                .map(|manifest| manifest == evidence.workload_images)
                .unwrap_or(false);
        push_check(
            &mut checks,
            &mut errors,
            "workload_manifest_binding",
            workload_manifest_bound,
            "workload image manifest is not completely derived from the quote-bound compose document",
        );
        push_check(
            &mut checks,
            &mut errors,
            "image_provenance",
            !evidence.workload_images.is_empty()
                && evidence
                    .workload_images
                    .iter()
                    .all(crate::WorkloadImage::is_digest_pinned)
                && evidence.workload_images == route_reference.workload_images,
            "complete digest-pinned workload image manifest does not match reference values",
        );
        push_check(
            &mut checks,
            &mut errors,
            "model_artifact_provenance",
            route_reference.model_artifacts.iter().all(|expected| {
                evidence
                    .model_artifacts
                    .iter()
                    .any(|actual| actual == expected)
            }),
            "model artifact digests do not match reference values",
        );
    } else {
        checks.insert(
            "workload_manifest_binding".into(),
            CheckResult::NotApplicable,
        );
        checks.insert("image_provenance".into(), CheckResult::NotApplicable);
        checks.insert(
            "model_artifact_provenance".into(),
            CheckResult::NotApplicable,
        );
    }
    push_unsupported_provenance_checks(&mut checks, &mut errors, &request.policy);

    push_per_request_freshness_check(&mut checks, &mut errors, &request.policy);

    let failed_required = checks.values().any(|check| *check == CheckResult::Failed);
    let would_block_under_enforce = failed_required;
    let request_allowed = match request.policy.enforcement {
        EnforcementMode::Disabled | EnforcementMode::Observe => true,
        EnforcementMode::Enforce => !failed_required,
    };

    let status = match request.policy.enforcement {
        EnforcementMode::Disabled => VerificationStatus::Disabled,
        _ if failed_required => VerificationStatus::Failed,
        _ if hardware_verified && channel_verified => VerificationStatus::Verified,
        _ => VerificationStatus::Partial,
    };
    // `request.route.trust_tier` is the registry's advertised capability. This
    // evidence path proves the TEE, but it does not cryptographically bind
    // request/response bytes to the advertised app-E2EE key. Report only the
    // achieved tier so a hardware-only policy cannot overstate its verdict.
    let achieved_trust_tier = if hardware_verified {
        TrustTier::TeeOnly
    } else {
        TrustTier::None
    };

    let raw_evidence_digest = sha256_digest(&request.raw_evidence);
    let evidence_digest = canonical_digest(&evidence)?;
    let policy_digest = request.policy.digest()?;
    let validity = compute_validity_bounds(
        &evidence.issued_at,
        request.policy.verdict_ttl_millis.0,
        [
            ValidityCandidate {
                epoch_ms: evidence.expires_at_epoch_ms,
                timestamp: &evidence.expires_at,
            },
            ValidityCandidate {
                epoch_ms: route_reference.valid_until_epoch_ms,
                timestamp: &route_reference.valid_until,
            },
            ValidityCandidate {
                epoch_ms: request.reference_values.valid_until_epoch_ms,
                timestamp: &request.reference_values.valid_until,
            },
        ],
    )?;

    let verdict = AttestationVerdict {
        schema: AttestationVerdict::SCHEMA.into(),
        required: Vec::new(),
        check_outcomes: build_check_outcomes(&checks, &errors, &request.policy),
        route_attribution: Some(build_route_attribution(
            &request,
            Some(evidence.hardware.cpu.as_policy_str()),
        )),
        policy_schema: VerificationPolicy::SCHEMA.into(),
        reference_values_schema: ReferenceValuesPayload::SCHEMA.into(),
        provider_registry_schema: "confidential-inference.provider-registry.v1".into(),
        status,
        enforcement: request.policy.enforcement.clone(),
        request_allowed,
        would_block_under_enforce,
        trust_tier: achieved_trust_tier,
        provider: request.route.provider.clone(),
        requested_model: request.route.requested_model.clone(),
        provider_model: request.route.provider_model.clone(),
        canonical_model: request.route.canonical_model.clone(),
        route_id: request.route.route_id.clone(),
        evidence_family: request.route.evidence_family.clone(),
        alias_confidence: request.route.alias_confidence.clone(),
        adapter_version: request.route.adapter_version.clone(),
        api_endpoint: request.route.api_endpoint.clone(),
        evidence_endpoint: request.route.evidence_endpoint.clone(),
        freshness_class: request.route.freshness_class.clone(),
        streaming_allowed: request.route.streaming_allowed,
        route_execution_status: request.route_execution_status,
        chat_executable: request.chat_executable,
        known_unsupported_modes: request.known_unsupported_modes,
        channel_binding_kind: request.route.channel_binding_kind.clone(),
        model_binding_result,
        request_channel_bound: false,
        request_confidentiality_result,
        response_confidentiality_result,
        response_channel_bound: false,
        response_integrity_result,
        policy_digest,
        provider_registry_digest: request.registry_digest,
        registry_version: request.registry_version,
        registry_source: request.registry_source,
        registry_sync_completed_at: request.registry_sync_completed_at,
        registry_signature: request.registry_signature,
        reference_values_digest: request.reference_values_digest,
        reference_values_version: request.reference_values.version.clone(),
        reference_values_source: request.reference_values_source,
        reference_values_signature: request.reference_signature,
        raw_evidence_digest,
        evidence_digest,
        verified_at: evidence.issued_at,
        expires_at: validity.expires_at.clone(),
        expires_at_epoch_ms: validity.expires_at_epoch_ms,
        validity: ValidityWindow {
            policy_ttl_until: validity.policy_ttl_until,
            collateral_valid_until: validity.expires_at.clone(),
            certificate_valid_until: validity.expires_at.clone(),
            quote_valid_until: validity.expires_at.clone(),
            tcb_valid_until: validity.expires_at.clone(),
            reference_values_valid_until: request.reference_values.valid_until,
            computed_expires_at: validity.expires_at,
        },
        checks,
        artifacts: VerdictArtifacts {
            source_url: Some(request.route.evidence_endpoint),
            tee_measurement: Some(evidence.tee_measurement),
            report_data: Some(evidence.channel_binding.public_key_digest),
            signing_public_key: None,
            e2ee_capability: Some("dstack-e2ee".into()),
            model_manifest: evidence.attested_model,
            model_artifacts: evidence.model_artifacts,
        },
        errors,
    };

    verdict.validate_summary_consistency()?;
    trace_verdict_completed(&verdict);
    Ok(verdict)
}

pub fn verify_tinfoil_tls_evidence(request: VerificationRequest) -> Result<AttestationVerdict> {
    verify_tinfoil_tls_evidence_with_quote_verifier(request, &FailClosedTinfoilQuoteVerifier)
}

pub fn verify_tinfoil_tls_evidence_with_quote_verifier(
    request: VerificationRequest,
    tinfoil_quote_verifier: &dyn TinfoilQuoteVerifier,
) -> Result<AttestationVerdict> {
    let raw_schema = serde_json::from_slice::<serde_json::Value>(&request.raw_evidence)
        .ok()
        .and_then(|value| {
            value
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        });
    if raw_schema.as_deref() == Some(TinfoilLiveCaptureEvidence::SCHEMA) {
        return verify_tinfoil_live_capture_with_quote_verifier(request, tinfoil_quote_verifier);
    }

    let evidence: TinfoilTlsEvidence = serde_json::from_slice(&request.raw_evidence)?;
    if evidence.schema != TinfoilTlsEvidence::SCHEMA {
        return Err(AttestationError::InvalidEvidence(format!(
            "unsupported schema {}",
            evidence.schema
        )));
    }
    let raw_evidence_digest = sha256_digest(&request.raw_evidence);
    let evidence = VerifiedTinfoilTlsEvidence::from_structured(evidence)?;

    verify_tinfoil_verified_evidence(request, evidence, raw_evidence_digest)
}

pub fn verify_tinfoil_live_capture_with_quote_verifier(
    request: VerificationRequest,
    tinfoil_quote_verifier: &dyn TinfoilQuoteVerifier,
) -> Result<AttestationVerdict> {
    let raw_evidence_digest = sha256_digest(&request.raw_evidence);
    let parsed = crate::parse_tinfoil_live_capture(&request.raw_evidence)?;
    validate_tinfoil_live_capture_binding(&parsed, &request)?;
    let quote_request = TinfoilQuoteVerificationRequest {
        capture: &parsed.capture,
        attestation_format: parsed.attestation_format,
        quote_bytes: &parsed.quote_bytes,
        live_tls_leaf_certificate_der: &parsed.live_tls_leaf_certificate_der,
        live_tls_spki_sha256: &parsed.capture.live_tls_spki_sha256,
    };
    let verified_quote = tinfoil_quote_verifier.verify_tinfoil_quote(&quote_request)?;
    let evidence = VerifiedTinfoilTlsEvidence::from_live_capture(&parsed, verified_quote)?;

    verify_tinfoil_verified_evidence(request, evidence, raw_evidence_digest)
}

#[derive(serde::Serialize)]
struct TinfoilLiveVerifiedEvidenceDigest<'a> {
    schema: &'static str,
    capture: &'a TinfoilLiveCaptureEvidence,
    verified_quote: &'a VerifiedTinfoilQuote,
}

#[derive(Clone, Debug)]
struct VerifiedTinfoilTlsEvidence {
    provider: String,
    route_id: String,
    evidence_family: String,
    tee_measurement: String,
    hardware: crate::EvidenceHardware,
    report_data: String,
    leaf_certificate_der_base64: String,
    attested_model: Option<String>,
    workload_image_digest: Option<String>,
    model_artifacts: Vec<crate::ArtifactDigest>,
    issued_at: String,
    expires_at: String,
    expires_at_epoch_ms: u64,
    evidence_digest: String,
}

impl VerifiedTinfoilTlsEvidence {
    fn from_structured(evidence: TinfoilTlsEvidence) -> Result<Self> {
        let evidence_digest = canonical_digest(&evidence)?;
        Ok(Self {
            provider: evidence.provider,
            route_id: evidence.route_id,
            evidence_family: evidence.evidence_family,
            tee_measurement: evidence.tee_measurement,
            hardware: evidence.hardware,
            report_data: evidence.report_data,
            leaf_certificate_der_base64: evidence.leaf_certificate_der_base64,
            attested_model: Some(evidence.attested_model),
            workload_image_digest: Some(evidence.workload_image_digest),
            model_artifacts: evidence.model_artifacts,
            issued_at: evidence.issued_at,
            expires_at: evidence.expires_at,
            expires_at_epoch_ms: evidence.expires_at_epoch_ms,
            evidence_digest,
        })
    }

    fn from_live_capture(
        parsed: &ParsedTinfoilLiveCapture,
        verified_quote: VerifiedTinfoilQuote,
    ) -> Result<Self> {
        let returned_format =
            crate::TinfoilAttestationFormat::parse(verified_quote.attestation_format.as_str())?;
        if returned_format != parsed.attestation_format {
            return Err(AttestationError::InvalidEvidence(
                "Tinfoil quote verifier returned a different attestation format".into(),
            ));
        }
        if verified_quote.hardware.cpu != parsed.attestation_format.cpu_kind() {
            return Err(AttestationError::InvalidEvidence(format!(
                "Tinfoil quote verifier returned {} hardware for {} capture",
                verified_quote.hardware.cpu.as_policy_str(),
                parsed.attestation_format.quote_kind()
            )));
        }
        if verified_quote.tee_measurement.trim().is_empty() {
            return Err(AttestationError::InvalidEvidence(
                "Tinfoil quote verifier returned an empty TEE measurement".into(),
            ));
        }

        let evidence_digest = canonical_digest(&TinfoilLiveVerifiedEvidenceDigest {
            schema: "confidential-inference.tinfoil-live-verified-evidence.v1",
            capture: &parsed.capture,
            verified_quote: &verified_quote,
        })?;

        Ok(Self {
            provider: parsed.capture.provider.clone(),
            route_id: parsed.capture.route_id.clone(),
            evidence_family: parsed.capture.evidence_family.clone(),
            tee_measurement: verified_quote.tee_measurement,
            hardware: verified_quote.hardware,
            report_data: verified_quote.report_data,
            leaf_certificate_der_base64: parsed
                .capture
                .live_tls_leaf_certificate_der_base64
                .clone(),
            attested_model: verified_quote.attested_model,
            workload_image_digest: verified_quote.workload_image_digest,
            model_artifacts: verified_quote.model_artifacts,
            issued_at: verified_quote.issued_at,
            expires_at: verified_quote.expires_at,
            expires_at_epoch_ms: verified_quote.expires_at_epoch_ms,
            evidence_digest,
        })
    }
}

fn verify_tinfoil_verified_evidence(
    request: VerificationRequest,
    evidence: VerifiedTinfoilTlsEvidence,
    raw_evidence_digest: String,
) -> Result<AttestationVerdict> {
    let provider_reference = request
        .reference_values
        .providers
        .get(&request.route.provider)
        .ok_or_else(|| AttestationError::MissingProviderReference {
            provider: request.route.provider.clone(),
        })?;
    let route_reference = provider_reference
        .routes
        .get(&request.route.route_id)
        .ok_or_else(|| AttestationError::MissingRouteReference {
            route_id: request.route.route_id.clone(),
        })?;

    let mut checks = BTreeMap::new();
    let mut errors = Vec::new();

    push_check(
        &mut checks,
        &mut errors,
        "route_metadata_binding",
        evidence.provider == request.route.provider
            && evidence.route_id == request.route.route_id
            && evidence.evidence_family == request.route.evidence_family
            && route_reference.provider_model == request.route.provider_model
            && route_reference.canonical_model == request.route.canonical_model
            && route_reference.evidence_family == request.route.evidence_family,
        "evidence route metadata does not match registry/reference route",
    );
    mark_request_route_unproven(&mut checks);

    let hardware_verified = match &request.policy.hardware.cpu {
        CpuTeeRequirement::NotRequired => {
            checks.insert("cpu_tee".into(), CheckResult::NotApplicable);
            true
        }
        CpuTeeRequirement::AnyCpuTee => {
            let ok = cpu_allowed(&evidence.hardware.cpu, &route_reference.accepted_cpu_tees)
                && provider_reference
                    .accepted_measurements
                    .iter()
                    .any(|measurement| measurement == &evidence.tee_measurement);
            push_check(
                &mut checks,
                &mut errors,
                "cpu_tee",
                ok,
                "CPU TEE or measurement is not accepted by reference values",
            );
            ok
        }
        CpuTeeRequirement::OneOf { allowed } => {
            let ok = allowed
                .iter()
                .any(|candidate| candidate == &evidence.hardware.cpu)
                && cpu_allowed(&evidence.hardware.cpu, &route_reference.accepted_cpu_tees)
                && provider_reference
                    .accepted_measurements
                    .iter()
                    .any(|measurement| measurement == &evidence.tee_measurement);
            push_check(
                &mut checks,
                &mut errors,
                "cpu_tee",
                ok,
                "CPU TEE kind or measurement is not accepted by policy/reference values",
            );
            ok
        }
    };

    checks.insert("gpu_tee".into(), CheckResult::NotApplicable);
    checks.insert("e2ee_key_binding".into(), CheckResult::NotApplicable);

    let certificate_der = base64::engine::general_purpose::STANDARD
        .decode(&evidence.leaf_certificate_der_base64)
        .map_err(|err| {
            AttestationError::InvalidEvidence(format!("leaf certificate DER is not base64: {err}"))
        })?;
    let spki_sha256 = certificate_spki_sha256_hex(&certificate_der)?;
    let report_data_binding =
        verify_tls_spki_report_data_binding(&evidence.report_data, &spki_sha256);
    let reference_spki_matches = route_reference
        .tls_spki_sha256
        .as_deref()
        .and_then(strip_sha256_prefix)
        .map(|expected| expected.eq_ignore_ascii_case(&spki_sha256))
        .unwrap_or(false);
    let tls_binding_verified = request
        .route
        .channel_binding_kind
        .satisfies(&request.policy.channel_binding_requirement)
        && route_reference.channel_binding_kind == request.route.channel_binding_kind
        && route_reference
            .channel_binding_kind
            .satisfies(&request.policy.channel_binding_requirement)
        && report_data_binding
            .as_ref()
            .map(|binding| binding.matches)
            .unwrap_or(false)
        && reference_spki_matches;
    tracing::debug!(
        tls_binding_verified,
        reference_spki_matches,
        report_data_binding_matches = report_data_binding
            .as_ref()
            .map(|binding| binding.matches)
            .unwrap_or(false),
        "Tinfoil TLS binding checked"
    );
    push_check(
        &mut checks,
        &mut errors,
        "tls_binding",
        tls_binding_verified,
        "TLS certificate SPKI is not bound to attested report data and reference values",
    );

    let request_confidentiality_result = if tls_binding_verified {
        ConfidentialityResult::ChannelBound
    } else {
        ConfidentialityResult::NotBound
    };
    let response_confidentiality_result = if tls_binding_verified {
        ConfidentialityResult::ChannelBound
    } else {
        ConfidentialityResult::NotBound
    };
    let response_integrity_result = if tls_binding_verified {
        ResponseIntegrityResult::ChannelBound
    } else {
        ResponseIntegrityResult::NotBound
    };

    push_check(
        &mut checks,
        &mut errors,
        "request_key_binding",
        request_confidentiality_result
            .satisfies(&request.policy.request_confidentiality_requirement),
        "request confidentiality is not bound to the attested workload",
    );
    checks.insert(
        "request_encryption".into(),
        if tls_binding_verified {
            CheckResult::Verified
        } else {
            CheckResult::Failed
        },
    );

    push_check(
        &mut checks,
        &mut errors,
        "response_key_binding",
        response_confidentiality_result
            .satisfies(&request.policy.response_confidentiality_requirement),
        "response confidentiality is not bound to the attested workload",
    );
    checks.insert(
        "response_encryption".into(),
        if tls_binding_verified {
            CheckResult::Verified
        } else {
            CheckResult::Failed
        },
    );

    push_check(
        &mut checks,
        &mut errors,
        "response_channel_binding",
        response_integrity_result.satisfies(&request.policy.response_integrity_requirement),
        "response bytes are not cryptographically bound as required by policy",
    );
    checks.insert("response_receipt".into(), CheckResult::NotApplicable);
    checks.insert("nonce_binding".into(), CheckResult::NotApplicable);

    let model_binding_verified = evidence
        .attested_model
        .as_deref()
        .map(|model| {
            model == request.route.canonical_model
                && route_reference.canonical_model == request.route.canonical_model
        })
        .unwrap_or(false);
    let model_binding_result = match &request.policy.model_binding_requirement {
        ModelBindingRequirement::NotRequired => {
            checks.insert("model_binding".into(), CheckResult::NotApplicable);
            ModelBindingResult::NotSupported
        }
        ModelBindingRequirement::IfProviderSupports if evidence.attested_model.is_none() => {
            checks.insert("model_binding".into(), CheckResult::NotSupported);
            ModelBindingResult::NotSupported
        }
        ModelBindingRequirement::IfProviderSupports | ModelBindingRequirement::Required => {
            push_check(
                &mut checks,
                &mut errors,
                "model_binding",
                model_binding_verified,
                "attested model identity does not match the requested canonical model",
            );
            if model_binding_verified {
                ModelBindingResult::Verified
            } else {
                ModelBindingResult::Failed
            }
        }
    };

    let provenance_required = request.policy.provenance.workload_image
        || request.policy.provenance.model_artifacts
        || request.policy.provenance.reproducible_build
        || request.policy.provenance.source_attestation
        || request.policy.provenance.dependency_sbom;
    if provenance_required {
        push_check(
            &mut checks,
            &mut errors,
            "image_provenance",
            evidence.workload_image_digest.as_deref()
                == Some(route_reference.workload_image_digest.as_str()),
            "workload image digest does not match reference values",
        );
        push_check(
            &mut checks,
            &mut errors,
            "model_artifact_provenance",
            route_reference.model_artifacts.iter().all(|expected| {
                evidence
                    .model_artifacts
                    .iter()
                    .any(|actual| actual == expected)
            }),
            "model artifact digests do not match reference values",
        );
    } else {
        checks.insert("image_provenance".into(), CheckResult::NotApplicable);
        checks.insert(
            "model_artifact_provenance".into(),
            CheckResult::NotApplicable,
        );
    }
    push_unsupported_provenance_checks(&mut checks, &mut errors, &request.policy);

    push_per_request_freshness_check(&mut checks, &mut errors, &request.policy);

    let failed_required = checks.values().any(|check| *check == CheckResult::Failed);
    let would_block_under_enforce = failed_required;
    let request_allowed = match request.policy.enforcement {
        EnforcementMode::Disabled | EnforcementMode::Observe => true,
        EnforcementMode::Enforce => !failed_required,
    };

    let status = match request.policy.enforcement {
        EnforcementMode::Disabled => VerificationStatus::Disabled,
        _ if failed_required => VerificationStatus::Failed,
        _ if hardware_verified && tls_binding_verified => VerificationStatus::Verified,
        _ => VerificationStatus::Partial,
    };

    let evidence_digest = evidence.evidence_digest.clone();
    let policy_digest = request.policy.digest()?;
    let validity = compute_validity_bounds(
        &evidence.issued_at,
        request.policy.verdict_ttl_millis.0,
        [
            ValidityCandidate {
                epoch_ms: evidence.expires_at_epoch_ms,
                timestamp: &evidence.expires_at,
            },
            ValidityCandidate {
                epoch_ms: route_reference.valid_until_epoch_ms,
                timestamp: &route_reference.valid_until,
            },
            ValidityCandidate {
                epoch_ms: request.reference_values.valid_until_epoch_ms,
                timestamp: &request.reference_values.valid_until,
            },
        ],
    )?;

    let verdict = AttestationVerdict {
        schema: AttestationVerdict::SCHEMA.into(),
        required: Vec::new(),
        check_outcomes: build_check_outcomes(&checks, &errors, &request.policy),
        route_attribution: Some(build_route_attribution(
            &request,
            Some(evidence.hardware.cpu.as_policy_str()),
        )),
        policy_schema: VerificationPolicy::SCHEMA.into(),
        reference_values_schema: ReferenceValuesPayload::SCHEMA.into(),
        provider_registry_schema: "confidential-inference.provider-registry.v1".into(),
        status,
        enforcement: request.policy.enforcement.clone(),
        request_allowed,
        would_block_under_enforce,
        trust_tier: request.route.trust_tier.clone(),
        provider: request.route.provider.clone(),
        requested_model: request.route.requested_model.clone(),
        provider_model: request.route.provider_model.clone(),
        canonical_model: request.route.canonical_model.clone(),
        route_id: request.route.route_id.clone(),
        evidence_family: request.route.evidence_family.clone(),
        alias_confidence: request.route.alias_confidence.clone(),
        adapter_version: request.route.adapter_version.clone(),
        api_endpoint: request.route.api_endpoint.clone(),
        evidence_endpoint: request.route.evidence_endpoint.clone(),
        freshness_class: request.route.freshness_class.clone(),
        streaming_allowed: request.route.streaming_allowed,
        route_execution_status: request.route_execution_status,
        chat_executable: request.chat_executable,
        known_unsupported_modes: request.known_unsupported_modes,
        channel_binding_kind: request.route.channel_binding_kind.clone(),
        model_binding_result,
        request_channel_bound: tls_binding_verified,
        request_confidentiality_result,
        response_confidentiality_result,
        response_channel_bound: tls_binding_verified,
        response_integrity_result,
        policy_digest,
        provider_registry_digest: request.registry_digest,
        registry_version: request.registry_version,
        registry_source: request.registry_source,
        registry_sync_completed_at: request.registry_sync_completed_at,
        registry_signature: request.registry_signature,
        reference_values_digest: request.reference_values_digest,
        reference_values_version: request.reference_values.version.clone(),
        reference_values_source: request.reference_values_source,
        reference_values_signature: request.reference_signature,
        raw_evidence_digest,
        evidence_digest,
        verified_at: evidence.issued_at,
        expires_at: validity.expires_at.clone(),
        expires_at_epoch_ms: validity.expires_at_epoch_ms,
        validity: ValidityWindow {
            policy_ttl_until: validity.policy_ttl_until,
            collateral_valid_until: validity.expires_at.clone(),
            certificate_valid_until: validity.expires_at.clone(),
            quote_valid_until: validity.expires_at.clone(),
            tcb_valid_until: validity.expires_at.clone(),
            reference_values_valid_until: request.reference_values.valid_until,
            computed_expires_at: validity.expires_at,
        },
        checks,
        artifacts: VerdictArtifacts {
            source_url: Some(request.route.evidence_endpoint),
            tee_measurement: Some(evidence.tee_measurement),
            report_data: Some(evidence.report_data),
            signing_public_key: Some(format!("sha256:{spki_sha256}")),
            e2ee_capability: None,
            model_manifest: evidence.attested_model,
            model_artifacts: evidence.model_artifacts,
        },
        errors,
    };

    verdict.validate_summary_consistency()?;
    trace_verdict_completed(&verdict);
    Ok(verdict)
}

fn validate_tinfoil_live_capture_binding(
    parsed: &ParsedTinfoilLiveCapture,
    request: &VerificationRequest,
) -> Result<()> {
    let capture = &parsed.capture;
    let policy_digest = request.policy.digest()?;
    if capture.provider != request.route.provider
        || capture.route_id != request.route.route_id
        || capture.evidence_family != request.route.evidence_family
        || capture.requested_model != request.route.requested_model
        || capture.evidence_endpoint != request.route.evidence_endpoint
        || capture.policy_digest != policy_digest
    {
        return Err(AttestationError::InvalidEvidence(
            "live Tinfoil capture metadata does not match verification request".into(),
        ));
    }

    Ok(())
}

pub fn verify_fixture_evidence(request: VerificationRequest) -> Result<AttestationVerdict> {
    let evidence: FixtureEvidence = serde_json::from_slice(&request.raw_evidence)?;
    if evidence.schema != FixtureEvidence::SCHEMA {
        return Err(AttestationError::InvalidEvidence(format!(
            "unsupported schema {}",
            evidence.schema
        )));
    }

    let provider_reference = request
        .reference_values
        .providers
        .get(&request.route.provider)
        .ok_or_else(|| AttestationError::MissingProviderReference {
            provider: request.route.provider.clone(),
        })?;
    let route_reference = provider_reference
        .routes
        .get(&request.route.route_id)
        .ok_or_else(|| AttestationError::MissingRouteReference {
            route_id: request.route.route_id.clone(),
        })?;

    let mut checks = BTreeMap::new();
    let mut errors = Vec::new();

    push_check(
        &mut checks,
        &mut errors,
        "route_metadata_binding",
        evidence.provider == request.route.provider
            && evidence.route_id == request.route.route_id
            && evidence.evidence_family == request.route.evidence_family
            && route_reference.provider_model == request.route.provider_model
            && route_reference.canonical_model == request.route.canonical_model
            && route_reference.evidence_family == request.route.evidence_family,
        "evidence route metadata does not match registry/reference route",
    );
    mark_request_route_unproven(&mut checks);

    let hardware_verified = match &request.policy.hardware.cpu {
        CpuTeeRequirement::NotRequired => {
            checks.insert("cpu_tee".into(), CheckResult::NotApplicable);
            true
        }
        CpuTeeRequirement::AnyCpuTee => {
            let ok = cpu_allowed(&evidence.hardware.cpu, &route_reference.accepted_cpu_tees)
                && provider_reference
                    .accepted_measurements
                    .iter()
                    .any(|measurement| measurement == &evidence.tee_measurement);
            push_check(
                &mut checks,
                &mut errors,
                "cpu_tee",
                ok,
                "CPU TEE or measurement is not accepted by reference values",
            );
            ok
        }
        CpuTeeRequirement::OneOf { allowed } => {
            let ok = allowed
                .iter()
                .any(|candidate| candidate == &evidence.hardware.cpu)
                && cpu_allowed(&evidence.hardware.cpu, &route_reference.accepted_cpu_tees)
                && provider_reference
                    .accepted_measurements
                    .iter()
                    .any(|measurement| measurement == &evidence.tee_measurement);
            push_check(
                &mut checks,
                &mut errors,
                "cpu_tee",
                ok,
                "CPU TEE kind or measurement is not accepted by policy/reference values",
            );
            ok
        }
    };

    checks.insert("gpu_tee".into(), CheckResult::NotApplicable);
    checks.insert("tls_binding".into(), CheckResult::NotApplicable);

    let channel_verified = request
        .route
        .channel_binding_kind
        .satisfies(&request.policy.channel_binding_requirement)
        && evidence
            .channel_binding
            .kind
            .satisfies(&request.policy.channel_binding_requirement)
        && evidence.channel_binding.kind == route_reference.channel_binding_kind
        && evidence.channel_binding.public_key_digest == route_reference.e2ee_public_key_digest;
    tracing::debug!(channel_verified, "fixture channel binding checked");
    match request.policy.channel_binding_requirement {
        ChannelBindingRequirement::NotRequired => {
            checks.insert("e2ee_key_binding".into(), CheckResult::NotApplicable);
        }
        _ => {
            push_check(
                &mut checks,
                &mut errors,
                "e2ee_key_binding",
                channel_verified,
                "attested channel key is missing or does not match reference values",
            );
        }
    }

    let request_confidentiality_result = if evidence.channel_binding.request_bound {
        ConfidentialityResult::EncryptedBound
    } else {
        ConfidentialityResult::NotBound
    };
    let response_confidentiality_result = if evidence.channel_binding.response_bound {
        ConfidentialityResult::EncryptedBound
    } else {
        ConfidentialityResult::NotBound
    };
    let response_integrity_result = if evidence.channel_binding.response_bound {
        ResponseIntegrityResult::ChannelBound
    } else {
        ResponseIntegrityResult::NotBound
    };

    push_check(
        &mut checks,
        &mut errors,
        "request_key_binding",
        request_confidentiality_result
            .satisfies(&request.policy.request_confidentiality_requirement),
        "request confidentiality is not bound to the attested workload",
    );
    checks.insert(
        "request_encryption".into(),
        if evidence.channel_binding.request_bound {
            CheckResult::Verified
        } else {
            CheckResult::Failed
        },
    );

    push_check(
        &mut checks,
        &mut errors,
        "response_key_binding",
        response_confidentiality_result
            .satisfies(&request.policy.response_confidentiality_requirement),
        "response confidentiality is not bound to the attested workload",
    );
    checks.insert(
        "response_encryption".into(),
        if evidence.channel_binding.response_bound {
            CheckResult::Verified
        } else {
            CheckResult::Failed
        },
    );

    push_check(
        &mut checks,
        &mut errors,
        "response_channel_binding",
        response_integrity_result.satisfies(&request.policy.response_integrity_requirement),
        "response bytes are not cryptographically bound as required by policy",
    );
    checks.insert("response_receipt".into(), CheckResult::NotApplicable);
    checks.insert("nonce_binding".into(), CheckResult::NotApplicable);

    let model_binding_verified = evidence.attested_model == request.route.canonical_model
        && route_reference.canonical_model == request.route.canonical_model;
    let model_binding_result = push_model_binding_check(
        &mut checks,
        &mut errors,
        &request.policy.model_binding_requirement,
        true,
        model_binding_verified,
    );

    let provenance_required = request.policy.provenance.workload_image
        || request.policy.provenance.model_artifacts
        || request.policy.provenance.reproducible_build
        || request.policy.provenance.source_attestation
        || request.policy.provenance.dependency_sbom;
    if provenance_required {
        push_check(
            &mut checks,
            &mut errors,
            "image_provenance",
            evidence.workload_image_digest == route_reference.workload_image_digest,
            "workload image digest does not match reference values",
        );
        push_check(
            &mut checks,
            &mut errors,
            "model_artifact_provenance",
            route_reference.model_artifacts.iter().all(|expected| {
                evidence
                    .model_artifacts
                    .iter()
                    .any(|actual| actual == expected)
            }),
            "model artifact digests do not match reference values",
        );
    } else {
        checks.insert("image_provenance".into(), CheckResult::NotApplicable);
        checks.insert(
            "model_artifact_provenance".into(),
            CheckResult::NotApplicable,
        );
    }
    push_unsupported_provenance_checks(&mut checks, &mut errors, &request.policy);

    push_per_request_freshness_check(&mut checks, &mut errors, &request.policy);

    let failed_required = checks.values().any(|check| *check == CheckResult::Failed);
    let would_block_under_enforce = failed_required;
    let request_allowed = match request.policy.enforcement {
        EnforcementMode::Disabled | EnforcementMode::Observe => true,
        EnforcementMode::Enforce => !failed_required,
    };

    let status = match request.policy.enforcement {
        EnforcementMode::Disabled => VerificationStatus::Disabled,
        _ if failed_required => VerificationStatus::Failed,
        _ if hardware_verified && channel_verified => VerificationStatus::Verified,
        _ => VerificationStatus::Partial,
    };

    let raw_evidence_digest = sha256_digest(&request.raw_evidence);
    let evidence_digest = canonical_digest(&evidence)?;
    let policy_digest = request.policy.digest()?;
    let validity = compute_validity_bounds(
        &evidence.issued_at,
        request.policy.verdict_ttl_millis.0,
        [
            ValidityCandidate {
                epoch_ms: evidence.expires_at_epoch_ms,
                timestamp: &evidence.expires_at,
            },
            ValidityCandidate {
                epoch_ms: route_reference.valid_until_epoch_ms,
                timestamp: &route_reference.valid_until,
            },
            ValidityCandidate {
                epoch_ms: request.reference_values.valid_until_epoch_ms,
                timestamp: &request.reference_values.valid_until,
            },
        ],
    )?;

    let verdict = AttestationVerdict {
        schema: AttestationVerdict::SCHEMA.into(),
        required: Vec::new(),
        check_outcomes: build_check_outcomes(&checks, &errors, &request.policy),
        route_attribution: Some(build_route_attribution(
            &request,
            Some(evidence.hardware.cpu.as_policy_str()),
        )),
        policy_schema: VerificationPolicy::SCHEMA.into(),
        reference_values_schema: ReferenceValuesPayload::SCHEMA.into(),
        provider_registry_schema: "confidential-inference.provider-registry.v1".into(),
        status,
        enforcement: request.policy.enforcement.clone(),
        request_allowed,
        would_block_under_enforce,
        trust_tier: request.route.trust_tier.clone(),
        provider: request.route.provider.clone(),
        requested_model: request.route.requested_model.clone(),
        provider_model: request.route.provider_model.clone(),
        canonical_model: request.route.canonical_model.clone(),
        route_id: request.route.route_id.clone(),
        evidence_family: request.route.evidence_family.clone(),
        alias_confidence: request.route.alias_confidence.clone(),
        adapter_version: request.route.adapter_version.clone(),
        api_endpoint: request.route.api_endpoint.clone(),
        evidence_endpoint: request.route.evidence_endpoint.clone(),
        freshness_class: request.route.freshness_class.clone(),
        streaming_allowed: request.route.streaming_allowed,
        route_execution_status: request.route_execution_status,
        chat_executable: request.chat_executable,
        known_unsupported_modes: request.known_unsupported_modes,
        channel_binding_kind: request.route.channel_binding_kind.clone(),
        model_binding_result,
        request_channel_bound: evidence.channel_binding.request_bound,
        request_confidentiality_result,
        response_confidentiality_result,
        response_channel_bound: evidence.channel_binding.response_bound,
        response_integrity_result,
        policy_digest,
        provider_registry_digest: request.registry_digest,
        registry_version: request.registry_version,
        registry_source: request.registry_source,
        registry_sync_completed_at: request.registry_sync_completed_at,
        registry_signature: request.registry_signature,
        reference_values_digest: request.reference_values_digest,
        reference_values_version: request.reference_values.version.clone(),
        reference_values_source: request.reference_values_source,
        reference_values_signature: request.reference_signature,
        raw_evidence_digest,
        evidence_digest,
        verified_at: evidence.issued_at,
        expires_at: validity.expires_at.clone(),
        expires_at_epoch_ms: validity.expires_at_epoch_ms,
        validity: ValidityWindow {
            policy_ttl_until: validity.policy_ttl_until,
            collateral_valid_until: validity.expires_at.clone(),
            certificate_valid_until: validity.expires_at.clone(),
            quote_valid_until: validity.expires_at.clone(),
            tcb_valid_until: validity.expires_at.clone(),
            reference_values_valid_until: request.reference_values.valid_until,
            computed_expires_at: validity.expires_at,
        },
        checks,
        artifacts: VerdictArtifacts {
            source_url: Some(request.route.evidence_endpoint),
            tee_measurement: Some(evidence.tee_measurement),
            report_data: Some(evidence.channel_binding.public_key_digest),
            signing_public_key: None,
            e2ee_capability: Some("fixture-e2ee".into()),
            model_manifest: Some(evidence.attested_model),
            model_artifacts: evidence.model_artifacts,
        },
        errors,
    };

    verdict.validate_summary_consistency()?;
    trace_verdict_completed(&verdict);
    Ok(verdict)
}

fn trace_verdict_completed(verdict: &AttestationVerdict) {
    tracing::info!(
        provider = %verdict.provider,
        route_id = %verdict.route_id,
        evidence_family = %verdict.evidence_family,
        status = ?verdict.status,
        request_allowed = verdict.request_allowed,
        would_block_under_enforce = verdict.would_block_under_enforce,
        error_count = verdict.errors.len(),
        "attestation verdict completed"
    );
}

struct ComputedValidityBounds {
    policy_ttl_until: String,
    expires_at: String,
    expires_at_epoch_ms: u64,
}

struct ValidityCandidate<'a> {
    epoch_ms: u64,
    timestamp: &'a str,
}

fn compute_validity_bounds(
    issued_at: &str,
    policy_ttl_millis: u64,
    candidates: [ValidityCandidate<'_>; 3],
) -> Result<ComputedValidityBounds> {
    let policy_ttl_epoch_ms =
        parse_utc_timestamp_millis(issued_at)?.saturating_add(policy_ttl_millis);
    let policy_ttl_until = format_utc_timestamp_millis(policy_ttl_epoch_ms);
    let mut expires_at_epoch_ms = policy_ttl_epoch_ms;
    let mut expires_at = policy_ttl_until.clone();

    for candidate in candidates {
        if candidate.epoch_ms < expires_at_epoch_ms {
            expires_at_epoch_ms = candidate.epoch_ms;
            expires_at = candidate.timestamp.to_owned();
        }
    }

    Ok(ComputedValidityBounds {
        policy_ttl_until,
        expires_at,
        expires_at_epoch_ms,
    })
}

pub fn parse_utc_timestamp_millis(timestamp: &str) -> Result<u64> {
    let (main, millis) = match timestamp.len() {
        20 if timestamp.ends_with('Z') => (&timestamp[..19], 0_u64),
        24 if timestamp.ends_with('Z') && timestamp.as_bytes()[19] == b'.' => {
            let millis = parse_digits(&timestamp[20..23])?;
            (&timestamp[..19], millis)
        }
        _ => {
            return Err(AttestationError::InvalidEvidence(format!(
                "timestamp {timestamp} is not canonical UTC RFC3339"
            )));
        }
    };

    if &main[4..5] != "-"
        || &main[7..8] != "-"
        || &main[10..11] != "T"
        || &main[13..14] != ":"
        || &main[16..17] != ":"
    {
        return Err(AttestationError::InvalidEvidence(format!(
            "timestamp {timestamp} is not canonical UTC RFC3339"
        )));
    }

    let year = parse_digits(&main[0..4])? as i32;
    let month = parse_digits(&main[5..7])? as u32;
    let day = parse_digits(&main[8..10])? as u32;
    let hour = parse_digits(&main[11..13])? as u32;
    let minute = parse_digits(&main[14..16])? as u32;
    let second = parse_digits(&main[17..19])? as u32;

    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(AttestationError::InvalidEvidence(format!(
            "timestamp {timestamp} contains an out-of-range component"
        )));
    }

    let days = days_from_civil(year, month, day);
    if days < 0 {
        return Err(AttestationError::InvalidEvidence(format!(
            "timestamp {timestamp} is before the Unix epoch"
        )));
    }

    let seconds = days as u64 * 86_400 + u64::from(hour * 3_600 + minute * 60 + second);
    Ok(seconds.saturating_mul(1_000).saturating_add(millis))
}

fn parse_digits(value: &str) -> Result<u64> {
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        value
            .parse::<u64>()
            .map_err(|error| AttestationError::InvalidEvidence(error.to_string()))
    } else {
        Err(AttestationError::InvalidEvidence(format!(
            "{value} contains non-digit characters"
        )))
    }
}

pub fn format_utc_timestamp_millis(epoch_millis: u64) -> String {
    let total_seconds = epoch_millis / 1_000;
    let millis = epoch_millis % 1_000;
    let days = (total_seconds / 86_400) as i64;
    let seconds_of_day = total_seconds % 86_400;
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    let (year, month, day) = civil_from_days(days);

    if millis == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
    }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    i64::from(era) * 146_097 + i64::from(day_of_era) - 719_468
}

fn civil_from_days(days: i64) -> (i64, u64, u64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };

    (year, month as u64, day as u64)
}

fn push_check(
    checks: &mut BTreeMap<String, CheckResult>,
    errors: &mut Vec<VerdictError>,
    name: &str,
    ok: bool,
    message: &str,
) {
    if ok {
        checks.insert(name.to_owned(), CheckResult::Verified);
    } else {
        checks.insert(name.to_owned(), CheckResult::Failed);
        errors.push(VerdictError {
            code: name.to_owned(),
            message: message.to_owned(),
        });
    }
}

fn build_check_outcomes(
    checks: &BTreeMap<String, CheckResult>,
    errors: &[VerdictError],
    policy: &VerificationPolicy,
) -> BTreeMap<String, CheckOutcome> {
    checks
        .iter()
        .map(|(name, state)| {
            let detail = errors
                .iter()
                .find(|error| error.code == *name)
                .map(|error| error.message.clone())
                .unwrap_or_else(|| match state {
                    CheckResult::Verified => "check verified against the cited evidence".to_owned(),
                    CheckResult::Failed => "required check failed without detail".to_owned(),
                    CheckResult::NotApplicable => {
                        "check is not applicable to the active policy and route".to_owned()
                    }
                    CheckResult::NotSupported => {
                        "the selected evidence path cannot directly prove this check".to_owned()
                    }
                    CheckResult::Unknown => {
                        "available evidence is insufficient to determine this check".to_owned()
                    }
                });
            let required = check_is_required(name, state, policy);
            let evidence_refs = check_evidence_refs(name);
            (
                name.clone(),
                CheckOutcome {
                    state: state.clone(),
                    required,
                    detail,
                    evidence_refs,
                },
            )
        })
        .collect()
}

fn check_is_required(name: &str, state: &CheckResult, policy: &VerificationPolicy) -> bool {
    if *state == CheckResult::Failed {
        return true;
    }
    if *state == CheckResult::NotApplicable {
        return false;
    }
    let provenance_required = policy.provenance.workload_image
        || policy.provenance.model_artifacts
        || policy.provenance.reproducible_build
        || policy.provenance.source_attestation
        || policy.provenance.dependency_sbom;
    match name {
        "route_metadata_binding" | "tcb_compose_hash" | "response_signing_key_binding" => true,
        "cpu_tee" => !matches!(policy.hardware.cpu, CpuTeeRequirement::NotRequired),
        "gpu_tee" => !matches!(policy.hardware.gpu, GpuTeeRequirement::NotRequired),
        "tls_binding" | "e2ee_key_binding" | "e2ee_key_reference_match" => !matches!(
            policy.channel_binding_requirement,
            ChannelBindingRequirement::NotRequired
        ),
        "request_key_binding" | "request_encryption" => !matches!(
            policy.request_confidentiality_requirement,
            crate::BoundDataRequirement::NotRequired
        ),
        "response_key_binding" | "response_encryption" => !matches!(
            policy.response_confidentiality_requirement,
            crate::BoundDataRequirement::NotRequired
        ),
        "response_channel_binding" | "response_receipt" => !matches!(
            policy.response_integrity_requirement,
            crate::ResponseIntegrityRequirement::NotRequired
        ),
        "nonce_binding" | "per_request_freshness" => {
            matches!(policy.freshness, FreshnessPolicy::PerRequest)
        }
        "model_binding" => {
            matches!(
                policy.model_binding_requirement,
                ModelBindingRequirement::Required
            ) || (matches!(
                policy.model_binding_requirement,
                ModelBindingRequirement::IfProviderSupports
            ) && !matches!(
                state,
                CheckResult::NotSupported | CheckResult::NotApplicable
            ))
        }
        "workload_manifest_binding" | "image_provenance" => {
            policy.provenance.workload_image || provenance_required
        }
        "model_artifact_provenance" => policy.provenance.model_artifacts || provenance_required,
        "sigstore" => policy.provenance.reproducible_build,
        "contrast_manifest" => {
            policy.provenance.source_attestation || policy.provenance.dependency_sbom
        }
        _ => false,
    }
}

fn check_evidence_refs(name: &str) -> Vec<String> {
    let mut refs = vec!["policy_digest".to_owned()];
    if matches!(
        name,
        "route_metadata_binding"
            | "request_route_binding"
            | "route_binding"
            | "e2ee_key_reference_match"
            | "image_provenance"
            | "model_artifact_provenance"
            | "response_signing_key_binding"
            | "tls_binding"
    ) {
        refs.push("provider_registry_digest".into());
        refs.push("reference_values_digest".into());
    }
    if !matches!(name, "request_route_binding" | "route_binding") {
        refs.push("raw_evidence_digest".into());
    }
    refs.sort();
    refs.dedup();
    refs
}

fn build_route_attribution(
    request: &VerificationRequest,
    tee_platform: Option<&str>,
) -> RouteAttribution {
    let unknown = |role, detail: &str| RoutePartyAttribution {
        role,
        party_id: None,
        source: AttributionSource::Unknown,
        detail: detail.to_owned(),
        evidence_refs: Vec::new(),
    };
    let tee_platform = tee_platform.map_or_else(
        || {
            unknown(
                RoutePartyRole::TeePlatform,
                "the evidence does not identify a TEE platform directly",
            )
        },
        |platform| RoutePartyAttribution {
            role: RoutePartyRole::TeePlatform,
            party_id: Some(platform.to_owned()),
            source: AttributionSource::AttestedEvidence,
            detail: "TEE kind is taken directly from parsed evidence; consult the hardware checks for verification state".into(),
            evidence_refs: vec!["raw_evidence_digest".into()],
        },
    );

    RouteAttribution {
        parties: vec![
            RoutePartyAttribution {
                role: RoutePartyRole::InferenceProvider,
                party_id: Some(request.route.provider.clone()),
                source: AttributionSource::SignedRegistry,
                detail: "provider identity is selected directly from the signed registry route"
                    .into(),
                evidence_refs: vec!["provider_registry_digest".into()],
            },
            RoutePartyAttribution {
                role: RoutePartyRole::RegistryAuthority,
                party_id: Some(request.registry_signature.signer.clone()),
                source: AttributionSource::SignedRegistry,
                detail: "authority identity is taken from the verified registry signature metadata"
                    .into(),
                evidence_refs: vec!["provider_registry_digest".into()],
            },
            RoutePartyAttribution {
                role: RoutePartyRole::ReferenceValuesAuthority,
                party_id: Some(request.reference_values.issuer.clone()),
                source: AttributionSource::SignedReferenceValues,
                detail: "authority identity is taken from the signed reference-values issuer"
                    .into(),
                evidence_refs: vec!["reference_values_digest".into()],
            },
            unknown(
                RoutePartyRole::WorkloadOperator,
                "workload-operator identity is not directly asserted by the current evidence",
            ),
            tee_platform,
            unknown(
                RoutePartyRole::CloudHost,
                "cloud-host identity is not directly asserted by the current evidence",
            ),
        ],
    }
}

fn mark_request_route_unproven(checks: &mut BTreeMap<String, CheckResult>) {
    // `route_binding` is retained as a compatibility key, but it now has the
    // same conservative meaning as the explicit request-route check. Registry
    // and evidence metadata agreement is reported separately above.
    checks.insert("request_route_binding".into(), CheckResult::NotSupported);
    checks.insert("route_binding".into(), CheckResult::NotSupported);
}

fn push_model_binding_check(
    checks: &mut BTreeMap<String, CheckResult>,
    errors: &mut Vec<VerdictError>,
    requirement: &ModelBindingRequirement,
    provider_supports_model_binding: bool,
    model_binding_verified: bool,
) -> ModelBindingResult {
    match requirement {
        ModelBindingRequirement::NotRequired => {
            checks.insert("model_binding".into(), CheckResult::NotApplicable);
            ModelBindingResult::NotSupported
        }
        ModelBindingRequirement::IfProviderSupports if !provider_supports_model_binding => {
            checks.insert("model_binding".into(), CheckResult::NotSupported);
            ModelBindingResult::NotSupported
        }
        ModelBindingRequirement::IfProviderSupports | ModelBindingRequirement::Required => {
            let verified = provider_supports_model_binding && model_binding_verified;
            push_check(
                checks,
                errors,
                "model_binding",
                verified,
                "attested model identity does not match the requested canonical model",
            );
            if verified {
                ModelBindingResult::Verified
            } else {
                ModelBindingResult::Failed
            }
        }
    }
}

fn push_unsupported_provenance_checks(
    checks: &mut BTreeMap<String, CheckResult>,
    errors: &mut Vec<VerdictError>,
    policy: &VerificationPolicy,
) {
    if policy.provenance.reproducible_build {
        push_check(
            checks,
            errors,
            "sigstore",
            false,
            "reproducible-build provenance is required but no verified build attestation is present",
        );
    } else {
        checks.insert("sigstore".into(), CheckResult::NotApplicable);
    }

    if policy.provenance.source_attestation || policy.provenance.dependency_sbom {
        push_check(
            checks,
            errors,
            "contrast_manifest",
            false,
            "source-attestation or dependency-SBOM provenance is required but no verified evidence is present",
        );
    } else {
        checks.insert("contrast_manifest".into(), CheckResult::NotApplicable);
    }
}

fn push_per_request_freshness_check(
    checks: &mut BTreeMap<String, CheckResult>,
    errors: &mut Vec<VerdictError>,
    policy: &VerificationPolicy,
) {
    if !matches!(&policy.freshness, FreshnessPolicy::PerRequest) {
        return;
    }

    let freshness_verified = matches!(checks.get("nonce_binding"), Some(CheckResult::Verified))
        || matches!(checks.get("response_receipt"), Some(CheckResult::Verified));
    push_check(
        checks,
        errors,
        "per_request_freshness",
        freshness_verified,
        "per-request freshness policy requires a verified nonce binding or response receipt",
    );
}

fn freshness_nonce_matches_policy(
    policy: &VerificationPolicy,
    expected_nonce: Option<&str>,
    evidence_nonce: &str,
) -> bool {
    match expected_nonce {
        Some(expected_nonce) => expected_nonce == evidence_nonce,
        None => !matches!(policy.freshness, FreshnessPolicy::PerRequest),
    }
}

fn strip_sha256_prefix(value: &str) -> Option<&str> {
    value
        .strip_prefix("sha256:")
        .or(Some(value))
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AliasConfidence, AttestedRoute, BoundDataRequirement, ChannelBindingKind, FreshnessClass,
        GpuAttestationVerifier, GpuTeeKind, GpuTeeRequirement, NvidiaGpuAttestationEvidence,
        NvidiaGpuAttestationVerificationRequest, ProvenanceRequirement, ProviderReference,
        ReferenceValuesEnvelope, ReferenceValuesPayload, ResponseIntegrityRequirement,
        RouteReference, TinfoilAttestationDoc, TinfoilLiveCaptureEvidence, TrustTier,
        VerifiedGpuAttestation, TINFOIL_TDX_GUEST_V2_FORMAT,
    };
    use crate::{
        ArtifactDigest, ChannelBindingEvidence, CpuTeeKind, DstackTcbInfo, EvidenceHardware,
        TdxQuoteMeasurements, WorkloadImage,
    };
    use base64::Engine;
    use flate2::{write::GzEncoder, Compression};
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::path::PathBuf;

    fn demo_route() -> AttestedRoute {
        AttestedRoute {
            provider: "demo".into(),
            route_id: "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p".into(),
            evidence_family: "fixture_dstack".into(),
            requested_model: "gpt-oss-120b".into(),
            provider_model: "e2ee-gpt-oss-120b-p".into(),
            canonical_model: "gpt-oss-120b".into(),
            api_endpoint: "http://127.0.0.1/demo/v1".into(),
            evidence_endpoint: "http://127.0.0.1/demo/v1/confidentiality".into(),
            adapter_version: "demo-fixture-adapter/0.1.0".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            alias_confidence: AliasConfidence::Curated,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            streaming_allowed: false,
        }
    }

    fn tinfoil_route() -> AttestedRoute {
        AttestedRoute {
            provider: "tinfoil-fixture".into(),
            route_id: "tinfoil-fixture:llama-3-3-70b:llama-3-3-70b".into(),
            evidence_family: "tinfoil_hw_verified_tls".into(),
            requested_model: "llama-3-3-70b".into(),
            provider_model: "llama-3-3-70b".into(),
            canonical_model: "llama-3-3-70b".into(),
            api_endpoint: "https://inference.tinfoil.sh/v1".into(),
            evidence_endpoint: "https://inference.tinfoil.sh/.well-known/tinfoil-attestation"
                .into(),
            adapter_version: "tinfoil-fixture-adapter/0.1.0".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::TeeTerminatedTls,
            trust_tier: TrustTier::HwVerifiedTls,
            alias_confidence: AliasConfidence::Curated,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::ChannelBound,
            streaming_allowed: false,
        }
    }

    fn dstack_route() -> AttestedRoute {
        AttestedRoute {
            provider: "venice-fixture".into(),
            route_id: "venice-fixture:gpt-oss-120b:e2ee-gpt-oss-120b-p".into(),
            evidence_family: "dstack_app_e2ee".into(),
            requested_model: "gpt-oss-120b".into(),
            provider_model: "e2ee-gpt-oss-120b-p".into(),
            canonical_model: "gpt-oss-120b".into(),
            api_endpoint: "https://api.venice.ai/api/v1".into(),
            evidence_endpoint: "https://api.venice.ai/api/v1/confidentiality".into(),
            adapter_version: "venice-dstack-fixture-adapter/0.1.0".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            alias_confidence: AliasConfidence::Curated,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            streaming_allowed: false,
        }
    }

    fn chutes_route() -> AttestedRoute {
        AttestedRoute {
            provider: "redpill-fixture".into(),
            route_id: "redpill-fixture:gpt-oss-120b:private-org-gpt-oss-120b-thinking-TEE".into(),
            evidence_family: "chutes_e2ee".into(),
            requested_model: "gpt-oss-120b".into(),
            provider_model: "private/org/gpt-oss-120b:thinking-TEE".into(),
            canonical_model: "gpt-oss-120b".into(),
            api_endpoint: "https://api.redpill.ai/v1".into(),
            evidence_endpoint: "https://api.redpill.ai/v1/attestation/report".into(),
            adapter_version: "redpill-chutes-fixture-adapter/0.1.0".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            alias_confidence: AliasConfidence::Curated,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            streaming_allowed: false,
        }
    }

    fn request_with_evidence(raw_evidence: &[u8]) -> VerificationRequest {
        request_with_evidence_and_policy(raw_evidence, VerificationPolicy::require_attested_e2ee())
    }

    fn request_with_evidence_and_policy(
        raw_evidence: &[u8],
        policy: VerificationPolicy,
    ) -> VerificationRequest {
        let envelope = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let registry_digest = sha256_digest(b"demo-registry");
        let reference_values_digest = envelope.payload.digest().unwrap();
        VerificationRequest {
            route: demo_route(),
            route_execution_status: "test".into(),
            chat_executable: true,
            known_unsupported_modes: Vec::new(),
            expected_freshness_nonce: None,
            policy: policy
                .with_artifact_digests(registry_digest.clone(), reference_values_digest.clone()),
            reference_values: envelope.payload.clone(),
            reference_signature: SignatureMetadata {
                signer: envelope.signature.signer,
                key_id: envelope.signature.key_id,
                alg: envelope.signature.alg,
            },
            reference_values_digest,
            reference_values_source: "test".into(),
            registry_digest,
            registry_version: "2026-07-05-demo".into(),
            registry_source: "bundled".into(),
            registry_sync_completed_at: "2026-07-05T00:00:00Z".into(),
            registry_signature: SignatureMetadata {
                signer: "confidential-inference".into(),
                key_id: "test".into(),
                alg: "ed25519".into(),
            },
            raw_evidence: raw_evidence.to_vec(),
        }
    }

    fn request_with_tinfoil_evidence(
        evidence: TinfoilTlsEvidence,
        reference_tls_spki_sha256: Option<String>,
    ) -> VerificationRequest {
        let mut providers = BTreeMap::new();
        let route = tinfoil_route();
        let route_reference = RouteReference {
            canonical_model: route.canonical_model.clone(),
            provider_model: route.provider_model.clone(),
            evidence_family: route.evidence_family.clone(),
            channel_binding_kind: route.channel_binding_kind.clone(),
            trust_tier: route.trust_tier.clone(),
            accepted_cpu_tees: vec![CpuTeeKind::Tdx],
            e2ee_public_key_digest: String::new(),
            response_signing_key_digest: None,
            tls_spki_sha256: reference_tls_spki_sha256,
            workload_images: Vec::new(),
            workload_image_digest: "sha256:tinfoil-workload-image".into(),
            model_artifacts: vec![ArtifactDigest {
                kind: "weights".into(),
                name: "llama-3-3-70b".into(),
                digest: "sha256:tinfoil-weights".into(),
            }],
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
        };
        providers.insert(
            route.provider.clone(),
            ProviderReference {
                accepted_measurements: vec!["sha256:tinfoil-tee-measurement".into()],
                routes: BTreeMap::from([(route.route_id.clone(), route_reference)]),
            },
        );
        let reference_values = ReferenceValuesPayload {
            schema: ReferenceValuesPayload::SCHEMA.into(),
            version: "2026-07-05-tinfoil-fixture".into(),
            issuer: "confidential-inference".into(),
            valid_from: "2026-07-05T00:00:00Z".into(),
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
            revocation_epoch: 1,
            minimum_acceptable_version: "2026-07-05-tinfoil-fixture".into(),
            providers,
        };
        let reference_values_digest = reference_values.digest().unwrap();
        let registry_digest = sha256_digest(b"tinfoil-registry");

        VerificationRequest {
            route,
            route_execution_status: "test".into(),
            chat_executable: true,
            known_unsupported_modes: Vec::new(),
            expected_freshness_nonce: None,
            policy: {
                let mut policy = VerificationPolicy::require_hw_verified_tls();
                policy.model_binding_requirement = ModelBindingRequirement::IfProviderSupports;
                policy
                    .with_artifact_digests(registry_digest.clone(), reference_values_digest.clone())
            },
            reference_values,
            reference_signature: SignatureMetadata {
                signer: "confidential-inference".into(),
                key_id: "test".into(),
                alg: "ed25519".into(),
            },
            reference_values_digest,
            reference_values_source: "test".into(),
            registry_digest,
            registry_version: "2026-07-05-tinfoil-fixture".into(),
            registry_source: "test".into(),
            registry_sync_completed_at: "2026-07-05T00:00:00Z".into(),
            registry_signature: SignatureMetadata {
                signer: "confidential-inference".into(),
                key_id: "test".into(),
                alg: "ed25519".into(),
            },
            raw_evidence: serde_json::to_vec(&evidence).unwrap(),
        }
    }

    fn request_with_dstack_evidence(evidence: DstackEvidence) -> VerificationRequest {
        let mut providers = BTreeMap::new();
        let route = dstack_route();
        let route_reference = RouteReference {
            canonical_model: route.canonical_model.clone(),
            provider_model: route.provider_model.clone(),
            evidence_family: route.evidence_family.clone(),
            channel_binding_kind: route.channel_binding_kind.clone(),
            trust_tier: route.trust_tier.clone(),
            accepted_cpu_tees: vec![CpuTeeKind::Tdx],
            e2ee_public_key_digest: "sha256:venice-e2ee-key".into(),
            response_signing_key_digest: None,
            tls_spki_sha256: None,
            workload_images: evidence.workload_images.clone(),
            workload_image_digest: "sha256:venice-workload-image".into(),
            model_artifacts: vec![ArtifactDigest {
                kind: "weights".into(),
                name: "gpt-oss-120b".into(),
                digest: "sha256:venice-weights".into(),
            }],
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
        };
        providers.insert(
            route.provider.clone(),
            ProviderReference {
                accepted_measurements: vec!["sha256:venice-tee-measurement".into()],
                routes: BTreeMap::from([(route.route_id.clone(), route_reference)]),
            },
        );
        let reference_values = ReferenceValuesPayload {
            schema: ReferenceValuesPayload::SCHEMA.into(),
            version: "2026-07-05-dstack-fixture".into(),
            issuer: "confidential-inference".into(),
            valid_from: "2026-07-05T00:00:00Z".into(),
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
            revocation_epoch: 1,
            minimum_acceptable_version: "2026-07-05-dstack-fixture".into(),
            providers,
        };
        let reference_values_digest = reference_values.digest().unwrap();
        let registry_digest = sha256_digest(b"dstack-registry");

        VerificationRequest {
            route,
            route_execution_status: "test".into(),
            chat_executable: true,
            known_unsupported_modes: Vec::new(),
            expected_freshness_nonce: None,
            policy: VerificationPolicy::require_attested_e2ee()
                .with_artifact_digests(registry_digest.clone(), reference_values_digest.clone()),
            reference_values,
            reference_signature: SignatureMetadata {
                signer: "confidential-inference".into(),
                key_id: "test".into(),
                alg: "ed25519".into(),
            },
            reference_values_digest,
            reference_values_source: "test".into(),
            registry_digest,
            registry_version: "2026-07-05-dstack-fixture".into(),
            registry_source: "test".into(),
            registry_sync_completed_at: "2026-07-05T00:00:00Z".into(),
            registry_signature: SignatureMetadata {
                signer: "confidential-inference".into(),
                key_id: "test".into(),
                alg: "ed25519".into(),
            },
            raw_evidence: serde_json::to_vec(&evidence).unwrap(),
        }
    }

    fn request_with_chutes_evidence(
        evidence: ChutesE2eeEvidence,
        reference_key_digest: Option<String>,
    ) -> VerificationRequest {
        request_with_chutes_evidence_and_policy(
            evidence,
            reference_key_digest,
            VerificationPolicy::require_attested_e2ee(),
        )
    }

    fn request_with_chutes_evidence_and_policy(
        evidence: ChutesE2eeEvidence,
        reference_key_digest: Option<String>,
        policy: VerificationPolicy,
    ) -> VerificationRequest {
        let mut providers = BTreeMap::new();
        let route = chutes_route();
        let route_reference = RouteReference {
            canonical_model: route.canonical_model.clone(),
            provider_model: route.provider_model.clone(),
            evidence_family: route.evidence_family.clone(),
            channel_binding_kind: route.channel_binding_kind.clone(),
            trust_tier: route.trust_tier.clone(),
            accepted_cpu_tees: vec![CpuTeeKind::Tdx],
            e2ee_public_key_digest: reference_key_digest
                .unwrap_or_else(|| sha256_digest(chutes_public_key().as_bytes())),
            response_signing_key_digest: None,
            tls_spki_sha256: None,
            workload_images: Vec::new(),
            workload_image_digest: "sha256:chutes-workload-image".into(),
            model_artifacts: vec![ArtifactDigest {
                kind: "weights".into(),
                name: "gpt-oss-120b".into(),
                digest: "sha256:chutes-weights".into(),
            }],
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
        };
        providers.insert(
            route.provider.clone(),
            ProviderReference {
                accepted_measurements: vec!["sha256:chutes-tee-measurement".into()],
                routes: BTreeMap::from([(route.route_id.clone(), route_reference)]),
            },
        );
        let reference_values = ReferenceValuesPayload {
            schema: ReferenceValuesPayload::SCHEMA.into(),
            version: "2026-07-05-chutes-fixture".into(),
            issuer: "confidential-inference".into(),
            valid_from: "2026-07-05T00:00:00Z".into(),
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
            revocation_epoch: 1,
            minimum_acceptable_version: "2026-07-05-chutes-fixture".into(),
            providers,
        };
        let reference_values_digest = reference_values.digest().unwrap();
        let registry_digest = sha256_digest(b"chutes-registry");

        VerificationRequest {
            route,
            route_execution_status: "test".into(),
            chat_executable: true,
            known_unsupported_modes: Vec::new(),
            expected_freshness_nonce: None,
            policy: policy
                .with_artifact_digests(registry_digest.clone(), reference_values_digest.clone()),
            reference_values,
            reference_signature: SignatureMetadata {
                signer: "confidential-inference".into(),
                key_id: "test".into(),
                alg: "ed25519".into(),
            },
            reference_values_digest,
            reference_values_source: "test".into(),
            registry_digest,
            registry_version: "2026-07-05-chutes-fixture".into(),
            registry_source: "test".into(),
            registry_sync_completed_at: "2026-07-05T00:00:00Z".into(),
            registry_signature: SignatureMetadata {
                signer: "confidential-inference".into(),
                key_id: "test".into(),
                alg: "ed25519".into(),
            },
            raw_evidence: serde_json::to_vec(&evidence).unwrap(),
        }
    }

    fn dstack_evidence() -> DstackEvidence {
        let workload_image = WorkloadImage {
            service: "root".into(),
            reference: concat!(
                "venice/worker@sha256:",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .into(),
            digest: concat!(
                "sha256:",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .into(),
        };
        let app_compose = format!(
            r#"{{"image":"{}","model":"gpt-oss-120b"}}"#,
            workload_image.reference
        );
        DstackEvidence {
            schema: DstackEvidence::SCHEMA.into(),
            provider: "venice-fixture".into(),
            route_id: "venice-fixture:gpt-oss-120b:e2ee-gpt-oss-120b-p".into(),
            evidence_family: "dstack_app_e2ee".into(),
            tee_measurement: "sha256:venice-tee-measurement".into(),
            hardware: EvidenceHardware {
                cpu: CpuTeeKind::Tdx,
                gpu: None,
            },
            quote_measurements: TdxQuoteMeasurements {
                mr_td: "aa".repeat(24),
                rtmr0: "bb".repeat(24),
            },
            tcb_info: DstackTcbInfo {
                mrtd: "aa".repeat(24),
                rtmr0: "bb".repeat(24),
                app_compose: app_compose.clone(),
                compose_hash: sha256_digest(app_compose.as_bytes())
                    .trim_start_matches("sha256:")
                    .into(),
            },
            channel_binding: ChannelBindingEvidence {
                kind: ChannelBindingKind::AttestedAppE2ee,
                public_key_digest: "sha256:venice-e2ee-key".into(),
                request_bound: true,
                response_bound: true,
            },
            attested_model: Some("gpt-oss-120b".into()),
            workload_images: vec![workload_image],
            workload_image_digest: "sha256:venice-workload-image".into(),
            model_artifacts: vec![ArtifactDigest {
                kind: "weights".into(),
                name: "gpt-oss-120b".into(),
                digest: "sha256:venice-weights".into(),
            }],
            issued_at: "2026-07-05T00:00:00Z".into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            expires_at_epoch_ms: 4_070_908_800_000,
        }
    }

    fn chutes_evidence() -> ChutesE2eeEvidence {
        let nonce = "33".repeat(32);
        let public_key = chutes_public_key();
        let report_prefix = crate::chutes_expected_report_data_prefix(&nonce, public_key).unwrap();
        ChutesE2eeEvidence {
            schema: ChutesE2eeEvidence::SCHEMA.into(),
            provider: "redpill-fixture".into(),
            route_id: "redpill-fixture:gpt-oss-120b:private-org-gpt-oss-120b-thinking-TEE".into(),
            evidence_family: "chutes_e2ee".into(),
            tee_measurement: "sha256:chutes-tee-measurement".into(),
            hardware: EvidenceHardware {
                cpu: CpuTeeKind::Tdx,
                gpu: None,
            },
            gpu_attestation: None,
            report_data: format!("{}{}", report_prefix, "00".repeat(32)),
            nonce,
            e2e_public_key: public_key.into(),
            attested_model: Some("gpt-oss-120b".into()),
            workload_image_digest: "sha256:chutes-workload-image".into(),
            model_artifacts: vec![ArtifactDigest {
                kind: "weights".into(),
                name: "gpt-oss-120b".into(),
                digest: "sha256:chutes-weights".into(),
            }],
            issued_at: "2026-07-05T00:00:00Z".into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            expires_at_epoch_ms: 4_070_908_800_000,
        }
    }

    fn chutes_public_key() -> &'static str {
        "chutes-test-public-key"
    }

    fn nvidia_gpu_attestation(nonce: &str) -> NvidiaGpuAttestationEvidence {
        NvidiaGpuAttestationEvidence {
            schema: NvidiaGpuAttestationEvidence::SCHEMA.into(),
            attestation_format: NvidiaGpuAttestationEvidence::NRAS_GPU_EVIDENCE_V3.into(),
            nonce: nonce.into(),
            arch: Some("gpu-hopper-h100".into()),
            payload_sha256: Some("sha256:nvidia-gpu-payload".into()),
            raw_payload_base64: Some(
                base64::engine::general_purpose::STANDARD
                    .encode(br#"{"evidence_list":[{"evidence":"fixture"}]}"#),
            ),
            nras_token: None,
        }
    }

    #[derive(Clone, Debug)]
    struct StaticGpuAttestationVerifier;

    impl GpuAttestationVerifier for StaticGpuAttestationVerifier {
        fn verify_nvidia_gpu_attestation(
            &self,
            request: &NvidiaGpuAttestationVerificationRequest<'_>,
        ) -> Result<VerifiedGpuAttestation> {
            assert_eq!(request.expected_tee, GpuTeeKind::NvidiaCc);
            assert_eq!(request.expected_nonce, request.evidence.nonce);
            assert_eq!(request.provider, "redpill-fixture");
            assert_eq!(
                request.route_id,
                "redpill-fixture:gpt-oss-120b:private-org-gpt-oss-120b-thinking-TEE"
            );
            Ok(VerifiedGpuAttestation::nvidia_cc(
                request.expected_nonce,
                request.evidence.attestation_format.clone(),
                "static-test-verifier",
            ))
        }
    }

    fn tinfoil_evidence(report_data: String) -> TinfoilTlsEvidence {
        TinfoilTlsEvidence {
            schema: TinfoilTlsEvidence::SCHEMA.into(),
            provider: "tinfoil-fixture".into(),
            route_id: "tinfoil-fixture:llama-3-3-70b:llama-3-3-70b".into(),
            evidence_family: "tinfoil_hw_verified_tls".into(),
            tee_measurement: "sha256:tinfoil-tee-measurement".into(),
            hardware: EvidenceHardware {
                cpu: CpuTeeKind::Tdx,
                gpu: None,
            },
            report_data,
            leaf_certificate_der_base64: crate::tls::TEST_CERT_DER_BASE64.into(),
            attested_model: "llama-3-3-70b".into(),
            workload_image_digest: "sha256:tinfoil-workload-image".into(),
            model_artifacts: vec![ArtifactDigest {
                kind: "weights".into(),
                name: "llama-3-3-70b".into(),
                digest: "sha256:tinfoil-weights".into(),
            }],
            issued_at: "2026-07-05T00:00:00Z".into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            expires_at_epoch_ms: 4_070_908_800_000,
        }
    }

    fn require_attested_e2ee_with_provenance() -> VerificationPolicy {
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.provenance = ProvenanceRequirement {
            workload_image: true,
            model_artifacts: true,
            reproducible_build: false,
            source_attestation: false,
            dependency_sbom: false,
        };
        policy
    }

    fn require_attested_e2ee_with_gpu() -> VerificationPolicy {
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.hardware.gpu = GpuTeeRequirement::one_of(vec![GpuTeeKind::NvidiaCc]);
        policy
    }

    #[test]
    fn valid_fixture_evidence_verifies() {
        let raw = include_bytes!("../../../fixtures/evidence/demo-valid.json");
        let verdict = verify_fixture_evidence(request_with_evidence(raw)).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Verified);
        assert!(verdict.request_allowed);
        assert_eq!(verdict.model_binding_result, ModelBindingResult::Verified);
        assert_eq!(
            verdict.check("route_metadata_binding"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            verdict.check("request_route_binding"),
            Some(&CheckResult::NotSupported)
        );
        assert_eq!(
            verdict.check("route_binding"),
            Some(&CheckResult::NotSupported)
        );
        assert_eq!(
            verdict.response_integrity_result,
            ResponseIntegrityResult::ChannelBound
        );
        assert_eq!(verdict.validity.policy_ttl_until, "2099-01-01T00:00:00Z");
        assert_eq!(verdict.expires_at, "2099-01-01T00:00:00Z");
        assert_eq!(verdict.check_outcomes.len(), verdict.checks.len());
        let model_outcome = verdict.check_outcomes.get("model_binding").unwrap();
        assert_eq!(model_outcome.state, CheckResult::Verified);
        assert!(model_outcome.required);
        assert!(model_outcome
            .evidence_refs
            .contains(&"raw_evidence_digest".into()));
        let route_attribution = verdict.route_attribution.as_ref().unwrap();
        assert_eq!(route_attribution.parties.len(), 6);
        assert!(route_attribution.parties.iter().any(|party| {
            party.role == RoutePartyRole::InferenceProvider
                && party.party_id.as_deref() == Some("demo")
                && party.source == AttributionSource::SignedRegistry
        }));
        assert!(route_attribution.parties.iter().any(|party| {
            party.role == RoutePartyRole::WorkloadOperator
                && party.party_id.is_none()
                && party.source == AttributionSource::Unknown
        }));
    }

    #[test]
    fn unsupported_full_provenance_requirements_fail_closed_with_structured_outcomes() {
        let raw = include_bytes!("../../../fixtures/evidence/demo-valid.json");
        let policy =
            VerificationPolicy::require_full_provenance(ChannelBindingRequirement::AttestedAppE2ee)
                .unwrap();

        let verdict =
            verify_fixture_evidence(request_with_evidence_and_policy(raw, policy)).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        for check in ["sigstore", "contrast_manifest"] {
            assert_eq!(verdict.check(check), Some(&CheckResult::Failed));
            let outcome = verdict.check_outcomes.get(check).unwrap();
            assert!(outcome.required);
            assert!(!outcome.detail.is_empty());
        }
    }

    #[test]
    fn per_request_freshness_fails_for_fixture_without_nonce_binding() {
        let raw = include_bytes!("../../../fixtures/evidence/demo-valid.json");
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.freshness = FreshnessPolicy::PerRequest;

        let verdict =
            verify_fixture_evidence(request_with_evidence_and_policy(raw, policy)).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert!(verdict.would_block_under_enforce);
        assert_eq!(
            verdict.check("nonce_binding"),
            Some(&CheckResult::NotApplicable)
        );
        assert_eq!(
            verdict.check("response_receipt"),
            Some(&CheckResult::NotApplicable)
        );
        assert_eq!(
            verdict.check("per_request_freshness"),
            Some(&CheckResult::Failed)
        );
        assert!(verdict
            .errors
            .iter()
            .any(|error| error.code == "per_request_freshness"));
    }

    #[test]
    fn normalized_evidence_rejects_provider_side_verified_claims() {
        let mut evidence: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../fixtures/evidence/demo-valid.json"))
                .unwrap();
        evidence["verified"] = serde_json::json!(true);
        let raw = serde_json::to_vec(&evidence).unwrap();

        let error = verify_evidence(request_with_evidence(&raw)).unwrap_err();

        assert!(matches!(
            error,
            AttestationError::Json(error)
                if error.to_string().contains("unknown field `verified`")
        ));
    }

    #[test]
    fn verdict_expiry_is_bounded_by_policy_ttl() {
        let mut evidence: FixtureEvidence =
            serde_json::from_slice(include_bytes!("../../../fixtures/evidence/demo-valid.json"))
                .unwrap();
        evidence.issued_at = "2026-07-05T00:00:00Z".into();
        evidence.expires_at = "2099-01-01T00:00:00Z".into();
        evidence.expires_at_epoch_ms = 4_070_908_800_000;
        let raw = serde_json::to_vec(&evidence).unwrap();

        let verdict = verify_fixture_evidence(request_with_evidence(&raw)).unwrap();

        assert_eq!(verdict.validity.policy_ttl_until, "2026-07-05T00:10:00Z");
        assert_eq!(verdict.expires_at, "2026-07-05T00:10:00Z");
        assert_eq!(verdict.expires_at_epoch_ms, 1_783_210_200_000);
        assert_eq!(verdict.validity.computed_expires_at, "2026-07-05T00:10:00Z");
    }

    #[test]
    fn evidence_dispatch_fails_closed_for_unsupported_family() {
        let raw = include_bytes!("../../../fixtures/evidence/demo-valid.json");
        let mut request = request_with_evidence(raw);
        request.route.evidence_family = "unknown_family".into();

        assert!(matches!(
            verify_evidence(request),
            Err(AttestationError::InvalidEvidence(message))
                if message.contains("unsupported evidence family unknown_family")
        ));
    }

    #[test]
    fn tinfoil_tls_evidence_verifies_spki_report_data_binding() {
        let evidence = tinfoil_evidence(format!(
            "{}{}",
            crate::tls::TEST_SPKI_SHA256,
            "00".repeat(32)
        ));
        let request = request_with_tinfoil_evidence(
            evidence,
            Some(format!("sha256:{}", crate::tls::TEST_SPKI_SHA256)),
        );

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Verified);
        assert!(verdict.request_allowed);
        assert_eq!(verdict.check("tls_binding"), Some(&CheckResult::Verified));
        assert_eq!(
            verdict.request_confidentiality_result,
            ConfidentialityResult::ChannelBound
        );
        assert_eq!(
            verdict.response_integrity_result,
            ResponseIntegrityResult::ChannelBound
        );
        assert_eq!(
            verdict.artifacts.signing_public_key,
            Some(format!("sha256:{}", crate::tls::TEST_SPKI_SHA256))
        );
    }

    #[test]
    fn tinfoil_tls_evidence_fails_closed_for_wrong_report_data() {
        let evidence = tinfoil_evidence(format!("{}{}", "00".repeat(32), "11".repeat(32)));
        let request = request_with_tinfoil_evidence(
            evidence,
            Some(format!("sha256:{}", crate::tls::TEST_SPKI_SHA256)),
        );

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert_eq!(verdict.check("tls_binding"), Some(&CheckResult::Failed));
        assert_eq!(
            verdict.response_integrity_result,
            ResponseIntegrityResult::NotBound
        );
    }

    #[test]
    fn tinfoil_tls_evidence_fails_closed_without_reference_spki() {
        let evidence = tinfoil_evidence(format!(
            "{}{}",
            crate::tls::TEST_SPKI_SHA256,
            "00".repeat(32)
        ));
        let request = request_with_tinfoil_evidence(evidence, None);

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert_eq!(verdict.check("tls_binding"), Some(&CheckResult::Failed));
    }

    #[test]
    fn live_tinfoil_capture_fails_closed_until_quote_verifier_is_ported() {
        let mut request = request_with_tinfoil_evidence(
            tinfoil_evidence(format!(
                "{}{}",
                crate::tls::TEST_SPKI_SHA256,
                "00".repeat(32)
            )),
            Some(format!("sha256:{}", crate::tls::TEST_SPKI_SHA256)),
        );
        request.raw_evidence = live_tinfoil_capture_json(&request);

        let error = verify_tinfoil_tls_evidence(request).unwrap_err();

        assert!(matches!(error, AttestationError::InvalidEvidence(_)));
        assert!(error.to_string().contains("TDX/SNP quote verification"));
    }

    #[test]
    fn live_tinfoil_capture_verifies_with_verified_quote_backend() {
        let mut request = request_with_tinfoil_evidence(
            tinfoil_evidence(format!(
                "{}{}",
                crate::tls::TEST_SPKI_SHA256,
                "00".repeat(32)
            )),
            Some(format!("sha256:{}", crate::tls::TEST_SPKI_SHA256)),
        );
        let raw_capture = live_tinfoil_capture_json(&request);
        request.raw_evidence = raw_capture.clone();
        let verifier = StaticTinfoilQuoteVerifier {
            quote: verified_tinfoil_quote(format!(
                "{}{}",
                crate::tls::TEST_SPKI_SHA256,
                "00".repeat(32)
            )),
        };

        let verdict = verify_tinfoil_tls_evidence_with_quote_verifier(request, &verifier).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Verified);
        assert!(verdict.request_allowed);
        assert_eq!(verdict.raw_evidence_digest, sha256_digest(&raw_capture));
        assert_eq!(verdict.check("cpu_tee"), Some(&CheckResult::Verified));
        assert_eq!(verdict.check("tls_binding"), Some(&CheckResult::Verified));
        assert_eq!(
            verdict.check("model_binding"),
            Some(&CheckResult::NotSupported)
        );
        assert_eq!(
            verdict.model_binding_result,
            ModelBindingResult::NotSupported
        );
        assert_eq!(
            verdict.artifacts.report_data,
            Some(format!(
                "{}{}",
                crate::tls::TEST_SPKI_SHA256,
                "00".repeat(32)
            ))
        );
    }

    #[test]
    fn live_tinfoil_capture_fails_when_verified_quote_does_not_bind_tls_spki() {
        let mut request = request_with_tinfoil_evidence(
            tinfoil_evidence(format!(
                "{}{}",
                crate::tls::TEST_SPKI_SHA256,
                "00".repeat(32)
            )),
            Some(format!("sha256:{}", crate::tls::TEST_SPKI_SHA256)),
        );
        request.raw_evidence = live_tinfoil_capture_json(&request);
        let verifier = StaticTinfoilQuoteVerifier {
            quote: verified_tinfoil_quote(format!("{}{}", "00".repeat(32), "11".repeat(32))),
        };

        let verdict = verify_tinfoil_tls_evidence_with_quote_verifier(request, &verifier).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert_eq!(verdict.check("tls_binding"), Some(&CheckResult::Failed));
        assert_eq!(
            verdict.response_integrity_result,
            ResponseIntegrityResult::NotBound
        );
    }

    #[test]
    fn live_tinfoil_capture_fails_required_model_binding_without_attested_model() {
        let mut request = request_with_tinfoil_evidence(
            tinfoil_evidence(format!(
                "{}{}",
                crate::tls::TEST_SPKI_SHA256,
                "00".repeat(32)
            )),
            Some(format!("sha256:{}", crate::tls::TEST_SPKI_SHA256)),
        );
        request.policy.model_binding_requirement = ModelBindingRequirement::Required;
        request.raw_evidence = live_tinfoil_capture_json(&request);
        let verifier = StaticTinfoilQuoteVerifier {
            quote: verified_tinfoil_quote(format!(
                "{}{}",
                crate::tls::TEST_SPKI_SHA256,
                "00".repeat(32)
            )),
        };

        let verdict = verify_tinfoil_tls_evidence_with_quote_verifier(request, &verifier).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert_eq!(verdict.check("model_binding"), Some(&CheckResult::Failed));
        assert_eq!(verdict.model_binding_result, ModelBindingResult::Failed);
    }

    #[test]
    fn live_tinfoil_capture_rejects_quote_backend_format_mismatch() {
        let mut request = request_with_tinfoil_evidence(
            tinfoil_evidence(format!(
                "{}{}",
                crate::tls::TEST_SPKI_SHA256,
                "00".repeat(32)
            )),
            Some(format!("sha256:{}", crate::tls::TEST_SPKI_SHA256)),
        );
        request.raw_evidence = live_tinfoil_capture_json(&request);
        let mut quote = verified_tinfoil_quote(format!(
            "{}{}",
            crate::tls::TEST_SPKI_SHA256,
            "00".repeat(32)
        ));
        quote.attestation_format = crate::TINFOIL_SEV_SNP_GUEST_V2_FORMAT.into();
        let verifier = StaticTinfoilQuoteVerifier { quote };

        let error =
            verify_tinfoil_tls_evidence_with_quote_verifier(request, &verifier).unwrap_err();

        assert!(error.to_string().contains("different attestation format"));
    }

    #[derive(Clone)]
    struct StaticTinfoilQuoteVerifier {
        quote: VerifiedTinfoilQuote,
    }

    impl TinfoilQuoteVerifier for StaticTinfoilQuoteVerifier {
        fn verify_tinfoil_quote(
            &self,
            request: &TinfoilQuoteVerificationRequest<'_>,
        ) -> Result<VerifiedTinfoilQuote> {
            assert_eq!(
                request.attestation_format,
                crate::TinfoilAttestationFormat::TdxGuestV2
            );
            assert!(request.quote_bytes.iter().all(|byte| *byte == 7));
            assert_eq!(request.quote_bytes.len(), 48);
            assert_eq!(request.live_tls_spki_sha256, crate::tls::TEST_SPKI_SHA256);
            assert!(!request.live_tls_leaf_certificate_der.is_empty());
            assert_eq!(request.capture.provider, "tinfoil-fixture");
            Ok(self.quote.clone())
        }
    }

    #[derive(Clone)]
    struct StaticTdxQuoteVerifier {
        quote: VerifiedTdxQuote,
    }

    impl TinfoilQuoteVerifier for StaticTdxQuoteVerifier {
        fn verify_tinfoil_quote(
            &self,
            _request: &TinfoilQuoteVerificationRequest<'_>,
        ) -> Result<VerifiedTinfoilQuote> {
            Err(AttestationError::InvalidEvidence(
                "test verifier only supports raw TDX quotes".into(),
            ))
        }

        fn verify_tdx_quote(&self, quote_bytes: &[u8]) -> Result<VerifiedTdxQuote> {
            assert_eq!(quote_bytes, &[7_u8; 48]);
            Ok(self.quote.clone())
        }
    }

    #[test]
    fn chutes_live_evidence_verifies_dynamic_ml_kem_and_certificate_binding() {
        let route = AttestedRoute {
            provider: "chutes".into(),
            route_id: "chutes:qwen3-32b:Qwen-Qwen3-32B-TEE".into(),
            evidence_family: "chutes_live_e2ee".into(),
            requested_model: "qwen3-32b".into(),
            provider_model: "Qwen/Qwen3-32B-TEE".into(),
            canonical_model: "qwen3-32b".into(),
            api_endpoint: "https://llm.chutes.ai/v1".into(),
            evidence_endpoint: "https://api.chutes.ai".into(),
            adapter_version: "chutes-live-e2ee/1".into(),
            freshness_class: FreshnessClass::PerRequest,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            alias_confidence: AliasConfidence::Curated,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            streaming_allowed: false,
        };
        let nonce = "44".repeat(32);
        let e2e_key = base64::engine::general_purpose::STANDARD.encode([9_u8; 1_184]);
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(crate::tls::TEST_CERT_DER_BASE64)
            .unwrap();
        let report_data = format!(
            "{}{}",
            crate::chutes_expected_report_data_prefix(&nonce, &e2e_key).unwrap(),
            crate::certificate_spki_sha256_hex(&cert_der).unwrap()
        );
        let measurement = format!(
            "tdx:mr_td:{}:rtmr0:{}:rtmr1:{}:rtmr2:{}:rtmr3:{}",
            "11".repeat(48),
            "22".repeat(48),
            "33".repeat(48),
            "44".repeat(48),
            "55".repeat(48)
        );
        let mut providers = BTreeMap::new();
        providers.insert(
            "chutes".into(),
            ProviderReference {
                accepted_measurements: vec![measurement.clone()],
                routes: BTreeMap::from([(
                    route.route_id.clone(),
                    RouteReference {
                        canonical_model: route.canonical_model.clone(),
                        provider_model: route.provider_model.clone(),
                        evidence_family: route.evidence_family.clone(),
                        channel_binding_kind: route.channel_binding_kind.clone(),
                        trust_tier: route.trust_tier.clone(),
                        accepted_cpu_tees: vec![CpuTeeKind::Tdx],
                        e2ee_public_key_digest: String::new(),
                        response_signing_key_digest: None,
                        tls_spki_sha256: None,
                        workload_images: Vec::new(),
                        workload_image_digest: String::new(),
                        model_artifacts: Vec::new(),
                        valid_until: "2099-01-01T00:00:00Z".into(),
                        valid_until_epoch_ms: 4_070_908_800_000,
                    },
                )]),
            },
        );
        let references = ReferenceValuesPayload {
            schema: ReferenceValuesPayload::SCHEMA.into(),
            version: "test".into(),
            issuer: "test".into(),
            valid_from: "2026-07-05T00:00:00Z".into(),
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
            revocation_epoch: 1,
            minimum_acceptable_version: "test".into(),
            providers,
        };
        let registry_digest = sha256_digest(b"registry");
        let reference_values_digest = references.digest().unwrap();
        let mut policy = VerificationPolicy::require_attested_e2ee()
            .with_artifact_digests(registry_digest.clone(), reference_values_digest.clone());
        policy.freshness = FreshnessPolicy::PerRequest;
        let capture = ChutesLiveEvidence {
            schema: ChutesLiveEvidence::SCHEMA.into(),
            provider: route.provider.clone(),
            route_id: route.route_id.clone(),
            evidence_family: route.evidence_family.clone(),
            requested_model: route.requested_model.clone(),
            policy_digest: policy.digest().unwrap(),
            request_nonce: nonce.clone(),
            evidence_endpoint: route.evidence_endpoint.clone(),
            chute_id: "00000000-0000-0000-0000-000000000001".into(),
            instance_id: "00000000-0000-0000-0000-000000000002".into(),
            e2e_public_key_base64: e2e_key,
            quote_base64: base64::engine::general_purpose::STANDARD.encode([7_u8; 48]),
            certificate_der_base64: base64::engine::general_purpose::STANDARD.encode(cert_der),
            gpu_attestation: None,
        };
        let request = VerificationRequest {
            route,
            route_execution_status: "executable".into(),
            chat_executable: true,
            known_unsupported_modes: vec!["streaming".into()],
            expected_freshness_nonce: Some(nonce),
            policy,
            reference_values: references,
            reference_signature: SignatureMetadata {
                signer: "test".into(),
                key_id: "test".into(),
                alg: "ed25519".into(),
            },
            reference_values_digest,
            registry_digest,
            registry_version: "test".into(),
            registry_source: "test".into(),
            registry_sync_completed_at: "2026-07-05T00:00:00Z".into(),
            registry_signature: SignatureMetadata {
                signer: "test".into(),
                key_id: "test".into(),
                alg: "ed25519".into(),
            },
            reference_values_source: "test".into(),
            raw_evidence: serde_json::to_vec(&capture).unwrap(),
        };
        let verifier = StaticTdxQuoteVerifier {
            quote: VerifiedTdxQuote {
                tee_measurement: format!("tdx:mr_td:{}", "11".repeat(48)),
                mr_td: "11".repeat(48),
                mr_config_id: format!("01{}", "00".repeat(47)),
                rtmr0: "22".repeat(48),
                rtmr1: "33".repeat(48),
                rtmr2: "44".repeat(48),
                rtmr3: "55".repeat(48),
                report_data,
                issued_at: "2026-07-05T12:00:00Z".into(),
                expires_at: "2026-07-06T00:00:00Z".into(),
                expires_at_epoch_ms: 1_783_296_000_000,
            },
        };

        let verdict = verify_chutes_live_evidence_with_attestation_verifiers(
            request,
            &verifier,
            &FailClosedGpuAttestationVerifier,
        )
        .unwrap();

        assert_eq!(verdict.status, VerificationStatus::Verified);
        assert!(verdict.request_allowed);
        assert_eq!(
            verdict.check("e2ee_key_binding"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            verdict.check("per_request_freshness"),
            Some(&CheckResult::Verified)
        );
    }

    #[test]
    fn near_live_evidence_verifies_nonce_model_and_live_tls_binding() {
        let route = AttestedRoute {
            provider: "near".into(),
            route_id: "near:gpt-oss-120b:openai-gpt-oss-120b".into(),
            evidence_family: "near_hw_verified_tls".into(),
            requested_model: "gpt-oss-120b".into(),
            provider_model: "openai/gpt-oss-120b".into(),
            canonical_model: "gpt-oss-120b".into(),
            api_endpoint: "https://gpt-oss-120b.completions.near.ai/v1".into(),
            evidence_endpoint: "https://gpt-oss-120b.completions.near.ai/v1/attestation/report"
                .into(),
            adapter_version: "near-live-tls/1".into(),
            freshness_class: FreshnessClass::PerRequest,
            channel_binding_kind: ChannelBindingKind::TeeTerminatedTls,
            trust_tier: TrustTier::HwVerifiedTls,
            alias_confidence: AliasConfidence::Curated,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::ChannelBound,
            streaming_allowed: false,
        };
        let nonce = "66".repeat(32);
        let certificate_der = base64::engine::general_purpose::STANDARD
            .decode(crate::tls::TEST_CERT_DER_BASE64)
            .unwrap();
        let tls_spki = crate::certificate_spki_sha256_hex(&certificate_der).unwrap();
        let signing_address = [0xaa_u8; 20];
        let mut binding_input = signing_address.to_vec();
        binding_input.extend_from_slice(&decode_hex("test TLS SPKI", &tls_spki).unwrap());
        let binding_digest = Sha256::digest(&binding_input)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let report_data = format!("{binding_digest}{nonce}");
        let mr_config_id = format!("01{}", "00".repeat(47));
        let measurement = format!("tdx:mr_config_id:{mr_config_id}");
        let mut providers = BTreeMap::new();
        providers.insert(
            "near".into(),
            ProviderReference {
                accepted_measurements: vec![measurement],
                routes: BTreeMap::from([(
                    route.route_id.clone(),
                    RouteReference {
                        canonical_model: route.canonical_model.clone(),
                        provider_model: route.provider_model.clone(),
                        evidence_family: route.evidence_family.clone(),
                        channel_binding_kind: route.channel_binding_kind.clone(),
                        trust_tier: route.trust_tier.clone(),
                        accepted_cpu_tees: vec![CpuTeeKind::Tdx],
                        e2ee_public_key_digest: String::new(),
                        response_signing_key_digest: None,
                        tls_spki_sha256: None,
                        workload_images: Vec::new(),
                        workload_image_digest: String::new(),
                        model_artifacts: Vec::new(),
                        valid_until: "2099-01-01T00:00:00Z".into(),
                        valid_until_epoch_ms: 4_070_908_800_000,
                    },
                )]),
            },
        );
        let references = ReferenceValuesPayload {
            schema: ReferenceValuesPayload::SCHEMA.into(),
            version: "test".into(),
            issuer: "test".into(),
            valid_from: "2026-07-05T00:00:00Z".into(),
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
            revocation_epoch: 1,
            minimum_acceptable_version: "test".into(),
            providers,
        };
        let registry_digest = sha256_digest(b"registry");
        let reference_values_digest = references.digest().unwrap();
        let mut policy = VerificationPolicy::require_hw_verified_tls()
            .with_artifact_digests(registry_digest.clone(), reference_values_digest.clone());
        policy.freshness = FreshnessPolicy::PerRequest;
        policy.model_binding_requirement = ModelBindingRequirement::Required;
        let raw_report = serde_json::to_vec(&serde_json::json!({
            "intel_quote": "07".repeat(48),
            "request_nonce": nonce,
            "signing_address": format!(
                "0x{}",
                signing_address
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
            "signing_algo": "ecdsa",
            "tls_cert_fingerprint": tls_spki,
            "model_name": route.provider_model,
        }))
        .unwrap();
        let capture = NearLiveEvidence {
            schema: NearLiveEvidence::SCHEMA.into(),
            provider: route.provider.clone(),
            route_id: route.route_id.clone(),
            evidence_family: route.evidence_family.clone(),
            requested_model: route.requested_model.clone(),
            policy_digest: policy.digest().unwrap(),
            request_nonce: nonce.clone(),
            evidence_endpoint: route.evidence_endpoint.clone(),
            live_tls_spki_sha256: tls_spki,
            live_tls_leaf_certificate_der_base64: base64::engine::general_purpose::STANDARD
                .encode(certificate_der),
            raw_attestation_body_base64: base64::engine::general_purpose::STANDARD
                .encode(raw_report),
            gpu_attestation: None,
        };
        let request = VerificationRequest {
            route,
            route_execution_status: "executable".into(),
            chat_executable: true,
            known_unsupported_modes: vec!["streaming".into()],
            expected_freshness_nonce: Some(nonce),
            policy,
            reference_values: references,
            reference_signature: SignatureMetadata {
                signer: "test".into(),
                key_id: "test".into(),
                alg: "ed25519".into(),
            },
            reference_values_digest,
            registry_digest,
            registry_version: "test".into(),
            registry_source: "test".into(),
            registry_sync_completed_at: "2026-07-05T00:00:00Z".into(),
            registry_signature: SignatureMetadata {
                signer: "test".into(),
                key_id: "test".into(),
                alg: "ed25519".into(),
            },
            reference_values_source: "test".into(),
            raw_evidence: serde_json::to_vec(&capture).unwrap(),
        };
        let verifier = StaticTdxQuoteVerifier {
            quote: VerifiedTdxQuote {
                tee_measurement: format!("tdx:mr_td:{}", "11".repeat(48)),
                mr_td: "11".repeat(48),
                mr_config_id,
                rtmr0: "22".repeat(48),
                rtmr1: "33".repeat(48),
                rtmr2: "44".repeat(48),
                rtmr3: "55".repeat(48),
                report_data,
                issued_at: "2026-07-05T12:00:00Z".into(),
                expires_at: "2026-07-06T00:00:00Z".into(),
                expires_at_epoch_ms: 1_783_296_000_000,
            },
        };

        let verdict = verify_near_live_evidence_with_attestation_verifiers(
            request,
            &verifier,
            &FailClosedGpuAttestationVerifier,
        )
        .unwrap();

        assert_eq!(verdict.status, VerificationStatus::Verified);
        assert!(verdict.request_allowed);
        assert_eq!(verdict.check("tls_binding"), Some(&CheckResult::Verified));
        assert_eq!(verdict.model_binding_result, ModelBindingResult::Verified);
    }

    fn verified_tinfoil_quote(report_data: String) -> VerifiedTinfoilQuote {
        VerifiedTinfoilQuote::from_verified_quote(
            crate::TinfoilAttestationFormat::TdxGuestV2,
            EvidenceHardware {
                cpu: CpuTeeKind::Tdx,
                gpu: None,
            },
            "sha256:tinfoil-tee-measurement",
            report_data,
            "2026-07-05T00:00:00Z",
            "2099-01-01T00:00:00Z",
            4_070_908_800_000,
        )
    }

    fn live_tinfoil_capture_json(request: &VerificationRequest) -> Vec<u8> {
        let attestation_doc = TinfoilAttestationDoc {
            format: TINFOIL_TDX_GUEST_V2_FORMAT.into(),
            body: gzip_base64(&[7_u8; 48]),
        };
        let capture = TinfoilLiveCaptureEvidence {
            schema: TinfoilLiveCaptureEvidence::SCHEMA.into(),
            provider: request.route.provider.clone(),
            route_id: request.route.route_id.clone(),
            evidence_family: request.route.evidence_family.clone(),
            requested_model: request.route.requested_model.clone(),
            policy_digest: request.policy.digest().unwrap(),
            nonce: None,
            evidence_endpoint: request.route.evidence_endpoint.clone(),
            live_tls_spki_sha256: crate::tls::TEST_SPKI_SHA256.into(),
            live_tls_leaf_certificate_der_base64: crate::tls::TEST_CERT_DER_BASE64.into(),
            raw_attestation_body_base64: base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&attestation_doc).unwrap()),
        };
        serde_json::to_vec(&capture).unwrap()
    }

    fn gzip_base64(bytes: &[u8]) -> String {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        base64::engine::general_purpose::STANDARD.encode(encoder.finish().unwrap())
    }

    #[test]
    fn dstack_evidence_verifies_tcb_but_does_not_infer_request_binding() {
        let mut request = request_with_dstack_evidence(dstack_evidence());
        request.policy.provenance.workload_image = true;

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert_eq!(
            verdict.check("tcb_compose_hash"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            verdict.check("image_provenance"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            verdict.check("e2ee_key_reference_match"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            verdict.check("e2ee_key_binding"),
            Some(&CheckResult::NotSupported)
        );
        assert_eq!(
            verdict.request_confidentiality_result,
            ConfidentialityResult::Unknown
        );
        assert_eq!(
            verdict.response_integrity_result,
            ResponseIntegrityResult::Unknown
        );
        assert!(!verdict.request_channel_bound);
        assert!(!verdict.response_channel_bound);
    }

    #[test]
    fn dstack_image_provenance_requires_the_complete_signed_manifest() {
        let mut evidence = dstack_evidence();
        let app_compose = concat!(
            "services:\n",
            "  sidecar:\n",
            "    image: venice/sidecar@sha256:",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
            "  worker:\n",
            "    image: venice/worker@sha256:",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        );
        evidence.tcb_info.app_compose = app_compose.into();
        evidence.tcb_info.compose_hash = sha256_digest(app_compose.as_bytes())
            .trim_start_matches("sha256:")
            .into();
        evidence.workload_images = crate::parse_dstack_workload_images(app_compose).unwrap();
        let mut request = request_with_dstack_evidence(evidence);
        request.policy.provenance.workload_image = true;

        let route_reference = request
            .reference_values
            .providers
            .get_mut(&request.route.provider)
            .unwrap()
            .routes
            .get_mut(&request.route.route_id)
            .unwrap();
        route_reference.workload_images.pop();

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(
            verdict.check("image_provenance"),
            Some(&CheckResult::Failed)
        );
        assert_eq!(
            verdict.check("workload_manifest_binding"),
            Some(&CheckResult::Verified)
        );
        assert!(verdict.errors.iter().any(|error| {
            error.code == "image_provenance" && error.message.contains("complete digest-pinned")
        }));
    }

    #[test]
    fn missing_chutes_model_is_not_promoted_to_verified_model_binding() {
        let mut evidence = chutes_evidence();
        evidence.attested_model = None;
        let request = request_with_chutes_evidence(evidence, None);

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(
            verdict.check("model_binding"),
            Some(&CheckResult::NotSupported)
        );
        assert_eq!(
            verdict.model_binding_result,
            ModelBindingResult::NotSupported
        );
        assert_eq!(verdict.artifacts.model_manifest, None);
    }

    #[test]
    fn required_model_binding_fails_when_chutes_model_is_absent() {
        let mut evidence = chutes_evidence();
        evidence.attested_model = None;
        let mut request = request_with_chutes_evidence(evidence, None);
        request.policy.model_binding_requirement = ModelBindingRequirement::Required;

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert_eq!(verdict.check("model_binding"), Some(&CheckResult::Failed));
    }

    #[test]
    fn dstack_evidence_fails_closed_when_tcb_info_is_not_quote_bound() {
        let mut evidence = dstack_evidence();
        evidence.tcb_info.mrtd = "cc".repeat(24);
        let request = request_with_dstack_evidence(evidence);

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert_eq!(
            verdict.check("tcb_compose_hash"),
            Some(&CheckResult::Failed)
        );
    }

    #[test]
    fn chutes_e2ee_evidence_verifies_nonce_and_public_key_binding() {
        let request = request_with_chutes_evidence(chutes_evidence(), None);

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Verified);
        assert!(verdict.request_allowed);
        assert_eq!(
            verdict.check("e2ee_key_binding"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(verdict.check("nonce_binding"), Some(&CheckResult::Verified));
        assert_eq!(
            verdict.artifacts.signing_public_key.as_deref(),
            Some(sha256_digest(chutes_public_key().as_bytes()).as_str())
        );
        assert_eq!(
            verdict.artifacts.e2ee_capability.as_deref(),
            Some("chutes-e2ee")
        );
    }

    #[test]
    fn chutes_gpu_required_fails_closed_without_gpu_attestation_verifier() {
        let mut evidence = chutes_evidence();
        evidence.hardware.gpu = Some(GpuTeeKind::NvidiaCc);
        evidence.gpu_attestation = Some(nvidia_gpu_attestation(&evidence.nonce));
        let request = request_with_chutes_evidence_and_policy(
            evidence,
            None,
            require_attested_e2ee_with_gpu(),
        );

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert_eq!(verdict.check("gpu_tee"), Some(&CheckResult::Failed));
        assert!(verdict.errors.iter().any(|error| {
            error.code == "gpu_tee"
                && error
                    .message
                    .contains("NVIDIA GPU attestation verification backend is not configured")
        }));
    }

    #[test]
    fn chutes_gpu_required_verifies_with_gpu_attestation_verifier() {
        let mut evidence = chutes_evidence();
        evidence.hardware.gpu = Some(GpuTeeKind::NvidiaCc);
        evidence.gpu_attestation = Some(nvidia_gpu_attestation(&evidence.nonce));
        let request = request_with_chutes_evidence_and_policy(
            evidence,
            None,
            require_attested_e2ee_with_gpu(),
        );

        let verdict = verify_chutes_e2ee_evidence_with_gpu_attestation_verifier(
            request,
            &StaticGpuAttestationVerifier,
        )
        .unwrap();

        assert_eq!(verdict.status, VerificationStatus::Verified);
        assert!(verdict.request_allowed);
        assert_eq!(verdict.check("gpu_tee"), Some(&CheckResult::Verified));
        assert_eq!(
            verdict.check("e2ee_key_binding"),
            Some(&CheckResult::Verified)
        );
    }

    #[test]
    fn chutes_per_request_freshness_accepts_expected_nonce() {
        let evidence = chutes_evidence();
        let expected_nonce = evidence.nonce.clone();
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.freshness = FreshnessPolicy::PerRequest;
        let mut request = request_with_chutes_evidence_and_policy(evidence, None, policy);
        request.expected_freshness_nonce = Some(expected_nonce);

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Verified);
        assert!(verdict.request_allowed);
        assert_eq!(verdict.check("nonce_binding"), Some(&CheckResult::Verified));
        assert_eq!(
            verdict.check("per_request_freshness"),
            Some(&CheckResult::Verified)
        );
    }

    #[test]
    fn chutes_per_request_freshness_rejects_unexpected_nonce() {
        let evidence = chutes_evidence();
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.freshness = FreshnessPolicy::PerRequest;
        let mut request = request_with_chutes_evidence_and_policy(evidence, None, policy);
        request.expected_freshness_nonce = Some("55".repeat(32));

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert_eq!(verdict.check("nonce_binding"), Some(&CheckResult::Failed));
        assert_eq!(
            verdict.check("per_request_freshness"),
            Some(&CheckResult::Failed)
        );
    }

    #[test]
    fn chutes_e2ee_evidence_fails_closed_for_report_data_mismatch() {
        let mut evidence = chutes_evidence();
        evidence.report_data = "00".repeat(64);
        let request = request_with_chutes_evidence(evidence, None);

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert_eq!(verdict.check("nonce_binding"), Some(&CheckResult::Failed));
        assert_eq!(
            verdict.check("e2ee_key_binding"),
            Some(&CheckResult::Failed)
        );
    }

    #[test]
    fn chutes_e2ee_evidence_fails_closed_for_untrusted_public_key() {
        let evidence = chutes_evidence();
        let request =
            request_with_chutes_evidence(evidence, Some("sha256:untrusted-public-key".into()));

        let verdict = verify_evidence(request).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert_eq!(verdict.check("nonce_binding"), Some(&CheckResult::Verified));
        assert_eq!(
            verdict.check("e2ee_key_binding"),
            Some(&CheckResult::Failed)
        );
    }

    #[test]
    fn wrong_model_fixture_fails_closed() {
        let raw = include_bytes!("../../../fixtures/evidence/demo-wrong-model.json");
        let verdict = verify_fixture_evidence(request_with_evidence(raw)).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert_eq!(verdict.check("model_binding"), Some(&CheckResult::Failed));
    }

    #[test]
    fn wrong_key_fixture_fails_closed() {
        let raw = include_bytes!("../../../fixtures/evidence/demo-wrong-key.json");
        let verdict = verify_fixture_evidence(request_with_evidence(raw)).unwrap();

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert!(!verdict.request_allowed);
        assert_eq!(
            verdict.check("e2ee_key_binding"),
            Some(&CheckResult::Failed)
        );
    }

    #[test]
    fn fixture_evidence_corpus_matches_expected_outcomes() {
        let corpus: EvidenceCorpus = serde_json::from_str(include_str!(
            "../../../fixtures/corpus/fixture-evidence-corpus.json"
        ))
        .unwrap();
        assert_eq!(corpus.schema, "confidential-inference.evidence-corpus.v1");

        for case in corpus.cases {
            let evidence = std::fs::read(fixtures_root().join(&case.evidence_path))
                .unwrap_or_else(|err| panic!("{}: failed to read evidence: {err}", case.id));
            let policy = case.policy.build();
            let result = match case.evidence_family {
                CorpusEvidenceFamily::FixtureDstack => {
                    verify_evidence(request_with_evidence_and_policy(&evidence, policy))
                }
                CorpusEvidenceFamily::ChutesE2ee => {
                    let evidence: ChutesE2eeEvidence = serde_json::from_slice(&evidence)
                        .unwrap_or_else(|err| {
                            panic!("{}: failed to parse Chutes evidence: {err}", case.id)
                        });
                    verify_evidence(request_with_chutes_evidence_and_policy(
                        evidence, None, policy,
                    ))
                }
            };

            if let Some(expected_error) = &case.expected_error_contains {
                let err = result.unwrap_err();
                assert!(
                    err.to_string().contains(expected_error),
                    "case {} expected error containing {expected_error:?}, got {err}",
                    case.id
                );
                continue;
            }

            let verdict =
                result.unwrap_or_else(|err| panic!("{}: verification errored: {err}", case.id));
            let expected_status = case
                .expected_status
                .as_ref()
                .unwrap_or_else(|| panic!("{}: expected_status is required", case.id));
            let expected_request_allowed = case
                .expected_request_allowed
                .unwrap_or_else(|| panic!("{}: expected_request_allowed is required", case.id));

            assert_eq!(&verdict.status, expected_status, "case {}", case.id);
            assert_eq!(
                verdict.request_allowed, expected_request_allowed,
                "case {}",
                case.id
            );
            for check in &case.expected_failed_checks {
                assert_eq!(
                    verdict.check(check),
                    Some(&CheckResult::Failed),
                    "case {} expected failed check {check}",
                    case.id
                );
            }

            let unexpected_failures = verdict
                .checks
                .iter()
                .filter(|(check, result)| {
                    **result == CheckResult::Failed
                        && !case
                            .expected_failed_checks
                            .iter()
                            .any(|expected| expected == *check)
                })
                .map(|(check, _)| check.as_str())
                .collect::<Vec<_>>();
            assert!(
                unexpected_failures.is_empty(),
                "case {} had unexpected failed checks: {:?}",
                case.id,
                unexpected_failures
            );
        }
    }

    fn fixtures_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
    }

    #[derive(Debug, Deserialize)]
    struct EvidenceCorpus {
        schema: String,
        cases: Vec<EvidenceCorpusCase>,
    }

    #[derive(Debug, Deserialize)]
    struct EvidenceCorpusCase {
        id: String,
        evidence_path: String,
        #[serde(default)]
        evidence_family: CorpusEvidenceFamily,
        policy: CorpusPolicy,
        expected_status: Option<VerificationStatus>,
        expected_request_allowed: Option<bool>,
        expected_error_contains: Option<String>,
        #[serde(default)]
        expected_failed_checks: Vec<String>,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum CorpusEvidenceFamily {
        #[default]
        FixtureDstack,
        ChutesE2ee,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum CorpusPolicy {
        RequireAttestedE2ee,
        RequireAttestedE2eeWithProvenance,
        RequireAttestedE2eeWithGpu,
    }

    impl CorpusPolicy {
        fn build(&self) -> VerificationPolicy {
            match self {
                Self::RequireAttestedE2ee => VerificationPolicy::require_attested_e2ee(),
                Self::RequireAttestedE2eeWithProvenance => require_attested_e2ee_with_provenance(),
                Self::RequireAttestedE2eeWithGpu => require_attested_e2ee_with_gpu(),
            }
        }
    }
}
