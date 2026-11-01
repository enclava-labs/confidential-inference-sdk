//! Fuzzing entry points: each function takes raw bytes, drives an internal
//! parser/verifier, and discards the result. Only built under `--cfg fuzzing`.

use crate::policy::VerificationPolicy;
use crate::verdict::{FreshnessClass, SignatureMetadata};
use crate::{
    AliasConfidence, AttestedRoute, BoundDataRequirement, ChannelBindingKind,
    ResponseIntegrityRequirement, TrustTier,
};

const LIVE_CAPTURE: &[u8] =
    include_bytes!("../../../fixtures/evidence/sev-snp/tinfoil-live-capture.json");
const LIVE_VCEK: &[u8] = include_bytes!("../../../fixtures/evidence/sev-snp/tinfoil-vcek.der");
const LIVE_CAPTURED_AT_MS: u64 = 1_792_500_345_231;

pub fn timestamp(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = crate::parse_utc_timestamp_millis(text);
        let _ = crate::format_utc_timestamp_millis(
            crate::parse_utc_timestamp_millis(text).unwrap_or(0),
        );
    }
}

pub fn tinfoil_live_capture(data: &[u8]) {
    let _ = crate::parse_tinfoil_live_capture(data);
}

pub fn sev_snp_report(data: &[u8]) {
    if let Ok(parsed) = crate::parse_tinfoil_live_capture(LIVE_CAPTURE) {
        let request = crate::TinfoilQuoteVerificationRequest {
            capture: &parsed.capture,
            attestation_format: crate::TinfoilAttestationFormat::SevSnpGuestV2,
            quote_bytes: data,
            live_tls_leaf_certificate_der: &parsed.live_tls_leaf_certificate_der,
            live_tls_spki_sha256: &parsed.capture.live_tls_spki_sha256,
        };
        let _ = crate::verify_tinfoil_quote_with_vcek_at(&request, LIVE_VCEK, LIVE_CAPTURED_AT_MS);
    }
}

pub fn evidence(data: &[u8]) {
    let Ok(envelope) = crate::ReferenceValuesEnvelope::bundled_demo() else {
        return;
    };
    for evidence_family in [
        "dstack_app_e2ee",
        "chutes_e2ee",
        "tinfoil_hw_verified_tls",
        "chutes_live_e2ee",
        "near_hw_verified_tls",
    ] {
        let route = AttestedRoute {
            provider: "fuzz".into(),
            route_id: "fuzz:model:model".into(),
            evidence_family: evidence_family.into(),
            requested_model: "model".into(),
            provider_model: "model".into(),
            canonical_model: "model".into(),
            api_endpoint: "https://example.invalid/v1".into(),
            evidence_endpoint: "https://example.invalid/attestation".into(),
            adapter_version: "fuzz/1".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            alias_confidence: AliasConfidence::Curated,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            streaming_allowed: false,
        };
        let policy = VerificationPolicy::require_attested_e2ee();
        let request = crate::VerificationRequest {
            route,
            route_execution_status: "fuzz".into(),
            chat_executable: true,
            known_unsupported_modes: Vec::new(),
            expected_freshness_nonce: None,
            policy,
            reference_values: envelope.payload.clone(),
            reference_signature: SignatureMetadata {
                signer: envelope.signature.signer.clone(),
                key_id: envelope.signature.key_id.clone(),
                alg: envelope.signature.alg.clone(),
            },
            reference_values_digest: "sha256:".to_owned() + &"00".repeat(32),
            registry_digest: "sha256:".to_owned() + &"00".repeat(32),
            registry_version: "fuzz".into(),
            registry_source: "fuzz".into(),
            registry_sync_completed_at: "2026-07-05T00:00:00Z".into(),
            registry_signature: SignatureMetadata {
                signer: "fuzz".into(),
                key_id: "fuzz".into(),
                alg: "ed25519".into(),
            },
            reference_values_source: "fuzz".into(),
            raw_evidence: data.to_vec(),
        };
        let _ = crate::verify_evidence(request);
    }
}
