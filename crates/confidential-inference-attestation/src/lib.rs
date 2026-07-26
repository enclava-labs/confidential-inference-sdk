//! Library-grade attestation primitives for the Confidential Inference SDK.
//!
//! This crate intentionally has no dependency on provider adapters, OpenAI
//! request types, proxy code, or FFI. The current implementation includes the
//! stable policy/verdict surface and a deterministic fixture verifier used by
//! the SDK demo while production provider verifiers are reconciled and ported.

mod aci;
mod canonical;
mod e2ee;
mod error;
mod evidence;
mod gpu;
mod policy;
mod reference_values;
mod signature;
mod tcb;
mod tdx;
mod tinfoil;
mod tls;
mod verdict;
mod verifier;

pub use aci::{
    aci_expected_report_data, verify_aci_workload_keyset, AciCapabilities, AciEvidence,
    AciKeyAlgorithm, AciKeyUsage, AciKeysetCheckpoint, AciQuoteVerificationRequest,
    AciQuoteVerifier, AciSourceProvenance, AciVerificationRequest, AciWorkloadKey,
    AciWorkloadKeyset, AciWorkloadKeysetEnvelope, FailClosedAciQuoteVerifier, VerifiedAciQuote,
    VerifiedAciWorkloadKeyset,
};
pub use canonical::{canonical_digest, canonical_json, sha256_digest, MAX_SAFE_JSON_INT};
pub use e2ee::{
    chutes_expected_report_data_prefix, chutes_provider_nonce,
    verify_chutes_e2ee_report_data_binding, ChutesE2eeReportDataBinding,
};
pub use error::{AttestationError, Result};
pub use evidence::{
    parse_dstack_workload_images, ArtifactDigest, ChannelBindingEvidence, ChutesE2eeEvidence,
    DstackEvidence, EvidenceHardware, FixtureEvidence, IonetConfidentialEvidence,
    NvidiaGpuAttestationEvidence, TinfoilLiveCaptureEvidence, TinfoilTlsEvidence, WorkloadImage,
};
pub use gpu::{
    verify_nvidia_nras_jwt_with_jwks_json, FailClosedGpuAttestationVerifier,
    GpuAttestationVerifier, NvidiaGpuAttestationVerificationRequest, NvidiaNrasJwtVerifier,
    VerifiedGpuAttestation, VerifiedNvidiaNrasJwt, NVIDIA_NRAS_CLAIMS_VERSION, NVIDIA_NRAS_ISSUER,
};
pub use policy::{
    BoundDataRequirement, ChannelBindingRequirement, CpuTeeKind, CpuTeeRequirement,
    EnforcementMode, FreshnessPolicy, GpuTeeKind, GpuTeeRequirement, HardwareRequirement, Millis,
    ModelBindingRequirement, ProvenanceRequirement, ResponseIntegrityRequirement,
    StaleVerdictPolicy, VerificationPolicy,
};
pub use reference_values::{
    ProviderReference, ReferenceSignature, ReferenceValuesEnvelope, ReferenceValuesPayload,
    ReferenceValuesPin, ReferenceValuesSigningIdentity, RouteReference,
};
pub use signature::{
    default_trusted_signing_keys, verify_artifact_signature, verify_artifact_signature_with_keys,
    ArtifactSignature, TrustedSigningKey, ALIAS_MATRIX_FIXTURE_SIGNING_KEY_ID,
    ALIAS_MATRIX_FIXTURE_SIGNING_PUBLIC_KEY_BASE64URL, COMPATIBILITY_FIXTURE_SIGNING_KEY_ID,
    COMPATIBILITY_FIXTURE_SIGNING_PUBLIC_KEY_BASE64URL, DEMO_SIGNING_KEY_ID,
    DEMO_SIGNING_PUBLIC_KEY_BASE64URL, PHASE2_FIXTURE_SIGNING_KEY_ID,
    PHASE2_FIXTURE_SIGNING_PUBLIC_KEY_BASE64URL,
};
pub use tcb::{
    verify_dstack_tcb_compose_hash, DstackTcbInfo, TcbComposeHashBinding, TdxQuoteMeasurements,
};
pub use tdx::{
    DcapTdxCollateralBundle, DcapTdxCollateralBundleEnvelope, DcapTdxCollateralCache,
    DcapTdxCollateralSource, DcapTdxTinfoilQuoteVerifier,
};
pub use tinfoil::{
    decode_tinfoil_attestation_body, parse_tinfoil_live_capture, FailClosedTinfoilQuoteVerifier,
    ParsedTinfoilLiveCapture, TinfoilAttestationDoc, TinfoilAttestationFormat,
    TinfoilQuoteVerificationRequest, TinfoilQuoteVerifier, VerifiedTinfoilQuote,
    TINFOIL_SEV_SNP_GUEST_V2_FORMAT, TINFOIL_TDX_GUEST_V2_FORMAT,
};
pub use tls::{
    certificate_spki_sha256_hex, certificate_validity_epoch_millis,
    verify_certificate_spki_report_data_binding, verify_tls_spki_report_data_binding,
    TlsSpkiReportDataBinding,
};
pub use verdict::{
    AliasConfidence, AttestationVerdict, AttestedRoute, AttributionSource, ChannelBindingKind,
    CheckOutcome, CheckResult, ConfidentialityResult, FreshnessClass, ModelBindingResult,
    ResponseIntegrityResult, RouteAttribution, RoutePartyAttribution, RoutePartyRole,
    SignatureMetadata, TrustTier, ValidityWindow, VerdictArtifacts, VerdictError,
    VerificationStatus,
};
pub use verifier::{
    format_utc_timestamp_millis, parse_utc_timestamp_millis, verify_chutes_e2ee_evidence,
    verify_chutes_e2ee_evidence_with_gpu_attestation_verifier, verify_dstack_evidence,
    verify_evidence, verify_evidence_with_attestation_verifiers,
    verify_evidence_with_gpu_attestation_verifier, verify_evidence_with_tinfoil_quote_verifier,
    verify_fixture_evidence, verify_ionet_confidential_evidence,
    verify_ionet_confidential_evidence_with_gpu_attestation_verifier,
    verify_tinfoil_live_capture_with_quote_verifier, verify_tinfoil_tls_evidence,
    verify_tinfoil_tls_evidence_with_quote_verifier, VerificationRequest,
};
