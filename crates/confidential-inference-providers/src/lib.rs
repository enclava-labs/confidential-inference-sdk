mod chutes;
mod chutes_live;
mod compatibility;
mod contrast;
mod dcap_tdx;
mod demo;
mod dstack;
mod http;
mod near;
mod nvidia;
mod phase2_fixtures;
mod provider;
#[cfg(test)]
mod provider_evidence_corpus;
mod reference_values_generator;
mod registry;
mod sev_snp;
mod tls;
pub use sev_snp::{AmdKdsSevSnpVcekResolver, SevSnpVcekResolver};

pub use chutes_live::ChutesHttpProvider;
pub use compatibility::{
    CacheabilityClass, CredentialKind, ModelBindingSupport, ModelIdRewrite, ModelListingBehavior,
    OpenAiEndpoint, ProviderCompatibility, ProviderCompatibilityMatrix,
    ProviderCompatibilityMatrixEnvelope, RouteExecutionStatus, TokenParameterRewrite,
};
pub use confidential_inference_attestation::TinfoilLiveCaptureEvidence;
pub use contrast::{
    require_privatemode_contrast_images_verified, summarize_privatemode_contrast_initdata_texts,
    summarize_privatemode_contrast_manifest_bytes, verify_privatemode_contrast_active_evidence,
    PrivatemodeContrastActiveEvidence, PrivatemodeContrastActiveVerification,
    PrivatemodeContrastImageSummary, PrivatemodeContrastManifestSummary,
};
pub use dcap_tdx::{
    DcapTdxCollateralCacheEvent, DcapTdxCollateralCacheMetric, DcapTdxCollateralFetchEvent,
    DcapTdxCollateralFetchMetric, DcapTdxCollateralFetchPolicy, DcapTdxCollateralFetcher,
    DcapTdxCollateralMetricEvent, DcapTdxCollateralMetricsRecorder, DcapTdxCollateralQueueEvent,
    DcapTdxCollateralQueueMetric, DcapTdxCollateralResolver,
    InMemoryDcapTdxCollateralMetricsRecorder, NoopDcapTdxCollateralMetricsRecorder,
    PccsDcapTdxCollateralFetcher,
};
pub use demo::{DemoEvidenceMode, DemoProvider};
pub use http::{
    ConfidentialHttpProvider, DstackHttpProvider, OpenAiHttpProvider, PhalaHttpProvider,
    TinfoilHttpProvider,
};
pub use near::NearHttpProvider;
#[allow(deprecated)]
pub use nvidia::{
    extract_nras_token, NvidiaNrasRemoteClient, NVIDIA_NRAS_ATTEST_GPU_V3_URL,
    NVIDIA_NRAS_ATTEST_GPU_V4_URL, NVIDIA_NRAS_CLAIMS_VERSION, NVIDIA_NRAS_JWKS_URL,
};
pub use phase2_fixtures::{TinfoilFixtureProvider, VeniceFixtureProvider};
pub use provider::{
    DispatchOutcome, EvidenceRequest, ProviderAdapter, ProviderChatRequest, ProviderChatStream,
    ProviderEmbeddingsRequest, ProviderError, ProviderRequestConfidentiality,
    ProviderResponseManageRequest, ResponseManageOperation, Result, SdkAppE2eeConfig,
    SdkAppE2eeSecretKey, SdkAppE2eeSession, SdkEncryptedChatEnvelope,
    SdkEncryptedChatResponseEnvelope, SDK_APP_E2EE_ALG,
};
pub use reference_values_generator::{
    generate_app_e2ee_reference_values, generate_chutes_live_reference_values,
    generate_tinfoil_live_reference_values, AppE2eeReferenceEvidence, AppE2eeReferenceValuesInput,
    ChutesLiveReferenceValuesInput, TinfoilLiveReferenceValuesInput,
};
pub use registry::{
    EncryptionRequirement, ModelAliasCase, ModelAliasMatrix, ModelAliasMatrixEnvelope,
    ModelAliasProviderRoute, ProviderRegistry, ProviderRegistryDiffReport,
    ProviderRegistryEnvelope, ProviderRegistryPin, RegistryDiffChange, RegistryDiffKind,
    RegistryModel, RouteDefinition, RouteLifecycle, SourceSyncRun, StreamingSupport,
};

pub use tls::reqwest_client_builder;

/// Fuzz targets driving crate-internal parsers over arbitrary bytes.
/// Result values are deliberately discarded; crashes and panics are the
/// signal, not verifier outcomes.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    use crate::provider::EvidenceRequest;
    use crate::registry::{
        EncryptionRequirement, RouteDefinition, RouteLifecycle, StreamingSupport,
    };
    use confidential_inference_attestation::{
        AliasConfidence, BoundDataRequirement, ChannelBindingKind, FreshnessClass,
        ResponseIntegrityRequirement, TrustTier,
    };

    fn fuzz_route() -> RouteDefinition {
        RouteDefinition {
            route_id: "fuzz:model:model".into(),
            route_status: RouteLifecycle::Active,
            provider: "fuzz".into(),
            provider_model: "fuzz-model".into(),
            evidence_family: "dstack_app_e2ee".into(),
            api_base_url: "https://fuzz.invalid/v1".into(),
            evidence_endpoint: "https://fuzz.invalid/evidence".into(),
            adapter_version: "fuzz".into(),
            freshness_class: FreshnessClass::PerRequest,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            request_confidentiality_requirement: BoundDataRequirement::NotRequired,
            response_confidentiality_requirement: BoundDataRequirement::NotRequired,
            response_integrity_requirement: ResponseIntegrityRequirement::NotRequired,
            accepted_gpu_tees: Vec::new(),
            request_encryption: EncryptionRequirement::NotRequired,
            response_decryption: EncryptionRequirement::NotRequired,
            streaming: StreamingSupport::Unsupported,
            alias_confidence: AliasConfidence::Curated,
        }
    }

    fn fuzz_request() -> EvidenceRequest {
        EvidenceRequest {
            requested_model: "fuzz-model".into(),
            policy_digest: "sha256:fuzz".into(),
            nonce: Some("00".repeat(32)),
        }
    }

    pub fn normalize_dstack(data: &[u8]) {
        let _ =
            crate::dstack::normalize_dstack_evidence_bytes(&fuzz_route(), &fuzz_request(), data);
    }

    pub fn normalize_chutes_e2ee(data: &[u8]) {
        let _ = crate::chutes::normalize_chutes_e2ee_evidence_bytes(
            &fuzz_route(),
            &fuzz_request(),
            data,
        );
    }

    pub fn sse_frames(data: &[u8]) {
        let mut buffer = data.to_vec();
        // Drive the SSE frame splitter used by chat_stream: repeatedly drain
        // frames, then feed the remainder byte-by-byte.
        for _ in 0..data.len() {
            match crate::http::take_sse_frame(&mut buffer) {
                crate::http::SseTake::Incomplete => break,
                _ => {}
            }
        }
    }

    pub fn contrast_manifest(data: &[u8]) {
        let _ = crate::contrast::summarize_privatemode_contrast_manifest_bytes(data);
        if let Ok(text) = std::str::from_utf8(data) {
            let _ = crate::contrast::extract_marker_image_values(
                text,
                "io.kubernetes.cri.image-name\\\": \\\"",
            );
        }
    }

    pub fn contrast_initdata(data: &[u8]) {
        if let Ok(text) = std::str::from_utf8(data) {
            let _ = crate::contrast::summarize_privatemode_contrast_initdata_texts([text]);
        }
    }
}
