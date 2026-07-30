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
    export_dcap_tdx_collateral_metrics_otlp_http,
    export_dcap_tdx_collateral_metrics_otlp_http_with_timeout,
    export_dcap_tdx_collateral_metrics_otlp_json,
    export_dcap_tdx_collateral_metrics_prometheus_text, DcapTdxCollateralCacheEvent,
    DcapTdxCollateralCacheMetric, DcapTdxCollateralFetchEvent, DcapTdxCollateralFetchMetric,
    DcapTdxCollateralFetchPolicy, DcapTdxCollateralFetcher, DcapTdxCollateralMetricEvent,
    DcapTdxCollateralMetricsRecorder, DcapTdxCollateralQueueEvent, DcapTdxCollateralQueueMetric,
    DcapTdxCollateralResolver, InMemoryDcapTdxCollateralMetricsRecorder,
    NoopDcapTdxCollateralMetricsRecorder, PccsDcapTdxCollateralFetcher,
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
    EvidenceRequest, ProviderAdapter, ProviderChatRequest, ProviderError,
    ProviderRequestConfidentiality, Result, SdkAppE2eeConfig, SdkAppE2eeSecretKey,
    SdkAppE2eeSession, SdkEncryptedChatEnvelope, SdkEncryptedChatResponseEnvelope,
    SDK_APP_E2EE_ALG,
};
pub use reference_values_generator::{
    generate_app_e2ee_reference_values, generate_tinfoil_live_reference_values,
    AppE2eeReferenceEvidence, AppE2eeReferenceValuesInput, TinfoilLiveReferenceValuesInput,
};
pub use registry::{
    EncryptionRequirement, ModelAliasCase, ModelAliasMatrix, ModelAliasMatrixEnvelope,
    ModelAliasProviderRoute, ProviderRegistry, ProviderRegistryDiffReport,
    ProviderRegistryEnvelope, ProviderRegistryPin, ProviderRegistrySigningIdentity,
    RegistryDiffChange, RegistryDiffKind, RegistryModel, RouteDefinition, RouteLifecycle,
    SourceSyncRun, StreamingSupport,
};
