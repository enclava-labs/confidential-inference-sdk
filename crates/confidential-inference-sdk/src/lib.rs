use base64::Engine;
use confidential_inference_attestation::{
    chutes_provider_nonce, parse_tinfoil_live_capture, sha256_digest,
    verify_evidence_with_attestation_verifiers, ArtifactSignature, AttestationError,
    AttestationVerdict, AttestedRoute, BoundDataRequirement, ChannelBindingKind,
    ChutesLiveEvidence, CpuTeeRequirement, EnforcementMode, FailClosedGpuAttestationVerifier,
    FailClosedTinfoilQuoteVerifier, FreshnessPolicy, GpuAttestationVerifier, GpuTeeRequirement,
    ModelBindingRequirement, NearLiveEvidence, ReferenceValuesEnvelope, ReferenceValuesPayload,
    ReferenceValuesPin, ResponseIntegrityRequirement, ResponseIntegrityResult, SignatureMetadata,
    StaleVerdictPolicy, TinfoilAttestationFormat, TinfoilQuoteVerifier, TrustTier,
    TrustedSigningKey, VerificationPolicy, VerificationRequest,
};
use confidential_inference_openai::{
    ChatCompletionRequest, ChatCompletionResponse, ChatMessage, Model, ModelList,
    ResponseCompatibilityError, ResponseCreateRequest, ResponseInput, ResponseObject,
};
use confidential_inference_providers::{
    ChutesHttpProvider, ConfidentialHttpProvider, DcapTdxCollateralResolver, DemoProvider,
    EncryptionRequirement, EvidenceRequest, ModelBindingSupport, NearHttpProvider,
    NvidiaNrasRemoteClient, OpenAiEndpoint, OpenAiHttpProvider, ProviderAdapter,
    ProviderCompatibility, ProviderCompatibilityMatrix, ProviderError, ProviderRegistry,
    ProviderRegistryEnvelope, ProviderRegistryPin, RegistryModel, RouteDefinition,
    RouteExecutionStatus, RouteLifecycle, TinfoilHttpProvider,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Notify;
use tracing::Instrument;
use zeroize::Zeroizing;

const DEFAULT_REMOTE_REGISTRY_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_OTLP_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const CACHE_CLOCK_JUMP_REVALIDATION_THRESHOLD_MS: u64 = 60_000;
#[cfg(test)]
const SINGLE_FLIGHT_MAX_WAITERS: usize = 1;
#[cfg(not(test))]
const SINGLE_FLIGHT_MAX_WAITERS: usize = 64;

type TimeSource = Arc<dyn Fn() -> u64 + Send + Sync>;

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Clone)]
struct ClientApiKey(Zeroizing<String>);

impl ClientApiKey {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ClientApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl From<String> for ClientApiKey {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("attestation failed: {0}")]
    Attestation(#[from] AttestationError),

    #[error("provider failed: {0}")]
    Provider(#[from] ProviderError),

    #[error("provider {0} is not registered")]
    UnknownProvider(String),

    #[error("no active route for provider {provider:?} and model {model}")]
    RouteNotFound {
        provider: Option<String>,
        model: String,
    },

    #[error("no {purpose} route satisfies policy for provider {provider:?} and model {model}")]
    RouteSelectionFailed {
        provider: Option<String>,
        model: String,
        purpose: &'static str,
    },

    #[error("all policy-compatible chat route attempts failed for model {model}: {errors:?}")]
    RouteAttemptsFailed { model: String, errors: Vec<String> },

    #[error("invalid provider routing configuration for model {model}: {message}")]
    InvalidProviderRouting { model: String, message: String },

    #[error("verification policy denied request for route {route_id}")]
    PolicyDenied {
        route_id: String,
        verdict: Box<AttestationVerdict>,
    },

    #[error("streaming is not supported for route {route_id} under the selected policy")]
    StreamingNotSupported { route_id: String },

    #[error("Responses compatibility failed: {0}")]
    ResponseCompatibility(#[from] ResponseCompatibilityError),

    #[error("response JSON serialization failed: {0}")]
    ResponseJsonSerialization(String),

    #[error("metrics export failed: {0}")]
    MetricsExport(String),

    #[error("verified route expired at {expires_at}")]
    VerifiedRouteExpired { expires_at: String },

    #[error(
        "verified route {route_id} was bound to requested model {verified_model}, but chat request used model {request_model}"
    )]
    VerifiedRouteModelMismatch {
        route_id: String,
        verified_model: String,
        request_model: String,
    },

    #[error("verification wait queue is full for route {route_id}; max_waiters={max_waiters}")]
    VerificationWaitQueueFull {
        route_id: String,
        max_waiters: usize,
    },

    #[error("timed out waiting for in-flight verification for route {route_id}")]
    VerificationWaitTimeout { route_id: String },

    #[error("chat completion model was not configured")]
    MissingModel,

    #[error("chat completion messages were not configured")]
    MissingMessages,

    #[error("registry cache failed: {0}")]
    RegistryCache(String),

    #[error("reference values cache failed: {0}")]
    ReferenceValuesCache(String),

    #[error(
        "verification policy uses {enforcement:?} enforcement; call allow_insecure_plaintext(true) to acknowledge that observe/disabled modes can send plaintext or policy-failing traffic"
    )]
    InsecurePolicyRequiresOptIn { enforcement: EnforcementMode },
}

#[derive(Clone, Debug)]
pub enum RegistrySource {
    Bundled,
    Remote {
        url: String,
        fallback: Box<ProviderRegistryEnvelope>,
        cache_path: Option<PathBuf>,
    },
    Custom {
        source: String,
        registry: Box<ProviderRegistryEnvelope>,
    },
}

#[derive(Clone, Debug)]
pub enum ReferenceValuesSource {
    Bundled,
    Remote {
        url: String,
        fallback: Box<ReferenceValuesEnvelope>,
        cache_path: Option<PathBuf>,
    },
    Custom {
        source: String,
        reference_values: Box<ReferenceValuesEnvelope>,
    },
}

impl RegistrySource {
    pub fn bundled() -> Self {
        Self::Bundled
    }

    pub fn remote(url: impl Into<String>, registry: ProviderRegistryEnvelope) -> Self {
        Self::Remote {
            url: url.into(),
            fallback: Box::new(registry),
            cache_path: None,
        }
    }

    pub fn remote_with_cache(
        url: impl Into<String>,
        registry: ProviderRegistryEnvelope,
        cache_path: impl Into<PathBuf>,
    ) -> Self {
        Self::Remote {
            url: url.into(),
            fallback: Box::new(registry),
            cache_path: Some(cache_path.into()),
        }
    }

    pub fn custom(source: impl Into<String>, registry: ProviderRegistryEnvelope) -> Self {
        Self::Custom {
            source: source.into(),
            registry: Box::new(registry),
        }
    }

    async fn into_envelope_and_source(
        self,
        registry_pin: Option<&ProviderRegistryPin>,
        trusted_signing_keys: &[TrustedSigningKey],
        now_epoch_millis: u64,
    ) -> Result<(ProviderRegistryEnvelope, String)> {
        match self {
            RegistrySource::Bundled => {
                Ok((ProviderRegistryEnvelope::bundled_demo()?, "bundled".into()))
            }
            RegistrySource::Remote {
                url,
                fallback,
                cache_path,
            } => {
                select_remote_registry(
                    url,
                    *fallback,
                    cache_path,
                    registry_pin,
                    trusted_signing_keys,
                    now_epoch_millis,
                )
                .await
            }
            RegistrySource::Custom { source, registry } => {
                Ok((*registry, registry_source_label("custom", source)))
            }
        }
    }
}

impl ReferenceValuesSource {
    pub fn bundled() -> Self {
        Self::Bundled
    }

    pub fn remote(url: impl Into<String>, reference_values: ReferenceValuesEnvelope) -> Self {
        Self::Remote {
            url: url.into(),
            fallback: Box::new(reference_values),
            cache_path: None,
        }
    }

    pub fn remote_with_cache(
        url: impl Into<String>,
        reference_values: ReferenceValuesEnvelope,
        cache_path: impl Into<PathBuf>,
    ) -> Self {
        Self::Remote {
            url: url.into(),
            fallback: Box::new(reference_values),
            cache_path: Some(cache_path.into()),
        }
    }

    pub fn custom(source: impl Into<String>, reference_values: ReferenceValuesEnvelope) -> Self {
        Self::Custom {
            source: source.into(),
            reference_values: Box::new(reference_values),
        }
    }

    async fn into_envelope_and_source(
        self,
        reference_values_pin: Option<&ReferenceValuesPin>,
        trusted_signing_keys: &[TrustedSigningKey],
        now_epoch_millis: u64,
    ) -> Result<(ReferenceValuesEnvelope, String)> {
        match self {
            ReferenceValuesSource::Bundled => {
                Ok((ReferenceValuesEnvelope::bundled_demo()?, "bundled".into()))
            }
            ReferenceValuesSource::Remote {
                url,
                fallback,
                cache_path,
            } => {
                select_remote_reference_values(
                    url,
                    *fallback,
                    cache_path,
                    reference_values_pin,
                    trusted_signing_keys,
                    now_epoch_millis,
                )
                .await
            }
            ReferenceValuesSource::Custom {
                source,
                reference_values,
            } => Ok((*reference_values, registry_source_label("custom", source))),
        }
    }
}

async fn select_remote_registry(
    url: String,
    fallback: ProviderRegistryEnvelope,
    cache_path: Option<PathBuf>,
    registry_pin: Option<&ProviderRegistryPin>,
    trusted_signing_keys: &[TrustedSigningKey],
    now_epoch_millis: u64,
) -> Result<(ProviderRegistryEnvelope, String)> {
    let fallback_registry = fallback
        .clone()
        .into_verified_payload_with_keys(trusted_signing_keys)?;

    let cached = cache_path.as_deref().and_then(|cache_path| {
        accepted_registry_update(
            read_registry_cache(cache_path)?,
            &fallback_registry,
            registry_pin,
            trusted_signing_keys,
            now_epoch_millis,
        )
    });
    let baseline_registry = cached
        .as_ref()
        .map(|(_, registry)| registry)
        .unwrap_or(&fallback_registry);

    if let Ok(candidate) = fetch_remote_registry_envelope(&url).await {
        if let Some((candidate, _candidate_registry)) = accepted_registry_update(
            candidate,
            baseline_registry,
            registry_pin,
            trusted_signing_keys,
            now_epoch_millis,
        ) {
            if let Some(cache_path) = cache_path.as_deref() {
                write_registry_cache(cache_path, &candidate)?;
            }
            return Ok((candidate, registry_source_label("remote", url)));
        }
    }

    if let Some((cached, _cached_registry)) = cached {
        return Ok((cached, registry_source_label("remote-cache", url)));
    }

    Ok((fallback, registry_source_label("remote-fallback", url)))
}

async fn select_remote_reference_values(
    url: String,
    fallback: ReferenceValuesEnvelope,
    cache_path: Option<PathBuf>,
    reference_values_pin: Option<&ReferenceValuesPin>,
    trusted_signing_keys: &[TrustedSigningKey],
    now_epoch_millis: u64,
) -> Result<(ReferenceValuesEnvelope, String)> {
    let fallback_reference_values = fallback
        .clone()
        .into_verified_payload_with_keys(trusted_signing_keys)?;

    let cached = cache_path.as_deref().and_then(|cache_path| {
        accepted_reference_values_update(
            read_reference_values_cache(cache_path)?,
            &fallback_reference_values,
            reference_values_pin,
            trusted_signing_keys,
            now_epoch_millis,
        )
    });
    let baseline_reference_values = cached
        .as_ref()
        .map(|(_, reference_values)| reference_values)
        .unwrap_or(&fallback_reference_values);

    if let Ok(candidate) = fetch_remote_reference_values_envelope(&url).await {
        if let Some((candidate, _candidate_reference_values)) = accepted_reference_values_update(
            candidate,
            baseline_reference_values,
            reference_values_pin,
            trusted_signing_keys,
            now_epoch_millis,
        ) {
            if let Some(cache_path) = cache_path.as_deref() {
                write_reference_values_cache(cache_path, &candidate)?;
            }
            return Ok((candidate, registry_source_label("remote", url)));
        }
    }

    if let Some((cached, _cached_reference_values)) = cached {
        return Ok((cached, registry_source_label("remote-cache", url)));
    }

    Ok((fallback, registry_source_label("remote-fallback", url)))
}

fn accepted_registry_update(
    candidate: ProviderRegistryEnvelope,
    fallback_registry: &ProviderRegistry,
    registry_pin: Option<&ProviderRegistryPin>,
    trusted_signing_keys: &[TrustedSigningKey],
    now_epoch_millis: u64,
) -> Option<(ProviderRegistryEnvelope, ProviderRegistry)> {
    let candidate_registry = candidate
        .clone()
        .into_verified_update_from_with_keys(fallback_registry, trusted_signing_keys)
        .ok()?;
    let candidate_digest = candidate_registry.digest().ok()?;
    if let Some(pin) = registry_pin {
        pin.verify_envelope_with_digest_at(&candidate, &candidate_digest, now_epoch_millis)
            .ok()?;
    }
    Some((candidate, candidate_registry))
}

fn accepted_reference_values_update(
    candidate: ReferenceValuesEnvelope,
    fallback_reference_values: &ReferenceValuesPayload,
    reference_values_pin: Option<&ReferenceValuesPin>,
    trusted_signing_keys: &[TrustedSigningKey],
    now_epoch_millis: u64,
) -> Option<(ReferenceValuesEnvelope, ReferenceValuesPayload)> {
    let candidate_payload = candidate
        .clone()
        .into_verified_update_from_with_keys(fallback_reference_values, trusted_signing_keys)
        .ok()?;
    let candidate_digest = candidate_payload.digest().ok()?;
    if let Some(pin) = reference_values_pin {
        pin.verify_envelope_with_digest_at(&candidate, &candidate_digest, now_epoch_millis)
            .ok()?;
    }
    Some((candidate, candidate_payload))
}

fn read_registry_cache(cache_path: &Path) -> Option<ProviderRegistryEnvelope> {
    let bytes = std::fs::read(cache_path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn read_reference_values_cache(cache_path: &Path) -> Option<ReferenceValuesEnvelope> {
    let bytes = std::fs::read(cache_path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_registry_cache(cache_path: &Path, envelope: &ProviderRegistryEnvelope) -> Result<()> {
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            ClientError::RegistryCache(format!(
                "failed to create cache directory {}: {error}",
                parent.display()
            ))
        })?;
    }

    let bytes = serde_json::to_vec(envelope).map_err(|error| {
        ClientError::RegistryCache(format!("failed to serialize registry cache: {error}"))
    })?;
    let mut tmp_name = cache_path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| OsString::from("registry-cache"));
    tmp_name.push(".tmp");
    let tmp_path = cache_path.with_file_name(tmp_name);

    std::fs::write(&tmp_path, bytes).map_err(|error| {
        ClientError::RegistryCache(format!(
            "failed to write cache file {}: {error}",
            tmp_path.display()
        ))
    })?;
    std::fs::rename(&tmp_path, cache_path).map_err(|error| {
        let _ = std::fs::remove_file(&tmp_path);
        ClientError::RegistryCache(format!(
            "failed to replace cache file {}: {error}",
            cache_path.display()
        ))
    })?;
    Ok(())
}

fn write_reference_values_cache(
    cache_path: &Path,
    envelope: &ReferenceValuesEnvelope,
) -> Result<()> {
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            ClientError::ReferenceValuesCache(format!(
                "failed to create cache directory {}: {error}",
                parent.display()
            ))
        })?;
    }

    let bytes = serde_json::to_vec(envelope).map_err(|error| {
        ClientError::ReferenceValuesCache(format!(
            "failed to serialize reference values cache: {error}"
        ))
    })?;
    let mut tmp_name = cache_path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| OsString::from("reference-values-cache"));
    tmp_name.push(".tmp");
    let tmp_path = cache_path.with_file_name(tmp_name);

    std::fs::write(&tmp_path, bytes).map_err(|error| {
        ClientError::ReferenceValuesCache(format!(
            "failed to write cache file {}: {error}",
            tmp_path.display()
        ))
    })?;
    std::fs::rename(&tmp_path, cache_path).map_err(|error| {
        let _ = std::fs::remove_file(&tmp_path);
        ClientError::ReferenceValuesCache(format!(
            "failed to replace cache file {}: {error}",
            cache_path.display()
        ))
    })?;
    Ok(())
}

async fn fetch_remote_registry_envelope(
    url: &str,
) -> std::result::Result<ProviderRegistryEnvelope, String> {
    install_default_rustls_provider();
    let client = reqwest::Client::builder()
        .timeout(DEFAULT_REMOTE_REGISTRY_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("remote registry returned HTTP {status}"));
    }
    response
        .json::<ProviderRegistryEnvelope>()
        .await
        .map_err(|error| error.to_string())
}

async fn fetch_remote_reference_values_envelope(
    url: &str,
) -> std::result::Result<ReferenceValuesEnvelope, String> {
    install_default_rustls_provider();
    let client = reqwest::Client::builder()
        .timeout(DEFAULT_REMOTE_REGISTRY_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("remote reference values returned HTTP {status}"));
    }
    response
        .json::<ReferenceValuesEnvelope>()
        .await
        .map_err(|error| error.to_string())
}

fn install_default_rustls_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn registry_source_label(kind: &str, detail: String) -> String {
    let detail = redact_url_credentials(detail.trim());
    if detail.is_empty() || detail == kind {
        kind.to_owned()
    } else {
        format!("{kind}:{detail}")
    }
}

fn redact_url_credentials(url: &str) -> String {
    let Some((authority_start, authority_end)) = url_authority_bounds(url) else {
        return url.to_owned();
    };
    let authority = &url[authority_start..authority_end];
    let Some(credentials_end) = authority.rfind('@') else {
        return url.to_owned();
    };

    let mut redacted = String::with_capacity(url.len());
    redacted.push_str(&url[..authority_start]);
    redacted.push_str(&authority[credentials_end + 1..]);
    redacted.push_str(&url[authority_end..]);
    redacted
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialModel {
    pub canonical_model: String,
    pub display_name: String,
    pub family: String,
    pub aliases: Vec<String>,
    pub routes: Vec<ConfidentialRoute>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRoute {
    pub route_id: String,
    pub provider: String,
    pub provider_model: String,
    pub evidence_family: String,
    pub route_execution_status: RouteExecutionStatus,
    pub chat_executable: bool,
    pub known_unsupported_modes: Vec<String>,
    pub trust_tier: TrustTier,
    pub channel_binding_kind: ChannelBindingKind,
    pub request_encryption: EncryptionRequirement,
    pub response_decryption: EncryptionRequirement,
    pub streaming_allowed: bool,
    pub alias_confidence: confidential_inference_attestation::AliasConfidence,
    pub api_endpoint: String,
    pub evidence_endpoint: String,
    pub adapter_version: String,
}

#[derive(Clone)]
pub struct ConfidentialInference {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    policy: VerificationPolicy,
    registry: ProviderRegistry,
    registry_digest: String,
    registry_source: String,
    registry_signature: SignatureMetadata,
    registry_artifact_signature: ArtifactSignature,
    reference_values: ReferenceValuesPayload,
    reference_values_digest: String,
    reference_values_source: String,
    reference_signature: SignatureMetadata,
    reference_artifact_signature: ArtifactSignature,
    compatibility_matrix: ProviderCompatibilityMatrix,
    provider_routing: ProviderRoutingConfig,
    adapters: BTreeMap<String, Arc<dyn ProviderAdapter>>,
    tinfoil_quote_verifier: Arc<dyn TinfoilQuoteVerifier>,
    gpu_attestation_verifier: Arc<dyn GpuAttestationVerifier>,
    gpu_attestation_verifier_is_custom: bool,
    tinfoil_dcap_tdx_collateral_resolver: Option<DcapTdxCollateralResolver>,
    time_source: TimeSource,
    audit_sink: Arc<dyn AuditSink>,
    verdict_store: Arc<dyn VerdictStore>,
    metrics_recorder: Arc<dyn ConfidentialInferenceMetricsRecorder>,
    api_keys: BTreeMap<String, ClientApiKey>,
    verdict_cache: Mutex<BTreeMap<VerificationCacheKey, CachedVerdict>>,
    in_flight_verifications: Mutex<BTreeMap<VerificationCacheKey, VerificationFlightState>>,
}

/// Caller-owned provider preference order for canonical models. When a model
/// is present, only its listed providers are eligible for automatic chat
/// selection and failover, in the declared order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRoutingConfig {
    #[serde(default)]
    pub provider_order: BTreeMap<String, Vec<String>>,
}

impl ProviderRoutingConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_provider_order<I, S>(
        mut self,
        canonical_model: impl Into<String>,
        providers: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.provider_order.insert(
            canonical_model.into(),
            providers.into_iter().map(Into::into).collect(),
        );
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveTrustArtifacts {
    pub registry: ProviderRegistry,
    pub registry_digest: String,
    pub registry_source: String,
    pub registry_signature: ArtifactSignature,
    pub reference_values: ReferenceValuesPayload,
    pub reference_values_digest: String,
    pub reference_values_source: String,
    pub reference_values_signature: ArtifactSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivePolicySnapshot {
    pub schema: String,
    pub policy: VerificationPolicy,
    pub policy_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialInferenceRouteMetricLabels {
    pub provider: String,
    pub route_id: String,
    pub requested_model: String,
    pub provider_model: String,
    pub canonical_model: String,
    pub evidence_family: String,
}

impl ConfidentialInferenceRouteMetricLabels {
    fn from_route(route_definition: &RouteDefinition, route: &AttestedRoute) -> Self {
        Self {
            provider: route.provider.clone(),
            route_id: route.route_id.clone(),
            requested_model: route.requested_model.clone(),
            provider_model: route_definition.provider_model.clone(),
            canonical_model: route.canonical_model.clone(),
            evidence_family: route.evidence_family.clone(),
        }
    }

    fn from_verdict(verdict: &AttestationVerdict) -> Self {
        Self {
            provider: verdict.provider.clone(),
            route_id: verdict.route_id.clone(),
            requested_model: verdict.requested_model.clone(),
            provider_model: verdict.provider_model.clone(),
            canonical_model: verdict.canonical_model.clone(),
            evidence_family: verdict.evidence_family.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialInferenceMetricOutcome {
    Success,
    Failure,
}

impl ConfidentialInferenceMetricOutcome {
    fn from_success(success: bool) -> Self {
        if success {
            Self::Success
        } else {
            Self::Failure
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialInferenceMetricStep {
    RouteVerification,
    EvidenceFetch,
    EvidenceVerification,
    TinfoilDcapTdxCollateralResolution,
    ProviderChat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialInferenceVerificationCacheEvent {
    Hit,
    Miss,
    Store,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialInferenceSingleFlightEvent {
    Owner,
    Wait,
    QueueFull,
    WaitTimeout,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialInferenceRouteSelectionMetric {
    pub provider: String,
    pub requested_model: String,
    pub purpose: String,
    pub candidate_count: usize,
    pub selected_count: usize,
    pub duration_ms: u64,
    pub outcome: ConfidentialInferenceMetricOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialInferenceLatencyMetric {
    pub labels: ConfidentialInferenceRouteMetricLabels,
    pub step: ConfidentialInferenceMetricStep,
    pub duration_ms: u64,
    pub outcome: ConfidentialInferenceMetricOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialInferenceVerificationCacheMetric {
    pub labels: ConfidentialInferenceRouteMetricLabels,
    #[serde(rename = "cache_event")]
    pub event: ConfidentialInferenceVerificationCacheEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialInferenceSingleFlightMetric {
    pub labels: ConfidentialInferenceRouteMetricLabels,
    #[serde(rename = "single_flight_event")]
    pub event: ConfidentialInferenceSingleFlightEvent,
    pub wait_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialInferenceVerdictMetric {
    pub labels: ConfidentialInferenceRouteMetricLabels,
    pub status: confidential_inference_attestation::VerificationStatus,
    pub enforcement: EnforcementMode,
    pub request_allowed: bool,
    pub would_block_under_enforce: bool,
    pub cache_hit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialInferencePolicyFailureMetric {
    pub labels: ConfidentialInferenceRouteMetricLabels,
    pub check: String,
    pub status: confidential_inference_attestation::VerificationStatus,
    pub enforcement: EnforcementMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialInferenceStreamingFailClosedMetric {
    pub labels: ConfidentialInferenceRouteMetricLabels,
    pub endpoint: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ConfidentialInferenceMetricEvent {
    RouteSelection(ConfidentialInferenceRouteSelectionMetric),
    Latency(ConfidentialInferenceLatencyMetric),
    VerificationCache(ConfidentialInferenceVerificationCacheMetric),
    SingleFlight(ConfidentialInferenceSingleFlightMetric),
    Verdict(ConfidentialInferenceVerdictMetric),
    PolicyFailure(ConfidentialInferencePolicyFailureMetric),
    StreamingFailClosed(ConfidentialInferenceStreamingFailClosedMetric),
}

pub trait ConfidentialInferenceMetricsRecorder: Send + Sync {
    fn record(&self, event: &ConfidentialInferenceMetricEvent);
}

#[derive(Debug)]
pub struct NoopConfidentialInferenceMetricsRecorder;

impl ConfidentialInferenceMetricsRecorder for NoopConfidentialInferenceMetricsRecorder {
    fn record(&self, _event: &ConfidentialInferenceMetricEvent) {}
}

#[derive(Debug, Default)]
pub struct InMemoryConfidentialInferenceMetricsRecorder {
    events: Mutex<Vec<ConfidentialInferenceMetricEvent>>,
}

impl InMemoryConfidentialInferenceMetricsRecorder {
    pub fn events(&self) -> Vec<ConfidentialInferenceMetricEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    pub fn prometheus_text(&self) -> String {
        export_confidential_inference_metrics_prometheus_text(&self.events())
    }

    pub fn otlp_json(&self) -> serde_json::Result<String> {
        export_confidential_inference_metrics_otlp_json(&self.events())
    }

    pub async fn export_otlp_http(&self, endpoint: impl AsRef<str>) -> Result<()> {
        export_confidential_inference_metrics_otlp_http(&self.events(), endpoint).await
    }

    pub async fn export_otlp_http_with_timeout(
        &self,
        endpoint: impl AsRef<str>,
        timeout: Duration,
    ) -> Result<()> {
        export_confidential_inference_metrics_otlp_http_with_timeout(
            &self.events(),
            endpoint,
            timeout,
        )
        .await
    }
}

impl ConfidentialInferenceMetricsRecorder for InMemoryConfidentialInferenceMetricsRecorder {
    fn record(&self, event: &ConfidentialInferenceMetricEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event.clone());
        }
    }
}

#[derive(Debug)]
pub struct JsonlConfidentialInferenceMetricsRecorder {
    file: Mutex<std::fs::File>,
}

impl JsonlConfidentialInferenceMetricsRecorder {
    pub fn create(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl ConfidentialInferenceMetricsRecorder for JsonlConfidentialInferenceMetricsRecorder {
    fn record(&self, event: &ConfidentialInferenceMetricEvent) {
        let Ok(mut file) = self.file.lock() else {
            return;
        };
        if serde_json::to_writer(&mut *file, event).is_ok() {
            let _ = writeln!(&mut *file);
        }
    }
}

pub fn export_confidential_inference_metrics_prometheus_text(
    events: &[ConfidentialInferenceMetricEvent],
) -> String {
    let mut exporter = PrometheusTextExporter::default();
    record_confidential_inference_metric_counters(events, &mut exporter);
    exporter.finish()
}

pub fn export_confidential_inference_metrics_otlp_json(
    events: &[ConfidentialInferenceMetricEvent],
) -> serde_json::Result<String> {
    let mut exporter = OtlpJsonMetricsExporter::default();
    record_confidential_inference_metric_counters(events, &mut exporter);
    exporter.finish()
}

pub async fn export_confidential_inference_metrics_otlp_http(
    events: &[ConfidentialInferenceMetricEvent],
    endpoint: impl AsRef<str>,
) -> Result<()> {
    export_confidential_inference_metrics_otlp_http_with_timeout(
        events,
        endpoint,
        DEFAULT_OTLP_HTTP_TIMEOUT,
    )
    .await
}

pub async fn export_confidential_inference_metrics_otlp_http_with_timeout(
    events: &[ConfidentialInferenceMetricEvent],
    endpoint: impl AsRef<str>,
    timeout: Duration,
) -> Result<()> {
    let endpoint = endpoint.as_ref().trim();
    if endpoint.is_empty() {
        return Err(ClientError::MetricsExport(
            "OTLP HTTP endpoint is empty".into(),
        ));
    }
    let endpoint_label = redact_url_credentials(endpoint);
    let body = export_confidential_inference_metrics_otlp_json(events)
        .map_err(|error| ClientError::MetricsExport(format!("OTLP JSON failed: {error}")))?;
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|_| ClientError::MetricsExport("OTLP HTTP client build failed".into()))?;
    let response = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| {
            ClientError::MetricsExport(format!("OTLP HTTP POST to {endpoint_label} failed"))
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(ClientError::MetricsExport(format!(
            "OTLP HTTP POST to {endpoint_label} returned {status}"
        )));
    }
    Ok(())
}

fn record_confidential_inference_metric_counters(
    events: &[ConfidentialInferenceMetricEvent],
    exporter: &mut impl CounterMetricExporter,
) {
    for event in events {
        match event {
            ConfidentialInferenceMetricEvent::RouteSelection(metric) => {
                let labels = [
                    ("provider", metric.provider.as_str()),
                    ("requested_model", metric.requested_model.as_str()),
                    ("purpose", metric.purpose.as_str()),
                    ("outcome", metric_outcome_label(&metric.outcome)),
                ];
                exporter.counter(
                    "confidential_inference_route_selection_total",
                    "Route selection attempts by provider, requested model, purpose, and outcome.",
                    &labels,
                    1,
                );
                exporter.counter(
                    "confidential_inference_route_selection_duration_ms_count",
                    "Route selection duration sample count.",
                    &labels,
                    1,
                );
                exporter.counter(
                    "confidential_inference_route_selection_duration_ms_sum",
                    "Route selection duration sum in milliseconds.",
                    &labels,
                    metric.duration_ms,
                );
                exporter.counter(
                    "confidential_inference_route_selection_candidates_total",
                    "Matched route candidates observed during route selection.",
                    &labels,
                    metric.candidate_count as u64,
                );
                exporter.counter(
                    "confidential_inference_route_selection_selected_total",
                    "Selected routes observed during route selection.",
                    &labels,
                    metric.selected_count as u64,
                );
            }
            ConfidentialInferenceMetricEvent::Latency(metric) => {
                let mut labels = route_metric_label_pairs(&metric.labels);
                let step = metric_step_label(&metric.step);
                let outcome = metric_outcome_label(&metric.outcome);
                labels.push(("step", step));
                labels.push(("outcome", outcome));
                exporter.counter(
                    "confidential_inference_verification_step_duration_ms_count",
                    "Verification and provider execution step duration sample count.",
                    &labels,
                    1,
                );
                exporter.counter(
                    "confidential_inference_verification_step_duration_ms_sum",
                    "Verification and provider execution step duration sum in milliseconds.",
                    &labels,
                    metric.duration_ms,
                );
            }
            ConfidentialInferenceMetricEvent::VerificationCache(metric) => {
                let mut labels = route_metric_label_pairs(&metric.labels);
                let event = verification_cache_event_label(&metric.event);
                labels.push(("event", event));
                exporter.counter(
                    "confidential_inference_verdict_cache_events_total",
                    "Verdict cache hit, miss, and store events.",
                    &labels,
                    1,
                );
            }
            ConfidentialInferenceMetricEvent::SingleFlight(metric) => {
                let mut labels = route_metric_label_pairs(&metric.labels);
                let event = single_flight_event_label(&metric.event);
                labels.push(("event", event));
                exporter.counter(
                    "confidential_inference_single_flight_events_total",
                    "Single-flight route verification ownership and wait events.",
                    &labels,
                    1,
                );
                if let Some(wait_ms) = metric.wait_ms {
                    exporter.counter(
                        "confidential_inference_single_flight_wait_ms_count",
                        "Single-flight wait duration sample count.",
                        &labels,
                        1,
                    );
                    exporter.counter(
                        "confidential_inference_single_flight_wait_ms_sum",
                        "Single-flight wait duration sum in milliseconds.",
                        &labels,
                        wait_ms,
                    );
                }
            }
            ConfidentialInferenceMetricEvent::Verdict(metric) => {
                let mut labels = route_metric_label_pairs(&metric.labels);
                let status = serde_label(&metric.status);
                let enforcement = serde_label(&metric.enforcement);
                let request_allowed = bool_label(metric.request_allowed);
                let would_block = bool_label(metric.would_block_under_enforce);
                let cache_hit = bool_label(metric.cache_hit);
                labels.push(("status", status.as_str()));
                labels.push(("enforcement", enforcement.as_str()));
                labels.push(("request_allowed", request_allowed));
                labels.push(("would_block_under_enforce", would_block));
                labels.push(("cache_hit", cache_hit));
                exporter.counter(
                    "confidential_inference_verdict_status_total",
                    "Attestation verdict status counts.",
                    &labels,
                    1,
                );
            }
            ConfidentialInferenceMetricEvent::PolicyFailure(metric) => {
                let mut labels = route_metric_label_pairs(&metric.labels);
                let status = serde_label(&metric.status);
                let enforcement = serde_label(&metric.enforcement);
                labels.push(("check", metric.check.as_str()));
                labels.push(("status", status.as_str()));
                labels.push(("enforcement", enforcement.as_str()));
                exporter.counter(
                    "confidential_inference_policy_failures_total",
                    "Policy enforcement failures by check.",
                    &labels,
                    1,
                );
            }
            ConfidentialInferenceMetricEvent::StreamingFailClosed(metric) => {
                let mut labels = route_metric_label_pairs(&metric.labels);
                labels.push(("endpoint", metric.endpoint.as_str()));
                exporter.counter(
                    "confidential_inference_streaming_fail_closed_total",
                    "Streaming requests rejected because the selected confidential route cannot stream.",
                    &labels,
                    1,
                );
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RouteSelectionPurpose {
    Verify,
    Chat,
}

impl RouteSelectionPurpose {
    fn as_str(&self) -> &'static str {
        match self {
            RouteSelectionPurpose::Verify => "verification",
            RouteSelectionPurpose::Chat => "chat",
        }
    }
}

fn validate_provider_routing(
    routing: &ProviderRoutingConfig,
    registry: &ProviderRegistry,
    compatibility_matrix: &ProviderCompatibilityMatrix,
    adapters: &BTreeMap<String, Arc<dyn ProviderAdapter>>,
    policy: &VerificationPolicy,
) -> Result<()> {
    for (canonical_model, provider_order) in &routing.provider_order {
        if canonical_model.trim().is_empty() {
            return Err(ClientError::InvalidProviderRouting {
                model: canonical_model.clone(),
                message: "canonical model must not be empty".into(),
            });
        }
        let Some(model) = registry.models.get(canonical_model) else {
            return Err(ClientError::InvalidProviderRouting {
                model: canonical_model.clone(),
                message: "model is not present as a canonical model in the signed registry".into(),
            });
        };
        if provider_order.is_empty() {
            return Err(ClientError::InvalidProviderRouting {
                model: canonical_model.clone(),
                message: "provider order must contain at least one provider".into(),
            });
        }

        let mut seen = BTreeSet::new();
        for provider in provider_order {
            if provider.trim().is_empty() {
                return Err(ClientError::InvalidProviderRouting {
                    model: canonical_model.clone(),
                    message: "provider ids must not be empty".into(),
                });
            }
            if !seen.insert(provider) {
                return Err(ClientError::InvalidProviderRouting {
                    model: canonical_model.clone(),
                    message: format!("provider {provider} appears more than once"),
                });
            }
            let routes = model
                .routes
                .iter()
                .filter(|route| &route.provider == provider)
                .collect::<Vec<_>>();
            if routes.is_empty() {
                return Err(ClientError::InvalidProviderRouting {
                    model: canonical_model.clone(),
                    message: format!(
                        "provider {provider} does not offer this model in the signed registry"
                    ),
                });
            }
            if !adapters.contains_key(provider) {
                return Err(ClientError::InvalidProviderRouting {
                    model: canonical_model.clone(),
                    message: format!("provider {provider} has no registered adapter or API key"),
                });
            }
            let compatibility = compatibility_matrix.provider(provider).map_err(|_| {
                ClientError::InvalidProviderRouting {
                    model: canonical_model.clone(),
                    message: format!("provider {provider} has no compatibility profile"),
                }
            })?;
            let executable = routes.iter().any(|route| {
                compatibility.validate_route(route).is_ok()
                    && route_satisfies_policy(
                        route,
                        compatibility,
                        policy,
                        RouteSelectionPurpose::Chat,
                    )
            });
            if !executable {
                return Err(ClientError::InvalidProviderRouting {
                    model: canonical_model.clone(),
                    message: format!(
                        "provider {provider} has no active executable route satisfying the current policy"
                    ),
                });
            }
        }
    }
    Ok(())
}

fn route_satisfies_policy(
    route: &RouteDefinition,
    compatibility: &ProviderCompatibility,
    policy: &VerificationPolicy,
    purpose: RouteSelectionPurpose,
) -> bool {
    (match purpose {
        RouteSelectionPurpose::Verify => route.route_status.selectable_for_verification(),
        RouteSelectionPurpose::Chat => route.route_status.selectable_for_chat(),
    }) && route
        .channel_binding_kind
        .satisfies(&policy.channel_binding_requirement)
        && route_bound_data_satisfies_policy(
            &route.request_confidentiality_requirement,
            &policy.request_confidentiality_requirement,
        )
        && route_bound_data_satisfies_policy(
            &route.response_confidentiality_requirement,
            &policy.response_confidentiality_requirement,
        )
        && route_response_integrity_satisfies_policy(
            &route.response_integrity_requirement,
            &policy.response_integrity_requirement,
        )
        && route_hardware_satisfies_policy(route, policy)
        && route_model_binding_satisfies_policy(
            &compatibility.model_binding_support,
            &policy.model_binding_requirement,
        )
        && match purpose {
            RouteSelectionPurpose::Verify => true,
            RouteSelectionPurpose::Chat => {
                compatibility.route_execution_status.allows_chat_execution()
                    && compatibility.supports_endpoint(OpenAiEndpoint::ChatCompletions)
            }
        }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum VerificationRequestMode {
    VerifyOnly,
    NonStreamingChat,
    StreamingChat,
}

impl VerificationRequestMode {
    fn for_chat_request(request: &ChatCompletionRequest) -> Self {
        if request.streaming() {
            Self::StreamingChat
        } else {
            Self::NonStreamingChat
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::VerifyOnly => "verify_only",
            Self::NonStreamingChat => "non_streaming_chat",
            Self::StreamingChat => "streaming_chat",
        }
    }
}

impl ConfidentialInference {
    pub fn builder() -> ConfidentialInferenceBuilder {
        ConfidentialInferenceBuilder::new()
    }

    pub fn chat_completions(&self) -> ChatCompletionsBuilder {
        ChatCompletionsBuilder {
            client: self.clone(),
            model: None,
            messages: Vec::new(),
            stream: None,
            max_tokens: None,
            temperature: None,
        }
    }

    pub fn responses(&self) -> ResponsesBuilder {
        ResponsesBuilder {
            client: self.clone(),
            request: ResponseCreateRequest {
                model: None,
                input: None,
                instructions: None,
                stream: None,
                max_output_tokens: None,
                temperature: None,
                metadata: None,
            },
        }
    }

    pub async fn create_response(
        &self,
        request: ResponseCreateRequest,
    ) -> Result<ConfidentialResponse<ResponseObject>> {
        let chat_request = request.to_chat_completion_request()?;
        let chat_response = self.send_chat_completion_request(chat_request).await?;
        let ConfidentialResponse {
            response,
            provider,
            provider_model,
            requested_model,
            verdict,
            response_channel_bound,
            response_integrity_result,
            route,
        } = chat_response;

        Ok(ConfidentialResponse {
            response: ResponseObject::from_chat_completion(response),
            provider,
            provider_model,
            requested_model,
            verdict,
            response_channel_bound,
            response_integrity_result,
            route,
        })
    }

    pub async fn send_chat_completion_payload_json(
        &self,
        request: ChatCompletionRequestPayload,
    ) -> Result<String> {
        let response = self
            .send_chat_completion_request(request.into_inner())
            .await?;
        serialize_response_json(&response)
    }

    pub async fn create_response_payload_json(
        &self,
        request: ResponseCreateRequestPayload,
    ) -> Result<String> {
        let response = self.create_response(request.into_inner()).await?;
        serialize_response_json(&response)
    }

    async fn send_chat_completion_request(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ConfidentialResponse<ChatCompletionResponse>> {
        let model = request.model.clone();
        if request.messages.is_empty() {
            return Err(ClientError::MissingMessages);
        }
        let mut candidates = self.select_routes(None, &model, RouteSelectionPurpose::Chat)?;
        if candidates.is_empty() {
            return Err(ClientError::RouteSelectionFailed {
                provider: None,
                model,
                purpose: RouteSelectionPurpose::Chat.as_str(),
            });
        }
        if request.streaming() {
            let first_candidate = candidates.first().cloned();
            candidates
                .retain(|(route_definition, _)| route_definition.streaming.allows_streaming());
            if candidates.is_empty() {
                if let Some((route_definition, attested_route)) = first_candidate {
                    self.record_streaming_fail_closed(&route_definition, &attested_route);
                    return Err(ClientError::StreamingNotSupported {
                        route_id: route_definition.route_id,
                    });
                }
            }
        }

        let mut attempt_errors = Vec::new();
        let mut last_error = None;
        let mut unavailable_providers = BTreeSet::new();
        let request_mode = VerificationRequestMode::for_chat_request(&request);
        for (route_definition, attested_route) in candidates {
            let provider = attested_route.provider.clone();
            let route_id = attested_route.route_id.clone();
            if unavailable_providers.contains(&provider) {
                continue;
            }
            match self
                .verify_selected_route(route_definition, attested_route, request_mode)
                .await
            {
                Ok(verified) => match verified.chat(request.clone()).await {
                    Ok(response) => return Ok(response),
                    Err(error)
                        if matches!(
                            &error,
                            ClientError::Provider(provider_error)
                                if provider_error.is_retryable_outage()
                        ) =>
                    {
                        tracing::warn!(
                            provider = %provider,
                            route_id = %route_id,
                            "provider chat attempt was unavailable; trying next policy-compatible route"
                        );
                        attempt_errors.push(error.to_string());
                        last_error = Some(error);
                        unavailable_providers.insert(provider);
                    }
                    Err(error) => return Err(error),
                },
                Err(error) => {
                    if matches!(
                        &error,
                        ClientError::Provider(provider_error)
                            if provider_error.is_retryable_outage()
                    ) {
                        unavailable_providers.insert(provider);
                    }
                    attempt_errors.push(error.to_string());
                    last_error = Some(error);
                }
            }
        }

        if attempt_errors.len() == 1 {
            return Err(last_error.expect("single route-attempt error was recorded"));
        }

        Err(ClientError::RouteAttemptsFailed {
            model,
            errors: attempt_errors,
        })
    }

    fn record_streaming_fail_closed(
        &self,
        route_definition: &RouteDefinition,
        route: &AttestedRoute,
    ) {
        self.record_metric(ConfidentialInferenceMetricEvent::StreamingFailClosed(
            ConfidentialInferenceStreamingFailClosedMetric {
                labels: ConfidentialInferenceRouteMetricLabels::from_route(route_definition, route),
                endpoint: "chat_completions".into(),
            },
        ));
    }

    pub fn models(&self) -> ModelList {
        let data = self
            .confidential_models()
            .into_iter()
            .filter(|model| model.routes.iter().any(|route| route.chat_executable))
            .map(|model| Model {
                id: model.canonical_model,
                object: "model".into(),
                owned_by: "confidential-inference".into(),
            })
            .collect();

        ModelList::new(data)
    }

    pub fn confidential_models(&self) -> Vec<ConfidentialModel> {
        self.inner
            .registry
            .models
            .values()
            .filter_map(|model| self.confidential_model(model))
            .collect()
    }

    pub async fn verify_route(
        &self,
        provider: impl AsRef<str>,
        model: impl AsRef<str>,
    ) -> Result<VerifiedRoute> {
        let (route_definition, attested_route) = self.select_route(
            Some(provider.as_ref()),
            model.as_ref(),
            RouteSelectionPurpose::Verify,
        )?;
        self.verify_selected_route(
            route_definition,
            attested_route,
            VerificationRequestMode::VerifyOnly,
        )
        .await
    }

    fn confidential_model(&self, model: &RegistryModel) -> Option<ConfidentialModel> {
        let mut routes = model
            .routes
            .iter()
            .filter_map(|route| self.confidential_route(model, route))
            .collect::<Vec<_>>();

        if let Some(provider_order) = self
            .inner
            .provider_routing
            .provider_order
            .get(&model.canonical_model)
        {
            routes.sort_by_key(|route| {
                provider_order
                    .iter()
                    .position(|provider| provider == &route.provider)
                    .unwrap_or(usize::MAX)
            });
        }

        if routes.is_empty() {
            None
        } else {
            Some(ConfidentialModel {
                canonical_model: model.canonical_model.clone(),
                display_name: model.display_name.clone(),
                family: model.family.clone(),
                aliases: model.aliases.clone(),
                routes,
            })
        }
    }

    fn confidential_route(
        &self,
        model: &RegistryModel,
        route: &RouteDefinition,
    ) -> Option<ConfidentialRoute> {
        if !route.route_status.selectable_for_verification()
            || !self.inner.adapters.contains_key(&route.provider)
        {
            return None;
        }

        let compatibility = self
            .inner
            .compatibility_matrix
            .provider(&route.provider)
            .ok()?;
        if compatibility.validate_route(route).is_err()
            || !self.route_satisfies_policy(route, compatibility, RouteSelectionPurpose::Verify)
        {
            return None;
        }

        let preferred_for_chat = self
            .inner
            .provider_routing
            .provider_order
            .get(&model.canonical_model)
            .is_none_or(|providers| providers.contains(&route.provider));
        let chat_executable = preferred_for_chat
            && self.route_satisfies_policy(route, compatibility, RouteSelectionPurpose::Chat);

        Some(ConfidentialRoute {
            route_id: route.route_id.clone(),
            provider: route.provider.clone(),
            provider_model: route.provider_model.clone(),
            evidence_family: route.evidence_family.clone(),
            route_execution_status: compatibility.route_execution_status.clone(),
            chat_executable,
            known_unsupported_modes: compatibility.known_unsupported_modes.clone(),
            trust_tier: route.trust_tier.clone(),
            channel_binding_kind: route.channel_binding_kind.clone(),
            request_encryption: route.request_encryption.clone(),
            response_decryption: route.response_decryption.clone(),
            streaming_allowed: route.streaming.allows_streaming(),
            alias_confidence: route.alias_confidence.clone(),
            api_endpoint: route.api_base_url.clone(),
            evidence_endpoint: route.evidence_endpoint.clone(),
            adapter_version: route.adapter_version.clone(),
        })
    }

    fn select_route(
        &self,
        provider: Option<&str>,
        model: &str,
        purpose: RouteSelectionPurpose,
    ) -> Result<(RouteDefinition, AttestedRoute)> {
        self.select_routes(provider, model, purpose)?
            .into_iter()
            .next()
            .ok_or_else(|| ClientError::RouteSelectionFailed {
                provider: provider.map(ToOwned::to_owned),
                model: model.to_owned(),
                purpose: purpose.as_str(),
            })
    }

    fn select_routes(
        &self,
        provider: Option<&str>,
        model: &str,
        purpose: RouteSelectionPurpose,
    ) -> Result<Vec<(RouteDefinition, AttestedRoute)>> {
        let started_at = Instant::now();
        let _span = tracing::info_span!(
            "confidential-inference.route_select",
            provider = provider.unwrap_or("any"),
            requested_model = model,
            purpose = purpose.as_str()
        )
        .entered();
        let mut candidate_count = 0;
        let mut selected_count = 0;
        let result = (|| {
            let mut candidates = self.inner.registry.matching_routes(provider, model);
            candidate_count = candidates.len();
            tracing::debug!(candidate_count, "matched route candidates");
            if candidates.is_empty() {
                return Err(ClientError::RouteNotFound {
                    provider: provider.map(ToOwned::to_owned),
                    model: model.to_owned(),
                });
            }

            if provider.is_none() && purpose == RouteSelectionPurpose::Chat {
                let canonical_model = &candidates[0].0.canonical_model;
                if let Some(provider_order) = self
                    .inner
                    .provider_routing
                    .provider_order
                    .get(canonical_model)
                {
                    candidates.retain(|(_, route)| provider_order.contains(&route.provider));
                    candidates.sort_by_key(|(_, route)| {
                        provider_order
                            .iter()
                            .position(|candidate| candidate == &route.provider)
                            .unwrap_or(usize::MAX)
                    });
                }
            }

            let mut selected = Vec::new();
            for (registry_model, route) in candidates {
                if !self.inner.adapters.contains_key(&route.provider) {
                    continue;
                }
                let compatibility = self.inner.compatibility_matrix.provider(&route.provider)?;
                compatibility.validate_route(route)?;
                if !self.route_satisfies_policy(route, compatibility, purpose) {
                    continue;
                }

                let route = route.clone();
                let attested_route =
                    route.to_attested_route(model, registry_model.canonical_model.clone());
                selected.push((route, attested_route));
            }

            selected_count = selected.len();
            tracing::debug!(selected_count, "route selection completed");
            Ok(selected)
        })();
        self.record_metric(ConfidentialInferenceMetricEvent::RouteSelection(
            ConfidentialInferenceRouteSelectionMetric {
                provider: provider.unwrap_or("any").to_owned(),
                requested_model: model.to_owned(),
                purpose: purpose.as_str().to_owned(),
                candidate_count,
                selected_count,
                duration_ms: duration_millis(started_at.elapsed()),
                outcome: ConfidentialInferenceMetricOutcome::from_success(result.is_ok()),
            },
        ));
        result
    }

    fn route_satisfies_policy(
        &self,
        route: &RouteDefinition,
        compatibility: &ProviderCompatibility,
        purpose: RouteSelectionPurpose,
    ) -> bool {
        route_satisfies_policy(route, compatibility, &self.inner.policy, purpose)
    }

    async fn verify_selected_route(
        &self,
        route_definition: RouteDefinition,
        attested_route: AttestedRoute,
        request_mode: VerificationRequestMode,
    ) -> Result<VerifiedRoute> {
        let labels =
            ConfidentialInferenceRouteMetricLabels::from_route(&route_definition, &attested_route);
        let started_at = Instant::now();
        let span = tracing::info_span!(
            "confidential-inference.route_verify",
            provider = %route_definition.provider,
            route_id = %route_definition.route_id,
            evidence_family = %route_definition.evidence_family,
            requested_model = %attested_route.requested_model,
            provider_model = %route_definition.provider_model,
            canonical_model = %attested_route.canonical_model
        );
        let result = async move {
            let adapter = self.adapter(&route_definition.provider)?;
            let policy_digest = self.inner.policy.digest()?;
            let cache_key = VerificationCacheKey::new(
                &route_definition,
                &attested_route,
                request_mode,
                &policy_digest,
                &self.inner.registry_digest,
                &self.inner.reference_values_digest,
            );

            if let Some(verdict) = self.cached_verdict(&cache_key) {
                self.record_cache_metric(
                    &cache_key,
                    ConfidentialInferenceVerificationCacheEvent::Hit,
                );
                tracing::debug!("using cached attestation verdict");
                self.record_verdict(&verdict, true);
                return Ok(VerifiedRoute {
                    client: self.clone(),
                    route_definition,
                    route: attested_route,
                    verdict,
                });
            }
            self.record_cache_metric(
                &cache_key,
                ConfidentialInferenceVerificationCacheEvent::Miss,
            );

            if self.cache_enabled() {
                tracing::debug!("using single-flight route verification");
                return self
                    .verify_selected_route_single_flight(
                        route_definition,
                        attested_route,
                        adapter,
                        policy_digest,
                        cache_key,
                    )
                    .await;
            }

            let verdict = self
                .fetch_and_verify_route(adapter, &route_definition, &attested_route, policy_digest)
                .await?;
            self.record_verdict(&verdict, false);
            let verdict = self.enforce_verdict(verdict)?;

            Ok(VerifiedRoute {
                client: self.clone(),
                route_definition,
                route: attested_route,
                verdict,
            })
        }
        .instrument(span)
        .await;
        self.record_latency(
            labels,
            ConfidentialInferenceMetricStep::RouteVerification,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
    }

    async fn verify_selected_route_single_flight(
        &self,
        route_definition: RouteDefinition,
        attested_route: AttestedRoute,
        adapter: Arc<dyn ProviderAdapter>,
        policy_digest: String,
        cache_key: VerificationCacheKey,
    ) -> Result<VerifiedRoute> {
        loop {
            if let Some(verdict) = self.cached_verdict(&cache_key) {
                self.record_cache_metric(
                    &cache_key,
                    ConfidentialInferenceVerificationCacheEvent::Hit,
                );
                tracing::debug!("single-flight waiter using cached attestation verdict");
                self.record_verdict(&verdict, true);
                return Ok(VerifiedRoute {
                    client: self.clone(),
                    route_definition,
                    route: attested_route,
                    verdict,
                });
            }
            self.record_cache_metric(
                &cache_key,
                ConfidentialInferenceVerificationCacheEvent::Miss,
            );

            match self.acquire_verification_flight(&cache_key) {
                VerificationFlight::Wait(notify) => {
                    tracing::debug!("waiting for in-flight route verification");
                    let wait_started_at = Instant::now();
                    let wait_result =
                        tokio::time::timeout(single_flight_wait_timeout(), notify.notified()).await;
                    self.release_verification_waiter(&cache_key);
                    if wait_result.is_err() {
                        self.record_single_flight_metric(
                            &cache_key,
                            ConfidentialInferenceSingleFlightEvent::WaitTimeout,
                            Some(wait_started_at.elapsed()),
                        );
                        if let Some(verdict) = self.cached_verdict(&cache_key) {
                            self.record_cache_metric(
                                &cache_key,
                                ConfidentialInferenceVerificationCacheEvent::Hit,
                            );
                            self.record_verdict(&verdict, true);
                            return Ok(VerifiedRoute {
                                client: self.clone(),
                                route_definition,
                                route: attested_route,
                                verdict,
                            });
                        }
                        return Err(ClientError::VerificationWaitTimeout {
                            route_id: cache_key.route_id.clone(),
                        });
                    }
                    self.record_single_flight_metric(
                        &cache_key,
                        ConfidentialInferenceSingleFlightEvent::Wait,
                        Some(wait_started_at.elapsed()),
                    );
                }
                VerificationFlight::Owner => {
                    tracing::debug!("owning in-flight route verification");
                    self.record_single_flight_metric(
                        &cache_key,
                        ConfidentialInferenceSingleFlightEvent::Owner,
                        None,
                    );
                    let result = self
                        .verify_selected_route_as_flight_owner(
                            route_definition,
                            attested_route,
                            adapter,
                            policy_digest,
                            cache_key,
                        )
                        .await;
                    return result;
                }
                VerificationFlight::QueueFull => {
                    self.record_single_flight_metric(
                        &cache_key,
                        ConfidentialInferenceSingleFlightEvent::QueueFull,
                        None,
                    );
                    return Err(ClientError::VerificationWaitQueueFull {
                        route_id: cache_key.route_id.clone(),
                        max_waiters: SINGLE_FLIGHT_MAX_WAITERS,
                    });
                }
            }
        }
    }

    async fn verify_selected_route_as_flight_owner(
        &self,
        route_definition: RouteDefinition,
        attested_route: AttestedRoute,
        adapter: Arc<dyn ProviderAdapter>,
        policy_digest: String,
        cache_key: VerificationCacheKey,
    ) -> Result<VerifiedRoute> {
        let result = async {
            let verdict = self
                .fetch_and_verify_route(adapter, &route_definition, &attested_route, policy_digest)
                .await?;
            self.record_verdict(&verdict, false);
            let verdict = self.enforce_verdict(verdict)?;
            self.store_cached_verdict(cache_key.clone(), &verdict);

            Ok(VerifiedRoute {
                client: self.clone(),
                route_definition,
                route: attested_route,
                verdict,
            })
        }
        .await;

        self.finish_verification_flight(&cache_key);
        result
    }

    async fn refresh_selected_route_after_key_rotation(
        &self,
        route_definition: RouteDefinition,
        attested_route: AttestedRoute,
        request_mode: VerificationRequestMode,
    ) -> Result<VerifiedRoute> {
        let adapter = self.adapter(&route_definition.provider)?;
        let policy_digest = self.inner.policy.digest()?;
        let cache_key = VerificationCacheKey::new(
            &route_definition,
            &attested_route,
            request_mode,
            &policy_digest,
            &self.inner.registry_digest,
            &self.inner.reference_values_digest,
        );
        self.invalidate_cached_verdict(&cache_key);
        self.record_cache_metric(
            &cache_key,
            ConfidentialInferenceVerificationCacheEvent::Miss,
        );

        let verdict = self
            .fetch_and_verify_route(adapter, &route_definition, &attested_route, policy_digest)
            .await?;
        self.record_verdict(&verdict, false);
        let verdict = self.enforce_verdict(verdict)?;
        self.store_cached_verdict(cache_key, &verdict);

        Ok(VerifiedRoute {
            client: self.clone(),
            route_definition,
            route: attested_route,
            verdict,
        })
    }

    async fn fetch_and_verify_route(
        &self,
        adapter: Arc<dyn ProviderAdapter>,
        route_definition: &RouteDefinition,
        attested_route: &AttestedRoute,
        policy_digest: String,
    ) -> Result<AttestationVerdict> {
        let compatibility = self
            .inner
            .compatibility_matrix
            .provider(&route_definition.provider)?;
        compatibility.validate_route(route_definition)?;
        let route_execution_status =
            route_execution_status_label(&compatibility.route_execution_status).to_owned();
        let chat_executable = self.route_satisfies_policy(
            route_definition,
            compatibility,
            RouteSelectionPurpose::Chat,
        );
        let known_unsupported_modes = compatibility.known_unsupported_modes.clone();
        let evidence_request = EvidenceRequest {
            requested_model: attested_route.requested_model.clone(),
            policy_digest,
            nonce: self.evidence_nonce_for_policy(),
        };
        let fetch_started_at = Instant::now();
        let raw_evidence = adapter
            .fetch_evidence(route_definition, &evidence_request)
            .instrument(tracing::info_span!(
                "confidential-inference.evidence_fetch",
                provider = %route_definition.provider,
                route_id = %route_definition.route_id,
                evidence_family = %route_definition.evidence_family,
                requested_model = %attested_route.requested_model,
                provider_model = %attested_route.provider_model,
                canonical_model = %attested_route.canonical_model
            ))
            .await;
        self.record_latency(
            ConfidentialInferenceRouteMetricLabels::from_route(route_definition, attested_route),
            ConfidentialInferenceMetricStep::EvidenceFetch,
            fetch_started_at.elapsed(),
            raw_evidence.is_ok(),
        );
        let raw_evidence = raw_evidence?;
        tracing::debug!(
            raw_evidence_bytes = raw_evidence.len(),
            raw_evidence_digest = %sha256_digest(&raw_evidence),
            "provider evidence fetched"
        );
        let tinfoil_quote_verifier = self
            .tinfoil_quote_verifier_for_raw_evidence(
                &raw_evidence,
                route_definition,
                attested_route,
            )
            .await?;
        let gpu_attestation_verifier = self
            .gpu_attestation_verifier_for_raw_evidence(&raw_evidence)
            .await?;
        let verification = VerificationRequest {
            route: attested_route.clone(),
            route_execution_status,
            chat_executable,
            known_unsupported_modes,
            expected_freshness_nonce: self
                .expected_freshness_nonce_for_policy(route_definition, &evidence_request),
            policy: self.inner.policy.clone(),
            reference_values: self.inner.reference_values.clone(),
            reference_signature: self.inner.reference_signature.clone(),
            reference_values_digest: self.inner.reference_values_digest.clone(),
            reference_values_source: self.inner.reference_values_source.clone(),
            registry_digest: self.inner.registry_digest.clone(),
            registry_version: self.inner.registry.version.clone(),
            registry_source: self.inner.registry_source.clone(),
            registry_sync_completed_at: self.inner.registry.source_sync_run.completed_at.clone(),
            registry_signature: self.inner.registry_signature.clone(),
            raw_evidence,
        };
        let _span = tracing::info_span!(
            "confidential-inference.evidence_verify",
            provider = %attested_route.provider,
            route_id = %attested_route.route_id,
            evidence_family = %attested_route.evidence_family,
            requested_model = %attested_route.requested_model,
            provider_model = %attested_route.provider_model,
            canonical_model = %attested_route.canonical_model
        )
        .entered();
        let verify_started_at = Instant::now();
        let verdict = verify_evidence_with_attestation_verifiers(
            verification,
            tinfoil_quote_verifier.as_ref(),
            gpu_attestation_verifier.as_ref(),
        );
        self.record_latency(
            ConfidentialInferenceRouteMetricLabels::from_route(route_definition, attested_route),
            ConfidentialInferenceMetricStep::EvidenceVerification,
            verify_started_at.elapsed(),
            verdict.is_ok(),
        );
        let verdict = verdict?;
        tracing::info!(
            status = ?verdict.status,
            request_allowed = verdict.request_allowed,
            would_block_under_enforce = verdict.would_block_under_enforce,
            "evidence verification completed"
        );
        Ok(verdict)
    }

    async fn tinfoil_quote_verifier_for_raw_evidence(
        &self,
        raw_evidence: &[u8],
        route_definition: &RouteDefinition,
        attested_route: &AttestedRoute,
    ) -> Result<Arc<dyn TinfoilQuoteVerifier>> {
        let Some(resolver) = &self.inner.tinfoil_dcap_tdx_collateral_resolver else {
            tracing::debug!("using configured generic Tinfoil quote verifier");
            return Ok(self.inner.tinfoil_quote_verifier.clone());
        };
        let Some(quote_bytes) = raw_tdx_quote_bytes(raw_evidence)? else {
            tracing::debug!("raw evidence does not contain a supported live TDX quote");
            return Ok(self.inner.tinfoil_quote_verifier.clone());
        };

        let quote_digest = sha256_digest(&quote_bytes);
        let resolver_started_at = Instant::now();
        let verifier = resolver
            .verifier_for_quote_at(&quote_bytes, self.now_epoch_millis())
            .instrument(tracing::info_span!(
                "confidential-inference.tinfoil_dcap_tdx_collateral_resolve",
                provider = %attested_route.provider,
                route_id = %attested_route.route_id,
                evidence_family = %attested_route.evidence_family,
                quote_sha256 = %quote_digest
            ))
            .await;
        self.record_latency(
            ConfidentialInferenceRouteMetricLabels::from_route(route_definition, attested_route),
            ConfidentialInferenceMetricStep::TinfoilDcapTdxCollateralResolution,
            resolver_started_at.elapsed(),
            verifier.is_ok(),
        );
        let verifier = verifier?;
        tracing::debug!(quote_sha256 = %quote_digest, "using DCAP TDX quote verifier");
        Ok(Arc::new(verifier))
    }

    async fn gpu_attestation_verifier_for_raw_evidence(
        &self,
        raw_evidence: &[u8],
    ) -> Result<Arc<dyn GpuAttestationVerifier>> {
        if self.inner.gpu_attestation_verifier_is_custom
            || matches!(
                &self.inner.policy.hardware.gpu,
                GpuTeeRequirement::NotRequired
            )
            || !matches!(
                raw_schema(raw_evidence).as_deref(),
                Some(ChutesLiveEvidence::SCHEMA) | Some(NearLiveEvidence::SCHEMA)
            )
        {
            return Ok(self.inner.gpu_attestation_verifier.clone());
        }

        let verifier = NvidiaNrasRemoteClient::with_default_http()?
            .fetch_jwt_verifier()
            .await?;
        Ok(Arc::new(verifier))
    }

    fn enforce_verdict(&self, verdict: AttestationVerdict) -> Result<AttestationVerdict> {
        if verdict.request_allowed {
            Ok(verdict)
        } else {
            self.record_policy_failures(&verdict);
            Err(ClientError::PolicyDenied {
                route_id: verdict.route_id.clone(),
                verdict: Box::new(verdict),
            })
        }
    }

    fn record_verdict(&self, verdict: &AttestationVerdict, cache_hit: bool) {
        tracing::info!(
            provider = %verdict.provider,
            route_id = %verdict.route_id,
            evidence_family = %verdict.evidence_family,
            status = ?verdict.status,
            enforcement = ?verdict.enforcement,
            request_allowed = verdict.request_allowed,
            cache_hit,
            "recording attestation verdict"
        );
        let audit_event = AuditEvent::from_verdict(verdict, cache_hit);
        self.inner.audit_sink.record(&audit_event);
        let verdict_record = VerdictRecord::from_verdict(verdict, cache_hit);
        self.inner.verdict_store.persist(&verdict_record);
        self.record_metric(ConfidentialInferenceMetricEvent::Verdict(
            ConfidentialInferenceVerdictMetric {
                labels: ConfidentialInferenceRouteMetricLabels::from_verdict(verdict),
                status: verdict.status.clone(),
                enforcement: verdict.enforcement.clone(),
                request_allowed: verdict.request_allowed,
                would_block_under_enforce: verdict.would_block_under_enforce,
                cache_hit,
            },
        ));
    }

    fn record_metric(&self, event: ConfidentialInferenceMetricEvent) {
        self.inner.metrics_recorder.record(&event);
    }

    fn record_latency(
        &self,
        labels: ConfidentialInferenceRouteMetricLabels,
        step: ConfidentialInferenceMetricStep,
        duration: Duration,
        success: bool,
    ) {
        self.record_metric(ConfidentialInferenceMetricEvent::Latency(
            ConfidentialInferenceLatencyMetric {
                labels,
                step,
                duration_ms: duration_millis(duration),
                outcome: ConfidentialInferenceMetricOutcome::from_success(success),
            },
        ));
    }

    fn record_cache_metric(
        &self,
        key: &VerificationCacheKey,
        event: ConfidentialInferenceVerificationCacheEvent,
    ) {
        self.record_metric(ConfidentialInferenceMetricEvent::VerificationCache(
            ConfidentialInferenceVerificationCacheMetric {
                labels: key.metric_labels(),
                event,
            },
        ));
    }

    fn record_single_flight_metric(
        &self,
        key: &VerificationCacheKey,
        event: ConfidentialInferenceSingleFlightEvent,
        wait: Option<Duration>,
    ) {
        self.record_metric(ConfidentialInferenceMetricEvent::SingleFlight(
            ConfidentialInferenceSingleFlightMetric {
                labels: key.metric_labels(),
                event,
                wait_ms: wait.map(duration_millis),
            },
        ));
    }

    fn record_policy_failures(&self, verdict: &AttestationVerdict) {
        let labels = ConfidentialInferenceRouteMetricLabels::from_verdict(verdict);
        if verdict.errors.is_empty() {
            self.record_metric(ConfidentialInferenceMetricEvent::PolicyFailure(
                ConfidentialInferencePolicyFailureMetric {
                    labels,
                    check: "policy_denied".into(),
                    status: verdict.status.clone(),
                    enforcement: verdict.enforcement.clone(),
                },
            ));
            return;
        }

        for error in &verdict.errors {
            self.record_metric(ConfidentialInferenceMetricEvent::PolicyFailure(
                ConfidentialInferencePolicyFailureMetric {
                    labels: labels.clone(),
                    check: error.code.clone(),
                    status: verdict.status.clone(),
                    enforcement: verdict.enforcement.clone(),
                },
            ));
        }
    }

    fn adapter(&self, provider: &str) -> Result<Arc<dyn ProviderAdapter>> {
        self.inner
            .adapters
            .get(provider)
            .cloned()
            .ok_or_else(|| ClientError::UnknownProvider(provider.to_owned()))
    }

    pub fn policy(&self) -> &VerificationPolicy {
        &self.inner.policy
    }

    pub fn active_policy(&self) -> Result<ActivePolicySnapshot> {
        let policy = self.inner.policy.normalized();
        let policy_digest = policy.digest()?;
        Ok(ActivePolicySnapshot {
            schema: "confidential-inference.active-policy.v1".to_owned(),
            policy,
            policy_digest,
        })
    }

    pub fn registry_digest(&self) -> &str {
        &self.inner.registry_digest
    }

    pub fn registry_source(&self) -> &str {
        &self.inner.registry_source
    }

    pub fn registry_signature(&self) -> &SignatureMetadata {
        &self.inner.registry_signature
    }

    pub fn reference_values_digest(&self) -> &str {
        &self.inner.reference_values_digest
    }

    pub fn reference_values_source(&self) -> &str {
        &self.inner.reference_values_source
    }

    pub fn active_trust_artifacts(&self) -> ActiveTrustArtifacts {
        ActiveTrustArtifacts {
            registry: self.inner.registry.clone(),
            registry_digest: self.inner.registry_digest.clone(),
            registry_source: self.inner.registry_source.clone(),
            registry_signature: self.inner.registry_artifact_signature.clone(),
            reference_values: self.inner.reference_values.clone(),
            reference_values_digest: self.inner.reference_values_digest.clone(),
            reference_values_source: self.inner.reference_values_source.clone(),
            reference_values_signature: self.inner.reference_artifact_signature.clone(),
        }
    }

    pub fn has_api_key(&self, provider: &str) -> bool {
        self.inner.api_keys.contains_key(provider)
    }

    fn now_epoch_millis(&self) -> u64 {
        (self.inner.time_source)()
    }

    fn cached_verdict(&self, key: &VerificationCacheKey) -> Option<AttestationVerdict> {
        let max_cache_age_ms = self.cache_age_limit_millis()?;

        let mut cache = self.inner.verdict_cache.lock().ok()?;
        let cached = cache.get(key)?;
        if cached.is_valid(
            self.now_epoch_millis(),
            max_cache_age_ms,
            &self.inner.policy.stale_verdicts,
        ) {
            return Some(cached.verdict.clone());
        }
        cache.remove(key);
        None
    }

    fn store_cached_verdict(&self, key: VerificationCacheKey, verdict: &AttestationVerdict) {
        if !self.cache_enabled() {
            return;
        }

        if let Ok(mut cache) = self.inner.verdict_cache.lock() {
            let inserted_wall_clock_epoch_ms = self.now_epoch_millis();
            cache.insert(
                key.clone(),
                CachedVerdict {
                    verdict: verdict.clone(),
                    inserted_at: Instant::now(),
                    inserted_wall_clock_epoch_ms,
                },
            );
            self.record_cache_metric(&key, ConfidentialInferenceVerificationCacheEvent::Store);
        }
    }

    fn invalidate_cached_verdict(&self, key: &VerificationCacheKey) {
        if let Ok(mut cache) = self.inner.verdict_cache.lock() {
            cache.remove(key);
        }
    }

    fn acquire_verification_flight(&self, key: &VerificationCacheKey) -> VerificationFlight {
        let Ok(mut flights) = self.inner.in_flight_verifications.lock() else {
            return VerificationFlight::Owner;
        };

        if let Some(state) = flights.get_mut(key) {
            if state.waiters >= SINGLE_FLIGHT_MAX_WAITERS {
                return VerificationFlight::QueueFull;
            }
            state.waiters += 1;
            VerificationFlight::Wait(state.notify.clone())
        } else {
            flights.insert(
                key.clone(),
                VerificationFlightState {
                    notify: Arc::new(Notify::new()),
                    waiters: 0,
                },
            );
            VerificationFlight::Owner
        }
    }

    fn release_verification_waiter(&self, key: &VerificationCacheKey) {
        let Ok(mut flights) = self.inner.in_flight_verifications.lock() else {
            return;
        };

        if let Some(state) = flights.get_mut(key) {
            state.waiters = state.waiters.saturating_sub(1);
        }
    }

    fn finish_verification_flight(&self, key: &VerificationCacheKey) {
        let Ok(mut flights) = self.inner.in_flight_verifications.lock() else {
            return;
        };

        if let Some(state) = flights.remove(key) {
            state.notify.notify_waiters();
        }
    }

    fn cache_enabled(&self) -> bool {
        self.cache_age_limit_millis().is_some()
    }

    fn cache_age_limit_millis(&self) -> Option<u64> {
        let ttl_ms = self.inner.policy.verdict_ttl_millis.0;
        if ttl_ms == 0 {
            return None;
        }

        match self.inner.policy.freshness {
            FreshnessPolicy::PerRequest => None,
            FreshnessPolicy::PerSession => Some(ttl_ms),
            FreshnessPolicy::AllowCachedBindingMillis { millis } => {
                let limit = ttl_ms.min(millis.0);
                (limit > 0).then_some(limit)
            }
        }
    }

    fn verdict_expiry_allows_use(&self, verdict: &AttestationVerdict) -> bool {
        verdict_epoch_allowed_by_stale_policy(
            verdict.expires_at_epoch_ms,
            self.now_epoch_millis(),
            &self.inner.policy.stale_verdicts,
        )
    }

    fn evidence_nonce_for_policy(&self) -> Option<String> {
        matches!(self.inner.policy.freshness, FreshnessPolicy::PerRequest)
            .then(fresh_evidence_nonce)
    }

    fn expected_freshness_nonce_for_policy(
        &self,
        route_definition: &RouteDefinition,
        request: &EvidenceRequest,
    ) -> Option<String> {
        if !matches!(self.inner.policy.freshness, FreshnessPolicy::PerRequest) {
            return None;
        }

        request
            .nonce
            .as_deref()
            .map(|nonce| match route_definition.evidence_family.as_str() {
                "chutes_e2ee" => chutes_provider_nonce(nonce),
                _ => nonce.to_owned(),
            })
    }
}

fn verdict_epoch_allowed_by_stale_policy(
    expires_at_epoch_ms: u64,
    now_epoch_ms: u64,
    stale_policy: &StaleVerdictPolicy,
) -> bool {
    match stale_policy {
        StaleVerdictPolicy::FailClosed => now_epoch_ms < expires_at_epoch_ms,
        StaleVerdictPolicy::AllowForMillis { millis } => {
            now_epoch_ms < expires_at_epoch_ms.saturating_add(millis.0)
        }
    }
}

fn raw_schema(raw: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| {
            value
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        })
}

fn raw_tdx_quote_bytes(raw: &[u8]) -> Result<Option<Vec<u8>>> {
    match raw_schema(raw).as_deref() {
        Some(confidential_inference_attestation::TinfoilLiveCaptureEvidence::SCHEMA) => {
            let parsed = parse_tinfoil_live_capture(raw)?;
            if parsed.attestation_format == TinfoilAttestationFormat::TdxGuestV2 {
                Ok(Some(parsed.quote_bytes))
            } else {
                Ok(None)
            }
        }
        Some(ChutesLiveEvidence::SCHEMA) => {
            let capture: ChutesLiveEvidence = serde_json::from_slice(raw).map_err(|error| {
                AttestationError::InvalidEvidence(format!(
                    "invalid Chutes live evidence capture: {error}"
                ))
            })?;
            let quote = base64::engine::general_purpose::STANDARD
                .decode(&capture.quote_base64)
                .map_err(|error| {
                    AttestationError::InvalidEvidence(format!(
                        "Chutes TDX quote is not base64: {error}"
                    ))
                })?;
            Ok(Some(quote))
        }
        Some(NearLiveEvidence::SCHEMA) => {
            let capture: NearLiveEvidence = serde_json::from_slice(raw).map_err(|error| {
                AttestationError::InvalidEvidence(format!(
                    "invalid NEAR live evidence capture: {error}"
                ))
            })?;
            let body = base64::engine::general_purpose::STANDARD
                .decode(&capture.raw_attestation_body_base64)
                .map_err(|error| {
                    AttestationError::InvalidEvidence(format!(
                        "NEAR raw attestation body is not base64: {error}"
                    ))
                })?;
            let value: serde_json::Value = serde_json::from_slice(&body).map_err(|error| {
                AttestationError::InvalidEvidence(format!(
                    "NEAR raw attestation body is not JSON: {error}"
                ))
            })?;
            let quote_hex = value
                .get("intel_quote")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    AttestationError::InvalidEvidence(
                        "NEAR raw attestation body has no intel_quote".into(),
                    )
                })?;
            Ok(Some(decode_hex_bytes("NEAR TDX quote", quote_hex)?))
        }
        _ => Ok(None),
    }
}

fn decode_hex_bytes(field: &str, value: &str) -> std::result::Result<Vec<u8>, AttestationError> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AttestationError::InvalidEvidence(format!(
            "{field} is not canonical hex"
        )));
    }
    Ok(value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("validated hex") as u8;
            let low = (pair[1] as char).to_digit(16).expect("validated hex") as u8;
            (high << 4) | low
        })
        .collect())
}

fn fresh_evidence_nonce() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness unavailable");
    lower_hex(&bytes)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn route_bound_data_satisfies_policy(
    route_requirement: &BoundDataRequirement,
    policy_requirement: &BoundDataRequirement,
) -> bool {
    match policy_requirement {
        BoundDataRequirement::NotRequired => true,
        BoundDataRequirement::BoundToAttestedWorkload => {
            route_requirement == &BoundDataRequirement::BoundToAttestedWorkload
        }
    }
}

fn route_response_integrity_satisfies_policy(
    route_requirement: &ResponseIntegrityRequirement,
    policy_requirement: &ResponseIntegrityRequirement,
) -> bool {
    match policy_requirement {
        ResponseIntegrityRequirement::NotRequired => true,
        ResponseIntegrityRequirement::AnyBound => {
            route_requirement != &ResponseIntegrityRequirement::NotRequired
        }
        ResponseIntegrityRequirement::ChannelBound => {
            route_requirement == &ResponseIntegrityRequirement::ChannelBound
        }
        ResponseIntegrityRequirement::ReceiptBound => {
            route_requirement == &ResponseIntegrityRequirement::ReceiptBound
        }
    }
}

fn route_hardware_satisfies_policy(route: &RouteDefinition, policy: &VerificationPolicy) -> bool {
    let cpu_ok = match policy.hardware.cpu {
        CpuTeeRequirement::NotRequired => true,
        CpuTeeRequirement::AnyCpuTee | CpuTeeRequirement::OneOf { .. } => {
            route.trust_tier != TrustTier::None
        }
    };
    let gpu_ok = match &policy.hardware.gpu {
        GpuTeeRequirement::NotRequired => true,
        GpuTeeRequirement::OneOf { allowed } => allowed.iter().any(|allowed| {
            route
                .accepted_gpu_tees
                .iter()
                .any(|route_gpu| route_gpu == allowed)
        }),
    };

    cpu_ok && gpu_ok
}

fn route_model_binding_satisfies_policy(
    support: &ModelBindingSupport,
    requirement: &ModelBindingRequirement,
) -> bool {
    match requirement {
        ModelBindingRequirement::NotRequired | ModelBindingRequirement::IfProviderSupports => true,
        ModelBindingRequirement::Required => support == &ModelBindingSupport::Verified,
    }
}

fn route_execution_status_label(status: &RouteExecutionStatus) -> &'static str {
    match status {
        RouteExecutionStatus::ExecutableFixture => "executable_fixture",
        RouteExecutionStatus::AdapterShapeFixture => "adapter_shape_fixture",
        RouteExecutionStatus::VerificationOnly => "verification_only",
        RouteExecutionStatus::Executable => "executable",
    }
}

fn route_metric_label_pairs(
    labels: &ConfidentialInferenceRouteMetricLabels,
) -> Vec<(&'static str, &str)> {
    vec![
        ("provider", labels.provider.as_str()),
        ("route_id", labels.route_id.as_str()),
        ("requested_model", labels.requested_model.as_str()),
        ("provider_model", labels.provider_model.as_str()),
        ("canonical_model", labels.canonical_model.as_str()),
        ("evidence_family", labels.evidence_family.as_str()),
    ]
}

fn metric_outcome_label(outcome: &ConfidentialInferenceMetricOutcome) -> &'static str {
    match outcome {
        ConfidentialInferenceMetricOutcome::Success => "success",
        ConfidentialInferenceMetricOutcome::Failure => "failure",
    }
}

fn metric_step_label(step: &ConfidentialInferenceMetricStep) -> &'static str {
    match step {
        ConfidentialInferenceMetricStep::RouteVerification => "route_verification",
        ConfidentialInferenceMetricStep::EvidenceFetch => "evidence_fetch",
        ConfidentialInferenceMetricStep::EvidenceVerification => "evidence_verification",
        ConfidentialInferenceMetricStep::TinfoilDcapTdxCollateralResolution => {
            "tinfoil_dcap_tdx_collateral_resolution"
        }
        ConfidentialInferenceMetricStep::ProviderChat => "provider_chat",
    }
}

fn verification_cache_event_label(
    event: &ConfidentialInferenceVerificationCacheEvent,
) -> &'static str {
    match event {
        ConfidentialInferenceVerificationCacheEvent::Hit => "hit",
        ConfidentialInferenceVerificationCacheEvent::Miss => "miss",
        ConfidentialInferenceVerificationCacheEvent::Store => "store",
    }
}

fn single_flight_event_label(event: &ConfidentialInferenceSingleFlightEvent) -> &'static str {
    match event {
        ConfidentialInferenceSingleFlightEvent::Owner => "owner",
        ConfidentialInferenceSingleFlightEvent::Wait => "wait",
        ConfidentialInferenceSingleFlightEvent::QueueFull => "queue_full",
        ConfidentialInferenceSingleFlightEvent::WaitTimeout => "wait_timeout",
    }
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn serde_label<T>(value: &T) -> String
where
    T: Serialize + std::fmt::Debug,
{
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(label)) => label,
        _ => debug_label(value),
    }
}

fn debug_label<T>(value: &T) -> String
where
    T: std::fmt::Debug,
{
    let mut out = String::new();
    for (index, ch) in format!("{value:?}").chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

trait CounterMetricExporter {
    fn counter(
        &mut self,
        name: &'static str,
        help: &'static str,
        labels: &[(&str, &str)],
        value: u64,
    );
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PrometheusMetricKey {
    name: String,
    labels: Vec<(String, String)>,
}

#[derive(Debug, Default)]
struct PrometheusTextExporter {
    metadata: BTreeMap<String, (&'static str, &'static str)>,
    values: BTreeMap<PrometheusMetricKey, u64>,
}

impl CounterMetricExporter for PrometheusTextExporter {
    fn counter(
        &mut self,
        name: &'static str,
        help: &'static str,
        labels: &[(&str, &str)],
        value: u64,
    ) {
        self.metadata.insert(name.into(), (help, "counter"));
        let key = PrometheusMetricKey {
            name: name.into(),
            labels: labels
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        };
        *self.values.entry(key).or_default() += value;
    }
}

impl PrometheusTextExporter {
    fn finish(self) -> String {
        let mut out = String::new();
        for (name, (help, metric_type)) in self.metadata {
            out.push_str("# HELP ");
            out.push_str(&name);
            out.push(' ');
            out.push_str(help);
            out.push('\n');
            out.push_str("# TYPE ");
            out.push_str(&name);
            out.push(' ');
            out.push_str(metric_type);
            out.push('\n');
            for (key, value) in self.values.iter().filter(|(key, _)| key.name == name) {
                out.push_str(&key.name);
                write_prometheus_labels(&mut out, &key.labels);
                out.push(' ');
                out.push_str(&value.to_string());
                out.push('\n');
            }
        }
        out
    }
}

#[derive(Debug, Default)]
struct OtlpJsonMetricsExporter {
    metadata: BTreeMap<String, &'static str>,
    values: BTreeMap<PrometheusMetricKey, u64>,
}

impl CounterMetricExporter for OtlpJsonMetricsExporter {
    fn counter(
        &mut self,
        name: &'static str,
        help: &'static str,
        labels: &[(&str, &str)],
        value: u64,
    ) {
        self.metadata.insert(name.into(), help);
        let key = PrometheusMetricKey {
            name: name.into(),
            labels: labels
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        };
        *self.values.entry(key).or_default() += value;
    }
}

impl OtlpJsonMetricsExporter {
    fn finish(self) -> serde_json::Result<String> {
        let OtlpJsonMetricsExporter { metadata, values } = self;
        let metrics: Vec<_> = metadata
            .into_iter()
            .map(|(name, help)| {
                let data_points: Vec<_> = values
                    .iter()
                    .filter(|(key, _)| key.name == name)
                    .map(|(key, value)| {
                        serde_json::json!({
                            "attributes": otlp_string_attributes(&key.labels),
                            "asInt": value.to_string(),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "name": name,
                    "description": help,
                    "unit": "1",
                    "sum": {
                        "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                        "isMonotonic": true,
                        "dataPoints": data_points,
                    },
                })
            })
            .collect();
        serde_json::to_string(&serde_json::json!({
            "resourceMetrics": [
                {
                    "resource": {
                        "attributes": [
                            otlp_string_attribute("service.name", "confidential-inference-sdk"),
                            otlp_string_attribute("telemetry.sdk.name", "confidential-inference"),
                            otlp_string_attribute("telemetry.sdk.language", "rust"),
                            otlp_string_attribute("confidential-inference.component", "client"),
                        ],
                    },
                    "scopeMetrics": [
                        {
                            "scope": {
                                "name": "confidential-inference-sdk",
                                "version": env!("CARGO_PKG_VERSION"),
                            },
                            "metrics": metrics,
                        },
                    ],
                },
            ],
        }))
    }
}

fn otlp_string_attributes(labels: &[(String, String)]) -> Vec<serde_json::Value> {
    labels
        .iter()
        .map(|(key, value)| otlp_string_attribute(key, value))
        .collect()
}

fn otlp_string_attribute(key: &str, value: &str) -> serde_json::Value {
    serde_json::json!({
        "key": key,
        "value": {
            "stringValue": value,
        },
    })
}

fn write_prometheus_labels(out: &mut String, labels: &[(String, String)]) {
    if labels.is_empty() {
        return;
    }
    out.push('{');
    for (index, (key, value)) in labels.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(key);
        out.push_str("=\"");
        out.push_str(&escape_prometheus_label_value(value));
        out.push('"');
    }
    out.push('}');
}

fn escape_prometheus_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub struct ConfidentialInferenceBuilder {
    policy: VerificationPolicy,
    registry_source: RegistrySource,
    registry_pin: Option<ProviderRegistryPin>,
    reference_values_source: ReferenceValuesSource,
    reference_values_pin: Option<ReferenceValuesPin>,
    trusted_artifact_signing_keys: Vec<TrustedSigningKey>,
    compatibility_matrix: Option<ProviderCompatibilityMatrix>,
    provider_routing: ProviderRoutingConfig,
    adapters: BTreeMap<String, Arc<dyn ProviderAdapter>>,
    tinfoil_quote_verifier: Arc<dyn TinfoilQuoteVerifier>,
    gpu_attestation_verifier: Arc<dyn GpuAttestationVerifier>,
    gpu_attestation_verifier_is_custom: bool,
    tinfoil_dcap_tdx_collateral_resolver: Option<DcapTdxCollateralResolver>,
    time_source: TimeSource,
    audit_sink: Arc<dyn AuditSink>,
    verdict_store: Arc<dyn VerdictStore>,
    metrics_recorder: Arc<dyn ConfidentialInferenceMetricsRecorder>,
    api_keys: BTreeMap<String, ClientApiKey>,
    allow_insecure_plaintext: bool,
}

impl ConfidentialInferenceBuilder {
    pub fn new() -> Self {
        Self {
            policy: VerificationPolicy::require_attested_e2ee(),
            registry_source: RegistrySource::Bundled,
            registry_pin: None,
            reference_values_source: ReferenceValuesSource::Bundled,
            reference_values_pin: None,
            trusted_artifact_signing_keys: Vec::new(),
            compatibility_matrix: None,
            provider_routing: ProviderRoutingConfig::default(),
            adapters: BTreeMap::new(),
            tinfoil_quote_verifier: Arc::new(FailClosedTinfoilQuoteVerifier),
            gpu_attestation_verifier: Arc::new(FailClosedGpuAttestationVerifier),
            gpu_attestation_verifier_is_custom: false,
            tinfoil_dcap_tdx_collateral_resolver: None,
            time_source: Arc::new(now_epoch_millis),
            audit_sink: Arc::new(NoopAuditSink),
            verdict_store: Arc::new(NoopVerdictStore),
            metrics_recorder: Arc::new(NoopConfidentialInferenceMetricsRecorder),
            api_keys: BTreeMap::new(),
            allow_insecure_plaintext: false,
        }
    }

    pub fn policy(mut self, policy: VerificationPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn registry(mut self, registry: ProviderRegistryEnvelope) -> Self {
        self.registry_source = RegistrySource::custom("custom", registry);
        self
    }

    pub fn registry_source(mut self, registry_source: RegistrySource) -> Self {
        self.registry_source = registry_source;
        self
    }

    pub fn registry_with_source(
        mut self,
        registry: ProviderRegistryEnvelope,
        source: impl Into<String>,
    ) -> Self {
        self.registry_source = RegistrySource::custom(source, registry);
        self
    }

    pub fn remote_registry(
        mut self,
        url: impl Into<String>,
        registry: ProviderRegistryEnvelope,
    ) -> Self {
        self.registry_source = RegistrySource::remote(url, registry);
        self
    }

    pub fn remote_registry_with_cache(
        mut self,
        url: impl Into<String>,
        registry: ProviderRegistryEnvelope,
        cache_path: impl Into<PathBuf>,
    ) -> Self {
        self.registry_source = RegistrySource::remote_with_cache(url, registry, cache_path);
        self
    }

    pub fn registry_pin(mut self, registry_pin: ProviderRegistryPin) -> Self {
        self.registry_pin = Some(registry_pin);
        self
    }

    pub fn reference_values(mut self, reference_values: ReferenceValuesEnvelope) -> Self {
        self.reference_values_source = ReferenceValuesSource::custom("custom", reference_values);
        self
    }

    pub fn reference_values_pin(mut self, reference_values_pin: ReferenceValuesPin) -> Self {
        self.reference_values_pin = Some(reference_values_pin);
        self
    }

    pub fn reference_values_source(
        mut self,
        reference_values_source: ReferenceValuesSource,
    ) -> Self {
        self.reference_values_source = reference_values_source;
        self
    }

    pub fn reference_values_with_source(
        mut self,
        reference_values: ReferenceValuesEnvelope,
        source: impl Into<String>,
    ) -> Self {
        self.reference_values_source = ReferenceValuesSource::custom(source, reference_values);
        self
    }

    pub fn remote_reference_values(
        mut self,
        url: impl Into<String>,
        reference_values: ReferenceValuesEnvelope,
    ) -> Self {
        self.reference_values_source = ReferenceValuesSource::remote(url, reference_values);
        self
    }

    pub fn remote_reference_values_with_cache(
        mut self,
        url: impl Into<String>,
        reference_values: ReferenceValuesEnvelope,
        cache_path: impl Into<PathBuf>,
    ) -> Self {
        self.reference_values_source =
            ReferenceValuesSource::remote_with_cache(url, reference_values, cache_path);
        self
    }

    pub fn trusted_artifact_signing_key(mut self, trusted_key: TrustedSigningKey) -> Self {
        self.trusted_artifact_signing_keys.push(trusted_key);
        self
    }

    pub fn trusted_ed25519_artifact_signing_key(
        mut self,
        signer: impl Into<String>,
        key_id: impl Into<String>,
        public_key_base64url: impl Into<String>,
    ) -> Self {
        self.trusted_artifact_signing_keys
            .push(TrustedSigningKey::new(signer, key_id, public_key_base64url));
        self
    }

    pub fn compatibility_matrix(
        mut self,
        compatibility_matrix: ProviderCompatibilityMatrix,
    ) -> Self {
        self.compatibility_matrix = Some(compatibility_matrix);
        self
    }

    pub fn provider_routing(mut self, provider_routing: ProviderRoutingConfig) -> Self {
        self.provider_routing = provider_routing;
        self
    }

    pub fn provider_order<I, S>(mut self, canonical_model: impl Into<String>, providers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.provider_routing = self
            .provider_routing
            .with_provider_order(canonical_model, providers);
        self
    }

    pub fn api_key(mut self, provider: impl Into<String>, api_key: impl Into<String>) -> Self {
        self.api_keys
            .insert(provider.into(), ClientApiKey::from(api_key.into()));
        self
    }

    pub fn allow_insecure_plaintext(mut self, allow: bool) -> Self {
        self.allow_insecure_plaintext = allow;
        self
    }

    pub fn audit_sink(mut self, audit_sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = audit_sink;
        self
    }

    pub fn verdict_store(mut self, verdict_store: Arc<dyn VerdictStore>) -> Self {
        self.verdict_store = verdict_store;
        self
    }

    pub fn metrics_recorder(
        mut self,
        metrics_recorder: Arc<dyn ConfidentialInferenceMetricsRecorder>,
    ) -> Self {
        self.metrics_recorder = metrics_recorder;
        self
    }

    pub fn with_provider<P>(mut self, provider: P) -> Self
    where
        P: ProviderAdapter + 'static,
    {
        self.adapters
            .insert(provider.provider_id().to_owned(), Arc::new(provider));
        self
    }

    pub fn tinfoil_quote_verifier<V>(mut self, verifier: V) -> Self
    where
        V: TinfoilQuoteVerifier + 'static,
    {
        self.tinfoil_quote_verifier = Arc::new(verifier);
        self
    }

    pub fn tinfoil_quote_verifier_arc(mut self, verifier: Arc<dyn TinfoilQuoteVerifier>) -> Self {
        self.tinfoil_quote_verifier = verifier;
        self
    }

    pub fn gpu_attestation_verifier<V>(mut self, verifier: V) -> Self
    where
        V: GpuAttestationVerifier + 'static,
    {
        self.gpu_attestation_verifier = Arc::new(verifier);
        self.gpu_attestation_verifier_is_custom = true;
        self
    }

    pub fn gpu_attestation_verifier_arc(
        mut self,
        verifier: Arc<dyn GpuAttestationVerifier>,
    ) -> Self {
        self.gpu_attestation_verifier = verifier;
        self.gpu_attestation_verifier_is_custom = true;
        self
    }

    pub fn tinfoil_dcap_tdx_collateral_resolver(
        mut self,
        resolver: DcapTdxCollateralResolver,
    ) -> Self {
        self.tinfoil_dcap_tdx_collateral_resolver = Some(resolver);
        self
    }

    pub fn time_source<F>(mut self, time_source: F) -> Self
    where
        F: Fn() -> u64 + Send + Sync + 'static,
    {
        self.time_source = Arc::new(time_source);
        self
    }

    pub fn with_demo_provider(self) -> Self {
        self.with_provider(DemoProvider::valid())
    }

    pub async fn build(self) -> Result<ConfidentialInference> {
        if !self.allow_insecure_plaintext
            && !matches!(self.policy.enforcement, EnforcementMode::Enforce)
        {
            return Err(ClientError::InsecurePolicyRequiresOptIn {
                enforcement: self.policy.enforcement.clone(),
            });
        }

        let time_source = self.time_source.clone();
        let build_now_epoch_millis = time_source();
        let mut trusted_signing_keys =
            confidential_inference_attestation::default_trusted_signing_keys();
        trusted_signing_keys.extend(self.trusted_artifact_signing_keys);
        let (registry_envelope, registry_source) = self
            .registry_source
            .into_envelope_and_source(
                self.registry_pin.as_ref(),
                &trusted_signing_keys,
                build_now_epoch_millis,
            )
            .await?;
        let registry = registry_envelope
            .clone()
            .into_verified_payload_with_keys(&trusted_signing_keys)?;
        let registry_digest = registry.digest()?;
        if let Some(registry_pin) = &self.registry_pin {
            registry_pin.verify_envelope_with_digest_at(
                &registry_envelope,
                &registry_digest,
                build_now_epoch_millis,
            )?;
        }
        let (reference_values, reference_values_source) = self
            .reference_values_source
            .into_envelope_and_source(
                self.reference_values_pin.as_ref(),
                &trusted_signing_keys,
                build_now_epoch_millis,
            )
            .await?;
        reference_values.verify_signature_with_keys(&trusted_signing_keys)?;
        let reference_values_digest = reference_values.payload.digest()?;
        if let Some(reference_values_pin) = &self.reference_values_pin {
            reference_values_pin.verify_envelope_with_digest_at(
                &reference_values,
                &reference_values_digest,
                build_now_epoch_millis,
            )?;
        }
        let policy = self
            .policy
            .with_artifact_digests(registry_digest.clone(), reference_values_digest.clone());
        let registry_artifact_signature = registry_envelope.signature.clone();
        let reference_artifact_signature = reference_values.signature.clone();
        let compatibility_matrix = match self.compatibility_matrix {
            Some(compatibility_matrix) => compatibility_matrix,
            None => ProviderCompatibilityMatrix::bundled()?,
        };
        compatibility_matrix.validate()?;
        compatibility_matrix.validate_registry_routes(&registry)?;
        let mut adapters = self.adapters;
        install_default_credential_adapters(&registry, &self.api_keys, &mut adapters)?;
        let needs_live_tdx_collateral = registry.models.values().any(|model| {
            model.routes.iter().any(|route| {
                route.route_status == RouteLifecycle::Active
                    && matches!(
                        route.evidence_family.as_str(),
                        "chutes_live_e2ee" | "near_hw_verified_tls"
                    )
            })
        });
        let tinfoil_dcap_tdx_collateral_resolver = match self.tinfoil_dcap_tdx_collateral_resolver {
            Some(resolver) => Some(resolver),
            None if needs_live_tdx_collateral => {
                Some(DcapTdxCollateralResolver::with_phala_pccs()?)
            }
            None => None,
        };
        validate_provider_routing(
            &self.provider_routing,
            &registry,
            &compatibility_matrix,
            &adapters,
            &policy,
        )?;

        Ok(ConfidentialInference {
            inner: Arc::new(ClientInner {
                policy,
                registry,
                registry_digest,
                registry_source,
                registry_signature: SignatureMetadata {
                    signer: registry_artifact_signature.signer.clone(),
                    key_id: registry_artifact_signature.key_id.clone(),
                    alg: registry_artifact_signature.alg.clone(),
                },
                registry_artifact_signature,
                reference_values: reference_values.payload,
                reference_values_digest,
                reference_values_source,
                reference_signature: SignatureMetadata {
                    signer: reference_artifact_signature.signer.clone(),
                    key_id: reference_artifact_signature.key_id.clone(),
                    alg: reference_artifact_signature.alg.clone(),
                },
                reference_artifact_signature,
                compatibility_matrix,
                provider_routing: self.provider_routing,
                adapters,
                tinfoil_quote_verifier: self.tinfoil_quote_verifier,
                gpu_attestation_verifier: self.gpu_attestation_verifier,
                gpu_attestation_verifier_is_custom: self.gpu_attestation_verifier_is_custom,
                tinfoil_dcap_tdx_collateral_resolver,
                time_source,
                audit_sink: self.audit_sink,
                verdict_store: self.verdict_store,
                metrics_recorder: self.metrics_recorder,
                api_keys: self.api_keys,
                verdict_cache: Mutex::new(BTreeMap::new()),
                in_flight_verifications: Mutex::new(BTreeMap::new()),
            }),
        })
    }
}

fn install_default_credential_adapters(
    registry: &ProviderRegistry,
    api_keys: &BTreeMap<String, ClientApiKey>,
    adapters: &mut BTreeMap<String, Arc<dyn ProviderAdapter>>,
) -> Result<()> {
    for (provider_id, api_key) in api_keys {
        if adapters.contains_key(provider_id) {
            continue;
        }
        let routes = active_routes_for_provider(registry, provider_id);
        if routes.is_empty() {
            continue;
        }

        let adapter: Arc<dyn ProviderAdapter> = if provider_id == "chutes"
            && routes
                .iter()
                .any(|route| route.evidence_family == "chutes_live_e2ee")
        {
            Arc::new(ChutesHttpProvider::new(
                provider_id,
                routes,
                api_key.expose().to_owned(),
            )?)
        } else if provider_id == "near"
            && routes
                .iter()
                .any(|route| route.evidence_family == "near_hw_verified_tls")
        {
            Arc::new(NearHttpProvider::new(
                provider_id,
                routes,
                api_key.expose().to_owned(),
            )?)
        } else if provider_id == "tinfoil" {
            Arc::new(TinfoilHttpProvider::with_provider_id(
                provider_id,
                routes,
                Some(api_key.expose().to_owned()),
            )?)
        } else if routes.iter().any(|route| {
            matches!(
                route.evidence_family.as_str(),
                "dstack_app_e2ee" | "chutes_e2ee"
            )
        }) {
            Arc::new(ConfidentialHttpProvider::with_api_key(
                provider_id,
                routes,
                Some(api_key.expose().to_owned()),
            )?)
        } else {
            Arc::new(OpenAiHttpProvider::with_api_key(
                provider_id,
                routes,
                Some(api_key.expose().to_owned()),
            )?)
        };
        adapters.insert(provider_id.clone(), adapter);
    }

    Ok(())
}

fn active_routes_for_provider(registry: &ProviderRegistry, provider: &str) -> Vec<RouteDefinition> {
    registry
        .models
        .values()
        .flat_map(|model| model.routes.iter())
        .filter(|route| route.provider == provider && route.route_status == RouteLifecycle::Active)
        .cloned()
        .collect()
}

impl Default for ConfidentialInferenceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct VerifiedRoute {
    client: ConfidentialInference,
    route_definition: RouteDefinition,
    route: AttestedRoute,
    verdict: AttestationVerdict,
}

impl VerifiedRoute {
    pub fn verdict(&self) -> &AttestationVerdict {
        &self.verdict
    }

    pub fn route(&self) -> &AttestedRoute {
        &self.route
    }

    pub async fn chat(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ConfidentialResponse<ChatCompletionResponse>> {
        if request.model != self.route.requested_model {
            return Err(ClientError::VerifiedRouteModelMismatch {
                route_id: self.route.route_id.clone(),
                verified_model: self.route.requested_model.clone(),
                request_model: request.model,
            });
        }

        let request_mode = VerificationRequestMode::for_chat_request(&request);
        if request.streaming() && !self.route.streaming_allowed {
            self.client
                .record_streaming_fail_closed(&self.route_definition, &self.route);
            return Err(ClientError::StreamingNotSupported {
                route_id: self.route.route_id.clone(),
            });
        }

        if !self.client.verdict_expiry_allows_use(&self.verdict) {
            return Err(ClientError::VerifiedRouteExpired {
                expires_at: self.verdict.expires_at.clone(),
            });
        }

        // Send-time recheck: a detached verdict is never authority to execute.
        let mut refreshed = self
            .client
            .verify_selected_route(
                self.route_definition.clone(),
                self.route.clone(),
                request_mode,
            )
            .await?;

        if request.streaming() && !refreshed.route.streaming_allowed {
            refreshed
                .client
                .record_streaming_fail_closed(&refreshed.route_definition, &refreshed.route);
            return Err(ClientError::StreamingNotSupported {
                route_id: refreshed.route.route_id.clone(),
            });
        }

        let mut refreshed_after_rotation = false;
        loop {
            let adapter = refreshed.client.adapter(&refreshed.route.provider)?;
            let compatibility = refreshed
                .client
                .inner
                .compatibility_matrix
                .provider(&refreshed.route.provider)?;
            compatibility.validate_route(&refreshed.route_definition)?;
            if !compatibility.route_execution_status.allows_chat_execution() {
                return Err(ClientError::Provider(ProviderError::Compatibility(
                    format!(
                        "route {} is {:?} and cannot execute chat requests",
                        refreshed.route.route_id, compatibility.route_execution_status
                    ),
                )));
            }
            let provider_request =
                compatibility.adapt_chat_request(&refreshed.route_definition, &request)?;
            let chat_started_at = Instant::now();
            let response = adapter
                .chat(&refreshed.route_definition, provider_request)
                .instrument(tracing::info_span!(
                    "confidential-inference.provider_chat",
                    provider = %refreshed.route.provider,
                    route_id = %refreshed.route.route_id,
                    evidence_family = %refreshed.route.evidence_family,
                    requested_model = %refreshed.route.requested_model,
                    provider_model = %refreshed.route.provider_model,
                    canonical_model = %refreshed.route.canonical_model
                ))
                .await;
            let chat_succeeded = response.is_ok();
            refreshed.client.record_latency(
                ConfidentialInferenceRouteMetricLabels::from_route(
                    &refreshed.route_definition,
                    &refreshed.route,
                ),
                ConfidentialInferenceMetricStep::ProviderChat,
                chat_started_at.elapsed(),
                chat_succeeded,
            );

            match response {
                Ok(response) => {
                    refreshed.verdict.validate_summary_consistency()?;
                    return Ok(ConfidentialResponse {
                        provider: refreshed.route.provider.clone(),
                        provider_model: refreshed.route.provider_model.clone(),
                        requested_model: refreshed.route.requested_model.clone(),
                        response_channel_bound: refreshed.verdict.response_channel_bound,
                        response_integrity_result: refreshed
                            .verdict
                            .response_integrity_result
                            .clone(),
                        route: refreshed.route,
                        verdict: refreshed.verdict,
                        response,
                    });
                }
                Err(error) if error.is_key_rotation() && !refreshed_after_rotation => {
                    tracing::warn!(
                        provider = %refreshed.route.provider,
                        route_id = %refreshed.route.route_id,
                        "provider reported key rotation; refreshing evidence before retry"
                    );
                    refreshed_after_rotation = true;
                    refreshed = refreshed
                        .client
                        .refresh_selected_route_after_key_rotation(
                            refreshed.route_definition.clone(),
                            refreshed.route.clone(),
                            request_mode,
                        )
                        .await?;
                }
                Err(error) => return Err(ClientError::Provider(error)),
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfidentialResponse<T> {
    pub response: T,
    pub provider: String,
    pub provider_model: String,
    pub requested_model: String,
    pub verdict: AttestationVerdict,
    pub response_channel_bound: bool,
    pub response_integrity_result: ResponseIntegrityResult,
    pub route: AttestedRoute,
}

fn serialize_response_json<T: Serialize>(response: &ConfidentialResponse<T>) -> Result<String> {
    serde_json::to_string(response)
        .map_err(|error| ClientError::ResponseJsonSerialization(error.to_string()))
}

#[derive(Clone, Debug)]
pub struct ChatCompletionRequestPayload {
    request: ChatCompletionRequest,
}

impl ChatCompletionRequestPayload {
    pub fn from_json_str(request_json: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(request_json).map(|request| Self { request })
    }

    pub fn with_streaming(mut self, stream: bool) -> Self {
        self.request.stream = Some(stream);
        self
    }

    fn into_inner(self) -> ChatCompletionRequest {
        self.request
    }
}

#[derive(Clone, Debug)]
pub struct ResponseCreateRequestPayload {
    request: ResponseCreateRequest,
}

impl ResponseCreateRequestPayload {
    pub fn from_json_str(request_json: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(request_json).map(|request| Self { request })
    }

    fn into_inner(self) -> ResponseCreateRequest {
        self.request
    }
}

pub struct ChatCompletionsBuilder {
    client: ConfidentialInference,
    model: Option<String>,
    messages: Vec<ChatMessage>,
    stream: Option<bool>,
    max_tokens: Option<u32>,
    temperature: Option<f32>,
}

impl ChatCompletionsBuilder {
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    pub fn messages(mut self, messages: Vec<ChatMessage>) -> Self {
        self.messages = messages;
        self
    }

    pub fn message(mut self, message: ChatMessage) -> Self {
        self.messages.push(message);
        self
    }

    pub fn stream(mut self, stream: bool) -> Self {
        self.stream = Some(stream);
        self
    }

    pub fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    pub fn temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    pub async fn send(self) -> Result<ConfidentialResponse<ChatCompletionResponse>> {
        let model = self.model.ok_or(ClientError::MissingModel)?;
        let request = ChatCompletionRequest {
            model,
            messages: self.messages,
            stream: self.stream,
            max_tokens: self.max_tokens,
            temperature: self.temperature,
        };
        self.client.send_chat_completion_request(request).await
    }
}

pub struct ResponsesBuilder {
    client: ConfidentialInference,
    request: ResponseCreateRequest,
}

impl ResponsesBuilder {
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.request.model = Some(model.into());
        self
    }

    pub fn input(mut self, input: ResponseInput) -> Self {
        self.request.input = Some(input);
        self
    }

    pub fn text_input(mut self, input: impl Into<String>) -> Self {
        self.request.input = Some(ResponseInput::Text(input.into()));
        self
    }

    pub fn instructions(mut self, instructions: impl Into<String>) -> Self {
        self.request.instructions = Some(instructions.into());
        self
    }

    pub fn stream(mut self, stream: bool) -> Self {
        self.request.stream = Some(stream);
        self
    }

    pub fn max_output_tokens(mut self, max_output_tokens: u32) -> Self {
        self.request.max_output_tokens = Some(max_output_tokens);
        self
    }

    pub fn temperature(mut self, temperature: f32) -> Self {
        self.request.temperature = Some(temperature);
        self
    }

    pub async fn send(self) -> Result<ConfidentialResponse<ResponseObject>> {
        self.client.create_response(self.request).await
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub provider: String,
    pub route_id: String,
    pub requested_model: String,
    pub provider_model: String,
    pub canonical_model: String,
    pub evidence_family: String,
    pub adapter_version: String,
    pub trust_tier: TrustTier,
    pub channel_binding_kind: ChannelBindingKind,
    pub request_confidentiality_result: confidential_inference_attestation::ConfidentialityResult,
    pub response_confidentiality_result: confidential_inference_attestation::ConfidentialityResult,
    pub response_integrity_result: ResponseIntegrityResult,
    pub enforcement: EnforcementMode,
    pub status: confidential_inference_attestation::VerificationStatus,
    pub request_allowed: bool,
    pub would_block_under_enforce: bool,
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
    pub freshness_class: confidential_inference_attestation::FreshnessClass,
    pub streaming_allowed: bool,
    pub route_execution_status: String,
    pub chat_executable: bool,
    pub known_unsupported_modes: Vec<String>,
    pub cache_hit: bool,
    pub errors: Vec<String>,
}

impl AuditEvent {
    fn from_verdict(verdict: &AttestationVerdict, cache_hit: bool) -> Self {
        Self {
            provider: verdict.provider.clone(),
            route_id: verdict.route_id.clone(),
            requested_model: verdict.requested_model.clone(),
            provider_model: verdict.provider_model.clone(),
            canonical_model: verdict.canonical_model.clone(),
            evidence_family: verdict.evidence_family.clone(),
            adapter_version: verdict.adapter_version.clone(),
            trust_tier: verdict.trust_tier.clone(),
            channel_binding_kind: verdict.channel_binding_kind.clone(),
            request_confidentiality_result: verdict.request_confidentiality_result.clone(),
            response_confidentiality_result: verdict.response_confidentiality_result.clone(),
            response_integrity_result: verdict.response_integrity_result.clone(),
            enforcement: verdict.enforcement.clone(),
            status: verdict.status.clone(),
            request_allowed: verdict.request_allowed,
            would_block_under_enforce: verdict.would_block_under_enforce,
            policy_digest: verdict.policy_digest.clone(),
            provider_registry_digest: verdict.provider_registry_digest.clone(),
            registry_version: verdict.registry_version.clone(),
            registry_source: verdict.registry_source.clone(),
            registry_sync_completed_at: verdict.registry_sync_completed_at.clone(),
            registry_signature: verdict.registry_signature.clone(),
            reference_values_digest: verdict.reference_values_digest.clone(),
            reference_values_version: verdict.reference_values_version.clone(),
            reference_values_source: verdict.reference_values_source.clone(),
            reference_values_signature: verdict.reference_values_signature.clone(),
            raw_evidence_digest: verdict.raw_evidence_digest.clone(),
            evidence_digest: verdict.evidence_digest.clone(),
            verified_at: verdict.verified_at.clone(),
            expires_at: verdict.expires_at.clone(),
            freshness_class: verdict.freshness_class.clone(),
            streaming_allowed: verdict.streaming_allowed,
            route_execution_status: verdict.route_execution_status.clone(),
            chat_executable: verdict.chat_executable,
            known_unsupported_modes: verdict.known_unsupported_modes.clone(),
            cache_hit,
            errors: verdict
                .errors
                .iter()
                .map(|error| format!("{}:{}", error.code, error.message))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerdictRecord {
    pub request_id: String,
    pub provider: String,
    pub route_id: String,
    pub requested_model: String,
    pub provider_model: String,
    pub canonical_model: String,
    pub enforcement: EnforcementMode,
    pub status: confidential_inference_attestation::VerificationStatus,
    pub request_allowed: bool,
    pub would_block_under_enforce: bool,
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
    pub freshness_class: confidential_inference_attestation::FreshnessClass,
    pub streaming_allowed: bool,
    pub route_execution_status: String,
    pub chat_executable: bool,
    pub known_unsupported_modes: Vec<String>,
    pub cache_hit: bool,
    pub errors: Vec<String>,
    pub verdict_json: serde_json::Value,
}

impl VerdictRecord {
    fn from_verdict(verdict: &AttestationVerdict, cache_hit: bool) -> Self {
        Self {
            request_id: format!(
                "{}:{}:{}",
                verdict.route_id, verdict.verified_at, verdict.raw_evidence_digest
            ),
            provider: verdict.provider.clone(),
            route_id: verdict.route_id.clone(),
            requested_model: verdict.requested_model.clone(),
            provider_model: verdict.provider_model.clone(),
            canonical_model: verdict.canonical_model.clone(),
            enforcement: verdict.enforcement.clone(),
            status: verdict.status.clone(),
            request_allowed: verdict.request_allowed,
            would_block_under_enforce: verdict.would_block_under_enforce,
            policy_digest: verdict.policy_digest.clone(),
            provider_registry_digest: verdict.provider_registry_digest.clone(),
            registry_version: verdict.registry_version.clone(),
            registry_source: verdict.registry_source.clone(),
            registry_sync_completed_at: verdict.registry_sync_completed_at.clone(),
            registry_signature: verdict.registry_signature.clone(),
            reference_values_digest: verdict.reference_values_digest.clone(),
            reference_values_version: verdict.reference_values_version.clone(),
            reference_values_source: verdict.reference_values_source.clone(),
            reference_values_signature: verdict.reference_values_signature.clone(),
            raw_evidence_digest: verdict.raw_evidence_digest.clone(),
            evidence_digest: verdict.evidence_digest.clone(),
            verified_at: verdict.verified_at.clone(),
            expires_at: verdict.expires_at.clone(),
            freshness_class: verdict.freshness_class.clone(),
            streaming_allowed: verdict.streaming_allowed,
            route_execution_status: verdict.route_execution_status.clone(),
            chat_executable: verdict.chat_executable,
            known_unsupported_modes: verdict.known_unsupported_modes.clone(),
            cache_hit,
            errors: verdict
                .errors
                .iter()
                .map(|error| format!("{}:{}", error.code, error.message))
                .collect(),
            verdict_json: serde_json::to_value(verdict).unwrap_or(serde_json::Value::Null),
        }
    }
}

pub trait VerdictStore: Send + Sync {
    fn persist(&self, record: &VerdictRecord);
}

#[derive(Debug)]
pub struct NoopVerdictStore;

impl VerdictStore for NoopVerdictStore {
    fn persist(&self, _record: &VerdictRecord) {}
}

#[derive(Debug)]
pub struct JsonlVerdictStore {
    file: Mutex<std::fs::File>,
}

impl JsonlVerdictStore {
    pub fn create(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl VerdictStore for JsonlVerdictStore {
    fn persist(&self, record: &VerdictRecord) {
        let Ok(mut file) = self.file.lock() else {
            return;
        };
        if serde_json::to_writer(&mut *file, record).is_ok() {
            let _ = writeln!(&mut *file);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VerificationCacheKey {
    provider: String,
    route_id: String,
    evidence_family: String,
    requested_model: String,
    provider_model: String,
    canonical_model: String,
    api_endpoint: String,
    evidence_endpoint: String,
    policy_digest: String,
    reference_values_digest: String,
    provider_registry_digest: String,
    adapter_version: String,
    trust_tier: String,
    channel_binding_kind: String,
    request_confidentiality_requirement: String,
    response_confidentiality_requirement: String,
    response_integrity_requirement: String,
    request_encryption: String,
    response_decryption: String,
    streaming_allowed: bool,
    request_mode: &'static str,
}

impl VerificationCacheKey {
    fn new(
        route_definition: &RouteDefinition,
        route: &AttestedRoute,
        request_mode: VerificationRequestMode,
        policy_digest: &str,
        provider_registry_digest: &str,
        reference_values_digest: &str,
    ) -> Self {
        Self {
            provider: route.provider.clone(),
            route_id: route.route_id.clone(),
            evidence_family: route.evidence_family.clone(),
            requested_model: route.requested_model.clone(),
            provider_model: route.provider_model.clone(),
            canonical_model: route.canonical_model.clone(),
            api_endpoint: route.api_endpoint.clone(),
            evidence_endpoint: route.evidence_endpoint.clone(),
            policy_digest: policy_digest.to_owned(),
            reference_values_digest: reference_values_digest.to_owned(),
            provider_registry_digest: provider_registry_digest.to_owned(),
            adapter_version: route.adapter_version.clone(),
            trust_tier: format!("{:?}", route.trust_tier),
            channel_binding_kind: format!("{:?}", route.channel_binding_kind),
            request_confidentiality_requirement: format!(
                "{:?}",
                route_definition.request_confidentiality_requirement
            ),
            response_confidentiality_requirement: format!(
                "{:?}",
                route_definition.response_confidentiality_requirement
            ),
            response_integrity_requirement: format!(
                "{:?}",
                route_definition.response_integrity_requirement
            ),
            request_encryption: format!("{:?}", route_definition.request_encryption),
            response_decryption: format!("{:?}", route_definition.response_decryption),
            streaming_allowed: route.streaming_allowed,
            request_mode: request_mode.as_str(),
        }
    }

    fn metric_labels(&self) -> ConfidentialInferenceRouteMetricLabels {
        ConfidentialInferenceRouteMetricLabels {
            provider: self.provider.clone(),
            route_id: self.route_id.clone(),
            requested_model: self.requested_model.clone(),
            provider_model: self.provider_model.clone(),
            canonical_model: self.canonical_model.clone(),
            evidence_family: self.evidence_family.clone(),
        }
    }
}

#[derive(Clone)]
struct CachedVerdict {
    verdict: AttestationVerdict,
    inserted_at: Instant,
    inserted_wall_clock_epoch_ms: u64,
}

impl CachedVerdict {
    fn is_valid(
        &self,
        now_epoch_ms: u64,
        max_cache_age_ms: u64,
        stale_policy: &StaleVerdictPolicy,
    ) -> bool {
        verdict_epoch_allowed_by_stale_policy(
            self.verdict.expires_at_epoch_ms,
            now_epoch_ms,
            stale_policy,
        ) && self.inserted_at.elapsed().as_millis() <= u128::from(max_cache_age_ms)
            && !self.wall_clock_jump_detected(now_epoch_ms)
    }

    fn wall_clock_jump_detected(&self, now_epoch_ms: u64) -> bool {
        let monotonic_elapsed_ms = duration_millis(self.inserted_at.elapsed());
        let wall_elapsed_ms = now_epoch_ms.abs_diff(self.inserted_wall_clock_epoch_ms);
        monotonic_elapsed_ms.abs_diff(wall_elapsed_ms) > CACHE_CLOCK_JUMP_REVALIDATION_THRESHOLD_MS
    }
}

enum VerificationFlight {
    Owner,
    Wait(Arc<Notify>),
    QueueFull,
}

struct VerificationFlightState {
    notify: Arc<Notify>,
    waiters: usize,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent);
}

#[derive(Debug)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(&self, _event: &AuditEvent) {}
}

#[derive(Debug)]
pub struct JsonlAuditSink {
    file: Mutex<std::fs::File>,
}

impl JsonlAuditSink {
    pub fn create(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl AuditSink for JsonlAuditSink {
    fn record(&self, event: &AuditEvent) {
        let Ok(mut file) = self.file.lock() else {
            return;
        };
        if serde_json::to_writer(&mut *file, event).is_ok() {
            let _ = writeln!(&mut *file);
        }
    }
}

fn now_epoch_millis() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    millis.min(u128::from(u64::MAX)) as u64
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
fn single_flight_wait_timeout() -> Duration {
    Duration::from_millis(250)
}

#[cfg(not(test))]
fn single_flight_wait_timeout() -> Duration {
    Duration::from_secs(30)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use base64::Engine;
    use confidential_inference_attestation::{
        canonical_json, chutes_expected_report_data_prefix, AliasConfidence, ArtifactSignature,
        CheckResult, ConfidentialityResult, CpuTeeKind, DcapTdxCollateralBundle,
        DcapTdxCollateralSource, DcapTdxTinfoilQuoteVerifier, EvidenceHardware, FreshnessClass,
        FreshnessPolicy, Millis, ProviderReference, RouteReference, TinfoilAttestationDoc,
        TinfoilAttestationFormat, TinfoilLiveCaptureEvidence, TinfoilQuoteVerificationRequest,
        TinfoilQuoteVerifier, TinfoilTlsEvidence, TrustedSigningKey, VerificationStatus,
        VerifiedTinfoilQuote, DEMO_SIGNING_KEY_ID, TINFOIL_TDX_GUEST_V2_FORMAT,
    };
    use confidential_inference_attestation::{
        GpuAttestationVerifier, GpuTeeKind, NvidiaGpuAttestationVerificationRequest,
        VerifiedGpuAttestation,
    };
    use confidential_inference_openai::{ChatChoice, Usage};
    use confidential_inference_providers::{
        CacheabilityClass, CredentialKind, DcapTdxCollateralFetcher, DcapTdxCollateralResolver,
        DemoProvider, ModelIdRewrite, ModelListingBehavior, ProviderChatRequest,
        ProviderRequestConfidentiality, SdkAppE2eeSecretKey, SourceSyncRun, StreamingSupport,
        TinfoilFixtureProvider, TokenParameterRewrite, VeniceFixtureProvider,
    };
    use ed25519_compact::{KeyPair, Seed};
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tracing_subscriber::fmt::MakeWriter;

    const INVALID_ALGORITHMIC_ALIAS_REGISTRY_SIGNATURE: &str = "base64url:J07kTahwKDRVmjX2T1QIHLNKH7ddm1_zzR2Acic_h-VKMHfMzA9pRBqPU6-u0FjyNKtWeGRW1qgRj3Q36elEAg";
    const SAMPLE_DCAP_QUOTE: &[u8] =
        include_bytes!("../../../fixtures/evidence/dcap-qvl/tdx_quote.bin");
    const SAMPLE_DCAP_COLLATERAL: &[u8] =
        include_bytes!("../../../fixtures/evidence/dcap-qvl/tdx_quote_collateral.json");

    #[derive(Default)]
    struct MemoryAuditSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl AuditSink for MemoryAuditSink {
        fn record(&self, event: &AuditEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    #[derive(Default)]
    struct MemoryVerdictStore {
        records: Mutex<Vec<VerdictRecord>>,
    }

    impl VerdictStore for MemoryVerdictStore {
        fn persist(&self, record: &VerdictRecord) {
            self.records.lock().unwrap().push(record.clone());
        }
    }

    #[derive(Clone, Default)]
    struct CapturedTraceWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl<'writer> MakeWriter<'writer> for CapturedTraceWriter {
        type Writer = CapturedTraceWriteGuard;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedTraceWriteGuard {
                buffer: self.buffer.clone(),
            }
        }
    }

    struct CapturedTraceWriteGuard {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl std::io::Write for CapturedTraceWriteGuard {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.buffer.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct CountingProvider {
        inner: DemoProvider,
        evidence_fetches: Arc<AtomicUsize>,
        fetch_delay: Option<Duration>,
        evidence_nonces: Option<Arc<Mutex<Vec<Option<String>>>>>,
        chat_bodies: Option<Arc<Mutex<Vec<serde_json::Value>>>>,
    }

    impl CountingProvider {
        fn valid(fetches: Arc<AtomicUsize>) -> Self {
            Self {
                inner: DemoProvider::valid(),
                evidence_fetches: fetches,
                fetch_delay: None,
                evidence_nonces: None,
                chat_bodies: None,
            }
        }

        fn valid_with_delay(fetches: Arc<AtomicUsize>, fetch_delay: Duration) -> Self {
            Self {
                inner: DemoProvider::valid(),
                evidence_fetches: fetches,
                fetch_delay: Some(fetch_delay),
                evidence_nonces: None,
                chat_bodies: None,
            }
        }

        fn valid_with_nonce_capture(
            fetches: Arc<AtomicUsize>,
            evidence_nonces: Arc<Mutex<Vec<Option<String>>>>,
        ) -> Self {
            Self {
                inner: DemoProvider::valid(),
                evidence_fetches: fetches,
                fetch_delay: None,
                evidence_nonces: Some(evidence_nonces),
                chat_bodies: None,
            }
        }

        fn valid_with_body_capture(
            fetches: Arc<AtomicUsize>,
            chat_bodies: Arc<Mutex<Vec<serde_json::Value>>>,
        ) -> Self {
            Self {
                inner: DemoProvider::valid(),
                evidence_fetches: fetches,
                fetch_delay: None,
                evidence_nonces: None,
                chat_bodies: Some(chat_bodies),
            }
        }
    }

    #[async_trait]
    impl ProviderAdapter for CountingProvider {
        fn provider_id(&self) -> &str {
            self.inner.provider_id()
        }

        fn routes(&self) -> Vec<RouteDefinition> {
            self.inner.routes()
        }

        async fn fetch_evidence(
            &self,
            route: &RouteDefinition,
            request: &EvidenceRequest,
        ) -> std::result::Result<Vec<u8>, ProviderError> {
            self.evidence_fetches.fetch_add(1, Ordering::SeqCst);
            if let Some(evidence_nonces) = &self.evidence_nonces {
                evidence_nonces.lock().unwrap().push(request.nonce.clone());
            }
            if let Some(delay) = self.fetch_delay {
                tokio::time::sleep(delay).await;
            }
            self.inner.fetch_evidence(route, request).await
        }

        async fn chat(
            &self,
            route: &RouteDefinition,
            request: ProviderChatRequest,
        ) -> std::result::Result<ChatCompletionResponse, ProviderError> {
            if let Some(chat_bodies) = &self.chat_bodies {
                let body = request
                    .fixture_decrypted_body(route)
                    .unwrap_or_else(|_| request.body().clone());
                chat_bodies.lock().unwrap().push(body);
            }
            self.inner.chat(route, request).await
        }
    }

    #[derive(Clone)]
    struct KeyRotatingProvider {
        inner: CountingProvider,
        chat_attempts: Arc<AtomicUsize>,
    }

    impl KeyRotatingProvider {
        fn new(fetches: Arc<AtomicUsize>, chat_attempts: Arc<AtomicUsize>) -> Self {
            Self {
                inner: CountingProvider::valid(fetches),
                chat_attempts,
            }
        }
    }

    #[async_trait]
    impl ProviderAdapter for KeyRotatingProvider {
        fn provider_id(&self) -> &str {
            self.inner.provider_id()
        }

        fn routes(&self) -> Vec<RouteDefinition> {
            self.inner.routes()
        }

        async fn fetch_evidence(
            &self,
            route: &RouteDefinition,
            request: &EvidenceRequest,
        ) -> std::result::Result<Vec<u8>, ProviderError> {
            self.inner.fetch_evidence(route, request).await
        }

        async fn chat(
            &self,
            route: &RouteDefinition,
            request: ProviderChatRequest,
        ) -> std::result::Result<ChatCompletionResponse, ProviderError> {
            if self.chat_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(ProviderError::key_rotation(
                    route.route_id.clone(),
                    "test provider key changed after cached verification",
                ));
            }
            self.inner.chat(route, request).await
        }
    }

    #[derive(Clone)]
    struct SdkEncryptedDemoProvider {
        inner: DemoProvider,
        secret_key: SdkAppE2eeSecretKey,
        encrypted_bodies: Arc<Mutex<Vec<serde_json::Value>>>,
        decrypted_bodies: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    #[async_trait]
    impl ProviderAdapter for SdkEncryptedDemoProvider {
        fn provider_id(&self) -> &str {
            self.inner.provider_id()
        }

        fn routes(&self) -> Vec<RouteDefinition> {
            self.inner.routes()
        }

        async fn fetch_evidence(
            &self,
            route: &RouteDefinition,
            request: &EvidenceRequest,
        ) -> std::result::Result<Vec<u8>, ProviderError> {
            self.inner.fetch_evidence(route, request).await
        }

        async fn chat(
            &self,
            route: &RouteDefinition,
            request: ProviderChatRequest,
        ) -> std::result::Result<ChatCompletionResponse, ProviderError> {
            if request.confidentiality() != &ProviderRequestConfidentiality::SdkEncrypted {
                return Err(ProviderError::Adapter(
                    "SDK-encrypted demo provider requires SDK-encrypted request metadata".into(),
                ));
            }
            self.encrypted_bodies
                .lock()
                .unwrap()
                .push(request.body().clone());
            let (request, _session) =
                request.to_sdk_decrypted_openai_request(route, &self.secret_key)?;
            let decrypted = serde_json::to_value(&request)?;
            self.decrypted_bodies.lock().unwrap().push(decrypted);
            if route.provider_model != request.model {
                return Err(ProviderError::Adapter(format!(
                    "request model {} was not rewritten to provider model {}",
                    request.model, route.provider_model
                )));
            }

            let content = format!(
                "sdk encrypted demo response for {}: {}",
                route.provider_model,
                request.last_user_message().unwrap_or("")
            );
            let prompt_tokens = request
                .messages
                .iter()
                .map(|message| message.content.split_whitespace().count() as u32)
                .sum::<u32>();
            let completion_tokens = content.split_whitespace().count() as u32;

            Ok(ChatCompletionResponse {
                id: "chatcmpl-sdk-encrypted-demo".into(),
                object: "chat.completion".into(),
                created: 1_783_209_600,
                model: route.provider_model.clone(),
                choices: vec![ChatChoice {
                    index: 0,
                    message: ChatMessage::assistant(content),
                    finish_reason: "stop".into(),
                }],
                usage: Some(Usage {
                    prompt_tokens,
                    completion_tokens,
                    total_tokens: prompt_tokens + completion_tokens,
                }),
            })
        }
    }

    #[derive(Clone, Debug)]
    struct LiveTinfoilCaptureProvider {
        inner: TinfoilFixtureProvider,
        quote_bytes: Vec<u8>,
    }

    impl LiveTinfoilCaptureProvider {
        fn with_quote_bytes(quote_bytes: Vec<u8>) -> Self {
            Self {
                inner: TinfoilFixtureProvider,
                quote_bytes,
            }
        }
    }

    impl Default for LiveTinfoilCaptureProvider {
        fn default() -> Self {
            Self::with_quote_bytes(vec![7_u8; 48])
        }
    }

    #[async_trait]
    impl ProviderAdapter for LiveTinfoilCaptureProvider {
        fn provider_id(&self) -> &str {
            self.inner.provider_id()
        }

        fn routes(&self) -> Vec<RouteDefinition> {
            self.inner.routes()
        }

        async fn fetch_evidence(
            &self,
            route: &RouteDefinition,
            request: &EvidenceRequest,
        ) -> std::result::Result<Vec<u8>, ProviderError> {
            if route.provider != self.provider_id() {
                return Err(ProviderError::Adapter(format!(
                    "route {} does not belong to provider {}",
                    route.route_id,
                    self.provider_id()
                )));
            }
            Ok(live_tinfoil_capture_json(route, request, &self.quote_bytes))
        }

        async fn chat(
            &self,
            route: &RouteDefinition,
            request: ProviderChatRequest,
        ) -> std::result::Result<ChatCompletionResponse, ProviderError> {
            self.inner.chat(route, request).await
        }
    }

    #[derive(Clone)]
    struct StaticTinfoilQuoteVerifier {
        quote: VerifiedTinfoilQuote,
    }

    impl TinfoilQuoteVerifier for StaticTinfoilQuoteVerifier {
        fn verify_tinfoil_quote(
            &self,
            request: &TinfoilQuoteVerificationRequest<'_>,
        ) -> confidential_inference_attestation::Result<VerifiedTinfoilQuote> {
            assert_eq!(
                request.attestation_format,
                TinfoilAttestationFormat::TdxGuestV2
            );
            assert_eq!(request.quote_bytes.len(), 48);
            assert_eq!(request.live_tls_spki_sha256, tinfoil_fixture_spki_sha256());
            assert!(!request.live_tls_leaf_certificate_der.is_empty());
            Ok(self.quote.clone())
        }
    }

    #[derive(Clone)]
    struct StaticGpuAttestationVerifier;

    impl GpuAttestationVerifier for StaticGpuAttestationVerifier {
        fn verify_nvidia_gpu_attestation(
            &self,
            request: &NvidiaGpuAttestationVerificationRequest<'_>,
        ) -> confidential_inference_attestation::Result<VerifiedGpuAttestation> {
            assert_eq!(request.expected_tee, GpuTeeKind::NvidiaCc);
            assert_eq!(request.expected_nonce, request.evidence.nonce);
            assert_eq!(request.provider, "redpill-http-test");
            assert!(request
                .route_id
                .starts_with("redpill-http-test:gpt-oss-120b:"));
            assert!(request.evidence.raw_payload_base64.is_some());
            Ok(VerifiedGpuAttestation::nvidia_cc(
                request.expected_nonce,
                request.evidence.attestation_format.clone(),
                "static-client-test-verifier",
            ))
        }
    }

    #[derive(Clone)]
    struct StaticDcapCollateralFetcher {
        fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DcapTdxCollateralFetcher for StaticDcapCollateralFetcher {
        async fn fetch_bundle_at(
            &self,
            quote_bytes: &[u8],
            fetched_at_epoch_ms: u64,
        ) -> std::result::Result<DcapTdxCollateralBundle, ProviderError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let collateral = serde_json::from_slice(SAMPLE_DCAP_COLLATERAL).unwrap();
            DcapTdxCollateralBundle::from_collateral_at(
                collateral,
                fetched_at_epoch_ms,
                DcapTdxCollateralSource::offline_bundle(),
                Some(quote_bytes),
            )
            .map_err(|error| ProviderError::Compatibility(error.to_string()))
        }
    }

    fn live_tinfoil_quote(report_data: String) -> VerifiedTinfoilQuote {
        let mut quote = VerifiedTinfoilQuote::from_verified_quote(
            TinfoilAttestationFormat::TdxGuestV2,
            EvidenceHardware {
                cpu: CpuTeeKind::Tdx,
                gpu: None,
            },
            "sha256:tinfoil-tee-measurement",
            report_data,
            "2026-07-05T00:00:00Z",
            "2099-01-01T00:00:00Z",
            4_070_908_800_000,
        );
        quote.attested_model = Some("llama-3.3-70b".into());
        quote.workload_image_digest = Some("sha256:tinfoil-workload-image".into());
        quote.model_artifacts = vec![confidential_inference_attestation::ArtifactDigest {
            kind: "weights".into(),
            name: "llama-3.3-70b".into(),
            digest: "sha256:tinfoil-weights".into(),
        }];
        quote
    }

    fn live_tinfoil_capture_json(
        route: &RouteDefinition,
        request: &EvidenceRequest,
        quote_bytes: &[u8],
    ) -> Vec<u8> {
        let attestation_doc = TinfoilAttestationDoc {
            format: TINFOIL_TDX_GUEST_V2_FORMAT.into(),
            body: gzip_base64(quote_bytes),
        };
        let capture = TinfoilLiveCaptureEvidence {
            schema: TinfoilLiveCaptureEvidence::SCHEMA.into(),
            provider: route.provider.clone(),
            route_id: route.route_id.clone(),
            evidence_family: route.evidence_family.clone(),
            requested_model: request.requested_model.clone(),
            policy_digest: request.policy_digest.clone(),
            nonce: request.nonce.clone(),
            evidence_endpoint: route.evidence_endpoint.clone(),
            live_tls_spki_sha256: tinfoil_fixture_spki_sha256(),
            live_tls_leaf_certificate_der_base64: tinfoil_fixture_evidence()
                .leaf_certificate_der_base64,
            raw_attestation_body_base64: base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&attestation_doc).unwrap()),
        };
        serde_json::to_vec(&capture).unwrap()
    }

    fn tinfoil_fixture_evidence() -> TinfoilTlsEvidence {
        serde_json::from_str(include_str!(
            "../../../fixtures/evidence/tinfoil-valid.json"
        ))
        .unwrap()
    }

    fn tinfoil_fixture_spki_sha256() -> String {
        tinfoil_fixture_evidence().report_data[..64].to_owned()
    }

    fn sample_dcap_now_epoch_millis() -> u64 {
        confidential_inference_attestation::parse_utc_timestamp_millis("2025-06-20T00:00:00Z")
            .unwrap()
    }

    fn verified_sample_dcap_quote() -> VerifiedTinfoilQuote {
        let verifier = DcapTdxTinfoilQuoteVerifier::from_collateral_json_at(
            SAMPLE_DCAP_COLLATERAL,
            sample_dcap_now_epoch_millis(),
        )
        .unwrap();
        let capture = TinfoilLiveCaptureEvidence {
            schema: TinfoilLiveCaptureEvidence::SCHEMA.into(),
            provider: "tinfoil-fixture".into(),
            route_id: "tinfoil-fixture:llama-3.3-70b:llama-3.3-70b".into(),
            evidence_family: "tinfoil_hw_verified_tls".into(),
            requested_model: "llama-3.3-70b".into(),
            policy_digest: "sha256:test".into(),
            nonce: None,
            evidence_endpoint: "https://inference.tinfoil.sh/.well-known/tinfoil-attestation"
                .into(),
            live_tls_spki_sha256: tinfoil_fixture_spki_sha256(),
            live_tls_leaf_certificate_der_base64: tinfoil_fixture_evidence()
                .leaf_certificate_der_base64,
            raw_attestation_body_base64: String::new(),
        };
        let spki_sha256 = tinfoil_fixture_spki_sha256();
        let request = TinfoilQuoteVerificationRequest {
            capture: &capture,
            attestation_format: TinfoilAttestationFormat::TdxGuestV2,
            quote_bytes: SAMPLE_DCAP_QUOTE,
            live_tls_leaf_certificate_der: &[],
            live_tls_spki_sha256: &spki_sha256,
        };
        verifier.verify_tinfoil_quote(&request).unwrap()
    }

    fn phase2_tinfoil_reference_values_with_measurement(
        tee_measurement: &str,
    ) -> ReferenceValuesEnvelope {
        let mut reference_values = ReferenceValuesEnvelope::phase2_fixtures().unwrap();
        let provider = reference_values
            .payload
            .providers
            .get_mut("tinfoil-fixture")
            .unwrap();
        provider.accepted_measurements = vec![tee_measurement.to_owned()];
        reference_values.signature = custom_artifact_signature(&reference_values.payload);
        reference_values
    }

    fn custom_signed_registry() -> ProviderRegistryEnvelope {
        let mut registry = ProviderRegistryEnvelope::bundled_demo().unwrap();
        registry.signature = custom_artifact_signature(&registry.payload);
        registry
    }

    fn custom_signed_streaming_demo_registry() -> ProviderRegistryEnvelope {
        let mut registry = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let route = &mut registry
            .payload
            .models
            .get_mut("gpt-oss-120b")
            .unwrap()
            .routes[0];
        route.streaming = StreamingSupport::Supported;
        registry.signature = custom_artifact_signature(&registry.payload);
        registry
    }

    fn streaming_demo_compatibility_matrix() -> ProviderCompatibilityMatrix {
        let mut compatibility_matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let compatibility = compatibility_matrix.providers.get_mut("demo").unwrap();
        compatibility.streaming = StreamingSupport::Supported;
        compatibility
            .known_unsupported_modes
            .retain(|mode| mode != "streaming");
        compatibility_matrix
    }

    fn custom_signed_reference_values() -> ReferenceValuesEnvelope {
        let mut reference_values = ReferenceValuesEnvelope::bundled_demo().unwrap();
        reference_values.signature = custom_artifact_signature(&reference_values.payload);
        reference_values
    }

    fn custom_signed_reference_values_with_revocation_epoch(
        revocation_epoch: u64,
    ) -> ReferenceValuesEnvelope {
        let mut reference_values = ReferenceValuesEnvelope::bundled_demo().unwrap();
        reference_values.payload.revocation_epoch = revocation_epoch;
        reference_values.signature = custom_artifact_signature(&reference_values.payload);
        reference_values
    }

    fn custom_artifact_signature<T: serde::Serialize>(payload: &T) -> ArtifactSignature {
        let key_pair = custom_key_pair();
        let payload_json = canonical_json(payload).unwrap();
        let signature = key_pair.sk.sign(payload_json.as_bytes(), None);
        ArtifactSignature {
            signer: "test".into(),
            key_id: "client-test-ed25519".into(),
            alg: "ed25519".into(),
            value: format!(
                "base64url:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref())
            ),
        }
    }

    fn custom_trusted_signing_key() -> TrustedSigningKey {
        let key_pair = custom_key_pair();
        let public_key_base64url =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_pair.pk.as_ref());
        TrustedSigningKey {
            signer: "test".into(),
            key_id: "client-test-ed25519".into(),
            public_key_base64url,
        }
    }

    fn custom_key_pair() -> KeyPair {
        KeyPair::from_seed(Seed::new([29_u8; 32]))
    }

    fn gzip_base64(bytes: &[u8]) -> String {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        base64::engine::general_purpose::STANDARD.encode(encoder.finish().unwrap())
    }

    fn assert_send_sync_clone<T: Send + Sync + Clone>() {}

    #[test]
    fn confidential_inference_sdk_is_send_sync_and_cheaply_cloneable() {
        assert_send_sync_clone::<ConfidentialInference>();
    }

    #[derive(Clone)]
    struct UnavailableProvider {
        provider_id: String,
        routes: Vec<RouteDefinition>,
        evidence_fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ProviderAdapter for UnavailableProvider {
        fn provider_id(&self) -> &str {
            &self.provider_id
        }

        fn routes(&self) -> Vec<RouteDefinition> {
            self.routes.clone()
        }

        async fn fetch_evidence(
            &self,
            _route: &RouteDefinition,
            _request: &EvidenceRequest,
        ) -> std::result::Result<Vec<u8>, ProviderError> {
            self.evidence_fetches.fetch_add(1, Ordering::SeqCst);
            Err(ProviderError::Unavailable(self.provider_id.clone()))
        }

        async fn chat(
            &self,
            _route: &RouteDefinition,
            _request: ProviderChatRequest,
        ) -> std::result::Result<ChatCompletionResponse, ProviderError> {
            Err(ProviderError::Unavailable(self.provider_id.clone()))
        }
    }

    #[derive(Clone, Copy)]
    enum ScriptedChatFailure {
        Unavailable,
        HttpStatus(u16),
        Adapter,
    }

    #[derive(Clone)]
    struct ScriptedFixtureProvider {
        provider_id: String,
        routes: Vec<RouteDefinition>,
        evidence_fetches: Arc<AtomicUsize>,
        chat_attempts: Arc<AtomicUsize>,
        chat_failure: Option<ScriptedChatFailure>,
    }

    #[async_trait]
    impl ProviderAdapter for ScriptedFixtureProvider {
        fn provider_id(&self) -> &str {
            &self.provider_id
        }

        fn routes(&self) -> Vec<RouteDefinition> {
            self.routes.clone()
        }

        async fn fetch_evidence(
            &self,
            route: &RouteDefinition,
            _request: &EvidenceRequest,
        ) -> std::result::Result<Vec<u8>, ProviderError> {
            self.evidence_fetches.fetch_add(1, Ordering::SeqCst);
            let mut evidence: serde_json::Value = serde_json::from_slice(include_bytes!(
                "../../../fixtures/evidence/demo-valid.json"
            ))?;
            evidence["provider"] = serde_json::Value::String(route.provider.clone());
            evidence["route_id"] = serde_json::Value::String(route.route_id.clone());
            serde_json::to_vec(&evidence).map_err(Into::into)
        }

        async fn chat(
            &self,
            route: &RouteDefinition,
            request: ProviderChatRequest,
        ) -> std::result::Result<ChatCompletionResponse, ProviderError> {
            self.chat_attempts.fetch_add(1, Ordering::SeqCst);
            match self.chat_failure {
                Some(ScriptedChatFailure::Unavailable) => {
                    Err(ProviderError::Unavailable(self.provider_id.clone()))
                }
                Some(ScriptedChatFailure::HttpStatus(status)) => Err(ProviderError::HttpStatus {
                    status,
                    message: "scripted upstream response".into(),
                }),
                Some(ScriptedChatFailure::Adapter) => Err(ProviderError::Adapter(
                    "scripted encrypted response failure".into(),
                )),
                None => DemoProvider::valid().chat(route, request).await,
            }
        }
    }

    fn client_from_parts(
        registry: ProviderRegistry,
        compatibility_matrix: ProviderCompatibilityMatrix,
        adapters: BTreeMap<String, Arc<dyn ProviderAdapter>>,
        policy: VerificationPolicy,
    ) -> ConfidentialInference {
        let mut reference_values = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let demo_provider_reference = reference_values
            .payload
            .providers
            .get("demo")
            .unwrap()
            .clone();
        let demo_route_reference = demo_provider_reference
            .routes
            .values()
            .next()
            .unwrap()
            .clone();
        for (canonical_model, route) in registry.models.values().flat_map(|model| {
            model
                .routes
                .iter()
                .map(move |route| (&model.canonical_model, route))
        }) {
            if reference_values
                .payload
                .providers
                .contains_key(&route.provider)
            {
                continue;
            }
            let mut route_reference = demo_route_reference.clone();
            route_reference.canonical_model = canonical_model.clone();
            route_reference.provider_model = route.provider_model.clone();
            route_reference.evidence_family = route.evidence_family.clone();
            route_reference.channel_binding_kind = route.channel_binding_kind.clone();
            route_reference.trust_tier = route.trust_tier.clone();
            let mut provider_reference = demo_provider_reference.clone();
            provider_reference.routes = BTreeMap::from([(route.route_id.clone(), route_reference)]);
            reference_values
                .payload
                .providers
                .insert(route.provider.clone(), provider_reference);
        }
        let registry_digest = registry.digest().unwrap();
        let reference_values_digest = reference_values.payload.digest().unwrap();
        let policy =
            policy.with_artifact_digests(registry_digest.clone(), reference_values_digest.clone());
        let reference_artifact_signature = reference_values.signature.clone();

        ConfidentialInference {
            inner: Arc::new(ClientInner {
                policy,
                registry,
                registry_digest,
                registry_source: "test".into(),
                registry_signature: SignatureMetadata {
                    signer: "confidential-inference".into(),
                    key_id: "test".into(),
                    alg: "ed25519".into(),
                },
                registry_artifact_signature: ArtifactSignature {
                    signer: "confidential-inference".into(),
                    key_id: "test".into(),
                    alg: "ed25519".into(),
                    value: "base64url:test-signature".into(),
                },
                reference_values: reference_values.payload,
                reference_values_digest,
                reference_values_source: "test".into(),
                reference_signature: SignatureMetadata {
                    signer: reference_artifact_signature.signer.clone(),
                    key_id: reference_artifact_signature.key_id.clone(),
                    alg: reference_artifact_signature.alg.clone(),
                },
                reference_artifact_signature,
                compatibility_matrix,
                provider_routing: ProviderRoutingConfig::default(),
                adapters,
                tinfoil_quote_verifier: Arc::new(FailClosedTinfoilQuoteVerifier),
                gpu_attestation_verifier: Arc::new(FailClosedGpuAttestationVerifier),
                gpu_attestation_verifier_is_custom: false,
                tinfoil_dcap_tdx_collateral_resolver: None,
                time_source: Arc::new(now_epoch_millis),
                audit_sink: Arc::new(NoopAuditSink),
                verdict_store: Arc::new(NoopVerdictStore),
                metrics_recorder: Arc::new(NoopConfidentialInferenceMetricsRecorder),
                api_keys: BTreeMap::new(),
                verdict_cache: Mutex::new(BTreeMap::new()),
                in_flight_verifications: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    fn add_extra_demo_route(
        registry: &mut ProviderRegistry,
        provider: &str,
        trust_tier: TrustTier,
        channel_binding_kind: ChannelBindingKind,
    ) -> RouteDefinition {
        let model = registry.models.get_mut("gpt-oss-120b").unwrap();
        let mut route = model.routes[0].clone();
        route.provider = provider.into();
        route.route_id = format!("{provider}:gpt-oss-120b:e2ee-gpt-oss-120b-p");
        route.api_base_url = format!("http://127.0.0.1/{provider}/v1");
        route.evidence_endpoint = format!("http://127.0.0.1/{provider}/v1/confidentiality");
        route.adapter_version = format!("{provider}-fixture-adapter/0.1.0");
        route.trust_tier = trust_tier;
        route.channel_binding_kind = channel_binding_kind;
        if route.trust_tier == TrustTier::TeeOnly {
            route.request_confidentiality_requirement = BoundDataRequirement::NotRequired;
            route.response_confidentiality_requirement = BoundDataRequirement::NotRequired;
            route.response_integrity_requirement = ResponseIntegrityRequirement::NotRequired;
            route.request_encryption = EncryptionRequirement::NotRequired;
            route.response_decryption = EncryptionRequirement::NotRequired;
        }
        model.routes.insert(0, route.clone());
        route
    }

    fn add_compatibility_for_route(
        matrix: &mut ProviderCompatibilityMatrix,
        route: &RouteDefinition,
    ) {
        let mut compatibility = matrix.providers.get("demo").unwrap().clone();
        compatibility.provider = route.provider.clone();
        compatibility.api_base_url = route.api_base_url.clone();
        compatibility.expected_trust_tier = route.trust_tier.clone();
        compatibility.request_encryption = route.request_encryption.clone();
        compatibility.response_decryption = route.response_decryption.clone();
        compatibility.streaming = route.streaming.clone();
        compatibility.route_execution_status = RouteExecutionStatus::ExecutableFixture;
        matrix
            .providers
            .insert(compatibility.provider.clone(), compatibility);
    }

    fn scripted_failover_client(
        primary_failure: Option<ScriptedChatFailure>,
        fallback_failure: Option<ScriptedChatFailure>,
    ) -> (
        ConfidentialInference,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        let primary_route = add_extra_demo_route(
            &mut registry,
            "primary-demo",
            TrustTier::AppE2ee,
            ChannelBindingKind::AttestedAppE2ee,
        );
        let fallback_route = registry
            .find_route(Some("demo"), "gpt-oss-120b")
            .unwrap()
            .1
            .clone();
        let mut compatibility_matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        add_compatibility_for_route(&mut compatibility_matrix, &primary_route);

        let primary_evidence_fetches = Arc::new(AtomicUsize::new(0));
        let primary_chat_attempts = Arc::new(AtomicUsize::new(0));
        let fallback_evidence_fetches = Arc::new(AtomicUsize::new(0));
        let fallback_chat_attempts = Arc::new(AtomicUsize::new(0));
        let mut adapters = BTreeMap::<String, Arc<dyn ProviderAdapter>>::new();
        adapters.insert(
            "primary-demo".into(),
            Arc::new(ScriptedFixtureProvider {
                provider_id: "primary-demo".into(),
                routes: vec![primary_route],
                evidence_fetches: primary_evidence_fetches.clone(),
                chat_attempts: primary_chat_attempts.clone(),
                chat_failure: primary_failure,
            }),
        );
        adapters.insert(
            "demo".into(),
            Arc::new(ScriptedFixtureProvider {
                provider_id: "demo".into(),
                routes: vec![fallback_route],
                evidence_fetches: fallback_evidence_fetches.clone(),
                chat_attempts: fallback_chat_attempts.clone(),
                chat_failure: fallback_failure,
            }),
        );

        (
            client_from_parts(
                registry,
                compatibility_matrix,
                adapters,
                VerificationPolicy::require_attested_e2ee(),
            ),
            primary_evidence_fetches,
            primary_chat_attempts,
            fallback_evidence_fetches,
            fallback_chat_attempts,
        )
    }

    fn mutate_first_cached_verdict(
        client: &ConfidentialInference,
        mutate: impl FnOnce(&mut CachedVerdict),
    ) {
        let mut cache = client.inner.verdict_cache.lock().unwrap();
        let cached = cache.values_mut().next().expect("expected cached verdict");
        mutate(cached);
    }

    fn set_cached_verdict_expiry(cached: &mut CachedVerdict, expires_at_epoch_ms: u64) {
        let expires_at =
            confidential_inference_attestation::format_utc_timestamp_millis(expires_at_epoch_ms);
        cached.verdict.expires_at_epoch_ms = expires_at_epoch_ms;
        cached.verdict.expires_at = expires_at.clone();
        cached.verdict.validity.policy_ttl_until = expires_at.clone();
        cached.verdict.validity.collateral_valid_until = expires_at.clone();
        cached.verdict.validity.certificate_valid_until = expires_at.clone();
        cached.verdict.validity.quote_valid_until = expires_at.clone();
        cached.verdict.validity.tcb_valid_until = expires_at.clone();
        cached.verdict.validity.reference_values_valid_until = expires_at.clone();
        cached.verdict.validity.computed_expires_at = expires_at;
    }

    async fn serve_registry_response(body: String, status: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{addr}/registry.json")
    }

    async fn spawn_otlp_metrics_collector(
        status: u16,
    ) -> (String, tokio::task::JoinHandle<std::io::Result<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_test_http_request(&mut stream).await?;
            let reason = if status == 200 { "OK" } else { "ERROR" };
            let body = "{}";
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            Ok(request)
        });
        (format!("http://{addr}/v1/metrics"), handle)
    }

    async fn spawn_dstack_app_e2ee_http_server(
        secret_key: SdkAppE2eeSecretKey,
        raw_chat_requests: Arc<Mutex<Vec<String>>>,
    ) -> (
        RouteDefinition,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let route = dstack_http_route(&base_url);
        let server_route = route.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await?;
                let request = read_test_http_request(&mut stream).await?;
                let request_text = String::from_utf8_lossy(&request).into_owned();
                if !request_text.contains("authorization: Bearer sk-venice-http-test") {
                    return Err(std::io::Error::other(
                        "generic HTTP adapter did not send bearer token",
                    ));
                }
                let (method, path) = test_http_request_line(&request)?;
                let body = match (method, path) {
                    ("GET", "/v1/confidentiality") => dstack_http_provider_evidence(
                        &secret_key
                            .public_config()
                            .map_err(std::io::Error::other)?
                            .public_key_digest()
                            .map_err(std::io::Error::other)?,
                    )
                    .to_string(),
                    ("POST", "/v1/chat/completions") => {
                        raw_chat_requests.lock().unwrap().push(request_text.clone());
                        if request_text.contains("auto registered encrypted provider") {
                            return Err(std::io::Error::other(
                                "SDK app-E2EE HTTP envelope leaked plaintext prompt",
                            ));
                        }
                        let request_value: serde_json::Value =
                            serde_json::from_slice(test_http_body(&request))
                                .map_err(std::io::Error::other)?;
                        let provider_request = ProviderChatRequest::with_confidentiality(
                            request_value,
                            ProviderRequestConfidentiality::SdkEncrypted,
                        );
                        let (chat_request, session) = provider_request
                            .to_sdk_decrypted_openai_request(&server_route, &secret_key)
                            .map_err(std::io::Error::other)?;
                        if chat_request.model != server_route.provider_model {
                            return Err(std::io::Error::other(
                                "provider model rewrite was not applied",
                            ));
                        }
                        let prompt = chat_request.last_user_message().unwrap_or("");
                        let content = format!(
                            "venice HTTP app-E2EE response for {}: {}",
                            server_route.provider_model, prompt
                        );
                        let response_plaintext = serde_json::to_vec(&serde_json::json!({
                            "id": "chatcmpl-venice-http-app-e2ee-test",
                            "object": "chat.completion",
                            "created": 1_783_209_600u64,
                            "model": server_route.provider_model.clone(),
                            "choices": [{
                                "index": 0,
                                "message": {"role": "assistant", "content": content},
                                "finish_reason": "stop"
                            }],
                            "usage": {
                                "prompt_tokens": prompt.split_whitespace().count(),
                                "completion_tokens": content.split_whitespace().count(),
                                "total_tokens": prompt.split_whitespace().count()
                                    + content.split_whitespace().count()
                            }
                        }))
                        .map_err(std::io::Error::other)?;
                        let response_envelope = session
                            .encrypt_response_body(&server_route, &response_plaintext)
                            .map_err(std::io::Error::other)?;
                        serde_json::to_string(&response_envelope).map_err(std::io::Error::other)?
                    }
                    _ => serde_json::json!({"error": "not found"}).to_string(),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await?;
            }
            Ok(())
        });
        (route, handle)
    }

    async fn read_test_http_request(
        stream: &mut tokio::net::TcpStream,
    ) -> std::io::Result<Vec<u8>> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if test_http_request_complete(&request) {
                break;
            }
        }
        Ok(request)
    }

    fn test_http_request_line(request: &[u8]) -> std::io::Result<(&str, &str)> {
        let headers = std::str::from_utf8(
            &request[..test_http_header_end(request)
                .ok_or_else(|| std::io::Error::other("HTTP request headers are incomplete"))?],
        )
        .map_err(std::io::Error::other)?;
        let line = headers
            .lines()
            .next()
            .ok_or_else(|| std::io::Error::other("HTTP request line is missing"))?;
        let mut fields = line.split_whitespace();
        let method = fields
            .next()
            .ok_or_else(|| std::io::Error::other("HTTP method is missing"))?;
        let path = fields
            .next()
            .ok_or_else(|| std::io::Error::other("HTTP path is missing"))?;
        Ok((method, path))
    }

    fn test_http_request_complete(request: &[u8]) -> bool {
        let Some(header_end) = test_http_header_end(request) else {
            return false;
        };
        let content_length = std::str::from_utf8(&request[..header_end])
            .ok()
            .and_then(|headers| {
                headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(0);
        request.len() >= header_end + content_length
    }

    fn test_http_body(request: &[u8]) -> &[u8] {
        &request[test_http_header_end(request).unwrap_or(request.len())..]
    }

    fn test_http_header_end(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }

    fn dstack_http_route(base_url: &str) -> RouteDefinition {
        RouteDefinition {
            route_id: "venice-http-test:gpt-oss-120b:e2ee-gpt-oss-120b-p".into(),
            route_status: RouteLifecycle::Active,
            provider: "venice-http-test".into(),
            provider_model: "e2ee-gpt-oss-120b-p".into(),
            evidence_family: "dstack_app_e2ee".into(),
            api_base_url: format!("{}/v1", base_url.trim_end_matches('/')),
            evidence_endpoint: format!("{}/v1/confidentiality", base_url.trim_end_matches('/')),
            adapter_version: "venice-http-dstack-adapter/0.1.0".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            accepted_gpu_tees: Vec::new(),
            request_encryption: EncryptionRequirement::Required,
            response_decryption: EncryptionRequirement::Required,
            streaming: StreamingSupport::Unsupported,
            alias_confidence: AliasConfidence::Curated,
        }
    }

    fn signed_dstack_http_registry(route: RouteDefinition) -> ProviderRegistryEnvelope {
        let mut models = BTreeMap::new();
        models.insert(
            "gpt-oss-120b".into(),
            RegistryModel {
                canonical_model: "gpt-oss-120b".into(),
                display_name: "GPT-OSS 120B".into(),
                family: "OpenAI GPT".into(),
                aliases: vec!["gpt-oss-120b".into(), "GPT-OSS 120B".into()],
                routes: vec![route],
            },
        );
        let payload = ProviderRegistry {
            schema: ProviderRegistry::SCHEMA.into(),
            version: "2026-07-05-venice-http-test".into(),
            generated_at: "2026-07-05T00:00:00Z".into(),
            source_sync_run: SourceSyncRun {
                completed_at: "2026-07-05T00:00:00Z".into(),
                status: "success".into(),
                source: "client-test-venice-http".into(),
            },
            models,
        };
        ProviderRegistryEnvelope {
            schema: ProviderRegistryEnvelope::SCHEMA.into(),
            signature: custom_artifact_signature(&payload),
            payload,
        }
    }

    fn signed_dstack_http_reference_values(
        route: &RouteDefinition,
        public_key_digest: String,
    ) -> ReferenceValuesEnvelope {
        let mut routes = BTreeMap::new();
        routes.insert(
            route.route_id.clone(),
            RouteReference {
                canonical_model: "gpt-oss-120b".into(),
                provider_model: route.provider_model.clone(),
                evidence_family: route.evidence_family.clone(),
                channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
                trust_tier: TrustTier::AppE2ee,
                accepted_cpu_tees: vec![CpuTeeKind::Tdx],
                e2ee_public_key_digest: public_key_digest,
                response_signing_key_digest: None,
                tls_spki_sha256: None,
                workload_images: vec![confidential_inference_attestation::WorkloadImage {
                    service: "root".into(),
                    reference: concat!(
                        "venice-http/worker@sha256:",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    )
                    .into(),
                    digest: concat!(
                        "sha256:",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    )
                    .into(),
                }],
                workload_image_digest: "sha256:venice-http-workload-image".into(),
                model_artifacts: vec![confidential_inference_attestation::ArtifactDigest {
                    kind: "weights".into(),
                    name: "gpt-oss-120b".into(),
                    digest: "sha256:venice-http-weights".into(),
                }],
                valid_until: "2099-01-01T00:00:00Z".into(),
                valid_until_epoch_ms: 4_070_908_800_000,
            },
        );
        let mut providers = BTreeMap::new();
        providers.insert(
            "venice-http-test".into(),
            ProviderReference {
                accepted_measurements: vec!["sha256:venice-http-tee-measurement".into()],
                routes,
            },
        );
        let payload = ReferenceValuesPayload {
            schema: ReferenceValuesPayload::SCHEMA.into(),
            version: "2026-07-05-venice-http-test".into(),
            issuer: "test".into(),
            valid_from: "2026-07-05T00:00:00Z".into(),
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
            revocation_epoch: 1,
            minimum_acceptable_version: "2026-07-05-venice-http-test".into(),
            providers,
        };
        ReferenceValuesEnvelope {
            schema: ReferenceValuesEnvelope::SCHEMA.into(),
            signature: custom_artifact_signature(&payload),
            payload,
        }
    }

    fn dstack_http_compatibility(
        route: &RouteDefinition,
        secret_key: &SdkAppE2eeSecretKey,
    ) -> ProviderCompatibilityMatrix {
        let mut providers = BTreeMap::new();
        providers.insert(
            "venice-http-test".into(),
            ProviderCompatibility {
                provider: "venice-http-test".into(),
                route_execution_status: RouteExecutionStatus::Executable,
                api_base_url: route.api_base_url.clone(),
                supported_openai_endpoints: vec![OpenAiEndpoint::ChatCompletions],
                model_listing: ModelListingBehavior::SignedRegistryOnly,
                model_id_rewrite: ModelIdRewrite::UseRouteProviderModel,
                token_parameter_rewrite: TokenParameterRewrite::PreserveMaxTokens,
                streaming: StreamingSupport::Unsupported,
                request_encryption: EncryptionRequirement::Required,
                response_decryption: EncryptionRequirement::Required,
                sdk_app_e2ee: Some(secret_key.public_config().unwrap()),
                adapter_managed_encryption: false,
                attestation_endpoint_shape: "dstack_app_e2ee_http_test".into(),
                required_credentials: Vec::new(),
                freshness_class: FreshnessClass::PerSession,
                cacheability_class: CacheabilityClass::PerSessionVerdict,
                expected_trust_tier: TrustTier::AppE2ee,
                model_binding_support: ModelBindingSupport::Verified,
                known_unsupported_modes: vec!["streaming".into()],
            },
        );
        ProviderCompatibilityMatrix {
            schema: ProviderCompatibilityMatrix::SCHEMA.into(),
            providers,
        }
    }

    fn dstack_http_provider_evidence(public_key_digest: &str) -> serde_json::Value {
        let app_compose = serde_json::json!({
            "image": concat!(
                "venice-http/worker@sha256:",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            "model": "gpt-oss-120b",
            "provider": "venice-http-test"
        })
        .to_string();
        let compose_hash = sha256_digest(app_compose.as_bytes())
            .trim_start_matches("sha256:")
            .to_owned();
        serde_json::json!({
            "model": "e2ee-gpt-oss-120b-p",
            "upstream_model": "gpt-oss-120b",
            "tee_hardware": "tdx",
            "tee_measurement": "sha256:venice-http-tee-measurement",
            "quote_measurements": {
                "mr_td": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "rtmr0": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "info": {
                "tcb_info": {
                    "mrtd": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "rtmr0": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "app_compose": app_compose,
                    "compose_hash": compose_hash
                }
            },
            "channel_binding": {
                "public_key_digest": public_key_digest,
                "request_bound": true,
                "response_bound": true
            },
            "workload_image_digest": "sha256:venice-http-workload-image",
            "model_artifacts": [{
                "kind": "weights",
                "name": "gpt-oss-120b",
                "digest": "sha256:venice-http-weights"
            }],
            "issued_at": "2098-12-31T23:50:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "expires_at_epoch_ms": 4_070_908_800_000u64
        })
    }

    async fn spawn_phala_dstack_app_e2ee_http_server(
        secret_key: SdkAppE2eeSecretKey,
        raw_chat_requests: Arc<Mutex<Vec<String>>>,
    ) -> (
        RouteDefinition,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let route = phala_http_route(&base_url);
        let server_route = route.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await?;
                let request = read_test_http_request(&mut stream).await?;
                let request_text = String::from_utf8_lossy(&request).into_owned();
                if !request_text.contains("authorization: Bearer sk-phala-http-test") {
                    return Err(std::io::Error::other(
                        "Phala HTTP adapter did not send bearer token",
                    ));
                }
                let (method, path) = test_http_request_line(&request)?;
                let body = match (method, path) {
                    ("GET", "/v1/confidentiality") => phala_http_provider_evidence(
                        &secret_key
                            .public_config()
                            .map_err(std::io::Error::other)?
                            .public_key_digest()
                            .map_err(std::io::Error::other)?,
                    )
                    .to_string(),
                    ("POST", "/v1/chat/completions") => {
                        raw_chat_requests.lock().unwrap().push(request_text.clone());
                        if request_text.contains("direct Phala encrypted provider") {
                            return Err(std::io::Error::other(
                                "Phala SDK app-E2EE HTTP envelope leaked plaintext prompt",
                            ));
                        }
                        let request_value: serde_json::Value =
                            serde_json::from_slice(test_http_body(&request))
                                .map_err(std::io::Error::other)?;
                        let provider_request = ProviderChatRequest::with_confidentiality(
                            request_value,
                            ProviderRequestConfidentiality::SdkEncrypted,
                        );
                        let (chat_request, session) = provider_request
                            .to_sdk_decrypted_openai_request(&server_route, &secret_key)
                            .map_err(std::io::Error::other)?;
                        if chat_request.model != server_route.provider_model {
                            return Err(std::io::Error::other(
                                "Phala provider model rewrite was not applied",
                            ));
                        }
                        let prompt = chat_request.last_user_message().unwrap_or("");
                        let content = format!(
                            "Phala direct app-E2EE response for {}: {}",
                            server_route.provider_model, prompt
                        );
                        let response_plaintext = serde_json::to_vec(&serde_json::json!({
                            "id": "chatcmpl-phala-http-app-e2ee-test",
                            "object": "chat.completion",
                            "created": 1_783_209_600u64,
                            "model": server_route.provider_model.clone(),
                            "choices": [{
                                "index": 0,
                                "message": {"role": "assistant", "content": content},
                                "finish_reason": "stop"
                            }],
                            "usage": {
                                "prompt_tokens": prompt.split_whitespace().count(),
                                "completion_tokens": content.split_whitespace().count(),
                                "total_tokens": prompt.split_whitespace().count()
                                    + content.split_whitespace().count()
                            }
                        }))
                        .map_err(std::io::Error::other)?;
                        let response_envelope = session
                            .encrypt_response_body(&server_route, &response_plaintext)
                            .map_err(std::io::Error::other)?;
                        serde_json::to_string(&response_envelope).map_err(std::io::Error::other)?
                    }
                    _ => serde_json::json!({"error": "not found"}).to_string(),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await?;
            }
            Ok(())
        });
        (route, handle)
    }

    fn phala_http_route(base_url: &str) -> RouteDefinition {
        RouteDefinition {
            route_id: "phala-http-test:gpt-oss-120b:phala/gpt-oss-120b-confidential".into(),
            route_status: RouteLifecycle::Active,
            provider: "phala-http-test".into(),
            provider_model: "phala/gpt-oss-120b-confidential".into(),
            evidence_family: "dstack_app_e2ee".into(),
            api_base_url: format!("{}/v1", base_url.trim_end_matches('/')),
            evidence_endpoint: format!("{}/v1/confidentiality", base_url.trim_end_matches('/')),
            adapter_version: "phala-http-dstack-adapter/0.1.0".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            accepted_gpu_tees: Vec::new(),
            request_encryption: EncryptionRequirement::Required,
            response_decryption: EncryptionRequirement::Required,
            streaming: StreamingSupport::Unsupported,
            alias_confidence: AliasConfidence::Curated,
        }
    }

    fn signed_phala_http_registry(route: RouteDefinition) -> ProviderRegistryEnvelope {
        let mut models = BTreeMap::new();
        models.insert(
            "gpt-oss-120b".into(),
            RegistryModel {
                canonical_model: "gpt-oss-120b".into(),
                display_name: "GPT-OSS 120B".into(),
                family: "OpenAI GPT".into(),
                aliases: vec!["gpt-oss-120b".into(), "GPT-OSS 120B".into()],
                routes: vec![route],
            },
        );
        let payload = ProviderRegistry {
            schema: ProviderRegistry::SCHEMA.into(),
            version: "2026-07-05-phala-http-test".into(),
            generated_at: "2026-07-05T00:00:00Z".into(),
            source_sync_run: SourceSyncRun {
                completed_at: "2026-07-05T00:00:00Z".into(),
                status: "success".into(),
                source: "client-test-phala-http".into(),
            },
            models,
        };
        ProviderRegistryEnvelope {
            schema: ProviderRegistryEnvelope::SCHEMA.into(),
            signature: custom_artifact_signature(&payload),
            payload,
        }
    }

    fn signed_phala_http_reference_values(
        route: &RouteDefinition,
        public_key_digest: String,
    ) -> ReferenceValuesEnvelope {
        let mut routes = BTreeMap::new();
        routes.insert(
            route.route_id.clone(),
            RouteReference {
                canonical_model: "gpt-oss-120b".into(),
                provider_model: route.provider_model.clone(),
                evidence_family: route.evidence_family.clone(),
                channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
                trust_tier: TrustTier::AppE2ee,
                accepted_cpu_tees: vec![CpuTeeKind::Tdx],
                e2ee_public_key_digest: public_key_digest,
                response_signing_key_digest: None,
                tls_spki_sha256: None,
                workload_images: vec![confidential_inference_attestation::WorkloadImage {
                    service: "root".into(),
                    reference: concat!(
                        "phala-direct/worker@sha256:",
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    )
                    .into(),
                    digest: concat!(
                        "sha256:",
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    )
                    .into(),
                }],
                workload_image_digest: "sha256:phala-http-workload-image".into(),
                model_artifacts: vec![
                    confidential_inference_attestation::ArtifactDigest {
                        kind: "weights".into(),
                        name: "gpt-oss-120b".into(),
                        digest: "sha256:phala-http-weights".into(),
                    },
                    confidential_inference_attestation::ArtifactDigest {
                        kind: "tokenizer".into(),
                        name: "tokenizer.json".into(),
                        digest: "sha256:phala-http-tokenizer".into(),
                    },
                ],
                valid_until: "2099-01-01T00:00:00Z".into(),
                valid_until_epoch_ms: 4_070_908_800_000,
            },
        );
        let mut providers = BTreeMap::new();
        providers.insert(
            "phala-http-test".into(),
            ProviderReference {
                accepted_measurements: vec!["sha256:phala-http-tee-measurement".into()],
                routes,
            },
        );
        let payload = ReferenceValuesPayload {
            schema: ReferenceValuesPayload::SCHEMA.into(),
            version: "2026-07-05-phala-http-test".into(),
            issuer: "test".into(),
            valid_from: "2026-07-05T00:00:00Z".into(),
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
            revocation_epoch: 1,
            minimum_acceptable_version: "2026-07-05-phala-http-test".into(),
            providers,
        };
        ReferenceValuesEnvelope {
            schema: ReferenceValuesEnvelope::SCHEMA.into(),
            signature: custom_artifact_signature(&payload),
            payload,
        }
    }

    fn phala_http_compatibility(
        route: &RouteDefinition,
        secret_key: &SdkAppE2eeSecretKey,
    ) -> ProviderCompatibilityMatrix {
        let mut providers = BTreeMap::new();
        providers.insert(
            "phala-http-test".into(),
            ProviderCompatibility {
                provider: "phala-http-test".into(),
                route_execution_status: RouteExecutionStatus::Executable,
                api_base_url: route.api_base_url.clone(),
                supported_openai_endpoints: vec![OpenAiEndpoint::ChatCompletions],
                model_listing: ModelListingBehavior::SignedRegistryOnly,
                model_id_rewrite: ModelIdRewrite::UseRouteProviderModel,
                token_parameter_rewrite: TokenParameterRewrite::PreserveMaxTokens,
                streaming: StreamingSupport::Unsupported,
                request_encryption: EncryptionRequirement::Required,
                response_decryption: EncryptionRequirement::Required,
                sdk_app_e2ee: Some(secret_key.public_config().unwrap()),
                adapter_managed_encryption: false,
                attestation_endpoint_shape: "phala_dstack_app_e2ee_http_test".into(),
                required_credentials: vec![CredentialKind::BearerToken],
                freshness_class: FreshnessClass::PerSession,
                cacheability_class: CacheabilityClass::PerSessionVerdict,
                expected_trust_tier: TrustTier::AppE2ee,
                model_binding_support: ModelBindingSupport::Verified,
                known_unsupported_modes: vec!["streaming".into()],
            },
        );
        ProviderCompatibilityMatrix {
            schema: ProviderCompatibilityMatrix::SCHEMA.into(),
            providers,
        }
    }

    fn phala_http_provider_evidence(public_key_digest: &str) -> serde_json::Value {
        let app_compose = serde_json::json!({
            "image": concat!(
                "phala-direct/worker@sha256:",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ),
            "model": "gpt-oss-120b",
            "provider": "phala-http-test"
        })
        .to_string();
        let compose_hash = sha256_digest(app_compose.as_bytes())
            .trim_start_matches("sha256:")
            .to_owned();
        serde_json::json!({
            "model": "phala/gpt-oss-120b-confidential",
            "upstream_model": "gpt-oss-120b",
            "tee_hardware": "tdx",
            "tee_measurement": "sha256:phala-http-tee-measurement",
            "quote_measurements": {
                "mr_td": "cccccccccccccccccccccccccccccccccccccccccccccccc",
                "rtmr0": "dddddddddddddddddddddddddddddddddddddddddddddddd"
            },
            "info": {
                "tcb_info": {
                    "mrtd": "cccccccccccccccccccccccccccccccccccccccccccccccc",
                    "rtmr0": "dddddddddddddddddddddddddddddddddddddddddddddddd",
                    "app_compose": app_compose,
                    "compose_hash": compose_hash
                }
            },
            "channel_binding": {
                "public_key_digest": public_key_digest,
                "request_bound": true,
                "response_bound": true
            },
            "workload_image_digest": "sha256:phala-http-workload-image",
            "model_artifacts": [
                {
                    "kind": "weights",
                    "name": "gpt-oss-120b",
                    "digest": "sha256:phala-http-weights"
                },
                {
                    "kind": "tokenizer",
                    "name": "tokenizer.json",
                    "digest": "sha256:phala-http-tokenizer"
                }
            ],
            "issued_at": "2098-12-31T23:50:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "expires_at_epoch_ms": 4_070_908_800_000u64
        })
    }

    async fn spawn_chutes_e2ee_http_server() -> (
        RouteDefinition,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let route = chutes_http_route(&base_url);
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_test_http_request(&mut stream).await?;
            let request_text = String::from_utf8_lossy(&request);
            if !request_text.contains("authorization: Bearer sk-redpill-http-test") {
                return Err(std::io::Error::other(
                    "confidential HTTP adapter did not send bearer token",
                ));
            }
            let (method, path) = test_http_request_line(&request)?;
            let body = match (method, path) {
                ("GET", "/v1/attestation/report") => chutes_http_provider_evidence().to_string(),
                ("GET", path) if path.starts_with("/v1/attestation/report?nonce=") => {
                    let nonce = path.trim_start_matches("/v1/attestation/report?nonce=");
                    chutes_http_provider_evidence_for_nonce(nonce).to_string()
                }
                _ => serde_json::json!({"error": "not found"}).to_string(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            Ok(())
        });
        (route, handle)
    }

    fn chutes_http_route(base_url: &str) -> RouteDefinition {
        RouteDefinition {
            route_id: "redpill-http-test:gpt-oss-120b:private/org/gpt-oss-120b:thinking-TEE".into(),
            route_status: RouteLifecycle::Active,
            provider: "redpill-http-test".into(),
            provider_model: "private/org/gpt-oss-120b:thinking-TEE".into(),
            evidence_family: "chutes_e2ee".into(),
            api_base_url: format!("{}/v1", base_url.trim_end_matches('/')),
            evidence_endpoint: format!("{}/v1/attestation/report", base_url.trim_end_matches('/')),
            adapter_version: "redpill-http-chutes-adapter/0.1.0".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            accepted_gpu_tees: vec![GpuTeeKind::NvidiaCc],
            request_encryption: EncryptionRequirement::Required,
            response_decryption: EncryptionRequirement::Required,
            streaming: StreamingSupport::Unsupported,
            alias_confidence: AliasConfidence::Curated,
        }
    }

    fn signed_chutes_http_registry(route: RouteDefinition) -> ProviderRegistryEnvelope {
        let mut models = BTreeMap::new();
        models.insert(
            "gpt-oss-120b".into(),
            RegistryModel {
                canonical_model: "gpt-oss-120b".into(),
                display_name: "GPT-OSS 120B".into(),
                family: "OpenAI GPT".into(),
                aliases: vec!["gpt-oss-120b".into(), "GPT-OSS 120B".into()],
                routes: vec![route],
            },
        );
        let payload = ProviderRegistry {
            schema: ProviderRegistry::SCHEMA.into(),
            version: "2026-07-05-redpill-http-test".into(),
            generated_at: "2026-07-05T00:00:00Z".into(),
            source_sync_run: SourceSyncRun {
                completed_at: "2026-07-05T00:00:00Z".into(),
                status: "success".into(),
                source: "client-test-redpill-http".into(),
            },
            models,
        };
        ProviderRegistryEnvelope {
            schema: ProviderRegistryEnvelope::SCHEMA.into(),
            signature: custom_artifact_signature(&payload),
            payload,
        }
    }

    fn signed_chutes_http_reference_values(route: &RouteDefinition) -> ReferenceValuesEnvelope {
        let mut routes = BTreeMap::new();
        routes.insert(
            route.route_id.clone(),
            RouteReference {
                canonical_model: "gpt-oss-120b".into(),
                provider_model: route.provider_model.clone(),
                evidence_family: route.evidence_family.clone(),
                channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
                trust_tier: TrustTier::AppE2ee,
                accepted_cpu_tees: vec![CpuTeeKind::Tdx],
                e2ee_public_key_digest: sha256_digest(CHUTES_HTTP_E2E_PUBLIC_KEY.as_bytes()),
                response_signing_key_digest: None,
                tls_spki_sha256: None,
                workload_images: Vec::new(),
                workload_image_digest: "sha256:chutes-http-workload-image".into(),
                model_artifacts: vec![confidential_inference_attestation::ArtifactDigest {
                    kind: "weights".into(),
                    name: "gpt-oss-120b".into(),
                    digest: "sha256:chutes-http-weights".into(),
                }],
                valid_until: "2099-01-01T00:00:00Z".into(),
                valid_until_epoch_ms: 4_070_908_800_000,
            },
        );
        let mut providers = BTreeMap::new();
        providers.insert(
            "redpill-http-test".into(),
            ProviderReference {
                accepted_measurements: vec!["sha256:chutes-http-tee-measurement".into()],
                routes,
            },
        );
        let payload = ReferenceValuesPayload {
            schema: ReferenceValuesPayload::SCHEMA.into(),
            version: "2026-07-05-redpill-http-test".into(),
            issuer: "test".into(),
            valid_from: "2026-07-05T00:00:00Z".into(),
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
            revocation_epoch: 1,
            minimum_acceptable_version: "2026-07-05-redpill-http-test".into(),
            providers,
        };
        ReferenceValuesEnvelope {
            schema: ReferenceValuesEnvelope::SCHEMA.into(),
            signature: custom_artifact_signature(&payload),
            payload,
        }
    }

    fn chutes_http_compatibility(route: &RouteDefinition) -> ProviderCompatibilityMatrix {
        let mut providers = BTreeMap::new();
        providers.insert(
            "redpill-http-test".into(),
            ProviderCompatibility {
                provider: "redpill-http-test".into(),
                route_execution_status: RouteExecutionStatus::AdapterShapeFixture,
                api_base_url: route.api_base_url.clone(),
                supported_openai_endpoints: vec![OpenAiEndpoint::ChatCompletions],
                model_listing: ModelListingBehavior::SignedRegistryOnly,
                model_id_rewrite: ModelIdRewrite::UseRouteProviderModel,
                token_parameter_rewrite: TokenParameterRewrite::MaxTokensToMaxCompletionTokens,
                streaming: StreamingSupport::Unsupported,
                request_encryption: EncryptionRequirement::Required,
                response_decryption: EncryptionRequirement::Required,
                sdk_app_e2ee: None,
                adapter_managed_encryption: false,
                attestation_endpoint_shape: "chutes_e2ee_http_test".into(),
                required_credentials: Vec::new(),
                freshness_class: FreshnessClass::PerSession,
                cacheability_class: CacheabilityClass::PerSessionVerdict,
                expected_trust_tier: TrustTier::AppE2ee,
                model_binding_support: ModelBindingSupport::Verified,
                known_unsupported_modes: vec!["streaming", "chat_execution"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
        );
        ProviderCompatibilityMatrix {
            schema: ProviderCompatibilityMatrix::SCHEMA.into(),
            providers,
        }
    }

    const CHUTES_HTTP_NONCE: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";
    const CHUTES_HTTP_E2E_PUBLIC_KEY: &str = "chutes-http-test-public-key";

    fn chutes_http_provider_evidence() -> serde_json::Value {
        chutes_http_provider_evidence_for_nonce(CHUTES_HTTP_NONCE)
    }

    fn chutes_http_provider_evidence_for_nonce(nonce: &str) -> serde_json::Value {
        let report_data = format!(
            "{}{}",
            chutes_expected_report_data_prefix(nonce, CHUTES_HTTP_E2E_PUBLIC_KEY).unwrap(),
            "00".repeat(32)
        );
        serde_json::json!({
            "attestation_type": "chutes",
            "tee_measurement": "sha256:chutes-http-tee-measurement",
            "all_attestations": [{
                "model": "private/org/gpt-oss-120b:thinking-TEE",
                "nonce": nonce,
                "e2e_pubkey": CHUTES_HTTP_E2E_PUBLIC_KEY,
                "report_data": report_data,
                "gpu_evidence": [{"kind": "nvidia_cc_fixture"}]
            }],
            "workload_image_digest": "sha256:chutes-http-workload-image",
            "model_artifacts": [{
                "kind": "weights",
                "name": "gpt-oss-120b",
                "digest": "sha256:chutes-http-weights"
            }],
            "issued_at": "2098-12-31T23:50:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "expires_at_epoch_ms": 4_070_908_800_000u64
        })
    }

    fn temp_registry_cache_path(test_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "confidential-inference-registry-cache-{test_name}-{}-{}.json",
            std::process::id(),
            now_epoch_millis()
        ))
    }

    fn temp_reference_values_cache_path(test_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "confidential-inference-reference-values-cache-{test_name}-{}-{}.json",
            std::process::id(),
            now_epoch_millis()
        ))
    }

    #[tokio::test]
    async fn demo_chat_verifies_and_executes_end_to_end() {
        let expected_verdict: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/verdict/demo-verified.json"))
                .unwrap();
        let audit = Arc::new(MemoryAuditSink::default());
        let verdict_store = Arc::new(MemoryVerdictStore::default());
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .audit_sink(audit.clone())
            .verdict_store(verdict_store.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();
        let expected_registry: ProviderRegistryEnvelope = serde_json::from_str(include_str!(
            "../../../fixtures/registry/demo-registry.json"
        ))
        .unwrap();
        let expected_reference_values: ReferenceValuesEnvelope = serde_json::from_str(
            include_str!("../../../fixtures/reference-values/demo-envelope.json"),
        )
        .unwrap();
        let active_artifacts = client.active_trust_artifacts();
        assert_eq!(active_artifacts.registry.version, "2026-07-05-demo");
        assert_eq!(active_artifacts.registry_source, "bundled");
        assert_eq!(
            active_artifacts.registry_signature.key_id,
            DEMO_SIGNING_KEY_ID
        );
        assert_eq!(
            active_artifacts.registry_signature,
            expected_registry.signature
        );
        assert_eq!(active_artifacts.reference_values.version, "2026-07-05-demo");
        assert_eq!(active_artifacts.reference_values_source, "bundled");
        assert_eq!(
            active_artifacts.reference_values_signature.key_id,
            DEMO_SIGNING_KEY_ID
        );
        assert_eq!(
            active_artifacts.reference_values_signature,
            expected_reference_values.signature
        );
        assert_eq!(
            active_artifacts.registry_digest,
            client.registry_digest().to_owned()
        );
        assert_eq!(
            active_artifacts.reference_values_digest,
            client.reference_values_digest().to_owned()
        );

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("hello from the demo"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(response.provider_model, "e2ee-gpt-oss-120b-p");
        assert_eq!(response.verdict.status, VerificationStatus::Verified);
        assert!(response.response_channel_bound);
        assert_eq!(
            response.response_integrity_result,
            ResponseIntegrityResult::ChannelBound
        );
        assert_eq!(
            response.verdict.check("model_binding"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            serde_json::to_value(&response.verdict).unwrap(),
            expected_verdict
        );
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|event| event.cache_hit));
        let event = events
            .iter()
            .find(|event| !event.cache_hit)
            .expect("expected a fresh verification audit event");
        assert_eq!(event.provider, "demo");
        assert_eq!(event.requested_model, "gpt-oss-120b");
        assert_eq!(event.provider_model, "e2ee-gpt-oss-120b-p");
        assert_eq!(event.canonical_model, "gpt-oss-120b");
        assert_eq!(event.evidence_family, "fixture_dstack");
        assert_eq!(event.adapter_version, "demo-fixture-adapter/0.1.0");
        assert_eq!(event.trust_tier, TrustTier::AppE2ee);
        assert_eq!(
            event.channel_binding_kind,
            ChannelBindingKind::AttestedAppE2ee
        );
        assert_eq!(
            event.request_confidentiality_result,
            ConfidentialityResult::EncryptedBound
        );
        assert_eq!(
            event.response_confidentiality_result,
            ConfidentialityResult::EncryptedBound
        );
        assert_eq!(
            event.response_integrity_result,
            ResponseIntegrityResult::ChannelBound
        );
        assert_eq!(event.freshness_class, FreshnessClass::PerSession);
        assert!(!event.streaming_allowed);
        assert_eq!(event.route_execution_status, "executable_fixture");
        assert!(event.chat_executable);
        assert_eq!(event.known_unsupported_modes, vec!["streaming".to_owned()]);
        assert_eq!(event.registry_source, "bundled");
        assert_eq!(event.registry_version, "2026-07-05-demo");
        assert_eq!(event.registry_signature.signer, "confidential-inference");
        assert_eq!(event.registry_signature.key_id, DEMO_SIGNING_KEY_ID);
        assert_eq!(event.reference_values_version, "2026-07-05-demo");
        assert_eq!(event.reference_values_source, "bundled");
        assert_eq!(
            event.reference_values_signature.signer,
            "confidential-inference"
        );
        assert_eq!(event.reference_values_signature.key_id, DEMO_SIGNING_KEY_ID);
        assert!(!serde_json::to_string(&*events)
            .unwrap()
            .contains("hello from the demo"));
        drop(events);

        let verdict_records = verdict_store.records.lock().unwrap();
        assert_eq!(verdict_records.len(), 2);
        assert_eq!(
            verdict_records[0].verdict_json["schema"],
            serde_json::Value::String(AttestationVerdict::SCHEMA.into())
        );
        assert!(verdict_records.iter().any(|record| record.cache_hit));
        assert!(verdict_records
            .iter()
            .all(|record| record.registry_signature.key_id == DEMO_SIGNING_KEY_ID));
        assert!(verdict_records
            .iter()
            .all(|record| record.provider_registry_digest
                == response.verdict.provider_registry_digest));
        assert!(verdict_records
            .iter()
            .all(|record| record.registry_source == "bundled"));
        assert!(verdict_records
            .iter()
            .all(|record| !record.streaming_allowed));
        assert!(verdict_records
            .iter()
            .all(|record| record.route_execution_status == "executable_fixture"));
        assert!(verdict_records.iter().all(|record| record.chat_executable));
        assert!(verdict_records
            .iter()
            .all(|record| record.known_unsupported_modes == vec!["streaming".to_owned()]));
        assert!(verdict_records
            .iter()
            .all(|record| record.reference_values_source == "bundled"));
        assert!(verdict_records
            .iter()
            .all(|record| record.reference_values_signature.key_id == DEMO_SIGNING_KEY_ID));
        assert!(!serde_json::to_string(&*verdict_records)
            .unwrap()
            .contains("hello from the demo"));
    }

    #[tokio::test]
    async fn verified_route_chat_rejects_request_model_mismatch() {
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();
        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        let error = verified
            .chat(ChatCompletionRequest::new(
                "llama-3.3-70b",
                vec![ChatMessage::user("wrong model")],
            ))
            .await
            .unwrap_err();

        match error {
            ClientError::VerifiedRouteModelMismatch {
                route_id,
                verified_model,
                request_model,
            } => {
                assert_eq!(route_id, "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p");
                assert_eq!(verified_model, "gpt-oss-120b");
                assert_eq!(request_model, "llama-3.3-70b");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn metrics_recorder_captures_redacted_demo_flow() {
        let metrics = Arc::new(InMemoryConfidentialInferenceMetricsRecorder::default());
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .metrics_recorder(metrics.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("metrics secret prompt"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        let events = metrics.events();
        assert!(events.iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::RouteSelection(metric)
                if metric.provider == "any"
                    && metric.requested_model == "gpt-oss-120b"
                    && metric.selected_count == 1
                    && metric.outcome == ConfidentialInferenceMetricOutcome::Success
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::VerificationCache(metric)
                if metric.event == ConfidentialInferenceVerificationCacheEvent::Miss
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::VerificationCache(metric)
                if metric.event == ConfidentialInferenceVerificationCacheEvent::Hit
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::Latency(metric)
                if metric.step == ConfidentialInferenceMetricStep::EvidenceFetch
                    && metric.outcome == ConfidentialInferenceMetricOutcome::Success
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::Latency(metric)
                if metric.step == ConfidentialInferenceMetricStep::EvidenceVerification
                    && metric.outcome == ConfidentialInferenceMetricOutcome::Success
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::Latency(metric)
                if metric.step == ConfidentialInferenceMetricStep::ProviderChat
                    && metric.outcome == ConfidentialInferenceMetricOutcome::Success
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::Verdict(metric)
                if metric.labels.provider == "demo"
                    && metric.labels.evidence_family == "fixture_dstack"
                    && metric.status == VerificationStatus::Verified
        )));
        let serialized = serde_json::to_string(&events).unwrap();
        assert!(!serialized.contains("metrics secret prompt"));
        assert!(!serialized.contains("demo confidential response"));
        let prometheus = metrics.prometheus_text();
        assert!(prometheus.contains("# TYPE confidential_inference_verdict_status_total counter"));
        assert!(prometheus.contains("confidential_inference_route_selection_total"));
        assert!(prometheus.contains("confidential_inference_verdict_cache_events_total"));
        assert!(prometheus.contains("confidential_inference_verification_step_duration_ms_sum"));
        assert!(prometheus.contains("provider=\"demo\""));
        assert!(prometheus.contains("evidence_family=\"fixture_dstack\""));
        assert!(!prometheus.contains("metrics secret prompt"));
        assert!(!prometheus.contains("demo confidential response"));

        let otlp = metrics.otlp_json().unwrap();
        let otlp_value: serde_json::Value = serde_json::from_str(&otlp).unwrap();
        assert_eq!(
            otlp_value["resourceMetrics"][0]["resource"]["attributes"][0]["key"],
            "service.name"
        );
        let otlp_metrics = otlp_value["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap();
        assert!(otlp_metrics.iter().any(|metric| metric["name"]
            == "confidential_inference_verdict_status_total"
            && metric["sum"]["dataPoints"]
                .as_array()
                .unwrap()
                .iter()
                .any(|point| point["attributes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|attribute| attribute["key"] == "provider"
                        && attribute["value"]["stringValue"] == "demo"))));
        assert!(otlp_metrics
            .iter()
            .any(|metric| metric["name"]
                == "confidential_inference_verification_step_duration_ms_sum"));
        assert!(!otlp.contains("metrics secret prompt"));
        assert!(!otlp.contains("demo confidential response"));
    }

    #[tokio::test]
    async fn tracing_spans_capture_route_metadata_without_plaintext_or_credentials() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(CapturedTraceWriter {
                buffer: captured.clone(),
            })
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::DEBUG)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("test tracing subscriber should install once");
        tracing_core::callsite::rebuild_interest_cache();

        let prompt = "trace secret prompt";
        let api_key = "trace-demo-api-key";
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .api_key("demo", api_key)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user(prompt))
            .send()
            .await
            .unwrap();

        let trace_text = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(trace_text.contains("confidential-inference.route_select"));
        assert!(trace_text.contains("provider=demo"));
        assert!(trace_text.contains("route_id=demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"));
        assert!(trace_text.contains("evidence_family=fixture_dstack"));
        assert!(trace_text.contains("recording attestation verdict"));
        assert!(!trace_text.contains(prompt));
        assert!(!trace_text.contains(api_key));
        assert!(!trace_text.contains("demo confidential response"));
        assert!(!trace_text.contains(response.response.choices[0].message.content.as_str()));
    }

    #[test]
    fn prometheus_metrics_exporter_aggregates_and_escapes_labels() {
        let labels = ConfidentialInferenceRouteMetricLabels {
            provider: "demo\"provider".into(),
            route_id: "route\nid".into(),
            requested_model: "gpt-oss-120b".into(),
            provider_model: "e2ee-gpt-oss-120b-p".into(),
            canonical_model: "gpt-oss-120b".into(),
            evidence_family: "fixture\\dstack".into(),
        };
        let event = ConfidentialInferenceMetricEvent::StreamingFailClosed(
            ConfidentialInferenceStreamingFailClosedMetric {
                labels,
                endpoint: "chat_completions".into(),
            },
        );
        let text = export_confidential_inference_metrics_prometheus_text(&[event.clone(), event]);

        assert!(text.contains("provider=\"demo\\\"provider\""));
        assert!(text.contains("route_id=\"route\\nid\""));
        assert!(text.contains("evidence_family=\"fixture\\\\dstack\""));
        assert!(text.contains("confidential_inference_streaming_fail_closed_total"));
        assert!(text.contains("endpoint=\"chat_completions\"} 2"));
    }

    #[test]
    fn otlp_metrics_exporter_aggregates_labels_and_metadata() {
        let labels = ConfidentialInferenceRouteMetricLabels {
            provider: "demo\"provider".into(),
            route_id: "route\nid".into(),
            requested_model: "gpt-oss-120b".into(),
            provider_model: "e2ee-gpt-oss-120b-p".into(),
            canonical_model: "gpt-oss-120b".into(),
            evidence_family: "fixture\\dstack".into(),
        };
        let event = ConfidentialInferenceMetricEvent::StreamingFailClosed(
            ConfidentialInferenceStreamingFailClosedMetric {
                labels,
                endpoint: "chat_completions".into(),
            },
        );
        let text =
            export_confidential_inference_metrics_otlp_json(&[event.clone(), event]).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let resource_metrics = value["resourceMetrics"].as_array().unwrap();
        assert_eq!(resource_metrics.len(), 1);
        let resource_attributes = resource_metrics[0]["resource"]["attributes"]
            .as_array()
            .unwrap();
        assert!(resource_attributes.iter().any(|attribute| {
            attribute["key"] == "service.name"
                && attribute["value"]["stringValue"] == "confidential-inference-sdk"
        }));
        let scope_metrics = resource_metrics[0]["scopeMetrics"].as_array().unwrap();
        assert_eq!(
            scope_metrics[0]["scope"]["name"],
            "confidential-inference-sdk"
        );
        let metrics = scope_metrics[0]["metrics"].as_array().unwrap();
        let metric = metrics
            .iter()
            .find(|metric| metric["name"] == "confidential_inference_streaming_fail_closed_total")
            .unwrap();
        assert_eq!(
            metric["sum"]["aggregationTemporality"],
            "AGGREGATION_TEMPORALITY_CUMULATIVE"
        );
        assert_eq!(metric["sum"]["isMonotonic"], true);
        let points = metric["sum"]["dataPoints"].as_array().unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0]["asInt"], "2");
        let point_attributes = points[0]["attributes"].as_array().unwrap();
        assert!(point_attributes.iter().any(|attribute| {
            attribute["key"] == "provider" && attribute["value"]["stringValue"] == "demo\"provider"
        }));
        assert!(point_attributes.iter().any(|attribute| {
            attribute["key"] == "route_id" && attribute["value"]["stringValue"] == "route\nid"
        }));
        assert!(point_attributes.iter().any(|attribute| {
            attribute["key"] == "evidence_family"
                && attribute["value"]["stringValue"] == "fixture\\dstack"
        }));
    }

    #[tokio::test]
    async fn otlp_http_export_posts_json_payload_and_redacts_failures() {
        let labels = demo_route_metric_labels();
        let event = ConfidentialInferenceMetricEvent::StreamingFailClosed(
            ConfidentialInferenceStreamingFailClosedMetric {
                labels,
                endpoint: "chat_completions".into(),
            },
        );
        let (endpoint, request) = spawn_otlp_metrics_collector(200).await;

        export_confidential_inference_metrics_otlp_http(&[event.clone(), event], &endpoint)
            .await
            .unwrap();

        let request = request.await.unwrap().unwrap();
        let request_text = String::from_utf8_lossy(&request);
        assert!(request_text.starts_with("POST /v1/metrics HTTP/1.1"));
        assert!(request_text
            .lines()
            .any(|line| line.eq_ignore_ascii_case("content-type: application/json")));
        let body: serde_json::Value = serde_json::from_slice(test_http_body(&request)).unwrap();
        assert_eq!(
            body["resourceMetrics"][0]["scopeMetrics"][0]["scope"]["name"],
            "confidential-inference-sdk"
        );
        let metrics = body["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap();
        assert!(metrics.iter().any(|metric| {
            metric["name"] == "confidential_inference_streaming_fail_closed_total"
                && metric["sum"]["dataPoints"][0]["asInt"] == "2"
        }));

        let (endpoint, _request) = spawn_otlp_metrics_collector(500).await;
        let error = export_confidential_inference_metrics_otlp_http(
            &[],
            endpoint.replace("http://", "http://user:sk-test-secret@"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("returned 500"));
        assert!(!error.contains("sk-test-secret"));
    }

    #[test]
    fn json_metric_events_use_distinct_variant_and_detail_fields() {
        let labels = demo_route_metric_labels();
        let cache = serde_json::to_value(ConfidentialInferenceMetricEvent::VerificationCache(
            ConfidentialInferenceVerificationCacheMetric {
                labels: labels.clone(),
                event: ConfidentialInferenceVerificationCacheEvent::Hit,
            },
        ))
        .unwrap();
        assert_eq!(cache["event"], "verification_cache");
        assert_eq!(cache["cache_event"], "hit");

        let single_flight = serde_json::to_value(ConfidentialInferenceMetricEvent::SingleFlight(
            ConfidentialInferenceSingleFlightMetric {
                labels,
                event: ConfidentialInferenceSingleFlightEvent::Wait,
                wait_ms: Some(7),
            },
        ))
        .unwrap();
        assert_eq!(single_flight["event"], "single_flight");
        assert_eq!(single_flight["single_flight_event"], "wait");

        let queue_full = serde_json::to_value(ConfidentialInferenceMetricEvent::SingleFlight(
            ConfidentialInferenceSingleFlightMetric {
                labels: demo_route_metric_labels(),
                event: ConfidentialInferenceSingleFlightEvent::QueueFull,
                wait_ms: None,
            },
        ))
        .unwrap();
        assert_eq!(queue_full["event"], "single_flight");
        assert_eq!(queue_full["single_flight_event"], "queue_full");
    }

    fn demo_route_metric_labels() -> ConfidentialInferenceRouteMetricLabels {
        ConfidentialInferenceRouteMetricLabels {
            provider: "demo".into(),
            route_id: "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p".into(),
            requested_model: "gpt-oss-120b".into(),
            provider_model: "e2ee-gpt-oss-120b-p".into(),
            canonical_model: "gpt-oss-120b".into(),
            evidence_family: "fixture_dstack".into(),
        }
    }

    #[tokio::test]
    async fn responses_shim_executes_through_verified_chat_path() {
        let audit = Arc::new(MemoryAuditSink::default());
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .audit_sink(audit.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let response = client
            .responses()
            .model("gpt-oss-120b")
            .text_input("hello from responses")
            .max_output_tokens(64)
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(response.provider_model, "e2ee-gpt-oss-120b-p");
        assert_eq!(response.verdict.status, VerificationStatus::Verified);
        assert_eq!(response.response.object, "response");
        assert_eq!(response.response.status, "completed");
        assert_eq!(
            response
                .response
                .metadata
                .get("confidential_inference_compatibility"),
            Some(&"responses_to_chat_shim".to_owned())
        );
        assert_eq!(
            response.response.output_text,
            "demo confidential response for e2ee-gpt-oss-120b-p: hello from responses"
        );
        assert_eq!(
            response.verdict.check("response_channel_binding"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(audit.events.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn responses_shim_streaming_fails_closed_when_route_does_not_support_streaming() {
        let metrics = Arc::new(InMemoryConfidentialInferenceMetricsRecorder::default());
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .metrics_recorder(metrics.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let error = client
            .responses()
            .model("gpt-oss-120b")
            .text_input("streaming should fail closed")
            .stream(true)
            .send()
            .await
            .unwrap_err();

        assert!(matches!(error, ClientError::StreamingNotSupported { .. }));
        let events = metrics.events();
        assert!(events.iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::StreamingFailClosed(metric)
                if metric.labels.provider == "demo"
                    && metric.endpoint == "chat_completions"
        )));
        assert!(!serde_json::to_string(&events)
            .unwrap()
            .contains("streaming should fail closed"));
    }

    #[tokio::test]
    async fn tinfoil_fixture_route_verifies_and_executes_through_client() {
        let client = ConfidentialInference::builder()
            .registry(ProviderRegistryEnvelope::phase2_fixtures().unwrap())
            .reference_values(ReferenceValuesEnvelope::phase2_fixtures().unwrap())
            .with_provider(TinfoilFixtureProvider::valid())
            .policy(VerificationPolicy::require_hw_verified_tls())
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("llama-3.3-70b")
            .message(ChatMessage::user("fixture tls path"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "tinfoil-fixture");
        assert_eq!(response.provider_model, "llama-3.3-70b");
        assert_eq!(response.verdict.status, VerificationStatus::Verified);
        assert_eq!(
            response.verdict.check("tls_binding"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            response.response_integrity_result,
            ResponseIntegrityResult::ChannelBound
        );
    }

    #[tokio::test]
    async fn live_tinfoil_capture_uses_configured_quote_verifier_through_client() {
        let report_data = format!("{}{}", tinfoil_fixture_spki_sha256(), "00".repeat(32));
        let quote_verifier = StaticTinfoilQuoteVerifier {
            quote: live_tinfoil_quote(report_data),
        };
        let mut policy = VerificationPolicy::require_hw_verified_tls();
        policy.model_binding_requirement = ModelBindingRequirement::IfProviderSupports;
        let client = ConfidentialInference::builder()
            .registry(ProviderRegistryEnvelope::phase2_fixtures().unwrap())
            .reference_values(ReferenceValuesEnvelope::phase2_fixtures().unwrap())
            .with_provider(LiveTinfoilCaptureProvider::default())
            .tinfoil_quote_verifier(quote_verifier)
            .policy(policy)
            .build()
            .await
            .unwrap();

        let verified = client
            .verify_route("tinfoil-fixture", "llama-3.3-70b")
            .await
            .unwrap();

        assert_eq!(verified.verdict().status, VerificationStatus::Verified);
        assert_eq!(
            verified.verdict().check("tls_binding"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            verified.verdict().check("model_binding"),
            Some(&CheckResult::Verified)
        );
        assert!(verified
            .verdict()
            .raw_evidence_digest
            .starts_with("sha256:"));
    }

    #[tokio::test]
    async fn live_tinfoil_tdx_capture_uses_configured_dcap_collateral_resolver() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let resolver = DcapTdxCollateralResolver::from_fetcher(StaticDcapCollateralFetcher {
            fetches: fetches.clone(),
        });
        let client = ConfidentialInference::builder()
            .registry(ProviderRegistryEnvelope::phase2_fixtures().unwrap())
            .reference_values(ReferenceValuesEnvelope::phase2_fixtures().unwrap())
            .with_provider(LiveTinfoilCaptureProvider::default())
            .tinfoil_dcap_tdx_collateral_resolver(resolver)
            .policy(VerificationPolicy::require_hw_verified_tls())
            .build()
            .await
            .unwrap();

        let error = match client
            .verify_route("tinfoil-fixture", "llama-3.3-70b")
            .await
        {
            Ok(_) => panic!("expected DCAP collateral resolver failure"),
            Err(error) => error.to_string(),
        };

        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert!(error.contains("TDX DCAP collateral bundle expired"));
    }

    #[tokio::test]
    async fn live_tinfoil_real_dcap_quote_reaches_tls_binding_policy_verdict() {
        let sample_quote = verified_sample_dcap_quote();
        let fetches = Arc::new(AtomicUsize::new(0));
        let resolver = DcapTdxCollateralResolver::from_fetcher(StaticDcapCollateralFetcher {
            fetches: fetches.clone(),
        });
        let now = sample_dcap_now_epoch_millis();
        let client = ConfidentialInference::builder()
            .registry(ProviderRegistryEnvelope::phase2_fixtures().unwrap())
            .reference_values(phase2_tinfoil_reference_values_with_measurement(
                &sample_quote.tee_measurement,
            ))
            .trusted_artifact_signing_key(custom_trusted_signing_key())
            .with_provider(LiveTinfoilCaptureProvider::with_quote_bytes(
                SAMPLE_DCAP_QUOTE.to_vec(),
            ))
            .tinfoil_dcap_tdx_collateral_resolver(resolver)
            .time_source(move || now)
            .policy(VerificationPolicy::require_hw_verified_tls())
            .build()
            .await
            .unwrap();

        let error = match client
            .verify_route("tinfoil-fixture", "llama-3.3-70b")
            .await
        {
            Ok(_) => panic!("expected real DCAP quote to fail TLS binding policy"),
            Err(error) => error,
        };

        let ClientError::PolicyDenied { verdict, .. } = error else {
            panic!("expected policy denial after real DCAP quote verification");
        };
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert_eq!(verdict.check("cpu_tee"), Some(&CheckResult::Verified));
        assert_eq!(verdict.check("tls_binding"), Some(&CheckResult::Failed));
        assert_eq!(
            verdict.artifacts.tee_measurement.as_deref(),
            Some(sample_quote.tee_measurement.as_str())
        );
        assert!(verdict
            .errors
            .iter()
            .any(|error| error.code == "tls_binding"));
    }

    #[tokio::test]
    async fn venice_fixture_hardware_verifies_but_chat_is_verification_only() {
        let mut policy = VerificationPolicy::require_hardware();
        policy.model_binding_requirement = ModelBindingRequirement::Required;
        let client = ConfidentialInference::builder()
            .registry(ProviderRegistryEnvelope::phase2_fixtures().unwrap())
            .reference_values(ReferenceValuesEnvelope::phase2_fixtures().unwrap())
            .with_provider(VeniceFixtureProvider::valid())
            .policy(policy)
            .build()
            .await
            .unwrap();

        let verified = client
            .verify_route("venice-fixture", "gpt-oss-120b")
            .await
            .unwrap();

        assert_eq!(verified.verdict().status, VerificationStatus::Verified);
        assert_eq!(
            verified.verdict().check("tcb_compose_hash"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            verified.verdict().check("e2ee_key_binding"),
            Some(&CheckResult::NotApplicable)
        );
        assert_eq!(
            verified.verdict().check("route_metadata_binding"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            verified.verdict().check("route_binding"),
            Some(&CheckResult::NotSupported)
        );
        assert_eq!(
            verified.verdict().route_execution_status,
            "verification_only"
        );
        assert!(!verified.verdict().chat_executable);
        assert_eq!(
            verified.verdict().known_unsupported_modes,
            vec!["streaming".to_owned(), "live_execution".to_owned()]
        );

        let err = verified
            .chat(ChatCompletionRequest::new(
                "gpt-oss-120b",
                vec![ChatMessage::user("should not execute yet")],
            ))
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            ClientError::Provider(ProviderError::Compatibility(_))
        ));
    }

    #[tokio::test]
    async fn venice_fixture_attested_e2ee_policy_fails_closed_without_crypto_proof() {
        let client = ConfidentialInference::builder()
            .registry(ProviderRegistryEnvelope::phase2_fixtures().unwrap())
            .reference_values(ReferenceValuesEnvelope::phase2_fixtures().unwrap())
            .with_provider(VeniceFixtureProvider::valid())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let error = match client.verify_route("venice-fixture", "gpt-oss-120b").await {
            Ok(_) => panic!("expected strict app-E2EE policy denial"),
            Err(error) => error,
        };
        let ClientError::PolicyDenied { verdict, .. } = error else {
            panic!("expected strict app-E2EE policy denial");
        };

        assert_eq!(verdict.status, VerificationStatus::Failed);
        assert_eq!(verdict.check("cpu_tee"), Some(&CheckResult::Verified));
        assert_eq!(
            verdict.check("tcb_compose_hash"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            verdict.check("e2ee_key_binding"),
            Some(&CheckResult::NotSupported)
        );
        assert_eq!(
            verdict.check("request_key_binding"),
            Some(&CheckResult::Failed)
        );
        assert_eq!(
            verdict.check("response_key_binding"),
            Some(&CheckResult::Failed)
        );
        assert_eq!(
            verdict.check("response_channel_binding"),
            Some(&CheckResult::Failed)
        );
        assert_eq!(
            verdict.request_confidentiality_result,
            ConfidentialityResult::Unknown
        );
        assert_eq!(
            verdict.response_confidentiality_result,
            ConfidentialityResult::Unknown
        );
        assert_eq!(
            verdict.response_integrity_result,
            ResponseIntegrityResult::Unknown
        );
    }

    #[tokio::test]
    async fn model_discovery_reports_policy_compatible_executable_chat_models() {
        let client = ConfidentialInference::builder()
            .registry(ProviderRegistryEnvelope::phase2_fixtures().unwrap())
            .reference_values(ReferenceValuesEnvelope::phase2_fixtures().unwrap())
            .with_demo_provider()
            .with_provider(VeniceFixtureProvider::valid())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let openai_models = client.models();
        assert_eq!(openai_models.object, "list");
        assert_eq!(openai_models.data.len(), 1);
        assert_eq!(openai_models.data[0].id, "gpt-oss-120b");

        let confidential_models = client.confidential_models();
        assert_eq!(confidential_models.len(), 1);
        assert_eq!(confidential_models[0].canonical_model, "gpt-oss-120b");
        assert_eq!(confidential_models[0].routes.len(), 2);
        assert!(confidential_models[0]
            .routes
            .iter()
            .any(|route| route.provider == "demo" && route.chat_executable));
        let demo_route = confidential_models[0]
            .routes
            .iter()
            .find(|route| route.provider == "demo")
            .unwrap();
        assert_eq!(demo_route.known_unsupported_modes, vec!["streaming"]);
        let venice_route = confidential_models[0]
            .routes
            .iter()
            .find(|route| route.provider == "venice-fixture")
            .unwrap();
        assert!(!venice_route.chat_executable);
        assert_eq!(
            venice_route.known_unsupported_modes,
            vec!["streaming", "live_execution"]
        );

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("select executable route"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.provider, "demo");
    }

    #[tokio::test]
    async fn model_discovery_hides_routes_that_do_not_satisfy_policy() {
        let client = ConfidentialInference::builder()
            .registry(ProviderRegistryEnvelope::phase2_fixtures().unwrap())
            .reference_values(ReferenceValuesEnvelope::phase2_fixtures().unwrap())
            .with_provider(TinfoilFixtureProvider::valid())
            .with_provider(VeniceFixtureProvider::valid())
            .policy(VerificationPolicy::require_hw_verified_tls())
            .build()
            .await
            .unwrap();

        let model_ids = client
            .models()
            .data
            .into_iter()
            .map(|model| model.id)
            .collect::<Vec<_>>();
        assert_eq!(model_ids, vec!["llama-3.3-70b"]);

        let confidential_models = client.confidential_models();
        assert_eq!(confidential_models.len(), 1);
        assert_eq!(confidential_models[0].canonical_model, "llama-3.3-70b");
        assert_eq!(confidential_models[0].routes[0].provider, "tinfoil-fixture");
        assert!(confidential_models[0].routes[0].chat_executable);
    }

    #[tokio::test]
    async fn chat_send_fails_over_when_primary_route_verification_is_unavailable() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        let unavailable_route = add_extra_demo_route(
            &mut registry,
            "unavailable-demo",
            TrustTier::AppE2ee,
            ChannelBindingKind::AttestedAppE2ee,
        );
        let mut compatibility_matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        add_compatibility_for_route(&mut compatibility_matrix, &unavailable_route);
        let unavailable_fetches = Arc::new(AtomicUsize::new(0));
        let demo_fetches = Arc::new(AtomicUsize::new(0));
        let mut adapters = BTreeMap::<String, Arc<dyn ProviderAdapter>>::new();
        adapters.insert(
            "unavailable-demo".into(),
            Arc::new(UnavailableProvider {
                provider_id: "unavailable-demo".into(),
                routes: vec![unavailable_route],
                evidence_fetches: unavailable_fetches.clone(),
            }),
        );
        adapters.insert(
            "demo".into(),
            Arc::new(CountingProvider::valid(demo_fetches.clone())),
        );
        let client = client_from_parts(
            registry,
            compatibility_matrix,
            adapters,
            VerificationPolicy::require_attested_e2ee(),
        );

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("use fallback route"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(unavailable_fetches.load(Ordering::SeqCst), 1);
        assert_eq!(demo_fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn configured_provider_order_overrides_registry_order_and_drives_failover() {
        let (
            mut client,
            registry_first_evidence_fetches,
            registry_first_chat_attempts,
            preferred_evidence_fetches,
            preferred_chat_attempts,
        ) = scripted_failover_client(None, Some(ScriptedChatFailure::Unavailable));
        Arc::get_mut(&mut client.inner).unwrap().provider_routing = ProviderRoutingConfig::new()
            .with_provider_order("gpt-oss-120b", ["demo", "primary-demo"]);

        let routes = &client
            .confidential_models()
            .into_iter()
            .find(|model| model.canonical_model == "gpt-oss-120b")
            .unwrap()
            .routes;
        assert_eq!(routes[0].provider, "demo");
        assert_eq!(routes[1].provider, "primary-demo");

        let response = client
            .chat_completions()
            .model("GPT-OSS 120B")
            .message(ChatMessage::user("follow configured order"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "primary-demo");
        assert_eq!(preferred_evidence_fetches.load(Ordering::SeqCst), 1);
        assert_eq!(preferred_chat_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(registry_first_evidence_fetches.load(Ordering::SeqCst), 1);
        assert_eq!(registry_first_chat_attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn configured_provider_order_excludes_unlisted_providers() {
        let (
            mut client,
            unlisted_evidence_fetches,
            unlisted_chat_attempts,
            listed_evidence_fetches,
            listed_chat_attempts,
        ) = scripted_failover_client(None, Some(ScriptedChatFailure::Unavailable));
        Arc::get_mut(&mut client.inner).unwrap().provider_routing =
            ProviderRoutingConfig::new().with_provider_order("gpt-oss-120b", ["demo"]);

        let error = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("do not use an unlisted provider"))
            .send()
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ClientError::Provider(ProviderError::Unavailable(_))
        ));
        assert_eq!(listed_evidence_fetches.load(Ordering::SeqCst), 1);
        assert_eq!(listed_chat_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(unlisted_evidence_fetches.load(Ordering::SeqCst), 0);
        assert_eq!(unlisted_chat_attempts.load(Ordering::SeqCst), 0);
        let model = client
            .confidential_models()
            .into_iter()
            .find(|model| model.canonical_model == "gpt-oss-120b")
            .unwrap();
        assert!(
            model
                .routes
                .iter()
                .find(|route| route.provider == "demo")
                .unwrap()
                .chat_executable
        );
        assert!(
            !model
                .routes
                .iter()
                .find(|route| route.provider == "primary-demo")
                .unwrap()
                .chat_executable
        );
    }

    #[tokio::test]
    async fn provider_routing_builder_accepts_valid_canonical_model_order() {
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .provider_order("gpt-oss-120b", ["demo"])
            .build()
            .await
            .unwrap();

        assert_eq!(client.models().data[0].id, "gpt-oss-120b");
    }

    #[tokio::test]
    async fn provider_routing_builder_rejects_invalid_models_providers_and_order() {
        let invalid_orders = [
            ProviderRoutingConfig::new().with_provider_order("GPT-OSS 120B", ["demo"]),
            ProviderRoutingConfig::new().with_provider_order("gpt-oss-120b", ["missing-provider"]),
            ProviderRoutingConfig::new().with_provider_order("gpt-oss-120b", ["demo", "demo"]),
            ProviderRoutingConfig::new().with_provider_order("gpt-oss-120b", Vec::<String>::new()),
        ];

        for routing in invalid_orders {
            let result = ConfidentialInference::builder()
                .with_demo_provider()
                .provider_routing(routing)
                .build()
                .await;
            let error = match result {
                Ok(_) => panic!("expected invalid provider routing"),
                Err(error) => error,
            };
            assert!(matches!(error, ClientError::InvalidProviderRouting { .. }));
        }

        let result = ConfidentialInference::builder()
            .provider_order("gpt-oss-120b", ["demo"])
            .build()
            .await;
        let error = match result {
            Ok(_) => panic!("expected missing provider adapter to fail routing validation"),
            Err(error) => error,
        };
        assert!(matches!(error, ClientError::InvalidProviderRouting { .. }));
    }

    #[tokio::test]
    async fn provider_routing_builder_rejects_verification_only_provider() {
        let mut policy = VerificationPolicy::require_hardware();
        policy.model_binding_requirement = ModelBindingRequirement::Required;
        let result = ConfidentialInference::builder()
            .registry(ProviderRegistryEnvelope::phase2_fixtures().unwrap())
            .reference_values(ReferenceValuesEnvelope::phase2_fixtures().unwrap())
            .with_provider(VeniceFixtureProvider::valid())
            .provider_order("gpt-oss-120b", ["venice-fixture"])
            .policy(policy)
            .build()
            .await;
        let error = match result {
            Ok(_) => panic!("expected verification-only provider routing to fail"),
            Err(error) => error,
        };

        assert!(matches!(error, ClientError::InvalidProviderRouting { .. }));
    }

    #[tokio::test]
    async fn chat_send_fails_over_to_another_provider_when_primary_chat_is_unavailable() {
        let (
            client,
            primary_evidence_fetches,
            primary_chat_attempts,
            fallback_evidence_fetches,
            fallback_chat_attempts,
        ) = scripted_failover_client(Some(ScriptedChatFailure::Unavailable), None);

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("use provider fallback"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(primary_evidence_fetches.load(Ordering::SeqCst), 1);
        assert_eq!(primary_chat_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_evidence_fetches.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_chat_attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn chat_send_fails_over_on_retryable_provider_http_status() {
        let (client, _, primary_chat_attempts, _, fallback_chat_attempts) =
            scripted_failover_client(Some(ScriptedChatFailure::HttpStatus(503)), None);

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("retry a service outage"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(primary_chat_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_chat_attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn chat_send_does_not_fail_over_on_non_retryable_provider_error() {
        for failure in [
            ScriptedChatFailure::HttpStatus(401),
            ScriptedChatFailure::Adapter,
        ] {
            let (client, _, primary_chat_attempts, fallback_fetches, fallback_chat_attempts) =
                scripted_failover_client(Some(failure), None);

            let error = client
                .chat_completions()
                .model("gpt-oss-120b")
                .message(ChatMessage::user("fail closed"))
                .send()
                .await
                .unwrap_err();

            assert!(matches!(error, ClientError::Provider(_)));
            assert_eq!(primary_chat_attempts.load(Ordering::SeqCst), 1);
            assert_eq!(fallback_fetches.load(Ordering::SeqCst), 0);
            assert_eq!(fallback_chat_attempts.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn chat_send_aggregates_errors_when_all_providers_are_unavailable() {
        let (client, _, primary_chat_attempts, _, fallback_chat_attempts) =
            scripted_failover_client(
                Some(ScriptedChatFailure::Unavailable),
                Some(ScriptedChatFailure::HttpStatus(503)),
            );

        let error = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("all providers unavailable"))
            .send()
            .await
            .unwrap_err();

        let ClientError::RouteAttemptsFailed { errors, .. } = error else {
            panic!("expected aggregate route-attempt failure");
        };
        assert_eq!(errors.len(), 2);
        assert_eq!(primary_chat_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_chat_attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn chat_send_does_not_fail_over_to_policy_downgraded_routes() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        let downgraded_route = add_extra_demo_route(
            &mut registry,
            "downgraded-demo",
            TrustTier::TeeOnly,
            ChannelBindingKind::None,
        );
        let mut compatibility_matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        add_compatibility_for_route(&mut compatibility_matrix, &downgraded_route);
        let downgraded_fetches = Arc::new(AtomicUsize::new(0));
        let demo_fetches = Arc::new(AtomicUsize::new(0));
        let mut adapters = BTreeMap::<String, Arc<dyn ProviderAdapter>>::new();
        adapters.insert(
            "downgraded-demo".into(),
            Arc::new(UnavailableProvider {
                provider_id: "downgraded-demo".into(),
                routes: vec![downgraded_route],
                evidence_fetches: downgraded_fetches.clone(),
            }),
        );
        adapters.insert(
            "demo".into(),
            Arc::new(CountingProvider::valid(demo_fetches.clone())),
        );
        let client = client_from_parts(
            registry,
            compatibility_matrix,
            adapters,
            VerificationPolicy::require_attested_e2ee(),
        );

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("do not downgrade"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(downgraded_fetches.load(Ordering::SeqCst), 0);
        assert_eq!(demo_fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn chat_send_skips_verification_only_fallback_routes_without_evidence_fetch() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        let verification_only_route = add_extra_demo_route(
            &mut registry,
            "verification-only-demo",
            TrustTier::AppE2ee,
            ChannelBindingKind::AttestedAppE2ee,
        );
        let mut compatibility_matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        add_compatibility_for_route(&mut compatibility_matrix, &verification_only_route);
        compatibility_matrix
            .providers
            .get_mut("verification-only-demo")
            .unwrap()
            .route_execution_status = RouteExecutionStatus::VerificationOnly;
        let verification_only_fetches = Arc::new(AtomicUsize::new(0));
        let demo_fetches = Arc::new(AtomicUsize::new(0));
        let mut adapters = BTreeMap::<String, Arc<dyn ProviderAdapter>>::new();
        adapters.insert(
            "verification-only-demo".into(),
            Arc::new(UnavailableProvider {
                provider_id: "verification-only-demo".into(),
                routes: vec![verification_only_route],
                evidence_fetches: verification_only_fetches.clone(),
            }),
        );
        adapters.insert(
            "demo".into(),
            Arc::new(CountingProvider::valid(demo_fetches.clone())),
        );
        let client = client_from_parts(
            registry,
            compatibility_matrix,
            adapters,
            VerificationPolicy::require_attested_e2ee(),
        );

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("skip verification-only fallback"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(verification_only_fetches.load(Ordering::SeqCst), 0);
        assert_eq!(demo_fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn chat_send_skips_registry_verification_only_routes_without_evidence_fetch() {
        let mut registry = ProviderRegistry::bundled_demo().unwrap();
        let mut verification_only_route = add_extra_demo_route(
            &mut registry,
            "registry-verification-only-demo",
            TrustTier::AppE2ee,
            ChannelBindingKind::AttestedAppE2ee,
        );
        verification_only_route.route_status = RouteLifecycle::VerificationOnly;
        registry.models.get_mut("gpt-oss-120b").unwrap().routes[0] =
            verification_only_route.clone();
        let mut compatibility_matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        add_compatibility_for_route(&mut compatibility_matrix, &verification_only_route);
        let verification_only_fetches = Arc::new(AtomicUsize::new(0));
        let demo_fetches = Arc::new(AtomicUsize::new(0));
        let mut adapters = BTreeMap::<String, Arc<dyn ProviderAdapter>>::new();
        adapters.insert(
            "registry-verification-only-demo".into(),
            Arc::new(UnavailableProvider {
                provider_id: "registry-verification-only-demo".into(),
                routes: vec![verification_only_route],
                evidence_fetches: verification_only_fetches.clone(),
            }),
        );
        adapters.insert(
            "demo".into(),
            Arc::new(CountingProvider::valid(demo_fetches.clone())),
        );
        let client = client_from_parts(
            registry,
            compatibility_matrix,
            adapters,
            VerificationPolicy::require_attested_e2ee(),
        );

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user(
                "skip registry verification-only fallback",
            ))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(verification_only_fetches.load(Ordering::SeqCst), 0);
        assert_eq!(demo_fetches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn active_routes_for_provider_filters_registry_routes() {
        let registry = ProviderRegistry::phase2_fixtures().unwrap();

        let tinfoil_fixture_routes = active_routes_for_provider(&registry, "tinfoil-fixture");
        let tinfoil_live_routes = active_routes_for_provider(&registry, "tinfoil");

        assert_eq!(tinfoil_fixture_routes.len(), 1);
        assert!(tinfoil_live_routes.is_empty());
    }

    #[test]
    fn tinfoil_api_key_auto_registers_live_http_provider_when_registry_has_routes() {
        let mut registry = ProviderRegistry::phase2_fixtures().unwrap();
        for model in registry.models.values_mut() {
            for route in &mut model.routes {
                if route.provider == "tinfoil-fixture" {
                    route.provider = "tinfoil".into();
                }
            }
        }
        let api_keys =
            BTreeMap::from([("tinfoil".into(), ClientApiKey::from("sk-test".to_owned()))]);
        let mut adapters = BTreeMap::new();

        install_default_credential_adapters(&registry, &api_keys, &mut adapters).unwrap();

        assert!(adapters.contains_key("tinfoil"));
    }

    #[test]
    fn client_api_key_debug_redacts_secret_value() {
        let api_key = ClientApiKey::from("sk-client-debug-secret".to_owned());

        let rendered = format!("{api_key:?}");

        assert_eq!(rendered, "<redacted>");
        assert!(!rendered.contains("sk-client-debug-secret"));
    }

    #[tokio::test]
    async fn per_session_verification_cache_reuses_send_time_recheck() {
        let audit = Arc::new(MemoryAuditSink::default());
        let fetches = Arc::new(AtomicUsize::new(0));
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid(fetches.clone()))
            .audit_sink(audit.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("cache this route"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.verdict.status, VerificationStatus::Verified);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert!(!events[0].cache_hit);
        assert!(events[1].cache_hit);
    }

    #[tokio::test]
    async fn chat_revalidates_once_after_provider_key_rotation() {
        let audit = Arc::new(MemoryAuditSink::default());
        let fetches = Arc::new(AtomicUsize::new(0));
        let chat_attempts = Arc::new(AtomicUsize::new(0));
        let client = ConfidentialInference::builder()
            .with_provider(KeyRotatingProvider::new(
                fetches.clone(),
                chat_attempts.clone(),
            ))
            .audit_sink(audit.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("rotate once"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.verdict.status, VerificationStatus::Verified);
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        assert_eq!(chat_attempts.load(Ordering::SeqCst), 2);
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 3);
        assert!(!events[0].cache_hit);
        assert!(events[1].cache_hit);
        assert!(!events[2].cache_hit);
    }

    #[tokio::test]
    async fn streaming_and_non_streaming_chat_use_distinct_verification_cache_keys() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let client = ConfidentialInference::builder()
            .registry(custom_signed_streaming_demo_registry())
            .trusted_artifact_signing_key(custom_trusted_signing_key())
            .compatibility_matrix(streaming_demo_compatibility_matrix())
            .with_provider(CountingProvider::valid(fetches.clone()))
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("non-streaming cache entry"))
            .send()
            .await
            .unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("streaming cache entry"))
            .stream(true)
            .send()
            .await
            .unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);

        {
            let cache = client.inner.verdict_cache.lock().unwrap();
            let request_modes = cache.keys().map(|key| key.request_mode).collect::<Vec<_>>();
            assert_eq!(request_modes.len(), 2);
            assert!(request_modes.contains(&"non_streaming_chat"));
            assert!(request_modes.contains(&"streaming_chat"));
            assert!(!request_modes.contains(&"verify_only"));
        }

        client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("reuse streaming cache entry"))
            .stream(true)
            .send()
            .await
            .unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn verification_cache_key_includes_route_encryption_modes() {
        let route_definition = DemoProvider::valid().routes().remove(0);
        let attested_route = route_definition.to_attested_route("gpt-oss-120b", "gpt-oss-120b");
        let encrypted_key = VerificationCacheKey::new(
            &route_definition,
            &attested_route,
            VerificationRequestMode::NonStreamingChat,
            "sha256:policy",
            "sha256:registry",
            "sha256:reference",
        );

        let mut plaintext_route = route_definition.clone();
        plaintext_route.request_encryption = EncryptionRequirement::NotRequired;
        plaintext_route.response_decryption = EncryptionRequirement::NotRequired;
        let plaintext_key = VerificationCacheKey::new(
            &plaintext_route,
            &attested_route,
            VerificationRequestMode::NonStreamingChat,
            "sha256:policy",
            "sha256:registry",
            "sha256:reference",
        );

        assert_ne!(encrypted_key, plaintext_key);
        assert_eq!(encrypted_key.request_encryption, "Required");
        assert_eq!(encrypted_key.response_decryption, "Required");
        assert_eq!(plaintext_key.request_encryption, "NotRequired");
        assert_eq!(plaintext_key.response_decryption, "NotRequired");
    }

    #[tokio::test]
    async fn cached_fixture_route_verification_meets_local_latency_budget() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid(fetches.clone()))
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        client.verify_route("demo", "gpt-oss-120b").await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        let mut durations = Vec::new();
        for _ in 0..32 {
            let started = Instant::now();
            let route = client.verify_route("demo", "gpt-oss-120b").await.unwrap();
            assert_eq!(route.verdict.status, VerificationStatus::Verified);
            durations.push(started.elapsed().as_millis());
        }

        durations.sort_unstable();
        let p95_index = (durations.len() * 95).div_ceil(100).saturating_sub(1);
        let p95_ms = durations[p95_index];
        assert!(
            p95_ms <= 100,
            "cached fixture route verification p95 exceeded 100 ms: {p95_ms} ms; samples={durations:?}"
        );
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn chat_execution_uses_compatibility_matrix_request_adaptation() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let chat_bodies = Arc::new(Mutex::new(Vec::new()));
        let mut compatibility_matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        compatibility_matrix
            .providers
            .get_mut("demo")
            .unwrap()
            .token_parameter_rewrite = TokenParameterRewrite::MaxTokensToMaxCompletionTokens;
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid_with_body_capture(
                fetches,
                chat_bodies.clone(),
            ))
            .compatibility_matrix(compatibility_matrix)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("adapt through matrix"))
            .max_tokens(64)
            .send()
            .await
            .unwrap();

        let bodies = chat_bodies.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0]["model"], "e2ee-gpt-oss-120b-p");
        assert_eq!(bodies[0]["max_completion_tokens"], 64);
        assert!(bodies[0].get("max_tokens").is_none());
    }

    #[tokio::test]
    async fn executable_app_e2ee_chat_uses_sdk_encrypted_request_metadata() {
        let secret_key =
            SdkAppE2eeSecretKey::from_private_key_bytes("client-e2ee-key", [13_u8; 32]);
        let encrypted_bodies = Arc::new(Mutex::new(Vec::new()));
        let decrypted_bodies = Arc::new(Mutex::new(Vec::new()));
        let mut compatibility_matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        let compatibility = compatibility_matrix.providers.get_mut("demo").unwrap();
        compatibility.route_execution_status = RouteExecutionStatus::Executable;
        compatibility.sdk_app_e2ee = Some(secret_key.public_config().unwrap());
        let client = ConfidentialInference::builder()
            .with_provider(SdkEncryptedDemoProvider {
                inner: DemoProvider::valid(),
                secret_key,
                encrypted_bodies: encrypted_bodies.clone(),
                decrypted_bodies: decrypted_bodies.clone(),
            })
            .compatibility_matrix(compatibility_matrix)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("sdk encrypted client path"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "demo");
        assert_eq!(response.provider_model, "e2ee-gpt-oss-120b-p");
        assert_eq!(response.verdict.status, VerificationStatus::Verified);
        let encrypted_bodies = encrypted_bodies.lock().unwrap();
        assert_eq!(encrypted_bodies.len(), 1);
        let encrypted_json = encrypted_bodies[0].to_string();
        assert!(encrypted_json.contains("confidential-inference.sdk-encrypted-chat.v1"));
        assert!(!encrypted_json.contains("sdk encrypted client path"));
        drop(encrypted_bodies);

        let decrypted_bodies = decrypted_bodies.lock().unwrap();
        assert_eq!(decrypted_bodies.len(), 1);
        assert_eq!(decrypted_bodies[0]["model"], "e2ee-gpt-oss-120b-p");
        assert_eq!(
            decrypted_bodies[0]["messages"][0]["content"],
            "sdk encrypted client path"
        );
    }

    #[tokio::test]
    async fn api_key_auto_registers_confidential_http_provider_for_sdk_app_e2ee_route() {
        let secret_key =
            SdkAppE2eeSecretKey::from_private_key_bytes("venice-http-key", [21_u8; 32]);
        let raw_chat_requests = Arc::new(Mutex::new(Vec::new()));
        let (route, server) =
            spawn_dstack_app_e2ee_http_server(secret_key.clone(), raw_chat_requests.clone()).await;
        let registry = signed_dstack_http_registry(route.clone());
        let reference_values = signed_dstack_http_reference_values(
            &route,
            secret_key
                .public_config()
                .unwrap()
                .public_key_digest()
                .unwrap(),
        );
        let mut policy = VerificationPolicy::require_hardware();
        policy.model_binding_requirement = ModelBindingRequirement::Required;
        policy.provenance.workload_image = true;
        policy.provenance.model_artifacts = true;
        let client = ConfidentialInference::builder()
            .registry(registry)
            .reference_values(reference_values)
            .trusted_artifact_signing_key(custom_trusted_signing_key())
            .compatibility_matrix(dstack_http_compatibility(&route, &secret_key))
            .api_key("venice-http-test", "sk-venice-http-test")
            .policy(policy)
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("auto registered encrypted provider"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "venice-http-test");
        assert_eq!(response.provider_model, "e2ee-gpt-oss-120b-p");
        assert_eq!(response.verdict.status, VerificationStatus::Verified);
        for check in [
            "tcb_compose_hash",
            "e2ee_key_reference_match",
            "model_binding",
            "image_provenance",
            "model_artifact_provenance",
        ] {
            assert_eq!(response.verdict.check(check), Some(&CheckResult::Verified));
        }
        assert_eq!(
            response.verdict.check("e2ee_key_binding"),
            Some(&CheckResult::NotApplicable)
        );
        assert_eq!(
            response.verdict.check("request_encryption"),
            Some(&CheckResult::NotApplicable)
        );
        assert_eq!(
            response.verdict.check("response_encryption"),
            Some(&CheckResult::NotApplicable)
        );
        assert_eq!(
            response.verdict.request_confidentiality_result,
            ConfidentialityResult::Unknown
        );
        assert_eq!(
            response.verdict.response_confidentiality_result,
            ConfidentialityResult::Unknown
        );
        assert!(response.response.choices[0]
            .message
            .content
            .contains("auto registered encrypted provider"));
        {
            let raw_chat_requests = raw_chat_requests.lock().unwrap();
            assert_eq!(raw_chat_requests.len(), 1);
            assert!(raw_chat_requests[0].contains("confidential-inference.sdk-encrypted-chat.v1"));
            assert!(!raw_chat_requests[0].contains("auto registered encrypted provider"));
        }
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn api_key_auto_registers_direct_phala_dstack_http_provider() {
        let secret_key = SdkAppE2eeSecretKey::from_private_key_bytes("phala-http-key", [31_u8; 32]);
        let raw_chat_requests = Arc::new(Mutex::new(Vec::new()));
        let (route, server) =
            spawn_phala_dstack_app_e2ee_http_server(secret_key.clone(), raw_chat_requests.clone())
                .await;
        let registry = signed_phala_http_registry(route.clone());
        let reference_values = signed_phala_http_reference_values(
            &route,
            secret_key
                .public_config()
                .unwrap()
                .public_key_digest()
                .unwrap(),
        );
        let mut policy = VerificationPolicy::require_hardware();
        policy.model_binding_requirement = ModelBindingRequirement::Required;
        policy.provenance.workload_image = true;
        policy.provenance.model_artifacts = true;
        let client = ConfidentialInference::builder()
            .registry(registry)
            .reference_values(reference_values)
            .trusted_artifact_signing_key(custom_trusted_signing_key())
            .compatibility_matrix(phala_http_compatibility(&route, &secret_key))
            .api_key("phala-http-test", "sk-phala-http-test")
            .policy(policy)
            .build()
            .await
            .unwrap();

        let confidential_models = client.confidential_models();
        assert_eq!(confidential_models.len(), 1);
        assert_eq!(confidential_models[0].canonical_model, "gpt-oss-120b");
        assert_eq!(confidential_models[0].routes.len(), 1);
        assert_eq!(confidential_models[0].routes[0].provider, "phala-http-test");
        assert!(confidential_models[0].routes[0].chat_executable);

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("direct Phala encrypted provider"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.provider, "phala-http-test");
        assert_eq!(response.provider_model, "phala/gpt-oss-120b-confidential");
        assert_eq!(response.verdict.status, VerificationStatus::Verified);
        for check in [
            "tcb_compose_hash",
            "e2ee_key_reference_match",
            "model_binding",
            "image_provenance",
            "model_artifact_provenance",
        ] {
            assert_eq!(response.verdict.check(check), Some(&CheckResult::Verified));
        }
        assert_eq!(
            response.verdict.check("e2ee_key_binding"),
            Some(&CheckResult::NotApplicable)
        );
        assert_eq!(
            response.verdict.check("request_encryption"),
            Some(&CheckResult::NotApplicable)
        );
        assert_eq!(
            response.verdict.check("response_encryption"),
            Some(&CheckResult::NotApplicable)
        );
        assert_eq!(
            response.verdict.request_confidentiality_result,
            ConfidentialityResult::Unknown
        );
        assert_eq!(
            response.verdict.response_confidentiality_result,
            ConfidentialityResult::Unknown
        );
        assert!(response.response.choices[0]
            .message
            .content
            .contains("direct Phala encrypted provider"));
        {
            let raw_chat_requests = raw_chat_requests.lock().unwrap();
            assert_eq!(raw_chat_requests.len(), 1);
            assert!(raw_chat_requests[0].contains("authorization: Bearer sk-phala-http-test"));
            assert!(raw_chat_requests[0].contains("confidential-inference.sdk-encrypted-chat.v1"));
            assert!(!raw_chat_requests[0].contains("direct Phala encrypted provider"));
        }
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn api_key_auto_registers_confidential_http_provider_for_chutes_verification_route() {
        let (route, server) = spawn_chutes_e2ee_http_server().await;
        let registry = signed_chutes_http_registry(route.clone());
        let reference_values = signed_chutes_http_reference_values(&route);
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.hardware.gpu = GpuTeeRequirement::one_of(vec![GpuTeeKind::NvidiaCc]);
        policy.model_binding_requirement = ModelBindingRequirement::Required;
        policy.provenance.workload_image = true;
        policy.provenance.model_artifacts = true;
        assert_eq!(route.accepted_gpu_tees, vec![GpuTeeKind::NvidiaCc]);
        let client = ConfidentialInference::builder()
            .registry(registry)
            .reference_values(reference_values)
            .trusted_artifact_signing_key(custom_trusted_signing_key())
            .compatibility_matrix(chutes_http_compatibility(&route))
            .api_key("redpill-http-test", "sk-redpill-http-test")
            .gpu_attestation_verifier(StaticGpuAttestationVerifier)
            .policy(policy)
            .build()
            .await
            .unwrap();

        let verified = client
            .verify_route("redpill-http-test", "gpt-oss-120b")
            .await
            .unwrap();

        assert_eq!(verified.verdict().status, VerificationStatus::Verified);
        for check in [
            "e2ee_key_binding",
            "gpu_tee",
            "nonce_binding",
            "model_binding",
            "image_provenance",
            "model_artifact_provenance",
        ] {
            assert_eq!(
                verified.verdict().check(check),
                Some(&CheckResult::Verified)
            );
        }
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn chutes_http_per_request_freshness_verifies_nonce_bound_evidence() {
        let (route, server) = spawn_chutes_e2ee_http_server().await;
        let registry = signed_chutes_http_registry(route.clone());
        let reference_values = signed_chutes_http_reference_values(&route);
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.freshness = FreshnessPolicy::PerRequest;
        policy.hardware.gpu = GpuTeeRequirement::one_of(vec![GpuTeeKind::NvidiaCc]);
        policy.model_binding_requirement = ModelBindingRequirement::Required;
        policy.provenance.workload_image = true;
        policy.provenance.model_artifacts = true;
        let client = ConfidentialInference::builder()
            .registry(registry)
            .reference_values(reference_values)
            .trusted_artifact_signing_key(custom_trusted_signing_key())
            .compatibility_matrix(chutes_http_compatibility(&route))
            .api_key("redpill-http-test", "sk-redpill-http-test")
            .gpu_attestation_verifier(StaticGpuAttestationVerifier)
            .policy(policy)
            .build()
            .await
            .unwrap();

        let verified = client
            .verify_route("redpill-http-test", "gpt-oss-120b")
            .await
            .unwrap();

        assert_eq!(verified.verdict().status, VerificationStatus::Verified);
        assert_eq!(
            verified.verdict().check("nonce_binding"),
            Some(&CheckResult::Verified)
        );
        assert_eq!(
            verified.verdict().check("per_request_freshness"),
            Some(&CheckResult::Verified)
        );
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn compatibility_matrix_must_cover_active_registry_routes() {
        let mut compatibility_matrix = ProviderCompatibilityMatrix::bundled().unwrap();
        compatibility_matrix.providers.remove("demo");

        let result = ConfidentialInference::builder()
            .with_demo_provider()
            .compatibility_matrix(compatibility_matrix)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await;

        assert!(matches!(
            result,
            Err(ClientError::Provider(ProviderError::Compatibility(_)))
        ));
    }

    #[tokio::test]
    async fn registry_pin_accepts_matching_registry_before_build() {
        let envelope = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let digest = envelope.payload.digest().unwrap();
        let version = envelope.payload.version.clone();

        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .registry(envelope)
            .registry_pin(ProviderRegistryPin::digest_and_version(
                digest.clone(),
                version,
            ))
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        assert_eq!(client.registry_digest(), digest);
        assert_eq!(client.registry_source(), "custom");
    }

    #[tokio::test]
    async fn registry_pin_mismatch_fails_client_build() {
        let result = ConfidentialInference::builder()
            .with_demo_provider()
            .registry_pin(ProviderRegistryPin::digest("sha256:wrong"))
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await;

        match result {
            Err(ClientError::Attestation(AttestationError::InvalidRegistryUpdate(message))) => {
                assert!(message.contains("registry digest pin mismatch"));
            }
            Ok(_) => panic!("mismatched registry pin unexpectedly built a client"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn registry_signing_identity_pin_fails_client_build() {
        let result = ConfidentialInference::builder()
            .with_demo_provider()
            .registry_pin(
                ProviderRegistryPin::new()
                    .with_accepted_ed25519_signing_identity("confidential-inference", "other-key"),
            )
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await;

        match result {
            Err(ClientError::Attestation(AttestationError::InvalidRegistryUpdate(message))) => {
                assert!(message.contains("registry signing identity pin mismatch"));
            }
            Ok(_) => panic!("mismatched registry signing pin unexpectedly built a client"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn reference_values_pin_accepts_matching_bundle_before_build() {
        let envelope = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let digest = envelope.payload.digest().unwrap();
        let version = envelope.payload.version.clone();

        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .reference_values(envelope)
            .reference_values_pin(ReferenceValuesPin::digest_and_version(
                digest.clone(),
                version,
            ))
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        assert_eq!(client.reference_values_digest(), digest);
    }

    #[tokio::test]
    async fn reference_values_pin_mismatch_fails_client_build() {
        let result = ConfidentialInference::builder()
            .with_demo_provider()
            .reference_values_pin(ReferenceValuesPin::digest("sha256:wrong"))
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await;

        match result {
            Err(ClientError::Attestation(AttestationError::InvalidReferenceValuesUpdate(
                message,
            ))) => {
                assert!(message.contains("reference values digest pin mismatch"));
            }
            Ok(_) => panic!("mismatched reference values pin unexpectedly built a client"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn reference_values_revocation_epoch_pin_fails_stale_client_build() {
        let result = ConfidentialInference::builder()
            .with_demo_provider()
            .reference_values_pin(ReferenceValuesPin::minimum_revocation_epoch(2))
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await;

        match result {
            Err(ClientError::Attestation(AttestationError::InvalidReferenceValuesUpdate(
                message,
            ))) => {
                assert!(message.contains("revocation epoch 1 is older than pinned minimum 2"));
            }
            Ok(_) => panic!("stale reference values revocation epoch unexpectedly built a client"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn registry_source_label_redacts_url_credentials() {
        let label = registry_source_label(
            "remote",
            " https://token:secret@github.com:8443/enclava-labs/confidential-inference-sdk/registry.json?x=1 "
                .into(),
        );

        assert_eq!(
            label,
            "remote:https://github.com:8443/enclava-labs/confidential-inference-sdk/registry.json?x=1"
        );
        assert!(!label.contains("token"));
        assert!(!label.contains("secret"));
        assert!(!label.contains("token:secret@github.com"));
        assert_eq!(
            registry_source_label(
                "remote",
                "https://github.com/enclava-labs/confidential-inference-sdk/registry.json".into()
            ),
            "remote:https://github.com/enclava-labs/confidential-inference-sdk/registry.json"
        );
        assert_eq!(
            redact_url_credentials(
                "https://github.com/enclava-labs/confidential-inference-sdk/path/@metadata?owner=ops@confidential-inference.dev"
            ),
            "https://github.com/enclava-labs/confidential-inference-sdk/path/@metadata?owner=ops@confidential-inference.dev"
        );
    }

    #[tokio::test]
    async fn remote_registry_source_fetches_signed_registry_into_verdict() {
        let envelope = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let body = serde_json::to_string(&envelope).unwrap();
        let url = serve_registry_response(body, "200 OK").await;
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_registry(url.clone(), envelope)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        assert_eq!(verified.verdict().registry_source, format!("remote:{url}"));
    }

    #[tokio::test]
    async fn remote_registry_source_falls_back_to_last_good_signed_registry() {
        let envelope = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let fallback_digest = envelope.payload.digest().unwrap();
        let url = serve_registry_response("{\"not\":\"an envelope\"}".into(), "200 OK").await;
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_registry(url.clone(), envelope)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        assert_eq!(client.registry_digest(), fallback_digest);
        assert_eq!(
            verified.verdict().registry_source,
            format!("remote-fallback:{url}")
        );
    }

    #[tokio::test]
    async fn remote_registry_source_persists_and_reuses_last_good_cache() {
        let fallback = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let remote = ProviderRegistryEnvelope::phase2_fixtures().unwrap();
        let remote_digest = remote.payload.digest().unwrap();
        let cache_path = temp_registry_cache_path("reuse");

        let remote_url =
            serve_registry_response(serde_json::to_string(&remote).unwrap(), "200 OK").await;
        let remote_client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_registry_with_cache(remote_url.clone(), fallback.clone(), &cache_path)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        assert_eq!(remote_client.registry_digest(), remote_digest);
        assert!(std::fs::read_to_string(&cache_path)
            .unwrap()
            .contains("2026-07-05-phase2-fixtures"));

        let invalid_url =
            serve_registry_response("{\"not\":\"an envelope\"}".into(), "200 OK").await;
        let cached_client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_registry_with_cache(invalid_url.clone(), fallback, &cache_path)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = cached_client
            .verify_route("demo", "gpt-oss-120b")
            .await
            .unwrap();

        assert_eq!(cached_client.registry_digest(), remote_digest);
        assert_eq!(
            verified.verdict().registry_source,
            format!("remote-cache:{invalid_url}")
        );

        let _ = std::fs::remove_file(cache_path);
    }

    #[tokio::test]
    async fn remote_registry_source_keeps_cache_when_remote_is_stale_relative_to_cache() {
        let fallback = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let cached = ProviderRegistryEnvelope::phase2_fixtures().unwrap();
        let cached_digest = cached.payload.digest().unwrap();
        let cache_path = temp_registry_cache_path("stale-remote");
        std::fs::write(&cache_path, serde_json::to_string(&cached).unwrap()).unwrap();

        let stale_remote_url =
            serve_registry_response(serde_json::to_string(&fallback).unwrap(), "200 OK").await;
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_registry_with_cache(stale_remote_url.clone(), fallback, &cache_path)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        assert_eq!(client.registry_digest(), cached_digest);
        assert_eq!(
            verified.verdict().registry_source,
            format!("remote-cache:{stale_remote_url}")
        );
        assert!(std::fs::read_to_string(&cache_path)
            .unwrap()
            .contains("2026-07-05-phase2-fixtures"));

        let _ = std::fs::remove_file(cache_path);
    }

    #[tokio::test]
    async fn remote_registry_source_ignores_invalid_cache_and_uses_fallback() {
        let fallback = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let fallback_digest = fallback.payload.digest().unwrap();
        let cache_path = temp_registry_cache_path("invalid");
        std::fs::write(&cache_path, b"{\"not\":\"an envelope\"}").unwrap();
        let url = serve_registry_response("{\"also\":\"invalid\"}".into(), "200 OK").await;

        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_registry_with_cache(url.clone(), fallback, &cache_path)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        assert_eq!(client.registry_digest(), fallback_digest);
        assert_eq!(
            verified.verdict().registry_source,
            format!("remote-fallback:{url}")
        );

        let _ = std::fs::remove_file(cache_path);
    }

    #[tokio::test]
    async fn remote_registry_source_falls_back_when_candidate_signing_identity_is_not_pinned() {
        let fallback = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let fallback_digest = fallback.payload.digest().unwrap();
        let remote = ProviderRegistryEnvelope::phase2_fixtures().unwrap();
        let url = serve_registry_response(serde_json::to_string(&remote).unwrap(), "200 OK").await;
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_registry(url.clone(), fallback)
            .registry_pin(
                ProviderRegistryPin::new().with_accepted_ed25519_signing_identity(
                    "confidential-inference",
                    DEMO_SIGNING_KEY_ID,
                ),
            )
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        assert_eq!(client.registry_digest(), fallback_digest);
        assert_eq!(
            verified.verdict().registry_source,
            format!("remote-fallback:{url}")
        );
    }

    #[tokio::test]
    async fn remote_reference_values_source_fetches_signed_bundle_into_verdict() {
        let fallback = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let remote = ReferenceValuesEnvelope::phase2_fixtures().unwrap();
        let remote_digest = remote.payload.digest().unwrap();
        let url = serve_registry_response(serde_json::to_string(&remote).unwrap(), "200 OK").await;
        let expected_source = format!("remote:{url}");
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_reference_values(url, fallback)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        assert_eq!(client.reference_values_digest(), remote_digest);
        assert_eq!(client.reference_values_source(), expected_source);
        let active_artifacts = client.active_trust_artifacts();
        assert_eq!(active_artifacts.reference_values_digest, remote_digest);
        assert_eq!(active_artifacts.reference_values_source, expected_source);
        assert_eq!(verified.verdict().reference_values_digest, remote_digest);
        assert_eq!(verified.verdict().reference_values_source, expected_source);
        assert_eq!(
            verified.verdict().reference_values_version,
            "2026-07-05-phase2-fixtures"
        );
    }

    #[tokio::test]
    async fn remote_reference_values_source_accepts_signed_revocation_epoch_pin_update() {
        let fallback = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let remote = custom_signed_reference_values_with_revocation_epoch(2);
        let remote_digest = remote.payload.digest().unwrap();
        let url = serve_registry_response(serde_json::to_string(&remote).unwrap(), "200 OK").await;
        let expected_source = format!("remote:{url}");
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_reference_values(url, fallback)
            .trusted_artifact_signing_key(custom_trusted_signing_key())
            .reference_values_pin(ReferenceValuesPin::minimum_revocation_epoch(2))
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        assert_eq!(client.reference_values_digest(), remote_digest);
        assert_eq!(client.reference_values_source(), expected_source);
        assert_eq!(verified.verdict().reference_values_digest, remote_digest);
        assert_eq!(verified.verdict().reference_values_source, expected_source);
    }

    #[tokio::test]
    async fn remote_reference_values_source_falls_back_to_last_good_signed_bundle() {
        let fallback = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let fallback_digest = fallback.payload.digest().unwrap();
        let url = serve_registry_response("{\"not\":\"an envelope\"}".into(), "200 OK").await;
        let expected_source = format!("remote-fallback:{url}");
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_reference_values(url, fallback)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        assert_eq!(client.reference_values_digest(), fallback_digest);
        assert_eq!(client.reference_values_source(), expected_source);
        assert_eq!(verified.verdict().reference_values_digest, fallback_digest);
        assert_eq!(verified.verdict().reference_values_source, expected_source);
    }

    #[tokio::test]
    async fn remote_reference_values_source_persists_and_reuses_last_good_cache() {
        let fallback = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let remote = ReferenceValuesEnvelope::phase2_fixtures().unwrap();
        let remote_digest = remote.payload.digest().unwrap();
        let cache_path = temp_reference_values_cache_path("reuse");

        let remote_url =
            serve_registry_response(serde_json::to_string(&remote).unwrap(), "200 OK").await;
        let expected_remote_source = format!("remote:{remote_url}");
        let remote_client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_reference_values_with_cache(remote_url, fallback.clone(), &cache_path)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        assert_eq!(remote_client.reference_values_digest(), remote_digest);
        assert_eq!(
            remote_client.reference_values_source(),
            expected_remote_source
        );
        assert!(std::fs::read_to_string(&cache_path)
            .unwrap()
            .contains("2026-07-05-phase2-fixtures"));

        let invalid_url =
            serve_registry_response("{\"not\":\"an envelope\"}".into(), "200 OK").await;
        let expected_cache_source = format!("remote-cache:{invalid_url}");
        let cached_client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_reference_values_with_cache(invalid_url, fallback, &cache_path)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = cached_client
            .verify_route("demo", "gpt-oss-120b")
            .await
            .unwrap();

        assert_eq!(cached_client.reference_values_digest(), remote_digest);
        assert_eq!(
            cached_client.reference_values_source(),
            expected_cache_source
        );
        assert_eq!(verified.verdict().reference_values_digest, remote_digest);
        assert_eq!(
            verified.verdict().reference_values_source,
            expected_cache_source
        );

        let _ = std::fs::remove_file(cache_path);
    }

    #[tokio::test]
    async fn remote_reference_values_source_keeps_cache_when_remote_is_stale_relative_to_cache() {
        let fallback = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let cached = ReferenceValuesEnvelope::phase2_fixtures().unwrap();
        let cached_digest = cached.payload.digest().unwrap();
        let cache_path = temp_reference_values_cache_path("stale-remote");
        std::fs::write(&cache_path, serde_json::to_string(&cached).unwrap()).unwrap();

        let stale_remote_url =
            serve_registry_response(serde_json::to_string(&fallback).unwrap(), "200 OK").await;
        let expected_source = format!("remote-cache:{stale_remote_url}");
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_reference_values_with_cache(stale_remote_url, fallback, &cache_path)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        assert_eq!(client.reference_values_digest(), cached_digest);
        assert_eq!(client.reference_values_source(), expected_source);
        assert_eq!(verified.verdict().reference_values_digest, cached_digest);
        assert_eq!(verified.verdict().reference_values_source, expected_source);
        assert!(std::fs::read_to_string(&cache_path)
            .unwrap()
            .contains("2026-07-05-phase2-fixtures"));

        let _ = std::fs::remove_file(cache_path);
    }

    #[tokio::test]
    async fn remote_reference_values_source_ignores_tampered_remote_and_uses_fallback() {
        let fallback = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let fallback_digest = fallback.payload.digest().unwrap();
        let mut tampered = ReferenceValuesEnvelope::phase2_fixtures().unwrap();
        tampered.payload.version.push_str("-tampered");
        let url =
            serve_registry_response(serde_json::to_string(&tampered).unwrap(), "200 OK").await;
        let expected_source = format!("remote-fallback:{url}");
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_reference_values(url, fallback)
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        assert_eq!(client.reference_values_digest(), fallback_digest);
        assert_eq!(client.reference_values_source(), expected_source);
    }

    #[tokio::test]
    async fn remote_reference_values_source_falls_back_when_candidate_signing_identity_is_not_pinned(
    ) {
        let fallback = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let fallback_digest = fallback.payload.digest().unwrap();
        let remote = custom_signed_reference_values();
        let url = serve_registry_response(serde_json::to_string(&remote).unwrap(), "200 OK").await;
        let expected_source = format!("remote-fallback:{url}");
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .remote_reference_values(url, fallback)
            .trusted_artifact_signing_key(custom_trusted_signing_key())
            .reference_values_pin(
                ReferenceValuesPin::new().with_accepted_ed25519_signing_identity(
                    "confidential-inference",
                    DEMO_SIGNING_KEY_ID,
                ),
            )
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        assert_eq!(client.reference_values_digest(), fallback_digest);
        assert_eq!(client.reference_values_source(), expected_source);
    }

    #[tokio::test]
    async fn custom_registry_source_reaches_verdict() {
        let envelope = ProviderRegistryEnvelope::bundled_demo().unwrap();
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .registry_with_source(envelope, "file:///tmp/demo-registry.json")
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        assert_eq!(
            verified.verdict().registry_source,
            "custom:file:///tmp/demo-registry.json"
        );
        assert_eq!(client.registry_signature().signer, "confidential-inference");
        assert_eq!(
            verified.verdict().registry_signature.key_id,
            DEMO_SIGNING_KEY_ID
        );
    }

    #[tokio::test]
    async fn custom_reference_values_source_reaches_verdict() {
        let envelope = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .reference_values_with_source(envelope, "file:///tmp/demo-reference-values.json")
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let verified = client.verify_route("demo", "gpt-oss-120b").await.unwrap();

        assert_eq!(
            client.reference_values_source(),
            "custom:file:///tmp/demo-reference-values.json"
        );
        assert_eq!(
            client.active_trust_artifacts().reference_values_source,
            "custom:file:///tmp/demo-reference-values.json"
        );
        assert_eq!(
            verified.verdict().reference_values_source,
            "custom:file:///tmp/demo-reference-values.json"
        );
    }

    #[test]
    fn client_provider_errors_redact_credentials_and_plaintext() {
        let error = ClientError::Provider(ProviderError::Adapter(
            "Authorization: Bearer sk-live-secret api_key=demo-key prompt=plain completion=answer"
                .into(),
        ));
        let display = error.to_string();
        let debug = format!("{error:?}");

        for rendered in [display, debug] {
            assert!(!rendered.contains("sk-live-secret"));
            assert!(!rendered.contains("demo-key"));
            assert!(!rendered.contains("plain"));
            assert!(!rendered.contains("answer"));
            assert!(rendered.contains("[REDACTED]"));
        }
    }

    #[test]
    fn jsonl_verdict_store_writes_structured_records() {
        let path = std::env::temp_dir().join(format!(
            "confidential-inference-verdict-record-{}.jsonl",
            now_epoch_millis()
        ));
        let store = JsonlVerdictStore::create(&path).unwrap();
        let verdict: AttestationVerdict =
            serde_json::from_str(include_str!("../../../fixtures/verdict/demo-verified.json"))
                .unwrap();
        let record = VerdictRecord::from_verdict(&verdict, false);

        store.persist(&record);
        drop(store);

        let contents = std::fs::read_to_string(&path).unwrap();
        let parsed: VerdictRecord = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(parsed.route_id, verdict.route_id);
        assert_eq!(
            parsed.provider_registry_digest,
            verdict.provider_registry_digest
        );
        assert_eq!(parsed.registry_version, verdict.registry_version);
        assert_eq!(parsed.registry_source, verdict.registry_source);
        assert_eq!(parsed.registry_signature.key_id, DEMO_SIGNING_KEY_ID);
        assert_eq!(parsed.streaming_allowed, verdict.streaming_allowed);
        assert_eq!(
            parsed.route_execution_status,
            verdict.route_execution_status
        );
        assert_eq!(parsed.chat_executable, verdict.chat_executable);
        assert_eq!(
            parsed.known_unsupported_modes,
            verdict.known_unsupported_modes
        );
        assert_eq!(
            parsed.reference_values_signature.key_id,
            DEMO_SIGNING_KEY_ID
        );
        assert_eq!(parsed.verdict_json["schema"], AttestationVerdict::SCHEMA);
        assert!(!contents.contains("prompt"));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn jsonl_audit_sink_writes_structured_records_without_plaintext() {
        let path = std::env::temp_dir().join(format!(
            "confidential-inference-audit-record-{}-{}.jsonl",
            std::process::id(),
            now_epoch_millis()
        ));
        let audit_sink = Arc::new(JsonlAuditSink::create(&path).unwrap());
        let prompt = "jsonl audit secret prompt";
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .audit_sink(audit_sink.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user(prompt))
            .send()
            .await
            .unwrap();

        assert_eq!(response.verdict.status, VerificationStatus::Verified);
        drop(client);
        drop(audit_sink);

        let contents = std::fs::read_to_string(&path).unwrap();
        let records: Vec<AuditEvent> = contents
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|record| record.cache_hit));
        assert!(records.iter().any(|record| !record.cache_hit));
        assert!(records.iter().all(|record| record.provider == "demo"));
        assert!(records
            .iter()
            .all(|record| record.route_id == "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"));
        assert!(records
            .iter()
            .all(|record| record.enforcement == EnforcementMode::Enforce));
        assert!(records
            .iter()
            .all(|record| record.status == VerificationStatus::Verified));
        assert!(records.iter().all(|record| record.request_allowed));
        assert!(records
            .iter()
            .all(|record| !record.would_block_under_enforce));
        assert!(records
            .iter()
            .all(|record| record.registry_source == "bundled"));
        assert!(records
            .iter()
            .all(|record| record.registry_signature.key_id == DEMO_SIGNING_KEY_ID));
        assert!(records
            .iter()
            .all(|record| record.reference_values_source == "bundled"));
        assert!(records
            .iter()
            .all(|record| record.reference_values_signature.key_id == DEMO_SIGNING_KEY_ID));
        assert!(!contents.contains(prompt));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn concurrent_per_session_cache_misses_use_single_flight_verification() {
        let audit = Arc::new(MemoryAuditSink::default());
        let fetches = Arc::new(AtomicUsize::new(0));
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid_with_delay(
                fetches.clone(),
                Duration::from_millis(50),
            ))
            .audit_sink(audit.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let first_client = client.clone();
        let first =
            tokio::spawn(async move { first_client.verify_route("demo", "gpt-oss-120b").await });
        tokio::time::sleep(Duration::from_millis(10)).await;

        let second = client.verify_route("demo", "gpt-oss-120b").await.unwrap();
        let first = first.await.unwrap().unwrap();

        assert_eq!(first.verdict().status, VerificationStatus::Verified);
        assert_eq!(second.verdict().status, VerificationStatus::Verified);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events.iter().filter(|event| !event.cache_hit).count(), 1);
        assert_eq!(events.iter().filter(|event| event.cache_hit).count(), 1);
    }

    #[tokio::test]
    async fn concurrent_chat_on_cloned_client_shares_in_flight_verification() {
        let audit = Arc::new(MemoryAuditSink::default());
        let fetches = Arc::new(AtomicUsize::new(0));
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid_with_delay(
                fetches.clone(),
                Duration::from_millis(50),
            ))
            .audit_sink(audit.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let first_client = client.clone();
        let second_client = client.clone();
        let first = tokio::spawn(async move {
            first_client
                .chat_completions()
                .model("gpt-oss-120b")
                .message(ChatMessage::user("first concurrent prompt"))
                .send()
                .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let second = tokio::spawn(async move {
            second_client
                .chat_completions()
                .model("gpt-oss-120b")
                .message(ChatMessage::user("second concurrent prompt"))
                .send()
                .await
        });

        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();

        assert_eq!(first.verdict.status, VerificationStatus::Verified);
        assert_eq!(second.verdict.status, VerificationStatus::Verified);
        assert!(first.response.choices[0]
            .message
            .content
            .contains("first concurrent prompt"));
        assert!(second.response.choices[0]
            .message
            .content
            .contains("second concurrent prompt"));
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        let events = audit.events.lock().unwrap();
        assert!(events.iter().any(|event| !event.cache_hit));
        assert!(events.iter().any(|event| event.cache_hit));
        assert!(events.iter().all(|event| event.provider == "demo"));
        assert!(events
            .iter()
            .all(|event| event.route_id == "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"));
    }

    #[tokio::test]
    async fn single_flight_rejects_waiters_when_queue_is_full() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let metrics = Arc::new(InMemoryConfidentialInferenceMetricsRecorder::default());
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid(fetches.clone()))
            .metrics_recorder(metrics.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let (route_definition, attested_route) = client
            .select_route(Some("demo"), "gpt-oss-120b", RouteSelectionPurpose::Verify)
            .unwrap();
        let cache_key = VerificationCacheKey::new(
            &route_definition,
            &attested_route,
            VerificationRequestMode::VerifyOnly,
            &client.policy().digest().unwrap(),
            client.registry_digest(),
            client.reference_values_digest(),
        );
        client.inner.in_flight_verifications.lock().unwrap().insert(
            cache_key,
            VerificationFlightState {
                notify: Arc::new(Notify::new()),
                waiters: SINGLE_FLIGHT_MAX_WAITERS,
            },
        );

        let error = match client.verify_route("demo", "gpt-oss-120b").await {
            Ok(_) => panic!("queue-full verification unexpectedly succeeded"),
            Err(error) => error,
        };

        match error {
            ClientError::VerificationWaitQueueFull {
                route_id,
                max_waiters,
            } => {
                assert_eq!(route_id, "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p");
                assert_eq!(max_waiters, SINGLE_FLIGHT_MAX_WAITERS);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 0);
        assert!(metrics.events().iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::SingleFlight(metric)
                if metric.event == ConfidentialInferenceSingleFlightEvent::QueueFull
                    && metric.labels.route_id == "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"
                    && metric.wait_ms.is_none()
        )));
    }

    #[tokio::test]
    async fn single_flight_waiter_times_out_when_owner_is_stuck() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let metrics = Arc::new(InMemoryConfidentialInferenceMetricsRecorder::default());
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid_with_delay(
                fetches.clone(),
                Duration::from_millis(500),
            ))
            .metrics_recorder(metrics.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let owner_client = client.clone();
        let owner =
            tokio::spawn(async move { owner_client.verify_route("demo", "gpt-oss-120b").await });

        for _ in 0..20 {
            if !client
                .inner
                .in_flight_verifications
                .lock()
                .unwrap()
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(!client
            .inner
            .in_flight_verifications
            .lock()
            .unwrap()
            .is_empty());

        let error = match client.verify_route("demo", "gpt-oss-120b").await {
            Ok(_) => panic!("wait-timeout verification unexpectedly succeeded"),
            Err(error) => error,
        };

        match error {
            ClientError::VerificationWaitTimeout { route_id } => {
                assert_eq!(route_id, "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let owner = owner.await.unwrap().unwrap();
        assert_eq!(owner.verdict().status, VerificationStatus::Verified);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert!(client
            .inner
            .in_flight_verifications
            .lock()
            .unwrap()
            .is_empty());
        assert!(metrics.events().iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::SingleFlight(metric)
                if metric.event == ConfidentialInferenceSingleFlightEvent::WaitTimeout
                    && metric.labels.route_id == "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"
                    && metric.wait_ms.is_some()
        )));
    }

    #[tokio::test]
    async fn per_request_freshness_bypasses_verdict_cache() {
        let audit = Arc::new(MemoryAuditSink::default());
        let fetches = Arc::new(AtomicUsize::new(0));
        let evidence_nonces = Arc::new(Mutex::new(Vec::new()));
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.freshness = FreshnessPolicy::PerRequest;
        policy.enforcement = EnforcementMode::Observe;
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid_with_nonce_capture(
                fetches.clone(),
                evidence_nonces.clone(),
            ))
            .audit_sink(audit.clone())
            .policy(policy)
            .allow_insecure_plaintext(true)
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("fresh please"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.verdict.status, VerificationStatus::Failed);
        assert!(response.verdict.request_allowed);
        assert!(response.verdict.would_block_under_enforce);
        assert_eq!(
            response.verdict.check("per_request_freshness"),
            Some(&CheckResult::Failed)
        );

        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        assert!(audit
            .events
            .lock()
            .unwrap()
            .iter()
            .all(|event| !event.cache_hit));
        let nonces = evidence_nonces.lock().unwrap();
        assert_eq!(nonces.len(), 2);
        let first = nonces[0].as_deref().expect("first fetch missing nonce");
        let second = nonces[1].as_deref().expect("second fetch missing nonce");
        assert_ne!(first, second);
        for nonce in [first, second] {
            assert_eq!(nonce.len(), 64);
            assert!(nonce.chars().all(|ch| ch.is_ascii_hexdigit()));
            assert_eq!(nonce, nonce.to_ascii_lowercase());
        }
    }

    #[tokio::test]
    async fn allow_cached_binding_millis_limits_verdict_cache_age() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.freshness = FreshnessPolicy::AllowCachedBindingMillis { millis: Millis(5) };
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid(fetches.clone()))
            .policy(policy)
            .build()
            .await
            .unwrap();

        client.verify_route("demo", "gpt-oss-120b").await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        mutate_first_cached_verdict(&client, |cached| {
            cached.inserted_at = Instant::now()
                .checked_sub(Duration::from_millis(10))
                .unwrap();
        });

        client.verify_route("demo", "gpt-oss-120b").await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn wall_clock_jump_forward_invalidates_cached_verdict() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(AtomicU64::new(now_epoch_millis()));
        let time_source_now = now.clone();
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid(fetches.clone()))
            .time_source(move || time_source_now.load(Ordering::SeqCst))
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        client.verify_route("demo", "gpt-oss-120b").await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        now.fetch_add(
            CACHE_CLOCK_JUMP_REVALIDATION_THRESHOLD_MS * 2,
            Ordering::SeqCst,
        );

        client.verify_route("demo", "gpt-oss-120b").await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn wall_clock_jump_backward_invalidates_cached_verdict() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(AtomicU64::new(now_epoch_millis()));
        let time_source_now = now.clone();
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid(fetches.clone()))
            .time_source(move || time_source_now.load(Ordering::SeqCst))
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        client.verify_route("demo", "gpt-oss-120b").await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        now.fetch_sub(
            CACHE_CLOCK_JUMP_REVALIDATION_THRESHOLD_MS * 2,
            Ordering::SeqCst,
        );

        client.verify_route("demo", "gpt-oss-120b").await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn stale_verdicts_fail_closed_by_default() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid(fetches.clone()))
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        client.verify_route("demo", "gpt-oss-120b").await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        mutate_first_cached_verdict(&client, |cached| {
            set_cached_verdict_expiry(cached, now_epoch_millis().saturating_sub(10));
        });

        client.verify_route("demo", "gpt-oss-120b").await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn explicit_stale_verdict_window_allows_cached_chat_recheck() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.stale_verdicts = StaleVerdictPolicy::AllowForMillis {
            millis: Millis(60_000),
        };
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid(fetches.clone()))
            .policy(policy)
            .build()
            .await
            .unwrap();

        let first_response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("prime explicit stale policy"))
            .send()
            .await
            .unwrap();
        assert_eq!(first_response.provider, "demo");
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        mutate_first_cached_verdict(&client, |cached| {
            set_cached_verdict_expiry(cached, now_epoch_millis().saturating_sub(10));
        });

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("use explicit stale policy"))
            .send()
            .await
            .unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert!(response.verdict.expires_at_epoch_ms < now_epoch_millis());
        assert_eq!(response.provider, "demo");
    }

    #[tokio::test]
    async fn zero_verdict_ttl_bypasses_verdict_cache() {
        let audit = Arc::new(MemoryAuditSink::default());
        let fetches = Arc::new(AtomicUsize::new(0));
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.verdict_ttl_millis = Millis(0);
        let client = ConfidentialInference::builder()
            .with_provider(CountingProvider::valid(fetches.clone()))
            .audit_sink(audit.clone())
            .policy(policy)
            .build()
            .await
            .unwrap();

        client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("no cache"))
            .send()
            .await
            .unwrap();

        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        assert!(audit
            .events
            .lock()
            .unwrap()
            .iter()
            .all(|event| !event.cache_hit));
    }

    #[tokio::test]
    async fn enforcing_policy_blocks_wrong_model_evidence() {
        let audit = Arc::new(MemoryAuditSink::default());
        let verdict_store = Arc::new(MemoryVerdictStore::default());
        let metrics = Arc::new(InMemoryConfidentialInferenceMetricsRecorder::default());
        let client = ConfidentialInference::builder()
            .with_provider(DemoProvider::wrong_model())
            .audit_sink(audit.clone())
            .verdict_store(verdict_store.clone())
            .metrics_recorder(metrics.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let err = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("should fail"))
            .send()
            .await
            .unwrap_err();

        match err {
            ClientError::PolicyDenied { verdict, .. } => {
                assert_eq!(verdict.status, VerificationStatus::Failed);
                assert_eq!(verdict.check("model_binding"), Some(&CheckResult::Failed));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let records = verdict_store.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, VerificationStatus::Failed);
        assert!(!records[0].request_allowed);
        assert!(records[0].would_block_under_enforce);
        assert!(!records[0].cache_hit);
        let events = metrics.events();
        assert!(events.iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::PolicyFailure(metric)
                if metric.labels.provider == "demo"
                    && metric.check == "model_binding"
                    && metric.status == VerificationStatus::Failed
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::Verdict(metric)
                if metric.labels.provider == "demo"
                    && !metric.request_allowed
                    && metric.would_block_under_enforce
        )));
        assert!(!serde_json::to_string(&events)
            .unwrap()
            .contains("should fail"));
        let audit_events = audit.events.lock().unwrap();
        assert_eq!(audit_events.len(), 1);
        assert_eq!(audit_events[0].status, VerificationStatus::Failed);
        assert!(!audit_events[0].request_allowed);
        assert!(audit_events[0].would_block_under_enforce);
        assert!(!audit_events[0].cache_hit);
        assert!(!serde_json::to_string(&*audit_events)
            .unwrap()
            .contains("should fail"));
    }

    #[tokio::test]
    async fn observe_and_disabled_policies_require_explicit_insecure_plaintext_acknowledgement() {
        for enforcement in [EnforcementMode::Observe, EnforcementMode::Disabled] {
            let mut policy = VerificationPolicy::require_attested_e2ee();
            policy.enforcement = enforcement.clone();

            let result = ConfidentialInference::builder()
                .with_demo_provider()
                .policy(policy)
                .build()
                .await;
            let err = match result {
                Ok(_) => panic!("insecure policy build unexpectedly succeeded"),
                Err(error) => error,
            };

            match err {
                ClientError::InsecurePolicyRequiresOptIn {
                    enforcement: actual,
                } => assert_eq!(actual, enforcement),
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn observe_mode_allows_failed_verdict_but_records_status() {
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.enforcement = EnforcementMode::Observe;
        let audit = Arc::new(MemoryAuditSink::default());
        let verdict_store = Arc::new(MemoryVerdictStore::default());
        let client = ConfidentialInference::builder()
            .with_provider(DemoProvider::wrong_key())
            .audit_sink(audit.clone())
            .verdict_store(verdict_store.clone())
            .policy(policy)
            .allow_insecure_plaintext(true)
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("observe mode"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.verdict.status, VerificationStatus::Failed);
        assert!(response.verdict.request_allowed);
        assert_eq!(
            response.verdict.check("e2ee_key_binding"),
            Some(&CheckResult::Failed)
        );

        let records = verdict_store.records.lock().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record.request_allowed));
        assert!(records
            .iter()
            .all(|record| record.status == VerificationStatus::Failed));
        assert!(records
            .iter()
            .all(|record| record.would_block_under_enforce));
        let audit_events = audit.events.lock().unwrap();
        assert_eq!(audit_events.len(), 2);
        assert!(audit_events.iter().all(|event| event.request_allowed));
        assert!(audit_events
            .iter()
            .all(|event| event.status == VerificationStatus::Failed));
        assert!(audit_events
            .iter()
            .all(|event| event.would_block_under_enforce));
        assert!(!serde_json::to_string(&*audit_events)
            .unwrap()
            .contains("observe mode"));
    }

    #[tokio::test]
    async fn disabled_mode_allows_failed_verdict_and_marks_status_disabled() {
        let mut policy = VerificationPolicy::require_attested_e2ee();
        policy.enforcement = EnforcementMode::Disabled;
        let audit = Arc::new(MemoryAuditSink::default());
        let verdict_store = Arc::new(MemoryVerdictStore::default());
        let client = ConfidentialInference::builder()
            .with_provider(DemoProvider::wrong_key())
            .audit_sink(audit.clone())
            .verdict_store(verdict_store.clone())
            .policy(policy)
            .allow_insecure_plaintext(true)
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("disabled mode"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.verdict.status, VerificationStatus::Disabled);
        assert!(response.verdict.request_allowed);
        assert_eq!(
            response.verdict.check("e2ee_key_binding"),
            Some(&CheckResult::Failed)
        );

        let records = verdict_store.records.lock().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record.request_allowed));
        assert!(records
            .iter()
            .all(|record| record.status == VerificationStatus::Disabled));
        assert!(records
            .iter()
            .all(|record| record.would_block_under_enforce));
        let audit_events = audit.events.lock().unwrap();
        assert_eq!(audit_events.len(), 2);
        assert!(audit_events.iter().all(|event| event.request_allowed));
        assert!(audit_events
            .iter()
            .all(|event| event.status == VerificationStatus::Disabled));
        assert!(audit_events
            .iter()
            .all(|event| event.would_block_under_enforce));
        assert!(!serde_json::to_string(&*audit_events)
            .unwrap()
            .contains("disabled mode"));
    }

    #[tokio::test]
    async fn streaming_fails_closed_when_encrypted_route_does_not_support_it() {
        let audit = Arc::new(MemoryAuditSink::default());
        let verdict_store = Arc::new(MemoryVerdictStore::default());
        let metrics = Arc::new(InMemoryConfidentialInferenceMetricsRecorder::default());
        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .audit_sink(audit.clone())
            .verdict_store(verdict_store.clone())
            .metrics_recorder(metrics.clone())
            .policy(VerificationPolicy::require_attested_e2ee())
            .build()
            .await
            .unwrap();

        let err = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("stream please"))
            .stream(true)
            .send()
            .await
            .unwrap_err();

        assert!(matches!(err, ClientError::StreamingNotSupported { .. }));
        assert!(audit.events.lock().unwrap().is_empty());
        assert!(verdict_store.records.lock().unwrap().is_empty());
        assert!(metrics.events().iter().any(|event| matches!(
            event,
            ConfidentialInferenceMetricEvent::StreamingFailClosed(metric)
                if metric.labels.provider == "demo"
                    && metric.labels.route_id == "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"
                    && metric.endpoint == "chat_completions"
        )));
    }

    #[tokio::test]
    async fn tampered_reference_values_fail_client_build() {
        let mut reference_values = ReferenceValuesEnvelope::bundled_demo().unwrap();
        reference_values.payload.version = "tampered".into();

        let result = ConfidentialInference::builder()
            .with_demo_provider()
            .reference_values(reference_values)
            .build()
            .await;

        match result {
            Err(ClientError::Attestation(AttestationError::InvalidArtifactSignature(_))) => {}
            Ok(_) => panic!("tampered reference values unexpectedly built a client"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn custom_trusted_artifact_signing_key_accepts_custom_registry_and_reference_values() {
        let registry = custom_signed_registry();
        let reference_values = custom_signed_reference_values();

        let rejected = ConfidentialInference::builder()
            .with_demo_provider()
            .registry(registry.clone())
            .reference_values(reference_values.clone())
            .build()
            .await;
        assert!(matches!(
            rejected,
            Err(ClientError::Attestation(
                AttestationError::UnknownArtifactSigningKey { .. }
            ))
        ));

        let client = ConfidentialInference::builder()
            .with_demo_provider()
            .registry(registry)
            .reference_values(reference_values)
            .trusted_artifact_signing_key(custom_trusted_signing_key())
            .build()
            .await
            .unwrap();

        let response = client
            .chat_completions()
            .model("gpt-oss-120b")
            .message(ChatMessage::user("custom trusted artifacts"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.verdict.status, VerificationStatus::Verified);
        assert_eq!(response.verdict.registry_signature.signer, "test");
        assert_eq!(response.verdict.reference_values_signature.signer, "test");
    }

    #[tokio::test]
    async fn tampered_registry_fails_client_build() {
        let mut registry = ProviderRegistryEnvelope::bundled_demo().unwrap();
        registry.payload.version = "tampered".into();

        let result = ConfidentialInference::builder()
            .with_demo_provider()
            .registry(registry)
            .build()
            .await;

        match result {
            Err(ClientError::Attestation(AttestationError::InvalidArtifactSignature(_))) => {}
            Ok(_) => panic!("tampered registry unexpectedly built a client"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn signed_invalid_registry_fails_client_build() {
        let mut registry = ProviderRegistryEnvelope::bundled_demo().unwrap();
        registry
            .payload
            .models
            .get_mut("gpt-oss-120b")
            .unwrap()
            .routes[0]
            .alias_confidence = AliasConfidence::Algorithmic;
        registry.signature.value = INVALID_ALGORITHMIC_ALIAS_REGISTRY_SIGNATURE.into();

        let result = ConfidentialInference::builder()
            .with_demo_provider()
            .registry(registry)
            .build()
            .await;

        match result {
            Err(ClientError::Attestation(AttestationError::InvalidProviderRegistry(_))) => {}
            Ok(_) => panic!("invalid registry unexpectedly built a client"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
}
