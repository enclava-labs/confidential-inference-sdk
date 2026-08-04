use async_trait::async_trait;
use confidential_inference_attestation::{
    sha256_digest, DcapTdxCollateralBundle, DcapTdxCollateralBundleEnvelope,
    DcapTdxCollateralCache, DcapTdxCollateralSource, DcapTdxTinfoilQuoteVerifier,
    TrustedSigningKey,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tracing::Instrument;

use crate::{ProviderError, Result};

#[derive(Clone)]
struct DcapReqwestHttp(reqwest::Client);

impl dcap_qvl::http::HttpClient for DcapReqwestHttp {
    async fn get(&self, url: &str) -> anyhow::Result<dcap_qvl::http::HttpResponse> {
        let response = self.0.get(url).send().await?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| Ok((name.as_str().to_owned(), value.to_str()?.to_owned())))
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let body = response.bytes().await?.to_vec();
        Ok(dcap_qvl::http::HttpResponse {
            status,
            headers,
            body,
        })
    }
}

const DEFAULT_DCAP_TDX_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_DCAP_TDX_FETCH_ATTEMPTS: usize = 2;
const DEFAULT_DCAP_TDX_FETCH_INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const DEFAULT_DCAP_TDX_FETCH_MAX_BACKOFF: Duration = Duration::from_secs(2);
const DEFAULT_DCAP_TDX_MAX_CONCURRENT_FETCHES: usize = 4;
const DEFAULT_DCAP_TDX_MAX_QUEUED_FETCHES: usize = 16;
const DEFAULT_DCAP_TDX_FETCH_QUEUE_TIMEOUT: Duration = Duration::from_secs(30);

#[async_trait]
pub trait DcapTdxCollateralFetcher: Send + Sync {
    async fn fetch_bundle_at(
        &self,
        quote_bytes: &[u8],
        fetched_at_epoch_ms: u64,
    ) -> Result<DcapTdxCollateralBundle>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DcapTdxCollateralCacheEvent {
    MemoryHit,
    FileHit,
    Miss,
    Invalidated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DcapTdxCollateralQueueEvent {
    Acquired,
    Wait,
    Full,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DcapTdxCollateralFetchEvent {
    Success,
    Retry,
    Failure,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcapTdxCollateralCacheMetric {
    pub quote_sha256: String,
    pub event: DcapTdxCollateralCacheEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcapTdxCollateralQueueMetric {
    pub event: DcapTdxCollateralQueueEvent,
    pub queued_fetches: Option<usize>,
    pub max_queued_fetches: usize,
    pub wait_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcapTdxCollateralFetchMetric {
    pub quote_sha256: String,
    pub attempt: usize,
    pub max_attempts: usize,
    pub event: DcapTdxCollateralFetchEvent,
    pub duration_ms: u64,
    pub backoff_ms: Option<u64>,
    pub error_kind: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum DcapTdxCollateralMetricEvent {
    Cache(DcapTdxCollateralCacheMetric),
    Queue(DcapTdxCollateralQueueMetric),
    Fetch(DcapTdxCollateralFetchMetric),
}

pub trait DcapTdxCollateralMetricsRecorder: Send + Sync {
    fn record(&self, event: &DcapTdxCollateralMetricEvent);
}

#[derive(Debug)]
pub struct NoopDcapTdxCollateralMetricsRecorder;

impl DcapTdxCollateralMetricsRecorder for NoopDcapTdxCollateralMetricsRecorder {
    fn record(&self, _event: &DcapTdxCollateralMetricEvent) {}
}

#[derive(Debug, Default)]
pub struct InMemoryDcapTdxCollateralMetricsRecorder {
    events: Mutex<Vec<DcapTdxCollateralMetricEvent>>,
}

impl InMemoryDcapTdxCollateralMetricsRecorder {
    pub fn events(&self) -> Vec<DcapTdxCollateralMetricEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

impl DcapTdxCollateralMetricsRecorder for InMemoryDcapTdxCollateralMetricsRecorder {
    fn record(&self, event: &DcapTdxCollateralMetricEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event.clone());
        }
    }
}

#[derive(Clone)]
pub struct PccsDcapTdxCollateralFetcher {
    client:
        dcap_qvl::collateral::CollateralClient<dcap_qvl::configs::DefaultConfig, DcapReqwestHttp>,
    source: DcapTdxCollateralSource,
}

impl PccsDcapTdxCollateralFetcher {
    pub fn with_default_http(pccs_url: impl Into<String>) -> Result<Self> {
        install_default_rustls_provider();
        let client = reqwest::Client::builder()
            .build()
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        Ok(Self::with_reqwest_client(pccs_url, client))
    }

    pub fn with_reqwest_client(pccs_url: impl Into<String>, client: reqwest::Client) -> Self {
        let pccs_url = pccs_url.into();
        Self::new(
            dcap_qvl::collateral::CollateralClient::new(DcapReqwestHttp(client), pccs_url.clone()),
            pccs_url,
        )
    }

    fn new(
        client: dcap_qvl::collateral::CollateralClient<
            dcap_qvl::configs::DefaultConfig,
            DcapReqwestHttp,
        >,
        pccs_url: String,
    ) -> Self {
        Self {
            client,
            source: DcapTdxCollateralSource::pccs(pccs_url),
        }
    }
}

fn install_default_rustls_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

impl Debug for PccsDcapTdxCollateralFetcher {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PccsDcapTdxCollateralFetcher")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DcapTdxCollateralFetcher for PccsDcapTdxCollateralFetcher {
    async fn fetch_bundle_at(
        &self,
        quote_bytes: &[u8],
        fetched_at_epoch_ms: u64,
    ) -> Result<DcapTdxCollateralBundle> {
        let collateral = self
            .client
            .fetch(quote_bytes)
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        DcapTdxCollateralBundle::from_collateral_at(
            collateral,
            fetched_at_epoch_ms,
            self.source.clone(),
            Some(quote_bytes),
        )
        .map_err(provider_attestation_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcapTdxCollateralFetchPolicy {
    max_attempts: usize,
    per_attempt_timeout: Option<Duration>,
    initial_backoff: Duration,
    max_backoff: Duration,
    max_concurrent_fetches: usize,
    max_queued_fetches: usize,
    queue_timeout: Option<Duration>,
}

impl DcapTdxCollateralFetchPolicy {
    pub fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    pub fn per_attempt_timeout(&self) -> Option<Duration> {
        self.per_attempt_timeout
    }

    pub fn initial_backoff(&self) -> Duration {
        self.initial_backoff
    }

    pub fn max_backoff(&self) -> Duration {
        self.max_backoff
    }

    pub fn max_concurrent_fetches(&self) -> usize {
        self.max_concurrent_fetches
    }

    pub fn max_queued_fetches(&self) -> usize {
        self.max_queued_fetches
    }

    pub fn queue_timeout(&self) -> Option<Duration> {
        self.queue_timeout
    }

    pub fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts.max(1);
        self
    }

    pub fn with_per_attempt_timeout(mut self, timeout: Duration) -> Self {
        self.per_attempt_timeout = Some(timeout);
        self
    }

    pub fn without_per_attempt_timeout(mut self) -> Self {
        self.per_attempt_timeout = None;
        self
    }

    pub fn with_backoff(mut self, initial_backoff: Duration, max_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self.max_backoff = max_backoff.max(initial_backoff);
        self
    }

    pub fn with_max_concurrent_fetches(mut self, max_concurrent_fetches: usize) -> Self {
        self.max_concurrent_fetches = max_concurrent_fetches.max(1);
        self
    }

    pub fn with_max_queued_fetches(mut self, max_queued_fetches: usize) -> Self {
        self.max_queued_fetches = max_queued_fetches;
        self
    }

    pub fn with_queue_timeout(mut self, timeout: Duration) -> Self {
        self.queue_timeout = Some(timeout);
        self
    }

    pub fn without_queue_timeout(mut self) -> Self {
        self.queue_timeout = None;
        self
    }
}

impl Default for DcapTdxCollateralFetchPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_DCAP_TDX_FETCH_ATTEMPTS,
            per_attempt_timeout: Some(DEFAULT_DCAP_TDX_FETCH_TIMEOUT),
            initial_backoff: DEFAULT_DCAP_TDX_FETCH_INITIAL_BACKOFF,
            max_backoff: DEFAULT_DCAP_TDX_FETCH_MAX_BACKOFF,
            max_concurrent_fetches: DEFAULT_DCAP_TDX_MAX_CONCURRENT_FETCHES,
            max_queued_fetches: DEFAULT_DCAP_TDX_MAX_QUEUED_FETCHES,
            queue_timeout: Some(DEFAULT_DCAP_TDX_FETCH_QUEUE_TIMEOUT),
        }
    }
}

#[derive(Clone)]
pub struct DcapTdxCollateralResolver {
    fetcher: Arc<dyn DcapTdxCollateralFetcher>,
    memory_cache: Arc<Mutex<DcapTdxCollateralCache>>,
    cache_dir: Option<PathBuf>,
    fetch_policy: DcapTdxCollateralFetchPolicy,
    fetch_permits: Arc<Semaphore>,
    queued_fetches: Arc<AtomicUsize>,
    metrics_recorder: Arc<dyn DcapTdxCollateralMetricsRecorder>,
}

impl DcapTdxCollateralResolver {
    pub fn from_fetcher<F>(fetcher: F) -> Self
    where
        F: DcapTdxCollateralFetcher + 'static,
    {
        Self::new(Arc::new(fetcher))
    }

    pub fn new(fetcher: Arc<dyn DcapTdxCollateralFetcher>) -> Self {
        let fetch_policy = DcapTdxCollateralFetchPolicy::default();
        let fetch_permits = Arc::new(Semaphore::new(fetch_policy.max_concurrent_fetches));
        Self {
            fetcher,
            memory_cache: Arc::new(Mutex::new(DcapTdxCollateralCache::new())),
            cache_dir: None,
            fetch_policy,
            fetch_permits,
            queued_fetches: Arc::new(AtomicUsize::new(0)),
            metrics_recorder: Arc::new(NoopDcapTdxCollateralMetricsRecorder),
        }
    }

    pub fn with_phala_pccs() -> Result<Self> {
        Self::with_pccs_url(dcap_qvl::collateral::PHALA_PCCS_URL)
    }

    pub fn with_intel_pcs() -> Result<Self> {
        Self::with_pccs_url(dcap_qvl::collateral::INTEL_PCS_URL)
    }

    pub fn with_pccs_url(pccs_url: impl Into<String>) -> Result<Self> {
        Ok(Self::from_fetcher(
            PccsDcapTdxCollateralFetcher::with_default_http(pccs_url)?,
        ))
    }

    pub fn with_cache_dir(mut self, cache_dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(cache_dir.into());
        self
    }

    pub fn with_memory_cache(mut self, cache: DcapTdxCollateralCache) -> Self {
        self.memory_cache = Arc::new(Mutex::new(cache));
        self
    }

    pub fn with_offline_bundle_for_quote(
        self,
        quote_bytes: &[u8],
        bundle: DcapTdxCollateralBundle,
    ) -> Result<Self> {
        self.insert_memory_bundle(quote_bytes, bundle)?;
        Ok(self)
    }

    pub fn with_signed_offline_bundle_for_quote(
        self,
        quote_bytes: &[u8],
        envelope: DcapTdxCollateralBundleEnvelope,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> Result<Self> {
        let bundle = envelope
            .into_verified_bundle_with_keys(trusted_signing_keys)
            .map_err(provider_attestation_error)?;
        self.with_offline_bundle_for_quote(quote_bytes, bundle)
    }

    pub fn with_fetch_policy(mut self, policy: DcapTdxCollateralFetchPolicy) -> Self {
        self.fetch_permits = Arc::new(Semaphore::new(policy.max_concurrent_fetches));
        self.queued_fetches = Arc::new(AtomicUsize::new(0));
        self.fetch_policy = policy;
        self
    }

    pub fn with_metrics_recorder(
        mut self,
        metrics_recorder: Arc<dyn DcapTdxCollateralMetricsRecorder>,
    ) -> Self {
        self.metrics_recorder = metrics_recorder;
        self
    }

    pub fn cache_dir(&self) -> Option<&Path> {
        self.cache_dir.as_deref()
    }

    pub fn fetch_policy(&self) -> &DcapTdxCollateralFetchPolicy {
        &self.fetch_policy
    }

    pub async fn verifier_for_quote(
        &self,
        quote_bytes: &[u8],
    ) -> Result<DcapTdxTinfoilQuoteVerifier> {
        self.verifier_for_quote_at(quote_bytes, now_epoch_millis())
            .await
    }

    pub async fn verifier_for_quote_at(
        &self,
        quote_bytes: &[u8],
        now_epoch_ms: u64,
    ) -> Result<DcapTdxTinfoilQuoteVerifier> {
        let quote_digest = sha256_digest(quote_bytes);
        let quote_digest_for_span = quote_digest.clone();
        async move {
            if let Some(verifier) = self.memory_verifier_for_quote(quote_bytes, now_epoch_ms)? {
                tracing::debug!(cache_hit = "memory", "using TDX collateral memory cache");
                self.record_cache_metric(&quote_digest, DcapTdxCollateralCacheEvent::MemoryHit);
                return Ok(verifier);
            }

            if let Some(verifier) = self.file_verifier_for_quote(quote_bytes, now_epoch_ms)? {
                tracing::debug!(cache_hit = "file", "using TDX collateral file cache");
                self.record_cache_metric(&quote_digest, DcapTdxCollateralCacheEvent::FileHit);
                return Ok(verifier);
            }

            tracing::debug!("TDX collateral cache miss");
            self.record_cache_metric(&quote_digest, DcapTdxCollateralCacheEvent::Miss);
            let _permit = self.acquire_fetch_slot().await?;
            let bundle = self
                .fetch_bundle_with_policy(quote_bytes, now_epoch_ms)
                .await?;
            self.insert_memory_bundle(quote_bytes, bundle.clone())?;
            self.write_file_bundle(quote_bytes, &bundle)?;
            bundle
                .verifier_at(now_epoch_ms)
                .map_err(provider_attestation_error)
        }
        .instrument(tracing::info_span!(
            "confidential-inference.dcap_tdx.collateral_resolve",
            quote_sha256 = %quote_digest_for_span,
            now_epoch_ms
        ))
        .await
    }

    async fn acquire_fetch_slot(&self) -> Result<OwnedSemaphorePermit> {
        match self.fetch_permits.clone().try_acquire_owned() {
            Ok(permit) => {
                tracing::debug!("acquired TDX collateral fetch slot");
                self.record_queue_metric(DcapTdxCollateralQueueMetric {
                    event: DcapTdxCollateralQueueEvent::Acquired,
                    queued_fetches: None,
                    max_queued_fetches: self.fetch_policy.max_queued_fetches,
                    wait_ms: None,
                });
                Ok(permit)
            }
            Err(TryAcquireError::NoPermits) => self.wait_for_fetch_slot().await,
            Err(TryAcquireError::Closed) => Err(ProviderError::Adapter(
                "TDX collateral fetch queue was closed".into(),
            )),
        }
    }

    async fn wait_for_fetch_slot(&self) -> Result<OwnedSemaphorePermit> {
        let (queued, _queue_guard) = QueuedFetchGuard::enter(self.queued_fetches.as_ref());
        let wait_started_at = std::time::Instant::now();
        let queued_fetches = queued + 1;
        tracing::debug!(queued_fetches, "waiting for TDX collateral fetch slot");
        self.record_queue_metric(DcapTdxCollateralQueueMetric {
            event: DcapTdxCollateralQueueEvent::Wait,
            queued_fetches: Some(queued_fetches),
            max_queued_fetches: self.fetch_policy.max_queued_fetches,
            wait_ms: None,
        });
        if queued >= self.fetch_policy.max_queued_fetches {
            tracing::warn!(
                max_queued_fetches = self.fetch_policy.max_queued_fetches,
                "TDX collateral fetch queue is full"
            );
            self.record_queue_metric(DcapTdxCollateralQueueMetric {
                event: DcapTdxCollateralQueueEvent::Full,
                queued_fetches: Some(queued_fetches),
                max_queued_fetches: self.fetch_policy.max_queued_fetches,
                wait_ms: Some(duration_millis(wait_started_at.elapsed())),
            });
            return Err(ProviderError::Adapter(format!(
                "TDX collateral fetch queue is full ({}/{})",
                self.fetch_policy.max_queued_fetches, self.fetch_policy.max_queued_fetches
            )));
        }

        let acquire = self.fetch_permits.clone().acquire_owned();
        let result = match self.fetch_policy.queue_timeout {
            Some(timeout) if !timeout.is_zero() => {
                match tokio::time::timeout(timeout, acquire).await {
                    Ok(result) => result,
                    Err(_) => {
                        tracing::warn!(
                            timeout_ms = timeout.as_millis() as u64,
                            "TDX collateral fetch queue timed out"
                        );
                        self.record_queue_metric(DcapTdxCollateralQueueMetric {
                            event: DcapTdxCollateralQueueEvent::Timeout,
                            queued_fetches: Some(queued_fetches),
                            max_queued_fetches: self.fetch_policy.max_queued_fetches,
                            wait_ms: Some(duration_millis(wait_started_at.elapsed())),
                        });
                        return Err(ProviderError::Adapter(format!(
                            "TDX collateral fetch queue timed out after {}ms",
                            timeout.as_millis()
                        )));
                    }
                }
            }
            _ => acquire.await,
        };
        result
            .inspect(|_| {
                self.record_queue_metric(DcapTdxCollateralQueueMetric {
                    event: DcapTdxCollateralQueueEvent::Acquired,
                    queued_fetches: Some(queued_fetches),
                    max_queued_fetches: self.fetch_policy.max_queued_fetches,
                    wait_ms: Some(duration_millis(wait_started_at.elapsed())),
                });
            })
            .map_err(|_| ProviderError::Adapter("TDX collateral fetch queue was closed".into()))
    }

    async fn fetch_bundle_with_policy(
        &self,
        quote_bytes: &[u8],
        fetched_at_epoch_ms: u64,
    ) -> Result<DcapTdxCollateralBundle> {
        let quote_digest = sha256_digest(quote_bytes);
        let quote_digest_for_span = quote_digest.clone();
        async move {
            let max_attempts = self.fetch_policy.max_attempts.max(1);
            let mut attempt = 1;
            let mut backoff = self.fetch_policy.initial_backoff;

            loop {
                tracing::debug!(attempt, max_attempts, "fetching TDX collateral bundle");
                let attempt_started_at = std::time::Instant::now();
                let result = self
                    .fetch_bundle_once(quote_bytes, fetched_at_epoch_ms)
                    .await;
                match result {
                    Ok(bundle) => {
                        self.record_fetch_metric(DcapTdxCollateralFetchMetric {
                            quote_sha256: quote_digest.clone(),
                            attempt,
                            max_attempts,
                            event: DcapTdxCollateralFetchEvent::Success,
                            duration_ms: duration_millis(attempt_started_at.elapsed()),
                            backoff_ms: None,
                            error_kind: None,
                        });
                        tracing::debug!(attempt, "TDX collateral fetch succeeded");
                        return Ok(bundle);
                    }
                    Err(error) if attempt < max_attempts && should_retry_fetch_error(&error) => {
                        self.record_fetch_metric(DcapTdxCollateralFetchMetric {
                            quote_sha256: quote_digest.clone(),
                            attempt,
                            max_attempts,
                            event: DcapTdxCollateralFetchEvent::Retry,
                            duration_ms: duration_millis(attempt_started_at.elapsed()),
                            backoff_ms: Some(duration_millis(backoff)),
                            error_kind: Some(provider_error_kind(&error).into()),
                        });
                        tracing::warn!(
                            attempt,
                            max_attempts,
                            backoff_ms = backoff.as_millis() as u64,
                            error = %error,
                            "retrying TDX collateral fetch"
                        );
                        if !backoff.is_zero() {
                            tokio::time::sleep(backoff).await;
                        }
                        backoff = next_backoff(backoff, self.fetch_policy.max_backoff);
                        attempt += 1;
                    }
                    Err(error) if should_retry_fetch_error(&error) && max_attempts > 1 => {
                        self.record_fetch_metric(DcapTdxCollateralFetchMetric {
                            quote_sha256: quote_digest.clone(),
                            attempt,
                            max_attempts,
                            event: DcapTdxCollateralFetchEvent::Failure,
                            duration_ms: duration_millis(attempt_started_at.elapsed()),
                            backoff_ms: None,
                            error_kind: Some(provider_error_kind(&error).into()),
                        });
                        tracing::warn!(
                            attempt,
                            max_attempts,
                            error = %error,
                            "TDX collateral fetch attempts exhausted"
                        );
                        return Err(ProviderError::Http(format!(
                            "TDX collateral fetch failed after {attempt} attempts: {error}"
                        )));
                    }
                    Err(error) => {
                        self.record_fetch_metric(DcapTdxCollateralFetchMetric {
                            quote_sha256: quote_digest.clone(),
                            attempt,
                            max_attempts,
                            event: DcapTdxCollateralFetchEvent::Failure,
                            duration_ms: duration_millis(attempt_started_at.elapsed()),
                            backoff_ms: None,
                            error_kind: Some(provider_error_kind(&error).into()),
                        });
                        return Err(error);
                    }
                }
            }
        }
        .instrument(tracing::info_span!(
            "confidential-inference.dcap_tdx.collateral_fetch",
            quote_sha256 = %quote_digest_for_span,
            fetched_at_epoch_ms
        ))
        .await
    }

    async fn fetch_bundle_once(
        &self,
        quote_bytes: &[u8],
        fetched_at_epoch_ms: u64,
    ) -> Result<DcapTdxCollateralBundle> {
        let fetch = self
            .fetcher
            .fetch_bundle_at(quote_bytes, fetched_at_epoch_ms);
        let Some(timeout) = self.fetch_policy.per_attempt_timeout else {
            return fetch.await;
        };
        if timeout.is_zero() {
            return fetch.await;
        }
        tokio::time::timeout(timeout, fetch).await.map_err(|_| {
            tracing::warn!(
                timeout_ms = timeout.as_millis() as u64,
                "TDX collateral fetch timed out"
            );
            ProviderError::Http(format!(
                "TDX collateral fetch timed out after {}ms",
                timeout.as_millis()
            ))
        })?
    }

    fn memory_verifier_for_quote(
        &self,
        quote_bytes: &[u8],
        now_epoch_ms: u64,
    ) -> Result<Option<DcapTdxTinfoilQuoteVerifier>> {
        let cache = self
            .memory_cache
            .lock()
            .map_err(|_| ProviderError::Adapter("TDX collateral cache lock is poisoned".into()))?;
        let Some(bundle) = cache.bundle_for_quote(quote_bytes) else {
            return Ok(None);
        };
        if !bundle.is_valid_at(now_epoch_ms) {
            return Ok(None);
        }
        bundle
            .verifier_at(now_epoch_ms)
            .map(Some)
            .map_err(provider_attestation_error)
    }

    fn file_verifier_for_quote(
        &self,
        quote_bytes: &[u8],
        now_epoch_ms: u64,
    ) -> Result<Option<DcapTdxTinfoilQuoteVerifier>> {
        let Some(path) = self.cache_path_for_quote(quote_bytes)? else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }

        let key = sha256_digest(quote_bytes);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(ProviderError::Adapter(format!(
                    "failed to read TDX collateral cache {}: {error}",
                    path.display()
                )));
            }
        };

        let bundle = match DcapTdxCollateralBundle::from_json(&bytes) {
            Ok(bundle) => bundle,
            Err(_) => {
                remove_cache_file(&path)?;
                self.record_cache_metric(&key, DcapTdxCollateralCacheEvent::Invalidated);
                return Ok(None);
            }
        };
        if bundle.quote_sha256() != Some(key.as_str()) {
            remove_cache_file(&path)?;
            self.record_cache_metric(&key, DcapTdxCollateralCacheEvent::Invalidated);
            return Ok(None);
        }
        if !bundle.is_valid_at(now_epoch_ms) {
            remove_cache_file(&path)?;
            self.record_cache_metric(&key, DcapTdxCollateralCacheEvent::Invalidated);
            return Ok(None);
        }

        self.insert_memory_bundle(quote_bytes, bundle.clone())?;
        bundle
            .verifier_at(now_epoch_ms)
            .map(Some)
            .map_err(provider_attestation_error)
    }

    fn insert_memory_bundle(
        &self,
        quote_bytes: &[u8],
        bundle: DcapTdxCollateralBundle,
    ) -> Result<()> {
        self.memory_cache
            .lock()
            .map_err(|_| ProviderError::Adapter("TDX collateral cache lock is poisoned".into()))?
            .insert_for_quote(quote_bytes, bundle)
            .map_err(provider_attestation_error)
    }

    fn write_file_bundle(
        &self,
        quote_bytes: &[u8],
        bundle: &DcapTdxCollateralBundle,
    ) -> Result<()> {
        let Some(path) = self.cache_path_for_quote(quote_bytes)? else {
            return Ok(());
        };
        let Some(parent) = path.parent() else {
            return Err(ProviderError::Adapter(
                "TDX collateral cache path has no parent directory".into(),
            ));
        };
        fs::create_dir_all(parent).map_err(|error| {
            ProviderError::Adapter(format!(
                "failed to create TDX collateral cache directory {}: {error}",
                parent.display()
            ))
        })?;
        let bytes = bundle.to_json().map_err(provider_attestation_error)?;
        let temp_path = path.with_extension(format!("json.tmp-{}", std::process::id()));
        fs::write(&temp_path, bytes).map_err(|error| {
            ProviderError::Adapter(format!(
                "failed to write TDX collateral cache {}: {error}",
                temp_path.display()
            ))
        })?;
        fs::rename(&temp_path, &path).map_err(|error| {
            ProviderError::Adapter(format!(
                "failed to commit TDX collateral cache {}: {error}",
                path.display()
            ))
        })?;
        Ok(())
    }

    fn cache_path_for_quote(&self, quote_bytes: &[u8]) -> Result<Option<PathBuf>> {
        let Some(cache_dir) = &self.cache_dir else {
            return Ok(None);
        };
        let digest = sha256_digest(quote_bytes);
        let filename = cache_filename_for_digest(&digest)?;
        Ok(Some(cache_dir.join(filename)))
    }

    fn record_cache_metric(&self, quote_sha256: &str, event: DcapTdxCollateralCacheEvent) {
        tracing::info!(
            target: "confidential_inference.metrics",
            metric = "dcap_tdx_collateral_cache",
            quote_sha256 = %quote_sha256,
            event = ?event,
        );
        self.metrics_recorder
            .record(&DcapTdxCollateralMetricEvent::Cache(
                DcapTdxCollateralCacheMetric {
                    quote_sha256: quote_sha256.to_owned(),
                    event,
                },
            ));
    }

    fn record_queue_metric(&self, metric: DcapTdxCollateralQueueMetric) {
        tracing::info!(
            target: "confidential_inference.metrics",
            metric = "dcap_tdx_collateral_queue",
            event = ?metric.event,
            queued_fetches = ?metric.queued_fetches,
            max_queued_fetches = metric.max_queued_fetches,
            wait_ms = ?metric.wait_ms,
        );
        self.metrics_recorder
            .record(&DcapTdxCollateralMetricEvent::Queue(metric));
    }

    fn record_fetch_metric(&self, metric: DcapTdxCollateralFetchMetric) {
        tracing::info!(
            target: "confidential_inference.metrics",
            metric = "dcap_tdx_collateral_fetch",
            quote_sha256 = %metric.quote_sha256,
            attempt = metric.attempt,
            event = ?metric.event,
            duration_ms = metric.duration_ms,
        );
        self.metrics_recorder
            .record(&DcapTdxCollateralMetricEvent::Fetch(metric));
    }
}

impl Debug for DcapTdxCollateralResolver {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DcapTdxCollateralResolver")
            .field("cache_dir", &self.cache_dir)
            .field("fetch_policy", &self.fetch_policy)
            .finish_non_exhaustive()
    }
}

fn cache_filename_for_digest(digest: &str) -> Result<String> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(ProviderError::Adapter(
            "TDX collateral cache key is not a sha256 digest".into(),
        ));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProviderError::Adapter(
            "TDX collateral cache key is not valid hex".into(),
        ));
    }
    Ok(format!("sha256-{hex}.json"))
}

fn remove_cache_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ProviderError::Adapter(format!(
            "failed to remove stale TDX collateral cache {}: {error}",
            path.display()
        ))),
    }
}

fn provider_attestation_error(
    error: confidential_inference_attestation::AttestationError,
) -> ProviderError {
    ProviderError::Compatibility(error.to_string())
}

fn provider_error_kind(error: &ProviderError) -> &'static str {
    match error {
        ProviderError::Unavailable(_) => "unavailable",
        ProviderError::Adapter(_) => "adapter",
        ProviderError::Compatibility(_) => "compatibility",
        ProviderError::KeyRotation { .. } => "key_rotation",
        ProviderError::Http(_) => "http",
        ProviderError::HttpStatus { .. } => "http_status",
        ProviderError::Json(_) => "json",
    }
}

fn should_retry_fetch_error(error: &ProviderError) -> bool {
    error.is_retryable_outage()
}

fn next_backoff(current: Duration, max_backoff: Duration) -> Duration {
    if current.is_zero() || max_backoff.is_zero() {
        return Duration::ZERO;
    }
    current
        .checked_mul(2)
        .unwrap_or(max_backoff)
        .min(max_backoff)
}

struct QueuedFetchGuard<'a> {
    queued_fetches: &'a AtomicUsize,
}

impl<'a> QueuedFetchGuard<'a> {
    fn enter(queued_fetches: &'a AtomicUsize) -> (usize, Self) {
        let queued = queued_fetches.fetch_add(1, Ordering::SeqCst);
        (queued, Self { queued_fetches })
    }
}

impl Drop for QueuedFetchGuard<'_> {
    fn drop(&mut self) {
        self.queued_fetches.fetch_sub(1, Ordering::SeqCst);
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
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use confidential_inference_attestation::{
        canonical_json, parse_utc_timestamp_millis, ArtifactSignature,
    };
    use ed25519_compact::{KeyPair, Seed};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SAMPLE_QUOTE: &[u8] = include_bytes!("../../../fixtures/evidence/dcap-qvl/tdx_quote.bin");
    const SAMPLE_COLLATERAL: &[u8] =
        include_bytes!("../../../fixtures/evidence/dcap-qvl/tdx_quote_collateral.json");

    #[derive(Clone)]
    struct StaticFetcher {
        fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DcapTdxCollateralFetcher for StaticFetcher {
        async fn fetch_bundle_at(
            &self,
            quote_bytes: &[u8],
            fetched_at_epoch_ms: u64,
        ) -> Result<DcapTdxCollateralBundle> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            sample_bundle_at(quote_bytes, fetched_at_epoch_ms)
        }
    }

    #[derive(Clone)]
    struct FlakyFetcher {
        attempts: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DcapTdxCollateralFetcher for FlakyFetcher {
        async fn fetch_bundle_at(
            &self,
            quote_bytes: &[u8],
            fetched_at_epoch_ms: u64,
        ) -> Result<DcapTdxCollateralBundle> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt == 1 {
                return Err(ProviderError::Http("transient PCCS outage".into()));
            }
            sample_bundle_at(quote_bytes, fetched_at_epoch_ms)
        }
    }

    #[derive(Clone)]
    struct InvalidCollateralFetcher {
        attempts: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DcapTdxCollateralFetcher for InvalidCollateralFetcher {
        async fn fetch_bundle_at(
            &self,
            _quote_bytes: &[u8],
            _fetched_at_epoch_ms: u64,
        ) -> Result<DcapTdxCollateralBundle> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Err(ProviderError::Compatibility(
                "invalid TDX collateral fixture".into(),
            ))
        }
    }

    #[derive(Clone)]
    struct SlowFetcher {
        started: Arc<AtomicUsize>,
        completed: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DcapTdxCollateralFetcher for SlowFetcher {
        async fn fetch_bundle_at(
            &self,
            quote_bytes: &[u8],
            fetched_at_epoch_ms: u64,
        ) -> Result<DcapTdxCollateralBundle> {
            self.started.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(100)).await;
            self.completed.fetch_add(1, Ordering::SeqCst);
            sample_bundle_at(quote_bytes, fetched_at_epoch_ms)
        }
    }

    #[tokio::test]
    async fn resolver_uses_memory_cache_before_fetching() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let collateral = serde_json::from_slice(SAMPLE_COLLATERAL).unwrap();
        let bundle = DcapTdxCollateralBundle::from_collateral_at(
            collateral,
            now,
            DcapTdxCollateralSource::offline_bundle(),
            Some(SAMPLE_QUOTE),
        )
        .unwrap();
        let mut cache = DcapTdxCollateralCache::new();
        cache.insert_for_quote(SAMPLE_QUOTE, bundle).unwrap();
        let fetches = Arc::new(AtomicUsize::new(0));
        let resolver = DcapTdxCollateralResolver::from_fetcher(StaticFetcher {
            fetches: fetches.clone(),
        })
        .with_memory_cache(cache);

        let verifier = resolver
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .await
            .unwrap();

        assert_eq!(fetches.load(Ordering::SeqCst), 0);
        assert_eq!(
            verifier.collateral_valid_until_epoch_millis().unwrap(),
            parse_utc_timestamp_millis("2025-07-19T10:00:35Z").unwrap()
        );
    }

    #[tokio::test]
    async fn resolver_uses_signed_offline_bundle_before_fetching() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let bundle = sample_offline_bundle_at(SAMPLE_QUOTE, now);
        let (envelope, trusted_key) = signed_test_envelope(bundle);
        let fetches = Arc::new(AtomicUsize::new(0));
        let resolver = DcapTdxCollateralResolver::from_fetcher(StaticFetcher {
            fetches: fetches.clone(),
        })
        .with_signed_offline_bundle_for_quote(SAMPLE_QUOTE, envelope, &[trusted_key])
        .unwrap();

        let verifier = resolver
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .await
            .unwrap();

        assert_eq!(fetches.load(Ordering::SeqCst), 0);
        assert_eq!(
            verifier.collateral_valid_until_epoch_millis().unwrap(),
            parse_utc_timestamp_millis("2025-07-19T10:00:35Z").unwrap()
        );
    }

    #[test]
    fn resolver_rejects_untrusted_signed_offline_bundle() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let bundle = sample_offline_bundle_at(SAMPLE_QUOTE, now);
        let (envelope, _trusted_key) = signed_test_envelope(bundle);
        let fetches = Arc::new(AtomicUsize::new(0));

        let error = DcapTdxCollateralResolver::from_fetcher(StaticFetcher {
            fetches: fetches.clone(),
        })
        .with_signed_offline_bundle_for_quote(SAMPLE_QUOTE, envelope, &[])
        .unwrap_err();

        assert_eq!(fetches.load(Ordering::SeqCst), 0);
        assert!(error.to_string().contains("unknown artifact signing key"));
    }

    #[tokio::test]
    async fn resolver_fetches_persists_and_reuses_file_cache() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let cache_dir = temp_cache_dir("fetches-persists");
        let fetches = Arc::new(AtomicUsize::new(0));
        let resolver = DcapTdxCollateralResolver::from_fetcher(StaticFetcher {
            fetches: fetches.clone(),
        })
        .with_cache_dir(cache_dir.clone());

        resolver
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .await
            .unwrap();

        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert!(cache_file(&cache_dir, SAMPLE_QUOTE).exists());

        let second_fetches = Arc::new(AtomicUsize::new(0));
        let second_resolver = DcapTdxCollateralResolver::from_fetcher(StaticFetcher {
            fetches: second_fetches.clone(),
        })
        .with_cache_dir(cache_dir.clone());

        second_resolver
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .await
            .unwrap();

        assert_eq!(second_fetches.load(Ordering::SeqCst), 0);
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[tokio::test]
    async fn resolver_invalidates_file_cache_bound_to_other_quote() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let cache_dir = temp_cache_dir("digest-mismatch");
        fs::create_dir_all(&cache_dir).unwrap();
        let mut other_quote = SAMPLE_QUOTE.to_vec();
        other_quote[0] ^= 0x01;
        let collateral = serde_json::from_slice(SAMPLE_COLLATERAL).unwrap();
        let wrong_bundle = DcapTdxCollateralBundle::from_collateral_at(
            collateral,
            now,
            DcapTdxCollateralSource::offline_bundle(),
            Some(SAMPLE_QUOTE),
        )
        .unwrap();
        fs::write(
            cache_file(&cache_dir, &other_quote),
            wrong_bundle.to_json().unwrap(),
        )
        .unwrap();
        let fetches = Arc::new(AtomicUsize::new(0));
        let resolver = DcapTdxCollateralResolver::from_fetcher(StaticFetcher {
            fetches: fetches.clone(),
        })
        .with_cache_dir(cache_dir.clone());

        resolver
            .verifier_for_quote_at(&other_quote, now)
            .await
            .unwrap();

        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        let rewritten = DcapTdxCollateralBundle::from_json(
            &fs::read(cache_file(&cache_dir, &other_quote)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            rewritten.quote_sha256(),
            Some(sha256_digest(&other_quote).as_str())
        );
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[tokio::test]
    async fn resolver_retries_transient_collateral_fetch_failure() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let policy = DcapTdxCollateralFetchPolicy::default()
            .with_max_attempts(2)
            .with_per_attempt_timeout(Duration::from_secs(1))
            .with_backoff(Duration::ZERO, Duration::ZERO);
        let resolver = DcapTdxCollateralResolver::from_fetcher(FlakyFetcher {
            attempts: attempts.clone(),
        })
        .with_fetch_policy(policy);

        resolver
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .await
            .unwrap();

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn resolver_records_redacted_cache_queue_and_retry_metrics() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let metrics = Arc::new(InMemoryDcapTdxCollateralMetricsRecorder::default());
        let policy = DcapTdxCollateralFetchPolicy::default()
            .with_max_attempts(2)
            .with_per_attempt_timeout(Duration::from_secs(1))
            .with_backoff(Duration::ZERO, Duration::ZERO);
        let resolver = DcapTdxCollateralResolver::from_fetcher(FlakyFetcher {
            attempts: attempts.clone(),
        })
        .with_fetch_policy(policy)
        .with_metrics_recorder(metrics.clone());

        resolver
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .await
            .unwrap();

        let events = metrics.events();
        let quote_digest = sha256_digest(SAMPLE_QUOTE);
        assert!(events.iter().any(|event| matches!(
            event,
            DcapTdxCollateralMetricEvent::Cache(metric)
                if metric.quote_sha256 == quote_digest
                    && metric.event == DcapTdxCollateralCacheEvent::Miss
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            DcapTdxCollateralMetricEvent::Queue(metric)
                if metric.event == DcapTdxCollateralQueueEvent::Acquired
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            DcapTdxCollateralMetricEvent::Fetch(metric)
                if metric.quote_sha256 == quote_digest
                    && metric.attempt == 1
                    && metric.event == DcapTdxCollateralFetchEvent::Retry
                    && metric.error_kind.as_deref() == Some("http")
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            DcapTdxCollateralMetricEvent::Fetch(metric)
                if metric.quote_sha256 == quote_digest
                    && metric.attempt == 2
                    && metric.event == DcapTdxCollateralFetchEvent::Success
        )));
        let serialized = serde_json::to_string(&events).unwrap();
        assert!(
            !serialized.contains(&base64::engine::general_purpose::STANDARD.encode(SAMPLE_QUOTE))
        );
        assert!(!serialized.contains("transient PCCS outage"));
    }

    #[tokio::test]
    async fn resolver_does_not_retry_invalid_collateral() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let policy = DcapTdxCollateralFetchPolicy::default()
            .with_max_attempts(3)
            .with_backoff(Duration::ZERO, Duration::ZERO);
        let resolver = DcapTdxCollateralResolver::from_fetcher(InvalidCollateralFetcher {
            attempts: attempts.clone(),
        })
        .with_fetch_policy(policy);

        let error = resolver
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .await
            .unwrap_err();

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(error.to_string().contains("invalid TDX collateral fixture"));
    }

    #[tokio::test]
    async fn resolver_times_out_stuck_collateral_fetch() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let policy = DcapTdxCollateralFetchPolicy::default()
            .with_max_attempts(1)
            .with_per_attempt_timeout(Duration::from_millis(5));
        let resolver = DcapTdxCollateralResolver::from_fetcher(SlowFetcher {
            started: started.clone(),
            completed: completed.clone(),
        })
        .with_fetch_policy(policy);

        let error = resolver
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .await
            .unwrap_err();

        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(completed.load(Ordering::SeqCst), 0);
        assert!(error.to_string().contains("TDX collateral fetch timed out"));
    }

    #[tokio::test]
    async fn resolver_rejects_collateral_fetch_when_queue_is_full() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let policy = DcapTdxCollateralFetchPolicy::default()
            .with_max_concurrent_fetches(1)
            .with_max_queued_fetches(0)
            .with_per_attempt_timeout(Duration::from_secs(1));
        let resolver = DcapTdxCollateralResolver::from_fetcher(SlowFetcher {
            started: started.clone(),
            completed: completed.clone(),
        })
        .with_fetch_policy(policy);
        let first_resolver = resolver.clone();
        let first = tokio::spawn(async move {
            first_resolver
                .verifier_for_quote_at(SAMPLE_QUOTE, now)
                .await
        });
        wait_for_started(&started).await;

        let error = resolver
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("TDX collateral fetch queue is full"));
        first.await.unwrap().unwrap();
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resolver_times_out_waiting_for_collateral_fetch_queue() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let policy = DcapTdxCollateralFetchPolicy::default()
            .with_max_concurrent_fetches(1)
            .with_max_queued_fetches(1)
            .with_queue_timeout(Duration::from_millis(5))
            .with_per_attempt_timeout(Duration::from_secs(1));
        let resolver = DcapTdxCollateralResolver::from_fetcher(SlowFetcher {
            started: started.clone(),
            completed: completed.clone(),
        })
        .with_fetch_policy(policy);
        let first_resolver = resolver.clone();
        let first = tokio::spawn(async move {
            first_resolver
                .verifier_for_quote_at(SAMPLE_QUOTE, now)
                .await
        });
        wait_for_started(&started).await;

        let error = resolver
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("TDX collateral fetch queue timed out"));
        first.await.unwrap().unwrap();
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }

    fn temp_cache_dir(test_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "confidential-inference-tdx-collateral-cache-{test_name}-{}-{}",
            std::process::id(),
            now_epoch_millis()
        ))
    }

    fn cache_file(cache_dir: &Path, quote: &[u8]) -> PathBuf {
        cache_dir.join(cache_filename_for_digest(&sha256_digest(quote)).unwrap())
    }
    fn sample_bundle_at(
        quote_bytes: &[u8],
        fetched_at_epoch_ms: u64,
    ) -> Result<DcapTdxCollateralBundle> {
        let collateral = serde_json::from_slice(SAMPLE_COLLATERAL).unwrap();
        DcapTdxCollateralBundle::from_collateral_at(
            collateral,
            fetched_at_epoch_ms,
            DcapTdxCollateralSource::pccs(
                "https://api.trustedservices.intel.com/tdx/certification/v4",
            ),
            Some(quote_bytes),
        )
        .map_err(provider_attestation_error)
    }

    fn sample_offline_bundle_at(
        quote_bytes: &[u8],
        fetched_at_epoch_ms: u64,
    ) -> DcapTdxCollateralBundle {
        let collateral = serde_json::from_slice(SAMPLE_COLLATERAL).unwrap();
        DcapTdxCollateralBundle::from_collateral_at(
            collateral,
            fetched_at_epoch_ms,
            DcapTdxCollateralSource::offline_bundle(),
            Some(quote_bytes),
        )
        .unwrap()
    }

    fn signed_test_envelope(
        payload: DcapTdxCollateralBundle,
    ) -> (DcapTdxCollateralBundleEnvelope, TrustedSigningKey) {
        let key_pair = KeyPair::from_seed(Seed::new([11u8; 32]));
        let payload_json = canonical_json(&payload).unwrap();
        let signature = key_pair.sk.sign(payload_json.as_bytes(), None);
        let public_key_base64url = URL_SAFE_NO_PAD.encode(key_pair.pk.as_ref());
        let trusted_key = TrustedSigningKey {
            signer: "test".into(),
            key_id: "tdx-provider-resolver-test-key".into(),
            public_key_base64url,
        };
        let envelope = DcapTdxCollateralBundleEnvelope {
            schema: DcapTdxCollateralBundleEnvelope::SCHEMA.into(),
            payload,
            signature: ArtifactSignature {
                signer: trusted_key.signer.clone(),
                key_id: trusted_key.key_id.clone(),
                alg: "ed25519".into(),
                value: format!("base64url:{}", URL_SAFE_NO_PAD.encode(signature.as_ref())),
            },
        };
        (envelope, trusted_key)
    }

    async fn wait_for_started(started: &AtomicUsize) {
        for _ in 0..50 {
            if started.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("timed out waiting for test fetcher to start");
    }
}
