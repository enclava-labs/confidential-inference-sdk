use confidential_inference_attestation::certificate_spki_sha256_hex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{ProviderError, Result};

/// Connect timeout for provider inference requests (the TLS handshake runs
/// under it). Evidence/collateral fetches additionally apply
/// [`FETCH_REQUEST_TIMEOUT`] as a per-request total.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle-between-reads timeout for inference responses so long completions and
/// SSE streams are not killed by a total timeout.
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(600);
/// Per-request total timeout for evidence/attestation/collateral fetches.
pub(crate) const FETCH_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on cached SPKI-pinned inference clients per adapter.
const MAX_PINNED_CLIENTS: usize = 8;

fn platform_tls_config() -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier: Arc<dyn ServerCertVerifier> =
        match rustls_platform_verifier::Verifier::new(provider.clone()) {
            Ok(verifier) => Arc::new(verifier),
            Err(error) => Arc::new(FailingVerifier::new(format!(
                "platform TLS verification is unavailable: {error}"
            ))),
        };
    tls_config_with_verifier(provider, verifier)
}

/// Reqwest builder for every SDK HTTP client: an explicit ring-backed rustls
/// config with the platform verifier (reqwest's default verification), so no
/// process-wide rustls `CryptoProvider` is installed or required, and no
/// redirects (a redirect could re-send credentials or prompts to another host).
pub fn reqwest_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .tls_backend_preconfigured(platform_tls_config())
        .redirect(reqwest::redirect::Policy::none())
}

fn tls_config_with_verifier(
    provider: Arc<CryptoProvider>,
    verifier: Arc<dyn ServerCertVerifier>,
) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|_| {
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3 is always supported by the ring provider")
        });
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// The pinned-SPKI verifier failed the handshake: the presented leaf
/// certificate does not match the SPKI bound into verified evidence. Tracked
/// through the reqwest error chain so callers can classify the refusal as
/// key rotation (nothing was dispatched).
#[derive(Debug)]
pub(crate) struct PinnedSpkiMismatch {
    expected_spki_sha256: String,
    observed_spki_sha256: String,
}

impl std::fmt::Display for PinnedSpkiMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "TLS server SPKI {} does not match attested pin {}",
            self.observed_spki_sha256, self.expected_spki_sha256
        )
    }
}

impl std::error::Error for PinnedSpkiMismatch {}

/// Returns true when `error`'s source chain ends in a [`PinnedSpkiMismatch`]
/// raised while verifying the peer certificate, meaning no request bytes were
/// sent.
pub(crate) fn is_pinned_spki_mismatch(error: &reqwest::Error) -> bool {
    fn is_pin(error: &(dyn std::error::Error + 'static)) -> bool {
        matches!(
            error.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::Other(other)) if other.0.is::<PinnedSpkiMismatch>()
        )
    }
    let mut source = std::error::Error::source(error);
    while let Some(error) = source {
        // io::Error::source() skips the error it wraps (and hyper nests
        // io::Errors), so descend through io::Error payloads explicitly.
        let mut payload = Some(error);
        while let Some(current) = payload {
            if is_pin(current) {
                return true;
            }
            payload = current
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::get_ref)
                .map(|inner| inner as &(dyn std::error::Error + 'static));
        }
        source = error.source();
    }
    false
}

#[derive(Debug)]
struct SpkiPinnedVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    expected_spki_sha256: String,
}

impl ServerCertVerifier for SpkiPinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let observed = certificate_spki_sha256_hex(end_entity.as_ref())
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        if observed != self.expected_spki_sha256 {
            return Err(rustls::Error::Other(rustls::OtherError(Arc::new(
                PinnedSpkiMismatch {
                    expected_spki_sha256: self.expected_spki_sha256.clone(),
                    observed_spki_sha256: observed,
                },
            ))));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Used when the platform verifier cannot be constructed: verification still
/// fails closed at handshake time with a clear message instead of panicking
/// while building the client.
#[derive(Debug)]
struct FailingVerifier {
    message: String,
}

impl FailingVerifier {
    fn new(message: String) -> Self {
        Self { message }
    }

    fn error(&self) -> rustls::Error {
        rustls::Error::General(self.message.clone())
    }
}

impl ServerCertVerifier for FailingVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Err(self.error())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(self.error())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(self.error())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        Vec::new()
    }
}

/// Reusable HTTP and TLS settings for attested transports.
///
/// The builder factory is invoked for evidence and for each pinned client.
/// Its TLS backend, redirect policy and TLS-info setting are replaced by the
/// SDK; configure trust and client authentication in `tls_config` and pass
/// the corresponding server verifier separately so the SDK can wrap it.
#[derive(Clone)]
pub struct AttestedHttpTransport {
    builder: Arc<dyn Fn() -> reqwest::ClientBuilder + Send + Sync>,
    tls_config: ClientConfig,
    verifier: Arc<dyn ServerCertVerifier>,
}

impl std::fmt::Debug for AttestedHttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestedHttpTransport")
            .finish_non_exhaustive()
    }
}

impl Default for AttestedHttpTransport {
    fn default() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier: Arc<dyn ServerCertVerifier> =
            match rustls_platform_verifier::Verifier::new(provider.clone()) {
                Ok(verifier) => Arc::new(verifier),
                Err(error) => Arc::new(FailingVerifier::new(format!(
                    "platform TLS verification is unavailable: {error}"
                ))),
            };
        Self::new(
            || {
                reqwest::Client::builder()
                    .connect_timeout(CONNECT_TIMEOUT)
                    .read_timeout(READ_TIMEOUT)
            },
            tls_config_with_verifier(provider, verifier.clone()),
            verifier,
        )
    }
}

impl AttestedHttpTransport {
    pub fn new(
        builder: impl Fn() -> reqwest::ClientBuilder + Send + Sync + 'static,
        tls_config: ClientConfig,
        verifier: Arc<dyn ServerCertVerifier>,
    ) -> Self {
        Self {
            builder: Arc::new(builder),
            tls_config,
            verifier,
        }
    }

    fn client(&self, pin: Option<&str>) -> Result<reqwest::Client> {
        let mut config = self.tls_config.clone();
        let verifier: Arc<dyn ServerCertVerifier> = match pin {
            Some(pin) => Arc::new(SpkiPinnedVerifier {
                inner: self.verifier.clone(),
                expected_spki_sha256: pin.to_owned(),
            }),
            None => self.verifier.clone(),
        };
        config.dangerous().set_certificate_verifier(verifier);
        (self.builder)()
            .tls_backend_preconfigured(config)
            .redirect(reqwest::redirect::Policy::none())
            .tls_info(true)
            .build()
            .map_err(|error| ProviderError::Http(error.to_string()))
    }

    pub(crate) fn evidence_client(&self) -> Result<reqwest::Client> {
        self.client(None)
    }
}

/// Small bounded cache of SPKI-pinned inference clients keyed by the verified
/// SPKI sha256 hex. Clients are shareable, so a fixed-size map with
/// oldest-key eviction suffices.
#[derive(Clone, Debug)]
pub(crate) struct PinnedSpkiClientCache {
    clients: Arc<Mutex<BTreeMap<String, (u64, reqwest::Client)>>>,
    sequence: Arc<std::sync::atomic::AtomicU64>,
    transport: AttestedHttpTransport,
}

impl PinnedSpkiClientCache {
    pub(crate) fn new(transport: AttestedHttpTransport) -> Self {
        Self {
            transport,
            clients: Arc::new(Mutex::new(BTreeMap::new())),
            sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub(crate) fn client(&self, expected_spki_sha256: &str) -> Result<reqwest::Client> {
        {
            let clients = self.clients.lock().map_err(|_| {
                ProviderError::Adapter("pinned TLS client cache lock is poisoned".into())
            })?;
            if let Some((_, client)) = clients.get(expected_spki_sha256) {
                return Ok(client.clone());
            }
        }
        let client = self.transport.client(Some(expected_spki_sha256))?;
        let mut clients = self.clients.lock().map_err(|_| {
            ProviderError::Adapter("pinned TLS client cache lock is poisoned".into())
        })?;
        if !clients.contains_key(expected_spki_sha256) && clients.len() >= MAX_PINNED_CLIENTS {
            if let Some(oldest) = clients
                .iter()
                .min_by_key(|(_, (sequence, _))| *sequence)
                .map(|(key, _)| key.clone())
            {
                clients.remove(&oldest);
            }
        }
        let sequence = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(clients
            .entry(expected_spki_sha256.to_owned())
            .or_insert((sequence, client))
            .1
            .clone())
    }
}
