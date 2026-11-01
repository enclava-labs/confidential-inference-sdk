// AMD KDS paths support blSPL/teeSPL/snpSPL/ucodeSPL; Turin's FMC SPL is not represented.
use crate::{ProviderError, Result};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_VCEK_BYTES: usize = 1024 * 1024;

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

type CacheKey = (String, [u8; 64], [u8; 4]);

#[async_trait]
pub trait SevSnpVcekResolver: Send + Sync {
    async fn resolve_vcek(&self, product: &str, hwid: &[u8; 64], tcb: [u8; 4]) -> Result<Vec<u8>>;
}

#[derive(Clone)]
pub struct AmdKdsSevSnpVcekResolver {
    base_url: String,
    client: reqwest::Client,
    cache: Arc<Mutex<HashMap<CacheKey, VcekCacheEntry>>>,
}

#[derive(Clone)]
struct VcekCacheEntry {
    result: std::result::Result<Vec<u8>, String>,
    stored_at: Instant,
}

/// Failed KDS lookups are cached briefly so a KDS outage does not turn every
/// verification into a live request, and so transient failures are retried
/// later instead of being remembered forever.
const VCEK_FAILURE_TTL: Duration = Duration::from_secs(300);
const VCEK_CACHE_MAX_ENTRIES: usize = 256;

impl AmdKdsSevSnpVcekResolver {
    pub fn new() -> Result<Self> {
        Self::with_base_url("https://kdsintf.amd.com")
    }

    pub fn with_base_url(base_url: impl Into<String>) -> Result<Self> {
        let client = crate::tls::reqwest_client_builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            client,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    #[cfg(test)]
    fn with_timeout(base_url: impl Into<String>, timeout: Duration) -> Result<Self> {
        let mut resolver = Self::with_base_url(base_url)?;
        resolver.client = crate::tls::reqwest_client_builder()
            .timeout(timeout)
            .build()
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        Ok(resolver)
    }

    async fn fetch(&self, product: &str, hwid: &[u8; 64], tcb: [u8; 4]) -> Result<Vec<u8>> {
        let url = format!("{}/vcek/v1/{}/{}", self.base_url, product, encode_hex(hwid));
        let response = self
            .client
            .get(url)
            .query(&[
                ("blSPL", tcb[0].to_string()),
                ("teeSPL", tcb[1].to_string()),
                ("snpSPL", tcb[2].to_string()),
                ("ucodeSPL", tcb[3].to_string()),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        if !response.status().is_success() {
            return Err(ProviderError::Http(format!(
                "AMD KDS returned {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_VCEK_BYTES as u64)
        {
            return Err(ProviderError::Http(
                "AMD KDS VCEK response exceeds size limit".into(),
            ));
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| ProviderError::Http(e.to_string()))?;
            if bytes.len().saturating_add(chunk.len()) > MAX_VCEK_BYTES {
                return Err(ProviderError::Http(
                    "AMD KDS VCEK response exceeds size limit".into(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

#[async_trait]
impl SevSnpVcekResolver for AmdKdsSevSnpVcekResolver {
    async fn resolve_vcek(&self, product: &str, hwid: &[u8; 64], tcb: [u8; 4]) -> Result<Vec<u8>> {
        let key = (product.to_owned(), *hwid, tcb);
        if let Some(entry) = self
            .cache
            .lock()
            .map_err(|_| ProviderError::Http("VCEK cache unavailable".into()))?
            .get(&key)
            .cloned()
        {
            match &entry.result {
                Ok(cert) => return Ok(cert.clone()),
                Err(message) if entry.stored_at.elapsed() < VCEK_FAILURE_TTL => {
                    return Err(ProviderError::Http(format!(
                        "AMD KDS VCEK lookup failed recently: {message}"
                    )));
                }
                Err(_) => {}
            }
        }
        let result = self.fetch(product, hwid, tcb).await;
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| ProviderError::Http("VCEK cache unavailable".into()))?;
        if !cache.contains_key(&key) && cache.len() >= VCEK_CACHE_MAX_ENTRIES {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.stored_at)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest);
            }
        }
        match result {
            Ok(cert) => {
                cache.insert(
                    key,
                    VcekCacheEntry {
                        result: Ok(cert.clone()),
                        stored_at: Instant::now(),
                    },
                );
                Ok(cert)
            }
            Err(error) => {
                cache.insert(
                    key,
                    VcekCacheEntry {
                        result: Err(error.to_string()),
                        stored_at: Instant::now(),
                    },
                );
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn server(
        body: Vec<u8>,
        delay: Duration,
        count: Arc<std::sync::atomic::AtomicUsize>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = body.clone();
                let count = count.clone();
                tokio::spawn(async move {
                    let mut request = [0; 2048];
                    let _ = stream.read(&mut request).await;
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                });
            }
        });
        format!("http://{address}")
    }

    fn args() -> (&'static str, [u8; 64], [u8; 4]) {
        ("Genoa", [7; 64], [1, 2, 3, 4])
    }

    #[test]
    fn encodes_chip_id_as_lowercase_hex() {
        assert_eq!(encode_hex(&[0xab, 0x01]), "ab01");
    }

    #[tokio::test]
    async fn rejects_oversized_vcek() {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = server(vec![0; MAX_VCEK_BYTES + 1], Duration::ZERO, count).await;
        let resolver = AmdKdsSevSnpVcekResolver::with_base_url(url).unwrap();
        let (product, hwid, tcb) = args();
        assert!(resolver.resolve_vcek(product, &hwid, tcb).await.is_err());
    }

    #[tokio::test]
    async fn times_out_kds_request() {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = server(vec![1], Duration::from_millis(100), count).await;
        let resolver =
            AmdKdsSevSnpVcekResolver::with_timeout(url, Duration::from_millis(10)).unwrap();
        let (product, hwid, tcb) = args();
        assert!(resolver.resolve_vcek(product, &hwid, tcb).await.is_err());
    }

    #[tokio::test]
    async fn caches_vcek_by_hwid_and_tcb() {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = server(vec![1, 2, 3], Duration::ZERO, count.clone()).await;
        let resolver = AmdKdsSevSnpVcekResolver::with_base_url(url).unwrap();
        let (product, hwid, tcb) = args();
        assert_eq!(
            resolver.resolve_vcek(product, &hwid, tcb).await.unwrap(),
            [1, 2, 3]
        );
        assert_eq!(
            resolver.resolve_vcek(product, &hwid, tcb).await.unwrap(),
            [1, 2, 3]
        );
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn caches_failed_lookups_briefly() {
        // The server replies with an oversized body, so every fetch fails;
        // the failure is remembered for VCEK_FAILURE_TTL instead of hitting
        // KDS again on every verification.
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let url = server(vec![0; MAX_VCEK_BYTES + 1], Duration::ZERO, count.clone()).await;
        let resolver = AmdKdsSevSnpVcekResolver::with_base_url(url).unwrap();
        let (product, hwid, tcb) = args();
        assert!(resolver.resolve_vcek(product, &hwid, tcb).await.is_err());
        assert!(resolver.resolve_vcek(product, &hwid, tcb).await.is_err());
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
