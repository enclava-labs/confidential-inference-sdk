use crate::{
    format_utc_timestamp_millis, parse_utc_timestamp_millis, sha256_digest,
    verify_artifact_signature, verify_artifact_signature_with_keys, ArtifactSignature,
    AttestationError, CpuTeeKind, EvidenceHardware, Result, TinfoilAttestationFormat,
    TinfoilQuoteVerificationRequest, TinfoilQuoteVerifier, TrustedSigningKey, VerifiedTdxQuote,
    VerifiedTinfoilQuote,
};
use dcap_qvl::{
    quote::{Quote, Report, TDReport10},
    QuoteCollateralV3,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use x509_cert::{certificate::Rfc5280, crl::CertificateList, der::Decode};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcapTdxCollateralBundle {
    pub schema: String,
    pub source: DcapTdxCollateralSource,
    pub fetched_at: String,
    pub fetched_at_epoch_ms: u64,
    pub valid_until: String,
    pub valid_until_epoch_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_sha256: Option<String>,
    pub collateral: QuoteCollateralV3,
}

impl DcapTdxCollateralBundle {
    pub const SCHEMA: &'static str = "confidential-inference.dcap-tdx-collateral-bundle.v1";

    pub fn from_collateral_at(
        collateral: QuoteCollateralV3,
        fetched_at_epoch_ms: u64,
        source: DcapTdxCollateralSource,
        quote_bytes: Option<&[u8]>,
    ) -> Result<Self> {
        let valid_until_epoch_ms = dcap_collateral_valid_until_epoch_millis(&collateral)?;
        Ok(Self {
            schema: Self::SCHEMA.into(),
            source,
            fetched_at: format_utc_timestamp_millis(fetched_at_epoch_ms),
            fetched_at_epoch_ms,
            valid_until: format_utc_timestamp_millis(valid_until_epoch_ms),
            valid_until_epoch_ms,
            quote_sha256: quote_bytes.map(sha256_digest),
            collateral,
        })
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let bundle: Self = serde_json::from_slice(bytes).map_err(|err| {
            AttestationError::InvalidEvidence(format!(
                "invalid TDX DCAP collateral bundle JSON: {err}"
            ))
        })?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|err| {
            AttestationError::InvalidEvidence(format!(
                "failed to encode TDX DCAP collateral bundle: {err}"
            ))
        })
    }

    pub fn verifier_at(&self, now_epoch_millis: u64) -> Result<DcapTdxTinfoilQuoteVerifier> {
        self.validate()?;
        if now_epoch_millis >= self.valid_until_epoch_ms {
            return Err(AttestationError::InvalidEvidence(format!(
                "TDX DCAP collateral bundle expired at {}",
                self.valid_until
            )));
        }
        Ok(DcapTdxTinfoilQuoteVerifier::from_collateral_at(
            self.collateral.clone(),
            now_epoch_millis,
        ))
    }

    pub fn quote_sha256(&self) -> Option<&str> {
        self.quote_sha256.as_deref()
    }

    pub fn is_valid_at(&self, now_epoch_millis: u64) -> bool {
        now_epoch_millis < self.valid_until_epoch_ms
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(AttestationError::InvalidEvidence(format!(
                "unsupported TDX DCAP collateral bundle schema {}",
                self.schema
            )));
        }
        let computed_valid_until = dcap_collateral_valid_until_epoch_millis(&self.collateral)?;
        if computed_valid_until != self.valid_until_epoch_ms
            || format_utc_timestamp_millis(computed_valid_until) != self.valid_until
        {
            return Err(AttestationError::InvalidEvidence(
                "TDX DCAP collateral bundle validity does not match bundled collateral".into(),
            ));
        }
        if format_utc_timestamp_millis(self.fetched_at_epoch_ms) != self.fetched_at {
            return Err(AttestationError::InvalidEvidence(
                "TDX DCAP collateral bundle fetched_at fields are inconsistent".into(),
            ));
        }
        if self.quote_sha256.as_deref().is_some_and(|digest| {
            !digest.starts_with("sha256:") || digest.len() != "sha256:".len() + 64
        }) {
            return Err(AttestationError::InvalidEvidence(
                "TDX DCAP collateral bundle quote_sha256 is not a sha256 digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcapTdxCollateralBundleEnvelope {
    pub schema: String,
    pub payload: DcapTdxCollateralBundle,
    pub signature: ArtifactSignature,
}

impl DcapTdxCollateralBundleEnvelope {
    pub const SCHEMA: &'static str =
        "confidential-inference.dcap-tdx-collateral-bundle-envelope.v1";

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let envelope: Self = serde_json::from_slice(bytes).map_err(|err| {
            AttestationError::InvalidEvidence(format!(
                "invalid TDX DCAP collateral bundle envelope JSON: {err}"
            ))
        })?;
        envelope.validate_envelope()?;
        Ok(envelope)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|err| {
            AttestationError::InvalidEvidence(format!(
                "failed to encode TDX DCAP collateral bundle envelope: {err}"
            ))
        })
    }

    pub fn verify_signature(&self) -> Result<()> {
        self.validate_envelope()?;
        verify_artifact_signature(&self.signature, &self.payload)
    }

    pub fn verify_signature_with_keys(
        &self,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> Result<()> {
        self.validate_envelope()?;
        verify_artifact_signature_with_keys(&self.signature, &self.payload, trusted_signing_keys)
    }

    pub fn into_verified_bundle(self) -> Result<DcapTdxCollateralBundle> {
        self.verify_signature()?;
        Ok(self.payload)
    }

    pub fn into_verified_bundle_with_keys(
        self,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> Result<DcapTdxCollateralBundle> {
        self.verify_signature_with_keys(trusted_signing_keys)?;
        Ok(self.payload)
    }

    pub fn verifier_at(&self, now_epoch_millis: u64) -> Result<DcapTdxTinfoilQuoteVerifier> {
        self.verify_signature()?;
        self.payload.verifier_at(now_epoch_millis)
    }

    pub fn verifier_at_with_keys(
        &self,
        now_epoch_millis: u64,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> Result<DcapTdxTinfoilQuoteVerifier> {
        self.verify_signature_with_keys(trusted_signing_keys)?;
        self.payload.verifier_at(now_epoch_millis)
    }

    fn validate_envelope(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(AttestationError::InvalidEvidence(format!(
                "unsupported TDX DCAP collateral bundle envelope schema {}",
                self.schema
            )));
        }
        self.payload.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcapTdxCollateralSource {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl DcapTdxCollateralSource {
    pub fn offline_bundle() -> Self {
        Self {
            kind: "offline_bundle".into(),
            url: None,
        }
    }

    pub fn pccs(url: impl Into<String>) -> Self {
        Self {
            kind: "pccs".into(),
            url: Some(url.into()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DcapTdxCollateralCache {
    bundles_by_quote_sha256: BTreeMap<String, DcapTdxCollateralBundle>,
}

impl DcapTdxCollateralCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_for_quote(
        &mut self,
        quote_bytes: &[u8],
        bundle: DcapTdxCollateralBundle,
    ) -> Result<()> {
        let key = sha256_digest(quote_bytes);
        if let Some(bundle_key) = &bundle.quote_sha256 {
            if bundle_key != &key {
                return Err(AttestationError::InvalidEvidence(
                    "TDX DCAP collateral bundle quote digest does not match cache key".into(),
                ));
            }
        }
        bundle.validate()?;
        self.bundles_by_quote_sha256.insert(key, bundle);
        Ok(())
    }

    pub fn insert_signed_bundle_for_quote(
        &mut self,
        quote_bytes: &[u8],
        envelope: DcapTdxCollateralBundleEnvelope,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> Result<()> {
        let bundle = envelope.into_verified_bundle_with_keys(trusted_signing_keys)?;
        self.insert_for_quote(quote_bytes, bundle)
    }

    pub fn bundle_for_quote(&self, quote_bytes: &[u8]) -> Option<&DcapTdxCollateralBundle> {
        let key = sha256_digest(quote_bytes);
        self.bundles_by_quote_sha256.get(&key)
    }

    pub fn remove_for_quote(&mut self, quote_bytes: &[u8]) -> Option<DcapTdxCollateralBundle> {
        let key = sha256_digest(quote_bytes);
        self.bundles_by_quote_sha256.remove(&key)
    }

    pub fn verifier_for_quote_at(
        &self,
        quote_bytes: &[u8],
        now_epoch_millis: u64,
    ) -> Result<Option<DcapTdxTinfoilQuoteVerifier>> {
        let key = sha256_digest(quote_bytes);
        self.bundles_by_quote_sha256
            .get(&key)
            .map(|bundle| bundle.verifier_at(now_epoch_millis))
            .transpose()
    }
}

#[derive(Clone, Debug)]
pub struct DcapTdxTinfoilQuoteVerifier {
    collateral: QuoteCollateralV3,
    now_epoch_millis: u64,
}

impl DcapTdxTinfoilQuoteVerifier {
    pub fn from_collateral_json_at(collateral_json: &[u8], now_epoch_millis: u64) -> Result<Self> {
        let collateral = serde_json::from_slice(collateral_json).map_err(|err| {
            AttestationError::InvalidEvidence(format!("invalid TDX DCAP collateral JSON: {err}"))
        })?;
        Ok(Self::from_collateral_at(collateral, now_epoch_millis))
    }

    pub fn from_collateral_at(collateral: QuoteCollateralV3, now_epoch_millis: u64) -> Self {
        Self {
            collateral,
            now_epoch_millis,
        }
    }

    pub fn collateral_valid_until_epoch_millis(&self) -> Result<u64> {
        dcap_collateral_valid_until_epoch_millis(&self.collateral)
    }
}

impl TinfoilQuoteVerifier for DcapTdxTinfoilQuoteVerifier {
    fn verify_tinfoil_quote(
        &self,
        request: &TinfoilQuoteVerificationRequest<'_>,
    ) -> Result<VerifiedTinfoilQuote> {
        if request.attestation_format != TinfoilAttestationFormat::TdxGuestV2 {
            return Err(AttestationError::InvalidEvidence(format!(
                "DCAP TDX verifier cannot verify {} Tinfoil captures",
                request.attestation_format.quote_kind()
            )));
        }
        let verified = self.verify_tdx_quote(request.quote_bytes)?;

        Ok(VerifiedTinfoilQuote::from_verified_quote(
            TinfoilAttestationFormat::TdxGuestV2,
            EvidenceHardware {
                cpu: CpuTeeKind::Tdx,
                gpu: None,
            },
            verified.tee_measurement,
            verified.report_data,
            verified.issued_at,
            verified.expires_at,
            verified.expires_at_epoch_ms,
        ))
    }

    fn verify_tdx_quote(&self, quote_bytes: &[u8]) -> Result<VerifiedTdxQuote> {
        let quote_digest = sha256_digest(quote_bytes);
        let _span = tracing::info_span!(
            "confidential-inference.tdx_dcap.quote_verify",
            attestation_format = "intel-tdx-dcap",
            quote_sha256 = %quote_digest,
            quote_bytes = quote_bytes.len(),
            now_epoch_millis = self.now_epoch_millis
        )
        .entered();
        let expires_at_epoch_ms = self.collateral_valid_until_epoch_millis()?;
        if self.now_epoch_millis >= expires_at_epoch_ms {
            return Err(AttestationError::InvalidEvidence(format!(
                "TDX DCAP collateral expired at {}",
                format_utc_timestamp_millis(expires_at_epoch_ms)
            )));
        }
        let verified = catch_unwind(AssertUnwindSafe(|| {
            dcap_qvl::verify::verify(quote_bytes, &self.collateral, self.now_epoch_millis / 1000)
        }))
        .map_err(|_| {
            AttestationError::InvalidEvidence("TDX DCAP quote verification panicked".into())
        })?
        .map_err(|err| {
            AttestationError::InvalidEvidence(format!("TDX DCAP quote verification failed: {err}"))
        })?;
        tracing::debug!(
            collateral_status = %verified.status,
            advisory_count = verified.advisory_ids.len(),
            expires_at_epoch_ms,
            "TDX DCAP quote verification returned collateral status"
        );
        if verified.status != "UpToDate" {
            return Err(AttestationError::InvalidEvidence(format!(
                "TDX DCAP collateral status is not UpToDate: {}",
                verified.status
            )));
        }
        if !verified.advisory_ids.is_empty() {
            return Err(AttestationError::InvalidEvidence(format!(
                "TDX DCAP quote returned advisories: {:?}",
                verified.advisory_ids
            )));
        }

        let quote = Quote::parse(quote_bytes).map_err(|err| {
            AttestationError::InvalidEvidence(format!("TDX quote parse failed: {err}"))
        })?;
        let report = tdx_report(&quote)?;
        tracing::info!(
            tee_measurement = %format!("tdx:mr_td:{}", hex_bytes(&report.mr_td)),
            expires_at_epoch_ms,
            "TDX DCAP quote verified"
        );

        Ok(VerifiedTdxQuote {
            tee_measurement: format!("tdx:mr_td:{}", hex_bytes(&report.mr_td)),
            mr_td: hex_bytes(&report.mr_td),
            mr_config_id: hex_bytes(&report.mr_config_id),
            rtmr0: hex_bytes(&report.rt_mr0),
            rtmr1: hex_bytes(&report.rt_mr1),
            rtmr2: hex_bytes(&report.rt_mr2),
            rtmr3: hex_bytes(&report.rt_mr3),
            report_data: hex_bytes(&report.report_data),
            issued_at: format_utc_timestamp_millis(self.now_epoch_millis),
            expires_at: format_utc_timestamp_millis(expires_at_epoch_ms),
            expires_at_epoch_ms,
        })
    }
}

fn tdx_report(quote: &Quote) -> Result<&TDReport10> {
    match &quote.report {
        Report::TD10(report) => Ok(report),
        Report::TD15(report) => Ok(&report.base),
        Report::SgxEnclave(_) => Err(AttestationError::InvalidEvidence(
            "TDX verifier received an SGX quote".into(),
        )),
    }
}

fn dcap_collateral_valid_until_epoch_millis(collateral: &QuoteCollateralV3) -> Result<u64> {
    let mut expires_at = u64::MAX;
    for json in [&collateral.tcb_info, &collateral.qe_identity] {
        expires_at = expires_at.min(collateral_json_next_update_epoch_millis(json)?);
    }
    for crl_der in [&collateral.root_ca_crl[..], &collateral.pck_crl[..]] {
        if let Some(next_update) = crl_next_update_epoch_millis(crl_der)? {
            expires_at = expires_at.min(next_update);
        }
    }

    if expires_at == u64::MAX {
        return Err(AttestationError::InvalidEvidence(
            "TDX DCAP collateral does not contain an expiration bound".into(),
        ));
    }
    Ok(expires_at)
}

fn collateral_json_next_update_epoch_millis(json: &str) -> Result<u64> {
    let value: Value = serde_json::from_str(json).map_err(|err| {
        AttestationError::InvalidEvidence(format!("invalid TDX collateral JSON field: {err}"))
    })?;
    let next_update = value
        .get("nextUpdate")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AttestationError::InvalidEvidence("TDX collateral JSON is missing nextUpdate".into())
        })?;
    parse_utc_timestamp_millis(next_update)
}

fn crl_next_update_epoch_millis(crl_der: &[u8]) -> Result<Option<u64>> {
    let crl = CertificateList::<Rfc5280>::from_der(crl_der)
        .map_err(|err| AttestationError::InvalidEvidence(format!("invalid DCAP CRL: {err}")))?;
    Ok(crl
        .tbs_cert_list
        .next_update
        .map(|time| time.to_unix_duration().as_secs().saturating_mul(1000)))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_compact::{KeyPair, Seed};
    use serde::Deserialize;

    const SAMPLE_QUOTE: &[u8] = include_bytes!("../../../fixtures/evidence/dcap-qvl/tdx_quote.bin");
    const SAMPLE_COLLATERAL: &[u8] =
        include_bytes!("../../../fixtures/evidence/dcap-qvl/tdx_quote_collateral.json");

    #[derive(Debug, Deserialize)]
    struct DcapMalformedCorpus {
        schema: String,
        cases: Vec<DcapMalformedCase>,
    }

    #[derive(Debug, Deserialize)]
    struct DcapMalformedCase {
        id: String,
        target: DcapMalformedTarget,
        mutation: DcapMalformedMutation,
        expected_error_contains: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum DcapMalformedTarget {
        Quote,
        CollateralJson,
    }

    #[derive(Debug, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum DcapMalformedMutation {
        Truncate { len: usize },
        FlipByte { offset: usize, xor: u8 },
        ReplaceJson { value: String },
        ReplaceTcbInfoJson { value: String },
        ReplaceQeIdentityJson { value: String },
    }

    #[derive(Debug, Deserialize)]
    struct DcapMutationSweep {
        schema: String,
        quote_truncation_lengths: Vec<usize>,
        quote_flip_offsets: Vec<usize>,
        quote_flip_xors: Vec<u8>,
        collateral_nested_json_truncation_lengths: Vec<usize>,
        collateral_nested_json_replacements: Vec<String>,
    }

    #[derive(Clone, Copy, Debug)]
    enum DcapCollateralNestedJsonField {
        TcbInfo,
        QeIdentity,
    }

    #[test]
    fn dcap_tdx_verifier_accepts_real_quote_with_matching_collateral() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let verifier =
            DcapTdxTinfoilQuoteVerifier::from_collateral_json_at(SAMPLE_COLLATERAL, now).unwrap();
        let capture = quote_capture();
        let request = quote_request(SAMPLE_QUOTE, &capture);

        let verified = verifier.verify_tinfoil_quote(&request).unwrap();

        assert_eq!(
            verified.attestation_format,
            TinfoilAttestationFormat::TdxGuestV2.as_str()
        );
        assert_eq!(verified.hardware.cpu, CpuTeeKind::Tdx);
        assert!(verified.tee_measurement.starts_with("tdx:mr_td:"));
        assert_eq!(verified.report_data.len(), 128);
        assert_eq!(verified.issued_at, "2025-06-20T00:00:00Z");
        assert_eq!(verified.expires_at, "2025-07-19T10:00:35Z");
    }

    #[test]
    fn dcap_tdx_verifier_rejects_expired_collateral() {
        let now = parse_utc_timestamp_millis("2025-07-19T10:00:35Z").unwrap();
        let verifier =
            DcapTdxTinfoilQuoteVerifier::from_collateral_json_at(SAMPLE_COLLATERAL, now).unwrap();
        let capture = quote_capture();
        let request = quote_request(SAMPLE_QUOTE, &capture);

        let error = verifier.verify_tinfoil_quote(&request).unwrap_err();

        assert!(error.to_string().contains("TDX DCAP collateral expired"));
    }

    #[test]
    fn dcap_tdx_collateral_bundle_round_trips_and_feeds_cache() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let collateral = sample_collateral();
        let bundle = DcapTdxCollateralBundle::from_collateral_at(
            collateral,
            now,
            DcapTdxCollateralSource::offline_bundle(),
            Some(SAMPLE_QUOTE),
        )
        .unwrap();

        assert_eq!(bundle.schema, DcapTdxCollateralBundle::SCHEMA);
        assert_eq!(bundle.valid_until, "2025-07-19T10:00:35Z");
        let expected_quote_digest = sha256_digest(SAMPLE_QUOTE);
        assert_eq!(
            bundle.quote_sha256.as_deref(),
            Some(expected_quote_digest.as_str())
        );

        let json = bundle.to_json().unwrap();
        let roundtrip = DcapTdxCollateralBundle::from_json(&json).unwrap();
        assert_eq!(roundtrip, bundle);

        let mut cache = DcapTdxCollateralCache::new();
        cache.insert_for_quote(SAMPLE_QUOTE, roundtrip).unwrap();
        assert!(cache
            .verifier_for_quote_at(b"missing quote", now)
            .unwrap()
            .is_none());

        let cached = cache
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .unwrap()
            .unwrap();
        let capture = quote_capture();
        let request = quote_request(SAMPLE_QUOTE, &capture);

        let verified = cached.verify_tinfoil_quote(&request).unwrap();

        assert_eq!(verified.hardware.cpu, CpuTeeKind::Tdx);
        assert_eq!(verified.expires_at, "2025-07-19T10:00:35Z");
    }

    #[test]
    fn dcap_tdx_signed_collateral_bundle_envelope_verifies_with_explicit_trust_key() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let bundle = sample_bundle_at(now);
        let (envelope, trusted_key) = signed_test_envelope(bundle.clone());

        envelope
            .verify_signature_with_keys(std::slice::from_ref(&trusted_key))
            .unwrap();

        let json = envelope.to_json().unwrap();
        let roundtrip = DcapTdxCollateralBundleEnvelope::from_json(&json).unwrap();
        assert_eq!(
            roundtrip
                .clone()
                .into_verified_bundle_with_keys(std::slice::from_ref(&trusted_key))
                .unwrap(),
            bundle
        );

        let mut cache = DcapTdxCollateralCache::new();
        cache
            .insert_signed_bundle_for_quote(
                SAMPLE_QUOTE,
                roundtrip,
                std::slice::from_ref(&trusted_key),
            )
            .unwrap();

        let cached = cache
            .verifier_for_quote_at(SAMPLE_QUOTE, now)
            .unwrap()
            .unwrap();
        assert_eq!(
            cached.collateral_valid_until_epoch_millis().unwrap(),
            parse_utc_timestamp_millis("2025-07-19T10:00:35Z").unwrap()
        );
    }

    #[test]
    fn dcap_tdx_signed_collateral_bundle_envelope_rejects_tampering() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let (mut envelope, trusted_key) = signed_test_envelope(sample_bundle_at(now));

        envelope.payload.source.kind = "tampered".into();

        let error = envelope
            .verify_signature_with_keys(&[trusted_key])
            .unwrap_err();
        assert!(matches!(
            error,
            AttestationError::InvalidArtifactSignature(_)
        ));
    }

    #[test]
    fn dcap_tdx_signed_collateral_bundle_envelope_rejects_re_signed_extended_validity() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let mut bundle = sample_bundle_at(now);
        bundle.valid_until_epoch_ms += 1;
        bundle.valid_until = format_utc_timestamp_millis(bundle.valid_until_epoch_ms);
        let (envelope, trusted_key) = signed_test_envelope(bundle);

        let error = envelope
            .verify_signature_with_keys(&[trusted_key])
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("validity does not match bundled collateral"));
    }

    #[test]
    fn dcap_tdx_collateral_cache_rejects_quote_digest_mismatch() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let bundle = DcapTdxCollateralBundle::from_collateral_at(
            sample_collateral(),
            now,
            DcapTdxCollateralSource::offline_bundle(),
            Some(SAMPLE_QUOTE),
        )
        .unwrap();
        let mut other_quote = SAMPLE_QUOTE.to_vec();
        other_quote[0] ^= 0x01;
        let mut cache = DcapTdxCollateralCache::new();

        let error = cache.insert_for_quote(&other_quote, bundle).unwrap_err();

        assert!(error.to_string().contains("quote digest does not match"));
    }

    #[test]
    fn dcap_tdx_collateral_bundle_rejects_expired_cache_hit() {
        let fetched_at = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let expired_at = parse_utc_timestamp_millis("2025-07-19T10:00:35Z").unwrap();
        let bundle = DcapTdxCollateralBundle::from_collateral_at(
            sample_collateral(),
            fetched_at,
            DcapTdxCollateralSource::pccs(
                "https://api.trustedservices.intel.com/tdx/certification/v4",
            ),
            Some(SAMPLE_QUOTE),
        )
        .unwrap();
        let mut cache = DcapTdxCollateralCache::new();
        cache.insert_for_quote(SAMPLE_QUOTE, bundle).unwrap();

        let error = cache
            .verifier_for_quote_at(SAMPLE_QUOTE, expired_at)
            .unwrap_err();

        assert!(error.to_string().contains("collateral bundle expired"));
    }

    #[test]
    fn dcap_tdx_verifier_rejects_mutated_quote() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let verifier =
            DcapTdxTinfoilQuoteVerifier::from_collateral_json_at(SAMPLE_COLLATERAL, now).unwrap();
        let mut quote = SAMPLE_QUOTE.to_vec();
        const QUOTE_V4_HEADER_LEN: usize = 48;
        const TD10_REPORT_DATA_OFFSET: usize = 520;
        quote[QUOTE_V4_HEADER_LEN + TD10_REPORT_DATA_OFFSET] ^= 0x01;
        let capture = quote_capture();
        let request = quote_request(&quote, &capture);

        let error = verifier.verify_tinfoil_quote(&request).unwrap_err();

        assert!(error.to_string().contains("TDX DCAP quote verification"));
    }

    #[test]
    fn dcap_tdx_malformed_corpus_fails_closed() {
        let corpus: DcapMalformedCorpus = serde_json::from_str(include_str!(
            "../../../fixtures/evidence/dcap-qvl/malformed-corpus.json"
        ))
        .unwrap();
        assert_eq!(
            corpus.schema,
            "confidential-inference.dcap-tdx-malformed-corpus.v1"
        );

        for case in corpus.cases {
            let result = match case.target {
                DcapMalformedTarget::Quote => {
                    let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
                    let verifier = DcapTdxTinfoilQuoteVerifier::from_collateral_json_at(
                        SAMPLE_COLLATERAL,
                        now,
                    )
                    .unwrap();
                    let quote = mutated_quote(&case);
                    let capture = quote_capture();
                    let request = quote_request(&quote, &capture);
                    verifier.verify_tinfoil_quote(&request)
                }
                DcapMalformedTarget::CollateralJson => {
                    let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
                    DcapTdxTinfoilQuoteVerifier::from_collateral_json_at(
                        &mutated_collateral_json(&case),
                        now,
                    )
                    .and_then(|verifier| {
                        let capture = quote_capture();
                        let request = quote_request(SAMPLE_QUOTE, &capture);
                        verifier.verify_tinfoil_quote(&request)
                    })
                }
            };

            let error = match result {
                Ok(_) => panic!("{}: malformed DCAP case verified", case.id),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(&case.expected_error_contains),
                "{}: expected error containing {:?}, got {error:?}",
                case.id,
                case.expected_error_contains
            );
        }
    }

    #[test]
    fn dcap_tdx_mutation_sweep_fails_closed() {
        let sweep: DcapMutationSweep = serde_json::from_str(include_str!(
            "../../../fixtures/evidence/dcap-qvl/mutation-sweep.json"
        ))
        .unwrap();
        assert_eq!(
            sweep.schema,
            "confidential-inference.dcap-tdx-mutation-sweep.v1"
        );
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let verifier =
            DcapTdxTinfoilQuoteVerifier::from_collateral_json_at(SAMPLE_COLLATERAL, now).unwrap();
        let mut case_count = 0_usize;

        for len in &sweep.quote_truncation_lengths {
            assert!(
                *len < SAMPLE_QUOTE.len(),
                "quote truncation length must be shorter than the sample quote: {len}"
            );
            let mut quote = SAMPLE_QUOTE.to_vec();
            quote.truncate(*len);
            assert_dcap_quote_rejected(&verifier, &format!("quote-truncate-{len}"), &quote);
            case_count += 1;
        }

        for offset in &sweep.quote_flip_offsets {
            assert!(
                *offset < SAMPLE_QUOTE.len(),
                "quote flip offset out of range: {offset}"
            );
            for xor in &sweep.quote_flip_xors {
                assert_ne!(*xor, 0, "quote flip xor must mutate the sample quote");
                let mut quote = SAMPLE_QUOTE.to_vec();
                quote[*offset] ^= *xor;
                assert_dcap_quote_rejected(
                    &verifier,
                    &format!("quote-flip-{offset}-xor-{xor}"),
                    &quote,
                );
                case_count += 1;
            }
        }

        for field in [
            DcapCollateralNestedJsonField::TcbInfo,
            DcapCollateralNestedJsonField::QeIdentity,
        ] {
            for len in &sweep.collateral_nested_json_truncation_lengths {
                let original = collateral_nested_json(field);
                assert!(
                    *len < original.len(),
                    "collateral nested JSON truncation must be shorter than {field:?}: {len}"
                );
                let json = mutated_collateral_nested_json(field, &original[..*len]);
                assert_dcap_collateral_rejected(
                    now,
                    &format!("collateral-{field:?}-truncate-{len}"),
                    &json,
                );
                case_count += 1;
            }

            for replacement in &sweep.collateral_nested_json_replacements {
                let json = mutated_collateral_nested_json(field, replacement);
                assert_dcap_collateral_rejected(
                    now,
                    &format!("collateral-{field:?}-replace-{replacement:?}"),
                    &json,
                );
                case_count += 1;
            }
        }

        assert!(
            case_count >= 50,
            "DCAP mutation sweep should keep broad deterministic coverage"
        );
    }

    #[test]
    fn dcap_tdx_verifier_rejects_snp_capture_format() {
        let now = parse_utc_timestamp_millis("2025-06-20T00:00:00Z").unwrap();
        let verifier =
            DcapTdxTinfoilQuoteVerifier::from_collateral_json_at(SAMPLE_COLLATERAL, now).unwrap();
        let capture = quote_capture();
        let mut request = quote_request(SAMPLE_QUOTE, &capture);
        request.attestation_format = TinfoilAttestationFormat::SevSnpGuestV2;

        let error = verifier.verify_tinfoil_quote(&request).unwrap_err();

        assert!(error.to_string().contains("cannot verify SEV-SNP"));
    }

    fn sample_collateral() -> QuoteCollateralV3 {
        serde_json::from_slice(SAMPLE_COLLATERAL).unwrap()
    }

    fn assert_dcap_quote_rejected(
        verifier: &DcapTdxTinfoilQuoteVerifier,
        case_id: &str,
        quote: &[u8],
    ) {
        let capture = quote_capture();
        let request = quote_request(quote, &capture);
        if let Ok(verified) = verifier.verify_tinfoil_quote(&request) {
            panic!("{case_id}: mutated DCAP quote verified unexpectedly: {verified:?}");
        }
    }

    fn assert_dcap_collateral_rejected(
        now_epoch_millis: u64,
        case_id: &str,
        collateral_json: &[u8],
    ) {
        let result =
            DcapTdxTinfoilQuoteVerifier::from_collateral_json_at(collateral_json, now_epoch_millis)
                .and_then(|verifier| {
                    let capture = quote_capture();
                    let request = quote_request(SAMPLE_QUOTE, &capture);
                    verifier.verify_tinfoil_quote(&request)
                });
        if let Ok(verified) = result {
            panic!("{case_id}: mutated DCAP collateral verified unexpectedly: {verified:?}");
        }
    }

    fn collateral_nested_json(field: DcapCollateralNestedJsonField) -> String {
        let collateral = sample_collateral();
        match field {
            DcapCollateralNestedJsonField::TcbInfo => collateral.tcb_info,
            DcapCollateralNestedJsonField::QeIdentity => collateral.qe_identity,
        }
    }

    fn mutated_collateral_nested_json(
        field: DcapCollateralNestedJsonField,
        value: &str,
    ) -> Vec<u8> {
        let mut collateral = sample_collateral();
        match field {
            DcapCollateralNestedJsonField::TcbInfo => collateral.tcb_info = value.into(),
            DcapCollateralNestedJsonField::QeIdentity => collateral.qe_identity = value.into(),
        }
        serde_json::to_vec(&collateral).unwrap()
    }

    fn sample_bundle_at(fetched_at_epoch_ms: u64) -> DcapTdxCollateralBundle {
        DcapTdxCollateralBundle::from_collateral_at(
            sample_collateral(),
            fetched_at_epoch_ms,
            DcapTdxCollateralSource::offline_bundle(),
            Some(SAMPLE_QUOTE),
        )
        .unwrap()
    }

    fn signed_test_envelope(
        payload: DcapTdxCollateralBundle,
    ) -> (DcapTdxCollateralBundleEnvelope, TrustedSigningKey) {
        let key_pair = KeyPair::from_seed(Seed::new([7u8; 32]));
        let payload_json = crate::canonical_json(&payload).unwrap();
        let signature = key_pair.sk.sign(payload_json.as_bytes(), None);
        let public_key_base64url = URL_SAFE_NO_PAD.encode(key_pair.pk.as_ref());
        let trusted_key = TrustedSigningKey {
            signer: "test".into(),
            key_id: "tdx-collateral-test-key".into(),
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

    fn quote_request<'a>(
        quote_bytes: &'a [u8],
        capture: &'a crate::TinfoilLiveCaptureEvidence,
    ) -> TinfoilQuoteVerificationRequest<'a> {
        TinfoilQuoteVerificationRequest {
            capture,
            attestation_format: TinfoilAttestationFormat::TdxGuestV2,
            quote_bytes,
            live_tls_leaf_certificate_der: &[],
            live_tls_spki_sha256: "",
        }
    }

    fn quote_capture() -> crate::TinfoilLiveCaptureEvidence {
        crate::TinfoilLiveCaptureEvidence {
            schema: crate::TinfoilLiveCaptureEvidence::SCHEMA.into(),
            provider: "tdx-fixture".into(),
            route_id: "tdx-fixture:model:model".into(),
            evidence_family: "tinfoil_hw_verified_tls".into(),
            requested_model: "model".into(),
            policy_digest: "sha256:test".into(),
            nonce: None,
            evidence_endpoint: "https://inference.tinfoil.sh/.well-known/tinfoil-attestation"
                .into(),
            live_tls_spki_sha256: "00".repeat(32),
            live_tls_leaf_certificate_der_base64: String::new(),
            raw_attestation_body_base64: String::new(),
        }
    }

    fn mutated_quote(case: &DcapMalformedCase) -> Vec<u8> {
        let mut quote = SAMPLE_QUOTE.to_vec();
        match case.mutation {
            DcapMalformedMutation::Truncate { len } => quote.truncate(len),
            DcapMalformedMutation::FlipByte { offset, xor } => {
                let byte = quote
                    .get_mut(offset)
                    .unwrap_or_else(|| panic!("{}: quote mutation offset out of range", case.id));
                *byte ^= xor;
            }
            _ => panic!("{}: mutation does not apply to quote target", case.id),
        }
        quote
    }

    fn mutated_collateral_json(case: &DcapMalformedCase) -> Vec<u8> {
        match &case.mutation {
            DcapMalformedMutation::ReplaceJson { value } => value.as_bytes().to_vec(),
            DcapMalformedMutation::ReplaceTcbInfoJson { value } => {
                let mut collateral = sample_collateral();
                collateral.tcb_info.clone_from(value);
                serde_json::to_vec(&collateral).unwrap()
            }
            DcapMalformedMutation::ReplaceQeIdentityJson { value } => {
                let mut collateral = sample_collateral();
                collateral.qe_identity.clone_from(value);
                serde_json::to_vec(&collateral).unwrap()
            }
            _ => panic!(
                "{}: mutation does not apply to collateral_json target",
                case.id
            ),
        }
    }
}
