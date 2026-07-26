use crate::{
    certificate_spki_sha256_hex, ArtifactDigest, AttestationError, CpuTeeKind, EvidenceHardware,
    Result, TinfoilLiveCaptureEvidence,
};
use base64::Engine;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::io::Read;

pub const TINFOIL_TDX_GUEST_V2_FORMAT: &str = "https://tinfoil.sh/predicate/tdx-guest/v2";
pub const TINFOIL_SEV_SNP_GUEST_V2_FORMAT: &str = "https://tinfoil.sh/predicate/sev-snp-guest/v2";

const MAX_TINFOIL_ATTESTATION_BODY_BYTES: usize = 1024 * 1024;
const MIN_TDX_QUOTE_BYTES: usize = 48;
const SNP_REPORT_BYTES: usize = 1184;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TinfoilAttestationDoc {
    pub format: String,
    pub body: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TinfoilAttestationFormat {
    TdxGuestV2,
    SevSnpGuestV2,
}

impl TinfoilAttestationFormat {
    pub fn parse(format: &str) -> Result<Self> {
        match format {
            TINFOIL_TDX_GUEST_V2_FORMAT => Ok(Self::TdxGuestV2),
            TINFOIL_SEV_SNP_GUEST_V2_FORMAT => Ok(Self::SevSnpGuestV2),
            other => Err(AttestationError::InvalidEvidence(format!(
                "unknown Tinfoil attestation format {other}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::TdxGuestV2 => TINFOIL_TDX_GUEST_V2_FORMAT,
            Self::SevSnpGuestV2 => TINFOIL_SEV_SNP_GUEST_V2_FORMAT,
        }
    }

    pub fn quote_kind(self) -> &'static str {
        match self {
            Self::TdxGuestV2 => "TDX",
            Self::SevSnpGuestV2 => "SEV-SNP",
        }
    }

    pub fn cpu_kind(self) -> CpuTeeKind {
        match self {
            Self::TdxGuestV2 => CpuTeeKind::Tdx,
            Self::SevSnpGuestV2 => CpuTeeKind::SevSnp,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTinfoilLiveCapture {
    pub capture: TinfoilLiveCaptureEvidence,
    pub attestation_doc: TinfoilAttestationDoc,
    pub attestation_format: TinfoilAttestationFormat,
    pub quote_bytes: Vec<u8>,
    pub live_tls_leaf_certificate_der: Vec<u8>,
}

#[derive(Debug)]
pub struct TinfoilQuoteVerificationRequest<'a> {
    pub capture: &'a TinfoilLiveCaptureEvidence,
    pub attestation_format: TinfoilAttestationFormat,
    pub quote_bytes: &'a [u8],
    pub live_tls_leaf_certificate_der: &'a [u8],
    pub live_tls_spki_sha256: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedTinfoilQuote {
    pub attestation_format: String,
    pub hardware: EvidenceHardware,
    pub tee_measurement: String,
    pub report_data: String,
    pub issued_at: String,
    pub expires_at: String,
    pub expires_at_epoch_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_image_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_artifacts: Vec<ArtifactDigest>,
}

impl VerifiedTinfoilQuote {
    pub fn from_verified_quote(
        attestation_format: TinfoilAttestationFormat,
        hardware: EvidenceHardware,
        tee_measurement: impl Into<String>,
        report_data: impl Into<String>,
        issued_at: impl Into<String>,
        expires_at: impl Into<String>,
        expires_at_epoch_ms: u64,
    ) -> Self {
        Self {
            attestation_format: attestation_format.as_str().into(),
            hardware,
            tee_measurement: tee_measurement.into(),
            report_data: report_data.into(),
            issued_at: issued_at.into(),
            expires_at: expires_at.into(),
            expires_at_epoch_ms,
            attested_model: None,
            workload_image_digest: None,
            model_artifacts: Vec::new(),
        }
    }
}

pub trait TinfoilQuoteVerifier: Send + Sync {
    fn verify_tinfoil_quote(
        &self,
        request: &TinfoilQuoteVerificationRequest<'_>,
    ) -> Result<VerifiedTinfoilQuote>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FailClosedTinfoilQuoteVerifier;

impl TinfoilQuoteVerifier for FailClosedTinfoilQuoteVerifier {
    fn verify_tinfoil_quote(
        &self,
        request: &TinfoilQuoteVerificationRequest<'_>,
    ) -> Result<VerifiedTinfoilQuote> {
        Err(AttestationError::InvalidEvidence(format!(
            "live Tinfoil {} capture requires TDX/SNP quote verification before it can authorize requests",
            request.attestation_format.quote_kind()
        )))
    }
}

pub fn parse_tinfoil_live_capture(raw: &[u8]) -> Result<ParsedTinfoilLiveCapture> {
    let capture: TinfoilLiveCaptureEvidence = serde_json::from_slice(raw)?;
    if capture.schema != TinfoilLiveCaptureEvidence::SCHEMA {
        return Err(AttestationError::InvalidEvidence(format!(
            "unsupported schema {}",
            capture.schema
        )));
    }

    let live_tls_leaf_certificate_der = decode_base64_field(
        "live_tls_leaf_certificate_der_base64",
        &capture.live_tls_leaf_certificate_der_base64,
    )?;
    let observed_spki = certificate_spki_sha256_hex(&live_tls_leaf_certificate_der)?;
    if !observed_spki.eq_ignore_ascii_case(&capture.live_tls_spki_sha256) {
        return Err(AttestationError::InvalidEvidence(
            "live TLS SPKI digest does not match captured leaf certificate".into(),
        ));
    }

    let raw_attestation_body = decode_base64_field(
        "raw_attestation_body_base64",
        &capture.raw_attestation_body_base64,
    )?;
    let attestation_doc: TinfoilAttestationDoc = serde_json::from_slice(&raw_attestation_body)
        .map_err(|err| {
            AttestationError::InvalidEvidence(format!("invalid Tinfoil attestation JSON: {err}"))
        })?;
    let attestation_format = TinfoilAttestationFormat::parse(&attestation_doc.format)?;
    let quote_bytes = decode_tinfoil_attestation_body(&attestation_doc.body)?;
    validate_quote_shape(attestation_format, quote_bytes.len())?;

    Ok(ParsedTinfoilLiveCapture {
        capture,
        attestation_doc,
        attestation_format,
        quote_bytes,
        live_tls_leaf_certificate_der,
    })
}

pub fn decode_tinfoil_attestation_body(body: &str) -> Result<Vec<u8>> {
    let compressed = decode_base64_field("body", body)?;
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut out = Vec::new();
    decoder
        .by_ref()
        .take((MAX_TINFOIL_ATTESTATION_BODY_BYTES + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|err| {
            AttestationError::InvalidEvidence(format!(
                "invalid gzip in Tinfoil attestation body: {err}"
            ))
        })?;
    if out.len() > MAX_TINFOIL_ATTESTATION_BODY_BYTES {
        return Err(AttestationError::InvalidEvidence(format!(
            "Tinfoil attestation body exceeds {MAX_TINFOIL_ATTESTATION_BODY_BYTES} bytes"
        )));
    }

    Ok(out)
}

fn validate_quote_shape(format: TinfoilAttestationFormat, len: usize) -> Result<()> {
    match format {
        TinfoilAttestationFormat::TdxGuestV2 if len < MIN_TDX_QUOTE_BYTES => {
            Err(AttestationError::InvalidEvidence(format!(
                "decoded TDX quote is too short: {len} bytes"
            )))
        }
        TinfoilAttestationFormat::SevSnpGuestV2 if len != SNP_REPORT_BYTES => {
            Err(AttestationError::InvalidEvidence(format!(
                "decoded SEV-SNP report has wrong size: {len} bytes"
            )))
        }
        _ => Ok(()),
    }
}

fn decode_base64_field(field: &str, value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|err| {
            AttestationError::InvalidEvidence(format!("{field} is not valid base64: {err}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    #[test]
    fn live_capture_parser_decodes_tdx_attestation_document() {
        let quote = vec![7_u8; MIN_TDX_QUOTE_BYTES];
        let raw = live_capture_json(TINFOIL_TDX_GUEST_V2_FORMAT, &quote);

        let parsed = parse_tinfoil_live_capture(&raw).unwrap();

        assert_eq!(
            parsed.attestation_format,
            TinfoilAttestationFormat::TdxGuestV2
        );
        assert_eq!(parsed.quote_bytes, quote);
        assert_eq!(
            parsed.capture.live_tls_spki_sha256,
            crate::tls::TEST_SPKI_SHA256
        );
    }

    #[test]
    fn live_capture_parser_decodes_snp_attestation_document() {
        let report = vec![9_u8; SNP_REPORT_BYTES];
        let raw = live_capture_json(TINFOIL_SEV_SNP_GUEST_V2_FORMAT, &report);

        let parsed = parse_tinfoil_live_capture(&raw).unwrap();

        assert_eq!(
            parsed.attestation_format,
            TinfoilAttestationFormat::SevSnpGuestV2
        );
        assert_eq!(parsed.quote_bytes, report);
    }

    #[test]
    fn live_capture_parser_rejects_unknown_format() {
        let raw = live_capture_json("unknown-live-capture-format", &[1; 48]);

        let error = parse_tinfoil_live_capture(&raw).unwrap_err();

        assert!(error
            .to_string()
            .contains("unknown Tinfoil attestation format"));
    }

    #[test]
    fn live_capture_parser_rejects_tls_spki_mismatch() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&live_capture_json(TINFOIL_TDX_GUEST_V2_FORMAT, &[1; 48]))
                .unwrap();
        value["live_tls_spki_sha256"] = serde_json::Value::String("00".repeat(32));
        let raw = serde_json::to_vec(&value).unwrap();

        let error = parse_tinfoil_live_capture(&raw).unwrap_err();

        assert!(error.to_string().contains("SPKI digest does not match"));
    }

    #[test]
    fn live_capture_parser_rejects_snp_report_with_wrong_size() {
        let raw = live_capture_json(TINFOIL_SEV_SNP_GUEST_V2_FORMAT, &[1; 48]);

        let error = parse_tinfoil_live_capture(&raw).unwrap_err();

        assert!(error.to_string().contains("wrong size"));
    }

    pub(crate) fn live_capture_json(format: &str, quote_bytes: &[u8]) -> Vec<u8> {
        let attestation_doc = serde_json::json!({
            "format": format,
            "body": gzip_base64(quote_bytes),
        });
        serde_json::to_vec(&serde_json::json!({
            "schema": TinfoilLiveCaptureEvidence::SCHEMA,
            "provider": "tinfoil-fixture",
            "route_id": "tinfoil-fixture:llama-3-3-70b:llama-3-3-70b",
            "evidence_family": "tinfoil_hw_verified_tls",
            "requested_model": "llama-3-3-70b",
            "policy_digest": "sha256:test-policy",
            "evidence_endpoint": "https://inference.tinfoil.sh/.well-known/tinfoil-attestation",
            "live_tls_spki_sha256": crate::tls::TEST_SPKI_SHA256,
            "live_tls_leaf_certificate_der_base64": crate::tls::TEST_CERT_DER_BASE64,
            "raw_attestation_body_base64": base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&attestation_doc).unwrap()),
        }))
        .unwrap()
    }

    fn gzip_base64(bytes: &[u8]) -> String {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        base64::engine::general_purpose::STANDARD.encode(encoder.finish().unwrap())
    }
}
