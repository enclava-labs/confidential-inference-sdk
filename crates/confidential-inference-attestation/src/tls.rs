use crate::{sha256_digest, AttestationError, Result};
use serde::{Deserialize, Serialize};
use x509_cert::der::{Decode, Encode};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsSpkiReportDataBinding {
    pub spki_sha256: String,
    pub report_data_prefix: String,
    pub matches: bool,
}

pub fn certificate_spki_sha256_hex(cert_der: &[u8]) -> Result<String> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|err| AttestationError::InvalidCertificate(err.to_string()))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|err| AttestationError::InvalidCertificate(err.to_string()))?;

    Ok(sha256_digest(&spki_der)
        .trim_start_matches("sha256:")
        .to_owned())
}

pub fn certificate_validity_epoch_millis(cert_der: &[u8]) -> Result<(u64, u64)> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|err| AttestationError::InvalidCertificate(err.to_string()))?;
    let validity = &cert.tbs_certificate.validity;
    let not_before = validity
        .not_before
        .to_unix_duration()
        .as_secs()
        .saturating_mul(1_000);
    let not_after = validity
        .not_after
        .to_unix_duration()
        .as_secs()
        .saturating_mul(1_000);
    Ok((not_before, not_after))
}

pub fn verify_certificate_spki_report_data_binding(
    cert_der: &[u8],
    report_data_hex: &str,
) -> Result<Option<TlsSpkiReportDataBinding>> {
    let spki_sha256 = certificate_spki_sha256_hex(cert_der)?;
    Ok(verify_tls_spki_report_data_binding(
        report_data_hex,
        &spki_sha256,
    ))
}

pub fn verify_tls_spki_report_data_binding(
    report_data_hex: &str,
    spki_sha256_hex: &str,
) -> Option<TlsSpkiReportDataBinding> {
    let spki_sha256 = normalize_sha256_hex(spki_sha256_hex)?;
    let report_data_prefix = report_data_sha256_prefix(report_data_hex)?;
    let matches = report_data_prefix.eq_ignore_ascii_case(&spki_sha256);

    Some(TlsSpkiReportDataBinding {
        spki_sha256,
        report_data_prefix,
        matches,
    })
}

fn normalize_sha256_hex(value: &str) -> Option<String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Some(value.to_ascii_lowercase());
    }

    None
}

fn report_data_sha256_prefix(value: &str) -> Option<String> {
    if value.len() < 64 {
        return None;
    }

    let prefix = &value[..64];
    if prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Some(prefix.to_ascii_lowercase());
    }

    None
}

#[cfg(test)]
pub(crate) const TEST_CERT_DER_BASE64: &str = concat!(
    "MIIDGzCCAgOgAwIBAgIUAjMO3OhvZPgEWRWQYomFbHMN8pUwDQYJKoZIhvcNAQELBQAwHTEb",
    "MBkGA1UEAwwSZW5jbGF2YS10ZXN0LmxvY2FsMB4XDTI2MDcwNTExMDU0NVoXDTI2MDcwNjEx",
    "MDU0NVowHTEbMBkGA1UEAwwSZW5jbGF2YS10ZXN0LmxvY2FsMIIBIjANBgkqhkiG9w0BAQEF",
    "AAOCAQ8AMIIBCgKCAQEArTL6xaF71lFhaA6Ohe4jbzExpBsGvQxg76P9R14jYZz0J6STFJg",
    "Cj4XNWZdymLw3Ua6HBqF/0F6LVpRRtKLMtDqDTDJsINZpA1yqTOJiYsKUG+S6iifhFDkO0MJ",
    "7QV3w1GZi+TRe9ahCpqhKGl/LYlRr3zbaT6Vl2MsJhwonjSzzn08c7937soBxW7s7Fg805j8",
    "UO0mkLb5kfWV72+ET9MEoVaYPgvDeiMJfD6gAK4tZ3q6PBMBxmRqd20Utm1BoGZie7tiyJA4",
    "oH8vjM+Aw8O2HjjBck6Z4PZf11CkZQNvOXu7qwzoIhoTn5au53MYfMgiLM7HTG/9qDTT0VN4",
    "MVQIDAQABo1MwUTAdBgNVHQ4EFgQU2Zf0ANwb0g5UWOKv5FHy5/HjsXgwHwYDVR0jBBgwFoAU",
    "2Zf0ANwb0g5UWOKv5FHy5/HjsXgwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC",
    "AQEAhG5lD+HAEajqUBM2JI0hBctIIhMmJCuTT3zvb1E1pNrBbiPTC1vHLeJdQijCHcFiVuJL",
    "CJh/c99+ymE/1KESiolU+4LIPV2bfSL+3BsB0gg/JuQETSfiUBq3nqscYRBmSDbZkt/UCk6+",
    "GvLQ9A+mEBI+AY4pO7H/OSozdYj2/whN6lxs4wwmtCe/M6gfm3YLKzpBmoDGmw9SZ03canoAn",
    "BzvXi3x7WHy6+6QVdaDj0r0XAYze0wDYUIznSRjUC7o5koYsLI/VRLwVJaPLg6mzlUkZcP1l",
    "4L2zuDEkopTBM7xBVBBoigimsIDhwrpFXs8S9rbe94bRvTSppx51oUiUg==",
);

#[cfg(test)]
pub(crate) const TEST_SPKI_SHA256: &str =
    "fd162e4bf87ec09d1c2e6c1acb9161534bc91eb2ee822d5aab5008b08e47dfaa";

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn certificate_spki_sha256_hex_matches_known_der() {
        let cert_der = test_cert_der();

        assert_eq!(
            certificate_spki_sha256_hex(&cert_der).unwrap(),
            TEST_SPKI_SHA256
        );
    }

    #[test]
    fn certificate_validity_is_read_from_der() {
        let cert_der = test_cert_der();

        let (not_before, not_after) = certificate_validity_epoch_millis(&cert_der).unwrap();

        assert_eq!(
            crate::format_utc_timestamp_millis(not_before),
            "2026-07-05T11:05:45Z"
        );
        assert_eq!(
            crate::format_utc_timestamp_millis(not_after),
            "2026-07-06T11:05:45Z"
        );
    }

    #[test]
    fn tls_spki_report_data_binding_matches_prefix() {
        let report_data = format!(
            "{}{}",
            TEST_SPKI_SHA256.to_ascii_uppercase(),
            "00".repeat(32)
        );

        let binding = verify_tls_spki_report_data_binding(&report_data, TEST_SPKI_SHA256).unwrap();

        assert_eq!(
            binding,
            TlsSpkiReportDataBinding {
                spki_sha256: TEST_SPKI_SHA256.into(),
                report_data_prefix: TEST_SPKI_SHA256.into(),
                matches: true,
            }
        );
    }

    #[test]
    fn certificate_spki_report_data_binding_combines_parse_and_compare() {
        let cert_der = test_cert_der();
        let report_data = format!("{}{}", TEST_SPKI_SHA256, "00".repeat(32));

        let binding = verify_certificate_spki_report_data_binding(&cert_der, &report_data)
            .unwrap()
            .unwrap();

        assert!(binding.matches);
    }

    #[test]
    fn tls_spki_report_data_binding_detects_mismatch() {
        let report_data = format!("{}{}", "00".repeat(32), "11".repeat(32));

        let binding = verify_tls_spki_report_data_binding(&report_data, TEST_SPKI_SHA256).unwrap();

        assert!(!binding.matches);
        assert_eq!(binding.report_data_prefix, "00".repeat(32));
    }

    #[test]
    fn tls_spki_report_data_binding_rejects_invalid_inputs() {
        assert!(verify_tls_spki_report_data_binding("abc", TEST_SPKI_SHA256).is_none());
        assert!(verify_tls_spki_report_data_binding(&"zz".repeat(32), TEST_SPKI_SHA256).is_none());
        assert!(verify_tls_spki_report_data_binding(&"00".repeat(32), "abc").is_none());
        assert!(verify_tls_spki_report_data_binding(&"00".repeat(32), &"zz".repeat(32)).is_none());
    }

    #[test]
    fn certificate_spki_sha256_hex_rejects_non_certificate_der() {
        assert!(matches!(
            certificate_spki_sha256_hex(b"not a cert"),
            Err(AttestationError::InvalidCertificate(_))
        ));
    }

    fn test_cert_der() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(TEST_CERT_DER_BASE64)
            .unwrap()
    }
}
