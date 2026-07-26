use crate::sha256_digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChutesE2eeReportDataBinding {
    Verified,
    InvalidNonce,
    MissingPublicKey,
    ReportDataMismatch,
}

pub fn chutes_expected_report_data_prefix(nonce_hex: &str, e2e_public_key: &str) -> Option<String> {
    if !is_canonical_nonce_hex(nonce_hex) {
        return None;
    }
    if e2e_public_key.is_empty() {
        return None;
    }

    Some(
        sha256_digest(format!("{nonce_hex}{e2e_public_key}").as_bytes())
            .trim_start_matches("sha256:")
            .to_owned(),
    )
}

pub fn chutes_provider_nonce(request_nonce: &str) -> String {
    if is_canonical_nonce_hex(request_nonce) {
        return request_nonce.to_ascii_lowercase();
    }

    sha256_digest(format!("confidential-inference.chutes.nonce.v1:{request_nonce}").as_bytes())
        .trim_start_matches("sha256:")
        .to_owned()
}

pub fn verify_chutes_e2ee_report_data_binding(
    report_data_hex: &str,
    nonce_hex: &str,
    e2e_public_key: &str,
) -> ChutesE2eeReportDataBinding {
    if !is_canonical_nonce_hex(nonce_hex) {
        return ChutesE2eeReportDataBinding::InvalidNonce;
    }
    if e2e_public_key.is_empty() {
        return ChutesE2eeReportDataBinding::MissingPublicKey;
    }

    let expected = chutes_expected_report_data_prefix(nonce_hex, e2e_public_key)
        .expect("nonce and public key were prevalidated");
    if report_data_hex.len() >= expected.len()
        && report_data_hex[..expected.len()].eq_ignore_ascii_case(&expected)
    {
        ChutesE2eeReportDataBinding::Verified
    } else {
        ChutesE2eeReportDataBinding::ReportDataMismatch
    }
}

fn is_canonical_nonce_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chutes_e2ee_report_data_binding_matches_nonce_and_key() {
        let nonce = "11".repeat(32);
        let public_key = "test-public-key";
        let expected = chutes_expected_report_data_prefix(&nonce, public_key).unwrap();
        let report_data = format!("{}{}", expected, "00".repeat(32));

        assert_eq!(
            verify_chutes_e2ee_report_data_binding(&report_data, &nonce, public_key),
            ChutesE2eeReportDataBinding::Verified
        );
    }

    #[test]
    fn chutes_e2ee_report_data_binding_rejects_wrong_key() {
        let nonce = "11".repeat(32);
        let public_key = "test-public-key";
        let expected = chutes_expected_report_data_prefix(&nonce, public_key).unwrap();
        let report_data = format!("{}{}", expected, "00".repeat(32));

        assert_eq!(
            verify_chutes_e2ee_report_data_binding(&report_data, &nonce, "wrong-public-key"),
            ChutesE2eeReportDataBinding::ReportDataMismatch
        );
    }

    #[test]
    fn chutes_e2ee_report_data_binding_rejects_wrong_nonce() {
        let nonce = "11".repeat(32);
        let public_key = "test-public-key";
        let expected = chutes_expected_report_data_prefix(&nonce, public_key).unwrap();
        let report_data = format!("{}{}", expected, "00".repeat(32));

        assert_eq!(
            verify_chutes_e2ee_report_data_binding(&report_data, &"22".repeat(32), public_key),
            ChutesE2eeReportDataBinding::ReportDataMismatch
        );
    }

    #[test]
    fn chutes_e2ee_report_data_binding_rejects_invalid_inputs() {
        assert_eq!(
            verify_chutes_e2ee_report_data_binding("", "not-hex", "public-key"),
            ChutesE2eeReportDataBinding::InvalidNonce
        );
        assert_eq!(
            verify_chutes_e2ee_report_data_binding("", &"11".repeat(32), ""),
            ChutesE2eeReportDataBinding::MissingPublicKey
        );
    }

    #[test]
    fn chutes_provider_nonce_preserves_canonical_nonce_or_derives_one() {
        let canonical = "AB".repeat(32);
        assert_eq!(chutes_provider_nonce(&canonical), "ab".repeat(32));

        let derived = chutes_provider_nonce(&"11".repeat(16));
        assert_eq!(derived.len(), 64);
        assert!(derived.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(derived, derived.to_ascii_lowercase());
    }
}
