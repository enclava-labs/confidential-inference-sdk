use crate::sha256_digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdxQuoteMeasurements {
    pub mr_td: String,
    pub rtmr0: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DstackTcbInfo {
    pub mrtd: String,
    pub rtmr0: String,
    pub app_compose: String,
    pub compose_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcbComposeHashBinding {
    Verified,
    MissingBinding,
    MeasurementMismatch,
    ComposeHashMismatch,
}

pub fn verify_dstack_tcb_compose_hash(
    tcb_info: Option<&DstackTcbInfo>,
    measurements: Option<&TdxQuoteMeasurements>,
) -> TcbComposeHashBinding {
    let Some(tcb_info) = tcb_info else {
        return TcbComposeHashBinding::MissingBinding;
    };
    let Some(measurements) = measurements else {
        return TcbComposeHashBinding::MissingBinding;
    };
    if tcb_info.mrtd.is_empty() || tcb_info.rtmr0.is_empty() {
        return TcbComposeHashBinding::MissingBinding;
    }
    if tcb_info.mrtd != measurements.mr_td || tcb_info.rtmr0 != measurements.rtmr0 {
        return TcbComposeHashBinding::MeasurementMismatch;
    }

    let computed = sha256_digest(tcb_info.app_compose.as_bytes());
    let computed = computed.trim_start_matches("sha256:");
    if computed == tcb_info.compose_hash {
        TcbComposeHashBinding::Verified
    } else {
        TcbComposeHashBinding::ComposeHashMismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcb_compose_hash_verifies_when_measurements_match_quote() {
        let tcb_info = tcb_info("a1", "b2", r#"{"image":"app:1"}"#);
        let measurements = measurements("a1", "b2");

        assert_eq!(
            verify_dstack_tcb_compose_hash(Some(&tcb_info), Some(&measurements)),
            TcbComposeHashBinding::Verified
        );
    }

    #[test]
    fn tcb_compose_hash_rejects_provider_json_that_does_not_match_quote() {
        let tcb_info = tcb_info("deadbeef", "b2", r#"{"image":"app:1"}"#);
        let measurements = measurements("a1", "b2");

        assert_eq!(
            verify_dstack_tcb_compose_hash(Some(&tcb_info), Some(&measurements)),
            TcbComposeHashBinding::MeasurementMismatch
        );
    }

    #[test]
    fn tcb_compose_hash_rejects_self_inconsistent_tcb_info() {
        let mut tcb_info = tcb_info("a1", "b2", r#"{"image":"app:1"}"#);
        tcb_info.compose_hash = "00".repeat(32);
        let measurements = measurements("a1", "b2");

        assert_eq!(
            verify_dstack_tcb_compose_hash(Some(&tcb_info), Some(&measurements)),
            TcbComposeHashBinding::ComposeHashMismatch
        );
    }

    #[test]
    fn tcb_compose_hash_reports_missing_binding_without_tcb_or_quote_measurements() {
        let tcb_info = tcb_info("a1", "b2", r#"{"image":"app:1"}"#);
        let measurements = measurements("a1", "b2");
        let mut missing_measurements = tcb_info.clone();
        missing_measurements.mrtd.clear();

        assert_eq!(
            verify_dstack_tcb_compose_hash(None, Some(&measurements)),
            TcbComposeHashBinding::MissingBinding
        );
        assert_eq!(
            verify_dstack_tcb_compose_hash(Some(&tcb_info), None),
            TcbComposeHashBinding::MissingBinding
        );
        assert_eq!(
            verify_dstack_tcb_compose_hash(Some(&missing_measurements), Some(&measurements)),
            TcbComposeHashBinding::MissingBinding
        );
    }

    fn tcb_info(mrtd: &str, rtmr0: &str, app_compose: &str) -> DstackTcbInfo {
        let digest = sha256_digest(app_compose.as_bytes());
        DstackTcbInfo {
            mrtd: mrtd.repeat(24),
            rtmr0: rtmr0.repeat(24),
            app_compose: app_compose.into(),
            compose_hash: digest.trim_start_matches("sha256:").into(),
        }
    }

    fn measurements(mr_td: &str, rtmr0: &str) -> TdxQuoteMeasurements {
        TdxQuoteMeasurements {
            mr_td: mr_td.repeat(24),
            rtmr0: rtmr0.repeat(24),
        }
    }
}
