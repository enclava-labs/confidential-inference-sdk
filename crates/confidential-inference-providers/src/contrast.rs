use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::{ProviderError, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivatemodeContrastManifestSummary {
    pub manifest_sha256: String,
    pub reference_values: Vec<String>,
    pub workloads: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivatemodeContrastImageSummary {
    pub image_refs: Vec<String>,
    pub images_verified: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivatemodeContrastActiveEvidence {
    pub manifest_bytes: Vec<u8>,
    pub initdata_texts: Vec<String>,
    pub coordinator_attestation_verified: bool,
    pub local_proxy_model_path: Option<String>,
    pub expected_model_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivatemodeContrastActiveVerification {
    pub manifest: PrivatemodeContrastManifestSummary,
    pub images: PrivatemodeContrastImageSummary,
    pub model_path: String,
}

pub fn summarize_privatemode_contrast_manifest_bytes(
    manifest_bytes: &[u8],
) -> Result<PrivatemodeContrastManifestSummary> {
    let manifest_sha256 = sha256_hex(manifest_bytes);
    let manifest: Value = serde_json::from_slice(manifest_bytes)?;
    let mut reference_values = vec![format!("manifest-sha256:{manifest_sha256}")];
    reference_values.extend(extract_reference_values(&manifest));
    let workloads = extract_manifest_workloads(&manifest);

    Ok(PrivatemodeContrastManifestSummary {
        manifest_sha256,
        reference_values,
        workloads,
    })
}

pub fn summarize_privatemode_contrast_initdata_texts<'a>(
    texts: impl IntoIterator<Item = &'a str>,
) -> PrivatemodeContrastImageSummary {
    let mut image_names = HashSet::new();
    let mut digest_refs = HashSet::new();

    for text in texts {
        for value in extract_marker_image_values(text, "io.kubernetes.cri.image-name\\\": \\\"") {
            image_names.insert(value);
        }
        for value in extract_marker_image_values(text, "io.kubernetes.cri.image-name\": \"") {
            image_names.insert(value);
        }
        for value in extract_digest_pinned_image_refs(text) {
            digest_refs.insert(value);
        }
    }

    let mut image_refs = if image_names.is_empty() {
        digest_refs.into_iter().collect::<Vec<_>>()
    } else {
        image_names.into_iter().collect::<Vec<_>>()
    };
    image_refs.sort();
    image_refs.dedup();
    let images_verified = if image_refs.is_empty() {
        None
    } else {
        Some(image_refs.iter().all(|image| has_valid_sha256_pin(image)))
    };

    PrivatemodeContrastImageSummary {
        image_refs,
        images_verified,
    }
}

pub fn require_privatemode_contrast_images_verified(
    summary: &PrivatemodeContrastImageSummary,
) -> Result<()> {
    match summary.images_verified {
        Some(true) => Ok(()),
        Some(false) => Err(ProviderError::Compatibility(
            "Privatemode Contrast initdata contains unpinned workload image references".into(),
        )),
        None => Err(ProviderError::Compatibility(
            "Privatemode Contrast initdata did not expose workload image references".into(),
        )),
    }
}

pub fn verify_privatemode_contrast_active_evidence(
    evidence: &PrivatemodeContrastActiveEvidence,
) -> Result<PrivatemodeContrastActiveVerification> {
    let manifest = summarize_privatemode_contrast_manifest_bytes(&evidence.manifest_bytes)?;
    require_privatemode_contrast_manifest_active(&manifest)?;

    let images = summarize_privatemode_contrast_initdata_texts(
        evidence.initdata_texts.iter().map(String::as_str),
    );
    require_privatemode_contrast_images_verified(&images)?;

    if !evidence.coordinator_attestation_verified {
        return Err(ProviderError::Compatibility(
            "Privatemode Contrast Coordinator attestation was not verified".into(),
        ));
    }

    let expected_model_path = required_model_path(
        evidence.expected_model_path.as_deref(),
        "Privatemode Contrast expected model path was not configured",
    )?;
    let local_proxy_model_path = required_model_path(
        evidence.local_proxy_model_path.as_deref(),
        "Privatemode Contrast local proxy model path was not confirmed",
    )?;

    if local_proxy_model_path != expected_model_path {
        return Err(ProviderError::Compatibility(
            "Privatemode Contrast local proxy model path mismatch".into(),
        ));
    }

    Ok(PrivatemodeContrastActiveVerification {
        manifest,
        images,
        model_path: local_proxy_model_path.to_owned(),
    })
}

fn extract_reference_values(manifest: &Value) -> Vec<String> {
    let mut reference_values = Vec::new();
    if let Some(snp_refs) = manifest
        .get("ReferenceValues")
        .and_then(|rv| rv.get("snp"))
        .and_then(Value::as_array)
    {
        for entry in snp_refs {
            if let Some(measurement) = string_field(entry, &["TrustedMeasurement"])
                .or_else(|| string_field(entry, &["measurement"]))
            {
                let product = string_field(entry, &["ProductName"])
                    .or_else(|| string_field(entry, &["product_name"]))
                    .unwrap_or_else(|| "unknown".into());
                reference_values.push(format!(
                    "SNP/{product}:{}",
                    &measurement[..24.min(measurement.len())]
                ));
            }
        }
    }
    if let Some(tdx_refs) = manifest
        .get("ReferenceValues")
        .and_then(|rv| rv.get("tdx"))
        .and_then(Value::as_array)
    {
        for entry in tdx_refs {
            if let Some(mr_td) =
                string_field(entry, &["MrTd"]).or_else(|| string_field(entry, &["mr_td"]))
            {
                reference_values.push(format!("TDX:{}", &mr_td[..24.min(mr_td.len())]));
            }
        }
    }
    reference_values.sort();
    reference_values.dedup();
    reference_values
}

fn extract_manifest_workloads(manifest: &Value) -> Vec<String> {
    let mut workloads = Vec::new();
    if let Some(policies) = manifest.get("Policies").and_then(Value::as_object) {
        for policy in policies.values() {
            let sans = policy
                .get("SANs")
                .or_else(|| policy.get("sans"))
                .and_then(Value::as_array)
                .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .unwrap_or_default();
            let role = policy
                .get("Role")
                .or_else(|| policy.get("role"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if role == "coordinator" {
                workloads.push("coordinator".into());
            } else if let Some(name) = sans.iter().find(|san| san.starts_with("workload-")) {
                workloads.push(name.trim_start_matches("workload-").into());
            }
        }
    }
    workloads.sort();
    workloads.dedup();
    workloads
}

fn require_privatemode_contrast_manifest_active(
    summary: &PrivatemodeContrastManifestSummary,
) -> Result<()> {
    let has_platform_reference = summary
        .reference_values
        .iter()
        .any(|value| !value.starts_with("manifest-sha256:"));
    if !has_platform_reference {
        return Err(ProviderError::Compatibility(
            "Privatemode Contrast manifest did not expose platform reference values".into(),
        ));
    }

    if !summary
        .workloads
        .iter()
        .any(|workload| workload == "coordinator")
    {
        return Err(ProviderError::Compatibility(
            "Privatemode Contrast manifest did not expose a coordinator workload".into(),
        ));
    }

    Ok(())
}

fn required_model_path<'a>(value: Option<&'a str>, message: &str) -> Result<&'a str> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ProviderError::Compatibility(message.into()))
}

fn extract_marker_image_values(text: &str, marker: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut offset = 0;
    while let Some(position) = text[offset..].find(marker) {
        let value_start = offset + position + marker.len();
        let value = text[value_start..]
            .chars()
            .take_while(|c| is_image_ref_char(*c))
            .collect::<String>();
        if looks_like_container_image_ref(&value) {
            values.push(value);
        }
        offset = value_start.saturating_add(1);
    }
    values
}

fn extract_digest_pinned_image_refs(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut refs = Vec::new();
    let mut offset = 0;

    while let Some(position) = text[offset..].find("@sha256:") {
        let at_position = offset + position;
        let digest_start = at_position + "@sha256:".len();
        if digest_start + 64 > bytes.len()
            || !bytes[digest_start..digest_start + 64]
                .iter()
                .all(u8::is_ascii_hexdigit)
        {
            offset = digest_start;
            continue;
        }

        let mut start = at_position;
        while start > 0 && is_image_ref_byte(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = digest_start + 64;
        while end < bytes.len() && is_image_ref_byte(bytes[end]) {
            end += 1;
        }
        if let Ok(value) = std::str::from_utf8(&bytes[start..end]) {
            if looks_like_container_image_ref(value) {
                refs.push(value.to_string());
            }
        }
        offset = end;
    }

    refs
}

fn has_valid_sha256_pin(value: &str) -> bool {
    let Some(position) = value.find("@sha256:") else {
        return false;
    };
    let digest_start = position + "@sha256:".len();
    value[digest_start..].len() == 64
        && value[digest_start..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn looks_like_container_image_ref(value: &str) -> bool {
    let Some((registry, _)) = value.split_once('/') else {
        return false;
    };
    !value.is_empty()
        && registry.contains('.')
        && value
            .bytes()
            .all(|byte| is_image_ref_byte(byte) || byte.is_ascii_hexdigit())
}

fn is_image_ref_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, '.' | '_' | '-' | '/' | ':' | '@')
}

fn is_image_ref_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-' | b'/' | b':' | b'@')
}

fn string_field(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(ToOwned::to_owned)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const MODEL_PATH: &str = "privatemode/models/llama-3.1-8b";

    #[derive(Debug, Deserialize)]
    struct PrivatemodeContrastActiveCorpus {
        schema: String,
        cases: Vec<PrivatemodeContrastActiveCorpusCase>,
    }

    #[derive(Debug, Deserialize)]
    struct PrivatemodeContrastActiveCorpusCase {
        id: String,
        manifest: Value,
        initdata_texts: Vec<String>,
        coordinator_attestation_verified: bool,
        local_proxy_model_path: Option<String>,
        expected_model_path: Option<String>,
        expected: Option<ExpectedPrivatemodeContrastActiveVerification>,
        expected_error_contains: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct ExpectedPrivatemodeContrastActiveVerification {
        model_path: String,
        workloads: Vec<String>,
        reference_values: Vec<String>,
        image_refs: Vec<String>,
    }

    fn active_contrast_manifest_bytes() -> Vec<u8> {
        let manifest = serde_json::json!({
            "ReferenceValues": {
                "snp": [{
                    "ProductName": "Genoa",
                    "TrustedMeasurement": "33".repeat(48)
                }]
            },
            "Policies": {
                "coordinator-policy": {
                    "Role": "coordinator",
                    "SANs": ["coordinator.privatemode.ai"]
                },
                "worker-policy": {
                    "Role": "worker",
                    "SANs": ["workload-inference-proxy"]
                }
            }
        });
        serde_json::to_vec(&manifest).unwrap()
    }

    fn active_contrast_initdata_text() -> String {
        format!(
            r#"\"io.kubernetes.cri.image-name\": \"ghcr.io/edgelesssys/privatemode/inference-proxy:v1.45.0@sha256:{}\""#,
            "44".repeat(32)
        )
    }

    fn active_contrast_evidence() -> PrivatemodeContrastActiveEvidence {
        PrivatemodeContrastActiveEvidence {
            manifest_bytes: active_contrast_manifest_bytes(),
            initdata_texts: vec![active_contrast_initdata_text()],
            coordinator_attestation_verified: true,
            local_proxy_model_path: Some(MODEL_PATH.into()),
            expected_model_path: Some(MODEL_PATH.into()),
        }
    }

    #[test]
    fn privatemode_contrast_active_corpus_matches_expected_outcomes() {
        let corpus: PrivatemodeContrastActiveCorpus = serde_json::from_str(include_str!(
            "../../../fixtures/providers/privatemode-contrast-active-corpus.json"
        ))
        .unwrap();
        assert_eq!(
            corpus.schema,
            "confidential-inference.privatemode-contrast-active-corpus.v1"
        );

        for case in corpus.cases {
            let evidence = PrivatemodeContrastActiveEvidence {
                manifest_bytes: serde_json::to_vec(&case.manifest).unwrap(),
                initdata_texts: case.initdata_texts.clone(),
                coordinator_attestation_verified: case.coordinator_attestation_verified,
                local_proxy_model_path: case.local_proxy_model_path.clone(),
                expected_model_path: case.expected_model_path.clone(),
            };
            let result = verify_privatemode_contrast_active_evidence(&evidence);

            match (
                case.expected.as_ref(),
                case.expected_error_contains.as_deref(),
                result,
            ) {
                (Some(expected), None, Ok(actual)) => {
                    assert_eq!(
                        actual.model_path, expected.model_path,
                        "{}: model path",
                        case.id
                    );
                    assert_eq!(
                        actual.manifest.workloads, expected.workloads,
                        "{}: workloads",
                        case.id
                    );
                    for reference_value in &expected.reference_values {
                        assert!(
                            actual.manifest.reference_values.contains(reference_value),
                            "{}: missing reference value {reference_value:?} in {:?}",
                            case.id,
                            actual.manifest.reference_values
                        );
                    }
                    assert_eq!(
                        actual.images.image_refs, expected.image_refs,
                        "{}: image refs",
                        case.id
                    );
                    assert_eq!(
                        actual.images.images_verified,
                        Some(true),
                        "{}: image verification",
                        case.id
                    );
                }
                (None, Some(expected_error), Err(error)) => {
                    let error = error.to_string();
                    assert!(
                        error.contains(expected_error),
                        "{}: expected error containing {:?}, got {error:?}",
                        case.id,
                        expected_error
                    );
                }
                (Some(_), None, Err(error)) => {
                    panic!(
                        "{}: expected active verification success, got {error}",
                        case.id
                    );
                }
                (None, Some(_), Ok(actual)) => {
                    panic!(
                        "{}: expected active verification failure, got {:?}",
                        case.id, actual
                    );
                }
                _ => panic!(
                    "{}: corpus case must define exactly one expected outcome",
                    case.id
                ),
            }
        }
    }

    #[test]
    fn privatemode_manifest_summary_extracts_reference_values_and_workloads() {
        let manifest = serde_json::json!({
            "ReferenceValues": {
                "snp": [{
                    "ProductName": "Milan",
                    "TrustedMeasurement": "11".repeat(48)
                }],
                "tdx": [{
                    "MrTd": "22".repeat(48)
                }]
            },
            "Policies": {
                "coordinator-policy": {
                    "Role": "coordinator",
                    "SANs": ["coordinator.privatemode.ai"]
                },
                "worker-policy": {
                    "Role": "worker",
                    "SANs": ["workload-inference-proxy", "internal.local"]
                }
            }
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();

        let summary = summarize_privatemode_contrast_manifest_bytes(&bytes).unwrap();

        assert_eq!(summary.manifest_sha256, sha256_hex(&bytes));
        assert!(summary
            .reference_values
            .contains(&format!("manifest-sha256:{}", sha256_hex(&bytes))));
        assert!(summary
            .reference_values
            .contains(&format!("SNP/Milan:{}", "11".repeat(12))));
        assert!(summary
            .reference_values
            .contains(&format!("TDX:{}", "22".repeat(12))));
        assert_eq!(summary.workloads, vec!["coordinator", "inference-proxy"]);
    }

    #[test]
    fn privatemode_initdata_extracts_digest_pinned_image_refs() {
        let text = r#"\"io.kubernetes.cri.image-name\": \"ghcr.io/edgelesssys/privatemode/inference-proxy:v1.45.0@sha256:44b458e3e7f72cc417a9e235a843cec0e53fd43def0023579b59ebab0a2207a5\""#;

        let summary = summarize_privatemode_contrast_initdata_texts([text]);

        assert_eq!(
            summary.image_refs,
            vec![
                "ghcr.io/edgelesssys/privatemode/inference-proxy:v1.45.0@sha256:44b458e3e7f72cc417a9e235a843cec0e53fd43def0023579b59ebab0a2207a5"
            ]
        );
        assert_eq!(summary.images_verified, Some(true));
        require_privatemode_contrast_images_verified(&summary).unwrap();
    }

    #[test]
    fn privatemode_initdata_rejects_unpinned_image_refs() {
        let text = r#"\"io.kubernetes.cri.image-name\": \"ghcr.io/edgelesssys/privatemode/inference-proxy:v1.45.0\""#;

        let summary = summarize_privatemode_contrast_initdata_texts([text]);

        assert_eq!(
            summary.image_refs,
            vec!["ghcr.io/edgelesssys/privatemode/inference-proxy:v1.45.0"]
        );
        assert_eq!(summary.images_verified, Some(false));
        let error = require_privatemode_contrast_images_verified(&summary)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unpinned workload image"));
    }

    #[test]
    fn privatemode_initdata_falls_back_to_digest_refs_without_image_marker() {
        let text = "image=ghcr.io/edgelesssys/privatemode/worker@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let summary = summarize_privatemode_contrast_initdata_texts([text]);

        assert_eq!(
            summary.image_refs,
            vec![
                "ghcr.io/edgelesssys/privatemode/worker@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ]
        );
        assert_eq!(summary.images_verified, Some(true));
    }

    #[test]
    fn privatemode_initdata_without_images_is_not_verified() {
        let summary = summarize_privatemode_contrast_initdata_texts(["no images here"]);

        assert_eq!(summary.image_refs, Vec::<String>::new());
        assert_eq!(summary.images_verified, None);
        let error = require_privatemode_contrast_images_verified(&summary)
            .unwrap_err()
            .to_string();
        assert!(error.contains("did not expose workload image references"));
    }

    #[test]
    fn privatemode_active_evidence_verifies_manifest_images_coordinator_and_model_path() {
        let evidence = active_contrast_evidence();

        let verification = verify_privatemode_contrast_active_evidence(&evidence).unwrap();

        assert_eq!(verification.model_path, MODEL_PATH);
        assert_eq!(
            verification.manifest.manifest_sha256,
            sha256_hex(&evidence.manifest_bytes)
        );
        assert!(verification
            .manifest
            .reference_values
            .iter()
            .any(|value| value.starts_with("SNP/Genoa:")));
        assert_eq!(verification.images.images_verified, Some(true));
    }

    #[test]
    fn privatemode_active_evidence_rejects_unverified_coordinator_attestation() {
        let mut evidence = active_contrast_evidence();
        evidence.coordinator_attestation_verified = false;

        let error = verify_privatemode_contrast_active_evidence(&evidence)
            .unwrap_err()
            .to_string();

        assert!(error.contains("Coordinator attestation was not verified"));
    }

    #[test]
    fn privatemode_active_evidence_rejects_local_proxy_model_path_mismatch() {
        let mut evidence = active_contrast_evidence();
        evidence.local_proxy_model_path = Some("privatemode/models/wrong-model".into());

        let error = verify_privatemode_contrast_active_evidence(&evidence)
            .unwrap_err()
            .to_string();

        assert!(error.contains("local proxy model path mismatch"));
    }

    #[test]
    fn privatemode_active_evidence_rejects_missing_local_proxy_model_path() {
        let mut evidence = active_contrast_evidence();
        evidence.local_proxy_model_path = None;

        let error = verify_privatemode_contrast_active_evidence(&evidence)
            .unwrap_err()
            .to_string();

        assert!(error.contains("local proxy model path was not confirmed"));
    }

    #[test]
    fn privatemode_active_evidence_rejects_manifest_without_coordinator_workload() {
        let mut evidence = active_contrast_evidence();
        let manifest = serde_json::json!({
            "ReferenceValues": {
                "snp": [{
                    "ProductName": "Genoa",
                    "TrustedMeasurement": "33".repeat(48)
                }]
            },
            "Policies": {
                "worker-policy": {
                    "Role": "worker",
                    "SANs": ["workload-inference-proxy"]
                }
            }
        });
        evidence.manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        let error = verify_privatemode_contrast_active_evidence(&evidence)
            .unwrap_err()
            .to_string();

        assert!(error.contains("coordinator workload"));
    }

    #[test]
    fn privatemode_active_evidence_rejects_manifest_without_platform_references() {
        let mut evidence = active_contrast_evidence();
        let manifest = serde_json::json!({
            "Policies": {
                "coordinator-policy": {
                    "Role": "coordinator",
                    "SANs": ["coordinator.privatemode.ai"]
                }
            }
        });
        evidence.manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        let error = verify_privatemode_contrast_active_evidence(&evidence)
            .unwrap_err()
            .to_string();

        assert!(error.contains("platform reference values"));
    }
}
