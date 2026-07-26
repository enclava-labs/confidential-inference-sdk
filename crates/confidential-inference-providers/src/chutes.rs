use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use confidential_inference_attestation::{
    chutes_provider_nonce, format_utc_timestamp_millis, parse_utc_timestamp_millis, sha256_digest,
    ArtifactDigest, ChutesE2eeEvidence, CpuTeeKind, EvidenceHardware, GpuTeeKind,
    NvidiaGpuAttestationEvidence,
};
use dcap_qvl::quote::Quote;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{EvidenceRequest, ProviderError, Result, RouteDefinition};

const DEFAULT_CHUTES_EVIDENCE_TTL_MILLIS: u64 = 5 * 60 * 1000;

pub(crate) fn normalize_chutes_e2ee_evidence_bytes(
    route: &RouteDefinition,
    request: &EvidenceRequest,
    body: &[u8],
) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(body)?;
    if value.get("schema").and_then(Value::as_str) == Some(ChutesE2eeEvidence::SCHEMA) {
        let evidence: ChutesE2eeEvidence = serde_json::from_value(value)?;
        validate_chutes_request_nonce(request, &evidence.nonce)?;
        return serde_json::to_vec(&evidence).map_err(Into::into);
    }

    let evidence = normalize_chutes_e2ee_evidence_value(route, request, &value)?;
    serde_json::to_vec(&evidence).map_err(Into::into)
}

fn normalize_chutes_e2ee_evidence_value(
    route: &RouteDefinition,
    request: &EvidenceRequest,
    value: &Value,
) -> Result<ChutesE2eeEvidence> {
    let nested = primary_chutes_attestation(value);
    let quote_details = first_string(
        value,
        nested,
        &[
            &["intel_quote"][..],
            &["quote"][..],
            &["tdx_quote"][..],
            &["attestation", "intel_quote"][..],
        ],
    )
    .as_deref()
    .map(quote_details_from_tdx_quote)
    .transpose()?;
    let report_data = first_string(
        value,
        nested,
        &[
            &["report_data"][..],
            &["tdx", "report_data"][..],
            &["attestation", "report_data"][..],
        ],
    )
    .or_else(|| {
        quote_details
            .as_ref()
            .map(|details| details.report_data.clone())
    })
    .ok_or_else(|| {
        ProviderError::Adapter("Chutes E2EE evidence is missing quote report_data".into())
    })?;
    let nonce = first_string(
        value,
        nested,
        &[
            &["nonce"][..],
            &["request_nonce"][..],
            &["attestation", "nonce"][..],
        ],
    )
    .ok_or_else(|| ProviderError::Adapter("Chutes E2EE evidence is missing nonce".into()))?;
    validate_chutes_request_nonce(request, &nonce)?;
    let gpu_attestation = extract_gpu_attestation(value, nested, &nonce)?;
    let e2e_public_key = first_string(
        value,
        nested,
        &[
            &["e2e_pubkey"][..],
            &["e2e_public_key"][..],
            &["e2ee_public_key"][..],
            &["public_key"][..],
        ],
    )
    .ok_or_else(|| {
        ProviderError::Adapter("Chutes E2EE evidence is missing E2E public key".into())
    })?;
    let raw_model = first_string(
        value,
        nested,
        &[
            &["attested_model"][..],
            &["model"][..],
            &["model_name"][..],
            &["upstream_model"][..],
        ],
    );
    let attested_model = normalize_attested_model(route, request, raw_model.as_deref())?;
    let (issued_at, expires_at, expires_at_epoch_ms) = evidence_times(value)?;

    Ok(ChutesE2eeEvidence {
        schema: ChutesE2eeEvidence::SCHEMA.into(),
        provider: route.provider.clone(),
        route_id: route.route_id.clone(),
        evidence_family: route.evidence_family.clone(),
        tee_measurement: extract_tee_measurement(value)
            .or_else(|| {
                quote_details
                    .as_ref()
                    .map(|details| details.tee_measurement.clone())
            })
            .unwrap_or_default(),
        hardware: EvidenceHardware {
            cpu: extract_cpu_tee(value),
            gpu: extract_gpu_tee(value, nested),
        },
        gpu_attestation,
        report_data,
        nonce,
        e2e_public_key,
        attested_model,
        workload_image_digest: string_field(value, &["workload_image_digest"]).unwrap_or_default(),
        model_artifacts: extract_model_artifacts(value, nested)?,
        issued_at,
        expires_at,
        expires_at_epoch_ms,
    })
}

fn validate_chutes_request_nonce(request: &EvidenceRequest, evidence_nonce: &str) -> Result<()> {
    let Some(request_nonce) = request.nonce.as_deref() else {
        return Ok(());
    };
    let expected = chutes_provider_nonce(request_nonce);
    if evidence_nonce == expected {
        Ok(())
    } else {
        Err(ProviderError::Adapter(
            "Chutes E2EE evidence nonce does not match request nonce".into(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QuoteDetails {
    tee_measurement: String,
    report_data: String,
}

fn quote_details_from_tdx_quote(quote: &str) -> Result<QuoteDetails> {
    let quote_bytes = decode_quote(quote).ok_or_else(|| {
        ProviderError::Adapter("Chutes intel_quote is neither hex nor base64".into())
    })?;
    let quote = Quote::parse(&quote_bytes)
        .map_err(|error| ProviderError::Adapter(format!("TDX quote parse failed: {error}")))?;
    let report = quote
        .report
        .as_td10()
        .ok_or_else(|| ProviderError::Adapter("Chutes quote is not a TDX quote".into()))?;
    let mr_td = hex_bytes(&report.mr_td);
    Ok(QuoteDetails {
        tee_measurement: format!("tdx:mr_td:{mr_td}"),
        report_data: hex_bytes(&report.report_data),
    })
}

fn primary_chutes_attestation(value: &Value) -> Option<&Value> {
    value_path(value, &["all_attestations"])
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries.iter().find(|entry| {
                string_field(entry, &["nonce"]).is_some()
                    && first_string(
                        entry,
                        None,
                        &[
                            &["e2e_pubkey"][..],
                            &["e2e_public_key"][..],
                            &["e2ee_public_key"][..],
                        ],
                    )
                    .is_some()
                    && (string_field(entry, &["report_data"]).is_some()
                        || string_field(entry, &["intel_quote"]).is_some())
            })
        })
        .or_else(|| {
            value_path(value, &["all_attestations"])
                .and_then(Value::as_array)
                .and_then(|entries| entries.first())
        })
        .or_else(|| value_path(value, &["attestation"]))
}

fn normalize_attested_model(
    route: &RouteDefinition,
    request: &EvidenceRequest,
    raw_model: Option<&str>,
) -> Result<Option<String>> {
    let canonical_model = canonical_model_from_route_id(route).unwrap_or(&request.requested_model);
    let Some(raw_model) = raw_model else {
        return Ok(None);
    };
    if raw_model == route.provider_model
        || raw_model == canonical_model
        || raw_model == request.requested_model
    {
        return Ok(Some(canonical_model.to_owned()));
    }
    Err(ProviderError::Adapter(format!(
        "Chutes evidence model {raw_model} does not match route provider model {}",
        route.provider_model
    )))
}

fn canonical_model_from_route_id(route: &RouteDefinition) -> Option<&str> {
    let mut parts = route.route_id.split(':');
    let _provider = parts.next()?;
    let canonical_model = parts.next()?;
    (!canonical_model.trim().is_empty()).then_some(canonical_model)
}

fn extract_tee_measurement(value: &Value) -> Option<String> {
    string_field(value, &["tee_measurement"])
        .or_else(|| string_field(value, &["measurement"]))
        .or_else(|| string_field(value, &["tdx", "tee_measurement"]))
}

fn extract_cpu_tee(value: &Value) -> CpuTeeKind {
    let cpu = string_field(value, &["hardware", "cpu"])
        .or_else(|| string_field(value, &["tee_hardware"]))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if cpu.contains("sev") || cpu.contains("snp") {
        CpuTeeKind::SevSnp
    } else if cpu.contains("nitro") {
        CpuTeeKind::Nitro
    } else {
        CpuTeeKind::Tdx
    }
}

fn extract_gpu_tee(value: &Value, nested: Option<&Value>) -> Option<GpuTeeKind> {
    let has_gpu = first_value(
        value,
        nested,
        &[
            &["gpu_evidence"][..],
            &["nvidia_payload"][..],
            &["nvidia"][..],
            &["hardware", "gpu"][..],
        ],
    )
    .is_some();
    has_gpu.then_some(GpuTeeKind::NvidiaCc)
}

fn extract_gpu_attestation(
    value: &Value,
    nested: Option<&Value>,
    nonce: &str,
) -> Result<Option<NvidiaGpuAttestationEvidence>> {
    let Some(payload) = first_value(
        value,
        nested,
        &[
            &["gpu_evidence"][..],
            &["nvidia_payload"][..],
            &["nvidia"][..],
        ],
    ) else {
        return Ok(None);
    };
    let payload_bytes = serde_json::to_vec(payload)?;
    let arch = first_string(
        payload,
        None,
        &[&["arch"][..], &["gpu_arch"][..], &["architecture"][..]],
    )
    .or_else(|| {
        payload
            .as_array()
            .and_then(|entries| entries.first())
            .and_then(|entry| {
                first_string(
                    entry,
                    None,
                    &[&["arch"][..], &["gpu_arch"][..], &["architecture"][..]],
                )
            })
    })
    .or_else(|| {
        value_path(payload, &["evidence_list"])
            .and_then(Value::as_array)
            .and_then(|entries| entries.first())
            .and_then(|entry| string_field(entry, &["arch"]))
    });
    Ok(Some(NvidiaGpuAttestationEvidence {
        schema: NvidiaGpuAttestationEvidence::SCHEMA.into(),
        attestation_format: NvidiaGpuAttestationEvidence::NRAS_GPU_EVIDENCE_V3.into(),
        nonce: nonce.to_owned(),
        arch,
        payload_sha256: Some(sha256_digest(&payload_bytes)),
        raw_payload_base64: Some(STANDARD.encode(payload_bytes)),
        nras_token: first_string(
            value,
            nested,
            &[
                &["nras_token"][..],
                &["nvidia_nras_token"][..],
                &["nvidia_attestation_token"][..],
                &["attestation_token"][..],
                &["token"][..],
            ],
        )
        .or_else(|| {
            first_string(
                payload,
                None,
                &[
                    &["nras_token"][..],
                    &["nvidia_nras_token"][..],
                    &["attestation_token"][..],
                    &["token"][..],
                ],
            )
        }),
    }))
}

fn extract_model_artifacts(value: &Value, nested: Option<&Value>) -> Result<Vec<ArtifactDigest>> {
    if let Some(artifacts) = first_value(value, nested, &[&["model_artifacts"][..]]) {
        return serde_json::from_value(artifacts.clone()).map_err(Into::into);
    }
    if let Some(digest) = first_string(
        value,
        nested,
        &[
            &["model_artifact_digest"][..],
            &["weights_digest"][..],
            &["model_weights_digest"][..],
        ],
    ) {
        return Ok(vec![ArtifactDigest {
            kind: "weights".into(),
            name: first_string(value, nested, &[&["model"][..], &["model_name"][..]])
                .unwrap_or_else(|| "model".into()),
            digest,
        }]);
    }
    Ok(Vec::new())
}

fn evidence_times(value: &Value) -> Result<(String, String, u64)> {
    let now = now_epoch_millis();
    let issued_at = string_field(value, &["issued_at"])
        .or_else(|| string_field(value, &["timestamp"]))
        .unwrap_or_else(|| format_utc_timestamp_millis(now));
    let issued_epoch = epoch_field(value, &["issued_at_epoch_ms"])
        .or_else(|| parse_utc_timestamp_millis(&issued_at).ok())
        .unwrap_or(now);
    let expires_epoch = epoch_field(value, &["expires_at_epoch_ms"])
        .or_else(|| {
            string_field(value, &["expires_at"])
                .and_then(|expires| parse_utc_timestamp_millis(&expires).ok())
        })
        .unwrap_or_else(|| issued_epoch.saturating_add(DEFAULT_CHUTES_EVIDENCE_TTL_MILLIS));
    let expires_at = string_field(value, &["expires_at"])
        .unwrap_or_else(|| format_utc_timestamp_millis(expires_epoch));
    Ok((issued_at, expires_at, expires_epoch))
}

fn first_value<'a>(
    value: &'a Value,
    nested: Option<&'a Value>,
    paths: &[&[&str]],
) -> Option<&'a Value> {
    paths.iter().find_map(|path| {
        value_path(value, path).or_else(|| nested.and_then(|nested| value_path(nested, path)))
    })
}

fn first_string(value: &Value, nested: Option<&Value>, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| {
        string_field(value, path).or_else(|| nested.and_then(|nested| string_field(nested, path)))
    })
}

fn value_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn string_field(value: &Value, path: &[&str]) -> Option<String> {
    value_path(value, path)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn epoch_field(value: &Value, path: &[&str]) -> Option<u64> {
    let value = value_path(value, path)?;
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
}

fn decode_quote(value: &str) -> Option<Vec<u8>> {
    hex_decode(value).or_else(|| STANDARD.decode(value).ok())
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    let value = value.strip_prefix("0x").unwrap_or(value);
    if !value.len().is_multiple_of(2) || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        let byte = u8::from_str_radix(&value[index..index + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn now_epoch_millis() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    millis.min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptionRequirement, RouteLifecycle, StreamingSupport};
    use confidential_inference_attestation::{
        chutes_expected_report_data_prefix, AliasConfidence, BoundDataRequirement,
        ChannelBindingKind, FreshnessClass, ResponseIntegrityRequirement, TrustTier,
    };
    use serde_json::json;

    const SAMPLE_TDX_QUOTE: &[u8] =
        include_bytes!("../../../fixtures/evidence/dcap-qvl/tdx_quote.bin");

    #[test]
    fn normalizes_redpill_chutes_all_attestations_shape() {
        let route = test_route();
        let request = test_request();
        let nonce = "33".repeat(32);
        let e2e_pubkey = "chutes-test-public-key";
        let report_data = format!(
            "{}{}",
            chutes_expected_report_data_prefix(&nonce, e2e_pubkey).unwrap(),
            "00".repeat(32)
        );
        let raw = json!({
            "attestation_type": "chutes",
            "tee_measurement": "sha256:chutes-tee-measurement",
            "all_attestations": [{
                "model": "private/org/gpt-oss-120b:thinking-TEE",
                "nonce": nonce,
                "e2e_pubkey": e2e_pubkey,
                "report_data": report_data,
                "gpu_evidence": [{"kind": "nvidia_cc_fixture", "arch": "gpu-hopper-h100"}]
            }],
            "nras_token": "fixture.nras.jwt",
            "workload_image_digest": "sha256:chutes-workload-image",
            "model_artifacts": [{
                "kind": "weights",
                "name": "gpt-oss-120b",
                "digest": "sha256:chutes-weights"
            }],
            "issued_at": "2098-12-31T23:50:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "expires_at_epoch_ms": 4070908800000u64
        });

        let evidence = normalize_chutes_e2ee_evidence_value(&route, &request, &raw).unwrap();

        assert_eq!(evidence.schema, ChutesE2eeEvidence::SCHEMA);
        assert_eq!(evidence.provider, "redpill-http-test");
        assert_eq!(evidence.tee_measurement, "sha256:chutes-tee-measurement");
        assert_eq!(evidence.report_data, report_data);
        assert_eq!(evidence.nonce, nonce);
        assert_eq!(evidence.e2e_public_key, e2e_pubkey);
        assert_eq!(evidence.hardware.gpu, Some(GpuTeeKind::NvidiaCc));
        let gpu_attestation = evidence.gpu_attestation.as_ref().unwrap();
        assert_eq!(gpu_attestation.schema, NvidiaGpuAttestationEvidence::SCHEMA);
        assert_eq!(gpu_attestation.nonce, nonce);
        assert_eq!(gpu_attestation.arch.as_deref(), Some("gpu-hopper-h100"));
        assert!(gpu_attestation.raw_payload_base64.is_some());
        assert_eq!(
            gpu_attestation.nras_token.as_deref(),
            Some("fixture.nras.jwt")
        );
        assert_eq!(evidence.attested_model.as_deref(), Some("gpt-oss-120b"));
        assert_eq!(evidence.model_artifacts.len(), 1);
    }

    #[test]
    fn extracts_report_data_and_measurement_from_tdx_quote() {
        let route = test_route();
        let request = test_request();
        let quote = Quote::parse(SAMPLE_TDX_QUOTE).unwrap();
        let report = quote.report.as_td10().unwrap();
        let raw = json!({
            "model": "private/org/gpt-oss-120b:thinking-TEE",
            "nonce": "33".repeat(32),
            "e2e_pubkey": "chutes-test-public-key",
            "intel_quote": hex_bytes(SAMPLE_TDX_QUOTE)
        });

        let evidence = normalize_chutes_e2ee_evidence_value(&route, &request, &raw).unwrap();

        assert_eq!(evidence.report_data, hex_bytes(&report.report_data));
        assert_eq!(
            evidence.tee_measurement,
            format!("tdx:mr_td:{}", hex_bytes(&report.mr_td))
        );
    }

    #[test]
    fn missing_model_remains_unattested() {
        let route = test_route();
        let request = test_request();
        let nonce = "33".repeat(32);
        let e2e_pubkey = "chutes-test-public-key";
        let report_data = format!(
            "{}{}",
            chutes_expected_report_data_prefix(&nonce, e2e_pubkey).unwrap(),
            "00".repeat(32)
        );
        let raw = json!({
            "nonce": nonce,
            "e2e_pubkey": e2e_pubkey,
            "report_data": report_data
        });

        let evidence = normalize_chutes_e2ee_evidence_value(&route, &request, &raw).unwrap();

        assert_eq!(evidence.attested_model, None);
    }

    #[test]
    fn request_nonce_is_normalized_to_chutes_provider_nonce() {
        let route = test_route();
        let request_nonce = "11".repeat(16);
        let request = test_request_with_nonce(&request_nonce);
        let nonce = chutes_provider_nonce(&request_nonce);
        let e2e_pubkey = "chutes-test-public-key";
        let report_data = format!(
            "{}{}",
            chutes_expected_report_data_prefix(&nonce, e2e_pubkey).unwrap(),
            "00".repeat(32)
        );
        let raw = json!({
            "model": "private/org/gpt-oss-120b:thinking-TEE",
            "nonce": nonce,
            "e2e_pubkey": e2e_pubkey,
            "report_data": report_data
        });

        let evidence = normalize_chutes_e2ee_evidence_value(&route, &request, &raw).unwrap();

        assert_eq!(evidence.nonce, chutes_provider_nonce(&request_nonce));
        assert_eq!(evidence.report_data, report_data);
    }

    #[test]
    fn request_nonce_rejects_mismatched_chutes_evidence_nonce() {
        let route = test_route();
        let request = test_request_with_nonce(&"11".repeat(16));
        let nonce = "33".repeat(32);
        let e2e_pubkey = "chutes-test-public-key";
        let report_data = format!(
            "{}{}",
            chutes_expected_report_data_prefix(&nonce, e2e_pubkey).unwrap(),
            "00".repeat(32)
        );
        let raw = json!({
            "model": "private/org/gpt-oss-120b:thinking-TEE",
            "nonce": nonce,
            "e2e_pubkey": e2e_pubkey,
            "report_data": report_data
        });

        let error = normalize_chutes_e2ee_evidence_value(&route, &request, &raw)
            .unwrap_err()
            .to_string();

        assert!(error.contains("nonce does not match request nonce"));
    }

    #[test]
    fn rejects_missing_key_or_report_binding_material() {
        let route = test_route();
        let request = test_request();
        let raw = json!({
            "nonce": "33".repeat(32),
            "report_data": "00".repeat(64)
        });

        let error = normalize_chutes_e2ee_evidence_value(&route, &request, &raw)
            .unwrap_err()
            .to_string();

        assert!(error.contains("missing E2E public key"));
    }

    fn test_route() -> RouteDefinition {
        RouteDefinition {
            route_id: "redpill-http-test:gpt-oss-120b:private/org/gpt-oss-120b:thinking-TEE".into(),
            route_status: RouteLifecycle::Active,
            provider: "redpill-http-test".into(),
            provider_model: "private/org/gpt-oss-120b:thinking-TEE".into(),
            evidence_family: "chutes_e2ee".into(),
            api_base_url: "http://127.0.0.1/v1".into(),
            evidence_endpoint: "http://127.0.0.1/v1/attestation/report".into(),
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

    fn test_request() -> EvidenceRequest {
        EvidenceRequest {
            requested_model: "gpt-oss-120b".into(),
            policy_digest: "sha256:policy".into(),
            nonce: None,
        }
    }

    fn test_request_with_nonce(nonce: &str) -> EvidenceRequest {
        EvidenceRequest {
            requested_model: "gpt-oss-120b".into(),
            policy_digest: "sha256:policy".into(),
            nonce: Some(nonce.into()),
        }
    }
}
