use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use confidential_inference_attestation::{
    format_utc_timestamp_millis, parse_dstack_workload_images, parse_utc_timestamp_millis,
    sha256_digest, ArtifactDigest, ChannelBindingEvidence, CpuTeeKind, DstackEvidence,
    DstackTcbInfo, EvidenceHardware, GpuTeeKind, TdxQuoteMeasurements,
};
use dcap_qvl::quote::Quote;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{EvidenceRequest, ProviderError, Result, RouteDefinition};

const DEFAULT_DSTACK_EVIDENCE_TTL_MILLIS: u64 = 5 * 60 * 1000;

pub(crate) fn normalize_dstack_evidence_bytes(
    route: &RouteDefinition,
    request: &EvidenceRequest,
    body: &[u8],
) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(body)?;
    if value.get("schema").and_then(Value::as_str) == Some(DstackEvidence::SCHEMA) {
        let evidence: DstackEvidence = serde_json::from_value(value)?;
        return serde_json::to_vec(&evidence).map_err(Into::into);
    }

    let evidence = normalize_dstack_evidence_value(route, request, &value)?;
    serde_json::to_vec(&evidence).map_err(Into::into)
}

fn normalize_dstack_evidence_value(
    route: &RouteDefinition,
    request: &EvidenceRequest,
    value: &Value,
) -> Result<DstackEvidence> {
    let nested = primary_model_attestation(value);
    let tcb_value = first_value(
        value,
        nested,
        &[
            &["tcb_info"][..],
            &["info", "tcb_info"][..],
            &["attestation", "info", "tcb_info"][..],
        ],
    )
    .ok_or_else(|| ProviderError::Adapter("dstack evidence is missing tcb_info".into()))?;
    let compose_hash = first_string(
        value,
        nested,
        &[
            &["compose_hash"][..],
            &["info", "compose_hash"][..],
            &["attestation", "info", "compose_hash"][..],
        ],
    );
    let tcb_info = extract_tcb_info(tcb_value, compose_hash)?;
    let workload_images = parse_dstack_workload_images(&tcb_info.app_compose)
        .map_err(|error| ProviderError::Adapter(error.to_string()))?;
    let quote_measurements = extract_quote_measurements(value, nested)?.ok_or_else(|| {
        ProviderError::Adapter(
            "dstack evidence is missing quote-derived measurements or intel_quote".into(),
        )
    })?;
    let public_key_digest = extract_public_key_digest(value, nested)?.ok_or_else(|| {
        ProviderError::Adapter("dstack evidence is missing an attested E2EE public key".into())
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

    Ok(DstackEvidence {
        schema: DstackEvidence::SCHEMA.into(),
        provider: route.provider.clone(),
        route_id: route.route_id.clone(),
        evidence_family: route.evidence_family.clone(),
        tee_measurement: extract_tee_measurement(value)
            .unwrap_or_else(|| format!("tdx:mr_td:{}", quote_measurements.mr_td)),
        hardware: EvidenceHardware {
            cpu: extract_cpu_tee(value),
            gpu: extract_gpu_tee(value, nested),
        },
        quote_measurements,
        tcb_info,
        channel_binding: ChannelBindingEvidence {
            kind: route.channel_binding_kind.clone(),
            public_key_digest,
            request_bound: bool_field(value, &["channel_binding", "request_bound"])
                .unwrap_or(false),
            response_bound: bool_field(value, &["channel_binding", "response_bound"])
                .unwrap_or(false),
        },
        attested_model,
        workload_image_digest: extract_workload_image_digest(value, tcb_value)
            .or_else(|| workload_images.first().map(|image| image.digest.clone()))
            .unwrap_or_default(),
        workload_images,
        model_artifacts: extract_model_artifacts(value, nested)?,
        issued_at,
        expires_at,
        expires_at_epoch_ms,
    })
}

fn extract_tcb_info(
    tcb_value: &Value,
    compose_hash_override: Option<String>,
) -> Result<DstackTcbInfo> {
    let app_compose = string_field(tcb_value, &["app_compose"])
        .ok_or_else(|| ProviderError::Adapter("dstack tcb_info is missing app_compose".into()))?;
    let compose_hash = string_field(tcb_value, &["compose_hash"])
        .or(compose_hash_override)
        .ok_or_else(|| ProviderError::Adapter("dstack tcb_info is missing compose_hash".into()))?;
    Ok(DstackTcbInfo {
        mrtd: string_field(tcb_value, &["mrtd"])
            .or_else(|| string_field(tcb_value, &["mr_td"]))
            .ok_or_else(|| ProviderError::Adapter("dstack tcb_info is missing mrtd".into()))?,
        rtmr0: string_field(tcb_value, &["rtmr0"])
            .or_else(|| string_field(tcb_value, &["rt_mr0"]))
            .ok_or_else(|| ProviderError::Adapter("dstack tcb_info is missing rtmr0".into()))?,
        app_compose,
        compose_hash,
    })
}

fn extract_quote_measurements(
    value: &Value,
    nested: Option<&Value>,
) -> Result<Option<TdxQuoteMeasurements>> {
    if let Some(measurements) = explicit_quote_measurements(value, nested) {
        return Ok(Some(measurements));
    }
    let Some(quote) = first_string(
        value,
        nested,
        &[
            &["intel_quote"][..],
            &["quote"][..],
            &["tdx_quote"][..],
            &["attestation", "intel_quote"][..],
        ],
    ) else {
        return Ok(None);
    };
    let quote_bytes = decode_quote(&quote).ok_or_else(|| {
        ProviderError::Adapter("dstack intel_quote is neither hex nor base64".into())
    })?;
    quote_measurements_from_tdx_quote(&quote_bytes).map(Some)
}

fn explicit_quote_measurements(
    value: &Value,
    nested: Option<&Value>,
) -> Option<TdxQuoteMeasurements> {
    let mr_td = first_string(
        value,
        nested,
        &[
            &["quote_measurements", "mr_td"][..],
            &["quote_measurements", "mrtd"][..],
            &["tdx", "mr_td"][..],
            &["measurements", "mr_td"][..],
            &["mr_td"][..],
        ],
    )?;
    let rtmr0 = first_string(
        value,
        nested,
        &[
            &["quote_measurements", "rtmr0"][..],
            &["quote_measurements", "rt_mr0"][..],
            &["tdx", "rtmr0"][..],
            &["tdx", "rt_mr0"][..],
            &["measurements", "rtmr0"][..],
            &["rtmr0"][..],
        ],
    )?;
    Some(TdxQuoteMeasurements { mr_td, rtmr0 })
}

fn quote_measurements_from_tdx_quote(quote_bytes: &[u8]) -> Result<TdxQuoteMeasurements> {
    let quote = Quote::parse(quote_bytes)
        .map_err(|error| ProviderError::Adapter(format!("TDX quote parse failed: {error}")))?;
    let report = quote
        .report
        .as_td10()
        .ok_or_else(|| ProviderError::Adapter("dstack quote is not a TDX quote".into()))?;
    Ok(TdxQuoteMeasurements {
        mr_td: hex_bytes(&report.mr_td),
        rtmr0: hex_bytes(&report.rt_mr0),
    })
}

fn extract_public_key_digest(value: &Value, nested: Option<&Value>) -> Result<Option<String>> {
    if let Some(digest) = first_string(
        value,
        nested,
        &[
            &["channel_binding", "public_key_digest"][..],
            &["e2ee_public_key_digest"][..],
            &["public_key_digest"][..],
            &["signing_public_key_digest"][..],
        ],
    ) {
        return Ok(Some(digest));
    }
    Ok(first_string(
        value,
        nested,
        &[
            &["signing_public_key"][..],
            &["e2e_pubkey"][..],
            &["e2e_public_key"][..],
            &["e2ee_public_key"][..],
            &["public_key"][..],
        ],
    )
    .map(|public_key| sha256_digest(public_key.as_bytes())))
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
        "dstack evidence model {raw_model} does not match route provider model {}",
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
            &["nvidia_payload"][..],
            &["gpu_evidence"][..],
            &["nvidia"][..],
            &["hardware", "gpu"][..],
        ],
    )
    .is_some();
    has_gpu.then_some(GpuTeeKind::NvidiaCc)
}

fn extract_workload_image_digest(value: &Value, tcb_value: &Value) -> Option<String> {
    string_field(value, &["workload_image_digest"])
        .or_else(|| string_field(value, &["workload_image"]))
        .or_else(|| string_field(tcb_value, &["os_image_hash"]))
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
        .unwrap_or_else(|| issued_epoch.saturating_add(DEFAULT_DSTACK_EVIDENCE_TTL_MILLIS));
    let expires_at = string_field(value, &["expires_at"])
        .unwrap_or_else(|| format_utc_timestamp_millis(expires_epoch));
    Ok((issued_at, expires_at, expires_epoch))
}

fn primary_model_attestation(value: &Value) -> Option<&Value> {
    value_path(value, &["model_attestations"])
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .or_else(|| {
            value_path(value, &["all_attestations"])
                .and_then(Value::as_array)
                .and_then(|entries| entries.first())
        })
        .or_else(|| value_path(value, &["model_attestation"]))
        .or_else(|| value_path(value, &["attestation"]))
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

fn bool_field(value: &Value, path: &[&str]) -> Option<bool> {
    value_path(value, path).and_then(Value::as_bool)
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
        AliasConfidence, BoundDataRequirement, ChannelBindingKind, FreshnessClass,
        ResponseIntegrityRequirement, TrustTier, WorkloadImage,
    };
    use serde_json::json;

    const SAMPLE_TDX_QUOTE: &[u8] =
        include_bytes!("../../../fixtures/evidence/dcap-qvl/tdx_quote.bin");

    #[test]
    fn normalizes_flat_provider_shape_with_explicit_measurements() {
        let route = test_route();
        let request = test_request();
        let app_compose = r#"{"image":"venice-http/worker@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","model":"gpt-oss-120b"}"#;
        let raw = json!({
            "model": "e2ee-gpt-oss-120b-p",
            "tee_measurement": "sha256:venice-http-tee-measurement",
            "quote_measurements": {
                "mr_td": "a1",
                "rtmr0": "b2"
            },
            "info": {
                "tcb_info": {
                    "mrtd": "a1",
                    "rtmr0": "b2",
                    "app_compose": app_compose,
                    "compose_hash": sha256_digest(app_compose.as_bytes())
                        .trim_start_matches("sha256:")
                }
            },
            "channel_binding": {
                "public_key_digest": "sha256:e2ee-key",
                "request_bound": true,
                "response_bound": true
            },
            "workload_image_digest": "sha256:venice-http-workload-image",
            "model_artifacts": [{
                "kind": "weights",
                "name": "gpt-oss-120b",
                "digest": "sha256:venice-http-weights"
            }],
            "issued_at": "2098-12-31T23:50:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "expires_at_epoch_ms": 4070908800000u64
        });

        let evidence = normalize_dstack_evidence_value(&route, &request, &raw).unwrap();

        assert_eq!(evidence.schema, DstackEvidence::SCHEMA);
        assert_eq!(evidence.provider, "venice-http-test");
        assert_eq!(
            evidence.tee_measurement,
            "sha256:venice-http-tee-measurement"
        );
        assert_eq!(evidence.quote_measurements.mr_td, "a1");
        assert_eq!(evidence.tcb_info.app_compose, app_compose);
        assert_eq!(
            evidence.channel_binding.public_key_digest,
            "sha256:e2ee-key"
        );
        assert_eq!(evidence.attested_model.as_deref(), Some("gpt-oss-120b"));
        assert_eq!(
            evidence.workload_image_digest,
            "sha256:venice-http-workload-image"
        );
        assert_eq!(
            evidence.workload_images,
            vec![WorkloadImage {
                service: "root".into(),
                reference: concat!(
                    "venice-http/worker@sha256:",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .into(),
                digest: concat!(
                    "sha256:",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .into(),
            }]
        );
        assert_eq!(evidence.model_artifacts.len(), 1);
    }

    #[test]
    fn extracts_every_digest_pinned_compose_service_in_canonical_order() {
        let compose = concat!(
            "services:\n",
            "  worker:\n",
            "    image: example/worker@sha256:",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
            "  gateway:\n",
            "    image: example/gateway@sha256:",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        );

        let images = parse_dstack_workload_images(compose).unwrap();

        assert_eq!(images.len(), 2);
        assert_eq!(images[0].service, "gateway");
        assert_eq!(images[1].service, "worker");
        assert!(images.iter().all(WorkloadImage::is_digest_pinned));
    }

    #[test]
    fn rejects_compose_when_any_service_image_is_unpinned() {
        let compose = concat!(
            "services:\n",
            "  worker:\n",
            "    image: example/worker@sha256:",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
            "  gateway:\n",
            "    image: example/gateway:latest\n"
        );

        let error = parse_dstack_workload_images(compose)
            .unwrap_err()
            .to_string();

        assert!(error.contains("gateway image is not pinned"));
    }

    #[test]
    fn rejects_compose_service_without_an_image() {
        let compose = "services:\n  worker:\n    build: .\n";

        let error = parse_dstack_workload_images(compose)
            .unwrap_err()
            .to_string();

        assert!(error.contains("worker has no digest-pinned image"));
    }

    #[test]
    fn rejects_tcb_info_without_quote_measurements_or_quote() {
        let route = test_route();
        let request = test_request();
        let raw = json!({
            "model": "e2ee-gpt-oss-120b-p",
            "info": {
                "tcb_info": {
                    "mrtd": "a1",
                    "rtmr0": "b2",
                    "app_compose": "{}",
                    "compose_hash": sha256_digest(b"{}").trim_start_matches("sha256:")
                }
            },
            "channel_binding": {
                "public_key_digest": "sha256:e2ee-key"
            }
        });

        let error = normalize_dstack_evidence_value(&route, &request, &raw)
            .unwrap_err()
            .to_string();

        assert!(error.contains("missing quote-derived measurements"));
    }

    #[test]
    fn missing_model_and_binding_claims_remain_unproven() {
        let route = test_route();
        let request = test_request();
        let raw = json!({
            "quote_measurements": { "mr_td": "a1", "rtmr0": "b2" },
            "info": {
                "tcb_info": {
                    "mrtd": "a1",
                    "rtmr0": "b2",
                    "app_compose": "{}",
                    "compose_hash": sha256_digest(b"{}").trim_start_matches("sha256:")
                }
            },
            "channel_binding": { "public_key_digest": "sha256:e2ee-key" }
        });

        let evidence = normalize_dstack_evidence_value(&route, &request, &raw).unwrap();

        assert_eq!(evidence.attested_model, None);
        assert!(!evidence.channel_binding.request_bound);
        assert!(!evidence.channel_binding.response_bound);
    }

    #[test]
    fn normalizes_provider_model_to_route_canonical_model_for_alias_requests() {
        let route = test_route();
        let mut request = test_request();
        request.requested_model = "GPT-OSS 120B".into();
        let raw = json!({
            "model": "e2ee-gpt-oss-120b-p",
            "quote_measurements": {
                "mr_td": "a1",
                "rtmr0": "b2"
            },
            "info": {
                "tcb_info": {
                    "mrtd": "a1",
                    "rtmr0": "b2",
                    "app_compose": "{}",
                    "compose_hash": sha256_digest(b"{}").trim_start_matches("sha256:")
                }
            },
            "channel_binding": {
                "public_key_digest": "sha256:e2ee-key"
            }
        });

        let evidence = normalize_dstack_evidence_value(&route, &request, &raw).unwrap();

        assert_eq!(evidence.attested_model.as_deref(), Some("gpt-oss-120b"));
        assert!(!evidence.channel_binding.request_bound);
        assert!(!evidence.channel_binding.response_bound);
    }

    #[test]
    fn extracts_quote_measurements_from_hex_tdx_quote() {
        let route = test_route();
        let request = test_request();
        let quote = Quote::parse(SAMPLE_TDX_QUOTE).unwrap();
        let report = quote.report.as_td10().unwrap();
        let mr_td = hex_bytes(&report.mr_td);
        let rtmr0 = hex_bytes(&report.rt_mr0);
        let app_compose = r#"{"image":"venice-http/worker@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","model":"gpt-oss-120b"}"#;
        let raw = json!({
            "model": "e2ee-gpt-oss-120b-p",
            "intel_quote": hex_bytes(SAMPLE_TDX_QUOTE),
            "info": {
                "tcb_info": {
                    "mrtd": mr_td,
                    "rtmr0": rtmr0,
                    "app_compose": app_compose,
                    "compose_hash": sha256_digest(app_compose.as_bytes())
                        .trim_start_matches("sha256:")
                }
            },
            "signing_public_key": "fixture-public-key"
        });

        let evidence = normalize_dstack_evidence_value(&route, &request, &raw).unwrap();

        assert_eq!(evidence.quote_measurements.mr_td, mr_td);
        assert_eq!(evidence.quote_measurements.rtmr0, rtmr0);
        assert_eq!(evidence.tee_measurement, format!("tdx:mr_td:{mr_td}"));
        assert_eq!(
            evidence.channel_binding.public_key_digest,
            sha256_digest("fixture-public-key".as_bytes())
        );
    }

    fn test_route() -> RouteDefinition {
        RouteDefinition {
            route_id: "venice-http-test:gpt-oss-120b:e2ee-gpt-oss-120b-p".into(),
            route_status: RouteLifecycle::Active,
            provider: "venice-http-test".into(),
            provider_model: "e2ee-gpt-oss-120b-p".into(),
            evidence_family: "dstack_app_e2ee".into(),
            api_base_url: "http://127.0.0.1/v1".into(),
            evidence_endpoint: "http://127.0.0.1/v1/confidentiality".into(),
            adapter_version: "venice-http-dstack-adapter/0.1.0".into(),
            freshness_class: FreshnessClass::PerSession,
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
            response_integrity_requirement: ResponseIntegrityRequirement::AnyBound,
            accepted_gpu_tees: Vec::new(),
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
}
