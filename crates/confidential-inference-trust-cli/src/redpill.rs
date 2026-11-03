use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::Path,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use confidential_inference_attestation::{
    format_utc_timestamp_millis, redpill_aci_quote_bytes, sha256_digest,
    verify_redpill_aci_capture, AliasConfidence, BoundDataRequirement, ChannelBindingKind,
    CpuTeeKind, CpuTeeRequirement, FreshnessClass, GpuTeeKind, GpuTeeRequirement,
    ProviderReference, RedpillAciLiveEvidence, ReferenceValuesEnvelope, ReferenceValuesPayload,
    ResponseIntegrityRequirement, RouteReference, TrustTier, TrustedSigningKey, VerificationPolicy,
    VerifiedRedpillAciCapture,
};
use confidential_inference_openai::ChatMessage;
use confidential_inference_providers::{
    CredentialKind, DcapTdxCollateralResolver, EncryptionRequirement, EvidenceRequest,
    ModelBindingSupport, NvidiaNrasRemoteClient, ProviderAdapter, ProviderCompatibilityMatrix,
    ProviderCompatibilityMatrixEnvelope, ProviderRegistry, ProviderRegistryEnvelope,
    RedpillHttpProvider, RegistryModel, RouteDefinition, RouteExecutionStatus, RouteLifecycle,
    SourceSyncRun, StreamingSupport,
};
use confidential_inference_sdk::ConfidentialInference;

use crate::{load_signing_key, now_epoch_ms, random_nonce_hex, sign, write_json, ISSUER};

const API_BASE: &str = "https://tee.redpill.ai/v1";
const EVIDENCE_ENDPOINT: &str = "https://tee.redpill.ai/v1/aci/attestation";
const POLICY_DIGEST: &str = "sha256:operator-pin-capture";

fn route(canonical: &str, model: &str) -> RouteDefinition {
    RouteDefinition {
        route_id: format!("redpill:{canonical}:live"),
        route_status: RouteLifecycle::Active,
        provider: "redpill".into(),
        provider_model: model.into(),
        evidence_family: "redpill_aci_verified_tls".into(),
        api_base_url: API_BASE.into(),
        evidence_endpoint: EVIDENCE_ENDPOINT.into(),
        adapter_version: "redpill-aci-live-v1".into(),
        freshness_class: FreshnessClass::PerRequest,
        channel_binding_kind: ChannelBindingKind::TeeTerminatedTls,
        trust_tier: TrustTier::HwVerifiedTls,
        request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_integrity_requirement: ResponseIntegrityRequirement::ChannelBound,
        accepted_gpu_tees: vec![GpuTeeKind::NvidiaCc],
        request_encryption: EncryptionRequirement::NotRequired,
        response_decryption: EncryptionRequirement::NotRequired,
        streaming: StreamingSupport::Unsupported,
        alias_confidence: AliasConfidence::ProviderDeclared,
    }
}

fn compatibility_matrix() -> Result<ProviderCompatibilityMatrix, Box<dyn Error>> {
    let mut matrix = ProviderCompatibilityMatrix::bundled()?;
    let mut profile = matrix
        .providers
        .remove("redpill-fixture")
        .ok_or("bundled compatibility matrix has no RedPill profile")?;
    matrix.providers.clear();
    profile.provider = "redpill".into();
    profile.api_base_url = API_BASE.into();
    profile.route_execution_status = RouteExecutionStatus::Executable;
    profile.request_encryption = EncryptionRequirement::NotRequired;
    profile.response_decryption = EncryptionRequirement::NotRequired;
    profile.adapter_managed_encryption = false;
    profile.sdk_app_e2ee = None;
    profile.attestation_endpoint_shape = "redpill_aci_verified_tls".into();
    profile.required_credentials = vec![CredentialKind::BearerToken];
    profile.freshness_class = FreshnessClass::PerRequest;
    profile.expected_trust_tier = TrustTier::HwVerifiedTls;
    profile.model_binding_support = ModelBindingSupport::Unsupported;
    profile.known_unsupported_modes.clear();
    matrix.providers.insert("redpill".into(), profile);
    matrix.validate()?;
    Ok(matrix)
}

async fn verified_measurement(
    provider: &RedpillHttpProvider,
    route: &RouteDefinition,
    resolver: &DcapTdxCollateralResolver,
    nras: &NvidiaNrasRemoteClient,
) -> Result<String, Box<dyn Error>> {
    let nonce = random_nonce_hex()?;
    let raw = provider
        .fetch_evidence(
            route,
            &EvidenceRequest {
                requested_model: route.provider_model.clone(),
                policy_digest: POLICY_DIGEST.into(),
                nonce: Some(nonce.clone()),
            },
        )
        .await?;
    let capture: RedpillAciLiveEvidence = serde_json::from_slice(&raw)?;
    if capture.schema != RedpillAciLiveEvidence::SCHEMA
        || capture.provider != route.provider
        || capture.route_id != route.route_id
        || capture.evidence_family != route.evidence_family
        || capture.requested_model != route.provider_model
        || capture.policy_digest != POLICY_DIGEST
        || capture.request_nonce != nonce
        || capture.evidence_endpoint != route.evidence_endpoint
    {
        return Err(
            "captured RedPill evidence does not match the requested route and nonce".into(),
        );
    }
    let (gateway_quote, model_quote) = redpill_aci_quote_bytes(&capture)?;
    let gateway_verifier = resolver.verifier_for_quote(&gateway_quote).await?;
    let model_verifier = resolver.verifier_for_quote(&model_quote).await?;
    let gpu_verifier = nras.fetch_jwt_verifier().await?;
    let verified = verify_redpill_aci_capture(
        &capture,
        &gateway_verifier,
        &model_verifier,
        &gpu_verifier,
        &route.api_base_url,
        &route.provider_model,
        now_epoch_ms()?,
    )?;
    enforce_capture_compose_policy(&capture, &verified)?;
    Ok(verified.tee_measurement)
}

const FORBIDDEN_ALLOWED_ENVS: &[&str] = &[
    "DSTACK_ROOT_PUBLIC_KEY",
    "DSTACK_AUTHORIZED_KEYS",
    "DSTACK_ROOT_PASSWORD",
];

fn as_compose_value(value: &serde_json::Value) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(match value {
        serde_json::Value::String(raw) => serde_json::from_str(raw)?,
        other => other.clone(),
    })
}

fn capture_app_compose(
    value: &serde_json::Value,
    side: &str,
) -> Result<(String, serde_json::Value), Box<dyn Error>> {
    let raw = value
        .as_str()
        .ok_or_else(|| format!("RedPill {side} app_compose must be a JSON string"))?
        .to_owned();
    let parsed: serde_json::Value = serde_json::from_str(&raw)?;
    if !parsed.is_object() {
        return Err(format!("RedPill {side} app_compose must be a JSON object").into());
    }
    Ok((raw, parsed))
}

fn session_evidence_value(
    capture: &RedpillAciLiveEvidence,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let data = capture
        .session
        .pointer("/evidence/data")
        .and_then(serde_json::Value::as_str)
        .ok_or("RedPill session evidence is missing")?;
    let (_, encoded) = data
        .split_once(',')
        .ok_or("RedPill session evidence data URI is malformed")?;
    Ok(serde_json::from_slice(&STANDARD.decode(encoded)?)?)
}

fn enforce_capture_compose_policy(
    capture: &RedpillAciLiveEvidence,
    verified: &VerifiedRedpillAciCapture,
) -> Result<(), Box<dyn Error>> {
    let gateway = capture
        .gateway_report
        .pointer("/attestation/evidence/app_compose")
        .ok_or("RedPill gateway app_compose is missing")?;
    enforce_compose_policy("gateway", gateway, &verified.gateway_compose_hash)?;
    let model = session_evidence_value(capture)?;
    let tcb_info = model
        .pointer("/info/tcb_info")
        .ok_or("RedPill model tcb_info is missing")?;
    let tcb_info = as_compose_value(tcb_info)?;
    let app_compose = tcb_info
        .get("app_compose")
        .ok_or("RedPill model app_compose is missing")?;
    enforce_compose_policy("model", app_compose, &verified.model_compose_hash)
}

fn enforce_compose_policy(
    side: &str,
    app_compose: &serde_json::Value,
    expected_compose_hash: &str,
) -> Result<(), Box<dyn Error>> {
    let (raw, parsed) = capture_app_compose(app_compose, side)?;
    let computed = sha256_digest(raw.as_bytes());
    let computed = computed.trim_start_matches("sha256:");
    if computed != expected_compose_hash {
        return Err(format!(
            "RedPill {side} app_compose does not match the replay-authenticated compose hash {expected_compose_hash} (computed {computed})"
        )
        .into());
    }
    let mut offenders = Vec::new();
    if let Some(envs) = parsed.get("allowed_envs") {
        let envs = envs
            .as_array()
            .ok_or("RedPill allowed_envs must be an array")?;
        for value in envs {
            let name = value
                .as_str()
                .ok_or("RedPill allowed_envs entries must be strings")?;
            if FORBIDDEN_ALLOWED_ENVS.contains(&name) {
                offenders.push(format!("allowed_envs permits {name}"));
            }
        }
    }
    let script = match parsed.get("pre_launch_script") {
        Some(value) => value
            .as_str()
            .ok_or("RedPill pre_launch_script must be a string")?,
        None => "",
    };
    let script_lc = script.to_ascii_lowercase();
    let touches_authorized_keys =
        script_lc.contains("authorized_keys") || script_lc.contains(".ssh/");
    if touches_authorized_keys {
        let mut reads = Vec::new();
        for name in FORBIDDEN_ALLOWED_ENVS {
            if script.contains(name) {
                reads.push((*name).to_string());
            }
        }
        if script_lc.contains("ssh_authorized_keys") {
            reads.push("ssh_authorized_keys".into());
        }
        if script_lc.contains("/dstack/user_config") {
            reads.push("/dstack/user_config".into());
        }
        if reads.is_empty() {
            reads.push("environment variables".into());
        }
        offenders.push(format!(
            "pre_launch_script provisions authorized_keys from {}",
            reads.join(", ")
        ));
    }
    if !offenders.is_empty() {
        return Err(format!(
            "RedPill {side} app_compose fails pin policy; offending fields: {}",
            offenders.join("; ")
        )
        .into());
    }
    Ok(())
}

pub(crate) async fn pin(
    models: &[(String, String)],
    key_dir: &Path,
    out: &Path,
    smoke_chat: Option<String>,
) -> Result<(), Box<dyn Error>> {
    if models.is_empty() {
        return Err("at least one RedPill model is required".into());
    }
    let mut canonical_names = BTreeSet::new();
    for (provider_model, canonical) in models {
        if canonical.trim().is_empty()
            || provider_model.trim().is_empty()
            || !canonical_names.insert(canonical)
        {
            return Err("model names must be nonempty and canonical names must be unique".into());
        }
    }
    let api_key = std::env::var("REDPILL_API_KEY")
        .ok()
        .filter(|key| !key.is_empty())
        .ok_or("REDPILL_API_KEY must be set in the environment")?;
    let (pair, key_entry) = load_signing_key(key_dir)?;
    let routes: Vec<_> = models
        .iter()
        .map(|(model, canonical)| route(canonical, model))
        .collect();
    let provider = RedpillHttpProvider::new("redpill", routes.clone(), api_key.clone())?;
    let resolver = DcapTdxCollateralResolver::with_phala_pccs()?;
    let nras = NvidiaNrasRemoteClient::with_default_http()?;
    let mut measurements = BTreeSet::new();
    for route in &routes {
        let first = verified_measurement(&provider, route, &resolver, &nras).await?;
        let second = verified_measurement(&provider, route, &resolver, &nras).await?;
        if first != second {
            return Err(format!(
                "verified RedPill captures disagree for {}",
                route.provider_model
            )
            .into());
        }
        measurements.insert(first);
        println!("verified two RedPill captures for {}", route.provider_model);
    }

    let now_ms = now_epoch_ms()?;
    let now = format_utc_timestamp_millis(now_ms);
    let expires_ms = now_ms
        .checked_add(7 * 24 * 60 * 60 * 1000)
        .ok_or("reference expiry overflow")?;
    let expires = format_utc_timestamp_millis(expires_ms);
    let version = format!("operator-pin-{now_ms}");
    let mut registry_models = BTreeMap::new();
    let mut references = BTreeMap::new();
    for ((_, canonical), route) in models.iter().zip(routes) {
        references.insert(
            route.route_id.clone(),
            RouteReference {
                canonical_model: canonical.clone(),
                provider_model: route.provider_model.clone(),
                evidence_family: route.evidence_family.clone(),
                channel_binding_kind: route.channel_binding_kind.clone(),
                trust_tier: route.trust_tier.clone(),
                accepted_cpu_tees: vec![CpuTeeKind::Tdx],
                e2ee_public_key_digest: "sha256:not-applicable".into(),
                response_signing_key_digest: None,
                tls_spki_sha256: None,
                workload_images: Vec::new(),
                workload_image_digest: "sha256:not-applicable".into(),
                model_artifacts: Vec::new(),
                valid_until: expires.clone(),
                valid_until_epoch_ms: expires_ms,
            },
        );
        registry_models.insert(
            canonical.clone(),
            RegistryModel {
                canonical_model: canonical.clone(),
                display_name: canonical.clone(),
                family: "redpill".into(),
                aliases: vec![canonical.clone()],
                routes: vec![route],
            },
        );
    }
    let registry = ProviderRegistry {
        schema: ProviderRegistry::SCHEMA.into(),
        version: version.clone(),
        generated_at: now.clone(),
        source_sync_run: SourceSyncRun {
            completed_at: now.clone(),
            status: "success".into(),
            source: format!("{ISSUER}: confidential-inference-trust pin redpill"),
        },
        models: registry_models,
    };
    let reference_values = ReferenceValuesPayload {
        schema: ReferenceValuesPayload::SCHEMA.into(),
        version: version.clone(),
        issuer: ISSUER.into(),
        valid_from: now,
        valid_until: expires,
        valid_until_epoch_ms: expires_ms,
        revocation_epoch: 0,
        minimum_acceptable_version: version,
        providers: BTreeMap::from([(
            "redpill".into(),
            ProviderReference {
                accepted_measurements: measurements.into_iter().collect(),
                routes: references,
            },
        )]),
    };
    let matrix = compatibility_matrix()?;
    matrix.validate_registry_routes(&registry)?;
    let registry_envelope = ProviderRegistryEnvelope {
        schema: ProviderRegistryEnvelope::SCHEMA.into(),
        signature: sign(&pair, &key_entry, &registry)?,
        payload: registry,
    };
    let reference_envelope = ReferenceValuesEnvelope {
        schema: ReferenceValuesEnvelope::SCHEMA.into(),
        signature: sign(&pair, &key_entry, &reference_values)?,
        payload: reference_values,
    };
    let matrix_envelope = ProviderCompatibilityMatrixEnvelope {
        schema: ProviderCompatibilityMatrixEnvelope::SCHEMA.into(),
        signature: sign(&pair, &key_entry, &matrix)?,
        payload: matrix,
    };
    let mut policy = VerificationPolicy::require_hw_verified_tls();
    policy.hardware.cpu = CpuTeeRequirement::one_of(vec![CpuTeeKind::Tdx]);
    policy.hardware.gpu = GpuTeeRequirement::one_of(vec![GpuTeeKind::NvidiaCc]);
    let client = ConfidentialInference::builder()
        .exclusive_trusted_artifact_signing_keys(vec![TrustedSigningKey::new(
            key_entry.signer.clone(),
            key_entry.key_id.clone(),
            key_entry.public_key_base64url.clone(),
        )])
        .registry(registry_envelope.clone())
        .reference_values(reference_envelope.clone())
        .compatibility_matrix(matrix_envelope.payload.clone())
        .api_key("redpill", api_key)
        .policy(policy.clone())
        .build()
        .await?;
    for (_, canonical) in models {
        client.verify_route("redpill", canonical).await?;
    }

    fs::create_dir_all(out)?;
    write_json(&out.join("registry.envelope.json"), &registry_envelope)?;
    write_json(
        &out.join("reference-values.envelope.json"),
        &reference_envelope,
    )?;
    write_json(
        &out.join("compatibility-matrix.envelope.json"),
        &matrix_envelope,
    )?;
    write_json(
        &out.join("operator-config.json"),
        &serde_json::json!({
            "demo_provider": false,
            "trusted_ed25519_signing_keys": [key_entry],
            "registry": registry_envelope,
            "reference_values": reference_envelope,
            "compatibility_matrix": matrix_envelope,
            "api_keys": {"redpill": {"env": "REDPILL_API_KEY"}},
            "policy": policy,
        }),
    )?;
    eprintln!("WARNING: these artifacts pin observed, verified RedPill measurements (trust-on-first-use), not provider-published production reference values.");
    if let Some(prompt) = smoke_chat {
        for (_, canonical) in models {
            let result = client
                .chat_completions()
                .model(canonical.clone())
                .message(ChatMessage::user(prompt.clone()))
                .max_tokens(32)
                .send()
                .await?;
            let choice = result
                .response
                .choices
                .first()
                .ok_or("smoke chat returned no choices")?;
            println!(
                "{canonical}: smoke chat verdict {:?}; response: {}",
                result.verdict.status,
                choice.message.content.text().unwrap_or_default()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_matches_live_route() {
        let route = route("canonical", "provider/model");
        let matrix = compatibility_matrix().unwrap();
        let profile = matrix.provider("redpill").unwrap();
        profile.validate_route(&route).unwrap();
        assert!(profile.route_execution_status.allows_chat_execution());
        assert_eq!(
            profile.model_binding_support,
            ModelBindingSupport::Unsupported
        );
        assert_eq!(route.evidence_family, "redpill_aci_verified_tls");
    }

    fn compose_hash(raw: &str) -> String {
        sha256_digest(raw.as_bytes())
            .trim_start_matches("sha256:")
            .to_string()
    }

    fn compose(raw: &str) -> serde_json::Value {
        serde_json::Value::String(raw.into())
    }

    #[test]
    fn compose_policy_accepts_clean_compose() {
        let raw = r##"{"allowed_envs":["MODEL_TOKEN"],"pre_launch_script":"#!/bin/sh\ntrue\n"}"##;
        enforce_compose_policy("model", &compose(raw), &compose_hash(raw)).unwrap();
    }

    #[test]
    fn compose_policy_rejects_malformed_security_fields() {
        for raw in [
            r#"{"allowed_envs":"DSTACK_ROOT_PUBLIC_KEY"}"#,
            r#"{"allowed_envs":[null]}"#,
            r#"{"pre_launch_script":{}}"#,
        ] {
            assert!(enforce_compose_policy("gateway", &compose(raw), &compose_hash(raw)).is_err());
        }
    }

    #[test]
    fn compose_policy_rejects_hash_mismatch() {
        let raw = r#"{"allowed_envs":[],"docker_compose_file":"services: {}"}"#;
        let error = enforce_compose_policy("gateway", &compose(raw), &"0".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(error.contains("gateway app_compose"));
        assert!(error.contains("replay-authenticated compose hash"));
    }

    #[test]
    fn compose_policy_rejects_forbidden_allowed_envs() {
        for name in FORBIDDEN_ALLOWED_ENVS {
            let raw =
                format!(r#"{{"allowed_envs":["{name}","MODEL_TOKEN"],"docker_compose_file":"x"}}"#);
            let error = enforce_compose_policy("model", &compose(&raw), &compose_hash(&raw))
                .unwrap_err()
                .to_string();
            assert!(error.contains("offending fields"), "{error}");
            assert!(error.contains("allowed_envs"), "{error}");
            assert!(error.contains(name), "{error}");
        }
    }

    #[test]
    fn compose_policy_rejects_ssh_provisioning_from_env_and_user_config() {
        let raw = concat!(
            r##"{"allowed_envs":[],"pre_launch_script":"#!/bin/bash\n"##,
            r#"echo \"$DSTACK_ROOT_PUBLIC_KEY\" >> /home/root/.ssh/authorized_keys\n"#,
            r#"echo \"$DSTACK_AUTHORIZED_KEYS\" >> /home/root/.ssh/authorized_keys\n"#,
            r#"jq -r .ssh_authorized_keys /dstack/user_config >> /home/root/.ssh/authorized_keys\n"}"#
        );
        let error = enforce_compose_policy("gateway", &compose(raw), &compose_hash(raw))
            .unwrap_err()
            .to_string();
        assert!(error.contains("pre_launch_script"), "{error}");
        assert!(error.contains("DSTACK_ROOT_PUBLIC_KEY"), "{error}");
        assert!(error.contains("DSTACK_AUTHORIZED_KEYS"), "{error}");
        assert!(error.contains("/dstack/user_config"), "{error}");
    }

    #[test]
    fn compose_policy_reports_fields_not_secret_values() {
        let raw = concat!(
            r##"{"allowed_envs":[],"pre_launch_script":"#!/bin/bash\n"##,
            r#"export KEY=supersecretvalue\n"#,
            r#"echo \"$KEY\" >> /home/root/.ssh/authorized_keys\n"}"#
        );
        let error = enforce_compose_policy("model", &compose(raw), &compose_hash(raw))
            .unwrap_err()
            .to_string();
        assert!(error.contains("pre_launch_script"), "{error}");
        assert!(!error.contains("supersecretvalue"), "{error}");
    }

    #[test]
    fn compose_policy_accepts_tcb_info_string_shape() {
        let raw = r#"{"allowed_envs":[],"docker_compose_file":"services: {}"}"#;
        let tcb_info = serde_json::json!({"app_compose": raw});
        let tcb_info_str = serde_json::Value::String(tcb_info.to_string());
        let parsed = as_compose_value(&tcb_info_str).unwrap();
        let app_compose = parsed.get("app_compose").unwrap();
        enforce_compose_policy("model", app_compose, &compose_hash(raw)).unwrap();
    }
}
