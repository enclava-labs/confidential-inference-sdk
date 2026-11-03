use super::*;
use confidential_inference_attestation::{
    parse_ppq_ehbp_evidence, verify_ppq_ehbp_quote, PpqEhbpLiveEvidence, ProviderReference,
    ReferenceValuesPayload, RouteReference, SevSnpTinfoilQuoteVerifier, TinfoilAttestationFormat,
    VerifiedTinfoilQuote,
};
use confidential_inference_providers::PpqPrivateHttpProvider;

const API_BASE: &str = "https://api.ppq.ai/private/v1";
const EVIDENCE_ENDPOINT: &str = "https://api.ppq.ai/private/attestation";

fn route(canonical_model: &str, provider_model: &str) -> RouteDefinition {
    RouteDefinition {
        route_id: format!("ppq:{canonical_model}:live"),
        route_status: RouteLifecycle::Active,
        provider: "ppq".into(),
        provider_model: provider_model.into(),
        evidence_family: "ppq_ehbp".into(),
        api_base_url: API_BASE.into(),
        evidence_endpoint: EVIDENCE_ENDPOINT.into(),
        adapter_version: "ppq-ehbp-live-v1".into(),
        freshness_class: FreshnessClass::PerSession,
        channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
        trust_tier: TrustTier::AppE2ee,
        request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_integrity_requirement: ResponseIntegrityRequirement::ChannelBound,
        accepted_gpu_tees: Vec::new(),
        request_encryption: EncryptionRequirement::Required,
        response_decryption: EncryptionRequirement::Required,
        streaming: StreamingSupport::Unsupported,
        alias_confidence: AliasConfidence::ProviderDeclared,
    }
}

fn require_latest_release(observed: &str, latest: &str) -> Result<String, Box<dyn Error>> {
    let observed = observed.to_ascii_lowercase();
    let latest = latest.to_ascii_lowercase();
    if observed != latest {
        return Err(format!("PPQ release digest sha256:{observed} differs from latest Tinfoil release digest sha256:{latest}").into());
    }
    Ok(observed)
}

async fn verified_capture(
    provider: &PpqPrivateHttpProvider,
    route: &RouteDefinition,
    tdx_resolver: &DcapTdxCollateralResolver,
    latest_digest: &str,
) -> Result<(VerifiedTinfoilQuote, String), Box<dyn Error>> {
    let policy_digest = "sha256:operator-pin-capture";
    let raw = provider
        .fetch_evidence(
            route,
            &EvidenceRequest {
                requested_model: route.provider_model.clone(),
                policy_digest: policy_digest.into(),
                nonce: None,
            },
        )
        .await?;
    let capture: PpqEhbpLiveEvidence = serde_json::from_slice(&raw)?;
    if capture.schema != PpqEhbpLiveEvidence::SCHEMA
        || capture.provider != route.provider
        || capture.route_id != route.route_id
        || capture.evidence_family != route.evidence_family
        || capture.requested_model != route.provider_model
        || capture.policy_digest != policy_digest
        || capture.evidence_endpoint != route.evidence_endpoint
    {
        return Err("captured PPQ evidence does not match the pinned route".into());
    }
    let raw_bundle = STANDARD.decode(&capture.raw_bundle_base64)?;
    let bundle: serde_json::Value = serde_json::from_slice(&raw_bundle)?;
    let digest = require_latest_release(
        bundle["digest"]
            .as_str()
            .ok_or("PPQ bundle digest missing")?,
        latest_digest,
    )?;
    let sigstore = bundle
        .get("sigstoreBundle")
        .ok_or("PPQ Sigstore bundle missing")?;
    let release_measurement =
        verify_tinfoil_sigstore_bundle(sigstore, TINFOIL_SIGSTORE_REPO, &digest)?;
    let parsed = parse_ppq_ehbp_evidence(&capture)?;
    let quote = match parsed.format {
        TinfoilAttestationFormat::SevSnpGuestV2 => {
            let verifier = SevSnpTinfoilQuoteVerifier::new(parsed.vcek.clone());
            verify_ppq_ehbp_quote(&capture, &parsed, &verifier)?
        }
        TinfoilAttestationFormat::TdxGuestV2 => {
            let verifier = tdx_resolver.verifier_for_quote(&parsed.quote).await?;
            verify_ppq_ehbp_quote(&capture, &parsed, &verifier)?
        }
    };
    verify_tinfoil_release_measurement(&release_measurement, &quote)?;
    println!("Sigstore verified: repo={TINFOIL_SIGSTORE_REPO} digest=sha256:{digest} measurement={release_measurement}");
    Ok((quote, digest))
}

pub(crate) async fn pin(
    models: &[(String, String)],
    key_dir: &Path,
    out: &Path,
    smoke_chat: Option<String>,
) -> Result<(), Box<dyn Error>> {
    if models.is_empty() {
        return Err("at least one PPQ model is required".into());
    }
    let api_key = env::var("PPQ_API_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or("PPQ_API_KEY must be set in the environment")?;
    let (pair, key_entry) = load_signing_key(key_dir)?;
    let (latest_digest, _) = tinfoil_release().await?;
    let mut routes = Vec::with_capacity(models.len());
    let mut canonical_names = BTreeSet::new();
    let mut provider_names = BTreeSet::new();
    for (provider_model, canonical_model) in models {
        if provider_model.trim() != provider_model
            || canonical_model.trim() != canonical_model
            || !provider_model.starts_with("private/")
            || provider_model.len() == "private/".len()
            || canonical_model.is_empty()
            || !canonical_names.insert(canonical_model)
            || !provider_names.insert(provider_model)
        {
            return Err("PPQ models must have unique nonempty canonical names and unique private/ provider model IDs".into());
        }
        routes.push(route(canonical_model, provider_model));
    }
    let provider = PpqPrivateHttpProvider::new(routes.clone(), api_key.clone())?;
    let tdx_resolver = DcapTdxCollateralResolver::with_phala_pccs()?;
    let now_ms = now_epoch_ms()?;
    let now = format_utc_timestamp_millis(now_ms);
    let version = format!("operator-pin-{now_ms}");
    let mut registry_models = BTreeMap::new();
    let mut route_references = BTreeMap::new();
    let mut measurement: Option<String> = None;
    let mut release_digest: Option<String> = None;
    let mut valid_until_ms = u64::MAX;

    for ((_, canonical_model), route) in models.iter().zip(&routes) {
        let (first, first_digest) =
            verified_capture(&provider, route, &tdx_resolver, &latest_digest).await?;
        let (second, second_digest) =
            verified_capture(&provider, route, &tdx_resolver, &latest_digest).await?;
        if first_digest != second_digest
            || release_digest
                .as_ref()
                .is_some_and(|digest| digest != &first_digest)
        {
            return Err("PPQ captures have different release digests".into());
        }
        release_digest = Some(first_digest);
        if first.attestation_format != second.attestation_format
            || first.hardware != second.hardware
            || first.tee_measurement != second.tee_measurement
        {
            return Err(
                format!("the two verified PPQ captures disagree for {canonical_model}").into(),
            );
        }
        if measurement
            .as_ref()
            .is_some_and(|value| value != &first.tee_measurement)
        {
            return Err("PPQ routes have different measurements; provider-wide references cannot safely pin them together".into());
        }
        measurement = Some(first.tee_measurement.clone());
        let expires = first.expires_at_epoch_ms.min(second.expires_at_epoch_ms);
        valid_until_ms = valid_until_ms.min(expires);
        route_references.insert(
            route.route_id.clone(),
            RouteReference {
                canonical_model: canonical_model.clone(),
                provider_model: route.provider_model.clone(),
                evidence_family: route.evidence_family.clone(),
                channel_binding_kind: route.channel_binding_kind.clone(),
                trust_tier: route.trust_tier.clone(),
                accepted_cpu_tees: vec![first.hardware.cpu.clone()],
                e2ee_public_key_digest: "sha256:not-applicable".into(),
                response_signing_key_digest: None,
                tls_spki_sha256: None,
                workload_images: Vec::new(),
                workload_image_digest: "sha256:not-applicable".into(),
                model_artifacts: Vec::new(),
                valid_until: format_utc_timestamp_millis(expires),
                valid_until_epoch_ms: expires,
            },
        );
        registry_models.insert(
            canonical_model.clone(),
            RegistryModel {
                canonical_model: canonical_model.clone(),
                display_name: canonical_model.clone(),
                family: "ppq".into(),
                aliases: vec![canonical_model.clone()],
                routes: vec![route.clone()],
            },
        );
        println!("{canonical_model}: two captures verified");
    }
    let provenance = release_provenance(&release_digest.ok_or("missing PPQ release digest")?);
    let registry = ProviderRegistry {
        schema: ProviderRegistry::SCHEMA.into(),
        version: version.clone(),
        generated_at: now.clone(),
        source_sync_run: SourceSyncRun {
            completed_at: now.clone(),
            status: "success".into(),
            source: format!("{provenance}: confidential-inference-trust pin ppq"),
        },
        models: registry_models,
    };
    let reference_values = ReferenceValuesPayload {
        schema: ReferenceValuesPayload::SCHEMA.into(),
        version: version.clone(),
        issuer: provenance,
        valid_from: now,
        valid_until: format_utc_timestamp_millis(valid_until_ms),
        valid_until_epoch_ms: valid_until_ms,
        revocation_epoch: 0,
        minimum_acceptable_version: version,
        providers: BTreeMap::from([(
            "ppq".into(),
            ProviderReference {
                accepted_measurements: vec![measurement.ok_or("missing PPQ measurement")?],
                routes: route_references,
            },
        )]),
    };
    reference_values.validate_for_activation()?;
    let mut matrix = ProviderCompatibilityMatrix::bundled()?;
    let mut profile = matrix
        .providers
        .remove("ppq-private-fixture")
        .ok_or("bundled compatibility matrix has no PPQ profile")?;
    matrix.providers.clear();
    profile.provider = "ppq".into();
    profile.api_base_url = API_BASE.into();
    profile.attestation_endpoint_shape = "ppq_ehbp".into();
    profile.required_credentials = vec![CredentialKind::BearerToken];
    profile
        .known_unsupported_modes
        .retain(|mode| mode != "live_execution");
    profile.route_execution_status = RouteExecutionStatus::Executable;
    profile.adapter_managed_encryption = true;
    profile.model_binding_support = ModelBindingSupport::Unsupported;
    matrix.providers.insert("ppq".into(), profile);
    matrix.validate()?;
    matrix.validate_registry_routes(&registry)?;
    let policy = VerificationPolicy::require_attested_e2ee();
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
    let client = ConfidentialInference::builder()
        .exclusive_trusted_artifact_signing_keys(vec![TrustedSigningKey::new(
            key_entry.signer.clone(),
            key_entry.key_id.clone(),
            key_entry.public_key_base64url.clone(),
        )])
        .registry(registry_envelope.clone())
        .reference_values(reference_envelope.clone())
        .compatibility_matrix(matrix_envelope.payload.clone())
        .api_key("ppq", api_key)
        .policy(policy.clone())
        .build()
        .await?;
    if let Some(prompt) = smoke_chat {
        for (_, canonical_model) in models {
            let result = client
                .chat_completions()
                .model(canonical_model.clone())
                .message(ChatMessage::user(prompt.clone()))
                .max_tokens(256)
                .send()
                .await?;
            println!(
                "{canonical_model} smoke chat verdict: {:?}",
                result.verdict.status
            );
            if result.verdict.status
                != confidential_inference_attestation::VerificationStatus::Verified
            {
                return Err("PPQ smoke chat was not verified".into());
            }
            let choice = result
                .response
                .choices
                .first()
                .ok_or("smoke chat returned no choices")?;
            let content = choice
                .message
                .content
                .text()
                .filter(|s| !s.trim().is_empty())
                .ok_or("smoke chat returned empty content")?;
            println!("smoke chat response: {content}");
        }
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
            "api_keys": {"ppq": {"env": "PPQ_API_KEY"}},
            "policy": policy,
        }),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppq_digest_must_equal_latest_release() {
        assert_eq!(require_latest_release("ABCD", "abcd").unwrap(), "abcd");
        let error = require_latest_release("old", "new")
            .unwrap_err()
            .to_string();
        assert!(error.contains("old") && error.contains("new"));
    }
}
