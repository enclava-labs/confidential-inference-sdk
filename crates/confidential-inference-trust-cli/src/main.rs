use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use confidential_inference_attestation::{
    canonical_json, certificate_spki_sha256_hex, chutes_live_tee_measurement,
    format_utc_timestamp_millis, parse_tinfoil_live_capture,
    verify_chutes_live_report_data_binding, verify_tinfoil_quote_with_vcek, AliasConfidence,
    ArtifactSignature, BoundDataRequirement, ChannelBindingKind, CheckResult, ChutesLiveEvidence,
    ChutesLiveReportDataBinding, FreshnessClass, GpuAttestationVerifier, GpuTeeKind,
    ModelBindingRequirement, NvidiaGpuAttestationVerificationRequest, ReferenceValuesEnvelope,
    ResponseIntegrityRequirement, TinfoilQuoteVerificationRequest, TinfoilQuoteVerifier, TrustTier,
    TrustedSigningKey, VerificationPolicy,
};
use confidential_inference_openai::ChatMessage;
use confidential_inference_providers::{
    generate_chutes_live_reference_values, generate_tinfoil_live_reference_values,
    AmdKdsSevSnpVcekResolver, ChutesHttpProvider, ChutesLiveReferenceValuesInput, CredentialKind,
    DcapTdxCollateralResolver, EncryptionRequirement, EvidenceRequest, ModelBindingSupport,
    NvidiaNrasRemoteClient, ProviderAdapter, ProviderCompatibilityMatrix,
    ProviderCompatibilityMatrixEnvelope, ProviderRegistry, ProviderRegistryEnvelope, RegistryModel,
    RouteDefinition, RouteExecutionStatus, RouteLifecycle, SevSnpVcekResolver, SourceSyncRun,
    StreamingSupport, TinfoilHttpProvider, TinfoilLiveReferenceValuesInput,
};
use confidential_inference_sdk::{ClientError, ConfidentialInference};
use ed25519_compact::{KeyPair, Seed};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const ISSUER: &str = "operator-pinned-observed";
const PRIVATE_KEY_FILE: &str = "operator-ed25519.key";
const PUBLIC_KEY_FILE: &str = "trusted-ed25519-signing-key.json";
const CHUTES_API_BASE_URL: &str = "https://llm.chutes.ai/v1";
const CHUTES_EVIDENCE_ENDPOINT: &str = "https://api.chutes.ai";
const TINFOIL_API_BASE_URL: &str = "https://inference.tinfoil.sh/v1";
const TINFOIL_EVIDENCE_ENDPOINT: &str =
    "https://inference.tinfoil.sh/.well-known/tinfoil-attestation";

const USAGE: &str = "usage:
  confidential-inference-trust keygen --out <dir>
  confidential-inference-trust pin chutes --model <provider-model> --canonical-model <name>
      --key-dir <dir> --out <dir> [--captures <n>] [--valid-days <d>] [--smoke-chat <prompt>]
  confidential-inference-trust pin tinfoil --model <provider-model> --canonical-model <name>
      --key-dir <dir> --out <dir> [--smoke-chat <prompt>]

pin chutes reads CHUTES_API_KEY; pin tinfoil reads TINFOIL_API_KEY. Both commands
verify live provider evidence before signing operator trust-on-first-use artifacts.";

#[derive(Serialize, Deserialize)]
struct PublicKeyEntry {
    signer: String,
    key_id: String,
    public_key_base64url: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("confidential-inference-trust: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return Err(USAGE.into());
    }
    match args.remove(0).as_str() {
        "keygen" => {
            let flags = parse_flags(&args, &["--out"])?;
            keygen(Path::new(required(&flags, "--out")?))
        }
        "pin" => {
            let provider = args.first().map(String::as_str).unwrap_or_default();
            let allowed: &[&str] = match provider {
                "chutes" => &[
                    "--model",
                    "--canonical-model",
                    "--key-dir",
                    "--out",
                    "--captures",
                    "--valid-days",
                    "--smoke-chat",
                ],
                "tinfoil" => &[
                    "--model",
                    "--canonical-model",
                    "--key-dir",
                    "--out",
                    "--smoke-chat",
                ],
                _ => return Err(format!("unsupported pin provider {provider:?}\n{USAGE}").into()),
            };
            let flags = parse_flags(&args[1..], allowed)?;
            let options = PinOptions {
                provider_model: required(&flags, "--model")?.to_owned(),
                canonical_model: required(&flags, "--canonical-model")?.to_owned(),
                key_dir: PathBuf::from(required(&flags, "--key-dir")?),
                out: PathBuf::from(required(&flags, "--out")?),
                captures: optional_number(&flags, "--captures", 3)?,
                valid_days: optional_number(&flags, "--valid-days", 7)?,
                smoke_chat: flags.get("--smoke-chat").cloned(),
            };
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            match provider {
                "chutes" => runtime.block_on(pin_chutes(options)),
                "tinfoil" => runtime.block_on(pin_tinfoil(options)),
                _ => unreachable!(),
            }
        }
        _ => Err(USAGE.into()),
    }
}

fn parse_flags(args: &[String], allowed: &[&str]) -> Result<BTreeMap<String, String>, String> {
    let mut flags = BTreeMap::new();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        if !allowed.contains(&flag.as_str()) {
            return Err(format!("unexpected argument {flag}\n{USAGE}"));
        }
        let value = iter
            .next()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        if flags.insert(flag.clone(), value.clone()).is_some() {
            return Err(format!("{flag} given more than once"));
        }
    }
    Ok(flags)
}

fn required<'a>(flags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    flags
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required\n{USAGE}"))
}

fn optional_number(
    flags: &BTreeMap<String, String>,
    name: &str,
    default: u64,
) -> Result<u64, String> {
    match flags.get(name) {
        None => Ok(default),
        Some(value) => match value.parse::<u64>() {
            Ok(number) if number > 0 => Ok(number),
            _ => Err(format!("{name} must be a positive integer")),
        },
    }
}

fn keygen(out: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(out)?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)?;
    let pair = KeyPair::from_seed(Seed::new(seed));
    let key_id = format!(
        "operator-ed25519-{}",
        &URL_SAFE_NO_PAD.encode(pair.pk.as_ref())[..12]
    );
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    let mut private_file = options.open(out.join(PRIVATE_KEY_FILE))?;
    private_file.write_all(&seed)?;
    private_file.sync_all()?;
    seed.fill(0);
    let entry = PublicKeyEntry {
        signer: ISSUER.into(),
        key_id,
        public_key_base64url: URL_SAFE_NO_PAD.encode(pair.pk.as_ref()),
    };
    let public_path = out.join(PUBLIC_KEY_FILE);
    fs::write(&public_path, serde_json::to_vec_pretty(&entry)?)?;
    println!("Public key entry: {}", public_path.display());
    Ok(())
}

struct PinOptions {
    provider_model: String,
    canonical_model: String,
    key_dir: PathBuf,
    out: PathBuf,
    captures: u64,
    valid_days: u64,
    smoke_chat: Option<String>,
}

fn chutes_route(canonical_model: &str, provider_model: &str) -> RouteDefinition {
    RouteDefinition {
        route_id: format!("chutes:{canonical_model}:live"),
        route_status: RouteLifecycle::Active,
        provider: "chutes".into(),
        provider_model: provider_model.into(),
        evidence_family: "chutes_live_e2ee".into(),
        api_base_url: CHUTES_API_BASE_URL.into(),
        evidence_endpoint: CHUTES_EVIDENCE_ENDPOINT.into(),
        adapter_version: "chutes-live-v1".into(),
        freshness_class: FreshnessClass::PerRequest,
        channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
        trust_tier: TrustTier::AppE2ee,
        request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_integrity_requirement: ResponseIntegrityRequirement::ChannelBound,
        accepted_gpu_tees: vec![GpuTeeKind::NvidiaCc],
        request_encryption: EncryptionRequirement::Required,
        response_decryption: EncryptionRequirement::Required,
        streaming: StreamingSupport::Unsupported,
        alias_confidence: AliasConfidence::ProviderDeclared,
    }
}

fn random_nonce_hex() -> Result<String, Box<dyn Error>> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Captures one Chutes live evidence bundle and returns its measurement only
/// if every check the live verifier performs on the quote and GPU token passes.
async fn verified_chutes_measurement(
    provider: &ChutesHttpProvider,
    route: &RouteDefinition,
    nras: &NvidiaNrasRemoteClient,
) -> Result<String, Box<dyn Error>> {
    let raw = provider
        .fetch_evidence(
            route,
            &EvidenceRequest {
                requested_model: route.provider_model.clone(),
                policy_digest: "sha256:operator-pin-capture".into(),
                nonce: Some(random_nonce_hex()?),
            },
        )
        .await?;
    let evidence: ChutesLiveEvidence = serde_json::from_slice(&raw)?;
    if evidence.schema != ChutesLiveEvidence::SCHEMA || evidence.route_id != route.route_id {
        return Err("captured evidence does not match the pinned route".into());
    }

    let gpu = evidence
        .gpu_attestation
        .as_ref()
        .ok_or("capture has no NVIDIA GPU attestation")?;
    nras.fetch_jwt_verifier()
        .await?
        .verify_nvidia_gpu_attestation(&NvidiaGpuAttestationVerificationRequest {
            evidence: gpu,
            expected_nonce: &gpu.nonce,
            expected_tee: GpuTeeKind::NvidiaCc,
            provider: &route.provider,
            route_id: &route.route_id,
        })?;

    let quote = STANDARD.decode(&evidence.quote_base64)?;
    let verified_quote = DcapTdxCollateralResolver::with_phala_pccs()?
        .verifier_for_quote(&quote)
        .await?
        .verify_tdx_quote(&quote)?;
    let certificate = STANDARD.decode(&evidence.certificate_der_base64)?;
    let certificate_spki = certificate_spki_sha256_hex(&certificate)?;
    if verify_chutes_live_report_data_binding(
        &verified_quote.report_data,
        &evidence.request_nonce,
        &evidence.e2e_public_key_base64,
        &certificate_spki,
    ) != ChutesLiveReportDataBinding::Verified
    {
        return Err("quote report data is not bound to the nonce, E2EE key and certificate".into());
    }
    Ok(chutes_live_tee_measurement(&verified_quote))
}

fn load_signing_key(key_dir: &Path) -> Result<(KeyPair, PublicKeyEntry), Box<dyn Error>> {
    let seed_bytes = fs::read(key_dir.join(PRIVATE_KEY_FILE))?;
    let seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "operator private key must be a 32-byte Ed25519 seed")?;
    let pair = KeyPair::from_seed(Seed::new(seed));
    let entry: PublicKeyEntry = serde_json::from_slice(&fs::read(key_dir.join(PUBLIC_KEY_FILE))?)?;
    if entry.public_key_base64url != URL_SAFE_NO_PAD.encode(pair.pk.as_ref()) {
        return Err("public key entry does not match the operator private key".into());
    }
    Ok((pair, entry))
}

fn sign<T: Serialize>(
    pair: &KeyPair,
    entry: &PublicKeyEntry,
    payload: &T,
) -> Result<ArtifactSignature, Box<dyn Error>> {
    let message = canonical_json(payload)?;
    let signature = pair.sk.sign(message.as_bytes(), None);
    Ok(ArtifactSignature {
        signer: entry.signer.clone(),
        key_id: entry.key_id.clone(),
        alg: "ed25519".into(),
        value: format!("base64url:{}", URL_SAFE_NO_PAD.encode(signature.as_ref())),
    })
}

fn now_epoch_ms() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn Error>> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    println!("wrote {}", path.display());
    Ok(())
}

async fn pin_chutes(options: PinOptions) -> Result<(), Box<dyn Error>> {
    let api_key = env::var("CHUTES_API_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or("CHUTES_API_KEY must be set in the environment")?;
    let (pair, key_entry) = load_signing_key(&options.key_dir)?;
    let route = chutes_route(&options.canonical_model, &options.provider_model);
    let provider = ChutesHttpProvider::new("chutes", vec![route.clone()], api_key.clone())?;
    let nras = NvidiaNrasRemoteClient::with_default_http()?;

    let mut measurements = BTreeSet::new();
    for capture in 1..=options.captures {
        let measurement = verified_chutes_measurement(&provider, &route, &nras).await?;
        println!("capture {capture}/{}: verified", options.captures);
        measurements.insert(measurement);
    }
    println!(
        "verified {} capture(s), {} distinct TDX measurement(s)",
        options.captures,
        measurements.len()
    );

    let now_ms = now_epoch_ms()?;
    let now = format_utc_timestamp_millis(now_ms);
    let valid_until_epoch_ms = now_ms + options.valid_days * 24 * 60 * 60 * 1000;
    let version = format!("operator-pin-{now_ms}");

    let registry = ProviderRegistry {
        schema: ProviderRegistry::SCHEMA.into(),
        version: version.clone(),
        generated_at: now.clone(),
        source_sync_run: SourceSyncRun {
            completed_at: now.clone(),
            status: "success".into(),
            source: format!("{ISSUER}: confidential-inference-trust pin chutes"),
        },
        models: BTreeMap::from([(
            options.canonical_model.clone(),
            RegistryModel {
                canonical_model: options.canonical_model.clone(),
                display_name: options.canonical_model.clone(),
                family: "chutes".into(),
                aliases: vec![options.canonical_model.clone()],
                routes: vec![route.clone()],
            },
        )]),
    };
    ProviderCompatibilityMatrix::bundled()?.validate_registry_routes(&registry)?;

    let reference_values = generate_chutes_live_reference_values(ChutesLiveReferenceValuesInput {
        version,
        issuer: ISSUER.into(),
        valid_from: now,
        valid_until: format_utc_timestamp_millis(valid_until_epoch_ms),
        valid_until_epoch_ms,
        canonical_model: options.canonical_model.clone(),
        route,
        verified_measurements: measurements.into_iter().collect(),
    })?;

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

    // Self-check: the artifacts must load through the same builder path any
    // integrator uses, with the operator key as the exclusive trust root.
    let client = ConfidentialInference::builder()
        .exclusive_trusted_artifact_signing_keys(vec![TrustedSigningKey::new(
            key_entry.signer.clone(),
            key_entry.key_id.clone(),
            key_entry.public_key_base64url.clone(),
        )])
        .registry(registry_envelope.clone())
        .reference_values(reference_envelope.clone())
        .api_key("chutes", api_key)
        .build()
        .await?;

    fs::create_dir_all(&options.out)?;
    write_json(
        &options.out.join("registry.envelope.json"),
        &registry_envelope,
    )?;
    write_json(
        &options.out.join("reference-values.envelope.json"),
        &reference_envelope,
    )?;
    write_json(
        &options.out.join("operator-config.json"),
        &serde_json::json!({
            "demo_provider": false,
            "trusted_ed25519_signing_keys": [key_entry],
            "registry": registry_envelope,
            "reference_values": reference_envelope,
            "api_keys": {"chutes": {"env": "CHUTES_API_KEY"}},
        }),
    )?;
    eprintln!(
        "WARNING: these artifacts pin observed, verified measurements (trust-on-first-use). \
         They are operator development trust material, not provider-published production \
         reference values."
    );

    if let Some(prompt) = options.smoke_chat {
        let result = match client
            .chat_completions()
            .model(options.canonical_model)
            .message(ChatMessage::user(prompt))
            .max_tokens(32)
            .send()
            .await
        {
            Ok(result) => result,
            Err(ClientError::PolicyDenied { route_id, verdict }) => {
                eprintln!("smoke chat denied for {route_id}; unmet checks:");
                for (check, outcome) in &verdict.checks {
                    if *outcome != CheckResult::Verified && *outcome != CheckResult::NotApplicable {
                        eprintln!("  {check}: {outcome:?}");
                    }
                }
                for error in &verdict.errors {
                    eprintln!("  error {}: {}", error.code, error.message);
                }
                return Err("smoke chat denied by verification policy".into());
            }
            Err(other) => return Err(other.into()),
        };
        println!("smoke chat verdict: {:?}", result.verdict.status);
        println!(
            "smoke chat response: {}",
            result.response.choices[0]
                .message
                .content
                .text()
                .unwrap_or_default()
        );
    }
    Ok(())
}

fn tinfoil_route(canonical_model: &str, provider_model: &str) -> RouteDefinition {
    RouteDefinition {
        route_id: format!("tinfoil:{canonical_model}:live"),
        route_status: RouteLifecycle::Active,
        provider: "tinfoil".into(),
        provider_model: provider_model.into(),
        evidence_family: "tinfoil_hw_verified_tls".into(),
        api_base_url: TINFOIL_API_BASE_URL.into(),
        evidence_endpoint: TINFOIL_EVIDENCE_ENDPOINT.into(),
        adapter_version: "tinfoil-live-v1".into(),
        freshness_class: FreshnessClass::PerSession,
        channel_binding_kind: ChannelBindingKind::TeeTerminatedTls,
        trust_tier: TrustTier::HwVerifiedTls,
        request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_integrity_requirement: ResponseIntegrityRequirement::ChannelBound,
        accepted_gpu_tees: Vec::new(),
        request_encryption: EncryptionRequirement::NotRequired,
        response_decryption: EncryptionRequirement::NotRequired,
        streaming: StreamingSupport::Unsupported,
        alias_confidence: AliasConfidence::ProviderDeclared,
    }
}

fn tinfoil_compatibility_matrix(
    model_binding_support: Option<ModelBindingSupport>,
) -> Result<ProviderCompatibilityMatrix, Box<dyn Error>> {
    let mut matrix = ProviderCompatibilityMatrix::bundled()?;
    let mut profile = matrix
        .providers
        .remove("tinfoil-fixture")
        .ok_or("bundled compatibility matrix has no Tinfoil profile")?;
    matrix.providers.clear();
    profile.provider = "tinfoil".into();
    profile.api_base_url = TINFOIL_API_BASE_URL.into();
    profile.required_credentials = vec![CredentialKind::BearerToken];
    profile
        .known_unsupported_modes
        .retain(|mode| mode != "live_tdx_quote");
    profile.route_execution_status = RouteExecutionStatus::Executable;
    if let Some(support) = model_binding_support {
        profile.model_binding_support = support;
    }
    matrix.providers.insert("tinfoil".into(), profile);
    matrix.validate()?;
    Ok(matrix)
}

fn tinfoil_profile_matches(
    first: &confidential_inference_attestation::VerifiedTinfoilQuote,
    second: &confidential_inference_attestation::VerifiedTinfoilQuote,
    first_spki: &str,
    second_spki: &str,
) -> bool {
    first.attestation_format == second.attestation_format
        && first.hardware == second.hardware
        && first.tee_measurement == second.tee_measurement
        && first.attested_model == second.attested_model
        && first.workload_image_digest == second.workload_image_digest
        && first.model_artifacts == second.model_artifacts
        && first_spki.eq_ignore_ascii_case(second_spki)
}

async fn verified_tinfoil_capture(
    provider: &TinfoilHttpProvider,
    route: &RouteDefinition,
    tdx_resolver: &DcapTdxCollateralResolver,
    snp_resolver: &AmdKdsSevSnpVcekResolver,
) -> Result<
    (
        confidential_inference_attestation::VerifiedTinfoilQuote,
        String,
    ),
    Box<dyn Error>,
> {
    let raw = provider
        .fetch_evidence(
            route,
            &EvidenceRequest {
                requested_model: route.provider_model.clone(),
                policy_digest: "sha256:operator-pin-capture".into(),
                nonce: None,
            },
        )
        .await?;
    let parsed = parse_tinfoil_live_capture(&raw)?;
    if parsed.capture.provider != route.provider
        || parsed.capture.route_id != route.route_id
        || parsed.capture.evidence_family != route.evidence_family
        || parsed.capture.requested_model != route.provider_model
        || parsed.capture.evidence_endpoint != route.evidence_endpoint
    {
        return Err("captured Tinfoil evidence does not match the pinned route".into());
    }
    let request = TinfoilQuoteVerificationRequest {
        capture: &parsed.capture,
        attestation_format: parsed.attestation_format,
        quote_bytes: &parsed.quote_bytes,
        live_tls_leaf_certificate_der: &parsed.live_tls_leaf_certificate_der,
        live_tls_spki_sha256: &parsed.capture.live_tls_spki_sha256,
    };
    let quote = match parsed.attestation_format {
        confidential_inference_attestation::TinfoilAttestationFormat::TdxGuestV2 => tdx_resolver
            .verifier_for_quote(&parsed.quote_bytes)
            .await?
            .verify_tinfoil_quote(&request)?,
        confidential_inference_attestation::TinfoilAttestationFormat::SevSnpGuestV2 => {
            let report = &parsed.quote_bytes;
            if report.len() != 1184 {
                return Err("SEV-SNP report has wrong size".into());
            }
            let chip_id: [u8; 64] = report[416..480].try_into()?;
            let reported_tcb = u64::from_le_bytes(report[384..392].try_into()?);
            let tcb = [
                reported_tcb as u8,
                (reported_tcb >> 8) as u8,
                (reported_tcb >> 48) as u8,
                (reported_tcb >> 56) as u8,
            ];
            if chip_id.iter().all(|byte| *byte == 0) || reported_tcb == 0 {
                return Err("SEV-SNP report chip_id or TCB is empty".into());
            }
            let vcek = snp_resolver.resolve_vcek("Genoa", &chip_id, tcb).await?;
            verify_tinfoil_quote_with_vcek(&request, &vcek)?
        }
    };
    Ok((quote, parsed.capture.live_tls_spki_sha256))
}

async fn pin_tinfoil(options: PinOptions) -> Result<(), Box<dyn Error>> {
    let api_key = env::var("TINFOIL_API_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or("TINFOIL_API_KEY must be set in the environment")?;
    let (pair, key_entry) = load_signing_key(&options.key_dir)?;
    let route = tinfoil_route(&options.canonical_model, &options.provider_model);
    let provider = TinfoilHttpProvider::new(vec![route.clone()], Some(api_key.clone()))?;
    let resolver = DcapTdxCollateralResolver::with_phala_pccs()?;
    let snp_resolver = AmdKdsSevSnpVcekResolver::new()?;

    let (first_quote, first_spki) =
        verified_tinfoil_capture(&provider, &route, &resolver, &snp_resolver).await?;
    println!("capture 1/2: verified");
    let snp_router_mode = first_quote.attestation_format
        == confidential_inference_attestation::TINFOIL_SEV_SNP_GUEST_V2_FORMAT;
    let (second_quote, second_spki) =
        verified_tinfoil_capture(&provider, &route, &resolver, &snp_resolver).await?;
    println!("capture 2/2: verified");
    if !tinfoil_profile_matches(&first_quote, &second_quote, &first_spki, &second_spki) {
        return Err("the two verified Tinfoil captures disagree on pinned profile values".into());
    }

    let now_ms = now_epoch_ms()?;
    let now = format_utc_timestamp_millis(now_ms);
    let version = format!("operator-pin-{now_ms}");
    let reference_values =
        generate_tinfoil_live_reference_values(TinfoilLiveReferenceValuesInput {
            version: version.clone(),
            issuer: ISSUER.into(),
            valid_from: now.clone(),
            revocation_epoch: 0,
            minimum_acceptable_version: version.clone(),
            canonical_model: options.canonical_model.clone(),
            route: route.clone(),
            verified_quote: first_quote,
            live_tls_spki_sha256: first_spki,
        })?;
    let registry = ProviderRegistry {
        schema: ProviderRegistry::SCHEMA.into(),
        version: version.clone(),
        generated_at: now.clone(),
        source_sync_run: SourceSyncRun {
            completed_at: now,
            status: "success".into(),
            source: format!("{ISSUER}: confidential-inference-trust pin tinfoil"),
        },
        models: BTreeMap::from([(
            options.canonical_model.clone(),
            RegistryModel {
                canonical_model: options.canonical_model.clone(),
                display_name: options.canonical_model.clone(),
                family: "tinfoil".into(),
                aliases: vec![options.canonical_model.clone()],
                routes: vec![route],
            },
        )]),
    };
    let matrix =
        tinfoil_compatibility_matrix(snp_router_mode.then_some(ModelBindingSupport::Unsupported))?;
    let mut policy = VerificationPolicy::require_hw_verified_tls();
    if snp_router_mode {
        policy.model_binding_requirement = ModelBindingRequirement::IfProviderSupports;
    }
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
    let client = ConfidentialInference::builder()
        .exclusive_trusted_artifact_signing_keys(vec![TrustedSigningKey::new(
            key_entry.signer.clone(),
            key_entry.key_id.clone(),
            key_entry.public_key_base64url.clone(),
        )])
        .registry(registry_envelope.clone())
        .reference_values(reference_envelope.clone())
        .compatibility_matrix(matrix_envelope.payload.clone())
        .api_key("tinfoil", api_key)
        .tinfoil_sev_snp_vcek_resolver(snp_resolver)
        .policy(policy.clone())
        .build()
        .await?;
    fs::create_dir_all(&options.out)?;
    write_json(
        &options.out.join("registry.envelope.json"),
        &registry_envelope,
    )?;
    write_json(
        &options.out.join("reference-values.envelope.json"),
        &reference_envelope,
    )?;
    write_json(
        &options.out.join("compatibility-matrix.envelope.json"),
        &matrix_envelope,
    )?;
    write_json(
        &options.out.join("operator-config.json"),
        &serde_json::json!({
            "demo_provider": false,
            "trusted_ed25519_signing_keys": [key_entry],
            "registry": registry_envelope,
            "reference_values": reference_envelope,
            "compatibility_matrix": matrix_envelope,
            "api_keys": {"tinfoil": {"env": "TINFOIL_API_KEY"}},
            "policy": policy,
        }),
    )?;
    eprintln!(
        "WARNING: artifacts pin two observed, verified Tinfoil captures (trust-on-first-use), not provider-published production reference values."
    );
    if let Some(prompt) = options.smoke_chat {
        let result = client
            .chat_completions()
            .model(options.canonical_model)
            .message(ChatMessage::user(prompt))
            .max_tokens(32)
            .send()
            .await?;
        println!("smoke chat verdict: {:?}", result.verdict.status);
        println!(
            "smoke chat response: {}",
            result.response.choices[0]
                .message
                .content
                .text()
                .unwrap_or_default()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tinfoil_pin_tests {
    use super::*;
    use confidential_inference_attestation::{CpuTeeKind, EvidenceHardware, VerifiedTinfoilQuote};

    fn verified(measurement: &str) -> VerifiedTinfoilQuote {
        let mut quote = VerifiedTinfoilQuote::from_verified_quote(
            confidential_inference_attestation::TinfoilAttestationFormat::TdxGuestV2,
            EvidenceHardware {
                cpu: CpuTeeKind::Tdx,
                gpu: None,
            },
            measurement,
            "00",
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
            1,
        );
        quote.attested_model = Some("model".into());
        quote.workload_image_digest = Some("sha256:image".into());
        quote
    }
    #[test]
    fn snp_tcb_uses_kds_spl_byte_order() {
        let reported_tcb = u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let tcb = [
            reported_tcb as u8,
            (reported_tcb >> 8) as u8,
            (reported_tcb >> 48) as u8,
            (reported_tcb >> 56) as u8,
        ];
        assert_eq!(tcb, [1, 2, 7, 8]);
    }

    #[test]
    fn tinfoil_profile_requires_two_captures_to_agree() {
        let first = verified("tdx:mr_td:one");
        assert!(tinfoil_profile_matches(&first, &first, "abcd", "ABCD"));
        assert!(!tinfoil_profile_matches(
            &first,
            &verified("tdx:mr_td:two"),
            "abcd",
            "abcd"
        ));
        assert!(!tinfoil_profile_matches(&first, &first, "abcd", "efgh"));
    }

    #[test]
    fn tinfoil_compatibility_profile_is_executable_for_live_provider() {
        let matrix = tinfoil_compatibility_matrix(None).unwrap();
        let profile = matrix.provider("tinfoil").unwrap();
        assert!(profile.route_execution_status.allows_chat_execution());
        assert_eq!(profile.api_base_url, TINFOIL_API_BASE_URL);
    }
}
