mod ppq;
mod redpill;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use confidential_inference_attestation::{
    canonical_json, certificate_spki_sha256_hex, chutes_live_tee_measurement,
    format_utc_timestamp_millis, parse_tinfoil_live_capture,
    verify_chutes_live_report_data_binding, verify_tinfoil_quote_with_vcek,
    verify_tinfoil_release_measurement, verify_tinfoil_sigstore_bundle, AliasConfidence,
    ArtifactSignature, BoundDataRequirement, ChannelBindingKind, CheckResult, ChutesLiveEvidence,
    ChutesLiveReportDataBinding, FreshnessClass, GpuAttestationVerifier, GpuTeeKind,
    ModelBindingRequirement, NvidiaGpuAttestationVerificationRequest, ReferenceValuesEnvelope,
    ResponseIntegrityRequirement, TinfoilQuoteVerificationRequest, TinfoilQuoteVerifier, TrustTier,
    TrustedSigningKey, VerificationPolicy,
};
use confidential_inference_openai::ChatMessage;
use confidential_inference_providers::{
    generate_chutes_live_reference_values_for_routes,
    generate_tinfoil_live_reference_values_for_routes, AmdKdsSevSnpVcekResolver,
    ChutesHttpProvider, ChutesLiveReferenceValuesInput, CredentialKind, DcapTdxCollateralResolver,
    EncryptionRequirement, EvidenceRequest, ModelBindingSupport, NvidiaNrasRemoteClient,
    ProviderAdapter, ProviderCompatibilityMatrix, ProviderCompatibilityMatrixEnvelope,
    ProviderRegistry, ProviderRegistryEnvelope, RegistryModel, RouteDefinition,
    RouteExecutionStatus, RouteLifecycle, SevSnpVcekResolver, SourceSyncRun, StreamingSupport,
    TinfoilHttpProvider, TinfoilLiveReferenceValuesInput,
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
use zeroize::Zeroizing;

const ISSUER: &str = "operator-pinned-observed";
const PRIVATE_KEY_FILE: &str = "operator-ed25519.key";
const PUBLIC_KEY_FILE: &str = "trusted-ed25519-signing-key.json";
const CHUTES_API_BASE_URL: &str = "https://llm.chutes.ai/v1";
const CHUTES_EVIDENCE_ENDPOINT: &str = "https://api.chutes.ai";
const TINFOIL_API_BASE_URL: &str = "https://inference.tinfoil.sh/v1";
const TINFOIL_EVIDENCE_ENDPOINT: &str =
    "https://inference.tinfoil.sh/.well-known/tinfoil-attestation";
const TINFOIL_SIGSTORE_REPO: &str = "tinfoilsh/confidential-model-router";

fn release_provenance(digest: &str) -> String {
    format!("sigstore-verified-release:{TINFOIL_SIGSTORE_REPO}:sha256:{digest}")
}

fn append_response_chunk(
    buffer: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
) -> Result<(), Box<dyn Error>> {
    if chunk.len() > limit.saturating_sub(buffer.len()) {
        return Err(format!("GitHub response exceeds {limit} bytes").into());
    }
    buffer.extend_from_slice(chunk);
    Ok(())
}

async fn bounded_response(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    response = response.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(format!("GitHub response exceeds {limit} bytes").into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        append_response_chunk(&mut bytes, &chunk, limit)?;
    }
    Ok(bytes)
}

async fn tinfoil_release() -> Result<(String, String), Box<dyn Error>> {
    let client = confidential_inference_providers::reqwest_client_builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("confidential-inference-trust")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let base = format!("https://api.github.com/repos/{TINFOIL_SIGSTORE_REPO}");
    let release: serde_json::Value = serde_json::from_slice(
        &bounded_response(
            client.get(format!("{base}/releases/latest")).send().await?,
            1024 * 1024,
        )
        .await?,
    )?;
    let tag = release["tag_name"].as_str().ok_or("release tag missing")?;
    if tag.is_empty()
        || !tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("invalid Tinfoil release tag".into());
    }
    let hash_bytes = bounded_response(
        client
            .get(format!(
                "https://github.com/{TINFOIL_SIGSTORE_REPO}/releases/download/{tag}/tinfoil.hash"
            ))
            .send()
            .await?,
        1024 * 1024,
    )
    .await?;
    let digest = std::str::from_utf8(&hash_bytes)?
        .trim()
        .to_ascii_lowercase();
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid Tinfoil release digest".into());
    }
    let attestations: serde_json::Value = serde_json::from_slice(
        &bounded_response(
            client
                .get(format!("{base}/attestations/sha256:{digest}"))
                .send()
                .await?,
            8 * 1024 * 1024,
        )
        .await?,
    )?;
    let bundle = attestations["attestations"]
        .as_array()
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get("bundle"))
        .ok_or("Tinfoil release attestation missing")?;
    let measurement = verify_tinfoil_sigstore_bundle(bundle, TINFOIL_SIGSTORE_REPO, &digest)?;
    Ok((digest, measurement))
}

const USAGE: &str = "usage:
  confidential-inference-trust keygen --out <dir>
  confidential-inference-trust pin chutes --model <provider-model[,provider-model...]> --canonical-model <name[,name...]>
      --key-dir <dir> --out <dir> [--captures <n>] [--valid-days <d>] [--smoke-chat <prompt>]
  confidential-inference-trust pin tinfoil --model <provider-model[,provider-model...]> --canonical-model <name[,name...]>
      --key-dir <dir> --out <dir> [--smoke-chat <prompt>]
  confidential-inference-trust pin ppq --model <provider-model[,provider-model...]> --canonical-model <name[,name...]>
      --key-dir <dir> --out <dir> [--smoke-chat <prompt>]
  confidential-inference-trust pin redpill --model <provider-model[,provider-model...]> --canonical-model <name[,name...]>
      --key-dir <dir> --out <dir> [--smoke-chat <prompt>]

pin chutes reads CHUTES_API_KEY; pin tinfoil reads TINFOIL_API_KEY; pin ppq reads PPQ_API_KEY;
pin redpill reads REDPILL_API_KEY. Tinfoil and PPQ pins require Sigstore-verified release measurements;
Chutes pins observed verified evidence.";

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
                "tinfoil" | "ppq" | "redpill" => &[
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
                models: parse_models(
                    required(&flags, "--model")?,
                    required(&flags, "--canonical-model")?,
                )?,
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
                "ppq" => runtime.block_on(ppq::pin(
                    &options.models,
                    &options.key_dir,
                    &options.out,
                    options.smoke_chat,
                )),
                "redpill" => runtime.block_on(redpill::pin(
                    &options.models,
                    &options.key_dir,
                    &options.out,
                    options.smoke_chat,
                )),
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

fn parse_models(
    provider_models: &str,
    canonical_models: &str,
) -> Result<Vec<(String, String)>, String> {
    let provider_models: Vec<_> = provider_models.split(',').map(str::trim).collect();
    let canonical_models: Vec<_> = canonical_models.split(',').map(str::trim).collect();
    if provider_models.len() != canonical_models.len() {
        return Err("--model and --canonical-model must contain the same number of entries".into());
    }
    let mut providers = BTreeSet::new();
    let mut canonicals = BTreeSet::new();
    provider_models
        .into_iter()
        .zip(canonical_models)
        .map(|(provider, canonical)| {
            if provider.is_empty() || canonical.is_empty() {
                return Err("model entries must not be empty".into());
            }
            if !providers.insert(provider) || !canonicals.insert(canonical) {
                return Err("model entries must not contain duplicates".into());
            }
            Ok((provider.to_owned(), canonical.to_owned()))
        })
        .collect()
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
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed)?;
    let pair = KeyPair::from_seed(Seed::new(*seed));
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
    #[cfg(windows)]
    eprintln!(
        "warning: {} is not access-restricted on Windows; protect {} manually",
        PRIVATE_KEY_FILE,
        out.display()
    );
    use std::io::Write;
    let mut private_file = options.open(out.join(PRIVATE_KEY_FILE))?;
    private_file.write_all(&*seed)?;
    private_file.sync_all()?;
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
    models: Vec<(String, String)>,
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
    // Reads the seed straight into zeroing memory; KeyPair's SecretKey wipes
    // itself on Drop (ed25519-compact), so no un-wiped secret copy remains.
    use std::io::Read;
    let mut seed = Zeroizing::new([0u8; 32]);
    let mut file = fs::File::open(key_dir.join(PRIVATE_KEY_FILE))?;
    file.read_exact(&mut *seed)?;
    let mut trailing = Zeroizing::new([0u8; 1]);
    if file.read(&mut *trailing)? != 0 {
        return Err("operator signing seed must contain exactly 32 bytes".into());
    }
    let pair = KeyPair::from_seed(Seed::new(*seed));
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
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    fs::write(&tmp_path, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&tmp_path, path)?;
    println!("wrote {}", path.display());
    Ok(())
}

async fn pin_chutes(options: PinOptions) -> Result<(), Box<dyn Error>> {
    let api_key = env::var("CHUTES_API_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or("CHUTES_API_KEY must be set in the environment")?;
    let (pair, key_entry) = load_signing_key(&options.key_dir)?;
    let routes: Vec<_> = options
        .models
        .iter()
        .map(|(provider, canonical)| chutes_route(canonical, provider))
        .collect();
    let provider = ChutesHttpProvider::new("chutes", routes.clone(), api_key.clone())?;
    let nras = NvidiaNrasRemoteClient::with_default_http()?;
    let mut all_measurements = Vec::new();
    for route in &routes {
        let mut measurements = BTreeSet::new();
        for capture in 1..=options.captures {
            let measurement = verified_chutes_measurement(&provider, route, &nras).await?;
            println!(
                "{} capture {capture}/{}: verified",
                route.provider_model, options.captures
            );
            measurements.insert(measurement);
        }
        all_measurements.push(measurements.into_iter().collect::<Vec<_>>());
    }

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
        models: options
            .models
            .iter()
            .zip(&routes)
            .map(|((_, canonical), route)| {
                (
                    canonical.clone(),
                    RegistryModel {
                        canonical_model: canonical.clone(),
                        display_name: canonical.clone(),
                        family: "chutes".into(),
                        aliases: vec![canonical.clone()],
                        routes: vec![route.clone()],
                    },
                )
            })
            .collect(),
    };
    let mut matrix = ProviderCompatibilityMatrix::bundled()?;
    matrix.providers.retain(|provider, _| provider == "chutes");
    matrix.validate_registry_routes(&registry)?;
    let matrix_envelope = ProviderCompatibilityMatrixEnvelope {
        schema: ProviderCompatibilityMatrixEnvelope::SCHEMA.into(),
        signature: sign(&pair, &key_entry, &matrix)?,
        payload: matrix,
    };

    let reference_values = generate_chutes_live_reference_values_for_routes(
        options
            .models
            .iter()
            .zip(routes)
            .zip(all_measurements)
            .map(
                |(((_, canonical), route), measurements)| ChutesLiveReferenceValuesInput {
                    version: version.clone(),
                    issuer: ISSUER.into(),
                    valid_from: now.clone(),
                    revocation_epoch: 0,
                    minimum_acceptable_version: version.clone(),
                    valid_until: format_utc_timestamp_millis(valid_until_epoch_ms),
                    valid_until_epoch_ms,
                    canonical_model: canonical.clone(),
                    route,
                    verified_measurements: measurements,
                },
            )
            .collect(),
    )?;

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
        .compatibility_matrix(matrix_envelope.payload.clone())
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
            "api_keys": {"chutes": {"env": "CHUTES_API_KEY"}},
        }),
    )?;
    eprintln!(
        "WARNING: these artifacts pin observed, verified measurements (trust-on-first-use). \
         They are operator development trust material, not provider-published production \
         reference values."
    );

    if let Some(prompt) = &options.smoke_chat {
        for (_, canonical) in &options.models {
            let result = match client
                .chat_completions()
                .model(canonical)
                .message(ChatMessage::user(prompt))
                .max_tokens(32)
                .send()
                .await
            {
                Ok(result) => result,
                Err(ClientError::PolicyDenied { route_id, verdict }) => {
                    eprintln!("smoke chat denied for {route_id}; unmet checks:");
                    for (check, outcome) in &verdict.checks {
                        if *outcome != CheckResult::Verified
                            && *outcome != CheckResult::NotApplicable
                        {
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
            let choice = result
                .response
                .choices
                .first()
                .ok_or("smoke chat returned no choices")?;
            println!(
                "smoke chat response: {}",
                choice.message.content.text().unwrap_or_default()
            );
        }
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
        streaming: StreamingSupport::Supported,
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
        .retain(|mode| mode != "live_tdx_quote" && mode != "streaming");
    profile.route_execution_status = RouteExecutionStatus::Executable;
    profile.streaming = StreamingSupport::Supported;
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
    let (digest, release_measurement) = tinfoil_release().await?;
    let provenance = release_provenance(&digest);
    println!("Sigstore verified: repo={TINFOIL_SIGSTORE_REPO} digest=sha256:{digest} measurement={release_measurement}");
    let routes: Vec<_> = options
        .models
        .iter()
        .map(|(provider, canonical)| tinfoil_route(canonical, provider))
        .collect();
    let provider = TinfoilHttpProvider::new(routes.clone(), Some(api_key.clone()))?;
    let resolver = DcapTdxCollateralResolver::with_phala_pccs()?;
    let snp_resolver = AmdKdsSevSnpVcekResolver::new()?;
    let mut captures = Vec::new();
    let mut snp_router_mode = None;
    for route in &routes {
        let (first_quote, first_spki) =
            verified_tinfoil_capture(&provider, route, &resolver, &snp_resolver).await?;
        println!("{} capture 1/2: verified", route.provider_model);
        let (second_quote, second_spki) =
            verified_tinfoil_capture(&provider, route, &resolver, &snp_resolver).await?;
        println!("{} capture 2/2: verified", route.provider_model);
        verify_tinfoil_release_measurement(&release_measurement, &first_quote)?;
        verify_tinfoil_release_measurement(&release_measurement, &second_quote)?;
        if !tinfoil_profile_matches(&first_quote, &second_quote, &first_spki, &second_spki) {
            return Err(
                "the two verified Tinfoil captures disagree on pinned profile values".into(),
            );
        }
        let route_is_snp = first_quote.attestation_format
            == confidential_inference_attestation::TINFOIL_SEV_SNP_GUEST_V2_FORMAT;
        if snp_router_mode.is_some_and(|mode| mode != route_is_snp) {
            return Err("Tinfoil models have incompatible attestation formats".into());
        }
        snp_router_mode = Some(route_is_snp);
        captures.push((first_quote, first_spki));
    }
    let snp_router_mode = snp_router_mode.unwrap_or(false);

    let now_ms = now_epoch_ms()?;
    let now = format_utc_timestamp_millis(now_ms);
    let version = format!("operator-pin-{now_ms}");
    let reference_values = generate_tinfoil_live_reference_values_for_routes(
        options
            .models
            .iter()
            .zip(&routes)
            .zip(captures)
            .map(
                |(((_, canonical), route), (quote, spki))| TinfoilLiveReferenceValuesInput {
                    version: version.clone(),
                    issuer: provenance.clone(),
                    valid_from: now.clone(),
                    revocation_epoch: 0,
                    minimum_acceptable_version: version.clone(),
                    canonical_model: canonical.clone(),
                    route: route.clone(),
                    verified_quote: quote,
                    live_tls_spki_sha256: spki,
                },
            )
            .collect(),
    )?;
    let registry = ProviderRegistry {
        schema: ProviderRegistry::SCHEMA.into(),
        version: version.clone(),
        generated_at: now.clone(),
        source_sync_run: SourceSyncRun {
            completed_at: now,
            status: "success".into(),
            source: format!("{provenance}: confidential-inference-trust pin tinfoil"),
        },
        models: options
            .models
            .iter()
            .zip(routes)
            .map(|((_, canonical), route)| {
                (
                    canonical.clone(),
                    RegistryModel {
                        canonical_model: canonical.clone(),
                        display_name: canonical.clone(),
                        family: "tinfoil".into(),
                        aliases: vec![canonical.clone()],
                        routes: vec![route],
                    },
                )
            })
            .collect(),
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
    if let Some(prompt) = &options.smoke_chat {
        for (_, canonical) in &options.models {
            let result = client
                .chat_completions()
                .model(canonical)
                .message(ChatMessage::user(prompt))
                .max_tokens(32)
                .send()
                .await?;
            println!("smoke chat verdict: {:?}", result.verdict.status);
            if result.verdict.status
                != confidential_inference_attestation::VerificationStatus::Verified
            {
                return Err("Tinfoil smoke chat was not verified".into());
            }
            let choice = result
                .response
                .choices
                .first()
                .ok_or("smoke chat returned no choices")?;
            println!(
                "smoke chat response: {}",
                choice.message.content.text().unwrap_or_default()
            );
        }
    }
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
    Ok(())
}

#[cfg(test)]
mod tinfoil_pin_tests {
    use super::*;
    use confidential_inference_attestation::{CpuTeeKind, EvidenceHardware, VerifiedTinfoilQuote};

    #[test]
    fn model_lists_require_unique_nonempty_pairs() {
        assert_eq!(
            parse_models("a,b", "x,y").unwrap(),
            vec![("a".into(), "x".into()), ("b".into(), "y".into())]
        );
        for (models, canonical) in [
            ("a,b", "x"),
            ("a,", "x,y"),
            ("a,a", "x,y"),
            ("a,b", "x,x"),
            ("", ""),
        ] {
            assert!(parse_models(models, canonical).is_err());
        }
    }

    #[test]
    fn pinned_tinfoil_streaming_profile_preserves_stream_options() {
        let route = tinfoil_route("canonical", "provider-model");
        let profile = tinfoil_compatibility_matrix(None)
            .unwrap()
            .providers
            .remove("tinfoil")
            .unwrap();
        profile.validate_route(&route).unwrap();
        assert!(
            route
                .to_attested_route("canonical", "canonical")
                .streaming_allowed
        );
        assert!(!profile
            .known_unsupported_modes
            .iter()
            .any(|mode| mode == "streaming"));
        let mut request = confidential_inference_openai::ChatCompletionRequest::new(
            "canonical",
            vec![ChatMessage::user("hi")],
        );
        request.stream = Some(true);
        request.extra.insert(
            "stream_options".into(),
            serde_json::json!({"include_usage": true}),
        );
        let adapted = profile.adapt_chat_request(&route, &request).unwrap();
        assert_eq!(adapted.body()["stream_options"]["include_usage"], true);
        assert_eq!(adapted.body()["model"], "provider-model");
    }

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
    fn github_response_limit_applies_across_chunks() {
        let mut body = Vec::new();
        append_response_chunk(&mut body, b"123", 5).unwrap();
        append_response_chunk(&mut body, b"45", 5).unwrap();
        assert!(append_response_chunk(&mut body, b"6", 5).is_err());
        assert_eq!(body, b"12345");
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

    #[test]
    fn signing_seed_rejects_truncated_and_oversized_files() {
        let dir = std::env::temp_dir().join(format!(
            "trust-cli-seed-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        keygen(&dir).unwrap();
        assert!(load_signing_key(&dir).is_ok());
        let seed = Zeroizing::new(fs::read(dir.join(PRIVATE_KEY_FILE)).unwrap());
        for length in [31, 33, 64] {
            let mut malformed = Zeroizing::new(seed.to_vec());
            malformed.resize(length, 0);
            fs::write(dir.join(PRIVATE_KEY_FILE), &*malformed).unwrap();
            assert!(load_signing_key(&dir).is_err());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_json_replaces_existing_artifact_atomically() {
        let dir = std::env::temp_dir().join(format!("trust-cli-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("artifact.json");
        write_json(&path, &serde_json::json!({"v": 1})).unwrap();
        write_json(&path, &serde_json::json!({"v": 2})).unwrap();

        let written: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(written["v"], 2);
        assert!(!dir.join("artifact.json.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
