use base64::Engine;
use confidential_inference_attestation::{
    canonical_json, certificate_spki_sha256_hex, sha256_digest, AliasConfidence, ArtifactDigest,
    ArtifactSignature, AttestationError, AttestationVerdict, BoundDataRequirement,
    ChannelBindingKind, CheckResult, ConfidentialityResult, CpuTeeKind, EvidenceHardware,
    FreshnessClass, ModelBindingRequirement, ProviderReference, ReferenceValuesEnvelope,
    ReferenceValuesPayload, ResponseIntegrityRequirement, ResponseIntegrityResult, RouteReference,
    TinfoilAttestationDoc, TinfoilAttestationFormat, TinfoilQuoteVerificationRequest,
    TinfoilQuoteVerifier, TrustTier, TrustedSigningKey, VerificationPolicy, VerifiedTinfoilQuote,
    TINFOIL_TDX_GUEST_V2_FORMAT,
};
use confidential_inference_openai::{ChatCompletionRequest, ChatMessage};
use confidential_inference_providers::{
    generate_tinfoil_live_reference_values, CacheabilityClass, EncryptionRequirement,
    ModelBindingSupport, ModelIdRewrite, ModelListingBehavior, OpenAiEndpoint, ProviderChatRequest,
    ProviderCompatibility, ProviderCompatibilityMatrix, ProviderCompatibilityMatrixEnvelope,
    ProviderRegistry, ProviderRegistryEnvelope, ProviderRequestConfidentiality, RegistryModel,
    RouteDefinition, RouteExecutionStatus, RouteLifecycle, SdkAppE2eeSecretKey, SourceSyncRun,
    StreamingSupport, TinfoilFixtureProvider, TinfoilHttpProvider, TinfoilLiveReferenceValuesInput,
    TokenParameterRewrite, VeniceFixtureProvider,
};
use confidential_inference_proxy::{ConfidentialInferenceProxy, ProxyConfig, ProxyHttpRequest};
use confidential_inference_sdk::{
    ActivePolicySnapshot, ActiveTrustArtifacts, ClientError, ConfidentialInference,
    ConfidentialInferenceMetricEvent, ConfidentialInferenceMetricsRecorder,
    ConfidentialInferenceVerificationCacheEvent, ConfidentialResponse,
    InMemoryConfidentialInferenceMetricsRecorder, JsonlAuditSink,
    JsonlConfidentialInferenceMetricsRecorder, JsonlVerdictStore, ModelRef,
};
use ed25519_compact::{KeyPair, Seed};
use flate2::{write::GzEncoder, Compression};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::ffi::{c_char, CStr};
use std::io::Write;
use std::ptr;
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

type DemoError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
struct TeeMetricsRecorder {
    memory: Arc<InMemoryConfidentialInferenceMetricsRecorder>,
    jsonl: Arc<JsonlConfidentialInferenceMetricsRecorder>,
}

impl ConfidentialInferenceMetricsRecorder for TeeMetricsRecorder {
    fn record(&self, event: &ConfidentialInferenceMetricEvent) {
        self.memory.record(event);
        self.jsonl.record(event);
    }
}

const LOCAL_TINFOIL_PROVIDER: &str = "local-tinfoil-live";
const LOCAL_TINFOIL_ROUTE_ID: &str = "local-tinfoil-live:llama-3.3-70b:llama-3.3-70b";
const LOCAL_TINFOIL_MODEL: &str = "llama-3.3-70b";
const LOCAL_TINFOIL_MEASUREMENT: &str = "sha256:local-live-tinfoil-tee-measurement";
const LOCAL_TINFOIL_WORKLOAD_IMAGE: &str = "sha256:local-live-tinfoil-workload-image";
const LOCAL_TINFOIL_WEIGHTS: &str = "sha256:local-live-tinfoil-weights";
const LOCAL_APP_E2EE_PROVIDER: &str = "local-sdk-app-e2ee";
const LOCAL_APP_E2EE_ROUTE_ID: &str = "local-sdk-app-e2ee:gpt-oss-120b:e2ee-gpt-oss-120b-p";
const LOCAL_APP_E2EE_MODEL: &str = "gpt-oss-120b";
const LOCAL_APP_E2EE_PROVIDER_MODEL: &str = "e2ee-gpt-oss-120b-p";
const LOCAL_APP_E2EE_MEASUREMENT: &str = "sha256:local-sdk-app-e2ee-tee-measurement";
const LOCAL_APP_E2EE_WORKLOAD_IMAGE: &str = concat!(
    "sha256:",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
);
const LOCAL_APP_E2EE_WORKLOAD_IMAGE_REFERENCE: &str = concat!(
    "local-sdk-app-e2ee/worker@sha256:",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
);
const LOCAL_APP_E2EE_WEIGHTS: &str = "sha256:local-sdk-app-e2ee-weights";
const LOCAL_APP_E2EE_PROMPT: &str = "verify the local SDK app-E2EE path";
const PHASE2_TINFOIL_PROMPT: &str = "verify the signed Tinfoil fixture path";
const PHASE2_VENICE_BLOCKED_PROMPT: &str = "this route is verification-only";
const LOCAL_ARTIFACT_SIGNER: &str = "confidential-inference-local-demo";
const LOCAL_ARTIFACT_KEY_ID: &str = "confidential-inference-local-demo-ed25519-2026";
const LOCAL_TINFOIL_QUOTE_BYTES: [u8; 48] = [42_u8; 48];
const LOCAL_TINFOIL_CERT_DER_BASE64: &str = concat!(
    "MIIDTTCCAjWgAwIBAgIUF0+ODWj0TBiZ451P+xEHiX4O2SUwDQYJKoZIhvcNAQELBQAw",
    "KDEmMCQGA1UEAwwdZW5jbGF2YS1sb2NhbC10aW5mb2lsLmludmFsaWQwHhcNMjYw",
    "NzA1MTY0NjU0WhcNMzYwNzAyMTY0NjU0WjAoMSYwJAYDVQQDDB1lbmNsYXZh",
    "LWxvY2FsLXRpbmZvaWwuaW52YWxpZDCCASIwDQYJKoZIhvcNAQEBBQADggEP",
    "ADCCAQoCggEBALY1+xYGvS1ORL0iyTP2QlYriI/EhyxMB2kzWUueYMI7w4UNoV",
    "TO3QwhXuZU8d/ziZabwvrB64OH8tV9fCtBqnPtJee7kEoAfmLjEyzEb7FPc3I",
    "QixuzTnRtrfqb3tbk9Enq09LpAuBkysNdSiMmT3UiJpU7G3Y4zZFjNQvYWr7go",
    "AwMvHzhXZRkAIxl7edr6dT9Sx8QZjMNb11Wv6ooTcKiC+v5c6Kgmat1gpEJ8v",
    "RaCYGHaAUyQ4b/k+TwrRPtGms4rCbYXMLE8S1haFVkGlJ0gKIu85Hh5wAuDrHC",
    "tRE+OI0yxbqEE+WPQd6/p+ArVqWya4D98YHE7/gLiObwcPMCAwEAAaNvMG0w",
    "HQYDVR0OBBYEFA1EBWbMUpCzcm8VFxhfa7odiCZUMB8GA1UdIwQYMBaAFA1E",
    "BWbMUpCzcm8VFxhfa7odiCZUMA8GA1UdEwEB/wQFMAMBAf8wGgYDVR0RBBMw",
    "EYIJbG9jYWxob3N0hwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQCNXb3vkwmR",
    "NnHubyUcZXD+l2Dqh0dGO/jSMStB88Tm4+SjsAGGMM9nhZHcVI7F/LZ4KwYA9",
    "xYTb9XHmUg8ZP/yszKr6QqCmErG9oN1LyhamjJLWMk8Q57L6PRF9/mQG7MKNK",
    "b1wsJ98EhaabQA88N43U6mU2vqWsuLZ7y7FsxbGUI57Qci+n2SmsX/GqupUUd",
    "mLGOIWHPI8ArjHzVUdZ8/JeW+rFv48oCPxPlyiLUkxNSuYwKkQ2to2cQlWrFv",
    "6WydJS7vPX6VKIu5rPnulEtSban2x2m1V0+/vHjJsxvXMEPrKGXx+Mxgb7xA",
    "Z9Qxj/btKwDPr8hVL6AYjnEm9I2A",
);
const ED25519_SIGNATURE_BYTE_LEN: usize = 64;
const LOCAL_TINFOIL_KEY_DER_BASE64: &str = concat!(
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2NfsWBr0tTkS9",
    "Iskz9kJWK4iPxIcsTAdpM1lLnmDCO8OFDaFUzt0MIV7mVPHf84mWm8L6weuDh/LV",
    "fXwrQapz7SXnu5BKAH5i4xMsxG+xT3NyEIsbs050ba36m97W5PRJ6tPS6QLgZMr",
    "DXUojJk91IiaVOxt2OM2RYzUL2Fq+4KAMDLx84V2UZACMZe3na+nU/UsfEGYzD",
    "W9dVr+qKE3Cogvr+XOioJmrdYKRCfL0WgmBh2gFMkOG/5Pk8K0T7RprOKwm2Fz",
    "CxPEtYWhVZBpSdICiLvOR4ecALg6xwrURPjiNMsW6hBPlj0Hev6fgK1alsmuA",
    "/fGBxO/4C4jm8HDzAgMBAAECggEACT5fQpZM0negvlGZ9ARGlnkTPN2t3vNeAf",
    "3AuBxMuDa3ndBRCaWMQ1lU7ongi57mFNIth8gbQCsiszUpNpzKJaMT+UKHRuHM",
    "+WFm6HWMspR0p3g5t0n6rVFKckNtR3dDOusxVM4wlFXG5KitE/4x8LxZgi3N",
    "9XVbQNbBo+Ncj50X6bgqeiDqW0txc7/P4Vw3cYp9uyZNGVvfIOzjV6Zd8wTH+",
    "KWJ8GUpjQxx7BE6MIdTkGwj7fNRWQnXY/R1kjVHiAtpV0IKbN9byrobnjRSWJ",
    "zTQm7Pq+YUdV1VnQdYWN7Yt9snTP89PPOvPJ2MrgsKejj+E2VsDG0SoE/AzEg",
    "ETQKBgQDyPt7C3ima02SFxMW9zNBz2BoU/9c3ugLQr7A0KfxENcorkKqhhYP0",
    "5l45QHMpmuHnQ9nViBaAvL9XFGqipA2J9zKQoBbU5nNeyoxpbAIiF4j+Ld5S",
    "bBEvsc9h14NL35IlWws06EdyuffXx1Ero3RYMH6gf37P+3AM4LmvFovQpwKB",
    "gQDAjnvLA1ImJLBABxLqNKJNoQ78WV9G35kFkIOFDjXY1w1vJwZcyiETQXHL",
    "7OcER/Ad2H1vAskBwrQLjQl9HkdezFZjQUPYhycxUWzWMq1u6XRqOhTLFUeYo",
    "6C6qKEeiADDPzPyOMmqOFUKJ0i93PDs7uAxJRmnqPRj/NU08ro61QKBgFp/O",
    "DLuUfagEEaU6xZrxFfynFPJ+/m6iMCzUY07Ph2xRpSd19C9kz1TLlIPDLa3Q",
    "LtnsqI908JGQOjkHK4jwVcQPRigZcclTGZWHrxneCiKSEhElHCQJJ9/uqyfm",
    "VIn9G32JCqgt8hZRwiaUm2OA7HKdBO7bYF/Oi3lahjJwHOzAoGBAJcaOIKi",
    "5IASIkzcQDeRfhu023GjIGUZaZc4RDzRXef/OgeTdCa0ZygZHxeLm+18Fi0V",
    "ibjnUp0TEP5Pera4YAFAEDprKLZtuI+2+dVMh1SV1kjVsyN6W2ioXqSbV3Q",
    "B/bc5jaXyci4lbnY9RZPYISeMfFmUZ4Ftz/n2mcinAQTRAoGBAIVs6j59tr",
    "qCVEKtTSpSKv182hIMgknTUaiyx0wODVJWzTE8eHJxSWkpGO6iQEALrodx/",
    "FCbanFofmIot+wvLfLqbMOW3XnISHGQdbbBGbN6WhmTGpi44eGmwhIMByIT",
    "jM0KeLi0TN4EGSarPlwybsSMpawHyhSXwM0yilS+Y70Y",
);

#[tokio::main]
async fn main() -> Result<(), DemoError> {
    run_ffi_status_demo()?;
    run_local_demo().await?;
    run_signed_artifact_fail_closed_demo().await?;
    run_proxy_demo().await?;
    run_phase2_fixtures().await?;
    run_local_sdk_app_e2ee_demo().await?;
    run_local_live_tinfoil_demo().await?;

    Ok(())
}

fn run_ffi_status_demo() -> Result<(), DemoError> {
    let mut status_json: *mut c_char = ptr::null_mut();
    let status_code =
        unsafe { confidential_inference_ffi::confidential_inference_status(&mut status_json) };
    if status_code != confidential_inference_ffi::CONFIDENTIAL_INFERENCE_FFI_OK {
        return Err(
            format!("confidential_inference_status failed with FFI status {status_code}").into(),
        );
    }
    let status_text = unsafe {
        let text = CStr::from_ptr(status_json).to_str()?.to_owned();
        confidential_inference_ffi::confidential_inference_string_free(status_json);
        text
    };
    let status: Value = serde_json::from_str(&status_text)?;

    for field in [
        "async_handle_abi_available",
        "callbacks_available",
        "stream_handle_abi_available",
        "blocking_helpers_available",
    ] {
        if status[field] != true {
            return Err(format!("FFI status field {field} was not true").into());
        }
    }
    if status["readiness_fd_available"].as_bool() != Some(cfg!(unix)) {
        return Err("FFI readiness_fd_available did not match platform support".into());
    }
    let reason = status["reason"]
        .as_str()
        .ok_or("FFI status reason was not a string")?;
    if !reason.contains("chat, responses, verify") || !reason.contains("stream handles") {
        return Err("FFI status reason did not describe core SDK surfaces".into());
    }

    println!(
        "ffi_status_async_handle_abi_available: {}",
        status["async_handle_abi_available"]
    );
    println!(
        "ffi_status_callbacks_available: {}",
        status["callbacks_available"]
    );
    println!(
        "ffi_status_readiness_fd_available: {}",
        status["readiness_fd_available"]
    );
    println!(
        "ffi_status_stream_handle_abi_available: {}",
        status["stream_handle_abi_available"]
    );
    println!(
        "ffi_status_blocking_helpers_available: {}",
        status["blocking_helpers_available"]
    );
    println!("ffi_status_reason_contains_core_surfaces: true");

    Ok(())
}

async fn run_signed_artifact_fail_closed_demo() -> Result<(), DemoError> {
    let mut tampered_registry = ProviderRegistryEnvelope::bundled_demo()?;
    tampered_registry.payload.version.push_str("-tampered");
    let registry_result = ConfidentialInference::builder()
        .registry(tampered_registry)
        .reference_values(ReferenceValuesEnvelope::bundled_demo()?)
        .with_demo_provider()
        .policy(VerificationPolicy::require_attested_e2ee())
        .build()
        .await;
    if registry_result.is_ok() {
        return Err("tampered signed registry unexpectedly built a client".into());
    }

    let mut tampered_reference_values = ReferenceValuesEnvelope::bundled_demo()?;
    tampered_reference_values
        .payload
        .version
        .push_str("-tampered");
    let reference_values_result = ConfidentialInference::builder()
        .registry(ProviderRegistryEnvelope::bundled_demo()?)
        .reference_values(tampered_reference_values)
        .with_demo_provider()
        .policy(VerificationPolicy::require_attested_e2ee())
        .build()
        .await;
    if reference_values_result.is_ok() {
        return Err("tampered signed reference values unexpectedly built a client".into());
    }

    let mut invalid_registry_metadata = ProviderRegistryEnvelope::bundled_demo()?;
    invalid_registry_metadata.payload.generated_at = "not-a-timestamp".into();
    invalid_registry_metadata.signature = sign_local_artifact(&invalid_registry_metadata.payload)?;
    let invalid_registry_metadata_result = ConfidentialInference::builder()
        .registry(invalid_registry_metadata)
        .trusted_artifact_signing_key(local_trusted_signing_key())
        .reference_values(ReferenceValuesEnvelope::bundled_demo()?)
        .with_demo_provider()
        .policy(VerificationPolicy::require_attested_e2ee())
        .build()
        .await;
    match invalid_registry_metadata_result {
        Err(ClientError::Attestation(AttestationError::InvalidRegistryUpdate(message)))
            if message.contains("generated_at") => {}
        Ok(_) => return Err("signed invalid registry metadata unexpectedly built a client".into()),
        Err(error) => {
            return Err(
                format!("signed invalid registry metadata failed unexpectedly: {error}").into(),
            );
        }
    }

    let mut invalid_reference_validity = ReferenceValuesEnvelope::bundled_demo()?;
    invalid_reference_validity.payload.valid_until_epoch_ms += 1;
    invalid_reference_validity.signature =
        sign_local_artifact(&invalid_reference_validity.payload)?;
    let invalid_reference_validity_result = ConfidentialInference::builder()
        .registry(ProviderRegistryEnvelope::bundled_demo()?)
        .reference_values(invalid_reference_validity)
        .trusted_artifact_signing_key(local_trusted_signing_key())
        .with_demo_provider()
        .policy(VerificationPolicy::require_attested_e2ee())
        .build()
        .await;
    match invalid_reference_validity_result {
        Err(ClientError::Attestation(AttestationError::InvalidReferenceValuesUpdate(message)))
            if message.contains("valid_until_epoch_ms") => {}
        Ok(_) => {
            return Err(
                "signed invalid reference-values validity unexpectedly built a client".into(),
            );
        }
        Err(error) => {
            return Err(format!(
                "signed invalid reference-values validity failed unexpectedly: {error}"
            )
            .into());
        }
    }

    println!();
    println!("tampered_registry_rejected: true");
    println!("tampered_reference_values_rejected: true");
    println!("signed_invalid_registry_metadata_rejected: true");
    println!("signed_invalid_reference_validity_rejected: true");

    Ok(())
}

async fn run_proxy_demo() -> Result<(), DemoError> {
    let verdict_path = proxy_verdict_path()?;
    let verdict_store = Arc::new(JsonlVerdictStore::create(&verdict_path)?);
    let client = ConfidentialInference::builder()
        .verdict_store(verdict_store)
        .with_demo_provider()
        .policy(VerificationPolicy::require_attested_e2ee())
        .build()
        .await?;
    let proxy = ConfidentialInferenceProxy::from_config(client, ProxyConfig::default())?;
    let prompt = "verify the proxy SDK path";
    let request = ChatCompletionRequest::new("gpt-oss-120b", vec![ChatMessage::user(prompt)]);

    let response = proxy
        .handle(ProxyHttpRequest::post_json(
            "/v1/chat/completions",
            serde_json::to_vec(&request)?,
        ))
        .await;
    if response.status != 200 {
        return Err(format!("proxy chat route failed with status {}", response.status).into());
    }
    let body: Value = serde_json::from_str(&response.body)?;
    if body.get("verdict").is_some() {
        return Err("proxy embedded verdict data in the OpenAI response body".into());
    }
    let verdict_json = response
        .verdict_json
        .as_deref()
        .ok_or("proxy chat response did not include a verdict sidecar")?;
    let proxy_sidecar_prompt_redacted = !verdict_json.contains(prompt);
    if !proxy_sidecar_prompt_redacted {
        return Err("proxy verdict sidecar leaked prompt plaintext".into());
    }
    let verdict: AttestationVerdict = serde_json::from_str(verdict_json)?;
    require_verified_check(&verdict, "model_binding")?;
    require_verdict_summary(
        &verdict,
        true,
        ConfidentialityResult::EncryptedBound,
        true,
        ConfidentialityResult::EncryptedBound,
        ResponseIntegrityResult::ChannelBound,
    )?;
    if verdict.route_execution_status != "executable_fixture" || !verdict.chat_executable {
        return Err(format!(
            "proxy verdict reported unexpected route capability: status={}, chat_executable={}",
            verdict.route_execution_status, verdict.chat_executable
        )
        .into());
    }

    let models = proxy.handle(ProxyHttpRequest::get("/v1/models")).await;
    if models.status != 200 {
        return Err(format!(
            "proxy model discovery route failed with status {}",
            models.status
        )
        .into());
    }
    if models.verdict_json.is_some() {
        return Err("proxy model discovery route unexpectedly included a verdict sidecar".into());
    }
    let models_body: Value = serde_json::from_str(&models.body)?;
    if models_body.get("object").and_then(Value::as_str) != Some("list") {
        return Err("proxy model discovery route did not return an OpenAI model list".into());
    }
    let model_list = models_body
        .get("data")
        .and_then(Value::as_array)
        .ok_or("proxy model discovery route did not return a data array")?;
    let has_demo_model = model_list.iter().any(|model| {
        model.get("id").and_then(Value::as_str) == Some("gpt-oss-120b")
            && model.get("object").and_then(Value::as_str) == Some("model")
    });
    if !has_demo_model {
        return Err("proxy model discovery route did not expose the executable demo model".into());
    }

    let confidentiality = proxy
        .handle(ProxyHttpRequest::get("/v1/confidentiality"))
        .await;
    if confidentiality.status != 200 {
        return Err(format!(
            "proxy confidentiality route failed with status {}",
            confidentiality.status
        )
        .into());
    }
    let confidential_models: Value = serde_json::from_str(&confidentiality.body)?;
    if confidential_models[0]["routes"][0]["known_unsupported_modes"][0] != "streaming" {
        return Err("proxy confidentiality route did not expose unsupported modes".into());
    }
    if confidential_models[0]["routes"][0]["route_id"].as_str() != Some(&verdict.route_id) {
        return Err("proxy confidentiality route did not match the proxy verdict route".into());
    }
    if confidential_models[0]["routes"][0]["chat_executable"].as_bool() != Some(true) {
        return Err("proxy confidentiality route was not chat executable".into());
    }

    let attestation = proxy
        .handle(ProxyHttpRequest::get("/v1/attestation/demo/gpt-oss-120b"))
        .await;
    if attestation.status != 200 {
        return Err(format!(
            "proxy attestation route failed with status {}",
            attestation.status
        )
        .into());
    }
    let attestation_verdict: AttestationVerdict = serde_json::from_str(&attestation.body)?;
    require_verified_check(&attestation_verdict, "model_binding")?;
    require_verdict_summary(
        &attestation_verdict,
        true,
        ConfidentialityResult::EncryptedBound,
        true,
        ConfidentialityResult::EncryptedBound,
        ResponseIntegrityResult::ChannelBound,
    )?;
    if attestation_verdict.route_id != verdict.route_id
        || attestation_verdict.policy_digest != verdict.policy_digest
        || attestation_verdict.provider_registry_digest != verdict.provider_registry_digest
        || attestation_verdict.reference_values_digest != verdict.reference_values_digest
    {
        return Err("proxy attestation verdict did not match the proxy chat verdict".into());
    }
    let proxy_response_text = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .ok_or("proxy chat body did not expose response content")?;
    let verdict_jsonl = read_jsonl_records(&verdict_path)?;
    let persisted_verdicts = verdict_jsonl.len();
    if persisted_verdicts < 2 {
        return Err(format!(
            "proxy verdict store expected at least two records, got {persisted_verdicts}"
        )
        .into());
    }
    validate_proxy_verdict_records(&verdict_jsonl, &[prompt, proxy_response_text])?;

    println!();
    println!("proxy_chat_status: {}", response.status);
    println!("proxy_chat_body_model: {}", body["model"]);
    println!(
        "proxy_body_without_verdict: {}",
        body.get("verdict").is_none()
    );
    println!("proxy_sidecar_prompt_redacted: {proxy_sidecar_prompt_redacted}");
    println!("proxy_verdict_status: {:?}", verdict.status);
    println!("proxy_verdict_provider: {}", verdict.provider);
    println!("proxy_verdict_route_id: {}", verdict.route_id);
    println!("proxy_verdict_requested_model: {}", verdict.requested_model);
    println!("proxy_verdict_provider_model: {}", verdict.provider_model);
    println!("proxy_verdict_canonical_model: {}", verdict.canonical_model);
    println!("proxy_verdict_policy_digest: {}", verdict.policy_digest);
    println!(
        "proxy_verdict_provider_registry_digest: {}",
        verdict.provider_registry_digest
    );
    println!(
        "proxy_verdict_reference_values_digest: {}",
        verdict.reference_values_digest
    );
    println!(
        "proxy_verdict_request_confidentiality_result: {}",
        serialized_string_label(
            &verdict.request_confidentiality_result,
            "proxy request result"
        )?
    );
    println!(
        "proxy_verdict_response_confidentiality_result: {}",
        serialized_string_label(
            &verdict.response_confidentiality_result,
            "proxy response result"
        )?
    );
    println!(
        "proxy_verdict_response_integrity_result: {}",
        serialized_string_label(&verdict.response_integrity_result, "proxy integrity result")?
    );
    println!(
        "proxy_route_execution_status: {}",
        verdict.route_execution_status
    );
    println!("proxy_chat_executable: {}", verdict.chat_executable);
    println!("proxy_models_count: {}", model_list.len());
    println!("proxy_models_contains_demo_model: {has_demo_model}");
    println!(
        "proxy_confidentiality_route_id: {}",
        confidential_models[0]["routes"][0]["route_id"]
            .as_str()
            .unwrap_or("")
    );
    println!(
        "proxy_confidentiality_chat_executable: {}",
        confidential_models[0]["routes"][0]["chat_executable"]
            .as_bool()
            .unwrap_or(false)
    );
    println!(
        "proxy_confidentiality_unsupported_modes: {}",
        confidential_models[0]["routes"][0]["known_unsupported_modes"]
    );
    println!("proxy_attestation_status: {:?}", attestation_verdict.status);
    println!(
        "proxy_attestation_route_id: {}",
        attestation_verdict.route_id
    );
    println!(
        "proxy_attestation_policy_digest: {}",
        attestation_verdict.policy_digest
    );
    println!(
        "proxy_attestation_provider_registry_digest: {}",
        attestation_verdict.provider_registry_digest
    );
    println!(
        "proxy_attestation_reference_values_digest: {}",
        attestation_verdict.reference_values_digest
    );
    println!(
        "proxy_attestation_request_confidentiality_result: {}",
        serialized_string_label(
            &attestation_verdict.request_confidentiality_result,
            "proxy attestation request result",
        )?
    );
    println!(
        "proxy_attestation_response_confidentiality_result: {}",
        serialized_string_label(
            &attestation_verdict.response_confidentiality_result,
            "proxy attestation response result",
        )?
    );
    println!(
        "proxy_attestation_response_integrity_result: {}",
        serialized_string_label(
            &attestation_verdict.response_integrity_result,
            "proxy attestation integrity result",
        )?
    );
    println!("proxy_persisted_verdicts: {persisted_verdicts}");
    println!("proxy_verdict_store: {}", verdict_path.display());

    Ok(())
}

fn serialized_string_label<T: Serialize>(value: &T, subject: &str) -> Result<String, DemoError> {
    match serde_json::to_value(value)? {
        Value::String(value) => Ok(value),
        other => Err(format!("{subject} did not serialize as a string label: {other}").into()),
    }
}

fn print_route_verdict_summary(
    prefix: &str,
    verdict: &AttestationVerdict,
) -> Result<(), DemoError> {
    println!("{prefix}_route_id: {}", verdict.route_id);
    println!("{prefix}_requested_model: {}", verdict.requested_model);
    println!("{prefix}_provider_model: {}", verdict.provider_model);
    println!("{prefix}_canonical_model: {}", verdict.canonical_model);
    println!(
        "{prefix}_trust_tier: {}",
        serialized_string_label(&verdict.trust_tier, "local route trust tier")?
    );
    println!("{prefix}_evidence_family: {}", verdict.evidence_family);
    println!(
        "{prefix}_channel_binding_kind: {}",
        serialized_string_label(
            &verdict.channel_binding_kind,
            "local route channel binding kind",
        )?
    );
    println!(
        "{prefix}_request_confidentiality_result: {}",
        serialized_string_label(
            &verdict.request_confidentiality_result,
            "local route request confidentiality result",
        )?
    );
    println!(
        "{prefix}_response_confidentiality_result: {}",
        serialized_string_label(
            &verdict.response_confidentiality_result,
            "local route response confidentiality result",
        )?
    );
    println!(
        "{prefix}_response_integrity_result: {}",
        serialized_string_label(
            &verdict.response_integrity_result,
            "local route response integrity result",
        )?
    );
    println!(
        "{prefix}_route_execution_status: {}",
        verdict.route_execution_status
    );
    println!("{prefix}_chat_executable: {}", verdict.chat_executable);
    println!("{prefix}_policy_digest: {}", verdict.policy_digest);
    println!(
        "{prefix}_provider_registry_digest: {}",
        verdict.provider_registry_digest
    );
    println!(
        "{prefix}_reference_values_digest: {}",
        verdict.reference_values_digest
    );
    println!("{prefix}_registry_source: {}", verdict.registry_source);
    println!(
        "{prefix}_reference_values_source: {}",
        verdict.reference_values_source
    );
    println!(
        "{prefix}_registry_signature_signer: {}",
        verdict.registry_signature.signer
    );
    println!(
        "{prefix}_reference_values_signature_signer: {}",
        verdict.reference_values_signature.signer
    );
    Ok(())
}

async fn run_local_demo() -> Result<(), DemoError> {
    let metrics = Arc::new(InMemoryConfidentialInferenceMetricsRecorder::default());
    let metrics_path = local_demo_metrics_path()?;
    let metrics_jsonl = Arc::new(JsonlConfidentialInferenceMetricsRecorder::create(
        &metrics_path,
    )?);
    let metrics_recorder = Arc::new(TeeMetricsRecorder {
        memory: metrics.clone(),
        jsonl: metrics_jsonl,
    });
    let audit_path = local_demo_audit_path()?;
    let audit_sink = Arc::new(JsonlAuditSink::create(&audit_path)?);
    let verdict_path = local_demo_verdict_path()?;
    let verdict_store = Arc::new(JsonlVerdictStore::create(&verdict_path)?);
    let prompt = "verify the confidential inference SDK path";
    let client = ConfidentialInference::builder()
        .with_demo_provider()
        .audit_sink(audit_sink)
        .verdict_store(verdict_store)
        .metrics_recorder(metrics_recorder)
        .policy(VerificationPolicy::require_attested_e2ee())
        .api_key("demo", "demo-api-key-not-used")
        .build()
        .await?;

    let response = client
        .chat_completions()
        .model("gpt-oss-120b")
        .message(ChatMessage::user(prompt))
        .send()
        .await?;
    require_response_summary(
        &response,
        true,
        ConfidentialityResult::EncryptedBound,
        true,
        ConfidentialityResult::EncryptedBound,
        ResponseIntegrityResult::ChannelBound,
    )?;
    require_active_metadata_matches_verdict(&client, &response.verdict)?;
    let streaming_prompt = "streaming must fail closed in confidential demo";
    let streaming_error = client
        .chat_completions()
        .model("gpt-oss-120b")
        .message(ChatMessage::user(streaming_prompt))
        .stream(true)
        .send()
        .await
        .err()
        .ok_or("streaming encrypted demo request unexpectedly succeeded")?;
    if !matches!(streaming_error, ClientError::StreamingNotSupported { .. }) {
        return Err(format!(
            "streaming encrypted demo request failed with unexpected error: {streaming_error}"
        )
        .into());
    }
    require_verified_route_model_mismatch_fails(&client).await?;

    println!("provider: {}", response.provider);
    println!("provider_model: {}", response.provider_model);
    println!("response: {}", response.response.choices[0].message.content);
    println!("verdict:");
    println!("{}", serde_json::to_string_pretty(&response.verdict)?);
    print_active_metadata_summary(&client, &response.verdict)?;
    persist_active_snapshot_artifacts(&client, &response.verdict)?;
    let cached_verify_durations = measure_cached_verify_route_latency(&client).await?;
    let cached_verify_p95_ms = p95_millis(&cached_verify_durations);
    if cached_verify_p95_ms > 100 {
        return Err(format!(
            "cached local route verification p95 exceeded 100 ms: {cached_verify_p95_ms} ms"
        )
        .into());
    }
    let metric_events = metrics.events();
    let cache_hits = metric_events
        .iter()
        .filter(|event| {
            matches!(
                event,
                ConfidentialInferenceMetricEvent::VerificationCache(metric)
                    if metric.event == ConfidentialInferenceVerificationCacheEvent::Hit
            )
        })
        .count();
    let verdict_metrics = metric_events
        .iter()
        .filter(|event| matches!(event, ConfidentialInferenceMetricEvent::Verdict(_)))
        .count();
    let streaming_fail_closed = metric_events
        .iter()
        .filter(|event| {
            matches!(
                event,
                ConfidentialInferenceMetricEvent::StreamingFailClosed(_)
            )
        })
        .count();
    if streaming_fail_closed == 0 {
        return Err("local demo metrics did not record streaming fail-closed event".into());
    }
    let audit_jsonl = read_jsonl_records(&audit_path)?;
    let audit_records = audit_jsonl.len();
    if audit_records < 2 {
        return Err(format!(
            "expected at least two local demo audit records, found {audit_records}"
        )
        .into());
    }
    let forbidden_plaintext = [
        prompt,
        streaming_prompt,
        response.response.choices[0].message.content.as_str(),
        "demo-api-key-not-used",
    ];
    validate_demo_audit_records(&audit_jsonl, &forbidden_plaintext)?;
    let verdict_jsonl = read_jsonl_records(&verdict_path)?;
    let persisted_verdicts = verdict_jsonl.len();
    if persisted_verdicts < 2 {
        return Err(format!(
            "expected at least two local demo verdict records, found {persisted_verdicts}"
        )
        .into());
    }
    validate_demo_verdict_records(&verdict_jsonl, &forbidden_plaintext)?;
    let metrics_jsonl = read_jsonl_records(&metrics_path)?;
    validate_demo_metrics_records(&metrics_jsonl, &forbidden_plaintext)?;
    let otlp_json = metrics.otlp_json()?;
    let metrics_otlp: Value = serde_json::from_str(&otlp_json)?;
    let (otlp_resource_metrics, otlp_scope_metrics, otlp_metrics, otlp_data_points) =
        validate_demo_otlp_metrics_payload(&metrics_otlp, &forbidden_plaintext)?;
    let (otlp_endpoint, otlp_server) = spawn_demo_otlp_metrics_collector().await?;
    metrics
        .export_otlp_http_with_timeout(&otlp_endpoint, Duration::from_secs(5))
        .await?;
    let otlp_request = otlp_server.await??;
    validate_demo_otlp_http_request(&otlp_request, &forbidden_plaintext)?;
    println!("metrics_events: {}", metric_events.len());
    println!("metrics_cache_hits: {cache_hits}");
    println!("metrics_verdicts: {verdict_metrics}");
    println!("metrics_streaming_fail_closed: {streaming_fail_closed}");
    println!("verified_route_model_mismatch_rejected: true");
    println!("metrics_jsonl_records: {}", metrics_jsonl.len());
    println!("cached_verify_samples: {}", cached_verify_durations.len());
    println!("cached_verify_p95_ms: {cached_verify_p95_ms}");
    println!(
        "metrics_prometheus_lines: {}",
        metrics.prometheus_text().lines().count()
    );
    println!("metrics_otlp_resource_metrics: {otlp_resource_metrics}");
    println!("metrics_otlp_scope_metrics: {otlp_scope_metrics}");
    println!("metrics_otlp_metrics: {otlp_metrics}");
    println!("metrics_otlp_data_points: {otlp_data_points}");
    println!("metrics_otlp_http_posted: true");
    println!("metrics_log: {}", metrics_path.display());
    println!("audit_records: {audit_records}");
    println!("audit_log: {}", audit_path.display());
    println!("primary_persisted_verdicts: {persisted_verdicts}");
    println!("primary_verdict_store: {}", verdict_path.display());

    Ok(())
}

fn print_active_metadata_summary(
    client: &ConfidentialInference,
    verdict: &AttestationVerdict,
) -> Result<(), DemoError> {
    let active_policy = client.active_policy()?;
    let active_artifacts = client.active_trust_artifacts();
    println!("active_policy_schema: {}", active_policy.schema);
    println!("active_policy_digest: {}", active_policy.policy_digest);
    println!(
        "active_policy_registry_digest: {}",
        active_policy.policy.provider_registry_digest
    );
    println!(
        "active_policy_reference_values_digest: {}",
        active_policy.policy.reference_values_digest
    );
    println!(
        "active_registry_schema: {}",
        active_artifacts.registry.schema
    );
    println!(
        "active_reference_values_schema: {}",
        active_artifacts.reference_values.schema
    );
    println!(
        "active_registry_digest: {}",
        active_artifacts.registry_digest
    );
    println!(
        "active_reference_values_digest: {}",
        active_artifacts.reference_values_digest
    );
    println!(
        "active_registry_source: {}",
        active_artifacts.registry_source
    );
    println!(
        "active_reference_values_source: {}",
        active_artifacts.reference_values_source
    );
    println!(
        "active_registry_signature_signer: {}",
        active_artifacts.registry_signature.signer
    );
    println!(
        "active_registry_signature_key_id: {}",
        active_artifacts.registry_signature.key_id
    );
    println!(
        "active_registry_signature_alg: {}",
        active_artifacts.registry_signature.alg
    );
    println!(
        "active_reference_values_signature_signer: {}",
        active_artifacts.reference_values_signature.signer
    );
    println!(
        "active_reference_values_signature_key_id: {}",
        active_artifacts.reference_values_signature.key_id
    );
    println!(
        "active_reference_values_signature_alg: {}",
        active_artifacts.reference_values_signature.alg
    );
    println!(
        "active_registry_signature_value_base64url: {}",
        active_artifacts
            .registry_signature
            .value
            .starts_with("base64url:")
    );
    println!(
        "active_reference_values_signature_value_base64url: {}",
        active_artifacts
            .reference_values_signature
            .value
            .starts_with("base64url:")
    );
    if active_policy.policy_digest != verdict.policy_digest
        || active_artifacts.registry_digest != verdict.provider_registry_digest
        || active_artifacts.reference_values_digest != verdict.reference_values_digest
    {
        return Err("active metadata summary did not match verdict digest fields".into());
    }
    Ok(())
}

async fn require_verified_route_model_mismatch_fails(
    client: &ConfidentialInference,
) -> Result<(), DemoError> {
    let verified = client
        .verify_route("demo", ModelRef::canonical("gpt-oss-120b"))
        .await?;
    let error = verified
        .chat(ChatCompletionRequest::new(
            "llama-3.3-70b",
            vec![ChatMessage::user("this model was not verified")],
        ))
        .await
        .err()
        .ok_or("verified route unexpectedly executed a request for a different model")?;

    match error {
        ClientError::VerifiedRouteModelMismatch {
            verified_model,
            request_model,
            ..
        } if verified_model == "gpt-oss-120b" && request_model == "llama-3.3-70b" => Ok(()),
        other => Err(format!("verified route model mismatch failed unexpectedly: {other}").into()),
    }
}

async fn measure_cached_verify_route_latency(
    client: &ConfidentialInference,
) -> Result<Vec<u128>, DemoError> {
    let mut durations = Vec::new();
    for _ in 0..32 {
        let started = Instant::now();
        let route = client
            .verify_route("demo", ModelRef::canonical("gpt-oss-120b"))
            .await?;
        require_verified_check(route.verdict(), "model_binding")?;
        durations.push(started.elapsed().as_millis());
    }
    Ok(durations)
}

fn p95_millis(samples: &[u128]) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = (sorted.len() * 95).div_ceil(100).saturating_sub(1);
    sorted[index]
}

async fn run_phase2_fixtures() -> Result<(), DemoError> {
    let registry = ProviderRegistryEnvelope::phase2_fixtures()?;
    let reference_values = ReferenceValuesEnvelope::phase2_fixtures()?;
    let verdict_path = phase2_fixture_verdict_path()?;
    let verdict_store = Arc::new(JsonlVerdictStore::create(&verdict_path)?);

    let tinfoil = ConfidentialInference::builder()
        .registry(registry.clone())
        .reference_values(reference_values.clone())
        .verdict_store(verdict_store.clone())
        .with_provider(TinfoilFixtureProvider::valid())
        .policy(VerificationPolicy::require_hw_verified_tls())
        .build()
        .await?;

    let tinfoil_response = tinfoil
        .chat_completions()
        .model("llama-3.3-70b")
        .message(ChatMessage::user(PHASE2_TINFOIL_PROMPT))
        .send()
        .await?;
    require_verified_check(&tinfoil_response.verdict, "tls_binding")?;
    require_response_summary(
        &tinfoil_response,
        true,
        ConfidentialityResult::ChannelBound,
        true,
        ConfidentialityResult::ChannelBound,
        ResponseIntegrityResult::ChannelBound,
    )?;

    println!();
    println!("phase2_tinfoil_provider: {}", tinfoil_response.provider);
    print_route_verdict_summary("phase2_tinfoil", &tinfoil_response.verdict)?;
    println!(
        "phase2_tinfoil_tls_binding: {:?}",
        tinfoil_response.verdict.check("tls_binding")
    );
    println!(
        "phase2_tinfoil_response: {}",
        tinfoil_response.response.choices[0].message.content
    );

    let mut venice_policy = VerificationPolicy::require_hardware();
    venice_policy.model_binding_requirement = ModelBindingRequirement::Required;
    let venice = ConfidentialInference::builder()
        .registry(registry)
        .reference_values(reference_values)
        .verdict_store(verdict_store)
        .with_provider(VeniceFixtureProvider::valid())
        .policy(venice_policy)
        .build()
        .await?;

    let venice_route = venice
        .verify_route("venice-fixture", ModelRef::canonical("gpt-oss-120b"))
        .await?;
    require_verified_check(venice_route.verdict(), "tcb_compose_hash")?;
    require_verified_check(venice_route.verdict(), "model_binding")?;
    if venice_route.verdict().check("e2ee_key_binding") != Some(&CheckResult::NotApplicable) {
        return Err("Venice hardware-only verdict must not claim an app-E2EE key binding".into());
    }
    require_verdict_summary(
        venice_route.verdict(),
        false,
        ConfidentialityResult::Unknown,
        false,
        ConfidentialityResult::Unknown,
        ResponseIntegrityResult::Unknown,
    )?;
    if venice_route.verdict().route_execution_status != "verification_only"
        || venice_route.verdict().chat_executable
    {
        return Err(format!(
            "Venice fixture must remain verification-only, got status={}, chat_executable={}",
            venice_route.verdict().route_execution_status,
            venice_route.verdict().chat_executable
        )
        .into());
    }
    println!();
    println!("phase2_venice_provider: {}", venice_route.route().provider);
    print_route_verdict_summary("phase2_venice", venice_route.verdict())?;
    println!(
        "phase2_venice_tcb_binding: {:?}",
        venice_route.verdict().check("tcb_compose_hash")
    );
    println!(
        "phase2_venice_e2ee_binding: {:?}",
        venice_route.verdict().check("e2ee_key_binding")
    );
    println!(
        "phase2_venice_model_binding: {:?}",
        venice_route.verdict().check("model_binding")
    );

    let blocked = venice_route
        .chat(ChatCompletionRequest::new(
            "gpt-oss-120b",
            vec![ChatMessage::user(PHASE2_VENICE_BLOCKED_PROMPT)],
        ))
        .await;
    if blocked.is_ok() {
        return Err("Venice verification-only fixture unexpectedly executed chat".into());
    }
    println!("phase2_venice_chat_blocked: {}", blocked.is_err());
    let verdict_jsonl = read_jsonl_records(&verdict_path)?;
    let persisted_verdicts = verdict_jsonl.len();
    if persisted_verdicts < 3 {
        return Err(format!(
            "phase2 fixture verdict store expected at least three records, got {persisted_verdicts}"
        )
        .into());
    }
    validate_phase2_fixture_verdict_records(
        &verdict_jsonl,
        &[
            PHASE2_TINFOIL_PROMPT,
            tinfoil_response.response.choices[0]
                .message
                .content
                .as_str(),
            PHASE2_VENICE_BLOCKED_PROMPT,
        ],
    )?;
    println!("phase2_fixture_persisted_verdicts: {persisted_verdicts}");
    println!("phase2_fixture_verdict_store: {}", verdict_path.display());

    Ok(())
}

async fn run_local_sdk_app_e2ee_demo() -> Result<(), DemoError> {
    let secret_key =
        SdkAppE2eeSecretKey::from_private_key_bytes("local-sdk-app-e2ee-key", [17_u8; 32]);
    let public_config = secret_key.public_config()?;
    let server = LocalSdkAppE2eeServer::spawn(secret_key.clone()).await?;
    let route = server.route.clone();
    let registry = signed_local_app_e2ee_registry(route.clone())?;
    let registry_path = local_app_e2ee_registry_path()?;
    let registry_digest = registry.payload.digest()?;
    write_json_artifact(&registry_path, &registry)?;
    validate_local_registry_artifact(
        &registry_path,
        &registry_digest,
        LOCAL_APP_E2EE_MODEL,
        &route,
        "local SDK app-E2EE registry artifact",
    )?;
    let public_key_digest = public_config.public_key_digest()?;
    let reference_values = signed_local_app_e2ee_reference_values(&route, &public_key_digest)?;
    let reference_values_path = local_app_e2ee_reference_values_path()?;
    let reference_values_digest = reference_values.payload.digest()?;
    write_json_artifact(&reference_values_path, &reference_values)?;
    validate_local_app_e2ee_reference_values_artifact(
        &reference_values_path,
        &reference_values_digest,
        &route,
        &public_key_digest,
    )?;
    let compatibility_matrix = local_app_e2ee_compatibility_matrix(&route, public_config);
    let compatibility_matrix_path = local_app_e2ee_compatibility_matrix_path()?;
    let compatibility_matrix_digest = compatibility_matrix.digest()?;
    let compatibility_matrix_artifact =
        signed_local_compatibility_matrix(compatibility_matrix.clone())?;
    write_json_artifact(&compatibility_matrix_path, &compatibility_matrix_artifact)?;
    validate_local_compatibility_matrix_artifact(
        &compatibility_matrix_path,
        &compatibility_matrix_digest,
        &compatibility_matrix,
        LOCAL_APP_E2EE_PROVIDER,
        &route,
        "local SDK app-E2EE compatibility matrix artifact",
    )?;
    let verdict_path = local_app_e2ee_verdict_path()?;
    let verdict_store = Arc::new(JsonlVerdictStore::create(&verdict_path)?);

    let client = ConfidentialInference::builder()
        .registry(registry)
        .reference_values(reference_values)
        .compatibility_matrix(compatibility_matrix)
        .verdict_store(verdict_store)
        .trusted_artifact_signing_key(local_trusted_signing_key())
        .api_key(LOCAL_APP_E2EE_PROVIDER, "local-sdk-app-e2ee-demo-key")
        .policy(local_app_e2ee_policy())
        .build()
        .await?;

    let response = client
        .chat_completions()
        .model(LOCAL_APP_E2EE_MODEL)
        .message(ChatMessage::user(LOCAL_APP_E2EE_PROMPT))
        .send()
        .await?;

    for check in [
        "tcb_compose_hash",
        "e2ee_key_reference_match",
        "model_binding",
        "workload_manifest_binding",
        "image_provenance",
        "model_artifact_provenance",
    ] {
        require_verified_check(&response.verdict, check)?;
    }
    for check in [
        "e2ee_key_binding",
        "request_encryption",
        "response_encryption",
    ] {
        if response.verdict.check(check) != Some(&CheckResult::NotApplicable) {
            return Err(format!(
                "local SDK app-E2EE transport-only check {check} must be not_applicable in the attestation verdict"
            )
            .into());
        }
    }
    require_response_summary(
        &response,
        false,
        ConfidentialityResult::Unknown,
        false,
        ConfidentialityResult::Unknown,
        ResponseIntegrityResult::Unknown,
    )?;
    let verdict_jsonl = read_jsonl_records(&verdict_path)?;
    let persisted_verdicts = verdict_jsonl.len();
    if persisted_verdicts < 2 {
        return Err(format!(
            "expected at least two persisted local SDK app-E2EE verdict records, found {persisted_verdicts}"
        )
        .into());
    }
    validate_local_app_e2ee_verdict_records(
        &verdict_jsonl,
        &[
            LOCAL_APP_E2EE_PROMPT,
            response.response.choices[0].message.content.as_str(),
        ],
    )?;

    println!();
    println!("local_sdk_app_e2ee_provider: {}", response.provider);
    print_route_verdict_summary("local_sdk_app_e2ee", &response.verdict)?;
    println!(
        "local_sdk_app_e2ee_request_encryption: {:?}",
        response.verdict.check("request_encryption")
    );
    println!(
        "local_sdk_app_e2ee_response_encryption: {:?}",
        response.verdict.check("response_encryption")
    );
    println!(
        "local_sdk_app_e2ee_model_binding: {:?}",
        response.verdict.check("model_binding")
    );
    println!(
        "local_sdk_app_e2ee_e2ee_key_binding: {:?}",
        response.verdict.check("e2ee_key_binding")
    );
    println!(
        "local_sdk_app_e2ee_image_provenance: {:?}",
        response.verdict.check("image_provenance")
    );
    println!(
        "local_sdk_app_e2ee_model_artifact_provenance: {:?}",
        response.verdict.check("model_artifact_provenance")
    );
    println!(
        "local_sdk_app_e2ee_response: {}",
        response.response.choices[0].message.content
    );
    println!("local_sdk_app_e2ee_persisted_verdicts: {persisted_verdicts}");
    println!(
        "local_sdk_app_e2ee_verdict_store: {}",
        verdict_path.display()
    );
    println!(
        "local_sdk_app_e2ee_registry_artifact: {}",
        registry_path.display()
    );
    println!("local_sdk_app_e2ee_registry_artifact_digest: {registry_digest}");
    println!(
        "local_sdk_app_e2ee_compatibility_matrix_artifact: {}",
        compatibility_matrix_path.display()
    );
    println!(
        "local_sdk_app_e2ee_compatibility_matrix_artifact_digest: {compatibility_matrix_digest}"
    );
    println!(
        "local_sdk_app_e2ee_reference_values_artifact: {}",
        reference_values_path.display()
    );
    println!("local_sdk_app_e2ee_reference_values_artifact_digest: {reference_values_digest}");

    server.await_shutdown().await?;
    Ok(())
}

async fn run_local_live_tinfoil_demo() -> Result<(), DemoError> {
    let server = LocalTinfoilServer::spawn().await?;
    let route = local_tinfoil_route(&server.base_url);
    let registry = signed_local_registry(route.clone())?;
    let registry_path = local_live_registry_path()?;
    let registry_digest = registry.payload.digest()?;
    write_json_artifact(&registry_path, &registry)?;
    validate_local_registry_artifact(
        &registry_path,
        &registry_digest,
        LOCAL_TINFOIL_MODEL,
        &route,
        "local live Tinfoil registry artifact",
    )?;
    let reference_values = signed_local_reference_values(&route, &server.spki_sha256)?;
    let reference_values_path = local_live_reference_values_path()?;
    let reference_values_digest = reference_values.payload.digest()?;
    write_json_artifact(&reference_values_path, &reference_values)?;
    validate_local_live_reference_values_artifact(
        &reference_values_path,
        &reference_values_digest,
        &route,
        &server.spki_sha256,
    )?;
    let compatibility_matrix = local_compatibility_matrix(&route);
    let compatibility_matrix_path = local_live_compatibility_matrix_path()?;
    let compatibility_matrix_digest = compatibility_matrix.digest()?;
    let compatibility_matrix_artifact =
        signed_local_compatibility_matrix(compatibility_matrix.clone())?;
    write_json_artifact(&compatibility_matrix_path, &compatibility_matrix_artifact)?;
    validate_local_compatibility_matrix_artifact(
        &compatibility_matrix_path,
        &compatibility_matrix_digest,
        &compatibility_matrix,
        LOCAL_TINFOIL_PROVIDER,
        &route,
        "local live Tinfoil compatibility matrix artifact",
    )?;
    let trusted_key = local_trusted_signing_key();
    let verdict_path = local_live_verdict_path()?;
    let verdict_store = Arc::new(JsonlVerdictStore::create(&verdict_path)?);
    let prompt = "verify the local live TLS path";

    let client = ConfidentialInference::builder()
        .registry(registry)
        .reference_values(reference_values)
        .compatibility_matrix(compatibility_matrix)
        .verdict_store(verdict_store)
        .trusted_artifact_signing_key(trusted_key)
        .with_provider(TinfoilHttpProvider::with_provider_id(
            LOCAL_TINFOIL_PROVIDER,
            vec![route],
            None::<String>,
        )?)
        .tinfoil_quote_verifier(LocalTinfoilQuoteVerifier {
            spki_sha256: server.spki_sha256.clone(),
        })
        .policy(local_live_tinfoil_policy())
        .build()
        .await?;

    let response = client
        .chat_completions()
        .model(LOCAL_TINFOIL_MODEL)
        .message(ChatMessage::user(prompt))
        .send()
        .await?;

    for check in [
        "tls_binding",
        "model_binding",
        "image_provenance",
        "model_artifact_provenance",
    ] {
        require_verified_check(&response.verdict, check)?;
    }
    require_response_summary(
        &response,
        true,
        ConfidentialityResult::ChannelBound,
        true,
        ConfidentialityResult::ChannelBound,
        ResponseIntegrityResult::ChannelBound,
    )?;
    let verdict_jsonl = read_jsonl_records(&verdict_path)?;
    let persisted_verdicts = verdict_jsonl.len();
    if persisted_verdicts < 2 {
        return Err(format!(
            "expected at least two persisted local-live verdict records, found {persisted_verdicts}"
        )
        .into());
    }
    validate_local_live_verdict_records(
        &verdict_jsonl,
        &[
            prompt,
            response.response.choices[0].message.content.as_str(),
        ],
    )?;

    println!();
    println!("local_live_tinfoil_provider: {}", response.provider);
    print_route_verdict_summary("local_live_tinfoil", &response.verdict)?;
    println!(
        "local_live_tinfoil_tls_binding: {:?}",
        response.verdict.check("tls_binding")
    );
    println!(
        "local_live_tinfoil_model_binding: {:?}",
        response.verdict.check("model_binding")
    );
    println!(
        "local_live_tinfoil_image_provenance: {:?}",
        response.verdict.check("image_provenance")
    );
    println!(
        "local_live_tinfoil_model_artifact_provenance: {:?}",
        response.verdict.check("model_artifact_provenance")
    );
    println!(
        "local_live_tinfoil_response: {}",
        response.response.choices[0].message.content
    );
    println!("local_live_tinfoil_persisted_verdicts: {persisted_verdicts}");
    println!(
        "local_live_tinfoil_verdict_store: {}",
        verdict_path.display()
    );
    println!(
        "local_live_tinfoil_registry_artifact: {}",
        registry_path.display()
    );
    println!("local_live_tinfoil_registry_artifact_digest: {registry_digest}");
    println!(
        "local_live_tinfoil_compatibility_matrix_artifact: {}",
        compatibility_matrix_path.display()
    );
    println!(
        "local_live_tinfoil_compatibility_matrix_artifact_digest: {compatibility_matrix_digest}"
    );
    println!(
        "local_live_tinfoil_reference_values_artifact: {}",
        reference_values_path.display()
    );
    println!("local_live_tinfoil_reference_values_artifact_digest: {reference_values_digest}");

    server.await_shutdown().await?;
    Ok(())
}

fn require_verified_check(verdict: &AttestationVerdict, check: &str) -> Result<(), DemoError> {
    match verdict.check(check) {
        Some(CheckResult::Verified) => Ok(()),
        other => Err(format!("expected {check} to be verified, got {other:?}").into()),
    }
}

fn require_response_summary<T>(
    response: &ConfidentialResponse<T>,
    request_channel_bound: bool,
    request_confidentiality_result: ConfidentialityResult,
    response_channel_bound: bool,
    response_confidentiality_result: ConfidentialityResult,
    response_integrity_result: ResponseIntegrityResult,
) -> Result<(), DemoError> {
    if response.response_channel_bound != response.verdict.response_channel_bound {
        return Err(format!(
            "response_channel_bound mirror expected {}, got {}",
            response.verdict.response_channel_bound, response.response_channel_bound
        )
        .into());
    }
    if response.response_integrity_result != response.verdict.response_integrity_result {
        return Err(format!(
            "response_integrity_result mirror expected {:?}, got {:?}",
            response.verdict.response_integrity_result, response.response_integrity_result
        )
        .into());
    }
    require_verdict_summary(
        &response.verdict,
        request_channel_bound,
        request_confidentiality_result,
        response_channel_bound,
        response_confidentiality_result,
        response_integrity_result,
    )
}

fn require_active_metadata_matches_verdict(
    client: &ConfidentialInference,
    verdict: &AttestationVerdict,
) -> Result<(), DemoError> {
    let active_policy = client.active_policy()?;
    if active_policy.schema != "confidential-inference.active-policy.v1" {
        return Err(format!(
            "active policy schema expected confidential-inference.active-policy.v1, got {}",
            active_policy.schema
        )
        .into());
    }
    if active_policy.policy_digest != verdict.policy_digest {
        return Err(format!(
            "active policy digest {} did not match verdict policy digest {}",
            active_policy.policy_digest, verdict.policy_digest
        )
        .into());
    }
    if active_policy.policy.provider_registry_digest != verdict.provider_registry_digest {
        return Err(format!(
            "active policy registry digest {} did not match verdict registry digest {}",
            active_policy.policy.provider_registry_digest, verdict.provider_registry_digest
        )
        .into());
    }
    if active_policy.policy.reference_values_digest != verdict.reference_values_digest {
        return Err(format!(
            "active policy reference-values digest {} did not match verdict reference-values digest {}",
            active_policy.policy.reference_values_digest, verdict.reference_values_digest
        )
        .into());
    }

    let active_artifacts = client.active_trust_artifacts();
    if active_artifacts.registry.schema != "confidential-inference.provider-registry.v1" {
        return Err(format!(
            "active registry schema expected confidential-inference.provider-registry.v1, got {}",
            active_artifacts.registry.schema
        )
        .into());
    }
    if active_artifacts.reference_values.schema != "confidential-inference.reference-values.v1" {
        return Err(format!(
            "active reference-values schema expected confidential-inference.reference-values.v1, got {}",
            active_artifacts.reference_values.schema
        )
        .into());
    }
    if active_artifacts.registry_digest != verdict.provider_registry_digest {
        return Err(format!(
            "active registry digest {} did not match verdict registry digest {}",
            active_artifacts.registry_digest, verdict.provider_registry_digest
        )
        .into());
    }
    if active_artifacts.reference_values_digest != verdict.reference_values_digest {
        return Err(format!(
            "active reference-values digest {} did not match verdict reference-values digest {}",
            active_artifacts.reference_values_digest, verdict.reference_values_digest
        )
        .into());
    }
    if active_artifacts.registry_source != verdict.registry_source {
        return Err(format!(
            "active registry source {} did not match verdict registry source {}",
            active_artifacts.registry_source, verdict.registry_source
        )
        .into());
    }
    if active_artifacts.reference_values_source != verdict.reference_values_source {
        return Err(format!(
            "active reference-values source {} did not match verdict reference-values source {}",
            active_artifacts.reference_values_source, verdict.reference_values_source
        )
        .into());
    }
    require_detached_ed25519_signature_value(
        &active_artifacts.registry_signature.value,
        "active registry",
    )?;
    require_detached_ed25519_signature_value(
        &active_artifacts.reference_values_signature.value,
        "active reference-values",
    )?;
    if active_artifacts.registry_source == "bundled" {
        let expected_registry = ProviderRegistryEnvelope::bundled_demo()?;
        if active_artifacts.registry_signature != expected_registry.signature {
            return Err("active bundled registry signature did not match signed fixture".into());
        }
    }
    if active_artifacts.reference_values_source == "bundled" {
        let expected_reference_values = ReferenceValuesEnvelope::bundled_demo()?;
        if active_artifacts.reference_values_signature != expected_reference_values.signature {
            return Err(
                "active bundled reference-values signature did not match signed fixture".into(),
            );
        }
    }
    if active_artifacts.registry_signature.signer != verdict.registry_signature.signer
        || active_artifacts.registry_signature.key_id != verdict.registry_signature.key_id
        || active_artifacts.registry_signature.alg != verdict.registry_signature.alg
    {
        return Err("active registry signature did not match verdict registry signature".into());
    }
    if active_artifacts.reference_values_signature.signer
        != verdict.reference_values_signature.signer
        || active_artifacts.reference_values_signature.key_id
            != verdict.reference_values_signature.key_id
        || active_artifacts.reference_values_signature.alg != verdict.reference_values_signature.alg
    {
        return Err(
            "active reference-values signature did not match verdict reference-values signature"
                .into(),
        );
    }
    Ok(())
}

fn persist_active_snapshot_artifacts(
    client: &ConfidentialInference,
    verdict: &AttestationVerdict,
) -> Result<(), DemoError> {
    let active_policy = client.active_policy()?;
    let active_artifacts = client.active_trust_artifacts();
    let policy_path = active_policy_snapshot_path()?;
    let artifacts_path = active_trust_artifacts_path()?;

    write_json_artifact(&policy_path, &active_policy)?;
    validate_active_policy_snapshot_artifact(&policy_path, &active_policy, verdict)?;
    write_json_artifact(&artifacts_path, &active_artifacts)?;
    validate_active_trust_artifacts_snapshot(&artifacts_path, &active_artifacts, verdict)?;

    println!("active_policy_artifact: {}", policy_path.display());
    println!(
        "active_trust_artifacts_artifact: {}",
        artifacts_path.display()
    );

    Ok(())
}

fn validate_active_policy_snapshot_artifact(
    path: &std::path::Path,
    expected: &ActivePolicySnapshot,
    verdict: &AttestationVerdict,
) -> Result<(), DemoError> {
    let snapshot: ActivePolicySnapshot = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    if &snapshot != expected {
        return Err("active policy artifact did not round-trip from the SDK snapshot".into());
    }
    if snapshot.schema != "confidential-inference.active-policy.v1" {
        return Err(format!(
            "active policy artifact schema expected confidential-inference.active-policy.v1, got {}",
            snapshot.schema
        )
        .into());
    }
    let digest = snapshot.policy.digest()?;
    if digest != snapshot.policy_digest {
        return Err(format!(
            "active policy artifact digest {digest} did not match embedded {}",
            snapshot.policy_digest
        )
        .into());
    }
    if snapshot.policy_digest != verdict.policy_digest {
        return Err(format!(
            "active policy artifact digest {} did not match verdict {}",
            snapshot.policy_digest, verdict.policy_digest
        )
        .into());
    }
    if snapshot.policy.provider_registry_digest != verdict.provider_registry_digest {
        return Err(format!(
            "active policy artifact registry digest {} did not match verdict {}",
            snapshot.policy.provider_registry_digest, verdict.provider_registry_digest
        )
        .into());
    }
    if snapshot.policy.reference_values_digest != verdict.reference_values_digest {
        return Err(format!(
            "active policy artifact reference-values digest {} did not match verdict {}",
            snapshot.policy.reference_values_digest, verdict.reference_values_digest
        )
        .into());
    }
    Ok(())
}

fn validate_active_trust_artifacts_snapshot(
    path: &std::path::Path,
    expected: &ActiveTrustArtifacts,
    verdict: &AttestationVerdict,
) -> Result<(), DemoError> {
    let artifacts: ActiveTrustArtifacts = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    if &artifacts != expected {
        return Err("active trust artifact did not round-trip from the SDK snapshot".into());
    }

    let registry_digest = artifacts.registry.digest()?;
    if registry_digest != artifacts.registry_digest
        || registry_digest != verdict.provider_registry_digest
    {
        return Err(format!(
            "active trust registry digest {registry_digest} did not match embedded {} and verdict {}",
            artifacts.registry_digest, verdict.provider_registry_digest
        )
        .into());
    }
    let reference_values_digest = artifacts.reference_values.digest()?;
    if reference_values_digest != artifacts.reference_values_digest
        || reference_values_digest != verdict.reference_values_digest
    {
        return Err(format!(
            "active trust reference-values digest {reference_values_digest} did not match embedded {} and verdict {}",
            artifacts.reference_values_digest, verdict.reference_values_digest
        )
        .into());
    }
    if artifacts.registry_source != verdict.registry_source {
        return Err(format!(
            "active trust registry source {} did not match verdict {}",
            artifacts.registry_source, verdict.registry_source
        )
        .into());
    }
    if artifacts.reference_values_source != verdict.reference_values_source {
        return Err(format!(
            "active trust reference-values source {} did not match verdict {}",
            artifacts.reference_values_source, verdict.reference_values_source
        )
        .into());
    }

    ProviderRegistryEnvelope {
        schema: ProviderRegistryEnvelope::SCHEMA.to_owned(),
        payload: artifacts.registry.clone(),
        signature: artifacts.registry_signature.clone(),
    }
    .verify_signature()?;
    ReferenceValuesEnvelope {
        schema: ReferenceValuesEnvelope::SCHEMA.to_owned(),
        payload: artifacts.reference_values.clone(),
        signature: artifacts.reference_values_signature.clone(),
    }
    .verify_signature()?;

    if artifacts.registry_signature.signer != verdict.registry_signature.signer
        || artifacts.registry_signature.key_id != verdict.registry_signature.key_id
        || artifacts.registry_signature.alg != verdict.registry_signature.alg
    {
        return Err(
            "active trust registry signature metadata did not match verdict metadata".into(),
        );
    }
    if artifacts.reference_values_signature.signer != verdict.reference_values_signature.signer
        || artifacts.reference_values_signature.key_id != verdict.reference_values_signature.key_id
        || artifacts.reference_values_signature.alg != verdict.reference_values_signature.alg
    {
        return Err(
            "active trust reference-values signature metadata did not match verdict metadata"
                .into(),
        );
    }

    Ok(())
}

fn require_detached_ed25519_signature_value(value: &str, subject: &str) -> Result<(), DemoError> {
    let encoded = value
        .strip_prefix("base64url:")
        .ok_or_else(|| format!("{subject} signature value is not base64url-prefixed"))?;
    if encoded.is_empty() || encoded.contains('=') {
        return Err(format!("{subject} signature value must be unpadded base64url").into());
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| format!("{subject} signature value is not base64url: {error}"))?;
    if decoded.len() != ED25519_SIGNATURE_BYTE_LEN {
        return Err(format!(
            "{subject} signature value decoded to {} bytes, expected {ED25519_SIGNATURE_BYTE_LEN}",
            decoded.len()
        )
        .into());
    }
    Ok(())
}

fn require_verdict_summary(
    verdict: &AttestationVerdict,
    request_channel_bound: bool,
    request_confidentiality_result: ConfidentialityResult,
    response_channel_bound: bool,
    response_confidentiality_result: ConfidentialityResult,
    response_integrity_result: ResponseIntegrityResult,
) -> Result<(), DemoError> {
    if verdict.request_channel_bound != request_channel_bound {
        return Err(format!(
            "request_channel_bound expected {request_channel_bound}, got {}",
            verdict.request_channel_bound
        )
        .into());
    }
    if verdict.request_confidentiality_result != request_confidentiality_result {
        return Err(format!(
            "request_confidentiality_result expected {:?}, got {:?}",
            request_confidentiality_result, verdict.request_confidentiality_result
        )
        .into());
    }
    if verdict.response_channel_bound != response_channel_bound {
        return Err(format!(
            "response_channel_bound expected {response_channel_bound}, got {}",
            verdict.response_channel_bound
        )
        .into());
    }
    if verdict.response_confidentiality_result != response_confidentiality_result {
        return Err(format!(
            "response_confidentiality_result expected {:?}, got {:?}",
            response_confidentiality_result, verdict.response_confidentiality_result
        )
        .into());
    }
    if verdict.response_integrity_result != response_integrity_result {
        return Err(format!(
            "response_integrity_result expected {:?}, got {:?}",
            response_integrity_result, verdict.response_integrity_result
        )
        .into());
    }
    Ok(())
}

fn local_live_verdict_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_jsonl_path("target/confidential-demo-local-live-verdicts.jsonl")
}

fn local_live_registry_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_artifact_path("target/confidential-demo-local-live-registry.json")
}

fn local_live_compatibility_matrix_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_artifact_path("target/confidential-demo-local-live-compatibility-matrix.json")
}

fn local_live_reference_values_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_artifact_path("target/confidential-demo-local-live-reference-values.json")
}

fn phase2_fixture_verdict_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_jsonl_path("target/confidential-demo-phase2-fixture-verdicts.jsonl")
}

fn proxy_verdict_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_jsonl_path("target/confidential-demo-proxy-verdicts.jsonl")
}

fn local_demo_verdict_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_jsonl_path("target/confidential-demo-verdicts.jsonl")
}

fn active_policy_snapshot_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_artifact_path("target/confidential-demo-active-policy.json")
}

fn active_trust_artifacts_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_artifact_path("target/confidential-demo-active-trust-artifacts.json")
}

fn local_app_e2ee_verdict_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_jsonl_path("target/confidential-demo-local-sdk-app-e2ee-verdicts.jsonl")
}

fn local_app_e2ee_registry_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_artifact_path("target/confidential-demo-local-sdk-app-e2ee-registry.json")
}

fn local_app_e2ee_compatibility_matrix_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_artifact_path(
        "target/confidential-demo-local-sdk-app-e2ee-compatibility-matrix.json",
    )
}

fn local_app_e2ee_reference_values_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_artifact_path("target/confidential-demo-local-sdk-app-e2ee-reference-values.json")
}

fn local_demo_audit_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_jsonl_path("target/confidential-demo-audit.jsonl")
}

fn local_demo_metrics_path() -> Result<std::path::PathBuf, DemoError> {
    reset_demo_jsonl_path("target/confidential-demo-metrics.jsonl")
}

fn reset_demo_jsonl_path(path: &str) -> Result<std::path::PathBuf, DemoError> {
    reset_demo_artifact_path(path)
}

fn reset_demo_artifact_path(path: &str) -> Result<std::path::PathBuf, DemoError> {
    let path = std::path::PathBuf::from(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(path)
}

fn write_json_artifact<T: Serialize>(path: &std::path::Path, value: &T) -> Result<(), DemoError> {
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn read_jsonl_records(path: &std::path::Path) -> Result<Vec<Value>, DemoError> {
    let records = std::fs::read_to_string(path)?;
    records
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|error| {
                format!(
                    "{} line {} is not valid JSON: {error}",
                    path.display(),
                    index + 1
                )
                .into()
            })
        })
        .collect()
}

fn validate_demo_audit_records(records: &[Value], forbidden: &[&str]) -> Result<(), DemoError> {
    validate_jsonl_redaction(records, forbidden, "local demo audit log")?;
    require_cache_hit_coverage(records, "local demo audit log")?;
    for record in records {
        require_json_string(record, "provider", "demo")?;
        require_json_string(record, "status", "verified")?;
        require_json_string(record, "enforcement", "enforce")?;
        require_json_bool(record, "request_allowed", true)?;
        require_json_bool(record, "would_block_under_enforce", false)?;
        require_json_bool(record, "chat_executable", true)?;
        require_json_string(record, "route_execution_status", "executable_fixture")?;
        require_json_string(record, "request_confidentiality_result", "encrypted_bound")?;
        require_json_string(record, "response_confidentiality_result", "encrypted_bound")?;
        require_json_string(record, "response_integrity_result", "channel_bound")?;
        require_digest_field(record, "policy_digest")?;
        require_digest_field(record, "provider_registry_digest")?;
        require_digest_field(record, "reference_values_digest")?;
        require_digest_field(record, "raw_evidence_digest")?;
        require_digest_field(record, "evidence_digest")?;
        require_json_object(record, "registry_signature")?;
        require_json_object(record, "reference_values_signature")?;
    }
    Ok(())
}

fn validate_demo_verdict_records(records: &[Value], forbidden: &[&str]) -> Result<(), DemoError> {
    validate_jsonl_redaction(records, forbidden, "local demo verdict store")?;
    require_cache_hit_coverage(records, "local demo verdict store")?;
    for record in records {
        require_json_string(record, "provider", "demo")?;
        require_json_string(record, "status", "verified")?;
        require_json_string(record, "enforcement", "enforce")?;
        require_json_bool(record, "request_allowed", true)?;
        require_json_bool(record, "would_block_under_enforce", false)?;
        require_json_bool(record, "chat_executable", true)?;
        require_json_string(record, "route_execution_status", "executable_fixture")?;
        require_digest_field(record, "policy_digest")?;
        require_digest_field(record, "provider_registry_digest")?;
        require_digest_field(record, "reference_values_digest")?;
        require_digest_field(record, "raw_evidence_digest")?;
        require_digest_field(record, "evidence_digest")?;
        require_json_object(record, "registry_signature")?;
        require_json_object(record, "reference_values_signature")?;
        let verdict_json = record
            .get("verdict_json")
            .ok_or("local demo verdict record is missing verdict_json")?;
        require_record_or_verdict_json_string(
            record,
            verdict_json,
            "request_confidentiality_result",
            "encrypted_bound",
        )?;
        require_record_or_verdict_json_string(
            record,
            verdict_json,
            "response_confidentiality_result",
            "encrypted_bound",
        )?;
        require_record_or_verdict_json_string(
            record,
            verdict_json,
            "response_integrity_result",
            "channel_bound",
        )?;
        for check in [
            "cpu_tee",
            "e2ee_key_binding",
            "model_binding",
            "request_encryption",
            "response_encryption",
            "response_channel_binding",
            "route_metadata_binding",
        ] {
            let got = verdict_json
                .get("checks")
                .and_then(|checks| checks.get(check))
                .and_then(Value::as_str);
            if got != Some("verified") {
                return Err(format!(
                    "local demo verdict_json check {check} expected verified, got {got:?}"
                )
                .into());
            }
        }
    }
    Ok(())
}

fn validate_local_registry_artifact(
    path: &std::path::Path,
    expected_digest: &str,
    expected_model: &str,
    expected_route: &RouteDefinition,
    subject: &str,
) -> Result<(), DemoError> {
    let envelope: ProviderRegistryEnvelope = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    envelope.verify_signature_with_keys(&[local_trusted_signing_key()])?;
    let digest = envelope.payload.digest()?;
    if digest != expected_digest {
        return Err(
            format!("{subject} digest {digest} did not match expected {expected_digest}").into(),
        );
    }
    if envelope.signature.signer != LOCAL_ARTIFACT_SIGNER
        || envelope.signature.key_id != LOCAL_ARTIFACT_KEY_ID
        || envelope.signature.alg != "ed25519"
    {
        return Err(format!("{subject} signature identity drifted").into());
    }

    let model = envelope
        .payload
        .models
        .get(expected_model)
        .ok_or_else(|| format!("{subject} missing model {expected_model}"))?;
    if model.canonical_model != expected_model {
        return Err(format!(
            "{subject} model {} canonical_model expected {expected_model}, got {}",
            expected_model, model.canonical_model
        )
        .into());
    }
    let route = model
        .routes
        .iter()
        .find(|route| route.route_id == expected_route.route_id)
        .ok_or_else(|| {
            format!(
                "{subject} missing executable route {}",
                expected_route.route_id
            )
        })?;
    if route != expected_route {
        return Err(format!(
            "{subject} route {} did not match the executable route used by the demo",
            expected_route.route_id
        )
        .into());
    }

    Ok(())
}

fn validate_local_compatibility_matrix_artifact(
    path: &std::path::Path,
    expected_digest: &str,
    expected_matrix: &ProviderCompatibilityMatrix,
    expected_provider: &str,
    route: &RouteDefinition,
    subject: &str,
) -> Result<(), DemoError> {
    let envelope: ProviderCompatibilityMatrixEnvelope =
        serde_json::from_str(&std::fs::read_to_string(path)?)?;
    envelope.verify_signature_with_keys(&[local_trusted_signing_key()])?;
    let digest = envelope.payload.digest()?;
    if digest != expected_digest {
        return Err(
            format!("{subject} digest {digest} did not match expected {expected_digest}").into(),
        );
    }
    if envelope.signature.signer != LOCAL_ARTIFACT_SIGNER
        || envelope.signature.key_id != LOCAL_ARTIFACT_KEY_ID
        || envelope.signature.alg != "ed25519"
    {
        return Err(format!("{subject} signature identity drifted").into());
    }
    if &envelope.payload != expected_matrix {
        return Err(format!(
            "{subject} payload did not match the executable matrix used by the demo"
        )
        .into());
    }

    let provider = envelope.payload.provider(expected_provider)?;
    provider.validate_route(route)?;
    if provider.route_execution_status != RouteExecutionStatus::Executable
        || !provider.supports_endpoint(OpenAiEndpoint::ChatCompletions)
        || !provider
            .known_unsupported_modes
            .iter()
            .any(|mode| mode == "streaming")
        || !provider.required_credentials.is_empty()
    {
        return Err(format!("{subject} did not bind the expected executable profile").into());
    }

    Ok(())
}

fn validate_local_live_reference_values_artifact(
    path: &std::path::Path,
    expected_digest: &str,
    route: &RouteDefinition,
    spki_sha256: &str,
) -> Result<(), DemoError> {
    let envelope: ReferenceValuesEnvelope = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    envelope.verify_signature_with_keys(&[local_trusted_signing_key()])?;
    let digest = envelope.payload.digest()?;
    if digest != expected_digest {
        return Err(format!(
            "local live reference-values artifact digest {digest} did not match expected {expected_digest}"
        )
        .into());
    }
    if envelope.signature.signer != LOCAL_ARTIFACT_SIGNER
        || envelope.signature.key_id != LOCAL_ARTIFACT_KEY_ID
        || envelope.signature.alg != "ed25519"
    {
        return Err("local live reference-values artifact signature identity drifted".into());
    }

    let provider = envelope
        .payload
        .providers
        .get(LOCAL_TINFOIL_PROVIDER)
        .ok_or("local live reference-values artifact missing local Tinfoil provider")?;
    if !provider
        .accepted_measurements
        .iter()
        .any(|measurement| measurement == LOCAL_TINFOIL_MEASUREMENT)
    {
        return Err(
            "local live reference-values artifact missing verified Tinfoil measurement".into(),
        );
    }
    let route_reference = provider
        .routes
        .get(&route.route_id)
        .ok_or("local live reference-values artifact missing local Tinfoil route")?;
    let expected_spki = format!("sha256:{spki_sha256}");
    if route_reference.canonical_model != LOCAL_TINFOIL_MODEL
        || route_reference.provider_model != LOCAL_TINFOIL_MODEL
        || route_reference.evidence_family != "tinfoil_hw_verified_tls"
        || route_reference.channel_binding_kind != ChannelBindingKind::TeeTerminatedTls
        || route_reference.trust_tier != TrustTier::HwVerifiedTls
        || route_reference.tls_spki_sha256.as_deref() != Some(expected_spki.as_str())
        || route_reference.workload_image_digest != LOCAL_TINFOIL_WORKLOAD_IMAGE
        || !route_reference.model_artifacts.iter().any(|artifact| {
            artifact.kind == "weights"
                && artifact.name == LOCAL_TINFOIL_MODEL
                && artifact.digest == LOCAL_TINFOIL_WEIGHTS
        })
    {
        return Err(
            "local live reference-values artifact did not bind the expected Tinfoil route".into(),
        );
    }
    Ok(())
}

fn validate_local_app_e2ee_reference_values_artifact(
    path: &std::path::Path,
    expected_digest: &str,
    route: &RouteDefinition,
    public_key_digest: &str,
) -> Result<(), DemoError> {
    let envelope: ReferenceValuesEnvelope = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    envelope.verify_signature_with_keys(&[local_trusted_signing_key()])?;
    let digest = envelope.payload.digest()?;
    if digest != expected_digest {
        return Err(format!(
            "local SDK app-E2EE reference-values artifact digest {digest} did not match expected {expected_digest}"
        )
        .into());
    }
    if envelope.signature.signer != LOCAL_ARTIFACT_SIGNER
        || envelope.signature.key_id != LOCAL_ARTIFACT_KEY_ID
        || envelope.signature.alg != "ed25519"
    {
        return Err(
            "local SDK app-E2EE reference-values artifact signature identity drifted".into(),
        );
    }

    let provider = envelope
        .payload
        .providers
        .get(LOCAL_APP_E2EE_PROVIDER)
        .ok_or("local SDK app-E2EE reference-values artifact missing provider")?;
    if !provider
        .accepted_measurements
        .iter()
        .any(|measurement| measurement == LOCAL_APP_E2EE_MEASUREMENT)
    {
        return Err("local SDK app-E2EE reference-values artifact missing TDX measurement".into());
    }
    let route_reference = provider
        .routes
        .get(&route.route_id)
        .ok_or("local SDK app-E2EE reference-values artifact missing route")?;
    if route_reference.canonical_model != LOCAL_APP_E2EE_MODEL
        || route_reference.provider_model != LOCAL_APP_E2EE_PROVIDER_MODEL
        || route_reference.evidence_family != "dstack_app_e2ee"
        || route_reference.channel_binding_kind != ChannelBindingKind::AttestedAppE2ee
        || route_reference.trust_tier != TrustTier::AppE2ee
        || !route_reference
            .accepted_cpu_tees
            .iter()
            .any(|cpu| cpu == &CpuTeeKind::Tdx)
        || route_reference.e2ee_public_key_digest != public_key_digest
        || route_reference.workload_images
            != vec![confidential_inference_attestation::WorkloadImage {
                service: "root".into(),
                reference: LOCAL_APP_E2EE_WORKLOAD_IMAGE_REFERENCE.into(),
                digest: LOCAL_APP_E2EE_WORKLOAD_IMAGE.into(),
            }]
        || route_reference.workload_image_digest != LOCAL_APP_E2EE_WORKLOAD_IMAGE
        || !route_reference.model_artifacts.iter().any(|artifact| {
            artifact.kind == "weights"
                && artifact.name == LOCAL_APP_E2EE_MODEL
                && artifact.digest == LOCAL_APP_E2EE_WEIGHTS
        })
    {
        return Err(
            "local SDK app-E2EE reference-values artifact did not bind the expected route".into(),
        );
    }
    Ok(())
}

fn validate_demo_metrics_records(records: &[Value], forbidden: &[&str]) -> Result<(), DemoError> {
    validate_jsonl_redaction(records, forbidden, "local demo metrics log")?;
    if records.is_empty() {
        return Err("local demo metrics log did not contain any records".into());
    }
    if !records.iter().any(|record| {
        json_string(record, "event") == Some("route_selection")
            && json_string(record, "provider") == Some("any")
            && json_string(record, "requested_model") == Some("gpt-oss-120b")
            && json_string(record, "purpose") == Some("chat")
            && json_string(record, "outcome") == Some("success")
    }) {
        return Err("local demo metrics log missing successful chat route selection".into());
    }
    require_metric_event_with_label(records, "verdict", "demo")?;
    require_metric_event_with_label(records, "latency", "demo")?;
    for step in ["evidence_fetch", "evidence_verification", "provider_chat"] {
        if !records.iter().any(|record| {
            json_string(record, "event") == Some("latency")
                && json_string(record, "step") == Some(step)
                && record_label(record, "provider") == Some("demo")
                && record_label(record, "evidence_family") == Some("fixture_dstack")
                && json_string(record, "outcome") == Some("success")
        }) {
            return Err(format!("local demo metrics log missing latency step {step}").into());
        }
    }
    for cache_event in ["miss", "hit"] {
        if !records.iter().any(|record| {
            json_string(record, "event") == Some("verification_cache")
                && json_string(record, "cache_event") == Some(cache_event)
                && record_label(record, "provider") == Some("demo")
                && record_label(record, "evidence_family") == Some("fixture_dstack")
        }) {
            return Err(
                format!("local demo metrics log missing verification cache {cache_event}").into(),
            );
        }
    }
    Ok(())
}

fn validate_proxy_verdict_records(records: &[Value], forbidden: &[&str]) -> Result<(), DemoError> {
    validate_jsonl_redaction(records, forbidden, "proxy verdict store")?;
    require_cache_hit_coverage(records, "proxy verdict store")?;
    for record in records {
        require_json_string(record, "provider", "demo")?;
        require_json_string(record, "status", "verified")?;
        require_json_string(record, "enforcement", "enforce")?;
        require_json_bool(record, "request_allowed", true)?;
        require_json_bool(record, "would_block_under_enforce", false)?;
        require_json_bool(record, "chat_executable", true)?;
        require_json_string(record, "route_execution_status", "executable_fixture")?;
        require_digest_field(record, "policy_digest")?;
        require_digest_field(record, "provider_registry_digest")?;
        require_digest_field(record, "reference_values_digest")?;
        require_digest_field(record, "raw_evidence_digest")?;
        require_digest_field(record, "evidence_digest")?;
        require_json_object(record, "registry_signature")?;
        require_json_object(record, "reference_values_signature")?;
        let verdict_json = record
            .get("verdict_json")
            .ok_or("proxy verdict record is missing verdict_json")?;
        require_record_or_verdict_json_string(
            record,
            verdict_json,
            "request_confidentiality_result",
            "encrypted_bound",
        )?;
        require_record_or_verdict_json_string(
            record,
            verdict_json,
            "response_confidentiality_result",
            "encrypted_bound",
        )?;
        require_record_or_verdict_json_string(
            record,
            verdict_json,
            "response_integrity_result",
            "channel_bound",
        )?;
        for check in [
            "cpu_tee",
            "e2ee_key_binding",
            "model_binding",
            "request_encryption",
            "response_encryption",
            "response_channel_binding",
            "route_metadata_binding",
        ] {
            let got = verdict_json
                .get("checks")
                .and_then(|checks| checks.get(check))
                .and_then(Value::as_str);
            if got != Some("verified") {
                return Err(format!(
                    "proxy verdict_json check {check} expected verified, got {got:?}"
                )
                .into());
            }
        }
    }
    Ok(())
}

fn validate_demo_otlp_metrics_payload(
    payload: &Value,
    forbidden: &[&str],
) -> Result<(usize, usize, usize, usize), DemoError> {
    validate_json_redaction(payload, forbidden, "local demo OTLP metrics payload")?;
    let resource_metrics = payload
        .get("resourceMetrics")
        .and_then(Value::as_array)
        .ok_or("local demo OTLP metrics missing resourceMetrics array")?;
    if resource_metrics.is_empty() {
        return Err("local demo OTLP metrics resourceMetrics array was empty".into());
    }

    let mut saw_service_name = false;
    let mut saw_verdict_status = false;
    let mut saw_streaming_fail_closed = false;
    let mut scope_metric_count = 0;
    let mut metric_count = 0;
    let mut data_point_count = 0;

    for resource_metric in resource_metrics {
        let attributes = resource_metric
            .get("resource")
            .and_then(|resource| resource.get("attributes"))
            .and_then(Value::as_array)
            .ok_or("local demo OTLP metrics resource missing attributes")?;
        if otlp_attribute(attributes, "service.name") == Some("confidential-inference-sdk") {
            saw_service_name = true;
        }

        let scope_metrics = resource_metric
            .get("scopeMetrics")
            .and_then(Value::as_array)
            .ok_or("local demo OTLP metrics missing scopeMetrics array")?;
        scope_metric_count += scope_metrics.len();
        for scope_metric in scope_metrics {
            let scope_name = scope_metric
                .get("scope")
                .and_then(|scope| scope.get("name"))
                .and_then(Value::as_str);
            if scope_name != Some("confidential-inference-sdk") {
                return Err(format!(
                    "local demo OTLP metrics scope name expected confidential-inference-sdk, got {scope_name:?}"
                )
                .into());
            }

            let metrics = scope_metric
                .get("metrics")
                .and_then(Value::as_array)
                .ok_or("local demo OTLP scopeMetrics entry missing metrics array")?;
            metric_count += metrics.len();
            for metric in metrics {
                let name = metric
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or("local demo OTLP metric missing name")?;
                let sum = metric
                    .get("sum")
                    .ok_or("local demo OTLP metric missing sum")?;
                if sum.get("aggregationTemporality").and_then(Value::as_str)
                    != Some("AGGREGATION_TEMPORALITY_CUMULATIVE")
                {
                    return Err(format!("local demo OTLP metric {name} was not cumulative").into());
                }
                if sum.get("isMonotonic").and_then(Value::as_bool) != Some(true) {
                    return Err(format!("local demo OTLP metric {name} was not monotonic").into());
                }
                let data_points = sum
                    .get("dataPoints")
                    .and_then(Value::as_array)
                    .ok_or("local demo OTLP metric missing dataPoints")?;
                data_point_count += data_points.len();
                for data_point in data_points {
                    let value = data_point
                        .get("asInt")
                        .and_then(Value::as_str)
                        .ok_or("local demo OTLP data point missing string asInt")?;
                    value.parse::<u64>().map_err(|error| {
                        format!("local demo OTLP data point asInt was not u64: {error}")
                    })?;
                    let attributes = data_point
                        .get("attributes")
                        .and_then(Value::as_array)
                        .ok_or("local demo OTLP data point missing attributes")?;
                    if name == "confidential_inference_verdict_status_total"
                        && otlp_attribute(attributes, "provider") == Some("demo")
                        && otlp_attribute(attributes, "status") == Some("verified")
                    {
                        saw_verdict_status = true;
                    }
                    if name == "confidential_inference_streaming_fail_closed_total"
                        && otlp_attribute(attributes, "provider") == Some("demo")
                        && otlp_attribute(attributes, "endpoint") == Some("chat_completions")
                    {
                        saw_streaming_fail_closed = true;
                    }
                }
            }
        }
    }

    if !saw_service_name {
        return Err("local demo OTLP metrics missing service.name resource attribute".into());
    }
    if !saw_verdict_status {
        return Err("local demo OTLP metrics missing verified demo verdict metric".into());
    }
    if !saw_streaming_fail_closed {
        return Err("local demo OTLP metrics missing streaming fail-closed metric".into());
    }

    Ok((
        resource_metrics.len(),
        scope_metric_count,
        metric_count,
        data_point_count,
    ))
}

async fn spawn_demo_otlp_metrics_collector(
) -> Result<(String, JoinHandle<Result<Vec<u8>, DemoError>>), DemoError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/v1/metrics", listener.local_addr()?);
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request = read_http_request(&mut stream).await?;
        write_http_response(&mut stream, 200, "OK", "{}").await?;
        Ok(request)
    });
    Ok((endpoint, handle))
}

fn validate_demo_otlp_http_request(request: &[u8], forbidden: &[&str]) -> Result<(), DemoError> {
    let (method, path) = request_line(request)?;
    if method != "POST" || path != "/v1/metrics" {
        return Err(format!(
            "local demo OTLP HTTP request expected POST /v1/metrics, got {method} {path}"
        )
        .into());
    }
    let headers = std::str::from_utf8(&request[..header_end(request).unwrap_or(0)])?;
    if !headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("content-type: application/json"))
    {
        return Err("local demo OTLP HTTP request missing application/json content type".into());
    }
    let payload: Value = serde_json::from_slice(request_body(request)?)?;
    validate_demo_otlp_metrics_payload(&payload, forbidden)?;
    Ok(())
}

fn validate_local_live_verdict_records(
    records: &[Value],
    forbidden: &[&str],
) -> Result<(), DemoError> {
    validate_jsonl_redaction(records, forbidden, "local live Tinfoil verdict store")?;
    require_cache_hit_coverage(records, "local live Tinfoil verdict store")?;
    for record in records {
        require_json_string(record, "provider", LOCAL_TINFOIL_PROVIDER)?;
        require_json_string(record, "status", "verified")?;
        require_json_string(record, "enforcement", "enforce")?;
        require_json_bool(record, "request_allowed", true)?;
        require_json_bool(record, "would_block_under_enforce", false)?;
        require_json_bool(record, "chat_executable", true)?;
        require_json_string(record, "route_execution_status", "executable")?;
        require_digest_field(record, "policy_digest")?;
        require_digest_field(record, "provider_registry_digest")?;
        require_digest_field(record, "reference_values_digest")?;
        require_digest_field(record, "raw_evidence_digest")?;
        require_digest_field(record, "evidence_digest")?;
        require_json_object(record, "registry_signature")?;
        require_json_object(record, "reference_values_signature")?;
        let verdict_json = record
            .get("verdict_json")
            .ok_or("local live Tinfoil verdict record is missing verdict_json")?;
        for check in [
            "tls_binding",
            "model_binding",
            "image_provenance",
            "model_artifact_provenance",
        ] {
            let got = verdict_json
                .get("checks")
                .and_then(|checks| checks.get(check))
                .and_then(Value::as_str);
            if got != Some("verified") {
                return Err(format!(
                    "local live Tinfoil verdict_json check {check} expected verified, got {got:?}"
                )
                .into());
            }
        }
    }
    Ok(())
}

fn validate_phase2_fixture_verdict_records(
    records: &[Value],
    forbidden: &[&str],
) -> Result<(), DemoError> {
    validate_jsonl_redaction(records, forbidden, "phase2 fixture verdict store")?;
    let saw_tinfoil = records
        .iter()
        .any(|record| json_string(record, "provider") == Some("tinfoil-fixture"));
    let saw_venice = records
        .iter()
        .any(|record| json_string(record, "provider") == Some("venice-fixture"));
    if !saw_tinfoil || !saw_venice {
        return Err("phase2 fixture verdict store must include Tinfoil and Venice records".into());
    }
    let saw_tinfoil_miss = records.iter().any(|record| {
        json_string(record, "provider") == Some("tinfoil-fixture")
            && record.get("cache_hit").and_then(Value::as_bool) == Some(false)
    });
    let saw_tinfoil_hit = records.iter().any(|record| {
        json_string(record, "provider") == Some("tinfoil-fixture")
            && record.get("cache_hit").and_then(Value::as_bool) == Some(true)
    });
    if !saw_tinfoil_miss || !saw_tinfoil_hit {
        return Err(
            "phase2 fixture verdict store did not include Tinfoil cache miss and hit records"
                .into(),
        );
    }

    for record in records {
        require_json_string(record, "status", "verified")?;
        require_json_string(record, "enforcement", "enforce")?;
        require_json_bool(record, "request_allowed", true)?;
        require_json_bool(record, "would_block_under_enforce", false)?;
        require_digest_field(record, "policy_digest")?;
        require_digest_field(record, "provider_registry_digest")?;
        require_digest_field(record, "reference_values_digest")?;
        require_digest_field(record, "raw_evidence_digest")?;
        require_digest_field(record, "evidence_digest")?;
        require_json_object(record, "registry_signature")?;
        require_json_object(record, "reference_values_signature")?;
        let verdict_json = record
            .get("verdict_json")
            .ok_or("phase2 fixture verdict record is missing verdict_json")?;
        match json_string(record, "provider") {
            Some("tinfoil-fixture") => {
                require_json_string(record, "route_execution_status", "executable_fixture")?;
                require_json_bool(record, "chat_executable", true)?;
                require_record_or_verdict_json_string(
                    record,
                    verdict_json,
                    "request_confidentiality_result",
                    "channel_bound",
                )?;
                require_record_or_verdict_json_string(
                    record,
                    verdict_json,
                    "response_confidentiality_result",
                    "channel_bound",
                )?;
                require_record_or_verdict_json_string(
                    record,
                    verdict_json,
                    "response_integrity_result",
                    "channel_bound",
                )?;
                let tls_binding = verdict_json
                    .get("checks")
                    .and_then(|checks| checks.get("tls_binding"))
                    .and_then(Value::as_str);
                if tls_binding != Some("verified") {
                    return Err(format!(
                        "phase2 Tinfoil verdict_json check tls_binding expected verified, got {tls_binding:?}"
                    )
                    .into());
                }
                let model_binding = verdict_json
                    .get("checks")
                    .and_then(|checks| checks.get("model_binding"))
                    .and_then(Value::as_str);
                if model_binding != Some("not_applicable") {
                    return Err(format!(
                        "phase2 Tinfoil verdict_json check model_binding expected not_applicable, got {model_binding:?}"
                    )
                    .into());
                }
            }
            Some("venice-fixture") => {
                require_json_string(record, "route_execution_status", "verification_only")?;
                require_json_bool(record, "chat_executable", false)?;
                require_record_or_verdict_json_string(
                    record,
                    verdict_json,
                    "request_confidentiality_result",
                    "unknown",
                )?;
                require_record_or_verdict_json_string(
                    record,
                    verdict_json,
                    "response_confidentiality_result",
                    "unknown",
                )?;
                require_record_or_verdict_json_string(
                    record,
                    verdict_json,
                    "response_integrity_result",
                    "unknown",
                )?;
                for check in ["tcb_compose_hash", "model_binding"] {
                    let got = verdict_json
                        .get("checks")
                        .and_then(|checks| checks.get(check))
                        .and_then(Value::as_str);
                    if got != Some("verified") {
                        return Err(format!(
                            "phase2 Venice verdict_json check {check} expected verified, got {got:?}"
                        )
                        .into());
                    }
                }
                let e2ee_key_binding = verdict_json
                    .get("checks")
                    .and_then(|checks| checks.get("e2ee_key_binding"))
                    .and_then(Value::as_str);
                if e2ee_key_binding != Some("not_applicable") {
                    return Err(format!(
                        "phase2 Venice verdict_json check e2ee_key_binding expected not_applicable, got {e2ee_key_binding:?}"
                    )
                    .into());
                }
            }
            other => {
                return Err(format!("unexpected phase2 fixture provider {other:?}").into());
            }
        }
    }
    Ok(())
}

fn validate_local_app_e2ee_verdict_records(
    records: &[Value],
    forbidden: &[&str],
) -> Result<(), DemoError> {
    validate_jsonl_redaction(records, forbidden, "local SDK app-E2EE verdict store")?;
    require_cache_hit_coverage(records, "local SDK app-E2EE verdict store")?;
    for record in records {
        require_json_string(record, "provider", LOCAL_APP_E2EE_PROVIDER)?;
        require_json_string(record, "status", "verified")?;
        require_json_string(record, "enforcement", "enforce")?;
        require_json_bool(record, "request_allowed", true)?;
        require_json_bool(record, "would_block_under_enforce", false)?;
        require_json_bool(record, "chat_executable", true)?;
        require_json_string(record, "route_execution_status", "executable")?;
        require_digest_field(record, "policy_digest")?;
        require_digest_field(record, "provider_registry_digest")?;
        require_digest_field(record, "reference_values_digest")?;
        require_digest_field(record, "raw_evidence_digest")?;
        require_digest_field(record, "evidence_digest")?;
        require_json_object(record, "registry_signature")?;
        require_json_object(record, "reference_values_signature")?;
        let verdict_json = record
            .get("verdict_json")
            .ok_or("local SDK app-E2EE verdict record is missing verdict_json")?;
        require_record_or_verdict_json_string(
            record,
            verdict_json,
            "request_confidentiality_result",
            "unknown",
        )?;
        require_record_or_verdict_json_string(
            record,
            verdict_json,
            "response_confidentiality_result",
            "unknown",
        )?;
        require_record_or_verdict_json_string(
            record,
            verdict_json,
            "response_integrity_result",
            "unknown",
        )?;
        for check in [
            "tcb_compose_hash",
            "e2ee_key_reference_match",
            "model_binding",
            "workload_manifest_binding",
            "image_provenance",
            "model_artifact_provenance",
        ] {
            let got = verdict_json
                .get("checks")
                .and_then(|checks| checks.get(check))
                .and_then(Value::as_str);
            if got != Some("verified") {
                return Err(format!(
                    "local SDK app-E2EE verdict_json check {check} expected verified, got {got:?}"
                )
                .into());
            }
        }
        for check in [
            "e2ee_key_binding",
            "request_encryption",
            "response_encryption",
        ] {
            let got = verdict_json
                .get("checks")
                .and_then(|checks| checks.get(check))
                .and_then(Value::as_str);
            if got != Some("not_applicable") {
                return Err(format!(
                    "local SDK app-E2EE verdict_json check {check} expected not_applicable, got {got:?}"
                )
                .into());
            }
        }
    }
    Ok(())
}

fn validate_jsonl_redaction(
    records: &[Value],
    forbidden: &[&str],
    label: &str,
) -> Result<(), DemoError> {
    validate_json_redaction(&json!(records), forbidden, label)
}

fn validate_json_redaction(
    record: &Value,
    forbidden: &[&str],
    label: &str,
) -> Result<(), DemoError> {
    let serialized = serde_json::to_string(record)?;
    for value in forbidden {
        if !value.is_empty() && serialized.contains(value) {
            return Err(format!("{label} leaked forbidden plaintext").into());
        }
    }
    Ok(())
}

fn otlp_attribute<'a>(attributes: &'a [Value], key: &str) -> Option<&'a str> {
    attributes.iter().find_map(|attribute| {
        if attribute.get("key").and_then(Value::as_str) == Some(key) {
            attribute
                .get("value")
                .and_then(|value| value.get("stringValue"))
                .and_then(Value::as_str)
        } else {
            None
        }
    })
}

fn require_cache_hit_coverage(records: &[Value], label: &str) -> Result<(), DemoError> {
    let saw_miss = records
        .iter()
        .any(|record| record.get("cache_hit").and_then(Value::as_bool) == Some(false));
    let saw_hit = records
        .iter()
        .any(|record| record.get("cache_hit").and_then(Value::as_bool) == Some(true));
    if !saw_miss || !saw_hit {
        return Err(
            format!("{label} did not include both cache miss and cache hit records").into(),
        );
    }
    Ok(())
}

fn require_json_string(record: &Value, field: &str, expected: &str) -> Result<(), DemoError> {
    let got = record.get(field).and_then(Value::as_str);
    if got != Some(expected) {
        return Err(format!("{field} expected {expected:?}, got {got:?}").into());
    }
    Ok(())
}

fn require_record_or_verdict_json_string(
    record: &Value,
    verdict_json: &Value,
    field: &str,
    expected: &str,
) -> Result<(), DemoError> {
    let got = record
        .get(field)
        .and_then(Value::as_str)
        .or_else(|| verdict_json.get(field).and_then(Value::as_str));
    if got != Some(expected) {
        return Err(format!("{field} expected {expected:?}, got {got:?}").into());
    }
    Ok(())
}

fn require_json_bool(record: &Value, field: &str, expected: bool) -> Result<(), DemoError> {
    let got = record.get(field).and_then(Value::as_bool);
    if got != Some(expected) {
        return Err(format!("{field} expected {expected}, got {got:?}").into());
    }
    Ok(())
}

fn require_json_object(record: &Value, field: &str) -> Result<(), DemoError> {
    if !record.get(field).is_some_and(Value::is_object) {
        return Err(format!("{field} expected object").into());
    }
    Ok(())
}

fn require_digest_field(record: &Value, field: &str) -> Result<(), DemoError> {
    let got = record.get(field).and_then(Value::as_str);
    match got {
        Some(value) if is_canonical_sha256_digest(value) => Ok(()),
        _ => Err(format!("{field} expected canonical sha256 digest, got {got:?}").into()),
    }
}

fn is_canonical_sha256_digest(value: &str) -> bool {
    const PREFIX: &str = "sha256:";
    let Some(hex) = value.strip_prefix(PREFIX) else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn require_metric_event_with_label(
    records: &[Value],
    event: &str,
    provider: &str,
) -> Result<(), DemoError> {
    if records.iter().any(|record| {
        json_string(record, "event") == Some(event)
            && record_label(record, "provider") == Some(provider)
    }) {
        Ok(())
    } else {
        Err(format!("local demo metrics log missing {event} for provider {provider}").into())
    }
}

fn json_string<'a>(record: &'a Value, field: &str) -> Option<&'a str> {
    record.get(field).and_then(Value::as_str)
}

fn record_label<'a>(record: &'a Value, label: &str) -> Option<&'a str> {
    record
        .get("labels")
        .and_then(|labels| labels.get(label))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_digest_validator_requires_canonical_lowercase_sha256() {
        assert!(is_canonical_sha256_digest(&format!(
            "sha256:{}",
            "a".repeat(64)
        )));
        assert!(!is_canonical_sha256_digest("sha256:nothex"));
        assert!(!is_canonical_sha256_digest(&format!(
            "sha256:{}",
            "A".repeat(64)
        )));
        assert!(!is_canonical_sha256_digest(&format!(
            "sha512:{}",
            "a".repeat(64)
        )));
    }
}

fn local_live_tinfoil_policy() -> VerificationPolicy {
    let mut policy = VerificationPolicy::require_hw_verified_tls();
    policy.model_binding_requirement = ModelBindingRequirement::Required;
    policy.provenance.workload_image = true;
    policy.provenance.model_artifacts = true;
    policy
}

fn local_app_e2ee_policy() -> VerificationPolicy {
    let mut policy = VerificationPolicy::require_hardware();
    policy.model_binding_requirement = ModelBindingRequirement::Required;
    policy.provenance.workload_image = true;
    policy.provenance.model_artifacts = true;
    policy
}

fn local_app_e2ee_route(base_url: &str) -> RouteDefinition {
    RouteDefinition {
        route_id: LOCAL_APP_E2EE_ROUTE_ID.into(),
        route_status: RouteLifecycle::Active,
        provider: LOCAL_APP_E2EE_PROVIDER.into(),
        provider_model: LOCAL_APP_E2EE_PROVIDER_MODEL.into(),
        evidence_family: "dstack_app_e2ee".into(),
        api_base_url: format!("{}/v1", base_url.trim_end_matches('/')),
        evidence_endpoint: format!("{}/v1/confidentiality", base_url.trim_end_matches('/')),
        adapter_version: "local-sdk-app-e2ee-demo-adapter/0.1.0".into(),
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

fn signed_local_app_e2ee_registry(
    route: RouteDefinition,
) -> Result<ProviderRegistryEnvelope, DemoError> {
    let mut models = BTreeMap::new();
    models.insert(
        LOCAL_APP_E2EE_MODEL.into(),
        RegistryModel {
            canonical_model: LOCAL_APP_E2EE_MODEL.into(),
            display_name: "GPT-OSS 120B".into(),
            family: "OpenAI GPT".into(),
            aliases: vec![LOCAL_APP_E2EE_MODEL.into(), "GPT-OSS 120B".into()],
            routes: vec![route],
        },
    );

    let payload = ProviderRegistry {
        schema: ProviderRegistry::SCHEMA.into(),
        version: "2026-07-05-local-sdk-app-e2ee-demo".into(),
        generated_at: "2026-07-05T00:00:00Z".into(),
        source_sync_run: SourceSyncRun {
            completed_at: "2026-07-05T00:00:00Z".into(),
            status: "success".into(),
            source: "confidential-demo-local-sdk-app-e2ee".into(),
        },
        models,
    };
    let signature = sign_local_artifact(&payload)?;

    Ok(ProviderRegistryEnvelope {
        schema: ProviderRegistryEnvelope::SCHEMA.into(),
        payload,
        signature,
    })
}

fn signed_local_app_e2ee_reference_values(
    route: &RouteDefinition,
    public_key_digest: &str,
) -> Result<ReferenceValuesEnvelope, DemoError> {
    let mut routes = BTreeMap::new();
    routes.insert(
        route.route_id.clone(),
        RouteReference {
            canonical_model: LOCAL_APP_E2EE_MODEL.into(),
            provider_model: LOCAL_APP_E2EE_PROVIDER_MODEL.into(),
            evidence_family: route.evidence_family.clone(),
            channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
            trust_tier: TrustTier::AppE2ee,
            accepted_cpu_tees: vec![CpuTeeKind::Tdx],
            e2ee_public_key_digest: public_key_digest.into(),
            response_signing_key_digest: None,
            tls_spki_sha256: None,
            workload_images: vec![confidential_inference_attestation::WorkloadImage {
                service: "root".into(),
                reference: LOCAL_APP_E2EE_WORKLOAD_IMAGE_REFERENCE.into(),
                digest: LOCAL_APP_E2EE_WORKLOAD_IMAGE.into(),
            }],
            workload_image_digest: LOCAL_APP_E2EE_WORKLOAD_IMAGE.into(),
            model_artifacts: vec![ArtifactDigest {
                kind: "weights".into(),
                name: LOCAL_APP_E2EE_MODEL.into(),
                digest: LOCAL_APP_E2EE_WEIGHTS.into(),
            }],
            valid_until: "2099-01-01T00:00:00Z".into(),
            valid_until_epoch_ms: 4_070_908_800_000,
        },
    );

    let mut providers = BTreeMap::new();
    providers.insert(
        LOCAL_APP_E2EE_PROVIDER.into(),
        ProviderReference {
            accepted_measurements: vec![LOCAL_APP_E2EE_MEASUREMENT.into()],
            routes,
        },
    );

    let payload = ReferenceValuesPayload {
        schema: ReferenceValuesPayload::SCHEMA.into(),
        version: "2026-07-05-local-sdk-app-e2ee-demo".into(),
        issuer: "confidential-inference-local-demo".into(),
        valid_from: "2026-07-05T00:00:00Z".into(),
        valid_until: "2099-01-01T00:00:00Z".into(),
        valid_until_epoch_ms: 4_070_908_800_000,
        revocation_epoch: 1,
        minimum_acceptable_version: "2026-07-05-local-sdk-app-e2ee-demo".into(),
        providers,
    };
    let signature = sign_local_artifact(&payload)?;

    Ok(ReferenceValuesEnvelope {
        schema: ReferenceValuesEnvelope::SCHEMA.into(),
        payload,
        signature,
    })
}

fn signed_local_compatibility_matrix(
    payload: ProviderCompatibilityMatrix,
) -> Result<ProviderCompatibilityMatrixEnvelope, DemoError> {
    let signature = sign_local_artifact(&payload)?;

    Ok(ProviderCompatibilityMatrixEnvelope {
        schema: ProviderCompatibilityMatrixEnvelope::SCHEMA.into(),
        payload,
        signature,
    })
}

fn local_app_e2ee_compatibility_matrix(
    route: &RouteDefinition,
    public_config: confidential_inference_providers::SdkAppE2eeConfig,
) -> ProviderCompatibilityMatrix {
    let mut providers = BTreeMap::new();
    providers.insert(
        LOCAL_APP_E2EE_PROVIDER.into(),
        ProviderCompatibility {
            provider: LOCAL_APP_E2EE_PROVIDER.into(),
            route_execution_status: RouteExecutionStatus::Executable,
            api_base_url: route.api_base_url.clone(),
            supported_openai_endpoints: vec![OpenAiEndpoint::ChatCompletions],
            model_listing: ModelListingBehavior::SignedRegistryOnly,
            model_id_rewrite: ModelIdRewrite::UseRouteProviderModel,
            token_parameter_rewrite: TokenParameterRewrite::PreserveMaxTokens,
            streaming: StreamingSupport::Unsupported,
            request_encryption: EncryptionRequirement::Required,
            response_decryption: EncryptionRequirement::Required,
            sdk_app_e2ee: Some(public_config),
            adapter_managed_encryption: false,
            attestation_endpoint_shape: "dstack_app_e2ee_local_demo".into(),
            required_credentials: Vec::new(),
            freshness_class: FreshnessClass::PerSession,
            cacheability_class: CacheabilityClass::PerSessionVerdict,
            expected_trust_tier: TrustTier::AppE2ee,
            model_binding_support: ModelBindingSupport::Verified,
            known_unsupported_modes: vec!["streaming".into()],
        },
    );

    ProviderCompatibilityMatrix {
        schema: ProviderCompatibilityMatrix::SCHEMA.into(),
        providers,
    }
}

struct LocalSdkAppE2eeServer {
    route: RouteDefinition,
    handle: JoinHandle<Result<(), DemoError>>,
}

impl LocalSdkAppE2eeServer {
    async fn spawn(secret_key: SdkAppE2eeSecretKey) -> Result<Self, DemoError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base_url = format!("http://{}", listener.local_addr()?);
        let route = local_app_e2ee_route(&base_url);
        let server_route = route.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await?;
                handle_local_app_e2ee_request(&mut stream, &server_route, &secret_key).await?;
            }
            Ok(())
        });

        Ok(Self { route, handle })
    }

    async fn await_shutdown(self) -> Result<(), DemoError> {
        self.handle.await.map_err(|error| {
            std::io::Error::other(format!("local SDK app-E2EE server task failed: {error}"))
        })??;
        Ok(())
    }
}

async fn handle_local_app_e2ee_request<S>(
    stream: &mut S,
    route: &RouteDefinition,
    secret_key: &SdkAppE2eeSecretKey,
) -> Result<(), DemoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_http_request(stream).await?;
    let request_text = String::from_utf8_lossy(&request);
    if !request_text.contains("authorization: Bearer local-sdk-app-e2ee-demo-key") {
        return Err("local SDK app-E2EE demo did not receive the configured bearer token".into());
    }
    let (method, path) = request_line(&request)?;
    let body = match (method, path) {
        ("GET", "/v1/confidentiality") => local_app_e2ee_evidence_body(secret_key)?,
        ("POST", "/v1/chat/completions") => {
            local_app_e2ee_encrypted_chat_body(&request, route, secret_key)?
        }
        _ => {
            let body = json!({"error": "not found"}).to_string();
            write_http_response(stream, 404, "Not Found", &body).await?;
            return Ok(());
        }
    };

    write_http_response(stream, 200, "OK", &body).await
}

fn local_app_e2ee_evidence_body(secret_key: &SdkAppE2eeSecretKey) -> Result<String, DemoError> {
    let public_key_digest = secret_key.public_config()?.public_key_digest()?;
    let app_compose = json!({
        "image": LOCAL_APP_E2EE_WORKLOAD_IMAGE_REFERENCE,
        "model": LOCAL_APP_E2EE_MODEL,
        "provider": LOCAL_APP_E2EE_PROVIDER
    })
    .to_string();
    let compose_hash = sha256_digest(app_compose.as_bytes())
        .trim_start_matches("sha256:")
        .to_owned();
    let evidence = json!({
        "model": LOCAL_APP_E2EE_PROVIDER_MODEL,
        "upstream_model": LOCAL_APP_E2EE_MODEL,
        "tee_hardware": "tdx",
        "tee_measurement": LOCAL_APP_E2EE_MEASUREMENT,
        "quote_measurements": {
            "mr_td": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "rtmr0": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "info": {
            "tcb_info": {
                "mrtd": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "rtmr0": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "app_compose": app_compose,
                "compose_hash": compose_hash
            }
        },
        "channel_binding": {
            "public_key_digest": public_key_digest,
            "request_bound": true,
            "response_bound": true
        },
        "workload_image_digest": LOCAL_APP_E2EE_WORKLOAD_IMAGE,
        "model_artifacts": [{
            "kind": "weights",
            "name": LOCAL_APP_E2EE_MODEL,
            "digest": LOCAL_APP_E2EE_WEIGHTS
        }],
        "issued_at": "2098-12-31T23:50:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "expires_at_epoch_ms": 4_070_908_800_000u64
    });

    Ok(serde_json::to_string(&evidence)?)
}

fn local_app_e2ee_encrypted_chat_body(
    request: &[u8],
    route: &RouteDefinition,
    secret_key: &SdkAppE2eeSecretKey,
) -> Result<String, DemoError> {
    let request_text = String::from_utf8_lossy(request);
    if request_text.contains(LOCAL_APP_E2EE_PROMPT) {
        return Err("SDK app-E2EE HTTP envelope leaked plaintext prompt".into());
    }
    let body = request_body(request)?;
    let request_value: Value = serde_json::from_slice(body)?;
    let provider_request = ProviderChatRequest::with_confidentiality(
        request_value,
        ProviderRequestConfidentiality::SdkEncrypted,
    );
    let (request, session) = provider_request.to_sdk_decrypted_openai_request(route, secret_key)?;
    if request.model != LOCAL_APP_E2EE_PROVIDER_MODEL {
        return Err(format!(
            "request model {} was not rewritten to provider model {}",
            request.model, LOCAL_APP_E2EE_PROVIDER_MODEL
        )
        .into());
    }
    let prompt = request.last_user_message().unwrap_or("");
    let content =
        format!("local SDK app-E2EE response for {LOCAL_APP_E2EE_PROVIDER_MODEL}: {prompt}");
    let response_plaintext = serde_json::to_vec(&json!({
        "id": "chatcmpl-local-sdk-app-e2ee-demo",
        "object": "chat.completion",
        "created": 1783209600u64,
        "model": LOCAL_APP_E2EE_PROVIDER_MODEL,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": prompt.split_whitespace().count(),
            "completion_tokens": content.split_whitespace().count(),
            "total_tokens": prompt.split_whitespace().count() + content.split_whitespace().count()
        }
    }))?;
    let response_envelope = session.encrypt_response_body(route, &response_plaintext)?;
    Ok(serde_json::to_string(&response_envelope)?)
}

fn local_tinfoil_route(base_url: &str) -> RouteDefinition {
    RouteDefinition {
        route_id: LOCAL_TINFOIL_ROUTE_ID.into(),
        route_status: RouteLifecycle::Active,
        provider: LOCAL_TINFOIL_PROVIDER.into(),
        provider_model: LOCAL_TINFOIL_MODEL.into(),
        evidence_family: "tinfoil_hw_verified_tls".into(),
        api_base_url: format!("{}/v1", base_url.trim_end_matches('/')),
        evidence_endpoint: format!(
            "{}/.well-known/tinfoil-attestation",
            base_url.trim_end_matches('/')
        ),
        adapter_version: "local-live-tinfoil-demo-adapter/0.1.0".into(),
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
        alias_confidence: AliasConfidence::Curated,
    }
}

fn signed_local_registry(route: RouteDefinition) -> Result<ProviderRegistryEnvelope, DemoError> {
    let mut models = BTreeMap::new();
    models.insert(
        LOCAL_TINFOIL_MODEL.into(),
        RegistryModel {
            canonical_model: LOCAL_TINFOIL_MODEL.into(),
            display_name: "Llama 3.3 70B".into(),
            family: "Llama".into(),
            aliases: vec![LOCAL_TINFOIL_MODEL.into(), "Llama 3.3 70B".into()],
            routes: vec![route],
        },
    );

    let payload = ProviderRegistry {
        schema: ProviderRegistry::SCHEMA.into(),
        version: "2026-07-05-local-live-tinfoil-demo".into(),
        generated_at: "2026-07-05T00:00:00Z".into(),
        source_sync_run: SourceSyncRun {
            completed_at: "2026-07-05T00:00:00Z".into(),
            status: "success".into(),
            source: "confidential-demo-local-live-tinfoil".into(),
        },
        models,
    };
    let signature = sign_local_artifact(&payload)?;

    Ok(ProviderRegistryEnvelope {
        schema: ProviderRegistryEnvelope::SCHEMA.into(),
        payload,
        signature,
    })
}

fn signed_local_reference_values(
    route: &RouteDefinition,
    spki_sha256: &str,
) -> Result<ReferenceValuesEnvelope, DemoError> {
    let payload = generate_tinfoil_live_reference_values(TinfoilLiveReferenceValuesInput {
        version: "2026-07-05-local-live-tinfoil-demo".into(),
        issuer: "confidential-inference-local-demo".into(),
        valid_from: "2026-07-05T00:00:00Z".into(),
        revocation_epoch: 1,
        minimum_acceptable_version: "2026-07-05-local-live-tinfoil-demo".into(),
        canonical_model: LOCAL_TINFOIL_MODEL.into(),
        route: route.clone(),
        verified_quote: local_verified_tinfoil_quote(spki_sha256),
        live_tls_spki_sha256: spki_sha256.into(),
    })?;
    let signature = sign_local_artifact(&payload)?;

    Ok(ReferenceValuesEnvelope {
        schema: ReferenceValuesEnvelope::SCHEMA.into(),
        payload,
        signature,
    })
}

fn local_compatibility_matrix(route: &RouteDefinition) -> ProviderCompatibilityMatrix {
    let mut providers = BTreeMap::new();
    providers.insert(
        LOCAL_TINFOIL_PROVIDER.into(),
        ProviderCompatibility {
            provider: LOCAL_TINFOIL_PROVIDER.into(),
            route_execution_status: RouteExecutionStatus::Executable,
            api_base_url: route.api_base_url.clone(),
            supported_openai_endpoints: vec![OpenAiEndpoint::ChatCompletions],
            model_listing: ModelListingBehavior::SignedRegistryOnly,
            model_id_rewrite: ModelIdRewrite::UseRouteProviderModel,
            token_parameter_rewrite: TokenParameterRewrite::PreserveMaxTokens,
            streaming: StreamingSupport::Unsupported,
            request_encryption: EncryptionRequirement::NotRequired,
            response_decryption: EncryptionRequirement::NotRequired,
            sdk_app_e2ee: None,
            adapter_managed_encryption: false,
            attestation_endpoint_shape: "tinfoil_live_tls_local_demo".into(),
            required_credentials: Vec::new(),
            freshness_class: FreshnessClass::PerSession,
            cacheability_class: CacheabilityClass::PerSessionVerdict,
            expected_trust_tier: TrustTier::HwVerifiedTls,
            model_binding_support: ModelBindingSupport::Verified,
            known_unsupported_modes: vec!["streaming".into()],
        },
    );

    ProviderCompatibilityMatrix {
        schema: ProviderCompatibilityMatrix::SCHEMA.into(),
        providers,
    }
}

fn sign_local_artifact<T: Serialize>(payload: &T) -> Result<ArtifactSignature, DemoError> {
    let key_pair = local_key_pair();
    let payload_json = canonical_json(payload)?;
    let signature = key_pair.sk.sign(payload_json.as_bytes(), None);

    Ok(ArtifactSignature {
        signer: LOCAL_ARTIFACT_SIGNER.into(),
        key_id: LOCAL_ARTIFACT_KEY_ID.into(),
        alg: "ed25519".into(),
        value: format!(
            "base64url:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref())
        ),
    })
}

fn local_trusted_signing_key() -> TrustedSigningKey {
    let key_pair = local_key_pair();
    let public_key_base64url =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_pair.pk.as_ref());

    TrustedSigningKey {
        signer: LOCAL_ARTIFACT_SIGNER.into(),
        key_id: LOCAL_ARTIFACT_KEY_ID.into(),
        public_key_base64url,
    }
}

fn local_key_pair() -> KeyPair {
    KeyPair::from_seed(Seed::new([13_u8; 32]))
}

#[derive(Clone, Debug)]

struct LocalTinfoilQuoteVerifier {
    spki_sha256: String,
}

impl TinfoilQuoteVerifier for LocalTinfoilQuoteVerifier {
    fn verify_tinfoil_quote(
        &self,
        request: &TinfoilQuoteVerificationRequest<'_>,
    ) -> confidential_inference_attestation::Result<VerifiedTinfoilQuote> {
        if request.attestation_format != TinfoilAttestationFormat::TdxGuestV2 {
            return Err(AttestationError::InvalidEvidence(format!(
                "local demo expected TDX quote, got {}",
                request.attestation_format.quote_kind()
            )));
        }
        if request.quote_bytes != LOCAL_TINFOIL_QUOTE_BYTES {
            return Err(AttestationError::InvalidEvidence(
                "local demo quote bytes did not match the signed local route".into(),
            ));
        }
        if request.live_tls_spki_sha256 != self.spki_sha256 {
            return Err(AttestationError::InvalidEvidence(
                "local demo TLS SPKI did not match the verified quote input".into(),
            ));
        }

        Ok(local_verified_tinfoil_quote(&self.spki_sha256))
    }
}

fn local_verified_tinfoil_quote(spki_sha256: &str) -> VerifiedTinfoilQuote {
    let mut quote = VerifiedTinfoilQuote::from_verified_quote(
        TinfoilAttestationFormat::TdxGuestV2,
        EvidenceHardware {
            cpu: CpuTeeKind::Tdx,
            gpu: None,
        },
        LOCAL_TINFOIL_MEASUREMENT,
        format!("{}{}", spki_sha256, "00".repeat(32)),
        "2098-12-31T23:50:00Z",
        "2099-01-01T00:00:00Z",
        4_070_908_800_000,
    );
    quote.attested_model = Some(LOCAL_TINFOIL_MODEL.into());
    quote.workload_image_digest = Some(LOCAL_TINFOIL_WORKLOAD_IMAGE.into());
    quote.model_artifacts = vec![ArtifactDigest {
        kind: "weights".into(),
        name: LOCAL_TINFOIL_MODEL.into(),
        digest: LOCAL_TINFOIL_WEIGHTS.into(),
    }];
    quote
}

struct LocalTinfoilServer {
    base_url: String,
    spki_sha256: String,
    handle: JoinHandle<Result<(), DemoError>>,
}

impl LocalTinfoilServer {
    async fn spawn() -> Result<Self, DemoError> {
        install_default_rustls_provider();
        let cert_der = decode_base64(LOCAL_TINFOIL_CERT_DER_BASE64)?;
        let key_der = decode_base64(LOCAL_TINFOIL_KEY_DER_BASE64)?;
        let spki_sha256 = certificate_spki_sha256_hex(&cert_der)?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der)],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der)),
            )?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let base_url = format!("https://{address}");

        let handle = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await?;
                let mut stream = acceptor.accept(stream).await?;
                handle_local_tinfoil_request(&mut stream).await?;
            }
            Ok(())
        });

        Ok(Self {
            base_url,
            spki_sha256,
            handle,
        })
    }

    async fn await_shutdown(self) -> Result<(), DemoError> {
        self.handle.await.map_err(|error| {
            std::io::Error::other(format!("local Tinfoil server task failed: {error}"))
        })??;
        Ok(())
    }
}

async fn handle_local_tinfoil_request<S>(stream: &mut S) -> Result<(), DemoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_http_request(stream).await?;
    let (method, path) = request_line(&request)?;
    let body = match (method, path) {
        ("GET", "/.well-known/tinfoil-attestation") => local_tinfoil_attestation_body()?,
        ("POST", "/v1/chat/completions") => local_tinfoil_chat_body(&request)?,
        _ => {
            let body = json!({"error": "not found"}).to_string();
            write_http_response(stream, 404, "Not Found", &body).await?;
            return Ok(());
        }
    };

    write_http_response(stream, 200, "OK", &body).await
}

async fn read_http_request<S>(stream: &mut S) -> Result<Vec<u8>, DemoError>
where
    S: AsyncRead + Unpin,
{
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request_complete(&request) {
            break;
        }
    }
    Ok(request)
}

fn request_line(request: &[u8]) -> Result<(&str, &str), DemoError> {
    let header_end = header_end(request).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP request headers are incomplete",
        )
    })?;
    let headers = std::str::from_utf8(&request[..header_end])?;
    let line = headers.lines().next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP request line is missing",
        )
    })?;
    let mut fields = line.split_whitespace();
    let method = fields.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "HTTP method is missing")
    })?;
    let path = fields.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "HTTP path is missing")
    })?;
    Ok((method, path))
}

fn local_tinfoil_attestation_body() -> Result<String, DemoError> {
    let attestation_doc = TinfoilAttestationDoc {
        format: TINFOIL_TDX_GUEST_V2_FORMAT.into(),
        body: gzip_base64(&LOCAL_TINFOIL_QUOTE_BYTES)?,
    };
    Ok(serde_json::to_string(&attestation_doc)?)
}

fn local_tinfoil_chat_body(request: &[u8]) -> Result<String, DemoError> {
    let body = request_body(request)?;
    let request: Value = serde_json::from_slice(body)?;
    let model = request
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or(LOCAL_TINFOIL_MODEL);
    let prompt = request
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| {
            messages
                .iter()
                .rev()
                .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))
        })
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let content = format!("local live Tinfoil response for {model}: {prompt}");
    Ok(json!({
        "id": "chatcmpl-local-live-tinfoil-demo",
        "object": "chat.completion",
        "created": 1783209600u64,
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": prompt.split_whitespace().count(),
            "completion_tokens": content.split_whitespace().count(),
            "total_tokens": prompt.split_whitespace().count() + content.split_whitespace().count()
        }
    })
    .to_string())
}

async fn write_http_response<S>(
    stream: &mut S,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<(), DemoError>
where
    S: AsyncWrite + Unpin,
{
    write_http_response_with_headers(stream, status, reason, body, &[]).await
}

async fn write_http_response_with_headers<S>(
    stream: &mut S,
    status: u16,
    reason: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> Result<(), DemoError>
where
    S: AsyncWrite + Unpin,
{
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    let mut response = response;
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    response.push_str(body);
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

fn request_complete(request: &[u8]) -> bool {
    let Some(header_end) = header_end(request) else {
        return false;
    };
    let content_length = content_length(&request[..header_end]).unwrap_or(0);
    request.len() >= header_end + content_length
}

fn request_body(request: &[u8]) -> Result<&[u8], DemoError> {
    let header_end = header_end(request).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP request headers are incomplete",
        )
    })?;
    Ok(&request[header_end..])
}

fn header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn content_length(headers: &[u8]) -> Option<usize> {
    let headers = std::str::from_utf8(headers).ok()?;
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    })
}

fn gzip_base64(bytes: &[u8]) -> Result<String, DemoError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(encoder.finish()?))
}

fn decode_base64(value: &str) -> Result<Vec<u8>, DemoError> {
    Ok(base64::engine::general_purpose::STANDARD.decode(value)?)
}

fn install_default_rustls_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
