//! Blocking and stream-handle C ABI for `confidential-inference-sdk`.
//!
//! Complex request and response payloads cross the ABI as JSON. Provider
//! routing, request adaptation, attestation, and verdict enforcement remain in
//! `confidential-inference-sdk` and lower crates.

use confidential_inference_sdk::{
    ChatCompletionRequestPayload, ClientError, ConfidentialInference, EmbeddingsRequestPayload,
    EnforcementMode, ProviderCompatibilityMatrixEnvelope, ProviderRegistryEnvelope,
    ProviderRoutingConfig, ReferenceValuesEnvelope, ResponseCreateRequestPayload, ResponseManageOp,
    ResponseManageRequest, TrustedSigningKey, VerificationPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::env;
use std::ffi::{c_char, c_int, CStr, CString};
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;
use tokio::runtime::{Handle, Runtime};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

pub const CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION: u32 = 1;
pub const CONFIDENTIAL_INFERENCE_FFI_OK: c_int = 0;
pub const CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT: c_int = 1;
pub const CONFIDENTIAL_INFERENCE_FFI_PANIC: c_int = 2;
pub const CONFIDENTIAL_INFERENCE_FFI_BUSY: c_int = 3;
pub const CONFIDENTIAL_INFERENCE_FFI_PENDING: c_int = 4;
pub const CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED: c_int = 5;
pub const CONFIDENTIAL_INFERENCE_FFI_INTERNAL: c_int = 6;
/// An SDK operation (chat, response, verify) failed. The error envelope's
/// `dispatch` says whether the provider may have processed the request.
pub const CONFIDENTIAL_INFERENCE_FFI_OPERATION_FAILED: c_int = 7;

thread_local! {
    static LAST_ERROR: RefCell<Option<FfiErrorJson>> = const { RefCell::new(None) };
}

/// Most recent error for the calling thread.
fn take_last_error() -> Option<FfiErrorJson> {
    LAST_ERROR.with(|slot| slot.borrow().clone())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FfiErrorJson {
    code: &'static str,
    message: String,
    /// `not_dispatched`, `rejected` or `unknown` for operation failures.
    dispatch: Option<&'static str>,
    /// Provider HTTP status for `rejected` operation failures.
    http_status: Option<u16>,
}

/// A failed SDK operation with its dispatch classification.
struct FfiOperationError {
    code: &'static str,
    message: String,
    dispatch: &'static str,
    http_status: Option<u16>,
}

impl FfiOperationError {
    fn not_dispatched(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            dispatch: "not_dispatched",
            http_status: None,
        }
    }
}

impl From<ClientError> for FfiOperationError {
    fn from(error: ClientError) -> Self {
        Self {
            code: error.code(),
            dispatch: error.dispatch_outcome().as_str(),
            http_status: error.provider_http_status(),
            message: error.to_string(),
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    #[serde(default)]
    demo_provider: bool,
    #[serde(default)]
    allow_inline_api_keys: bool,
    #[serde(default)]
    api_keys: BTreeMap<String, ApiKeyConfig>,
    #[serde(default)]
    routing: ProviderRoutingConfig,
    #[serde(default)]
    trusted_ed25519_signing_keys: Vec<TrustedEd25519SigningKeyConfig>,
    #[serde(default)]
    registry: Option<ProviderRegistryEnvelope>,
    #[serde(default)]
    reference_values: Option<ReferenceValuesEnvelope>,
    #[serde(default)]
    compatibility_matrix: Option<ProviderCompatibilityMatrixEnvelope>,
    /// Operator-chosen verification policy; only with an operator trust root.
    #[serde(default)]
    policy: Option<VerificationPolicy>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedEd25519SigningKeyConfig {
    signer: String,
    key_id: String,
    public_key_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiKeyConfig {
    #[serde(default)]
    env: Option<String>,
    #[serde(default)]
    inline: Option<Zeroizing<String>>,
}

fn resolve_trusted_signing_keys(
    config: &ClientConfig,
) -> Result<Vec<TrustedSigningKey>, ConfigError> {
    if config.demo_provider && !config.trusted_ed25519_signing_keys.is_empty() {
        return Err(ConfigError {
            code: "trusted_signing_keys_ambiguous",
            message: "trusted_ed25519_signing_keys cannot be combined with demo_provider=true; set demo_provider=false to configure an exclusive operator trust root".to_owned(),
        });
    }
    if !config.demo_provider && config.trusted_ed25519_signing_keys.is_empty() {
        return Err(ConfigError {
            code: "trusted_signing_keys_required",
            message: "demo_provider=false requires a non-empty trusted_ed25519_signing_keys list; the bundled fixture keys are only trusted by the demo provider".to_owned(),
        });
    }
    let mut keys = Vec::with_capacity(config.trusted_ed25519_signing_keys.len());
    for key in &config.trusted_ed25519_signing_keys {
        if key.signer.trim().is_empty()
            || key.key_id.trim().is_empty()
            || key.public_key_base64url.trim().is_empty()
        {
            return Err(ConfigError {
                code: "trusted_signing_key_field_empty",
                message:
                    "trusted_ed25519_signing_keys entries require non-empty signer, key_id, and public_key_base64url"
                        .to_owned(),
            });
        }
        keys.push(TrustedSigningKey::new(
            key.signer.clone(),
            key.key_id.clone(),
            key.public_key_base64url.clone(),
        ));
    }
    Ok(keys)
}

fn validate_trust_artifact_config(config: &ClientConfig) -> Result<(), ConfigError> {
    if config.demo_provider
        && (config.registry.is_some()
            || config.reference_values.is_some()
            || config.compatibility_matrix.is_some())
    {
        return Err(ConfigError {
            code: "trust_artifacts_ambiguous",
            message: "registry, reference_values, and compatibility_matrix cannot be combined with demo_provider=true"
                .to_owned(),
        });
    }
    if config.compatibility_matrix.is_some() && config.trusted_ed25519_signing_keys.is_empty() {
        return Err(ConfigError {
            code: "compatibility_matrix_trust_keys_required",
            message: "compatibility_matrix requires trusted_ed25519_signing_keys".to_owned(),
        });
    }
    if let Some(policy) = &config.policy {
        if config.demo_provider {
            return Err(ConfigError {
                code: "policy_requires_operator_trust",
                message: "policy cannot be combined with demo_provider=true".to_owned(),
            });
        }
        // The FFI exposes no insecure-mode opt-in, so only enforcing policies are accepted.
        if policy.enforcement != EnforcementMode::Enforce {
            return Err(ConfigError {
                code: "policy_enforcement_must_be_enforce",
                message: format!(
                    "policy enforcement must be enforce, got {:?}",
                    policy.enforcement
                ),
            });
        }
    }
    if config.registry.is_some() != config.reference_values.is_some() {
        return Err(ConfigError {
            code: "trust_artifact_pair_required",
            message: "registry and reference_values must be provided together".to_owned(),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfigError {
    code: &'static str,
    message: String,
}

fn resolve_api_keys(
    config: ClientConfig,
) -> Result<BTreeMap<String, Zeroizing<String>>, ConfigError> {
    let mut api_keys = BTreeMap::new();
    for (provider, api_key) in config.api_keys {
        if provider.trim().is_empty() {
            return Err(ConfigError {
                code: "credential_provider_empty",
                message: "api_keys provider id must not be empty".to_owned(),
            });
        }
        let env_source = api_key.env;
        let inline_source = api_key.inline;
        if env_source.is_some() && inline_source.is_some() {
            return Err(ConfigError {
                code: "credential_source_ambiguous",
                message: format!(
                    "api key for provider {provider} must use either env or inline, not both"
                ),
            });
        }
        if let Some(inline) = inline_source {
            if !config.allow_inline_api_keys {
                return Err(ConfigError {
                    code: "inline_credentials_not_allowed",
                    message: format!(
                        "inline API key for provider {provider} requires allow_inline_api_keys=true"
                    ),
                });
            }
            if inline.is_empty() {
                return Err(ConfigError {
                    code: "credential_inline_empty_value",
                    message: format!("inline API key for provider {provider} must not be empty"),
                });
            }
            api_keys.insert(provider, inline);
            continue;
        }
        let Some(env_name) = env_source else {
            return Err(ConfigError {
                code: "credential_source_missing",
                message: format!("api key for provider {provider} must specify env or inline"),
            });
        };
        let env_name = env_name.trim();
        if env_name.is_empty() {
            return Err(ConfigError {
                code: "credential_env_empty",
                message: format!(
                    "api key environment variable for provider {provider} must not be empty"
                ),
            });
        }
        let value = match env::var(env_name) {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => {
                return Err(ConfigError {
                    code: "credential_env_missing",
                    message: format!(
                        "api key environment variable {env_name} for provider {provider} is not set"
                    ),
                });
            }
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ConfigError {
                    code: "credential_env_invalid",
                    message: format!(
                        "api key environment variable {env_name} for provider {provider} is not valid Unicode"
                    ),
                });
            }
        };
        if value.is_empty() {
            return Err(ConfigError {
                code: "credential_env_empty_value",
                message: format!(
                    "api key environment variable {env_name} for provider {provider} is empty"
                ),
            });
        }
        api_keys.insert(provider, Zeroizing::new(value));
    }
    Ok(api_keys)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    provider: String,
    model: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseManageEnvelope {
    op: ResponseManageOp,
    provider: String,
    provider_response_id: String,
    params: serde_json::Value,
}
pub struct ConfidentialInferenceFfiClient {
    shared: Arc<ClientShared>,
    owner_pid: u32,
}

struct ClientShared {
    runtime: Runtime,
    client: ConfidentialInference,
    live_operations: AtomicUsize,
}

pub struct ConfidentialInferenceFfiStream {
    shared: Arc<ClientShared>,
    owner_pid: u32,
    state: Arc<(Mutex<StreamState>, Condvar)>,
    join: Arc<Mutex<Option<JoinHandle<()>>>>,
}

fn live_client_handles() -> &'static Mutex<HashSet<usize>> {
    static HANDLES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn live_stream_handles() -> &'static Mutex<HashSet<usize>> {
    static HANDLES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn live_string_handles() -> &'static Mutex<HashSet<usize>> {
    static HANDLES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn pointer_key<T>(ptr: *const T) -> usize {
    ptr as usize
}

fn register_handle<T>(handles: &'static Mutex<HashSet<usize>>, ptr: *mut T) {
    if let Ok(mut handles) = handles.lock() {
        handles.insert(pointer_key(ptr));
    }
}

fn unregister_handle<T>(handles: &'static Mutex<HashSet<usize>>, ptr: *mut T) -> bool {
    !ptr.is_null()
        && handles
            .lock()
            .map(|mut handles| handles.remove(&pointer_key(ptr)))
            .unwrap_or(false)
}

#[derive(Debug)]
struct StreamState {
    events: VecDeque<String>,
    terminal: bool,
}

impl StreamState {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            terminal: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FfiStatus {
    pub abi_version: u32,
    pub stream_handle_abi_available: bool,
    pub blocking_helpers_available: bool,
    pub reason: &'static str,
}

pub fn status() -> FfiStatus {
    FfiStatus {
        abi_version: CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION,
        stream_handle_abi_available: true,
        blocking_helpers_available: true,
        reason: "chat, Responses creation and lifecycle management, verify, model discovery, confidentiality catalog, active policy, active trust artifacts, stream handles, and blocking helper wrappers are available; current stream execution preserves SDK fail-closed streaming semantics",
    }
}

#[no_mangle]
/// Returns the loaded FFI capability status as a newly allocated JSON string.
///
/// # Safety
///
/// `out_status_json` must be a valid writable pointer. The returned string must
/// be freed with `confidential_inference_string_free`.
pub unsafe extern "C" fn confidential_inference_status(out_status_json: *mut *mut c_char) -> c_int {
    ffi_boundary(|| match serde_json::to_string(&status()) {
        Ok(status_json) => write_c_string(out_status_json, status_json),
        Err(error) => ffi_error(
            CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
            "status_serialization_failed",
            &format!("failed to serialize FFI status JSON: {error}"),
        ),
    })
}

#[no_mangle]
/// Creates an SDK client handle from optional JSON configuration.
///
/// # Safety
///
/// `out_client` must be a valid writable pointer to a client-handle slot.
/// `config_json`, when non-null, must point to a valid NUL-terminated UTF-8 C
/// string for the duration of the call.
pub unsafe extern "C" fn confidential_inference_sdk_new(
    config_json: *const c_char,
    out_client: *mut *mut ConfidentialInferenceFfiClient,
) -> c_int {
    ffi_boundary(|| unsafe {
        if out_client.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_client must not be null",
            );
        }
        *out_client = ptr::null_mut();

        let config = match optional_json_config(config_json) {
            Ok(config) => config,
            Err(message) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    "invalid_config_json",
                    &message,
                );
            }
        };

        let runtime = match Runtime::new() {
            Ok(runtime) => runtime,
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "runtime_create_failed",
                    &format!("failed to create Tokio runtime: {error}"),
                );
            }
        };

        if let Err(error) = validate_trust_artifact_config(&config) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                error.code,
                &error.message,
            );
        }
        let trusted_signing_keys = match resolve_trusted_signing_keys(&config) {
            Ok(keys) => keys,
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    error.code,
                    &error.message,
                );
            }
        };
        let compatibility_matrix = match config.compatibility_matrix.clone() {
            Some(envelope) => match envelope.into_verified_payload_with_keys(&trusted_signing_keys)
            {
                Ok(matrix) => Some(matrix),
                Err(error) => {
                    let (code, message) =
                        if error.to_string().contains("unknown artifact signing key") {
                            ("compatibility_matrix_untrusted_signer", error.to_string())
                        } else {
                            ("compatibility_matrix_tampered", error.to_string())
                        };
                    return ffi_error(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, code, &message);
                }
            },
            None => None,
        };
        let registry = config.registry.clone();
        let reference_values = config.reference_values.clone();
        let provider_routing = config.routing.clone();
        let mut builder = ConfidentialInference::builder().provider_routing(provider_routing);
        if config.demo_provider {
            builder = builder.with_demo_provider();
        } else {
            builder = builder.exclusive_trusted_artifact_signing_keys(trusted_signing_keys);
            if let (Some(registry), Some(reference_values)) = (registry, reference_values) {
                builder = builder
                    .registry(registry)
                    .reference_values(reference_values);
            }
        }
        if let Some(compatibility_matrix) = compatibility_matrix {
            builder = builder.compatibility_matrix(compatibility_matrix);
        }
        if let Some(policy) = config.policy.clone() {
            builder = builder.policy(policy);
        }
        for (provider, api_key) in match resolve_api_keys(config) {
            Ok(api_keys) => api_keys,
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    error.code,
                    &error.message,
                );
            }
        } {
            builder = builder.api_key(provider, api_key.as_str());
        }
        let client = match runtime.block_on(builder.build()) {
            Ok(client) => client,
            Err(error @ ClientError::InvalidProviderRouting { .. }) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    "invalid_provider_routing",
                    &error.to_string(),
                );
            }
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "client_build_failed",
                    &format!("failed to build ConfidentialInference client: {error}"),
                );
            }
        };

        let handle = Box::new(ConfidentialInferenceFfiClient {
            shared: Arc::new(ClientShared {
                runtime,
                client,
                live_operations: AtomicUsize::new(0),
            }),
            owner_pid: process::id(),
        });
        let handle = Box::into_raw(handle);
        register_handle(live_client_handles(), handle);
        *out_client = handle;
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}
/// Fork guard: a client created before fork() must never be used in the
/// child — its Tokio runtime threads do not survive the fork.
unsafe fn client_fork_error(client: *mut ConfidentialInferenceFfiClient) -> Option<c_int> {
    if !client.is_null() && (*client).owner_pid != process::id() {
        return Some(ffi_error(
            CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
            "client_used_after_fork",
            "client was created before fork(); create a new client in the child process",
        ));
    }
    None
}

/// Fork guard for stream handles (same owner pid as the spawning client).
unsafe fn stream_fork_error(stream: *mut ConfidentialInferenceFfiStream) -> Option<c_int> {
    if !stream.is_null() && (*stream).owner_pid != process::id() {
        return Some(ffi_error(
            CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
            "client_used_after_fork",
            "stream was created before fork(); create a new client in the child process",
        ));
    }
    None
}

#[no_mangle]
/// Frees a client handle. Blocking calls are not counted: they hold `Arc`
/// clones of the client's shared state, so freeing stays memory-safe while
/// they run — `CONFIDENTIAL_INFERENCE_FFI_BUSY` applies to live streams only.
///
/// # Safety
///
/// `client` must be null or a handle returned by `confidential_inference_sdk_new` that has
/// not already been freed. If live streams reference the client, this function returns
/// `CONFIDENTIAL_INFERENCE_FFI_BUSY` and leaves ownership with the caller. In a
/// forked child process this releases the handle and leaks the runtime
/// (dropping it would hang); create clients after fork.
pub unsafe extern "C" fn confidential_inference_sdk_free(
    client: *mut ConfidentialInferenceFfiClient,
) -> c_int {
    ffi_boundary(|| unsafe {
        if client.is_null() {
            clear_last_error();
            return CONFIDENTIAL_INFERENCE_FFI_OK;
        }
        // Hold the handle-registry lock from the liveness check through the
        // handle removal: `client_shared` dereferences the handle only under
        // the same lock, so no accessor can race the drop below.
        let Ok(mut handles) = live_client_handles().lock() else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                "handle_registry_poisoned",
                "client handle registry lock is poisoned",
            );
        };
        if !handles.contains(&pointer_key(client)) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client handle is not live or was already freed",
            );
        }

        let client_ref = &*client;
        if client_ref.owner_pid != process::id() {
            // Forked child: dropping the runtime here hangs (worker threads did
            // not survive the fork). Release the handle and leak instead —
            // the child's address space dies with it anyway.
            handles.remove(&pointer_key(client));
            drop(handles);
            std::mem::forget(Box::from_raw(client));
            clear_last_error();
            return CONFIDENTIAL_INFERENCE_FFI_OK;
        }
        let live_operations = client_ref.shared.live_operations.load(Ordering::SeqCst);
        if live_operations > 0 {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_BUSY,
                "client_busy",
                "client still has live operations",
            );
        }
        if in_tokio_runtime_context() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_BUSY,
                "runtime_teardown_from_runtime_context",
                "client runtime cannot be freed from a Tokio runtime context",
            );
        }

        handles.remove(&pointer_key(client));
        drop(handles);
        drop(Box::from_raw(client));
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Runs a chat operation synchronously and returns a newly allocated JSON string.
///
/// # Safety
///
/// `client` must be a valid live client handle. `request_json` must point to a
/// valid NUL-terminated UTF-8 C string for the duration of the call.
/// `out_response_json` must be a valid writable pointer. The returned string
/// must be freed with `confidential_inference_string_free`. A `timeout_ms` of zero waits
/// without a timeout.
pub unsafe extern "C" fn confidential_inference_chat_blocking(
    client: *mut ConfidentialInferenceFfiClient,
    request_json: *const c_char,
    timeout_ms: u64,
    out_response_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary_with_error(out_response_json, || unsafe {
        if let Some(code) = client_fork_error(client) {
            return code;
        }
        let Some(shared) = client_shared(client) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client must not be null",
            );
        };
        let request_json = match required_c_string(request_json, "request_json") {
            Ok(value) => value,
            Err(message) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    "invalid_argument",
                    &message,
                );
            }
        };
        if out_response_json.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_response_json must not be null",
            );
        }
        *out_response_json = ptr::null_mut();

        let request = match parse_chat_request(&request_json, "chat") {
            Ok(request) => request,
            Err(code) => return code,
        };

        let response_json = match run_blocking_result_json(shared, timeout_ms, move || async move {
            chat_result_json(request).await
        }) {
            Ok(response_json) => response_json,
            Err(code) => return code,
        };
        write_c_string(out_response_json, response_json)
    })
}

#[no_mangle]
/// Runs a Responses lifecycle operation synchronously and returns its confidential response JSON.
///
/// # Safety
///
/// `client` must be a valid live client handle. `request_json` must point to a
/// valid NUL-terminated UTF-8 C string for the duration of the call.
/// `out_response_json` must be a valid writable pointer. The returned string
/// must be freed with `confidential_inference_string_free`. A `timeout_ms` of zero waits
/// without a timeout.
pub unsafe extern "C" fn confidential_inference_response_manage_blocking(
    client: *mut ConfidentialInferenceFfiClient,
    request_json: *const c_char,
    timeout_ms: u64,
    out_response_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary_with_error(out_response_json, || unsafe {
        if let Some(code) = client_fork_error(client) {
            return code;
        }
        let Some(shared) = client_shared(client) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client must not be null",
            );
        };
        let request_json = match required_c_string(request_json, "request_json") {
            Ok(value) => value,
            Err(message) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    "invalid_argument",
                    &message,
                );
            }
        };
        if out_response_json.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_response_json must not be null",
            );
        }
        *out_response_json = ptr::null_mut();

        let request = match parse_response_manage_request(&request_json) {
            Ok(request) => request,
            Err(code) => return code,
        };
        let response_json = match run_blocking_result_json(shared, timeout_ms, move || async move {
            response_manage_result_json(request).await
        }) {
            Ok(response_json) => response_json,
            Err(code) => return code,
        };
        write_c_string(out_response_json, response_json)
    })
}
#[no_mangle]
/// Runs a Responses API operation synchronously and returns a newly allocated JSON string.
///
/// # Safety
///
/// `client` must be a valid live client handle. `request_json` must point to a
/// valid NUL-terminated UTF-8 C string for the duration of the call.
/// `out_response_json` must be a valid writable pointer. The returned string
/// must be freed with `confidential_inference_string_free`. A `timeout_ms` of zero waits
/// without a timeout.
pub unsafe extern "C" fn confidential_inference_response_blocking(
    client: *mut ConfidentialInferenceFfiClient,
    request_json: *const c_char,
    timeout_ms: u64,
    out_response_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary_with_error(out_response_json, || unsafe {
        if let Some(code) = client_fork_error(client) {
            return code;
        }
        let Some(shared) = client_shared(client) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client must not be null",
            );
        };
        let request_json = match required_c_string(request_json, "request_json") {
            Ok(value) => value,
            Err(message) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    "invalid_argument",
                    &message,
                );
            }
        };
        if out_response_json.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_response_json must not be null",
            );
        }
        *out_response_json = ptr::null_mut();

        let request = match parse_response_request(&request_json, "response") {
            Ok(request) => request,
            Err(code) => return code,
        };

        let response_json = match run_blocking_result_json(shared, timeout_ms, move || async move {
            response_result_json(request).await
        }) {
            Ok(response_json) => response_json,
            Err(code) => return code,
        };
        write_c_string(out_response_json, response_json)
    })
}

#[no_mangle]
/// Runs an embeddings operation synchronously and returns a newly allocated JSON string.
///
/// # Safety
///
/// `client` must be a valid live client handle. `request_json` must point to a
/// valid NUL-terminated UTF-8 C string for the duration of the call.
/// `out_response_json` must be a valid writable pointer. The returned string
/// must be freed with `confidential_inference_string_free`. A `timeout_ms` of zero waits
/// without a timeout.
pub unsafe extern "C" fn confidential_inference_embeddings_blocking(
    client: *mut ConfidentialInferenceFfiClient,
    request_json: *const c_char,
    timeout_ms: u64,
    out_response_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary_with_error(out_response_json, || unsafe {
        if let Some(code) = client_fork_error(client) {
            return code;
        }
        let Some(shared) = client_shared(client) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client must not be null",
            );
        };
        let request_json = match required_c_string(request_json, "request_json") {
            Ok(value) => value,
            Err(message) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    "invalid_argument",
                    &message,
                );
            }
        };
        if out_response_json.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_response_json must not be null",
            );
        }
        *out_response_json = ptr::null_mut();

        let request = match parse_embeddings_request(&request_json, "embeddings") {
            Ok(request) => request,
            Err(code) => return code,
        };

        let response_json = match run_blocking_result_json(shared, timeout_ms, move || async move {
            embeddings_result_json(request).await
        }) {
            Ok(response_json) => response_json,
            Err(code) => return code,
        };
        write_c_string(out_response_json, response_json)
    })
}

#[no_mangle]
/// Runs a route verification operation synchronously.
///
/// # Safety
///
/// `client` must be a valid live client handle. `request_json` must point to a
/// valid NUL-terminated UTF-8 C string containing
/// `{"provider":"...","model":"..."}` for the duration of the call.
/// `out_verdict_json` must be a valid writable pointer. The returned string
/// must be freed with `confidential_inference_string_free`. A `timeout_ms` of zero waits
/// without a timeout.
pub unsafe extern "C" fn confidential_inference_verify_blocking(
    client: *mut ConfidentialInferenceFfiClient,
    request_json: *const c_char,
    timeout_ms: u64,
    out_verdict_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary_with_error(out_verdict_json, || unsafe {
        if let Some(code) = client_fork_error(client) {
            return code;
        }
        let Some(shared) = client_shared(client) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client must not be null",
            );
        };
        let request_json = match required_c_string(request_json, "request_json") {
            Ok(value) => value,
            Err(message) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    "invalid_argument",
                    &message,
                );
            }
        };
        if out_verdict_json.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_verdict_json must not be null",
            );
        }
        *out_verdict_json = ptr::null_mut();

        let request = match parse_verify_request(&request_json, "verify") {
            Ok(request) => request,
            Err(code) => return code,
        };

        let verdict_json = match run_blocking_result_json(shared, timeout_ms, move || async move {
            verify_result_json(request).await
        }) {
            Ok(verdict_json) => verdict_json,
            Err(code) => return code,
        };
        write_c_string(out_verdict_json, verdict_json)
    })
}

#[no_mangle]
/// Returns OpenAI-shaped model discovery JSON from the active SDK client.
///
/// # Safety
///
/// `client` must be a valid live client handle. `out_models_json` must be a
/// valid writable pointer. The returned string must be freed with
/// `confidential_inference_string_free`.
pub unsafe extern "C" fn confidential_inference_models_blocking(
    client: *mut ConfidentialInferenceFfiClient,
    out_models_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary_with_error(out_models_json, || unsafe {
        if let Some(code) = client_fork_error(client) {
            return code;
        }
        let Some(shared) = client_shared(client) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client must not be null",
            );
        };
        if out_models_json.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_models_json must not be null",
            );
        }
        *out_models_json = ptr::null_mut();

        let models_json = match serde_json::to_string(&shared.client.models()) {
            Ok(json) => json,
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "models_serialization_failed",
                    &format!("failed to serialize model discovery JSON: {error}"),
                );
            }
        };
        write_c_string(out_models_json, models_json)
    })
}

#[no_mangle]
/// Returns confidential route catalog JSON from the active SDK client.
///
/// # Safety
///
/// `client` must be a valid live client handle. `out_catalog_json` must be a
/// valid writable pointer. The returned string must be freed with
/// `confidential_inference_string_free`.
pub unsafe extern "C" fn confidential_inference_confidentiality_blocking(
    client: *mut ConfidentialInferenceFfiClient,
    out_catalog_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary_with_error(out_catalog_json, || unsafe {
        if let Some(code) = client_fork_error(client) {
            return code;
        }
        let Some(shared) = client_shared(client) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client must not be null",
            );
        };
        if out_catalog_json.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_catalog_json must not be null",
            );
        }
        *out_catalog_json = ptr::null_mut();

        let catalog_json = match serde_json::to_string(&shared.client.confidential_models()) {
            Ok(json) => json,
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "confidentiality_serialization_failed",
                    &format!("failed to serialize confidentiality catalog JSON: {error}"),
                );
            }
        };
        write_c_string(out_catalog_json, catalog_json)
    })
}

#[no_mangle]
/// Returns active verification policy JSON and its SDK-computed digest.
///
/// # Safety
///
/// `client` must be a valid live client handle. `out_policy_json` must be a
/// valid writable pointer. The returned string must be freed with
/// `confidential_inference_string_free`.
pub unsafe extern "C" fn confidential_inference_active_policy_blocking(
    client: *mut ConfidentialInferenceFfiClient,
    out_policy_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary_with_error(out_policy_json, || unsafe {
        if let Some(code) = client_fork_error(client) {
            return code;
        }
        let Some(shared) = client_shared(client) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client must not be null",
            );
        };
        if out_policy_json.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_policy_json must not be null",
            );
        }
        *out_policy_json = ptr::null_mut();

        let snapshot = match shared.client.active_policy() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "active_policy_digest_failed",
                    &format!("failed to compute active policy digest: {error}"),
                );
            }
        };
        let policy_json = match serde_json::to_string(&snapshot) {
            Ok(json) => json,
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "active_policy_serialization_failed",
                    &format!("failed to serialize active policy JSON: {error}"),
                );
            }
        };
        write_c_string(out_policy_json, policy_json)
    })
}

#[no_mangle]
/// Returns active signed registry/reference artifact JSON from the SDK client.
///
/// # Safety
///
/// `client` must be a valid live client handle. `out_artifacts_json` must be a
/// valid writable pointer. The returned string must be freed with
/// `confidential_inference_string_free`.
pub unsafe extern "C" fn confidential_inference_active_trust_artifacts_blocking(
    client: *mut ConfidentialInferenceFfiClient,
    out_artifacts_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary_with_error(out_artifacts_json, || unsafe {
        if let Some(code) = client_fork_error(client) {
            return code;
        }
        let Some(shared) = client_shared(client) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client must not be null",
            );
        };
        if out_artifacts_json.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_artifacts_json must not be null",
            );
        }
        *out_artifacts_json = ptr::null_mut();

        let artifacts_json = match serde_json::to_string(&shared.client.active_trust_artifacts()) {
            Ok(json) => json,
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "active_trust_artifacts_serialization_failed",
                    &format!("failed to serialize active trust artifacts JSON: {error}"),
                );
            }
        };
        write_c_string(out_artifacts_json, artifacts_json)
    })
}

#[no_mangle]
/// Starts a chat stream handle from OpenAI-shaped request JSON. Streaming fails
/// closed unless the SDK verifies route evidence before returning the stream.
/// Events contain a first `verdict`, normalized OpenAI JSON `chunk` events,
/// optional terminal `usage`, and `done` (or an error event).
///
/// # Safety
///
/// `client` must be a valid live client handle. `request_json` must point to a
/// valid NUL-terminated UTF-8 C string for the duration of the call.
/// `out_stream` must be a valid writable pointer to a stream-handle slot.
pub unsafe extern "C" fn confidential_inference_chat_stream_start(
    client: *mut ConfidentialInferenceFfiClient,
    request_json: *const c_char,
    out_stream: *mut *mut ConfidentialInferenceFfiStream,
) -> c_int {
    ffi_boundary(|| unsafe {
        if let Some(code) = client_fork_error(client) {
            return code;
        }
        let Some(shared) = client_shared(client) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client must not be null",
            );
        };
        let request_json = match required_c_string(request_json, "request_json") {
            Ok(value) => value,
            Err(message) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    "invalid_argument",
                    &message,
                );
            }
        };
        if out_stream.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_stream must not be null",
            );
        }
        *out_stream = ptr::null_mut();

        let request = match parse_chat_request(&request_json, "chat stream") {
            Ok(request) => request,
            Err(code) => return code,
        };
        let stream = spawn_stream_with_client(shared, move |client, state| async move {
            stream_events(client, request, state).await
        });
        let stream = Box::into_raw(stream);
        register_handle(live_stream_handles(), stream);
        *out_stream = stream;
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Returns the next available event in order: verdict, zero or more raw chat
/// chunks, optional terminal usage, then done. Failure returns an error event.
///
/// # Safety
///
/// `stream` must be a valid live stream handle. `out_event_json` must be a
/// valid writable pointer. The returned string must be freed with
/// `confidential_inference_string_free`. A `timeout_ms` of zero is a
/// non-blocking poll (returns `CONFIDENTIAL_INFERENCE_FFI_PENDING` when no
/// event is ready); unlike the blocking exports it never waits indefinitely.
pub unsafe extern "C" fn confidential_inference_stream_next(
    stream: *mut ConfidentialInferenceFfiStream,
    timeout_ms: u64,
    out_event_json: *mut *mut c_char,
) -> c_int {
    clear_last_error();
    let status = ffi_boundary(|| unsafe {
        if let Some(code) = stream_fork_error(stream) {
            return code;
        }
        let Some(parts) = stream_parts(stream) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_stream",
                "stream must not be null",
            );
        };
        settle_finished_stream_task(&parts);
        match next_stream_event(&parts.state, Duration::from_millis(timeout_ms)) {
            StreamNext::Event(event) => write_c_string(out_event_json, event),
            StreamNext::Closed => {
                write_c_string(out_event_json, json!({ "type": "closed" }).to_string())
            }
            StreamNext::Pending => ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_PENDING,
                "stream_pending",
                "stream event is not ready yet",
            ),
        }
    });
    if status == CONFIDENTIAL_INFERENCE_FFI_PENDING {
        status
    } else {
        attach_error_json(out_event_json, status)
    }
}

#[no_mangle]
/// Cancels a stream if it has not reached terminal state.
///
/// # Safety
///
/// `stream` must be a valid live stream handle. Cancellation is idempotent and
/// enqueues a terminal cancellation event if the stream was still active.
pub unsafe extern "C" fn confidential_inference_stream_cancel(
    stream: *mut ConfidentialInferenceFfiStream,
) -> c_int {
    ffi_boundary(|| unsafe {
        if let Some(code) = stream_fork_error(stream) {
            return code;
        }
        let Some(parts) = stream_parts(stream) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_stream",
                "stream must not be null",
            );
        };
        if let Ok(mut join) = parts.join.lock() {
            if let Some(handle) = join.take() {
                handle.abort();
            }
        }
        complete_stream(
            &parts.state,
            vec![json!({ "type": "cancelled" }).to_string()],
        );
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Frees a terminal stream handle.
///
/// # Safety
///
/// `stream` must be null or a handle returned by `confidential_inference_chat_stream_start`
/// that has not already been freed. Pending streams return `CONFIDENTIAL_INFERENCE_FFI_BUSY`
/// and remain owned by the caller.
pub unsafe extern "C" fn confidential_inference_stream_free(
    stream: *mut ConfidentialInferenceFfiStream,
) -> c_int {
    ffi_boundary(|| unsafe {
        if stream.is_null() {
            clear_last_error();
            return CONFIDENTIAL_INFERENCE_FFI_OK;
        }
        if let Some(code) = stream_fork_error(stream) {
            return code;
        }
        // Hold the handle-registry lock across the liveness check and the
        // clone of the interior Arcs; after that the raw pointer is not
        // dereferenced again, so the drop below cannot race `stream_parts`.
        let parts = {
            let Ok(handles) = live_stream_handles().lock() else {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "handle_registry_poisoned",
                    "stream handle registry lock is poisoned",
                );
            };
            if !handles.contains(&pointer_key(stream)) {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    "invalid_stream",
                    "stream handle is not live or was already freed",
                );
            }
            let stream_ref = &*stream;
            StreamParts {
                shared: stream_ref.shared.clone(),
                state: stream_ref.state.clone(),
                join: stream_ref.join.clone(),
            }
        };

        settle_finished_stream_task(&parts);
        if stream_is_pending(&parts.state) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_BUSY,
                "stream_busy",
                "stream is still pending; cancel or drain before freeing",
            );
        }

        let Ok(mut handles) = live_stream_handles().lock() else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                "handle_registry_poisoned",
                "stream handle registry lock is poisoned",
            );
        };
        if !handles.remove(&pointer_key(stream)) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_stream",
                "stream handle is not live or was already freed",
            );
        }
        drop(handles);

        parts.shared.live_operations.fetch_sub(1, Ordering::SeqCst);
        drop(Box::from_raw(stream));
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Returns the thread-local synchronous FFI error as a newly allocated JSON string.
///
/// # Safety
///
/// `out_error_json` must be a valid writable pointer. The returned string must
/// be freed with `confidential_inference_string_free`.
pub unsafe extern "C" fn confidential_inference_last_error(
    out_error_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary(|| {
        let error = take_last_error();
        let body = error_json_body(error.as_ref());
        write_c_string(out_error_json, body)
    })
}

#[no_mangle]
/// Frees a string returned by this FFI crate.
///
/// # Safety
///
/// `ptr` must be null or a pointer previously returned by this crate through
/// `CString::into_raw` and not already freed.
pub unsafe extern "C" fn confidential_inference_string_free(ptr: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        if ptr.is_null() {
            clear_last_error();
            return;
        }
        if !unregister_handle(live_string_handles(), ptr) {
            let _ = ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_string",
                "string pointer is not live or was already freed",
            );
            return;
        }
        drop(CString::from_raw(ptr));
        clear_last_error();
    }));
}

async fn chat_result_json(
    request: ChatCompletionRequestPayload,
) -> Result<String, FfiOperationError> {
    let client = current_operation_client().ok_or_else(missing_operation_client)?;
    Ok(client.send_chat_completion_payload_json(request).await?)
}

async fn embeddings_result_json(
    request: EmbeddingsRequestPayload,
) -> Result<String, FfiOperationError> {
    let client = current_operation_client().ok_or_else(missing_operation_client)?;
    Ok(client.send_embeddings_payload_json(request).await?)
}

async fn response_result_json(
    request: ResponseCreateRequestPayload,
) -> Result<String, FfiOperationError> {
    let client = current_operation_client().ok_or_else(missing_operation_client)?;
    Ok(client.create_response_payload_json(request).await?)
}

async fn response_manage_result_json(
    request: ResponseManageEnvelope,
) -> Result<String, FfiOperationError> {
    let client = current_operation_client().ok_or_else(missing_operation_client)?;
    let response = client
        .manage_response(
            &request.provider,
            ResponseManageRequest {
                op: request.op,
                provider_response_id: request.provider_response_id,
                params: request.params,
            },
        )
        .await?;
    serde_json::to_string(&response).map_err(|error| {
        FfiOperationError::not_dispatched(
            "response_serialization_failed",
            format!("failed to serialize Responses lifecycle JSON: {error}"),
        )
    })
}
async fn verify_result_json(request: VerifyRequest) -> Result<String, FfiOperationError> {
    let client = current_operation_client().ok_or_else(missing_operation_client)?;
    let verified = client.verify_route(request.provider, request.model).await?;
    serde_json::to_string(verified.verdict()).map_err(|error| {
        FfiOperationError::not_dispatched(
            "verdict_serialization_failed",
            format!("failed to serialize attestation verdict JSON: {error}"),
        )
    })
}

fn missing_operation_client() -> FfiOperationError {
    FfiOperationError::not_dispatched("operation_client_missing", "operation client missing")
}

tokio::task_local! {
    static OPERATION_CLIENT: ConfidentialInference;
}

fn current_operation_client() -> Option<ConfidentialInference> {
    OPERATION_CLIENT.try_with(Clone::clone).ok()
}

fn parse_chat_request(
    request_json: &str,
    operation: &'static str,
) -> Result<ChatCompletionRequestPayload, c_int> {
    ChatCompletionRequestPayload::from_json_str(request_json).map_err(|error| {
        ffi_error(
            CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
            "invalid_request_json",
            &format!("failed to parse {operation} request JSON: {error}"),
        )
    })
}

fn parse_embeddings_request(
    request_json: &str,
    operation: &'static str,
) -> Result<EmbeddingsRequestPayload, c_int> {
    EmbeddingsRequestPayload::from_json_str(request_json).map_err(|error| {
        ffi_error(
            CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
            "invalid_request_json",
            &format!("failed to parse {operation} request JSON: {error}"),
        )
    })
}

fn parse_response_request(
    request_json: &str,
    operation: &'static str,
) -> Result<ResponseCreateRequestPayload, c_int> {
    ResponseCreateRequestPayload::from_json_str(request_json).map_err(|error| {
        ffi_error(
            CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
            "invalid_request_json",
            &format!("failed to parse {operation} request JSON: {error}"),
        )
    })
}
fn parse_response_manage_request(request_json: &str) -> Result<ResponseManageEnvelope, c_int> {
    serde_json::from_str::<ResponseManageEnvelope>(request_json).map_err(|error| {
        ffi_error(
            CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
            "invalid_request_json",
            &format!("failed to parse response manage request JSON: {error}"),
        )
    })
}

fn parse_verify_request(
    request_json: &str,
    operation: &'static str,
) -> Result<VerifyRequest, c_int> {
    serde_json::from_str::<VerifyRequest>(request_json).map_err(|error| {
        ffi_error(
            CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
            "invalid_request_json",
            &format!("failed to parse {operation} request JSON: {error}"),
        )
    })
}

fn run_blocking_result_json<F, Fut>(
    shared: Arc<ClientShared>,
    timeout_ms: u64,
    operation: F,
) -> Result<String, c_int>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<String, FfiOperationError>>,
{
    let client = shared.client.clone();
    let future = async move { OPERATION_CLIENT.scope(client, operation()).await };
    let result = if timeout_ms == 0 {
        shared.runtime.block_on(future)
    } else {
        match shared.runtime.block_on(async move {
            tokio::time::timeout(Duration::from_millis(timeout_ms), future).await
        }) {
            Ok(result) => result,
            Err(_) => {
                // The dropped operation may already have sent its request.
                return Err(ffi_error_detail(
                    CONFIDENTIAL_INFERENCE_FFI_PENDING,
                    FfiErrorJson {
                        code: "operation_timeout",
                        message: "blocking operation did not complete before timeout".into(),
                        dispatch: Some("unknown"),
                        http_status: None,
                    },
                ));
            }
        }
    };

    result.map_err(|error| {
        ffi_error_detail(
            CONFIDENTIAL_INFERENCE_FFI_OPERATION_FAILED,
            FfiErrorJson {
                code: error.code,
                message: error.message,
                dispatch: Some(error.dispatch),
                http_status: error.http_status,
            },
        )
    })
}

fn spawn_stream<F, Fut>(shared: Arc<ClientShared>, future: F) -> Box<ConfidentialInferenceFfiStream>
where
    F: FnOnce(Arc<(Mutex<StreamState>, Condvar)>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    shared.live_operations.fetch_add(1, Ordering::SeqCst);
    let state = Arc::new((Mutex::new(StreamState::new()), Condvar::new()));
    let task_state = state.clone();
    let join = shared.runtime.spawn(async move {
        future(task_state.clone()).await;
        finish_stream(&task_state);
    });

    Box::new(ConfidentialInferenceFfiStream {
        shared,
        owner_pid: process::id(),
        state,
        join: Arc::new(Mutex::new(Some(join))),
    })
}

fn spawn_stream_with_client<F, Fut>(
    shared: Arc<ClientShared>,
    stream: F,
) -> Box<ConfidentialInferenceFfiStream>
where
    F: FnOnce(ConfidentialInference, Arc<(Mutex<StreamState>, Condvar)>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let client = shared.client.clone();
    spawn_stream(shared, move |state| stream(client, state))
}

async fn stream_events(
    client: ConfidentialInference,
    request: ChatCompletionRequestPayload,
    state: Arc<(Mutex<StreamState>, Condvar)>,
) {
    let mut stream = match client.send_chat_stream_payload_json(request).await {
        Ok(stream) => stream,
        Err(error) => {
            let error = FfiOperationError::from(error);
            complete_stream(&state, vec![stream_operation_error_event(&error)]);
            return;
        }
    };
    let verdict = match serde_json::to_value(&stream.verdict) {
        Ok(verdict) => verdict,
        Err(error) => {
            complete_stream(
                &state,
                vec![stream_operation_error_event(&FfiOperationError {
                    code: "stream_verdict_serialization_failed",
                    message: error.to_string(),
                    dispatch: "unknown",
                    http_status: None,
                })],
            );
            return;
        }
    };
    if verdict["response_integrity_result"] == "receipt_bound" {
        complete_stream(
            &state,
            vec![stream_operation_error_event(&FfiOperationError {
                code: "stream_verdict_receipt_bound",
                message:
                    "stream verdict cannot be receipt-bound before a terminal response receipt"
                        .into(),
                dispatch: "unknown",
                http_status: None,
            })],
        );
        return;
    }
    push_stream_event(&state, stream_verdict_event(verdict));

    while let Some(result) = stream.next().await {
        match result {
            Ok(chunk) => match serde_json::to_value(chunk) {
                Ok(chunk) => push_stream_event(&state, stream_chunk_event(chunk)),
                Err(error) => {
                    let error = FfiOperationError {
                        code: "stream_chunk_serialization_failed",
                        message: error.to_string(),
                        dispatch: "unknown",
                        http_status: None,
                    };
                    complete_stream(&state, vec![stream_operation_error_event(&error)]);
                    return;
                }
            },
            Err(error) => {
                let mut error = FfiOperationError::from(error);
                error.dispatch = "unknown";
                error.http_status = None;
                complete_stream(&state, vec![stream_operation_error_event(&error)]);
                return;
            }
        }
    }
    if let Some(usage) = stream.terminal_usage {
        push_stream_event(&state, stream_usage_event(usage));
    }
    push_stream_event(&state, json!({ "type": "done" }).to_string());
}
fn stream_verdict_event(verdict: serde_json::Value) -> String {
    let response_channel_bound = verdict["response_channel_bound"].clone();
    let response_integrity_result = verdict["response_integrity_result"].clone();
    json!({
        "type": "verdict",
        "verdict": verdict,
        "response_channel_bound": response_channel_bound,
        "response_integrity_result": response_integrity_result,
    })
    .to_string()
}

fn stream_chunk_event(chunk: serde_json::Value) -> String {
    json!({ "type": "chunk", "chunk": chunk }).to_string()
}

fn stream_usage_event(usage: impl Serialize) -> String {
    json!({ "type": "usage", "usage": usage }).to_string()
}

fn push_stream_event(state: &Arc<(Mutex<StreamState>, Condvar)>, event: String) {
    let (state_lock, ready) = &**state;
    if let Ok(mut state) = state_lock.lock() {
        if !state.terminal {
            state.events.push_back(event);
            ready.notify_all();
        }
    }
}

fn finish_stream(state: &Arc<(Mutex<StreamState>, Condvar)>) {
    let (state_lock, ready) = &**state;
    if let Ok(mut state) = state_lock.lock() {
        state.terminal = true;
        ready.notify_all();
    }
}

fn stream_error_event(message: &str) -> String {
    json!({
        "type": "error",
        "status": "failed",
        "error": {
            "type": "confidential_inference_stream_error",
            "message": message,
        }
    })
    .to_string()
}

fn stream_operation_error_event(error: &FfiOperationError) -> String {
    let mut detail = json!({
        "type": "confidential_inference_stream_error",
        "code": error.code,
        "message": error.message,
        "dispatch": error.dispatch,
    });
    if let Some(http_status) = error.http_status {
        detail["http_status"] = json!(http_status);
    }
    json!({ "type": "error", "status": "failed", "error": detail }).to_string()
}

fn complete_stream(state: &Arc<(Mutex<StreamState>, Condvar)>, events: Vec<String>) {
    let (state_lock, ready) = &**state;
    let Ok(mut state) = state_lock.lock() else {
        return;
    };
    if state.terminal {
        return;
    }
    state.events.extend(events);
    state.terminal = true;
    ready.notify_all();
}

fn settle_finished_stream_task(parts: &StreamParts) {
    let handle = {
        let Ok(mut join) = parts.join.lock() else {
            return;
        };
        let Some(handle) = join.as_ref() else {
            return;
        };
        if !handle.is_finished() {
            return;
        }
        join.take()
    };

    let Some(handle) = handle else {
        return;
    };
    if !stream_is_pending(&parts.state) {
        drop(handle);
        return;
    }
    if in_tokio_runtime_context() {
        complete_stream(
            &parts.state,
            vec![stream_error_event(
                "stream task finished but cannot be joined from a Tokio runtime context",
            )],
        );
        drop(handle);
        return;
    }
    match parts.shared.runtime.block_on(handle) {
        Ok(()) => {}
        Err(error) if error.is_cancelled() => {
            complete_stream(
                &parts.state,
                vec![json!({ "type": "cancelled" }).to_string()],
            );
        }
        Err(error) => {
            complete_stream(
                &parts.state,
                vec![stream_error_event(&format!("stream task failed: {error}"))],
            );
        }
    }
}

enum StreamNext {
    Event(String),
    Pending,
    Closed,
}

fn next_stream_event(state: &Arc<(Mutex<StreamState>, Condvar)>, timeout: Duration) -> StreamNext {
    let (state_lock, ready) = &**state;
    let Ok(mut state) = state_lock.lock() else {
        return StreamNext::Event(stream_error_event("stream lock failed"));
    };
    if state.events.is_empty() && !state.terminal && !timeout.is_zero() {
        let Ok((waited, _)) = ready.wait_timeout_while(state, timeout, |state| {
            state.events.is_empty() && !state.terminal
        }) else {
            return StreamNext::Event(stream_error_event("stream wait failed"));
        };
        state = waited;
    }
    if let Some(event) = state.events.pop_front() {
        StreamNext::Event(event)
    } else if state.terminal {
        StreamNext::Closed
    } else {
        StreamNext::Pending
    }
}

fn stream_is_pending(state: &Arc<(Mutex<StreamState>, Condvar)>) -> bool {
    state.0.lock().map(|state| !state.terminal).unwrap_or(false)
}

fn in_tokio_runtime_context() -> bool {
    Handle::try_current().is_ok()
}

unsafe fn client_shared(client: *mut ConfidentialInferenceFfiClient) -> Option<Arc<ClientShared>> {
    // The handle-registry lock is held across the liveness check and the
    // pointer dereference so a concurrent `confidential_inference_sdk_free`
    // cannot unregister and drop the handle between the two.
    let handles = live_client_handles().lock().ok()?;
    if !handles.contains(&pointer_key(client)) {
        return None;
    }
    Some((*client).shared.clone())
}

struct StreamParts {
    shared: Arc<ClientShared>,
    state: Arc<(Mutex<StreamState>, Condvar)>,
    join: Arc<Mutex<Option<JoinHandle<()>>>>,
}

unsafe fn stream_parts(stream: *mut ConfidentialInferenceFfiStream) -> Option<StreamParts> {
    // Same lock-held-deref discipline as `client_shared`: after this returns,
    // callers only touch the cloned Arcs, so a concurrent
    // `confidential_inference_stream_free` can never invalidate them.
    let handles = live_stream_handles().lock().ok()?;
    if !handles.contains(&pointer_key(stream)) {
        return None;
    }
    let stream = &*stream;
    Some(StreamParts {
        shared: stream.shared.clone(),
        state: stream.state.clone(),
        join: stream.join.clone(),
    })
}

unsafe fn optional_json_config(config_json: *const c_char) -> Result<ClientConfig, String> {
    if config_json.is_null() {
        return Ok(ClientConfig::default());
    }
    let value = Zeroizing::new(c_string_to_string(config_json, "config_json")?);
    if value.trim().is_empty() {
        Ok(ClientConfig::default())
    } else {
        // Report only the serde error category + position: the default
        // Display message embeds the offending value, which can be an
        // inline API key from the raw config JSON.
        serde_json::from_str(&value).map_err(|error| {
            format!(
                "failed to parse config JSON: {:?} error at line {} column {}",
                error.classify(),
                error.line(),
                error.column()
            )
        })
    }
}

unsafe fn required_c_string(ptr: *const c_char, name: &str) -> Result<String, String> {
    if ptr.is_null() {
        Err(format!("{name} must not be null"))
    } else {
        c_string_to_string(ptr, name)
    }
}

unsafe fn c_string_to_string(ptr: *const c_char, name: &str) -> Result<String, String> {
    CStr::from_ptr(ptr)
        .to_str()
        .map(str::to_owned)
        .map_err(|error| format!("{name} must be valid UTF-8: {error}"))
}

fn write_c_string(out: *mut *mut c_char, value: String) -> c_int {
    unsafe {
        if out.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "output string pointer must not be null",
            );
        }
        match CString::new(value) {
            Ok(value) => {
                let value = value.into_raw();
                register_handle(live_string_handles(), value);
                *out = value;
                clear_last_error();
                CONFIDENTIAL_INFERENCE_FFI_OK
            }
            Err(error) => ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                "string_contains_nul",
                &format!("response string contains NUL byte: {error}"),
            ),
        }
    }
}

fn ffi_boundary(operation: impl FnOnce() -> c_int) -> c_int {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(code) => code,
        Err(_) => ffi_error(
            CONFIDENTIAL_INFERENCE_FFI_PANIC,
            "panic",
            "panic was contained at the FFI boundary",
        ),
    }
}

fn ffi_boundary_with_error(out_json: *mut *mut c_char, operation: impl FnOnce() -> c_int) -> c_int {
    clear_last_error();
    let status = ffi_boundary(operation);
    attach_error_json(out_json, status)
}

fn attach_error_json(out_json: *mut *mut c_char, status: c_int) -> c_int {
    if status != CONFIDENTIAL_INFERENCE_FFI_OK {
        if let Some(error) = take_last_error() {
            write_error_c_string(out_json, &error);
        }
    }
    status
}

fn error_json_body(error: Option<&FfiErrorJson>) -> String {
    match error {
        Some(error) => {
            let mut body = json!({
                "type": "confidential_inference_ffi_error",
                "code": error.code,
                "message": error.message,
            });
            if let Some(dispatch) = error.dispatch {
                body["dispatch"] = json!(dispatch);
            }
            if let Some(http_status) = error.http_status {
                body["http_status"] = json!(http_status);
            }
            json!({ "error": body }).to_string()
        }
        None => json!({ "error": null }).to_string(),
    }
}

fn write_error_c_string(out: *mut *mut c_char, error: &FfiErrorJson) {
    if out.is_null() {
        return;
    }
    let Ok(value) = CString::new(error_json_body(Some(error))) else {
        return;
    };
    let value = value.into_raw();
    register_handle(live_string_handles(), value);
    unsafe { *out = value };
}

fn ffi_error(status: c_int, code: &'static str, message: &str) -> c_int {
    ffi_error_detail(
        status,
        FfiErrorJson {
            code,
            message: message.to_owned(),
            dispatch: None,
            http_status: None,
        },
    )
}

fn ffi_error_detail(status: c_int, error: FfiErrorJson) -> c_int {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(error);
    });
    status
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::time::Duration;

    fn c_string(value: &str) -> CString {
        CString::new(value).unwrap()
    }

    fn chat_request_json(prompt: &str) -> CString {
        c_string(
            &json!({
                "model": "gpt-oss-120b",
                "messages": [
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
            })
            .to_string(),
        )
    }

    fn streaming_chat_request_json(prompt: &str) -> CString {
        c_string(
            &json!({
                "model": "gpt-oss-120b",
                "messages": [
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                "stream": true,
            })
            .to_string(),
        )
    }

    fn response_request_json(prompt: &str) -> CString {
        c_string(
            &json!({
                "model": "gpt-oss-120b",
                "input": prompt,
            })
            .to_string(),
        )
    }

    fn embeddings_request_json(model: &str) -> CString {
        c_string(&json!({"model": model, "input": "hello"}).to_string())
    }

    unsafe fn take_string(ptr: *mut c_char) -> String {
        let value = CStr::from_ptr(ptr).to_str().unwrap().to_owned();
        confidential_inference_string_free(ptr);
        value
    }

    unsafe fn last_error_value() -> Value {
        let mut error = ptr::null_mut();
        assert_eq!(
            confidential_inference_last_error(&mut error),
            CONFIDENTIAL_INFERENCE_FFI_OK
        );
        serde_json::from_str(&take_string(error)).unwrap()
    }

    fn new_demo_client() -> *mut ConfidentialInferenceFfiClient {
        let mut client = ptr::null_mut();
        let config = c_string(r#"{"demo_provider":true}"#);
        let code = unsafe { confidential_inference_sdk_new(config.as_ptr(), &mut client) };
        assert_eq!(code, CONFIDENTIAL_INFERENCE_FFI_OK);
        assert!(!client.is_null());
        client
    }

    unsafe fn free_stream_and_client(
        stream: *mut ConfidentialInferenceFfiStream,
        client: *mut ConfidentialInferenceFfiClient,
    ) {
        assert_eq!(
            confidential_inference_stream_free(stream),
            CONFIDENTIAL_INFERENCE_FFI_OK
        );
        assert_eq!(
            confidential_inference_sdk_free(client),
            CONFIDENTIAL_INFERENCE_FFI_OK
        );
    }

    #[test]
    fn ffi_chat_blocking_returns_confidential_response_json() {
        unsafe {
            let client = new_demo_client();
            let request_json = chat_request_json("ffi blocking chat path");
            let mut result = ptr::null_mut();

            assert_eq!(
                confidential_inference_chat_blocking(
                    client,
                    request_json.as_ptr(),
                    2_000,
                    &mut result
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let result: Value = serde_json::from_str(&take_string(result)).unwrap();
            assert_eq!(result["provider"], "demo");
            assert_eq!(result["verdict"]["status"], "verified");
            assert_eq!(
                result["response"]["choices"][0]["message"]["content"],
                "demo confidential response for e2ee-gpt-oss-120b-p: ffi blocking chat path"
            );

            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_embeddings_blocking_returns_confidential_response_json() {
        unsafe {
            let client = new_demo_client();
            let request_json = embeddings_request_json("gpt-oss-120b");
            let mut result = ptr::null_mut();

            assert_eq!(
                confidential_inference_embeddings_blocking(
                    client,
                    request_json.as_ptr(),
                    2_000,
                    &mut result
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let result: Value = serde_json::from_str(&take_string(result)).unwrap();
            assert_eq!(result["provider"], "demo");
            assert_eq!(result["verdict"]["status"], "verified");
            assert_eq!(result["response"]["object"], "list");

            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_response_blocking_returns_responses_shim_json() {
        unsafe {
            let client = new_demo_client();
            let request_json = response_request_json("ffi blocking response path");
            let mut result = ptr::null_mut();

            assert_eq!(
                confidential_inference_response_blocking(
                    client,
                    request_json.as_ptr(),
                    2_000,
                    &mut result
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let result: Value = serde_json::from_str(&take_string(result)).unwrap();
            assert_eq!(result["provider"], "demo");
            assert_eq!(result["verdict"]["status"], "verified");
            assert_eq!(result["response"]["object"], "response");
            assert_eq!(result["response"]["status"], "completed");
            assert_eq!(
                result["response"]["metadata"]["native_provider_responses_api"],
                "false"
            );
            assert_eq!(
                result["response"]["output_text"],
                "demo confidential response for e2ee-gpt-oss-120b-p: ffi blocking response path"
            );

            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_response_manage_accepts_envelope_and_classifies_unsupported_route() {
        unsafe {
            let client = new_demo_client();
            let request_json = c_string(
                r#"{"op":"retrieve","provider":"demo","provider_response_id":"resp_demo","params":{}}"#,
            );
            let mut result = ptr::null_mut();
            assert_eq!(
                confidential_inference_response_manage_blocking(
                    client,
                    request_json.as_ptr(),
                    2_000,
                    &mut result
                ),
                CONFIDENTIAL_INFERENCE_FFI_OPERATION_FAILED
            );
            let result: Value = serde_json::from_str(&take_string(result)).unwrap();
            assert_eq!(result["error"]["code"], "provider_response_manage_failed");
            assert_eq!(result["error"]["dispatch"], "unknown");
            assert!(result["error"].get("http_status").is_none());
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_verify_blocking_returns_verdict_json() {
        unsafe {
            let client = new_demo_client();
            let request = c_string(r#"{"provider":"demo","model":"gpt-oss-120b"}"#);
            let mut result = ptr::null_mut();

            assert_eq!(
                confidential_inference_verify_blocking(
                    client,
                    request.as_ptr(),
                    2_000,
                    &mut result
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let result: Value = serde_json::from_str(&take_string(result)).unwrap();
            assert_eq!(result["status"], "verified");
            assert_eq!(result["route_id"], "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p");

            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_models_and_confidentiality_blocking_return_discovery_json() {
        unsafe {
            let client = new_demo_client();
            let mut models = ptr::null_mut();
            let mut confidentiality = ptr::null_mut();

            assert_eq!(
                confidential_inference_models_blocking(client, &mut models),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert_eq!(
                confidential_inference_confidentiality_blocking(client, &mut confidentiality),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let models: Value = serde_json::from_str(&take_string(models)).unwrap();
            let confidentiality: Value =
                serde_json::from_str(&take_string(confidentiality)).unwrap();
            assert_eq!(models["object"], "list");
            assert_eq!(models["data"][0]["id"], "gpt-oss-120b");
            assert_eq!(confidentiality[0]["canonical_model"], "gpt-oss-120b");
            assert_eq!(confidentiality[0]["routes"][0]["provider"], "demo");
            assert_eq!(
                confidentiality[0]["routes"][0]["route_execution_status"],
                "executable_fixture"
            );
            assert_eq!(
                confidentiality[0]["routes"][0]["known_unsupported_modes"][0],
                "streaming"
            );

            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_active_policy_blocking_returns_shared_policy_fixture_and_digest() {
        unsafe {
            let client = new_demo_client();
            let mut policy = ptr::null_mut();

            assert_eq!(
                confidential_inference_active_policy_blocking(client, &mut policy),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let snapshot: Value = serde_json::from_str(&take_string(policy)).unwrap();
            let expected_policy: Value = serde_json::from_str(include_str!(
                "../../../fixtures/policy/require_attested_e2ee.json"
            ))
            .unwrap();
            let vectors: Value = serde_json::from_str(include_str!(
                "../../../fixtures/policy/canonical-vectors.json"
            ))
            .unwrap();
            let expected_vector = vectors["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|vector| vector["id"] == "require-attested-e2ee-demo")
                .unwrap();

            assert_eq!(
                snapshot["schema"],
                "confidential-inference.active-policy.v1"
            );
            assert_eq!(snapshot["policy"], expected_policy);
            assert_eq!(snapshot["policy"], expected_vector["policy"]);
            assert_eq!(snapshot["policy_digest"], expected_vector["digest"]);

            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_active_trust_artifacts_blocking_returns_signed_artifact_snapshot() {
        unsafe {
            let client = new_demo_client();
            let mut artifacts = ptr::null_mut();

            assert_eq!(
                confidential_inference_active_trust_artifacts_blocking(client, &mut artifacts),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let artifacts: Value = serde_json::from_str(&take_string(artifacts)).unwrap();
            let expected_registry: Value = serde_json::from_str(include_str!(
                "../../../fixtures/registry/demo-registry.json"
            ))
            .unwrap();
            let expected_reference_values: Value = serde_json::from_str(include_str!(
                "../../../fixtures/reference-values/demo-envelope.json"
            ))
            .unwrap();
            assert_eq!(artifacts["registry"]["version"], "2026-07-05-demo");
            assert_eq!(artifacts["registry_source"], "bundled");
            assert!(artifacts["registry_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"));
            assert_eq!(
                artifacts["registry_signature"]["signer"],
                "confidential-inference"
            );
            assert_eq!(
                artifacts["registry_signature"],
                expected_registry["signature"]
            );
            assert_eq!(artifacts["reference_values"]["version"], "2026-07-05-demo");
            assert_eq!(artifacts["reference_values_source"], "bundled");
            assert!(artifacts["reference_values_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"));
            assert_eq!(
                artifacts["reference_values_signature"]["signer"],
                "confidential-inference"
            );
            assert_eq!(
                artifacts["reference_values_signature"],
                expected_reference_values["signature"]
            );

            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_chat_blocking_reports_sdk_failure_as_operation_error() {
        unsafe {
            let client = new_demo_client();
            let request_json = streaming_chat_request_json("ffi blocking unsupported stream");
            let mut result = ptr::null_mut();

            assert_eq!(
                confidential_inference_chat_blocking(
                    client,
                    request_json.as_ptr(),
                    2_000,
                    &mut result
                ),
                CONFIDENTIAL_INFERENCE_FFI_OPERATION_FAILED
            );
            let result_json = take_string(result);
            let result: Value = serde_json::from_str(&result_json).unwrap();
            assert_eq!(result["error"]["code"], "streaming_not_supported");
            assert_eq!(result["error"]["dispatch"], "not_dispatched");
            assert!(result["error"].get("http_status").is_none());
            assert!(result["error"]["message"]
                .as_str()
                .unwrap()
                .contains("streaming is not supported"));
            assert!(!result_json.contains("ffi blocking unsupported stream"));

            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_embeddings_blocking_reports_sdk_failure_as_operation_error() {
        unsafe {
            let client = new_demo_client();
            let request_json = embeddings_request_json("no-such-model");
            let mut result = ptr::null_mut();

            assert_eq!(
                confidential_inference_embeddings_blocking(
                    client,
                    request_json.as_ptr(),
                    2_000,
                    &mut result
                ),
                CONFIDENTIAL_INFERENCE_FFI_OPERATION_FAILED
            );
            let result: Value = serde_json::from_str(&take_string(result)).unwrap();
            assert_eq!(result["error"]["dispatch"], "not_dispatched");
            assert!(result["error"]["code"].as_str().is_some());
            assert!(result["error"]["message"].as_str().is_some());
            assert!(result["error"].get("http_status").is_none());

            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_blocking_timeout_sets_last_error_without_live_operation() {
        unsafe {
            let client = new_demo_client();
            let shared = client_shared(client).unwrap();

            let result = run_blocking_result_json(shared, 1, || async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(json!({ "status": "late" }).to_string())
            });
            assert_eq!(result.unwrap_err(), CONFIDENTIAL_INFERENCE_FFI_PENDING);

            let mut error = ptr::null_mut();
            assert_eq!(
                confidential_inference_last_error(&mut error),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let error = take_string(error);
            assert!(error.contains("operation_timeout"));
            // A timed-out request may already be in flight.
            assert!(error.contains("\"dispatch\":\"unknown\""));
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_last_error_reports_synchronous_argument_failures() {
        unsafe {
            let mut client = ptr::null_mut();
            assert_eq!(
                confidential_inference_sdk_new(ptr::null(), ptr::null_mut()),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );

            let mut error = ptr::null_mut();
            assert_eq!(
                confidential_inference_last_error(&mut error),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let error: Value = serde_json::from_str(&take_string(error)).unwrap();
            assert_eq!(error["error"]["code"], "invalid_argument");

            assert_eq!(
                confidential_inference_sdk_new(
                    c_string(r#"{"demo_provider":true}"#).as_ptr(),
                    &mut client
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_blocking_failure_returns_call_specific_error_json() {
        unsafe {
            let client = new_demo_client();
            let request = c_string(r#"{"nope":true}"#);
            let mut error = ptr::null_mut();

            assert_eq!(
                confidential_inference_chat_blocking(client, request.as_ptr(), 0, &mut error),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );
            let error: Value = serde_json::from_str(&take_string(error)).unwrap();
            assert_eq!(error["error"]["code"], "invalid_request_json");
            assert!(error["error"]["message"]
                .as_str()
                .unwrap()
                .contains("chat request JSON"));

            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    const PHASE2_FIXTURE_KEY: &str = "cN-eInmtvsbRK_KSEYTJIi6yTthSAFv2QBOfUuWc2a4";

    fn phase2_operator_config() -> Value {
        json!({
            "demo_provider": false,
            "trusted_ed25519_signing_keys": [{
                "signer": "confidential-inference",
                "key_id": "confidential-inference-phase2-fixture-ed25519-2026",
                "public_key_base64url": PHASE2_FIXTURE_KEY
            }],
            "registry": serde_json::from_str::<Value>(include_str!("../../../fixtures/registry/phase2-fixtures-registry.json")).unwrap(),
            "reference_values": serde_json::from_str::<Value>(include_str!("../../../fixtures/reference-values/phase2-fixtures-envelope.json")).unwrap()
        })
    }

    fn ffi_config_result(config: &Value) -> (c_int, Option<String>) {
        unsafe {
            let config = c_string(&config.to_string());
            let mut client = ptr::null_mut();
            let status = confidential_inference_sdk_new(config.as_ptr(), &mut client);
            let code = if status == CONFIDENTIAL_INFERENCE_FFI_OK {
                assert_eq!(
                    confidential_inference_sdk_free(client),
                    CONFIDENTIAL_INFERENCE_FFI_OK
                );
                None
            } else {
                Some(
                    last_error_value()["error"]["code"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                )
            };
            (status, code)
        }
    }

    #[test]
    fn ffi_client_config_accepts_operator_signed_trust_artifacts() {
        let (status, code) = ffi_config_result(&phase2_operator_config());
        assert_eq!(
            status, CONFIDENTIAL_INFERENCE_FFI_OK,
            "error code: {code:?}"
        );
    }
    #[test]
    fn ffi_client_config_accepts_and_rejects_operator_compatibility_matrix() {
        const MATRIX_KEY: &str = "bjLBl0Hwr4JgYSrpn9E9ijiURyLgiWTdI5c49VKmFTs";
        let matrix = serde_json::from_str::<Value>(include_str!(
            "../../../crates/confidential-inference-providers/assets/providers/compatibility-matrix-envelope.json"
        ))
        .unwrap();
        let mut config = phase2_operator_config();
        config["trusted_ed25519_signing_keys"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "signer": "confidential-inference",
                "key_id": "confidential-inference-compatibility-fixture-ed25519-2026",
                "public_key_base64url": MATRIX_KEY
            }));
        config["compatibility_matrix"] = matrix.clone();
        assert_eq!(ffi_config_result(&config).0, CONFIDENTIAL_INFERENCE_FFI_OK);

        let mut untrusted = config.clone();
        untrusted["trusted_ed25519_signing_keys"][1]["key_id"] = json!("untrusted");
        assert_eq!(
            ffi_config_result(&untrusted).1.as_deref(),
            Some("compatibility_matrix_untrusted_signer")
        );

        let mut tampered = config.clone();
        tampered["compatibility_matrix"]["payload"]["providers"]["demo"]["streaming"] =
            json!("supported");
        assert_eq!(
            ffi_config_result(&tampered).1.as_deref(),
            Some("compatibility_matrix_tampered")
        );

        let mut demo = config.clone();
        demo["demo_provider"] = json!(true);
        assert_eq!(
            ffi_config_result(&demo).1.as_deref(),
            Some("trust_artifacts_ambiguous")
        );

        let mut no_keys = config;
        no_keys["trusted_ed25519_signing_keys"] = json!([]);
        assert_eq!(
            ffi_config_result(&no_keys).1.as_deref(),
            Some("compatibility_matrix_trust_keys_required")
        );
    }

    #[test]
    fn ffi_client_config_accepts_enforcing_operator_policy_only() {
        let policy = serde_json::to_value(
            confidential_inference_sdk::VerificationPolicy::require_hw_verified_tls(),
        )
        .unwrap();
        let mut config = phase2_operator_config();
        config["policy"] = policy.clone();
        assert_eq!(ffi_config_result(&config).0, CONFIDENTIAL_INFERENCE_FFI_OK);

        let mut observe = config.clone();
        observe["policy"]["enforcement"] = json!("observe");
        assert_eq!(
            ffi_config_result(&observe).1.as_deref(),
            Some("policy_enforcement_must_be_enforce")
        );

        let mut demo = json!({ "demo_provider": true });
        demo["policy"] = policy.clone();
        assert_eq!(
            ffi_config_result(&demo).1.as_deref(),
            Some("policy_requires_operator_trust")
        );

        let mut unknown_field = config;
        unknown_field["policy"]["skip_attestation"] = json!(true);
        assert_eq!(
            ffi_config_result(&unknown_field).1.as_deref(),
            Some("invalid_config_json")
        );
    }

    #[test]
    fn ffi_client_config_rejects_demo_artifacts_and_incomplete_pair() {
        let mut config = phase2_operator_config();
        config["demo_provider"] = json!(true);
        assert_eq!(
            ffi_config_result(&config).1.as_deref(),
            Some("trust_artifacts_ambiguous")
        );

        let mut config = phase2_operator_config();
        config.as_object_mut().unwrap().remove("reference_values");
        assert_eq!(
            ffi_config_result(&config).1.as_deref(),
            Some("trust_artifact_pair_required")
        );
    }

    #[test]
    fn ffi_client_config_rejects_untrusted_and_tampered_artifacts() {
        let mut config = phase2_operator_config();
        config["trusted_ed25519_signing_keys"][0]["public_key_base64url"] =
            json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(ffi_config_result(&config).0 != CONFIDENTIAL_INFERENCE_FFI_OK);

        let mut config = phase2_operator_config();
        config["registry"]["payload"]["version"] = json!("tampered");
        assert!(ffi_config_result(&config).0 != CONFIDENTIAL_INFERENCE_FFI_OK);
    }

    #[test]
    fn ffi_client_config_loads_api_key_from_env_reference() {
        unsafe {
            let env_name = "CONFIDENTIAL_INFERENCE_FFI_TEST_API_KEY_ENV_REFERENCE";
            env::set_var(env_name, "sk-ffi-env-secret");
            let config = c_string(&format!(
                r#"{{"demo_provider":true,"api_keys":{{"demo":{{"env":"{env_name}"}}}}}}"#
            ));
            let mut client = ptr::null_mut();

            assert_eq!(
                confidential_inference_sdk_new(config.as_ptr(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            env::remove_var(env_name);

            let shared = client_shared(client).unwrap();
            assert!(shared.client.has_api_key("demo"));
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_client_config_missing_api_key_env_fails_without_secret_echo() {
        unsafe {
            let env_name = "CONFIDENTIAL_INFERENCE_FFI_TEST_MISSING_API_KEY_ENV_REFERENCE";
            env::remove_var(env_name);
            let config = c_string(&format!(
                r#"{{"demo_provider":true,"api_keys":{{"demo":{{"env":"{env_name}"}}}}}}"#
            ));
            let mut client = ptr::null_mut();

            assert_eq!(
                confidential_inference_sdk_new(config.as_ptr(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );

            let mut error = ptr::null_mut();
            assert_eq!(
                confidential_inference_last_error(&mut error),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let error_json = take_string(error);
            let error: Value = serde_json::from_str(&error_json).unwrap();
            assert_eq!(error["error"]["code"], "credential_env_missing");
            assert!(error["error"]["message"]
                .as_str()
                .unwrap()
                .contains(env_name));
            assert!(!error_json.contains("sk-ffi-env-secret"));
        }
    }

    #[test]
    fn ffi_client_config_rejects_inline_api_key_without_echoing_secret() {
        unsafe {
            let secret = "sk-ffi-inline-secret";
            let config = c_string(&format!(
                r#"{{"demo_provider":true,"api_keys":{{"demo":{{"inline":"{secret}"}}}}}}"#
            ));
            let mut client = ptr::null_mut();

            assert_eq!(
                confidential_inference_sdk_new(config.as_ptr(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );

            let mut error = ptr::null_mut();
            assert_eq!(
                confidential_inference_last_error(&mut error),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let error_json = take_string(error);
            let error: Value = serde_json::from_str(&error_json).unwrap();
            assert_eq!(error["error"]["code"], "inline_credentials_not_allowed");
            assert!(!error_json.contains(secret));
        }
    }

    #[test]
    fn ffi_client_config_accepts_inline_api_key_with_explicit_opt_in() {
        unsafe {
            let secret = "sk-ffi-inline-secret-allowed";
            let config = c_string(&format!(
                r#"{{"demo_provider":true,"allow_inline_api_keys":true,"api_keys":{{"demo":{{"inline":"{secret}"}}}}}}"#
            ));
            let mut client = ptr::null_mut();

            assert_eq!(
                confidential_inference_sdk_new(config.as_ptr(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let shared = client_shared(client).unwrap();
            assert!(shared.client.has_api_key("demo"));
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_client_config_accepts_named_provider_order() {
        unsafe {
            let config = c_string(
                r#"{"demo_provider":true,"routing":{"provider_order":{"gpt-oss-120b":["demo"]}}}"#,
            );
            let mut client = ptr::null_mut();

            assert_eq!(
                confidential_inference_sdk_new(config.as_ptr(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_client_config_rejects_invalid_named_provider_order() {
        unsafe {
            let config = c_string(
                r#"{"demo_provider":true,"routing":{"provider_order":{"gpt-oss-120b":["demo","demo"]}}}"#,
            );
            let mut client = ptr::null_mut();

            assert_eq!(
                confidential_inference_sdk_new(config.as_ptr(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );
            let mut error = ptr::null_mut();
            assert_eq!(
                confidential_inference_last_error(&mut error),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let error: Value = serde_json::from_str(&take_string(error)).unwrap();
            assert_eq!(error["error"]["code"], "invalid_provider_routing");
            assert!(error["error"]["message"]
                .as_str()
                .unwrap()
                .contains("appears more than once"));
            assert!(client.is_null());
        }
    }

    #[test]
    fn ffi_client_config_rejects_ambiguous_api_key_source_without_echoing_secret() {
        unsafe {
            let secret = "sk-ffi-inline-secret-ambiguous";
            let config = c_string(&format!(
                r#"{{"demo_provider":true,"allow_inline_api_keys":true,"api_keys":{{"demo":{{"env":"CONFIDENTIAL_INFERENCE_FFI_UNUSED_ENV","inline":"{secret}"}}}}}}"#
            ));
            let mut client = ptr::null_mut();

            assert_eq!(
                confidential_inference_sdk_new(config.as_ptr(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );

            let mut error = ptr::null_mut();
            assert_eq!(
                confidential_inference_last_error(&mut error),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let error_json = take_string(error);
            let error: Value = serde_json::from_str(&error_json).unwrap();
            assert_eq!(error["error"]["code"], "credential_source_ambiguous");
            assert!(!error_json.contains(secret));
        }
    }

    #[test]
    fn status_json_reports_abi_version() {
        let value = serde_json::to_value(status()).unwrap();
        assert_eq!(value["abi_version"], CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION);
    }

    #[test]
    fn ffi_client_config_rejects_demo_provider_with_trusted_signing_keys() {
        unsafe {
            let config = c_string(
                r#"{"demo_provider":true,"trusted_ed25519_signing_keys":[{"signer":"test","key_id":"test-key","public_key_base64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}"#,
            );
            let mut client = ptr::null_mut();

            assert_eq!(
                confidential_inference_sdk_new(config.as_ptr(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );
            let error = last_error_value();
            assert_eq!(error["error"]["code"], "trusted_signing_keys_ambiguous");
            assert!(client.is_null());
        }
    }

    #[test]
    fn ffi_client_config_rejects_non_demo_without_trusted_signing_keys() {
        unsafe {
            for config_json in [
                r#"{"demo_provider":false}"#,
                r#"{"demo_provider":false,"trusted_ed25519_signing_keys":[]}"#,
            ] {
                let config = c_string(config_json);
                let mut client = ptr::null_mut();

                assert_eq!(
                    confidential_inference_sdk_new(config.as_ptr(), &mut client),
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
                );
                let error = last_error_value();
                assert_eq!(error["error"]["code"], "trusted_signing_keys_required");
                assert!(client.is_null());
            }
        }
    }
    #[test]
    fn ffi_client_config_defaults_fail_closed_without_demo_opt_in() {
        unsafe {
            // demo_provider defaults to false: NULL, empty, and omitted
            // configs must all hit the trusted-keys-required refusal.
            for config_ptr in [
                ptr::null(),
                c_string("").as_ptr(),
                c_string("   ").as_ptr(),
                c_string("{}").as_ptr(),
            ] {
                let mut client = ptr::null_mut();
                assert_eq!(
                    confidential_inference_sdk_new(config_ptr, &mut client),
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
                );
                let error = last_error_value();
                assert_eq!(error["error"]["code"], "trusted_signing_keys_required");
                assert!(client.is_null());
            }
        }
    }

    #[test]
    fn ffi_client_config_parse_error_never_echoes_inline_secret() {
        unsafe {
            let secret = "sk-live-parse-secret";
            // Wrong type for api_keys value: serde reports a category error
            // whose Display embeds the raw value — must be scrubbed.
            let config = c_string(&format!(
                r#"{{"demo_provider":true,"api_keys":{{"tinfoil":"{secret}"}}}}"#
            ));
            let mut client = ptr::null_mut();

            assert_eq!(
                confidential_inference_sdk_new(config.as_ptr(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );
            let error_json = {
                let mut error = ptr::null_mut();
                assert_eq!(
                    confidential_inference_last_error(&mut error),
                    CONFIDENTIAL_INFERENCE_FFI_OK
                );
                take_string(error)
            };
            let error: Value = serde_json::from_str(&error_json).unwrap();
            assert_eq!(error["error"]["code"], "invalid_config_json");
            assert!(
                !error_json.contains(secret),
                "error echoed secret: {error_json}"
            );
            assert!(error["error"]["message"].as_str().unwrap().contains("line"));
            assert!(client.is_null());
        }
    }

    #[test]
    fn ffi_client_used_after_fork_refuses_calls() {
        unsafe {
            let client = new_demo_client();
            // Simulate the forked child: owner pid no longer matches.
            let owner_pid = (*client).owner_pid;
            (*client).owner_pid = owner_pid.wrapping_add(1);

            let request = chat_request_json("forked child call");
            let mut out = ptr::null_mut();
            assert_eq!(
                confidential_inference_chat_blocking(client, request.as_ptr(), 0, &mut out),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );
            let error: Value = serde_json::from_str(&take_string(out)).unwrap();
            assert_eq!(error["error"]["code"], "client_used_after_fork");

            (*client).owner_pid = owner_pid;
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_client_free_in_forked_child_leaks_runtime_instead_of_hanging() {
        unsafe {
            let client = new_demo_client();
            (*client).owner_pid = process::id().wrapping_add(1);

            // The child releases the handle and leaks the runtime rather
            // than dropping it (drop would hang on dead worker threads).
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert!(client_shared(client).is_none());
        }
    }

    #[test]
    fn ffi_client_config_rejects_signing_key_with_empty_fields() {
        unsafe {
            let config = c_string(
                r#"{"demo_provider":false,"trusted_ed25519_signing_keys":[{"signer":"test","key_id":"","public_key_base64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}"#,
            );
            let mut client = ptr::null_mut();

            assert_eq!(
                confidential_inference_sdk_new(config.as_ptr(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );
            let error = last_error_value();
            assert_eq!(error["error"]["code"], "trusted_signing_key_field_empty");
            assert!(client.is_null());
        }
    }

    #[test]
    fn ffi_client_config_accepts_exclusive_trusted_signing_keys() {
        unsafe {
            let config = c_string(
                r#"{"demo_provider":false,"trusted_ed25519_signing_keys":[{"signer":"confidential-inference","key_id":"confidential-inference-demo-ed25519-2026","public_key_base64url":"4oqJcHUzMr1y_vQT5rCy7xtKrdp6osFB8jNxKmh2s1E"}]}"#,
            );
            let mut client = ptr::null_mut();

            assert_eq!(
                confidential_inference_sdk_new(config.as_ptr(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_client_free_refuses_runtime_context_teardown() {
        unsafe {
            let client = new_demo_client();
            let runtime = Runtime::new().unwrap();

            let status = runtime.block_on(async { confidential_inference_sdk_free(client) });
            assert_eq!(status, CONFIDENTIAL_INFERENCE_FFI_BUSY);
            let error = last_error_value();
            assert_eq!(
                error["error"]["code"],
                "runtime_teardown_from_runtime_context"
            );

            drop(runtime);
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_client_after_free_returns_invalid_client_without_deref() {
        unsafe {
            let client = new_demo_client();
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let mut policy = ptr::null_mut();
            assert_eq!(
                confidential_inference_active_policy_blocking(client, &mut policy),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );
            let error = last_error_value();
            assert_eq!(error["error"]["code"], "invalid_client");
        }
    }

    #[test]
    fn ffi_string_double_free_sets_defined_last_error() {
        unsafe {
            let mut value = ptr::null_mut();
            assert_eq!(
                confidential_inference_last_error(&mut value),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            confidential_inference_string_free(value);
            confidential_inference_string_free(value);

            let error = last_error_value();
            assert_eq!(error["error"]["code"], "invalid_string");
        }
    }

    #[test]
    fn ffi_stream_start_emits_fail_closed_error_event_for_unsupported_streaming() {
        unsafe {
            let client = new_demo_client();
            let request_json = chat_request_json("ffi stream path");
            let mut stream = ptr::null_mut();

            assert_eq!(
                confidential_inference_chat_stream_start(
                    client,
                    request_json.as_ptr(),
                    &mut stream
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert!(!stream.is_null());
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_BUSY
            );

            let mut event = ptr::null_mut();
            assert_eq!(
                confidential_inference_stream_next(stream, 2_000, &mut event),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let event_json = take_string(event);
            let event: Value = serde_json::from_str(&event_json).unwrap();
            assert_eq!(event["type"], "error");
            assert_eq!(event["status"], "failed");
            assert!(event["error"]["message"]
                .as_str()
                .unwrap()
                .contains("streaming is not supported"));
            assert!(!event_json.contains("ffi stream path"));

            let mut closed = ptr::null_mut();
            assert_eq!(
                confidential_inference_stream_next(stream, 0, &mut closed),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let closed: Value = serde_json::from_str(&take_string(closed)).unwrap();
            assert_eq!(closed["type"], "closed");

            free_stream_and_client(stream, client);
        }
    }

    #[test]
    fn ffi_stream_event_builders_preserve_verdict_chunk_and_usage_payloads() {
        let verdict = json!({
            "response_channel_bound": true,
            "response_integrity_result": "channel_bound",
            "status": "verified"
        });
        let chunk = json!({
            "id": "chunk-id",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "model",
            "choices": [{"index": 0, "delta": {"content": "hi"}, "finish_reason": null}],
            "provider_extra": {"preserved": true}
        });
        let usage = json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3});

        let verdict_event: Value =
            serde_json::from_str(&stream_verdict_event(verdict.clone())).unwrap();
        let chunk_value = chunk.clone();
        let chunk: confidential_inference_sdk::ChatCompletionChunk =
            serde_json::from_value(chunk).unwrap();
        let chunk_event: Value =
            serde_json::from_str(&stream_chunk_event(serde_json::to_value(&chunk).unwrap()))
                .unwrap();
        let usage_event: Value = serde_json::from_str(&stream_usage_event(usage.clone())).unwrap();

        assert_eq!(verdict_event["type"], "verdict");
        assert_eq!(verdict_event["verdict"], verdict);
        assert_eq!(verdict_event["response_channel_bound"], true);
        assert_eq!(chunk_event["type"], "chunk");
        assert_eq!(chunk_event["chunk"], chunk_value);
        assert_eq!(usage_event["type"], "usage");
        assert_eq!(usage_event["usage"], usage);
    }

    #[test]
    fn ffi_stream_error_event_keeps_dispatch_classification() {
        let error = FfiOperationError {
            code: "stream_failed",
            message: "stream failed".into(),
            dispatch: "unknown",
            http_status: None,
        };
        let event: Value = serde_json::from_str(&stream_operation_error_event(&error)).unwrap();
        assert_eq!(event["type"], "error");
        assert_eq!(event["status"], "failed");
        assert_eq!(event["error"]["dispatch"], "unknown");
    }

    #[test]
    fn ffi_stream_open_error_preserves_sdk_dispatch_metadata() {
        let preflight = FfiOperationError::from(ClientError::StreamingNotSupported {
            route_id: "route".into(),
        });
        let dispatched = FfiOperationError::from(ClientError::ResponseJsonSerialization(
            "invalid response".into(),
        ));

        assert_eq!(preflight.dispatch, "not_dispatched");
        assert_eq!(dispatched.dispatch, "unknown");
    }

    #[test]
    fn ffi_stream_queue_publishes_before_terminal_completion() {
        let state = Arc::new((Mutex::new(StreamState::new()), Condvar::new()));
        for event_type in ["verdict", "chunk", "usage", "done"] {
            push_stream_event(&state, json!({ "type": event_type }).to_string());
        }

        for event_type in ["verdict", "chunk", "usage", "done"] {
            match next_stream_event(&state, Duration::ZERO) {
                StreamNext::Event(event) => {
                    let event: Value = serde_json::from_str(&event).unwrap();
                    assert_eq!(event["type"], event_type);
                }
                _ => panic!("incremental event was not available"),
            }
        }
        assert!(matches!(
            next_stream_event(&state, Duration::ZERO),
            StreamNext::Pending
        ));

        finish_stream(&state);
        assert!(matches!(
            next_stream_event(&state, Duration::ZERO),
            StreamNext::Closed
        ));
    }

    #[test]
    fn ffi_stream_after_free_returns_invalid_stream_without_deref() {
        unsafe {
            let client = new_demo_client();
            let request_json = chat_request_json("ffi stream stale handle");
            let mut stream = ptr::null_mut();

            assert_eq!(
                confidential_inference_chat_stream_start(
                    client,
                    request_json.as_ptr(),
                    &mut stream
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let mut event = ptr::null_mut();
            assert_eq!(
                confidential_inference_stream_next(stream, 2_000, &mut event),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            confidential_inference_string_free(event);
            assert_eq!(
                confidential_inference_stream_free(stream),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let mut stale_event = ptr::null_mut();
            assert_eq!(
                confidential_inference_stream_next(stream, 0, &mut stale_event),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );
            let error: Value = serde_json::from_str(&take_string(stale_event)).unwrap();
            assert_eq!(error["error"]["code"], "invalid_stream");
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_stream_free_and_next_refuse_pending_stream() {
        unsafe {
            let client = new_demo_client();
            let shared = client_shared(client).unwrap();
            let stream = Box::into_raw(spawn_stream(shared, |_| async {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }));
            register_handle(live_stream_handles(), stream);

            let mut event = ptr::null_mut();
            assert_eq!(
                confidential_inference_stream_next(stream, 0, &mut event),
                CONFIDENTIAL_INFERENCE_FFI_PENDING
            );
            assert!(event.is_null());
            let error = last_error_value();
            assert_eq!(error["error"]["code"], "stream_pending");

            assert_eq!(
                confidential_inference_stream_free(stream),
                CONFIDENTIAL_INFERENCE_FFI_BUSY
            );
            let error = last_error_value();
            assert_eq!(error["error"]["code"], "stream_busy");

            assert_eq!(
                confidential_inference_stream_cancel(stream),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            free_stream_and_client(stream, client);
        }
    }

    #[test]
    fn ffi_stream_cancel_is_idempotent_and_returns_cancellation_event() {
        unsafe {
            let client = new_demo_client();
            let request_json = chat_request_json("ffi stream cancel");
            let mut stream = ptr::null_mut();
            assert_eq!(
                confidential_inference_chat_stream_start(
                    client,
                    request_json.as_ptr(),
                    &mut stream
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            assert_eq!(
                confidential_inference_stream_cancel(stream),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert_eq!(
                confidential_inference_stream_cancel(stream),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let mut event = ptr::null_mut();
            assert_eq!(
                confidential_inference_stream_next(stream, 0, &mut event),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let event: Value = serde_json::from_str(&take_string(event)).unwrap();
            assert!(event["type"] == "cancelled" || event["type"] == "error");

            free_stream_and_client(stream, client);
        }
    }

    #[test]
    fn ffi_status_reports_available_and_future_surfaces() {
        let status = status();
        assert!(status.stream_handle_abi_available);
        assert!(status.blocking_helpers_available);
    }

    #[test]
    fn ffi_status_export_returns_capability_json() {
        unsafe {
            let mut status_json = ptr::null_mut();
            assert_eq!(
                confidential_inference_status(&mut status_json),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let status: Value = serde_json::from_str(&take_string(status_json)).unwrap();
            assert_eq!(status["stream_handle_abi_available"], true);
            assert_eq!(status["blocking_helpers_available"], true);
            assert!(status["reason"]
                .as_str()
                .unwrap()
                .contains("chat, Responses creation and lifecycle management, verify"));

            assert_eq!(
                confidential_inference_status(ptr::null_mut()),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );
            let error = last_error_value();
            assert_eq!(error["error"]["code"], "invalid_argument");
            assert!(error["error"]["message"]
                .as_str()
                .unwrap()
                .contains("output string pointer"));
        }
    }

    #[test]
    fn ffi_header_lists_exported_abi_surface() {
        let header = include_str!("../include/confidential_inference_ffi.h");
        for needle in [
            "#define CONFIDENTIAL_INFERENCE_FFI_OK 0",
            "#define CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT 1",
            "#define CONFIDENTIAL_INFERENCE_FFI_PANIC 2",
            "#define CONFIDENTIAL_INFERENCE_FFI_BUSY 3",
            "#define CONFIDENTIAL_INFERENCE_FFI_PENDING 4",
            "#define CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED 5",
            "#define CONFIDENTIAL_INFERENCE_FFI_INTERNAL 6",
            "typedef struct ConfidentialInferenceFfiClient ConfidentialInferenceFfiClient;",
            "typedef struct ConfidentialInferenceFfiStream ConfidentialInferenceFfiStream;",
            "int confidential_inference_status(",
            "int confidential_inference_sdk_new(",
            "int confidential_inference_sdk_free(",
            "int confidential_inference_chat_blocking(",
            "int confidential_inference_embeddings_blocking(",
            "int confidential_inference_response_blocking(",
            "int confidential_inference_verify_blocking(",
            "int confidential_inference_models_blocking(",
            "int confidential_inference_confidentiality_blocking(",
            "int confidential_inference_active_policy_blocking(",
            "int confidential_inference_active_trust_artifacts_blocking(",
            "int confidential_inference_chat_stream_start(",
            "int confidential_inference_stream_next(",
            "int confidential_inference_stream_cancel(",
            "int confidential_inference_stream_free(",
            "int confidential_inference_last_error(",
            "void confidential_inference_string_free(",
        ] {
            assert!(header.contains(needle), "header missing {needle}");
        }
    }
}
