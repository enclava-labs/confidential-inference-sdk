//! Async operation-handle C ABI for `confidential-inference-sdk`.
//!
//! Complex request and response payloads cross the ABI as JSON. Provider
//! routing, request adaptation, attestation, and verdict enforcement remain in
//! `confidential-inference-sdk` and lower crates.

use confidential_inference_sdk::{
    ChatCompletionRequestPayload, ClientError, ConfidentialInference, ProviderRoutingConfig,
    ResponseCreateRequestPayload,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::env;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::future::Future;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::IntoRawFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tokio::runtime::{Handle, Runtime};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

pub const CONFIDENTIAL_INFERENCE_FFI_OK: c_int = 0;
pub const CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT: c_int = 1;
pub const CONFIDENTIAL_INFERENCE_FFI_PANIC: c_int = 2;
pub const CONFIDENTIAL_INFERENCE_FFI_BUSY: c_int = 3;
pub const CONFIDENTIAL_INFERENCE_FFI_PENDING: c_int = 4;
pub const CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED: c_int = 5;
pub const CONFIDENTIAL_INFERENCE_FFI_INTERNAL: c_int = 6;

pub type ConfidentialInferenceFfiCallback = extern "C" fn(user_data: *mut c_void);

thread_local! {
    static LAST_ERROR: RefCell<Option<FfiErrorJson>> = const { RefCell::new(None) };
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FfiErrorJson {
    code: &'static str,
    message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    #[serde(default = "default_true")]
    demo_provider: bool,
    #[serde(default)]
    allow_inline_api_keys: bool,
    #[serde(default)]
    api_keys: BTreeMap<String, ApiKeyConfig>,
    #[serde(default)]
    routing: ProviderRoutingConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiKeyConfig {
    #[serde(default)]
    env: Option<String>,
    #[serde(default)]
    inline: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            demo_provider: true,
            allow_inline_api_keys: false,
            api_keys: BTreeMap::new(),
            routing: ProviderRoutingConfig::default(),
        }
    }
}

fn default_true() -> bool {
    true
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
            let inline = Zeroizing::new(inline);
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
                })
            }
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ConfigError {
                    code: "credential_env_invalid",
                    message: format!(
                        "api key environment variable {env_name} for provider {provider} is not valid Unicode"
                    ),
                })
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

pub struct ConfidentialInferenceFfiClient {
    shared: Arc<ClientShared>,
}

struct ClientShared {
    runtime: Runtime,
    client: ConfidentialInference,
    live_operations: AtomicUsize,
}

pub struct ConfidentialInferenceFfiOperation {
    shared: Arc<ClientShared>,
    state: Arc<Mutex<OperationState>>,
    join: Mutex<Option<JoinHandle<()>>>,
    #[cfg(unix)]
    readiness_read: Mutex<Option<UnixStream>>,
}

pub struct ConfidentialInferenceFfiStream {
    shared: Arc<ClientShared>,
    state: Arc<Mutex<StreamState>>,
    join: Mutex<Option<JoinHandle<()>>>,
    #[cfg(unix)]
    readiness_read: Mutex<Option<UnixStream>>,
}

fn live_client_handles() -> &'static Mutex<HashSet<usize>> {
    static HANDLES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn live_operation_handles() -> &'static Mutex<HashSet<usize>> {
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

fn is_handle_live<T>(handles: &'static Mutex<HashSet<usize>>, ptr: *const T) -> bool {
    !ptr.is_null()
        && handles
            .lock()
            .map(|handles| handles.contains(&pointer_key(ptr)))
            .unwrap_or(false)
}

fn unregister_handle<T>(handles: &'static Mutex<HashSet<usize>>, ptr: *mut T) -> bool {
    !ptr.is_null()
        && handles
            .lock()
            .map(|mut handles| handles.remove(&pointer_key(ptr)))
            .unwrap_or(false)
}

#[derive(Debug)]
struct OperationState {
    terminal: OperationTerminal,
    callback: Option<ConfidentialInferenceFfiCallback>,
    user_data: usize,
    #[cfg(unix)]
    readiness_writer: Option<UnixStream>,
}

impl OperationState {
    fn new(#[cfg(unix)] readiness_writer: Option<UnixStream>) -> Self {
        Self {
            terminal: OperationTerminal::Pending,
            callback: None,
            user_data: 0,
            #[cfg(unix)]
            readiness_writer,
        }
    }
}

#[derive(Clone, Debug)]
enum OperationTerminal {
    Pending,
    Ready(String),
    Failed(String),
    Cancelled,
}

#[derive(Debug)]
struct StreamState {
    events: VecDeque<String>,
    terminal: bool,
    callback: Option<ConfidentialInferenceFfiCallback>,
    user_data: usize,
    #[cfg(unix)]
    readiness_writer: Option<UnixStream>,
}

impl StreamState {
    fn new(#[cfg(unix)] readiness_writer: Option<UnixStream>) -> Self {
        Self {
            events: VecDeque::new(),
            terminal: false,
            callback: None,
            user_data: 0,
            #[cfg(unix)]
            readiness_writer,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FfiStatus {
    pub async_handle_abi_available: bool,
    pub callbacks_available: bool,
    pub readiness_fd_available: bool,
    pub stream_handle_abi_available: bool,
    pub blocking_helpers_available: bool,
    pub reason: &'static str,
}

pub fn status() -> FfiStatus {
    FfiStatus {
        async_handle_abi_available: true,
        callbacks_available: true,
        readiness_fd_available: cfg!(unix),
        stream_handle_abi_available: true,
        blocking_helpers_available: true,
        reason: "chat, responses, verify, model discovery, confidentiality catalog, active policy, active trust artifacts, stream handles, and blocking helper wrappers are available; current stream execution preserves SDK fail-closed streaming semantics",
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
                )
            }
        };

        let runtime = match Runtime::new() {
            Ok(runtime) => runtime,
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "runtime_create_failed",
                    &format!("failed to create Tokio runtime: {error}"),
                )
            }
        };

        let provider_routing = config.routing.clone();
        let mut builder = ConfidentialInference::builder().provider_routing(provider_routing);
        if config.demo_provider {
            builder = builder.with_demo_provider();
        }
        for (provider, api_key) in match resolve_api_keys(config) {
            Ok(api_keys) => api_keys,
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    error.code,
                    &error.message,
                )
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
                )
            }
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "client_build_failed",
                    &format!("failed to build ConfidentialInference client: {error}"),
                )
            }
        };

        let handle = Box::new(ConfidentialInferenceFfiClient {
            shared: Arc::new(ClientShared {
                runtime,
                client,
                live_operations: AtomicUsize::new(0),
            }),
        });
        let handle = Box::into_raw(handle);
        register_handle(live_client_handles(), handle);
        *out_client = handle;
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Frees a client handle when no operations spawned from it are live.
///
/// # Safety
///
/// `client` must be null or a handle returned by `confidential_inference_sdk_new` that has
/// not already been freed. If operations are live, this function returns
/// `CONFIDENTIAL_INFERENCE_FFI_BUSY` and leaves ownership with the caller.
pub unsafe extern "C" fn confidential_inference_sdk_free(
    client: *mut ConfidentialInferenceFfiClient,
) -> c_int {
    ffi_boundary(|| unsafe {
        if client.is_null() {
            clear_last_error();
            return CONFIDENTIAL_INFERENCE_FFI_OK;
        }
        if !is_handle_live(live_client_handles(), client) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client handle is not live or was already freed",
            );
        }

        let client_ref = &*client;
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

        if !unregister_handle(live_client_handles(), client) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_client",
                "client handle is not live or was already freed",
            );
        }
        drop(Box::from_raw(client));
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Starts an asynchronous chat operation from OpenAI-shaped request JSON.
///
/// # Safety
///
/// `client` must be a valid live client handle. `request_json` must point to a
/// valid NUL-terminated UTF-8 C string for the duration of the call.
/// `out_operation` must be a valid writable pointer to an operation-handle slot.
pub unsafe extern "C" fn confidential_inference_chat_start(
    client: *mut ConfidentialInferenceFfiClient,
    request_json: *const c_char,
    out_operation: *mut *mut ConfidentialInferenceFfiOperation,
) -> c_int {
    ffi_boundary(|| unsafe {
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
                )
            }
        };
        if out_operation.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_operation must not be null",
            );
        }
        *out_operation = ptr::null_mut();

        let request = match parse_chat_request(&request_json, "chat") {
            Ok(request) => request,
            Err(code) => return code,
        };

        let operation =
            spawn_operation_with_client(
                shared,
                move || async move { chat_result_json(request).await },
            );
        let operation = Box::into_raw(operation);
        register_handle(live_operation_handles(), operation);
        *out_operation = operation;
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Starts an asynchronous Responses API operation from OpenAI-shaped request JSON.
///
/// # Safety
///
/// `client` must be a valid live client handle. `request_json` must point to a
/// valid NUL-terminated UTF-8 C string for the duration of the call.
/// `out_operation` must be a valid writable pointer to an operation-handle slot.
pub unsafe extern "C" fn confidential_inference_response_start(
    client: *mut ConfidentialInferenceFfiClient,
    request_json: *const c_char,
    out_operation: *mut *mut ConfidentialInferenceFfiOperation,
) -> c_int {
    ffi_boundary(|| unsafe {
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
                )
            }
        };
        if out_operation.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_operation must not be null",
            );
        }
        *out_operation = ptr::null_mut();

        let request = match parse_response_request(&request_json, "response") {
            Ok(request) => request,
            Err(code) => return code,
        };

        let operation = spawn_operation_with_client(shared, move || async move {
            response_result_json(request).await
        });
        let operation = Box::into_raw(operation);
        register_handle(live_operation_handles(), operation);
        *out_operation = operation;
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Starts an asynchronous route verification operation.
///
/// # Safety
///
/// `client` must be a valid live client handle. `request_json` must point to a
/// valid NUL-terminated UTF-8 C string containing
/// `{"provider":"...","model":"..."}` for the duration of the call.
/// `out_operation` must be a valid writable pointer to an operation-handle slot.
pub unsafe extern "C" fn confidential_inference_verify_start(
    client: *mut ConfidentialInferenceFfiClient,
    request_json: *const c_char,
    out_operation: *mut *mut ConfidentialInferenceFfiOperation,
) -> c_int {
    ffi_boundary(|| unsafe {
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
                )
            }
        };
        if out_operation.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_operation must not be null",
            );
        }
        *out_operation = ptr::null_mut();

        let request = match parse_verify_request(&request_json, "verify") {
            Ok(request) => request,
            Err(code) => return code,
        };

        let operation = spawn_operation_with_client(shared, move || async move {
            verify_result_json(request).await
        });
        let operation = Box::into_raw(operation);
        register_handle(live_operation_handles(), operation);
        *out_operation = operation;
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
    ffi_boundary(|| unsafe {
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
                )
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
    ffi_boundary(|| unsafe {
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
                )
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
    ffi_boundary(|| unsafe {
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
                )
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
    ffi_boundary(|| unsafe {
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
                )
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
    ffi_boundary(|| unsafe {
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
                )
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
    ffi_boundary(|| unsafe {
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
                )
            }
        };
        let policy_json = match serde_json::to_string(&snapshot) {
            Ok(json) => json,
            Err(error) => {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "active_policy_serialization_failed",
                    &format!("failed to serialize active policy JSON: {error}"),
                )
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
    ffi_boundary(|| unsafe {
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
                )
            }
        };
        write_c_string(out_artifacts_json, artifacts_json)
    })
}

#[no_mangle]
/// Polls an operation and returns a newly allocated JSON state string.
///
/// # Safety
///
/// `operation` must be a valid live operation handle. `out_state_json` must be
/// a valid writable pointer. The returned string must be freed with
/// `confidential_inference_string_free`.
pub unsafe extern "C" fn confidential_inference_op_poll(
    operation: *mut ConfidentialInferenceFfiOperation,
    out_state_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary(|| unsafe {
        let Some(operation) = operation_ref(operation) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_operation",
                "operation must not be null",
            );
        };
        settle_finished_task(operation);
        let state_json = operation_state_json(operation);
        write_c_string(out_state_json, state_json)
    })
}

#[no_mangle]
/// Returns a newly allocated operation result JSON string after terminal state.
///
/// # Safety
///
/// `operation` must be a valid live operation handle. `out_result_json` must be
/// a valid writable pointer. The returned string must be freed with
/// `confidential_inference_string_free`.
pub unsafe extern "C" fn confidential_inference_op_result_json(
    operation: *mut ConfidentialInferenceFfiOperation,
    out_result_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary(|| unsafe {
        let Some(operation) = operation_ref(operation) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_operation",
                "operation must not be null",
            );
        };
        settle_finished_task(operation);
        let result = operation_result_json(operation);
        match result {
            Ok(json) => write_c_string(out_result_json, json),
            Err(code) => code,
        }
    })
}

#[no_mangle]
/// Registers or clears a callback invoked when the operation reaches a terminal state.
///
/// # Safety
///
/// `operation` must be a valid live operation handle. `callback`, when present,
/// must be safe to call with `user_data` on an SDK runtime worker thread or the
/// calling thread if the operation is already terminal. Rust never dereferences
/// `user_data`.
pub unsafe extern "C" fn confidential_inference_op_set_callback(
    operation: *mut ConfidentialInferenceFfiOperation,
    callback: Option<ConfidentialInferenceFfiCallback>,
    user_data: *mut c_void,
) -> c_int {
    ffi_boundary(|| unsafe {
        let Some(operation) = operation_ref(operation) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_operation",
                "operation must not be null",
            );
        };
        settle_finished_task(operation);

        let call_now = {
            let Ok(mut state) = operation.state.lock() else {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "operation_lock_failed",
                    "failed to lock operation state",
                );
            };
            state.callback = callback;
            state.user_data = user_data as usize;
            terminal_status(&state.terminal) != "pending"
        };

        if call_now {
            if let Some(callback) = callback {
                callback(user_data);
            }
        }
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Requests a readiness file descriptor for an operation.
///
/// # Safety
///
/// `operation` must be a valid live operation handle. `out_fd` must be
/// writable. On Unix this returns a readable file descriptor exactly once; the
/// caller owns and must close it. On non-Unix targets this returns
/// `CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED` and writes `-1`.
pub unsafe extern "C" fn confidential_inference_op_readiness_fd(
    operation: *mut ConfidentialInferenceFfiOperation,
    out_fd: *mut c_int,
) -> c_int {
    ffi_boundary(|| unsafe {
        if out_fd.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_fd must not be null",
            );
        }
        *out_fd = -1;

        #[cfg(unix)]
        {
            let Some(operation) = operation_ref(operation) else {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    "invalid_operation",
                    "operation must not be null",
                );
            };
            settle_finished_task(operation);
            let fd = {
                let Ok(mut readiness_read) = operation.readiness_read.lock() else {
                    return ffi_error(
                        CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                        "readiness_fd_lock_failed",
                        "failed to lock readiness fd state",
                    );
                };
                let Some(readiness_read) = readiness_read.take() else {
                    return ffi_error(
                        CONFIDENTIAL_INFERENCE_FFI_BUSY,
                        "readiness_fd_already_taken",
                        "operation readiness fd was already taken",
                    );
                };
                readiness_read.into_raw_fd()
            };
            *out_fd = fd;
            clear_last_error();
            CONFIDENTIAL_INFERENCE_FFI_OK
        }

        #[cfg(not(unix))]
        {
            let _ = operation;
            ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED,
                "readiness_fd_unsupported",
                "readiness file descriptors are not available on this platform",
            )
        }
    })
}

#[no_mangle]
/// Cancels an operation if it has not completed.
///
/// # Safety
///
/// `operation` must be a valid live operation handle. Cancellation is
/// idempotent; result JSON for a cancelled operation is
/// `{"status":"cancelled"}`.
pub unsafe extern "C" fn confidential_inference_op_cancel(
    operation: *mut ConfidentialInferenceFfiOperation,
) -> c_int {
    ffi_boundary(|| unsafe {
        let Some(operation) = operation_ref(operation) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_operation",
                "operation must not be null",
            );
        };
        if let Ok(mut join) = operation.join.lock() {
            if let Some(handle) = join.take() {
                handle.abort();
            }
        }
        complete_operation(&operation.state, OperationTerminal::Cancelled);
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Frees a terminal operation handle.
///
/// # Safety
///
/// `operation` must be null or a handle returned by `confidential_inference_chat_start` or
/// `confidential_inference_verify_start` that has not already been freed. Pending operations
/// return `CONFIDENTIAL_INFERENCE_FFI_BUSY` and remain owned by the caller.
pub unsafe extern "C" fn confidential_inference_op_free(
    operation: *mut ConfidentialInferenceFfiOperation,
) -> c_int {
    ffi_boundary(|| unsafe {
        if operation.is_null() {
            clear_last_error();
            return CONFIDENTIAL_INFERENCE_FFI_OK;
        }
        if !is_handle_live(live_operation_handles(), operation) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_operation",
                "operation handle is not live or was already freed",
            );
        }
        let operation_ref = &*operation;
        settle_finished_task(operation_ref);
        if operation_is_pending(operation_ref) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_BUSY,
                "operation_busy",
                "operation is still pending; cancel or wait before freeing",
            );
        }

        if !unregister_handle(live_operation_handles(), operation) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_operation",
                "operation handle is not live or was already freed",
            );
        }
        let operation = Box::from_raw(operation);
        operation
            .shared
            .live_operations
            .fetch_sub(1, Ordering::SeqCst);
        drop(operation);
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Starts a chat stream handle from OpenAI-shaped request JSON.
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
                )
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
        let request = request.with_streaming(true);

        let stream =
            spawn_stream_with_client(shared, move || async move { stream_events(request).await });
        let stream = Box::into_raw(stream);
        register_handle(live_stream_handles(), stream);
        *out_stream = stream;
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Returns the next stream event as a newly allocated JSON string.
///
/// # Safety
///
/// `stream` must be a valid live stream handle. `out_event_json` must be a
/// valid writable pointer. The returned string must be freed with
/// `confidential_inference_string_free`.
pub unsafe extern "C" fn confidential_inference_stream_next(
    stream: *mut ConfidentialInferenceFfiStream,
    timeout_ms: u64,
    out_event_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary(|| unsafe {
        let Some(stream) = stream_ref(stream) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_stream",
                "stream must not be null",
            );
        };
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            settle_finished_stream_task(stream);
            match next_stream_event(stream) {
                StreamNext::Event(event) => return write_c_string(out_event_json, event),
                StreamNext::Closed => {
                    return write_c_string(out_event_json, json!({ "type": "closed" }).to_string())
                }
                StreamNext::Pending => {
                    if timeout_ms == 0 || Instant::now() >= deadline {
                        return ffi_error(
                            CONFIDENTIAL_INFERENCE_FFI_PENDING,
                            "stream_pending",
                            "stream event is not ready yet",
                        );
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
    })
}

#[no_mangle]
/// Registers or clears a callback invoked when stream events become available.
///
/// # Safety
///
/// `stream` must be a valid live stream handle. `callback`, when present, must
/// be safe to call with `user_data` on an SDK runtime worker thread or the
/// calling thread if events are already available. Rust never dereferences
/// `user_data`.
pub unsafe extern "C" fn confidential_inference_stream_set_callback(
    stream: *mut ConfidentialInferenceFfiStream,
    callback: Option<ConfidentialInferenceFfiCallback>,
    user_data: *mut c_void,
) -> c_int {
    ffi_boundary(|| unsafe {
        let Some(stream) = stream_ref(stream) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_stream",
                "stream must not be null",
            );
        };
        settle_finished_stream_task(stream);
        let call_now = {
            let Ok(mut state) = stream.state.lock() else {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                    "stream_lock_failed",
                    "failed to lock stream state",
                );
            };
            state.callback = callback;
            state.user_data = user_data as usize;
            !state.events.is_empty() || state.terminal
        };
        if call_now {
            if let Some(callback) = callback {
                callback(user_data);
            }
        }
        clear_last_error();
        CONFIDENTIAL_INFERENCE_FFI_OK
    })
}

#[no_mangle]
/// Requests a readiness file descriptor for a stream.
///
/// # Safety
///
/// `stream` must be a valid live stream handle. `out_fd` must be writable. On
/// Unix this returns a readable file descriptor exactly once; the caller owns
/// and must close it. On non-Unix targets this returns `CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED`
/// and writes `-1`.
pub unsafe extern "C" fn confidential_inference_stream_readiness_fd(
    stream: *mut ConfidentialInferenceFfiStream,
    out_fd: *mut c_int,
) -> c_int {
    ffi_boundary(|| unsafe {
        if out_fd.is_null() {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_argument",
                "out_fd must not be null",
            );
        }
        *out_fd = -1;

        #[cfg(unix)]
        {
            let Some(stream) = stream_ref(stream) else {
                return ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                    "invalid_stream",
                    "stream must not be null",
                );
            };
            settle_finished_stream_task(stream);
            let fd = {
                let Ok(mut readiness_read) = stream.readiness_read.lock() else {
                    return ffi_error(
                        CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                        "readiness_fd_lock_failed",
                        "failed to lock stream readiness fd state",
                    );
                };
                let Some(readiness_read) = readiness_read.take() else {
                    return ffi_error(
                        CONFIDENTIAL_INFERENCE_FFI_BUSY,
                        "readiness_fd_already_taken",
                        "stream readiness fd was already taken",
                    );
                };
                readiness_read.into_raw_fd()
            };
            *out_fd = fd;
            clear_last_error();
            CONFIDENTIAL_INFERENCE_FFI_OK
        }

        #[cfg(not(unix))]
        {
            let _ = stream;
            ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED,
                "readiness_fd_unsupported",
                "stream readiness file descriptors are not available on this platform",
            )
        }
    })
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
        let Some(stream) = stream_ref(stream) else {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_stream",
                "stream must not be null",
            );
        };
        if let Ok(mut join) = stream.join.lock() {
            if let Some(handle) = join.take() {
                handle.abort();
            }
        }
        complete_stream(
            &stream.state,
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
        if !is_handle_live(live_stream_handles(), stream) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_stream",
                "stream handle is not live or was already freed",
            );
        }
        let stream_ref = &*stream;
        settle_finished_stream_task(stream_ref);
        if stream_is_pending(stream_ref) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_BUSY,
                "stream_busy",
                "stream is still pending; cancel or drain before freeing",
            );
        }

        if !unregister_handle(live_stream_handles(), stream) {
            return ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                "invalid_stream",
                "stream handle is not live or was already freed",
            );
        }
        let stream = Box::from_raw(stream);
        stream.shared.live_operations.fetch_sub(1, Ordering::SeqCst);
        drop(stream);
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
        let body = LAST_ERROR.with(|slot| {
            let error = slot.borrow().clone();
            match error {
                Some(error) => json!({
                    "error": {
                        "type": "confidential_inference_ffi_error",
                        "code": error.code,
                        "message": error.message,
                    }
                })
                .to_string(),
                None => json!({ "error": null }).to_string(),
            }
        });
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

fn spawn_operation<F>(
    shared: Arc<ClientShared>,
    future: F,
) -> Box<ConfidentialInferenceFfiOperation>
where
    F: std::future::Future<Output = Result<String, String>> + Send + 'static,
{
    shared.live_operations.fetch_add(1, Ordering::SeqCst);
    #[cfg(unix)]
    let (readiness_read, readiness_writer) = readiness_pair();
    let state = Arc::new(Mutex::new(OperationState::new(
        #[cfg(unix)]
        readiness_writer,
    )));
    let task_state = state.clone();
    let join = shared.runtime.spawn(async move {
        let terminal = match future.await {
            Ok(json) => OperationTerminal::Ready(json),
            Err(message) => OperationTerminal::Failed(async_error_json(&message)),
        };
        complete_operation(&task_state, terminal);
    });

    Box::new(ConfidentialInferenceFfiOperation {
        shared,
        state,
        join: Mutex::new(Some(join)),
        #[cfg(unix)]
        readiness_read: Mutex::new(readiness_read),
    })
}

async fn chat_result_json(request: ChatCompletionRequestPayload) -> Result<String, String> {
    let client = current_operation_client().ok_or_else(|| "operation client missing".to_owned())?;
    client
        .send_chat_completion_payload_json(request)
        .await
        .map_err(|error| error.to_string())
}

async fn response_result_json(request: ResponseCreateRequestPayload) -> Result<String, String> {
    let client = current_operation_client().ok_or_else(|| "operation client missing".to_owned())?;
    client
        .create_response_payload_json(request)
        .await
        .map_err(|error| error.to_string())
}

async fn verify_result_json(request: VerifyRequest) -> Result<String, String> {
    let client = current_operation_client().ok_or_else(|| "operation client missing".to_owned())?;
    let verified = client
        .verify_route(request.provider, request.model)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_string(verified.verdict())
        .map_err(|error| format!("failed to serialize attestation verdict JSON: {error}"))
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
    Fut: Future<Output = Result<String, String>>,
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
                return Err(ffi_error(
                    CONFIDENTIAL_INFERENCE_FFI_PENDING,
                    "operation_timeout",
                    "blocking operation did not complete before timeout",
                ))
            }
        }
    };

    Ok(match result {
        Ok(json) => json,
        Err(message) => async_error_json(&message),
    })
}

fn spawn_operation_with_client<F, Fut>(
    shared: Arc<ClientShared>,
    operation: F,
) -> Box<ConfidentialInferenceFfiOperation>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<String, String>> + Send + 'static,
{
    let client = shared.client.clone();
    spawn_operation(shared, async move {
        OPERATION_CLIENT.scope(client, operation()).await
    })
}

fn spawn_stream<F>(shared: Arc<ClientShared>, future: F) -> Box<ConfidentialInferenceFfiStream>
where
    F: std::future::Future<Output = Vec<String>> + Send + 'static,
{
    shared.live_operations.fetch_add(1, Ordering::SeqCst);
    #[cfg(unix)]
    let (readiness_read, readiness_writer) = readiness_pair();
    let state = Arc::new(Mutex::new(StreamState::new(
        #[cfg(unix)]
        readiness_writer,
    )));
    let task_state = state.clone();
    let join = shared.runtime.spawn(async move {
        let events = future.await;
        complete_stream(&task_state, events);
    });

    Box::new(ConfidentialInferenceFfiStream {
        shared,
        state,
        join: Mutex::new(Some(join)),
        #[cfg(unix)]
        readiness_read: Mutex::new(readiness_read),
    })
}

fn spawn_stream_with_client<F, Fut>(
    shared: Arc<ClientShared>,
    stream: F,
) -> Box<ConfidentialInferenceFfiStream>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Vec<String>> + Send + 'static,
{
    let client = shared.client.clone();
    spawn_stream(shared, async move {
        OPERATION_CLIENT.scope(client, stream()).await
    })
}

async fn stream_events(request: ChatCompletionRequestPayload) -> Vec<String> {
    let Some(client) = current_operation_client() else {
        return vec![stream_error_event("operation client missing")];
    };

    match client.send_chat_completion_payload_json(request).await {
        Ok(response_json) => match stream_response_events(&response_json) {
            Ok(events) => events,
            Err(error) => vec![stream_error_event(&error)],
        },
        Err(error) => vec![stream_error_event(&error.to_string())],
    }
}

fn stream_response_events(response_json: &str) -> Result<Vec<String>, String> {
    let response: serde_json::Value = serde_json::from_str(response_json)
        .map_err(|error| format!("failed to parse chat response JSON: {error}"))?;
    let response_integrity_result = response
        .get("response_integrity_result")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "chat response JSON is missing response_integrity_result".to_owned())?;
    if response_integrity_result == "receipt_bound" {
        return Err(
            "stream opening verdict must not report receipt-bound response integrity before a terminal response_receipt event"
                .into(),
        );
    }
    Ok(vec![
        json!({
            "type": "verdict",
            "response_channel_bound": response["response_channel_bound"].clone(),
            "response_integrity_result": response["response_integrity_result"].clone(),
            "verdict": response["verdict"].clone(),
        })
        .to_string(),
        json!({
            "type": "response",
            "response": response["response"].clone(),
        })
        .to_string(),
        json!({ "type": "done" }).to_string(),
    ])
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

fn complete_operation(state: &Arc<Mutex<OperationState>>, terminal: OperationTerminal) {
    #[cfg(unix)]
    let readiness_writer;
    #[cfg(not(unix))]
    let readiness_writer = ();
    let callback = {
        let Ok(mut state) = state.lock() else {
            return;
        };
        if !matches!(state.terminal, OperationTerminal::Pending) {
            return;
        }
        state.terminal = terminal;
        #[cfg(unix)]
        {
            readiness_writer = state.readiness_writer.take();
        }
        state
            .callback
            .map(|callback| (callback, state.user_data as *mut c_void))
    };

    signal_readiness(readiness_writer);

    if let Some((callback, user_data)) = callback {
        callback(user_data);
    }
}

fn complete_stream(state: &Arc<Mutex<StreamState>>, events: Vec<String>) {
    #[cfg(unix)]
    let readiness_writer;
    #[cfg(not(unix))]
    let readiness_writer = ();
    let callback = {
        let Ok(mut state) = state.lock() else {
            return;
        };
        if state.terminal {
            return;
        }
        state.events.extend(events);
        state.terminal = true;
        #[cfg(unix)]
        {
            readiness_writer = state.readiness_writer.take();
        }
        state
            .callback
            .map(|callback| (callback, state.user_data as *mut c_void))
    };

    signal_readiness(readiness_writer);

    if let Some((callback, user_data)) = callback {
        callback(user_data);
    }
}

fn settle_finished_task(operation: &ConfidentialInferenceFfiOperation) {
    let handle = {
        let Ok(mut join) = operation.join.lock() else {
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
    if !operation_is_pending(operation) {
        drop(handle);
        return;
    }
    if in_tokio_runtime_context() {
        complete_operation(
            &operation.state,
            OperationTerminal::Failed(async_error_json(
                "operation task finished but cannot be joined from a Tokio runtime context",
            )),
        );
        drop(handle);
        return;
    }
    match operation.shared.runtime.block_on(handle) {
        Ok(()) => {}
        Err(error) if error.is_cancelled() => {
            complete_operation(&operation.state, OperationTerminal::Cancelled);
        }
        Err(error) => {
            complete_operation(
                &operation.state,
                OperationTerminal::Failed(async_error_json(&format!(
                    "operation task failed: {error}"
                ))),
            );
        }
    }
}

fn settle_finished_stream_task(stream: &ConfidentialInferenceFfiStream) {
    let handle = {
        let Ok(mut join) = stream.join.lock() else {
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
    if !stream_is_pending(stream) {
        drop(handle);
        return;
    }
    if in_tokio_runtime_context() {
        complete_stream(
            &stream.state,
            vec![stream_error_event(
                "stream task finished but cannot be joined from a Tokio runtime context",
            )],
        );
        drop(handle);
        return;
    }
    match stream.shared.runtime.block_on(handle) {
        Ok(()) => {}
        Err(error) if error.is_cancelled() => {
            complete_stream(
                &stream.state,
                vec![json!({ "type": "cancelled" }).to_string()],
            );
        }
        Err(error) => {
            complete_stream(
                &stream.state,
                vec![stream_error_event(&format!("stream task failed: {error}"))],
            );
        }
    }
}

fn operation_state_json(operation: &ConfidentialInferenceFfiOperation) -> String {
    let terminal = operation
        .state
        .lock()
        .map(|state| state.terminal.clone())
        .unwrap_or_else(|_| OperationTerminal::Failed(async_error_json("operation lock failed")));
    match terminal {
        OperationTerminal::Pending => json!({ "status": "pending" }).to_string(),
        OperationTerminal::Ready(_) => json!({ "status": "ready" }).to_string(),
        OperationTerminal::Failed(json) => json!({
            "status": "failed",
            "result_available": true,
            "error": serde_json::from_str::<serde_json::Value>(&json).unwrap_or_else(|_| json!({ "message": json })),
        })
        .to_string(),
        OperationTerminal::Cancelled => json!({ "status": "cancelled" }).to_string(),
    }
}

fn operation_result_json(operation: &ConfidentialInferenceFfiOperation) -> Result<String, c_int> {
    let terminal = match operation.state.lock() {
        Ok(state) => state.terminal.clone(),
        Err(_) => {
            return Err(ffi_error(
                CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                "operation_lock_failed",
                "failed to lock operation state",
            ))
        }
    };
    match terminal {
        OperationTerminal::Pending => Err(ffi_error(
            CONFIDENTIAL_INFERENCE_FFI_PENDING,
            "operation_pending",
            "operation result is not ready yet",
        )),
        OperationTerminal::Ready(json) | OperationTerminal::Failed(json) => Ok(json),
        OperationTerminal::Cancelled => Ok(json!({ "status": "cancelled" }).to_string()),
    }
}

fn operation_is_pending(operation: &ConfidentialInferenceFfiOperation) -> bool {
    operation
        .state
        .lock()
        .map(|state| matches!(state.terminal, OperationTerminal::Pending))
        .unwrap_or(false)
}

enum StreamNext {
    Event(String),
    Pending,
    Closed,
}

fn next_stream_event(stream: &ConfidentialInferenceFfiStream) -> StreamNext {
    let Ok(mut state) = stream.state.lock() else {
        return StreamNext::Event(stream_error_event("stream lock failed"));
    };
    if let Some(event) = state.events.pop_front() {
        StreamNext::Event(event)
    } else if state.terminal {
        StreamNext::Closed
    } else {
        StreamNext::Pending
    }
}

fn stream_is_pending(stream: &ConfidentialInferenceFfiStream) -> bool {
    stream
        .state
        .lock()
        .map(|state| !state.terminal)
        .unwrap_or(false)
}

fn terminal_status(terminal: &OperationTerminal) -> &'static str {
    match terminal {
        OperationTerminal::Pending => "pending",
        OperationTerminal::Ready(_) => "ready",
        OperationTerminal::Failed(_) => "failed",
        OperationTerminal::Cancelled => "cancelled",
    }
}

fn async_error_json(message: &str) -> String {
    json!({
        "status": "failed",
        "error": {
            "type": "confidential_inference_async_error",
            "message": message,
        }
    })
    .to_string()
}

#[cfg(unix)]
fn readiness_pair() -> (Option<UnixStream>, Option<UnixStream>) {
    UnixStream::pair()
        .map(|(read, write)| (Some(read), Some(write)))
        .unwrap_or((None, None))
}

#[cfg(unix)]
fn signal_readiness(mut readiness_writer: Option<UnixStream>) {
    if let Some(writer) = readiness_writer.as_mut() {
        let _ = writer.write_all(&[1]);
    }
}

#[cfg(not(unix))]
fn signal_readiness(_: ()) {}

fn in_tokio_runtime_context() -> bool {
    Handle::try_current().is_ok()
}

unsafe fn client_shared(client: *mut ConfidentialInferenceFfiClient) -> Option<Arc<ClientShared>> {
    if !is_handle_live(live_client_handles(), client) {
        None
    } else {
        Some((*client).shared.clone())
    }
}

unsafe fn operation_ref<'a>(
    operation: *mut ConfidentialInferenceFfiOperation,
) -> Option<&'a ConfidentialInferenceFfiOperation> {
    if !is_handle_live(live_operation_handles(), operation) {
        None
    } else {
        Some(&*operation)
    }
}

unsafe fn stream_ref<'a>(
    stream: *mut ConfidentialInferenceFfiStream,
) -> Option<&'a ConfidentialInferenceFfiStream> {
    if !is_handle_live(live_stream_handles(), stream) {
        None
    } else {
        Some(&*stream)
    }
}

unsafe fn optional_json_config(config_json: *const c_char) -> Result<ClientConfig, String> {
    if config_json.is_null() {
        return Ok(ClientConfig::default());
    }
    let value = c_string_to_string(config_json, "config_json")?;
    if value.trim().is_empty() {
        Ok(ClientConfig::default())
    } else {
        serde_json::from_str(&value)
            .map_err(|error| format!("failed to parse config JSON: {error}"))
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

fn ffi_error(status: c_int, code: &'static str, message: &str) -> c_int {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(FfiErrorJson {
            code,
            message: message.to_owned(),
        });
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
    #[cfg(unix)]
    use std::io::Read;
    #[cfg(unix)]
    use std::os::fd::FromRawFd;
    use std::sync::atomic::AtomicUsize;
    use std::thread;
    use std::time::{Duration, Instant};

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
        let code = unsafe { confidential_inference_sdk_new(ptr::null(), &mut client) };
        assert_eq!(code, CONFIDENTIAL_INFERENCE_FFI_OK);
        assert!(!client.is_null());
        client
    }

    unsafe fn wait_for_terminal(operation: *mut ConfidentialInferenceFfiOperation) -> Value {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut state = ptr::null_mut();
            assert_eq!(
                confidential_inference_op_poll(operation, &mut state),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let state_json = take_string(state);
            let state: Value = serde_json::from_str(&state_json).unwrap();
            if state["status"] != "pending" {
                return state;
            }
            assert!(Instant::now() < deadline, "operation did not finish");
            thread::sleep(Duration::from_millis(10));
        }
    }

    unsafe fn free_operation_and_client(
        operation: *mut ConfidentialInferenceFfiOperation,
        client: *mut ConfidentialInferenceFfiClient,
    ) {
        assert_eq!(
            confidential_inference_op_free(operation),
            CONFIDENTIAL_INFERENCE_FFI_OK
        );
        assert_eq!(
            confidential_inference_sdk_free(client),
            CONFIDENTIAL_INFERENCE_FFI_OK
        );
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
    fn ffi_chat_operation_returns_confidential_response_json() {
        unsafe {
            let client = new_demo_client();
            let request_json = chat_request_json("ffi chat path");
            let mut operation = ptr::null_mut();

            assert_eq!(
                confidential_inference_chat_start(client, request_json.as_ptr(), &mut operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert!(!operation.is_null());
            let state = wait_for_terminal(operation);
            assert_eq!(state["status"], "ready");

            let mut result = ptr::null_mut();
            assert_eq!(
                confidential_inference_op_result_json(operation, &mut result),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let result: Value = serde_json::from_str(&take_string(result)).unwrap();
            assert_eq!(result["provider"], "demo");
            assert_eq!(result["provider_model"], "e2ee-gpt-oss-120b-p");
            assert_eq!(result["verdict"]["status"], "verified");
            assert_eq!(
                result["response_channel_bound"],
                result["verdict"]["response_channel_bound"]
            );
            assert_eq!(
                result["response_integrity_result"],
                result["verdict"]["response_integrity_result"]
            );
            assert_eq!(
                result["response"]["choices"][0]["message"]["content"],
                "demo confidential response for e2ee-gpt-oss-120b-p: ffi chat path"
            );

            free_operation_and_client(operation, client);
        }
    }

    #[test]
    fn ffi_response_operation_returns_responses_shim_json() {
        unsafe {
            let client = new_demo_client();
            let request_json = response_request_json("ffi response path");
            let mut operation = ptr::null_mut();

            assert_eq!(
                confidential_inference_response_start(
                    client,
                    request_json.as_ptr(),
                    &mut operation
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert!(!operation.is_null());
            let state = wait_for_terminal(operation);
            assert_eq!(state["status"], "ready");

            let mut result = ptr::null_mut();
            assert_eq!(
                confidential_inference_op_result_json(operation, &mut result),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let result: Value = serde_json::from_str(&take_string(result)).unwrap();
            assert_eq!(result["provider"], "demo");
            assert_eq!(result["provider_model"], "e2ee-gpt-oss-120b-p");
            assert_eq!(result["verdict"]["status"], "verified");
            assert_eq!(
                result["response_channel_bound"],
                result["verdict"]["response_channel_bound"]
            );
            assert_eq!(
                result["response_integrity_result"],
                result["verdict"]["response_integrity_result"]
            );
            assert_eq!(result["response"]["object"], "response");
            assert_eq!(
                result["response"]["metadata"]["confidential_inference_compatibility"],
                "responses_to_chat_shim"
            );
            assert_eq!(
                result["response"]["output_text"],
                "demo confidential response for e2ee-gpt-oss-120b-p: ffi response path"
            );

            free_operation_and_client(operation, client);
        }
    }

    #[test]
    fn ffi_verify_operation_returns_verdict_json() {
        unsafe {
            let client = new_demo_client();
            let request = c_string(r#"{"provider":"demo","model":"gpt-oss-120b"}"#);
            let mut operation = ptr::null_mut();

            assert_eq!(
                confidential_inference_verify_start(client, request.as_ptr(), &mut operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert_eq!(wait_for_terminal(operation)["status"], "ready");

            let mut result = ptr::null_mut();
            assert_eq!(
                confidential_inference_op_result_json(operation, &mut result),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let result: Value = serde_json::from_str(&take_string(result)).unwrap();
            assert_eq!(result["status"], "verified");
            assert_eq!(result["route_id"], "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p");

            free_operation_and_client(operation, client);
        }
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
    fn ffi_chat_blocking_returns_sdk_failure_as_result_json() {
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
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let result_json = take_string(result);
            let result: Value = serde_json::from_str(&result_json).unwrap();
            assert_eq!(result["status"], "failed");
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
            assert!(take_string(error).contains("operation_timeout"));
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
                confidential_inference_sdk_new(ptr::null(), &mut client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_client_config_loads_api_key_from_env_reference() {
        unsafe {
            let env_name = "CONFIDENTIAL_INFERENCE_FFI_TEST_API_KEY_ENV_REFERENCE";
            env::set_var(env_name, "sk-ffi-env-secret");
            let config = c_string(&format!(
                r#"{{"api_keys":{{"demo":{{"env":"{env_name}"}}}}}}"#
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
                r#"{{"api_keys":{{"demo":{{"env":"{env_name}"}}}}}}"#
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
                r#"{{"api_keys":{{"demo":{{"inline":"{secret}"}}}}}}"#
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
                r#"{{"allow_inline_api_keys":true,"api_keys":{{"demo":{{"inline":"{secret}"}}}}}}"#
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
            let config = c_string(r#"{"routing":{"provider_order":{"gpt-oss-120b":["demo"]}}}"#);
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
            let config =
                c_string(r#"{"routing":{"provider_order":{"gpt-oss-120b":["demo","demo"]}}}"#);
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
                r#"{{"allow_inline_api_keys":true,"api_keys":{{"demo":{{"env":"CONFIDENTIAL_INFERENCE_FFI_UNUSED_ENV","inline":"{secret}"}}}}}}"#
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
    fn ffi_client_free_refuses_live_operation_until_operation_is_freed() {
        unsafe {
            let client = new_demo_client();
            let request = c_string(r#"{"provider":"demo","model":"gpt-oss-120b"}"#);
            let mut operation = ptr::null_mut();
            assert_eq!(
                confidential_inference_verify_start(client, request.as_ptr(), &mut operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_BUSY
            );
            let mut error = ptr::null_mut();
            assert_eq!(
                confidential_inference_last_error(&mut error),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert!(take_string(error).contains("client_busy"));

            wait_for_terminal(operation);
            free_operation_and_client(operation, client);
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
    fn ffi_operation_after_free_returns_invalid_operation_without_deref() {
        unsafe {
            let client = new_demo_client();
            let request = c_string(r#"{"provider":"demo","model":"gpt-oss-120b"}"#);
            let mut operation = ptr::null_mut();
            assert_eq!(
                confidential_inference_verify_start(client, request.as_ptr(), &mut operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            wait_for_terminal(operation);
            assert_eq!(
                confidential_inference_op_free(operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let mut state = ptr::null_mut();
            assert_eq!(
                confidential_inference_op_poll(operation, &mut state),
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT
            );
            let error = last_error_value();
            assert_eq!(error["error"]["code"], "invalid_operation");
            assert_eq!(
                confidential_inference_sdk_free(client),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
        }
    }

    #[test]
    fn ffi_operation_result_after_finished_join_from_runtime_context_does_not_panic() {
        unsafe {
            let client = new_demo_client();
            let request = c_string(r#"{"provider":"demo","model":"gpt-oss-120b"}"#);
            let mut operation = ptr::null_mut();
            assert_eq!(
                confidential_inference_verify_start(client, request.as_ptr(), &mut operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let is_terminal = !operation_is_pending(&*operation);
                let join_finished = (*operation)
                    .join
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|handle| handle.is_finished())
                    .unwrap_or(true);
                if is_terminal && join_finished {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "operation did not finish in time"
                );
                thread::sleep(Duration::from_millis(5));
            }

            let runtime = Runtime::new().unwrap();
            let mut result = ptr::null_mut();
            let status = runtime
                .block_on(async { confidential_inference_op_result_json(operation, &mut result) });
            assert_eq!(status, CONFIDENTIAL_INFERENCE_FFI_OK);
            drop(runtime);

            let result: Value = serde_json::from_str(&take_string(result)).unwrap();
            assert_eq!(result["status"], "verified");
            free_operation_and_client(operation, client);
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

    extern "C" fn increment_callback(user_data: *mut c_void) {
        let counter = unsafe { &*(user_data as *const AtomicUsize) };
        counter.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn ffi_operation_callback_runs_after_terminal_state_without_lock_reentry() {
        unsafe {
            let client = new_demo_client();
            let request = c_string(r#"{"provider":"demo","model":"gpt-oss-120b"}"#);
            let mut operation = ptr::null_mut();
            let counter = AtomicUsize::new(0);

            assert_eq!(
                confidential_inference_verify_start(client, request.as_ptr(), &mut operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert_eq!(
                confidential_inference_op_set_callback(
                    operation,
                    Some(increment_callback),
                    (&counter as *const AtomicUsize).cast_mut().cast(),
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            wait_for_terminal(operation);

            assert_eq!(counter.load(Ordering::SeqCst), 1);
            free_operation_and_client(operation, client);
        }
    }

    #[test]
    fn ffi_cancel_is_idempotent_and_returns_cancellation_json() {
        unsafe {
            let client = new_demo_client();
            let shared = client_shared(client).unwrap();
            let operation = Box::into_raw(spawn_operation(shared, async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(json!({ "status": "late" }).to_string())
            }));
            register_handle(live_operation_handles(), operation);

            assert_eq!(
                confidential_inference_op_cancel(operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert_eq!(
                confidential_inference_op_cancel(operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let mut result = ptr::null_mut();
            assert_eq!(
                confidential_inference_op_result_json(operation, &mut result),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let result: Value = serde_json::from_str(&take_string(result)).unwrap();
            assert_eq!(result["status"], "cancelled");

            free_operation_and_client(operation, client);
        }
    }

    #[test]
    fn ffi_op_free_and_result_refuse_pending_operation() {
        unsafe {
            let client = new_demo_client();
            let shared = client_shared(client).unwrap();
            let operation = Box::into_raw(spawn_operation(shared, async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(json!({ "status": "late" }).to_string())
            }));
            register_handle(live_operation_handles(), operation);

            let mut result = ptr::null_mut();
            assert_eq!(
                confidential_inference_op_result_json(operation, &mut result),
                CONFIDENTIAL_INFERENCE_FFI_PENDING
            );
            assert!(result.is_null());
            let error = last_error_value();
            assert_eq!(error["error"]["code"], "operation_pending");

            assert_eq!(
                confidential_inference_op_free(operation),
                CONFIDENTIAL_INFERENCE_FFI_BUSY
            );
            let error = last_error_value();
            assert_eq!(error["error"]["code"], "operation_busy");

            assert_eq!(
                confidential_inference_op_cancel(operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            free_operation_and_client(operation, client);
        }
    }

    #[cfg(unix)]
    #[test]
    fn ffi_readiness_fd_becomes_readable_at_terminal_state() {
        unsafe {
            let client = new_demo_client();
            let request = c_string(r#"{"provider":"demo","model":"gpt-oss-120b"}"#);
            let mut operation = ptr::null_mut();
            assert_eq!(
                confidential_inference_verify_start(client, request.as_ptr(), &mut operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let mut fd = -1;
            assert_eq!(
                confidential_inference_op_readiness_fd(operation, &mut fd),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert!(fd >= 0);
            let mut readiness = UnixStream::from_raw_fd(fd);
            readiness
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();

            assert_eq!(wait_for_terminal(operation)["status"], "ready");
            let mut byte = [0_u8; 1];
            assert_eq!(readiness.read(&mut byte).unwrap(), 1);
            assert_eq!(byte[0], 1);

            free_operation_and_client(operation, client);
        }
    }

    #[cfg(unix)]
    #[test]
    fn ffi_readiness_fd_can_only_be_taken_once() {
        unsafe {
            let client = new_demo_client();
            let request = c_string(r#"{"provider":"demo","model":"gpt-oss-120b"}"#);
            let mut operation = ptr::null_mut();
            assert_eq!(
                confidential_inference_verify_start(client, request.as_ptr(), &mut operation),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );

            let mut first_fd = -1;
            let mut second_fd = -1;
            assert_eq!(
                confidential_inference_op_readiness_fd(operation, &mut first_fd),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert!(first_fd >= 0);
            let readiness = UnixStream::from_raw_fd(first_fd);
            assert_eq!(
                confidential_inference_op_readiness_fd(operation, &mut second_fd),
                CONFIDENTIAL_INFERENCE_FFI_BUSY
            );
            assert_eq!(second_fd, -1);

            wait_for_terminal(operation);
            drop(readiness);
            free_operation_and_client(operation, client);
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
    fn ffi_stream_response_events_reject_receipt_bound_opening_verdict() {
        let response = json!({
            "response_channel_bound": false,
            "response_integrity_result": "receipt_bound",
            "verdict": {
                "response_channel_bound": false,
                "response_integrity_result": "receipt_bound"
            },
            "response": {}
        });

        let error = stream_response_events(&response.to_string()).unwrap_err();

        assert!(error.contains("opening verdict"));
        assert!(error.contains("receipt-bound"));
    }

    #[test]
    fn ffi_stream_response_events_preserve_non_receipt_verdict_event() {
        let response = json!({
            "response_channel_bound": true,
            "response_integrity_result": "channel_bound",
            "verdict": {
                "response_channel_bound": true,
                "response_integrity_result": "channel_bound"
            },
            "response": {"choices": []}
        });

        let events = stream_response_events(&response.to_string()).unwrap();
        let verdict_event: Value = serde_json::from_str(&events[0]).unwrap();
        let response_event: Value = serde_json::from_str(&events[1]).unwrap();
        let done_event: Value = serde_json::from_str(&events[2]).unwrap();

        assert_eq!(verdict_event["type"], "verdict");
        assert_eq!(verdict_event["response_channel_bound"], true);
        assert_eq!(verdict_event["response_integrity_result"], "channel_bound");
        assert_eq!(response_event["type"], "response");
        assert_eq!(done_event["type"], "done");
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
            let error = last_error_value();
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
            let stream = Box::into_raw(spawn_stream(shared, async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                vec![json!({ "type": "late" }).to_string()]
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

    #[cfg(unix)]
    #[test]
    fn ffi_stream_callback_and_readiness_fd_signal_terminal_event() {
        unsafe {
            let client = new_demo_client();
            let request_json = chat_request_json("ffi stream readiness");
            let mut stream = ptr::null_mut();
            let counter = AtomicUsize::new(0);

            assert_eq!(
                confidential_inference_chat_stream_start(
                    client,
                    request_json.as_ptr(),
                    &mut stream
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert_eq!(
                confidential_inference_stream_set_callback(
                    stream,
                    Some(increment_callback),
                    (&counter as *const AtomicUsize).cast_mut().cast(),
                ),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let mut fd = -1;
            assert_eq!(
                confidential_inference_stream_readiness_fd(stream, &mut fd),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert!(fd >= 0);
            let mut readiness = UnixStream::from_raw_fd(fd);
            readiness
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();

            let mut event = ptr::null_mut();
            assert_eq!(
                confidential_inference_stream_next(stream, 2_000, &mut event),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            let event: Value = serde_json::from_str(&take_string(event)).unwrap();
            assert_eq!(event["type"], "error");

            let mut byte = [0_u8; 1];
            assert_eq!(readiness.read(&mut byte).unwrap(), 1);
            assert_eq!(byte[0], 1);
            assert_eq!(counter.load(Ordering::SeqCst), 1);

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

    #[cfg(not(unix))]
    #[test]
    fn ffi_readiness_fd_is_explicitly_unsupported_on_non_unix() {
        unsafe {
            let mut fd = 0;
            assert_eq!(
                confidential_inference_op_readiness_fd(ptr::null_mut(), &mut fd),
                CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED
            );
            assert_eq!(fd, -1);
            let mut error = ptr::null_mut();
            assert_eq!(
                confidential_inference_last_error(&mut error),
                CONFIDENTIAL_INFERENCE_FFI_OK
            );
            assert!(take_string(error).contains("readiness_fd_unsupported"));
        }
    }

    #[test]
    fn ffi_status_reports_available_and_future_surfaces() {
        let status = status();
        assert!(status.async_handle_abi_available);
        assert!(status.callbacks_available);
        assert_eq!(status.readiness_fd_available, cfg!(unix));
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
            assert_eq!(status["async_handle_abi_available"], true);
            assert_eq!(status["callbacks_available"], true);
            assert_eq!(status["readiness_fd_available"], cfg!(unix));
            assert_eq!(status["stream_handle_abi_available"], true);
            assert_eq!(status["blocking_helpers_available"], true);
            assert!(status["reason"]
                .as_str()
                .unwrap()
                .contains("chat, responses, verify"));

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
            "typedef struct ConfidentialInferenceFfiOperation ConfidentialInferenceFfiOperation;",
            "typedef struct ConfidentialInferenceFfiStream ConfidentialInferenceFfiStream;",
            "typedef void (*ConfidentialInferenceFfiCallback)(void *user_data);",
            "int confidential_inference_status(",
            "int confidential_inference_sdk_new(",
            "int confidential_inference_sdk_free(",
            "int confidential_inference_chat_start(",
            "int confidential_inference_response_start(",
            "int confidential_inference_verify_start(",
            "int confidential_inference_chat_blocking(",
            "int confidential_inference_response_blocking(",
            "int confidential_inference_verify_blocking(",
            "int confidential_inference_models_blocking(",
            "int confidential_inference_confidentiality_blocking(",
            "int confidential_inference_active_policy_blocking(",
            "int confidential_inference_active_trust_artifacts_blocking(",
            "int confidential_inference_op_poll(",
            "int confidential_inference_op_result_json(",
            "int confidential_inference_op_set_callback(",
            "int confidential_inference_op_readiness_fd(",
            "int confidential_inference_op_cancel(",
            "int confidential_inference_op_free(",
            "int confidential_inference_chat_stream_start(",
            "int confidential_inference_stream_next(",
            "int confidential_inference_stream_set_callback(",
            "int confidential_inference_stream_readiness_fd(",
            "int confidential_inference_stream_cancel(",
            "int confidential_inference_stream_free(",
            "int confidential_inference_last_error(",
            "void confidential_inference_string_free(",
        ] {
            assert!(header.contains(needle), "header missing {needle}");
        }
    }
}
