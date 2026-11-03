'use strict';

/**
 * Thin Node bindings for the Confidential Inference SDK C ABI.
 *
 * Rust owns every attestation/policy/registry/digest/signature decision. This
 * module loads the native library, marshals JSON across the ABI, and applies
 * minimal ABI-shape checks on the way back. Client methods are async and Stream
 * is an async iterator.
 */

const fs = require('node:fs');
const path = require('node:path');
const koffi = require('koffi');

// Koffi async worker threads default to a 128 kiB stack, which is too small
// for the Tokio runtime the FFI drives with block_on: measured, 128/256 kiB
// stacks segfault and the full request fanout needs ~1 MiB, so 2 MiB leaves
// margin. Heap covers FFI argument marshalling. max_async_calls bounds the
// queued-call memory: 32 * (2 MiB stack + 512 kiB heap) = 80 MiB worst case.
koffi.config({
  async_stack_size: 2 * 1024 * 1024,
  async_heap_size: 512 * 1024,
  max_async_calls: 32,
});

// Invoke a registered Koffi function on one of its worker threads and resolve
// with the C return value; out-pointer arguments are filled in before resolve.
function callAsync(fn, ...args) {
  return new Promise((resolve, reject) => {
    fn.async(...args, (error, result) => (error ? reject(error) : resolve(result)));
  });
}

const CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION = 1;
const CONFIDENTIAL_INFERENCE_FFI_OK = 0;
const CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT = 1;
const CONFIDENTIAL_INFERENCE_FFI_PANIC = 2;
const CONFIDENTIAL_INFERENCE_FFI_BUSY = 3;
const CONFIDENTIAL_INFERENCE_FFI_PENDING = 4;
const CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED = 5;
const CONFIDENTIAL_INFERENCE_FFI_INTERNAL = 6;
// A chat, response or verify operation failed; see ConfidentialInferenceError#dispatch.
const CONFIDENTIAL_INFERENCE_FFI_OPERATION_FAILED = 7;

class ConfidentialInferenceError extends Error {
  constructor(status, error) {
    const detail = error || {};
    const code = detail.code || 'ffi_error';
    const message = detail.message || `FFI status ${status}`;
    super(`${code}: ${message}`);
    this.name = 'ConfidentialInferenceError';
    this.status = status;
    this.error = detail;
    // 'not_dispatched' | 'rejected' | 'unknown' for operation failures;
    // 'unknown' means the provider may have processed the request.
    this.dispatch = detail.dispatch;
    this.httpStatus = detail.http_status;
  }
}

// Refuse a native library built for a different ABI before creating clients.
function validateAbiVersion(version) {
  if (version !== CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION) {
    throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, {
      code: 'abi_version_mismatch',
      message: `Confidential Inference FFI ABI version mismatch: binding expects ${CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION}, library reports ${JSON.stringify(version)}`,
    });
  }
}

function asObject(payload, code = 'malformed_json_object') {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INTERNAL, {
      code,
      message: 'expected a JSON object',
    });
  }
  return payload;
}

function asArray(payload, code = 'malformed_json_array') {
  if (!Array.isArray(payload)) {
    throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INTERNAL, {
      code,
      message: 'expected a JSON array',
    });
  }
  return payload;
}

const ClientHandle = koffi.opaque('ConfidentialInferenceFfiClient');
const StreamHandle = koffi.opaque('ConfidentialInferenceFfiStream');
const ClientPtr = koffi.pointer(ClientHandle);
const StreamPtr = koffi.pointer(StreamHandle);
const VoidPtr = koffi.pointer('void');
const ClientOut = koffi.out(koffi.pointer(ClientPtr));
const StreamOut = koffi.out(koffi.pointer(StreamPtr));
const StringOut = koffi.out(koffi.pointer(VoidPtr));

function configureFunctions(lib) {
  return {
    confidential_inference_status: lib.func('confidential_inference_status', 'int', [StringOut]),
    confidential_inference_sdk_new: lib.func('confidential_inference_sdk_new', 'int', ['str', ClientOut]),
    confidential_inference_sdk_free: lib.func('confidential_inference_sdk_free', 'int', [ClientPtr]),
    confidential_inference_chat_blocking: lib.func('confidential_inference_chat_blocking', 'int', [
      ClientPtr,
      'str',
      'uint64_t',
      StringOut,
    ]),
    confidential_inference_embeddings_blocking: lib.func('confidential_inference_embeddings_blocking', 'int', [
      ClientPtr,
      'str',
      'uint64_t',
      StringOut,
    ]),
    confidential_inference_response_blocking: lib.func('confidential_inference_response_blocking', 'int', [
      ClientPtr,
      'str',
      'uint64_t',
      StringOut,
    ]),
    confidential_inference_response_manage_blocking: lib.func('confidential_inference_response_manage_blocking', 'int', [
      ClientPtr,
      'str',
      'uint64_t',
      StringOut,
    ]),
    confidential_inference_verify_blocking: lib.func('confidential_inference_verify_blocking', 'int', [
      ClientPtr,
      'str',
      'uint64_t',
      StringOut,
    ]),
    confidential_inference_models_blocking: lib.func('confidential_inference_models_blocking', 'int', [
      ClientPtr,
      StringOut,
    ]),
    confidential_inference_confidentiality_blocking: lib.func(
      'confidential_inference_confidentiality_blocking',
      'int',
      [ClientPtr, StringOut]
    ),
    confidential_inference_active_policy_blocking: lib.func(
      'confidential_inference_active_policy_blocking',
      'int',
      [ClientPtr, StringOut]
    ),
    confidential_inference_active_trust_artifacts_blocking: lib.func(
      'confidential_inference_active_trust_artifacts_blocking',
      'int',
      [ClientPtr, StringOut]
    ),
    confidential_inference_chat_stream_start: lib.func('confidential_inference_chat_stream_start', 'int', [
      ClientPtr,
      'str',
      StreamOut,
    ]),
    confidential_inference_stream_next: lib.func('confidential_inference_stream_next', 'int', [
      StreamPtr,
      'uint64_t',
      StringOut,
    ]),
    confidential_inference_stream_cancel: lib.func('confidential_inference_stream_cancel', 'int', [
      StreamPtr,
    ]),
    confidential_inference_stream_free: lib.func('confidential_inference_stream_free', 'int', [StreamPtr]),
    confidential_inference_last_error: lib.func('confidential_inference_last_error', 'int', [StringOut]),
    confidential_inference_string_free: lib.func('confidential_inference_string_free', 'void', [VoidPtr]),
  };
}

class Native {
  constructor(libraryPath) {
    this.path = resolveLibraryPath(libraryPath);
    this.lib = koffi.load(this.path);
    this.functions = configureFunctions(this.lib);
    this.validateAbi();
  }

  takeJsonString(ptr) {
    if (!ptr) {
      throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INTERNAL, {
        code: 'missing_string',
        message: 'FFI returned a null JSON string pointer',
      });
    }
    let text;
    try {
      text = koffi.decode.string(ptr);
    } finally {
      this.functions.confidential_inference_string_free(ptr);
    }
    return JSON.parse(text);
  }

  status() {
    const out = [null];
    const status = this.functions.confidential_inference_status(out);
    this.raiseForStatus(status);
    return asObject(this.takeJsonString(out[0]));
  }

  validateAbi() {
    validateAbiVersion(this.status().abi_version);
  }

  lastError() {
    const out = [null];
    const status = this.functions.confidential_inference_last_error(out);
    if (status !== CONFIDENTIAL_INFERENCE_FFI_OK) {
      return { code: 'last_error_failed', message: `confidential_inference_last_error returned ${status}` };
    }
    return asObject(this.takeJsonString(out[0])).error;
  }

  raiseForStatus(status, errorPtr = null) {
    if (status !== CONFIDENTIAL_INFERENCE_FFI_OK) {
      const error = errorPtr
        ? asObject(this.takeJsonString(errorPtr)).error
        : this.lastError();
      throw new ConfidentialInferenceError(status, error);
    }
  }
}

class Stream {
  constructor(native, handle) {
    this._native = native;
    this._handle = handle;
    // Count of worker-thread calls still referencing this native handle. The
    // FFI holds shared state via Arc, so calls stay memory-safe if the handle
    // is freed mid-call — the counter exists for the free contract (BUSY on
    // close while calls run), not for memory safety.
    this._inFlight = 0;
  }

  get closed() {
    return this._handle === null;
  }

  next(timeoutMs = 0) {
    if (this._handle === null) {
      throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, {
        code: 'stream_closed',
        message: 'stream is closed',
      });
    }
    const out = [null];
    const status = this._native.functions.confidential_inference_stream_next(
      this._handle,
      BigInt(timeoutMs),
      out
    );
    if (status === CONFIDENTIAL_INFERENCE_FFI_PENDING) {
      return null;
    }
    this._native.raiseForStatus(status);
    return asObject(this._native.takeJsonString(out[0]));
  }

  // Non-blocking variant used by the async iterator; the blocking C call runs
  // on a Koffi worker thread instead of the Node event loop.
  _nextAsync(timeoutMs = 0) {
    if (this._handle === null) {
      return Promise.reject(
        new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, {
          code: 'stream_closed',
          message: 'stream is closed',
        })
      );
    }
    this._inFlight += 1;
    const out = [null];
    return callAsync(
      this._native.functions.confidential_inference_stream_next,
      this._handle,
      BigInt(timeoutMs),
      out
    )
      .then((status) => {
        if (status === CONFIDENTIAL_INFERENCE_FFI_PENDING && out[0] === null) {
          return null;
        }
        this._native.raiseForStatus(status, out[0]);
        return asObject(this._native.takeJsonString(out[0]));
      })
      .finally(() => {
        this._inFlight -= 1;
      });
  }

  cancel() {
    if (this._handle !== null) {
      this._native.functions.confidential_inference_stream_cancel(this._handle);
    }
  }

  close() {
    if (this._handle === null) {
      return;
    }
    // Refuse to free while a worker-thread call is in flight: the handle must
    // stay valid until the caller retries after the call settles.
    if (this._inFlight > 0) {
      throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_BUSY, {
        code: 'stream_busy',
        message: 'stream has in-flight calls; await them before closing',
      });
    }
    // Cancel first so the native handle is never left pending: stream_free
    // refuses (FFI_BUSY) to free a live stream, which would leak it.
    this.cancel();
    const status = this._native.functions.confidential_inference_stream_free(this._handle);
    if (status === CONFIDENTIAL_INFERENCE_FFI_OK) {
      this._handle = null;
    } else {
      // Keep the handle so the caller can retry after draining/cancelling.
      this._native.raiseForStatus(status);
    }
  }

  async *[Symbol.asyncIterator]({ timeoutMs = 0, pollIntervalMs = 10 } = {}) {
    try {
      while (true) {
        const event = await this._nextAsync(timeoutMs);
        if (event === null) {
          await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
          continue;
        }
        yield event;
        const type = String(event.type || '').toLowerCase();
        if (['closed', 'done', 'cancelled', 'error'].includes(type)) {
          break;
        }
      }
    } finally {
      this.close();
    }
  }
}

class Client {
  constructor(config = null, options = {}) {
    const libraryPath = typeof options === 'string' ? options : options.libraryPath;
    this._native = new Native(libraryPath);
    this._handle = null;
    // Count of worker-thread calls that still hold this native handle; see
    // Stream._inFlight. Incremented synchronously at dispatch and decremented
    // when the call settles, both on the Node thread, so close() can rely on
    // it without a lock.
    this._inFlight = 0;
    const out = [null];
    const configBytes = config === null ? null : JSON.stringify(config);
    const status = this._native.functions.confidential_inference_sdk_new(configBytes, out);
    this._native.raiseForStatus(status);
    this._handle = out[0];
  }

  close() {
    if (this._handle === null) {
      return;
    }
    // Refuse to free while a worker-thread call is in flight: the handle must
    // stay valid until the caller retries after the call settles.
    if (this._inFlight > 0) {
      throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_BUSY, {
        code: 'client_busy',
        message: 'client has in-flight calls; await them before closing',
      });
    }
    const status = this._native.functions.confidential_inference_sdk_free(this._handle);
    if (status === CONFIDENTIAL_INFERENCE_FFI_OK) {
      this._handle = null;
    } else {
      // FFI_BUSY means live streams still reference the client; keep the
      // handle so the caller can close them and retry instead of leaking it.
      this._native.raiseForStatus(status);
    }
  }

  status() {
    return this._native.status();
  }

  async chat(request, timeoutMs = 0) {
    return this._callJson(
      this._native.functions.confidential_inference_chat_blocking,
      request,
      timeoutMs
    );
  }

  async embeddings(request, timeoutMs = 0) {
    return this._callJson(
      this._native.functions.confidential_inference_embeddings_blocking,
      request,
      timeoutMs
    );
  }
  async createResponse(request, timeoutMs = 0) {
    return this._callJson(
      this._native.functions.confidential_inference_response_blocking,
      request,
      timeoutMs
    );
  }

  async response(request, timeoutMs = 0) {
    return this.createResponse(request, timeoutMs);
  }
  async responseManage(request, timeoutMs = 0) {
    return this._callJson(
      this._native.functions.confidential_inference_response_manage_blocking,
      request,
      timeoutMs
    );
  }

  async verify(provider, model, timeoutMs = 0) {
    return this._callJson(
      this._native.functions.confidential_inference_verify_blocking,
      { provider, model },
      timeoutMs
    );
  }

  async models() {
    return this._callNoRequestJson(this._native.functions.confidential_inference_models_blocking);
  }

  async confidentialModels() {
    return asArray(
      await this._callNoRequestJson(
        this._native.functions.confidential_inference_confidentiality_blocking
      )
    );
  }

  async confidentiality() {
    return this.confidentialModels();
  }

  async activePolicy() {
    return this._callNoRequestJson(
      this._native.functions.confidential_inference_active_policy_blocking
    );
  }

  async activeTrustArtifacts() {
    return this._callNoRequestJson(
      this._native.functions.confidential_inference_active_trust_artifacts_blocking
    );
  }

  startStream(request) {
    this._requireOpen();
    const out = [null];
    const status = this._native.functions.confidential_inference_chat_stream_start(
      this._handle,
      JSON.stringify(request),
      out
    );
    this._native.raiseForStatus(status);
    return new Stream(this._native, out[0]);
  }

  async *stream(request, options = {}) {
    const stream = this.startStream(request);
    const timeoutMs = options.timeoutMs ?? 0;
    const pollIntervalMs = options.pollIntervalMs ?? 10;
    try {
      while (true) {
        const event = await stream._nextAsync(timeoutMs);
        if (event === null) {
          await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
          continue;
        }
        yield event;
        const type = String(event.type || '').toLowerCase();
        if (['closed', 'done', 'cancelled', 'error'].includes(type)) {
          break;
        }
      }
    } finally {
      stream.close();
    }
  }

  _callJson(fn, request, timeoutMs) {
    this._requireOpen();
    this._inFlight += 1;
    const out = [null];
    return callAsync(fn, this._handle, JSON.stringify(request), BigInt(timeoutMs), out)
      .then((status) => {
        this._native.raiseForStatus(status, out[0]);
        return asObject(this._native.takeJsonString(out[0]));
      })
      .finally(() => {
        this._inFlight -= 1;
      });
  }

  _callNoRequestJson(fn) {
    this._requireOpen();
    this._inFlight += 1;
    const out = [null];
    return callAsync(fn, this._handle, out)
      .then((status) => {
        this._native.raiseForStatus(status, out[0]);
        return this._native.takeJsonString(out[0]);
      })
      .finally(() => {
        this._inFlight -= 1;
      });
  }

  _requireOpen() {
    if (this._handle === null) {
      throw new ConfidentialInferenceError(1, {
        code: 'client_closed',
        message: 'client is closed',
      });
    }
  }
}

function resolveLibraryPath(explicit) {
  // Explicit selection wins and is exclusive: a missing file is an error,
  // never a silent fallback to whatever happens to sit in target/.
  const chosen = explicit
    ? String(explicit)
    : process.env.CONFIDENTIAL_INFERENCE_FFI_LIBRARY;
  if (chosen) {
    const resolved = path.resolve(chosen);
    if (!fs.existsSync(resolved)) {
      throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, {
        code: 'ffi_library_not_found',
        message: `explicit FFI library path does not exist: ${resolved}`,
        candidates: [resolved],
      });
    }
    return resolved;
  }
  const repoRoot = path.resolve(__dirname, '..', '..');
  const names =
    process.platform === 'win32'
      ? ['confidential_inference_ffi.dll']
      : process.platform === 'darwin'
        ? ['libconfidential_inference_ffi.dylib']
        : ['libconfidential_inference_ffi.so'];
  // Workspace fallback under the repo root only — the process CWD is never
  // searched; release is preferred over debug.
  const candidates = [];
  for (const profile of ['release', 'debug']) {
    for (const name of names) {
      candidates.push(path.join(repoRoot, 'target', profile, name));
    }
  }
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, {
    code: 'ffi_library_not_found',
    message: `could not find confidential-inference-ffi library; build it with cargo build -p confidential-inference-ffi or set CONFIDENTIAL_INFERENCE_FFI_LIBRARY`,
    candidates,
  });
}

function status(options = {}) {
  const libraryPath = typeof options === 'string' ? options : options.libraryPath;
  return new Native(libraryPath).status();
}

module.exports = {
  Client,
  Stream,
  ConfidentialInferenceError,
  _validateAbiVersion: validateAbiVersion,
  status,
  CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION,
  CONFIDENTIAL_INFERENCE_FFI_OK,
  CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
  CONFIDENTIAL_INFERENCE_FFI_PANIC,
  CONFIDENTIAL_INFERENCE_FFI_BUSY,
  CONFIDENTIAL_INFERENCE_FFI_PENDING,
  CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED,
  CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
  CONFIDENTIAL_INFERENCE_FFI_OPERATION_FAILED,
};
