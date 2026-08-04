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

const CONFIDENTIAL_INFERENCE_FFI_OK = 0;
const CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT = 1;
const CONFIDENTIAL_INFERENCE_FFI_PANIC = 2;
const CONFIDENTIAL_INFERENCE_FFI_BUSY = 3;
const CONFIDENTIAL_INFERENCE_FFI_PENDING = 4;
const CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED = 5;
const CONFIDENTIAL_INFERENCE_FFI_INTERNAL = 6;

class ConfidentialInferenceError extends Error {
  constructor(status, error = {}) {
    const code = error.code || 'ffi_error';
    const message = error.message || `FFI status ${status}`;
    super(`${code}: ${message}`);
    this.name = 'ConfidentialInferenceError';
    this.status = status;
    this.error = error;
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
    confidential_inference_response_blocking: lib.func('confidential_inference_response_blocking', 'int', [
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

  lastError() {
    const out = [null];
    const status = this.functions.confidential_inference_last_error(out);
    if (status !== CONFIDENTIAL_INFERENCE_FFI_OK) {
      return { code: 'last_error_failed', message: `confidential_inference_last_error returned ${status}` };
    }
    return asObject(this.takeJsonString(out[0])).error;
  }

  raiseForStatus(status) {
    if (status !== CONFIDENTIAL_INFERENCE_FFI_OK) {
      throw new ConfidentialInferenceError(status, this.lastError());
    }
  }
}

class Stream {
  constructor(native, handle) {
    this._native = native;
    this._handle = handle;
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

  cancel() {
    if (this._handle !== null) {
      this._native.functions.confidential_inference_stream_cancel(this._handle);
    }
  }

  close() {
    if (this._handle !== null) {
      const handle = this._handle;
      this._handle = null;
      this._native.functions.confidential_inference_stream_free(handle);
    }
  }

  async *[Symbol.asyncIterator]({ timeoutMs = 0, pollIntervalMs = 10 } = {}) {
    try {
      while (true) {
        const event = this.next(timeoutMs);
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
    const out = [null];
    const configBytes = config === null ? null : JSON.stringify(config);
    const status = this._native.functions.confidential_inference_sdk_new(configBytes, out);
    this._native.raiseForStatus(status);
    this._handle = out[0];
  }

  close() {
    if (this._handle !== null) {
      const handle = this._handle;
      this._handle = null;
      this._native.functions.confidential_inference_sdk_free(handle);
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
      this._callNoRequestJson(this._native.functions.confidential_inference_confidentiality_blocking)
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
        const event = stream.next(timeoutMs);
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
    const out = [null];
    const status = fn(this._handle, JSON.stringify(request), BigInt(timeoutMs), out);
    this._native.raiseForStatus(status);
    return asObject(this._native.takeJsonString(out[0]));
  }

  _callNoRequestJson(fn) {
    this._requireOpen();
    const out = [null];
    const status = fn(this._handle, out);
    this._native.raiseForStatus(status);
    return this._native.takeJsonString(out[0]);
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
  const candidates = [];
  if (explicit) {
    candidates.push(path.resolve(String(explicit)));
  }
  if (process.env.CONFIDENTIAL_INFERENCE_FFI_LIBRARY) {
    candidates.push(path.resolve(process.env.CONFIDENTIAL_INFERENCE_FFI_LIBRARY));
  }
  const repoRoot = path.resolve(__dirname, '..', '..');
  const names =
    process.platform === 'win32'
      ? ['confidential_inference_ffi.dll']
      : process.platform === 'darwin'
        ? ['libconfidential_inference_ffi.dylib']
        : ['libconfidential_inference_ffi.so'];
  for (const root of [process.cwd(), repoRoot]) {
    for (const profile of ['debug', 'release']) {
      for (const name of names) {
        candidates.push(path.join(root, 'target', profile, name));
      }
    }
  }
  const seen = new Set();
  for (const candidate of candidates) {
    if (seen.has(candidate)) {
      continue;
    }
    seen.add(candidate);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, {
    code: 'ffi_library_not_found',
    message: `could not find confidential-inference-ffi library; build it with cargo build -p confidential-inference-ffi or set CONFIDENTIAL_INFERENCE_FFI_LIBRARY`,
    candidates: Array.from(seen),
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
  status,
  CONFIDENTIAL_INFERENCE_FFI_OK,
  CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
  CONFIDENTIAL_INFERENCE_FFI_PANIC,
  CONFIDENTIAL_INFERENCE_FFI_BUSY,
  CONFIDENTIAL_INFERENCE_FFI_PENDING,
  CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED,
  CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
};
