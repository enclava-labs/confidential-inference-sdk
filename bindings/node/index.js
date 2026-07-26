'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const net = require('node:net');
const path = require('node:path');
const koffi = require('koffi');

const CONFIDENTIAL_INFERENCE_FFI_OK = 0;
const CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT = 1;
const CONFIDENTIAL_INFERENCE_FFI_PANIC = 2;
const CONFIDENTIAL_INFERENCE_FFI_BUSY = 3;
const CONFIDENTIAL_INFERENCE_FFI_PENDING = 4;
const CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED = 5;
const CONFIDENTIAL_INFERENCE_FFI_INTERNAL = 6;
const MAX_SAFE_JSON_INT = Number.MAX_SAFE_INTEGER;
const SHA256_DIGEST_PREFIX = 'sha256:';
const SHA256_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const BASE64URL_SIGNATURE_PREFIX = 'base64url:';
const BASE64URL_NO_PAD_RE = /^[A-Za-z0-9_-]+$/;
const ED25519_PUBLIC_KEY_BYTE_LEN = 32;
const ED25519_SIGNATURE_BYTE_LEN = 64;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const UTC_TIMESTAMP_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$/;
const TRUSTED_ARTIFACT_SIGNING_KEYS = new Map([
  [
    'confidential-inference\0confidential-inference-demo-ed25519-2026',
    '4oqJcHUzMr1y_vQT5rCy7xtKrdp6osFB8jNxKmh2s1E',
  ],
  [
    'confidential-inference\0confidential-inference-phase2-fixture-ed25519-2026',
    'cN-eInmtvsbRK_KSEYTJIi6yTthSAFv2QBOfUuWc2a4',
  ],
  [
    'confidential-inference\0confidential-inference-compatibility-fixture-ed25519-2026',
    'bjLBl0Hwr4JgYSrpn9E9ijiURyLgiWTdI5c49VKmFTs',
  ],
  [
    'confidential-inference\0confidential-inference-alias-matrix-fixture-ed25519-2026',
    'zxs36F3ACu6U8QEIs38VHio3s64qDK53Uh-DSI25xNc',
  ],
]);

const VERIFICATION_STATUS_VALUES = new Set([
  'verified',
  'partial',
  'failed',
  'unreachable',
  'disabled',
]);
const ENFORCEMENT_VALUES = new Set(['disabled', 'observe', 'enforce']);
const TRUST_TIER_VALUES = new Set(['hw-verified-tls', 'app-e2ee', 'tee-only', 'none']);
const CHANNEL_BINDING_KIND_VALUES = new Set([
  'not_required',
  'tee_terminated_tls',
  'attested_app_e2ee',
  'any_attested_channel',
  'none',
]);
const MODEL_BINDING_RESULT_VALUES = new Set(['verified', 'partial', 'not_supported', 'failed']);
const CONFIDENTIALITY_RESULT_VALUES = new Set([
  'channel_bound',
  'encrypted_bound',
  'not_bound',
  'unknown',
]);
const RESPONSE_INTEGRITY_RESULT_VALUES = new Set([
  'channel_bound',
  'receipt_bound',
  'not_bound',
  'unknown',
]);
const CHECK_RESULT_VALUES = new Set([
  'verified',
  'failed',
  'not_applicable',
  'not_supported',
  'unknown',
]);
const POLICY_CHANNEL_BINDING_REQUIREMENT_VALUES = new Set([
  'not_required',
  'any_attested_channel',
  'tee_terminated_tls',
  'attested_app_e2ee',
]);
const POLICY_BOUND_DATA_REQUIREMENT_VALUES = new Set([
  'not_required',
  'bound_to_attested_workload',
]);
const POLICY_RESPONSE_INTEGRITY_REQUIREMENT_VALUES = new Set([
  'not_required',
  'any_bound',
  'channel_bound',
  'receipt_bound',
]);
const POLICY_MODEL_BINDING_REQUIREMENT_VALUES = new Set([
  'not_required',
  'if_provider_supports',
  'required',
]);
const POLICY_CPU_TEE_MODES = new Set(['not_required', 'any_cpu_tee', 'one_of']);
const POLICY_CPU_TEE_KINDS = new Set(['tdx', 'sev_snp', 'nitro']);
const POLICY_GPU_TEE_MODES = new Set(['not_required', 'one_of']);
const POLICY_GPU_TEE_KINDS = new Set(['nvidia_cc']);
const REGISTRY_ROUTE_STATUS_VALUES = new Set([
  'active',
  'new_unverified',
  'verification_only',
  'deprecated',
  'removed',
  'blocked',
]);
const REGISTRY_ENCRYPTION_REQUIREMENT_VALUES = new Set(['required', 'not_required']);
const REGISTRY_STREAMING_VALUES = new Set([
  'supported',
  'supported_if_encryption_supports_streaming',
  'unsupported',
]);
const CATALOG_ROUTE_EXECUTION_STATUS_VALUES = new Set([
  'executable_fixture',
  'adapter_shape_fixture',
  'verification_only',
  'executable',
]);
const FRESHNESS_CLASS_VALUES = new Set(['per_request', 'per_session', 'cached_binding']);
const ALIAS_CONFIDENCE_VALUES = new Set([
  'curated',
  'provider_declared',
  'algorithmic',
  'manual_override',
]);
const POLICY_FRESHNESS_MODES = new Set([
  'per_request',
  'per_session',
  'allow_cached_binding_millis',
]);
const POLICY_STALE_VERDICT_MODES = new Set(['fail_closed', 'allow_for_millis']);

const POLICY_DIGEST_FIELDS = new Set([
  'schema',
  'enforcement',
  'hardware',
  'channel_binding_requirement',
  'request_confidentiality_requirement',
  'response_confidentiality_requirement',
  'response_integrity_requirement',
  'model_binding_requirement',
  'provenance',
  'freshness',
  'stale_verdicts',
  'verdict_ttl_millis',
  'provider_registry_digest',
  'reference_values_digest',
]);
const ACTIVE_POLICY_SNAPSHOT_KNOWN_FIELDS = new Set(['schema', 'policy', 'policy_digest', 'required']);
const POLICY_KNOWN_FIELDS = new Set([...POLICY_DIGEST_FIELDS, 'required']);
const POLICY_HARDWARE_FIELDS = new Set(['cpu', 'gpu']);
const POLICY_TEE_BASE_FIELDS = new Set(['mode']);
const POLICY_TEE_ONE_OF_FIELDS = new Set(['mode', 'allowed']);
const POLICY_TAGGED_BASE_FIELDS = new Set(['mode']);
const POLICY_TAGGED_MILLIS_FIELDS = new Set(['mode', 'millis']);
const POLICY_PROVENANCE_FIELDS = new Set([
  'workload_image',
  'model_artifacts',
  'reproducible_build',
  'source_attestation',
  'dependency_sbom',
]);
const TRUST_ARTIFACTS_KNOWN_FIELDS = new Set([
  'registry',
  'registry_digest',
  'registry_source',
  'registry_signature',
  'reference_values',
  'reference_values_digest',
  'reference_values_source',
  'reference_values_signature',
  'required',
]);
const REGISTRY_PAYLOAD_KNOWN_FIELDS = new Set([
  'schema',
  'version',
  'generated_at',
  'source_sync_run',
  'models',
  'required',
]);
const REFERENCE_VALUES_PAYLOAD_KNOWN_FIELDS = new Set([
  'schema',
  'version',
  'issuer',
  'valid_from',
  'valid_until',
  'valid_until_epoch_ms',
  'revocation_epoch',
  'minimum_acceptable_version',
  'providers',
  'required',
]);
const VERDICT_KNOWN_FIELDS = new Set([
  'schema',
  'policy_schema',
  'reference_values_schema',
  'provider_registry_schema',
  'status',
  'enforcement',
  'request_allowed',
  'would_block_under_enforce',
  'trust_tier',
  'provider',
  'requested_model',
  'provider_model',
  'canonical_model',
  'route_id',
  'evidence_family',
  'alias_confidence',
  'adapter_version',
  'api_endpoint',
  'evidence_endpoint',
  'freshness_class',
  'streaming_allowed',
  'route_execution_status',
  'chat_executable',
  'known_unsupported_modes',
  'channel_binding_kind',
  'model_binding_result',
  'request_channel_bound',
  'request_confidentiality_result',
  'response_confidentiality_result',
  'response_channel_bound',
  'response_integrity_result',
  'policy_digest',
  'provider_registry_digest',
  'registry_version',
  'registry_source',
  'registry_sync_completed_at',
  'registry_signature',
  'reference_values_digest',
  'reference_values_version',
  'reference_values_source',
  'reference_values_signature',
  'raw_evidence_digest',
  'evidence_digest',
  'verified_at',
  'expires_at',
  'expires_at_epoch_ms',
  'validity',
  'checks',
  'check_outcomes',
  'route_attribution',
  'artifacts',
  'errors',
  'required',
]);
const VERDICT_EVIDENCE_REFS = new Set([
  'policy_digest',
  'provider_registry_digest',
  'reference_values_digest',
  'raw_evidence_digest',
  'evidence_digest',
]);
const ROUTE_PARTY_ROLES = new Set([
  'inference_provider',
  'registry_authority',
  'reference_values_authority',
  'workload_operator',
  'tee_platform',
  'cloud_host',
]);
const ATTRIBUTION_SOURCES = new Set([
  'signed_registry',
  'signed_reference_values',
  'attested_evidence',
  'unknown',
]);
const VERDICT_VALIDITY_FIELDS = [
  'policy_ttl_until',
  'collateral_valid_until',
  'certificate_valid_until',
  'quote_valid_until',
  'tcb_valid_until',
  'reference_values_valid_until',
  'computed_expires_at',
];
const OPERATION_STATUS_VALUES = new Set(['pending', 'ready', 'failed', 'cancelled']);
const OPERATION_STATE_BASE_FIELDS = new Set(['status']);
const OPERATION_STATE_FAILED_FIELDS = new Set(['status', 'result_available', 'error']);
const STREAM_EVENT_TYPES = new Set([
  'verdict',
  'response',
  'response_receipt',
  'done',
  'error',
  'cancelled',
  'closed',
]);
const STREAM_VERDICT_EVENT_FIELDS = new Set([
  'type',
  'response_channel_bound',
  'response_integrity_result',
  'verdict',
]);
const STREAM_RECEIPT_EVENT_FIELDS = new Set([
  'type',
  'response_integrity_result',
  'receipt_verified',
  'receipt',
]);
const STREAM_RESPONSE_EVENT_FIELDS = new Set(['type', 'response']);
const STREAM_ERROR_EVENT_FIELDS = new Set(['type', 'status', 'error']);
const STREAM_TERMINAL_EVENT_FIELDS = new Set(['type']);
const MODEL_LIST_FIELDS = new Set(['object', 'data']);
const MODEL_RECORD_FIELDS = new Set(['id', 'object', 'owned_by']);
const CONFIDENTIAL_MODEL_FIELDS = new Set([
  'canonical_model',
  'display_name',
  'family',
  'aliases',
  'routes',
]);
const CONFIDENTIAL_ROUTE_FIELDS = new Set([
  'route_id',
  'provider',
  'provider_model',
  'evidence_family',
  'route_execution_status',
  'chat_executable',
  'known_unsupported_modes',
  'trust_tier',
  'channel_binding_kind',
  'request_encryption',
  'response_decryption',
  'streaming_allowed',
  'alias_confidence',
  'api_endpoint',
  'evidence_endpoint',
  'adapter_version',
]);
const FFI_ERROR_ENVELOPE_FIELDS = new Set(['error']);
const FFI_ERROR_FIELDS = new Set(['type', 'code', 'message']);
const FFI_STATUS_FIELDS = new Set([
  'async_handle_abi_available',
  'callbacks_available',
  'readiness_fd_available',
  'stream_handle_abi_available',
  'blocking_helpers_available',
  'reason',
]);

const ClientHandle = koffi.opaque('ConfidentialInferenceFfiClient');
const OperationHandle = koffi.opaque('ConfidentialInferenceFfiOperation');
const StreamHandle = koffi.opaque('ConfidentialInferenceFfiStream');
const ClientPtr = koffi.pointer(ClientHandle);
const OperationPtr = koffi.pointer(OperationHandle);
const StreamPtr = koffi.pointer(StreamHandle);
const VoidPtr = koffi.pointer('void');
const ClientOut = koffi.out(koffi.pointer(ClientPtr));
const OperationOut = koffi.out(koffi.pointer(OperationPtr));
const StreamOut = koffi.out(koffi.pointer(StreamPtr));
const StringOut = koffi.out(koffi.pointer(VoidPtr));
const IntOut = koffi.out(koffi.pointer('int'));

class ConfidentialInferenceError extends Error {
  constructor(status, error) {
    const payload = error || { code: 'confidential_inference_ffi_error', message: `FFI status ${status}` };
    super(payload.message || payload.code || `FFI status ${status}`);
    this.name = 'ConfidentialInferenceError';
    this.status = status;
    this.error = payload;
  }
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
    return validateFfiStatus(this.takeJsonString(out[0]));
  }

  lastError() {
    const out = [null];
    const status = this.functions.confidential_inference_last_error(out);
    if (status !== CONFIDENTIAL_INFERENCE_FFI_OK) {
      return { code: 'last_error_failed', message: `confidential_inference_last_error returned ${status}` };
    }
    const payload = validateFfiErrorEnvelope(this.takeJsonString(out[0]));
    return payload.error;
  }

  raiseForStatus(status) {
    if (status !== CONFIDENTIAL_INFERENCE_FFI_OK) {
      throw new ConfidentialInferenceError(status, this.lastError());
    }
  }
}

class Client {
  constructor(config = null, options = {}) {
    const libraryPath = typeof options === 'string' ? options : options.libraryPath;
    this._native = new Native(libraryPath);
    this._handle = null;
    const out = [null];
    const configJson = config == null ? null : JSON.stringify(config);
    const status = this._native.functions.confidential_inference_sdk_new(configJson, out);
    this._native.raiseForStatus(status);
    this._handle = out[0];
  }

  status() {
    return this._native.status();
  }

  close() {
    if (!this._handle) {
      return;
    }
    const handle = this._handle;
    const status = this._native.functions.confidential_inference_sdk_free(handle);
    this._native.raiseForStatus(status);
    this._handle = null;
  }

  chat(request, options = {}) {
    return this._callJson(
      this._native.functions.confidential_inference_chat_blocking,
      request,
      timeoutMs(options),
      validateConfidentialResponse,
    );
  }

  createResponse(request, options = {}) {
    return this._callJson(
      this._native.functions.confidential_inference_response_blocking,
      request,
      timeoutMs(options),
      validateConfidentialResponse,
    );
  }

  response(request, options = {}) {
    return this.createResponse(request, options);
  }

  verify(provider, model, options = {}) {
    return this._callJson(
      this._native.functions.confidential_inference_verify_blocking,
      { provider, model },
      timeoutMs(options),
      validateVerdict,
    );
  }

  models() {
    return this._callNoRequestJson(
      this._native.functions.confidential_inference_models_blocking,
      validateModelList,
    );
  }

  confidentialModels() {
    return this._callNoRequestJson(
      this._native.functions.confidential_inference_confidentiality_blocking,
      validateConfidentialModels,
    );
  }

  confidentiality() {
    return this.confidentialModels();
  }

  activePolicy() {
    return this._callNoRequestJson(
      this._native.functions.confidential_inference_active_policy_blocking,
      validateActivePolicySnapshot,
    );
  }

  activeTrustArtifacts() {
    return this._callNoRequestJson(
      this._native.functions.confidential_inference_active_trust_artifacts_blocking,
      validateActiveTrustArtifacts,
    );
  }

  startChat(request) {
    return this._startOperation(
      this._native.functions.confidential_inference_chat_start,
      request,
      validateConfidentialResponse,
    );
  }

  startResponse(request) {
    return this._startOperation(
      this._native.functions.confidential_inference_response_start,
      request,
      validateConfidentialResponse,
    );
  }

  startVerify(provider, model) {
    return this._startOperation(
      this._native.functions.confidential_inference_verify_start,
      { provider, model },
      validateVerdict,
    );
  }

  startStream(request) {
    this._requireOpen();
    const out = [null];
    const status = this._native.functions.confidential_inference_chat_stream_start(
      this._handle,
      JSON.stringify(request),
      out,
    );
    this._native.raiseForStatus(status);
    return new Stream(this._native, out[0]);
  }

  async chatAsync(request, options = {}) {
    const operation = this.startChat(request);
    try {
      return await operation.wait(options);
    } finally {
      closeOrCancelOperation(operation);
    }
  }

  async createResponseAsync(request, options = {}) {
    const operation = this.startResponse(request);
    try {
      return await operation.wait(options);
    } finally {
      closeOrCancelOperation(operation);
    }
  }

  async responseAsync(request, options = {}) {
    return this.createResponseAsync(request, options);
  }

  async verifyAsync(provider, model, options = {}) {
    const operation = this.startVerify(provider, model);
    try {
      return await operation.wait(options);
    } finally {
      closeOrCancelOperation(operation);
    }
  }

  async *streamAsync(request, options = {}) {
    const stream = this.startStream(request);
    try {
      yield* stream.events(options);
    } finally {
      closeOrCancelStream(stream);
    }
  }

  _callJson(fn, request, timeout, validator) {
    this._requireOpen();
    const out = [null];
    const status = fn(this._handle, JSON.stringify(request), timeout, out);
    this._native.raiseForStatus(status);
    const payload = this._native.takeJsonString(out[0]);
    return validator ? validator(payload) : payload;
  }

  _callNoRequestJson(fn, validator) {
    this._requireOpen();
    const out = [null];
    const status = fn(this._handle, out);
    this._native.raiseForStatus(status);
    const payload = this._native.takeJsonString(out[0]);
    return validator ? validator(payload) : payload;
  }

  _startOperation(fn, request, validator) {
    this._requireOpen();
    const out = [null];
    const status = fn(this._handle, JSON.stringify(request), out);
    this._native.raiseForStatus(status);
    return new Operation(this._native, out[0], validator);
  }

  _requireOpen() {
    if (!this._handle) {
      throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, {
        code: 'client_closed',
        message: 'client is closed',
      });
    }
  }
}

class Operation {
  constructor(native, handle, validator) {
    this._native = native;
    this._handle = handle;
    this._validator = validator;
    this._callbackWatch = null;
  }

  poll() {
    this._requireOpen();
    const out = [null];
    const status = this._native.functions.confidential_inference_op_poll(this._handle, out);
    this._native.raiseForStatus(status);
    return validateOperationState(this._native.takeJsonString(out[0]));
  }

  result() {
    this._requireOpen();
    const out = [null];
    const status = this._native.functions.confidential_inference_op_result_json(this._handle, out);
    this._native.raiseForStatus(status);
    const payload = this._native.takeJsonString(out[0]);
    return this._validator ? this._validator(payload) : payload;
  }

  async wait(options = {}) {
    try {
      return await this._wait(options);
    } catch (error) {
      if (isAbortError(error)) {
        cancelQuietly(this);
      }
      throw error;
    }
  }

  async _wait(options = {}) {
    const timeout = timeoutMs(options);
    const signal = abortSignal(options);
    throwIfAborted(signal);
    if (process.platform !== 'win32') {
      const readinessAbort = new AbortController();
      try {
        const fd = this.readinessFd();
        const fallbackDelay = timeout > 0
          ? Math.min(pollIntervalMs(options), timeout)
          : pollIntervalMs(options);
        await Promise.race([
          waitForReadinessFd(
            fd,
            timeout,
            'operation_timeout',
              'operation timed out',
              readinessAbort.signal,
            ),
          delay(fallbackDelay, signal).then(() => {
            throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED, {
              code: 'readiness_fd_poll_fallback',
              message: 'operation readiness fd did not signal before poll fallback',
            });
          }),
        ]);
        return this.result();
      } catch (error) {
        if (!(error instanceof ConfidentialInferenceError)) {
          throw error;
        }
        if (![CONFIDENTIAL_INFERENCE_FFI_BUSY, CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED].includes(error.status)) {
          throw error;
        }
      } finally {
        readinessAbort.abort();
      }
    }
    return this._waitByPolling(options);
  }

  async _waitByPolling(options = {}) {
    const timeout = timeoutMs(options);
    const pollInterval = pollIntervalMs(options);
    const signal = abortSignal(options);
    const deadline = timeout === 0 ? null : Date.now() + timeout;
    for (;;) {
      throwIfAborted(signal);
      const state = this.poll();
      if (state.status !== 'pending') {
        return this.result();
      }
      if (deadline != null && Date.now() >= deadline) {
        throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_PENDING, {
          code: 'operation_timeout',
          message: 'operation timed out',
        });
      }
      await delay(pollInterval, signal);
    }
  }

  cancel() {
    this._requireOpen();
    const status = this._native.functions.confidential_inference_op_cancel(this._handle);
    this._native.raiseForStatus(status);
  }

  setCallback(callback) {
    this._requireOpen();
    this._clearCallback();
    if (!callback) {
      return;
    }
    const watch = { active: true, timer: null };
    const tick = () => {
      if (!watch.active || !this._handle) {
        return;
      }
      try {
        const state = this.poll();
        if (state.status !== 'pending') {
          watch.active = false;
          if (this._callbackWatch === watch) {
            this._callbackWatch = null;
          }
          callback();
          return;
        }
      } catch (_) {
        watch.active = false;
        if (this._callbackWatch === watch) {
          this._callbackWatch = null;
        }
        return;
      }
      watch.timer = setTimeout(tick, 10);
    };
    this._callbackWatch = watch;
    watch.timer = setTimeout(tick, 0);
  }

  readinessFd() {
    this._requireOpen();
    const out = [-1];
    const status = this._native.functions.confidential_inference_op_readiness_fd(this._handle, out);
    this._native.raiseForStatus(status);
    return out[0];
  }

  close() {
    if (!this._handle) {
      return;
    }
    this._clearCallback();
    const handle = this._handle;
    const status = this._native.functions.confidential_inference_op_free(handle);
    this._native.raiseForStatus(status);
    this._handle = null;
  }

  _clearCallback() {
    if (this._callbackWatch) {
      this._callbackWatch.active = false;
      if (this._callbackWatch.timer) {
        clearTimeout(this._callbackWatch.timer);
      }
      this._callbackWatch = null;
    }
  }

  _requireOpen() {
    if (!this._handle) {
      throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, {
        code: 'operation_closed',
        message: 'operation is closed',
      });
    }
  }
}

class Stream {
  constructor(native, handle) {
    this._native = native;
    this._handle = handle;
    this._callbackWatch = null;
    this._eventQueue = [];
  }

  next(options = {}) {
    this._requireOpen();
    if (this._eventQueue.length > 0) {
      return this._eventQueue.shift();
    }
    return this._nextNative(timeoutMs(options));
  }

  _nextNative(timeout) {
    const out = [null];
    const status = this._native.functions.confidential_inference_stream_next(
      this._handle,
      timeout,
      out,
    );
    this._native.raiseForStatus(status);
    return validateStreamEvent(this._native.takeJsonString(out[0]));
  }

  async *events(options = {}) {
    const timeout = timeoutMs(options);
    const pollInterval = pollIntervalMs(options);
    const signal = abortSignal(options);
    const deadline = timeout === 0 ? null : Date.now() + timeout;
    let readinessTaken = false;
    try {
      for (;;) {
        throwIfAborted(signal);
        try {
          const event = this.next(0);
          if (event.type === 'closed') {
            return;
          }
          yield event;
        } catch (error) {
          if (!(error instanceof ConfidentialInferenceError) || error.status !== CONFIDENTIAL_INFERENCE_FFI_PENDING) {
            throw error;
          }
          if (deadline != null && Date.now() >= deadline) {
            throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_PENDING, {
              code: 'stream_timeout',
              message: 'stream event timed out',
            });
          }
          if (process.platform !== 'win32' && !readinessTaken) {
            try {
              const fd = this.readinessFd();
              readinessTaken = true;
              await waitForReadinessFd(
                fd,
                remainingTimeoutMs(deadline),
                'stream_timeout',
                'stream event timed out',
                signal,
              );
              continue;
            } catch (readinessError) {
              if (!(readinessError instanceof ConfidentialInferenceError)) {
                throw readinessError;
              }
              if (![CONFIDENTIAL_INFERENCE_FFI_BUSY, CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED].includes(readinessError.status)) {
                throw readinessError;
              }
            }
          }
          await delay(pollInterval, signal);
        }
      }
    } catch (error) {
      if (isAbortError(error)) {
        cancelQuietly(this);
      }
      throw error;
    }
  }

  cancel() {
    this._requireOpen();
    const status = this._native.functions.confidential_inference_stream_cancel(this._handle);
    this._native.raiseForStatus(status);
  }

  setCallback(callback) {
    this._requireOpen();
    this._clearCallback();
    if (!callback) {
      return;
    }
    const watch = { active: true, timer: null };
    const tick = () => {
      if (!watch.active || !this._handle) {
        return;
      }
      if (this._eventQueue.length > 0) {
        watch.active = false;
        if (this._callbackWatch === watch) {
          this._callbackWatch = null;
        }
        callback();
        return;
      }
      try {
        const event = this._nextNative(0);
        this._eventQueue.push(event);
        watch.active = false;
        if (this._callbackWatch === watch) {
          this._callbackWatch = null;
        }
        callback();
      } catch (error) {
        if (error instanceof ConfidentialInferenceError && error.status === CONFIDENTIAL_INFERENCE_FFI_PENDING) {
          watch.timer = setTimeout(tick, 10);
          return;
        }
        watch.active = false;
        if (this._callbackWatch === watch) {
          this._callbackWatch = null;
        }
      }
    };
    this._callbackWatch = watch;
    watch.timer = setTimeout(tick, 0);
  }

  readinessFd() {
    this._requireOpen();
    const out = [-1];
    const status = this._native.functions.confidential_inference_stream_readiness_fd(this._handle, out);
    this._native.raiseForStatus(status);
    return out[0];
  }

  close() {
    if (!this._handle) {
      return;
    }
    this._clearCallback();
    const handle = this._handle;
    const status = this._native.functions.confidential_inference_stream_free(handle);
    this._native.raiseForStatus(status);
    this._handle = null;
  }

  _clearCallback() {
    if (this._callbackWatch) {
      this._callbackWatch.active = false;
      if (this._callbackWatch.timer) {
        clearTimeout(this._callbackWatch.timer);
      }
      this._callbackWatch = null;
    }
  }

  _requireOpen() {
    if (!this._handle) {
      throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, {
        code: 'stream_closed',
        message: 'stream is closed',
      });
    }
  }
}

function configureFunctions(lib) {
  return {
    confidential_inference_status: lib.func('confidential_inference_status', 'int', [StringOut]),
    confidential_inference_sdk_new: lib.func('confidential_inference_sdk_new', 'int', ['str', ClientOut]),
    confidential_inference_sdk_free: lib.func('confidential_inference_sdk_free', 'int', [ClientPtr]),
    confidential_inference_chat_start: lib.func('confidential_inference_chat_start', 'int', [
      ClientPtr,
      'str',
      OperationOut,
    ]),
    confidential_inference_response_start: lib.func('confidential_inference_response_start', 'int', [
      ClientPtr,
      'str',
      OperationOut,
    ]),
    confidential_inference_verify_start: lib.func('confidential_inference_verify_start', 'int', [
      ClientPtr,
      'str',
      OperationOut,
    ]),
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
    confidential_inference_confidentiality_blocking: lib.func('confidential_inference_confidentiality_blocking', 'int', [
      ClientPtr,
      StringOut,
    ]),
    confidential_inference_active_policy_blocking: lib.func('confidential_inference_active_policy_blocking', 'int', [
      ClientPtr,
      StringOut,
    ]),
    confidential_inference_active_trust_artifacts_blocking: lib.func(
      'confidential_inference_active_trust_artifacts_blocking',
      'int',
      [ClientPtr, StringOut],
    ),
    confidential_inference_op_poll: lib.func('confidential_inference_op_poll', 'int', [OperationPtr, StringOut]),
    confidential_inference_op_result_json: lib.func('confidential_inference_op_result_json', 'int', [
      OperationPtr,
      StringOut,
    ]),
    confidential_inference_op_readiness_fd: lib.func('confidential_inference_op_readiness_fd', 'int', [
      OperationPtr,
      IntOut,
    ]),
    confidential_inference_op_cancel: lib.func('confidential_inference_op_cancel', 'int', [OperationPtr]),
    confidential_inference_op_free: lib.func('confidential_inference_op_free', 'int', [OperationPtr]),
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
    confidential_inference_stream_readiness_fd: lib.func('confidential_inference_stream_readiness_fd', 'int', [
      StreamPtr,
      IntOut,
    ]),
    confidential_inference_stream_cancel: lib.func('confidential_inference_stream_cancel', 'int', [StreamPtr]),
    confidential_inference_stream_free: lib.func('confidential_inference_stream_free', 'int', [StreamPtr]),
    confidential_inference_last_error: lib.func('confidential_inference_last_error', 'int', [StringOut]),
    confidential_inference_string_free: lib.func('confidential_inference_string_free', 'void', [VoidPtr]),
  };
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

function canonicalJson(value) {
  if (value === null) {
    return 'null';
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (typeof value === 'number') {
    validateJsonInteger(value);
    return String(value);
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  if (isObject(value)) {
    return `{${Object.keys(value)
      // JCS orders object member names by raw UTF-16 code units. JavaScript's
      // default string sort has exactly those semantics.
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throwMalformed(
    'malformed_canonical_json',
    `canonical JSON does not support values of type ${typeof value}`,
  );
}

function canonicalSha256Digest(value) {
  return `${SHA256_DIGEST_PREFIX}${crypto
    .createHash('sha256')
    .update(canonicalJson(value), 'utf8')
    .digest('hex')}`;
}

function policyCanonicalJson(policy) {
  return canonicalJson(normalizedPolicyForDigest(policy));
}

function policyDigest(policy) {
  return canonicalSha256Digest(normalizedPolicyForDigest(policy));
}

function normalizedPolicyForDigest(policy) {
  if (!isObject(policy)) {
    throwMalformed('malformed_policy_digest', 'policy payload must be an object');
  }
  validateSchemaMajor(
    policy,
    'schema',
    'confidential-inference.policy',
    'policy schema',
    'malformed_policy_digest',
    'incompatible_policy_digest',
    'policy payload',
  );
  requireExactFields(policy, POLICY_DIGEST_FIELDS, 'policy payload', 'malformed_policy_digest');

  const hardware = policy.hardware;
  if (!isObject(hardware)) {
    throwMalformed('malformed_policy_digest', 'policy payload hardware must be an object');
  }
  requireExactFields(
    hardware,
    POLICY_HARDWARE_FIELDS,
    'policy payload hardware',
    'malformed_policy_digest',
  );
  validatePolicyTeeRequirement(hardware.cpu, 'hardware.cpu');
  validatePolicyTeeRequirement(hardware.gpu, 'hardware.gpu');

  const provenance = policy.provenance;
  if (!isObject(provenance)) {
    throwMalformed('malformed_policy_digest', 'policy payload provenance must be an object');
  }
  requireExactFields(
    provenance,
    POLICY_PROVENANCE_FIELDS,
    'policy payload provenance',
    'malformed_policy_digest',
  );
  validatePolicyTaggedMillis(policy.freshness, 'freshness', 'allow_cached_binding_millis');
  validatePolicyTaggedMillis(policy.stale_verdicts, 'stale_verdicts', 'allow_for_millis');

  const normalized = cloneJsonValue(policy);
  for (const field of ['cpu', 'gpu']) {
    const requirement = normalized.hardware[field];
    if (requirement.mode === 'one_of') {
      requirement.allowed = Array.from(new Set(requirement.allowed)).sort(compareUtf8);
    }
  }
  validateActivePolicySchemaFields(normalized);
  validateActivePolicyMillisFields(normalized);
  return normalized;
}

function validatePolicyTeeRequirement(value, field) {
  if (!isObject(value)) {
    throwMalformed('malformed_policy_digest', `policy payload ${field} must be an object`);
  }
  requireExactFields(
    value,
    value.mode === 'one_of' ? POLICY_TEE_ONE_OF_FIELDS : POLICY_TEE_BASE_FIELDS,
    `policy payload ${field}`,
    'malformed_policy_digest',
  );
}

function validatePolicyTaggedMillis(value, field, millisMode) {
  if (!isObject(value)) {
    throwMalformed('malformed_policy_digest', `policy payload ${field} must be an object`);
  }
  requireExactFields(
    value,
    value.mode === millisMode ? POLICY_TAGGED_MILLIS_FIELDS : POLICY_TAGGED_BASE_FIELDS,
    `policy payload ${field}`,
    'malformed_policy_digest',
  );
}

function requireExactFields(payload, allowed, subject, code) {
  const actual = Object.keys(payload);
  const missing = Array.from(allowed).filter((field) => !Object.hasOwn(payload, field)).sort(compareUtf8);
  if (missing.length > 0) {
    throwMalformed(code, `${subject} is missing ${missing.join(', ')}`);
  }
  for (const field of actual.sort(compareUtf8)) {
    if (!allowed.has(field)) {
      throwMalformed(code, `${subject} has unsupported field ${field}`);
    }
  }
}

function cloneJsonValue(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    validateJsonInteger(value);
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => cloneJsonValue(item));
  }
  if (isObject(value)) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, cloneJsonValue(item)]));
  }
  throwMalformed(
    'malformed_canonical_json',
    `canonical JSON does not support values of type ${typeof value}`,
  );
}

function validateJsonInteger(value) {
  if (!Number.isInteger(value)) {
    throwMalformed('malformed_canonical_json', 'canonical JSON does not support floating point numbers');
  }
  if (!Number.isSafeInteger(value)) {
    throwMalformed(
      'malformed_canonical_json',
      'canonical JSON integer exceeds the cross-language JSON safe integer limit',
    );
  }
}

function validateSafeJsonInt(value, field, subject, code, label = 'integer') {
  if (!Number.isInteger(value) || value < 0) {
    throwMalformed(code, `${subject} ${field} must be a non-negative ${label}`);
  }
  if (!Number.isSafeInteger(value)) {
    throwMalformed(code, `${subject} ${field} exceeds the cross-language JSON safe integer limit`);
  }
}

function validateSchemaMajor(payload, field, prefix, label, malformedCode, incompatibleCode, subject) {
  const schema = payload[field];
  const marker = `${prefix}.v`;
  if (typeof schema !== 'string' || !schema.startsWith(marker)) {
    throwMalformed(malformedCode, `${subject} ${label} is not a Confidential Inference schema`);
  }
  const majorText = schema.slice(marker.length).split('.')[0];
  if (!/^[0-9]+$/.test(majorText)) {
    throwMalformed(malformedCode, `${subject} ${label} has malformed major version`);
  }
  if (Number(majorText) !== 1) {
    throwMalformed(incompatibleCode, `${subject} ${label} major version ${majorText} is not supported`);
  }
}

function compareUtf8(a, b) {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

function choices(values) {
  return Array.from(values).sort(compareUtf8).join(', ');
}

function validateOperationState(state) {
  if (!isObject(state)) {
    throwMalformed('malformed_operation_state', 'operation state must be an object');
  }
  const status = state.status;
  if (typeof status !== 'string' || !OPERATION_STATUS_VALUES.has(status)) {
    throwMalformed(
      'malformed_operation_state',
      `operation state status must be one of: ${choices(OPERATION_STATUS_VALUES)}`,
    );
  }
  const fields =
    status === 'failed' ? OPERATION_STATE_FAILED_FIELDS : OPERATION_STATE_BASE_FIELDS;
  requireExactFields(state, fields, 'operation state', 'malformed_operation_state');
  if (status === 'failed') {
    if (state.result_available !== true) {
      throwMalformed(
        'malformed_operation_state',
        'failed operation state must have result_available=true',
      );
    }
    if (!isObject(state.error)) {
      throwMalformed('malformed_operation_state', 'failed operation state must include error metadata');
    }
  }
  return state;
}

function validateFfiErrorEnvelope(payload) {
  if (!isObject(payload)) {
    throwMalformed('malformed_ffi_error', 'FFI error envelope must be an object');
  }
  requireExactFields(payload, FFI_ERROR_ENVELOPE_FIELDS, 'FFI error envelope', 'malformed_ffi_error');
  const { error } = payload;
  if (error === null) {
    return payload;
  }
  if (!isObject(error)) {
    throwMalformed('malformed_ffi_error', 'FFI error must be an object or null');
  }
  requireExactFields(error, FFI_ERROR_FIELDS, 'FFI error', 'malformed_ffi_error');
  if (error.type !== 'confidential_inference_ffi_error') {
    throwMalformed('malformed_ffi_error', `FFI error type has invalid value ${error.type}`);
  }
  for (const field of ['code', 'message']) {
    if (typeof error[field] !== 'string' || error[field].length === 0) {
      throwMalformed('malformed_ffi_error', `FFI error ${field} must be a non-empty string`);
    }
  }
  return payload;
}

function validateFfiStatus(payload) {
  if (!isObject(payload)) {
    throwMalformed('malformed_ffi_status', 'FFI status must be an object');
  }
  requireExactFields(payload, FFI_STATUS_FIELDS, 'FFI status', 'malformed_ffi_status');
  for (const field of [
    'async_handle_abi_available',
    'callbacks_available',
    'readiness_fd_available',
    'stream_handle_abi_available',
    'blocking_helpers_available',
  ]) {
    if (typeof payload[field] !== 'boolean') {
      throwMalformed('malformed_ffi_status', `FFI status ${field} must be a boolean`);
    }
  }
  if (typeof payload.reason !== 'string' || payload.reason.length === 0) {
    throwMalformed('malformed_ffi_status', 'FFI status reason must be a non-empty string');
  }
  return payload;
}

function validateModelList(payload) {
  if (!isObject(payload)) {
    throwMalformed('malformed_model_discovery', 'model discovery payload must be an object');
  }
  requireExactFields(
    payload,
    MODEL_LIST_FIELDS,
    'model discovery payload',
    'malformed_model_discovery',
  );
  if (payload.object !== 'list') {
    throwMalformed('malformed_model_discovery', 'model discovery payload object must be list');
  }
  if (!Array.isArray(payload.data)) {
    throwMalformed('malformed_model_discovery', 'model discovery payload data must be a list');
  }
  payload.data.forEach((model, index) => validateModelRecord(model, index));
  return payload;
}

function validateModelRecord(model, index) {
  const subject = `model discovery payload data[${index}]`;
  if (!isObject(model)) {
    throwMalformed('malformed_model_discovery', `${subject} must be an object`);
  }
  requireExactFields(
    model,
    MODEL_RECORD_FIELDS,
    subject,
    'malformed_model_discovery',
  );
  validateRequiredString(model, 'id', subject, 'malformed_model_discovery');
  validateRequiredString(model, 'owned_by', subject, 'malformed_model_discovery');
  if (model.object !== 'model') {
    throwMalformed('malformed_model_discovery', `${subject}.object must be model`);
  }
}

function validateConfidentialModels(payload) {
  if (!Array.isArray(payload)) {
    throwMalformed('malformed_confidential_catalog', 'confidential catalog payload must be a list');
  }
  payload.forEach((model, index) => validateConfidentialModel(model, index));
  return payload;
}

function validateConfidentialModel(model, index) {
  const subject = `confidential catalog payload model[${index}]`;
  if (!isObject(model)) {
    throwMalformed('malformed_confidential_catalog', `${subject} must be an object`);
  }
  requireExactFields(
    model,
    CONFIDENTIAL_MODEL_FIELDS,
    subject,
    'malformed_confidential_catalog',
  );
  for (const field of ['canonical_model', 'display_name', 'family']) {
    validateRequiredString(model, field, subject, 'malformed_confidential_catalog');
  }
  validateStringList(model.aliases, `${subject}.aliases`, 'malformed_confidential_catalog');
  if (!Array.isArray(model.routes) || model.routes.length === 0) {
    throwMalformed('malformed_confidential_catalog', `${subject}.routes must be a non-empty list`);
  }
  model.routes.forEach((route, routeIndex) =>
    validateConfidentialRoute(route, model.canonical_model, routeIndex),
  );
}

function validateConfidentialRoute(route, modelId, routeIndex) {
  const subject = `confidential catalog payload model ${modelId} route[${routeIndex}]`;
  if (!isObject(route)) {
    throwMalformed('malformed_confidential_catalog', `${subject} must be an object`);
  }
  requireExactFields(
    route,
    CONFIDENTIAL_ROUTE_FIELDS,
    subject,
    'malformed_confidential_catalog',
  );
  for (const field of [
    'route_id',
    'provider',
    'provider_model',
    'evidence_family',
    'api_endpoint',
    'evidence_endpoint',
    'adapter_version',
  ]) {
    validateRequiredString(route, field, subject, 'malformed_confidential_catalog');
  }
  validateCatalogChoice(
    route,
    subject,
    'route_execution_status',
    CATALOG_ROUTE_EXECUTION_STATUS_VALUES,
  );
  validateCatalogChoice(route, subject, 'trust_tier', TRUST_TIER_VALUES);
  validateCatalogChoice(route, subject, 'channel_binding_kind', CHANNEL_BINDING_KIND_VALUES);
  validateCatalogChoice(route, subject, 'request_encryption', REGISTRY_ENCRYPTION_REQUIREMENT_VALUES);
  validateCatalogChoice(route, subject, 'response_decryption', REGISTRY_ENCRYPTION_REQUIREMENT_VALUES);
  validateCatalogChoice(route, subject, 'alias_confidence', ALIAS_CONFIDENCE_VALUES);
  validateBoolFieldWithCode(route, 'chat_executable', subject, 'malformed_confidential_catalog');
  validateBoolFieldWithCode(route, 'streaming_allowed', subject, 'malformed_confidential_catalog');
  validateStringList(
    route.known_unsupported_modes,
    `${subject}.known_unsupported_modes`,
    'malformed_confidential_catalog',
  );
  validateTrustTierChannelBindingPair(
    route.trust_tier,
    route.channel_binding_kind,
    subject,
    'malformed_confidential_catalog',
  );
}

function validateCatalogChoice(route, subject, field, allowed) {
  const value = route[field];
  if (!allowed.has(value)) {
    throwMalformed(
      'malformed_confidential_catalog',
      `${subject}.${field} must be one of: ${choices(allowed)}`,
    );
  }
  return value;
}

function validateRequiredString(payload, field, subject, code) {
  const value = payload[field];
  if (typeof value !== 'string' || value.length === 0) {
    throwMalformed(code, `${subject}.${field} must be a non-empty string`);
  }
}

function validateStringList(value, subject, code) {
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== 'string' || item.length === 0)
  ) {
    throwMalformed(code, `${subject} must contain non-empty strings`);
  }
}

function validateBoolFieldWithCode(payload, field, subject, code) {
  if (typeof payload[field] !== 'boolean') {
    throwMalformed(code, `${subject}.${field} must be a boolean`);
  }
}

function timeoutMs(options) {
  if (typeof options === 'number') {
    return options;
  }
  return options?.timeoutMs || 0;
}

function pollIntervalMs(options) {
  if (typeof options === 'number') {
    return 10;
  }
  return options?.pollIntervalMs || 10;
}

function abortSignal(options) {
  if (typeof options !== 'object' || options === null) {
    return undefined;
  }
  return options.signal;
}

function throwIfAborted(signal) {
  if (signal?.aborted) {
    throw abortError(signal);
  }
}

function abortError(signal) {
  const reason = signal?.reason;
  if (reason && typeof reason === 'object' && reason.name === 'AbortError') {
    return reason;
  }
  const error = new Error('operation aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  error.reason = reason;
  return error;
}

function isAbortError(error) {
  return Boolean(error && (error.name === 'AbortError' || error.code === 'ABORT_ERR'));
}

function remainingTimeoutMs(deadline) {
  if (deadline == null) {
    return 0;
  }
  return Math.max(1, deadline - Date.now());
}

function delay(ms, signal) {
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    let timer = null;
    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
      }
      signal?.removeEventListener?.('abort', onAbort);
    };
    const onAbort = () => {
      cleanup();
      reject(abortError(signal));
    };
    timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);
    signal?.addEventListener?.('abort', onAbort, { once: true });
  });
}

function waitForReadinessFd(fd, timeout, code, message, signal) {
  throwIfAborted(signal);
  let socket;
  try {
    socket = new net.Socket({ fd, readable: true, writable: false });
  } catch (error) {
    try {
      fs.closeSync(fd);
    } catch (_) {
      // Ignore close errors while converting readiness-fd support failures.
    }
    throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED, {
      code: 'readiness_fd_unsupported',
      message: `event loop cannot wrap readiness file descriptor: ${error.message}`,
    });
  }

  return new Promise((resolve, reject) => {
    let timer = null;
    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
      }
      signal?.removeEventListener?.('abort', onAbort);
      socket.removeAllListeners();
      socket.destroy();
    };
    const onAbort = () => {
      cleanup();
      reject(abortError(signal));
    };
    socket.once('readable', () => {
      cleanup();
      resolve();
    });
    socket.once('error', (error) => {
      cleanup();
      reject(error);
    });
    if (timeout > 0) {
      timer = setTimeout(() => {
        cleanup();
        reject(new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_PENDING, { code, message }));
      }, timeout);
    }
    signal?.addEventListener?.('abort', onAbort, { once: true });
  });
}

function cancelQuietly(handle) {
  try {
    handle.cancel();
  } catch (_) {
    // Cancellation is best effort when the abort raced with terminal completion.
  }
}

function closeOrCancelOperation(operation) {
  try {
    operation.close();
  } catch (error) {
    if (!(error instanceof ConfidentialInferenceError) || error.status !== CONFIDENTIAL_INFERENCE_FFI_BUSY) {
      throw error;
    }
    operation.cancel();
    operation.close();
  }
}

function closeOrCancelStream(stream) {
  try {
    stream.close();
  } catch (error) {
    if (!(error instanceof ConfidentialInferenceError) || error.status !== CONFIDENTIAL_INFERENCE_FFI_BUSY) {
      throw error;
    }
    stream.cancel();
    stream.close();
  }
}

function validateActivePolicySnapshot(snapshot) {
  if (!isObject(snapshot)) {
    throwMalformed('malformed_active_policy', 'active policy snapshot must be a JSON object');
  }
  validateSchemaMajor(
    snapshot,
    'schema',
    'confidential-inference.active-policy',
    'active-policy schema',
    'malformed_active_policy_schema',
    'incompatible_active_policy_schema',
    'active policy snapshot',
  );
  validateRequiredFields(
    snapshot,
    ACTIVE_POLICY_SNAPSHOT_KNOWN_FIELDS,
    'malformed_active_policy_schema',
    'incompatible_active_policy_schema',
    'active policy snapshot',
  );

  const policy = snapshot.policy;
  if (!isObject(policy)) {
    throwMalformed('malformed_active_policy', 'active policy snapshot is missing policy');
  }
  validateSchemaMajor(
    policy,
    'schema',
    'confidential-inference.policy',
    'policy schema',
    'malformed_active_policy_schema',
    'incompatible_active_policy_schema',
    'active policy payload',
  );
  validateRequiredFields(
    policy,
    POLICY_KNOWN_FIELDS,
    'malformed_active_policy_schema',
    'incompatible_active_policy_schema',
    'active policy payload',
  );
  validateSha256DigestField(
    snapshot,
    'policy_digest',
    'malformed_active_policy_digest',
    'active policy snapshot',
  );
  validateSha256DigestField(
    policy,
    'provider_registry_digest',
    'malformed_active_policy_digest',
    'active policy payload',
  );
  validateSha256DigestField(
    policy,
    'reference_values_digest',
    'malformed_active_policy_digest',
    'active policy payload',
  );
  validateActivePolicySchemaFields(policy);
  validateActivePolicyMillisFields(policy);
  validateCanonicalPayloadDigest(
    policy,
    snapshot.policy_digest,
    'policy_digest',
    'active policy snapshot',
    'malformed_active_policy_digest',
  );
  return snapshot;
}

function validateActiveTrustArtifacts(artifacts) {
  if (!isObject(artifacts)) {
    throwMalformed('malformed_trust_artifacts', 'active trust artifacts must be a JSON object');
  }

  const registry = artifacts.registry;
  if (!isObject(registry)) {
    throwMalformed('malformed_trust_artifacts', 'active trust artifacts are missing registry');
  }
  validateSchemaMajor(
    registry,
    'schema',
    'confidential-inference.provider-registry',
    'provider-registry schema',
    'malformed_trust_artifacts_schema',
    'incompatible_trust_artifacts_schema',
    'active registry payload',
  );
  validateRequiredFields(
    artifacts,
    TRUST_ARTIFACTS_KNOWN_FIELDS,
    'malformed_trust_artifacts_schema',
    'incompatible_trust_artifacts_schema',
    'active trust artifacts',
  );
  validateRequiredFields(
    registry,
    REGISTRY_PAYLOAD_KNOWN_FIELDS,
    'malformed_trust_artifacts_schema',
    'incompatible_trust_artifacts_schema',
    'active registry payload',
  );

  const referenceValues = artifacts.reference_values;
  if (!isObject(referenceValues)) {
    throwMalformed('malformed_trust_artifacts', 'active trust artifacts are missing reference_values');
  }
  validateSchemaMajor(
    referenceValues,
    'schema',
    'confidential-inference.reference-values',
    'reference-values schema',
    'malformed_trust_artifacts_schema',
    'incompatible_trust_artifacts_schema',
    'active reference-values payload',
  );
  validateRequiredFields(
    referenceValues,
    REFERENCE_VALUES_PAYLOAD_KNOWN_FIELDS,
    'malformed_trust_artifacts_schema',
    'incompatible_trust_artifacts_schema',
    'active reference-values payload',
  );
  validateSha256DigestField(
    artifacts,
    'registry_digest',
    'malformed_trust_artifacts_digest',
    'active trust artifacts',
  );
  validateSha256DigestField(
    artifacts,
    'reference_values_digest',
    'malformed_trust_artifacts_digest',
    'active trust artifacts',
  );
  validateSignatureFields(
    artifacts,
    ['registry_signature', 'reference_values_signature'],
    'malformed_trust_artifacts_signature',
    'active trust artifacts',
    true,
  );
  validateActiveTrustArtifactMetadata(registry, referenceValues);
  validateCanonicalPayloadDigest(
    registry,
    artifacts.registry_digest,
    'registry_digest',
    'active trust artifacts',
    'malformed_trust_artifacts_digest',
  );
  validateCanonicalPayloadDigest(
    referenceValues,
    artifacts.reference_values_digest,
    'reference_values_digest',
    'active trust artifacts',
    'malformed_trust_artifacts_digest',
  );
  verifyKnownArtifactSignature(artifacts.registry_signature, registry, 'registry_signature');
  verifyKnownArtifactSignature(
    artifacts.reference_values_signature,
    referenceValues,
    'reference_values_signature',
  );
  return artifacts;
}

function validateActivePolicySchemaFields(policy) {
  validateActivePolicyChoiceField(policy, 'enforcement', ENFORCEMENT_VALUES);
  validateActivePolicyChoiceField(
    policy,
    'channel_binding_requirement',
    POLICY_CHANNEL_BINDING_REQUIREMENT_VALUES,
  );
  validateActivePolicyChoiceField(
    policy,
    'request_confidentiality_requirement',
    POLICY_BOUND_DATA_REQUIREMENT_VALUES,
  );
  validateActivePolicyChoiceField(
    policy,
    'response_confidentiality_requirement',
    POLICY_BOUND_DATA_REQUIREMENT_VALUES,
  );
  validateActivePolicyChoiceField(
    policy,
    'response_integrity_requirement',
    POLICY_RESPONSE_INTEGRITY_REQUIREMENT_VALUES,
  );
  validateActivePolicyChoiceField(
    policy,
    'model_binding_requirement',
    POLICY_MODEL_BINDING_REQUIREMENT_VALUES,
  );
  validateActivePolicyHardware(policy);
  validateActivePolicyProvenance(policy);
  validateActivePolicyFreshness(policy);
  validateActivePolicyStaleVerdicts(policy);
}

function validateActivePolicyChoiceField(policy, field, allowed) {
  const value = policy[field];
  if (!allowed.has(value)) {
    throwMalformed(
      'malformed_active_policy_schema',
      `active policy payload ${field} must be one of: ${choices(allowed)}`,
    );
  }
}

function validateActivePolicyHardware(policy) {
  const hardware = policy.hardware;
  if (!isObject(hardware)) {
    throwMalformed('malformed_active_policy_schema', 'active policy payload hardware must be an object');
  }
  validateActivePolicyTeeRequirement(
    hardware.cpu,
    'hardware.cpu',
    POLICY_CPU_TEE_MODES,
    POLICY_CPU_TEE_KINDS,
  );
  validateActivePolicyTeeRequirement(
    hardware.gpu,
    'hardware.gpu',
    POLICY_GPU_TEE_MODES,
    POLICY_GPU_TEE_KINDS,
  );
}

function validateActivePolicyTeeRequirement(payload, field, modes, allowedValues) {
  if (!isObject(payload)) {
    throwMalformed('malformed_active_policy_schema', `active policy payload ${field} must be an object`);
  }
  const mode = payload.mode;
  if (!modes.has(mode)) {
    throwMalformed(
      'malformed_active_policy_schema',
      `active policy payload ${field}.mode must be one of: ${choices(modes)}`,
    );
  }
  if (mode !== 'one_of') {
    if ('allowed' in payload) {
      throwMalformed(
        'malformed_active_policy_schema',
        `active policy payload ${field}.allowed is valid only for one_of`,
      );
    }
    return;
  }

  const allowed = payload.allowed;
  if (!Array.isArray(allowed) || allowed.length === 0) {
    throwMalformed(
      'malformed_active_policy_schema',
      `active policy payload ${field}.allowed must be a non-empty list`,
    );
  }
  if (allowed.some((value) => typeof value !== 'string' || !allowedValues.has(value))) {
    throwMalformed(
      'malformed_active_policy_schema',
      `active policy payload ${field}.allowed values must be one of: ${choices(allowedValues)}`,
    );
  }
  const sortedUnique = Array.from(new Set(allowed)).sort(compareUtf8);
  if (allowed.length !== sortedUnique.length || allowed.some((value, index) => value !== sortedUnique[index])) {
    throwMalformed(
      'malformed_active_policy_schema',
      `active policy payload ${field}.allowed must be sorted and unique`,
    );
  }
}

function validateActivePolicyProvenance(policy) {
  const provenance = policy.provenance;
  if (!isObject(provenance)) {
    throwMalformed('malformed_active_policy_schema', 'active policy payload provenance must be an object');
  }
  for (const field of Array.from(POLICY_PROVENANCE_FIELDS).sort(compareUtf8)) {
    if (typeof provenance[field] !== 'boolean') {
      throwMalformed(
        'malformed_active_policy_schema',
        `active policy payload provenance.${field} must be a boolean`,
      );
    }
  }
}

function validateActivePolicyFreshness(policy) {
  const freshness = policy.freshness;
  if (!isObject(freshness)) {
    throwMalformed('malformed_active_policy_schema', 'active policy payload freshness must be an object');
  }
  const mode = freshness.mode;
  if (!POLICY_FRESHNESS_MODES.has(mode)) {
    throwMalformed(
      'malformed_active_policy_schema',
      `active policy payload freshness.mode must be one of: ${choices(POLICY_FRESHNESS_MODES)}`,
    );
  }
  if (mode !== 'allow_cached_binding_millis' && 'millis' in freshness) {
    throwMalformed(
      'malformed_active_policy_schema',
      'active policy payload freshness.millis is valid only for allow_cached_binding_millis',
    );
  }
}

function validateActivePolicyStaleVerdicts(policy) {
  const staleVerdicts = policy.stale_verdicts;
  if (!isObject(staleVerdicts)) {
    throwMalformed('malformed_active_policy_schema', 'active policy payload stale_verdicts must be an object');
  }
  const mode = staleVerdicts.mode;
  if (!POLICY_STALE_VERDICT_MODES.has(mode)) {
    throwMalformed(
      'malformed_active_policy_schema',
      `active policy payload stale_verdicts.mode must be one of: ${choices(POLICY_STALE_VERDICT_MODES)}`,
    );
  }
  if (mode !== 'allow_for_millis' && 'millis' in staleVerdicts) {
    throwMalformed(
      'malformed_active_policy_schema',
      'active policy payload stale_verdicts.millis is valid only for allow_for_millis',
    );
  }
}

function validateActivePolicyMillisFields(policy) {
  if ('verdict_ttl_millis' in policy) {
    validateSafeJsonInt(
      policy.verdict_ttl_millis,
      'verdict_ttl_millis',
      'active policy payload',
      'malformed_active_policy_schema',
      'millisecond value',
    );
  }

  const freshness = policy.freshness;
  if (isObject(freshness) && freshness.mode === 'allow_cached_binding_millis') {
    if (!('millis' in freshness)) {
      throwMalformed('malformed_active_policy_schema', 'active policy payload freshness.millis is required');
    }
    validateSafeJsonInt(
      freshness.millis,
      'freshness.millis',
      'active policy payload',
      'malformed_active_policy_schema',
      'millisecond value',
    );
  }

  const staleVerdicts = policy.stale_verdicts;
  if (isObject(staleVerdicts) && staleVerdicts.mode === 'allow_for_millis') {
    if (!('millis' in staleVerdicts)) {
      throwMalformed('malformed_active_policy_schema', 'active policy payload stale_verdicts.millis is required');
    }
    validateSafeJsonInt(
      staleVerdicts.millis,
      'stale_verdicts.millis',
      'active policy payload',
      'malformed_active_policy_schema',
      'millisecond value',
    );
  }
}

function validateActiveTrustArtifactMetadata(registry, referenceValues) {
  if ('generated_at' in registry) {
    parseUtcEpochMs(
      requiredTimestamp(
        registry,
        'generated_at',
        'active registry payload',
        'malformed_trust_artifacts_schema',
      ),
      'active registry payload generated_at',
      'malformed_trust_artifacts_schema',
    );
  }

  const sourceSyncRun = registry.source_sync_run;
  if (sourceSyncRun !== undefined && sourceSyncRun !== null) {
    if (!isObject(sourceSyncRun)) {
      throwMalformed(
        'malformed_trust_artifacts_schema',
        'active registry payload source_sync_run must be an object',
      );
    }
    if ('completed_at' in sourceSyncRun) {
      parseUtcEpochMs(
        requiredTimestamp(
          sourceSyncRun,
          'completed_at',
          'active registry payload source_sync_run',
          'malformed_trust_artifacts_schema',
        ),
        'active registry payload source_sync_run.completed_at',
        'malformed_trust_artifacts_schema',
      );
    }
  }

  if ('valid_from' in referenceValues) {
    parseUtcEpochMs(
      requiredTimestamp(
        referenceValues,
        'valid_from',
        'active reference-values payload',
        'malformed_trust_artifacts_schema',
      ),
      'active reference-values payload valid_from',
      'malformed_trust_artifacts_schema',
    );
  }

  let parsedValidUntil = null;
  if ('valid_until' in referenceValues) {
    parsedValidUntil = parseUtcEpochMs(
      requiredTimestamp(
        referenceValues,
        'valid_until',
        'active reference-values payload',
        'malformed_trust_artifacts_schema',
      ),
      'active reference-values payload valid_until',
      'malformed_trust_artifacts_schema',
    );
  }
  if ('valid_until_epoch_ms' in referenceValues) {
    validateSafeJsonInt(
      referenceValues.valid_until_epoch_ms,
      'valid_until_epoch_ms',
      'active reference-values payload',
      'malformed_trust_artifacts_schema',
      'integer millisecond epoch',
    );
    if (parsedValidUntil !== null && referenceValues.valid_until_epoch_ms !== parsedValidUntil) {
      throwMalformed(
        'malformed_trust_artifacts_schema',
        'active reference-values payload valid_until_epoch_ms must match valid_until',
      );
    }
  }
  if ('revocation_epoch' in referenceValues) {
    validateSafeJsonInt(
      referenceValues.revocation_epoch,
      'revocation_epoch',
      'active reference-values payload',
      'malformed_trust_artifacts_schema',
    );
  }

  validateActiveRegistryModels(registry);
  validateActiveReferenceValuesProviders(referenceValues);
}

function validateActiveRegistryModels(registry) {
  const models = registry.models;
  if (models === undefined || models === null) {
    return;
  }
  if (!isObject(models)) {
    throwMalformed('malformed_trust_artifacts_schema', 'active registry payload models must be an object');
  }
  for (const [modelId, model] of Object.entries(models)) {
    if (typeof modelId !== 'string' || modelId.length === 0) {
      throwMalformed(
        'malformed_trust_artifacts_schema',
        'active registry payload model keys must be non-empty strings',
      );
    }
    if (!isObject(model)) {
      throwMalformed(
        'malformed_trust_artifacts_schema',
        `active registry payload model ${modelId} must be an object`,
      );
    }
    if (model.canonical_model !== modelId) {
      throwMalformed(
        'malformed_trust_artifacts_schema',
        `active registry payload model ${modelId} canonical_model must match model key`,
      );
    }
    const aliases = model.aliases;
    if (
      aliases !== undefined &&
      (!Array.isArray(aliases) || aliases.some((alias) => typeof alias !== 'string' || alias.length === 0))
    ) {
      throwMalformed(
        'malformed_trust_artifacts_schema',
        `active registry payload model ${modelId} aliases must be non-empty strings`,
      );
    }
    const routes = model.routes;
    if (routes === undefined || routes === null) {
      return;
    }
    if (!Array.isArray(routes)) {
      throwMalformed(
        'malformed_trust_artifacts_schema',
        `active registry payload model ${modelId} routes must be a list`,
      );
    }
    routes.forEach((route, routeIndex) => validateActiveRegistryRoute(modelId, routeIndex, route));
  }
}

function validateActiveRegistryRoute(modelId, routeIndex, route) {
  const subject = `active registry payload model ${modelId} route[${routeIndex}]`;
  if (!isObject(route)) {
    throwMalformed('malformed_trust_artifacts_schema', `${subject} must be an object`);
  }
  for (const field of [
    'route_id',
    'provider',
    'provider_model',
    'evidence_family',
    'api_base_url',
    'evidence_endpoint',
    'adapter_version',
  ]) {
    const value = route[field];
    if (typeof value !== 'string' || value.length === 0) {
      throwMalformed('malformed_trust_artifacts_schema', `${subject}.${field} must be a non-empty string`);
    }
  }

  const routeStatus = validateRegistryRouteChoice(
    route,
    subject,
    'route_status',
    REGISTRY_ROUTE_STATUS_VALUES,
  );
  const aliasConfidence = validateRegistryRouteChoice(
    route,
    subject,
    'alias_confidence',
    ALIAS_CONFIDENCE_VALUES,
  );
  validateRegistryRouteChoice(route, subject, 'freshness_class', FRESHNESS_CLASS_VALUES);
  const channelBindingKind = validateRegistryRouteChoice(
    route,
    subject,
    'channel_binding_kind',
    CHANNEL_BINDING_KIND_VALUES,
  );
  const trustTier = validateRegistryRouteChoice(route, subject, 'trust_tier', TRUST_TIER_VALUES);
  validateRegistryRouteChoice(
    route,
    subject,
    'request_confidentiality_requirement',
    POLICY_BOUND_DATA_REQUIREMENT_VALUES,
  );
  validateRegistryRouteChoice(
    route,
    subject,
    'response_confidentiality_requirement',
    POLICY_BOUND_DATA_REQUIREMENT_VALUES,
  );
  validateRegistryRouteChoice(
    route,
    subject,
    'response_integrity_requirement',
    POLICY_RESPONSE_INTEGRITY_REQUIREMENT_VALUES,
  );
  validateRegistryRouteChoice(route, subject, 'request_encryption', REGISTRY_ENCRYPTION_REQUIREMENT_VALUES);
  validateRegistryRouteChoice(route, subject, 'response_decryption', REGISTRY_ENCRYPTION_REQUIREMENT_VALUES);
  validateRegistryRouteChoice(route, subject, 'streaming', REGISTRY_STREAMING_VALUES);

  const acceptedGpuTees = route.accepted_gpu_tees;
  if (
    acceptedGpuTees !== undefined &&
    (!Array.isArray(acceptedGpuTees) ||
      acceptedGpuTees.some((value) => typeof value !== 'string' || !POLICY_GPU_TEE_KINDS.has(value)))
  ) {
    throwMalformed(
      'malformed_trust_artifacts_schema',
      `${subject}.accepted_gpu_tees values must be one of: ${choices(POLICY_GPU_TEE_KINDS)}`,
    );
  }

  if (routeStatus === 'active' && aliasConfidence === 'algorithmic') {
    throwMalformed(
      'malformed_trust_artifacts_schema',
      `${subject}.alias_confidence active routes must not use algorithmic aliases`,
    );
  }
  validateTrustTierChannelBindingPair(trustTier, channelBindingKind, subject);
}

function validateRegistryRouteChoice(route, subject, field, allowed) {
  const value = route[field];
  if (!allowed.has(value)) {
    throwMalformed(
      'malformed_trust_artifacts_schema',
      `${subject}.${field} must be one of: ${choices(allowed)}`,
    );
  }
  return value;
}

function validateActiveReferenceValuesProviders(referenceValues) {
  const providers = referenceValues.providers;
  if (providers === undefined || providers === null) {
    return;
  }
  if (!isObject(providers)) {
    throwMalformed(
      'malformed_trust_artifacts_schema',
      'active reference-values payload providers must be an object',
    );
  }
  for (const [providerId, provider] of Object.entries(providers)) {
    if (typeof providerId !== 'string' || providerId.length === 0) {
      throwMalformed(
        'malformed_trust_artifacts_schema',
        'active reference-values payload provider keys must be non-empty strings',
      );
    }
    const subject = `active reference-values payload provider ${providerId}`;
    if (!isObject(provider)) {
      throwMalformed('malformed_trust_artifacts_schema', `${subject} must be an object`);
    }
    validateNonEmptyStringList(provider.accepted_measurements, subject, 'accepted_measurements');
    const routes = provider.routes;
    if (!isObject(routes)) {
      throwMalformed('malformed_trust_artifacts_schema', `${subject}.routes must be an object`);
    }
    for (const [routeId, route] of Object.entries(routes)) {
      if (typeof routeId !== 'string' || routeId.length === 0) {
        throwMalformed('malformed_trust_artifacts_schema', `${subject}.routes keys must be non-empty strings`);
      }
      validateActiveReferenceValuesRoute(providerId, routeId, route);
    }
  }
}

function validateActiveReferenceValuesRoute(providerId, routeId, route) {
  const subject = `active reference-values payload provider ${providerId} route ${routeId}`;
  if (!isObject(route)) {
    throwMalformed('malformed_trust_artifacts_schema', `${subject} must be an object`);
  }
  for (const field of [
    'canonical_model',
    'provider_model',
    'evidence_family',
    'e2ee_public_key_digest',
    'workload_image_digest',
  ]) {
    validateNonEmptyStringField(route, field, subject);
  }

  const channelBindingKind = validateRegistryRouteChoice(
    route,
    subject,
    'channel_binding_kind',
    CHANNEL_BINDING_KIND_VALUES,
  );
  const trustTier = validateRegistryRouteChoice(route, subject, 'trust_tier', TRUST_TIER_VALUES);
  validateReferenceValuesTeeList(route, subject, 'accepted_cpu_tees', POLICY_CPU_TEE_KINDS);
  if ('accepted_gpu_tees' in route) {
    validateReferenceValuesTeeList(route, subject, 'accepted_gpu_tees', POLICY_GPU_TEE_KINDS);
  }

  for (const field of [
    'e2ee_public_key_digest',
    'response_signing_key_digest',
    'tls_spki_sha256',
    'workload_image_digest',
  ]) {
    if (field in route) {
      validateSha256ReferenceField(route, field, subject);
    }
  }

  const modelArtifacts = route.model_artifacts;
  if (!Array.isArray(modelArtifacts) || modelArtifacts.length === 0) {
    throwMalformed(
      'malformed_trust_artifacts_schema',
      `${subject}.model_artifacts must be a non-empty list`,
    );
  }
  modelArtifacts.forEach((artifact, artifactIndex) => {
    const artifactSubject = `${subject}.model_artifacts[${artifactIndex}]`;
    if (!isObject(artifact)) {
      throwMalformed('malformed_trust_artifacts_schema', `${artifactSubject} must be an object`);
    }
    for (const field of ['kind', 'name']) {
      validateNonEmptyStringField(artifact, field, artifactSubject);
    }
    validateSha256ReferenceField(artifact, 'digest', artifactSubject);
  });

  const parsedValidUntil = parseUtcEpochMs(
    requiredTimestamp(route, 'valid_until', subject, 'malformed_trust_artifacts_schema'),
    `${subject}.valid_until`,
    'malformed_trust_artifacts_schema',
  );
  validateSafeJsonInt(
    route.valid_until_epoch_ms,
    'valid_until_epoch_ms',
    subject,
    'malformed_trust_artifacts_schema',
    'integer millisecond epoch',
  );
  if (route.valid_until_epoch_ms !== parsedValidUntil) {
    throwMalformed(
      'malformed_trust_artifacts_schema',
      `${subject}.valid_until_epoch_ms must match valid_until`,
    );
  }

  validateTrustTierChannelBindingPair(trustTier, channelBindingKind, subject);
}

function validateTrustTierChannelBindingPair(
  trustTier,
  channelBindingKind,
  subject,
  code = 'malformed_trust_artifacts_schema',
) {
  if (trustTier === 'app-e2ee' && channelBindingKind !== 'attested_app_e2ee') {
    throwMalformed(
      code,
      `${subject} trust_tier=app-e2ee requires channel_binding_kind=attested_app_e2ee`,
    );
  }
  if (trustTier === 'hw-verified-tls' && channelBindingKind !== 'tee_terminated_tls') {
    throwMalformed(
      code,
      `${subject} trust_tier=hw-verified-tls requires channel_binding_kind=tee_terminated_tls`,
    );
  }
}

function validateNonEmptyStringField(payload, field, subject) {
  const value = payload[field];
  if (typeof value !== 'string' || value.length === 0) {
    throwMalformed('malformed_trust_artifacts_schema', `${subject}.${field} must be a non-empty string`);
  }
}

function validateNonEmptyStringList(value, subject, field) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((item) => typeof item !== 'string' || item.length === 0)
  ) {
    throwMalformed(
      'malformed_trust_artifacts_schema',
      `${subject}.${field} must be a non-empty list of strings`,
    );
  }
}

function validateReferenceValuesTeeList(route, subject, field, allowed) {
  const values = route[field];
  if (
    !Array.isArray(values) ||
    values.length === 0 ||
    values.some((value) => typeof value !== 'string' || !allowed.has(value))
  ) {
    throwMalformed(
      'malformed_trust_artifacts_schema',
      `${subject}.${field} values must be one of: ${choices(allowed)}`,
    );
  }
}

function validateSha256ReferenceField(payload, field, subject) {
  const value = payload[field];
  if (
    typeof value !== 'string' ||
    !value.startsWith(SHA256_DIGEST_PREFIX) ||
    value.length === SHA256_DIGEST_PREFIX.length
  ) {
    throwMalformed(
      'malformed_trust_artifacts_schema',
      `${subject}.${field} must be a sha256-prefixed reference`,
    );
  }
}

function validateSha256DigestField(payload, field, code, subject) {
  const digest = payload[field];
  if (typeof digest !== 'string' || !SHA256_DIGEST_RE.test(digest)) {
    throwMalformed(code, `${subject} ${field} must be a canonical sha256 digest`);
  }
}

function validateCanonicalPayloadDigest(payload, expectedDigest, field, subject, code) {
  if (canonicalSha256Digest(payload) !== expectedDigest) {
    throwMalformed(code, `${subject} ${field} must match the canonical payload digest`);
  }
}

function validateSignatureFields(payload, fields, code, subject, requireValue = false) {
  for (const field of fields) {
    const signature = payload[field];
    if (!isObject(signature)) {
      throwMalformed(code, `${subject} is missing ${field}`);
    }
    if (typeof signature.signer !== 'string' || signature.signer.length === 0) {
      throwMalformed(code, `${field} metadata is incomplete`);
    }
    if (typeof signature.key_id !== 'string' || signature.key_id.length === 0) {
      throwMalformed(code, `${field} metadata is incomplete`);
    }
    if (signature.alg !== 'ed25519') {
      throwMalformed(code, `${field} uses unsupported signature algorithm ${signature.alg}`);
    }
    if (requireValue) {
      const value = signature.value;
      if (
        typeof value !== 'string' ||
        !value.startsWith(BASE64URL_SIGNATURE_PREFIX) ||
        value.length === BASE64URL_SIGNATURE_PREFIX.length
      ) {
        throwMalformed(code, `${field} signature value is incomplete`);
      }
      decodeBase64urlBytes(value, field, code, ED25519_SIGNATURE_BYTE_LEN);
    }
  }
}

function decodeBase64urlBytes(value, field, code, expectedLength) {
  const encoded = value.startsWith(BASE64URL_SIGNATURE_PREFIX)
    ? value.slice(BASE64URL_SIGNATURE_PREFIX.length)
    : value;
  if (encoded.includes('=') || !BASE64URL_NO_PAD_RE.test(encoded) || encoded.length % 4 === 1) {
    throwMalformed(code, `${field} signature value must be unpadded base64url`);
  }
  const padded = `${encoded}${'='.repeat((4 - (encoded.length % 4)) % 4)}`;
  const decoded = Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (decoded.length !== expectedLength) {
    const label =
      expectedLength === ED25519_SIGNATURE_BYTE_LEN ? 'Ed25519 signature' : 'Ed25519 value';
    throwMalformed(
      code,
      `${field} signature value must decode to a ${expectedLength}-byte ${label}`,
    );
  }
  return decoded;
}

function verifyKnownArtifactSignature(signature, payload, field) {
  const publicKeyBase64url = TRUSTED_ARTIFACT_SIGNING_KEYS.get(
    `${signature.signer}\0${signature.key_id}`,
  );
  if (publicKeyBase64url === undefined) {
    return;
  }

  const signatureBytes = decodeBase64urlBytes(
    signature.value,
    field,
    'malformed_trust_artifacts_signature',
    ED25519_SIGNATURE_BYTE_LEN,
  );
  const publicKeyBytes = decodeBase64urlBytes(
    publicKeyBase64url,
    `${field} trusted public key`,
    'malformed_trust_artifacts_signature',
    ED25519_PUBLIC_KEY_BYTE_LEN,
  );
  const publicKey = crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicKeyBytes]),
    format: 'der',
    type: 'spki',
  });
  if (
    !crypto.verify(
      null,
      Buffer.from(canonicalJson(payload), 'utf8'),
      publicKey,
      signatureBytes,
    )
  ) {
    throwMalformed(
      'malformed_trust_artifacts_signature',
      `${field} signature is invalid`,
    );
  }
}

function validateConfidentialResponse(payload) {
  if (!isObject(payload)) {
    return payload;
  }
  if (!('response' in payload) && !('verdict' in payload)) {
    return payload;
  }
  if (!isObject(payload.verdict)) {
    throwMalformed('malformed_confidential_response', 'confidential response is missing an embedded verdict');
  }
  validateVerdict(payload.verdict);
  validateVerdictMirrors(payload, payload.verdict, 'malformed_confidential_response', 'confidential response');
  return payload;
}

function validateStreamEvent(event) {
  if (!isObject(event)) {
    throwMalformed('malformed_stream_event', 'stream event must be an object');
  }
  if (typeof event.type !== 'string' || !STREAM_EVENT_TYPES.has(event.type)) {
    throwMalformed(
      'malformed_stream_event',
      `stream event type must be one of: ${choices(STREAM_EVENT_TYPES)}`,
    );
  }
  if (event.type === 'response_receipt') {
    return validateStreamReceiptEvent(event);
  }
  if (event.type === 'response') {
    return validateStreamResponseEvent(event);
  }
  if (event.type === 'done' || event.type === 'cancelled' || event.type === 'closed') {
    return validateStreamTerminalEvent(event);
  }
  if (event.type === 'error') {
    return validateStreamErrorEvent(event);
  }
  return validateStreamVerdictEvent(event);
}

function validateStreamVerdictEvent(event) {
  requireExactFields(
    event,
    STREAM_VERDICT_EVENT_FIELDS,
    'stream verdict event',
    'malformed_stream_verdict',
  );
  if (!isObject(event.verdict)) {
    throwMalformed('malformed_stream_verdict', 'stream verdict event is missing an embedded verdict');
  }
  validateVerdict(event.verdict);
  validateVerdictMirrors(event, event.verdict, 'malformed_stream_verdict', 'stream verdict event');
  if (event.response_integrity_result === 'receipt_bound') {
    throwMalformed(
      'malformed_stream_verdict',
      'stream opening verdict must not report receipt-bound response integrity',
    );
  }
  return event;
}

function validateStreamReceiptEvent(event) {
  if (!isObject(event.receipt)) {
    throwMalformed('malformed_stream_receipt', 'response_receipt event is missing receipt metadata');
  }
  requireExactFields(
    event,
    STREAM_RECEIPT_EVENT_FIELDS,
    'response_receipt event',
    'malformed_stream_receipt',
  );
  if (event.response_integrity_result !== 'receipt_bound') {
    throwMalformed(
      'malformed_stream_receipt',
      'response_receipt event must report receipt-bound response integrity',
    );
  }
  if (event.receipt_verified !== true) {
    throwMalformed('malformed_stream_receipt', 'response_receipt event must set receipt_verified=true');
  }
  return event;
}

function validateStreamResponseEvent(event) {
  if (!isObject(event.response)) {
    throwMalformed('malformed_stream_event', 'stream response event must include response object');
  }
  requireExactFields(
    event,
    STREAM_RESPONSE_EVENT_FIELDS,
    'stream response event',
    'malformed_stream_event',
  );
  return event;
}

function validateStreamTerminalEvent(event) {
  requireExactFields(
    event,
    STREAM_TERMINAL_EVENT_FIELDS,
    'stream terminal event',
    'malformed_stream_event',
  );
  return event;
}

function validateStreamErrorEvent(event) {
  requireExactFields(
    event,
    STREAM_ERROR_EVENT_FIELDS,
    'stream error event',
    'malformed_stream_event',
  );
  if (event.status !== 'failed') {
    throwMalformed('malformed_stream_event', 'stream error event status must be failed');
  }
  if (!isObject(event.error)) {
    throwMalformed('malformed_stream_event', 'stream error event must include error metadata');
  }
  validateRequiredString(event.error, 'type', 'stream error event error', 'malformed_stream_event');
  validateRequiredString(event.error, 'message', 'stream error event error', 'malformed_stream_event');
  return event;
}

function validateVerdict(verdict) {
  if (!isObject(verdict)) {
    throwMalformed('malformed_verdict', 'verdict must be a JSON object');
  }
  validateSchemaMajor(
    verdict,
    'schema',
    'confidential-inference.verdict',
    'verdict schema',
    'malformed_verdict_schema',
    'incompatible_verdict_schema',
    'verdict',
  );
  validateSchemaMajor(
    verdict,
    'policy_schema',
    'confidential-inference.policy',
    'policy schema',
    'malformed_verdict_schema',
    'incompatible_verdict_schema',
    'verdict',
  );
  validateSchemaMajor(
    verdict,
    'reference_values_schema',
    'confidential-inference.reference-values',
    'reference-values schema',
    'malformed_verdict_schema',
    'incompatible_verdict_schema',
    'verdict',
  );
  validateSchemaMajor(
    verdict,
    'provider_registry_schema',
    'confidential-inference.provider-registry',
    'provider-registry schema',
    'malformed_verdict_schema',
    'incompatible_verdict_schema',
    'verdict',
  );
  validateRequiredFields(
    verdict,
    VERDICT_KNOWN_FIELDS,
    'malformed_verdict_schema',
    'incompatible_verdict_schema',
    'verdict',
  );
  validateVerdictDigestFields(verdict);
  validateVerdictSignatureFields(verdict);
  validateVerdictValidityFields(verdict);
  validateVerdictEnumFields(verdict);
  validateVerdictStructuredFields(verdict);
  validateVerdictSummaryConsistency(verdict);
  return verdict;
}

function validateVerdictMirrors(payload, verdict, code, subject) {
  for (const field of ['response_channel_bound', 'response_integrity_result']) {
    if (!(field in payload)) {
      throwMalformed(code, `${subject} is missing ${field}`);
    }
    if (!(field in verdict)) {
      throwMalformed(code, `${subject} verdict is missing ${field}`);
    }
    if (payload[field] !== verdict[field]) {
      throwMalformed(code, `${subject} ${field} conflicts with embedded verdict`);
    }
  }
}

function validateRequiredFields(payload, knownFields, errorCode, incompatibleCode, subject) {
  const required = payload.required;
  if (required === undefined) {
    return;
  }
  if (
    !Array.isArray(required) ||
    required.some((field) => typeof field !== 'string' || field.length === 0)
  ) {
    throwMalformed(errorCode, `${subject} required list must contain non-empty field names`);
  }
  for (const field of required) {
    if (!knownFields.has(field)) {
      throwMalformed(incompatibleCode, `${subject} declares unsupported required field ${field}`);
    }
    if (!(field in payload)) {
      throwMalformed(errorCode, `${subject} is missing declared required field ${field}`);
    }
  }
}

function validateVerdictDigestFields(verdict) {
  for (const field of [
    'policy_digest',
    'provider_registry_digest',
    'reference_values_digest',
    'raw_evidence_digest',
    'evidence_digest',
  ]) {
    if (typeof verdict[field] !== 'string' || !SHA256_DIGEST_RE.test(verdict[field])) {
      throwMalformed('malformed_verdict_digest', `verdict ${field} must be a canonical sha256 digest`);
    }
  }
}

function validateVerdictSignatureFields(verdict) {
  for (const field of ['registry_signature', 'reference_values_signature']) {
    const signature = verdict[field];
    if (!isObject(signature)) {
      throwMalformed('malformed_verdict_signature', `verdict is missing ${field}`);
    }
    if (typeof signature.signer !== 'string' || signature.signer.length === 0) {
      throwMalformed('malformed_verdict_signature', `${field} metadata is incomplete`);
    }
    if (typeof signature.key_id !== 'string' || signature.key_id.length === 0) {
      throwMalformed('malformed_verdict_signature', `${field} metadata is incomplete`);
    }
    if (signature.alg !== 'ed25519') {
      throwMalformed(
        'malformed_verdict_signature',
        `${field} uses unsupported signature algorithm ${signature.alg}`,
      );
    }
  }
}

function validateVerdictValidityFields(verdict) {
  if (typeof verdict.expires_at !== 'string') {
    throwMalformed('malformed_verdict_validity', 'verdict is missing expires_at');
  }
  if (!Number.isInteger(verdict.expires_at_epoch_ms) || verdict.expires_at_epoch_ms < 0) {
    throwMalformed('malformed_verdict_validity', 'verdict is missing expires_at_epoch_ms');
  }
  if (!Number.isSafeInteger(verdict.expires_at_epoch_ms)) {
    throwMalformed(
      'malformed_verdict_validity',
      'verdict expires_at_epoch_ms exceeds the cross-language JSON safe integer limit',
    );
  }
  if (!isObject(verdict.validity)) {
    throwMalformed('malformed_verdict_validity', 'verdict is missing validity');
  }
  const computedExpiresAt = requiredTimestamp(verdict.validity, 'computed_expires_at', 'validity');
  if (verdict.expires_at !== computedExpiresAt) {
    throwMalformed(
      'malformed_verdict_validity',
      'expires_at must match validity.computed_expires_at',
    );
  }
  const expiresAtEpochMs = parseUtcEpochMs(verdict.expires_at, 'expires_at');
  if (expiresAtEpochMs !== verdict.expires_at_epoch_ms) {
    throwMalformed('malformed_verdict_validity', 'expires_at_epoch_ms must match expires_at');
  }
  const minimumBound = Math.min(
    ...VERDICT_VALIDITY_FIELDS
      .filter((field) => field !== 'computed_expires_at')
      .map((field) => parseUtcEpochMs(requiredTimestamp(verdict.validity, field, 'validity'), `validity.${field}`)),
  );
  if (minimumBound !== expiresAtEpochMs) {
    throwMalformed(
      'malformed_verdict_validity',
      'validity.computed_expires_at must be the minimum validity bound',
    );
  }
}

function validateVerdictEnumFields(verdict) {
  validateEnumField(verdict, 'status', VERIFICATION_STATUS_VALUES);
  validateEnumField(verdict, 'enforcement', ENFORCEMENT_VALUES);
  validateEnumField(verdict, 'trust_tier', TRUST_TIER_VALUES);
  validateEnumField(verdict, 'channel_binding_kind', CHANNEL_BINDING_KIND_VALUES);
  validateEnumField(verdict, 'model_binding_result', MODEL_BINDING_RESULT_VALUES);
  validateEnumField(verdict, 'request_confidentiality_result', CONFIDENTIALITY_RESULT_VALUES);
  validateEnumField(verdict, 'response_confidentiality_result', CONFIDENTIALITY_RESULT_VALUES);
  validateEnumField(verdict, 'response_integrity_result', RESPONSE_INTEGRITY_RESULT_VALUES);
  validateBoolField(verdict, 'request_channel_bound');
  validateBoolField(verdict, 'response_channel_bound');
  validateBoolField(verdict, 'request_allowed');
  validateBoolField(verdict, 'would_block_under_enforce');

  const checks = verdict.checks;
  if (checks == null) {
    return;
  }
  if (!isObject(checks)) {
    throwMalformed('malformed_verdict_enum', 'verdict checks must be an object');
  }
  for (const [checkName, checkResult] of Object.entries(checks)) {
    if (typeof checkName !== 'string' || typeof checkResult !== 'string') {
      throwMalformed('malformed_verdict_enum', 'verdict checks must map string names to string results');
    }
    if (!CHECK_RESULT_VALUES.has(checkResult)) {
      throwMalformed(
        'malformed_verdict_enum',
        `verdict check ${checkName} has invalid result ${checkResult}`,
      );
    }
  }
}

function validateVerdictStructuredFields(verdict) {
  const outcomes = verdict.check_outcomes;
  if (outcomes !== undefined) {
    if (!isObject(outcomes) || !isObject(verdict.checks)) {
      throwMalformed(
        'malformed_verdict_checks',
        'verdict check_outcomes and checks must both be objects',
      );
    }
    const checkNames = Object.keys(verdict.checks).sort();
    const outcomeNames = Object.keys(outcomes).sort();
    if (JSON.stringify(checkNames) !== JSON.stringify(outcomeNames)) {
      throwMalformed(
        'malformed_verdict_checks',
        'check_outcomes must contain exactly the legacy check keys',
      );
    }
    for (const name of checkNames) {
      const outcome = outcomes[name];
      if (!isObject(outcome) || outcome.state !== verdict.checks[name]) {
        throwMalformed(
          'malformed_verdict_checks',
          `check_outcomes.${name}.state conflicts with checks.${name}`,
        );
      }
      if (typeof outcome.required !== 'boolean') {
        throwMalformed(
          'malformed_verdict_checks',
          `check_outcomes.${name}.required must be a boolean`,
        );
      }
      if (typeof outcome.detail !== 'string' || outcome.detail.trim().length === 0) {
        throwMalformed(
          'malformed_verdict_checks',
          `check_outcomes.${name}.detail must not be empty`,
        );
      }
      if (outcome.required && outcome.state === 'not_applicable') {
        throwMalformed(
          'malformed_verdict_checks',
          `required check_outcomes.${name} cannot be not_applicable`,
        );
      }
      validateVerdictEvidenceRefs(
        outcome.evidence_refs ?? [],
        `check_outcomes.${name}.evidence_refs`,
      );
    }
  }

  const attribution = verdict.route_attribution;
  if (attribution === undefined) {
    return;
  }
  if (!isObject(attribution) || !Array.isArray(attribution.parties)) {
    throwMalformed(
      'malformed_verdict_attribution',
      'route_attribution.parties must be an array',
    );
  }
  if (attribution.parties.length !== ROUTE_PARTY_ROLES.size) {
    throwMalformed(
      'malformed_verdict_attribution',
      'route_attribution must explicitly cover every route-party role',
    );
  }
  const seenRoles = new Set();
  for (const party of attribution.parties) {
    if (!isObject(party) || !ROUTE_PARTY_ROLES.has(party.role) || seenRoles.has(party.role)) {
      throwMalformed(
        'malformed_verdict_attribution',
        'route_attribution roles are missing or duplicated',
      );
    }
    seenRoles.add(party.role);
    if (!ATTRIBUTION_SOURCES.has(party.source)) {
      throwMalformed(
        'malformed_verdict_attribution',
        `route_attribution ${party.role} has an invalid source`,
      );
    }
    if (typeof party.detail !== 'string' || party.detail.trim().length === 0) {
      throwMalformed(
        'malformed_verdict_attribution',
        `route_attribution ${party.role} detail must not be empty`,
      );
    }
    if (party.source === 'unknown') {
      if (party.party_id !== undefined && party.party_id !== null) {
        throwMalformed(
          'malformed_verdict_attribution',
          `route_attribution ${party.role} cannot name a party from an unknown source`,
        );
      }
    } else if (typeof party.party_id !== 'string' || party.party_id.trim().length === 0) {
      throwMalformed(
        'malformed_verdict_attribution',
        `route_attribution ${party.role} requires a non-empty party_id`,
      );
    }
    validateVerdictEvidenceRefs(
      party.evidence_refs ?? [],
      `route_attribution.${party.role}.evidence_refs`,
    );
  }
  const provider = attribution.parties.find((party) => party.role === 'inference_provider');
  if (provider.party_id !== verdict.provider || provider.source !== 'signed_registry') {
    throwMalformed(
      'malformed_verdict_attribution',
      'inference-provider attribution must match the signed registry provider',
    );
  }
}

function validateVerdictEvidenceRefs(refs, subject) {
  if (!Array.isArray(refs) || refs.some((ref) => typeof ref !== 'string')) {
    throwMalformed('malformed_verdict_evidence_refs', `${subject} must be a string array`);
  }
  const canonical = [...new Set(refs)].sort();
  if (JSON.stringify(canonical) !== JSON.stringify(refs)) {
    throwMalformed(
      'malformed_verdict_evidence_refs',
      `${subject} must be sorted and unique`,
    );
  }
  const unsupported = refs.find((ref) => !VERDICT_EVIDENCE_REFS.has(ref));
  if (unsupported !== undefined) {
    throwMalformed(
      'malformed_verdict_evidence_refs',
      `${subject} contains unsupported evidence reference ${unsupported}`,
    );
  }
}

function validateVerdictSummaryConsistency(verdict) {
  const checks = verdict.checks;
  if (!isObject(checks)) {
    return;
  }

  if (verdict.model_binding_result === 'verified' && checks.model_binding !== 'verified') {
    throwMalformed(
      'malformed_verdict_summary',
      'model_binding_result=verified but model_binding check is not verified',
    );
  }

  if (['channel_bound', 'encrypted_bound'].includes(verdict.request_confidentiality_result)) {
    if (verdict.request_channel_bound !== true) {
      throwMalformed(
        'malformed_verdict_summary',
        'bound request_confidentiality_result conflicts with request_channel_bound=false',
      );
    }
    requireCheckVerified(checks, 'request_key_binding', 'bound request_confidentiality_result');
    requireCheckVerified(checks, 'request_encryption', 'bound request_confidentiality_result');
  }

  if (
    verdict.request_channel_bound === true &&
    !['channel_bound', 'encrypted_bound'].includes(verdict.request_confidentiality_result)
  ) {
    throwMalformed(
      'malformed_verdict_summary',
      'request_channel_bound conflicts with request_confidentiality_result',
    );
  }

  if (['channel_bound', 'encrypted_bound'].includes(verdict.response_confidentiality_result)) {
    if (verdict.response_channel_bound !== true) {
      throwMalformed(
        'malformed_verdict_summary',
        'bound response_confidentiality_result conflicts with response_channel_bound=false',
      );
    }
    requireCheckVerified(checks, 'response_key_binding', 'bound response_confidentiality_result');
    requireCheckVerified(checks, 'response_encryption', 'bound response_confidentiality_result');
  }

  if (
    verdict.response_channel_bound === true &&
    !['channel_bound', 'encrypted_bound'].includes(verdict.response_confidentiality_result)
  ) {
    throwMalformed(
      'malformed_verdict_summary',
      'response_channel_bound conflicts with response_confidentiality_result',
    );
  }

  if (verdict.response_channel_bound === true && verdict.response_integrity_result !== 'channel_bound') {
    throwMalformed(
      'malformed_verdict_summary',
      'response channel binding must mirror channel-bound response integrity',
    );
  }

  if (verdict.response_integrity_result === 'channel_bound') {
    if (verdict.response_channel_bound !== true) {
      throwMalformed(
        'malformed_verdict_summary',
        'channel-bound response integrity conflicts with response_channel_bound=false',
      );
    }
    requireCheckVerified(checks, 'response_channel_binding', 'channel-bound response_integrity_result');
  } else if (verdict.response_integrity_result === 'receipt_bound') {
    requireCheckVerified(checks, 'response_receipt', 'receipt-bound response_integrity_result');
  }

  if (verdict.status === 'verified') {
    validateVerifiedTrustTierSummary(verdict, checks);
  }

  const hasFailedCheck = Object.values(checks).some((check) => check === 'failed');
  if (hasFailedCheck && verdict.would_block_under_enforce !== true) {
    throwMalformed(
      'malformed_verdict_summary',
      'failed checks conflict with would_block_under_enforce=false',
    );
  }
  if (!hasFailedCheck && verdict.would_block_under_enforce === true) {
    throwMalformed(
      'malformed_verdict_summary',
      'would_block_under_enforce=true but no check is failed',
    );
  }

  if (verdict.status === 'disabled' && verdict.enforcement !== 'disabled') {
    throwMalformed('malformed_verdict_summary', 'status=disabled requires disabled enforcement');
  }

  if (verdict.enforcement === 'enforce') {
    if (verdict.would_block_under_enforce === true && verdict.request_allowed === true) {
      throwMalformed('malformed_verdict_summary', 'enforce verdict would block but request_allowed=true');
    }
    if (verdict.would_block_under_enforce === false && verdict.request_allowed === false) {
      throwMalformed('malformed_verdict_summary', 'enforce verdict allows policy but request_allowed=false');
    }
  } else if (['observe', 'disabled'].includes(verdict.enforcement) && verdict.request_allowed === false) {
    throwMalformed('malformed_verdict_summary', 'non-enforcing verdict must not set request_allowed=false');
  }

  if (verdict.enforcement === 'disabled' && verdict.status !== 'disabled') {
    throwMalformed('malformed_verdict_summary', 'disabled enforcement must emit status=disabled');
  }

  if (verdict.status === 'verified') {
    if (hasFailedCheck) {
      throwMalformed('malformed_verdict_summary', 'status=verified but at least one check is failed');
    }
    if (Array.isArray(verdict.errors) && verdict.errors.length > 0) {
      throwMalformed('malformed_verdict_summary', 'status=verified but verdict contains errors');
    }
    if (verdict.request_allowed === false) {
      throwMalformed('malformed_verdict_summary', 'status=verified conflicts with request_allowed=false');
    }
    if (verdict.would_block_under_enforce === true) {
      throwMalformed('malformed_verdict_summary', 'status=verified conflicts with would_block_under_enforce=true');
    }
  }
}

function validateVerifiedTrustTierSummary(verdict, checks) {
  if (verdict.trust_tier === 'app-e2ee') {
    if (verdict.channel_binding_kind !== 'attested_app_e2ee') {
      throwMalformed(
        'malformed_verdict_summary',
        'trust_tier=app-e2ee requires channel_binding_kind=attested_app_e2ee',
      );
    }
    if (verdict.request_channel_bound !== true || verdict.response_channel_bound !== true) {
      throwMalformed(
        'malformed_verdict_summary',
        'trust_tier=app-e2ee requires request and response channel binding',
      );
    }
  } else if (verdict.trust_tier === 'hw-verified-tls') {
    if (verdict.channel_binding_kind !== 'tee_terminated_tls') {
      throwMalformed(
        'malformed_verdict_summary',
        'trust_tier=hw-verified-tls requires channel_binding_kind=tee_terminated_tls',
      );
    }
    requireCheckVerified(checks, 'tls_binding', 'trust_tier=hw-verified-tls');
    if (
      verdict.request_confidentiality_result !== 'channel_bound' ||
      verdict.response_confidentiality_result !== 'channel_bound'
    ) {
      throwMalformed(
        'malformed_verdict_summary',
        'trust_tier=hw-verified-tls requires channel-bound request and response confidentiality',
      );
    }
  } else if (verdict.trust_tier === 'tee-only') {
    if (verdict.response_channel_bound === true) {
      throwMalformed(
        'malformed_verdict_summary',
        'trust_tier=tee-only must not report response_channel_bound=true',
      );
    }
  } else if (
    verdict.trust_tier === 'none' &&
    (verdict.request_channel_bound === true ||
      verdict.response_channel_bound === true ||
      ['channel_bound', 'receipt_bound'].includes(verdict.response_integrity_result) ||
      ['channel_bound', 'encrypted_bound'].includes(verdict.request_confidentiality_result) ||
      ['channel_bound', 'encrypted_bound'].includes(verdict.response_confidentiality_result))
  ) {
    throwMalformed(
      'malformed_verdict_summary',
      'trust_tier=none conflicts with bound channel or response integrity summaries',
    );
  }
}

function validateEnumField(payload, field, allowedValues) {
  const value = payload[field];
  if (typeof value !== 'string') {
    throwMalformed('malformed_verdict_enum', `verdict is missing ${field}`);
  }
  if (!allowedValues.has(value)) {
    throwMalformed('malformed_verdict_enum', `verdict field ${field} has invalid value ${value}`);
  }
}

function validateBoolField(payload, field) {
  if (typeof payload[field] !== 'boolean') {
    throwMalformed('malformed_verdict_enum', `verdict is missing ${field}`);
  }
}

function requireCheckVerified(checks, checkName, summary) {
  if (checks[checkName] !== 'verified') {
    throwMalformed(
      'malformed_verdict_summary',
      `${summary} requires ${checkName} check to be verified`,
    );
  }
}

function requiredTimestamp(payload, field, subject, code = 'malformed_verdict_validity') {
  const value = payload[field];
  if (typeof value !== 'string') {
    throwMalformed(code, `${subject} is missing ${field}`);
  }
  return value;
}

function parseUtcEpochMs(value, subject, code = 'malformed_verdict_validity') {
  const match = UTC_TIMESTAMP_RE.exec(value);
  if (!match) {
    throwMalformed(
      code,
      `${subject} must be a canonical UTC RFC3339 timestamp`,
    );
  }
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, millisText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const millis = millisText === undefined ? 0 : Number(millisText);
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, millis);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second ||
    date.getUTCMilliseconds() !== millis
  ) {
    throwMalformed(code, `${subject} must be a valid UTC timestamp`);
  }
  const epochMs = date.getTime();
  if (!Number.isSafeInteger(epochMs) || epochMs < 0) {
    throwMalformed(
      code,
      `${subject} exceeds the cross-language JSON safe integer limit`,
    );
  }
  return epochMs;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function throwMalformed(code, message) {
  throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, { code, message });
}

function status(options = {}) {
  const libraryPath = typeof options === 'string' ? options : options.libraryPath;
  const native = new Native(libraryPath);
  return native.status();
}

module.exports = {
  Client,
  Operation,
  Stream,
  ConfidentialInferenceError,
  canonicalJson,
  canonicalSha256Digest,
  policyCanonicalJson,
  policyDigest,
  status,
  validateActivePolicySnapshot,
  validateActiveTrustArtifacts,
  validateConfidentialResponse,
  validateConfidentialModels,
  validateFfiErrorEnvelope,
  validateFfiStatus,
  validateModelList,
  validateOperationState,
  validateStreamEvent,
  validateVerdict,
  MAX_SAFE_JSON_INT,
  CONFIDENTIAL_INFERENCE_FFI_OK,
  CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
  CONFIDENTIAL_INFERENCE_FFI_PANIC,
  CONFIDENTIAL_INFERENCE_FFI_BUSY,
  CONFIDENTIAL_INFERENCE_FFI_PENDING,
  CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED,
  CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
};
