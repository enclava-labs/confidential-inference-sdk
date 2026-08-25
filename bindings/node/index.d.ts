export type JsonObject = Record<string, unknown>;

export type ClientOptions = {
  libraryPath?: string;
};

export type StreamOptions = {
  timeoutMs?: number;
  pollIntervalMs?: number;
};

export type StreamEvent = JsonObject & { type?: string };

export class ConfidentialInferenceError extends Error {
  status: number;
  error: JsonObject;
}

/**
 * Thin wrapper over the Confidential Inference SDK C ABI.
 *
 * Rust owns every attestation/policy/registry/digest/signature decision; the
 * binding only marshals JSON across the ABI and applies minimal shape checks.
 * Inference methods run the blocking FFI call on a Koffi worker thread, so
 * they never block the Node event loop.
 */
export class Client {
  constructor(config?: JsonObject | null, options?: ClientOptions | string);
  status(): JsonObject;
  close(): void;
  chat(request: JsonObject, timeoutMs?: number): Promise<JsonObject>;
  createResponse(request: JsonObject, timeoutMs?: number): Promise<JsonObject>;
  response(request: JsonObject, timeoutMs?: number): Promise<JsonObject>;
  verify(provider: string, model: string, timeoutMs?: number): Promise<JsonObject>;
  models(): Promise<JsonObject>;
  confidentialModels(): Promise<JsonObject[]>;
  confidentiality(): Promise<JsonObject[]>;
  activePolicy(): Promise<JsonObject>;
  activeTrustArtifacts(): Promise<JsonObject>;
  startStream(request: JsonObject): Stream;
  stream(request: JsonObject, options?: StreamOptions): AsyncIterableIterator<StreamEvent>;
}

export class Stream {
  /**
   * Blocking variant: waits up to `timeoutMs` for the next stream event and
   * returns `null` when none is ready. Use the async iterator (or
   * `Client.stream`) to avoid blocking the event loop.
   */
  next(timeoutMs?: number): StreamEvent | null;
  cancel(): void;
  close(): void;
  [Symbol.asyncIterator](options?: StreamOptions): AsyncIterableIterator<StreamEvent>;
}

export function status(options?: ClientOptions | string): JsonObject;

export const CONFIDENTIAL_INFERENCE_FFI_OK: 0;
export const CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT: 1;
export const CONFIDENTIAL_INFERENCE_FFI_PANIC: 2;
export const CONFIDENTIAL_INFERENCE_FFI_BUSY: 3;
export const CONFIDENTIAL_INFERENCE_FFI_PENDING: 4;
export const CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED: 5;
export const CONFIDENTIAL_INFERENCE_FFI_INTERNAL: 6;
