export type JsonObject = Record<string, unknown>;

export type ClientOptions = {
  libraryPath?: string;
};

export type WaitOptions = {
  timeoutMs?: number;
  pollIntervalMs?: number;
  signal?: AbortSignalLike;
};

export type AbortSignalLike = {
  readonly aborted: boolean;
  readonly reason?: unknown;
  addEventListener(type: 'abort', listener: () => void, options?: { once?: boolean }): void;
  removeEventListener(type: 'abort', listener: () => void): void;
};

export class ConfidentialInferenceError extends Error {
  status: number;
  error: JsonObject | null;
}

export class Client {
  constructor(config?: JsonObject | null, options?: ClientOptions | string);
  status(): JsonObject;
  close(): void;
  chat(request: JsonObject, options?: WaitOptions | number): JsonObject;
  createResponse(request: JsonObject, options?: WaitOptions | number): JsonObject;
  response(request: JsonObject, options?: WaitOptions | number): JsonObject;
  verify(provider: string, model: string, options?: WaitOptions | number): JsonObject;
  models(): JsonObject;
  confidentialModels(): JsonObject[];
  confidentiality(): JsonObject[];
  activePolicy(): JsonObject;
  activeTrustArtifacts(): JsonObject;
  startChat(request: JsonObject): Operation;
  startResponse(request: JsonObject): Operation;
  startVerify(provider: string, model: string): Operation;
  startStream(request: JsonObject): Stream;
  chatAsync(request: JsonObject, options?: WaitOptions): Promise<JsonObject>;
  createResponseAsync(request: JsonObject, options?: WaitOptions): Promise<JsonObject>;
  responseAsync(request: JsonObject, options?: WaitOptions): Promise<JsonObject>;
  verifyAsync(provider: string, model: string, options?: WaitOptions): Promise<JsonObject>;
  streamAsync(request: JsonObject, options?: WaitOptions): AsyncIterable<JsonObject>;
}

export class Operation {
  poll(): JsonObject;
  result(): JsonObject;
  wait(options?: WaitOptions): Promise<JsonObject>;
  cancel(): void;
  setCallback(callback: (() => void) | null): void;
  readinessFd(): number;
  close(): void;
}

export class Stream {
  next(options?: WaitOptions | number): JsonObject;
  events(options?: WaitOptions): AsyncIterable<JsonObject>;
  cancel(): void;
  setCallback(callback: (() => void) | null): void;
  readinessFd(): number;
  close(): void;
}

export function canonicalJson(value: unknown): string;
export function canonicalSha256Digest(value: unknown): string;
export function policyCanonicalJson(policy: JsonObject): string;
export function policyDigest(policy: JsonObject): string;
export function status(options?: ClientOptions | string): JsonObject;
export function validateActivePolicySnapshot(snapshot: unknown): unknown;
export function validateActiveTrustArtifacts(artifacts: unknown): unknown;
export function validateConfidentialResponse(payload: unknown): unknown;
export function validateConfidentialModels(payload: unknown): unknown;
export function validateFfiErrorEnvelope(payload: unknown): unknown;
export function validateFfiStatus(payload: unknown): unknown;
export function validateModelList(payload: unknown): unknown;
export function validateOperationState(state: unknown): unknown;
export function validateStreamEvent(event: unknown): unknown;
export function validateVerdict(verdict: unknown): unknown;

export const MAX_SAFE_JSON_INT: number;
export const CONFIDENTIAL_INFERENCE_FFI_OK: 0;
export const CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT: 1;
export const CONFIDENTIAL_INFERENCE_FFI_PANIC: 2;
export const CONFIDENTIAL_INFERENCE_FFI_BUSY: 3;
export const CONFIDENTIAL_INFERENCE_FFI_PENDING: 4;
export const CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED: 5;
export const CONFIDENTIAL_INFERENCE_FFI_INTERNAL: 6;
