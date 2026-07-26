'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {
  Client,
  ConfidentialInferenceError,
  CONFIDENTIAL_INFERENCE_FFI_PENDING,
  CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED,
  MAX_SAFE_JSON_INT,
  canonicalJson,
  canonicalSha256Digest,
  status: ffiStatus,
  policyCanonicalJson,
  policyDigest,
  validateActivePolicySnapshot,
  validateActiveTrustArtifacts,
  validateConfidentialModels,
  validateConfidentialResponse,
  validateFfiErrorEnvelope,
  validateFfiStatus,
  validateModelList,
  validateOperationState,
  validateStreamEvent,
  validateVerdict,
} = require('../index.js');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const VALID_DIGEST = `sha256:${'0'.repeat(64)}`;
const VALID_REGISTRY_SIGNATURE_VALUE =
  'base64url:Xwtv2PpYiarqO1ZLC2s_n0b5Cu1-gJyUCnnkHspDlI_sU_uk_WorpQGUN4VvldAz4S0--E0d4_3GN0L3VowrBg';
const VALID_REFERENCE_VALUES_SIGNATURE_VALUE =
  'base64url:ULskkFC98v_FXOt4lBLINcrVnPoMjMOd_Aj4NpvMaqiBxcU-O9ydZ3JgxxBWmnA74vPoKQEgNcmvRmxJJc5nAA';

function chatRequest(content, extra = {}) {
  return {
    model: 'gpt-oss-120b',
    messages: [{ role: 'user', content }],
    ...extra,
  };
}

async function waitFor(predicate, timeoutMs = 250) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function validVerdictStub(overrides = {}) {
  return {
    schema: 'confidential-inference.verdict.v1',
    policy_schema: 'confidential-inference.policy.v1',
    reference_values_schema: 'confidential-inference.reference-values.v1',
    provider_registry_schema: 'confidential-inference.provider-registry.v1',
    status: 'verified',
    enforcement: 'enforce',
    request_allowed: true,
    would_block_under_enforce: false,
    trust_tier: 'app-e2ee',
    channel_binding_kind: 'attested_app_e2ee',
    model_binding_result: 'verified',
    request_channel_bound: true,
    request_confidentiality_result: 'encrypted_bound',
    response_confidentiality_result: 'encrypted_bound',
    response_channel_bound: true,
    response_integrity_result: 'channel_bound',
    policy_digest: VALID_DIGEST,
    provider_registry_digest: VALID_DIGEST,
    registry_signature: {
      signer: 'confidential-inference',
      key_id: 'confidential-inference-demo-ed25519-2026',
      alg: 'ed25519',
    },
    reference_values_digest: VALID_DIGEST,
    reference_values_signature: {
      signer: 'confidential-inference',
      key_id: 'confidential-inference-demo-ed25519-2026',
      alg: 'ed25519',
    },
    raw_evidence_digest: VALID_DIGEST,
    evidence_digest: VALID_DIGEST,
    expires_at: '2099-01-01T00:00:00Z',
    expires_at_epoch_ms: 4070908800000,
    validity: {
      policy_ttl_until: '2099-01-01T00:00:00Z',
      collateral_valid_until: '2099-01-01T00:00:00Z',
      certificate_valid_until: '2099-01-01T00:00:00Z',
      quote_valid_until: '2099-01-01T00:00:00Z',
      tcb_valid_until: '2099-01-01T00:00:00Z',
      reference_values_valid_until: '2099-01-01T00:00:00Z',
      computed_expires_at: '2099-01-01T00:00:00Z',
    },
    checks: {
      model_binding: 'verified',
      request_key_binding: 'verified',
      request_encryption: 'verified',
      response_key_binding: 'verified',
      response_encryption: 'verified',
      response_channel_binding: 'verified',
      response_receipt: 'not_applicable',
    },
    errors: [],
    ...overrides,
  };
}

function canonicalDigestOrPlaceholder(payload) {
  try {
    return canonicalSha256Digest(payload);
  } catch (_) {
    return VALID_DIGEST;
  }
}

function validActivePolicySnapshotStub(policyOverrides = {}) {
  const policy = {
    schema: 'confidential-inference.policy.v1',
    enforcement: 'enforce',
    hardware: {
      cpu: { mode: 'any_cpu_tee' },
      gpu: { mode: 'not_required' },
    },
    channel_binding_requirement: 'attested_app_e2ee',
    request_confidentiality_requirement: 'bound_to_attested_workload',
    response_confidentiality_requirement: 'bound_to_attested_workload',
    response_integrity_requirement: 'any_bound',
    model_binding_requirement: 'if_provider_supports',
    provenance: {
      workload_image: false,
      model_artifacts: false,
      reproducible_build: false,
      source_attestation: false,
      dependency_sbom: false,
    },
    freshness: { mode: 'per_session' },
    stale_verdicts: { mode: 'fail_closed' },
    verdict_ttl_millis: 600000,
    provider_registry_digest: VALID_DIGEST,
    reference_values_digest: VALID_DIGEST,
    ...policyOverrides,
  };
  return {
    schema: 'confidential-inference.active-policy.v1',
    policy,
    policy_digest: canonicalDigestOrPlaceholder(policy),
  };
}

function validTrustArtifactsStub(overrides = {}) {
  const artifacts = {
    registry: { schema: 'confidential-inference.provider-registry.v1' },
    reference_values: { schema: 'confidential-inference.reference-values.v1' },
    registry_signature: {
      signer: 'confidential-inference-binding-test',
      key_id: 'binding-test-ed25519-2026',
      alg: 'ed25519',
      value: VALID_REGISTRY_SIGNATURE_VALUE,
    },
    reference_values_signature: {
      signer: 'confidential-inference-binding-test',
      key_id: 'binding-test-ed25519-2026',
      alg: 'ed25519',
      value: VALID_REFERENCE_VALUES_SIGNATURE_VALUE,
    },
    ...overrides,
  };
  if (!Object.hasOwn(overrides, 'registry_digest')) {
    artifacts.registry_digest = canonicalDigestOrPlaceholder(artifacts.registry);
  }
  if (!Object.hasOwn(overrides, 'reference_values_digest')) {
    artifacts.reference_values_digest = canonicalDigestOrPlaceholder(artifacts.reference_values);
  }
  return artifacts;
}

function validRegistryPayloadWithRoute(routeOverrides = {}) {
  const route = {
    route_id: 'demo:gpt-oss-120b:e2ee-gpt-oss-120b-p',
    provider: 'demo',
    provider_model: 'e2ee-gpt-oss-120b-p',
    evidence_family: 'demo-app-e2ee',
    api_base_url: 'https://demo.invalid/v1',
    evidence_endpoint: 'https://demo.invalid/evidence',
    adapter_version: '2026-07-05-demo',
    route_status: 'active',
    alias_confidence: 'curated',
    freshness_class: 'per_session',
    channel_binding_kind: 'attested_app_e2ee',
    trust_tier: 'app-e2ee',
    request_confidentiality_requirement: 'bound_to_attested_workload',
    response_confidentiality_requirement: 'bound_to_attested_workload',
    response_integrity_requirement: 'any_bound',
    request_encryption: 'required',
    response_decryption: 'required',
    streaming: 'unsupported',
    accepted_gpu_tees: ['nvidia_cc'],
    ...routeOverrides,
  };
  return {
    schema: 'confidential-inference.provider-registry.v1',
    models: {
      'gpt-oss-120b': {
        canonical_model: 'gpt-oss-120b',
        aliases: ['gpt-oss-120b'],
        routes: [route],
      },
    },
  };
}

function validReferenceValuesPayloadWithRoute(routeOverrides = {}) {
  const route = {
    canonical_model: 'gpt-oss-120b',
    provider_model: 'e2ee-gpt-oss-120b-p',
    evidence_family: 'demo-app-e2ee',
    e2ee_public_key_digest: VALID_DIGEST,
    workload_image_digest: VALID_DIGEST,
    channel_binding_kind: 'attested_app_e2ee',
    trust_tier: 'app-e2ee',
    accepted_cpu_tees: ['tdx'],
    accepted_gpu_tees: ['nvidia_cc'],
    model_artifacts: [{ kind: 'weights', name: 'gpt-oss-120b', digest: VALID_DIGEST }],
    valid_until: '2099-01-01T00:00:00Z',
    valid_until_epoch_ms: 4070908800000,
    ...routeOverrides,
  };
  return {
    schema: 'confidential-inference.reference-values.v1',
    providers: {
      demo: {
        accepted_measurements: [VALID_DIGEST],
        routes: {
          'demo:gpt-oss-120b:e2ee-gpt-oss-120b-p': route,
        },
      },
    },
  };
}

function assertValidationError(fn, code, messagePattern) {
  assert.throws(fn, (error) => {
    assert.ok(error instanceof ConfidentialInferenceError);
    assert.equal(error.error.code, code);
    if (messagePattern) {
      assert.match(error.error.message, messagePattern);
    }
    return true;
  });
}

test('FFI status helper reports loaded SDK capabilities', () => {
  const moduleStatus = ffiStatus();
  assert.equal(validateFfiStatus(moduleStatus), moduleStatus);
  assert.equal(moduleStatus.async_handle_abi_available, true);
  assert.equal(moduleStatus.callbacks_available, true);
  assert.equal(moduleStatus.stream_handle_abi_available, true);
  assert.equal(moduleStatus.blocking_helpers_available, true);
  assert.equal(typeof moduleStatus.readiness_fd_available, 'boolean');
  assert.match(moduleStatus.reason, /chat, responses, verify/);

  const client = new Client();
  try {
    const clientStatus = client.status();
    assert.deepEqual(clientStatus, moduleStatus);
  } finally {
    client.close();
  }
});

test('FFI status validator rejects malformed capability payloads', () => {
  const valid = {
    async_handle_abi_available: true,
    callbacks_available: true,
    readiness_fd_available: process.platform !== 'win32',
    stream_handle_abi_available: true,
    blocking_helpers_available: true,
    reason: 'capabilities available',
  };
  assert.equal(validateFfiStatus(valid), valid);

  assertValidationError(
    () => validateFfiStatus({ ...valid, reason: '' }),
    'malformed_ffi_status',
    /reason/,
  );
  assertValidationError(
    () => validateFfiStatus({ ...valid, callbacks_available: 'yes' }),
    'malformed_ffi_status',
    /callbacks_available/,
  );
  assertValidationError(
    () => validateFfiStatus({ ...valid, extra: true }),
    'malformed_ffi_status',
    /unsupported field extra/,
  );
});

test('blocking chat delegates to Rust SDK and validates verdict mirrors', () => {
  const prompt = 'node binding path';
  const client = new Client();
  try {
    const response = client.chat(chatRequest(prompt), { timeoutMs: 2000 });
    assert.equal(response.provider, 'demo');
    assert.equal(response.provider_model, 'e2ee-gpt-oss-120b-p');
    assert.equal(response.verdict.status, 'verified');
    assert.equal(response.response_channel_bound, response.verdict.response_channel_bound);
    assert.equal(response.response_integrity_result, response.verdict.response_integrity_result);
    assert.equal(
      response.response.choices[0].message.content,
      `demo confidential response for e2ee-gpt-oss-120b-p: ${prompt}`,
    );
    assert.equal(JSON.stringify(response.verdict).includes(prompt), false);
  } finally {
    client.close();
  }
});

test('Promise verify helper uses operation handle path', async () => {
  const client = new Client();
  try {
    const verdict = await client.verifyAsync('demo', 'gpt-oss-120b', { timeoutMs: 2000 });
    assert.equal(verdict.status, 'verified');
    assert.equal(verdict.route_id, 'demo:gpt-oss-120b:e2ee-gpt-oss-120b-p');
  } finally {
    client.close();
  }
});

test('operation callback fires at terminal state', async () => {
  const client = new Client();
  const operation = client.startVerify('demo', 'gpt-oss-120b');
  let callbackCount = 0;
  try {
    operation.setCallback(() => {
      callbackCount += 1;
    });
    const verdict = await operation.wait({ timeoutMs: 2000 });
    await waitFor(() => callbackCount === 1);
    assert.equal(verdict.status, 'verified');
    assert.equal(callbackCount, 1);
  } finally {
    operation.close();
    client.close();
  }
});

test('operation poll validates Rust state JSON', () => {
  const client = new Client();
  const operation = client.startVerify('demo', 'gpt-oss-120b');
  try {
    const state = operation.poll();
    assert.equal(validateOperationState(state), state);
    assert.ok(['pending', 'ready', 'failed', 'cancelled'].includes(state.status));
  } finally {
    operation.cancel();
    operation.close();
    client.close();
  }
});

test('operation state validator rejects malformed poll states', () => {
  const failedState = {
    status: 'failed',
    result_available: true,
    error: {
      status: 'failed',
      error: { type: 'confidential_inference_async_error', message: 'operation failed' },
    },
  };

  for (const state of [
    { status: 'pending' },
    { status: 'ready' },
    { status: 'cancelled' },
    failedState,
  ]) {
    assert.equal(validateOperationState(state), state);
  }

  assertValidationError(
    () => validateOperationState({ status: 'complete' }),
    'malformed_operation_state',
    /status/,
  );
  assertValidationError(
    () => validateOperationState({ status: 'pending', result_available: false }),
    'malformed_operation_state',
    /unsupported field/,
  );
  assertValidationError(
    () => validateOperationState({ status: 'failed', result_available: false, error: {} }),
    'malformed_operation_state',
    /result_available=true/,
  );
  assertValidationError(
    () => validateOperationState({ status: 'failed', result_available: true }),
    'malformed_operation_state',
    /error/,
  );
});

test('FFI error validator rejects malformed error envelopes', () => {
  const emptyEnvelope = { error: null };
  const errorEnvelope = {
    error: {
      type: 'confidential_inference_ffi_error',
      code: 'invalid_argument',
      message: 'request JSON is invalid',
    },
  };

  assert.equal(validateFfiErrorEnvelope(emptyEnvelope), emptyEnvelope);
  assert.equal(validateFfiErrorEnvelope(errorEnvelope), errorEnvelope);

  assertValidationError(
    () => validateFfiErrorEnvelope({}),
    'malformed_ffi_error',
    /missing error/,
  );
  assertValidationError(
    () => validateFfiErrorEnvelope({ error: { type: 'other', code: 'x', message: 'bad' } }),
    'malformed_ffi_error',
    /type/,
  );
  assertValidationError(
    () => validateFfiErrorEnvelope({
      error: {
        type: 'confidential_inference_ffi_error',
        code: '',
        message: 'bad',
      },
    }),
    'malformed_ffi_error',
    /code/,
  );
  assertValidationError(
    () => validateFfiErrorEnvelope({
      error: {
        type: 'confidential_inference_ffi_error',
        code: 'invalid_argument',
        message: 'bad',
        detail: 'unexpected',
      },
    }),
    'malformed_ffi_error',
    /unsupported field detail/,
  );
});

test('stream async iterable preserves Rust fail-closed streaming event', async () => {
  const prompt = 'node stream secret';
  const client = new Client();
  const events = [];
  try {
    for await (const event of client.streamAsync(chatRequest(prompt), { timeoutMs: 2000 })) {
      events.push(event);
    }
    assert.equal(events.length, 1);
    assert.equal(events[0].type, 'error');
    assert.equal(events[0].status, 'failed');
    assert.match(events[0].error.message, /streaming is not supported/);
    assert.equal(JSON.stringify(events[0]).includes(prompt), false);
  } finally {
    client.close();
  }
});

test('discovery and artifact helpers expose SDK JSON', () => {
  const client = new Client();
  try {
    const models = client.models();
    const confidentiality = client.confidentialModels();
    const policy = client.activePolicy();
    const artifacts = client.activeTrustArtifacts();

    assert.equal(models.object, 'list');
    assert.equal(models.data[0].id, 'gpt-oss-120b');
    assert.equal(confidentiality[0].canonical_model, 'gpt-oss-120b');
    assert.equal(validateModelList(models), models);
    assert.equal(validateConfidentialModels(confidentiality), confidentiality);
    assert.equal(policy.schema, 'confidential-inference.active-policy.v1');
    assert.equal(validateActivePolicySnapshot(policy), policy);
    assert.equal(validateActiveTrustArtifacts(artifacts), artifacts);
    assert.equal(canonicalSha256Digest(policy.policy), policy.policy_digest);
    assert.equal(policyDigest(policy.policy), policy.policy_digest);
    assert.equal(artifacts.registry.version, '2026-07-05-demo');
    assert.equal(artifacts.reference_values.version, '2026-07-05-demo');
  } finally {
    client.close();
  }
});

test('discovery validators reject malformed model and confidential catalog JSON', () => {
  const catalog = [
    {
      canonical_model: 'gpt-oss-120b',
      display_name: 'GPT-OSS 120B',
      family: 'OpenAI GPT',
      aliases: ['gpt-oss-120b'],
      routes: [
        {
          route_id: 'demo:gpt-oss-120b:e2ee-gpt-oss-120b-p',
          provider: 'demo',
          provider_model: 'e2ee-gpt-oss-120b-p',
          evidence_family: 'fixture_dstack',
          route_execution_status: 'executable_fixture',
          chat_executable: true,
          known_unsupported_modes: ['streaming'],
          trust_tier: 'app-e2ee',
          channel_binding_kind: 'attested_app_e2ee',
          request_encryption: 'required',
          response_decryption: 'required',
          streaming_allowed: false,
          alias_confidence: 'curated',
          api_endpoint: 'http://127.0.0.1/demo/v1',
          evidence_endpoint: 'http://127.0.0.1/demo/v1/confidentiality',
          adapter_version: 'demo-fixture-adapter/0.1.0',
        },
      ],
    },
  ];

  const modelList = {
    object: 'list',
    data: [{ id: 'gpt-oss-120b', object: 'model', owned_by: 'confidential-inference' }],
  };
  assert.equal(validateModelList(modelList), modelList);
  assert.equal(validateConfidentialModels(catalog), catalog);

  assertValidationError(
    () => validateModelList({ object: 'models', data: [] }),
    'malformed_model_discovery',
    /object/,
  );
  assertValidationError(
    () =>
      validateModelList({
        object: 'list',
        data: [{ id: '', object: 'model', owned_by: 'confidential-inference' }],
      }),
    'malformed_model_discovery',
    /id/,
  );

  const invalidStatus = JSON.parse(JSON.stringify(catalog));
  invalidStatus[0].routes[0].route_execution_status = 'active';
  assertValidationError(
    () => validateConfidentialModels(invalidStatus),
    'malformed_confidential_catalog',
    /route_execution_status/,
  );

  const invalidTrustTier = JSON.parse(JSON.stringify(catalog));
  invalidTrustTier[0].routes[0].channel_binding_kind = 'none';
  assertValidationError(
    () => validateConfidentialModels(invalidTrustTier),
    'malformed_confidential_catalog',
    /trust_tier=app-e2ee/,
  );
});

test('active policy validator handles schema major, required fields, and digests', () => {
  const sameMajor = validActivePolicySnapshotStub({
    schema: 'confidential-inference.policy.v1.1',
    future_optional_field: { ignored: true },
  });
  sameMajor.schema = 'confidential-inference.active-policy.v1.1';
  sameMajor.policy_digest = canonicalSha256Digest(sameMajor.policy);
  assert.equal(validateActivePolicySnapshot(sameMajor), sameMajor);

  const unknownRequired = validActivePolicySnapshotStub();
  unknownRequired.required = ['future_required_field'];
  unknownRequired.future_required_field = true;
  assertValidationError(
    () => validateActivePolicySnapshot(unknownRequired),
    'incompatible_active_policy_schema',
    /future_required_field/,
  );

  const missingPolicyRequired = validActivePolicySnapshotStub();
  missingPolicyRequired.policy.required = ['enforcement'];
  delete missingPolicyRequired.policy.enforcement;
  missingPolicyRequired.policy_digest = canonicalDigestOrPlaceholder(missingPolicyRequired.policy);
  assertValidationError(
    () => validateActivePolicySnapshot(missingPolicyRequired),
    'malformed_active_policy_schema',
    /enforcement/,
  );

  const badDigestField = validActivePolicySnapshotStub({
    provider_registry_digest: `sha256:${'A'.repeat(64)}`,
  });
  assertValidationError(
    () => validateActivePolicySnapshot(badDigestField),
    'malformed_active_policy_digest',
    /provider_registry_digest/,
  );

  const mismatchedDigest = validActivePolicySnapshotStub();
  mismatchedDigest.policy_digest = `sha256:${'1'.repeat(64)}`;
  assertValidationError(
    () => validateActivePolicySnapshot(mismatchedDigest),
    'malformed_active_policy_digest',
    /policy_digest/,
  );
});

test('active policy validator rejects unsafe and noncanonical policy metadata', () => {
  const unsafeTtl = validActivePolicySnapshotStub({ verdict_ttl_millis: MAX_SAFE_JSON_INT + 1 });
  assertValidationError(
    () => validateActivePolicySnapshot(unsafeTtl),
    'malformed_active_policy_schema',
    /verdict_ttl_millis.*safe integer/,
  );

  const missingFreshnessMillis = validActivePolicySnapshotStub({
    freshness: { mode: 'allow_cached_binding_millis' },
  });
  assertValidationError(
    () => validateActivePolicySnapshot(missingFreshnessMillis),
    'malformed_active_policy_schema',
    /freshness\.millis/,
  );

  const duplicateAllowed = validActivePolicySnapshotStub({
    hardware: {
      cpu: { mode: 'one_of', allowed: ['tdx', 'sev_snp', 'tdx'] },
      gpu: { mode: 'not_required' },
    },
  });
  assertValidationError(
    () => validateActivePolicySnapshot(duplicateAllowed),
    'malformed_active_policy_schema',
    /hardware\.cpu\.allowed/,
  );

  const staleMillisOnFailClosed = validActivePolicySnapshotStub({
    stale_verdicts: { mode: 'fail_closed', millis: 1 },
  });
  assertValidationError(
    () => validateActivePolicySnapshot(staleMillisOnFailClosed),
    'malformed_active_policy_schema',
    /stale_verdicts\.millis/,
  );
});

test('active trust artifacts validator handles schema, digests, and signatures', () => {
  const sameMajor = validTrustArtifactsStub({
    registry: { schema: 'confidential-inference.provider-registry.v1.1' },
    reference_values: { schema: 'confidential-inference.reference-values.v1.1' },
  });
  assert.equal(validateActiveTrustArtifacts(sameMajor), sameMajor);

  const unknownRegistryMajor = validTrustArtifactsStub({
    registry: { schema: 'confidential-inference.provider-registry.v2' },
  });
  assertValidationError(
    () => validateActiveTrustArtifacts(unknownRegistryMajor),
    'incompatible_trust_artifacts_schema',
    /provider-registry schema/,
  );

  const badDigest = validTrustArtifactsStub({ registry_digest: `sha256:${'g'.repeat(64)}` });
  assertValidationError(
    () => validateActiveTrustArtifacts(badDigest),
    'malformed_trust_artifacts_digest',
    /registry_digest/,
  );

  const mismatchedDigest = validTrustArtifactsStub({
    registry: validRegistryPayloadWithRoute(),
    registry_digest: `sha256:${'1'.repeat(64)}`,
  });
  assertValidationError(
    () => validateActiveTrustArtifacts(mismatchedDigest),
    'malformed_trust_artifacts_digest',
    /registry_digest/,
  );

  const unsupportedSignature = validTrustArtifactsStub();
  unsupportedSignature.reference_values_signature.alg = 'rsa';
  assertValidationError(
    () => validateActiveTrustArtifacts(unsupportedSignature),
    'malformed_trust_artifacts_signature',
    /reference_values_signature/,
  );

  const badSignatureValue = validTrustArtifactsStub();
  badSignatureValue.registry_signature.value = `${VALID_REGISTRY_SIGNATURE_VALUE}=`;
  assertValidationError(
    () => validateActiveTrustArtifacts(badSignatureValue),
    'malformed_trust_artifacts_signature',
    /signature value/,
  );
});

test('active trust artifacts validator verifies known bundled signatures', () => {
  const client = new Client();
  let artifacts;
  try {
    artifacts = client.activeTrustArtifacts();
  } finally {
    client.close();
  }

  artifacts.registry.version = 'tampered';
  artifacts.registry_digest = canonicalSha256Digest(artifacts.registry);

  assertValidationError(
    () => validateActiveTrustArtifacts(artifacts),
    'malformed_trust_artifacts_signature',
    /registry_signature signature is invalid/,
  );
});

test('active trust artifacts validator rejects freshness and route metadata drift', () => {
  const badRegistryFreshness = validTrustArtifactsStub({
    registry: { schema: 'confidential-inference.provider-registry.v1', generated_at: '2026-07-05T00:00:00+00:00' },
  });
  assertValidationError(
    () => validateActiveTrustArtifacts(badRegistryFreshness),
    'malformed_trust_artifacts_schema',
    /generated_at/,
  );

  const algorithmicActiveRoute = validTrustArtifactsStub({
    registry: validRegistryPayloadWithRoute({ alias_confidence: 'algorithmic' }),
  });
  assertValidationError(
    () => validateActiveTrustArtifacts(algorithmicActiveRoute),
    'malformed_trust_artifacts_schema',
    /alias_confidence/,
  );

  const referenceEpochMismatch = validTrustArtifactsStub({
    reference_values: validReferenceValuesPayloadWithRoute({ valid_until_epoch_ms: 1 }),
  });
  assertValidationError(
    () => validateActiveTrustArtifacts(referenceEpochMismatch),
    'malformed_trust_artifacts_schema',
    /valid_until_epoch_ms/,
  );

  const badReferenceDigest = validTrustArtifactsStub({
    reference_values: validReferenceValuesPayloadWithRoute({ e2ee_public_key_digest: 'demo-key' }),
  });
  assertValidationError(
    () => validateActiveTrustArtifacts(badReferenceDigest),
    'malformed_trust_artifacts_schema',
    /e2ee_public_key_digest/,
  );
});

test('policy digest helpers match shared canonical vectors', () => {
  const vectors = JSON.parse(
    fs.readFileSync(path.join(ROOT, 'fixtures/policy/canonical-vectors.json'), 'utf8'),
  );
  const vectorById = new Map(vectors.vectors.map((vector) => [vector.id, vector]));

  for (const vector of vectors.vectors) {
    assert.equal(policyCanonicalJson(vector.policy), vector.canonical_json);
    assert.equal(policyDigest(vector.policy), vector.digest);
  }
  for (const equivalenceCase of vectors.equivalence_cases) {
    const expected = vectorById.get(equivalenceCase.equivalent_to);
    assert.equal(policyCanonicalJson(equivalenceCase.policy), expected.canonical_json);
    assert.equal(policyDigest(equivalenceCase.policy), expected.digest);
  }
});

test('canonical JSON orders object keys by UTF-16 code units', () => {
  assert.equal(canonicalJson({ '\uE000': 2, '\u{10000}': 1 }), '{"𐀀":1,"":2}');
});

test('policy digest helpers reject unknown, unsafe, and semantically invalid policy values', () => {
  const vectors = JSON.parse(
    fs.readFileSync(path.join(ROOT, 'fixtures/policy/canonical-vectors.json'), 'utf8'),
  );
  const clonePolicy = () => JSON.parse(JSON.stringify(vectors.vectors[0].policy));

  const policy = { ...clonePolicy(), unexpected: true };
  assert.throws(
    () => policyDigest(policy),
    (error) =>
      error instanceof ConfidentialInferenceError &&
      error.error.code === 'malformed_policy_digest' &&
      /unsupported field/.test(error.error.message),
  );

  const unsafePolicy = clonePolicy();
  unsafePolicy.verdict_ttl_millis = MAX_SAFE_JSON_INT + 1;
  assert.throws(
    () => policyDigest(unsafePolicy),
    (error) =>
      error instanceof ConfidentialInferenceError &&
      error.error.code === 'malformed_canonical_json' &&
      /safe integer/.test(error.error.message),
  );

  const invalidEnforcement = clonePolicy();
  invalidEnforcement.enforcement = 'audit_only';
  assertValidationError(
    () => policyDigest(invalidEnforcement),
    'malformed_active_policy_schema',
    /enforcement/,
  );

  const invalidTee = clonePolicy();
  invalidTee.hardware.cpu = { mode: 'one_of', allowed: ['bogus_tee'] };
  assertValidationError(
    () => policyDigest(invalidTee),
    'malformed_active_policy_schema',
    /hardware\.cpu\.allowed/,
  );

  const invalidFreshness = clonePolicy();
  invalidFreshness.freshness = { mode: 'sometimes' };
  assertValidationError(
    () => policyDigest(invalidFreshness),
    'malformed_active_policy_schema',
    /freshness\.mode/,
  );
});

test('verdict validator handles schema major and declared required fields', () => {
  const sameMajor = validVerdictStub({
    schema: 'confidential-inference.verdict.v1.1',
    policy_schema: 'confidential-inference.policy.v1.1',
    reference_values_schema: 'confidential-inference.reference-values.v1.1',
    provider_registry_schema: 'confidential-inference.provider-registry.v1.1',
    future_optional_field: { ignored: true },
  });
  assert.equal(validateVerdict(sameMajor), sameMajor);

  assertValidationError(
    () => validateVerdict(validVerdictStub({ schema: 'confidential-inference.verdict.v2' })),
    'incompatible_verdict_schema',
    /major version 2/,
  );
  assertValidationError(
    () => validateVerdict(validVerdictStub({ schema: 'confidential-inference.verdict.v10' })),
    'incompatible_verdict_schema',
    /major version 10/,
  );

  const unknownRequired = validVerdictStub({
    schema: 'confidential-inference.verdict.v1.1',
    required: ['future_required_field'],
    future_required_field: true,
  });
  assertValidationError(
    () => validateVerdict(unknownRequired),
    'incompatible_verdict_schema',
    /future_required_field/,
  );

  const missingRequired = validVerdictStub({ required: ['policy_digest'] });
  delete missingRequired.policy_digest;
  assertValidationError(
    () => validateVerdict(missingRequired),
    'malformed_verdict_schema',
    /policy_digest/,
  );
});

test('verdict validator checks structured outcomes and direct route attribution', () => {
  const verdict = validVerdictStub({ provider: 'demo' });
  verdict.check_outcomes = Object.fromEntries(
    Object.entries(verdict.checks).map(([name, state]) => [
      name,
      {
        state,
        required: state !== 'not_applicable',
        detail: 'binding test detail',
        evidence_refs: [],
      },
    ]),
  );
  verdict.route_attribution = {
    parties: [
      {
        role: 'inference_provider',
        party_id: 'demo',
        source: 'signed_registry',
        detail: 'signed registry provider',
        evidence_refs: ['provider_registry_digest'],
      },
      {
        role: 'registry_authority',
        party_id: 'confidential-inference',
        source: 'signed_registry',
        detail: 'registry signer',
        evidence_refs: ['provider_registry_digest'],
      },
      {
        role: 'reference_values_authority',
        party_id: 'confidential-inference',
        source: 'signed_reference_values',
        detail: 'reference issuer',
        evidence_refs: ['reference_values_digest'],
      },
      {
        role: 'workload_operator',
        source: 'unknown',
        detail: 'not directly asserted',
        evidence_refs: [],
      },
      {
        role: 'tee_platform',
        party_id: 'tdx',
        source: 'attested_evidence',
        detail: 'parsed evidence platform',
        evidence_refs: ['raw_evidence_digest'],
      },
      {
        role: 'cloud_host',
        source: 'unknown',
        detail: 'not directly asserted',
        evidence_refs: [],
      },
    ],
  };
  assert.equal(validateVerdict(verdict), verdict);

  const mismatched = structuredClone(verdict);
  mismatched.check_outcomes.model_binding.state = 'failed';
  assertValidationError(
    () => validateVerdict(mismatched),
    'malformed_verdict_checks',
    /model_binding\.state conflicts/,
  );

  const inferred = structuredClone(verdict);
  inferred.route_attribution.parties[0].party_id = 'other';
  assertValidationError(
    () => validateVerdict(inferred),
    'malformed_verdict_attribution',
    /signed registry provider/,
  );
});

test('verdict validator rejects malformed digest and signature metadata', () => {
  assertValidationError(
    () => validateVerdict(validVerdictStub({ policy_digest: `sha256:${'g'.repeat(64)}` })),
    'malformed_verdict_digest',
    /policy_digest/,
  );

  const missingSignature = validVerdictStub();
  delete missingSignature.registry_signature;
  assertValidationError(
    () => validateVerdict(missingSignature),
    'malformed_verdict_signature',
    /registry_signature/,
  );

  const incompleteSignature = validVerdictStub({
    reference_values_signature: {
      signer: 'confidential-inference',
      key_id: '',
      alg: 'ed25519',
    },
  });
  assertValidationError(
    () => validateVerdict(incompleteSignature),
    'malformed_verdict_signature',
    /metadata is incomplete/,
  );

  const unsupportedSignature = validVerdictStub({
    registry_signature: {
      signer: 'confidential-inference',
      key_id: 'confidential-inference-demo-ed25519-2026',
      alg: 'rsa',
    },
  });
  assertValidationError(
    () => validateVerdict(unsupportedSignature),
    'malformed_verdict_signature',
    /unsupported signature algorithm/,
  );
});

test('verdict validator rejects unsafe or incoherent validity metadata', () => {
  assertValidationError(
    () => validateVerdict(validVerdictStub({ expires_at: '2099-01-01T00:00:01Z' })),
    'malformed_verdict_validity',
    /computed_expires_at/,
  );
  assertValidationError(
    () => validateVerdict(validVerdictStub({ expires_at_epoch_ms: 4070908800001 })),
    'malformed_verdict_validity',
    /expires_at_epoch_ms/,
  );
  assertValidationError(
    () => validateVerdict(validVerdictStub({ expires_at_epoch_ms: MAX_SAFE_JSON_INT + 1 })),
    'malformed_verdict_validity',
    /safe integer/,
  );

  const invalidMinimum = validVerdictStub();
  invalidMinimum.validity = {
    ...invalidMinimum.validity,
    policy_ttl_until: '2098-12-31T23:59:59Z',
  };
  assertValidationError(
    () => validateVerdict(invalidMinimum),
    'malformed_verdict_validity',
    /minimum validity bound/,
  );
});

test('timestamp validators accept canonical millisecond precision and reject other fractions', () => {
  const millisecondVerdict = validVerdictStub({
    expires_at: '2099-01-01T00:00:00.123Z',
    expires_at_epoch_ms: 4070908800123,
    validity: {
      policy_ttl_until: '2099-01-01T00:00:00.123Z',
      collateral_valid_until: '2099-01-01T00:00:00.123Z',
      certificate_valid_until: '2099-01-01T00:00:00.123Z',
      quote_valid_until: '2099-01-01T00:00:00.123Z',
      tcb_valid_until: '2099-01-01T00:00:00.123Z',
      reference_values_valid_until: '2099-01-01T00:00:00.123Z',
      computed_expires_at: '2099-01-01T00:00:00.123Z',
    },
  });
  assert.equal(validateVerdict(millisecondVerdict), millisecondVerdict);

  const referenceValues = validReferenceValuesPayloadWithRoute({
    valid_until: '2099-01-01T00:00:00.123Z',
    valid_until_epoch_ms: 4070908800123,
  });
  const artifacts = validTrustArtifactsStub({ reference_values: referenceValues });
  assert.equal(validateActiveTrustArtifacts(artifacts), artifacts);

  const microsecondRegistry = validTrustArtifactsStub({
    registry: { schema: 'confidential-inference.provider-registry.v1', generated_at: '2099-01-01T00:00:00.123456Z' },
  });
  assertValidationError(
    () => validateActiveTrustArtifacts(microsecondRegistry),
    'malformed_trust_artifacts_schema',
    /canonical UTC/,
  );
});

test('verdict validator rejects invalid result domains and check values', () => {
  assertValidationError(
    () => validateVerdict(validVerdictStub({ response_integrity_result: 'any_bound' })),
    'malformed_verdict_enum',
    /response_integrity_result/,
  );
  assertValidationError(
    () => validateVerdict(validVerdictStub({ request_confidentiality_result: 'bound_to_attested_workload' })),
    'malformed_verdict_enum',
    /request_confidentiality_result/,
  );
  assertValidationError(
    () => validateVerdict(validVerdictStub({ checks: { model_binding: 'required' } })),
    'malformed_verdict_enum',
    /model_binding/,
  );

  const missingAllowed = validVerdictStub();
  delete missingAllowed.request_allowed;
  assertValidationError(
    () => validateVerdict(missingAllowed),
    'malformed_verdict_enum',
    /request_allowed/,
  );
});

test('verdict validator rejects summary and check conflicts', () => {
  assertValidationError(
    () => validateVerdict(validVerdictStub({ checks: { ...validVerdictStub().checks, model_binding: 'failed' } })),
    'malformed_verdict_summary',
    /model_binding_result=verified/,
  );

  for (const checkName of ['request_key_binding', 'request_encryption']) {
    const verdict = validVerdictStub();
    verdict.checks[checkName] = 'failed';
    assertValidationError(
      () => validateVerdict(verdict),
      'malformed_verdict_summary',
      new RegExp(checkName),
    );
  }

  for (const checkName of ['response_key_binding', 'response_encryption', 'response_channel_binding']) {
    const verdict = validVerdictStub();
    verdict.checks[checkName] = 'failed';
    assertValidationError(
      () => validateVerdict(verdict),
      'malformed_verdict_summary',
      new RegExp(checkName),
    );
  }

  const receiptIntegrity = validVerdictStub({
    response_channel_bound: false,
    response_confidentiality_result: 'unknown',
    response_integrity_result: 'receipt_bound',
  });
  receiptIntegrity.checks.response_receipt = 'failed';
  assertValidationError(
    () => validateVerdict(receiptIntegrity),
    'malformed_verdict_summary',
    /response_receipt/,
  );
});

test('verdict validator rejects enforcement and trust-tier conflicts', () => {
  const failedWithoutBlock = validVerdictStub({ status: 'failed' });
  failedWithoutBlock.checks.image_provenance = 'failed';
  assertValidationError(
    () => validateVerdict(failedWithoutBlock),
    'malformed_verdict_summary',
    /would_block_under_enforce=false/,
  );

  const enforceWouldBlockAllowed = validVerdictStub({
    status: 'failed',
    request_allowed: true,
    would_block_under_enforce: true,
  });
  enforceWouldBlockAllowed.checks.image_provenance = 'failed';
  assertValidationError(
    () => validateVerdict(enforceWouldBlockAllowed),
    'malformed_verdict_summary',
    /request_allowed=true/,
  );

  assertValidationError(
    () => validateVerdict(validVerdictStub({ enforcement: 'disabled', status: 'partial' })),
    'malformed_verdict_summary',
    /status=disabled/,
  );
  assertValidationError(
    () => validateVerdict(validVerdictStub({ channel_binding_kind: 'tee_terminated_tls' })),
    'malformed_verdict_summary',
    /trust_tier=app-e2ee/,
  );

  const hwTls = validVerdictStub({
    trust_tier: 'hw-verified-tls',
    channel_binding_kind: 'tee_terminated_tls',
    request_confidentiality_result: 'channel_bound',
    response_confidentiality_result: 'channel_bound',
  });
  hwTls.checks.tls_binding = 'not_applicable';
  assertValidationError(
    () => validateVerdict(hwTls),
    'malformed_verdict_summary',
    /tls_binding/,
  );
});

test('response and stream validators require verdict mirror fields', () => {
  const verdict = validVerdictStub();
  const response = {
    response: {},
    response_channel_bound: true,
    response_integrity_result: 'channel_bound',
    verdict,
  };
  assert.equal(validateConfidentialResponse(response), response);

  const missingMirror = {
    response: {},
    response_channel_bound: true,
    verdict,
  };
  assertValidationError(
    () => validateConfidentialResponse(missingMirror),
    'malformed_confidential_response',
    /response_integrity_result/,
  );

  const streamEvent = {
    type: 'verdict',
    response_channel_bound: false,
    response_integrity_result: 'receipt_bound',
    verdict: validVerdictStub({
      status: 'partial',
      response_channel_bound: false,
      response_confidentiality_result: 'unknown',
      response_integrity_result: 'receipt_bound',
      checks: {
        ...validVerdictStub().checks,
        response_receipt: 'verified',
      },
    }),
  };
  assertValidationError(
    () => validateStreamEvent(streamEvent),
    'malformed_stream_verdict',
    /opening verdict/,
  );
});

test('stream validator accepts verified terminal response receipt event', () => {
  const event = {
    type: 'response_receipt',
    response_integrity_result: 'receipt_bound',
    receipt_verified: true,
    receipt: { signature: 'base64url:test' },
  };

  assert.equal(validateStreamEvent(event), event);
});

test('stream validator accepts known control, response, and error events', () => {
  const events = [
    { type: 'response', response: { object: 'chat.completion' } },
    { type: 'done' },
    { type: 'cancelled' },
    { type: 'closed' },
    {
      type: 'error',
      status: 'failed',
      error: { type: 'confidential_inference_stream_error', message: 'stream failed' },
    },
  ];

  for (const event of events) {
    assert.equal(validateStreamEvent(event), event);
  }
});

test('stream validator rejects malformed stream event envelopes', () => {
  assertValidationError(
    () => validateStreamEvent('closed'),
    'malformed_stream_event',
    /object/,
  );
  assertValidationError(
    () => validateStreamEvent({ type: 'delta', delta: {} }),
    'malformed_stream_event',
    /type/,
  );
  assertValidationError(
    () => validateStreamEvent({ type: 'closed', extra: true }),
    'malformed_stream_event',
    /unsupported field/,
  );
  assertValidationError(
    () => validateStreamEvent({ type: 'response' }),
    'malformed_stream_event',
    /response object/,
  );
  assertValidationError(
    () => validateStreamEvent({ type: 'error', status: 'ok', error: {} }),
    'malformed_stream_event',
    /status/,
  );
  assertValidationError(
    () => validateStreamEvent({ type: 'error', status: 'failed', error: { type: 'x' } }),
    'malformed_stream_event',
    /message/,
  );
});

test('stream validator rejects malformed terminal response receipt events', () => {
  assertValidationError(
    () =>
      validateStreamEvent({
        type: 'response_receipt',
        response_integrity_result: 'unknown',
        receipt_verified: true,
        receipt: { signature: 'base64url:test' },
      }),
    'malformed_stream_receipt',
    /receipt-bound/,
  );

  assertValidationError(
    () =>
      validateStreamEvent({
        type: 'response_receipt',
        response_integrity_result: 'receipt_bound',
        receipt_verified: false,
        receipt: { signature: 'base64url:test' },
      }),
    'malformed_stream_receipt',
    /receipt_verified=true/,
  );

  assertValidationError(
    () =>
      validateStreamEvent({
        type: 'response_receipt',
        response_integrity_result: 'receipt_bound',
        receipt_verified: true,
      }),
    'malformed_stream_receipt',
    /receipt metadata/,
  );
});

test('inline credential config is rejected without echoing the secret', () => {
  const secret = 'sk-node-binding-secret';
  assert.throws(
    () => new Client({ api_keys: { demo: { inline: secret } } }),
    (error) => {
      assert.ok(error instanceof ConfidentialInferenceError);
      assert.equal(error.error.code, 'inline_credentials_not_allowed');
      assert.equal(JSON.stringify(error.error).includes(secret), false);
      return true;
    },
  );
});

test('stream next preserves immediate Rust stream state', () => {
  const client = new Client();
  const prompt = 'node pending stream';
  const stream = client.startStream(chatRequest(prompt));
  try {
    try {
      const event = stream.next({ timeoutMs: 0 });
      assert.equal(event.type, 'error');
      assert.equal(event.status, 'failed');
      assert.match(event.error.message, /streaming is not supported/);
      assert.equal(JSON.stringify(event).includes(prompt), false);
    } catch (error) {
      assert.ok(error instanceof ConfidentialInferenceError);
      assert.equal(error.status, CONFIDENTIAL_INFERENCE_FFI_PENDING);
    }
  } finally {
    stream.cancel();
    stream.close();
    client.close();
  }
});

test('operation wait abort signal cancels operation handle', async () => {
  const client = new Client();
  const operation = client.startVerify('demo', 'gpt-oss-120b');
  const originalCancel = operation.cancel.bind(operation);
  const controller = new AbortController();
  let cancelCalled = false;
  try {
    operation.readinessFd = () => {
      throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED, {
        code: 'readiness_fd_unsupported',
        message: 'forced polling fallback',
      });
    };
    operation.poll = () => ({ status: 'pending' });
    operation.cancel = () => {
      cancelCalled = true;
      originalCancel();
    };

    const promise = operation.wait({ pollIntervalMs: 60000, signal: controller.signal });
    await new Promise((resolve) => setImmediate(resolve));
    controller.abort();

    await assert.rejects(promise, (error) => error.name === 'AbortError');
    assert.equal(cancelCalled, true);
  } finally {
    operation.close();
    client.close();
  }
});

test('stream event abort signal cancels stream handle', async () => {
  const client = new Client();
  const stream = client.startStream(chatRequest('cancel node stream'));
  const originalCancel = stream.cancel.bind(stream);
  const controller = new AbortController();
  let cancelCalled = false;
  try {
    stream.next = () => {
      throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_PENDING, {
        code: 'stream_pending',
        message: 'stream event is not ready yet',
      });
    };
    stream.readinessFd = () => {
      throw new ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED, {
        code: 'readiness_fd_unsupported',
        message: 'forced polling fallback',
      });
    };
    stream.cancel = () => {
      cancelCalled = true;
      originalCancel();
    };

    const iterator = stream.events({ pollIntervalMs: 60000, signal: controller.signal });
    const promise = iterator.next();
    await new Promise((resolve) => setImmediate(resolve));
    controller.abort();

    await assert.rejects(promise, (error) => error.name === 'AbortError');
    assert.equal(cancelCalled, true);
  } finally {
    stream.close();
    client.close();
  }
});
