'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  Client,
  Stream,
  ConfidentialInferenceError,
  status: ffiStatus,
} = require('../index.js');

const ROOT = path.resolve(__dirname, '..', '..', '..');

function chatRequest(prompt = 'node binding path') {
  return {
    model: 'gpt-oss-120b',
    messages: [{ role: 'user', content: prompt }],
  };
}

test('status reports blocking and stream capabilities', () => {
  const status = ffiStatus();
  assert.equal(status.blocking_helpers_available, true);
  assert.equal(status.stream_handle_abi_available, true);
});

test('chat returns a verified confidential response', async () => {
  const expected = JSON.parse(
    fs.readFileSync(path.join(ROOT, 'fixtures', 'verdict', 'demo-verified.json'), 'utf8')
  );
  const client = new Client();
  try {
    const response = await client.chat(chatRequest(), 5_000);
    assert.equal(response.provider, 'demo');
    assert.equal(response.provider_model, 'e2ee-gpt-oss-120b-p');
    assert.deepEqual(response.verdict, expected);
    assert.equal(response.verdict.status, 'verified');
    assert.equal(
      response.response.choices[0].message.content,
      'demo confidential response for e2ee-gpt-oss-120b-p: node binding path'
    );
  } finally {
    client.close();
  }
});

test('verify returns a route verdict', async () => {
  const client = new Client();
  try {
    const verdict = await client.verify('demo', 'gpt-oss-120b', 5_000);
    assert.equal(verdict.status, 'verified');
    assert.equal(verdict.provider, 'demo');
  } finally {
    client.close();
  }
});

test('response returns the Responses shim object', async () => {
  const client = new Client();
  try {
    const response = await client.response({ model: 'gpt-oss-120b', input: 'responses path' }, 5_000);
    assert.equal(response.provider, 'demo');
    assert.equal(response.response.object, 'response');
  } finally {
    client.close();
  }
});

test('model discovery and confidentiality catalog return JSON shapes', async () => {
  const client = new Client();
  try {
    const models = await client.models();
    const catalog = await client.confidentiality();
    assert.ok(Array.isArray(models.data));
    assert.ok(Array.isArray(catalog));
  } finally {
    client.close();
  }
});

test('active policy and trust artifacts cross the ABI', async () => {
  const client = new Client();
  try {
    const policy = await client.activePolicy();
    const artifacts = await client.activeTrustArtifacts();
    assert.equal(policy.schema, 'confidential-inference.active-policy.v1');
    assert.ok('registry_digest' in artifacts);
    assert.ok('reference_values_digest' in artifacts);
  } finally {
    client.close();
  }
});

test('stream fails closed for a non-streaming route', async () => {
  const client = new Client();
  try {
    const events = [];
    for await (const event of client.stream(chatRequest('stream path'), { timeoutMs: 5_000 })) {
      events.push(event);
    }
    // The demo route does not support streaming; the SDK fails closed with a
    // structured error event instead of emitting an unverified stream.
    assert.equal(events[0].type, 'error');
    assert.equal(events[0].status, 'failed');
  } finally {
    client.close();
  }
});

test('closed client rejects calls', async () => {
  const client = new Client();
  client.close();
  await assert.rejects(() => client.models(), ConfidentialInferenceError);
});

test('closing a client with a live stream fails and preserves the handle', () => {
  const client = new Client();
  const stream = client.startStream(chatRequest());
  // The pending stream keeps the native client live; freeing must fail
  // without discarding the handle (which would leak both objects).
  assert.throws(
    () => client.close(),
    (error) => error instanceof ConfidentialInferenceError && error.status === 3 /* FFI_BUSY */
  );
  assert.ok(client._handle !== null, 'client handle should be preserved on failed free');
  stream.close();
  client.close();
  assert.ok(client._handle === null, 'client should free once streams are closed');
});

test('closing while a worker-thread call is in flight refuses and preserves the handle', async () => {
  const client = new Client();
  // Dispatch synchronously: the in-flight counter is bumped before this line
  // returns, so the same-tick close() deterministically observes it.
  const pending = client.chat(chatRequest(), 5_000);
  assert.throws(
    () => client.close(),
    (error) =>
      error instanceof ConfidentialInferenceError &&
      error.status === 3 &&
      error.error.code === 'client_busy'
  );
  assert.ok(client._handle !== null, 'client handle must be preserved while calls run');
  const response = await pending;
  assert.equal(response.verdict.status, 'verified');
  client.close();
  assert.ok(client._handle === null, 'client frees once in-flight calls settle');
});

test('closing a stream while stream_next is in flight refuses and preserves the handle', async () => {
  const client = new Client();
  const stream = client.startStream(chatRequest());
  const pending = stream._nextAsync(5_000);
  assert.throws(
    () => stream.close(),
    (error) =>
      error instanceof ConfidentialInferenceError &&
      error.status === 3 &&
      error.error.code === 'stream_busy'
  );
  assert.ok(stream._handle !== null, 'stream handle must be preserved while next runs');
  await pending;
  stream.close();
  client.close();
});

test('failed inference surfaces the native error code across the worker boundary', async () => {
  const client = new Client();
  try {
    await client.chat({ nope: true });
    assert.fail('expected a failure');
  } catch (error) {
    assert.ok(error instanceof ConfidentialInferenceError);
    assert.equal(error.status, 1);
    assert.equal(error.error.code, 'invalid_request_json');
    assert.match(error.error.message, /missing field `model`/);
  } finally {
    client.close();
  }
});

test('concurrent failures retain their call-specific error details', async () => {
  const client = new Client();
  try {
    const [chat, verify] = await Promise.allSettled([
      client.chat({ nope: true }),
      client.verify(undefined, undefined),
    ]);
    assert.equal(chat.status, 'rejected');
    assert.equal(verify.status, 'rejected');
    assert.match(chat.reason.error.message, /chat request JSON/);
    assert.match(verify.reason.error.message, /verify request JSON/);
  } finally {
    client.close();
  }
});

test('concurrent inference calls all resolve under the koffi async pool', async () => {
  const client = new Client();
  try {
    const jobs = [];
    for (let i = 0; i < 8; i += 1) {
      jobs.push(client.chat(chatRequest(`fanout ${i}`), 5_000));
    }
    jobs.push(client.models(), client.confidentiality(), client.activePolicy());
    const results = await Promise.all(jobs);
    for (let i = 0; i < 8; i += 1) {
      assert.equal(results[i].verdict.status, 'verified');
    }
  } finally {
    client.close();
  }
});

test('inference methods do not block the event loop', async () => {
  const client = new Client();
  try {
    // The blocking C call runs on a Koffi worker thread, so the promise must
    // still be pending after an already-queued event-loop turn. A synchronous
    // call would settle its continuation on the microtask queue first.
    let settled = false;
    const pending = client.chat(chatRequest(), 5_000).then((response) => {
      settled = true;
      return response;
    });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false, 'chat resolved before the event loop turned');
    const response = await pending;
    assert.equal(response.verdict.status, 'verified');
  } finally {
    client.close();
  }
});
