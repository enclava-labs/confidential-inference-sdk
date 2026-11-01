# Node.js binding

This directory contains a CommonJS and TypeScript binding for the
Confidential Inference SDK C ABI. Routing, attestation, policy, digest, and
signature decisions remain in Rust.

The package is private and is not published to npm. It must be used with a
locally built `confidential-inference-ffi` shared library.

## Requirements

- Node.js `22` or later
- Rust `1.97` or later
- npm with lockfile support

## Build and test

From the repository root:

```bash
cargo build -p confidential-inference-ffi --locked
cd bindings/node
npm ci
npm test
```

The binding searches the workspace `target/release` and `target/debug`
directories (release first; the working directory is never searched). Set
`CONFIDENTIAL_INFERENCE_FFI_LIBRARY` — or pass `libraryPath` — to an explicit
shared library path when embedding it elsewhere; an explicit path is
exclusive and must exist.
Each binding checks the library's reported ABI version when loading it and
rejects incompatible versions before use.

## Example

Run this from the repository root after building the FFI library:

```js
const { Client } = require('./bindings/node');

async function main() {
  const client = new Client({ demo_provider: true });

  try {
    const result = await client.chat({
      model: 'gpt-oss-120b',
      messages: [{ role: 'user', content: 'Verify this route.' }],
    });

    console.log(result.verdict.status);
    console.log(result.response.choices[0].message.content);
  } finally {
    client.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
```

The demo provider uses fixture trust material and does not make a network
request.

## API

`Client` provides Promise-based Chat Completions, Responses, Responses lifecycle
management (`responseManage`), embeddings, route verification, model discovery,
and active policy / trust-artifact inspection.
`Client.stream` and `Stream` expose every native event as it arrives through
async iterables. The demo and other non-plaintext routes that cannot stream
fail closed with a structured error event. See `index.d.ts` for the complete API.
Embedding requests may use text or token IDs. Token IDs are encrypted with the
request on supported E2EE routes; an adapter that cannot encrypt them may pass
them through only on a plaintext-compatible route. Otherwise the SDK fails
closed.
`Client.responseManage` accepts `{op, provider, provider_response_id, params}`;
supported operations are `retrieve`, `list_input_items`, `cancel`, `delete`,
`input_tokens`, and `compact`.


Inference methods run the blocking FFI call on a Koffi worker thread, so they
do not block the Node event loop. Rust owns every
attestation/policy/registry/digest/signature decision; the binding only
parses the JSON that crosses the ABI and applies minimal object/array shape
checks on the way back. Each async call occupies a libuv threadpool thread
for its full duration: real concurrency is bounded by `UV_THREADPOOL_SIZE`
(default 4), not by the 32-call Koffi queue cap. Set
`UV_THREADPOOL_SIZE=<expected concurrent native calls>+4` at process start —
it cannot be raised later — for larger fan-outs.

## Artifact trust

`demo_provider: true` is the offline/demo mode: it installs the demo provider
and trusts the bundled fixture signing keys for the bundled artifacts only.
It must be opted into explicitly — `demo_provider` defaults to `false`, so a
missing, empty, or NULL config fails closed with
`trusted_signing_keys_required`.

Clients create a private Tokio runtime. Create them **after** `fork()`:
handles used in a forked child fail with `client_used_after_fork`.

Setting `demo_provider: false` requires a non-empty
`trusted_ed25519_signing_keys` list, which becomes the exclusive trust root
for every artifact — including the bundled ones:

```js
const client = new Client({
  demo_provider: false,
  trusted_ed25519_signing_keys: [
    {
      signer: 'my-operator',
      key_id: 'operator-ed25519-2026',
      public_key_base64url: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
  ],
});
```

Combining `demo_provider: true` with a non-empty `trusted_ed25519_signing_keys`
list is rejected as ambiguous. The bundled fixture keys can never verify
remote or custom artifacts.

The configuration also accepts `registry` and `reference_values`, each a
signed envelope object matching the SDK's provider-registry and reference-
values envelope schemas. They are REQUIRED together. `compatibility_matrix`
accepts a signed provider-compatibility-matrix envelope object; all three
options are only allowed with `demo_provider: false` and are verified against
the configured trusted signing keys by Rust.

```js
const client = new Client({
  demo_provider: false,
  trusted_ed25519_signing_keys: [...],
  registry: {...},
  reference_values: {...},
  compatibility_matrix: {...},
});
```

## Credentials

Prefer environment-variable references:

```js
const client = new Client({
  demo_provider: false,
  trusted_ed25519_signing_keys: [
    {
      signer: 'my-operator',
      key_id: 'operator-ed25519-2026',
      public_key_base64url: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
  ],
  api_keys: {
    tinfoil: { env: 'TINFOIL_API_KEY' },
  },
});
```

Inline values are rejected unless `allow_inline_api_keys: true` is explicitly
set. Environment references avoid retaining credentials in application config
objects and error logs.

## Library ownership

Close streams before closing their client: freeing a client with live streams
fails with `FFI_BUSY` and preserves the handle so it can be retried. `Stream`
cancels before freeing so a pending stream never leaks its native handle.
Strings returned by Rust are decoded and released through
`confidential_inference_string_free`.

## License

Licensed under the repository's [MIT License](../../LICENSE).
