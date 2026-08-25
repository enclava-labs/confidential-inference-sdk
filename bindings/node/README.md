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

The binding searches the workspace `target/debug` and `target/release`
directories. Set `CONFIDENTIAL_INFERENCE_FFI_LIBRARY` to an explicit shared
library path when embedding it elsewhere.

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

`Client` provides Promise-based Chat Completions, Responses, route
verification, model discovery, and active policy / trust-artifact inspection.
`Client.stream` and `Stream` expose fail-closed stream events as async
iterables. See `index.d.ts` for the complete API.

Inference methods run the blocking FFI call on a Koffi worker thread, so they
do not block the Node event loop. Rust owns every
attestation/policy/registry/digest/signature decision; the binding only
parses the JSON that crosses the ABI and applies minimal object/array shape
checks on the way back. The process-wide Koffi pool accepts up to 32 concurrent
native calls; apply backpressure before that limit for larger fan-outs.

## Credentials

Prefer environment-variable references:

```js
const client = new Client({
  demo_provider: false,
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
