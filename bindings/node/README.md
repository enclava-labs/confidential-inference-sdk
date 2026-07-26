# Node.js binding

This directory contains a CommonJS and TypeScript binding for the
Confidential Inference SDK C ABI. Routing, attestation, and policy enforcement
remain in Rust.

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
    const result = await client.chatAsync({
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

`Client` provides:

- blocking and Promise-based Chat Completions and Responses calls;
- route verification and model discovery;
- active policy and trust-artifact inspection;
- explicit operation and stream handles;
- `AbortSignal` cancellation for Promise waits and async stream iteration.

`Operation` and `Stream` expose polling, callbacks, cancellation, and Unix
readiness file descriptors. See `index.d.ts` for the complete API.

Returned FFI payloads are validated before they are exposed to callers,
including schema versions, required fields, verdict consistency, digest and
signature metadata, model catalogs, operation states, and stream events.

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

Close clients, operations, and streams when they are no longer needed. Strings
returned by Rust are decoded and released through
`confidential_inference_string_free`.

## License

Licensed under the repository's [MIT License](../../LICENSE).
