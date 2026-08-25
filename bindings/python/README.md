# Python binding

This directory contains a source-only `ctypes` binding for the Confidential
Inference SDK C ABI. Routing, attestation, policy, digest, and signature
decisions remain in Rust.

The binding is not published to PyPI and does not currently include packaging
metadata. It must be used with a locally built
`confidential-inference-ffi` shared library.

## Requirements

- Python `3.11` or later
- Rust `1.97` or later

The binding has no third-party Python dependencies.

## Build and test

From the repository root:

```bash
cargo build -p confidential-inference-ffi --locked
python3 -m unittest discover -s bindings/python/tests
```

The binding searches the workspace `target/debug` and `target/release`
directories. Set `CONFIDENTIAL_INFERENCE_FFI_LIBRARY` to an explicit shared
library path when embedding it elsewhere.

## Example

Make `bindings/python` importable, then create a client:

```python
from confidential_inference_sdk import Client

with Client(config={"demo_provider": True}) as client:
    result = client.chat(
        {
            "model": "gpt-oss-120b",
            "messages": [{"role": "user", "content": "Verify this route."}],
        }
    )

    print(result["verdict"]["status"])
    print(result["response"]["choices"][0]["message"]["content"])
```

For example, save the snippet as `example.py` and run it from the repository
root:

```bash
PYTHONPATH=bindings/python python3 example.py
```

The demo provider uses fixture trust material and does not make a network
request.

## API

`Client` provides blocking and async Chat Completions, Responses, route
verification, model discovery, and active policy / trust-artifact inspection.
`Client.stream_async` and `Stream.events_async` expose fail-closed stream
events as async iterators. Async methods run the blocking FFI call through
`asyncio.to_thread` so they never block the event loop.

Rust owns every attestation/policy/registry/digest/signature decision; the
binding only parses the JSON that crosses the ABI and applies minimal
object/array shape checks on the way back.

## Credentials

Prefer environment-variable references:

```python
client = Client(
    config={
        "demo_provider": False,
        "api_keys": {
            "tinfoil": {"env": "TINFOIL_API_KEY"},
        },
    }
)
```

Inline values are rejected unless `allow_inline_api_keys` is explicitly set to
`True`. Environment references avoid retaining credentials in application
config dictionaries and error logs.

## Routing

An ordered provider list can be configured per canonical model:

```python
client = Client(
    config={
        "demo_provider": False,
        "api_keys": {
            "tinfoil": {"env": "TINFOIL_API_KEY"},
            "phala": {"env": "PHALA_API_KEY"},
        },
        "routing": {
            "provider_order": {
                "gpt-oss-120b": ["tinfoil", "phala"],
            }
        },
    }
)
```

Configured providers must identify active, executable, policy-compatible
routes. Unlisted providers are excluded from automatic chat selection for that
model, but explicit route verification remains available.

## Library ownership

Close streams before closing their client: freeing a client with live streams
fails with `FFI_BUSY` and preserves the handle so it can be retried. `Stream`
cancels before freeing so a pending stream never leaks its native handle.
Strings returned by Rust are decoded and released through
`confidential_inference_string_free`.

## License

Licensed under the repository's [MIT License](../../LICENSE).
