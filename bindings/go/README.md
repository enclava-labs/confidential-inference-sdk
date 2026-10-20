# Go binding

This directory contains a Go binding for the Confidential Inference SDK C
ABI. Routing, attestation, policy, digest, and signature decisions remain in
Rust.

The binding loads `confidential-inference-ffi` at run time with
[purego](https://github.com/ebitengine/purego), so callers do not need cgo.
It must be used with a locally built shared library and is not a standalone
registry package.

## Requirements

- Go `1.25` or later
- Rust `1.97` or later
- Linux, macOS, or Windows on amd64/arm64 (purego platforms)

## Build and test

From the repository root:

```bash
cargo build -p confidential-inference-ffi --locked
cd bindings/go
go test
```

The binding searches the workspace `target/debug` and `target/release`
directories. Set `CONFIDENTIAL_INFERENCE_FFI_LIBRARY` to an explicit shared
library path when embedding it elsewhere, or pass `WithLibraryPath`.

## Example

Run this after building the FFI library:

```go
package main

import (
	"fmt"

	confidentialinference "github.com/enclava-labs/confidential-inference-sdk/bindings/go"
)

func main() {
	// nil config installs the offline demo provider.
	client, err := confidentialinference.NewClient(nil)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	result, err := client.Chat(map[string]any{
		"model": "gpt-oss-120b",
		"messages": []map[string]any{
			{"role": "user", "content": "Verify this route."},
		},
	}, 0)
	if err != nil {
		panic(err)
	}

	verdict := result["verdict"].(map[string]any)
	fmt.Println(verdict["status"])
}
```

The demo provider uses fixture trust material and does not make a network
request.

## API

`Client` provides blocking Chat Completions (`Chat`), Responses
(`CreateResponse`/`Response`), route verification (`Verify`), model
discovery (`Models`), the confidentiality catalog (`Confidentiality`), and
active policy / trust-artifact inspection (`ActivePolicy`,
`ActiveTrustArtifacts`). `Client.Stream` and `Stream` expose fail-closed
stream events.

Timeouts are `time.Duration`; `0` waits indefinitely for inference calls and
means a non-blocking poll for `Stream.Next`. A timed-out inference call
returns an `*Error` with `Status == StatusPending`.

`Client.Stream` returns a Go 1.23 range-over-func iterator:

```go
for event, err := range client.Stream(request, 5*time.Second) {
	if err != nil {
		return err
	}
	fmt.Println(event["type"])
}
```

Errors are `*confidentialinference.Error`: `Status` carries the FFI status
code and `Code`/`Message` carry the Rust error envelope. FFI calls run on a
locked OS thread so the thread-local `last_error` is read on the thread that
produced it.

## Artifact trust

A `nil` config selects the offline/demo mode: it installs the demo provider
and trusts the bundled fixture signing keys for the bundled artifacts only.
For production configuration (`demo_provider: false`,
`trusted_ed25519_signing_keys`, environment-referenced `api_keys`), see the
[Node.js binding README](../node/README.md); the config object schema is
identical and is marshaled to JSON before crossing the ABI.

## Library ownership

Close streams before closing their client: freeing a client with live
streams fails with `StatusBusy` and preserves the handle so it can be
retried. `Stream.Close` cancels before freeing so a pending stream never
leaks its native handle. Strings returned by Rust are copied and released
through `confidential_inference_string_free`.

## License

Licensed under the repository's [MIT License](../../LICENSE).
