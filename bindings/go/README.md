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

The binding searches the workspace `target/release` and `target/debug`
directories (release first; the working directory is never searched). Set
`CONFIDENTIAL_INFERENCE_FFI_LIBRARY` to an explicit shared library path when
embedding it elsewhere, or pass `WithLibraryPath`; an explicit path is
exclusive and must exist.

This module is tagged `bindings/go/vX.Y.Z`. Consumers fetching it from the
Go module cache have no repository `target/` tree — they MUST set
`CONFIDENTIAL_INFERENCE_FFI_LIBRARY` or use `WithLibraryPath`.

The binding requires FFI ABI version 1 and rejects libraries reporting a different version.

## Example

Run this after building the FFI library:

```go
package main

import (
	"encoding/json"
	"fmt"

	confidentialinference "github.com/enclava-labs/confidential-inference-sdk/bindings/go"
)

func main() {
	// Explicit demo opt-in: demo_provider defaults to false and a nil/empty
	// config fails closed with trusted_signing_keys_required.
	client, err := confidentialinference.NewClient(json.RawMessage(`{"demo_provider":true}`))
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

`Client` provides blocking Chat Completions (`Chat`), embeddings
(`Embeddings`), Responses (`CreateResponse`/`Response`), lifecycle operations
(`ResponseManage`), route verification (`Verify`), model discovery (`Models`),
the confidentiality catalog (`Confidentiality`), and active policy /
trust-artifact inspection (`ActivePolicy`, `ActiveTrustArtifacts`). `Client.Stream` yields every native
event as it arrives. The demo and other non-plaintext routes that cannot
stream fail closed with a structured error event.
Embedding requests may use text or token IDs. Token IDs are encrypted with the
request on supported E2EE routes; an adapter that cannot encrypt them may pass
them through only on a plaintext-compatible route. Otherwise the SDK fails
closed.

`ResponseManage` accepts the lifecycle envelope `{op, provider, provider_response_id, params}`.
Supported `op` values are `retrieve`, `list_input_items`, `cancel`, `delete`,
`input_tokens`, and `compact`.

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

`nil` config fails closed (`demo_provider` defaults to `false`): the offline
demo mode requires an explicit `{"demo_provider":true}` opt-in. It installs
the demo provider and trusts the bundled fixture signing keys for the
bundled artifacts only.

Clients create a private Tokio runtime. Create them **after** `fork()`:
handles used in a forked child fail with `client_used_after_fork`.

For production, use `NewConfiguredClient` with an exclusive operator public
key and signed envelopes. The Go `Config` fields map directly to the FFI
JSON names: `DemoProvider` (`*bool`, omitted means `false` — demo is opt-in),
`TrustedEd25519SigningKeys`, `APIKeys` (environment reference or inline
`APIKeyConfig`), `AllowInlineAPIKeys`, `Registry`, `ReferenceValues`,
`CompatibilityMatrix`, and `Routing`. Keep provider credentials in environment
variables where possible:

```go
package main

import (
	"log"
	"os"

	confidentialinference "github.com/enclava-labs/confidential-inference-sdk/bindings/go"
)

func main() {
	registryEnvelopeJSON, err := os.ReadFile("registry-envelope.json")
	if err != nil {
		log.Fatal(err)
	}
	referenceValuesEnvelopeJSON, err := os.ReadFile("reference-values-envelope.json")
	if err != nil {
		log.Fatal(err)
	}

	demo := false
	client, err := confidentialinference.NewConfiguredClient(confidentialinference.Config{
		DemoProvider: &demo,
		TrustedEd25519SigningKeys: []confidentialinference.TrustedSigningKey{{
			Signer: "my-operator",
			KeyID: "operator-ed25519-2026",
			PublicKeyBase64URL: "YOUR_OPERATOR_PUBLIC_KEY_BASE64URL",
		}},
		APIKeys: map[string]confidentialinference.APIKeyConfig{
			"tinfoil": {Env: "TINFOIL_API_KEY"},
		},
		Registry: registryEnvelopeJSON,
		ReferenceValues: referenceValuesEnvelopeJSON,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
```

`Registry` and `ReferenceValues` are `json.RawMessage` signed envelope objects;
they must be present together, cannot be used with `demo_provider: true`, and
are verified by Rust against `TrustedEd25519SigningKeys`. `CompatibilityMatrix`
is a `json.RawMessage` signed provider-compatibility-matrix envelope and is
verified against the same trust roots. `Routing` is also `json.RawMessage`
containing the SDK routing object. Inline API keys require
`AllowInlineAPIKeys: true`. `NewClient(json.RawMessage)` remains available for
callers needing complete control of the JSON.

## Library ownership

Close streams before closing their client: freeing a client with live
streams fails with `StatusBusy` and preserves the handle so it can be
retried. `Stream.Close` cancels before freeing so a pending stream never
leaks its native handle. Strings returned by Rust are copied and released
through `confidential_inference_string_free`.

## License

Licensed under the repository's [MIT License](../../LICENSE).
