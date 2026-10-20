# Confidential Inference SDK

[![CI](https://github.com/enclava-labs/confidential-inference-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/enclava-labs/confidential-inference-sdk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A fail-closed Rust SDK for sending OpenAI-compatible inference requests only
after the selected route satisfies an explicit attestation policy.

## Supported providers

**Tinfoil · Venice · RedPill (Chutes E2EE) · Phala · Chutes · NEAR · Privatemode**

| Provider | SDK integration | Current scope |
| --- | --- | --- |
| **Tinfoil** | Dedicated HTTP adapter, attestation endpoint capture, TLS certificate/SPKI binding, and TDX/DCAP quote verification | Live adapter and verifier path |
| **Venice** | OpenAI-compatible HTTP execution, dstack evidence normalization, and SDK-managed app-E2EE | Live adapter and evidence path |
| **RedPill** | OpenAI-compatible HTTP execution, Chutes E2EE evidence, nonce/public-key report-data binding, and NVIDIA CC verification through NRAS | Live adapter and evidence path (claims matched against signed reference values; the TDX quote signature is not verified on this family, so the default policy rejects its CPU evidence — set the CPU requirement to not required to use the app-E2EE checks) |
| **Phala** | OpenAI-compatible HTTP execution, dstack evidence normalization, and SDK-managed app-E2EE | Live adapter and evidence path |
| **Chutes** | Dedicated ML-KEM-768/ChaCha20-Poly1305 E2EE adapter, per-instance TDX/certificate/key binding, DCAP verification, and NVIDIA CC verification through NRAS | Live non-streaming adapter and verifier path |
| **NEAR** | Model-direct adapter with same-connection TLS certificate capture, TDX nonce/signing-address/TLS/model binding, DCAP verification, and NVIDIA CC verification through NRAS | Live non-streaming adapter and verifier path |
| **Privatemode** | Contrast manifest, initdata, image-pin, coordinator-attestation, and model-path verification | Verification component; the caller supplies live transport |

Tinfoil, Venice, RedPill, Phala, Chutes, and NEAR have provider-specific HTTP
integrations. The Tinfoil adapter validates TLS certificates normally and
additionally binds the observed leaf SPKI into the verified quote. Chutes
invocations are encrypted for the selected attested instance and consume
one-use invocation nonces. NEAR requests use the model-direct TLS connection
whose leaf-certificate SPKI was bound into the verified quote. Privatemode
support covers verification of Contrast deployment evidence rather than a
turn-key HTTP adapter.

Provider support does not make an arbitrary deployment trusted. Production
routes still require provider-issued signed metadata and reference values, the
applicable quote or GPU verifier, and a successful credentialed conformance
run. Provider names that appear only in model-alias or compatibility fixtures
are not supported live integrations.

The SDK combines provider routing, signed provider metadata, reference values,
hardware-evidence verification, request and response protection, and structured
attestation verdicts. Rust owns the trust decisions; the C, Python, Node.js, and
Go layers call the same verification path.

Artifact trust is explicit. The bundled fixture signing keys open only the
bundled demo and fixture artifacts, and only when the caller opts in with
`with_demo_provider()`. Production callers configure an operator-controlled
trust root with
`ConfidentialInferenceBuilder::exclusive_trusted_artifact_signing_keys`
(or append operator keys with `trusted_artifact_signing_key` /
`trusted_ed25519_artifact_signing_key`, which never add fixture keys). Remote
and custom registry/reference-value artifacts always verify against the
operator key set only; the bundled fixture keys cannot rescue a
fixture-signed remote or custom body.

> [!IMPORTANT]
> This is a `0.1.0` preview. The offline verification paths and deterministic
> demo are extensively tested. Production use still requires
> operator-controlled trust roots, provider-published artifacts, credentialed
> live-conformance checks, and the verifier backends required by each route.

## Capabilities

- Fail-closed policy enforcement before a provider request is sent.
- Signed provider registries, compatibility profiles, and reference values.
- Offline Intel TDX/DCAP quote verification with supplied collateral.
- Evidence paths for dstack, Chutes/Redpill, Chutes live, NEAR live, Tinfoil,
  and Privatemode.
- SDK-managed app-E2EE for compatible routes and adapter-managed Chutes E2EE.
- OpenAI-shaped Chat Completions and a text-only Responses compatibility path.
- Structured verdicts, persisted verdict records, metrics, and optional verdict caching.
- Rust, C ABI, Python, Node.js, Go, and proxy integration surfaces.

A provider name or model alias is never treated as proof. Authorization depends
on signed route metadata, verified evidence, reference values, policy, and the
request and response channel properties.

## Current status

| Area | Status |
| --- | --- |
| Offline demo and adversarial corpus | Ready |
| Rust, FFI, Python, Node.js, and Go tests | Ready |
| Signed registry and reference-value validation | Ready |
| Intel TDX/DCAP offline verification | Implemented; production review still required |
| Live provider execution | Provider- and deployment-specific |
| SEV-SNP production verification | Genoa Tinfoil v2 reports verified; model binding unsupported |
| API stability | Preview; breaking changes may occur before `1.0` |

See [development status](docs/development-status.md) for current limitations
and release requirements.

## Requirements

- Rust `1.97` or later; `rust-toolchain.toml` selects the current stable channel
- Python `3.11` or later for the repository tools and Python binding
- Node.js `22` or later for the Node.js binding
- Go `1.25` or later for the Go binding

## Build and run

Clone the repository and run the small offline example:

```bash
git clone https://github.com/enclava-labs/confidential-inference-sdk.git
cd confidential-inference-sdk
cargo run -p confidential-inference-sdk --example offline_demo --locked
```

The deterministic demo runs one verified chat completion against the fixture
provider (its integration surface — failures, proxy, FFI, bindings — is
covered by the workspace tests):

```bash
cargo run -p confidential-demo --locked
```

Neither command needs API keys or network access. Both use fixture trust
material and prove SDK behavior, not the trustworthiness of a live provider.

## Use as a Rust dependency

The `0.1.0` crates are not published to crates.io and no git tag exists yet.
A reproducible build pins a commit `rev` until a release tag is published:

```toml
[dependencies]
confidential-inference-sdk = { git = "https://github.com/enclava-labs/confidential-inference-sdk", rev = "a903676" }
confidential-inference-openai = { git = "https://github.com/enclava-labs/confidential-inference-sdk", rev = "a903676" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use confidential_inference_openai::ChatMessage;
use confidential_inference_sdk::ConfidentialInference;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Demo provider: the only configuration that trusts the bundled fixture
    // signing keys. Production clients instead configure
    // exclusive_trusted_artifact_signing_keys and their own sources.
    let client = ConfidentialInference::builder()
        .with_demo_provider()
        .build()
        .await?;

    let result = client
        .chat_completions()
        .model("gpt-oss-120b")
        .message(ChatMessage::user("Explain why this route is trusted."))
        .send()
        .await?;

    println!("status: {:?}", result.verdict.status);
    println!("response: {}", result.response.choices[0].message.content);
    Ok(())
}
```

For incremental output, use a configured streaming-enabled route that does not
require request/response E2EE (the demo E2EE route intentionally fails closed).
Call `.stream(true).streaming().await`. The returned stream includes the
verified `verdict` and route metadata before the first chunk:

```rust
let mut stream = client
    .chat_completions()
    .model("gpt-oss-120b")
    .message(ChatMessage::user("Explain this route."))
    .stream(true)
    .streaming()
    .await?;

println!("status: {:?}", stream.verdict.status);
while let Some(chunk) = stream.next().await {
    let chunk = chunk?;
    if let Some(content) = chunk.choices.first().and_then(|choice| choice.delta.content.as_ref()) {
        print!("{content}");
    }
}
// A terminal usage frame is optional; None means usage is unknown.
if let Some(usage) = stream.terminal_usage {
    println!("usage: {usage:?}");
}
```

For Responses lifecycle operations, `ConfidentialInference::manage_response`
takes a provider and a `ResponseManageRequest` (`op`, `provider_response_id`,
and `params`); the operation is covered by the same verified-route and
structured error handling as inference calls. The C ABI and language bindings
accept `{op, provider, provider_response_id, params}`.
The FFI and language bindings emit a `verdict` event first, then normalized
OpenAI chunk JSON in each `chunk` event, optional terminal `usage`, and `done`.
They do not expose provider SSE framing directly.

Streaming is fail-closed for routes requiring request or response E2EE. If the
provider omits terminal usage, the SDK reports `terminal_usage: None`; callers
must treat usage as unknown, not zero.

The Python, Node.js, and Go bindings currently build against the workspace
FFI library and are not standalone registry packages. See the
[Python binding](bindings/python/README.md),
[Node.js binding](bindings/node/README.md), and
[Go binding](bindings/go/README.md) instructions.

## Production integration

A production client supplies:

1. An enforcement policy matching the application's confidentiality and
   integrity requirements.
2. An operator-controlled trust root via
   `exclusive_trusted_artifact_signing_keys`, plus signed provider registry
   and reference-value artifacts. The bundled fixture keys are never trusted
   for remote or custom artifacts.
3. Provider credentials through environment-backed secret handling.
4. Quote, GPU, and collateral verifiers required by the enabled routes.
5. A verdict store and metrics observation appropriate for the deployment
   (metrics are emitted as `tracing` events; attach any exporter you want).

Metric events use the `confidential_inference.metrics` target. Collect that
target in an exporter or filter it from normal application logs; high-frequency
cache and single-flight events are emitted at `DEBUG`.

The builder rejects incomplete or weakening trust configuration. Production
release qualification additionally requires the signed live-conformance and
DCAP review artifacts described in
[development status](docs/development-status.md#production-prerequisites).

## Workspace

| Package | Purpose |
| --- | --- |
| `confidential-inference-sdk` | High-level async client and policy enforcement |
| `confidential-inference-attestation` | Evidence, policy, signature, and verdict primitives |
| `confidential-inference-providers` | Provider registry, adapters, and DCAP collateral support |
| `confidential-inference-openai` | Provider-neutral OpenAI request and response types |
| `confidential-inference-proxy` | Optional OpenAI-compatible proxy primitives |
| `confidential-inference-ffi` | C ABI used by the language bindings |

TDX verification uses upstream `dcap-qvl` with default features disabled and
the `ring` backend selected explicitly. The rationale is documented in
[DCAP QVL dependency](docs/dcap-qvl-dependency.md).

## Documentation

- [Development status and limitations](docs/development-status.md)
- [Attestation hardening contracts](docs/attestation-hardening.md)
- [DCAP QVL dependency decision](docs/dcap-qvl-dependency.md)
- [DCAP QVL dependency audit](docs/dcap-qvl-audit.md)
- [DCAP QVL upstream review policy](docs/dcap-qvl-upstream-sync.md)
- [Fixture inventory](fixtures/README.md)

## Verification

The primary offline gates are:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 -m unittest discover -s tools -p 'test_*.py'
python3 -m unittest discover -s bindings/python/tests
(cd bindings/node && npm ci && npm test)
(cd bindings/go && go test -race -count=1 ./...)
python3 tools/check_release_packaging.py
```

Credentialed Chutes and NEAR attestation checks can load the ignored local
`.env` directly:

```bash
python3 tools/live_conformance.py \
  --env-file .env \
  --allow-network \
  --enable-provider chutes \
  --enable-provider near \
  --timeout-seconds 60 \
  --output target/chutes-near-live-conformance.json
```

These checks perform model discovery and fetch provider evidence shapes. They
do not submit an inference request or consume inference balance. Run the
ignored Rust live tests for the stronger provider-specific capture, NRAS, and
TDX/DCAP gate:

```bash
cargo test -p confidential-inference-providers \
  --test live_chutes_near \
  --locked \
  -- --ignored --test-threads=1
```

The Rust live tests load `CHUTES_API_KEY` and `NEAR_API_KEY` from the process
environment or the ignored workspace `.env`. A passing result proves the live
cryptographic evidence path; production inference additionally requires an
operator-trusted signed registry and reference values. A positive provider
balance is needed only when the provider charges for the inference request,
not for these evidence-verification calls.

Supply-chain gates:

```bash
cargo deny check
cargo audit --ignore RUSTSEC-2023-0071
python3 tools/check_supply_chain_policy.py
```

The Cargo Audit exception is limited to upstream webpki's optional
`rsa 0.9.10` lockfile metadata. `cargo tree --target all -i rsa` is empty, so
RSA is not compiled for any SDK target. See
[DCAP QVL dependency](docs/dcap-qvl-dependency.md#remaining-upstream-metadata).

## Security

Do not weaken a policy to make an unsupported provider route executable. Treat
attestation policy, signing keys, registry artifacts, reference values, and
collateral as security-critical configuration.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Do not open a public issue for an undisclosed vulnerability.

## License

Licensed under the [MIT License](LICENSE). Copied third-party fixture data is
listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); dependencies remain
subject to their own licenses.
