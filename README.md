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
| **RedPill** | OpenAI-compatible HTTP execution, Chutes E2EE evidence, nonce/public-key report-data binding, and NVIDIA CC verification through NRAS | Live adapter and verifier path |
| **Phala** | OpenAI-compatible HTTP execution, dstack evidence normalization, and SDK-managed app-E2EE | Live adapter and evidence path |
| **Chutes** | Dedicated ML-KEM-768/ChaCha20-Poly1305 E2EE adapter, per-instance TDX/certificate/key binding, DCAP verification, and NVIDIA CC verification through NRAS | Live non-streaming adapter and verifier path |
| **NEAR** | Model-direct adapter with same-connection TLS certificate capture, TDX nonce/signing-address/TLS/model binding, DCAP verification, and NVIDIA CC verification through NRAS | Live non-streaming adapter and verifier path |
| **Privatemode** | Contrast manifest, initdata, image-pin, coordinator-attestation, and model-path verification | Verification component; the caller supplies live transport |

Tinfoil, Venice, RedPill, Phala, Chutes, and NEAR have provider-specific HTTP
integrations. Chutes invocations are encrypted for the selected attested
instance and consume one-use invocation nonces. NEAR requests use the
model-direct TLS connection whose leaf-certificate SPKI was bound into the
verified quote. Privatemode support covers verification of Contrast deployment
evidence rather than a turn-key HTTP adapter.

Provider support does not make an arbitrary deployment trusted. Production
routes still require provider-issued signed metadata and reference values, the
applicable quote or GPU verifier, and a successful credentialed conformance
run. Provider names that appear only in model-alias or compatibility fixtures
are not supported live integrations.

The SDK combines provider routing, signed provider metadata, reference values,
hardware-evidence verification, request and response protection, and structured
attestation verdicts. Rust owns the trust decisions; the C, Python, and Node.js
layers call the same verification path.

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
- Structured verdicts, audit records, metrics, and optional verdict caching.
- Rust, C ABI, Python, Node.js, middleware, and proxy integration surfaces.

A provider name or model alias is never treated as proof. Authorization depends
on signed route metadata, verified evidence, reference values, policy, and the
request and response channel properties.

## Current status

| Area | Status |
| --- | --- |
| Offline demo and adversarial corpus | Ready |
| Rust, FFI, Python, and Node.js tests | Ready |
| Signed registry and reference-value validation | Ready |
| Intel TDX/DCAP offline verification | Implemented; production review still required |
| Live provider execution | Provider- and deployment-specific |
| SEV-SNP production verification | Not supported |
| API stability | Preview; breaking changes may occur before `1.0` |

See [development status](docs/development-status.md) for current limitations
and release requirements.

## Requirements

- Rust `1.97` or later; `rust-toolchain.toml` selects the current stable channel
- Python `3.11` or later for the repository tools and Python binding
- Node.js `22` or later for the Node.js binding

## Build and run

Clone the repository and run the small offline example:

```bash
git clone https://github.com/enclava-labs/confidential-inference-sdk.git
cd confidential-inference-sdk
cargo run -p confidential-inference-sdk --example offline_demo --locked
```

The full deterministic demo exercises the wider integration surface:

```bash
set -o pipefail
cargo run -p confidential-demo --locked | tee target/confidential-demo.out
python3 tools/check_demo_output.py target/confidential-demo.out
```

Neither command needs API keys or network access. Both use fixture trust
material and prove SDK behavior, not the trustworthiness of a live provider.

## Use as a Rust dependency

The `0.1.0` crates are not yet published to crates.io. For initial testing, use
the Git repository:

```toml
[dependencies]
confidential-inference-sdk = { git = "https://github.com/enclava-labs/confidential-inference-sdk", branch = "main" }
confidential-inference-openai = { git = "https://github.com/enclava-labs/confidential-inference-sdk", branch = "main" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Replace `branch = "main"` with a release `tag` or `rev` before relying on the
dependency in a reproducible build.

```rust
use confidential_inference_openai::ChatMessage;
use confidential_inference_sdk::ConfidentialInference;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

The Python and Node.js bindings currently build against the workspace FFI
library and are not standalone registry packages. See the
[Python binding](bindings/python/README.md) and
[Node.js binding](bindings/node/README.md) instructions.

## Production integration

A production client supplies:

1. An enforcement policy matching the application's confidentiality and
   integrity requirements.
2. Trusted signing keys and signed provider registry and reference-value
   artifacts.
3. Provider credentials through environment-backed secret handling.
4. Quote, GPU, and collateral verifiers required by the enabled routes.
5. Audit, verdict, and metrics sinks appropriate for the deployment.

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
| `confidential-inference-middleware` | Middleware integration helpers |
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
