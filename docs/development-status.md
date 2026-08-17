# Development status

The SDK is a `0.1.0` preview. Its offline verification paths, local demo, and
language bindings are covered by CI. Production deployments still need
operator-controlled trust material and live validation for every enabled
provider route.

## Implemented

| Area | Current state |
| --- | --- |
| Policy enforcement | Fail-closed route selection and send-time revalidation |
| Trust artifacts | Signed provider registries, compatibility profiles, and reference values |
| Intel TDX/DCAP | Offline quote verification with caller-supplied collateral |
| Provider evidence | dstack, Chutes/Redpill, Chutes live, NEAR live, Tinfoil, and Privatemode adapter and verifier paths |
| Request protection | SDK-managed app-E2EE plus Chutes adapter-managed ML-KEM-768/ChaCha20-Poly1305 |
| Response integrity | Verdict and receipt binding where the selected route supports it |
| OpenAI API shapes | Chat Completions and a text-only Responses compatibility path |
| Integrations | Rust, C ABI, Python, Node.js, and proxy surfaces |
| Release tooling | Package verification, SBOM, checksums, detached signatures, and policy checks |

The deterministic demo exercises verified fixture routes, failure cases,
proxy, FFI, bindings, verdict records, and metrics without using
external credentials. Fixture success demonstrates SDK behavior; it does not
establish that a live provider deployment is trustworthy.

## Production prerequisites

A production deployment must provide and review:

- trusted signing keys and provider-published registry and reference-value
  artifacts;
- a policy that matches the application's confidentiality and integrity
  requirements;
- quote, GPU, and collateral verification backends required by each selected
  route;
- credentialed live-conformance results for every enabled provider;
- audit, verdict, metrics, secret-handling, and key-rotation procedures;
- an independent review of changes to the TDX/DCAP verification dependency and
  its resolved cryptographic backends.

The release-manifest checker can require a signed, credentialed live-conformance
report and a production DCAP review artifact. A network-disabled dry run or the
CI fixture signing key cannot satisfy that production gate.

## Known limitations

- SEV-SNP does not have a production-supported verifier backend.
- The checked-in provider compatibility profiles include executable Chutes and
  NEAR transport profiles, but they are not substitutes for a signed live
  provider registry and signed deployment reference values.
- Chutes and NEAR confidential streaming is not yet supported. Their live
  adapters reject streaming instead of weakening the verified channel.
- Live provider routes require provider-issued trust artifacts and real evidence
  captures; the checked-in fixtures are not substitutes.
- Confidential streaming is rejected for the current profiles rather than
  silently weakening request or response guarantees.
- The Responses API support is a text-only compatibility shim over the same
  verified execution path.
- The Python and Node.js bindings are source bindings over the Rust shared
  library. They are not published as standalone registry packages.
- Public APIs and schemas may change before `1.0`.

## Release checks

CI runs the following offline gates:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked --quiet
cargo run -p confidential-demo --locked
python3 tools/check_normative_fixtures.py
python3 tools/check_ffi_exports.py
python3 -m unittest discover -s bindings/python/tests
(cd bindings/node && npm ci && npm test)
cargo deny check
cargo audit --ignore RUSTSEC-2023-0071
python3 tools/check_supply_chain_policy.py
python3 tools/check_release_packaging.py
python3 -m unittest discover -s tools -p 'test_*.py'
```

The complete workflow, including SBOM and release-manifest checks, is in
`.github/workflows/ci.yml`.

See `dcap-qvl-upstream-sync.md` for the additional review required when
shipping the TDX/DCAP path.
