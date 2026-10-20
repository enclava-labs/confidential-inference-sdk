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
| Provider evidence | dstack, Chutes/Redpill (app-E2EE only; the TDX quote signature is not verified on this family), Chutes live, NEAR live, Tinfoil, and Privatemode adapter and verifier paths |
| Request protection | SDK-managed app-E2EE plus Chutes adapter-managed ML-KEM-768/ChaCha20-Poly1305 |
| Response integrity | Verdict and receipt binding where the selected route supports it |
| OpenAI API shapes | Chat Completions and a text-only Responses compatibility path |
| Integrations | Rust, C ABI, Python, Node.js, and proxy surfaces |
| Release tooling | Package verification, SBOM, checksums, detached signatures, and policy checks |

The demo binary performs a single verified offline chat against the fixture
provider without external credentials. The wider integration surface —
failure cases, proxy, FFI, bindings, verdict records, and metrics — is covered
by the workspace tests and binding test suites in CI. Fixture success
demonstrates SDK behavior; it does not establish that a live provider
deployment is trustworthy.

## Production prerequisites

A production deployment must provide and review:

- an operator-controlled trust root via
  `exclusive_trusted_artifact_signing_keys` — the bundled fixture signing keys
  are never trusted implicitly and cannot verify remote or custom artifacts;
- provider-published registry and reference-value artifacts signed by that
  trust root;
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

- Artifact trust is explicit: there is no implicit fixture-key trust. The
  bundled fixture keys apply to bundled artifacts only, and only after an
  explicit `with_demo_provider()` opt-in. Remote, custom, cached, and fetched
  artifacts verify against the operator key set alone.
- The RedPill (`chutes_e2ee`) evidence path does not verify the TDX quote
  signature, so the default policy rejects its CPU evidence (`cpu_tee` fails
  closed). Setting the CPU requirement to `NotRequired` keeps the app-E2EE
  checks usable; the trust tier stays capped below `HwVerifiedTls`.
  Live Tinfoil SEV-SNP v2 verification is implemented for Genoa reports with
  pinned AMD ARK/ASK trust, VCEK resolution, report signature and policy
  checks. SNP verifies router identity and TLS binding, not a model claim;
  the operator pin marks model binding unsupported and opts into the
  provider-conditional policy.
- The checked-in provider compatibility profiles include executable Chutes and
  NEAR transport profiles, but they are not substitutes for a signed live
  provider registry and signed deployment reference values.
- Chutes and NEAR confidential streaming is not yet supported. Their live
  adapters reject streaming instead of weakening the verified channel.
- The live Chutes/NEAR conformance checks remain ignored local tests that load
  credentials from the process environment or the workspace `.env`; they are
  not run in CI.
- Live provider routes require provider-issued trust artifacts and real evidence
  captures; the checked-in fixtures are not substitutes.
- Confidential streaming is rejected for the current profiles rather than
  silently weakening request or response guarantees.
- The Responses API support is a text-only compatibility shim over the same
  verified execution path.
- The Python and Node.js bindings are source bindings over the Rust shared
  library. They are not published as standalone registry packages.
- The minimum supported Rust version is `1.97` (the workspace `rust-version`);
  CI runs `cargo +1.97 check --workspace --locked --all-targets` for it.
- macOS and Windows CI coverage builds `confidential-inference-ffi` and runs
  the Node.js binding tests only; the full workspace suite runs on Ubuntu.
- The `fuzz/` cargo-fuzz target (`dcap_quote_parse`) is compiled in CI so the
  harness keeps building, but no production fuzz campaign has been run; one
  remains required before release.
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
