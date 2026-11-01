# Contributing

## Offline checks

Run everything at once (skips optional steps whose toolchains are missing):

```bash
tools/run_offline_gates.sh
```

The individual gates, in dependency order (bindings load the FFI library, so
build it first; `--require-clean` needs a committed tree):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.97 check --workspace --locked --all-targets   # MSRV
cargo run -p confidential-demo --locked
cargo +nightly fuzz build                            # after installing pinned cargo-fuzz
python3 tools/check_normative_fixtures.py
python3 tools/check_ffi_exports.py
python3 -m unittest discover -s tools -p 'test_*.py'
python3 -m unittest discover -s bindings/python/tests
cargo build -p confidential-inference-ffi --locked
(cd bindings/node && npm ci && npm test)
(cd bindings/go && go test -race -count=1 ./...)
cargo deny check
cargo audit
python3 tools/check_supply_chain_policy.py
python3 tools/check_release_packaging.py --require-clean
python3 tools/generate_sbom.py --output target/confidential-inference-sbom.json
python3 tools/generate_sbom.py --output target/confidential-inference-sbom.json --check
```

The minimum supported Rust version is the workspace `rust-version` (`1.97`).
CI additionally runs the Node.js and Go binding suites on macOS and Windows,
and the release-manifest policy checks in `.github/workflows/ci.yml`.

Do not run the ignored live provider tests (`--test live_chutes_near`) or any
network-dependent conformance tooling unless you are intentionally validating
against real deployments with your own credentials.

## Fixture policy

Public attestation captures that contain no secrets may be committed as
fixtures when their provenance is documented in
[fixtures/README.md](fixtures/README.md) (for example
`fixtures/evidence/sev-snp/`). Never commit credentials, API keys, or
bearer tokens — not even expired ones — and never commit live provider
evidence captures that embed them.

## Trust material

The bundled fixture signing keys exist only so the offline demo and fixture
tests verify. Never extend their implicit trust, and never commit secrets,
credentials, or live provider evidence captures.

## Security reports

Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Do not open a public issue for an undisclosed
vulnerability.
