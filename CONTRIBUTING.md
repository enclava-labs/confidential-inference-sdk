# Contributing

## Offline checks

Every change must pass the offline gates from the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 -m unittest discover -s tools -p 'test_*.py'
python3 -m unittest discover -s bindings/python/tests
cargo build -p confidential-inference-ffi --locked
(cd bindings/node && npm ci && npm test)
```

The minimum supported Rust version is the workspace `rust-version` (`1.97`);
CI checks `cargo +1.97 check --workspace --locked --all-targets`.

Do not run the ignored live provider tests (`--test live_chutes_near`) or any
network-dependent conformance tooling unless you are intentionally validating
against real deployments with your own credentials.

## Trust material

The bundled fixture signing keys exist only so the offline demo and fixture
tests verify. Never extend their implicit trust, and never commit secrets,
credentials, or live provider evidence captures.

## Security reports

Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Do not open a public issue for an undisclosed
vulnerability.
