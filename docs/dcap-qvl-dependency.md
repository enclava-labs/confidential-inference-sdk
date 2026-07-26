# DCAP QVL dependency

## Decision

The SDK depends directly on the upstream `dcap-qvl` crate and does not maintain
or publish a source fork.

The workspace currently selects:

- `dcap-qvl` `0.6.1`
- default features disabled
- `std`, `ring`, and `default-x509` enabled
- `report` additionally enabled by the provider crate that fetches collateral

## Why no fork is needed

An earlier local fork kept `dcap-qvl 0.4.0` compatible with Rust 1.75.
Upstream used `slice::split_at_checked`, stabilized in Rust 1.80, and its open
dependency ranges could resolve packages unsupported by Cargo 1.75.

The SDK now requires Rust 1.97 or later and follows the stable toolchain selected
by `rust-toolchain.toml`. The compatibility patch therefore has no remaining
purpose.

The former webpki fork only removed optional cryptographic backends; it did not
fix verifier behavior used by the SDK. Maintaining that fork would make the SDK
responsible for tracking security-sensitive upstream parsing and certificate
validation code without changing the runtime path. Upstream feature selection
and a locked dependency graph provide the required backend control with less
maintenance risk.

## Remaining upstream metadata

`dcap-qvl-webpki` declares an optional RustCrypto RSA backend. Cargo records
`rsa 0.9.10` in `Cargo.lock`, so Cargo Audit sees RUSTSEC-2023-0071 even though
the SDK selects `ring`.

```bash
cargo tree --target all -i rsa
```

The command prints no reverse dependency tree: RSA is not enabled or compiled
for any SDK target. Removing the lockfile entry would require an upstream
webpki release that drops the optional dependency or another local fork. The
SDK keeps the narrowly scoped Cargo Audit exception and verifies the active
graph instead.

## Release policy

Upstream DCAP changes remain security-sensitive. Before a production release:

1. Review changes in `dcap-qvl`, `dcap-qvl-webpki`, quote parsing, certificate
   validation, collateral handling, and cryptographic backend selection.
2. Run the real quote/collateral corpus, malformed corpus, and mutation sweep.
3. Run RustSec, license, source, and dependency policy checks.
4. Record the exact upstream versions and lockfile used for the release.
5. Require the production DCAP review artifact described in
   `dcap-qvl-upstream-sync.md`.
