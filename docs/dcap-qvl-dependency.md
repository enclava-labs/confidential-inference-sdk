# DCAP QVL dependency

## Decision

The SDK depends directly on the upstream `dcap-qvl` crate and does not maintain
or publish a source fork.

The workspace currently selects:

- `dcap-qvl` `0.6.6` (resolved in `Cargo.lock`; the `0.6.1` requirement selects it)
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

## Lockfile hygiene

`rsa` no longer appears in `Cargo.lock`, so no Cargo Audit exception is
required. `cargo audit` runs unfiltered in CI.

## Release policy

Upstream DCAP changes remain security-sensitive. Before a production release:

1. Review changes in `dcap-qvl`, `dcap-qvl-webpki`, quote parsing, certificate
   validation, collateral handling, and cryptographic backend selection.
2. Run the real quote/collateral corpus, malformed corpus, and mutation sweep.
3. Run RustSec, license, source, and dependency policy checks.
4. Record the exact upstream versions and lockfile used for the release.
5. Require the production DCAP review artifact described in
   `dcap-qvl-upstream-sync.md`.
