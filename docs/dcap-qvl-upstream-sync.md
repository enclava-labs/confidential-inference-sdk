# DCAP QVL upstream review policy

Status: required review gate for a production release that claims offline
TDX/DCAP readiness.

The SDK consumes the published upstream `dcap-qvl` crate with default features
disabled and the `ring` backend selected explicitly. No verifier source is
vendored in this repository.

## Triggers

Run this review before each production release and whenever:

- the resolved `dcap-qvl` or `dcap-qvl-webpki` version changes;
- verifier, quote parser, certificate, CRL, TCB, QE identity, PCCS, PCS, or
  collateral behavior changes upstream;
- a relevant RustSec advisory is published;
- Intel changes DCAP quote or collateral validation requirements;
- enabled QVL features or resolved cryptographic backends change;
- the real evidence, malformed-input, or mutation corpus changes.

## Procedure

1. Record the upstream crate versions, source checksums, repository tag or
   commit, and workspace lockfile digest.
2. Review upstream changes affecting parsing and trust decisions.
3. Confirm the SDK still disables QVL default features and explicitly enables
   only its reviewed feature set.
4. Inspect `cargo tree -e features` for unexpected verifier, network, or
   cryptographic backends.
5. Add positive and negative fixtures for any changed verifier behavior.
6. Run the required commands below and retain their output with the release
   record.
7. Produce a canonical
   `confidential-inference.dcap-qvl-production-review.v1` artifact that binds
   to `fixtures/supply-chain/dcap-qvl-audit.json`, records the reviewed
   commands, confirms independent human security review and the required fuzz
   campaign, and has no open findings.
8. Pass that artifact to `tools/check_release_manifest.py` with
   `--dcap-production-review`.

## Required commands

```bash
cargo test -p confidential-inference-providers --test dcap_qvl_audit --locked
cargo test -p confidential-inference-attestation dcap_tdx_malformed_corpus --locked
cargo test -p confidential-inference-attestation dcap_tdx_mutation_sweep --locked
cargo test --workspace --locked
cargo deny check
cargo audit --ignore RUSTSEC-2023-0071
```

Tests are necessary but not sufficient for a production verifier claim. A
human security review of upstream drift and the resolved graph remains
mandatory.
