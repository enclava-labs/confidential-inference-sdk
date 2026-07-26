# DCAP QVL dependency audit

Status: lockfile- and fixture-backed audit baseline for the upstream TDX/DCAP
verification path.

The SDK does not vendor or publish DCAP forks. The audit protects:

- the exact upstream QVL dependency and explicitly selected features;
- the upstream review policy;
- the real TDX quote and collateral fixtures;
- the malformed-input and deterministic mutation corpora;
- the workspace lockfile used for release verification.

The authoritative audit fixture is
`fixtures/supply-chain/dcap-qvl-audit.json`. The integration test
`crates/confidential-inference-providers/tests/dcap_qvl_audit.rs`
verifies its file hashes and manifest invariants.

Changing the QVL version, enabled features, reviewed evidence, or lockfile
requires refreshing the audit fixture and following
`docs/dcap-qvl-upstream-sync.md`.
