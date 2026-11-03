# DCAP QVL upstream review policy

Status: required review gate for a production release that claims offline
TDX/DCAP readiness.

The SDK consumes the published upstream `dcap-qvl` crate with default features
disabled and the `ring` backend selected explicitly. No verifier source is
vendored in this repository.

## Review log

### 2026-11-03 — dcap-qvl 0.6.6 → 0.7.0

Resolved dependency graph after the upgrade:

- `dcap-qvl` 0.7.0 (registry checksum
  `b992c9511adf7135ae7c63c023c9303a3615c0f38d7b39514dcc262f91c6adda`),
  upstream commit `94208e2753a854191759e493ca5892be482ad453` (tag `v0.7.0`);
- `dcap-qvl-webpki` 0.103.15+dcap.1, unchanged: both 0.6.6 and 0.7.0 pin
  `=0.103.15`, so the reviewed webpki backend is retained across the upgrade.

Reviewed upstream changes (source diff of the published crates, not only the
release notes):

- **Quote v5 body type 4 (TDX 1.5ex, `TDReport15Ex`, 885 bytes).** The
  `Report` enum gained a `TD15Ex` variant; `as_td10()`/`as_td15()` reach
  through it, and the parser now rejects a v5 quote whose declared body size
  does not match the body type's struct size ("Invalid body size"). The
  extension fields (vmid, td_id, service-TD hashes, initial TCB) sit inside
  the signed region but are not appraised. The SDK's `tdx_report` gained the
  matching arm, and the upstream `sample/tdx_quote_td15ex` fixture is
  exercised end to end.
- **TD attributes realigned to Intel TDX module ABI 348551-008US.** SEC bits
  are re-decoded (ICSSD, SERVTD_EXT, LASS, MIGRATABLE at bit 29 — previously
  treated as reserved), OTHER bit 62 is TPA, and reserved bits are enforced
  against the ABI MBZ mask. New verifier rejections: MIGRATABLE always,
  SERVTD_EXT unless `allow_service_td`, TUD profiling bits unless
  `allow_debug`. The SDK keeps upstream defaults (both false).
- **Intel-aligned TCB status convergence.** `converge_with_component` now
  follows Intel QVL's `convergeTcbStatuses`: only an `OutOfDate` or `Revoked`
  component status (TDX module level or QE level) degrades the platform
  status; `ConfigurationNeeded`, `SWHardeningNeeded`, and
  `OutOfDateConfigurationNeeded` component statuses leave the platform status
  unchanged (advisory IDs still union). Because a QE `ConfigurationNeeded` no
  longer surfaces in the merged status, the SDK additionally requires
  `platform_status` and `qe_status` to each be `UpToDate` in
  `tdx.rs::verify_tdx_quote`, preserving the pre-upgrade gate.
- **TDX 1.5 relaunch statuses.** `TcbStatus` gained `TDRelaunchAdvised` and
  `TDRelaunchAdvisedConfigurationNeeded`, produced when a TD 1.5 launched
  with an out-of-date TCB (`TEE_TCB_SVN`) but its current TCB
  (`TEE_TCB_SVN2`) appraises cleanly — current TCB `Revoked` still fails
  verification outright. The SDK's `status != "UpToDate"` gate rejects both
  relaunch statuses.
- **TCB collateral status validation.** TCB levels from TCB Info, TDX module
  identities, and QE Identity are now rejected when their `tcbStatus` is not
  in Intel QVL's accepted set for that structure (`ensure_valid_status`),
  closing the unrecognized-status acceptance gap.
- **TDX module TCB evaluation.** For TDX module versions ≥ 1, module SVNs
  (indices 0–1 of `tee_tcb_svn`) are appraised by the module identity's TCB
  levels instead of the platform `tdxtcbcomponents`, and the converged level
  is dated by its oldest component.
- **DoS hardening.** `verify_certificate_chain` rejects more than 4
  intermediate certificates (the webpki path builder re-parses candidates
  each step), and DER `SEQUENCE` entry iteration is linear instead of
  quadratic.
- Removed derives: `PartialOrd`/`Ord` on `TcbStatus` and several collateral
  structs (the severity `max()` merge was replaced by convergence). No SDK
  caller relied on them.

New evidence: `fixtures/evidence/dcap-qvl/tdx_quote_td15ex.bin` and
`tdx_quote_td15ex_collateral.json`, byte-for-byte copies of the upstream 0.7.0
samples, cover positive verification, signed-extension tampering, and the new
v5 body-size check. The malformed corpus and mutation sweep are unchanged.

This records technical review scope only. Independent human security review
of the upstream diff and the 24-hour fuzz campaign remain outstanding
production-release blockers; no review attestation is claimed here.

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
cargo audit
```

Tests are necessary but not sufficient for a production verifier claim. A
human security review of upstream drift and the resolved graph remains
mandatory.
