# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Breaking changes

These changes break the public API, the FFI client configuration, the verdict
JSON check set, and existing test expectations. That is acceptable because
`0.1.0` has never been tagged or published and there are no downstream users.

#### Artifact trust is explicit

- `default_trusted_signing_keys` is renamed to
  `bundled_fixture_signing_keys`. These keys open the bundled fixture
  artifacts only; they are not a production trust root.
- `ConfidentialInferenceBuilder::build` no longer unions the bundled fixture
  keys into the trust set. A bare `ConfidentialInference::builder().build()`
  fails with `BundledSourceRequiresTrust`.
- `with_demo_provider()` is the explicit offline/demo opt-in: it installs the
  demo provider and trusts `bundled_fixture_signing_keys()` for the bundled
  registry and bundled reference values only.
- `trusted_artifact_signing_key` and `trusted_ed25519_artifact_signing_key`
  append operator keys; they never add fixture keys.
- `exclusive_trusted_artifact_signing_keys` replaces the trust root with
  exactly the caller-supplied keys for every artifact, including bundled
  sources.
- Remote and custom registry/reference-value envelopes, fetched remote
  candidates, and on-disk caches verify against the operator key set only.
  Bundled fallback artifacts verify against the bundled fixture keys only in
  demo mode.
- `verify_artifact_signature` and the implicit-key envelope helpers are
  removed. Use `verify_artifact_signature_with_keys` and the
  `*_with_keys`/`verifier_at` variants with an explicit trust root.
- FFI `ClientConfig` gains `trusted_ed25519_signing_keys`. With
  `demo_provider: false` a non-empty list is required and is installed as the
  exclusive trust root; combining a non-empty list with
  `demo_provider: true` is rejected as ambiguous.

#### RedPill (`chutes_e2ee`) fails closed when a CPU TEE is required

- `chutes_e2ee` evidence no longer reports `cpu_tee` as verified: the path
  parses the TDX quote and compares measurements but does not verify the quote
  signature. Under any policy that requires a CPU TEE — including the default
  `require_attested_e2ee` policy — `cpu_tee` is `Failed` and the verdict is
  denied.
- A new `cpu_measurement_reference` check reports whether the claimed
  measurement matches signed reference values. It never upgrades the `cpu_tee`
  result; a measurement match is not quote verification.
- When the CPU requirement is `NotRequired`, `cpu_tee` is `NotApplicable` and
  the route may still verify on the app-E2EE checks it actually performs. The
  trust tier stays capped at `AppE2ee`/`TeeOnly`, never `HwVerifiedTls`.
- `AttestationVerdict::validate_status_summary` rejects `verified` verdicts
  that contain a required `not_supported` or `unknown` check.

### Added

- Live Tinfoil SEV-SNP verification now validates Genoa VCEK/ASK/ARK trust,
  report signatures, TCB and guest policy, and TLS SPKI report-data binding.
  The trust CLI pins verified SNP measurements and supports smoke chat through
  the AMD KDS VCEK resolver.
- FFI and Go/Python/Node client configuration accept an operator-signed
  `compatibility_matrix` envelope, verified against the exclusive operator
  signing keys; custom executable route compatibility remains explicit.

- Go binding under `bindings/go`. It loads `confidential-inference-ffi` at
  run time through purego (no cgo required by callers), mirrors the Python
  and Node.js API surface (`Client`, `Stream`, JSON-in/JSON-out calls), and
  resolves the shared library from `CONFIDENTIAL_INFERENCE_FFI_LIBRARY` or
  the workspace `target/{debug,release}` directories.
