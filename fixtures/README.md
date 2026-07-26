# Test fixtures

This directory contains deterministic inputs for the SDK's offline tests,
bindings, and demo. Fixture signing keys and reference values are test material;
they must never be used as production trust roots.

The TDX quote and collateral under `evidence/dcap-qvl/` are upstream sample
evidence used to exercise the real DCAP verifier. The remaining evidence files
model provider and failure scenarios and do not establish trust in any live
deployment.

## Layout

| Directory | Contents |
| --- | --- |
| `policy/` | Policy examples and canonical JSON/digest vectors |
| `registry/` | Signed provider registries and model-alias fixtures |
| `reference-values/` | Signed reference-value envelopes |
| `providers/` | Compatibility, normalization, live-sync, and conformance fixtures |
| `evidence/` | Valid, invalid, and provider-shaped attestation evidence |
| `corpus/` | Manifest-driven adversarial evidence cases |
| `verdict/` | Expected high-level SDK verdicts |
| `supply-chain/` | DCAP dependency and lockfile audit baseline |

## Core fixtures

- `policy/require_attested_e2ee.json` is the demo enforcement policy.
- `policy/canonical-vectors.json` fixes canonical JSON and digest behavior
  across Rust, Python, and Node.js.
- `registry/demo-registry.json` and
  `reference-values/demo-envelope.json` are the signed trust inputs for the
  local demo route.
- `registry/phase2-fixtures-registry.json` and
  `reference-values/phase2-fixtures-envelope.json` provide the signed
  multi-route fixture set used by SDK integration tests.
- `registry/model-alias-matrix-envelope.json` and
  `providers/compatibility-matrix-envelope.json` are the signed forms consumed
  by Rust. Their unsigned JSON counterparts are checked for exact payload
  equality by the repository tooling.
- `corpus/fixture-evidence-corpus.json` lists valid and fail-closed evidence
  cases with their expected verdict outcomes.
- `verdict/demo-verified.json` is the complete expected verdict emitted by the
  deterministic demo client.

## Provider conformance

- `providers/live-conformance-plan.json` defines network-disabled-by-default
  model and evidence-shape checks. A dry run validates the plan and signed
  matrices without contacting providers.
- `providers/live-sync-corpus.json` covers accepted provider model-list shapes
  and malformed input.
- `providers/evidence-normalizer-corpus.json` covers dstack,
  Redpill/Chutes, and related evidence normalization.
- `providers/tinfoil-live-reference-corpus.json` covers reference-value
  generation from already verified TDX and SEV-SNP results. It does not provide
  a production SEV-SNP verifier.
- `providers/privatemode-contrast-active-corpus.json` covers the local
  Privatemode trust-decision inputs and failure cases.

Checked-in live-sync and compatibility fixtures cannot make a provider route
production-ready. The policy checker keeps fixture-only routes
non-executable or verification-only until the required live evidence and signed
provider artifacts exist.

## DCAP corpus

- `evidence/dcap-qvl/tdx_quote.bin` and
  `evidence/dcap-qvl/tdx_quote_collateral.json` are the positive sample.
- `evidence/dcap-qvl/malformed-corpus.json` covers malformed quote and
  collateral inputs.
- `evidence/dcap-qvl/mutation-sweep.json` defines deterministic quote and
  collateral mutations.
- `supply-chain/dcap-qvl-audit.json` pins the reviewed upstream crate versions,
  selected features, corpus files, review policy, and workspace lockfile.

## Validation

Run:

```bash
python3 tools/check_normative_fixtures.py
cargo test --workspace --locked
cargo test -p confidential-inference-providers --test dcap_qvl_audit --locked
```

`tools/check_normative_fixtures.py` verifies schemas, digests, timestamps,
route metadata, and Ed25519 signatures. The Rust tests assert the expected
success and failure outcomes through the actual verifier and client paths.

Some fixtures are copied into crate `assets/` directories so published crates
can load them without referring outside their package. The release packaging
check verifies that those copies remain byte-for-byte identical:

```bash
python3 tools/check_release_packaging.py
```

When changing a signed fixture, regenerate its signature with the designated
test key, update every mirrored copy, and rerun all three checks above.
