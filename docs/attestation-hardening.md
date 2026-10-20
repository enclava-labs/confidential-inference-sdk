# Attestation hardening contracts

This document summarizes the fail-closed contracts enforced by the SDK's
attestation and provider layers.

## NVIDIA NRAS

`confidential-inference-providers` submits GPU evidence to the NRAS v4 endpoint with
`claims_version = "3.0"`. The adapter rejects empty or malformed evidence,
requires a non-empty nonce, and rejects a provider nonce that differs from the
request before making a network call. `NvidiaNrasJwtVerifier` requires the
signed `x-nvidia-ver` claim to equal `3.0`, in addition to the existing issuer,
signature, nonce, and overall-result checks.

The old v3 endpoint constant remains deprecated for source compatibility. It
is not the default. `NvidiaGpuAttestationEvidence::NRAS_GPU_EVIDENCE_V3`
continues to name NVIDIA's input evidence format; it does not select the NRAS
HTTP API version.

## Artifact trust roots

The bundled fixture signing keys are test material. They verify bundled
artifacts only, and only after an explicit `with_demo_provider()` opt-in or an
explicit `exclusive_trusted_artifact_signing_keys` set that lists them. Remote
and custom registry/reference-value envelopes — including fetched candidates
and on-disk caches — verify against the operator key set alone, and `build`
fails when that set is empty for a non-bundled source.

## Chutes E2EE quote claims are not CPU verification

The `chutes_e2ee` evidence family parses the TDX quote and compares claimed
measurements against signed reference values, but never verifies the quote
signature. When a policy requires a CPU TEE, `cpu_tee` fails closed and the
verdict is denied; `cpu_measurement_reference` only reports whether the
claimed measurement matched. With `CpuTeeRequirement::NotRequired`, `cpu_tee`
is `not_applicable` and the app-E2EE checks can still reach `verified`, capped
below `hw_verified_tls`.

## Evidence is not proof

Provider response booleans and absent fields never become verified facts:

- Missing dstack or Chutes model identity produces an unsupported or
  failed model-binding result according to policy. The requested model is not
  copied into evidence.
- dstack `request_bound` and `response_bound` default to `false` and are not
  accepted as cryptographic request/response proof. The current dstack path
  reports request and response binding as unknown/not supported and blocks a
  policy that requires them.
- Registry/evidence route metadata agreement is `route_metadata_binding`.
  `request_route_binding` and the legacy `route_binding` key remain
  `not_supported` until the execution layer supplies request-bound routing
  proof.
- A provenance requirement with no supported build/source/SBOM proof now
  fails. It is not reported as `not_applicable`.

## Complete workload image manifests

dstack compose documents are parsed as YAML (JSON is a YAML subset). Every
service image must be pinned as `repository@sha256:<64 lowercase hex>`. The
parser rejects an unpinned sibling service, a service without an image,
duplicate service identities, invalid digests, and non-canonical ordering.

The canonical `workload_images` set is carried in normalized evidence and
signed reference values. Verification re-parses the quote-bound compose
document, requires exact equality with normalized evidence, and then requires
exact equality with the signed reference set. Checking only the first image or
only a legacy image digest is not sufficient. Signed reference updates cannot
remove or change a previously activated manifest without failing the
non-weakening update gate.

Legacy non-dstack references may omit `workload_images`. A dstack reference
generated from evidence requires a non-empty complete manifest.

## Structured verdicts and route attribution

Generated verdicts retain the stable `checks: {name: state}` map and add:

- `check_outcomes.{name}.state`
- `check_outcomes.{name}.required`
- `check_outcomes.{name}.detail`
- `check_outcomes.{name}.evidence_refs`
- `route_attribution.parties[]`

The Rust, Node, and Python validators require structured check keys and states
to agree exactly with the legacy map. Evidence references are limited to named
digest fields in the verdict and must be sorted and unique.

Route attribution uses only direct sources. The inference provider comes from
the signed registry, the registry authority comes from its signature metadata,
the reference-values authority comes from the signed issuer, and the TEE kind
comes from parsed evidence. Workload-operator and cloud-host identities remain
explicitly `unknown` unless a future evidence format asserts them. Endpoint
hostnames and provider names are not used to guess those parties.

These fields are additive within verdict schema major version 1. Older verdict
fixtures without them still validate; newly generated SDK verdicts always
include them.

## Canonical JSON

Canonical object keys are ordered by raw UTF-16 code units, matching JCS and
ECMAScript. Floats and integers outside the cross-language JSON safe-integer
range remain rejected.

## Verification commands

The focused adversarial tests live beside each primitive. The release-level
gate is the workspace CI matrix; at minimum run:

```bash
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
(cd bindings/node && npm ci && npm test)
python3 -m unittest discover -s bindings/python/tests
```
