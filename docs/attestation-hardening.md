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

## Evidence is not proof

Provider response booleans and absent fields never become verified facts:

- Missing dstack, Chutes, or io.net model identity produces an unsupported or
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

## Hardened ACI workload keysets

`confidential-inference-attestation` exposes a provider-neutral ACI v1 primitive through
`verify_aci_workload_keyset`. Its security boundary is deliberately split:

1. The workload keyset is endorsed by an explicitly trusted Ed25519 identity.
2. A caller-supplied `AciQuoteVerifier` authenticates the vendor TEE quote.
3. Quote `report_data` binds a canonical 32-byte challenge nonce and the
   canonical digest of the complete keyset.
4. The complete keyset includes its epoch, validity, TLS SPKI, capabilities,
   keys, workload images, model artifacts, source commit, and SBOM digest.
5. The observed leaf certificate SPKI must match the identity-endorsed SPKI,
   and the certificate must be valid at verification time.

The leaf certificate passed in `AciEvidence` must be captured from the same
certificate-chain-validated live TLS connection being authorized. Supplying a
certificate from an unrelated connection defeats the meaning of “live,” even
though its SPKI and quote bindings are still checked.

The default `FailClosedAciQuoteVerifier` never authorizes evidence. Production
callers must install a backend that verifies the relevant TDX, SEV-SNP, or
Nitro signature and collateral before returning `VerifiedAciQuote`.

Keysets are bounded and canonical. Key IDs and usage lists must be sorted and
unique; Ed25519 and X25519 keys must be canonical 32-byte base64url values;
algorithms must match their declared usages; and advertised encryption or
response-signing capabilities require the corresponding key.

Callers persist `VerifiedAciWorkloadKeyset::checkpoint()` and supply it on the
next verification. A lower epoch is rollback, and a different keyset at the
same epoch is equivocation. A higher epoch permits reviewed key rotation.

The returned cache expiry is the earliest of:

- keyset `stale_after`;
- keyset `not_after`;
- quote expiry;
- quote collateral expiry; and
- TLS certificate expiry.

The result is never cacheable for zero time. Callers should discard it at the
returned epoch even if a broader application cache remains valid.

## Canonical JSON

Canonical object keys are ordered by raw UTF-16 code units, matching JCS and
ECMAScript. Rust, Node, and Python have a shared non-BMP test vector. Floats and
integers outside the cross-language JSON safe-integer range remain rejected.

## Verification commands

The focused adversarial tests live beside each primitive. The release-level
gate is the workspace CI matrix; at minimum run:

```bash
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
(cd bindings/node && npm ci && npm test)
python3 -m unittest discover -s bindings/python/tests
```
