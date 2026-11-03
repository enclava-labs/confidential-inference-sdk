# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Breaking changes

These changes break the public API, the FFI client configuration, the verdict
JSON check set, and existing test expectations. That is acceptable because
`0.1.0` has never been tagged or published and there are no downstream users.

#### Final PR review corrections

- Native fork guards read handle fields under the lifetime registry lock.
  Concurrent client/stream destruction retains in-flight state safely.
  After SDK initialization, forked children must exec before SDK use; inherited
  creation/use/free calls fail with `client_used_after_fork`.
- Tinfoil, NEAR, and RedPill replace `with_client` with `with_transport` and
  `AttestedHttpTransport`: reusable HTTP builder settings, TLS configuration,
  and a certificate verifier apply to both evidence and pinned inference.
  SPKI pinning, disabled redirects, and TLS metadata remain SDK-enforced.
  Loopback TLS tests use trusted CA-signed leaves, not a verification bypass.
- A concurrent failed AMD KDS lookup no longer replaces a successful VCEK cache
  entry. Proxy accept retries back off on resource exhaustion and return
  permanent errors instead of spinning.
- Signing seeds must contain exactly 32 bytes. UTF-8 regression fixtures now
  cross the guarded byte boundary.
- Offline gates require Python, select the FFI library from the actual build
  output, and run SBOM generation and validation. Release CLI examples use
  the supported flags; Rust installation uses the existing `main` branch
  until release tags are published.

#### Release-readiness review fixes

Security and trust decisions:

- `dstack_app_e2ee` evidence and the structured Tinfoil schema
  (`confidential-inference.tinfoil-tls-evidence.v1`) are claims-only: no quote
  signature is verified. Like RedPill `chutes_e2ee`, a required CPU TEE now
  yields `cpu_tee: failed` (denied under enforce); the claimed measurement is
  reported separately as `cpu_measurement_reference`.
- `fixture_*` evidence families are honored only with `with_demo_provider()`;
  outside demo mode such registry routes are dropped with a warning.
- Under `enforce`, a required check that is `not_supported` or `unknown` now
  blocks the request (previously only `failed` checks did).
- Provider requests carry the digest of the evidence their verdict verified
  (`ProviderChatRequest::with_verified_evidence_digest`). Tinfoil, NEAR and
  Chutes adapters key fetched TLS/instance state by that digest, so a later or
  concurrent fetch (including one that failed verification) can no longer
  change the key a request is sent to.
- Tinfoil and NEAR pin the attested leaf SPKI inside the TLS handshake: a
  mismatch fails before any request bytes are sent (`key_rotation`, one
  refresh and retry). A mismatch seen only after a response is now dispatch
  `unknown` and is never retried or failed over. SDK HTTP clients no longer
  follow redirects.
- NEAR now pins `mr_td`, `rtmr0-2` and `mr_config_id`
  (`near_live_tee_measurement`); `VerifiedTdxQuote.tee_measurement` includes
  `rtmr0-3`. Tinfoil TDX reference values must be regenerated.
- Artifact versions compare naturally (`compare_artifact_versions`:
  `1.9.0 < 1.10.0`) for registry, reference-value and pin rollback checks.
- `verify_privatemode_contrast_active_evidence` requires the expected manifest
  sha256 and compares it.
- NVIDIA NRAS tokens must carry `exp`; claims-only verdict lifetimes are
  bounded by wall-clock time plus the policy TTL.
- Malformed provider strings (multi-byte timestamps, report data, TLS hashes,
  Contrast manifests) return errors instead of panicking.
- FFI and all bindings: `demo_provider` defaults to `false`; NULL/empty
  configs fail with `trusted_signing_keys_required`. Config parse errors no
  longer echo values (inline API keys); inline keys and the raw config are
  zeroized; a client used after `fork()` returns `client_used_after_fork`.
- Python, Node and Go bindings load only the explicitly configured library
  (path or `CONFIDENTIAL_INFERENCE_FFI_LIBRARY`) when one is given and never
  search the current directory.
- Proxy: with CORS disabled, requests carrying `Origin` get 403; loopback mode
  requires a loopback `Host`; POST bodies must be `application/json`; request
  reads time out after 30 s (408); transient accept errors are retried with backoff.
- `ctutils` 0.4.7 (RUSTSEC-2026-0385). Registry source labels drop query
  strings and fragments. `live_conformance.py` never forwards credentials on
  redirects.

Reliability and API:

- Cancelling a verification no longer wedges its route (single-flight owner
  and waiter drop guards).
- Inference HTTP uses a 30 s connect and 600 s idle-read timeout instead of a
  30 s total timeout, so long completions and streams finish; evidence fetches
  keep a 30 s total timeout.
- TDX collateral is cached per platform (FMSPC + PCK CA, at most 256 entries,
  one file per platform), so nonce-bearing quotes stop refetching collateral.
- Send paths verify once per request (was twice); the NRAS JWT verifier is
  cached for one hour; failed AMD KDS VCEK lookups are cached for five minutes;
  PCCS responses are size-capped.
- No process-wide rustls `CryptoProvider` is installed; SDK clients use
  `confidential_inference_providers::reqwest_client_builder()`.
- Non-streaming paths reject `stream: true`: `streaming_not_supported` when the
  route cannot stream, `streaming_path_required` otherwise. A malformed stream
  item ends the stream with an error.
- `ResponseCreateRequest` rejects unknown fields; embeddings reject empty input
  (`missing_input`) and non-`float` `encoding_format` before attestation.
- `verify_route(provider, "")` and `manage_response` pick an active,
  executable route. `compatibility_matrix_envelope` installs an operator-signed
  matrix; the bundled matrix is compiled-in SDK code. Demo fallback accepts
  only the bundled envelope. `confidential_inference_sdk::providers`
  re-exports the adapter API.
- Proxy chat forwards request bodies losslessly (`tools`, `response_format`,
  `stop`, ...) and returns 400 for `stream: true`. Removed the unused
  `allow_provider_credentials_from_unauthenticated_callers` option and
  `ProxySecurityDefaults`.
- Trust CLI: artifacts are written atomically, signing seeds are zeroized, and
  an empty smoke-chat response is an error. Generator inputs take
  `revocation_epoch` and `minimum_acceptable_version`.
- Bindings: Python `embeddings_async`/`response_manage_async`/`models_async`;
  Python streams keep their client alive; Go streams no longer busy-spin, round
  sub-millisecond timeouts up and always close; Go no longer unloads the
  library on `Close`.
- Exact version pins removed (`reqwest`, `zeroize`, `zeroize_derive`); LICENSE
  ships in every crate and binding package.

Release tooling: fuzz targets for SDK parsers (built with nightly in CI),
`.gitattributes` for LF fixtures, packaging without `[patch]` overrides
(`--require-clean` in CI), `--check` flags that cannot pass vacuously, SBOMs
without absolute paths, and a production release gate that verifies
operator-signed matrices and a live-conformance plan limited to Tinfoil and
Chutes.

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

- Tinfoil streaming: `TinfoilHttpProvider::chat_stream` streams over the
  client pinned to the verified leaf SPKI and re-checks the observed peer
  before yielding a chunk; `pin tinfoil` signs streamable routes. Request
  extras such as `stream_options.include_usage` reach the provider.
- Streaming dispatch: provider failures before the first chunk keep their
  real dispatch outcome (`rejected{status}`, `not_dispatched`, `unknown`)
  instead of always `unknown`, and `streaming()` falls back to the next
  streaming-capable candidate under the same rule as non-streaming sends
  (`not_dispatched` or `rejected` 429/503). FFI stream `error` events carry
  `dispatch` and `http_status`.
- FFI, Go, and Node client configuration accept
  `"verdict_store": {"jsonl_path": "<file>"}` (unknown subfields rejected),
  backed by `JsonlVerdictStore`.
- Trust CLI: `--model a,b --canonical-model x,y` pins several models into one
  registry, reference-values envelope, matrix, and `operator-config.json`;
  mixed Tinfoil attestation formats are rejected; smoke chat runs per model.
- PPQ private live adapter (`PpqPrivateHttpProvider`, family `ppq_ehbp`) and
  `pin ppq`: Tinfoil-enclave bundle with SEV-SNP (VCEK chained to the pinned
  Genoa ARK) or TDX/DCAP quote verification, report data binding the enclave
  TLS SPKI and HPKE key, attestation-document/HPKE certificate SANs, and EHBP
  (HPKE X25519/HKDF-SHA256/AES-256-GCM) request/response encryption validated
  against vectors from the Go reference. Non-streaming; the bundle carries no
  request nonce and model binding is reported unsupported.
- Sigstore-verified release pins: `pin tinfoil` and `pin ppq` verify Tinfoil's
  release attestation offline against an embedded Sigstore public-good
  trusted root (sha256 `6494e21e…6bc0b66`): Fulcio chain valid at the Rekor
  integrated time, GitHub Actions issuer and repository identity pinned to
  `tinfoilsh/confidential-model-router`, SCT, DSSE signature and subject
  digest, Rekor SET, inclusion proof, and checkpoint. Every verified capture's
  SNP measurement must equal the signed release measurement or nothing is
  written; artifacts record `sigstore-verified-release`, repository, and
  digest. TDX pins fail closed; there is no trust-on-first-use fallback for
  these two providers. The trust CLI gains `reqwest` (workspace version).
- RedPill ACI adapter (`RedpillHttpProvider`, family
  `redpill_aci_verified_tls`) and `pin redpill`: DCAP-verified gateway quote
  bound to a nonce-carrying ACI statement and the gateway TLS SPKI, a
  content-addressed (RFC 8785 JCS) model-instance session with its own DCAP
  quote and NVIDIA NRAS evidence for the route's model, dispatch over the
  pinned gateway SPKI with `provider.aci_session_ids` forced to the verified
  session, and signed receipts whose every upstream event must name that
  session. Gateway and model measurements pin `mr_td`, RTMR0-2,
  `mr_config_id`, and the compose-hash, app-id, and KMS key-provider from a
  dstack event-log replay that must equal the DCAP-verified RTMR3 (raw RTMR3
  varies per instance and is not pinned). `pin redpill` also requires
  sha256(app_compose) to equal the replayed compose-hash and refuses composes
  that let the host provision root SSH access (`DSTACK_ROOT_PUBLIC_KEY`,
  `DSTACK_AUTHORIZED_KEYS`, `DSTACK_ROOT_PASSWORD`, `authorized_keys` from env
  or `/dstack/user_config`); RedPill's current gateway and model composes do,
  so they cannot be pinned. The newest listed session is used (30 s skew
  allowed on its establishment time); a session's verification is reused only
  while its id and evidence digest are still listed and before both the
  session and its NRAS token expire. `412 session_not_accepted` (no inference
  ran) is a key rotation with up to 3 fully re-verified attempts; other
  providers keep one retry. Non-streaming; model binding reported
  unsupported. Adds the `serde_json_canonicalizer` dependency.

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
