# Release checklist

Complete every gate from the repository root before publishing `v0.1.0`.

## 1. Offline gates

```bash
# Rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.97 check --workspace --locked --all-targets
cargo run -p confidential-demo --locked

# Bindings
cargo build -p confidential-inference-ffi --locked
python3 -m unittest discover -s bindings/python/tests
(cd bindings/node && npm ci && npm test)
(cd bindings/go && go test -race -count=1 ./...)

# Python tooling
python3 -m unittest discover -s tools -p 'test_*.py'

# Policy and supply chain
python3 tools/check_normative_fixtures.py
python3 tools/check_ffi_exports.py
cargo deny check
cargo audit
python3 tools/check_supply_chain_policy.py
python3 tools/check_release_packaging.py --require-clean

# SBOM and release manifest
python3 tools/generate_sbom.py --output target/confidential-inference-sbom.json
python3 tools/generate_sbom.py --output target/confidential-inference-sbom.json --check
python3 tools/generate_release_manifest.py \
  --manifest target/confidential-inference-release-manifest.json \
  --artifact-glob 'target/package/*.crate' \
  --artifact target/confidential-inference-sbom.json \
  --sbom target/confidential-inference-sbom.json \
  --signature-key-seed-env CONFIDENTIAL_INFERENCE_RELEASE_CI_SIGNING_KEY_SEED_BASE64URL \
  --signature-signer confidential-inference-release-ci \
  --signature-key-id release-ci-key
python3 tools/check_release_manifest.py --manifest target/confidential-inference-release-manifest.json \
  --artifact-glob 'target/package/*.crate' --artifact target/confidential-inference-sbom.json \
  --sbom target/confidential-inference-sbom.json \
  --signature target/confidential-inference-release-manifest.ci.sig.json \
  --trusted-release-key confidential-inference-release-ci:release-ci-key:<ci-public-key>

# Fuzz harness build
cargo +nightly fuzz build
```

## 2. Production release gate

For a production (non-CI) release, `check_release_manifest.py` must verify the
manifest against operator-supplied artifacts instead of fixture ones:

```bash
python3 tools/check_release_manifest.py \
  --manifest <release-manifest>.json \
  --artifact-glob 'target/package/*.crate' \
  --artifact target/confidential-inference-sbom.json \
  --sbom target/confidential-inference-sbom.json \
  --signature <manifest>.sig.json \
  --trusted-release-key <signer>:<key-id>:<public-key> \
  --live-conformance-report <signed-report>.json \
  --require-production-release \
  --live-conformance-plan-path <operator-plan>.json \
  --dcap-production-review-path <dcap-production-review>.json
```

- `--trusted-release-key` must be the operator release key. CI/test public
  keys (`confidential-inference-release-ci:release-ci-key`) are rejected.
- The live-conformance report must cover every provider in the supplied plan
  (`live-conformance-plan-path`), with observed model IDs matching the
  operator's compatibility and model-alias matrices, all signed by the
  operator release key. Report fields are schema-checked against
  `confidential-inference.live-conformance-report.v1`; the plan against
  `confidential-inference.live-conformance-plan.v1`. The compatibility matrix
  must not name a `*-fixture` provider in production mode.
- `--dcap-production-review-path` must point to a passing
  `confidential-inference.dcap-qvl-production-review.v1` document (see
  `dcap-qvl-upstream-sync.md`), produced by the human review in step 3.

## 3. Fuzz campaign

Build the harnesses with `cargo +nightly fuzz build`, then run each target for
at least the configured minimum duration (default 24 hours per target):

```bash
cd fuzz
cargo +nightly fuzz run attestation_timestamp -- -max_total_time=86400
cargo +nightly fuzz run attestation_tinfoil_live_capture -- -max_total_time=86400
cargo +nightly fuzz run attestation_sev_snp_report -- -max_total_time=86400
cargo +nightly fuzz run attestation_evidence -- -max_total_time=86400
cargo +nightly fuzz run providers_normalize_dstack -- -max_total_time=86400
cargo +nightly fuzz run providers_normalize_chutes_e2ee -- -max_total_time=86400
cargo +nightly fuzz run providers_sse_frames -- -max_total_time=86400
cargo +nightly fuzz run providers_contrast_manifest -- -max_total_time=86400
cargo +nightly fuzz run providers_contrast_initdata -- -max_total_time=86400
cargo +nightly fuzz run proxy_http_request -- -max_total_time=86400
cargo +nightly fuzz run dcap_quote_parse -- -max_total_time=86400
```

Targets may run in parallel or serially; every target must reach the minimum
duration with zero unresolved crashes (deduplicated crashes may be triaged and
documented).

## 4. Human DCAP upstream review

Produce the `dcap-qvl-production-review` artifact per
[dcap-qvl-upstream-sync.md](dcap-qvl-upstream-sync.md) before the manifest
check in step 2.

## 5. Publish

Publish order (each crate waits for its predecessors to appear on crates.io):

1. `confidential-inference-attestation`
2. `confidential-inference-openai`
3. `confidential-inference-providers`
4. `confidential-inference-sdk`
5. `confidential-inference-proxy`
6. `confidential-inference-ffi`
7. `confidential-inference-trust-cli`

Then tag:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git tag -a bindings/go/v0.1.0 -m "bindings/go v0.1.0"
```

The `bindings/go/v0.1.0` module tag publishes the Go binding for
`go get module-path@v0.1.0`; attach the per-target
`libconfidential_inference_ffi` artifacts to the release so consumers can pin
`CONFIDENTIAL_INFERENCE_FFI_LIBRARY`.

Final verification: all manifest checks in CI are green.
