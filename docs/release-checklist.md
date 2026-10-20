# Release checklist

A registry publish is blocked until all of the following exist:

1. A git tag for the release. `0.1.0` has never been tagged or published.
2. A signed, credentialed live-conformance report passed to
   `tools/check_release_manifest.py`.
3. The human DCAP production-review artifact produced by the process in
   [dcap-qvl-upstream-sync.md](dcap-qvl-upstream-sync.md).
4. A completed fuzz campaign (the checked-in `fuzz/` target is only built in
   CI; building it is not a campaign).

Publish order:

1. `confidential-inference-attestation`
2. `confidential-inference-openai`
3. `confidential-inference-providers`
4. `confidential-inference-sdk`
5. `confidential-inference-proxy`
6. `confidential-inference-ffi`

`confidential-demo` is `publish = false` and is never published.

Before publishing, rerun the full offline gate set listed in
[CONTRIBUTING.md](../CONTRIBUTING.md) and confirm the release-manifest checks
in CI are green.
