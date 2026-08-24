#!/usr/bin/env python3
"""Validate that CI runs the SDK's required offline verification gates."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


SCHEMA = "confidential-inference.ci-workflow-policy.v1"
RUSTUP_COMPONENT_INSTALL_SNIPPET = (
    "rustup toolchain install stable --profile minimal --component clippy,rustfmt"
)
DEMO_PIPEFAIL_SNIPPET = (
    "set -o pipefail\n"
    "          cargo run -p confidential-demo --locked | tee target/confidential-demo.out\n"
    "          python3 tools/check_demo_output.py target/confidential-demo.out"
)

REQUIRED_SNIPPETS = [
    "permissions:",
    "contents: read",
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
    "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0",
    'python-version: "3.11"',
    'python-version: "3.12"',
    RUSTUP_COMPONENT_INSTALL_SNIPPET,
    "cargo fmt --all -- --check",
    "cargo clippy --workspace --all-targets --locked -- -D warnings",
    "cargo test --workspace --locked --quiet",
    "cargo test -p confidential-inference-providers --test dcap_qvl_audit --locked",
    "cargo fuzz build",
    "No fuzz targets checked in; offline corpus tests are covered by cargo test --workspace.",
    DEMO_PIPEFAIL_SNIPPET,
    "cargo run -p confidential-demo --locked",
    "python3 tools/check_demo_output.py target/confidential-demo.out",
    "python3 tools/check_normative_fixtures.py",
    "python3 tools/check_ffi_exports.py",
    "cargo build -p confidential-inference-ffi --locked",
    "python3 -m unittest discover -s bindings/python/tests",
    "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0",
    "node-version: \"22\"",
    "cache-dependency-path: bindings/node/package-lock.json",
    "npm ci",
    "working-directory: bindings/node",
    "npm test",
    "live-conformance:",
    "python3 tools/live_conformance.py --output target/live-conformance-disabled-network.json",
    "rustup toolchain install stable --profile minimal",
    "cargo install --locked cargo-deny --version 0.20.2",
    "cargo install --locked cargo-audit --version 0.22.2",
    "cargo deny check",
    "cargo audit --ignore RUSTSEC-2023-0071",
    "python3 tools/check_supply_chain_policy.py",
    "python3 tools/check_release_packaging.py",
    "python3 tools/generate_sbom.py --output target/confidential-inference-sbom.json --check",
    "python3 tools/generate_release_manifest.py --artifact-glob 'target/package/*.crate' --artifact target/confidential-inference-sbom.json --sbom target/confidential-inference-sbom.json --output target/confidential-inference-release-manifest.json --check",
    "python3 tools/check_release_manifest.py --manifest target/confidential-inference-release-manifest.json --artifact-glob 'target/package/*.crate' --artifact target/confidential-inference-sbom.json --sbom target/confidential-inference-sbom.json",
    "CONFIDENTIAL_INFERENCE_RELEASE_CI_SIGNING_KEY_SEED_BASE64URL: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    "python3 tools/generate_release_manifest.py --artifact-glob 'target/package/*.crate' --artifact target/confidential-inference-sbom.json --sbom target/confidential-inference-sbom.json --output target/confidential-inference-release-manifest.json --signature-output target/confidential-inference-release-manifest.ci.sig.json --signature-key-seed-env CONFIDENTIAL_INFERENCE_RELEASE_CI_SIGNING_KEY_SEED_BASE64URL --signature-signer confidential-inference-release-ci --signature-key-id release-ci-key --check",
    "python3 tools/check_release_manifest.py --manifest target/confidential-inference-release-manifest.json --artifact-glob 'target/package/*.crate' --artifact target/confidential-inference-sbom.json --sbom target/confidential-inference-sbom.json --signature target/confidential-inference-release-manifest.ci.sig.json --trusted-release-key confidential-inference-release-ci:release-ci-key:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
    "python3 tools/check_ci_workflow.py",
    "python3 -m unittest discover -s tools -p 'test_*.py'",
]


def check_workflow(path: Path) -> dict[str, object]:
    if not path.exists():
        return {
            "schema": SCHEMA,
            "workflow": path.as_posix(),
            "missing": [f"{path} does not exist"],
        }

    text = path.read_text(encoding="utf-8")
    missing = [snippet for snippet in REQUIRED_SNIPPETS if snippet not in text]
    return {
        "schema": SCHEMA,
        "workflow": path.as_posix(),
        "required_snippet_count": len(REQUIRED_SNIPPETS),
        "missing": missing,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workflow",
        type=Path,
        default=Path(".github/workflows/ci.yml"),
        help="Workflow file to validate. Defaults to .github/workflows/ci.yml.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full validation report as JSON.",
    )
    args = parser.parse_args(argv)

    report = check_workflow(args.workflow)
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2, separators=(",", ": ")))
    elif report["missing"]:
        for missing in report["missing"]:
            print(f"workflow policy violation: missing {missing}", file=sys.stderr)
    else:
        print(
            "ci workflow policy ok: "
            f"workflow={report['workflow']} required_snippets={report['required_snippet_count']}"
        )
    return 1 if report["missing"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
