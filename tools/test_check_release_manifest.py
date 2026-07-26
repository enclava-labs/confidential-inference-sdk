from __future__ import annotations

import datetime
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
REPO_ROOT = Path(__file__).resolve().parents[1]

GENERATE_MODULE_PATH = Path(__file__).with_name("generate_release_manifest.py")
GENERATE_SPEC = importlib.util.spec_from_file_location(
    "generate_release_manifest",
    GENERATE_MODULE_PATH,
)
assert GENERATE_SPEC is not None
generate_release_manifest = importlib.util.module_from_spec(GENERATE_SPEC)
assert GENERATE_SPEC.loader is not None
GENERATE_SPEC.loader.exec_module(generate_release_manifest)

CHECK_MODULE_PATH = Path(__file__).with_name("check_release_manifest.py")
CHECK_SPEC = importlib.util.spec_from_file_location(
    "check_release_manifest",
    CHECK_MODULE_PATH,
)
assert CHECK_SPEC is not None
check_release_manifest = importlib.util.module_from_spec(CHECK_SPEC)
assert CHECK_SPEC.loader is not None
CHECK_SPEC.loader.exec_module(check_release_manifest)


LIVE_PROVIDER_IDS = ("tinfoil", "venice", "redpill", "phala", "ionet")
LIVE_COMPATIBILITY_PROVIDER_IDS = {
    "tinfoil": "tinfoil-fixture",
    "venice": "venice-fixture",
    "redpill": "redpill-fixture",
    "phala": "phala-direct-fixture",
    "ionet": "ionet-confidential-fixture",
}
LIVE_AUTH_ENVS = {
    "tinfoil": "TINFOIL_API_KEY",
    "venice": "VENICE_API_KEY",
    "redpill": "REDPILL_API_KEY",
    "phala": "PHALA_API_KEY",
    "ionet": "IONET_API_KEY",
}
LIVE_MODEL_LIST_URLS = {
    "tinfoil": "https://inference.tinfoil.sh/v1/models",
    "venice": "https://api.venice.ai/api/v1/models",
    "redpill": "https://api.redpill.ai/v1/models",
    "phala": "https://inference.phala.com/v1/models",
    "ionet": "https://api.intelligence.io.solutions/api/v1/models",
}
LIVE_ATTESTATION_URLS = {
    "tinfoil": "https://inference.tinfoil.sh/.well-known/tinfoil-attestation",
    "venice": "https://api.venice.ai/api/v1/confidentiality",
    "redpill": "https://api.redpill.ai/v1/attestation/report",
    "phala": "https://inference.phala.com/v1/aci/attestation",
    "ionet": "https://api.intelligence.io.solutions/api/v1/attestation",
}
COMPATIBILITY_FIXTURE_SEED = bytes([47]) * 32


def canonical_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def response_metadata(url: str, body: bytes = b'{"ok":true}') -> dict[str, object]:
    return {
        "url": url,
        "status": 200,
        "content_type": "application/json",
        "body_size": len(body),
        "body_sha256": check_release_manifest.sha256_digest(body),
    }


def alias_provider_models(alias_matrix: dict[str, object]) -> dict[str, list[str]]:
    provider_models: dict[str, set[str]] = {}
    models = alias_matrix.get("models")
    if not isinstance(models, list):
        return {}
    for model in models:
        if not isinstance(model, dict):
            continue
        routes = model.get("provider_routes")
        if not isinstance(routes, list):
            continue
        for route in routes:
            if not isinstance(route, dict):
                continue
            provider = route.get("provider")
            provider_model = route.get("provider_model")
            if isinstance(provider, str) and isinstance(provider_model, str):
                provider_models.setdefault(provider, set()).add(provider_model)
    return {
        provider: sorted(models_for_provider)
        for provider, models_for_provider in provider_models.items()
    }


def write_workspace(root: Path) -> None:
    (root / "Cargo.toml").write_text(
        """
[workspace]
members = [
    "crates/confidential-inference-sdk",
    "crates/confidential-inference-providers",
    "demo/confidential-demo",
]

[workspace.package]
version = "0.1.0"
rust-version = "1.75"
license = "Apache-2.0"
repository = "https://github.com/enclava-labs/confidential-inference-sdk"
""".lstrip(),
        encoding="utf-8",
    )
    (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
    for member, package_name, publish in (
        ("crates/confidential-inference-sdk", "confidential-inference-sdk", True),
        ("crates/confidential-inference-providers", "confidential-inference-providers", True),
        ("demo/confidential-demo", "confidential-demo", False),
    ):
        manifest_dir = root / member
        manifest_dir.mkdir(parents=True)
        manifest_dir.joinpath("Cargo.toml").write_text(
            f"""
[package]
name = "{package_name}"
version.workspace = true
edition = "2021"
publish = {str(publish).lower()}
""".lstrip(),
            encoding="utf-8",
        )


def write_manifest(root: Path, extra_artifacts: list[Path] | None = None) -> Path:
    package_dir = root / "target" / "package"
    package_dir.mkdir(parents=True)
    (package_dir / "confidential-inference-sdk-0.1.0.crate").write_bytes(b"client crate")
    (package_dir / "confidential-inference-providers-0.1.0.crate").write_bytes(b"providers crate")
    sbom = root / "target" / "confidential-inference-sbom.json"
    sbom.write_text('{"schema":"confidential-inference.sbom.v1","package_count":0}\n', encoding="utf-8")
    artifact_paths = [
        Path("target/package/confidential-inference-sdk-0.1.0.crate"),
        Path("target/package/confidential-inference-providers-0.1.0.crate"),
        Path("target/confidential-inference-sbom.json"),
    ]
    artifact_paths.extend(extra_artifacts or [])
    manifest = generate_release_manifest.build_release_manifest(
        root,
        artifact_paths,
        Path("target/confidential-inference-sbom.json"),
    )
    manifest_path = root / "target" / "confidential-inference-release-manifest.json"
    manifest_path.write_text(
        generate_release_manifest.render_manifest(manifest),
        encoding="utf-8",
    )
    return manifest_path


def write_manifest_signature(
    root: Path,
    manifest_path: Path,
    *,
    signer: str = "confidential-inference-release-test",
    key_id: str = "release-test-key",
    seed: bytes | None = None,
) -> tuple[Path, str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    seed = seed if seed is not None else bytes(range(32))
    seed_base64url = generate_release_manifest.encode_unpadded_base64url(seed)
    signature = generate_release_manifest.build_release_manifest_signature(
        root,
        manifest_path,
        manifest,
        signer,
        key_id,
        seed_base64url,
    )
    signature_path = root / "target" / "confidential-inference-release-manifest.sig.json"
    signature_path.write_text(
        generate_release_manifest.render_signature(signature),
        encoding="utf-8",
    )
    trusted_key = (
        f"{signer}:{key_id}:{signature['public_key_base64url']}"
    )
    return signature_path, trusted_key


def write_live_conformance_plan(
    root: Path,
    provider_ids: tuple[str, ...] = LIVE_PROVIDER_IDS,
) -> None:
    plan_path = root / "fixtures" / "providers" / "live-conformance-plan.json"
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan = {
        "schema": "confidential-inference.live-conformance-plan.v1",
        "model_alias_matrix_path": (
            check_release_manifest.MODEL_ALIAS_MATRIX_PATH.as_posix()
        ),
        "model_alias_matrix_envelope_path": (
            check_release_manifest.MODEL_ALIAS_MATRIX_ENVELOPE_PATH.as_posix()
        ),
        "compatibility_matrix_path": (
            check_release_manifest.COMPATIBILITY_MATRIX_PATH.as_posix()
        ),
        "compatibility_matrix_envelope_path": (
            check_release_manifest.COMPATIBILITY_MATRIX_ENVELOPE_PATH.as_posix()
        ),
        "providers": [
            {
                "id": provider_id,
                "enabled": False,
                "model_list_url": LIVE_MODEL_LIST_URLS[provider_id],
                "attestation_url": LIVE_ATTESTATION_URLS[provider_id],
                "auth_env": LIVE_AUTH_ENVS[provider_id],
                "expected_model_ids_from_alias_matrix": True,
                "compatibility_provider": LIVE_COMPATIBILITY_PROVIDER_IDS[provider_id],
            }
            for provider_id in provider_ids
        ],
    }
    plan_path.write_text(
        json.dumps(plan, sort_keys=True, indent=2, separators=(",", ": ")) + "\n",
        encoding="utf-8",
    )


def write_json(root: Path, relative_path: Path, payload: dict[str, object]) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, separators=(",", ": ")) + "\n",
        encoding="utf-8",
    )


def load_repo_json(relative_path: Path) -> dict[str, object]:
    return json.loads((REPO_ROOT / relative_path).read_text(encoding="utf-8"))


def write_live_conformance_artifacts(
    root: Path,
    *,
    production_compatibility: bool = True,
) -> dict[str, object]:
    alias_matrix = load_repo_json(check_release_manifest.MODEL_ALIAS_MATRIX_PATH)
    alias_envelope = load_repo_json(
        check_release_manifest.MODEL_ALIAS_MATRIX_ENVELOPE_PATH
    )
    alias_signature = alias_envelope["signature"]
    compatibility_matrix = load_repo_json(check_release_manifest.COMPATIBILITY_MATRIX_PATH)
    if production_compatibility:
        compatibility_matrix = production_compatibility_matrix(compatibility_matrix)
        compatibility_envelope = signed_compatibility_envelope(compatibility_matrix)
    else:
        compatibility_envelope = load_repo_json(
            check_release_manifest.COMPATIBILITY_MATRIX_ENVELOPE_PATH
        )
    compatibility_signature = compatibility_envelope["signature"]
    alias_models = alias_provider_models(alias_matrix)
    compatibility_providers = compatibility_matrix["providers"]
    assert isinstance(compatibility_providers, dict)

    write_json(root, check_release_manifest.MODEL_ALIAS_MATRIX_PATH, alias_matrix)
    write_json(root, check_release_manifest.MODEL_ALIAS_MATRIX_ENVELOPE_PATH, alias_envelope)
    write_json(root, check_release_manifest.COMPATIBILITY_MATRIX_PATH, compatibility_matrix)
    write_json(
        root,
        check_release_manifest.COMPATIBILITY_MATRIX_ENVELOPE_PATH,
        compatibility_envelope,
    )

    return {
        "model_alias_matrix": {
            "path": check_release_manifest.MODEL_ALIAS_MATRIX_PATH.as_posix(),
            "digest": check_release_manifest.canonical_sha256_digest(alias_matrix),
            "providers": sorted(alias_models),
        },
        "model_alias_matrix_envelope": {
            "path": check_release_manifest.MODEL_ALIAS_MATRIX_ENVELOPE_PATH.as_posix(),
            "digest": check_release_manifest.canonical_sha256_digest(alias_envelope),
            "payload_digest": check_release_manifest.canonical_sha256_digest(alias_matrix),
            "signature": alias_signature,
        },
        "compatibility_matrix": {
            "path": check_release_manifest.COMPATIBILITY_MATRIX_PATH.as_posix(),
            "digest": check_release_manifest.canonical_sha256_digest(compatibility_matrix),
            "providers": sorted(compatibility_providers),
        },
        "compatibility_matrix_envelope": {
            "path": check_release_manifest.COMPATIBILITY_MATRIX_ENVELOPE_PATH.as_posix(),
            "digest": check_release_manifest.canonical_sha256_digest(compatibility_envelope),
            "payload_digest": check_release_manifest.canonical_sha256_digest(
                compatibility_matrix
            ),
            "signature": compatibility_signature,
        },
    }


def production_compatibility_matrix(matrix: dict[str, object]) -> dict[str, object]:
    providers = matrix["providers"]
    assert isinstance(providers, dict)
    live_shapes = {
        "tinfoil-fixture": "tinfoil_hw_verified_tls_live",
        "venice-fixture": "dstack_app_e2ee_live",
        "redpill-fixture": "chutes_e2ee_gpu_live",
        "phala-direct-fixture": "phala_dstack_app_e2ee_live",
        "ionet-confidential-fixture": "ionet_confidential_live",
    }
    for provider_id, attestation_shape in live_shapes.items():
        profile = providers[provider_id]
        assert isinstance(profile, dict)
        profile["route_execution_status"] = "executable"
        profile["model_listing"] = "live_catalog"
        profile["attestation_endpoint_shape"] = attestation_shape
        profile["required_credentials"] = ["bearer_token"]
        unsupported_modes = profile.get("known_unsupported_modes")
        assert isinstance(unsupported_modes, list)
        profile["known_unsupported_modes"] = [
            mode
            for mode in unsupported_modes
            if mode not in ("live_execution", "live_tdx_quote")
        ]
    return matrix


def signed_compatibility_envelope(matrix: dict[str, object]) -> dict[str, object]:
    payload = json.loads(
        json.dumps(matrix, sort_keys=True, separators=(",", ":"))
    )
    signature = generate_release_manifest.sign_ed25519(
        COMPATIBILITY_FIXTURE_SEED,
        check_release_manifest.canonical_json(payload).encode("utf-8"),
    )
    return {
        "schema": "confidential-inference.provider-compatibility-matrix-envelope.v1",
        "payload": payload,
        "signature": {
            "signer": "confidential-inference",
            "key_id": "confidential-inference-compatibility-fixture-ed25519-2026",
            "alg": "ed25519",
            "value": "base64url:"
            + generate_release_manifest.encode_unpadded_base64url(signature),
        },
    }


def write_live_conformance_report(
    root: Path,
    *,
    network_enabled: bool = True,
    status: str = "passed",
    live_checked: bool = True,
    gate_status: str = "passed",
    remaining_provider_ids: list[str] | None = None,
    provider_ids: tuple[str, ...] = LIVE_PROVIDER_IDS,
    production_compatibility: bool = True,
    completed_at: str | None = None,
) -> Path:
    write_live_conformance_plan(root)
    artifact_metadata = write_live_conformance_artifacts(
        root,
        production_compatibility=production_compatibility,
    )
    alias_matrix = load_repo_json(check_release_manifest.MODEL_ALIAS_MATRIX_PATH)
    provider_models = alias_provider_models(alias_matrix)
    compatibility_matrix_source = check_release_manifest.load_compatibility_matrix(
        root / check_release_manifest.COMPATIBILITY_MATRIX_PATH
    )
    providers = [
        {
            "provider": provider_id,
            "configured_enabled": False,
            "enabled_by_override": True,
            "auth_env": LIVE_AUTH_ENVS[provider_id],
            "credential_source": "env",
            "credential_configured": status == "passed" and live_checked,
            "expected_model_ids": provider_models[provider_id],
            "expected_model_ids_source": "model_alias_matrix",
            "compatibility_profile": (
                compatibility_matrix_source.provider_report_metadata(
                    LIVE_COMPATIBILITY_PROVIDER_IDS[provider_id]
                )
            ),
            "status": status,
            "live_checked": live_checked,
            "duration_ms": 1.0,
            "model_list_response": response_metadata(
                LIVE_MODEL_LIST_URLS[provider_id],
                json.dumps(
                    {"data": [{"id": model} for model in provider_models[provider_id]]},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8"),
            ),
            "attestation_response": response_metadata(
                LIVE_ATTESTATION_URLS[provider_id],
                b'{"attestation":"ok"}',
            ),
            "observed_model_ids": (
                provider_models[provider_id] if status == "passed" else []
            ),
            "new_unverified": [],
            "removed": [],
            "attestation_shape_ok": status == "passed",
            "attestation_errors": [],
            "errors": [],
        }
        for provider_id in provider_ids
    ]
    provider_count = len(providers)
    passed = provider_count if status == "passed" else 0
    skipped = provider_count if str(status).startswith("skipped") else 0
    drift = provider_count if status == "drift" else 0
    failed = provider_count if status == "failed" else 0
    report = {
        "schema": "confidential-inference.live-conformance-report.v1",
        "plan_schema": "confidential-inference.live-conformance-plan.v1",
        "completed_at": completed_at or canonical_now(),
        "network_enabled": network_enabled,
        "provider_enable_overrides": {"all": True, "providers": []},
        **artifact_metadata,
        "summary": {
            "providers": provider_count,
            "passed": passed,
            "drift": drift,
            "failed": failed,
            "skipped": skipped,
            "live_checked": provider_count if live_checked else 0,
        },
        "credentialed_live_gate": {
            "status": gate_status,
            "required_for_production": True,
            "remaining_provider_ids": remaining_provider_ids or [],
        },
        "providers": providers,
    }
    path = root / "target" / "live-conformance-prod.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, sort_keys=True, indent=2, separators=(",", ": ")) + "\n",
        encoding="utf-8",
    )
    return path


def write_dcap_dependency_audit(root: Path) -> Path:
    audit = {
        "schema": "confidential-inference.dcap-qvl-audit.v1",
        "upstream_sync_policy": {
            "path": "docs/dcap-qvl-upstream-sync.md",
            "required_release_gate": True,
            "required_commands": [
                "cargo test -p confidential-inference-providers --test dcap_qvl_audit",
                "cargo test -p confidential-inference-attestation dcap_tdx_malformed_corpus",
                "cargo test -p confidential-inference-attestation dcap_tdx_mutation_sweep",
            ],
        },
    }
    path = root / check_release_manifest.DCAP_AUDIT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(audit, sort_keys=True, indent=2, separators=(",", ": ")) + "\n",
        encoding="utf-8",
    )
    return path


def write_dcap_production_review(
    root: Path,
    *,
    status: str = "passed",
) -> Path:
    audit_path = write_dcap_dependency_audit(root)
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    review = {
        "schema": check_release_manifest.DCAP_PRODUCTION_REVIEW_SCHEMA,
        "status": status,
        "dependency_audit": {
            "path": check_release_manifest.DCAP_AUDIT_PATH.as_posix(),
            "sha256": check_release_manifest.sha256_digest(
                audit_path.read_bytes()
            ),
        },
        "reviewed_commands": audit["upstream_sync_policy"]["required_commands"],
        "independent_security_review": {
            "status": status,
            "reviewer": "external-reviewer@confidential-inference.dev",
            "completed_at": "2026-07-06T00:00:00Z",
        },
        "long_running_fuzz": {
            "status": status,
            "completed_at": "2026-07-06T00:00:00Z",
            "duration_hours": 24,
            "targets": ["dcap-qvl-tdx-quote-verification"],
            "crashes_found": 0,
        },
        "open_findings": [],
    }
    path = root / "target" / "dcap-qvl-production-review.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(review, sort_keys=True, indent=2, separators=(",", ": ")) + "\n",
        encoding="utf-8",
    )
    return path


class CheckReleaseManifestTests(unittest.TestCase):
    def test_release_manifest_matches_artifacts_lockfile_and_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
            )

            self.assertEqual(report["schema"], "confidential-inference.release-manifest-check.v1")
            self.assertEqual(report["artifact_count"], 3)
            self.assertEqual(report["release_package_archive_count"], 2)
            self.assertFalse(report["signature_verified"])
            self.assertFalse(report["live_conformance_gate_verified"])
            self.assertFalse(report["production_release_verified"])
            self.assertEqual(report["violations"], [])

    def test_production_release_requires_signature_live_conformance_and_dcap_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                require_production_release=True,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("production release requires a verified detached", joined)
            self.assertIn("production release requires a credentialed all-provider", joined)
            self.assertIn("production release requires a passed DCAP vendor", joined)
            self.assertFalse(report["signature_verified"])
            self.assertFalse(report["live_conformance_gate_verified"])
            self.assertFalse(report["dcap_production_review_verified"])
            self.assertFalse(report["production_release_verified"])

    def test_production_release_passes_with_signature_live_conformance_and_dcap_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            live_report_path = write_live_conformance_report(root)
            dcap_review_path = write_dcap_production_review(root)
            evidence_artifacts = [
                Path("target/live-conformance-prod.json"),
                Path("target/dcap-qvl-production-review.json"),
            ]
            expected_artifacts = [Path("target/confidential-inference-sbom.json"), *evidence_artifacts]
            manifest_path = write_manifest(root, evidence_artifacts)
            signature_path, trusted_key = write_manifest_signature(
                root,
                manifest_path,
                signer="confidential-inference-release",
                key_id="confidential-inference-release-ed25519",
                seed=bytes(reversed(range(32))),
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                expected_artifacts,
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                signature_path,
                [check_release_manifest.parse_trusted_release_key(trusted_key)],
                live_report_path,
                require_production_release=True,
                dcap_production_review_path=dcap_review_path,
            )

            self.assertEqual(report["violations"], [])
            self.assertTrue(report["signature_verified"])
            self.assertTrue(report["live_conformance_gate_verified"])
            self.assertTrue(report["dcap_production_review_verified"])
            self.assertTrue(report["production_release_verified"])

    def test_production_release_requires_evidence_artifacts_in_signed_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            live_report_path = write_live_conformance_report(root)
            dcap_review_path = write_dcap_production_review(root)
            manifest_path = write_manifest(root)
            signature_path, trusted_key = write_manifest_signature(
                root,
                manifest_path,
                signer="confidential-inference-release",
                key_id="confidential-inference-release-ed25519",
                seed=bytes(reversed(range(32))),
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                signature_path,
                [check_release_manifest.parse_trusted_release_key(trusted_key)],
                live_report_path,
                require_production_release=True,
                dcap_production_review_path=dcap_review_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("live conformance report must be included", joined)
            self.assertIn("DCAP production review must be included", joined)
            self.assertTrue(report["signature_verified"])
            self.assertTrue(report["live_conformance_gate_verified"])
            self.assertTrue(report["dcap_production_review_verified"])
            self.assertFalse(report["production_release_verified"])

    def test_production_release_rejects_ci_fixture_signing_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            live_report_path = write_live_conformance_report(root)
            dcap_review_path = write_dcap_production_review(root)
            evidence_artifacts = [
                Path("target/live-conformance-prod.json"),
                Path("target/dcap-qvl-production-review.json"),
            ]
            expected_artifacts = [Path("target/confidential-inference-sbom.json"), *evidence_artifacts]
            manifest_path = write_manifest(root, evidence_artifacts)
            signature_path, trusted_key = write_manifest_signature(
                root,
                manifest_path,
                signer="confidential-inference-release-ci",
                key_id="release-ci-key",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                expected_artifacts,
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                signature_path,
                [check_release_manifest.parse_trusted_release_key(trusted_key)],
                live_report_path,
                require_production_release=True,
                dcap_production_review_path=dcap_review_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("must not use CI/test release signing key", joined)
            self.assertIn("production release requires a verified detached", joined)
            self.assertFalse(report["signature_verified"])
            self.assertTrue(report["live_conformance_gate_verified"])
            self.assertTrue(report["dcap_production_review_verified"])
            self.assertFalse(report["production_release_verified"])

    def test_production_release_rejects_relabelled_ci_fixture_public_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            live_report_path = write_live_conformance_report(root)
            dcap_review_path = write_dcap_production_review(root)
            evidence_artifacts = [
                Path("target/live-conformance-prod.json"),
                Path("target/dcap-qvl-production-review.json"),
            ]
            expected_artifacts = [Path("target/confidential-inference-sbom.json"), *evidence_artifacts]
            manifest_path = write_manifest(root, evidence_artifacts)
            signature_path, trusted_key = write_manifest_signature(
                root,
                manifest_path,
                signer="confidential-inference-release",
                key_id="confidential-inference-release-ed25519",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                expected_artifacts,
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                signature_path,
                [check_release_manifest.parse_trusted_release_key(trusted_key)],
                live_report_path,
                require_production_release=True,
                dcap_production_review_path=dcap_review_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("must not use CI/test release public key", joined)
            self.assertIn("production release requires a verified detached", joined)
            self.assertFalse(report["signature_verified"])
            self.assertTrue(report["live_conformance_gate_verified"])
            self.assertTrue(report["dcap_production_review_verified"])
            self.assertFalse(report["production_release_verified"])

    def test_production_release_rejects_ci_public_key_in_trusted_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            live_report_path = write_live_conformance_report(root)
            dcap_review_path = write_dcap_production_review(root)
            evidence_artifacts = [
                Path("target/live-conformance-prod.json"),
                Path("target/dcap-qvl-production-review.json"),
            ]
            expected_artifacts = [Path("target/confidential-inference-sbom.json"), *evidence_artifacts]
            manifest_path = write_manifest(root, evidence_artifacts)
            signature_path, trusted_key = write_manifest_signature(
                root,
                manifest_path,
                signer="confidential-inference-release",
                key_id="confidential-inference-release-ed25519",
            )
            signature_doc = json.loads(signature_path.read_text(encoding="utf-8"))
            signature_doc.pop("public_key_base64url")
            signature_path.write_text(
                json.dumps(signature_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                expected_artifacts,
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                signature_path,
                [check_release_manifest.parse_trusted_release_key(trusted_key)],
                live_report_path,
                require_production_release=True,
                dcap_production_review_path=dcap_review_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("must not trust CI/test release public key", joined)
            self.assertIn("production release requires a verified detached", joined)
            self.assertFalse(report["signature_verified"])
            self.assertTrue(report["live_conformance_gate_verified"])
            self.assertTrue(report["dcap_production_review_verified"])
            self.assertFalse(report["production_release_verified"])

    def test_release_manifest_can_require_credentialed_live_conformance_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            self.assertEqual(report["violations"], [])
            self.assertTrue(report["live_conformance_gate_verified"])

    def test_release_manifest_can_validate_dcap_production_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            dcap_review_path = write_dcap_production_review(root)

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                dcap_production_review_path=dcap_review_path,
            )

            self.assertEqual(report["violations"], [])
            self.assertTrue(report["dcap_production_review_verified"])

    def test_dcap_production_review_rejects_stale_audit_open_findings_and_crashes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            dcap_review_path = write_dcap_production_review(root)
            review = json.loads(dcap_review_path.read_text(encoding="utf-8"))
            review["dependency_audit"]["sha256"] = "sha256:" + ("0" * 64)
            review["reviewed_commands"] = [
                "cargo test -p confidential-inference-providers --test dcap_qvl_audit",
                "cargo test -p confidential-inference-providers --test dcap_qvl_audit",
                "cargo test -p confidential-inference-attestation dcap_tdx_malformed_corpus",
                "extra smoke test",
            ]
            review["independent_security_review"]["status"] = "failed"
            review["independent_security_review"]["completed_at"] = "2026-07-06 00:00:00Z"
            review["long_running_fuzz"]["completed_at"] = "not-a-timestamp"
            review["long_running_fuzz"]["duration_hours"] = 1
            review["long_running_fuzz"]["crashes_found"] = 1
            review["open_findings"] = ["manual review follow-up"]
            dcap_review_path.write_text(
                json.dumps(review, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                dcap_production_review_path=dcap_review_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("dependency_audit.sha256 does not match", joined)
            self.assertIn("reviewed_commands is missing required", joined)
            self.assertIn("reviewed_commands must not contain duplicates", joined)
            self.assertIn("reviewed_commands contains commands not required", joined)
            self.assertIn("independent_security_review.status must be passed", joined)
            self.assertIn("independent_security_review.completed_at", joined)
            self.assertIn("long_running_fuzz.completed_at", joined)
            self.assertIn("duration_hours must be at least 24", joined)
            self.assertIn("crashes_found must be zero", joined)
            self.assertIn("open_findings must be empty", joined)
            self.assertFalse(report["dcap_production_review_verified"])

    def test_release_manifest_rejects_live_report_missing_plan_providers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(
                root,
                provider_ids=("tinfoil",),
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn(
                "providers must match fixtures/providers/live-conformance-plan.json",
                joined,
            )
            self.assertIn("venice", joined)
            self.assertIn("ionet", joined)
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_live_report_without_provider_enable_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)
            report_doc = json.loads(live_report_path.read_text(encoding="utf-8"))
            report_doc["provider_enable_overrides"] = {"all": False, "providers": []}
            provider = report_doc["providers"][0]
            provider["enabled_by_override"] = False
            live_report_path.write_text(
                json.dumps(report_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("enabled_by_override must be true", joined)
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_live_report_without_credential_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)
            report_doc = json.loads(live_report_path.read_text(encoding="utf-8"))
            provider = report_doc["providers"][0]
            provider.pop("auth_env")
            provider["credential_source"] = "none"
            provider["credential_configured"] = False
            live_report_path.write_text(
                json.dumps(report_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("auth_env must match", joined)
            self.assertIn("credential_source must be env", joined)
            self.assertIn("credential_configured must be true", joined)
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_production_plan_without_credential_env(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)
            plan_path = root / check_release_manifest.LIVE_CONFORMANCE_PLAN_PATH
            plan_doc = json.loads(plan_path.read_text(encoding="utf-8"))
            plan_doc["providers"][0].pop("auth_env")
            plan_path.write_text(
                json.dumps(plan_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            self.assertIn(
                "to define a credential environment variable",
                "\n".join(report["violations"]),
            )
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_live_report_stale_matrix_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)
            report_doc = json.loads(live_report_path.read_text(encoding="utf-8"))
            report_doc["model_alias_matrix"]["digest"] = "sha256:" + ("0" * 64)
            report_doc["compatibility_matrix_envelope"]["payload_digest"] = (
                "sha256:" + ("1" * 64)
            )
            live_report_path.write_text(
                json.dumps(report_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("model_alias_matrix.digest does not match", joined)
            self.assertIn(
                "compatibility_matrix_envelope.payload_digest does not match",
                joined,
            )
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_missing_stale_or_future_live_report_timestamp(
        self,
    ) -> None:
        cases = (
            ("missing", None, "completed_at must be a canonical UTC RFC3339 timestamp string"),
            ("stale", "2020-01-01T00:00:00Z", "completed_at is older than"),
            (
                "future",
                (
                    datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(hours=1)
                )
                .replace(microsecond=0)
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
                "completed_at must not be in the future",
            ),
        )
        for label, timestamp, expected in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    write_workspace(root)
                    manifest_path = write_manifest(root)
                    live_report_path = write_live_conformance_report(
                        root,
                        completed_at=timestamp or canonical_now(),
                    )
                    if timestamp is None:
                        report_doc = json.loads(live_report_path.read_text(encoding="utf-8"))
                        report_doc.pop("completed_at")
                        live_report_path.write_text(
                            json.dumps(
                                report_doc,
                                sort_keys=True,
                                indent=2,
                                separators=(",", ": "),
                            )
                            + "\n",
                            encoding="utf-8",
                        )

                    report = check_release_manifest.validate_manifest(
                        root,
                        manifest_path,
                        [Path("target/confidential-inference-sbom.json")],
                        ["target/package/*.crate"],
                        Path("target/confidential-inference-sbom.json"),
                        live_conformance_report_path=live_report_path,
                    )

                    self.assertIn(expected, "\n".join(report["violations"]))
                    self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_live_report_plan_trust_artifact_path_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)
            plan_path = root / check_release_manifest.LIVE_CONFORMANCE_PLAN_PATH
            plan_doc = json.loads(plan_path.read_text(encoding="utf-8"))
            plan_doc["compatibility_matrix_path"] = "fixtures/providers/other.json"
            plan_path.write_text(
                json.dumps(plan_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            self.assertIn(
                "live conformance plan compatibility_matrix_path must be",
                "\n".join(report["violations"]),
            )
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_live_report_stale_model_alias_models(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)
            report_doc = json.loads(live_report_path.read_text(encoding="utf-8"))
            report_doc["providers"][0]["expected_model_ids"] = ["tampered-model"]
            report_doc["providers"][0]["observed_model_ids"] = ["tampered-model"]
            live_report_path.write_text(
                json.dumps(report_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn(
                "expected_model_ids must match signed model alias matrix provider",
                joined,
            )
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_live_report_missing_response_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)
            report_doc = json.loads(live_report_path.read_text(encoding="utf-8"))
            provider = report_doc["providers"][0]
            provider.pop("model_list_response")
            provider["attestation_response"]["url"] = "https://api.redpill.ai/evidence"
            provider["attestation_response"]["body_sha256"] = "not-a-digest"
            provider["attestation_response"]["body_size"] = 0
            live_report_path.write_text(
                json.dumps(report_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("model_list_response must be an object", joined)
            self.assertIn("attestation_response.url must match", joined)
            self.assertIn("attestation_response.body_sha256 must be", joined)
            self.assertIn("attestation_response.body_size must be positive", joined)
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_live_report_stale_compatibility_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)
            report_doc = json.loads(live_report_path.read_text(encoding="utf-8"))
            report_doc["providers"][0]["compatibility_profile"]["request_encryption"] = (
                "required"
            )
            live_report_path.write_text(
                json.dumps(report_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn(
                "compatibility_profile must match signed compatibility matrix provider",
                joined,
            )
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_fixture_only_compatibility_profiles_for_production(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(
                root,
                production_compatibility=False,
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("route_execution_status must be executable", joined)
            self.assertIn("model_listing must be live_catalog", joined)
            self.assertIn("attestation_endpoint_shape must not be fixture-based", joined)
            self.assertIn("production live blockers", joined)
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_live_report_with_invalid_trust_artifact_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)
            envelope_path = root / check_release_manifest.MODEL_ALIAS_MATRIX_ENVELOPE_PATH
            envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
            signature_value = envelope["signature"]["value"]
            envelope["signature"]["value"] = (
                signature_value[:-1] + ("A" if signature_value[-1] != "A" else "B")
            )
            envelope_path.write_text(
                json.dumps(envelope, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )
            report_doc = json.loads(live_report_path.read_text(encoding="utf-8"))
            report_doc["model_alias_matrix_envelope"]["digest"] = (
                check_release_manifest.canonical_sha256_digest(envelope)
            )
            report_doc["model_alias_matrix_envelope"]["signature"] = envelope["signature"]
            live_report_path.write_text(
                json.dumps(report_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            self.assertIn("signature is invalid", "\n".join(report["violations"]))
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_dry_run_live_conformance_report_for_production(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(
                root,
                network_enabled=False,
                status="skipped_disabled",
                live_checked=False,
                gate_status="open",
                remaining_provider_ids=["tinfoil"],
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("network_enabled=true", joined)
            self.assertIn("credentialed_live_gate.status must be passed", joined)
            self.assertIn("did not pass credentialed live checks", joined)
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_passed_live_report_with_hidden_provider_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)
            report_doc = json.loads(live_report_path.read_text(encoding="utf-8"))
            provider = report_doc["providers"][0]
            provider["new_unverified"] = ["unreviewed-live-model"]
            provider["observed_model_ids"] = ["different-model"]
            provider["attestation_shape_ok"] = False
            provider["attestation_errors"] = ["missing JSON field 'attestation'"]
            provider["errors"] = ["model list warning"]
            provider["expected_model_ids_source"] = "plan"
            live_report_path.write_text(
                json.dumps(report_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("expected_model_ids_source must be model_alias_matrix", joined)
            self.assertIn("observed_model_ids must match expected_model_ids", joined)
            self.assertIn("new_unverified must be empty", joined)
            self.assertIn("attestation_errors must be empty", joined)
            self.assertIn("errors must be empty", joined)
            self.assertIn("attestation_shape_ok must be true", joined)
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_rejects_passed_live_report_with_empty_model_lists(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            live_report_path = write_live_conformance_report(root)
            report_doc = json.loads(live_report_path.read_text(encoding="utf-8"))
            provider = report_doc["providers"][0]
            provider["expected_model_ids"] = []
            provider["observed_model_ids"] = []
            live_report_path.write_text(
                json.dumps(report_doc, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                live_conformance_report_path=live_report_path,
            )

            joined = "\n".join(report["violations"])
            self.assertIn("expected_model_ids must be non-empty", joined)
            self.assertIn("observed_model_ids must be non-empty", joined)
            self.assertFalse(report["live_conformance_gate_verified"])

    def test_release_manifest_signature_verifies_with_trusted_release_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            signature_path, trusted_key = write_manifest_signature(root, manifest_path)

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                signature_path,
                [check_release_manifest.parse_trusted_release_key(trusted_key)],
            )

            self.assertEqual(report["violations"], [])
            self.assertTrue(report["signature_verified"])

    def test_release_manifest_signature_requires_trusted_key_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            signature_path, trusted_key = write_manifest_signature(root, manifest_path)

            missing_key_report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                signature_path,
                [],
            )
            self.assertIn(
                "trusted release signing key is required",
                "\n".join(missing_key_report["violations"]),
            )
            self.assertFalse(missing_key_report["signature_verified"])

            signature = json.loads(signature_path.read_text(encoding="utf-8"))
            encoded_signature = signature["signature"]["value"]
            value_offset = len("base64url:")
            signature["signature"]["value"] = (
                encoded_signature[:value_offset]
                + ("A" if encoded_signature[value_offset] != "A" else "B")
                + encoded_signature[value_offset + 1 :]
            )
            signature_path.write_text(
                json.dumps(signature, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )
            tampered_report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                signature_path,
                [check_release_manifest.parse_trusted_release_key(trusted_key)],
            )

            self.assertIn(
                "release manifest signature is invalid",
                "\n".join(tampered_report["violations"]),
            )
            self.assertFalse(tampered_report["signature_verified"])

    def test_release_manifest_signature_metadata_must_match_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            signature_path, trusted_key = write_manifest_signature(root, manifest_path)
            signature = json.loads(signature_path.read_text(encoding="utf-8"))
            signature["manifest_path"] = "target/other-release-manifest.json"
            signature["signed_payload"] = {"format": "json"}
            signature_path.write_text(
                json.dumps(signature, sort_keys=True, indent=2, separators=(",", ": "))
                + "\n",
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
                signature_path,
                [check_release_manifest.parse_trusted_release_key(trusted_key)],
            )

            joined = "\n".join(report["violations"])
            self.assertIn("release signature manifest_path must be", joined)
            self.assertIn("release signature signed_payload does not match", joined)
            self.assertFalse(report["signature_verified"])

    def test_trusted_release_key_argument_requires_public_key_metadata(self) -> None:
        with self.assertRaises(check_release_manifest.ReleaseManifestError):
            check_release_manifest.parse_trusted_release_key("missing-parts")

    def test_release_manifest_requires_every_publishable_workspace_crate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["artifacts"] = [
                artifact
                for artifact in manifest["artifacts"]
                if artifact["path"] != "target/package/confidential-inference-providers-0.1.0.crate"
            ]
            manifest["artifact_count"] = len(manifest["artifacts"])
            manifest_path.write_text(
                generate_release_manifest.render_manifest(manifest),
                encoding="utf-8",
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [],
                [],
                Path("target/confidential-inference-sbom.json"),
            )

            joined = "\n".join(report["violations"])
            self.assertIn("publishable workspace packages", joined)
            self.assertIn("confidential-inference-providers-0.1.0.crate", joined)

    def test_release_manifest_rejects_stale_artifact_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            (root / "target" / "package" / "confidential-inference-sdk-0.1.0.crate").write_bytes(
                b"tampered crate"
            )

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
            )

            joined = "\n".join(report["violations"])
            self.assertIn("sha256 does not match current file", joined)
            self.assertIn("size does not match current file", joined)

    def test_release_manifest_rejects_wrong_expected_artifact_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            extra = root / "target" / "manual-extra.crate"
            extra.write_bytes(b"extra")

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json"), Path("target/manual-extra.crate")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
            )

            joined = "\n".join(report["violations"])
            self.assertIn("artifact set does not match expected artifact inputs", joined)

    def test_release_manifest_must_be_canonical_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_workspace(root)
            manifest_path = write_manifest(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            report = check_release_manifest.validate_manifest(
                root,
                manifest_path,
                [Path("target/confidential-inference-sbom.json")],
                ["target/package/*.crate"],
                Path("target/confidential-inference-sbom.json"),
            )

            joined = "\n".join(report["violations"])
            self.assertIn("not canonical JSON", joined)


if __name__ == "__main__":
    unittest.main()
