#!/usr/bin/env python3
"""Validate a generated release checksum manifest against current artifacts."""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

from generate_release_manifest import (
    SCHEMA as RELEASE_MANIFEST_SCHEMA,
    SIGNATURE_SCHEMA as RELEASE_SIGNATURE_SCHEMA,
    SIGNING_CANONICALIZATION,
    ReleaseManifestError,
    _artifact_record,
    _relative_path,
    _workspace_package_metadata,
    expand_artifact_inputs,
    render_manifest,
    sha256_digest,
)
from live_conformance import (
    LiveConformanceError,
    canonical_json,
    canonical_sha256_digest,
    load_compatibility_matrix,
    load_compatibility_matrix_envelope,
    load_model_alias_matrix,
    load_model_alias_matrix_envelope,
    validate_compatibility_matrix_envelope_matches_payload,
    validate_model_alias_matrix_envelope_matches_payload,
)
from artifact_signatures import (
    ArtifactSignatureError,
    TrustedSigningKey,
    verify_artifact_signature,
)


SCHEMA = "confidential-inference.release-manifest-check.v1"
SBOM_SCHEMA = "confidential-inference.sbom.v1"
LIVE_CONFORMANCE_REPORT_SCHEMA = "confidential-inference.live-conformance-report.v1"
LIVE_CONFORMANCE_PLAN_SCHEMA = "confidential-inference.live-conformance-plan.v1"
LIVE_CONFORMANCE_PLAN_PATH = Path("fixtures/providers/live-conformance-plan.json")
MODEL_ALIAS_MATRIX_PATH = Path("fixtures/registry/model-alias-matrix.json")
MODEL_ALIAS_MATRIX_ENVELOPE_PATH = Path("fixtures/registry/model-alias-matrix-envelope.json")
COMPATIBILITY_MATRIX_PATH = Path("fixtures/providers/compatibility-matrix.json")
COMPATIBILITY_MATRIX_ENVELOPE_PATH = Path("fixtures/providers/compatibility-matrix-envelope.json")
DCAP_PRODUCTION_REVIEW_SCHEMA = "confidential-inference.dcap-qvl-production-review.v1"
DCAP_AUDIT_PATH = Path("fixtures/supply-chain/dcap-qvl-audit.json")
MIN_DCAP_FUZZ_DURATION_HOURS = 24
MAX_LIVE_CONFORMANCE_REPORT_AGE_HOURS = 24
MAX_LIVE_CONFORMANCE_REPORT_FUTURE_SKEW_SECONDS = 300
SHA256_PREFIX = "sha256:"
SHA256_HEX = set("0123456789abcdef")
UTC_TIMESTAMP_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$"
)
SIGNING_PAYLOAD = {
    "format": "json",
    "canonicalization": SIGNING_CANONICALIZATION,
    "required_release_signatures": [
        "detached ed25519 signature over canonical manifest bytes"
    ],
}
SIGNATURE_SIGNED_PAYLOAD = {
    "format": "raw-bytes",
    "canonicalization": SIGNING_CANONICALIZATION,
}
FORBIDDEN_PRODUCTION_RELEASE_SIGNING_KEYS = {
    ("confidential-inference-release-ci", "release-ci-key"),
    ("confidential-inference-release-test", "release-test-key"),
}
FORBIDDEN_PRODUCTION_RELEASE_PUBLIC_KEYS = {
    # Public key for the documented CI/test seed:
    # AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
    "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
}


def load_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def is_sha256_digest(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith(SHA256_PREFIX):
        return False
    digest = value[len(SHA256_PREFIX) :]
    return len(digest) == 64 and all(character in SHA256_HEX for character in digest)


def _workspace_members(root_manifest: dict[str, Any]) -> list[str]:
    members = root_manifest.get("workspace", {}).get("members", [])
    if not isinstance(members, list):
        return []
    return [str(member) for member in members]


def _package_version(
    manifest_path: Path,
    package: dict[str, Any],
    workspace_version: Any,
    violations: list[str],
) -> str | None:
    version = package.get("version")
    if isinstance(version, str) and version:
        return version
    if isinstance(version, dict) and version.get("workspace") is True:
        if isinstance(workspace_version, str) and workspace_version:
            return workspace_version
        violations.append(
            f"{manifest_path}: package.version inherits missing workspace.package.version"
        )
        return None
    violations.append(f"{manifest_path}: package.version is required for release coverage")
    return None


def _expected_release_package_archives(
    workspace_root: Path,
    violations: list[str],
) -> list[str]:
    root_manifest_path = workspace_root / "Cargo.toml"
    try:
        root_manifest = load_toml(root_manifest_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        violations.append(f"{root_manifest_path}: cannot load workspace manifest: {error}")
        return []

    workspace_version = root_manifest.get("workspace", {}).get("package", {}).get("version")
    expected: list[str] = []
    for member in _workspace_members(root_manifest):
        manifest_path = workspace_root / member / "Cargo.toml"
        try:
            manifest = load_toml(manifest_path)
        except (OSError, tomllib.TOMLDecodeError) as error:
            violations.append(f"{manifest_path}: cannot load member manifest: {error}")
            continue
        package = manifest.get("package")
        if not isinstance(package, dict):
            violations.append(f"{manifest_path}: package section is required")
            continue
        if package.get("publish") is False:
            continue
        name = package.get("name")
        if not isinstance(name, str) or not name:
            violations.append(f"{manifest_path}: package.name is required")
            continue
        version = _package_version(manifest_path, package, workspace_version, violations)
        if version is None:
            continue
        expected.append(f"target/package/{name}-{version}.crate")
    return sorted(expected)


def _manifest_artifact_paths(manifest: dict[str, Any], violations: list[str]) -> list[str]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        violations.append("manifest artifacts must be an array")
        return []

    paths: list[str] = []
    for index, artifact in enumerate(artifacts):
        subject = f"manifest artifacts[{index}]"
        if not isinstance(artifact, dict):
            violations.append(f"{subject} must be an object")
            continue
        path = artifact.get("path")
        if not isinstance(path, str) or not path:
            violations.append(f"{subject}.path must be a non-empty string")
            continue
        if Path(path).is_absolute():
            violations.append(f"{subject}.path must be workspace-relative")
            continue
        if Path(path).name.startswith("."):
            violations.append(f"{subject}.path must not reference hidden artifacts")
            continue
        paths.append(path)

    if paths != sorted(paths):
        violations.append("manifest artifacts must be sorted by path")
    duplicates = sorted({path for path in paths if paths.count(path) > 1})
    if duplicates:
        violations.append(f"manifest artifacts contain duplicate paths {duplicates}")
    if manifest.get("artifact_count") != len(artifacts):
        violations.append("manifest artifact_count does not match artifacts length")
    return paths


def _validate_artifact_records(
    workspace_root: Path,
    manifest: dict[str, Any],
    violations: list[str],
) -> list[str]:
    paths = _manifest_artifact_paths(manifest, violations)
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return paths

    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            continue
        relative_path = artifact["path"]
        path = workspace_root / relative_path
        try:
            expected = _artifact_record(path, workspace_root)
        except (OSError, ReleaseManifestError) as error:
            violations.append(f"manifest artifacts[{index}] {relative_path}: {error}")
            continue
        for field in ("path", "size", "sha256", "mode"):
            if artifact.get(field) != expected[field]:
                violations.append(
                    f"manifest artifacts[{index}] {relative_path}: {field} "
                    f"does not match current file"
                )
        if not is_sha256_digest(artifact.get("sha256")):
            violations.append(
                f"manifest artifacts[{index}] {relative_path}: sha256 is not canonical"
            )
    return paths


def _validate_release_package_archive_coverage(
    workspace_root: Path,
    manifest_paths: list[str],
    violations: list[str],
) -> list[str]:
    expected = _expected_release_package_archives(workspace_root, violations)
    if not expected:
        return expected
    package_archives = sorted(
        path
        for path in manifest_paths
        if path.startswith("target/package/") and Path(path).suffix == ".crate"
    )
    if package_archives != expected:
        missing = sorted(set(expected) - set(package_archives))
        extra = sorted(set(package_archives) - set(expected))
        violations.append(
            "manifest package archives do not cover publishable workspace packages: "
            f"missing={missing} extra={extra}"
        )
    return expected


def _validate_expected_artifact_set(
    workspace_root: Path,
    manifest_paths: list[str],
    artifacts: list[Path],
    artifact_globs: list[str],
    violations: list[str],
) -> None:
    if not artifacts and not artifact_globs:
        return
    try:
        expected_paths = sorted(
            _relative_path(
                path if path.is_absolute() else workspace_root / path,
                workspace_root,
            )
            for path in expand_artifact_inputs(workspace_root, artifacts, artifact_globs)
        )
    except (OSError, ReleaseManifestError) as error:
        violations.append(f"expected artifact inputs are invalid: {error}")
        return
    if sorted(manifest_paths) != expected_paths:
        violations.append(
            "manifest artifact set does not match expected artifact inputs: "
            f"expected={expected_paths} actual={sorted(manifest_paths)}"
        )


def _validate_production_evidence_artifact_coverage(
    workspace_root: Path,
    manifest_paths: list[str],
    live_conformance_report_path: Path | None,
    dcap_production_review_path: Path | None,
    violations: list[str],
) -> None:
    required_artifacts = (
        ("live conformance report", live_conformance_report_path),
        ("DCAP production review", dcap_production_review_path),
    )
    for label, path in required_artifacts:
        if path is None:
            continue
        try:
            relative_path = _relative_path(
                path if path.is_absolute() else workspace_root / path,
                workspace_root,
            )
        except ReleaseManifestError as error:
            violations.append(f"production {label} path is invalid: {error}")
            continue
        if relative_path not in manifest_paths:
            violations.append(
                f"production {label} must be included in the signed release manifest "
                f"artifacts: {relative_path}"
            )


def _validate_sbom(
    workspace_root: Path,
    manifest: dict[str, Any],
    expected_sbom_path: Path | None,
    violations: list[str],
) -> None:
    sbom = manifest.get("sbom")
    if expected_sbom_path is not None and not isinstance(sbom, dict):
        violations.append("manifest sbom section is required")
        return
    if sbom is None:
        return
    if not isinstance(sbom, dict):
        violations.append("manifest sbom must be an object")
        return
    path_value = sbom.get("path")
    if not isinstance(path_value, str) or not path_value:
        violations.append("manifest sbom.path must be a non-empty string")
        return
    if Path(path_value).is_absolute():
        violations.append("manifest sbom.path must be workspace-relative")
        return

    if expected_sbom_path is not None:
        try:
            expected_relative = _relative_path(
                expected_sbom_path
                if expected_sbom_path.is_absolute()
                else workspace_root / expected_sbom_path,
                workspace_root,
            )
        except ReleaseManifestError as error:
            violations.append(f"expected SBOM path is invalid: {error}")
            return
        if path_value != expected_relative:
            violations.append(
                f"manifest sbom.path must be {expected_relative}, got {path_value}"
            )

    sbom_path = workspace_root / path_value
    try:
        data = sbom_path.read_bytes()
    except OSError as error:
        violations.append(f"manifest sbom.path cannot be read: {error}")
        return
    digest = sha256_digest(data)
    if sbom.get("sha256") != digest:
        violations.append("manifest sbom.sha256 does not match current SBOM file")
    if not is_sha256_digest(sbom.get("sha256")):
        violations.append("manifest sbom.sha256 is not canonical")
    try:
        sbom_payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        violations.append(f"manifest SBOM file is not valid JSON: {error}")
        return
    if not isinstance(sbom_payload, dict) or sbom_payload.get("schema") != SBOM_SCHEMA:
        violations.append(f"manifest SBOM file schema must be {SBOM_SCHEMA}")


def _int_field(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _string_list_field(value: Any) -> list[str] | None:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        return None
    return value


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _parse_canonical_utc_timestamp(
    subject: str,
    value: Any,
    violations: list[str],
) -> datetime.datetime | None:
    if not isinstance(value, str):
        violations.append(f"{subject} must be a canonical UTC RFC3339 timestamp string")
        return None
    match = UTC_TIMESTAMP_RE.match(value)
    if match is None:
        violations.append(f"{subject} must be a canonical UTC RFC3339 timestamp")
        return None
    year, month, day, hour, minute, second, millis = match.groups()
    try:
        timestamp = datetime.datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second),
            int(millis) * 1000 if millis else 0,
            tzinfo=datetime.timezone.utc,
        )
    except ValueError:
        violations.append(f"{subject} contains an out-of-range timestamp component")
        return None
    if timestamp < datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc):
        violations.append(f"{subject} must not be before the Unix epoch")
        return None
    return timestamp


def _validate_canonical_utc_timestamp(
    subject: str,
    value: Any,
    violations: list[str],
) -> None:
    _parse_canonical_utc_timestamp(subject, value, violations)


def _validate_live_report_freshness(
    report: dict[str, Any],
    violations: list[str],
) -> None:
    completed_at = _parse_canonical_utc_timestamp(
        "live conformance report completed_at",
        report.get("completed_at"),
        violations,
    )
    if completed_at is None:
        return
    now = datetime.datetime.now(datetime.timezone.utc)
    future_skew = datetime.timedelta(
        seconds=MAX_LIVE_CONFORMANCE_REPORT_FUTURE_SKEW_SECONDS
    )
    if completed_at - now > future_skew:
        violations.append("live conformance report completed_at must not be in the future")
        return
    max_age = datetime.timedelta(hours=MAX_LIVE_CONFORMANCE_REPORT_AGE_HOURS)
    if now - completed_at > max_age:
        violations.append(
            "live conformance report completed_at is older than "
            f"{MAX_LIVE_CONFORMANCE_REPORT_AGE_HOURS} hours"
        )


def _load_json_artifact(
    workspace_root: Path,
    relative_path: Path,
    violations: list[str],
) -> Any:
    path = workspace_root / relative_path
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        violations.append(f"{relative_path.as_posix()} cannot be loaded: {error}")
        return None


def _validate_live_report_artifact_metadata(
    report: dict[str, Any],
    workspace_root: Path,
    section: str,
    relative_path: Path,
    violations: list[str],
    *,
    require_payload_digest: bool,
) -> None:
    metadata = report.get(section)
    if not isinstance(metadata, dict):
        violations.append(f"live conformance report {section} must be an object")
        return
    if metadata.get("path") != relative_path.as_posix():
        violations.append(
            f"live conformance report {section}.path must be {relative_path.as_posix()}"
        )

    artifact = _load_json_artifact(workspace_root, relative_path, violations)
    if artifact is None:
        return
    artifact_digest = canonical_sha256_digest(artifact)
    if metadata.get("digest") != artifact_digest:
        violations.append(
            f"live conformance report {section}.digest does not match current "
            f"{relative_path.as_posix()}"
        )
    if require_payload_digest:
        payload = artifact.get("payload") if isinstance(artifact, dict) else None
        if not isinstance(payload, dict):
            violations.append(f"{relative_path.as_posix()} payload must be an object")
            return
        payload_digest = canonical_sha256_digest(payload)
        if metadata.get("payload_digest") != payload_digest:
            violations.append(
                f"live conformance report {section}.payload_digest does not match "
                f"current {relative_path.as_posix()} payload"
            )
        signature = artifact.get("signature")
        if isinstance(signature, dict) and metadata.get("signature") != signature:
            violations.append(
                f"live conformance report {section}.signature does not match current "
                f"{relative_path.as_posix()}"
            )
        elif not isinstance(signature, dict):
            violations.append(f"{relative_path.as_posix()} signature must be an object")
        else:
            try:
                verify_artifact_signature(
                    signature,
                    canonical_json(payload).encode("utf-8"),
                    relative_path.as_posix(),
                )
            except (ArtifactSignatureError, ValueError) as error:
                violations.append(str(error))


def _validate_live_report_trust_artifact_metadata(
    report: dict[str, Any],
    workspace_root: Path,
    violations: list[str],
) -> None:
    _validate_live_report_artifact_metadata(
        report,
        workspace_root,
        "model_alias_matrix",
        MODEL_ALIAS_MATRIX_PATH,
        violations,
        require_payload_digest=False,
    )
    _validate_live_report_artifact_metadata(
        report,
        workspace_root,
        "model_alias_matrix_envelope",
        MODEL_ALIAS_MATRIX_ENVELOPE_PATH,
        violations,
        require_payload_digest=True,
    )
    _validate_live_report_artifact_metadata(
        report,
        workspace_root,
        "compatibility_matrix",
        COMPATIBILITY_MATRIX_PATH,
        violations,
        require_payload_digest=False,
    )
    _validate_live_report_artifact_metadata(
        report,
        workspace_root,
        "compatibility_matrix_envelope",
        COMPATIBILITY_MATRIX_ENVELOPE_PATH,
        violations,
        require_payload_digest=True,
    )


def _signed_live_compatibility_profiles(
    workspace_root: Path,
    violations: list[str],
) -> dict[str, dict[str, Any]] | None:
    try:
        matrix_source = load_compatibility_matrix(workspace_root / COMPATIBILITY_MATRIX_PATH)
        envelope_source = load_compatibility_matrix_envelope(
            workspace_root / COMPATIBILITY_MATRIX_ENVELOPE_PATH
        )
        validate_compatibility_matrix_envelope_matches_payload(
            matrix_source,
            envelope_source,
        )
    except LiveConformanceError as error:
        violations.append(f"live conformance compatibility matrix cannot be verified: {error}")
        return None

    return {
        provider_id: matrix_source.provider_report_metadata(provider_id)
        for provider_id in matrix_source.profiles
    }


def _signed_live_model_alias_provider_models(
    workspace_root: Path,
    violations: list[str],
) -> dict[str, list[str]] | None:
    try:
        matrix_source = load_model_alias_matrix(workspace_root / MODEL_ALIAS_MATRIX_PATH)
        envelope_source = load_model_alias_matrix_envelope(
            workspace_root / MODEL_ALIAS_MATRIX_ENVELOPE_PATH
        )
        validate_model_alias_matrix_envelope_matches_payload(
            matrix_source,
            envelope_source,
        )
    except LiveConformanceError as error:
        violations.append(f"live conformance model alias matrix cannot be verified: {error}")
        return None

    return matrix_source.provider_models


def _expected_live_conformance_plan_providers(
    workspace_root: Path,
    violations: list[str],
) -> dict[str, dict[str, Any]]:
    plan_path = workspace_root / LIVE_CONFORMANCE_PLAN_PATH
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        violations.append(
            f"live conformance plan cannot be loaded from "
            f"{LIVE_CONFORMANCE_PLAN_PATH.as_posix()}: {error}"
        )
        return {}
    if not isinstance(plan, dict):
        violations.append("live conformance plan must be an object")
        return {}
    if plan.get("schema") != LIVE_CONFORMANCE_PLAN_SCHEMA:
        violations.append(
            f"live conformance plan schema must be {LIVE_CONFORMANCE_PLAN_SCHEMA}"
        )
    for field, expected_path in (
        ("model_alias_matrix_path", MODEL_ALIAS_MATRIX_PATH),
        ("model_alias_matrix_envelope_path", MODEL_ALIAS_MATRIX_ENVELOPE_PATH),
        ("compatibility_matrix_path", COMPATIBILITY_MATRIX_PATH),
        ("compatibility_matrix_envelope_path", COMPATIBILITY_MATRIX_ENVELOPE_PATH),
    ):
        if plan.get(field) != expected_path.as_posix():
            violations.append(
                f"live conformance plan {field} must be {expected_path.as_posix()}"
            )
    providers = plan.get("providers")
    if not isinstance(providers, list) or not providers:
        violations.append("live conformance plan providers must be a non-empty array")
        return {}
    plan_providers: dict[str, dict[str, Any]] = {}
    for index, provider in enumerate(providers):
        if not isinstance(provider, dict):
            violations.append(f"live conformance plan providers[{index}] must be an object")
            continue
        provider_id = provider.get("id")
        if not isinstance(provider_id, str) or not provider_id:
            violations.append(
                f"live conformance plan providers[{index}].id must be non-empty"
            )
            continue
        if provider_id in plan_providers:
            violations.append(
                f"live conformance plan provider ids must be unique: {provider_id}"
            )
            continue
        plan_providers[provider_id] = provider
    return plan_providers


def _expected_live_conformance_provider_ids(
    workspace_root: Path,
    violations: list[str],
) -> list[str]:
    return sorted(
        _expected_live_conformance_plan_providers(workspace_root, violations)
    )


def _live_report_provider_enable_overrides(
    report: dict[str, Any],
    violations: list[str],
) -> tuple[bool, list[str]]:
    overrides = report.get("provider_enable_overrides")
    if not isinstance(overrides, dict):
        violations.append("live conformance report provider_enable_overrides must be an object")
        return False, []
    enable_all = overrides.get("all")
    if not isinstance(enable_all, bool):
        violations.append("live conformance report provider_enable_overrides.all must be a boolean")
        enable_all = False
    enabled_providers = _string_list_field(overrides.get("providers"))
    if enabled_providers is None:
        violations.append(
            "live conformance report provider_enable_overrides.providers must be a string array"
        )
        enabled_providers = []
    duplicates = sorted(
        provider_id
        for provider_id in set(enabled_providers)
        if enabled_providers.count(provider_id) > 1
    )
    if duplicates:
        violations.append(
            "live conformance report provider_enable_overrides.providers "
            f"contains duplicates: {duplicates}"
        )
    return enable_all, sorted(enabled_providers)


def _validate_passed_live_provider_report(
    provider_subject: str,
    provider: dict[str, Any],
    plan_provider: dict[str, Any] | None,
    model_alias_provider_models: dict[str, list[str]] | None,
    compatibility_profiles: dict[str, dict[str, Any]] | None,
    violations: list[str],
) -> None:
    if provider.get("expected_model_ids_source") != "model_alias_matrix":
        violations.append(
            f"{provider_subject}.expected_model_ids_source must be model_alias_matrix"
        )
    if (
        plan_provider is not None
        and plan_provider.get("expected_model_ids_from_alias_matrix") is not True
    ):
        violations.append(
            f"{provider_subject}.expected_model_ids_source requires "
            f"{LIVE_CONFORMANCE_PLAN_PATH.as_posix()} "
            "expected_model_ids_from_alias_matrix=true"
        )

    expected_model_ids = _string_list_field(provider.get("expected_model_ids"))
    observed_model_ids = _string_list_field(provider.get("observed_model_ids"))
    if expected_model_ids is None:
        violations.append(f"{provider_subject}.expected_model_ids must be a string array")
    elif not expected_model_ids:
        violations.append(
            f"{provider_subject}.expected_model_ids must be non-empty for production release"
        )
    if observed_model_ids is None:
        violations.append(f"{provider_subject}.observed_model_ids must be a string array")
    elif not observed_model_ids:
        violations.append(
            f"{provider_subject}.observed_model_ids must be non-empty for production release"
        )
    if (
        expected_model_ids is not None
        and observed_model_ids is not None
        and sorted(observed_model_ids) != sorted(expected_model_ids)
    ):
        violations.append(
            f"{provider_subject}.observed_model_ids must match expected_model_ids "
            "without drift"
        )
    provider_id = provider.get("provider")
    if (
        model_alias_provider_models is not None
        and expected_model_ids is not None
        and isinstance(provider_id, str)
    ):
        matrix_model_ids = model_alias_provider_models.get(provider_id)
        if matrix_model_ids is None:
            violations.append(
                f"{provider_subject}.expected_model_ids references missing signed "
                f"model alias matrix provider {provider_id!r}"
            )
        elif sorted(expected_model_ids) != matrix_model_ids:
            violations.append(
                f"{provider_subject}.expected_model_ids must match signed "
                f"model alias matrix provider {provider_id!r}"
            )

    for field in ("new_unverified", "removed", "attestation_errors", "errors"):
        values = provider.get(field)
        if not isinstance(values, list):
            violations.append(f"{provider_subject}.{field} must be an array")
        elif values:
            violations.append(
                f"{provider_subject}.{field} must be empty for production release"
            )

    if provider.get("attestation_shape_ok") is not True:
        violations.append(f"{provider_subject}.attestation_shape_ok must be true")

    if plan_provider is not None:
        _validate_live_provider_response_metadata(
            provider_subject,
            provider,
            plan_provider,
            violations,
        )
        expected_auth_env = plan_provider.get("auth_env")
        if not _non_empty_string(expected_auth_env):
            violations.append(
                f"{provider_subject}.auth_env requires "
                f"{LIVE_CONFORMANCE_PLAN_PATH.as_posix()} to define a credential "
                "environment variable for production release"
            )
        else:
            if provider.get("auth_env") != expected_auth_env:
                violations.append(
                    f"{provider_subject}.auth_env must match "
                    f"{LIVE_CONFORMANCE_PLAN_PATH.as_posix()} auth_env"
                )
            if provider.get("credential_source") != "env":
                violations.append(f"{provider_subject}.credential_source must be env")
            if provider.get("credential_configured") is not True:
                violations.append(
                    f"{provider_subject}.credential_configured must be true"
                )

    if plan_provider is None or compatibility_profiles is None:
        return
    compatibility_provider = plan_provider.get("compatibility_provider")
    if not isinstance(compatibility_provider, str) or not compatibility_provider:
        violations.append(
            f"{provider_subject}.compatibility_profile requires "
            f"{LIVE_CONFORMANCE_PLAN_PATH.as_posix()} compatibility_provider"
        )
        return
    expected_profile = compatibility_profiles.get(compatibility_provider)
    if expected_profile is None:
        violations.append(
            f"{provider_subject}.compatibility_profile references missing signed "
            f"compatibility matrix provider {compatibility_provider!r}"
        )
        return
    compatibility_profile = provider.get("compatibility_profile")
    if not isinstance(compatibility_profile, dict):
        violations.append(f"{provider_subject}.compatibility_profile must be an object")
        return
    if compatibility_profile != expected_profile:
        violations.append(
            f"{provider_subject}.compatibility_profile must match signed "
            f"compatibility matrix provider {compatibility_provider!r}"
        )
    _validate_production_compatibility_profile(
        f"{provider_subject}.compatibility_profile",
        compatibility_profile,
        violations,
    )


def _validate_production_compatibility_profile(
    provider_subject: str,
    profile: dict[str, Any],
    violations: list[str],
) -> None:
    if profile.get("route_execution_status") != "executable":
        violations.append(
            f"{provider_subject}.route_execution_status must be executable "
            "for production release"
        )
    if profile.get("model_listing") != "live_catalog":
        violations.append(
            f"{provider_subject}.model_listing must be live_catalog "
            "for production release"
        )
    attestation_shape = profile.get("attestation_endpoint_shape")
    if not _non_empty_string(attestation_shape):
        violations.append(f"{provider_subject}.attestation_endpoint_shape must be non-empty")
    elif "fixture" in attestation_shape:
        violations.append(
            f"{provider_subject}.attestation_endpoint_shape must not be fixture-based "
            "for production release"
        )
    unsupported_modes = profile.get("known_unsupported_modes")
    if not isinstance(unsupported_modes, list):
        violations.append(f"{provider_subject}.known_unsupported_modes must be an array")
    else:
        production_blockers = sorted(
            mode
            for mode in ("live_execution", "live_tdx_quote")
            if mode in unsupported_modes
        )
        if production_blockers:
            violations.append(
                f"{provider_subject}.known_unsupported_modes must not contain "
                f"production live blockers {production_blockers}"
            )
    required_credentials = profile.get("required_credentials")
    if not isinstance(required_credentials, list) or not required_credentials:
        violations.append(
            f"{provider_subject}.required_credentials must be non-empty "
            "for production release"
        )


def _validate_live_provider_response_metadata(
    provider_subject: str,
    provider: dict[str, Any],
    plan_provider: dict[str, Any],
    violations: list[str],
) -> None:
    _validate_http_response_metadata(
        f"{provider_subject}.model_list_response",
        provider.get("model_list_response"),
        plan_provider.get("model_list_url"),
        violations,
    )
    if _non_empty_string(plan_provider.get("attestation_url")):
        _validate_http_response_metadata(
            f"{provider_subject}.attestation_response",
            provider.get("attestation_response"),
            plan_provider.get("attestation_url"),
            violations,
        )


def _validate_http_response_metadata(
    subject: str,
    metadata: Any,
    expected_url: Any,
    violations: list[str],
) -> None:
    if not isinstance(metadata, dict):
        violations.append(f"{subject} must be an object")
        return
    if metadata.get("url") != expected_url:
        violations.append(f"{subject}.url must match live conformance plan URL")
    status = metadata.get("status")
    if isinstance(status, bool) or not isinstance(status, int):
        violations.append(f"{subject}.status must be an integer")
    elif status < 200 or status >= 300:
        violations.append(f"{subject}.status must be a successful HTTP status")
    if not isinstance(metadata.get("content_type"), str):
        violations.append(f"{subject}.content_type must be a string")
    body_size = metadata.get("body_size")
    if isinstance(body_size, bool) or not isinstance(body_size, int):
        violations.append(f"{subject}.body_size must be an integer")
    elif body_size <= 0:
        violations.append(f"{subject}.body_size must be positive")
    if not is_sha256_digest(metadata.get("body_sha256")):
        violations.append(f"{subject}.body_sha256 must be a canonical sha256 digest")


def _validate_live_provider_enablement(
    provider_subject: str,
    provider: dict[str, Any],
    plan_provider: dict[str, Any] | None,
    enable_all: bool,
    enabled_provider_overrides: list[str],
    violations: list[str],
) -> None:
    if plan_provider is None:
        return
    configured_enabled = provider.get("configured_enabled")
    enabled_by_override = provider.get("enabled_by_override")
    if not isinstance(configured_enabled, bool):
        violations.append(f"{provider_subject}.configured_enabled must be a boolean")
        return
    if not isinstance(enabled_by_override, bool):
        violations.append(f"{provider_subject}.enabled_by_override must be a boolean")
        return

    expected_configured = plan_provider.get("enabled") is True
    if configured_enabled != expected_configured:
        violations.append(
            f"{provider_subject}.configured_enabled must match "
            f"{LIVE_CONFORMANCE_PLAN_PATH.as_posix()} provider enabled state"
        )
    if expected_configured:
        if enabled_by_override:
            violations.append(
                f"{provider_subject}.enabled_by_override must be false for a "
                "provider already enabled in the live conformance plan"
            )
        return

    if not enabled_by_override:
        violations.append(
            f"{provider_subject}.enabled_by_override must be true for a "
            "disabled-by-default production live provider"
        )
    provider_id = provider.get("provider")
    if isinstance(provider_id, str) and not (
        enable_all or provider_id in enabled_provider_overrides
    ):
        violations.append(
            f"{provider_subject}.enabled_by_override is true but "
            "provider_enable_overrides does not enable that provider"
        )


def _validate_live_conformance_report(
    workspace_root: Path,
    report_path: Path | None,
    violations: list[str],
) -> bool:
    if report_path is None:
        return False
    before = len(violations)
    report_path = report_path if report_path.is_absolute() else workspace_root / report_path
    try:
        rendered = report_path.read_text(encoding="utf-8")
        report = json.loads(rendered)
    except (OSError, json.JSONDecodeError) as error:
        violations.append(f"live conformance report cannot be loaded: {error}")
        return False
    if not isinstance(report, dict):
        violations.append("live conformance report must be an object")
        return False
    if json.dumps(report, sort_keys=True, indent=2, separators=(",", ": ")) + "\n" != rendered:
        violations.append("live conformance report is not canonical JSON")
    if report.get("schema") != LIVE_CONFORMANCE_REPORT_SCHEMA:
        violations.append(
            f"live conformance report schema must be {LIVE_CONFORMANCE_REPORT_SCHEMA}"
        )
    if report.get("plan_schema") != LIVE_CONFORMANCE_PLAN_SCHEMA:
        violations.append(
            f"live conformance report plan_schema must be {LIVE_CONFORMANCE_PLAN_SCHEMA}"
        )
    if report.get("network_enabled") is not True:
        violations.append("live conformance report must be generated with network_enabled=true")
    _validate_live_report_freshness(report, violations)
    _validate_live_report_trust_artifact_metadata(report, workspace_root, violations)
    enable_all, enabled_provider_overrides = _live_report_provider_enable_overrides(
        report,
        violations,
    )
    plan_providers = _expected_live_conformance_plan_providers(
        workspace_root,
        violations,
    )
    model_alias_provider_models = _signed_live_model_alias_provider_models(
        workspace_root,
        violations,
    )
    compatibility_profiles = _signed_live_compatibility_profiles(
        workspace_root,
        violations,
    )

    providers = report.get("providers")
    if not isinstance(providers, list) or not providers:
        violations.append("live conformance report providers must be a non-empty array")
        providers = []
    skipped_or_unchecked: list[str] = []
    report_provider_ids: list[str] = []
    for index, provider in enumerate(providers):
        provider_subject = f"live conformance report providers[{index}]"
        if not isinstance(provider, dict):
            violations.append(f"{provider_subject} must be an object")
            continue
        provider_id = provider.get("provider")
        if not isinstance(provider_id, str) or not provider_id:
            violations.append(
                f"{provider_subject}.provider must be non-empty"
            )
            provider_id = f"providers[{index}]"
        else:
            report_provider_ids.append(provider_id)
        if provider.get("status") != "passed" or provider.get("live_checked") is not True:
            skipped_or_unchecked.append(provider_id)
        else:
            _validate_live_provider_enablement(
                provider_subject,
                provider,
                plan_providers.get(provider_id) if isinstance(provider_id, str) else None,
                enable_all,
                enabled_provider_overrides,
                violations,
            )
            _validate_passed_live_provider_report(
                provider_subject,
                provider,
                plan_providers.get(provider_id) if isinstance(provider_id, str) else None,
                model_alias_provider_models,
                compatibility_profiles,
                violations,
            )
    duplicate_report_providers = sorted(
        provider_id
        for provider_id in set(report_provider_ids)
        if report_provider_ids.count(provider_id) > 1
    )
    if duplicate_report_providers:
        violations.append(
            "live conformance report provider ids must be unique: "
            f"{duplicate_report_providers}"
        )
    expected_provider_ids = sorted(plan_providers)
    if expected_provider_ids and sorted(report_provider_ids) != expected_provider_ids:
        missing = sorted(set(expected_provider_ids) - set(report_provider_ids))
        extra = sorted(set(report_provider_ids) - set(expected_provider_ids))
        violations.append(
            "live conformance report providers must match "
            f"{LIVE_CONFORMANCE_PLAN_PATH.as_posix()}: missing={missing} extra={extra}"
        )
    unknown_enabled_overrides = sorted(
        set(enabled_provider_overrides) - set(expected_provider_ids)
    )
    if unknown_enabled_overrides:
        violations.append(
            "live conformance report provider_enable_overrides.providers contains "
            f"unknown providers: {unknown_enabled_overrides}"
        )
    if skipped_or_unchecked:
        violations.append(
            "live conformance report has providers that did not pass credentialed "
            f"live checks: {sorted(skipped_or_unchecked)}"
        )

    summary = report.get("summary")
    if not isinstance(summary, dict):
        violations.append("live conformance report summary must be an object")
        summary = {}
    summary_providers = _int_field(summary.get("providers"))
    summary_live_checked = _int_field(summary.get("live_checked"))
    summary_passed = _int_field(summary.get("passed"))
    summary_failed = _int_field(summary.get("failed"))
    summary_drift = _int_field(summary.get("drift"))
    summary_skipped = _int_field(summary.get("skipped"))
    if any(
        value is None
        for value in (
            summary_providers,
            summary_live_checked,
            summary_passed,
            summary_failed,
            summary_drift,
            summary_skipped,
        )
    ):
        violations.append("live conformance report summary counts must be integers")
    else:
        provider_count = len(providers)
        if summary_providers != provider_count:
            violations.append(
                "live conformance report summary.providers does not match providers length"
            )
        if summary_live_checked != provider_count or summary_passed != provider_count:
            violations.append(
                "live conformance report summary must show every provider live-checked and passed"
            )
        if summary_failed != 0 or summary_drift != 0 or summary_skipped != 0:
            violations.append(
                "live conformance report summary must have zero failed, drift, and skipped providers"
            )

    gate = report.get("credentialed_live_gate")
    if not isinstance(gate, dict):
        violations.append("live conformance report credentialed_live_gate must be an object")
    else:
        if gate.get("status") != "passed":
            violations.append("credentialed_live_gate.status must be passed")
        if gate.get("required_for_production") is not True:
            violations.append("credentialed_live_gate.required_for_production must be true")
        if gate.get("remaining_provider_ids") != []:
            violations.append("credentialed_live_gate.remaining_provider_ids must be empty")

    return len(violations) == before


def _validate_dcap_production_review(
    workspace_root: Path,
    review_path: Path | None,
    violations: list[str],
) -> bool:
    if review_path is None:
        return False
    before = len(violations)
    review_path = review_path if review_path.is_absolute() else workspace_root / review_path
    try:
        rendered = review_path.read_text(encoding="utf-8")
        review = json.loads(rendered)
    except (OSError, json.JSONDecodeError) as error:
        violations.append(f"DCAP production review cannot be loaded: {error}")
        return False
    if not isinstance(review, dict):
        violations.append("DCAP production review must be an object")
        return False
    if json.dumps(review, sort_keys=True, indent=2, separators=(",", ": ")) + "\n" != rendered:
        violations.append("DCAP production review is not canonical JSON")
    if review.get("schema") != DCAP_PRODUCTION_REVIEW_SCHEMA:
        violations.append(
            f"DCAP production review schema must be {DCAP_PRODUCTION_REVIEW_SCHEMA}"
        )
    if review.get("status") != "passed":
        violations.append("DCAP production review status must be passed")

    dependency_audit = review.get("dependency_audit")
    audit_required_commands: list[str] = []
    if not isinstance(dependency_audit, dict):
        violations.append("DCAP production review dependency_audit must be an object")
    else:
        if dependency_audit.get("path") != DCAP_AUDIT_PATH.as_posix():
            violations.append(
                "DCAP production review dependency_audit.path must be "
                f"{DCAP_AUDIT_PATH.as_posix()}"
            )
        audit_path = workspace_root / DCAP_AUDIT_PATH
        try:
            audit_bytes = audit_path.read_bytes()
            audit = json.loads(audit_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            violations.append(
                f"DCAP dependency audit cannot be loaded from "
                f"{DCAP_AUDIT_PATH.as_posix()}: {error}"
            )
            audit = None
        else:
            expected_digest = sha256_digest(audit_bytes)
            if dependency_audit.get("sha256") != expected_digest:
                violations.append(
                    "DCAP production review dependency_audit.sha256 does not match "
                    f"current {DCAP_AUDIT_PATH.as_posix()}"
                )
            if not isinstance(audit, dict) or audit.get("schema") != "confidential-inference.dcap-qvl-audit.v1":
                violations.append(
                    "DCAP dependency audit schema must be "
                    "confidential-inference.dcap-qvl-audit.v1"
                )
            elif not isinstance(audit.get("upstream_sync_policy"), dict):
                violations.append(
                    "DCAP dependency audit upstream_sync_policy must be an object"
                )
            else:
                upstream_sync_policy = audit["upstream_sync_policy"]
                if upstream_sync_policy.get("required_release_gate") is not True:
                    violations.append(
                        "DCAP dependency audit upstream_sync_policy.required_release_gate "
                        "must be true"
                    )
                commands = upstream_sync_policy.get("required_commands")
                if not isinstance(commands, list) or not all(
                    _non_empty_string(command) for command in commands
                ):
                    violations.append(
                        "DCAP dependency audit upstream_sync_policy.required_commands "
                        "must be a string array"
                    )
                else:
                    audit_required_commands = commands

    reviewed_commands = review.get("reviewed_commands")
    if not isinstance(reviewed_commands, list) or not all(
        _non_empty_string(command) for command in reviewed_commands
    ):
        violations.append("DCAP production review reviewed_commands must be a string array")
    else:
        duplicate_commands = sorted(
            command
            for command in set(reviewed_commands)
            if reviewed_commands.count(command) > 1
        )
        if duplicate_commands:
            violations.append(
                "DCAP production review reviewed_commands must not contain "
                f"duplicates: {duplicate_commands}"
            )
        missing_commands = sorted(set(audit_required_commands) - set(reviewed_commands))
        extra_commands = sorted(set(reviewed_commands) - set(audit_required_commands))
        if missing_commands:
            violations.append(
                "DCAP production review reviewed_commands is missing required "
                f"release commands: {missing_commands}"
            )
        if extra_commands:
            violations.append(
                "DCAP production review reviewed_commands contains commands not "
                f"required by the audited policy: {extra_commands}"
            )

    security_review = review.get("independent_security_review")
    if not isinstance(security_review, dict):
        violations.append(
            "DCAP production review independent_security_review must be an object"
        )
    else:
        if security_review.get("status") != "passed":
            violations.append(
                "DCAP production review independent_security_review.status must be passed"
            )
        if not _non_empty_string(security_review.get("reviewer")):
            violations.append(
                "DCAP production review independent_security_review.reviewer "
                "must be non-empty"
            )
        _validate_canonical_utc_timestamp(
            "DCAP production review independent_security_review.completed_at",
            security_review.get("completed_at"),
            violations,
        )

    fuzz = review.get("long_running_fuzz")
    if not isinstance(fuzz, dict):
        violations.append("DCAP production review long_running_fuzz must be an object")
    else:
        if fuzz.get("status") != "passed":
            violations.append(
                "DCAP production review long_running_fuzz.status must be passed"
            )
        _validate_canonical_utc_timestamp(
            "DCAP production review long_running_fuzz.completed_at",
            fuzz.get("completed_at"),
            violations,
        )
        duration_hours = fuzz.get("duration_hours")
        if isinstance(duration_hours, bool) or not isinstance(duration_hours, int):
            violations.append(
                "DCAP production review long_running_fuzz.duration_hours must be "
                "a positive integer"
            )
        elif duration_hours < MIN_DCAP_FUZZ_DURATION_HOURS:
            violations.append(
                "DCAP production review long_running_fuzz.duration_hours must be "
                f"at least {MIN_DCAP_FUZZ_DURATION_HOURS}"
            )
        targets = fuzz.get("targets")
        if not isinstance(targets, list) or not all(
            _non_empty_string(target) for target in targets
        ):
            violations.append(
                "DCAP production review long_running_fuzz.targets must be a "
                "non-empty string array"
            )
        elif not targets:
            violations.append(
                "DCAP production review long_running_fuzz.targets must be non-empty"
            )
        crashes_found = fuzz.get("crashes_found")
        if isinstance(crashes_found, bool) or not isinstance(crashes_found, int):
            violations.append(
                "DCAP production review long_running_fuzz.crashes_found must be an integer"
            )
        elif crashes_found != 0:
            violations.append(
                "DCAP production review long_running_fuzz.crashes_found must be zero"
            )

    open_findings = review.get("open_findings")
    if open_findings != []:
        violations.append("DCAP production review open_findings must be empty")

    return len(violations) == before


def _validate_workspace_metadata(
    workspace_root: Path,
    manifest: dict[str, Any],
    violations: list[str],
) -> None:
    try:
        expected_workspace_package = _workspace_package_metadata(workspace_root)
    except (OSError, tomllib.TOMLDecodeError) as error:
        violations.append(f"workspace package metadata cannot be loaded: {error}")
        return
    if manifest.get("workspace_package") != expected_workspace_package:
        violations.append("manifest workspace_package does not match current Cargo.toml")

    cargo_lock = workspace_root / "Cargo.lock"
    try:
        expected_lock_digest = sha256_digest(cargo_lock.read_bytes())
    except OSError as error:
        violations.append(f"Cargo.lock cannot be read: {error}")
        return
    if manifest.get("cargo_lock_digest") != expected_lock_digest:
        violations.append("manifest cargo_lock_digest does not match current Cargo.lock")
    if not is_sha256_digest(manifest.get("cargo_lock_digest")):
        violations.append("manifest cargo_lock_digest is not canonical")


def parse_trusted_release_key(value: str) -> TrustedSigningKey:
    parts = value.split(":")
    if len(parts) != 3 or any(not part for part in parts):
        raise ReleaseManifestError(
            "trusted release key must use signer:key_id:public_key_base64url"
        )
    signer, key_id, public_key_base64url = parts
    return TrustedSigningKey(signer, key_id, public_key_base64url)


def _validate_trusted_release_keys(
    trusted_release_keys: list[TrustedSigningKey],
    violations: list[str],
    forbidden_public_keys: set[str] | None,
) -> None:
    if not forbidden_public_keys:
        return
    for trusted_key in trusted_release_keys:
        if trusted_key.public_key_base64url in forbidden_public_keys:
            violations.append(
                "production release must not trust CI/test release public key "
                f"signer={trusted_key.signer!r} key_id={trusted_key.key_id!r}"
            )


def _validate_release_signature(
    workspace_root: Path,
    manifest_path: Path,
    rendered_manifest: str,
    signature_path: Path | None,
    trusted_release_keys: list[TrustedSigningKey],
    violations: list[str],
    forbidden_signing_keys: set[tuple[str, str]] | None = None,
    forbidden_public_keys: set[str] | None = None,
) -> bool:
    if signature_path is None:
        return False
    if not trusted_release_keys:
        violations.append("trusted release signing key is required to verify signature")
        return False

    signature_path = (
        signature_path if signature_path.is_absolute() else workspace_root / signature_path
    )
    try:
        rendered_signature = signature_path.read_text(encoding="utf-8")
        signature_doc = json.loads(rendered_signature)
    except (OSError, json.JSONDecodeError) as error:
        violations.append(f"release signature cannot be loaded: {error}")
        return False

    if not isinstance(signature_doc, dict):
        violations.append("release signature must be an object")
        return False
    before = len(violations)
    if json.dumps(signature_doc, sort_keys=True, indent=2, separators=(",", ": ")) + "\n" != rendered_signature:
        violations.append("release signature is not canonical JSON")
    if signature_doc.get("schema") != RELEASE_SIGNATURE_SCHEMA:
        violations.append(f"release signature schema must be {RELEASE_SIGNATURE_SCHEMA}")
    try:
        expected_manifest_path = _relative_path(manifest_path, workspace_root)
    except ReleaseManifestError as error:
        violations.append(f"manifest path is invalid for signature verification: {error}")
        return False
    if signature_doc.get("manifest_path") != expected_manifest_path:
        violations.append(
            f"release signature manifest_path must be {expected_manifest_path}"
        )
    expected_digest = sha256_digest(rendered_manifest.encode("utf-8"))
    if signature_doc.get("manifest_sha256") != expected_digest:
        violations.append("release signature manifest_sha256 does not match manifest")
    if not is_sha256_digest(signature_doc.get("manifest_sha256")):
        violations.append("release signature manifest_sha256 is not canonical")
    if signature_doc.get("signed_payload") != SIGNATURE_SIGNED_PAYLOAD:
        violations.append("release signature signed_payload does not match signing policy")
    signature = signature_doc.get("signature")
    if not isinstance(signature, dict):
        violations.append("release signature.signature must be an object")
        return False
    signer = signature.get("signer")
    key_id = signature.get("key_id")
    if (
        forbidden_signing_keys
        and isinstance(signer, str)
        and isinstance(key_id, str)
        and (signer, key_id) in forbidden_signing_keys
    ):
        violations.append(
            "production release must not use CI/test release signing key "
            f"signer={signer!r} key_id={key_id!r}"
        )
    public_key = signature_doc.get("public_key_base64url")
    if public_key is not None and not isinstance(public_key, str):
        violations.append("release signature public_key_base64url must be a string")
    if (
        forbidden_public_keys
        and isinstance(public_key, str)
        and public_key in forbidden_public_keys
    ):
        violations.append(
            "production release must not use CI/test release public key "
            f"public_key_base64url={public_key!r}"
        )

    try:
        verify_artifact_signature(
            signature,
            rendered_manifest.encode("utf-8"),
            "release manifest",
            trusted_release_keys,
        )
    except ArtifactSignatureError as error:
        violations.append(str(error))
        return False
    return len(violations) == before


def validate_manifest(
    workspace_root: Path,
    manifest_path: Path,
    artifacts: list[Path] | None = None,
    artifact_globs: list[str] | None = None,
    sbom_path: Path | None = None,
    signature_path: Path | None = None,
    trusted_release_keys: list[TrustedSigningKey] | None = None,
    live_conformance_report_path: Path | None = None,
    require_production_release: bool = False,
    dcap_production_review_path: Path | None = None,
) -> dict[str, Any]:
    workspace_root = workspace_root.resolve()
    manifest_path = manifest_path if manifest_path.is_absolute() else workspace_root / manifest_path
    artifacts = artifacts or []
    artifact_globs = artifact_globs or []
    violations: list[str] = []

    try:
        rendered = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(rendered)
    except (OSError, json.JSONDecodeError) as error:
        return {
            "schema": SCHEMA,
            "manifest": manifest_path.as_posix(),
            "violations": [f"manifest cannot be loaded: {error}"],
        }

    if not isinstance(manifest, dict):
        violations.append("manifest must be an object")
        manifest = {}
    elif render_manifest(manifest) != rendered:
        violations.append(
            "manifest file is not canonical JSON with sorted keys, indent=2, and trailing newline"
        )

    if manifest.get("schema") != RELEASE_MANIFEST_SCHEMA:
        violations.append(f"manifest schema must be {RELEASE_MANIFEST_SCHEMA}")
    _validate_workspace_metadata(workspace_root, manifest, violations)
    manifest_paths = _validate_artifact_records(workspace_root, manifest, violations)
    expected_release_archives = _validate_release_package_archive_coverage(
        workspace_root,
        manifest_paths,
        violations,
    )
    _validate_expected_artifact_set(
        workspace_root,
        manifest_paths,
        artifacts,
        artifact_globs,
        violations,
    )
    _validate_sbom(workspace_root, manifest, sbom_path, violations)
    live_conformance_gate_verified = _validate_live_conformance_report(
        workspace_root,
        live_conformance_report_path,
        violations,
    )
    dcap_production_review_verified = _validate_dcap_production_review(
        workspace_root,
        dcap_production_review_path,
        violations,
    )
    if manifest.get("signing_payload") != SIGNING_PAYLOAD:
        violations.append("manifest signing_payload does not match release signing policy")
    forbidden_public_keys = (
        FORBIDDEN_PRODUCTION_RELEASE_PUBLIC_KEYS
        if require_production_release
        else None
    )
    trusted_key_violations_before = len(violations)
    _validate_trusted_release_keys(
        trusted_release_keys or [],
        violations,
        forbidden_public_keys,
    )
    trusted_release_keys_allowed = len(violations) == trusted_key_violations_before
    signature_verified = _validate_release_signature(
        workspace_root,
        manifest_path,
        rendered,
        signature_path,
        trusted_release_keys or [],
        violations,
        (
            FORBIDDEN_PRODUCTION_RELEASE_SIGNING_KEYS
            if require_production_release
            else None
        ),
        forbidden_public_keys,
    )
    if not trusted_release_keys_allowed:
        signature_verified = False
    if require_production_release:
        _validate_production_evidence_artifact_coverage(
            workspace_root,
            manifest_paths,
            live_conformance_report_path,
            dcap_production_review_path,
            violations,
        )
        if not signature_verified:
            violations.append(
                "production release requires a verified detached release-manifest signature"
            )
        if not live_conformance_gate_verified:
            violations.append(
                "production release requires a credentialed all-provider live conformance report"
            )
        if not dcap_production_review_verified:
            violations.append(
                "production release requires a passed DCAP vendor production review "
                "attestation"
            )

    return {
        "schema": SCHEMA,
        "manifest": manifest_path.as_posix(),
        "artifact_count": len(manifest_paths),
        "release_package_archive_count": len(expected_release_archives),
        "signature_verified": signature_verified,
        "live_conformance_gate_verified": live_conformance_gate_verified,
        "dcap_production_review_verified": dcap_production_review_verified,
        "production_release_verified": (
            require_production_release
            and signature_verified
            and live_conformance_gate_verified
            and dcap_production_review_verified
            and not violations
        ),
        "violations": sorted(violations),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path.cwd(),
        help="Cargo workspace root. Defaults to the current directory.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("target/confidential-inference-release-manifest.json"),
        help="Release manifest to validate.",
    )
    parser.add_argument(
        "--artifact",
        type=Path,
        action="append",
        default=[],
        help="Expected release artifact. May be repeated.",
    )
    parser.add_argument(
        "--artifact-glob",
        action="append",
        default=[],
        help="Expected artifact glob. May be repeated.",
    )
    parser.add_argument(
        "--sbom",
        type=Path,
        help="Expected SBOM path that must match the manifest sbom section.",
    )
    parser.add_argument(
        "--signature",
        type=Path,
        help="Optional detached release-manifest signature sidecar to verify.",
    )
    parser.add_argument(
        "--trusted-release-key",
        action="append",
        default=[],
        metavar="SIGNER:KEY_ID:PUBLIC_KEY_BASE64URL",
        help="Trusted Ed25519 public release key. Required when --signature is set.",
    )
    parser.add_argument(
        "--live-conformance-report",
        type=Path,
        help=(
            "Optional production live conformance report. When supplied, the "
            "report must be network-enabled and every provider must have passed "
            "credentialed live checks without drift."
        ),
    )
    parser.add_argument(
        "--production-release",
        action="store_true",
        help=(
            "Require production release evidence: a verified detached release "
            "manifest signature and a credentialed all-provider live "
            "conformance report, plus a passed DCAP production review "
            "attestation."
        ),
    )
    parser.add_argument(
        "--dcap-production-review",
        type=Path,
        help=(
            "Optional DCAP vendor production review attestation. Required by "
            "--production-release while the DCAP verifier remains part "
            "of the production trust path."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full validation report as JSON.",
    )
    args = parser.parse_args(argv)

    try:
        trusted_release_keys = [
            parse_trusted_release_key(value) for value in args.trusted_release_key
        ]
        report = validate_manifest(
            args.workspace_root,
            args.manifest,
            args.artifact,
            args.artifact_glob,
            args.sbom,
            args.signature,
            trusted_release_keys,
            args.live_conformance_report,
            args.production_release,
            args.dcap_production_review,
        )
    except ReleaseManifestError as error:
        print(f"check_release_manifest.py: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2, separators=(",", ": ")))
    elif report["violations"]:
        for violation in report["violations"]:
            print(f"release manifest policy violation: {violation}", file=sys.stderr)
    else:
        print(
            "release manifest ok: "
            f"manifest={report['manifest']} artifacts={report['artifact_count']} "
            f"signature_verified={report['signature_verified']} "
            f"live_conformance_gate_verified={report['live_conformance_gate_verified']} "
            f"dcap_production_review_verified={report['dcap_production_review_verified']} "
            f"production_release_verified={report['production_release_verified']}"
        )
    return 1 if report["violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
