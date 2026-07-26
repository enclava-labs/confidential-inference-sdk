#!/usr/bin/env python3
"""Validate normative SDK JSON fixtures for required trust metadata."""

from __future__ import annotations

import argparse
import base64
import binascii
import calendar
import datetime
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any

from artifact_signatures import ArtifactSignatureError, verify_artifact_signature


SCHEMA = "confidential-inference.normative-fixture-policy.v1"
SHA256_PREFIX = "sha256:"
SHA256_HEX = set("0123456789abcdef")
BASE64URL_PREFIX = "base64url:"
BASE64URL_NO_PAD_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
ED25519_SIGNATURE_BYTE_LEN = 64
MAX_SAFE_JSON_INT = 9_007_199_254_740_991
UNSUPPORTED_PRODUCTION_TINFOIL_CPU_TEES = {"sev_snp"}
EXECUTABLE_ROUTE_STATUSES = {"executable", "executable_fixture"}
PRODUCTION_EXECUTABLE_ROUTE_STATUS = "executable"
TINFOIL_FIXTURE_ATTESTATION_SHAPE = "tinfoil_tls_fixture"
TINFOIL_LIVE_TDX_UNSUPPORTED_MODE = "live_tdx_quote"
FIXTURE_ONLY_COMPATIBILITY_PROFILE_PATTERNS = {
    "chutes": "Chutes/Redpill E2EE+GPU",
    "phala": "Direct Phala dstack",
    "ionet": "io.net confidential inference",
    "ehbp": "PPQ EHBP",
}
FIXTURE_ONLY_COMPATIBILITY_PROVIDERS = {
    "venice-fixture": "Venice dstack app-E2EE",
}
FIXTURE_ONLY_LIVE_SYNC_PROVIDER_PATTERNS = {
    "venice": "Venice dstack app-E2EE",
    "phala": "Direct Phala dstack",
    "redpill": "Chutes/Redpill E2EE+GPU",
    "ionet": "io.net confidential inference",
    "tinfoil": "Tinfoil hw-verified TLS",
}
FIXTURE_ONLY_LIVE_SYNC_EVIDENCE_FAMILIES = {
    "dstack_app_e2ee": "dstack app-E2EE",
    "chutes_e2ee": "Chutes/Redpill E2EE+GPU",
    "ionet_confidential": "io.net confidential inference",
    "tinfoil_hw_verified_tls": "Tinfoil hw-verified TLS",
}
ACTIVE_REGISTRY_ROUTE_STATUS = "active"
NEW_UNVERIFIED_REGISTRY_ROUTE_STATUS = "new_unverified"
UTC_TIMESTAMP_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$"
)

VERDICT_FIXTURES = (Path("fixtures/verdict/demo-verified.json"),)
POLICY_FIXTURES = (Path("fixtures/policy/require_attested_e2ee.json"),)
REGISTRY_FIXTURES = (
    Path("fixtures/registry/demo-registry.json"),
    Path("fixtures/registry/phase2-fixtures-registry.json"),
)
REFERENCE_VALUE_FIXTURES = (
    Path("fixtures/reference-values/demo-envelope.json"),
    Path("fixtures/reference-values/phase2-fixtures-envelope.json"),
)
MODEL_ALIAS_MATRIX_FIXTURE = Path("fixtures/registry/model-alias-matrix.json")
MODEL_ALIAS_MATRIX_ENVELOPE_FIXTURE = Path("fixtures/registry/model-alias-matrix-envelope.json")
COMPATIBILITY_MATRIX_FIXTURE = Path("fixtures/providers/compatibility-matrix.json")
COMPATIBILITY_MATRIX_ENVELOPE_FIXTURE = Path(
    "fixtures/providers/compatibility-matrix-envelope.json"
)
LIVE_CONFORMANCE_PLAN_FIXTURES = (
    Path("fixtures/providers/live-conformance-plan.json"),
)
LIVE_SYNC_CORPUS_FIXTURES = (
    Path("fixtures/providers/live-sync-corpus.json"),
)

VERDICT_REQUIRED_FIELDS = (
    "schema",
    "policy_schema",
    "reference_values_schema",
    "provider_registry_schema",
    "status",
    "enforcement",
    "request_allowed",
    "would_block_under_enforce",
    "trust_tier",
    "provider",
    "requested_model",
    "provider_model",
    "canonical_model",
    "route_id",
    "evidence_family",
    "alias_confidence",
    "adapter_version",
    "api_endpoint",
    "evidence_endpoint",
    "freshness_class",
    "streaming_allowed",
    "route_execution_status",
    "chat_executable",
    "known_unsupported_modes",
    "channel_binding_kind",
    "model_binding_result",
    "request_channel_bound",
    "request_confidentiality_result",
    "response_confidentiality_result",
    "response_channel_bound",
    "response_integrity_result",
    "policy_digest",
    "provider_registry_digest",
    "registry_version",
    "registry_source",
    "registry_sync_completed_at",
    "registry_signature",
    "reference_values_digest",
    "reference_values_version",
    "reference_values_source",
    "reference_values_signature",
    "raw_evidence_digest",
    "evidence_digest",
    "verified_at",
    "expires_at",
    "expires_at_epoch_ms",
    "validity",
    "checks",
    "artifacts",
    "errors",
)

VERDICT_DIGEST_FIELDS = (
    "policy_digest",
    "provider_registry_digest",
    "reference_values_digest",
    "raw_evidence_digest",
    "evidence_digest",
)

REGISTRY_ROUTE_FIELDS = (
    "route_id",
    "route_status",
    "provider",
    "provider_model",
    "evidence_family",
    "api_base_url",
    "evidence_endpoint",
    "adapter_version",
    "freshness_class",
    "channel_binding_kind",
    "trust_tier",
    "request_confidentiality_requirement",
    "response_confidentiality_requirement",
    "response_integrity_requirement",
    "request_encryption",
    "response_decryption",
    "streaming",
    "alias_confidence",
)

REFERENCE_ROUTE_FIELDS = (
    "canonical_model",
    "provider_model",
    "evidence_family",
    "channel_binding_kind",
    "trust_tier",
    "accepted_cpu_tees",
    "workload_image_digest",
    "model_artifacts",
    "valid_until",
    "valid_until_epoch_ms",
)

COMPATIBILITY_PROFILE_REQUIRED_FIELDS = (
    "provider",
    "route_execution_status",
    "supported_openai_endpoints",
    "model_listing",
    "model_id_rewrite",
    "token_parameter_rewrite",
    "streaming",
    "request_encryption",
    "response_decryption",
    "attestation_endpoint_shape",
    "required_credentials",
    "freshness_class",
    "cacheability_class",
    "expected_trust_tier",
    "model_binding_support",
    "known_unsupported_modes",
)


class FixtureCanonicalJsonError(ValueError):
    pass


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def is_canonical_sha256_digest(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith(SHA256_PREFIX):
        return False
    digest_hex = value[len(SHA256_PREFIX) :]
    return len(digest_hex) == 64 and all(ch in SHA256_HEX for ch in digest_hex)


def non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def url_has_credentials(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    parsed = urllib.parse.urlsplit(value)
    return bool(parsed.username or parsed.password)


def validate_canonical_json_values(subject: str, value: Any, violations: list[str]) -> None:
    if value is None or isinstance(value, bool) or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_JSON_INT:
            violations.append(
                f"{subject}: JSON integer {value} exceeds the cross-language safe integer limit"
            )
        return
    if isinstance(value, float):
        violations.append(f"{subject}: canonical JSON does not permit floating point numbers")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_canonical_json_values(f"{subject}[{index}]", item, violations)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                violations.append(f"{subject}: canonical JSON object keys must be strings")
                continue
            validate_canonical_json_values(f"{subject}.{key}", item, violations)
        return
    violations.append(f"{subject}: canonical JSON does not support {type(value).__name__}")


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_JSON_INT:
            raise FixtureCanonicalJsonError(
                f"JSON integer {value} exceeds the cross-language safe integer limit"
            )
        return str(value)
    if isinstance(value, float):
        raise FixtureCanonicalJsonError(
            "canonical JSON does not permit floating point numbers"
        )
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise FixtureCanonicalJsonError("canonical JSON object keys must be strings")
        entries: list[str] = []
        for key in sorted(value, key=lambda item: item.encode("utf-8")):
            entries.append(
                json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                + ":"
                + canonical_json(value[key])
            )
        return "{" + ",".join(entries) + "}"
    raise FixtureCanonicalJsonError(
        f"canonical JSON does not support {type(value).__name__}"
    )


def require_fields(
    subject: str,
    payload: dict[str, Any],
    fields: tuple[str, ...],
    violations: list[str],
) -> None:
    for field in fields:
        if field not in payload:
            violations.append(f"{subject}: missing {field}")


def validate_signature_metadata(
    subject: str,
    signature: Any,
    violations: list[str],
    *,
    require_value: bool,
) -> None:
    if not isinstance(signature, dict):
        violations.append(f"{subject}: signature must be an object")
        return
    for field in ("signer", "key_id"):
        if not non_empty_string(signature.get(field)):
            violations.append(f"{subject}: signature {field} must be non-empty")
    if signature.get("alg") != "ed25519":
        violations.append(f"{subject}: signature alg must be ed25519")
    if require_value:
        value = signature.get("value")
        if not non_empty_string(value) or not value.startswith(BASE64URL_PREFIX):
            violations.append(f"{subject}: signature value must be base64url-prefixed")
        elif not is_base64url_ed25519_signature(value):
            violations.append(
                f"{subject}: signature value must be an unpadded base64url 64-byte ed25519 signature"
            )


def is_base64url_ed25519_signature(value: str) -> bool:
    encoded = value[len(BASE64URL_PREFIX) :]
    if (
        not encoded
        or "=" in encoded
        or any(character not in BASE64URL_NO_PAD_ALPHABET for character in encoded)
        or len(encoded) % 4 == 1
    ):
        return False
    padded = encoded + ("=" * ((4 - len(encoded) % 4) % 4))
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except binascii.Error:
        return False
    return len(decoded) == ED25519_SIGNATURE_BYTE_LEN


def parse_canonical_utc_timestamp_millis(
    subject: str,
    value: Any,
    violations: list[str],
) -> int | None:
    if not isinstance(value, str):
        violations.append(f"{subject}: must be a canonical UTC RFC3339 timestamp string")
        return None
    match = UTC_TIMESTAMP_RE.match(value)
    if match is None:
        violations.append(f"{subject}: must be a canonical UTC RFC3339 timestamp")
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
            tzinfo=datetime.timezone.utc,
        )
    except ValueError:
        violations.append(f"{subject}: contains an out-of-range timestamp component")
        return None

    epoch_seconds = calendar.timegm(timestamp.utctimetuple())
    if epoch_seconds < 0:
        violations.append(f"{subject}: must not be before the Unix epoch")
        return None
    return epoch_seconds * 1_000 + int(millis or "0")


def validate_payload_signature(
    subject: str,
    signature: Any,
    payload: Any,
    violations: list[str],
) -> None:
    if not isinstance(signature, dict) or not isinstance(payload, dict):
        return
    try:
        verify_artifact_signature(
            signature,
            canonical_json(payload).encode("utf-8"),
            subject,
        )
    except ArtifactSignatureError as error:
        violations.append(str(error))
    except FixtureCanonicalJsonError as error:
        violations.append(
            f"{subject}: payload could not be canonicalized for signature verification: "
            f"{error}"
        )


def validate_verdict_fixture(path: Path, payload: Any) -> list[str]:
    violations: list[str] = []
    subject = path.as_posix()
    if not isinstance(payload, dict):
        return [f"{subject}: verdict fixture must be an object"]

    require_fields(subject, payload, VERDICT_REQUIRED_FIELDS, violations)
    if payload.get("schema") != "confidential-inference.verdict.v1":
        violations.append(f"{subject}: schema must be confidential-inference.verdict.v1")
    for field in ("policy_schema", "reference_values_schema", "provider_registry_schema"):
        if not non_empty_string(payload.get(field)) or ".v1" not in payload[field]:
            violations.append(f"{subject}: {field} must declare major version 1")
    for field in VERDICT_DIGEST_FIELDS:
        if not is_canonical_sha256_digest(payload.get(field)):
            violations.append(f"{subject}: {field} must be a canonical sha256 digest")
    for field in ("registry_signature", "reference_values_signature"):
        validate_signature_metadata(
            f"{subject}: {field}",
            payload.get(field),
            violations,
            require_value=False,
        )
    for field in ("checks", "artifacts"):
        if field in payload and not isinstance(payload[field], dict):
            violations.append(f"{subject}: {field} must be an object")
    if "errors" in payload and not isinstance(payload["errors"], list):
        violations.append(f"{subject}: errors must be an array")
    if "known_unsupported_modes" in payload and not isinstance(
        payload["known_unsupported_modes"], list
    ):
        violations.append(f"{subject}: known_unsupported_modes must be an array")
    return violations


def validate_policy_fixture(path: Path, payload: Any) -> list[str]:
    violations: list[str] = []
    subject = path.as_posix()
    if not isinstance(payload, dict):
        return [f"{subject}: policy fixture must be an object"]
    validate_canonical_json_values(subject, payload, violations)

    required = (
        "schema",
        "enforcement",
        "hardware",
        "channel_binding_requirement",
        "request_confidentiality_requirement",
        "response_confidentiality_requirement",
        "response_integrity_requirement",
        "model_binding_requirement",
        "provenance",
        "freshness",
        "stale_verdicts",
        "verdict_ttl_millis",
        "provider_registry_digest",
        "reference_values_digest",
    )
    require_fields(subject, payload, required, violations)
    if payload.get("schema") != "confidential-inference.policy.v1":
        violations.append(f"{subject}: schema must be confidential-inference.policy.v1")
    for field in ("provider_registry_digest", "reference_values_digest"):
        if not is_canonical_sha256_digest(payload.get(field)):
            violations.append(f"{subject}: {field} must be a canonical sha256 digest")
    if not isinstance(payload.get("freshness"), dict) or "mode" not in payload.get(
        "freshness", {}
    ):
        violations.append(f"{subject}: freshness must be a tagged object")
    if not isinstance(payload.get("stale_verdicts"), dict) or "mode" not in payload.get(
        "stale_verdicts", {}
    ):
        violations.append(f"{subject}: stale_verdicts must be a tagged object")
    if not isinstance(payload.get("verdict_ttl_millis"), int) or isinstance(
        payload.get("verdict_ttl_millis"), bool
    ):
        violations.append(f"{subject}: verdict_ttl_millis must be an integer")
    return violations


def validate_registry_fixture(path: Path, envelope: Any) -> list[str]:
    violations: list[str] = []
    subject = path.as_posix()
    if not isinstance(envelope, dict):
        return [f"{subject}: registry envelope must be an object"]
    if envelope.get("schema") != "confidential-inference.provider-registry-envelope.v1":
        violations.append(
            f"{subject}: schema must be confidential-inference.provider-registry-envelope.v1"
        )
    validate_signature_metadata(
        f"{subject}: signature",
        envelope.get("signature"),
        violations,
        require_value=True,
    )
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        violations.append(f"{subject}: payload must be an object")
        return violations
    validate_canonical_json_values(f"{subject}: payload", payload, violations)
    validate_payload_signature(subject, envelope.get("signature"), payload, violations)
    for field in ("schema", "version", "generated_at", "source_sync_run", "models"):
        if field not in payload:
            violations.append(f"{subject}: payload missing {field}")
    if payload.get("schema") != "confidential-inference.provider-registry.v1":
        violations.append(f"{subject}: payload schema must be confidential-inference.provider-registry.v1")
    if "generated_at" in payload:
        parse_canonical_utc_timestamp_millis(
            f"{subject}: payload.generated_at",
            payload.get("generated_at"),
            violations,
        )
    sync = payload.get("source_sync_run")
    if not isinstance(sync, dict):
        violations.append(f"{subject}: source_sync_run must be an object")
    else:
        require_fields(
            f"{subject}: source_sync_run",
            sync,
            ("completed_at", "status", "source"),
            violations,
        )
        if "completed_at" in sync:
            parse_canonical_utc_timestamp_millis(
                f"{subject}: source_sync_run.completed_at",
                sync.get("completed_at"),
                violations,
            )
    models = payload.get("models")
    if not isinstance(models, dict) or not models:
        violations.append(f"{subject}: models must be a non-empty object")
        return violations
    for model_id, model in models.items():
        model_subject = f"{subject}: model {model_id}"
        if not isinstance(model, dict):
            violations.append(f"{model_subject}: model must be an object")
            continue
        require_fields(
            model_subject,
            model,
            ("canonical_model", "display_name", "family", "aliases", "routes"),
            violations,
        )
        if model.get("canonical_model") != model_id:
            violations.append(f"{model_subject}: canonical_model must match model key")
        routes = model.get("routes")
        if not isinstance(routes, list) or not routes:
            violations.append(f"{model_subject}: routes must be a non-empty array")
            continue
        for index, route in enumerate(routes):
            route_subject = f"{model_subject}: routes[{index}]"
            if not isinstance(route, dict):
                violations.append(f"{route_subject}: route must be an object")
                continue
            require_fields(route_subject, route, REGISTRY_ROUTE_FIELDS, violations)
    return violations


def validate_reference_values_fixture(path: Path, envelope: Any) -> list[str]:
    violations: list[str] = []
    subject = path.as_posix()
    if not isinstance(envelope, dict):
        return [f"{subject}: reference-values envelope must be an object"]
    if envelope.get("schema") != "confidential-inference.reference-values-envelope.v1":
        violations.append(
            f"{subject}: schema must be confidential-inference.reference-values-envelope.v1"
        )
    validate_signature_metadata(
        f"{subject}: signature",
        envelope.get("signature"),
        violations,
        require_value=True,
    )
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        violations.append(f"{subject}: payload must be an object")
        return violations
    validate_canonical_json_values(f"{subject}: payload", payload, violations)
    validate_payload_signature(subject, envelope.get("signature"), payload, violations)
    require_fields(
        f"{subject}: payload",
        payload,
        (
            "schema",
            "version",
            "issuer",
            "valid_from",
            "valid_until",
            "valid_until_epoch_ms",
            "revocation_epoch",
            "minimum_acceptable_version",
            "providers",
        ),
        violations,
    )
    if payload.get("schema") != "confidential-inference.reference-values.v1":
        violations.append(f"{subject}: payload schema must be confidential-inference.reference-values.v1")
    valid_from_epoch = parse_canonical_utc_timestamp_millis(
        f"{subject}: payload.valid_from",
        payload.get("valid_from"),
        violations,
    )
    valid_until_epoch = parse_canonical_utc_timestamp_millis(
        f"{subject}: payload.valid_until",
        payload.get("valid_until"),
        violations,
    )
    valid_until_epoch_field = payload.get("valid_until_epoch_ms")
    if not isinstance(valid_until_epoch_field, int) or isinstance(
        valid_until_epoch_field, bool
    ):
        violations.append(f"{subject}: payload.valid_until_epoch_ms must be an integer")
    elif (
        valid_until_epoch is not None
        and valid_until_epoch_field != valid_until_epoch
    ):
        violations.append(
            f"{subject}: payload.valid_until_epoch_ms must match payload.valid_until"
        )
    if (
        valid_from_epoch is not None
        and valid_until_epoch is not None
        and valid_from_epoch >= valid_until_epoch
    ):
        violations.append(
            f"{subject}: payload.valid_from must be before payload.valid_until"
        )
    providers = payload.get("providers")
    if not isinstance(providers, dict) or not providers:
        violations.append(f"{subject}: providers must be a non-empty object")
        return violations
    for provider_id, provider in providers.items():
        provider_subject = f"{subject}: provider {provider_id}"
        if not isinstance(provider, dict):
            violations.append(f"{provider_subject}: provider must be an object")
            continue
        require_fields(provider_subject, provider, ("accepted_measurements", "routes"), violations)
        routes = provider.get("routes")
        if not isinstance(routes, dict) or not routes:
            violations.append(f"{provider_subject}: routes must be a non-empty object")
            continue
        for route_id, route in routes.items():
            route_subject = f"{provider_subject}: route {route_id}"
            if not isinstance(route, dict):
                violations.append(f"{route_subject}: route must be an object")
                continue
            require_fields(route_subject, route, REFERENCE_ROUTE_FIELDS, violations)
            route_valid_until_epoch = parse_canonical_utc_timestamp_millis(
                f"{route_subject}: valid_until",
                route.get("valid_until"),
                violations,
            )
            route_valid_until_epoch_field = route.get("valid_until_epoch_ms")
            if not isinstance(route_valid_until_epoch_field, int) or isinstance(
                route_valid_until_epoch_field, bool
            ):
                violations.append(f"{route_subject}: valid_until_epoch_ms must be an integer")
            elif (
                route_valid_until_epoch is not None
                and route_valid_until_epoch_field != route_valid_until_epoch
            ):
                violations.append(
                    f"{route_subject}: valid_until_epoch_ms must match valid_until"
                )
            accepted_cpu_tees = route.get("accepted_cpu_tees")
            if (
                route.get("evidence_family") == "tinfoil_hw_verified_tls"
                and isinstance(accepted_cpu_tees, list)
            ):
                unsupported_cpu_tees = sorted(
                    tee
                    for tee in accepted_cpu_tees
                    if tee in UNSUPPORTED_PRODUCTION_TINFOIL_CPU_TEES
                )
                if unsupported_cpu_tees:
                    violations.append(
                        f"{route_subject}: tinfoil_hw_verified_tls reference values "
                        "must not accept unsupported production CPU TEEs before a "
                        f"backend and live corpus exist: {unsupported_cpu_tees}"
                    )
            artifacts = route.get("model_artifacts")
            if not isinstance(artifacts, list) or not artifacts:
                violations.append(f"{route_subject}: model_artifacts must be non-empty")
                continue
            for index, artifact in enumerate(artifacts):
                artifact_subject = f"{route_subject}: model_artifacts[{index}]"
                if not isinstance(artifact, dict):
                    violations.append(f"{artifact_subject}: artifact must be an object")
                    continue
                require_fields(artifact_subject, artifact, ("kind", "name", "digest"), violations)
    return violations


def validate_live_conformance_plan(path: Path, payload: Any, root: Path) -> list[str]:
    violations: list[str] = []
    subject = path.as_posix()
    if not isinstance(payload, dict):
        return [f"{subject}: live conformance plan must be an object"]
    if payload.get("schema") != "confidential-inference.live-conformance-plan.v1":
        violations.append(f"{subject}: schema must be confidential-inference.live-conformance-plan.v1")
    if payload.get("model_alias_matrix_path") != MODEL_ALIAS_MATRIX_FIXTURE.as_posix():
        violations.append(
            f"{subject}: model_alias_matrix_path must be "
            f"{MODEL_ALIAS_MATRIX_FIXTURE.as_posix()}"
        )
    if (
        payload.get("model_alias_matrix_envelope_path")
        != MODEL_ALIAS_MATRIX_ENVELOPE_FIXTURE.as_posix()
    ):
        violations.append(
            f"{subject}: model_alias_matrix_envelope_path must be "
            f"{MODEL_ALIAS_MATRIX_ENVELOPE_FIXTURE.as_posix()}"
        )
    if payload.get("compatibility_matrix_path") != COMPATIBILITY_MATRIX_FIXTURE.as_posix():
        violations.append(
            f"{subject}: compatibility_matrix_path must be "
            f"{COMPATIBILITY_MATRIX_FIXTURE.as_posix()}"
        )
    if (
        payload.get("compatibility_matrix_envelope_path")
        != COMPATIBILITY_MATRIX_ENVELOPE_FIXTURE.as_posix()
    ):
        violations.append(
            f"{subject}: compatibility_matrix_envelope_path must be "
            f"{COMPATIBILITY_MATRIX_ENVELOPE_FIXTURE.as_posix()}"
        )

    alias_matrix = load_dependency_fixture(
        root,
        MODEL_ALIAS_MATRIX_FIXTURE,
        subject,
        violations,
    )
    compatibility_matrix = load_dependency_fixture(
        root,
        COMPATIBILITY_MATRIX_FIXTURE,
        subject,
        violations,
    )
    alias_provider_models = collect_alias_provider_models(
        MODEL_ALIAS_MATRIX_FIXTURE,
        alias_matrix,
        violations,
    )
    compatibility_profiles = collect_compatibility_profiles(
        COMPATIBILITY_MATRIX_FIXTURE,
        compatibility_matrix,
        violations,
    )

    providers = payload.get("providers")
    if not isinstance(providers, list) or not providers:
        violations.append(f"{subject}: providers must be a non-empty array")
        return violations

    for index, provider in enumerate(providers):
        provider_subject = f"{subject}: providers[{index}]"
        if not isinstance(provider, dict):
            violations.append(f"{provider_subject}: provider must be an object")
            continue
        provider_id = provider.get("id")
        if not non_empty_string(provider_id):
            violations.append(f"{provider_subject}: id must be non-empty")
            provider_id = f"providers[{index}]"
        if provider.get("enabled") is not False:
            violations.append(f"{provider_subject}: enabled must be false by default")
        if "expected_model_ids" in provider:
            violations.append(
                f"{provider_subject}: expected_model_ids must be imported from "
                "the model alias matrix, not copied into the plan"
            )
        if provider.get("expected_model_ids_from_alias_matrix") is not True:
            violations.append(
                f"{provider_subject}: expected_model_ids_from_alias_matrix must be true"
            )
        elif isinstance(provider_id, str):
            expected_models = alias_provider_models.get(provider_id, [])
            if not expected_models:
                violations.append(
                    f"{provider_subject}: provider {provider_id} must have "
                    "provider_routes in the model alias matrix"
                )

        compatibility_provider = provider.get("compatibility_provider")
        if not non_empty_string(compatibility_provider):
            violations.append(f"{provider_subject}: compatibility_provider must be non-empty")
        elif compatibility_provider not in compatibility_profiles:
            violations.append(
                f"{provider_subject}: compatibility_provider {compatibility_provider} "
                "is missing from the compatibility matrix"
            )

        model_list_url = provider.get("model_list_url")
        if not non_empty_string(model_list_url):
            violations.append(f"{provider_subject}: model_list_url must be non-empty")
        elif url_has_credentials(model_list_url):
            violations.append(f"{provider_subject}: model_list_url must not include URL credentials")

        attestation_url = provider.get("attestation_url")
        expected_attestation = provider.get("expected_attestation")
        if attestation_url is None:
            if expected_attestation is not None:
                violations.append(
                    f"{provider_subject}: expected_attestation requires attestation_url"
                )
        elif not non_empty_string(attestation_url):
            violations.append(f"{provider_subject}: attestation_url must be non-empty")
        elif url_has_credentials(attestation_url):
            violations.append(f"{provider_subject}: attestation_url must not include URL credentials")
        if not non_empty_string(provider.get("auth_env")):
            violations.append(f"{provider_subject}: auth_env must be non-empty")
        if attestation_url is not None:
            validate_expected_attestation_shape(
                provider_subject,
                expected_attestation,
                violations,
            )

    return violations


def validate_live_sync_corpus(path: Path, payload: Any) -> list[str]:
    violations: list[str] = []
    subject = path.as_posix()
    if not isinstance(payload, dict):
        return [f"{subject}: live-sync corpus must be an object"]
    if payload.get("schema") != "confidential-inference.provider-live-sync-corpus.v1":
        violations.append(
            f"{subject}: schema must be confidential-inference.provider-live-sync-corpus.v1"
        )
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        violations.append(f"{subject}: cases must be a non-empty array")
        return violations

    for index, case in enumerate(cases):
        fallback_subject = f"{subject}: cases[{index}]"
        if not isinstance(case, dict):
            violations.append(f"{fallback_subject}: case must be an object")
            continue
        case_id = case.get("id")
        if not non_empty_string(case_id):
            violations.append(f"{fallback_subject}: id must be non-empty")
            case_subject = fallback_subject
        else:
            case_subject = f"{subject}: case {case_id}"
        provider = case.get("provider")
        if not non_empty_string(provider):
            violations.append(f"{case_subject}: provider must be non-empty")

        expected = case.get("expected")
        expected_error = case.get("expected_error_contains")
        if (expected is None) == (expected_error is None):
            violations.append(
                f"{case_subject}: define exactly one of expected or "
                "expected_error_contains"
            )
        elif expected_error is not None and not non_empty_string(expected_error):
            violations.append(
                f"{case_subject}: expected_error_contains must be non-empty"
            )

        fixture_label = live_sync_fixture_only_label(case)
        if fixture_label is not None:
            validate_live_sync_route_status_collection(
                f"{case_subject}: enrichments",
                case.get("enrichments"),
                fixture_label,
                violations,
                require_new_unverified=False,
            )

        if expected is None:
            continue
        if not isinstance(expected, dict):
            violations.append(f"{case_subject}: expected must be an object")
            continue
        if fixture_label is None:
            continue
        for field in ("reviewed_routes", "unreviewed_routes"):
            validate_live_sync_route_status_collection(
                f"{case_subject}: expected.{field}",
                expected.get(field),
                fixture_label,
                violations,
                require_new_unverified=(field == "unreviewed_routes"),
            )
    return violations


def live_sync_fixture_only_label(case: dict[str, Any]) -> str | None:
    provider = case.get("provider")
    if isinstance(provider, str):
        for pattern, label in FIXTURE_ONLY_LIVE_SYNC_PROVIDER_PATTERNS.items():
            if pattern in provider:
                return label
    evidence_family = case.get("evidence_family")
    if isinstance(evidence_family, str):
        return FIXTURE_ONLY_LIVE_SYNC_EVIDENCE_FAMILIES.get(evidence_family)
    return None


def validate_live_sync_route_status_collection(
    subject: str,
    routes: Any,
    fixture_label: str,
    violations: list[str],
    *,
    require_new_unverified: bool,
) -> None:
    if routes is None:
        return
    if not isinstance(routes, list):
        violations.append(f"{subject}: routes must be an array")
        return
    for index, route in enumerate(routes):
        route_subject = f"{subject}[{index}]"
        if not isinstance(route, dict):
            violations.append(f"{route_subject}: route must be an object")
            continue
        route_status = route.get("route_status")
        if not non_empty_string(route_status):
            violations.append(f"{route_subject}: route_status must be non-empty")
            continue
        if route_status == ACTIVE_REGISTRY_ROUTE_STATUS:
            violations.append(
                f"{route_subject}: live-sync fixture routes for {fixture_label} "
                "must not be active before credentialed live conformance and "
                "signed reference values exist"
            )
        if (
            require_new_unverified
            and route_status != NEW_UNVERIFIED_REGISTRY_ROUTE_STATUS
        ):
            violations.append(
                f"{route_subject}: unreviewed live-sync discoveries must remain "
                f"{NEW_UNVERIFIED_REGISTRY_ROUTE_STATUS}"
            )


def validate_compatibility_matrix_envelope(path: Path, envelope: Any, root: Path) -> list[str]:
    violations: list[str] = []
    subject = path.as_posix()
    if not isinstance(envelope, dict):
        return [f"{subject}: compatibility matrix envelope must be an object"]
    if envelope.get("schema") != "confidential-inference.provider-compatibility-matrix-envelope.v1":
        violations.append(
            f"{subject}: schema must be confidential-inference.provider-compatibility-matrix-envelope.v1"
        )
    validate_signature_metadata(
        f"{subject}: signature",
        envelope.get("signature"),
        violations,
        require_value=True,
    )
    payload = envelope.get("payload")
    validate_canonical_json_values(f"{subject}: payload", payload, violations)
    validate_payload_signature(subject, envelope.get("signature"), payload, violations)
    collect_compatibility_profiles(path, payload, violations)
    raw_matrix = load_dependency_fixture(
        root,
        COMPATIBILITY_MATRIX_FIXTURE,
        subject,
        violations,
    )
    if raw_matrix is not None and payload != raw_matrix:
        violations.append(
            f"{subject}: payload must match {COMPATIBILITY_MATRIX_FIXTURE.as_posix()}"
        )
    return violations


def validate_model_alias_matrix_envelope(path: Path, envelope: Any, root: Path) -> list[str]:
    violations: list[str] = []
    subject = path.as_posix()
    if not isinstance(envelope, dict):
        return [f"{subject}: model alias matrix envelope must be an object"]
    if envelope.get("schema") != "confidential-inference.model-alias-matrix-envelope.v1":
        violations.append(f"{subject}: schema must be confidential-inference.model-alias-matrix-envelope.v1")
    validate_signature_metadata(
        f"{subject}: signature",
        envelope.get("signature"),
        violations,
        require_value=True,
    )
    payload = envelope.get("payload")
    validate_canonical_json_values(f"{subject}: payload", payload, violations)
    validate_payload_signature(subject, envelope.get("signature"), payload, violations)
    collect_alias_provider_models(path, payload, violations)
    raw_matrix = load_dependency_fixture(
        root,
        MODEL_ALIAS_MATRIX_FIXTURE,
        subject,
        violations,
    )
    if raw_matrix is not None and payload != raw_matrix:
        violations.append(f"{subject}: payload must match {MODEL_ALIAS_MATRIX_FIXTURE.as_posix()}")
    return violations


def load_dependency_fixture(
    root: Path,
    relative_path: Path,
    subject: str,
    violations: list[str],
) -> Any:
    path = root / relative_path
    if not path.exists():
        violations.append(f"{subject}: dependency {relative_path.as_posix()} does not exist")
        return None
    try:
        return load_json(path)
    except json.JSONDecodeError as error:
        violations.append(
            f"{subject}: dependency {relative_path.as_posix()} invalid JSON: {error}"
        )
        return None


def collect_alias_provider_models(
    path: Path,
    payload: Any,
    violations: list[str],
) -> dict[str, list[str]]:
    subject = path.as_posix()
    provider_models: dict[str, set[str]] = {}
    if not isinstance(payload, dict):
        violations.append(f"{subject}: model alias matrix must be an object")
        return {}
    if payload.get("schema") != "confidential-inference.model-alias-matrix.v1":
        violations.append(f"{subject}: schema must be confidential-inference.model-alias-matrix.v1")
    models = payload.get("models")
    if not isinstance(models, list):
        violations.append(f"{subject}: models must be an array")
        return {}
    for model_index, model in enumerate(models):
        model_subject = f"{subject}: models[{model_index}]"
        if not isinstance(model, dict):
            violations.append(f"{model_subject}: model must be an object")
            continue
        routes = model.get("provider_routes")
        if not isinstance(routes, list):
            violations.append(f"{model_subject}: provider_routes must be an array")
            continue
        for route_index, route in enumerate(routes):
            route_subject = f"{model_subject}: provider_routes[{route_index}]"
            if not isinstance(route, dict):
                violations.append(f"{route_subject}: route must be an object")
                continue
            provider = route.get("provider")
            provider_model = route.get("provider_model")
            if not non_empty_string(provider):
                violations.append(f"{route_subject}: provider must be non-empty")
                continue
            if not non_empty_string(provider_model):
                violations.append(f"{route_subject}: provider_model must be non-empty")
                continue
            provider_models.setdefault(provider, set()).add(provider_model)
    return {
        provider: sorted(models_for_provider)
        for provider, models_for_provider in provider_models.items()
    }


def collect_compatibility_profiles(
    path: Path,
    payload: Any,
    violations: list[str],
) -> dict[str, dict[str, Any]]:
    subject = path.as_posix()
    if not isinstance(payload, dict):
        violations.append(f"{subject}: compatibility matrix must be an object")
        return {}
    if payload.get("schema") != "confidential-inference.provider-compatibility-matrix.v1":
        violations.append(
            f"{subject}: schema must be confidential-inference.provider-compatibility-matrix.v1"
        )
    providers = payload.get("providers")
    if not isinstance(providers, dict):
        violations.append(f"{subject}: providers must be an object")
        return {}
    profiles: dict[str, dict[str, Any]] = {}
    for provider_id, profile in providers.items():
        profile_subject = f"{subject}: provider {provider_id}"
        if not isinstance(provider_id, str) or not provider_id:
            violations.append(f"{subject}: provider keys must be non-empty strings")
            continue
        if not isinstance(profile, dict):
            violations.append(f"{profile_subject}: provider must be an object")
            continue
        require_fields(
            profile_subject,
            profile,
            COMPATIBILITY_PROFILE_REQUIRED_FIELDS,
            violations,
        )
        if profile.get("provider") != provider_id:
            violations.append(f"{profile_subject}: provider must match provider key")
        if profile.get("streaming") == "unsupported" and "streaming" not in (
            profile.get("known_unsupported_modes") or []
        ):
            violations.append(
                f"{profile_subject}: streaming must be listed in known_unsupported_modes"
            )
        validate_fixture_only_compatibility_profile(
            profile_subject,
            profile,
            violations,
        )
        for field in ("supported_openai_endpoints", "known_unsupported_modes"):
            if field in profile and not isinstance(profile[field], list):
                violations.append(f"{profile_subject}: {field} must be an array")
        profiles[provider_id] = profile
    return profiles


def validate_fixture_only_compatibility_profile(
    profile_subject: str,
    profile: dict[str, Any],
    violations: list[str],
) -> None:
    attestation_shape = profile.get("attestation_endpoint_shape")
    provider_id = profile.get("provider")
    if attestation_shape == TINFOIL_FIXTURE_ATTESTATION_SHAPE:
        if profile.get("route_execution_status") == PRODUCTION_EXECUTABLE_ROUTE_STATUS:
            violations.append(
                f"{profile_subject}: Tinfoil fixture profiles must remain "
                "executable_fixture until matching live quote/certificate corpus "
                "and signed reference values exist"
            )
        if TINFOIL_LIVE_TDX_UNSUPPORTED_MODE not in (
            profile.get("known_unsupported_modes") or []
        ):
            violations.append(
                f"{profile_subject}: Tinfoil fixture profiles must list "
                f"{TINFOIL_LIVE_TDX_UNSUPPORTED_MODE} in known_unsupported_modes "
                "before production live TDX enablement"
            )

    provider_label = (
        FIXTURE_ONLY_COMPATIBILITY_PROVIDERS.get(provider_id)
        if isinstance(provider_id, str)
        else None
    )
    if not isinstance(attestation_shape, str):
        matched_label = provider_label
    else:
        matched_label = provider_label or next(
            (
                label
                for pattern, label in FIXTURE_ONLY_COMPATIBILITY_PROFILE_PATTERNS.items()
                if pattern in attestation_shape
            ),
            None,
        )
    if matched_label is None:
        return
    if profile.get("route_execution_status") in EXECUTABLE_ROUTE_STATUSES:
        violations.append(
            f"{profile_subject}: {matched_label} profiles must remain "
            "adapter_shape_fixture or verification_only until live provider corpus "
            "and signed reference values exist"
        )
    if "live_execution" not in (profile.get("known_unsupported_modes") or []):
        violations.append(
            f"{profile_subject}: {matched_label} profiles must list live_execution "
            "in known_unsupported_modes before production enablement"
        )


def validate_expected_attestation_shape(
    subject: str,
    expected: Any,
    violations: list[str],
) -> None:
    if not isinstance(expected, dict):
        violations.append(f"{subject}: expected_attestation must be an object")
        return
    content_type_contains = expected.get("content_type_contains")
    json_fields = expected.get("json_fields")
    if content_type_contains is None and json_fields is None:
        violations.append(
            f"{subject}: expected_attestation must define content type or JSON fields"
        )
    if content_type_contains is not None and not non_empty_string(content_type_contains):
        violations.append(
            f"{subject}: expected_attestation.content_type_contains must be non-empty"
        )
    if (
        not isinstance(json_fields, list)
        or not json_fields
        or any(not non_empty_string(field) for field in json_fields)
    ):
        violations.append(
            f"{subject}: expected_attestation.json_fields must contain non-empty strings"
        )
    elif any(not segment for field in json_fields for segment in field.split(".")):
        violations.append(
            f"{subject}: expected_attestation.json_fields must not contain malformed paths"
        )


def check_fixtures(root: Path) -> dict[str, Any]:
    groups = (
        (VERDICT_FIXTURES, validate_verdict_fixture),
        (POLICY_FIXTURES, validate_policy_fixture),
        (REGISTRY_FIXTURES, validate_registry_fixture),
        (REFERENCE_VALUE_FIXTURES, validate_reference_values_fixture),
    )
    violations: list[str] = []
    checked: list[str] = []
    for paths, validator in groups:
        for relative_path in paths:
            path = root / relative_path
            checked.append(relative_path.as_posix())
            if not path.exists():
                violations.append(f"{relative_path.as_posix()}: file does not exist")
                continue
            try:
                payload = load_json(path)
            except json.JSONDecodeError as error:
                violations.append(f"{relative_path.as_posix()}: invalid JSON: {error}")
                continue
            violations.extend(validator(relative_path, payload))
    for relative_path in (MODEL_ALIAS_MATRIX_ENVELOPE_FIXTURE,):
        path = root / relative_path
        checked.append(relative_path.as_posix())
        if not path.exists():
            violations.append(f"{relative_path.as_posix()}: file does not exist")
            continue
        try:
            payload = load_json(path)
        except json.JSONDecodeError as error:
            violations.append(f"{relative_path.as_posix()}: invalid JSON: {error}")
            continue
        violations.extend(validate_model_alias_matrix_envelope(relative_path, payload, root))
    for relative_path in (COMPATIBILITY_MATRIX_ENVELOPE_FIXTURE,):
        path = root / relative_path
        checked.append(relative_path.as_posix())
        if not path.exists():
            violations.append(f"{relative_path.as_posix()}: file does not exist")
            continue
        try:
            payload = load_json(path)
        except json.JSONDecodeError as error:
            violations.append(f"{relative_path.as_posix()}: invalid JSON: {error}")
            continue
        violations.extend(validate_compatibility_matrix_envelope(relative_path, payload, root))
    for relative_path in LIVE_CONFORMANCE_PLAN_FIXTURES:
        path = root / relative_path
        checked.append(relative_path.as_posix())
        if not path.exists():
            violations.append(f"{relative_path.as_posix()}: file does not exist")
            continue
        try:
            payload = load_json(path)
        except json.JSONDecodeError as error:
            violations.append(f"{relative_path.as_posix()}: invalid JSON: {error}")
            continue
        violations.extend(validate_live_conformance_plan(relative_path, payload, root))
    for relative_path in LIVE_SYNC_CORPUS_FIXTURES:
        path = root / relative_path
        checked.append(relative_path.as_posix())
        if not path.exists():
            violations.append(f"{relative_path.as_posix()}: file does not exist")
            continue
        try:
            payload = load_json(path)
        except json.JSONDecodeError as error:
            violations.append(f"{relative_path.as_posix()}: invalid JSON: {error}")
            continue
        violations.extend(validate_live_sync_corpus(relative_path, payload))
    return {
        "schema": SCHEMA,
        "checked": checked,
        "checked_count": len(checked),
        "violations": violations,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="Repository root. Defaults to the current directory.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full validation report as JSON.",
    )
    args = parser.parse_args(argv)

    report = check_fixtures(args.root)
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2, separators=(",", ": ")))
    elif report["violations"]:
        for violation in report["violations"]:
            print(f"normative fixture violation: {violation}", file=sys.stderr)
    else:
        print(
            "normative fixtures ok: "
            f"checked={report['checked_count']} schema={report['schema']}"
        )
    return 1 if report["violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
