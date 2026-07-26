"""Thin Python bindings for the Confidential Inference SDK FFI.

The binding deliberately delegates routing, attestation, request adaptation,
and verdict enforcement to the Rust SDK through the C ABI.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import ctypes
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Iterator


CONFIDENTIAL_INFERENCE_FFI_OK = 0
CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT = 1
CONFIDENTIAL_INFERENCE_FFI_PANIC = 2
CONFIDENTIAL_INFERENCE_FFI_BUSY = 3
CONFIDENTIAL_INFERENCE_FFI_PENDING = 4
CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED = 5
CONFIDENTIAL_INFERENCE_FFI_INTERNAL = 6
ACTIVE_POLICY_SCHEMA_PREFIX = "confidential-inference.active-policy"
VERDICT_SCHEMA_PREFIX = "confidential-inference.verdict"
POLICY_SCHEMA_PREFIX = "confidential-inference.policy"
REFERENCE_VALUES_SCHEMA_PREFIX = "confidential-inference.reference-values"
PROVIDER_REGISTRY_SCHEMA_PREFIX = "confidential-inference.provider-registry"
SUPPORTED_SCHEMA_MAJOR = 1
SHA256_DIGEST_PREFIX = "sha256:"
BASE64URL_SIGNATURE_PREFIX = "base64url:"
BASE64URL_NO_PAD_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
ED25519_PUBLIC_KEY_BYTE_LEN = 32
ED25519_SIGNATURE_BYTE_LEN = 64
ED25519_P = 2**255 - 19
ED25519_Q = 2**252 + 27742317777372353535851937790883648493
ED25519_D = (-121665 * pow(121666, ED25519_P - 2, ED25519_P)) % ED25519_P
ED25519_I = pow(2, (ED25519_P - 1) // 4, ED25519_P)
ED25519_BASE_X = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202
)
ED25519_BASE_Y = (
    46316835694926478169428394003475163141307993866256225615783033603165251855960
)
SHA256_DIGEST_HEX_LEN = 64
SHA256_DIGEST_HEX = "0123456789abcdef"
MAX_SAFE_JSON_INT = 9_007_199_254_740_991
ED25519_IDENTITY = (0, 1, 1, 0)
ED25519_BASE_POINT = (
    ED25519_BASE_X,
    ED25519_BASE_Y,
    1,
    (ED25519_BASE_X * ED25519_BASE_Y) % ED25519_P,
)
TRUSTED_ARTIFACT_SIGNING_KEYS = {
    ("confidential-inference", "confidential-inference-demo-ed25519-2026"): (
        "4oqJcHUzMr1y_vQT5rCy7xtKrdp6osFB8jNxKmh2s1E"
    ),
    ("confidential-inference", "confidential-inference-phase2-fixture-ed25519-2026"): (
        "cN-eInmtvsbRK_KSEYTJIi6yTthSAFv2QBOfUuWc2a4"
    ),
    ("confidential-inference", "confidential-inference-compatibility-fixture-ed25519-2026"): (
        "bjLBl0Hwr4JgYSrpn9E9ijiURyLgiWTdI5c49VKmFTs"
    ),
    ("confidential-inference", "confidential-inference-alias-matrix-fixture-ed25519-2026"): (
        "zxs36F3ACu6U8QEIs38VHio3s64qDK53Uh-DSI25xNc"
    ),
}
VERIFICATION_STATUS_VALUES = {
    "verified",
    "partial",
    "failed",
    "unreachable",
    "disabled",
}
ENFORCEMENT_VALUES = {
    "disabled",
    "observe",
    "enforce",
}
TRUST_TIER_VALUES = {
    "hw-verified-tls",
    "app-e2ee",
    "tee-only",
    "none",
}
CHANNEL_BINDING_KIND_VALUES = {
    "not_required",
    "tee_terminated_tls",
    "attested_app_e2ee",
    "any_attested_channel",
    "none",
}
MODEL_BINDING_RESULT_VALUES = {
    "verified",
    "partial",
    "not_supported",
    "failed",
}
CONFIDENTIALITY_RESULT_VALUES = {
    "channel_bound",
    "encrypted_bound",
    "not_bound",
    "unknown",
}
RESPONSE_INTEGRITY_RESULT_VALUES = {
    "channel_bound",
    "receipt_bound",
    "not_bound",
    "unknown",
}
CHECK_RESULT_VALUES = {
    "verified",
    "failed",
    "not_applicable",
    "not_supported",
    "unknown",
}
POLICY_CHANNEL_BINDING_REQUIREMENT_VALUES = {
    "not_required",
    "any_attested_channel",
    "tee_terminated_tls",
    "attested_app_e2ee",
}
POLICY_BOUND_DATA_REQUIREMENT_VALUES = {
    "not_required",
    "bound_to_attested_workload",
}
POLICY_RESPONSE_INTEGRITY_REQUIREMENT_VALUES = {
    "not_required",
    "any_bound",
    "channel_bound",
    "receipt_bound",
}
POLICY_MODEL_BINDING_REQUIREMENT_VALUES = {
    "not_required",
    "if_provider_supports",
    "required",
}
POLICY_CPU_TEE_MODES = {
    "not_required",
    "any_cpu_tee",
    "one_of",
}
POLICY_CPU_TEE_KINDS = {
    "tdx",
    "sev_snp",
    "nitro",
}
POLICY_GPU_TEE_MODES = {
    "not_required",
    "one_of",
}
POLICY_GPU_TEE_KINDS = {
    "nvidia_cc",
}
REGISTRY_ROUTE_STATUS_VALUES = {
    "active",
    "new_unverified",
    "verification_only",
    "deprecated",
    "removed",
    "blocked",
}
REGISTRY_ENCRYPTION_REQUIREMENT_VALUES = {
    "required",
    "not_required",
}
REGISTRY_STREAMING_VALUES = {
    "supported",
    "supported_if_encryption_supports_streaming",
    "unsupported",
}
CATALOG_ROUTE_EXECUTION_STATUS_VALUES = {
    "executable_fixture",
    "adapter_shape_fixture",
    "verification_only",
    "executable",
}
FRESHNESS_CLASS_VALUES = {
    "per_request",
    "per_session",
    "cached_binding",
}
ALIAS_CONFIDENCE_VALUES = {
    "curated",
    "provider_declared",
    "algorithmic",
    "manual_override",
}
POLICY_FRESHNESS_MODES = {
    "per_request",
    "per_session",
    "allow_cached_binding_millis",
}
POLICY_STALE_VERDICT_MODES = {
    "fail_closed",
    "allow_for_millis",
}
POLICY_PROVENANCE_FIELDS = {
    "workload_image",
    "model_artifacts",
    "reproducible_build",
    "source_attestation",
    "dependency_sbom",
}
VERDICT_KNOWN_FIELDS = {
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
    "check_outcomes",
    "route_attribution",
    "artifacts",
    "errors",
    "required",
}
VERDICT_EVIDENCE_REFS = {
    "policy_digest",
    "provider_registry_digest",
    "reference_values_digest",
    "raw_evidence_digest",
    "evidence_digest",
}
ROUTE_PARTY_ROLES = {
    "inference_provider",
    "registry_authority",
    "reference_values_authority",
    "workload_operator",
    "tee_platform",
    "cloud_host",
}
ATTRIBUTION_SOURCES = {
    "signed_registry",
    "signed_reference_values",
    "attested_evidence",
    "unknown",
}
OPERATION_STATUS_VALUES = {"pending", "ready", "failed", "cancelled"}
OPERATION_STATE_BASE_FIELDS = {"status"}
OPERATION_STATE_FAILED_FIELDS = {"status", "result_available", "error"}
FFI_ERROR_ENVELOPE_FIELDS = {"error"}
FFI_ERROR_FIELDS = {"type", "code", "message"}
FFI_STATUS_FIELDS = {
    "async_handle_abi_available",
    "callbacks_available",
    "readiness_fd_available",
    "stream_handle_abi_available",
    "blocking_helpers_available",
    "reason",
}
STREAM_EVENT_TYPES = {
    "verdict",
    "response",
    "response_receipt",
    "done",
    "error",
    "cancelled",
    "closed",
}
STREAM_VERDICT_EVENT_FIELDS = {
    "type",
    "response_channel_bound",
    "response_integrity_result",
    "verdict",
}
STREAM_RECEIPT_EVENT_FIELDS = {
    "type",
    "response_integrity_result",
    "receipt_verified",
    "receipt",
}
STREAM_RESPONSE_EVENT_FIELDS = {"type", "response"}
STREAM_ERROR_EVENT_FIELDS = {"type", "status", "error"}
STREAM_TERMINAL_EVENT_FIELDS = {"type"}
MODEL_LIST_FIELDS = {"object", "data"}
MODEL_RECORD_FIELDS = {"id", "object", "owned_by"}
CONFIDENTIAL_MODEL_FIELDS = {
    "canonical_model",
    "display_name",
    "family",
    "aliases",
    "routes",
}
CONFIDENTIAL_ROUTE_FIELDS = {
    "route_id",
    "provider",
    "provider_model",
    "evidence_family",
    "route_execution_status",
    "chat_executable",
    "known_unsupported_modes",
    "trust_tier",
    "channel_binding_kind",
    "request_encryption",
    "response_decryption",
    "streaming_allowed",
    "alias_confidence",
    "api_endpoint",
    "evidence_endpoint",
    "adapter_version",
}
ACTIVE_POLICY_SNAPSHOT_KNOWN_FIELDS = {
    "schema",
    "policy",
    "policy_digest",
    "required",
}
POLICY_KNOWN_FIELDS = {
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
    "required",
}
POLICY_DIGEST_FIELDS = POLICY_KNOWN_FIELDS - {"required"}
POLICY_HARDWARE_FIELDS = {"cpu", "gpu"}
POLICY_TEE_BASE_FIELDS = {"mode"}
POLICY_TEE_ONE_OF_FIELDS = {"mode", "allowed"}
POLICY_TAGGED_BASE_FIELDS = {"mode"}
POLICY_TAGGED_MILLIS_FIELDS = {"mode", "millis"}
TRUST_ARTIFACTS_KNOWN_FIELDS = {
    "registry",
    "registry_digest",
    "registry_source",
    "registry_signature",
    "reference_values",
    "reference_values_digest",
    "reference_values_source",
    "reference_values_signature",
    "required",
}
REGISTRY_PAYLOAD_KNOWN_FIELDS = {
    "schema",
    "version",
    "generated_at",
    "source_sync_run",
    "models",
    "required",
}
REFERENCE_VALUES_PAYLOAD_KNOWN_FIELDS = {
    "schema",
    "version",
    "issuer",
    "valid_from",
    "valid_until",
    "valid_until_epoch_ms",
    "revocation_epoch",
    "minimum_acceptable_version",
    "providers",
    "required",
}


class ConfidentialInferenceError(RuntimeError):
    def __init__(self, status: int, error: dict[str, Any] | None = None):
        self.status = status
        self.error = error or {"code": "unknown", "message": "unknown FFI error"}
        code = self.error.get("code", "unknown")
        message = self.error.get("message", "unknown FFI error")
        super().__init__(f"{code}: {message}")


def canonical_json(value: Any) -> str:
    """Return the SDK canonical JSON encoding used for digest fixtures."""
    return _canonical_json_value(value)


def canonical_sha256_digest(value: Any) -> str:
    """Return `sha256:` plus the digest of the SDK canonical JSON encoding."""
    encoded = canonical_json(value).encode("utf-8")
    return SHA256_DIGEST_PREFIX + hashlib.sha256(encoded).hexdigest()


def policy_canonical_json(policy: dict[str, Any]) -> str:
    """Return the normalized canonical JSON form of a Confidential Inference policy payload."""
    return canonical_json(_normalized_policy_for_digest(policy))


def policy_digest(policy: dict[str, Any]) -> str:
    """Return the normalized canonical digest of a Confidential Inference policy payload."""
    return canonical_sha256_digest(_normalized_policy_for_digest(policy))


def status(library_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Return the loaded ConfidentialInference FFI capability status."""
    native = _Native(library_path)
    return native.status()


def _canonical_json_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_JSON_INT:
            _raise_malformed(
                "malformed_canonical_json",
                "canonical JSON integer exceeds the cross-language JSON safe integer limit",
            )
        return str(value)
    if isinstance(value, float):
        _raise_malformed(
            "malformed_canonical_json",
            "canonical JSON does not support floating point numbers",
        )
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json_value(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            _raise_malformed(
                "malformed_canonical_json",
                "canonical JSON object keys must be strings",
            )
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return (
            "{"
            + ",".join(
                f"{json.dumps(key, ensure_ascii=False, separators=(',', ':'))}:"
                f"{_canonical_json_value(item)}"
                for key, item in items
            )
            + "}"
        )
    _raise_malformed(
        "malformed_canonical_json",
        f"canonical JSON does not support values of type {type(value).__name__}",
    )


def _normalized_policy_for_digest(policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, dict):
        _raise_malformed("malformed_policy_digest", "policy payload must be an object")
    _validate_schema_major(
        policy,
        "schema",
        POLICY_SCHEMA_PREFIX,
        "policy schema",
        error_code="malformed_policy_digest",
        incompatible_code="incompatible_policy_digest",
        subject="policy payload",
    )
    _require_exact_fields(
        policy,
        POLICY_DIGEST_FIELDS,
        "policy payload",
        "malformed_policy_digest",
    )
    _validate_policy_digest_structured_fields(policy)
    normalized = _clone_json_value(policy)
    for field in ("cpu", "gpu"):
        tee_requirement = normalized["hardware"][field]
        if tee_requirement.get("mode") == "one_of":
            tee_requirement["allowed"] = sorted(set(tee_requirement["allowed"]))
    _validate_policy_schema_fields(normalized)
    _validate_policy_millis_fields(normalized)
    return normalized


def _validate_policy_digest_structured_fields(policy: dict[str, Any]) -> None:
    hardware = policy.get("hardware")
    if not isinstance(hardware, dict):
        _raise_malformed(
            "malformed_policy_digest",
            "policy payload hardware must be an object",
        )
    _require_exact_fields(
        hardware,
        POLICY_HARDWARE_FIELDS,
        "policy payload hardware",
        "malformed_policy_digest",
    )
    _validate_policy_digest_tee_requirement(hardware.get("cpu"), "hardware.cpu")
    _validate_policy_digest_tee_requirement(hardware.get("gpu"), "hardware.gpu")

    provenance = policy.get("provenance")
    if not isinstance(provenance, dict):
        _raise_malformed(
            "malformed_policy_digest",
            "policy payload provenance must be an object",
        )
    _require_exact_fields(
        provenance,
        POLICY_PROVENANCE_FIELDS,
        "policy payload provenance",
        "malformed_policy_digest",
    )
    _validate_policy_digest_tagged_millis(
        policy.get("freshness"),
        "freshness",
        "allow_cached_binding_millis",
    )
    _validate_policy_digest_tagged_millis(
        policy.get("stale_verdicts"),
        "stale_verdicts",
        "allow_for_millis",
    )


def _validate_policy_digest_tee_requirement(value: Any, field: str) -> None:
    if not isinstance(value, dict):
        _raise_malformed(
            "malformed_policy_digest",
            f"policy payload {field} must be an object",
        )
    allowed = (
        POLICY_TEE_ONE_OF_FIELDS
        if value.get("mode") == "one_of"
        else POLICY_TEE_BASE_FIELDS
    )
    _require_exact_fields(
        value,
        allowed,
        f"policy payload {field}",
        "malformed_policy_digest",
    )


def _validate_policy_digest_tagged_millis(
    value: Any,
    field: str,
    millis_mode: str,
) -> None:
    if not isinstance(value, dict):
        _raise_malformed(
            "malformed_policy_digest",
            f"policy payload {field} must be an object",
        )
    allowed = (
        POLICY_TAGGED_MILLIS_FIELDS
        if value.get("mode") == millis_mode
        else POLICY_TAGGED_BASE_FIELDS
    )
    _require_exact_fields(
        value,
        allowed,
        f"policy payload {field}",
        "malformed_policy_digest",
    )


def _require_exact_fields(
    payload: dict[str, Any],
    allowed: set[str],
    subject: str,
    code: str,
) -> None:
    if any(not isinstance(field, str) for field in payload):
        _raise_malformed(code, f"{subject} field names must be strings")
    actual = set(payload)
    missing = sorted(allowed - actual)
    if missing:
        _raise_malformed(code, f"{subject} is missing {', '.join(missing)}")
    extra = sorted(actual - allowed)
    if extra:
        _raise_malformed(code, f"{subject} has unsupported field {extra[0]}")


def _clone_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_JSON_INT:
            _raise_malformed(
                "malformed_canonical_json",
                "canonical JSON integer exceeds the cross-language JSON safe integer limit",
            )
        return value
    if isinstance(value, float):
        _raise_malformed(
            "malformed_canonical_json",
            "canonical JSON does not support floating point numbers",
        )
    if isinstance(value, list):
        return [_clone_json_value(item) for item in value]
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            _raise_malformed(
                "malformed_canonical_json",
                "canonical JSON object keys must be strings",
            )
        return {key: _clone_json_value(item) for key, item in value.items()}
    _raise_malformed(
        "malformed_canonical_json",
        f"canonical JSON does not support values of type {type(value).__name__}",
    )


def _validate_confidential_response(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    if "response" not in payload and "verdict" not in payload:
        return payload

    verdict = payload.get("verdict")
    if not isinstance(verdict, dict):
        _raise_malformed(
            "malformed_confidential_response",
            "confidential response is missing an embedded verdict",
        )
    _validate_verdict(verdict)
    _validate_verdict_mirrors(
        payload,
        verdict,
        "malformed_confidential_response",
        "confidential response",
    )
    return payload


def _validate_stream_event(event: Any) -> Any:
    if not isinstance(event, dict):
        _raise_malformed(
            "malformed_stream_event",
            "stream event must be an object",
        )
    event_type = event.get("type")
    if not isinstance(event_type, str) or event_type not in STREAM_EVENT_TYPES:
        choices = ", ".join(sorted(STREAM_EVENT_TYPES))
        _raise_malformed(
            "malformed_stream_event",
            f"stream event type must be one of: {choices}",
        )
    if event.get("type") == "response_receipt":
        return _validate_stream_receipt_event(event)
    if event.get("type") == "response":
        return _validate_stream_response_event(event)
    if event.get("type") in {"done", "cancelled", "closed"}:
        return _validate_stream_terminal_event(event)
    if event.get("type") == "error":
        return _validate_stream_error_event(event)
    return _validate_stream_verdict_event(event)


def _validate_stream_verdict_event(event: dict[str, Any]) -> Any:
    _require_exact_fields(
        event,
        STREAM_VERDICT_EVENT_FIELDS,
        "stream verdict event",
        "malformed_stream_verdict",
    )
    verdict = event.get("verdict")
    if not isinstance(verdict, dict):
        _raise_malformed(
            "malformed_stream_verdict",
            "stream verdict event is missing an embedded verdict",
        )
    _validate_verdict(verdict)
    _validate_verdict_mirrors(
        event,
        verdict,
        "malformed_stream_verdict",
        "stream verdict event",
    )
    if event["response_integrity_result"] == "receipt_bound":
        _raise_malformed(
            "malformed_stream_verdict",
            "stream opening verdict must not report receipt-bound response integrity",
        )
    return event


def _validate_stream_receipt_event(event: dict[str, Any]) -> Any:
    receipt = event.get("receipt")
    if not isinstance(receipt, dict):
        _raise_malformed(
            "malformed_stream_receipt",
            "response_receipt event is missing receipt metadata",
        )
    _require_exact_fields(
        event,
        STREAM_RECEIPT_EVENT_FIELDS,
        "response_receipt event",
        "malformed_stream_receipt",
    )
    if event.get("response_integrity_result") != "receipt_bound":
        _raise_malformed(
            "malformed_stream_receipt",
            "response_receipt event must report receipt-bound response integrity",
        )
    if event.get("receipt_verified") is not True:
        _raise_malformed(
            "malformed_stream_receipt",
            "response_receipt event must set receipt_verified=true",
        )
    return event


def _validate_stream_response_event(event: dict[str, Any]) -> Any:
    if not isinstance(event.get("response"), dict):
        _raise_malformed(
            "malformed_stream_event",
            "stream response event must include response object",
        )
    _require_exact_fields(
        event,
        STREAM_RESPONSE_EVENT_FIELDS,
        "stream response event",
        "malformed_stream_event",
    )
    return event


def _validate_stream_terminal_event(event: dict[str, Any]) -> Any:
    _require_exact_fields(
        event,
        STREAM_TERMINAL_EVENT_FIELDS,
        "stream terminal event",
        "malformed_stream_event",
    )
    return event


def _validate_stream_error_event(event: dict[str, Any]) -> Any:
    _require_exact_fields(
        event,
        STREAM_ERROR_EVENT_FIELDS,
        "stream error event",
        "malformed_stream_event",
    )
    if event.get("status") != "failed":
        _raise_malformed(
            "malformed_stream_event",
            "stream error event status must be failed",
        )
    error = event.get("error")
    if not isinstance(error, dict):
        _raise_malformed(
            "malformed_stream_event",
            "stream error event must include error metadata",
        )
    _validate_required_string(
        error,
        "type",
        "stream error event error",
        "malformed_stream_event",
    )
    _validate_required_string(
        error,
        "message",
        "stream error event error",
        "malformed_stream_event",
    )
    return event


def _validate_verdict(verdict: Any) -> Any:
    if not isinstance(verdict, dict):
        _raise_malformed("malformed_verdict", "verdict must be a JSON object")
    _validate_schema_major(
        verdict,
        "schema",
        VERDICT_SCHEMA_PREFIX,
        "verdict schema",
    )
    _validate_schema_major(
        verdict,
        "policy_schema",
        POLICY_SCHEMA_PREFIX,
        "policy schema",
    )
    _validate_schema_major(
        verdict,
        "reference_values_schema",
        REFERENCE_VALUES_SCHEMA_PREFIX,
        "reference-values schema",
    )
    _validate_schema_major(
        verdict,
        "provider_registry_schema",
        PROVIDER_REGISTRY_SCHEMA_PREFIX,
        "provider-registry schema",
    )
    _validate_required_fields(
        verdict,
        VERDICT_KNOWN_FIELDS,
        "malformed_verdict_schema",
        "incompatible_verdict_schema",
        "verdict",
    )
    _validate_verdict_digest_fields(verdict)
    _validate_verdict_signature_fields(verdict)
    _validate_verdict_validity_fields(verdict)
    _validate_verdict_enum_fields(verdict)
    _validate_verdict_structured_fields(verdict)
    _validate_verdict_summary_consistency(verdict)
    return verdict


def _validate_operation_state(state: Any) -> Any:
    if not isinstance(state, dict):
        _raise_malformed(
            "malformed_operation_state",
            "operation state must be an object",
        )
    status = state.get("status")
    if not isinstance(status, str) or status not in OPERATION_STATUS_VALUES:
        choices = ", ".join(sorted(OPERATION_STATUS_VALUES))
        _raise_malformed(
            "malformed_operation_state",
            f"operation state status must be one of: {choices}",
        )
    fields = (
        OPERATION_STATE_FAILED_FIELDS
        if status == "failed"
        else OPERATION_STATE_BASE_FIELDS
    )
    _require_exact_fields(state, fields, "operation state", "malformed_operation_state")
    if status == "failed":
        if state.get("result_available") is not True:
            _raise_malformed(
                "malformed_operation_state",
                "failed operation state must have result_available=true",
            )
        if not isinstance(state.get("error"), dict):
            _raise_malformed(
                "malformed_operation_state",
                "failed operation state must include error metadata",
            )
    return state


def _validate_ffi_error_envelope(payload: Any) -> Any:
    if not isinstance(payload, dict):
        _raise_malformed("malformed_ffi_error", "FFI error envelope must be an object")
    _require_exact_fields(
        payload,
        FFI_ERROR_ENVELOPE_FIELDS,
        "FFI error envelope",
        "malformed_ffi_error",
    )
    error = payload["error"]
    if error is None:
        return payload
    if not isinstance(error, dict):
        _raise_malformed("malformed_ffi_error", "FFI error must be an object or null")
    _require_exact_fields(error, FFI_ERROR_FIELDS, "FFI error", "malformed_ffi_error")
    if error["type"] != "confidential_inference_ffi_error":
        _raise_malformed(
            "malformed_ffi_error",
            f"FFI error type has invalid value {error['type']}",
        )
    for field in ("code", "message"):
        if not isinstance(error[field], str) or len(error[field]) == 0:
            _raise_malformed(
                "malformed_ffi_error",
                f"FFI error {field} must be a non-empty string",
            )
    return payload


def _validate_ffi_status(payload: Any) -> Any:
    if not isinstance(payload, dict):
        _raise_malformed("malformed_ffi_status", "FFI status must be an object")
    _require_exact_fields(payload, FFI_STATUS_FIELDS, "FFI status", "malformed_ffi_status")
    for field in (
        "async_handle_abi_available",
        "callbacks_available",
        "readiness_fd_available",
        "stream_handle_abi_available",
        "blocking_helpers_available",
    ):
        if not isinstance(payload[field], bool):
            _raise_malformed(
                "malformed_ffi_status",
                f"FFI status {field} must be a boolean",
            )
    if not isinstance(payload["reason"], str) or len(payload["reason"]) == 0:
        _raise_malformed(
            "malformed_ffi_status",
            "FFI status reason must be a non-empty string",
        )
    return payload


def _validate_model_list(payload: Any) -> Any:
    if not isinstance(payload, dict):
        _raise_malformed(
            "malformed_model_discovery",
            "model discovery payload must be an object",
        )
    _require_exact_fields(
        payload,
        MODEL_LIST_FIELDS,
        "model discovery payload",
        "malformed_model_discovery",
    )
    if payload.get("object") != "list":
        _raise_malformed(
            "malformed_model_discovery",
            "model discovery payload object must be list",
        )
    data = payload.get("data")
    if not isinstance(data, list):
        _raise_malformed(
            "malformed_model_discovery",
            "model discovery payload data must be a list",
        )
    for index, model in enumerate(data):
        _validate_model_record(model, index)
    return payload


def _validate_model_record(model: Any, index: int) -> None:
    subject = f"model discovery payload data[{index}]"
    if not isinstance(model, dict):
        _raise_malformed("malformed_model_discovery", f"{subject} must be an object")
    _require_exact_fields(
        model,
        MODEL_RECORD_FIELDS,
        subject,
        "malformed_model_discovery",
    )
    _validate_required_string(model, "id", subject, "malformed_model_discovery")
    _validate_required_string(model, "owned_by", subject, "malformed_model_discovery")
    if model.get("object") != "model":
        _raise_malformed("malformed_model_discovery", f"{subject}.object must be model")


def _validate_confidential_models(payload: Any) -> Any:
    if not isinstance(payload, list):
        _raise_malformed(
            "malformed_confidential_catalog",
            "confidential catalog payload must be a list",
        )
    for index, model in enumerate(payload):
        _validate_confidential_model(model, index)
    return payload


def _validate_confidential_model(model: Any, index: int) -> None:
    subject = f"confidential catalog payload model[{index}]"
    if not isinstance(model, dict):
        _raise_malformed("malformed_confidential_catalog", f"{subject} must be an object")
    _require_exact_fields(
        model,
        CONFIDENTIAL_MODEL_FIELDS,
        subject,
        "malformed_confidential_catalog",
    )
    for field in ("canonical_model", "display_name", "family"):
        _validate_required_string(model, field, subject, "malformed_confidential_catalog")
    _validate_string_list(
        model.get("aliases"),
        f"{subject}.aliases",
        "malformed_confidential_catalog",
    )
    routes = model.get("routes")
    if not isinstance(routes, list) or not routes:
        _raise_malformed(
            "malformed_confidential_catalog",
            f"{subject}.routes must be a non-empty list",
        )
    for route_index, route in enumerate(routes):
        _validate_confidential_route(route, model["canonical_model"], route_index)


def _validate_confidential_route(route: Any, model_id: str, route_index: int) -> None:
    subject = f"confidential catalog payload model {model_id} route[{route_index}]"
    if not isinstance(route, dict):
        _raise_malformed("malformed_confidential_catalog", f"{subject} must be an object")
    _require_exact_fields(
        route,
        CONFIDENTIAL_ROUTE_FIELDS,
        subject,
        "malformed_confidential_catalog",
    )
    for field in (
        "route_id",
        "provider",
        "provider_model",
        "evidence_family",
        "api_endpoint",
        "evidence_endpoint",
        "adapter_version",
    ):
        _validate_required_string(route, field, subject, "malformed_confidential_catalog")
    _validate_catalog_choice(
        route,
        subject,
        "route_execution_status",
        CATALOG_ROUTE_EXECUTION_STATUS_VALUES,
    )
    trust_tier = _validate_catalog_choice(route, subject, "trust_tier", TRUST_TIER_VALUES)
    channel_binding_kind = _validate_catalog_choice(
        route,
        subject,
        "channel_binding_kind",
        CHANNEL_BINDING_KIND_VALUES,
    )
    _validate_catalog_choice(
        route,
        subject,
        "request_encryption",
        REGISTRY_ENCRYPTION_REQUIREMENT_VALUES,
    )
    _validate_catalog_choice(
        route,
        subject,
        "response_decryption",
        REGISTRY_ENCRYPTION_REQUIREMENT_VALUES,
    )
    _validate_catalog_choice(route, subject, "alias_confidence", ALIAS_CONFIDENCE_VALUES)
    _validate_bool_field_for_subject(
        route,
        "chat_executable",
        subject,
        "malformed_confidential_catalog",
    )
    _validate_bool_field_for_subject(
        route,
        "streaming_allowed",
        subject,
        "malformed_confidential_catalog",
    )
    _validate_string_list(
        route.get("known_unsupported_modes"),
        f"{subject}.known_unsupported_modes",
        "malformed_confidential_catalog",
    )
    _validate_trust_tier_channel_binding_pair(
        trust_tier,
        channel_binding_kind,
        subject,
        "malformed_confidential_catalog",
    )


def _validate_catalog_choice(
    route: dict[str, Any],
    subject: str,
    field: str,
    allowed: set[str],
) -> str:
    value = route.get(field)
    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        _raise_malformed(
            "malformed_confidential_catalog",
            f"{subject}.{field} must be one of: {choices}",
        )
    return value


def _validate_required_string(
    payload: dict[str, Any],
    field: str,
    subject: str,
    code: str,
) -> None:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        _raise_malformed(code, f"{subject}.{field} must be a non-empty string")


def _validate_string_list(value: Any, subject: str, code: str) -> None:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        _raise_malformed(code, f"{subject} must contain non-empty strings")


def _validate_bool_field_for_subject(
    payload: dict[str, Any],
    field: str,
    subject: str,
    code: str,
) -> None:
    if not isinstance(payload.get(field), bool):
        _raise_malformed(code, f"{subject}.{field} must be a boolean")


def _validate_trust_tier_channel_binding_pair(
    trust_tier: str,
    channel_binding_kind: str,
    subject: str,
    code: str,
) -> None:
    if trust_tier == "app-e2ee" and channel_binding_kind != "attested_app_e2ee":
        _raise_malformed(
            code,
            f"{subject} trust_tier=app-e2ee requires channel_binding_kind=attested_app_e2ee",
        )
    if trust_tier == "hw-verified-tls" and channel_binding_kind != "tee_terminated_tls":
        _raise_malformed(
            code,
            f"{subject} trust_tier=hw-verified-tls requires channel_binding_kind=tee_terminated_tls",
        )


def _validate_active_policy_snapshot(snapshot: Any) -> Any:
    if not isinstance(snapshot, dict):
        _raise_malformed(
            "malformed_active_policy",
            "active policy snapshot must be a JSON object",
        )
    _validate_schema_major(
        snapshot,
        "schema",
        ACTIVE_POLICY_SCHEMA_PREFIX,
        "active-policy schema",
        error_code="malformed_active_policy_schema",
        incompatible_code="incompatible_active_policy_schema",
        subject="active policy snapshot",
    )
    _validate_required_fields(
        snapshot,
        ACTIVE_POLICY_SNAPSHOT_KNOWN_FIELDS,
        "malformed_active_policy_schema",
        "incompatible_active_policy_schema",
        "active policy snapshot",
    )
    policy = snapshot.get("policy")
    if not isinstance(policy, dict):
        _raise_malformed(
            "malformed_active_policy",
            "active policy snapshot is missing policy",
        )
    _validate_schema_major(
        policy,
        "schema",
        POLICY_SCHEMA_PREFIX,
        "policy schema",
        error_code="malformed_active_policy_schema",
        incompatible_code="incompatible_active_policy_schema",
        subject="active policy payload",
    )
    _validate_required_fields(
        policy,
        POLICY_KNOWN_FIELDS,
        "malformed_active_policy_schema",
        "incompatible_active_policy_schema",
        "active policy payload",
    )
    _validate_sha256_digest_field(
        snapshot,
        "policy_digest",
        "malformed_active_policy_digest",
        "active policy snapshot",
    )
    _validate_sha256_digest_field(
        policy,
        "provider_registry_digest",
        "malformed_active_policy_digest",
        "active policy payload",
    )
    _validate_sha256_digest_field(
        policy,
        "reference_values_digest",
        "malformed_active_policy_digest",
        "active policy payload",
    )
    _validate_policy_schema_fields(policy)
    _validate_policy_millis_fields(policy)
    _validate_canonical_payload_digest(
        policy,
        snapshot["policy_digest"],
        "policy_digest",
        "active policy snapshot",
        "malformed_active_policy_digest",
    )
    return snapshot


def _validate_active_trust_artifacts(artifacts: Any) -> Any:
    if not isinstance(artifacts, dict):
        _raise_malformed(
            "malformed_trust_artifacts",
            "active trust artifacts must be a JSON object",
        )
    registry = artifacts.get("registry")
    if not isinstance(registry, dict):
        _raise_malformed(
            "malformed_trust_artifacts",
            "active trust artifacts are missing registry",
        )
    _validate_schema_major(
        registry,
        "schema",
        PROVIDER_REGISTRY_SCHEMA_PREFIX,
        "provider-registry schema",
        error_code="malformed_trust_artifacts_schema",
        incompatible_code="incompatible_trust_artifacts_schema",
        subject="active registry payload",
    )
    _validate_required_fields(
        artifacts,
        TRUST_ARTIFACTS_KNOWN_FIELDS,
        "malformed_trust_artifacts_schema",
        "incompatible_trust_artifacts_schema",
        "active trust artifacts",
    )
    _validate_required_fields(
        registry,
        REGISTRY_PAYLOAD_KNOWN_FIELDS,
        "malformed_trust_artifacts_schema",
        "incompatible_trust_artifacts_schema",
        "active registry payload",
    )

    reference_values = artifacts.get("reference_values")
    if not isinstance(reference_values, dict):
        _raise_malformed(
            "malformed_trust_artifacts",
            "active trust artifacts are missing reference_values",
        )
    _validate_schema_major(
        reference_values,
        "schema",
        REFERENCE_VALUES_SCHEMA_PREFIX,
        "reference-values schema",
        error_code="malformed_trust_artifacts_schema",
        incompatible_code="incompatible_trust_artifacts_schema",
        subject="active reference-values payload",
    )
    _validate_required_fields(
        reference_values,
        REFERENCE_VALUES_PAYLOAD_KNOWN_FIELDS,
        "malformed_trust_artifacts_schema",
        "incompatible_trust_artifacts_schema",
        "active reference-values payload",
    )
    _validate_sha256_digest_field(
        artifacts,
        "registry_digest",
        "malformed_trust_artifacts_digest",
        "active trust artifacts",
    )
    _validate_sha256_digest_field(
        artifacts,
        "reference_values_digest",
        "malformed_trust_artifacts_digest",
        "active trust artifacts",
    )
    _validate_signature_fields(
        artifacts,
        ("registry_signature", "reference_values_signature"),
        "malformed_trust_artifacts_signature",
        "active trust artifacts",
        require_value=True,
    )
    _validate_active_trust_artifact_metadata(registry, reference_values)
    _validate_canonical_payload_digest(
        registry,
        artifacts["registry_digest"],
        "registry_digest",
        "active trust artifacts",
        "malformed_trust_artifacts_digest",
    )
    _validate_canonical_payload_digest(
        reference_values,
        artifacts["reference_values_digest"],
        "reference_values_digest",
        "active trust artifacts",
        "malformed_trust_artifacts_digest",
    )
    _verify_known_artifact_signature(
        artifacts["registry_signature"],
        registry,
        "registry_signature",
    )
    _verify_known_artifact_signature(
        artifacts["reference_values_signature"],
        reference_values,
        "reference_values_signature",
    )
    return artifacts


def _validate_canonical_payload_digest(
    payload: dict[str, Any],
    expected_digest: str,
    field: str,
    subject: str,
    code: str,
) -> None:
    actual_digest = canonical_sha256_digest(payload)
    if actual_digest != expected_digest:
        _raise_malformed(
            code,
            f"{subject} {field} must match the canonical payload digest",
        )


def _validate_schema_major(
    payload: dict[str, Any],
    field: str,
    prefix: str,
    label: str,
    error_code: str = "malformed_verdict_schema",
    incompatible_code: str = "incompatible_verdict_schema",
    subject: str = "verdict",
) -> None:
    schema = payload.get(field)
    if not isinstance(schema, str):
        _raise_malformed(error_code, f"{subject} is missing {field}")

    marker = f"{prefix}.v"
    if not schema.startswith(marker):
        _raise_malformed(
            error_code,
            f"{subject} {label} is not a Confidential Inference schema",
        )
    version_text = schema[len(marker) :]
    major_text = version_text.split(".", 1)[0]
    if not major_text.isdigit():
        _raise_malformed(
            error_code,
            f"{subject} {label} has a malformed major version",
        )
    major = int(major_text)
    if major != SUPPORTED_SCHEMA_MAJOR:
        _raise_malformed(
            incompatible_code,
            f"{subject} {label} major version {major} is not supported",
        )


def _validate_required_fields(
    payload: dict[str, Any],
    known_fields: set[str],
    error_code: str,
    incompatible_code: str,
    subject: str,
) -> None:
    required = payload.get("required")
    if required is None:
        return
    if (
        not isinstance(required, list)
        or any(not isinstance(field, str) or not field for field in required)
    ):
        _raise_malformed(
            error_code,
            f"{subject} required list must contain non-empty field names",
        )
    for field in required:
        if field not in known_fields:
            _raise_malformed(
                incompatible_code,
                f"{subject} declares unsupported required field {field}",
            )
        if field not in payload:
            _raise_malformed(
                error_code,
                f"{subject} is missing declared required field {field}",
            )


def _validate_policy_millis_fields(policy: dict[str, Any]) -> None:
    if "verdict_ttl_millis" in policy:
        _validate_safe_millis(
            policy["verdict_ttl_millis"],
            "verdict_ttl_millis",
            "active policy payload",
        )

    freshness = policy.get("freshness")
    if isinstance(freshness, dict) and freshness.get("mode") == "allow_cached_binding_millis":
        if "millis" not in freshness:
            _raise_malformed(
                "malformed_active_policy_schema",
                "active policy payload freshness.millis is required",
            )
        _validate_safe_millis(
            freshness["millis"],
            "freshness.millis",
            "active policy payload",
        )

    stale_verdicts = policy.get("stale_verdicts")
    if isinstance(stale_verdicts, dict) and stale_verdicts.get("mode") == "allow_for_millis":
        if "millis" not in stale_verdicts:
            _raise_malformed(
                "malformed_active_policy_schema",
                "active policy payload stale_verdicts.millis is required",
            )
        _validate_safe_millis(
            stale_verdicts["millis"],
            "stale_verdicts.millis",
            "active policy payload",
        )


def _validate_policy_schema_fields(policy: dict[str, Any]) -> None:
    _validate_policy_choice_field(policy, "enforcement", ENFORCEMENT_VALUES)
    _validate_policy_choice_field(
        policy,
        "channel_binding_requirement",
        POLICY_CHANNEL_BINDING_REQUIREMENT_VALUES,
    )
    _validate_policy_choice_field(
        policy,
        "request_confidentiality_requirement",
        POLICY_BOUND_DATA_REQUIREMENT_VALUES,
    )
    _validate_policy_choice_field(
        policy,
        "response_confidentiality_requirement",
        POLICY_BOUND_DATA_REQUIREMENT_VALUES,
    )
    _validate_policy_choice_field(
        policy,
        "response_integrity_requirement",
        POLICY_RESPONSE_INTEGRITY_REQUIREMENT_VALUES,
    )
    _validate_policy_choice_field(
        policy,
        "model_binding_requirement",
        POLICY_MODEL_BINDING_REQUIREMENT_VALUES,
    )
    _validate_policy_hardware(policy)
    _validate_policy_provenance(policy)
    _validate_policy_freshness(policy)
    _validate_policy_stale_verdicts(policy)


def _validate_policy_choice_field(
    policy: dict[str, Any],
    field: str,
    allowed: set[str],
) -> None:
    value = policy.get(field)
    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        _raise_malformed(
            "malformed_active_policy_schema",
            f"active policy payload {field} must be one of: {choices}",
        )


def _validate_policy_hardware(policy: dict[str, Any]) -> None:
    hardware = policy.get("hardware")
    if not isinstance(hardware, dict):
        _raise_malformed(
            "malformed_active_policy_schema",
            "active policy payload hardware must be an object",
        )
    _validate_policy_tee_requirement(
        hardware.get("cpu"),
        "hardware.cpu",
        POLICY_CPU_TEE_MODES,
        POLICY_CPU_TEE_KINDS,
    )
    _validate_policy_tee_requirement(
        hardware.get("gpu"),
        "hardware.gpu",
        POLICY_GPU_TEE_MODES,
        POLICY_GPU_TEE_KINDS,
    )


def _validate_policy_tee_requirement(
    payload: Any,
    field: str,
    modes: set[str],
    allowed_values: set[str],
) -> None:
    if not isinstance(payload, dict):
        _raise_malformed(
            "malformed_active_policy_schema",
            f"active policy payload {field} must be an object",
        )
    mode = payload.get("mode")
    if mode not in modes:
        choices = ", ".join(sorted(modes))
        _raise_malformed(
            "malformed_active_policy_schema",
            f"active policy payload {field}.mode must be one of: {choices}",
        )
    if mode != "one_of":
        if "allowed" in payload:
            _raise_malformed(
                "malformed_active_policy_schema",
                f"active policy payload {field}.allowed is valid only for one_of",
            )
        return

    allowed = payload.get("allowed")
    if not isinstance(allowed, list) or not allowed:
        _raise_malformed(
            "malformed_active_policy_schema",
            f"active policy payload {field}.allowed must be a non-empty list",
        )
    if any(not isinstance(value, str) or value not in allowed_values for value in allowed):
        choices = ", ".join(sorted(allowed_values))
        _raise_malformed(
            "malformed_active_policy_schema",
            f"active policy payload {field}.allowed values must be one of: {choices}",
        )
    if allowed != sorted(set(allowed)):
        _raise_malformed(
            "malformed_active_policy_schema",
            f"active policy payload {field}.allowed must be sorted and unique",
        )


def _validate_policy_provenance(policy: dict[str, Any]) -> None:
    provenance = policy.get("provenance")
    if not isinstance(provenance, dict):
        _raise_malformed(
            "malformed_active_policy_schema",
            "active policy payload provenance must be an object",
        )
    for field in sorted(POLICY_PROVENANCE_FIELDS):
        value = provenance.get(field)
        if not isinstance(value, bool):
            _raise_malformed(
                "malformed_active_policy_schema",
                f"active policy payload provenance.{field} must be a boolean",
            )


def _validate_policy_freshness(policy: dict[str, Any]) -> None:
    freshness = policy.get("freshness")
    if not isinstance(freshness, dict):
        _raise_malformed(
            "malformed_active_policy_schema",
            "active policy payload freshness must be an object",
        )
    mode = freshness.get("mode")
    if mode not in POLICY_FRESHNESS_MODES:
        choices = ", ".join(sorted(POLICY_FRESHNESS_MODES))
        _raise_malformed(
            "malformed_active_policy_schema",
            f"active policy payload freshness.mode must be one of: {choices}",
        )
    if mode != "allow_cached_binding_millis" and "millis" in freshness:
        _raise_malformed(
            "malformed_active_policy_schema",
            "active policy payload freshness.millis is valid only for allow_cached_binding_millis",
        )


def _validate_policy_stale_verdicts(policy: dict[str, Any]) -> None:
    stale_verdicts = policy.get("stale_verdicts")
    if not isinstance(stale_verdicts, dict):
        _raise_malformed(
            "malformed_active_policy_schema",
            "active policy payload stale_verdicts must be an object",
        )
    mode = stale_verdicts.get("mode")
    if mode not in POLICY_STALE_VERDICT_MODES:
        choices = ", ".join(sorted(POLICY_STALE_VERDICT_MODES))
        _raise_malformed(
            "malformed_active_policy_schema",
            f"active policy payload stale_verdicts.mode must be one of: {choices}",
        )
    if mode != "allow_for_millis" and "millis" in stale_verdicts:
        _raise_malformed(
            "malformed_active_policy_schema",
            "active policy payload stale_verdicts.millis is valid only for allow_for_millis",
        )


def _validate_safe_millis(value: Any, field: str, subject: str) -> None:
    _validate_safe_json_int(
        value,
        field,
        subject,
        "malformed_active_policy_schema",
        "millisecond value",
    )


def _validate_safe_json_int(
    value: Any,
    field: str,
    subject: str,
    code: str,
    label: str = "integer",
) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _raise_malformed(
            code,
            f"{subject} {field} must be a non-negative {label}",
        )
    if value > MAX_SAFE_JSON_INT:
        _raise_malformed(
            code,
            f"{subject} {field} exceeds the cross-language JSON safe integer limit",
        )


def _validate_active_trust_artifact_metadata(
    registry: dict[str, Any],
    reference_values: dict[str, Any],
) -> None:
    if "generated_at" in registry:
        _parse_utc_epoch_ms(
            _required_timestamp_field(
                registry,
                "generated_at",
                "active registry payload",
                "malformed_trust_artifacts_schema",
            ),
            "active registry payload generated_at",
            "malformed_trust_artifacts_schema",
        )

    source_sync_run = registry.get("source_sync_run")
    if source_sync_run is not None:
        if not isinstance(source_sync_run, dict):
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                "active registry payload source_sync_run must be an object",
            )
        if "completed_at" in source_sync_run:
            _parse_utc_epoch_ms(
                _required_timestamp_field(
                    source_sync_run,
                    "completed_at",
                    "active registry payload source_sync_run",
                    "malformed_trust_artifacts_schema",
                ),
                "active registry payload source_sync_run.completed_at",
                "malformed_trust_artifacts_schema",
            )

    if "valid_from" in reference_values:
        _parse_utc_epoch_ms(
            _required_timestamp_field(
                reference_values,
                "valid_from",
                "active reference-values payload",
                "malformed_trust_artifacts_schema",
            ),
            "active reference-values payload valid_from",
            "malformed_trust_artifacts_schema",
        )
    parsed_valid_until = None
    if "valid_until" in reference_values:
        parsed_valid_until = _parse_utc_epoch_ms(
            _required_timestamp_field(
                reference_values,
                "valid_until",
                "active reference-values payload",
                "malformed_trust_artifacts_schema",
            ),
            "active reference-values payload valid_until",
            "malformed_trust_artifacts_schema",
        )
    if "valid_until_epoch_ms" in reference_values:
        valid_until_epoch_ms = reference_values["valid_until_epoch_ms"]
        _validate_safe_json_int(
            valid_until_epoch_ms,
            "valid_until_epoch_ms",
            "active reference-values payload",
            "malformed_trust_artifacts_schema",
            "integer millisecond epoch",
        )
        if parsed_valid_until is not None and valid_until_epoch_ms != parsed_valid_until:
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                "active reference-values payload valid_until_epoch_ms must match valid_until",
            )
    if "revocation_epoch" in reference_values:
        _validate_safe_json_int(
            reference_values["revocation_epoch"],
            "revocation_epoch",
            "active reference-values payload",
            "malformed_trust_artifacts_schema",
        )
    _validate_active_registry_models(registry)
    _validate_active_reference_values_providers(reference_values)


def _validate_active_registry_models(registry: dict[str, Any]) -> None:
    models = registry.get("models")
    if models is None:
        return
    if not isinstance(models, dict):
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            "active registry payload models must be an object",
        )
    for model_id, model in models.items():
        if not isinstance(model_id, str) or not model_id:
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                "active registry payload model keys must be non-empty strings",
            )
        if not isinstance(model, dict):
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                f"active registry payload model {model_id} must be an object",
            )
        canonical_model = model.get("canonical_model")
        if canonical_model != model_id:
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                f"active registry payload model {model_id} canonical_model must match model key",
            )
        aliases = model.get("aliases")
        if aliases is not None and (
            not isinstance(aliases, list)
            or any(not isinstance(alias, str) or not alias for alias in aliases)
        ):
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                f"active registry payload model {model_id} aliases must be non-empty strings",
            )
        routes = model.get("routes")
        if routes is None:
            return
        if not isinstance(routes, list):
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                f"active registry payload model {model_id} routes must be a list",
            )
        for index, route in enumerate(routes):
            _validate_active_registry_route(model_id, index, route)


def _validate_active_registry_route(model_id: str, index: int, route: Any) -> None:
    subject = f"active registry payload model {model_id} route[{index}]"
    if not isinstance(route, dict):
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject} must be an object",
        )
    for field in (
        "route_id",
        "provider",
        "provider_model",
        "evidence_family",
        "api_base_url",
        "evidence_endpoint",
        "adapter_version",
    ):
        value = route.get(field)
        if not isinstance(value, str) or not value:
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                f"{subject}.{field} must be a non-empty string",
            )

    route_status = _validate_registry_route_choice(
        route,
        subject,
        "route_status",
        REGISTRY_ROUTE_STATUS_VALUES,
    )
    alias_confidence = _validate_registry_route_choice(
        route,
        subject,
        "alias_confidence",
        ALIAS_CONFIDENCE_VALUES,
    )
    _validate_registry_route_choice(route, subject, "freshness_class", FRESHNESS_CLASS_VALUES)
    channel_binding_kind = _validate_registry_route_choice(
        route,
        subject,
        "channel_binding_kind",
        CHANNEL_BINDING_KIND_VALUES,
    )
    trust_tier = _validate_registry_route_choice(
        route,
        subject,
        "trust_tier",
        TRUST_TIER_VALUES,
    )
    _validate_registry_route_choice(
        route,
        subject,
        "request_confidentiality_requirement",
        POLICY_BOUND_DATA_REQUIREMENT_VALUES,
    )
    _validate_registry_route_choice(
        route,
        subject,
        "response_confidentiality_requirement",
        POLICY_BOUND_DATA_REQUIREMENT_VALUES,
    )
    _validate_registry_route_choice(
        route,
        subject,
        "response_integrity_requirement",
        POLICY_RESPONSE_INTEGRITY_REQUIREMENT_VALUES,
    )
    _validate_registry_route_choice(
        route,
        subject,
        "request_encryption",
        REGISTRY_ENCRYPTION_REQUIREMENT_VALUES,
    )
    _validate_registry_route_choice(
        route,
        subject,
        "response_decryption",
        REGISTRY_ENCRYPTION_REQUIREMENT_VALUES,
    )
    _validate_registry_route_choice(route, subject, "streaming", REGISTRY_STREAMING_VALUES)

    accepted_gpu_tees = route.get("accepted_gpu_tees")
    if accepted_gpu_tees is not None:
        if not isinstance(accepted_gpu_tees, list) or any(
            not isinstance(value, str) or value not in POLICY_GPU_TEE_KINDS
            for value in accepted_gpu_tees
        ):
            choices = ", ".join(sorted(POLICY_GPU_TEE_KINDS))
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                f"{subject}.accepted_gpu_tees values must be one of: {choices}",
            )

    if route_status == "active" and alias_confidence == "algorithmic":
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject}.alias_confidence active routes must not use algorithmic aliases",
        )
    if trust_tier == "app-e2ee" and channel_binding_kind != "attested_app_e2ee":
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject} trust_tier=app-e2ee requires channel_binding_kind=attested_app_e2ee",
        )
    if trust_tier == "hw-verified-tls" and channel_binding_kind != "tee_terminated_tls":
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject} trust_tier=hw-verified-tls requires channel_binding_kind=tee_terminated_tls",
        )


def _validate_registry_route_choice(
    route: dict[str, Any],
    subject: str,
    field: str,
    allowed: set[str],
) -> str:
    value = route.get(field)
    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject}.{field} must be one of: {choices}",
        )
    return value


def _validate_active_reference_values_providers(
    reference_values: dict[str, Any],
) -> None:
    providers = reference_values.get("providers")
    if providers is None:
        return
    if not isinstance(providers, dict):
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            "active reference-values payload providers must be an object",
        )
    for provider_id, provider in providers.items():
        if not isinstance(provider_id, str) or not provider_id:
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                "active reference-values payload provider keys must be non-empty strings",
            )
        subject = f"active reference-values payload provider {provider_id}"
        if not isinstance(provider, dict):
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                f"{subject} must be an object",
            )
        _validate_non_empty_string_list(
            provider.get("accepted_measurements"),
            subject,
            "accepted_measurements",
        )
        routes = provider.get("routes")
        if not isinstance(routes, dict):
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                f"{subject}.routes must be an object",
            )
        for route_id, route in routes.items():
            if not isinstance(route_id, str) or not route_id:
                _raise_malformed(
                    "malformed_trust_artifacts_schema",
                    f"{subject}.routes keys must be non-empty strings",
                )
            _validate_active_reference_values_route(provider_id, route_id, route)


def _validate_active_reference_values_route(
    provider_id: str,
    route_id: str,
    route: Any,
) -> None:
    subject = f"active reference-values payload provider {provider_id} route {route_id}"
    if not isinstance(route, dict):
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject} must be an object",
        )
    for field in (
        "canonical_model",
        "provider_model",
        "evidence_family",
        "e2ee_public_key_digest",
        "workload_image_digest",
    ):
        _validate_non_empty_string_field(route, field, subject)

    channel_binding_kind = _validate_registry_route_choice(
        route,
        subject,
        "channel_binding_kind",
        CHANNEL_BINDING_KIND_VALUES,
    )
    trust_tier = _validate_registry_route_choice(route, subject, "trust_tier", TRUST_TIER_VALUES)
    _validate_reference_values_tee_list(
        route,
        subject,
        "accepted_cpu_tees",
        POLICY_CPU_TEE_KINDS,
    )
    if "accepted_gpu_tees" in route:
        _validate_reference_values_tee_list(
            route,
            subject,
            "accepted_gpu_tees",
            POLICY_GPU_TEE_KINDS,
        )

    for field in (
        "e2ee_public_key_digest",
        "response_signing_key_digest",
        "tls_spki_sha256",
        "workload_image_digest",
    ):
        if field in route:
            _validate_sha256_reference_field(route, field, subject)

    model_artifacts = route.get("model_artifacts")
    if not isinstance(model_artifacts, list) or not model_artifacts:
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject}.model_artifacts must be a non-empty list",
        )
    for index, artifact in enumerate(model_artifacts):
        artifact_subject = f"{subject}.model_artifacts[{index}]"
        if not isinstance(artifact, dict):
            _raise_malformed(
                "malformed_trust_artifacts_schema",
                f"{artifact_subject} must be an object",
            )
        for field in ("kind", "name"):
            _validate_non_empty_string_field(artifact, field, artifact_subject)
        _validate_sha256_reference_field(artifact, "digest", artifact_subject)

    parsed_valid_until = _parse_utc_epoch_ms(
        _required_timestamp_field(
            route,
            "valid_until",
            subject,
            "malformed_trust_artifacts_schema",
        ),
        f"{subject}.valid_until",
        "malformed_trust_artifacts_schema",
    )
    valid_until_epoch_ms = route.get("valid_until_epoch_ms")
    _validate_safe_json_int(
        valid_until_epoch_ms,
        "valid_until_epoch_ms",
        subject,
        "malformed_trust_artifacts_schema",
        "integer millisecond epoch",
    )
    if valid_until_epoch_ms != parsed_valid_until:
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject}.valid_until_epoch_ms must match valid_until",
        )

    if trust_tier == "app-e2ee" and channel_binding_kind != "attested_app_e2ee":
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject} trust_tier=app-e2ee requires channel_binding_kind=attested_app_e2ee",
        )
    if trust_tier == "hw-verified-tls" and channel_binding_kind != "tee_terminated_tls":
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject} trust_tier=hw-verified-tls requires channel_binding_kind=tee_terminated_tls",
        )


def _validate_non_empty_string_field(
    payload: dict[str, Any],
    field: str,
    subject: str,
) -> None:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject}.{field} must be a non-empty string",
        )


def _validate_non_empty_string_list(
    value: Any,
    subject: str,
    field: str,
) -> None:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject}.{field} must be a non-empty list of strings",
        )


def _validate_reference_values_tee_list(
    route: dict[str, Any],
    subject: str,
    field: str,
    allowed: set[str],
) -> None:
    values = route.get(field)
    if (
        not isinstance(values, list)
        or not values
        or any(not isinstance(value, str) or value not in allowed for value in values)
    ):
        choices = ", ".join(sorted(allowed))
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject}.{field} values must be one of: {choices}",
        )


def _validate_sha256_reference_field(
    payload: dict[str, Any],
    field: str,
    subject: str,
) -> None:
    value = payload.get(field)
    if (
        not isinstance(value, str)
        or not value.startswith(SHA256_DIGEST_PREFIX)
        or len(value) == len(SHA256_DIGEST_PREFIX)
    ):
        _raise_malformed(
            "malformed_trust_artifacts_schema",
            f"{subject}.{field} must be a sha256-prefixed reference",
        )


def _validate_sha256_digest_field(
    payload: dict[str, Any],
    field: str,
    code: str,
    subject: str,
) -> None:
    digest = payload.get(field)
    if not isinstance(digest, str):
        _raise_malformed(code, f"{subject} is missing {field}")
    digest_hex = digest[len(SHA256_DIGEST_PREFIX) :]
    if (
        not digest.startswith(SHA256_DIGEST_PREFIX)
        or len(digest_hex) != SHA256_DIGEST_HEX_LEN
        or any(ch not in SHA256_DIGEST_HEX for ch in digest_hex)
    ):
        _raise_malformed(
            code,
            f"{subject} {field} must be a canonical sha256 digest",
        )


def _validate_verdict_digest_fields(verdict: dict[str, Any]) -> None:
    for field in (
        "policy_digest",
        "provider_registry_digest",
        "reference_values_digest",
        "raw_evidence_digest",
        "evidence_digest",
    ):
        _validate_sha256_digest_field(
            verdict,
            field,
            "malformed_verdict_digest",
            "verdict",
        )


def _validate_signature_fields(
    payload: dict[str, Any],
    fields: tuple[str, ...],
    code: str,
    subject: str,
    require_value: bool = False,
) -> None:
    for field in fields:
        signature = payload.get(field)
        if not isinstance(signature, dict):
            _raise_malformed(code, f"{subject} is missing {field}")
        signer = signature.get("signer")
        key_id = signature.get("key_id")
        alg = signature.get("alg")
        if not isinstance(signer, str) or not signer:
            _raise_malformed(code, f"{field} metadata is incomplete")
        if not isinstance(key_id, str) or not key_id:
            _raise_malformed(code, f"{field} metadata is incomplete")
        if alg != "ed25519":
            _raise_malformed(
                code,
                f"{field} uses unsupported signature algorithm {alg}",
            )
        if require_value:
            value = signature.get("value")
            if (
                not isinstance(value, str)
                or not value.startswith(BASE64URL_SIGNATURE_PREFIX)
                or len(value) == len(BASE64URL_SIGNATURE_PREFIX)
            ):
                _raise_malformed(code, f"{field} signature value is incomplete")
            _validate_base64url_ed25519_signature_value(value, field, code)


def _validate_base64url_ed25519_signature_value(
    value: str,
    field: str,
    code: str,
) -> bytes:
    return _decode_unpadded_base64url(
        value,
        field,
        code,
        expected_len=ED25519_SIGNATURE_BYTE_LEN,
    )


def _decode_unpadded_base64url(
    value: str,
    field: str,
    code: str,
    *,
    expected_len: int,
) -> bytes:
    encoded = (
        value[len(BASE64URL_SIGNATURE_PREFIX) :]
        if value.startswith(BASE64URL_SIGNATURE_PREFIX)
        else value
    )
    if (
        "=" in encoded
        or any(character not in BASE64URL_NO_PAD_ALPHABET for character in encoded)
        or len(encoded) % 4 == 1
    ):
        _raise_malformed(
            code,
            f"{field} signature value must be unpadded base64url",
        )
    padded = encoded + ("=" * ((4 - len(encoded) % 4) % 4))
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except binascii.Error as error:
        _raise_malformed(
            code,
            f"{field} signature value must be unpadded base64url: {error}",
        )
    if len(decoded) != expected_len:
        label = (
            "Ed25519 signature"
            if expected_len == ED25519_SIGNATURE_BYTE_LEN
            else "Ed25519 value"
        )
        _raise_malformed(
            code,
            f"{field} signature value must decode to a {expected_len}-byte {label}",
        )
    return decoded


def _verify_known_artifact_signature(
    signature: dict[str, Any],
    payload: dict[str, Any],
    field: str,
) -> None:
    public_key_base64url = TRUSTED_ARTIFACT_SIGNING_KEYS.get(
        (signature["signer"], signature["key_id"])
    )
    if public_key_base64url is None:
        return

    signature_bytes = _decode_unpadded_base64url(
        signature["value"],
        field,
        "malformed_trust_artifacts_signature",
        expected_len=ED25519_SIGNATURE_BYTE_LEN,
    )
    public_key = _decode_unpadded_base64url(
        public_key_base64url,
        f"{field} trusted public key",
        "malformed_trust_artifacts_signature",
        expected_len=ED25519_PUBLIC_KEY_BYTE_LEN,
    )
    message = canonical_json(payload).encode("utf-8")
    if not _ed25519_verify(signature_bytes, public_key, message):
        _raise_malformed(
            "malformed_trust_artifacts_signature",
            f"{field} signature is invalid",
        )


def _ed25519_verify(signature: bytes, public_key: bytes, message: bytes) -> bool:
    if len(signature) != ED25519_SIGNATURE_BYTE_LEN:
        return False
    if len(public_key) != ED25519_PUBLIC_KEY_BYTE_LEN:
        return False

    try:
        encoded_r = signature[:32]
        r = _ed25519_decode_point(encoded_r)
        a = _ed25519_decode_point(public_key)
    except ValueError:
        return False

    s = int.from_bytes(signature[32:], "little")
    if s >= ED25519_Q:
        return False

    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(),
        "little",
    ) % ED25519_Q
    left = _ed25519_scalar_mult(ED25519_BASE_POINT, s)
    right = _ed25519_point_add(r, _ed25519_scalar_mult(a, challenge))
    return _ed25519_points_equal(left, right)


def _ed25519_decode_point(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != ED25519_PUBLIC_KEY_BYTE_LEN:
        raise ValueError("ed25519 point must be 32 bytes")
    compressed = int.from_bytes(encoded, "little")
    y = compressed & ((1 << 255) - 1)
    sign = compressed >> 255
    if y >= ED25519_P:
        raise ValueError("ed25519 point y-coordinate is not canonical")

    yy = (y * y) % ED25519_P
    xx = ((yy - 1) * pow(ED25519_D * yy + 1, ED25519_P - 2, ED25519_P)) % ED25519_P
    if xx == 0:
        if sign:
            raise ValueError("ed25519 point has invalid sign bit")
        x = 0
    else:
        x = pow(xx, (ED25519_P + 3) // 8, ED25519_P)
        if (x * x - xx) % ED25519_P != 0:
            x = (x * ED25519_I) % ED25519_P
        if (x * x - xx) % ED25519_P != 0:
            raise ValueError("ed25519 point is not on the curve")
        if (x & 1) != sign:
            x = ED25519_P - x

    if not _ed25519_is_on_curve(x, y):
        raise ValueError("ed25519 point is not on the curve")
    return (x, y, 1, (x * y) % ED25519_P)


def _ed25519_is_on_curve(x: int, y: int) -> bool:
    xx = (x * x) % ED25519_P
    yy = (y * y) % ED25519_P
    return (yy - xx - 1 - ED25519_D * xx * yy) % ED25519_P == 0


def _ed25519_point_add(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % ED25519_P
    b = ((y1 + x1) * (y2 + x2)) % ED25519_P
    c = (2 * ED25519_D * t1 * t2) % ED25519_P
    d = (2 * z1 * z2) % ED25519_P
    e = (b - a) % ED25519_P
    f = (d - c) % ED25519_P
    g = (d + c) % ED25519_P
    h = (b + a) % ED25519_P
    return (
        (e * f) % ED25519_P,
        (g * h) % ED25519_P,
        (f * g) % ED25519_P,
        (e * h) % ED25519_P,
    )


def _ed25519_scalar_mult(
    point: tuple[int, int, int, int],
    scalar: int,
) -> tuple[int, int, int, int]:
    result = ED25519_IDENTITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _ed25519_point_add(result, addend)
        addend = _ed25519_point_add(addend, addend)
        scalar >>= 1
    return result


def _ed25519_points_equal(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> bool:
    x1, y1, z1, _ = left
    x2, y2, z2, _ = right
    return (x1 * z2 - x2 * z1) % ED25519_P == 0 and (
        y1 * z2 - y2 * z1
    ) % ED25519_P == 0


def _validate_verdict_signature_fields(verdict: dict[str, Any]) -> None:
    _validate_signature_fields(
        verdict,
        ("registry_signature", "reference_values_signature"),
        "malformed_verdict_signature",
        "verdict",
    )


def _validate_verdict_validity_fields(verdict: dict[str, Any]) -> None:
    expires_at = verdict.get("expires_at")
    if not isinstance(expires_at, str):
        _raise_malformed("malformed_verdict_validity", "verdict is missing expires_at")
    expires_at_epoch_ms = verdict.get("expires_at_epoch_ms")
    if not isinstance(expires_at_epoch_ms, int) or isinstance(
        expires_at_epoch_ms, bool
    ):
        _raise_malformed(
            "malformed_verdict_validity",
            "verdict is missing expires_at_epoch_ms",
        )
    _validate_safe_json_int(
        expires_at_epoch_ms,
        "expires_at_epoch_ms",
        "verdict",
        "malformed_verdict_validity",
        "integer millisecond epoch",
    )
    validity = verdict.get("validity")
    if not isinstance(validity, dict):
        _raise_malformed("malformed_verdict_validity", "verdict is missing validity")

    computed_expires_at = _required_timestamp_field(
        validity,
        "computed_expires_at",
        "validity",
    )
    if expires_at != computed_expires_at:
        _raise_malformed(
            "malformed_verdict_validity",
            "expires_at must match validity.computed_expires_at",
        )
    parsed_expires_at = _parse_utc_epoch_ms(expires_at, "expires_at")
    if parsed_expires_at != expires_at_epoch_ms:
        _raise_malformed(
            "malformed_verdict_validity",
            "expires_at_epoch_ms must match expires_at",
        )

    bounds = [
        _parse_utc_epoch_ms(
            _required_timestamp_field(validity, field, "validity"),
            f"validity.{field}",
        )
        for field in (
            "policy_ttl_until",
            "collateral_valid_until",
            "certificate_valid_until",
            "quote_valid_until",
            "tcb_valid_until",
            "reference_values_valid_until",
        )
    ]
    if min(bounds) != parsed_expires_at:
        _raise_malformed(
            "malformed_verdict_validity",
            "validity.computed_expires_at must be the minimum validity bound",
        )


def _required_timestamp_field(
    payload: dict[str, Any],
    field: str,
    subject: str,
    code: str = "malformed_verdict_validity",
) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        _raise_malformed(
            code,
            f"{subject} is missing {field}",
        )
    return value


def _parse_utc_epoch_ms(
    timestamp: str,
    field: str,
    code: str = "malformed_verdict_validity",
) -> int:
    if not timestamp.endswith("Z") or len(timestamp) not in (20, 24):
        _raise_malformed(
            code,
            f"{field} must be a canonical UTC timestamp",
        )
    if len(timestamp) == 24 and timestamp[19] != ".":
        _raise_malformed(
            code,
            f"{field} must be a canonical UTC timestamp",
        )
    try:
        parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        try:
            parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            _raise_malformed(
                code,
                f"{field} must be a canonical UTC timestamp",
            )
    if parsed.microsecond % 1000 != 0:
        _raise_malformed(
            code,
            f"{field} must use millisecond precision",
        )
    return int(parsed.replace(tzinfo=timezone.utc).timestamp() * 1000)


def _validate_verdict_mirrors(
    container: dict[str, Any],
    verdict: dict[str, Any],
    code: str,
    label: str,
) -> None:
    for field in ("response_channel_bound", "response_integrity_result"):
        if field not in container:
            _raise_malformed(code, f"{label} is missing {field}")
        if field not in verdict:
            _raise_malformed(code, f"{label} verdict is missing {field}")
        if container[field] != verdict[field]:
            _raise_malformed(code, f"{label} {field} conflicts with embedded verdict")


def _validate_verdict_enum_fields(verdict: dict[str, Any]) -> None:
    _validate_enum_field(verdict, "status", VERIFICATION_STATUS_VALUES)
    _validate_enum_field(verdict, "enforcement", ENFORCEMENT_VALUES)
    _validate_enum_field(verdict, "trust_tier", TRUST_TIER_VALUES)
    _validate_enum_field(verdict, "channel_binding_kind", CHANNEL_BINDING_KIND_VALUES)
    _validate_enum_field(verdict, "model_binding_result", MODEL_BINDING_RESULT_VALUES)
    _validate_enum_field(
        verdict,
        "request_confidentiality_result",
        CONFIDENTIALITY_RESULT_VALUES,
    )
    _validate_enum_field(
        verdict,
        "response_confidentiality_result",
        CONFIDENTIALITY_RESULT_VALUES,
    )
    _validate_enum_field(
        verdict,
        "response_integrity_result",
        RESPONSE_INTEGRITY_RESULT_VALUES,
    )
    _validate_bool_field(verdict, "request_channel_bound")
    _validate_bool_field(verdict, "response_channel_bound")
    _validate_bool_field(verdict, "request_allowed")
    _validate_bool_field(verdict, "would_block_under_enforce")

    checks = verdict.get("checks")
    if checks is None:
        return
    if not isinstance(checks, dict):
        _raise_malformed("malformed_verdict_enum", "verdict checks must be an object")
    for check_name, check_result in checks.items():
        if not isinstance(check_name, str) or not isinstance(check_result, str):
            _raise_malformed(
                "malformed_verdict_enum",
                "verdict checks must map string names to string results",
            )
        if check_result not in CHECK_RESULT_VALUES:
            _raise_malformed(
                "malformed_verdict_enum",
                f"verdict check {check_name} has invalid result {check_result}",
            )


def _validate_verdict_structured_fields(verdict: dict[str, Any]) -> None:
    outcomes = verdict.get("check_outcomes")
    if outcomes is not None:
        checks = verdict.get("checks")
        if not isinstance(outcomes, dict) or not isinstance(checks, dict):
            _raise_malformed(
                "malformed_verdict_checks",
                "verdict check_outcomes and checks must both be objects",
            )
        if set(outcomes) != set(checks):
            _raise_malformed(
                "malformed_verdict_checks",
                "check_outcomes must contain exactly the legacy check keys",
            )
        for name, state in checks.items():
            outcome = outcomes.get(name)
            if not isinstance(outcome, dict) or outcome.get("state") != state:
                _raise_malformed(
                    "malformed_verdict_checks",
                    f"check_outcomes.{name}.state conflicts with checks.{name}",
                )
            if not isinstance(outcome.get("required"), bool):
                _raise_malformed(
                    "malformed_verdict_checks",
                    f"check_outcomes.{name}.required must be a boolean",
                )
            detail = outcome.get("detail")
            if not isinstance(detail, str) or not detail.strip():
                _raise_malformed(
                    "malformed_verdict_checks",
                    f"check_outcomes.{name}.detail must not be empty",
                )
            if outcome["required"] and outcome["state"] == "not_applicable":
                _raise_malformed(
                    "malformed_verdict_checks",
                    f"required check_outcomes.{name} cannot be not_applicable",
                )
            _validate_verdict_evidence_refs(
                outcome.get("evidence_refs", []),
                f"check_outcomes.{name}.evidence_refs",
            )

    attribution = verdict.get("route_attribution")
    if attribution is None:
        return
    if not isinstance(attribution, dict) or not isinstance(
        attribution.get("parties"), list
    ):
        _raise_malformed(
            "malformed_verdict_attribution",
            "route_attribution.parties must be an array",
        )
    parties = attribution["parties"]
    if len(parties) != len(ROUTE_PARTY_ROLES):
        _raise_malformed(
            "malformed_verdict_attribution",
            "route_attribution must explicitly cover every route-party role",
        )
    seen_roles: set[str] = set()
    for party in parties:
        if (
            not isinstance(party, dict)
            or party.get("role") not in ROUTE_PARTY_ROLES
            or party["role"] in seen_roles
        ):
            _raise_malformed(
                "malformed_verdict_attribution",
                "route_attribution roles are missing or duplicated",
            )
        role = party["role"]
        seen_roles.add(role)
        source = party.get("source")
        if source not in ATTRIBUTION_SOURCES:
            _raise_malformed(
                "malformed_verdict_attribution",
                f"route_attribution {role} has an invalid source",
            )
        detail = party.get("detail")
        if not isinstance(detail, str) or not detail.strip():
            _raise_malformed(
                "malformed_verdict_attribution",
                f"route_attribution {role} detail must not be empty",
            )
        party_id = party.get("party_id")
        if source == "unknown":
            if party_id is not None:
                _raise_malformed(
                    "malformed_verdict_attribution",
                    f"route_attribution {role} cannot name a party from an unknown source",
                )
        elif not isinstance(party_id, str) or not party_id.strip():
            _raise_malformed(
                "malformed_verdict_attribution",
                f"route_attribution {role} requires a non-empty party_id",
            )
        _validate_verdict_evidence_refs(
            party.get("evidence_refs", []),
            f"route_attribution.{role}.evidence_refs",
        )
    provider = next(party for party in parties if party["role"] == "inference_provider")
    if (
        provider.get("party_id") != verdict.get("provider")
        or provider.get("source") != "signed_registry"
    ):
        _raise_malformed(
            "malformed_verdict_attribution",
            "inference-provider attribution must match the signed registry provider",
        )


def _validate_verdict_evidence_refs(refs: Any, subject: str) -> None:
    if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
        _raise_malformed(
            "malformed_verdict_evidence_refs",
            f"{subject} must be a string array",
        )
    if refs != sorted(set(refs)):
        _raise_malformed(
            "malformed_verdict_evidence_refs",
            f"{subject} must be sorted and unique",
        )
    unsupported = next((ref for ref in refs if ref not in VERDICT_EVIDENCE_REFS), None)
    if unsupported is not None:
        _raise_malformed(
            "malformed_verdict_evidence_refs",
            f"{subject} contains unsupported evidence reference {unsupported}",
        )


def _validate_bool_field(payload: dict[str, Any], field: str) -> None:
    if not isinstance(payload.get(field), bool):
        _raise_malformed("malformed_verdict_enum", f"verdict is missing {field}")


def _validate_verdict_summary_consistency(verdict: dict[str, Any]) -> None:
    checks = verdict.get("checks")
    if not isinstance(checks, dict):
        return

    if (
        verdict["model_binding_result"] == "verified"
        and checks.get("model_binding") != "verified"
    ):
        _raise_malformed(
            "malformed_verdict_summary",
            "model_binding_result=verified but model_binding check is not verified",
        )

    if verdict["request_confidentiality_result"] in {
        "channel_bound",
        "encrypted_bound",
    }:
        if verdict.get("request_channel_bound") is not True:
            _raise_malformed(
                "malformed_verdict_summary",
                "bound request_confidentiality_result conflicts with request_channel_bound=false",
            )
        _require_check_verified(
            checks,
            "request_key_binding",
            "bound request_confidentiality_result",
        )
        _require_check_verified(
            checks,
            "request_encryption",
            "bound request_confidentiality_result",
        )

    if verdict.get("request_channel_bound") is True and verdict[
        "request_confidentiality_result"
    ] not in {
        "channel_bound",
        "encrypted_bound",
    }:
        _raise_malformed(
            "malformed_verdict_summary",
            "request_channel_bound conflicts with request_confidentiality_result",
        )

    if verdict["response_confidentiality_result"] in {
        "channel_bound",
        "encrypted_bound",
    }:
        if verdict.get("response_channel_bound") is not True:
            _raise_malformed(
                "malformed_verdict_summary",
                "bound response_confidentiality_result conflicts with response_channel_bound=false",
            )
        _require_check_verified(
            checks,
            "response_key_binding",
            "bound response_confidentiality_result",
        )
        _require_check_verified(
            checks,
            "response_encryption",
            "bound response_confidentiality_result",
        )

    if verdict.get("response_channel_bound") is True and verdict[
        "response_confidentiality_result"
    ] not in {
        "channel_bound",
        "encrypted_bound",
    }:
        _raise_malformed(
            "malformed_verdict_summary",
            "response_channel_bound conflicts with response_confidentiality_result",
        )

    if (
        verdict.get("response_channel_bound") is True
        and verdict["response_integrity_result"] != "channel_bound"
    ):
        _raise_malformed(
            "malformed_verdict_summary",
            "response channel binding must mirror channel-bound response integrity",
        )

    if verdict["response_integrity_result"] == "channel_bound":
        if verdict.get("response_channel_bound") is not True:
            _raise_malformed(
                "malformed_verdict_summary",
                "channel-bound response integrity conflicts with response_channel_bound=false",
            )
        _require_check_verified(
            checks,
            "response_channel_binding",
            "channel-bound response_integrity_result",
        )
    elif verdict["response_integrity_result"] == "receipt_bound":
        _require_check_verified(
            checks,
            "response_receipt",
            "receipt-bound response_integrity_result",
        )

    if verdict["status"] == "verified":
        if verdict["trust_tier"] == "app-e2ee":
            if verdict["channel_binding_kind"] != "attested_app_e2ee":
                _raise_malformed(
                    "malformed_verdict_summary",
                    "trust_tier=app-e2ee requires channel_binding_kind=attested_app_e2ee",
                )
            if (
                verdict.get("request_channel_bound") is not True
                or verdict.get("response_channel_bound") is not True
            ):
                _raise_malformed(
                    "malformed_verdict_summary",
                    "trust_tier=app-e2ee requires request and response channel binding",
                )
        elif verdict["trust_tier"] == "hw-verified-tls":
            if verdict["channel_binding_kind"] != "tee_terminated_tls":
                _raise_malformed(
                    "malformed_verdict_summary",
                    "trust_tier=hw-verified-tls requires channel_binding_kind=tee_terminated_tls",
                )
            _require_check_verified(
                checks,
                "tls_binding",
                "trust_tier=hw-verified-tls",
            )
            if (
                verdict["request_confidentiality_result"] != "channel_bound"
                or verdict["response_confidentiality_result"] != "channel_bound"
            ):
                _raise_malformed(
                    "malformed_verdict_summary",
                    "trust_tier=hw-verified-tls requires channel-bound request and response confidentiality",
                )
        elif verdict["trust_tier"] == "tee-only":
            if verdict.get("response_channel_bound") is True:
                _raise_malformed(
                    "malformed_verdict_summary",
                    "trust_tier=tee-only must not report response_channel_bound=true",
                )
        elif verdict["trust_tier"] == "none":
            if (
                verdict.get("request_channel_bound") is True
                or verdict.get("response_channel_bound") is True
                or verdict["response_integrity_result"]
                in {"channel_bound", "receipt_bound"}
                or verdict["request_confidentiality_result"]
                in {"channel_bound", "encrypted_bound"}
                or verdict["response_confidentiality_result"]
                in {"channel_bound", "encrypted_bound"}
            ):
                _raise_malformed(
                    "malformed_verdict_summary",
                    "trust_tier=none conflicts with bound channel or response integrity summaries",
                )

    has_failed_check = any(check == "failed" for check in checks.values())
    if has_failed_check and verdict.get("would_block_under_enforce") is not True:
        _raise_malformed(
            "malformed_verdict_summary",
            "failed checks conflict with would_block_under_enforce=false",
        )
    if not has_failed_check and verdict.get("would_block_under_enforce") is True:
        _raise_malformed(
            "malformed_verdict_summary",
            "would_block_under_enforce=true but no check is failed",
        )

    if verdict["status"] == "disabled" and verdict["enforcement"] != "disabled":
        _raise_malformed(
            "malformed_verdict_summary",
            "status=disabled requires disabled enforcement",
        )

    if verdict["enforcement"] == "enforce":
        if (
            verdict.get("would_block_under_enforce") is True
            and verdict.get("request_allowed") is True
        ):
            _raise_malformed(
                "malformed_verdict_summary",
                "enforce verdict would block but request_allowed=true",
            )
        if (
            verdict.get("would_block_under_enforce") is False
            and verdict.get("request_allowed") is False
        ):
            _raise_malformed(
                "malformed_verdict_summary",
                "enforce verdict allows policy but request_allowed=false",
            )
    elif verdict["enforcement"] in {"observe", "disabled"}:
        if verdict.get("request_allowed") is False:
            _raise_malformed(
                "malformed_verdict_summary",
                "non-enforcing verdict must not set request_allowed=false",
            )

    if verdict["enforcement"] == "disabled" and verdict["status"] != "disabled":
        _raise_malformed(
            "malformed_verdict_summary",
            "disabled enforcement must emit status=disabled",
        )

    if verdict["status"] == "verified":
        if any(check == "failed" for check in checks.values()):
            _raise_malformed(
                "malformed_verdict_summary",
                "status=verified but at least one check is failed",
            )
        errors = verdict.get("errors")
        if isinstance(errors, list) and errors:
            _raise_malformed(
                "malformed_verdict_summary",
                "status=verified but verdict contains errors",
            )
        if verdict.get("request_allowed") is False:
            _raise_malformed(
                "malformed_verdict_summary",
                "status=verified conflicts with request_allowed=false",
            )
        if verdict.get("would_block_under_enforce") is True:
            _raise_malformed(
                "malformed_verdict_summary",
                "status=verified conflicts with would_block_under_enforce=true",
            )


def _require_check_verified(
    checks: dict[str, Any],
    check_name: str,
    summary: str,
) -> None:
    if checks.get(check_name) != "verified":
        _raise_malformed(
            "malformed_verdict_summary",
            f"{summary} requires {check_name} check to be verified",
        )


def _validate_enum_field(
    payload: dict[str, Any],
    field: str,
    allowed_values: set[str],
) -> None:
    value = payload.get(field)
    if not isinstance(value, str):
        _raise_malformed("malformed_verdict_enum", f"verdict is missing {field}")
    if value not in allowed_values:
        _raise_malformed(
            "malformed_verdict_enum",
            f"verdict field {field} has invalid value {value}",
        )


def _raise_malformed(code: str, message: str) -> None:
    raise ConfidentialInferenceError(CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT, {"code": code, "message": message})


class _Native:
    def __init__(self, library_path: str | os.PathLike[str] | None = None):
        self.path = _resolve_library_path(library_path)
        self.lib = ctypes.CDLL(str(self.path))
        self.callback_type = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
        self._configure()

    def _configure(self) -> None:
        void_pp = ctypes.POINTER(ctypes.c_void_p)
        self.lib.confidential_inference_status.argtypes = [void_pp]
        self.lib.confidential_inference_status.restype = ctypes.c_int
        self.lib.confidential_inference_sdk_new.argtypes = [ctypes.c_char_p, void_pp]
        self.lib.confidential_inference_sdk_new.restype = ctypes.c_int
        self.lib.confidential_inference_sdk_free.argtypes = [ctypes.c_void_p]
        self.lib.confidential_inference_sdk_free.restype = ctypes.c_int
        self.lib.confidential_inference_chat_blocking.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint64,
            void_pp,
        ]
        self.lib.confidential_inference_chat_blocking.restype = ctypes.c_int
        self.lib.confidential_inference_response_blocking.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint64,
            void_pp,
        ]
        self.lib.confidential_inference_response_blocking.restype = ctypes.c_int
        self.lib.confidential_inference_verify_blocking.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint64,
            void_pp,
        ]
        self.lib.confidential_inference_verify_blocking.restype = ctypes.c_int
        self.lib.confidential_inference_models_blocking.argtypes = [ctypes.c_void_p, void_pp]
        self.lib.confidential_inference_models_blocking.restype = ctypes.c_int
        self.lib.confidential_inference_confidentiality_blocking.argtypes = [ctypes.c_void_p, void_pp]
        self.lib.confidential_inference_confidentiality_blocking.restype = ctypes.c_int
        self.lib.confidential_inference_active_policy_blocking.argtypes = [
            ctypes.c_void_p,
            void_pp,
        ]
        self.lib.confidential_inference_active_policy_blocking.restype = ctypes.c_int
        self.lib.confidential_inference_active_trust_artifacts_blocking.argtypes = [
            ctypes.c_void_p,
            void_pp,
        ]
        self.lib.confidential_inference_active_trust_artifacts_blocking.restype = ctypes.c_int
        self.lib.confidential_inference_chat_start.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            void_pp,
        ]
        self.lib.confidential_inference_chat_start.restype = ctypes.c_int
        self.lib.confidential_inference_response_start.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            void_pp,
        ]
        self.lib.confidential_inference_response_start.restype = ctypes.c_int
        self.lib.confidential_inference_verify_start.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            void_pp,
        ]
        self.lib.confidential_inference_verify_start.restype = ctypes.c_int
        self.lib.confidential_inference_op_poll.argtypes = [ctypes.c_void_p, void_pp]
        self.lib.confidential_inference_op_poll.restype = ctypes.c_int
        self.lib.confidential_inference_op_result_json.argtypes = [ctypes.c_void_p, void_pp]
        self.lib.confidential_inference_op_result_json.restype = ctypes.c_int
        self.lib.confidential_inference_op_set_callback.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self.lib.confidential_inference_op_set_callback.restype = ctypes.c_int
        self.lib.confidential_inference_op_readiness_fd.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
        self.lib.confidential_inference_op_readiness_fd.restype = ctypes.c_int
        self.lib.confidential_inference_op_cancel.argtypes = [ctypes.c_void_p]
        self.lib.confidential_inference_op_cancel.restype = ctypes.c_int
        self.lib.confidential_inference_op_free.argtypes = [ctypes.c_void_p]
        self.lib.confidential_inference_op_free.restype = ctypes.c_int
        self.lib.confidential_inference_chat_stream_start.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            void_pp,
        ]
        self.lib.confidential_inference_chat_stream_start.restype = ctypes.c_int
        self.lib.confidential_inference_stream_next.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            void_pp,
        ]
        self.lib.confidential_inference_stream_next.restype = ctypes.c_int
        self.lib.confidential_inference_stream_set_callback.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self.lib.confidential_inference_stream_set_callback.restype = ctypes.c_int
        self.lib.confidential_inference_stream_readiness_fd.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
        self.lib.confidential_inference_stream_readiness_fd.restype = ctypes.c_int
        self.lib.confidential_inference_stream_cancel.argtypes = [ctypes.c_void_p]
        self.lib.confidential_inference_stream_cancel.restype = ctypes.c_int
        self.lib.confidential_inference_stream_free.argtypes = [ctypes.c_void_p]
        self.lib.confidential_inference_stream_free.restype = ctypes.c_int
        self.lib.confidential_inference_last_error.argtypes = [void_pp]
        self.lib.confidential_inference_last_error.restype = ctypes.c_int
        self.lib.confidential_inference_string_free.argtypes = [ctypes.c_void_p]
        self.lib.confidential_inference_string_free.restype = None

    def take_json_string(self, ptr: ctypes.c_void_p) -> Any:
        if not ptr:
            raise ConfidentialInferenceError(
                CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                {
                    "code": "missing_string",
                    "message": "FFI returned a null JSON string pointer",
                },
            )
        try:
            value = ctypes.string_at(ptr).decode("utf-8")
        finally:
            self.lib.confidential_inference_string_free(ptr)
        return json.loads(value)

    def status(self) -> dict[str, Any]:
        out = ctypes.c_void_p()
        status = self.lib.confidential_inference_status(ctypes.byref(out))
        self.raise_for_status(status)
        return _validate_ffi_status(self.take_json_string(out))

    def last_error(self) -> dict[str, Any] | None:
        out = ctypes.c_void_p()
        code = self.lib.confidential_inference_last_error(ctypes.byref(out))
        if code != CONFIDENTIAL_INFERENCE_FFI_OK:
            return {"code": "last_error_failed", "message": f"status {code}"}
        payload = _validate_ffi_error_envelope(self.take_json_string(out))
        return payload.get("error")

    def raise_for_status(self, status: int) -> None:
        if status != CONFIDENTIAL_INFERENCE_FFI_OK:
            raise ConfidentialInferenceError(status, self.last_error())


class Client:
    def __init__(
        self,
        config: dict[str, Any] | None = None,
        library_path: str | os.PathLike[str] | None = None,
    ):
        self._native = _Native(library_path)
        self._handle = ctypes.c_void_p()
        config_bytes = None
        if config is not None:
            config_bytes = json.dumps(config, separators=(",", ":")).encode("utf-8")
        status = self._native.lib.confidential_inference_sdk_new(
            config_bytes, ctypes.byref(self._handle)
        )
        self._native.raise_for_status(status)

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if not self._handle else "open"
        return f"Client(state={state!r}, library={str(self._native.path)!r})"

    def close(self) -> None:
        if self._handle:
            handle = self._handle
            status = self._native.lib.confidential_inference_sdk_free(handle)
            self._native.raise_for_status(status)
            self._handle = ctypes.c_void_p()

    def status(self) -> dict[str, Any]:
        return self._native.status()

    def chat(self, request: dict[str, Any], timeout_ms: int = 0) -> dict[str, Any]:
        return self._call_json(
            self._native.lib.confidential_inference_chat_blocking,
            request,
            timeout_ms,
            validator=_validate_confidential_response,
        )

    def create_response(
        self, request: dict[str, Any], timeout_ms: int = 0
    ) -> dict[str, Any]:
        return self._call_json(
            self._native.lib.confidential_inference_response_blocking,
            request,
            timeout_ms,
            validator=_validate_confidential_response,
        )

    def response(self, request: dict[str, Any], timeout_ms: int = 0) -> dict[str, Any]:
        return self.create_response(request, timeout_ms=timeout_ms)

    def verify(self, provider: str, model: str, timeout_ms: int = 0) -> dict[str, Any]:
        return self._call_json(
            self._native.lib.confidential_inference_verify_blocking,
            {"provider": provider, "model": model},
            timeout_ms,
            validator=_validate_verdict,
        )

    def models(self) -> dict[str, Any]:
        return self._call_no_request_json(
            self._native.lib.confidential_inference_models_blocking,
            validator=_validate_model_list,
        )

    def confidential_models(self) -> list[dict[str, Any]]:
        return self._call_no_request_json(
            self._native.lib.confidential_inference_confidentiality_blocking,
            validator=_validate_confidential_models,
        )

    def confidentiality(self) -> list[dict[str, Any]]:
        return self.confidential_models()

    def active_policy(self) -> dict[str, Any]:
        return self._call_no_request_json(
            self._native.lib.confidential_inference_active_policy_blocking,
            validator=_validate_active_policy_snapshot,
        )

    def active_trust_artifacts(self) -> dict[str, Any]:
        return self._call_no_request_json(
            self._native.lib.confidential_inference_active_trust_artifacts_blocking,
            validator=_validate_active_trust_artifacts,
        )

    async def chat_async(
        self, request: dict[str, Any], timeout_ms: int = 0
    ) -> dict[str, Any]:
        operation = self.start_chat(request)
        try:
            return await operation.wait_async(timeout_ms=timeout_ms)
        finally:
            operation.close()

    async def create_response_async(
        self, request: dict[str, Any], timeout_ms: int = 0
    ) -> dict[str, Any]:
        operation = self.start_response(request)
        try:
            return await operation.wait_async(timeout_ms=timeout_ms)
        finally:
            operation.close()

    async def response_async(
        self, request: dict[str, Any], timeout_ms: int = 0
    ) -> dict[str, Any]:
        return await self.create_response_async(request, timeout_ms=timeout_ms)

    async def verify_async(
        self, provider: str, model: str, timeout_ms: int = 0
    ) -> dict[str, Any]:
        operation = self.start_verify(provider, model)
        try:
            return await operation.wait_async(timeout_ms=timeout_ms)
        finally:
            operation.close()

    async def stream_async(
        self,
        request: dict[str, Any],
        timeout_ms: int = 0,
        poll_interval: float = 0.01,
    ) -> AsyncIterator[dict[str, Any]]:
        stream = self.start_stream(request)
        try:
            async for event in stream.events_async(
                timeout_ms=timeout_ms,
                poll_interval=poll_interval,
            ):
                yield event
        finally:
            _close_or_cancel(stream)

    def start_chat(self, request: dict[str, Any]) -> "Operation":
        return self._start_operation(
            self._native.lib.confidential_inference_chat_start,
            request,
            validator=_validate_confidential_response,
        )

    def start_response(self, request: dict[str, Any]) -> "Operation":
        return self._start_operation(
            self._native.lib.confidential_inference_response_start,
            request,
            validator=_validate_confidential_response,
        )

    def start_verify(self, provider: str, model: str) -> "Operation":
        return self._start_operation(
            self._native.lib.confidential_inference_verify_start,
            {"provider": provider, "model": model},
            validator=_validate_verdict,
        )

    def start_stream(self, request: dict[str, Any]) -> "Stream":
        self._require_open()
        out = ctypes.c_void_p()
        status = self._native.lib.confidential_inference_chat_stream_start(
            self._handle, _json_bytes(request), ctypes.byref(out)
        )
        self._native.raise_for_status(status)
        return Stream(self._native, out)

    def _call_json(
        self,
        function: Any,
        request: dict[str, Any] | bytes,
        timeout_ms: int,
        validator: Callable[[Any], Any] | None = None,
    ) -> dict[str, Any]:
        self._require_open()
        request_bytes = _json_bytes(request)
        out = ctypes.c_void_p()
        status = function(
            self._handle,
            request_bytes,
            ctypes.c_uint64(timeout_ms),
            ctypes.byref(out),
        )
        self._native.raise_for_status(status)
        payload = self._native.take_json_string(out)
        return validator(payload) if validator is not None else payload

    def _call_no_request_json(
        self,
        function: Any,
        validator: Callable[[Any], Any] | None = None,
    ) -> Any:
        self._require_open()
        out = ctypes.c_void_p()
        status = function(self._handle, ctypes.byref(out))
        self._native.raise_for_status(status)
        payload = self._native.take_json_string(out)
        return validator(payload) if validator is not None else payload

    def _start_operation(
        self,
        function: Any,
        request: dict[str, Any],
        validator: Callable[[Any], Any] | None = None,
    ) -> "Operation":
        self._require_open()
        out = ctypes.c_void_p()
        status = function(self._handle, _json_bytes(request), ctypes.byref(out))
        self._native.raise_for_status(status)
        return Operation(self._native, out, validator=validator)

    def _require_open(self) -> None:
        if not self._handle:
            raise ConfidentialInferenceError(1, {"code": "client_closed", "message": "client is closed"})

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class Operation:
    def __init__(
        self,
        native: _Native,
        handle: ctypes.c_void_p,
        validator: Callable[[Any], Any] | None = None,
    ):
        self._native = native
        self._handle = handle
        self._validator = validator
        self.cancel_requested = False
        self._callback_refs: list[Any] = []

    def poll(self) -> dict[str, Any]:
        self._require_open()
        out = ctypes.c_void_p()
        status = self._native.lib.confidential_inference_op_poll(self._handle, ctypes.byref(out))
        self._native.raise_for_status(status)
        return _validate_operation_state(self._native.take_json_string(out))

    def result(self) -> dict[str, Any]:
        self._require_open()
        out = ctypes.c_void_p()
        status = self._native.lib.confidential_inference_op_result_json(self._handle, ctypes.byref(out))
        self._native.raise_for_status(status)
        payload = self._native.take_json_string(out)
        return self._validator(payload) if self._validator is not None else payload

    def cancel(self) -> None:
        self._require_open()
        self.cancel_requested = True
        status = self._native.lib.confidential_inference_op_cancel(self._handle)
        self._native.raise_for_status(status)

    def set_callback(self, callback: Callable[[], None] | None) -> None:
        self._require_open()
        callback_pointer = None
        if callback is not None:
            c_callback = self._native.callback_type(lambda _user_data: callback())
            self._callback_refs.append(c_callback)
            callback_pointer = ctypes.cast(c_callback, ctypes.c_void_p)
        status = self._native.lib.confidential_inference_op_set_callback(
            self._handle,
            callback_pointer,
            None,
        )
        self._native.raise_for_status(status)

    def readiness_fd(self) -> int:
        self._require_open()
        out = ctypes.c_int(-1)
        status = self._native.lib.confidential_inference_op_readiness_fd(
            self._handle,
            ctypes.byref(out),
        )
        self._native.raise_for_status(status)
        return out.value

    def wait(self, timeout_ms: int = 0, poll_interval: float = 0.01) -> dict[str, Any]:
        deadline = None if timeout_ms == 0 else time.monotonic() + timeout_ms / 1000
        while True:
            state = self.poll()
            if state.get("status") != "pending":
                return self.result()
            if deadline is not None and time.monotonic() >= deadline:
                raise ConfidentialInferenceError(
                    CONFIDENTIAL_INFERENCE_FFI_PENDING,
                    {"code": "operation_timeout", "message": "operation timed out"},
                )
            time.sleep(poll_interval)

    async def wait_async(
        self, timeout_ms: int = 0, poll_interval: float = 0.01
    ) -> dict[str, Any]:
        try:
            if os.name == "posix":
                try:
                    fd = self.readiness_fd()
                except ConfidentialInferenceError as error:
                    if error.status not in (CONFIDENTIAL_INFERENCE_FFI_BUSY, CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED):
                        raise
                else:
                    try:
                        await _wait_for_readiness_fd(
                            fd,
                            timeout_ms,
                            "operation_timeout",
                            "operation timed out",
                        )
                    except ConfidentialInferenceError as error:
                        if error.status != CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED:
                            raise
                    else:
                        return self.result()

            deadline = None if timeout_ms == 0 else time.monotonic() + timeout_ms / 1000
            while True:
                await asyncio.sleep(poll_interval)
                state = self.poll()
                if state.get("status") != "pending":
                    return self.result()
                if deadline is not None and time.monotonic() >= deadline:
                    raise ConfidentialInferenceError(
                        CONFIDENTIAL_INFERENCE_FFI_PENDING,
                        {"code": "operation_timeout", "message": "operation timed out"},
                    )
        except asyncio.CancelledError:
            self.cancel()
            raise

    def close(self) -> None:
        if self._handle:
            handle = self._handle
            status = self._native.lib.confidential_inference_op_free(handle)
            self._native.raise_for_status(status)
            self._handle = ctypes.c_void_p()
            self._callback_refs.clear()

    def _require_open(self) -> None:
        if not self._handle:
            raise ConfidentialInferenceError(
                1,
                {"code": "operation_closed", "message": "operation is closed"},
            )

    def __enter__(self) -> "Operation":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            if self._handle and self.poll().get("status") == "pending":
                self.cancel()
            self.close()
        except Exception:
            pass


class Stream:
    def __init__(self, native: _Native, handle: ctypes.c_void_p):
        self._native = native
        self._handle = handle
        self.cancel_requested = False
        self._callback_refs: list[Any] = []

    def next(self, timeout_ms: int = 0) -> dict[str, Any]:
        self._require_open()
        out = ctypes.c_void_p()
        status = self._native.lib.confidential_inference_stream_next(
            self._handle, ctypes.c_uint64(timeout_ms), ctypes.byref(out)
        )
        self._native.raise_for_status(status)
        return _validate_stream_event(self._native.take_json_string(out))

    def events(self, timeout_ms: int = 0) -> Iterator[dict[str, Any]]:
        while True:
            event = self.next(timeout_ms=timeout_ms)
            if event.get("type") == "closed":
                return
            yield event

    async def events_async(
        self, timeout_ms: int = 0, poll_interval: float = 0.01
    ) -> AsyncIterator[dict[str, Any]]:
        deadline = None if timeout_ms == 0 else time.monotonic() + timeout_ms / 1000
        readiness_fd: int | None = None
        try:
            while True:
                try:
                    event = self.next(timeout_ms=0)
                except ConfidentialInferenceError as error:
                    if error.status != CONFIDENTIAL_INFERENCE_FFI_PENDING:
                        raise
                    if deadline is not None and time.monotonic() >= deadline:
                        raise ConfidentialInferenceError(
                            CONFIDENTIAL_INFERENCE_FFI_PENDING,
                            {
                                "code": "stream_timeout",
                                "message": "stream event timed out",
                            },
                        ) from error
                    if os.name == "posix" and readiness_fd is None:
                        try:
                            readiness_fd = self.readiness_fd()
                        except ConfidentialInferenceError as readiness_error:
                            if readiness_error.status not in (
                                CONFIDENTIAL_INFERENCE_FFI_BUSY,
                                CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED,
                            ):
                                raise
                    if readiness_fd is not None:
                        try:
                            await _wait_for_readiness_fd(
                                readiness_fd,
                                _remaining_timeout_ms(deadline),
                                "stream_timeout",
                                "stream event timed out",
                            )
                        except ConfidentialInferenceError as readiness_error:
                            if readiness_error.status != CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED:
                                raise
                            readiness_fd = None
                        else:
                            readiness_fd = None
                    else:
                        await asyncio.sleep(poll_interval)
                    continue
                if event.get("type") == "closed":
                    return
                yield event
        except asyncio.CancelledError:
            self.cancel()
            raise

    def cancel(self) -> None:
        self._require_open()
        self.cancel_requested = True
        status = self._native.lib.confidential_inference_stream_cancel(self._handle)
        self._native.raise_for_status(status)

    def set_callback(self, callback: Callable[[], None] | None) -> None:
        self._require_open()
        callback_pointer = None
        if callback is not None:
            c_callback = self._native.callback_type(lambda _user_data: callback())
            self._callback_refs.append(c_callback)
            callback_pointer = ctypes.cast(c_callback, ctypes.c_void_p)
        status = self._native.lib.confidential_inference_stream_set_callback(
            self._handle,
            callback_pointer,
            None,
        )
        self._native.raise_for_status(status)

    def readiness_fd(self) -> int:
        self._require_open()
        out = ctypes.c_int(-1)
        status = self._native.lib.confidential_inference_stream_readiness_fd(
            self._handle,
            ctypes.byref(out),
        )
        self._native.raise_for_status(status)
        return out.value

    def close(self) -> None:
        if self._handle:
            handle = self._handle
            status = self._native.lib.confidential_inference_stream_free(handle)
            self._native.raise_for_status(status)
            self._handle = ctypes.c_void_p()
            self._callback_refs.clear()

    def _require_open(self) -> None:
        if not self._handle:
            raise ConfidentialInferenceError(1, {"code": "stream_closed", "message": "stream is closed"})

    def __enter__(self) -> "Stream":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            if self._handle:
                self.cancel()
            self.close()
        except Exception:
            pass


def _close_or_cancel(stream: Stream) -> None:
    try:
        stream.close()
    except ConfidentialInferenceError as error:
        if error.status != CONFIDENTIAL_INFERENCE_FFI_BUSY:
            raise
        stream.cancel()
        stream.close()


async def _wait_for_readiness_fd(
    fd: int,
    timeout_ms: int | None,
    timeout_code: str,
    timeout_message: str,
) -> None:
    loop = asyncio.get_running_loop()
    future: asyncio.Future[None] = loop.create_future()

    def ready() -> None:
        if not future.done():
            future.set_result(None)

    try:
        loop.add_reader(fd, ready)
    except (AttributeError, NotImplementedError, RuntimeError, OSError) as error:
        os.close(fd)
        raise ConfidentialInferenceError(
            CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED,
            {
                "code": "readiness_fd_unsupported",
                "message": "event loop does not support readiness file descriptors",
            },
        ) from error

    try:
        if timeout_ms in (None, 0):
            await future
        else:
            await asyncio.wait_for(future, timeout=timeout_ms / 1000)
    except asyncio.TimeoutError as error:
        raise ConfidentialInferenceError(
            CONFIDENTIAL_INFERENCE_FFI_PENDING,
            {"code": timeout_code, "message": timeout_message},
        ) from error
    finally:
        loop.remove_reader(fd)
        os.close(fd)


def _remaining_timeout_ms(deadline: float | None) -> int | None:
    if deadline is None:
        return 0
    remaining = deadline - time.monotonic()
    return max(1, int(remaining * 1000))


def _json_bytes(value: dict[str, Any] | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _resolve_library_path(
    explicit: str | os.PathLike[str] | None = None,
) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(Path(explicit))
    if "CONFIDENTIAL_INFERENCE_FFI_LIBRARY" in os.environ:
        candidates.append(Path(os.environ["CONFIDENTIAL_INFERENCE_FFI_LIBRARY"]))

    library_name = _library_name()
    root = Path(__file__).resolve().parents[3]
    candidates.extend(
        [
            root / "target" / "debug" / library_name,
            root / "target" / "release" / library_name,
            Path.cwd() / "target" / "debug" / library_name,
            Path.cwd() / "target" / "release" / library_name,
        ]
    )

    for candidate in candidates:
        if candidate.exists():
            return candidate

    searched = ", ".join(str(candidate) for candidate in candidates)
    raise ConfidentialInferenceError(
        1,
        {
            "code": "library_not_found",
            "message": f"could not find ConfidentialInference FFI library; searched {searched}",
        },
    )


def _library_name() -> str:
    if sys.platform == "darwin":
        return "libconfidential_inference_ffi.dylib"
    if sys.platform.startswith("win"):
        return "confidential_inference_ffi.dll"
    return "libconfidential_inference_ffi.so"


__all__ = [
    "Client",
    "ConfidentialInferenceError",
    "Operation",
    "Stream",
    "canonical_json",
    "canonical_sha256_digest",
    "policy_canonical_json",
    "policy_digest",
]
