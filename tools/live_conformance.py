#!/usr/bin/env python3
"""Optional live provider conformance/canary runner.

The runner performs network requests only when --allow-network is supplied.
It is intentionally separate from offline CI so provider outages or credential
availability cannot weaken local security-regression gates.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from artifact_signatures import ArtifactSignatureError, verify_artifact_signature


SCHEMA = "confidential-inference.live-conformance-report.v1"
PLAN_SCHEMA = "confidential-inference.live-conformance-plan.v1"
PROVIDER_URL_FIELDS = ("model_list_url", "attestation_url")
COMPATIBILITY_SCHEMA = "confidential-inference.provider-compatibility-matrix.v1"
MODEL_ALIAS_MATRIX_ENVELOPE_SCHEMA = "confidential-inference.model-alias-matrix-envelope.v1"
MODEL_ALIAS_MATRIX_SCHEMA = "confidential-inference.model-alias-matrix.v1"
COMPATIBILITY_ENVELOPE_SCHEMA = "confidential-inference.provider-compatibility-matrix-envelope.v1"
BASE64URL_PREFIX = "base64url:"
BASE64URL_NO_PAD_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
ED25519_SIGNATURE_BYTE_LEN = 64
MAX_SAFE_JSON_INT = 9_007_199_254_740_991
COMPATIBILITY_REQUIRED_STRING_FIELDS = (
    "route_execution_status",
    "api_base_url",
    "model_listing",
    "model_id_rewrite",
    "token_parameter_rewrite",
    "streaming",
    "request_encryption",
    "response_decryption",
    "attestation_endpoint_shape",
    "freshness_class",
    "cacheability_class",
    "expected_trust_tier",
    "model_binding_support",
)
COMPATIBILITY_REQUIRED_LIST_FIELDS = (
    "supported_openai_endpoints",
    "required_credentials",
    "known_unsupported_modes",
)
COMPATIBILITY_ENUM_VALUES = {
    "route_execution_status": {
        "executable_fixture",
        "adapter_shape_fixture",
        "verification_only",
        "executable",
    },
    "model_listing": {"signed_registry_only", "live_catalog", "unsupported"},
    "model_id_rewrite": {"use_route_provider_model"},
    "token_parameter_rewrite": {
        "preserve_max_tokens",
        "max_tokens_to_max_completion_tokens",
    },
    "streaming": {
        "supported",
        "supported_if_encryption_supports_streaming",
        "unsupported",
    },
    "request_encryption": {"required", "not_required"},
    "response_decryption": {"required", "not_required"},
    "freshness_class": {"per_request", "per_session", "cached_binding"},
    "cacheability_class": {
        "per_request_only",
        "per_session_verdict",
        "static_provenance",
    },
    "expected_trust_tier": {"hw-verified-tls", "app-e2ee", "tee-only", "none"},
    "model_binding_support": {"unsupported", "partial", "verified"},
}
COMPATIBILITY_LIST_ENUM_VALUES = {
    "supported_openai_endpoints": {"chat_completions", "models", "confidentiality"},
    "required_credentials": {"bearer_token", "api_key_header"},
}
COMPATIBILITY_PROFILE_REPORT_FIELDS = (
    "provider",
    "route_execution_status",
    "model_listing",
    "model_id_rewrite",
    "token_parameter_rewrite",
    "streaming",
    "request_encryption",
    "response_decryption",
    "supported_openai_endpoints",
    "attestation_endpoint_shape",
    "required_credentials",
    "freshness_class",
    "cacheability_class",
    "expected_trust_tier",
    "model_binding_support",
    "known_unsupported_modes",
)


class LiveConformanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class ModelAliasMatrixSource:
    path: str
    digest: str
    payload: dict[str, Any]
    provider_models: dict[str, list[str]]

    def report_metadata(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "digest": self.digest,
            "providers": sorted(self.provider_models),
        }


@dataclass(frozen=True)
class ModelAliasMatrixEnvelopeSource:
    path: str
    digest: str
    payload_digest: str
    payload: dict[str, Any]
    signature: dict[str, str]

    def report_metadata(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "digest": self.digest,
            "payload_digest": self.payload_digest,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class CompatibilityMatrixSource:
    path: str
    digest: str
    payload: dict[str, Any]
    profiles: dict[str, dict[str, Any]]

    def report_metadata(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "digest": self.digest,
            "providers": sorted(self.profiles),
        }

    def provider_report_metadata(self, provider_id: str) -> dict[str, Any]:
        profile = self.profiles[provider_id]
        return {
            field: profile[field]
            for field in COMPATIBILITY_PROFILE_REPORT_FIELDS
            if field in profile
        }


@dataclass(frozen=True)
class CompatibilityMatrixEnvelopeSource:
    path: str
    digest: str
    payload_digest: str
    payload: dict[str, Any]
    signature: dict[str, str]

    def report_metadata(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "digest": self.digest,
            "payload_digest": self.payload_digest,
            "signature": self.signature,
        }


class HttpClient:
    def get(self, url: str, headers: dict[str, str], timeout_seconds: float) -> HttpResult:
        request = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return HttpResult(
                status=response.status,
                headers={key.lower(): value for key, value in response.headers.items()},
                body=response.read(),
            )


def load_plan(path: Path) -> dict[str, Any]:
    plan = json.loads(path.read_text(encoding="utf-8"))
    validate_plan(plan, str(path))
    return plan


def validate_plan(plan: dict[str, Any], source: str = "live conformance plan") -> None:
    if plan.get("schema") != PLAN_SCHEMA:
        raise LiveConformanceError(
            f"{source} has unsupported schema {plan.get('schema')!r}"
        )
    providers = plan.get("providers")
    if not isinstance(providers, list):
        raise LiveConformanceError(f"{source} must contain providers[]")
    model_alias_matrix_path = plan.get("model_alias_matrix_path")
    if model_alias_matrix_path is not None and (
        not isinstance(model_alias_matrix_path, str) or not model_alias_matrix_path
    ):
        raise LiveConformanceError(f"{source} model_alias_matrix_path must be a non-empty string")
    model_alias_matrix_envelope_path = plan.get("model_alias_matrix_envelope_path")
    if model_alias_matrix_envelope_path is not None and (
        not isinstance(model_alias_matrix_envelope_path, str)
        or not model_alias_matrix_envelope_path
    ):
        raise LiveConformanceError(
            f"{source} model_alias_matrix_envelope_path must be a non-empty string"
        )
    compatibility_matrix_path = plan.get("compatibility_matrix_path")
    if compatibility_matrix_path is not None and (
        not isinstance(compatibility_matrix_path, str) or not compatibility_matrix_path
    ):
        raise LiveConformanceError(
            f"{source} compatibility_matrix_path must be a non-empty string"
        )
    compatibility_matrix_envelope_path = plan.get("compatibility_matrix_envelope_path")
    if compatibility_matrix_envelope_path is not None and (
        not isinstance(compatibility_matrix_envelope_path, str)
        or not compatibility_matrix_envelope_path
    ):
        raise LiveConformanceError(
            f"{source} compatibility_matrix_envelope_path must be a non-empty string"
        )
    for index, provider in enumerate(providers):
        if not isinstance(provider, dict):
            raise LiveConformanceError(f"{source} providers[{index}] must be an object")
        provider_id = str(provider.get("id") or f"providers[{index}]")
        expected_ids_present = "expected_model_ids" in provider
        expected_ids = provider.get("expected_model_ids")
        from_alias_matrix = provider.get("expected_model_ids_from_alias_matrix", False)
        if expected_ids_present and from_alias_matrix:
            raise LiveConformanceError(
                f"provider {provider_id} must not set both expected_model_ids and "
                "expected_model_ids_from_alias_matrix"
            )
        if expected_ids_present and (
            not isinstance(expected_ids, list)
            or not expected_ids
            or any(not isinstance(model, str) or not model for model in expected_ids)
        ):
            raise LiveConformanceError(
                f"provider {provider_id} expected_model_ids must contain at least one "
                "non-empty string"
            )
        if from_alias_matrix is not False and from_alias_matrix is not True:
            raise LiveConformanceError(
                f"provider {provider_id} expected_model_ids_from_alias_matrix must be a boolean"
            )
        if from_alias_matrix and not model_alias_matrix_path:
            raise LiveConformanceError(
                f"provider {provider_id} imports expected model IDs but "
                "model_alias_matrix_path is not configured"
            )
        if from_alias_matrix and not model_alias_matrix_envelope_path:
            raise LiveConformanceError(
                f"provider {provider_id} imports expected model IDs but "
                "model_alias_matrix_envelope_path is not configured"
            )
        compatibility_provider = provider.get("compatibility_provider")
        if compatibility_provider is not None and (
            not isinstance(compatibility_provider, str) or not compatibility_provider
        ):
            raise LiveConformanceError(
                f"provider {provider_id} compatibility_provider must be a non-empty string"
            )
        if compatibility_provider and not compatibility_matrix_path:
            raise LiveConformanceError(
                f"provider {provider_id} declares compatibility_provider but "
                "compatibility_matrix_path is not configured"
            )
        if compatibility_provider and not compatibility_matrix_envelope_path:
            raise LiveConformanceError(
                f"provider {provider_id} declares compatibility_provider but "
                "compatibility_matrix_envelope_path is not configured"
            )
        validate_expected_attestation(
            provider_id,
            provider.get("attestation_url"),
            provider.get("expected_attestation"),
        )
        for field in PROVIDER_URL_FIELDS:
            value = provider.get(field)
            if value and url_has_credentials(str(value)):
                raise LiveConformanceError(
                    f"provider {provider_id} {field} must not include URL credentials"
                )


def validate_expected_attestation(
    provider_id: str,
    attestation_url: Any,
    expected: Any,
) -> None:
    if not attestation_url:
        if expected is not None:
            raise LiveConformanceError(
                f"provider {provider_id} expected_attestation requires attestation_url"
            )
        return
    if not isinstance(expected, dict):
        raise LiveConformanceError(
            f"provider {provider_id} expected_attestation must be an object"
        )

    content_type_contains = expected.get("content_type_contains")
    json_fields = expected.get("json_fields")
    if content_type_contains is None and json_fields is None:
        raise LiveConformanceError(
            f"provider {provider_id} expected_attestation must define a content type or JSON fields"
        )
    if content_type_contains is not None and (
        not isinstance(content_type_contains, str) or not content_type_contains
    ):
        raise LiveConformanceError(
            f"provider {provider_id} expected_attestation.content_type_contains "
            "must be a non-empty string"
        )
    if json_fields is not None:
        if (
            not isinstance(json_fields, list)
            or not json_fields
            or any(not isinstance(field, str) or not field for field in json_fields)
        ):
            raise LiveConformanceError(
                f"provider {provider_id} expected_attestation.json_fields "
                "must contain non-empty strings"
            )
        for field in json_fields:
            if any(not segment for segment in field.split(".")):
                raise LiveConformanceError(
                    f"provider {provider_id} expected_attestation JSON field path "
                    f"{field!r} is malformed"
                )


def url_has_credentials(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    return bool(parsed.username or parsed.password)


def parse_model_ids(raw: bytes) -> list[str]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveConformanceError(f"model list response is not valid JSON: {error}") from error

    candidates = payload.get("data")
    if candidates is None:
        candidates = payload.get("models")
    if not isinstance(candidates, list):
        raise LiveConformanceError("model list response must contain data[] or models[]")

    model_ids: list[str] = []
    for index, item in enumerate(candidates):
        if isinstance(item, str):
            model_id = item
        elif isinstance(item, dict):
            model_id = item.get("id") or item.get("model_id")
        else:
            raise LiveConformanceError(f"model list item {index} has unsupported shape")
        if not isinstance(model_id, str) or not model_id:
            raise LiveConformanceError(f"model list item {index} is missing a string id/model_id")
        model_ids.append(model_id)

    if len(model_ids) != len(set(model_ids)):
        raise LiveConformanceError("model list response contains duplicate model identifiers")
    return sorted(model_ids)


def load_model_alias_matrix(path: Path) -> ModelAliasMatrixSource:
    try:
        matrix = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LiveConformanceError(f"model alias matrix could not be loaded: {error}") from error
    if matrix.get("schema") != MODEL_ALIAS_MATRIX_SCHEMA:
        raise LiveConformanceError(
            f"model alias matrix has unsupported schema {matrix.get('schema')!r}"
        )
    models = matrix.get("models")
    if not isinstance(models, list):
        raise LiveConformanceError("model alias matrix must contain models[]")

    provider_models: dict[str, set[str]] = {}
    for model_index, model in enumerate(models):
        if not isinstance(model, dict):
            raise LiveConformanceError(f"model alias matrix models[{model_index}] must be an object")
        routes = model.get("provider_routes")
        if not isinstance(routes, list):
            raise LiveConformanceError(
                f"model alias matrix models[{model_index}].provider_routes must be a list"
            )
        for route_index, route in enumerate(routes):
            if not isinstance(route, dict):
                raise LiveConformanceError(
                    f"model alias matrix models[{model_index}].provider_routes[{route_index}] "
                    "must be an object"
                )
            provider = route.get("provider")
            provider_model = route.get("provider_model")
            if not isinstance(provider, str) or not provider:
                raise LiveConformanceError("model alias matrix provider_routes provider is missing")
            if not isinstance(provider_model, str) or not provider_model:
                raise LiveConformanceError(
                    "model alias matrix provider_routes provider_model is missing"
                )
            provider_models.setdefault(provider, set()).add(provider_model)

    digest = canonical_sha256_digest(matrix)
    return ModelAliasMatrixSource(
        path=path.as_posix(),
        digest=digest,
        payload=matrix,
        provider_models={
            provider: sorted(models_for_provider)
            for provider, models_for_provider in provider_models.items()
        },
    )


def load_model_alias_matrix_envelope(path: Path) -> ModelAliasMatrixEnvelopeSource:
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LiveConformanceError(
            f"model alias matrix envelope could not be loaded: {error}"
        ) from error
    if envelope.get("schema") != MODEL_ALIAS_MATRIX_ENVELOPE_SCHEMA:
        raise LiveConformanceError(
            "model alias matrix envelope has unsupported schema "
            f"{envelope.get('schema')!r}"
        )
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise LiveConformanceError("model alias matrix envelope payload must be an object")
    if payload.get("schema") != MODEL_ALIAS_MATRIX_SCHEMA:
        raise LiveConformanceError(
            "model alias matrix envelope payload has unsupported schema "
            f"{payload.get('schema')!r}"
        )
    signature = _validate_artifact_signature_metadata(
        "model alias matrix envelope",
        envelope.get("signature"),
    )
    _verify_artifact_signature("model alias matrix envelope", signature, payload)
    return ModelAliasMatrixEnvelopeSource(
        path=path.as_posix(),
        digest=canonical_sha256_digest(envelope),
        payload_digest=canonical_sha256_digest(payload),
        payload=payload,
        signature=signature,
    )


def load_compatibility_matrix(path: Path) -> CompatibilityMatrixSource:
    try:
        matrix = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LiveConformanceError(f"compatibility matrix could not be loaded: {error}") from error
    if matrix.get("schema") != COMPATIBILITY_SCHEMA:
        raise LiveConformanceError(
            f"compatibility matrix has unsupported schema {matrix.get('schema')!r}"
        )
    providers = matrix.get("providers")
    if not isinstance(providers, dict):
        raise LiveConformanceError("compatibility matrix must contain providers{}")

    profiles: dict[str, dict[str, Any]] = {}
    for provider_id, profile in providers.items():
        if not isinstance(provider_id, str) or not provider_id:
            raise LiveConformanceError(
                "compatibility matrix provider keys must be non-empty strings"
            )
        if not isinstance(profile, dict):
            raise LiveConformanceError(
                f"compatibility matrix provider {provider_id} must be an object"
            )
        _validate_compatibility_profile(provider_id, profile)
        profiles[provider_id] = profile

    return CompatibilityMatrixSource(
        path=path.as_posix(),
        digest=canonical_sha256_digest(matrix),
        payload=matrix,
        profiles=profiles,
    )


def load_compatibility_matrix_envelope(path: Path) -> CompatibilityMatrixEnvelopeSource:
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LiveConformanceError(
            f"compatibility matrix envelope could not be loaded: {error}"
        ) from error
    if envelope.get("schema") != COMPATIBILITY_ENVELOPE_SCHEMA:
        raise LiveConformanceError(
            "compatibility matrix envelope has unsupported schema "
            f"{envelope.get('schema')!r}"
        )
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise LiveConformanceError("compatibility matrix envelope payload must be an object")
    if payload.get("schema") != COMPATIBILITY_SCHEMA:
        raise LiveConformanceError(
            "compatibility matrix envelope payload has unsupported schema "
            f"{payload.get('schema')!r}"
        )
    signature = _validate_artifact_signature_metadata(
        "compatibility matrix envelope",
        envelope.get("signature"),
    )
    _verify_artifact_signature("compatibility matrix envelope", signature, payload)
    return CompatibilityMatrixEnvelopeSource(
        path=path.as_posix(),
        digest=canonical_sha256_digest(envelope),
        payload_digest=canonical_sha256_digest(payload),
        payload=payload,
        signature=signature,
    )


def _validate_artifact_signature_metadata(
    subject: str,
    signature: Any,
) -> dict[str, str]:
    if not isinstance(signature, dict):
        raise LiveConformanceError(f"{subject} signature must be an object")
    normalized: dict[str, str] = {}
    for field in ("signer", "key_id", "alg", "value"):
        value = signature.get(field)
        if not isinstance(value, str) or not value:
            raise LiveConformanceError(f"{subject} signature {field} must be non-empty")
        normalized[field] = value
    if normalized["alg"] != "ed25519":
        raise LiveConformanceError(f"{subject} signature alg must be ed25519")
    if not _is_base64url_ed25519_signature(normalized["value"]):
        raise LiveConformanceError(
            f"{subject} signature value must be an unpadded base64url "
            "64-byte ed25519 signature"
        )
    return normalized


def _is_base64url_ed25519_signature(value: str) -> bool:
    encoded = value[len(BASE64URL_PREFIX) :] if value.startswith(BASE64URL_PREFIX) else value
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


def _verify_artifact_signature(
    subject: str,
    signature: dict[str, str],
    payload: dict[str, Any],
) -> None:
    try:
        verify_artifact_signature(
            signature,
            canonical_json(payload).encode("utf-8"),
            subject,
        )
    except ArtifactSignatureError as error:
        raise LiveConformanceError(str(error)) from error


def validate_compatibility_matrix_envelope_matches_payload(
    compatibility_matrix_source: CompatibilityMatrixSource | None,
    compatibility_matrix_envelope_source: CompatibilityMatrixEnvelopeSource | None,
) -> None:
    if compatibility_matrix_source is None or compatibility_matrix_envelope_source is None:
        return
    if compatibility_matrix_envelope_source.payload != compatibility_matrix_source.payload:
        raise LiveConformanceError(
            "compatibility matrix envelope payload does not match compatibility_matrix_path"
        )


def _validate_compatibility_profile(provider_id: str, profile: dict[str, Any]) -> None:
    if profile.get("provider") != provider_id:
        raise LiveConformanceError(
            f"compatibility matrix provider key {provider_id} does not match "
            f"provider {profile.get('provider')!r}"
        )
    for field in COMPATIBILITY_REQUIRED_STRING_FIELDS:
        value = profile.get(field)
        if not isinstance(value, str) or not value:
            raise LiveConformanceError(
                f"compatibility matrix provider {provider_id} field {field} "
                "must be a non-empty string"
            )
        allowed = COMPATIBILITY_ENUM_VALUES.get(field)
        if allowed is not None and value not in allowed:
            raise LiveConformanceError(
                f"compatibility matrix provider {provider_id} field {field} "
                f"has unsupported value {value!r}"
            )
    for field in COMPATIBILITY_REQUIRED_LIST_FIELDS:
        values = profile.get(field)
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value for value in values)
        ):
            raise LiveConformanceError(
                f"compatibility matrix provider {provider_id} field {field} "
                "must contain strings"
            )
        if len(values) != len(set(values)):
            raise LiveConformanceError(
                f"compatibility matrix provider {provider_id} field {field} "
                "must not contain duplicates"
            )
        allowed_values = COMPATIBILITY_LIST_ENUM_VALUES.get(field)
        if allowed_values is not None:
            unsupported = sorted(set(values) - allowed_values)
            if unsupported:
                raise LiveConformanceError(
                    f"compatibility matrix provider {provider_id} field {field} "
                    f"has unsupported values {unsupported}"
                )
    if "chat_completions" not in profile["supported_openai_endpoints"]:
        raise LiveConformanceError(
            f"compatibility matrix provider {provider_id} must support chat_completions"
        )
    if (
        profile["streaming"] == "unsupported"
        and "streaming" not in profile["known_unsupported_modes"]
    ):
        raise LiveConformanceError(
            f"compatibility matrix provider {provider_id} must list streaming "
            "in known_unsupported_modes when streaming is unsupported"
        )
    if url_has_credentials(str(profile["api_base_url"])):
        raise LiveConformanceError(
            f"compatibility matrix provider {provider_id} api_base_url "
            "must not include URL credentials"
        )
    sdk_app_e2ee = profile.get("sdk_app_e2ee")
    if sdk_app_e2ee is not None and not isinstance(sdk_app_e2ee, dict):
        raise LiveConformanceError(
            f"compatibility matrix provider {provider_id} sdk_app_e2ee must be an object"
        )


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_JSON_INT:
            raise LiveConformanceError(
                f"JSON integer {value} exceeds the cross-language safe integer limit"
            )
        return str(value)
    if isinstance(value, float):
        raise LiveConformanceError("canonical JSON does not permit floating point numbers")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise LiveConformanceError("canonical JSON object keys must be strings")
        entries: list[str] = []
        for key in sorted(value, key=lambda item: item.encode("utf-8")):
            entries.append(
                json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                + ":"
                + canonical_json(value[key])
            )
        return "{" + ",".join(entries) + "}"
    raise LiveConformanceError(f"canonical JSON does not support {type(value).__name__}")


def canonical_sha256_digest(value: Any) -> str:
    encoded = canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def raw_sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def http_response_metadata(url: str, result: HttpResult) -> dict[str, Any]:
    return {
        "url": url,
        "status": result.status,
        "content_type": result.headers.get("content-type", ""),
        "body_size": len(result.body),
        "body_sha256": raw_sha256_digest(result.body),
    }


def _expected_model_ids(
    provider: dict[str, Any],
    alias_matrix_source: ModelAliasMatrixSource | None,
) -> list[str]:
    if provider.get("expected_model_ids") is not None:
        return sorted(str(model) for model in provider.get("expected_model_ids", []))
    if provider.get("expected_model_ids_from_alias_matrix"):
        provider_id = str(provider.get("id") or "")
        if alias_matrix_source is None:
            raise LiveConformanceError(
                f"provider {provider_id} imports expected model IDs but no alias matrix is loaded"
            )
        expected = alias_matrix_source.provider_models.get(provider_id, [])
        if not expected:
            raise LiveConformanceError(
                f"provider {provider_id} has no provider_routes in the model alias matrix"
            )
        return expected
    return []


def _expected_model_ids_source(provider: dict[str, Any]) -> str:
    if provider.get("expected_model_ids_from_alias_matrix"):
        return "model_alias_matrix"
    if provider.get("expected_model_ids") is not None:
        return "plan"
    return "none"


def validate_alias_matrix_imports(
    plan: dict[str, Any],
    alias_matrix_source: ModelAliasMatrixSource | None,
) -> None:
    for provider in plan.get("providers", []):
        if isinstance(provider, dict) and provider.get("expected_model_ids_from_alias_matrix"):
            _expected_model_ids(provider, alias_matrix_source)


def validate_model_alias_matrix_envelope_matches_payload(
    alias_matrix_source: ModelAliasMatrixSource | None,
    alias_matrix_envelope_source: ModelAliasMatrixEnvelopeSource | None,
) -> None:
    if alias_matrix_source is None or alias_matrix_envelope_source is None:
        return
    if alias_matrix_envelope_source.payload != alias_matrix_source.payload:
        raise LiveConformanceError(
            "model alias matrix envelope payload does not match model_alias_matrix_path"
        )


def validate_compatibility_imports(
    plan: dict[str, Any],
    compatibility_matrix_source: CompatibilityMatrixSource | None,
) -> None:
    for provider in plan.get("providers", []):
        if not isinstance(provider, dict) or not provider.get("compatibility_provider"):
            continue
        _compatibility_profile(provider, compatibility_matrix_source)


def _compatibility_profile(
    provider: dict[str, Any],
    compatibility_matrix_source: CompatibilityMatrixSource | None,
) -> dict[str, Any] | None:
    compatibility_provider = provider.get("compatibility_provider")
    if compatibility_provider is None:
        return None
    provider_id = str(provider.get("id") or "")
    if compatibility_matrix_source is None:
        raise LiveConformanceError(
            f"provider {provider_id} declares compatibility_provider but no "
            "compatibility matrix is loaded"
        )
    if compatibility_provider not in compatibility_matrix_source.profiles:
        raise LiveConformanceError(
            f"provider {provider_id} compatibility_provider {compatibility_provider!r} "
            "is missing from the compatibility matrix"
        )
    return compatibility_matrix_source.provider_report_metadata(str(compatibility_provider))


def _auth_headers(provider: dict[str, Any]) -> tuple[dict[str, str], str | None]:
    auth_env = provider.get("auth_env")
    if not auth_env:
        return {}, None
    token = os.environ.get(str(auth_env))
    if not token:
        return {}, str(auth_env)
    return {"Authorization": f"Bearer {token}"}, None


def _check_attestation_shape(
    provider: dict[str, Any],
    result: HttpResult,
) -> tuple[bool, list[str]]:
    expected = provider.get("expected_attestation") or {}
    failures: list[str] = []

    expected_content = expected.get("content_type_contains")
    content_type = result.headers.get("content-type", "")
    if expected_content and str(expected_content).lower() not in content_type.lower():
        failures.append(f"content-type {content_type!r} does not contain {expected_content!r}")

    json_fields = expected.get("json_fields") or []
    if json_fields:
        try:
            payload = json.loads(result.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            failures.append(f"attestation response is not valid JSON: {error}")
        else:
            for field in json_fields:
                if not _json_path_exists(payload, str(field)):
                    failures.append(f"attestation response missing JSON field {field!r}")

    return not failures, failures


def _json_path_exists(payload: Any, field_path: str) -> bool:
    current = payload
    for segment in field_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return False
        current = current[segment]
    return True


def _provider_report(
    provider: dict[str, Any],
    http: HttpClient,
    allow_network: bool,
    timeout_seconds: float,
    alias_matrix_source: ModelAliasMatrixSource | None,
    compatibility_matrix_source: CompatibilityMatrixSource | None,
    enabled_provider_overrides: set[str],
    enable_all_providers: bool,
) -> dict[str, Any]:
    provider_id = str(provider.get("id") or "")
    if not provider_id:
        return {"provider": provider_id, "status": "invalid_plan", "errors": ["missing provider id"]}
    expected_model_ids_source = _expected_model_ids_source(provider)
    expected_model_ids = _expected_model_ids(provider, alias_matrix_source)
    compatibility_profile = _compatibility_profile(provider, compatibility_matrix_source)
    configured_enabled = bool(provider.get("enabled", False))
    enabled_by_override = (
        not configured_enabled
        and (enable_all_providers or provider_id in enabled_provider_overrides)
    )
    auth_env = provider.get("auth_env")
    auth_env_name = str(auth_env) if auth_env else None
    base_report = {
        "provider": provider_id,
        "configured_enabled": configured_enabled,
        "enabled_by_override": enabled_by_override,
        "auth_env": auth_env_name,
        "credential_source": "env" if auth_env_name else "none",
        "expected_model_ids": expected_model_ids,
        "expected_model_ids_source": expected_model_ids_source,
    }
    if compatibility_profile is not None:
        base_report["compatibility_profile"] = compatibility_profile
    if not expected_model_ids:
        return {
            **base_report,
            "status": "invalid_plan",
            "live_checked": False,
            "credential_configured": False,
            "errors": [
                "expected_model_ids must contain at least one model from the "
                "plan or model alias matrix"
            ],
        }
    if not configured_enabled and not enabled_by_override:
        return {
            **base_report,
            "status": "skipped_disabled",
            "live_checked": False,
            "credential_configured": False,
        }
    if not allow_network:
        return {
            **base_report,
            "status": "skipped_network_disabled",
            "live_checked": False,
            "credential_configured": False,
        }

    headers, missing_env = _auth_headers(provider)
    if missing_env:
        return {
            **base_report,
            "status": "skipped_missing_auth_env",
            "auth_env": missing_env,
            "credential_configured": False,
            "live_checked": False,
        }

    started = time.monotonic()
    errors: list[str] = []
    observed_model_ids: list[str] = []
    new_unverified: list[str] = []
    removed: list[str] = []
    attestation_ok: bool | None = None
    attestation_errors: list[str] = []
    model_list_response: dict[str, Any] | None = None
    attestation_response_metadata: dict[str, Any] | None = None

    try:
        model_list_url = str(provider["model_list_url"])
        model_response = http.get(model_list_url, headers, timeout_seconds)
        model_list_response = http_response_metadata(model_list_url, model_response)
        if model_response.status < 200 or model_response.status >= 300:
            errors.append(f"model list returned HTTP {model_response.status}")
        else:
            observed_model_ids = parse_model_ids(model_response.body)
            new_unverified = sorted(set(observed_model_ids) - set(expected_model_ids))
            removed = sorted(set(expected_model_ids) - set(observed_model_ids))
    except (KeyError, urllib.error.URLError, TimeoutError, OSError, LiveConformanceError) as error:
        errors.append(f"model list failed: {error}")

    if provider.get("attestation_url"):
        try:
            attestation_url = str(provider["attestation_url"])
            attestation_response = http.get(attestation_url, headers, timeout_seconds)
            attestation_response_metadata = http_response_metadata(
                attestation_url,
                attestation_response,
            )
            if attestation_response.status < 200 or attestation_response.status >= 300:
                attestation_ok = False
                attestation_errors.append(f"attestation endpoint returned HTTP {attestation_response.status}")
            else:
                attestation_ok, attestation_errors = _check_attestation_shape(
                    provider, attestation_response
                )
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            attestation_ok = False
            attestation_errors.append(f"attestation endpoint failed: {error}")

    drift = bool(new_unverified or removed)
    status = "passed"
    if errors or attestation_errors:
        status = "failed"
    elif drift:
        status = "drift"

    return {
        **base_report,
        "status": status,
        "live_checked": True,
        "credential_configured": bool(auth_env_name),
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
        "observed_model_ids": observed_model_ids,
        "new_unverified": new_unverified,
        "removed": removed,
        "model_list_response": model_list_response,
        "attestation_response": attestation_response_metadata,
        "attestation_shape_ok": attestation_ok,
        "attestation_errors": attestation_errors,
        "errors": errors,
    }


def run_conformance(
    plan: dict[str, Any],
    http: HttpClient | None = None,
    allow_network: bool = False,
    timeout_seconds: float = 10.0,
    enable_providers: set[str] | None = None,
    enable_all_providers: bool = False,
) -> dict[str, Any]:
    validate_plan(plan)
    http = http or HttpClient()
    completed_at = datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    enabled_provider_overrides = set(enable_providers or set())
    provider_ids = {
        str(provider.get("id"))
        for provider in plan.get("providers", [])
        if isinstance(provider, dict) and provider.get("id")
    }
    unknown_overrides = sorted(enabled_provider_overrides - provider_ids)
    if unknown_overrides:
        raise LiveConformanceError(
            "enabled provider override references unknown provider(s): "
            + ", ".join(unknown_overrides)
        )
    alias_matrix_source = None
    if plan.get("model_alias_matrix_path"):
        alias_matrix_source = load_model_alias_matrix(Path(str(plan["model_alias_matrix_path"])))
    alias_matrix_envelope_source = None
    if plan.get("model_alias_matrix_envelope_path"):
        alias_matrix_envelope_source = load_model_alias_matrix_envelope(
            Path(str(plan["model_alias_matrix_envelope_path"]))
        )
    compatibility_matrix_source = None
    if plan.get("compatibility_matrix_path"):
        compatibility_matrix_source = load_compatibility_matrix(
            Path(str(plan["compatibility_matrix_path"]))
        )
    compatibility_matrix_envelope_source = None
    if plan.get("compatibility_matrix_envelope_path"):
        compatibility_matrix_envelope_source = load_compatibility_matrix_envelope(
            Path(str(plan["compatibility_matrix_envelope_path"]))
        )
    validate_alias_matrix_imports(plan, alias_matrix_source)
    validate_model_alias_matrix_envelope_matches_payload(
        alias_matrix_source,
        alias_matrix_envelope_source,
    )
    validate_compatibility_matrix_envelope_matches_payload(
        compatibility_matrix_source,
        compatibility_matrix_envelope_source,
    )
    validate_compatibility_imports(plan, compatibility_matrix_source)
    providers = [
        _provider_report(
            provider,
            http,
            allow_network,
            timeout_seconds,
            alias_matrix_source,
            compatibility_matrix_source,
            enabled_provider_overrides,
            enable_all_providers,
        )
        for provider in plan.get("providers", [])
    ]
    failed = sum(1 for provider in providers if provider["status"] == "failed")
    drift = sum(1 for provider in providers if provider["status"] == "drift")
    skipped = sum(1 for provider in providers if str(provider["status"]).startswith("skipped"))
    passed = sum(1 for provider in providers if provider["status"] == "passed")
    live_checked = sum(1 for provider in providers if provider.get("live_checked") is True)
    remaining_live_provider_ids = sorted(
        str(provider["provider"])
        for provider in providers
        if provider.get("live_checked") is not True
    )
    live_gate_status = (
        "passed"
        if providers and live_checked == len(providers) and failed == 0 and drift == 0
        else "open"
    )
    return {
        "schema": SCHEMA,
        "plan_schema": plan.get("schema"),
        "completed_at": completed_at,
        "network_enabled": allow_network,
        "provider_enable_overrides": {
            "all": enable_all_providers,
            "providers": sorted(enabled_provider_overrides),
        },
        "model_alias_matrix": (
            alias_matrix_source.report_metadata() if alias_matrix_source else None
        ),
        "model_alias_matrix_envelope": (
            alias_matrix_envelope_source.report_metadata()
            if alias_matrix_envelope_source
            else None
        ),
        "compatibility_matrix": (
            compatibility_matrix_source.report_metadata()
            if compatibility_matrix_source
            else None
        ),
        "compatibility_matrix_envelope": (
            compatibility_matrix_envelope_source.report_metadata()
            if compatibility_matrix_envelope_source
            else None
        ),
        "summary": {
            "providers": len(providers),
            "passed": passed,
            "drift": drift,
            "failed": failed,
            "skipped": skipped,
            "live_checked": live_checked,
        },
        "credentialed_live_gate": {
            "status": live_gate_status,
            "required_for_production": True,
            "remaining_provider_ids": remaining_live_provider_ids,
        },
        "providers": providers,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan",
        type=Path,
        default=Path("fixtures/providers/live-conformance-plan.json"),
        help="Live conformance plan JSON.",
    )
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="Actually call configured live provider endpoints.",
    )
    parser.add_argument(
        "--enable-provider",
        action="append",
        default=[],
        metavar="ID",
        help=(
            "Enable a provider that is disabled in the plan. May be supplied "
            "multiple times. Network requests still require --allow-network."
        ),
    )
    parser.add_argument(
        "--enable-all-providers",
        action="store_true",
        help=(
            "Enable all providers disabled in the plan for this run. Network "
            "requests still require --allow-network."
        ),
    )
    parser.add_argument(
        "--allow-drift",
        action="store_true",
        help="Exit successfully when only model-list drift is observed.",
    )
    parser.add_argument(
        "--require-credentialed-live-gate",
        action="store_true",
        help=(
            "Exit non-zero unless credentialed_live_gate.status is passed. "
            "Use this for production live canaries; network-disabled dry runs "
            "intentionally fail this gate."
        ),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=10.0,
        help="Per-request timeout.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional report JSON output path.",
    )
    args = parser.parse_args(argv)

    try:
        plan = load_plan(args.plan)
        report = run_conformance(
            plan,
            allow_network=args.allow_network,
            timeout_seconds=args.timeout_seconds,
            enable_providers=set(args.enable_provider),
            enable_all_providers=args.enable_all_providers,
        )
    except (OSError, json.JSONDecodeError, LiveConformanceError) as error:
        print(f"live_conformance.py: {error}", file=sys.stderr)
        return 1

    rendered = json.dumps(report, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")

    failed = report["summary"]["failed"]
    drift = report["summary"]["drift"]
    if failed:
        return 1
    if drift and not args.allow_drift:
        return 2
    if (
        args.require_credentialed_live_gate
        and report["credentialed_live_gate"]["status"] != "passed"
    ):
        remaining = ", ".join(report["credentialed_live_gate"]["remaining_provider_ids"])
        print(
            "live_conformance.py: credentialed live gate is open"
            + (f"; remaining providers: {remaining}" if remaining else ""),
            file=sys.stderr,
        )
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
