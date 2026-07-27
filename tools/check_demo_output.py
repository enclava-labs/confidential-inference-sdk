#!/usr/bin/env python3
"""Validate the local confidential-demo transcript evidence markers."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from artifact_signatures import (  # noqa: E402
    ArtifactSignatureError,
    TrustedSigningKey,
    verify_artifact_signature,
)

SCHEMA = "confidential-inference.demo-output-policy.v1"
LABEL_RE = re.compile(r"^(?P<label>[A-Za-z0-9_]+): (?P<value>.*)$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_SAFE_JSON_INT = 9_007_199_254_740_991

LOCAL_DEMO_TRUSTED_SIGNING_KEYS = (
    TrustedSigningKey(
        signer="confidential-inference-local-demo",
        key_id="confidential-inference-local-demo-ed25519-2026",
        public_key_base64url="kaKKC3Q4FZOk2UaVeSCJJq_IrYLIg5t2RDWbnrqaSzo",
    ),
)

REQUIRED_LABELS = {
    "ffi_status_async_handle_abi_available": "true",
    "ffi_status_callbacks_available": "true",
    "ffi_status_stream_handle_abi_available": "true",
    "ffi_status_blocking_helpers_available": "true",
    "ffi_status_reason_contains_core_surfaces": "true",
    "provider": "demo",
    "provider_model": "e2ee-gpt-oss-120b-p",
    "active_policy_schema": "confidential-inference.active-policy.v1",
    "active_policy_artifact": "target/confidential-demo-active-policy.json",
    "active_trust_artifacts_artifact": (
        "target/confidential-demo-active-trust-artifacts.json"
    ),
    "active_registry_schema": "confidential-inference.provider-registry.v1",
    "active_reference_values_schema": "confidential-inference.reference-values.v1",
    "active_registry_signature_value_base64url": "true",
    "active_reference_values_signature_value_base64url": "true",
    "metrics_log": "target/confidential-demo-metrics.jsonl",
    "audit_log": "target/confidential-demo-audit.jsonl",
    "primary_verdict_store": "target/confidential-demo-verdicts.jsonl",
    "metrics_otlp_http_posted": "true",
    "verified_route_model_mismatch_rejected": "true",
    "tampered_registry_rejected": "true",
    "tampered_reference_values_rejected": "true",
    "signed_invalid_registry_metadata_rejected": "true",
    "signed_invalid_reference_validity_rejected": "true",
    "proxy_chat_status": "200",
    "proxy_chat_body_model": '"e2ee-gpt-oss-120b-p"',
    "proxy_body_without_verdict": "true",
    "proxy_sidecar_prompt_redacted": "true",
    "proxy_verdict_status": "Verified",
    "proxy_route_execution_status": "executable_fixture",
    "proxy_chat_executable": "true",
    "proxy_models_contains_demo_model": "true",
    "proxy_confidentiality_chat_executable": "true",
    "proxy_confidentiality_unsupported_modes": '["streaming"]',
    "proxy_attestation_status": "Verified",
    "proxy_verdict_store": "target/confidential-demo-proxy-verdicts.jsonl",
    "phase2_tinfoil_provider": "tinfoil-fixture",
    "phase2_tinfoil_route_id": "tinfoil-fixture:llama-3.3-70b:llama-3.3-70b",
    "phase2_tinfoil_requested_model": "llama-3.3-70b",
    "phase2_tinfoil_provider_model": "llama-3.3-70b",
    "phase2_tinfoil_canonical_model": "llama-3.3-70b",
    "phase2_tinfoil_trust_tier": "hw-verified-tls",
    "phase2_tinfoil_evidence_family": "tinfoil_hw_verified_tls",
    "phase2_tinfoil_channel_binding_kind": "tee_terminated_tls",
    "phase2_tinfoil_request_confidentiality_result": "channel_bound",
    "phase2_tinfoil_response_confidentiality_result": "channel_bound",
    "phase2_tinfoil_response_integrity_result": "channel_bound",
    "phase2_tinfoil_route_execution_status": "executable_fixture",
    "phase2_tinfoil_chat_executable": "true",
    "phase2_tinfoil_registry_source": "custom",
    "phase2_tinfoil_reference_values_source": "custom",
    "phase2_tinfoil_registry_signature_signer": "confidential-inference",
    "phase2_tinfoil_reference_values_signature_signer": "confidential-inference",
    "phase2_tinfoil_tls_binding": "Some(Verified)",
    "phase2_venice_provider": "venice-fixture",
    "phase2_venice_route_id": "venice-fixture:gpt-oss-120b:e2ee-gpt-oss-120b-p",
    "phase2_venice_requested_model": "gpt-oss-120b",
    "phase2_venice_provider_model": "e2ee-gpt-oss-120b-p",
    "phase2_venice_canonical_model": "gpt-oss-120b",
    "phase2_venice_trust_tier": "tee-only",
    "phase2_venice_evidence_family": "dstack_app_e2ee",
    "phase2_venice_channel_binding_kind": "attested_app_e2ee",
    "phase2_venice_request_confidentiality_result": "unknown",
    "phase2_venice_response_confidentiality_result": "unknown",
    "phase2_venice_response_integrity_result": "unknown",
    "phase2_venice_route_execution_status": "verification_only",
    "phase2_venice_chat_executable": "false",
    "phase2_venice_registry_source": "custom",
    "phase2_venice_reference_values_source": "custom",
    "phase2_venice_registry_signature_signer": "confidential-inference",
    "phase2_venice_reference_values_signature_signer": "confidential-inference",
    "phase2_venice_tcb_binding": "Some(Verified)",
    "phase2_venice_e2ee_binding": "Some(NotApplicable)",
    "phase2_venice_model_binding": "Some(Verified)",
    "phase2_venice_chat_blocked": "true",
    "phase2_fixture_verdict_store": "target/confidential-demo-phase2-fixture-verdicts.jsonl",
    "local_sdk_app_e2ee_provider": "local-sdk-app-e2ee",
    "local_sdk_app_e2ee_route_id": "local-sdk-app-e2ee:gpt-oss-120b:e2ee-gpt-oss-120b-p",
    "local_sdk_app_e2ee_requested_model": "gpt-oss-120b",
    "local_sdk_app_e2ee_provider_model": "e2ee-gpt-oss-120b-p",
    "local_sdk_app_e2ee_canonical_model": "gpt-oss-120b",
    "local_sdk_app_e2ee_trust_tier": "tee-only",
    "local_sdk_app_e2ee_evidence_family": "dstack_app_e2ee",
    "local_sdk_app_e2ee_channel_binding_kind": "attested_app_e2ee",
    "local_sdk_app_e2ee_request_confidentiality_result": "unknown",
    "local_sdk_app_e2ee_response_confidentiality_result": "unknown",
    "local_sdk_app_e2ee_response_integrity_result": "unknown",
    "local_sdk_app_e2ee_route_execution_status": "executable",
    "local_sdk_app_e2ee_chat_executable": "true",
    "local_sdk_app_e2ee_registry_source": "custom",
    "local_sdk_app_e2ee_reference_values_source": "custom",
    "local_sdk_app_e2ee_registry_signature_signer": "confidential-inference-local-demo",
    "local_sdk_app_e2ee_reference_values_signature_signer": "confidential-inference-local-demo",
    "local_sdk_app_e2ee_request_encryption": "Some(NotApplicable)",
    "local_sdk_app_e2ee_response_encryption": "Some(NotApplicable)",
    "local_sdk_app_e2ee_model_binding": "Some(Verified)",
    "local_sdk_app_e2ee_e2ee_key_binding": "Some(NotApplicable)",
    "local_sdk_app_e2ee_image_provenance": "Some(Verified)",
    "local_sdk_app_e2ee_model_artifact_provenance": "Some(Verified)",
    "local_sdk_app_e2ee_verdict_store": (
        "target/confidential-demo-local-sdk-app-e2ee-verdicts.jsonl"
    ),
    "local_sdk_app_e2ee_registry_artifact": (
        "target/confidential-demo-local-sdk-app-e2ee-registry.json"
    ),
    "local_sdk_app_e2ee_compatibility_matrix_artifact": (
        "target/confidential-demo-local-sdk-app-e2ee-compatibility-matrix.json"
    ),
    "local_sdk_app_e2ee_reference_values_artifact": (
        "target/confidential-demo-local-sdk-app-e2ee-reference-values.json"
    ),
    "local_live_tinfoil_provider": "local-tinfoil-live",
    "local_live_tinfoil_route_id": "local-tinfoil-live:llama-3.3-70b:llama-3.3-70b",
    "local_live_tinfoil_requested_model": "llama-3.3-70b",
    "local_live_tinfoil_provider_model": "llama-3.3-70b",
    "local_live_tinfoil_canonical_model": "llama-3.3-70b",
    "local_live_tinfoil_trust_tier": "hw-verified-tls",
    "local_live_tinfoil_evidence_family": "tinfoil_hw_verified_tls",
    "local_live_tinfoil_channel_binding_kind": "tee_terminated_tls",
    "local_live_tinfoil_request_confidentiality_result": "channel_bound",
    "local_live_tinfoil_response_confidentiality_result": "channel_bound",
    "local_live_tinfoil_response_integrity_result": "channel_bound",
    "local_live_tinfoil_route_execution_status": "executable",
    "local_live_tinfoil_chat_executable": "true",
    "local_live_tinfoil_registry_source": "custom",
    "local_live_tinfoil_reference_values_source": "custom",
    "local_live_tinfoil_registry_signature_signer": "confidential-inference-local-demo",
    "local_live_tinfoil_reference_values_signature_signer": "confidential-inference-local-demo",
    "local_live_tinfoil_tls_binding": "Some(Verified)",
    "local_live_tinfoil_model_binding": "Some(Verified)",
    "local_live_tinfoil_image_provenance": "Some(Verified)",
    "local_live_tinfoil_model_artifact_provenance": "Some(Verified)",
    "local_live_tinfoil_verdict_store": "target/confidential-demo-local-live-verdicts.jsonl",
    "local_live_tinfoil_registry_artifact": (
        "target/confidential-demo-local-live-registry.json"
    ),
    "local_live_tinfoil_compatibility_matrix_artifact": (
        "target/confidential-demo-local-live-compatibility-matrix.json"
    ),
    "local_live_tinfoil_reference_values_artifact": (
        "target/confidential-demo-local-live-reference-values.json"
    ),
}

BOOLEAN_LABELS = {
    "ffi_status_readiness_fd_available",
}

MIN_NUMERIC_LABELS = {
    "metrics_events": 1,
    "metrics_cache_hits": 1,
    "metrics_verdicts": 1,
    "metrics_jsonl_records": 1,
    "cached_verify_samples": 32,
    "cached_verify_p95_ms": 0,
    "metrics_prometheus_lines": 1,
    "metrics_otlp_resource_metrics": 1,
    "metrics_otlp_scope_metrics": 1,
    "metrics_otlp_metrics": 1,
    "metrics_otlp_data_points": 1,
    "audit_records": 1,
    "primary_persisted_verdicts": 2,
    "proxy_models_count": 1,
    "proxy_persisted_verdicts": 3,
    "phase2_fixture_persisted_verdicts": 4,
    "local_sdk_app_e2ee_persisted_verdicts": 2,
    "local_live_tinfoil_persisted_verdicts": 2,
}

EXACT_NUMERIC_LABELS = {
    "metrics_streaming_fail_closed": 1,
}

REQUIRED_SUBSTRINGS = (
    "response: demo confidential response for e2ee-gpt-oss-120b-p: "
    "verify the confidential inference SDK path",
    "phase2_tinfoil_response: tinfoil fixture response for llama-3.3-70b: "
    "verify the signed Tinfoil fixture path",
    "local_sdk_app_e2ee_response: local SDK app-E2EE response for "
    "e2ee-gpt-oss-120b-p: verify the local SDK app-E2EE path",
    "local_live_tinfoil_response: local live Tinfoil response for "
    "llama-3.3-70b: verify the local live TLS path",
)

REQUIRED_VERDICT_VALUES = {
    "schema": "confidential-inference.verdict.v1",
    "policy_schema": "confidential-inference.policy.v1",
    "reference_values_schema": "confidential-inference.reference-values.v1",
    "provider_registry_schema": "confidential-inference.provider-registry.v1",
    "status": "verified",
    "enforcement": "enforce",
    "request_allowed": True,
    "would_block_under_enforce": False,
    "trust_tier": "app-e2ee",
    "provider": "demo",
    "requested_model": "gpt-oss-120b",
    "provider_model": "e2ee-gpt-oss-120b-p",
    "canonical_model": "gpt-oss-120b",
    "route_execution_status": "executable_fixture",
    "streaming_allowed": False,
    "chat_executable": True,
    "channel_binding_kind": "attested_app_e2ee",
    "model_binding_result": "verified",
    "request_channel_bound": True,
    "request_confidentiality_result": "encrypted_bound",
    "response_confidentiality_result": "encrypted_bound",
    "response_channel_bound": True,
    "response_integrity_result": "channel_bound",
}

REQUIRED_VERDICT_DIGESTS = (
    "policy_digest",
    "provider_registry_digest",
    "reference_values_digest",
    "raw_evidence_digest",
    "evidence_digest",
)

REQUIRED_CHECKS = {
    "cpu_tee": "verified",
    "e2ee_key_binding": "verified",
    "model_binding": "verified",
    "request_encryption": "verified",
    "request_key_binding": "verified",
    "response_channel_binding": "verified",
    "response_encryption": "verified",
    "response_key_binding": "verified",
    "request_route_binding": "not_supported",
    "route_binding": "not_supported",
    "route_metadata_binding": "verified",
}
DEMO_SIGNATURE = {
    "signer": "confidential-inference",
    "key_id": "confidential-inference-demo-ed25519-2026",
    "alg": "ed25519",
}
PROXY_EXPECTED_VALUES = {
    "provider": "demo",
    "route_id": "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p",
    "requested_model": "gpt-oss-120b",
    "provider_model": "e2ee-gpt-oss-120b-p",
    "canonical_model": "gpt-oss-120b",
    "status": "verified",
    "enforcement": "enforce",
    "request_allowed": True,
    "would_block_under_enforce": False,
    "freshness_class": "per_session",
    "route_execution_status": "executable_fixture",
    "chat_executable": True,
    "streaming_allowed": False,
}
PROXY_VERDICT_VALUES = {
    "schema": "confidential-inference.verdict.v1",
    "policy_schema": "confidential-inference.policy.v1",
    "reference_values_schema": "confidential-inference.reference-values.v1",
    "provider_registry_schema": "confidential-inference.provider-registry.v1",
    "trust_tier": "app-e2ee",
    "evidence_family": "fixture_dstack",
    "adapter_version": "demo-fixture-adapter/0.1.0",
    "alias_confidence": "curated",
    "channel_binding_kind": "attested_app_e2ee",
    "model_binding_result": "verified",
    "request_channel_bound": True,
    "request_confidentiality_result": "encrypted_bound",
    "response_confidentiality_result": "encrypted_bound",
    "response_channel_bound": True,
    "response_integrity_result": "channel_bound",
    "registry_source": "bundled",
    "reference_values_source": "bundled",
}
PROXY_TRANSCRIPT_FIELDS = {
    "proxy_verdict_provider": "provider",
    "proxy_verdict_route_id": "route_id",
    "proxy_verdict_requested_model": "requested_model",
    "proxy_verdict_provider_model": "provider_model",
    "proxy_verdict_canonical_model": "canonical_model",
    "proxy_verdict_policy_digest": "policy_digest",
    "proxy_verdict_provider_registry_digest": "provider_registry_digest",
    "proxy_verdict_reference_values_digest": "reference_values_digest",
    "proxy_verdict_request_confidentiality_result": "request_confidentiality_result",
    "proxy_verdict_response_confidentiality_result": "response_confidentiality_result",
    "proxy_verdict_response_integrity_result": "response_integrity_result",
    "proxy_route_execution_status": "route_execution_status",
    "proxy_chat_executable": "chat_executable",
    "proxy_attestation_route_id": "route_id",
    "proxy_attestation_policy_digest": "policy_digest",
    "proxy_attestation_provider_registry_digest": "provider_registry_digest",
    "proxy_attestation_reference_values_digest": "reference_values_digest",
    "proxy_attestation_request_confidentiality_result": "request_confidentiality_result",
    "proxy_attestation_response_confidentiality_result": "response_confidentiality_result",
    "proxy_attestation_response_integrity_result": "response_integrity_result",
    "proxy_confidentiality_route_id": "route_id",
    "proxy_confidentiality_chat_executable": "chat_executable",
}
PROXY_REQUIRED_ARTIFACTS = (
    "source_url",
    "tee_measurement",
    "report_data",
    "e2ee_capability",
    "model_manifest",
    "model_artifacts",
)
PHASE2_FIXTURE_SIGNATURE = {
    "signer": "confidential-inference",
    "key_id": "confidential-inference-phase2-fixture-ed25519-2026",
    "alg": "ed25519",
}
PHASE2_TINFOIL_EXPECTED_VALUES = {
    "provider": "tinfoil-fixture",
    "route_id": "tinfoil-fixture:llama-3.3-70b:llama-3.3-70b",
    "requested_model": "llama-3.3-70b",
    "provider_model": "llama-3.3-70b",
    "canonical_model": "llama-3.3-70b",
    "status": "verified",
    "enforcement": "enforce",
    "request_allowed": True,
    "would_block_under_enforce": False,
    "freshness_class": "per_session",
    "route_execution_status": "executable_fixture",
    "chat_executable": True,
    "streaming_allowed": False,
}
PHASE2_TINFOIL_VERDICT_VALUES = {
    "schema": "confidential-inference.verdict.v1",
    "policy_schema": "confidential-inference.policy.v1",
    "reference_values_schema": "confidential-inference.reference-values.v1",
    "provider_registry_schema": "confidential-inference.provider-registry.v1",
    "trust_tier": "hw-verified-tls",
    "evidence_family": "tinfoil_hw_verified_tls",
    "adapter_version": "tinfoil-fixture-adapter/0.1.0",
    "alias_confidence": "curated",
    "channel_binding_kind": "tee_terminated_tls",
    "model_binding_result": "not_supported",
    "request_channel_bound": True,
    "request_confidentiality_result": "channel_bound",
    "response_confidentiality_result": "channel_bound",
    "response_channel_bound": True,
    "response_integrity_result": "channel_bound",
    "registry_source": "custom",
    "reference_values_source": "custom",
}
PHASE2_TINFOIL_REQUIRED_CHECKS = {
    "cpu_tee": "verified",
    "e2ee_key_binding": "not_applicable",
    "model_binding": "not_applicable",
    "request_encryption": "verified",
    "request_key_binding": "verified",
    "response_channel_binding": "verified",
    "response_encryption": "verified",
    "response_key_binding": "verified",
    "request_route_binding": "not_supported",
    "route_binding": "not_supported",
    "route_metadata_binding": "verified",
    "tls_binding": "verified",
}
PHASE2_TINFOIL_TRANSCRIPT_FIELDS = {
    "phase2_tinfoil_provider": "provider",
    "phase2_tinfoil_route_id": "route_id",
    "phase2_tinfoil_requested_model": "requested_model",
    "phase2_tinfoil_provider_model": "provider_model",
    "phase2_tinfoil_canonical_model": "canonical_model",
    "phase2_tinfoil_trust_tier": "trust_tier",
    "phase2_tinfoil_evidence_family": "evidence_family",
    "phase2_tinfoil_channel_binding_kind": "channel_binding_kind",
    "phase2_tinfoil_request_confidentiality_result": "request_confidentiality_result",
    "phase2_tinfoil_response_confidentiality_result": "response_confidentiality_result",
    "phase2_tinfoil_response_integrity_result": "response_integrity_result",
    "phase2_tinfoil_route_execution_status": "route_execution_status",
    "phase2_tinfoil_chat_executable": "chat_executable",
    "phase2_tinfoil_policy_digest": "policy_digest",
    "phase2_tinfoil_provider_registry_digest": "provider_registry_digest",
    "phase2_tinfoil_reference_values_digest": "reference_values_digest",
    "phase2_tinfoil_registry_source": "registry_source",
    "phase2_tinfoil_reference_values_source": "reference_values_source",
}
PHASE2_TINFOIL_REQUIRED_ARTIFACTS = (
    "source_url",
    "tee_measurement",
    "report_data",
    "signing_public_key",
    "model_manifest",
    "model_artifacts",
)
PHASE2_VENICE_EXPECTED_VALUES = {
    "provider": "venice-fixture",
    "route_id": "venice-fixture:gpt-oss-120b:e2ee-gpt-oss-120b-p",
    "requested_model": "gpt-oss-120b",
    "provider_model": "e2ee-gpt-oss-120b-p",
    "canonical_model": "gpt-oss-120b",
    "status": "verified",
    "enforcement": "enforce",
    "request_allowed": True,
    "would_block_under_enforce": False,
    "freshness_class": "per_session",
    "route_execution_status": "verification_only",
    "chat_executable": False,
    "streaming_allowed": False,
}
PHASE2_VENICE_VERDICT_VALUES = {
    "schema": "confidential-inference.verdict.v1",
    "policy_schema": "confidential-inference.policy.v1",
    "reference_values_schema": "confidential-inference.reference-values.v1",
    "provider_registry_schema": "confidential-inference.provider-registry.v1",
    "trust_tier": "tee-only",
    "evidence_family": "dstack_app_e2ee",
    "adapter_version": "venice-dstack-fixture-adapter/0.1.0",
    "alias_confidence": "curated",
    "channel_binding_kind": "attested_app_e2ee",
    "model_binding_result": "verified",
    "request_channel_bound": False,
    "request_confidentiality_result": "unknown",
    "response_confidentiality_result": "unknown",
    "response_channel_bound": False,
    "response_integrity_result": "unknown",
    "registry_source": "custom",
    "reference_values_source": "custom",
}
PHASE2_VENICE_REQUIRED_CHECKS = {
    "cpu_tee": "verified",
    "e2ee_key_binding": "not_applicable",
    "model_binding": "verified",
    "request_encryption": "not_applicable",
    "request_key_binding": "not_applicable",
    "request_route_binding": "not_supported",
    "response_channel_binding": "not_applicable",
    "response_encryption": "not_applicable",
    "response_key_binding": "not_applicable",
    "route_binding": "not_supported",
    "route_metadata_binding": "verified",
    "tcb_compose_hash": "verified",
}
PHASE2_VENICE_TRANSCRIPT_FIELDS = {
    "phase2_venice_provider": "provider",
    "phase2_venice_route_id": "route_id",
    "phase2_venice_requested_model": "requested_model",
    "phase2_venice_provider_model": "provider_model",
    "phase2_venice_canonical_model": "canonical_model",
    "phase2_venice_trust_tier": "trust_tier",
    "phase2_venice_evidence_family": "evidence_family",
    "phase2_venice_channel_binding_kind": "channel_binding_kind",
    "phase2_venice_request_confidentiality_result": "request_confidentiality_result",
    "phase2_venice_response_confidentiality_result": "response_confidentiality_result",
    "phase2_venice_response_integrity_result": "response_integrity_result",
    "phase2_venice_route_execution_status": "route_execution_status",
    "phase2_venice_chat_executable": "chat_executable",
    "phase2_venice_policy_digest": "policy_digest",
    "phase2_venice_provider_registry_digest": "provider_registry_digest",
    "phase2_venice_reference_values_digest": "reference_values_digest",
    "phase2_venice_registry_source": "registry_source",
    "phase2_venice_reference_values_source": "reference_values_source",
}
PHASE2_VENICE_REQUIRED_ARTIFACTS = (
    "source_url",
    "tee_measurement",
    "report_data",
    "e2ee_capability",
    "model_manifest",
    "model_artifacts",
)
LOCAL_LIVE_TINFOIL_EXPECTED_VALUES = {
    "provider": "local-tinfoil-live",
    "route_id": "local-tinfoil-live:llama-3.3-70b:llama-3.3-70b",
    "requested_model": "llama-3.3-70b",
    "provider_model": "llama-3.3-70b",
    "canonical_model": "llama-3.3-70b",
    "status": "verified",
    "enforcement": "enforce",
    "request_allowed": True,
    "would_block_under_enforce": False,
    "freshness_class": "per_session",
    "route_execution_status": "executable",
    "chat_executable": True,
    "streaming_allowed": False,
}
LOCAL_LIVE_TINFOIL_VERDICT_VALUES = {
    "schema": "confidential-inference.verdict.v1",
    "policy_schema": "confidential-inference.policy.v1",
    "reference_values_schema": "confidential-inference.reference-values.v1",
    "provider_registry_schema": "confidential-inference.provider-registry.v1",
    "trust_tier": "hw-verified-tls",
    "evidence_family": "tinfoil_hw_verified_tls",
    "adapter_version": "local-live-tinfoil-demo-adapter/0.1.0",
    "alias_confidence": "curated",
    "channel_binding_kind": "tee_terminated_tls",
    "model_binding_result": "verified",
    "request_channel_bound": True,
    "request_confidentiality_result": "channel_bound",
    "response_confidentiality_result": "channel_bound",
    "response_channel_bound": True,
    "response_integrity_result": "channel_bound",
    "registry_source": "custom",
    "reference_values_source": "custom",
}
LOCAL_LIVE_TINFOIL_REQUIRED_CHECKS = {
    "cpu_tee": "verified",
    "tls_binding": "verified",
    "image_provenance": "verified",
    "model_artifact_provenance": "verified",
    "model_binding": "verified",
    "request_encryption": "verified",
    "request_key_binding": "verified",
    "response_channel_binding": "verified",
    "response_encryption": "verified",
    "response_key_binding": "verified",
    "request_route_binding": "not_supported",
    "route_binding": "not_supported",
    "route_metadata_binding": "verified",
}
LOCAL_LIVE_TINFOIL_SIGNATURE = {
    "signer": "confidential-inference-local-demo",
    "key_id": "confidential-inference-local-demo-ed25519-2026",
    "alg": "ed25519",
}
LOCAL_LIVE_TINFOIL_MIRRORED_FIELDS = (
    "provider",
    "route_id",
    "requested_model",
    "provider_model",
    "canonical_model",
    "policy_digest",
    "provider_registry_digest",
    "reference_values_digest",
    "raw_evidence_digest",
    "evidence_digest",
    "registry_version",
    "registry_source",
    "registry_sync_completed_at",
    "registry_signature",
    "reference_values_version",
    "reference_values_source",
    "reference_values_signature",
    "verified_at",
    "expires_at",
    "freshness_class",
    "streaming_allowed",
    "route_execution_status",
    "chat_executable",
    "known_unsupported_modes",
    "status",
    "enforcement",
    "request_allowed",
    "would_block_under_enforce",
    "errors",
)
LOCAL_LIVE_TINFOIL_TRANSCRIPT_FIELDS = {
    "local_live_tinfoil_provider": "provider",
    "local_live_tinfoil_route_id": "route_id",
    "local_live_tinfoil_requested_model": "requested_model",
    "local_live_tinfoil_provider_model": "provider_model",
    "local_live_tinfoil_canonical_model": "canonical_model",
    "local_live_tinfoil_trust_tier": "trust_tier",
    "local_live_tinfoil_evidence_family": "evidence_family",
    "local_live_tinfoil_channel_binding_kind": "channel_binding_kind",
    "local_live_tinfoil_request_confidentiality_result": "request_confidentiality_result",
    "local_live_tinfoil_response_confidentiality_result": "response_confidentiality_result",
    "local_live_tinfoil_response_integrity_result": "response_integrity_result",
    "local_live_tinfoil_route_execution_status": "route_execution_status",
    "local_live_tinfoil_chat_executable": "chat_executable",
    "local_live_tinfoil_policy_digest": "policy_digest",
    "local_live_tinfoil_provider_registry_digest": "provider_registry_digest",
    "local_live_tinfoil_reference_values_digest": "reference_values_digest",
    "local_live_tinfoil_registry_source": "registry_source",
    "local_live_tinfoil_reference_values_source": "reference_values_source",
}
LOCAL_LIVE_TINFOIL_REQUIRED_ARTIFACTS = (
    "source_url",
    "tee_measurement",
    "report_data",
    "signing_public_key",
    "model_manifest",
    "model_artifacts",
)
LOCAL_APP_E2EE_EXPECTED_VALUES = {
    "provider": "local-sdk-app-e2ee",
    "route_id": "local-sdk-app-e2ee:gpt-oss-120b:e2ee-gpt-oss-120b-p",
    "requested_model": "gpt-oss-120b",
    "provider_model": "e2ee-gpt-oss-120b-p",
    "canonical_model": "gpt-oss-120b",
    "status": "verified",
    "enforcement": "enforce",
    "request_allowed": True,
    "would_block_under_enforce": False,
    "freshness_class": "per_session",
    "route_execution_status": "executable",
    "chat_executable": True,
    "streaming_allowed": False,
}
LOCAL_APP_E2EE_VERDICT_VALUES = {
    "schema": "confidential-inference.verdict.v1",
    "policy_schema": "confidential-inference.policy.v1",
    "reference_values_schema": "confidential-inference.reference-values.v1",
    "provider_registry_schema": "confidential-inference.provider-registry.v1",
    "trust_tier": "tee-only",
    "evidence_family": "dstack_app_e2ee",
    "adapter_version": "local-sdk-app-e2ee-demo-adapter/0.1.0",
    "alias_confidence": "curated",
    "channel_binding_kind": "attested_app_e2ee",
    "model_binding_result": "verified",
    "request_channel_bound": False,
    "request_confidentiality_result": "unknown",
    "response_confidentiality_result": "unknown",
    "response_channel_bound": False,
    "response_integrity_result": "unknown",
    "registry_source": "custom",
    "reference_values_source": "custom",
}
LOCAL_APP_E2EE_REQUIRED_CHECKS = {
    "cpu_tee": "verified",
    "e2ee_key_binding": "not_applicable",
    "tcb_compose_hash": "verified",
    "request_encryption": "not_applicable",
    "response_encryption": "not_applicable",
    "model_binding": "verified",
    "image_provenance": "verified",
    "model_artifact_provenance": "verified",
    "request_key_binding": "not_applicable",
    "request_route_binding": "not_supported",
    "response_channel_binding": "not_applicable",
    "response_key_binding": "not_applicable",
    "route_binding": "not_supported",
    "route_metadata_binding": "verified",
    "workload_manifest_binding": "verified",
}
LOCAL_APP_E2EE_TRANSCRIPT_FIELDS = {
    "local_sdk_app_e2ee_provider": "provider",
    "local_sdk_app_e2ee_route_id": "route_id",
    "local_sdk_app_e2ee_requested_model": "requested_model",
    "local_sdk_app_e2ee_provider_model": "provider_model",
    "local_sdk_app_e2ee_canonical_model": "canonical_model",
    "local_sdk_app_e2ee_trust_tier": "trust_tier",
    "local_sdk_app_e2ee_evidence_family": "evidence_family",
    "local_sdk_app_e2ee_channel_binding_kind": "channel_binding_kind",
    "local_sdk_app_e2ee_request_confidentiality_result": "request_confidentiality_result",
    "local_sdk_app_e2ee_response_confidentiality_result": "response_confidentiality_result",
    "local_sdk_app_e2ee_response_integrity_result": "response_integrity_result",
    "local_sdk_app_e2ee_route_execution_status": "route_execution_status",
    "local_sdk_app_e2ee_chat_executable": "chat_executable",
    "local_sdk_app_e2ee_policy_digest": "policy_digest",
    "local_sdk_app_e2ee_provider_registry_digest": "provider_registry_digest",
    "local_sdk_app_e2ee_reference_values_digest": "reference_values_digest",
    "local_sdk_app_e2ee_registry_source": "registry_source",
    "local_sdk_app_e2ee_reference_values_source": "reference_values_source",
}
LOCAL_APP_E2EE_REQUIRED_ARTIFACTS = (
    "source_url",
    "tee_measurement",
    "report_data",
    "e2ee_capability",
    "model_manifest",
    "model_artifacts",
)
FORBIDDEN_ARTIFACT_SUBSTRINGS = (
    "verify the confidential inference SDK path",
    "verify the proxy SDK path",
    "demo confidential response for e2ee-gpt-oss-120b-p",
    "verify the signed Tinfoil fixture path",
    "tinfoil fixture response for llama-3.3-70b",
    "this route is verification-only",
    "streaming must fail closed in confidential demo",
    "demo-api-key-not-used",
    "verify the local SDK app-E2EE path",
    "local SDK app-E2EE response",
    "verify the local live TLS path",
    "local live Tinfoil response",
)
REQUIRED_AUDIT_FIELDS = (
    "provider",
    "route_id",
    "requested_model",
    "provider_model",
    "canonical_model",
    "evidence_family",
    "adapter_version",
    "trust_tier",
    "channel_binding_kind",
    "request_confidentiality_result",
    "response_confidentiality_result",
    "response_integrity_result",
    "enforcement",
    "status",
    "request_allowed",
    "would_block_under_enforce",
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
    "freshness_class",
    "route_execution_status",
    "chat_executable",
    "known_unsupported_modes",
    "cache_hit",
)
REQUIRED_METRIC_LABEL_FIELDS = (
    "provider",
    "route_id",
    "requested_model",
    "provider_model",
    "canonical_model",
    "evidence_family",
)
REQUIRED_METRIC_EVENTS = {
    "route_selection",
    "verification_cache",
    "latency",
    "streaming_fail_closed",
    "verdict",
}
PRIMARY_METRIC_LABEL_FIELDS = (
    "provider",
    "route_id",
    "requested_model",
    "provider_model",
    "canonical_model",
    "evidence_family",
)
REQUIRED_PRIMARY_LATENCY_STEPS = {
    "evidence_fetch",
    "evidence_verification",
    "provider_chat",
}
PRIMARY_AUDIT_VERDICT_FIELDS = (
    "provider",
    "route_id",
    "requested_model",
    "provider_model",
    "canonical_model",
    "evidence_family",
    "adapter_version",
    "trust_tier",
    "channel_binding_kind",
    "request_confidentiality_result",
    "response_confidentiality_result",
    "response_integrity_result",
    "enforcement",
    "status",
    "request_allowed",
    "would_block_under_enforce",
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
    "freshness_class",
    "streaming_allowed",
    "route_execution_status",
    "chat_executable",
    "known_unsupported_modes",
    "errors",
)


def _parse_labels(text: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for line in text.splitlines():
        match = LABEL_RE.match(line)
        if match:
            labels[match.group("label")] = match.group("value").strip()
    return labels


def _extract_verdict(text: str) -> tuple[dict[str, Any] | None, list[str]]:
    marker = "verdict:\n"
    index = text.find(marker)
    if index < 0:
        return None, ["missing printed verdict JSON marker"]

    payload = text[index + len(marker) :].lstrip()
    try:
        verdict, _ = json.JSONDecoder().raw_decode(payload)
    except json.JSONDecodeError as error:
        return None, [f"printed verdict JSON is invalid: {error}"]

    if not isinstance(verdict, dict):
        return None, ["printed verdict JSON is not an object"]
    return verdict, []


def _validate_labels(labels: dict[str, str], text: str) -> list[str]:
    violations: list[str] = []
    for label, expected in REQUIRED_LABELS.items():
        actual = labels.get(label)
        if actual is None:
            violations.append(f"missing marker {label}")
        elif actual != expected:
            violations.append(f"{label} expected {expected!r}, got {actual!r}")

    for label in sorted(BOOLEAN_LABELS):
        actual = labels.get(label)
        if actual is None:
            violations.append(f"missing marker {label}")
        elif actual not in {"true", "false"}:
            violations.append(f"{label} expected boolean text, got {actual!r}")

    for label, minimum in MIN_NUMERIC_LABELS.items():
        actual = labels.get(label)
        if actual is None:
            violations.append(f"missing marker {label}")
            continue
        try:
            value = int(actual)
        except ValueError:
            violations.append(f"{label} expected integer >= {minimum}, got {actual!r}")
            continue
        if value < minimum:
            violations.append(f"{label} expected integer >= {minimum}, got {value}")

    for label, expected in EXACT_NUMERIC_LABELS.items():
        actual = labels.get(label)
        if actual is None:
            violations.append(f"missing marker {label}")
            continue
        try:
            value = int(actual)
        except ValueError:
            violations.append(f"{label} expected integer {expected}, got {actual!r}")
            continue
        if value != expected:
            violations.append(f"{label} expected integer {expected}, got {value}")

    for substring in REQUIRED_SUBSTRINGS:
        if substring not in text:
            violations.append(f"missing transcript substring {substring!r}")

    return violations


def _validate_verdict(verdict: dict[str, Any] | None) -> list[str]:
    if verdict is None:
        return []

    violations: list[str] = []
    for field, expected in REQUIRED_VERDICT_VALUES.items():
        actual = verdict.get(field)
        if actual != expected:
            violations.append(f"verdict.{field} expected {expected!r}, got {actual!r}")

    unsupported_modes = verdict.get("known_unsupported_modes")
    if not isinstance(unsupported_modes, list) or "streaming" not in unsupported_modes:
        violations.append("verdict.known_unsupported_modes must contain 'streaming'")

    for field in REQUIRED_VERDICT_DIGESTS:
        actual = verdict.get(field)
        if not isinstance(actual, str) or SHA256_RE.fullmatch(actual) is None:
            violations.append(f"verdict.{field} must be canonical sha256 hex digest")

    checks = verdict.get("checks")
    if not isinstance(checks, dict):
        violations.append("verdict.checks must be an object")
    else:
        for field, expected in REQUIRED_CHECKS.items():
            actual = checks.get(field)
            if actual != expected:
                violations.append(
                    f"verdict.checks.{field} expected {expected!r}, got {actual!r}"
                )

    if verdict.get("errors") != []:
        violations.append("verdict.errors must be empty for the local demo success path")

    registry_signature = verdict.get("registry_signature")
    if not isinstance(registry_signature, dict):
        violations.append("verdict.registry_signature must be an object")
    elif registry_signature.get("signer") != "confidential-inference":
        violations.append("verdict.registry_signature.signer must be 'confidential-inference'")

    reference_signature = verdict.get("reference_values_signature")
    if not isinstance(reference_signature, dict):
        violations.append("verdict.reference_values_signature must be an object")
    elif reference_signature.get("signer") != "confidential-inference":
        violations.append("verdict.reference_values_signature.signer must be 'confidential-inference'")

    validity = verdict.get("validity")
    if not isinstance(validity, dict):
        violations.append("verdict.validity must be an object")
    elif validity.get("computed_expires_at") != verdict.get("expires_at"):
        violations.append("verdict.validity.computed_expires_at must match expires_at")

    return violations


def _require_label_value(
    labels: dict[str, str],
    label: str,
    expected: Any,
    subject: str,
) -> list[str]:
    actual = labels.get(label)
    if actual is None:
        return [f"missing marker {label}"]
    if actual != expected:
        return [f"{subject} expected {expected!r}, got {actual!r}"]
    return []


def _validate_active_metadata_markers(
    labels: dict[str, str],
    verdict: dict[str, Any] | None,
) -> list[str]:
    if verdict is None:
        return []

    expectations = {
        "active_policy_digest": verdict.get("policy_digest"),
        "active_policy_registry_digest": verdict.get("provider_registry_digest"),
        "active_policy_reference_values_digest": verdict.get("reference_values_digest"),
        "active_registry_digest": verdict.get("provider_registry_digest"),
        "active_reference_values_digest": verdict.get("reference_values_digest"),
        "active_registry_source": verdict.get("registry_source"),
        "active_reference_values_source": verdict.get("reference_values_source"),
    }

    registry_signature = verdict.get("registry_signature")
    if isinstance(registry_signature, dict):
        expectations.update(
            {
                "active_registry_signature_signer": registry_signature.get("signer"),
                "active_registry_signature_key_id": registry_signature.get("key_id"),
                "active_registry_signature_alg": registry_signature.get("alg"),
            }
        )
    else:
        expectations.update(
            {
                "active_registry_signature_signer": None,
                "active_registry_signature_key_id": None,
                "active_registry_signature_alg": None,
            }
        )

    reference_signature = verdict.get("reference_values_signature")
    if isinstance(reference_signature, dict):
        expectations.update(
            {
                "active_reference_values_signature_signer": reference_signature.get("signer"),
                "active_reference_values_signature_key_id": reference_signature.get("key_id"),
                "active_reference_values_signature_alg": reference_signature.get("alg"),
            }
        )
    else:
        expectations.update(
            {
                "active_reference_values_signature_signer": None,
                "active_reference_values_signature_key_id": None,
                "active_reference_values_signature_alg": None,
            }
        )

    violations: list[str] = []
    for label, expected in expectations.items():
        if not isinstance(expected, str) or not expected:
            violations.append(f"verdict field for {label} must be non-empty before comparison")
            continue
        violations.extend(_require_label_value(labels, label, expected, label))
    return violations


def _validate_active_policy_artifact(
    artifact: Any,
    labels: dict[str, str],
    verdict: dict[str, Any] | None,
) -> list[str]:
    subject = "active policy artifact"
    if not isinstance(artifact, dict):
        return [f"{subject} must be an object"]

    violations: list[str] = []
    if artifact.get("schema") != "confidential-inference.active-policy.v1":
        violations.append(f"{subject}.schema must be confidential-inference.active-policy.v1")
    policy = artifact.get("policy")
    if not isinstance(policy, dict):
        return [*violations, f"{subject}.policy must be an object"]
    if policy.get("schema") != "confidential-inference.policy.v1":
        violations.append(f"{subject}.policy.schema must be confidential-inference.policy.v1")

    try:
        digest = _canonical_sha256_digest(policy)
    except ValueError as error:
        violations.append(f"{subject}.policy could not be canonicalized: {error}")
        digest = None

    embedded_digest = artifact.get("policy_digest")
    if not isinstance(embedded_digest, str) or SHA256_RE.fullmatch(embedded_digest) is None:
        violations.append(f"{subject}.policy_digest must be a canonical sha256 digest")
    elif digest is not None and embedded_digest != digest:
        violations.append(
            f"{subject}.policy_digest expected {digest!r}, got {embedded_digest!r}"
        )

    label_expectations = {
        "active_policy_digest": digest,
        "active_policy_registry_digest": policy.get("provider_registry_digest"),
        "active_policy_reference_values_digest": policy.get("reference_values_digest"),
    }
    for label, expected in label_expectations.items():
        if not isinstance(expected, str) or not expected:
            violations.append(f"{subject} expected non-empty value for {label}")
            continue
        actual = labels.get(label)
        if actual != expected:
            violations.append(f"{label} expected {expected!r}, got {actual!r}")

    if verdict is not None:
        verdict_expectations = {
            "policy_digest": embedded_digest,
            "provider_registry_digest": policy.get("provider_registry_digest"),
            "reference_values_digest": policy.get("reference_values_digest"),
        }
        for verdict_field, actual in verdict_expectations.items():
            expected = verdict.get(verdict_field)
            if actual != expected:
                violations.append(
                    f"{subject}.{verdict_field} expected {expected!r}, got {actual!r}"
                )

    return violations


def _validate_active_signature_metadata(
    subject: str,
    signature: Any,
    labels: dict[str, str],
    verdict_signature: Any,
    *,
    label_prefix: str,
) -> list[str]:
    if not isinstance(signature, dict):
        return [f"{subject}.signature must be an object"]

    violations: list[str] = []
    for field in ("signer", "key_id", "alg", "value"):
        if not isinstance(signature.get(field), str) or not signature[field]:
            violations.append(f"{subject}.signature.{field} must be non-empty")
    if isinstance(signature.get("value"), str) and not signature["value"].startswith(
        "base64url:"
    ):
        violations.append(f"{subject}.signature.value must be base64url-prefixed")

    label_expectations = {
        f"{label_prefix}_signature_signer": signature.get("signer"),
        f"{label_prefix}_signature_key_id": signature.get("key_id"),
        f"{label_prefix}_signature_alg": signature.get("alg"),
    }
    for label, expected in label_expectations.items():
        if not isinstance(expected, str) or not expected:
            continue
        actual = labels.get(label)
        if actual != expected:
            violations.append(f"{label} expected {expected!r}, got {actual!r}")

    if isinstance(verdict_signature, dict):
        for field in ("signer", "key_id", "alg"):
            expected = verdict_signature.get(field)
            actual = signature.get(field)
            if actual != expected:
                violations.append(
                    f"{subject}.signature.{field} expected {expected!r}, got {actual!r}"
                )

    return violations


def _validate_active_trust_artifacts_artifact(
    artifact: Any,
    labels: dict[str, str],
    verdict: dict[str, Any] | None,
) -> list[str]:
    subject = "active trust artifacts artifact"
    if not isinstance(artifact, dict):
        return [f"{subject} must be an object"]

    violations: list[str] = []
    registry = artifact.get("registry")
    reference_values = artifact.get("reference_values")
    if not isinstance(registry, dict):
        violations.append(f"{subject}.registry must be an object")
        registry = None
    elif registry.get("schema") != "confidential-inference.provider-registry.v1":
        violations.append(f"{subject}.registry.schema must be confidential-inference.provider-registry.v1")
    if not isinstance(reference_values, dict):
        violations.append(f"{subject}.reference_values must be an object")
        reference_values = None
    elif reference_values.get("schema") != "confidential-inference.reference-values.v1":
        violations.append(
            f"{subject}.reference_values.schema must be confidential-inference.reference-values.v1"
        )

    registry_digest = None
    if registry is not None:
        try:
            registry_digest = _canonical_sha256_digest(registry)
        except ValueError as error:
            violations.append(f"{subject}.registry could not be canonicalized: {error}")
    reference_values_digest = None
    if reference_values is not None:
        try:
            reference_values_digest = _canonical_sha256_digest(reference_values)
        except ValueError as error:
            violations.append(
                f"{subject}.reference_values could not be canonicalized: {error}"
            )

    digest_checks = (
        (
            "registry_digest",
            registry_digest,
            "active_registry_digest",
            verdict.get("provider_registry_digest") if verdict is not None else None,
        ),
        (
            "reference_values_digest",
            reference_values_digest,
            "active_reference_values_digest",
            verdict.get("reference_values_digest") if verdict is not None else None,
        ),
    )
    for artifact_field, digest, label, verdict_digest in digest_checks:
        embedded = artifact.get(artifact_field)
        if not isinstance(embedded, str) or SHA256_RE.fullmatch(embedded) is None:
            violations.append(f"{subject}.{artifact_field} must be a canonical sha256 digest")
        elif digest is not None and embedded != digest:
            violations.append(
                f"{subject}.{artifact_field} expected {digest!r}, got {embedded!r}"
            )
        label_value = labels.get(label)
        if digest is not None and label_value != digest:
            violations.append(f"{label} expected {digest!r}, got {label_value!r}")
        if verdict_digest is not None and digest is not None and verdict_digest != digest:
            violations.append(
                f"{subject}.{artifact_field} must match printed verdict digest"
            )

    source_checks = (
        ("registry_source", "active_registry_source", "registry_source"),
        (
            "reference_values_source",
            "active_reference_values_source",
            "reference_values_source",
        ),
    )
    for artifact_field, label, verdict_field in source_checks:
        artifact_value = artifact.get(artifact_field)
        label_value = labels.get(label)
        if not isinstance(artifact_value, str) or not artifact_value:
            violations.append(f"{subject}.{artifact_field} must be non-empty")
        elif label_value != artifact_value:
            violations.append(f"{label} expected {artifact_value!r}, got {label_value!r}")
        if verdict is not None and artifact_value != verdict.get(verdict_field):
            violations.append(
                f"{subject}.{artifact_field} expected {verdict.get(verdict_field)!r}, got {artifact_value!r}"
            )

    registry_signature = artifact.get("registry_signature")
    violations.extend(
        _validate_active_signature_metadata(
            f"{subject}.registry",
            registry_signature,
            labels,
            verdict.get("registry_signature") if verdict is not None else None,
            label_prefix="active_registry",
        )
    )
    reference_signature = artifact.get("reference_values_signature")
    violations.extend(
        _validate_active_signature_metadata(
            f"{subject}.reference_values",
            reference_signature,
            labels,
            verdict.get("reference_values_signature") if verdict is not None else None,
            label_prefix="active_reference_values",
        )
    )

    if isinstance(registry, dict) and isinstance(registry_signature, dict):
        try:
            verify_artifact_signature(
                registry_signature,
                _canonical_json(registry).encode("utf-8"),
                f"{subject}.registry",
            )
        except (ArtifactSignatureError, ValueError) as error:
            violations.append(str(error))
    if isinstance(reference_values, dict) and isinstance(reference_signature, dict):
        try:
            verify_artifact_signature(
                reference_signature,
                _canonical_json(reference_values).encode("utf-8"),
                f"{subject}.reference_values",
            )
        except (ArtifactSignatureError, ValueError) as error:
            violations.append(str(error))

    return violations


def _validate_proxy_markers(
    labels: dict[str, str],
    verdict: dict[str, Any] | None,
) -> list[str]:
    if verdict is None:
        return []

    proxy_verdict_fields = {
        "proxy_verdict_provider": "provider",
        "proxy_verdict_route_id": "route_id",
        "proxy_verdict_requested_model": "requested_model",
        "proxy_verdict_provider_model": "provider_model",
        "proxy_verdict_canonical_model": "canonical_model",
        "proxy_verdict_policy_digest": "policy_digest",
        "proxy_verdict_provider_registry_digest": "provider_registry_digest",
        "proxy_verdict_reference_values_digest": "reference_values_digest",
        "proxy_verdict_request_confidentiality_result": "request_confidentiality_result",
        "proxy_verdict_response_confidentiality_result": "response_confidentiality_result",
        "proxy_verdict_response_integrity_result": "response_integrity_result",
        "proxy_attestation_route_id": "route_id",
        "proxy_attestation_policy_digest": "policy_digest",
        "proxy_attestation_provider_registry_digest": "provider_registry_digest",
        "proxy_attestation_reference_values_digest": "reference_values_digest",
        "proxy_attestation_request_confidentiality_result": "request_confidentiality_result",
        "proxy_attestation_response_confidentiality_result": "response_confidentiality_result",
        "proxy_attestation_response_integrity_result": "response_integrity_result",
        "proxy_confidentiality_route_id": "route_id",
    }

    violations: list[str] = []
    for label, verdict_field in proxy_verdict_fields.items():
        expected = verdict.get(verdict_field)
        if not isinstance(expected, str) or not expected:
            violations.append(f"verdict.{verdict_field} must be non-empty before comparing {label}")
            continue
        violations.extend(_require_label_value(labels, label, expected, label))
    return violations


def _validate_route_digest_markers(labels: dict[str, str]) -> list[str]:
    violations: list[str] = []
    for prefix in (
        "phase2_tinfoil",
        "phase2_venice",
        "local_sdk_app_e2ee",
        "local_live_tinfoil",
    ):
        for suffix in (
            "policy_digest",
            "provider_registry_digest",
            "reference_values_digest",
        ):
            label = f"{prefix}_{suffix}"
            value = labels.get(label)
            if value is None:
                violations.append(f"missing marker {label}")
            elif SHA256_RE.fullmatch(value) is None:
                violations.append(f"{label} must be a canonical sha256 hex digest")
    return violations


def _resolve_artifact_path(output_path: Path, artifact_path: str) -> Path:
    path = Path(artifact_path)
    if path.is_absolute():
        return path
    candidates = [
        output_path.parent.parent / path,
        output_path.parent / path,
        path,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[1] if output_path.parent.name == "target" else candidates[0]


def _load_jsonl(path: Path, subject: str) -> tuple[list[dict[str, Any]], list[str], str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return [], [f"{subject} cannot be loaded from {path.as_posix()}: {error}"], ""
    violations: list[str] = []
    records: list[dict[str, Any]] = []
    if not text.strip():
        violations.append(f"{subject} must not be empty")
        return records, violations, text
    for index, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            violations.append(f"{subject} line {index} must not be blank")
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            violations.append(f"{subject} line {index} is invalid JSON: {error}")
            continue
        if not isinstance(record, dict):
            violations.append(f"{subject} line {index} must be a JSON object")
            continue
        records.append(record)
    return records, violations, text


def _load_json(path: Path, subject: str) -> tuple[Any, list[str], str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return None, [f"{subject} cannot be loaded from {path.as_posix()}: {error}"], ""
    if not text.strip():
        return None, [f"{subject} must not be empty"], text
    try:
        return json.loads(text), [], text
    except json.JSONDecodeError as error:
        return None, [f"{subject} is invalid JSON: {error}"], text


def _canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_JSON_INT:
            raise ValueError(f"JSON integer {value} exceeds the safe integer limit")
        return str(value)
    if isinstance(value, float):
        raise ValueError("canonical JSON does not permit floating point numbers")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("canonical JSON object keys must be strings")
        entries = []
        for key in sorted(value, key=lambda item: item.encode("utf-8")):
            entries.append(
                json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                + ":"
                + _canonical_json(value[key])
            )
        return "{" + ",".join(entries) + "}"
    raise ValueError(f"canonical JSON does not support {type(value).__name__}")


def _canonical_sha256_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _validate_no_artifact_plaintext(subject: str, text: str) -> list[str]:
    return [
        f"{subject} must not contain plaintext marker {marker!r}"
        for marker in FORBIDDEN_ARTIFACT_SUBSTRINGS
        if marker in text
    ]


def _validate_digest_field(subject: str, record: dict[str, Any], field: str) -> list[str]:
    value = record.get(field)
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        return [f"{subject}.{field} must be a canonical sha256 hex digest"]
    return []


def _validate_signature(subject: str, record: dict[str, Any], field: str) -> list[str]:
    signature = record.get(field)
    if not isinstance(signature, dict):
        return [f"{subject}.{field} must be an object"]
    violations = []
    for signature_field in ("signer", "key_id", "alg"):
        if not isinstance(signature.get(signature_field), str) or not signature[signature_field]:
            violations.append(f"{subject}.{field}.{signature_field} must be non-empty")
    if signature.get("alg") != "ed25519":
        violations.append(f"{subject}.{field}.alg must be ed25519")
    return violations


def _validate_audit_like_record(
    subject: str,
    record: dict[str, Any],
    *,
    require_nested_verdict: bool,
) -> list[str]:
    violations: list[str] = []
    verdict = record.get("verdict_json")
    nested_verdict = verdict if isinstance(verdict, dict) else {}
    for field in REQUIRED_AUDIT_FIELDS:
        if field not in record and field not in nested_verdict:
            location = " or verdict_json" if require_nested_verdict else ""
            violations.append(f"{subject}.{field}{location} is required")
    for field in (
        "policy_digest",
        "provider_registry_digest",
        "reference_values_digest",
        "raw_evidence_digest",
        "evidence_digest",
    ):
        violations.extend(_validate_digest_field(subject, record, field))
    for field in ("registry_signature", "reference_values_signature"):
        violations.extend(_validate_signature(subject, record, field))
    if not isinstance(record.get("known_unsupported_modes"), list):
        violations.append(f"{subject}.known_unsupported_modes must be an array")
    if not isinstance(record.get("errors"), list):
        violations.append(f"{subject}.errors must be an array")

    if require_nested_verdict:
        if not isinstance(verdict, dict):
            violations.append(f"{subject}.verdict_json must be an object")
        else:
            for field in (
                "policy_digest",
                "provider_registry_digest",
                "reference_values_digest",
                "raw_evidence_digest",
                "evidence_digest",
                "status",
                "enforcement",
                "request_allowed",
                "would_block_under_enforce",
            ):
                if verdict.get(field) != record.get(field):
                    violations.append(
                        f"{subject}.verdict_json.{field} must match top-level {field}"
                    )
            if verdict.get("errors") != record.get("errors"):
                violations.append(f"{subject}.verdict_json.errors must match top-level errors")
    elif "verdict_json" in record:
        violations.append(f"{subject}.verdict_json must not be persisted in audit JSONL")
    return violations


def _record_or_verdict_value(
    record: dict[str, Any],
    verdict: dict[str, Any],
    field: str,
) -> Any:
    if field in record:
        return record[field]
    return verdict.get(field)


def _label_text(value: Any) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str) and value:
        return value
    return None


def _validate_phase2_marker_binding(
    labels: dict[str, str],
    verdict_json: dict[str, Any] | None,
    *,
    prefix: str,
    subject: str,
    transcript_fields: dict[str, str],
) -> list[str]:
    if not isinstance(verdict_json, dict):
        return [f"{prefix} transcript markers require a fresh persisted verdict_json record"]

    violations: list[str] = []
    for label, verdict_field in transcript_fields.items():
        expected = _label_text(verdict_json.get(verdict_field))
        if expected is None:
            violations.append(
                f"{subject} verdict JSONL verdict_json.{verdict_field} must be non-empty before comparing {label}"
            )
            continue
        violations.extend(_require_label_value(labels, label, expected, label))

    signature_labels = {
        f"{prefix}_registry_signature_signer": "registry_signature",
        f"{prefix}_reference_values_signature_signer": "reference_values_signature",
    }
    for label, signature_field in signature_labels.items():
        signature = verdict_json.get(signature_field)
        expected = signature.get("signer") if isinstance(signature, dict) else None
        if not isinstance(expected, str) or not expected:
            violations.append(
                f"{subject} verdict JSONL verdict_json.{signature_field}.signer must be non-empty before comparing {label}"
            )
            continue
        violations.extend(_require_label_value(labels, label, expected, label))

    return violations


def _validate_proxy_store_marker_binding(
    labels: dict[str, str],
    verdict_json: dict[str, Any] | None,
) -> list[str]:
    if not isinstance(verdict_json, dict):
        return ["proxy transcript markers require a fresh persisted verdict_json record"]

    violations: list[str] = []
    for label, verdict_field in PROXY_TRANSCRIPT_FIELDS.items():
        expected = _label_text(verdict_json.get(verdict_field))
        if expected is None:
            violations.append(
                f"proxy verdict JSONL verdict_json.{verdict_field} must be non-empty before comparing {label}"
            )
            continue
        violations.extend(_require_label_value(labels, label, expected, label))
    return violations


def _validate_local_live_tinfoil_marker_binding(
    labels: dict[str, str],
    verdict_json: dict[str, Any] | None,
) -> list[str]:
    if not isinstance(verdict_json, dict):
        return [
            "local_live_tinfoil transcript markers require a fresh persisted verdict_json record"
        ]

    violations: list[str] = []
    for label, verdict_field in LOCAL_LIVE_TINFOIL_TRANSCRIPT_FIELDS.items():
        expected = _label_text(verdict_json.get(verdict_field))
        if expected is None:
            violations.append(
                f"local live verdict JSONL verdict_json.{verdict_field} must be non-empty before comparing {label}"
            )
            continue
        violations.extend(_require_label_value(labels, label, expected, label))

    signature_labels = {
        "local_live_tinfoil_registry_signature_signer": "registry_signature",
        "local_live_tinfoil_reference_values_signature_signer": "reference_values_signature",
    }
    for label, signature_field in signature_labels.items():
        signature = verdict_json.get(signature_field)
        expected = signature.get("signer") if isinstance(signature, dict) else None
        if not isinstance(expected, str) or not expected:
            violations.append(
                f"local live verdict JSONL verdict_json.{signature_field}.signer must be non-empty before comparing {label}"
            )
            continue
        violations.extend(_require_label_value(labels, label, expected, label))

    return violations


def _validate_local_sdk_app_e2ee_marker_binding(
    labels: dict[str, str],
    verdict_json: dict[str, Any] | None,
) -> list[str]:
    if not isinstance(verdict_json, dict):
        return [
            "local_sdk_app_e2ee transcript markers require a fresh persisted verdict_json record"
        ]

    violations: list[str] = []
    for label, verdict_field in LOCAL_APP_E2EE_TRANSCRIPT_FIELDS.items():
        expected = _label_text(verdict_json.get(verdict_field))
        if expected is None:
            violations.append(
                f"local SDK app-E2EE verdict JSONL verdict_json.{verdict_field} must be non-empty before comparing {label}"
            )
            continue
        violations.extend(_require_label_value(labels, label, expected, label))

    signature_labels = {
        "local_sdk_app_e2ee_registry_signature_signer": "registry_signature",
        "local_sdk_app_e2ee_reference_values_signature_signer": "reference_values_signature",
    }
    for label, signature_field in signature_labels.items():
        signature = verdict_json.get(signature_field)
        expected = signature.get("signer") if isinstance(signature, dict) else None
        if not isinstance(expected, str) or not expected:
            violations.append(
                f"local SDK app-E2EE verdict JSONL verdict_json.{signature_field}.signer must be non-empty before comparing {label}"
            )
            continue
        violations.extend(_require_label_value(labels, label, expected, label))

    return violations



def _phase2_profile(provider: str) -> dict[str, Any] | None:
    if provider == "tinfoil-fixture":
        return {
            "subject": "phase2 Tinfoil verdict JSONL",
            "expected": PHASE2_TINFOIL_EXPECTED_VALUES,
            "verdict": PHASE2_TINFOIL_VERDICT_VALUES,
            "checks": PHASE2_TINFOIL_REQUIRED_CHECKS,
            "artifacts": PHASE2_TINFOIL_REQUIRED_ARTIFACTS,
            "source_url": "https://inference.tinfoil.sh/.well-known/tinfoil-attestation",
            "model_manifest": "llama-3.3-70b",
            "e2ee_capability": None,
        }
    if provider == "venice-fixture":
        return {
            "subject": "phase2 Venice verdict JSONL",
            "expected": PHASE2_VENICE_EXPECTED_VALUES,
            "verdict": PHASE2_VENICE_VERDICT_VALUES,
            "checks": PHASE2_VENICE_REQUIRED_CHECKS,
            "artifacts": PHASE2_VENICE_REQUIRED_ARTIFACTS,
            "source_url": "https://api.venice.ai/api/v1/confidentiality",
            "model_manifest": "gpt-oss-120b",
            "e2ee_capability": "dstack-e2ee",
        }
    return None


def _validate_phase2_fixture_records(
    records: list[dict[str, Any]],
    labels: dict[str, str],
) -> list[str]:
    violations: list[str] = []
    cache_hit_states: dict[str, set[bool]] = {
        "tinfoil-fixture": set(),
        "venice-fixture": set(),
    }
    fresh_verdict_json: dict[str, dict[str, Any]] = {}

    for marker, provider in (
        ("phase2_tinfoil_provider", "tinfoil-fixture"),
        ("phase2_venice_provider", "venice-fixture"),
    ):
        if labels.get(marker) != provider:
            violations.append(
                f"{marker} marker must match persisted multi-route fixture provider"
            )

    for index, record in enumerate(records, start=1):
        provider = record.get("provider")
        subject = f"phase2 fixture verdict JSONL record {index}"
        if not isinstance(provider, str):
            violations.append(f"{subject}.provider must be a string")
            continue
        profile = _phase2_profile(provider)
        if profile is None:
            violations.append(
                f"{subject}.provider unexpected multi-route fixture provider {provider!r}"
            )
            continue

        verdict_json = record.get("verdict_json")
        if not isinstance(verdict_json, dict):
            continue

        cache_hit = record.get("cache_hit")
        if isinstance(cache_hit, bool):
            cache_hit_states[provider].add(cache_hit)
            if not cache_hit and provider not in fresh_verdict_json:
                fresh_verdict_json[provider] = verdict_json
        else:
            violations.append(f"{subject}.cache_hit must be a boolean")

        for field, expected in profile["expected"].items():
            actual = _record_or_verdict_value(record, verdict_json, field)
            if actual != expected:
                violations.append(f"{subject}.{field} expected {expected!r}, got {actual!r}")

        for field, expected in profile["verdict"].items():
            actual = verdict_json.get(field)
            if actual != expected:
                violations.append(
                    f"{subject}.verdict_json.{field} expected {expected!r}, got {actual!r}"
                )

        for field in LOCAL_LIVE_TINFOIL_MIRRORED_FIELDS:
            if (
                field in record
                and field in verdict_json
                and record.get(field) != verdict_json.get(field)
            ):
                violations.append(f"{subject}.verdict_json.{field} must match top-level {field}")

        for field in ("registry_signature", "reference_values_signature"):
            violations.extend(_validate_signature(f"{subject}.verdict_json", verdict_json, field))
            top_signature = record.get(field)
            verdict_signature = verdict_json.get(field)
            if top_signature != PHASE2_FIXTURE_SIGNATURE:
                violations.append(
                    f"{subject}.{field} expected {PHASE2_FIXTURE_SIGNATURE!r}, got {top_signature!r}"
                )
            if verdict_signature != PHASE2_FIXTURE_SIGNATURE:
                violations.append(
                    f"{subject}.verdict_json.{field} expected {PHASE2_FIXTURE_SIGNATURE!r}, got {verdict_signature!r}"
                )

        if record.get("errors") != []:
            violations.append(f"{subject}.errors must be empty")
        if verdict_json.get("errors") != []:
            violations.append(f"{subject}.verdict_json.errors must be empty")

        unsupported_modes = _record_or_verdict_value(
            record,
            verdict_json,
            "known_unsupported_modes",
        )
        if not isinstance(unsupported_modes, list) or "streaming" not in unsupported_modes:
            violations.append(f"{subject}.known_unsupported_modes must contain 'streaming'")

        checks = verdict_json.get("checks")
        if not isinstance(checks, dict):
            violations.append(f"{subject}.verdict_json.checks must be an object")
        else:
            for field, expected in profile["checks"].items():
                actual = checks.get(field)
                if actual != expected:
                    violations.append(
                        f"{subject}.verdict_json.checks.{field} expected "
                        f"{expected!r}, got {actual!r}"
                    )

        artifacts = verdict_json.get("artifacts")
        if not isinstance(artifacts, dict):
            violations.append(f"{subject}.verdict_json.artifacts must be an object")
        else:
            for field in profile["artifacts"]:
                value = artifacts.get(field)
                if value in (None, "", []):
                    violations.append(
                        f"{subject}.verdict_json.artifacts.{field} must be present"
                    )
            if artifacts.get("source_url") != profile["source_url"]:
                violations.append(
                    f"{subject}.verdict_json.artifacts.source_url must be {profile['source_url']}"
                )
            if artifacts.get("model_manifest") != profile["model_manifest"]:
                violations.append(
                    f"{subject}.verdict_json.artifacts.model_manifest must be {profile['model_manifest']}"
                )
            if artifacts.get("e2ee_capability") != profile["e2ee_capability"]:
                violations.append(
                    f"{subject}.verdict_json.artifacts.e2ee_capability expected {profile['e2ee_capability']!r}"
                )
            if not isinstance(artifacts.get("model_artifacts"), list):
                violations.append(
                    f"{subject}.verdict_json.artifacts.model_artifacts must be an array"
                )

    if cache_hit_states["tinfoil-fixture"] != {False, True}:
        violations.append(
            "phase2 fixture verdict JSONL must include Tinfoil fresh and cached records"
        )
    if False not in cache_hit_states["venice-fixture"]:
        violations.append("phase2 fixture verdict JSONL must include a fresh Venice record")

    violations.extend(
        _validate_phase2_marker_binding(
            labels,
            fresh_verdict_json.get("tinfoil-fixture"),
            prefix="phase2_tinfoil",
            subject="phase2 Tinfoil",
            transcript_fields=PHASE2_TINFOIL_TRANSCRIPT_FIELDS,
        )
    )
    violations.extend(
        _validate_phase2_marker_binding(
            labels,
            fresh_verdict_json.get("venice-fixture"),
            prefix="phase2_venice",
            subject="phase2 Venice",
            transcript_fields=PHASE2_VENICE_TRANSCRIPT_FIELDS,
        )
    )

    return violations


def _validate_proxy_verdict_records(
    records: list[dict[str, Any]],
    labels: dict[str, str],
) -> list[str]:
    violations: list[str] = []
    cache_hit_states = set()
    fresh_verdict_json: dict[str, Any] | None = None

    if labels.get("proxy_verdict_provider") != PROXY_EXPECTED_VALUES["provider"]:
        violations.append("proxy_verdict_provider marker must match persisted proxy verdict provider")

    for index, record in enumerate(records, start=1):
        subject = f"proxy verdict JSONL record {index}"
        verdict_json = record.get("verdict_json")
        if not isinstance(verdict_json, dict):
            continue

        cache_hit = record.get("cache_hit")
        if isinstance(cache_hit, bool):
            cache_hit_states.add(cache_hit)
            if not cache_hit and fresh_verdict_json is None:
                fresh_verdict_json = verdict_json
        else:
            violations.append(f"{subject}.cache_hit must be a boolean")

        for field, expected in PROXY_EXPECTED_VALUES.items():
            actual = _record_or_verdict_value(record, verdict_json, field)
            if actual != expected:
                violations.append(f"{subject}.{field} expected {expected!r}, got {actual!r}")

        for field, expected in PROXY_VERDICT_VALUES.items():
            actual = verdict_json.get(field)
            if actual != expected:
                violations.append(
                    f"{subject}.verdict_json.{field} expected {expected!r}, got {actual!r}"
                )

        for field in LOCAL_LIVE_TINFOIL_MIRRORED_FIELDS:
            if (
                field in record
                and field in verdict_json
                and record.get(field) != verdict_json.get(field)
            ):
                violations.append(f"{subject}.verdict_json.{field} must match top-level {field}")

        for field in ("registry_signature", "reference_values_signature"):
            violations.extend(_validate_signature(f"{subject}.verdict_json", verdict_json, field))
            top_signature = record.get(field)
            verdict_signature = verdict_json.get(field)
            if top_signature != DEMO_SIGNATURE:
                violations.append(
                    f"{subject}.{field} expected {DEMO_SIGNATURE!r}, got {top_signature!r}"
                )
            if verdict_signature != DEMO_SIGNATURE:
                violations.append(
                    f"{subject}.verdict_json.{field} expected {DEMO_SIGNATURE!r}, got {verdict_signature!r}"
                )

        if record.get("errors") != []:
            violations.append(f"{subject}.errors must be empty")
        if verdict_json.get("errors") != []:
            violations.append(f"{subject}.verdict_json.errors must be empty")

        unsupported_modes = _record_or_verdict_value(
            record,
            verdict_json,
            "known_unsupported_modes",
        )
        if not isinstance(unsupported_modes, list) or "streaming" not in unsupported_modes:
            violations.append(f"{subject}.known_unsupported_modes must contain 'streaming'")

        checks = verdict_json.get("checks")
        if not isinstance(checks, dict):
            violations.append(f"{subject}.verdict_json.checks must be an object")
        else:
            for field, expected in REQUIRED_CHECKS.items():
                actual = checks.get(field)
                if actual != expected:
                    violations.append(
                        f"{subject}.verdict_json.checks.{field} expected "
                        f"{expected!r}, got {actual!r}"
                    )

        artifacts = verdict_json.get("artifacts")
        if not isinstance(artifacts, dict):
            violations.append(f"{subject}.verdict_json.artifacts must be an object")
        else:
            for field in PROXY_REQUIRED_ARTIFACTS:
                value = artifacts.get(field)
                if value in (None, "", []):
                    violations.append(
                        f"{subject}.verdict_json.artifacts.{field} must be present"
                    )
            if artifacts.get("source_url") != "http://127.0.0.1/demo/v1/confidentiality":
                violations.append(
                    f"{subject}.verdict_json.artifacts.source_url must be the demo evidence endpoint"
                )
            if artifacts.get("e2ee_capability") != "fixture-e2ee":
                violations.append(
                    f"{subject}.verdict_json.artifacts.e2ee_capability must be fixture-e2ee"
                )
            if artifacts.get("model_manifest") != "gpt-oss-120b":
                violations.append(
                    f"{subject}.verdict_json.artifacts.model_manifest must be gpt-oss-120b"
                )
            if not isinstance(artifacts.get("model_artifacts"), list):
                violations.append(
                    f"{subject}.verdict_json.artifacts.model_artifacts must be an array"
                )

    if cache_hit_states != {False, True}:
        violations.append("proxy verdict JSONL must include both fresh and cached records")
    violations.extend(_validate_proxy_store_marker_binding(labels, fresh_verdict_json))

    return violations


def _validate_local_sdk_app_e2ee_records(
    records: list[dict[str, Any]],
    labels: dict[str, str],
) -> list[str]:
    violations: list[str] = []
    cache_hit_states = set()
    fresh_verdict_json: dict[str, Any] | None = None

    if labels.get("local_sdk_app_e2ee_provider") != LOCAL_APP_E2EE_EXPECTED_VALUES["provider"]:
        violations.append(
            "local_sdk_app_e2ee_provider marker must match persisted app-E2EE verdict provider"
        )

    for index, record in enumerate(records, start=1):
        subject = f"local SDK app-E2EE verdict JSONL record {index}"
        verdict_json = record.get("verdict_json")
        if not isinstance(verdict_json, dict):
            continue

        cache_hit = record.get("cache_hit")
        if isinstance(cache_hit, bool):
            cache_hit_states.add(cache_hit)
            if not cache_hit and fresh_verdict_json is None:
                fresh_verdict_json = verdict_json
        else:
            violations.append(f"{subject}.cache_hit must be a boolean")

        for field, expected in LOCAL_APP_E2EE_EXPECTED_VALUES.items():
            actual = _record_or_verdict_value(record, verdict_json, field)
            if actual != expected:
                violations.append(f"{subject}.{field} expected {expected!r}, got {actual!r}")

        for field, expected in LOCAL_APP_E2EE_VERDICT_VALUES.items():
            actual = verdict_json.get(field)
            if actual != expected:
                violations.append(
                    f"{subject}.verdict_json.{field} expected {expected!r}, got {actual!r}"
                )

        for field in LOCAL_LIVE_TINFOIL_MIRRORED_FIELDS:
            if (
                field in record
                and field in verdict_json
                and record.get(field) != verdict_json.get(field)
            ):
                violations.append(f"{subject}.verdict_json.{field} must match top-level {field}")

        for field in ("registry_signature", "reference_values_signature"):
            violations.extend(_validate_signature(f"{subject}.verdict_json", verdict_json, field))
            top_signature = record.get(field)
            verdict_signature = verdict_json.get(field)
            if top_signature != LOCAL_LIVE_TINFOIL_SIGNATURE:
                violations.append(
                    f"{subject}.{field} expected {LOCAL_LIVE_TINFOIL_SIGNATURE!r}, "
                    f"got {top_signature!r}"
                )
            if verdict_signature != LOCAL_LIVE_TINFOIL_SIGNATURE:
                violations.append(
                    f"{subject}.verdict_json.{field} expected "
                    f"{LOCAL_LIVE_TINFOIL_SIGNATURE!r}, got {verdict_signature!r}"
                )

        if record.get("errors") != []:
            violations.append(f"{subject}.errors must be empty")
        if verdict_json.get("errors") != []:
            violations.append(f"{subject}.verdict_json.errors must be empty")

        unsupported_modes = _record_or_verdict_value(
            record,
            verdict_json,
            "known_unsupported_modes",
        )
        if not isinstance(unsupported_modes, list) or "streaming" not in unsupported_modes:
            violations.append(f"{subject}.known_unsupported_modes must contain 'streaming'")

        checks = verdict_json.get("checks")
        if not isinstance(checks, dict):
            violations.append(f"{subject}.verdict_json.checks must be an object")
        else:
            for field, expected in LOCAL_APP_E2EE_REQUIRED_CHECKS.items():
                actual = checks.get(field)
                if actual != expected:
                    violations.append(
                        f"{subject}.verdict_json.checks.{field} expected "
                        f"{expected!r}, got {actual!r}"
                    )

        artifacts = verdict_json.get("artifacts")
        if not isinstance(artifacts, dict):
            violations.append(f"{subject}.verdict_json.artifacts must be an object")
        else:
            for field in LOCAL_APP_E2EE_REQUIRED_ARTIFACTS:
                value = artifacts.get(field)
                if value in (None, "", []):
                    violations.append(
                        f"{subject}.verdict_json.artifacts.{field} must be present"
                    )
            source_url = artifacts.get("source_url")
            if not (
                isinstance(source_url, str)
                and source_url.startswith("http://127.0.0.1:")
                and source_url.endswith("/v1/confidentiality")
            ):
                violations.append(
                    f"{subject}.verdict_json.artifacts.source_url must be the local app-E2EE evidence endpoint"
                )
            if artifacts.get("e2ee_capability") != "dstack-e2ee":
                violations.append(
                    f"{subject}.verdict_json.artifacts.e2ee_capability must be dstack-e2ee"
                )
            if not isinstance(artifacts.get("model_artifacts"), list):
                violations.append(
                    f"{subject}.verdict_json.artifacts.model_artifacts must be an array"
                )

    if cache_hit_states != {False, True}:
        violations.append(
            "local SDK app-E2EE verdict JSONL must include both fresh and cached records"
        )
    violations.extend(
        _validate_local_sdk_app_e2ee_marker_binding(labels, fresh_verdict_json)
    )

    return violations



def _validate_local_live_tinfoil_records(
    records: list[dict[str, Any]],
    labels: dict[str, str],
) -> list[str]:
    violations: list[str] = []
    cache_hit_states = set()
    fresh_verdict_json: dict[str, Any] | None = None

    if labels.get("local_live_tinfoil_provider") != LOCAL_LIVE_TINFOIL_EXPECTED_VALUES["provider"]:
        violations.append("local_live_tinfoil_provider marker must match local live verdict provider")

    for index, record in enumerate(records, start=1):
        subject = f"local live verdict JSONL record {index}"
        verdict_json = record.get("verdict_json")
        if not isinstance(verdict_json, dict):
            continue

        cache_hit = record.get("cache_hit")
        if isinstance(cache_hit, bool):
            cache_hit_states.add(cache_hit)
            if not cache_hit and fresh_verdict_json is None:
                fresh_verdict_json = verdict_json
        else:
            violations.append(f"{subject}.cache_hit must be a boolean")

        for field, expected in LOCAL_LIVE_TINFOIL_EXPECTED_VALUES.items():
            actual = _record_or_verdict_value(record, verdict_json, field)
            if actual != expected:
                violations.append(f"{subject}.{field} expected {expected!r}, got {actual!r}")

        for field, expected in LOCAL_LIVE_TINFOIL_VERDICT_VALUES.items():
            actual = verdict_json.get(field)
            if actual != expected:
                violations.append(
                    f"{subject}.verdict_json.{field} expected {expected!r}, got {actual!r}"
                )

        for field in LOCAL_LIVE_TINFOIL_MIRRORED_FIELDS:
            if (
                field in record
                and field in verdict_json
                and record.get(field) != verdict_json.get(field)
            ):
                violations.append(f"{subject}.verdict_json.{field} must match top-level {field}")

        for field in ("registry_signature", "reference_values_signature"):
            violations.extend(_validate_signature(f"{subject}.verdict_json", verdict_json, field))
            top_signature = record.get(field)
            verdict_signature = verdict_json.get(field)
            if top_signature != LOCAL_LIVE_TINFOIL_SIGNATURE:
                violations.append(
                    f"{subject}.{field} expected {LOCAL_LIVE_TINFOIL_SIGNATURE!r}, "
                    f"got {top_signature!r}"
                )
            if verdict_signature != LOCAL_LIVE_TINFOIL_SIGNATURE:
                violations.append(
                    f"{subject}.verdict_json.{field} expected "
                    f"{LOCAL_LIVE_TINFOIL_SIGNATURE!r}, got {verdict_signature!r}"
                )

        if record.get("errors") != []:
            violations.append(f"{subject}.errors must be empty")
        if verdict_json.get("errors") != []:
            violations.append(f"{subject}.verdict_json.errors must be empty")

        unsupported_modes = _record_or_verdict_value(
            record,
            verdict_json,
            "known_unsupported_modes",
        )
        if not isinstance(unsupported_modes, list) or "streaming" not in unsupported_modes:
            violations.append(f"{subject}.known_unsupported_modes must contain 'streaming'")

        checks = verdict_json.get("checks")
        if not isinstance(checks, dict):
            violations.append(f"{subject}.verdict_json.checks must be an object")
        else:
            for field, expected in LOCAL_LIVE_TINFOIL_REQUIRED_CHECKS.items():
                actual = checks.get(field)
                if actual != expected:
                    violations.append(
                        f"{subject}.verdict_json.checks.{field} expected "
                        f"{expected!r}, got {actual!r}"
                    )

        artifacts = verdict_json.get("artifacts")
        if not isinstance(artifacts, dict):
            violations.append(f"{subject}.verdict_json.artifacts must be an object")
        else:
            for field in LOCAL_LIVE_TINFOIL_REQUIRED_ARTIFACTS:
                value = artifacts.get(field)
                if value in (None, "", []):
                    violations.append(
                        f"{subject}.verdict_json.artifacts.{field} must be present"
                    )
            source_url = artifacts.get("source_url")
            if not (
                isinstance(source_url, str)
                and source_url.startswith("https://127.0.0.1:")
                and source_url.endswith("/.well-known/tinfoil-attestation")
            ):
                violations.append(
                    f"{subject}.verdict_json.artifacts.source_url must be the local HTTPS attestation endpoint"
                )
            if not isinstance(artifacts.get("model_artifacts"), list):
                violations.append(
                    f"{subject}.verdict_json.artifacts.model_artifacts must be an array"
                )

    if cache_hit_states != {False, True}:
        violations.append(
            "local live verdict JSONL must include both fresh and cached records"
        )
    violations.extend(
        _validate_local_live_tinfoil_marker_binding(labels, fresh_verdict_json)
    )

    return violations


def _primary_metric_labels(verdict: dict[str, Any] | None) -> dict[str, str]:
    if verdict is None:
        return {}
    labels: dict[str, str] = {}
    for field in PRIMARY_METRIC_LABEL_FIELDS:
        value = verdict.get(field)
        if isinstance(value, str) and value:
            labels[field] = value
    return labels


def _metric_labels_match(labels: Any, expected: dict[str, str]) -> bool:
    return isinstance(labels, dict) and all(labels.get(field) == value for field, value in expected.items())


def _validate_metrics_records(
    records: list[dict[str, Any]],
    labels_from_transcript: dict[str, str],
    verdict: dict[str, Any] | None,
) -> list[str]:
    violations: list[str] = []
    events = {record.get("event") for record in records}
    missing = sorted(REQUIRED_METRIC_EVENTS - {event for event in events if isinstance(event, str)})
    if missing:
        violations.append(f"metrics JSONL missing required event types: {missing}")
    count_expectations = {
        "metrics_events": len(records),
        "metrics_jsonl_records": len(records),
        "metrics_cache_hits": sum(
            1
            for record in records
            if record.get("event") == "verification_cache"
            and record.get("cache_event") == "hit"
        ),
        "metrics_verdicts": sum(1 for record in records if record.get("event") == "verdict"),
        "metrics_streaming_fail_closed": sum(
            1 for record in records if record.get("event") == "streaming_fail_closed"
        ),
    }
    for label, actual_count in count_expectations.items():
        expected_count = _integer_label(labels_from_transcript, label)
        if expected_count is not None and expected_count != actual_count:
            violations.append(
                f"{label} marker expected {expected_count} but metrics JSONL has {actual_count}"
            )

    primary_labels = _primary_metric_labels(verdict)
    primary_verdict_cache_states = set()
    primary_latency_steps = set()
    primary_streaming_fail_closed = 0
    for index, record in enumerate(records, start=1):
        subject = f"metrics JSONL record {index}"
        event = record.get("event")
        if not isinstance(event, str) or not event:
            violations.append(f"{subject}.event must be non-empty")
        labels = record.get("labels")
        if isinstance(labels, dict):
            for field in REQUIRED_METRIC_LABEL_FIELDS:
                if not isinstance(labels.get(field), str) or not labels[field]:
                    violations.append(f"{subject}.labels.{field} must be non-empty")
        elif event != "route_selection":
            violations.append(f"{subject}.labels must be an object")
        if primary_labels and event != "route_selection":
            labels = record.get("labels")
            if not _metric_labels_match(labels, primary_labels):
                violations.append(
                    f"{subject}.labels must match printed verdict route identity"
                )
        if event == "route_selection":
            for field in ("provider", "requested_model", "purpose", "outcome"):
                if not isinstance(record.get(field), str) or not record[field]:
                    violations.append(f"{subject}.{field} must be non-empty")
            if (
                verdict is not None
                and record.get("requested_model") == verdict.get("requested_model")
                and record.get("purpose") in {"chat", "verification"}
                and record.get("outcome") != "success"
            ):
                violations.append(
                    f"{subject}.outcome must be success for the printed verdict model"
                )
        if event == "verdict":
            for field in ("status", "enforcement"):
                if not isinstance(record.get(field), str) or not record[field]:
                    violations.append(f"{subject}.{field} must be non-empty")
            for field in ("request_allowed", "would_block_under_enforce", "cache_hit"):
                if not isinstance(record.get(field), bool):
                    violations.append(f"{subject}.{field} must be a boolean")
            if primary_labels and _metric_labels_match(record.get("labels"), primary_labels):
                for field in ("status", "enforcement", "request_allowed", "would_block_under_enforce"):
                    if record.get(field) != verdict.get(field):
                        violations.append(
                            f"{subject}.{field} must match printed verdict.{field}"
                        )
                if isinstance(record.get("cache_hit"), bool):
                    primary_verdict_cache_states.add(record["cache_hit"])
        if (
            event == "latency"
            and primary_labels
            and _metric_labels_match(record.get("labels"), primary_labels)
            and isinstance(record.get("step"), str)
        ):
            primary_latency_steps.add(record["step"])
        if event == "streaming_fail_closed":
            if record.get("endpoint") != "chat_completions":
                violations.append(f"{subject}.endpoint must be chat_completions")
            if primary_labels and _metric_labels_match(record.get("labels"), primary_labels):
                primary_streaming_fail_closed += 1
    if primary_labels:
        if primary_verdict_cache_states != {False, True}:
            violations.append(
                "metrics JSONL must include fresh and cached verdict metrics for the printed verdict route"
            )
        missing_latency_steps = sorted(REQUIRED_PRIMARY_LATENCY_STEPS - primary_latency_steps)
        if missing_latency_steps:
            violations.append(
                "metrics JSONL missing required latency steps for printed verdict route: "
                f"{missing_latency_steps}"
            )
        if primary_streaming_fail_closed != 1:
            violations.append(
                "metrics JSONL must include exactly one streaming_fail_closed event for the printed verdict route"
            )
    return violations


def _validate_primary_audit_records_match_verdict(
    records: list[dict[str, Any]],
    verdict: dict[str, Any] | None,
) -> list[str]:
    if verdict is None:
        return []

    identity_fields = (
        "provider",
        "route_id",
        "requested_model",
        "provider_model",
        "canonical_model",
    )
    candidates = [
        record
        for record in records
        if all(record.get(field) == verdict.get(field) for field in identity_fields)
    ]
    if not candidates:
        return ["audit JSONL must include records for the printed verdict route"]

    violations: list[str] = []
    cache_hit_states = set()
    for index, record in enumerate(candidates, start=1):
        cache_hit = record.get("cache_hit")
        if isinstance(cache_hit, bool):
            cache_hit_states.add(cache_hit)
        else:
            violations.append(
                f"primary audit record {index}.cache_hit must be a boolean"
            )
        for field in PRIMARY_AUDIT_VERDICT_FIELDS:
            if record.get(field) != verdict.get(field):
                violations.append(
                    f"primary audit record {index}.{field} must match printed verdict.{field}"
                )
    if cache_hit_states != {False, True}:
        violations.append(
            "audit JSONL must include both fresh and cached records for the printed verdict route"
        )
    return violations


def _validate_primary_verdict_records(
    records: list[dict[str, Any]],
    verdict: dict[str, Any] | None,
) -> list[str]:
    if verdict is None:
        return []

    violations: list[str] = []
    cache_hit_states = set()

    for index, record in enumerate(records, start=1):
        subject = f"primary verdict JSONL record {index}"
        verdict_json = record.get("verdict_json")
        if not isinstance(verdict_json, dict):
            continue

        cache_hit = record.get("cache_hit")
        if isinstance(cache_hit, bool):
            cache_hit_states.add(cache_hit)
        else:
            violations.append(f"{subject}.cache_hit must be a boolean")

        for field, expected in PROXY_EXPECTED_VALUES.items():
            actual = _record_or_verdict_value(record, verdict_json, field)
            if actual != expected:
                violations.append(f"{subject}.{field} expected {expected!r}, got {actual!r}")

        for field, expected in PROXY_VERDICT_VALUES.items():
            actual = verdict_json.get(field)
            if actual != expected:
                violations.append(
                    f"{subject}.verdict_json.{field} expected {expected!r}, got {actual!r}"
                )

        for field in LOCAL_LIVE_TINFOIL_MIRRORED_FIELDS:
            if (
                field in record
                and field in verdict_json
                and record.get(field) != verdict_json.get(field)
            ):
                violations.append(f"{subject}.verdict_json.{field} must match top-level {field}")

        for field in PRIMARY_AUDIT_VERDICT_FIELDS:
            actual = _record_or_verdict_value(record, verdict_json, field)
            if actual != verdict.get(field):
                violations.append(
                    f"{subject}.{field} must match printed verdict.{field}"
                )

        for field in ("registry_signature", "reference_values_signature"):
            violations.extend(_validate_signature(f"{subject}.verdict_json", verdict_json, field))
            top_signature = record.get(field)
            verdict_signature = verdict_json.get(field)
            if top_signature != DEMO_SIGNATURE:
                violations.append(
                    f"{subject}.{field} expected {DEMO_SIGNATURE!r}, got {top_signature!r}"
                )
            if verdict_signature != DEMO_SIGNATURE:
                violations.append(
                    f"{subject}.verdict_json.{field} expected {DEMO_SIGNATURE!r}, got {verdict_signature!r}"
                )

        if record.get("errors") != []:
            violations.append(f"{subject}.errors must be empty")
        if verdict_json.get("errors") != []:
            violations.append(f"{subject}.verdict_json.errors must be empty")

        unsupported_modes = _record_or_verdict_value(
            record,
            verdict_json,
            "known_unsupported_modes",
        )
        if not isinstance(unsupported_modes, list) or "streaming" not in unsupported_modes:
            violations.append(f"{subject}.known_unsupported_modes must contain 'streaming'")

        checks = verdict_json.get("checks")
        if not isinstance(checks, dict):
            violations.append(f"{subject}.verdict_json.checks must be an object")
        else:
            for field, expected in REQUIRED_CHECKS.items():
                actual = checks.get(field)
                if actual != expected:
                    violations.append(
                        f"{subject}.verdict_json.checks.{field} expected "
                        f"{expected!r}, got {actual!r}"
                    )

        artifacts = verdict_json.get("artifacts")
        if not isinstance(artifacts, dict):
            violations.append(f"{subject}.verdict_json.artifacts must be an object")
        else:
            for field in PROXY_REQUIRED_ARTIFACTS:
                value = artifacts.get(field)
                if value in (None, "", []):
                    violations.append(
                        f"{subject}.verdict_json.artifacts.{field} must be present"
                    )
            if artifacts.get("source_url") != "http://127.0.0.1/demo/v1/confidentiality":
                violations.append(
                    f"{subject}.verdict_json.artifacts.source_url must be the demo evidence endpoint"
                )
            if artifacts.get("e2ee_capability") != "fixture-e2ee":
                violations.append(
                    f"{subject}.verdict_json.artifacts.e2ee_capability must be fixture-e2ee"
                )
            if artifacts.get("model_manifest") != "gpt-oss-120b":
                violations.append(
                    f"{subject}.verdict_json.artifacts.model_manifest must be gpt-oss-120b"
                )
            if not isinstance(artifacts.get("model_artifacts"), list):
                violations.append(
                    f"{subject}.verdict_json.artifacts.model_artifacts must be an array"
                )

    if cache_hit_states != {False, True}:
        violations.append("primary verdict JSONL must include both fresh and cached records")

    return violations


def _validate_local_artifact_signature(
    subject: str,
    signature: Any,
    payload: dict[str, Any],
) -> list[str]:
    violations: list[str] = []
    if not isinstance(signature, dict):
        return [f"{subject}.signature must be an object"]
    for field in ("signer", "key_id", "alg", "value"):
        if not isinstance(signature.get(field), str) or not signature[field]:
            violations.append(f"{subject}.signature.{field} must be non-empty")
    if signature.get("signer") != "confidential-inference-local-demo":
        violations.append(f"{subject}.signature.signer must be confidential-inference-local-demo")
    if signature.get("key_id") != "confidential-inference-local-demo-ed25519-2026":
        violations.append(
            f"{subject}.signature.key_id must be confidential-inference-local-demo-ed25519-2026"
        )
    if signature.get("alg") != "ed25519":
        violations.append(f"{subject}.signature.alg must be ed25519")
    try:
        verify_artifact_signature(
            signature,
            _canonical_json(payload).encode("utf-8"),
            subject,
            LOCAL_DEMO_TRUSTED_SIGNING_KEYS,
        )
    except (ArtifactSignatureError, ValueError) as error:
        violations.append(str(error))
    return violations


def _validate_route_url(
    subject: str,
    route: dict[str, Any],
    *,
    field: str,
    scheme: str,
    suffix: str,
) -> list[str]:
    value = route.get(field)
    if not isinstance(value, str):
        return [f"{subject}.route.{field} must be a URL string"]
    if not value.startswith(f"{scheme}://127.0.0.1:") or not value.endswith(suffix):
        return [
            f"{subject}.route.{field} must use {scheme}://127.0.0.1:*{suffix}, got {value!r}"
        ]
    return []


def _validate_local_registry_artifact(
    artifact: Any,
    labels: dict[str, str],
    local_verdict: dict[str, Any] | None,
    *,
    prefix: str,
    subject: str,
    model_key: str,
    adapter_version: str,
    source: str,
    api_scheme: str,
    api_suffix: str,
    evidence_suffix: str,
    route_expectations: dict[str, Any],
) -> list[str]:
    if not isinstance(artifact, dict):
        return [f"{subject} must be a JSON object"]

    violations: list[str] = []
    if artifact.get("schema") != "confidential-inference.provider-registry-envelope.v1":
        violations.append(f"{subject}.schema must be confidential-inference.provider-registry-envelope.v1")
    payload = artifact.get("payload")
    if not isinstance(payload, dict):
        return [*violations, f"{subject}.payload must be an object"]
    if payload.get("schema") != "confidential-inference.provider-registry.v1":
        violations.append(f"{subject}.payload.schema must be confidential-inference.provider-registry.v1")

    violations.extend(
        _validate_local_artifact_signature(subject, artifact.get("signature"), payload)
    )

    try:
        digest = _canonical_sha256_digest(payload)
    except ValueError as error:
        violations.append(f"{subject}.payload could not be canonicalized: {error}")
        digest = None
    if digest is not None:
        for label in (
            f"{prefix}_provider_registry_digest",
            f"{prefix}_registry_artifact_digest",
        ):
            expected = labels.get(label)
            if expected is None:
                violations.append(f"missing marker {label}")
            elif expected != digest:
                violations.append(f"{label} expected {digest!r}, got {expected!r}")
        if (
            local_verdict is not None
            and local_verdict.get("provider_registry_digest") != digest
        ):
            violations.append(
                f"{subject} digest must match fresh {prefix} verdict.provider_registry_digest"
            )

    source_sync_run = payload.get("source_sync_run")
    if not isinstance(source_sync_run, dict):
        violations.append(f"{subject}.payload.source_sync_run must be an object")
    else:
        if source_sync_run.get("status") != "success":
            violations.append(f"{subject}.payload.source_sync_run.status must be success")
        if source_sync_run.get("source") != source:
            violations.append(
                f"{subject}.payload.source_sync_run.source expected {source!r}, got {source_sync_run.get('source')!r}"
            )

    models = payload.get("models")
    if not isinstance(models, dict):
        return [*violations, f"{subject}.payload.models must be an object"]
    model = models.get(model_key)
    if not isinstance(model, dict):
        return [*violations, f"{subject}.payload.models must include {model_key}"]
    canonical_model = labels.get(f"{prefix}_canonical_model")
    model_expectations = {
        "canonical_model": canonical_model,
    }
    for field, expected in model_expectations.items():
        actual = model.get(field)
        if actual != expected:
            violations.append(f"{subject}.model.{field} expected {expected!r}, got {actual!r}")
    aliases = model.get("aliases")
    if not isinstance(aliases, list) or canonical_model not in aliases:
        violations.append(f"{subject}.model.aliases must include {canonical_model!r}")

    routes = model.get("routes")
    route_id = labels.get(f"{prefix}_route_id")
    if not isinstance(routes, list):
        return [*violations, f"{subject}.model.routes must be an array"]
    route = next(
        (
            candidate
            for candidate in routes
            if isinstance(candidate, dict) and candidate.get("route_id") == route_id
        ),
        None,
    )
    if route is None:
        return [*violations, f"{subject}.model.routes must include {route_id}"]

    expected_route = {
        "route_id": route_id,
        "route_status": "active",
        "provider": labels.get(f"{prefix}_provider"),
        "provider_model": labels.get(f"{prefix}_provider_model"),
        "evidence_family": labels.get(f"{prefix}_evidence_family"),
        "adapter_version": adapter_version,
        "freshness_class": "per_session",
        "channel_binding_kind": labels.get(f"{prefix}_channel_binding_kind"),
        "trust_tier": (
            "app-e2ee"
            if prefix == "local_sdk_app_e2ee"
            else labels.get(f"{prefix}_trust_tier")
        ),
        "streaming": "unsupported",
        "alias_confidence": "curated",
        **route_expectations,
    }
    for field, expected in expected_route.items():
        actual = route.get(field)
        if field == "accepted_gpu_tees" and expected == [] and actual is None:
            continue
        if actual != expected:
            violations.append(f"{subject}.route.{field} expected {expected!r}, got {actual!r}")

    violations.extend(
        _validate_route_url(
            subject,
            route,
            field="api_base_url",
            scheme=api_scheme,
            suffix=api_suffix,
        )
    )
    violations.extend(
        _validate_route_url(
            subject,
            route,
            field="evidence_endpoint",
            scheme=api_scheme,
            suffix=evidence_suffix,
        )
    )
    verdict_artifacts = (
        local_verdict.get("artifacts") if isinstance(local_verdict, dict) else None
    )
    verdict_source_url = (
        verdict_artifacts.get("source_url") if isinstance(verdict_artifacts, dict) else None
    )
    if isinstance(verdict_source_url, str) and route.get("evidence_endpoint") != verdict_source_url:
        violations.append(
            f"{subject}.route.evidence_endpoint must match fresh {prefix} verdict artifacts.source_url"
        )

    return violations


def _validate_local_compatibility_matrix_artifact(
    artifact: Any,
    labels: dict[str, str],
    local_verdict: dict[str, Any] | None,
    *,
    prefix: str,
    subject: str,
    provider_id: str,
    api_scheme: str,
    api_suffix: str,
    attestation_endpoint_shape: str,
    request_encryption: str,
    response_decryption: str,
    require_sdk_app_e2ee: bool,
) -> list[str]:
    if not isinstance(artifact, dict):
        return [f"{subject} must be a JSON object"]

    violations: list[str] = []
    if artifact.get("schema") != "confidential-inference.provider-compatibility-matrix-envelope.v1":
        violations.append(
            f"{subject}.schema must be confidential-inference.provider-compatibility-matrix-envelope.v1"
        )
    payload = artifact.get("payload")
    if not isinstance(payload, dict):
        return [*violations, f"{subject}.payload must be an object"]
    if payload.get("schema") != "confidential-inference.provider-compatibility-matrix.v1":
        violations.append(
            f"{subject}.payload.schema must be confidential-inference.provider-compatibility-matrix.v1"
        )

    violations.extend(
        _validate_local_artifact_signature(subject, artifact.get("signature"), payload)
    )

    try:
        digest = _canonical_sha256_digest(payload)
    except ValueError as error:
        violations.append(f"{subject}.payload could not be canonicalized: {error}")
        digest = None
    if digest is not None:
        label = f"{prefix}_compatibility_matrix_artifact_digest"
        expected = labels.get(label)
        if expected is None:
            violations.append(f"missing marker {label}")
        elif expected != digest:
            violations.append(f"{label} expected {digest!r}, got {expected!r}")

    providers = payload.get("providers")
    if not isinstance(providers, dict):
        return [*violations, f"{subject}.payload.providers must be an object"]
    provider = providers.get(provider_id)
    if not isinstance(provider, dict):
        return [*violations, f"{subject}.payload.providers must include {provider_id}"]

    expected_profile = {
        "provider": labels.get(f"{prefix}_provider"),
        "route_execution_status": "executable",
        "supported_openai_endpoints": ["chat_completions"],
        "model_listing": "signed_registry_only",
        "model_id_rewrite": "use_route_provider_model",
        "token_parameter_rewrite": "preserve_max_tokens",
        "streaming": "unsupported",
        "request_encryption": request_encryption,
        "response_decryption": response_decryption,
        "attestation_endpoint_shape": attestation_endpoint_shape,
        "required_credentials": [],
        "freshness_class": "per_session",
        "cacheability_class": "per_session_verdict",
        "expected_trust_tier": (
            "app-e2ee"
            if prefix == "local_sdk_app_e2ee"
            else labels.get(f"{prefix}_trust_tier")
        ),
        "model_binding_support": "verified",
        "known_unsupported_modes": ["streaming"],
    }
    for field, expected_value in expected_profile.items():
        actual = provider.get(field)
        if actual != expected_value:
            violations.append(
                f"{subject}.provider.{field} expected {expected_value!r}, got {actual!r}"
            )

    violations.extend(
        _validate_route_url(
            subject,
            provider,
            field="api_base_url",
            scheme=api_scheme,
            suffix=api_suffix,
        )
    )

    sdk_app_e2ee = provider.get("sdk_app_e2ee")
    if require_sdk_app_e2ee:
        if not isinstance(sdk_app_e2ee, dict):
            violations.append(f"{subject}.provider.sdk_app_e2ee must be an object")
        else:
            if sdk_app_e2ee.get("key_id") != "local-sdk-app-e2ee-key":
                violations.append(
                    f"{subject}.provider.sdk_app_e2ee.key_id must be local-sdk-app-e2ee-key"
                )
            public_key_base64 = sdk_app_e2ee.get("public_key_base64")
            if not isinstance(public_key_base64, str) or not public_key_base64:
                violations.append(
                    f"{subject}.provider.sdk_app_e2ee.public_key_base64 must be non-empty"
                )
            else:
                try:
                    public_key = base64.b64decode(public_key_base64, validate=True)
                except (ValueError, binascii.Error) as error:
                    violations.append(
                        f"{subject}.provider.sdk_app_e2ee.public_key_base64 is invalid: {error}"
                    )
                else:
                    digest = "sha256:" + hashlib.sha256(public_key).hexdigest()
                    verdict_artifacts = (
                        local_verdict.get("artifacts")
                        if isinstance(local_verdict, dict)
                        else None
                    )
                    report_data = (
                        verdict_artifacts.get("report_data")
                        if isinstance(verdict_artifacts, dict)
                        else None
                    )
                    if report_data is not None and report_data != digest:
                        violations.append(
                            f"{subject}.provider.sdk_app_e2ee.public_key_base64 digest must match fresh {prefix} verdict report_data"
                        )
    elif sdk_app_e2ee is not None:
        violations.append(f"{subject}.provider.sdk_app_e2ee must be absent")

    return violations


def _validate_local_live_reference_values_artifact(
    artifact: Any,
    labels: dict[str, str],
    local_live_verdict: dict[str, Any] | None,
) -> list[str]:
    subject = "local live reference-values artifact"
    if not isinstance(artifact, dict):
        return [f"{subject} must be a JSON object"]

    violations: list[str] = []
    if artifact.get("schema") != "confidential-inference.reference-values-envelope.v1":
        violations.append(f"{subject}.schema must be confidential-inference.reference-values-envelope.v1")
    payload = artifact.get("payload")
    if not isinstance(payload, dict):
        return [*violations, f"{subject}.payload must be an object"]
    if payload.get("schema") != "confidential-inference.reference-values.v1":
        violations.append(f"{subject}.payload.schema must be confidential-inference.reference-values.v1")

    signature = artifact.get("signature")
    if not isinstance(signature, dict):
        violations.append(f"{subject}.signature must be an object")
    else:
        for field in ("signer", "key_id", "alg", "value"):
            if not isinstance(signature.get(field), str) or not signature[field]:
                violations.append(f"{subject}.signature.{field} must be non-empty")
        if signature.get("signer") != "confidential-inference-local-demo":
            violations.append(f"{subject}.signature.signer must be confidential-inference-local-demo")
        if signature.get("key_id") != "confidential-inference-local-demo-ed25519-2026":
            violations.append(
                f"{subject}.signature.key_id must be confidential-inference-local-demo-ed25519-2026"
            )
        if signature.get("alg") != "ed25519":
            violations.append(f"{subject}.signature.alg must be ed25519")
        try:
            verify_artifact_signature(
                signature,
                _canonical_json(payload).encode("utf-8"),
                subject,
                LOCAL_DEMO_TRUSTED_SIGNING_KEYS,
            )
        except (ArtifactSignatureError, ValueError) as error:
            violations.append(str(error))

    try:
        digest = _canonical_sha256_digest(payload)
    except ValueError as error:
        violations.append(f"{subject}.payload could not be canonicalized: {error}")
        digest = None
    if digest is not None:
        for label in (
            "local_live_tinfoil_reference_values_digest",
            "local_live_tinfoil_reference_values_artifact_digest",
        ):
            expected = labels.get(label)
            if expected is None:
                violations.append(f"missing marker {label}")
            elif expected != digest:
                violations.append(f"{label} expected {digest!r}, got {expected!r}")
        if (
            local_live_verdict is not None
            and local_live_verdict.get("reference_values_digest") != digest
        ):
            violations.append(
                "local live reference-values artifact digest must match fresh "
                "local-live verdict.reference_values_digest"
            )

    providers = payload.get("providers")
    if not isinstance(providers, dict):
        return [*violations, f"{subject}.payload.providers must be an object"]
    provider = providers.get("local-tinfoil-live")
    if not isinstance(provider, dict):
        return [*violations, f"{subject}.payload.providers.local-tinfoil-live must be an object"]
    accepted_measurements = provider.get("accepted_measurements")
    verdict_artifacts = (
        local_live_verdict.get("artifacts") if isinstance(local_live_verdict, dict) else None
    )
    tee_measurement = (
        verdict_artifacts.get("tee_measurement") if isinstance(verdict_artifacts, dict) else None
    )
    if not isinstance(accepted_measurements, list) or not accepted_measurements:
        violations.append(f"{subject}.accepted_measurements must be non-empty")
    elif isinstance(tee_measurement, str) and tee_measurement not in accepted_measurements:
        violations.append(
            f"{subject}.accepted_measurements must include fresh local-live verdict TEE measurement"
        )

    routes = provider.get("routes")
    route_id = labels.get("local_live_tinfoil_route_id")
    if not isinstance(routes, dict):
        return [*violations, f"{subject}.routes must be an object"]
    route_reference = routes.get(route_id)
    if not isinstance(route_reference, dict):
        return [*violations, f"{subject}.routes must include {route_id}"]

    route_expectations = {
        "canonical_model": labels.get("local_live_tinfoil_canonical_model"),
        "provider_model": labels.get("local_live_tinfoil_provider_model"),
        "evidence_family": "tinfoil_hw_verified_tls",
        "channel_binding_kind": "tee_terminated_tls",
        "trust_tier": "hw-verified-tls",
        "e2ee_public_key_digest": "sha256:not-applicable",
        "workload_image_digest": "sha256:local-live-tinfoil-workload-image",
    }
    for field, expected in route_expectations.items():
        actual = route_reference.get(field)
        if actual != expected:
            violations.append(f"{subject}.route.{field} expected {expected!r}, got {actual!r}")

    if route_reference.get("tls_spki_sha256") != (
        verdict_artifacts.get("signing_public_key")
        if isinstance(verdict_artifacts, dict)
        else None
    ):
        violations.append(
            f"{subject}.route.tls_spki_sha256 must match fresh local-live verdict signing_public_key"
        )
    accepted_cpu_tees = route_reference.get("accepted_cpu_tees")
    if not isinstance(accepted_cpu_tees, list) or "tdx" not in accepted_cpu_tees:
        violations.append(f"{subject}.route.accepted_cpu_tees must contain 'tdx'")
    model_artifacts = route_reference.get("model_artifacts")
    if not isinstance(model_artifacts, list) or not model_artifacts:
        violations.append(f"{subject}.route.model_artifacts must be non-empty")
    else:
        has_weights = any(
            isinstance(artifact, dict)
            and artifact.get("kind") == "weights"
            and artifact.get("name") == labels.get("local_live_tinfoil_canonical_model")
            and artifact.get("digest") == "sha256:local-live-tinfoil-weights"
            for artifact in model_artifacts
        )
        if not has_weights:
            violations.append(
                f"{subject}.route.model_artifacts must include local live model weights"
            )

    return violations


def _validate_local_app_e2ee_reference_values_artifact(
    artifact: Any,
    labels: dict[str, str],
    local_app_verdict: dict[str, Any] | None,
) -> list[str]:
    subject = "local SDK app-E2EE reference-values artifact"
    if not isinstance(artifact, dict):
        return [f"{subject} must be a JSON object"]

    violations: list[str] = []
    if artifact.get("schema") != "confidential-inference.reference-values-envelope.v1":
        violations.append(f"{subject}.schema must be confidential-inference.reference-values-envelope.v1")
    payload = artifact.get("payload")
    if not isinstance(payload, dict):
        return [*violations, f"{subject}.payload must be an object"]
    if payload.get("schema") != "confidential-inference.reference-values.v1":
        violations.append(f"{subject}.payload.schema must be confidential-inference.reference-values.v1")

    signature = artifact.get("signature")
    if not isinstance(signature, dict):
        violations.append(f"{subject}.signature must be an object")
    else:
        try:
            verify_artifact_signature(
                signature,
                _canonical_json(payload).encode("utf-8"),
                subject,
                LOCAL_DEMO_TRUSTED_SIGNING_KEYS,
            )
        except (ArtifactSignatureError, ValueError) as error:
            violations.append(str(error))
        if signature.get("signer") != "confidential-inference-local-demo":
            violations.append(f"{subject}.signature.signer must be confidential-inference-local-demo")
        if signature.get("key_id") != "confidential-inference-local-demo-ed25519-2026":
            violations.append(
                f"{subject}.signature.key_id must be confidential-inference-local-demo-ed25519-2026"
            )
        if signature.get("alg") != "ed25519":
            violations.append(f"{subject}.signature.alg must be ed25519")

    try:
        digest = _canonical_sha256_digest(payload)
    except ValueError as error:
        violations.append(f"{subject}.payload could not be canonicalized: {error}")
        digest = None
    if digest is not None:
        for label in (
            "local_sdk_app_e2ee_reference_values_digest",
            "local_sdk_app_e2ee_reference_values_artifact_digest",
        ):
            expected = labels.get(label)
            if expected is None:
                violations.append(f"missing marker {label}")
            elif expected != digest:
                violations.append(f"{label} expected {digest!r}, got {expected!r}")
        if (
            local_app_verdict is not None
            and local_app_verdict.get("reference_values_digest") != digest
        ):
            violations.append(
                "local SDK app-E2EE reference-values artifact digest must match "
                "fresh app-E2EE verdict.reference_values_digest"
            )

    providers = payload.get("providers")
    if not isinstance(providers, dict):
        return [*violations, f"{subject}.payload.providers must be an object"]
    provider = providers.get("local-sdk-app-e2ee")
    if not isinstance(provider, dict):
        return [*violations, f"{subject}.payload.providers.local-sdk-app-e2ee must be an object"]

    verdict_artifacts = (
        local_app_verdict.get("artifacts") if isinstance(local_app_verdict, dict) else None
    )
    accepted_measurements = provider.get("accepted_measurements")
    tee_measurement = (
        verdict_artifacts.get("tee_measurement") if isinstance(verdict_artifacts, dict) else None
    )
    if not isinstance(accepted_measurements, list) or not accepted_measurements:
        violations.append(f"{subject}.accepted_measurements must be non-empty")
    elif isinstance(tee_measurement, str) and tee_measurement not in accepted_measurements:
        violations.append(
            f"{subject}.accepted_measurements must include fresh app-E2EE verdict TEE measurement"
        )

    routes = provider.get("routes")
    route_id = labels.get("local_sdk_app_e2ee_route_id")
    if not isinstance(routes, dict):
        return [*violations, f"{subject}.routes must be an object"]
    route_reference = routes.get(route_id)
    if not isinstance(route_reference, dict):
        return [*violations, f"{subject}.routes must include {route_id}"]

    route_expectations = {
        "canonical_model": labels.get("local_sdk_app_e2ee_canonical_model"),
        "provider_model": labels.get("local_sdk_app_e2ee_provider_model"),
        "evidence_family": "dstack_app_e2ee",
        "channel_binding_kind": "attested_app_e2ee",
        "trust_tier": "app-e2ee",
        "workload_image_digest": "sha256:" + "a" * 64,
        "workload_images": [
            {
                "service": "root",
                "reference": "local-sdk-app-e2ee/worker@sha256:" + "a" * 64,
                "digest": "sha256:" + "a" * 64,
            }
        ],
    }
    for field, expected in route_expectations.items():
        actual = route_reference.get(field)
        if actual != expected:
            violations.append(f"{subject}.route.{field} expected {expected!r}, got {actual!r}")

    if route_reference.get("e2ee_public_key_digest") != (
        verdict_artifacts.get("report_data") if isinstance(verdict_artifacts, dict) else None
    ):
        violations.append(
            f"{subject}.route.e2ee_public_key_digest must match fresh app-E2EE verdict report_data"
        )
    accepted_cpu_tees = route_reference.get("accepted_cpu_tees")
    if not isinstance(accepted_cpu_tees, list) or "tdx" not in accepted_cpu_tees:
        violations.append(f"{subject}.route.accepted_cpu_tees must contain 'tdx'")
    model_artifacts = route_reference.get("model_artifacts")
    verdict_model_artifacts = (
        verdict_artifacts.get("model_artifacts") if isinstance(verdict_artifacts, dict) else None
    )
    if not isinstance(model_artifacts, list) or not model_artifacts:
        violations.append(f"{subject}.route.model_artifacts must be non-empty")
    elif isinstance(verdict_model_artifacts, list):
        for artifact in verdict_model_artifacts:
            if artifact not in model_artifacts:
                violations.append(
                    f"{subject}.route.model_artifacts must include fresh app-E2EE verdict artifact {artifact!r}"
                )

    return violations



def _integer_label(labels: dict[str, str], label: str) -> int | None:
    value = labels.get(label)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _fresh_verdict_json(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    for record in records:
        if record.get("cache_hit") is False and isinstance(record.get("verdict_json"), dict):
            return record["verdict_json"]
    return None


def _validate_demo_artifacts(
    output_path: Path,
    labels: dict[str, str],
    verdict: dict[str, Any] | None,
) -> list[str]:
    violations: list[str] = []
    local_app_e2ee_verdict_json: dict[str, Any] | None = None
    local_live_verdict_json: dict[str, Any] | None = None
    artifact_specs = (
        ("metrics_log", "metrics JSONL", "metrics_jsonl_records"),
        ("audit_log", "audit JSONL", "audit_records"),
        (
            "primary_verdict_store",
            "primary verdict JSONL",
            "primary_persisted_verdicts",
        ),
        (
            "proxy_verdict_store",
            "proxy verdict JSONL",
            "proxy_persisted_verdicts",
        ),
        (
            "phase2_fixture_verdict_store",
            "phase2 fixture verdict JSONL",
            "phase2_fixture_persisted_verdicts",
        ),
        (
            "local_sdk_app_e2ee_verdict_store",
            "local SDK app-E2EE verdict JSONL",
            "local_sdk_app_e2ee_persisted_verdicts",
        ),
        (
            "local_live_tinfoil_verdict_store",
            "local live verdict JSONL",
            "local_live_tinfoil_persisted_verdicts",
        ),
    )
    for label, subject, count_label in artifact_specs:
        artifact_label = labels.get(label)
        if not artifact_label:
            continue
        artifact_path = _resolve_artifact_path(output_path, artifact_label)
        records, load_violations, text = _load_jsonl(artifact_path, subject)
        violations.extend(load_violations)
        violations.extend(_validate_no_artifact_plaintext(subject, text))
        expected_count = _integer_label(labels, count_label)
        if expected_count is not None and len(records) != expected_count:
            violations.append(
                f"{subject} has {len(records)} records, expected exactly {expected_count}"
            )
        if not records:
            continue
        if label == "metrics_log":
            violations.extend(_validate_metrics_records(records, labels, verdict))
        else:
            require_nested_verdict = label in {
                "primary_verdict_store",
                "proxy_verdict_store",
                "phase2_fixture_verdict_store",
                "local_sdk_app_e2ee_verdict_store",
                "local_live_tinfoil_verdict_store",
            }
            for index, record in enumerate(records, start=1):
                violations.extend(
                    _validate_audit_like_record(
                        f"{subject} record {index}",
                        record,
                        require_nested_verdict=require_nested_verdict,
                    )
                )
            if label == "audit_log":
                violations.extend(
                    _validate_primary_audit_records_match_verdict(records, verdict)
                )
            elif label == "primary_verdict_store":
                violations.extend(_validate_primary_verdict_records(records, verdict))
            elif label == "proxy_verdict_store":
                violations.extend(_validate_proxy_verdict_records(records, labels))
            elif label == "phase2_fixture_verdict_store":
                violations.extend(_validate_phase2_fixture_records(records, labels))
            elif label == "local_sdk_app_e2ee_verdict_store":
                violations.extend(_validate_local_sdk_app_e2ee_records(records, labels))
                local_app_e2ee_verdict_json = _fresh_verdict_json(records)
            elif label == "local_live_tinfoil_verdict_store":
                violations.extend(_validate_local_live_tinfoil_records(records, labels))
                local_live_verdict_json = _fresh_verdict_json(records)
    json_artifact_specs = (
        (
            "active_policy_artifact",
            "active policy artifact",
        ),
        (
            "active_trust_artifacts_artifact",
            "active trust artifacts artifact",
        ),
        (
            "local_sdk_app_e2ee_registry_artifact",
            "local SDK app-E2EE registry artifact",
        ),
        (
            "local_sdk_app_e2ee_compatibility_matrix_artifact",
            "local SDK app-E2EE compatibility matrix artifact",
        ),
        (
            "local_sdk_app_e2ee_reference_values_artifact",
            "local SDK app-E2EE reference-values artifact",
        ),
        (
            "local_live_tinfoil_registry_artifact",
            "local live registry artifact",
        ),
        (
            "local_live_tinfoil_compatibility_matrix_artifact",
            "local live compatibility matrix artifact",
        ),
        (
            "local_live_tinfoil_reference_values_artifact",
            "local live reference-values artifact",
        ),
    )
    for label, subject in json_artifact_specs:
        artifact_label = labels.get(label)
        if not artifact_label:
            continue
        artifact_path = _resolve_artifact_path(output_path, artifact_label)
        artifact, load_violations, text = _load_json(artifact_path, subject)
        violations.extend(load_violations)
        violations.extend(_validate_no_artifact_plaintext(subject, text))
        if load_violations:
            continue
        if label == "active_policy_artifact":
            violations.extend(_validate_active_policy_artifact(artifact, labels, verdict))
        elif label == "active_trust_artifacts_artifact":
            violations.extend(
                _validate_active_trust_artifacts_artifact(artifact, labels, verdict)
            )
        elif label == "local_sdk_app_e2ee_registry_artifact":
            violations.extend(
                _validate_local_registry_artifact(
                    artifact,
                    labels,
                    local_app_e2ee_verdict_json,
                    prefix="local_sdk_app_e2ee",
                    subject="local SDK app-E2EE registry artifact",
                    model_key="gpt-oss-120b",
                    adapter_version="local-sdk-app-e2ee-demo-adapter/0.1.0",
                    source="confidential-demo-local-sdk-app-e2ee",
                    api_scheme="http",
                    api_suffix="/v1",
                    evidence_suffix="/v1/confidentiality",
                    route_expectations={
                        "request_confidentiality_requirement": (
                            "bound_to_attested_workload"
                        ),
                        "response_confidentiality_requirement": (
                            "bound_to_attested_workload"
                        ),
                        "response_integrity_requirement": "any_bound",
                        "accepted_gpu_tees": [],
                        "request_encryption": "required",
                        "response_decryption": "required",
                    },
                )
            )
        elif label == "local_sdk_app_e2ee_compatibility_matrix_artifact":
            violations.extend(
                _validate_local_compatibility_matrix_artifact(
                    artifact,
                    labels,
                    local_app_e2ee_verdict_json,
                    prefix="local_sdk_app_e2ee",
                    subject="local SDK app-E2EE compatibility matrix artifact",
                    provider_id="local-sdk-app-e2ee",
                    api_scheme="http",
                    api_suffix="/v1",
                    attestation_endpoint_shape="dstack_app_e2ee_local_demo",
                    request_encryption="required",
                    response_decryption="required",
                    require_sdk_app_e2ee=True,
                )
            )
        elif label == "local_sdk_app_e2ee_reference_values_artifact":
            violations.extend(
                _validate_local_app_e2ee_reference_values_artifact(
                    artifact,
                    labels,
                    local_app_e2ee_verdict_json,
                )
            )
        elif label == "local_live_tinfoil_registry_artifact":
            violations.extend(
                _validate_local_registry_artifact(
                    artifact,
                    labels,
                    local_live_verdict_json,
                    prefix="local_live_tinfoil",
                    subject="local live registry artifact",
                    model_key="llama-3.3-70b",
                    adapter_version="local-live-tinfoil-demo-adapter/0.1.0",
                    source="confidential-demo-local-live-tinfoil",
                    api_scheme="https",
                    api_suffix="/v1",
                    evidence_suffix="/.well-known/tinfoil-attestation",
                    route_expectations={
                        "request_confidentiality_requirement": (
                            "bound_to_attested_workload"
                        ),
                        "response_confidentiality_requirement": (
                            "bound_to_attested_workload"
                        ),
                        "response_integrity_requirement": "channel_bound",
                        "accepted_gpu_tees": [],
                        "request_encryption": "not_required",
                        "response_decryption": "not_required",
                    },
                )
            )
        elif label == "local_live_tinfoil_compatibility_matrix_artifact":
            violations.extend(
                _validate_local_compatibility_matrix_artifact(
                    artifact,
                    labels,
                    local_live_verdict_json,
                    prefix="local_live_tinfoil",
                    subject="local live compatibility matrix artifact",
                    provider_id="local-tinfoil-live",
                    api_scheme="https",
                    api_suffix="/v1",
                    attestation_endpoint_shape="tinfoil_live_tls_local_demo",
                    request_encryption="not_required",
                    response_decryption="not_required",
                    require_sdk_app_e2ee=False,
                )
            )
        elif label == "local_live_tinfoil_reference_values_artifact":
            violations.extend(
                _validate_local_live_reference_values_artifact(
                    artifact,
                    labels,
                    local_live_verdict_json,
                )
            )
    return violations


def check_demo_output(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema": SCHEMA,
            "output": path.as_posix(),
            "marker_count": 0,
            "violations": [f"{path} does not exist"],
        }

    text = path.read_text(encoding="utf-8")
    labels = _parse_labels(text)
    verdict, verdict_violations = _extract_verdict(text)
    violations = [
        *_validate_labels(labels, text),
        *verdict_violations,
        *_validate_verdict(verdict),
        *_validate_active_metadata_markers(labels, verdict),
        *_validate_proxy_markers(labels, verdict),
        *_validate_route_digest_markers(labels),
        *_validate_demo_artifacts(path, labels, verdict),
    ]

    return {
        "schema": SCHEMA,
        "output": path.as_posix(),
        "marker_count": len(labels),
        "verdict_status": verdict.get("status") if verdict else None,
        "violations": violations,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Path containing confidential-demo stdout.")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON.")
    args = parser.parse_args(argv)

    report = check_demo_output(args.output)
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2, separators=(",", ": ")))
    elif report["violations"]:
        for violation in report["violations"]:
            print(f"demo output policy violation: {violation}", file=sys.stderr)
    else:
        print(
            "demo output policy ok: "
            f"output={report['output']} "
            f"markers={report['marker_count']} "
            f"verdict_status={report['verdict_status']}"
        )
    return 1 if report["violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
