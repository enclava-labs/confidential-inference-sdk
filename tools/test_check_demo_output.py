from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check_demo_output.py")
SPEC = importlib.util.spec_from_file_location("check_demo_output", MODULE_PATH)
assert SPEC is not None
check_demo_output = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(check_demo_output)

from artifact_signatures import encode_unpadded_base64url, sign_ed25519  # noqa: E402


DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
DEMO_SIGNATURE = {
    "signer": "confidential-inference",
    "key_id": "confidential-inference-demo-ed25519-2026",
    "alg": "ed25519",
}
LOCAL_LIVE_SIGNATURE = {
    "signer": "confidential-inference-local-demo",
    "key_id": "confidential-inference-local-demo-ed25519-2026",
    "alg": "ed25519",
}
PHASE2_SIGNATURE = {
    "signer": "confidential-inference",
    "key_id": "confidential-inference-phase2-fixture-ed25519-2026",
    "alg": "ed25519",
}
LOCAL_DEMO_SEED = bytes([13]) * 32
LOCAL_APP_E2EE_PUBLIC_KEY_BYTES = bytes([2]) * 32
LOCAL_APP_E2EE_PUBLIC_KEY_BASE64 = base64.b64encode(
    LOCAL_APP_E2EE_PUBLIC_KEY_BYTES
).decode("ascii")
LOCAL_APP_E2EE_PUBLIC_KEY_DIGEST = (
    "sha256:" + hashlib.sha256(LOCAL_APP_E2EE_PUBLIC_KEY_BYTES).hexdigest()
)

REPO_ROOT = MODULE_PATH.parent.parent
DEMO_REGISTRY_ENVELOPE = json.loads(
    (REPO_ROOT / "fixtures/registry/demo-registry.json").read_text(encoding="utf-8")
)
DEMO_REFERENCE_VALUES_ENVELOPE = json.loads(
    (REPO_ROOT / "fixtures/reference-values/demo-envelope.json").read_text(
        encoding="utf-8"
    )
)
PRIMARY_REGISTRY_DIGEST = check_demo_output._canonical_sha256_digest(
    DEMO_REGISTRY_ENVELOPE["payload"]
)
PRIMARY_REFERENCE_VALUES_DIGEST = check_demo_output._canonical_sha256_digest(
    DEMO_REFERENCE_VALUES_ENVELOPE["payload"]
)


def sample_active_policy_payload(
    *,
    provider_registry_digest: str = PRIMARY_REGISTRY_DIGEST,
    reference_values_digest: str = PRIMARY_REFERENCE_VALUES_DIGEST,
):
    return {
        "schema": "confidential-inference.policy.v1",
        "enforcement": "enforce",
        "hardware": {
            "cpu": {"accepted_tees": ["tdx"], "required": True},
            "gpu": {"accepted_tees": [], "required": False},
        },
        "model_binding": "required",
        "request_channel_binding": "required",
        "response_integrity": "channel_bound",
        "provider_registry_digest": provider_registry_digest,
        "reference_values_digest": reference_values_digest,
    }


PRIMARY_POLICY_DIGEST = check_demo_output._canonical_sha256_digest(
    sample_active_policy_payload()
)


def sample_verdict(**overrides):
    verdict = {
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
        "route_id": "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p",
        "evidence_family": "fixture_dstack",
        "alias_confidence": "curated",
        "adapter_version": "demo-fixture-adapter/0.1.0",
        "freshness_class": "per_session",
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
        "known_unsupported_modes": ["streaming"],
        "policy_digest": PRIMARY_POLICY_DIGEST,
        "provider_registry_digest": PRIMARY_REGISTRY_DIGEST,
        "reference_values_digest": PRIMARY_REFERENCE_VALUES_DIGEST,
        "raw_evidence_digest": DIGEST,
        "evidence_digest": DIGEST,
        "registry_version": "2026-07-05-demo",
        "registry_source": "bundled",
        "registry_sync_completed_at": "2026-07-05T00:00:00Z",
        "registry_signature": DEMO_SIGNATURE,
        "reference_values_version": "2026-07-05-demo",
        "reference_values_source": "bundled",
        "reference_values_signature": DEMO_SIGNATURE,
        "verified_at": "2098-12-31T23:50:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "validity": {"computed_expires_at": "2099-01-01T00:00:00Z"},
        "checks": {
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
        },
        "artifacts": {
            "source_url": "http://127.0.0.1/demo/v1/confidentiality",
            "tee_measurement": "sha256:demo-tee-measurement",
            "report_data": "sha256:demo-e2ee-key",
            "signing_public_key": None,
            "e2ee_capability": "fixture-e2ee",
            "model_manifest": "gpt-oss-120b",
            "model_artifacts": [
                {
                    "kind": "weights",
                    "name": "gpt-oss-120b",
                    "digest": "sha256:demo-weights",
                },
                {
                    "kind": "tokenizer",
                    "name": "tokenizer.json",
                    "digest": "sha256:demo-tokenizer",
                },
            ],
        },
        "errors": [],
    }
    verdict.update(overrides)
    return verdict


def sample_active_policy_snapshot(policy=None):
    policy = sample_active_policy_payload() if policy is None else policy
    return {
        "schema": "confidential-inference.active-policy.v1",
        "policy": copy.deepcopy(policy),
        "policy_digest": check_demo_output._canonical_sha256_digest(policy),
    }


def sample_active_trust_artifacts():
    return {
        "registry": copy.deepcopy(DEMO_REGISTRY_ENVELOPE["payload"]),
        "registry_digest": PRIMARY_REGISTRY_DIGEST,
        "registry_source": "bundled",
        "registry_signature": copy.deepcopy(DEMO_REGISTRY_ENVELOPE["signature"]),
        "reference_values": copy.deepcopy(DEMO_REFERENCE_VALUES_ENVELOPE["payload"]),
        "reference_values_digest": PRIMARY_REFERENCE_VALUES_DIGEST,
        "reference_values_source": "bundled",
        "reference_values_signature": copy.deepcopy(
            DEMO_REFERENCE_VALUES_ENVELOPE["signature"]
        ),
    }


def sample_audit_record(*, include_nested_verdict: bool = False, **overrides):
    verdict = sample_verdict()
    record = {
        "provider": verdict["provider"],
        "route_id": verdict["route_id"],
        "requested_model": verdict["requested_model"],
        "provider_model": verdict["provider_model"],
        "canonical_model": verdict["canonical_model"],
        "evidence_family": verdict["evidence_family"],
        "adapter_version": verdict["adapter_version"],
        "trust_tier": verdict["trust_tier"],
        "channel_binding_kind": verdict["channel_binding_kind"],
        "request_confidentiality_result": verdict["request_confidentiality_result"],
        "response_confidentiality_result": verdict["response_confidentiality_result"],
        "response_integrity_result": verdict["response_integrity_result"],
        "enforcement": verdict["enforcement"],
        "status": verdict["status"],
        "request_allowed": verdict["request_allowed"],
        "would_block_under_enforce": verdict["would_block_under_enforce"],
        "policy_digest": verdict["policy_digest"],
        "provider_registry_digest": verdict["provider_registry_digest"],
        "registry_version": verdict["registry_version"],
        "registry_source": verdict["registry_source"],
        "registry_sync_completed_at": verdict["registry_sync_completed_at"],
        "registry_signature": verdict["registry_signature"],
        "reference_values_digest": verdict["reference_values_digest"],
        "reference_values_version": verdict["reference_values_version"],
        "reference_values_source": verdict["reference_values_source"],
        "reference_values_signature": verdict["reference_values_signature"],
        "raw_evidence_digest": verdict["raw_evidence_digest"],
        "evidence_digest": verdict["evidence_digest"],
        "verified_at": verdict["verified_at"],
        "expires_at": verdict["expires_at"],
        "freshness_class": verdict["freshness_class"],
        "streaming_allowed": verdict["streaming_allowed"],
        "route_execution_status": verdict["route_execution_status"],
        "chat_executable": verdict["chat_executable"],
        "known_unsupported_modes": verdict["known_unsupported_modes"],
        "cache_hit": False,
        "errors": verdict["errors"],
    }
    if include_nested_verdict:
        record["verdict_json"] = verdict
    record.update(overrides)
    return record


def sample_phase2_tinfoil_verdict(**overrides):
    verdict = sample_verdict(
        trust_tier="hw-verified-tls",
        provider="tinfoil-fixture",
        requested_model="llama-3.3-70b",
        provider_model="llama-3.3-70b",
        canonical_model="llama-3.3-70b",
        route_id="tinfoil-fixture:llama-3.3-70b:llama-3.3-70b",
        evidence_family="tinfoil_hw_verified_tls",
        adapter_version="tinfoil-fixture-adapter/0.1.0",
        route_execution_status="executable_fixture",
        channel_binding_kind="tee_terminated_tls",
        model_binding_result="not_supported",
        request_confidentiality_result="channel_bound",
        response_confidentiality_result="channel_bound",
        registry_source="custom",
        reference_values_source="custom",
        policy_digest=DIGEST,
        provider_registry_digest=DIGEST,
        reference_values_digest=DIGEST,
        registry_signature=PHASE2_SIGNATURE,
        reference_values_signature=PHASE2_SIGNATURE,
        alias_confidence="curated",
        registry_version="2026-07-05-phase2-fixtures",
        reference_values_version="2026-07-05-phase2-fixtures",
        checks={
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
        },
        artifacts={
            "source_url": "https://inference.tinfoil.sh/.well-known/tinfoil-attestation",
            "tee_measurement": "sha256:tinfoil-tee-measurement",
            "report_data": "0" * 128,
            "signing_public_key": "sha256:" + "5" * 64,
            "e2ee_capability": None,
            "model_manifest": "llama-3.3-70b",
            "model_artifacts": [
                {
                    "kind": "weights",
                    "name": "llama-3.3-70b",
                    "digest": "sha256:tinfoil-weights",
                }
            ],
        },
    )
    verdict.update(overrides)
    return verdict


def sample_phase2_venice_verdict(**overrides):
    verdict = sample_verdict(
        trust_tier="tee-only",
        provider="venice-fixture",
        requested_model="gpt-oss-120b",
        provider_model="e2ee-gpt-oss-120b-p",
        canonical_model="gpt-oss-120b",
        route_id="venice-fixture:gpt-oss-120b:e2ee-gpt-oss-120b-p",
        evidence_family="dstack_app_e2ee",
        adapter_version="venice-dstack-fixture-adapter/0.1.0",
        route_execution_status="verification_only",
        chat_executable=False,
        channel_binding_kind="attested_app_e2ee",
        model_binding_result="verified",
        request_channel_bound=False,
        request_confidentiality_result="unknown",
        response_confidentiality_result="unknown",
        response_channel_bound=False,
        response_integrity_result="unknown",
        registry_source="custom",
        reference_values_source="custom",
        policy_digest=DIGEST,
        provider_registry_digest=DIGEST,
        reference_values_digest=DIGEST,
        registry_signature=PHASE2_SIGNATURE,
        reference_values_signature=PHASE2_SIGNATURE,
        alias_confidence="curated",
        registry_version="2026-07-05-phase2-fixtures",
        reference_values_version="2026-07-05-phase2-fixtures",
        checks={
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
        },
        artifacts={
            "source_url": "https://api.venice.ai/api/v1/confidentiality",
            "tee_measurement": "sha256:venice-tee-measurement",
            "report_data": "sha256:venice-e2ee-key",
            "signing_public_key": None,
            "e2ee_capability": "dstack-e2ee",
            "model_manifest": "gpt-oss-120b",
            "model_artifacts": [
                {
                    "kind": "weights",
                    "name": "gpt-oss-120b",
                    "digest": "sha256:venice-weights",
                }
            ],
        },
    )
    verdict.update(overrides)
    return verdict


def sample_phase2_record(
    verdict,
    *,
    cache_hit: bool = False,
    **overrides,
):
    record = {
        "provider": verdict["provider"],
        "route_id": verdict["route_id"],
        "requested_model": verdict["requested_model"],
        "provider_model": verdict["provider_model"],
        "canonical_model": verdict["canonical_model"],
        "enforcement": verdict["enforcement"],
        "status": verdict["status"],
        "request_allowed": verdict["request_allowed"],
        "would_block_under_enforce": verdict["would_block_under_enforce"],
        "policy_digest": verdict["policy_digest"],
        "provider_registry_digest": verdict["provider_registry_digest"],
        "registry_version": verdict["registry_version"],
        "registry_source": verdict["registry_source"],
        "registry_sync_completed_at": verdict["registry_sync_completed_at"],
        "registry_signature": verdict["registry_signature"],
        "reference_values_digest": verdict["reference_values_digest"],
        "reference_values_version": verdict["reference_values_version"],
        "reference_values_source": verdict["reference_values_source"],
        "reference_values_signature": verdict["reference_values_signature"],
        "raw_evidence_digest": verdict["raw_evidence_digest"],
        "evidence_digest": verdict["evidence_digest"],
        "verified_at": verdict["verified_at"],
        "expires_at": verdict["expires_at"],
        "freshness_class": verdict["freshness_class"],
        "streaming_allowed": verdict["streaming_allowed"],
        "route_execution_status": verdict["route_execution_status"],
        "chat_executable": verdict["chat_executable"],
        "known_unsupported_modes": verdict["known_unsupported_modes"],
        "cache_hit": cache_hit,
        "errors": verdict["errors"],
        "verdict_json": verdict,
    }
    record.update(overrides)
    return record


def sample_local_live_reference_values_payload():
    return {
        "schema": "confidential-inference.reference-values.v1",
        "version": "2026-07-05-local-live-tinfoil-demo",
        "issuer": "confidential-inference-local-demo",
        "valid_from": "2026-07-05T00:00:00Z",
        "valid_until": "2099-01-01T00:00:00Z",
        "valid_until_epoch_ms": 4_070_908_800_000,
        "revocation_epoch": 1,
        "minimum_acceptable_version": "2026-07-05-local-live-tinfoil-demo",
        "providers": {
            "local-tinfoil-live": {
                "accepted_measurements": ["sha256:local-live-tinfoil-tee-measurement"],
                "routes": {
                    "local-tinfoil-live:llama-3.3-70b:llama-3.3-70b": {
                        "canonical_model": "llama-3.3-70b",
                        "provider_model": "llama-3.3-70b",
                        "evidence_family": "tinfoil_hw_verified_tls",
                        "channel_binding_kind": "tee_terminated_tls",
                        "trust_tier": "hw-verified-tls",
                        "accepted_cpu_tees": ["tdx"],
                        "e2ee_public_key_digest": "sha256:not-applicable",
                        "tls_spki_sha256": "sha256:" + "1" * 64,
                        "workload_image_digest": "sha256:local-live-tinfoil-workload-image",
                        "model_artifacts": [
                            {
                                "kind": "weights",
                                "name": "llama-3.3-70b",
                                "digest": "sha256:local-live-tinfoil-weights",
                            }
                        ],
                        "valid_until": "2099-01-01T00:00:00Z",
                        "valid_until_epoch_ms": 4_070_908_800_000,
                    }
                },
            }
        },
    }


def sample_local_live_registry_payload():
    return {
        "schema": "confidential-inference.provider-registry.v1",
        "version": "2026-07-05-local-live-tinfoil-demo",
        "generated_at": "2026-07-05T00:00:00Z",
        "source_sync_run": {
            "completed_at": "2026-07-05T00:00:00Z",
            "status": "success",
            "source": "confidential-demo-local-live-tinfoil",
        },
        "models": {
            "llama-3.3-70b": {
                "canonical_model": "llama-3.3-70b",
                "display_name": "Llama 3.3 70B",
                "family": "Llama",
                "aliases": ["llama-3.3-70b", "Llama 3.3 70B"],
                "routes": [
                    {
                        "route_id": "local-tinfoil-live:llama-3.3-70b:llama-3.3-70b",
                        "route_status": "active",
                        "provider": "local-tinfoil-live",
                        "provider_model": "llama-3.3-70b",
                        "evidence_family": "tinfoil_hw_verified_tls",
                        "api_base_url": "https://127.0.0.1:33789/v1",
                        "evidence_endpoint": (
                            "https://127.0.0.1:33789/.well-known/tinfoil-attestation"
                        ),
                        "adapter_version": "local-live-tinfoil-demo-adapter/0.1.0",
                        "freshness_class": "per_session",
                        "channel_binding_kind": "tee_terminated_tls",
                        "trust_tier": "hw-verified-tls",
                        "request_confidentiality_requirement": (
                            "bound_to_attested_workload"
                        ),
                        "response_confidentiality_requirement": (
                            "bound_to_attested_workload"
                        ),
                        "response_integrity_requirement": "channel_bound",
                        "request_encryption": "not_required",
                        "response_decryption": "not_required",
                        "streaming": "unsupported",
                        "alias_confidence": "curated",
                    }
                ],
            }
        },
    }


LOCAL_LIVE_REGISTRY_DIGEST = check_demo_output._canonical_sha256_digest(
    sample_local_live_registry_payload()
)


def sample_local_live_registry_envelope(payload=None):
    payload = sample_local_live_registry_payload() if payload is None else payload
    signature = sign_ed25519(
        LOCAL_DEMO_SEED,
        check_demo_output._canonical_json(payload).encode("utf-8"),
    )
    return {
        "schema": "confidential-inference.provider-registry-envelope.v1",
        "payload": payload,
        "signature": {
            **LOCAL_LIVE_SIGNATURE,
            "value": "base64url:" + encode_unpadded_base64url(signature),
        },
    }


def sample_local_live_compatibility_matrix_payload():
    return {
        "schema": "confidential-inference.provider-compatibility-matrix.v1",
        "providers": {
            "local-tinfoil-live": {
                "provider": "local-tinfoil-live",
                "route_execution_status": "executable",
                "api_base_url": "https://127.0.0.1:33789/v1",
                "supported_openai_endpoints": ["chat_completions"],
                "model_listing": "signed_registry_only",
                "model_id_rewrite": "use_route_provider_model",
                "token_parameter_rewrite": "preserve_max_tokens",
                "streaming": "unsupported",
                "request_encryption": "not_required",
                "response_decryption": "not_required",
                "attestation_endpoint_shape": "tinfoil_live_tls_local_demo",
                "required_credentials": [],
                "freshness_class": "per_session",
                "cacheability_class": "per_session_verdict",
                "expected_trust_tier": "hw-verified-tls",
                "model_binding_support": "verified",
                "known_unsupported_modes": ["streaming"],
            }
        },
    }


LOCAL_LIVE_COMPATIBILITY_MATRIX_DIGEST = check_demo_output._canonical_sha256_digest(
    sample_local_live_compatibility_matrix_payload()
)


def sample_local_live_compatibility_matrix_envelope(payload=None):
    payload = sample_local_live_compatibility_matrix_payload() if payload is None else payload
    signature = sign_ed25519(
        LOCAL_DEMO_SEED,
        check_demo_output._canonical_json(payload).encode("utf-8"),
    )
    return {
        "schema": "confidential-inference.provider-compatibility-matrix-envelope.v1",
        "payload": payload,
        "signature": {
            **LOCAL_LIVE_SIGNATURE,
            "value": "base64url:" + encode_unpadded_base64url(signature),
        },
    }


LOCAL_LIVE_REFERENCE_DIGEST = check_demo_output._canonical_sha256_digest(
    sample_local_live_reference_values_payload()
)


def sample_local_live_reference_values_envelope(payload=None):
    payload = sample_local_live_reference_values_payload() if payload is None else payload
    signature = sign_ed25519(
        LOCAL_DEMO_SEED,
        check_demo_output._canonical_json(payload).encode("utf-8"),
    )
    return {
        "schema": "confidential-inference.reference-values-envelope.v1",
        "payload": payload,
        "signature": {
            **LOCAL_LIVE_SIGNATURE,
            "value": "base64url:" + encode_unpadded_base64url(signature),
        },
    }


def sample_local_app_e2ee_reference_values_payload():
    return {
        "schema": "confidential-inference.reference-values.v1",
        "version": "2026-07-05-local-sdk-app-e2ee-demo",
        "issuer": "confidential-inference-local-demo",
        "valid_from": "2026-07-05T00:00:00Z",
        "valid_until": "2099-01-01T00:00:00Z",
        "valid_until_epoch_ms": 4_070_908_800_000,
        "revocation_epoch": 1,
        "minimum_acceptable_version": "2026-07-05-local-sdk-app-e2ee-demo",
        "providers": {
            "local-sdk-app-e2ee": {
                "accepted_measurements": ["sha256:local-sdk-app-e2ee-tee-measurement"],
                "routes": {
                    "local-sdk-app-e2ee:gpt-oss-120b:e2ee-gpt-oss-120b-p": {
                        "canonical_model": "gpt-oss-120b",
                        "provider_model": "e2ee-gpt-oss-120b-p",
                        "evidence_family": "dstack_app_e2ee",
                        "channel_binding_kind": "attested_app_e2ee",
                        "trust_tier": "app-e2ee",
                        "accepted_cpu_tees": ["tdx"],
                        "e2ee_public_key_digest": LOCAL_APP_E2EE_PUBLIC_KEY_DIGEST,
                        "workload_images": [
                            {
                                "service": "root",
                                "reference": (
                                    "local-sdk-app-e2ee/worker@sha256:"
                                    + "a" * 64
                                ),
                                "digest": DIGEST,
                            }
                        ],
                        "workload_image_digest": DIGEST,
                        "model_artifacts": [
                            {
                                "kind": "weights",
                                "name": "gpt-oss-120b",
                                "digest": "sha256:local-sdk-app-e2ee-weights",
                            }
                        ],
                        "valid_until": "2099-01-01T00:00:00Z",
                        "valid_until_epoch_ms": 4_070_908_800_000,
                    }
                },
            }
        },
    }


def sample_local_app_e2ee_registry_payload():
    return {
        "schema": "confidential-inference.provider-registry.v1",
        "version": "2026-07-05-local-sdk-app-e2ee-demo",
        "generated_at": "2026-07-05T00:00:00Z",
        "source_sync_run": {
            "completed_at": "2026-07-05T00:00:00Z",
            "status": "success",
            "source": "confidential-demo-local-sdk-app-e2ee",
        },
        "models": {
            "gpt-oss-120b": {
                "canonical_model": "gpt-oss-120b",
                "display_name": "GPT-OSS 120B",
                "family": "OpenAI GPT",
                "aliases": ["gpt-oss-120b", "GPT-OSS 120B"],
                "routes": [
                    {
                        "route_id": (
                            "local-sdk-app-e2ee:gpt-oss-120b:e2ee-gpt-oss-120b-p"
                        ),
                        "route_status": "active",
                        "provider": "local-sdk-app-e2ee",
                        "provider_model": "e2ee-gpt-oss-120b-p",
                        "evidence_family": "dstack_app_e2ee",
                        "api_base_url": "http://127.0.0.1:33790/v1",
                        "evidence_endpoint": "http://127.0.0.1:33790/v1/confidentiality",
                        "adapter_version": "local-sdk-app-e2ee-demo-adapter/0.1.0",
                        "freshness_class": "per_session",
                        "channel_binding_kind": "attested_app_e2ee",
                        "trust_tier": "app-e2ee",
                        "request_confidentiality_requirement": (
                            "bound_to_attested_workload"
                        ),
                        "response_confidentiality_requirement": (
                            "bound_to_attested_workload"
                        ),
                        "response_integrity_requirement": "any_bound",
                        "request_encryption": "required",
                        "response_decryption": "required",
                        "streaming": "unsupported",
                        "alias_confidence": "curated",
                    }
                ],
            }
        },
    }


LOCAL_APP_E2EE_REGISTRY_DIGEST = check_demo_output._canonical_sha256_digest(
    sample_local_app_e2ee_registry_payload()
)


def sample_local_app_e2ee_registry_envelope(payload=None):
    payload = sample_local_app_e2ee_registry_payload() if payload is None else payload
    signature = sign_ed25519(
        LOCAL_DEMO_SEED,
        check_demo_output._canonical_json(payload).encode("utf-8"),
    )
    return {
        "schema": "confidential-inference.provider-registry-envelope.v1",
        "payload": payload,
        "signature": {
            **LOCAL_LIVE_SIGNATURE,
            "value": "base64url:" + encode_unpadded_base64url(signature),
        },
    }


def sample_local_app_e2ee_compatibility_matrix_payload():
    return {
        "schema": "confidential-inference.provider-compatibility-matrix.v1",
        "providers": {
            "local-sdk-app-e2ee": {
                "provider": "local-sdk-app-e2ee",
                "route_execution_status": "executable",
                "api_base_url": "http://127.0.0.1:33790/v1",
                "supported_openai_endpoints": ["chat_completions"],
                "model_listing": "signed_registry_only",
                "model_id_rewrite": "use_route_provider_model",
                "token_parameter_rewrite": "preserve_max_tokens",
                "streaming": "unsupported",
                "request_encryption": "required",
                "response_decryption": "required",
                "sdk_app_e2ee": {
                    "key_id": "local-sdk-app-e2ee-key",
                    "public_key_base64": LOCAL_APP_E2EE_PUBLIC_KEY_BASE64,
                },
                "attestation_endpoint_shape": "dstack_app_e2ee_local_demo",
                "required_credentials": [],
                "freshness_class": "per_session",
                "cacheability_class": "per_session_verdict",
                "expected_trust_tier": "app-e2ee",
                "model_binding_support": "verified",
                "known_unsupported_modes": ["streaming"],
            }
        },
    }


LOCAL_APP_E2EE_COMPATIBILITY_MATRIX_DIGEST = check_demo_output._canonical_sha256_digest(
    sample_local_app_e2ee_compatibility_matrix_payload()
)


def sample_local_app_e2ee_compatibility_matrix_envelope(payload=None):
    payload = (
        sample_local_app_e2ee_compatibility_matrix_payload()
        if payload is None
        else payload
    )
    signature = sign_ed25519(
        LOCAL_DEMO_SEED,
        check_demo_output._canonical_json(payload).encode("utf-8"),
    )
    return {
        "schema": "confidential-inference.provider-compatibility-matrix-envelope.v1",
        "payload": payload,
        "signature": {
            **LOCAL_LIVE_SIGNATURE,
            "value": "base64url:" + encode_unpadded_base64url(signature),
        },
    }


LOCAL_APP_E2EE_REFERENCE_DIGEST = check_demo_output._canonical_sha256_digest(
    sample_local_app_e2ee_reference_values_payload()
)


def sample_local_app_e2ee_reference_values_envelope(payload=None):
    payload = sample_local_app_e2ee_reference_values_payload() if payload is None else payload
    signature = sign_ed25519(
        LOCAL_DEMO_SEED,
        check_demo_output._canonical_json(payload).encode("utf-8"),
    )
    return {
        "schema": "confidential-inference.reference-values-envelope.v1",
        "payload": payload,
        "signature": {
            **LOCAL_LIVE_SIGNATURE,
            "value": "base64url:" + encode_unpadded_base64url(signature),
        },
    }


def sample_local_ionet_reference_values_payload():
    return {
        "schema": "confidential-inference.reference-values.v1",
        "version": "2026-07-05-local-ionet-demo",
        "issuer": "confidential-inference-local-demo",
        "valid_from": "2026-07-05T00:00:00Z",
        "valid_until": "2099-01-01T00:00:00Z",
        "valid_until_epoch_ms": 4_070_908_800_000,
        "revocation_epoch": 1,
        "minimum_acceptable_version": "2026-07-05-local-ionet-demo",
        "providers": {
            "local-ionet": {
                "accepted_measurements": [],
                "routes": {
                    "local-ionet:llama-3.3-70b:local-ionet-llama-3-3-70b": {
                        "canonical_model": "llama-3.3-70b",
                        "provider_model": "local-ionet-llama-3-3-70b",
                        "evidence_family": "ionet_confidential",
                        "channel_binding_kind": "none",
                        "trust_tier": "tee-only",
                        "accepted_cpu_tees": [],
                        "e2ee_public_key_digest": "",
                        "response_signing_key_digest": "sha256:" + "3" * 64,
                        "workload_image_digest": "sha256:local-ionet-workload-image",
                        "model_artifacts": [
                            {
                                "kind": "provider_model",
                                "name": "local-ionet-llama-3-3-70b",
                                "digest": "sha256:" + "4" * 64,
                            }
                        ],
                        "valid_until": "2099-01-01T00:00:00Z",
                        "valid_until_epoch_ms": 4_070_908_800_000,
                    }
                },
            }
        },
    }


def sample_local_ionet_registry_payload():
    return {
        "schema": "confidential-inference.provider-registry.v1",
        "version": "2026-07-05-local-ionet-demo",
        "generated_at": "2026-07-05T00:00:00Z",
        "source_sync_run": {
            "completed_at": "2026-07-05T00:00:00Z",
            "status": "success",
            "source": "confidential-demo-local-ionet",
        },
        "models": {
            "llama-3.3-70b": {
                "canonical_model": "llama-3.3-70b",
                "display_name": "Llama 3.3 70B",
                "family": "Llama",
                "aliases": ["llama-3.3-70b", "Llama 3.3 70B"],
                "routes": [
                    {
                        "route_id": (
                            "local-ionet:llama-3.3-70b:local-ionet-llama-3-3-70b"
                        ),
                        "route_status": "active",
                        "provider": "local-ionet",
                        "provider_model": "local-ionet-llama-3-3-70b",
                        "evidence_family": "ionet_confidential",
                        "api_base_url": "http://127.0.0.1:33791/v1/private",
                        "evidence_endpoint": (
                            "http://127.0.0.1:33791/v1/private/attestation"
                        ),
                        "adapter_version": "local-ionet-demo-adapter/0.1.0",
                        "freshness_class": "per_session",
                        "channel_binding_kind": "none",
                        "trust_tier": "tee-only",
                        "request_confidentiality_requirement": "not_required",
                        "response_confidentiality_requirement": "not_required",
                        "response_integrity_requirement": "receipt_bound",
                        "accepted_gpu_tees": ["nvidia_cc"],
                        "request_encryption": "not_required",
                        "response_decryption": "not_required",
                        "streaming": "unsupported",
                        "alias_confidence": "curated",
                    }
                ],
            }
        },
    }


LOCAL_IONET_REGISTRY_DIGEST = check_demo_output._canonical_sha256_digest(
    sample_local_ionet_registry_payload()
)


def sample_local_ionet_registry_envelope(payload=None):
    payload = sample_local_ionet_registry_payload() if payload is None else payload
    signature = sign_ed25519(
        LOCAL_DEMO_SEED,
        check_demo_output._canonical_json(payload).encode("utf-8"),
    )
    return {
        "schema": "confidential-inference.provider-registry-envelope.v1",
        "payload": payload,
        "signature": {
            **LOCAL_LIVE_SIGNATURE,
            "value": "base64url:" + encode_unpadded_base64url(signature),
        },
    }


def sample_local_ionet_compatibility_matrix_payload():
    return {
        "schema": "confidential-inference.provider-compatibility-matrix.v1",
        "providers": {
            "local-ionet": {
                "provider": "local-ionet",
                "route_execution_status": "executable",
                "api_base_url": "http://127.0.0.1:33791/v1/private",
                "supported_openai_endpoints": ["chat_completions"],
                "model_listing": "signed_registry_only",
                "model_id_rewrite": "use_route_provider_model",
                "token_parameter_rewrite": "preserve_max_tokens",
                "streaming": "unsupported",
                "request_encryption": "not_required",
                "response_decryption": "not_required",
                "attestation_endpoint_shape": "ionet_confidential_local_demo",
                "required_credentials": [],
                "freshness_class": "per_session",
                "cacheability_class": "per_session_verdict",
                "expected_trust_tier": "tee-only",
                "model_binding_support": "verified",
                "known_unsupported_modes": ["streaming"],
            }
        },
    }


LOCAL_IONET_COMPATIBILITY_MATRIX_DIGEST = check_demo_output._canonical_sha256_digest(
    sample_local_ionet_compatibility_matrix_payload()
)


def sample_local_ionet_compatibility_matrix_envelope(payload=None):
    payload = sample_local_ionet_compatibility_matrix_payload() if payload is None else payload
    signature = sign_ed25519(
        LOCAL_DEMO_SEED,
        check_demo_output._canonical_json(payload).encode("utf-8"),
    )
    return {
        "schema": "confidential-inference.provider-compatibility-matrix-envelope.v1",
        "payload": payload,
        "signature": {
            **LOCAL_LIVE_SIGNATURE,
            "value": "base64url:" + encode_unpadded_base64url(signature),
        },
    }


LOCAL_IONET_REFERENCE_DIGEST = check_demo_output._canonical_sha256_digest(
    sample_local_ionet_reference_values_payload()
)


def sample_local_ionet_reference_values_envelope(payload=None):
    payload = sample_local_ionet_reference_values_payload() if payload is None else payload
    signature = sign_ed25519(
        LOCAL_DEMO_SEED,
        check_demo_output._canonical_json(payload).encode("utf-8"),
    )
    return {
        "schema": "confidential-inference.reference-values-envelope.v1",
        "payload": payload,
        "signature": {
            **LOCAL_LIVE_SIGNATURE,
            "value": "base64url:" + encode_unpadded_base64url(signature),
        },
    }


def sample_local_live_verdict(**overrides):
    verdict = sample_verdict(
        trust_tier="hw-verified-tls",
        provider="local-tinfoil-live",
        requested_model="llama-3.3-70b",
        provider_model="llama-3.3-70b",
        canonical_model="llama-3.3-70b",
        route_id="local-tinfoil-live:llama-3.3-70b:llama-3.3-70b",
        evidence_family="tinfoil_hw_verified_tls",
        adapter_version="local-live-tinfoil-demo-adapter/0.1.0",
        route_execution_status="executable",
        channel_binding_kind="tee_terminated_tls",
        model_binding_result="verified",
        request_confidentiality_result="channel_bound",
        response_confidentiality_result="channel_bound",
        registry_source="custom",
        reference_values_source="custom",
        policy_digest=DIGEST,
        provider_registry_digest=LOCAL_LIVE_REGISTRY_DIGEST,
        reference_values_digest=LOCAL_LIVE_REFERENCE_DIGEST,
        registry_signature=LOCAL_LIVE_SIGNATURE,
        reference_values_signature=LOCAL_LIVE_SIGNATURE,
        alias_confidence="curated",
        checks={
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
        },
        artifacts={
            "source_url": "https://127.0.0.1:33789/.well-known/tinfoil-attestation",
            "tee_measurement": "sha256:local-live-tinfoil-tee-measurement",
            "report_data": "0" * 128,
            "signing_public_key": "sha256:" + "1" * 64,
            "model_manifest": "llama-3.3-70b",
            "model_artifacts": [
                {
                    "kind": "weights",
                    "name": "llama-3.3-70b",
                    "digest": "sha256:local-live-tinfoil-weights",
                }
            ],
        },
    )
    verdict.update(overrides)
    return verdict


def sample_local_app_e2ee_verdict(**overrides):
    verdict = sample_verdict(
        trust_tier="tee-only",
        provider="local-sdk-app-e2ee",
        requested_model="gpt-oss-120b",
        provider_model="e2ee-gpt-oss-120b-p",
        canonical_model="gpt-oss-120b",
        route_id="local-sdk-app-e2ee:gpt-oss-120b:e2ee-gpt-oss-120b-p",
        evidence_family="dstack_app_e2ee",
        adapter_version="local-sdk-app-e2ee-demo-adapter/0.1.0",
        route_execution_status="executable",
        channel_binding_kind="attested_app_e2ee",
        model_binding_result="verified",
        request_channel_bound=False,
        request_confidentiality_result="unknown",
        response_confidentiality_result="unknown",
        response_channel_bound=False,
        response_integrity_result="unknown",
        registry_source="custom",
        reference_values_source="custom",
        policy_digest=DIGEST,
        provider_registry_digest=LOCAL_APP_E2EE_REGISTRY_DIGEST,
        reference_values_digest=LOCAL_APP_E2EE_REFERENCE_DIGEST,
        registry_signature=LOCAL_LIVE_SIGNATURE,
        reference_values_signature=LOCAL_LIVE_SIGNATURE,
        alias_confidence="curated",
        registry_version="2026-07-05-local-sdk-app-e2ee-demo",
        reference_values_version="2026-07-05-local-sdk-app-e2ee-demo",
        checks={
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
        },
        artifacts={
            "source_url": "http://127.0.0.1:33790/v1/confidentiality",
            "tee_measurement": "sha256:local-sdk-app-e2ee-tee-measurement",
            "report_data": LOCAL_APP_E2EE_PUBLIC_KEY_DIGEST,
            "signing_public_key": None,
            "e2ee_capability": "dstack-e2ee",
            "model_manifest": "gpt-oss-120b",
            "model_artifacts": [
                {
                    "kind": "weights",
                    "name": "gpt-oss-120b",
                    "digest": "sha256:local-sdk-app-e2ee-weights",
                }
            ],
        },
    )
    verdict.update(overrides)
    return verdict


def sample_local_app_e2ee_record(
    *,
    cache_hit: bool = False,
    nested_overrides: dict | None = None,
    **overrides,
):
    verdict = sample_local_app_e2ee_verdict(**(nested_overrides or {}))
    record = {
        "provider": verdict["provider"],
        "route_id": verdict["route_id"],
        "requested_model": verdict["requested_model"],
        "provider_model": verdict["provider_model"],
        "canonical_model": verdict["canonical_model"],
        "enforcement": verdict["enforcement"],
        "status": verdict["status"],
        "request_allowed": verdict["request_allowed"],
        "would_block_under_enforce": verdict["would_block_under_enforce"],
        "policy_digest": verdict["policy_digest"],
        "provider_registry_digest": verdict["provider_registry_digest"],
        "registry_version": verdict["registry_version"],
        "registry_source": verdict["registry_source"],
        "registry_sync_completed_at": verdict["registry_sync_completed_at"],
        "registry_signature": verdict["registry_signature"],
        "reference_values_digest": verdict["reference_values_digest"],
        "reference_values_version": verdict["reference_values_version"],
        "reference_values_source": verdict["reference_values_source"],
        "reference_values_signature": verdict["reference_values_signature"],
        "raw_evidence_digest": verdict["raw_evidence_digest"],
        "evidence_digest": verdict["evidence_digest"],
        "verified_at": verdict["verified_at"],
        "expires_at": verdict["expires_at"],
        "freshness_class": verdict["freshness_class"],
        "streaming_allowed": verdict["streaming_allowed"],
        "route_execution_status": verdict["route_execution_status"],
        "chat_executable": verdict["chat_executable"],
        "known_unsupported_modes": verdict["known_unsupported_modes"],
        "cache_hit": cache_hit,
        "errors": verdict["errors"],
        "verdict_json": verdict,
    }
    record.update(overrides)
    return record


def sample_local_ionet_verdict(**overrides):
    verdict = sample_verdict(
        trust_tier="tee-only",
        provider="local-ionet",
        requested_model="llama-3.3-70b",
        provider_model="local-ionet-llama-3-3-70b",
        canonical_model="llama-3.3-70b",
        route_id="local-ionet:llama-3.3-70b:local-ionet-llama-3-3-70b",
        evidence_family="ionet_confidential",
        adapter_version="local-ionet-demo-adapter/0.1.0",
        route_execution_status="executable",
        channel_binding_kind="none",
        model_binding_result="not_supported",
        request_channel_bound=False,
        request_confidentiality_result="unknown",
        response_confidentiality_result="unknown",
        response_channel_bound=False,
        response_integrity_result="receipt_bound",
        registry_source="custom",
        reference_values_source="custom",
        policy_digest=DIGEST,
        provider_registry_digest=LOCAL_IONET_REGISTRY_DIGEST,
        reference_values_digest=LOCAL_IONET_REFERENCE_DIGEST,
        registry_signature=LOCAL_LIVE_SIGNATURE,
        reference_values_signature=LOCAL_LIVE_SIGNATURE,
        alias_confidence="curated",
        registry_version="2026-07-05-local-ionet-demo",
        reference_values_version="2026-07-05-local-ionet-demo",
        checks={
            "cpu_tee": "not_applicable",
            "e2ee_key_binding": "not_applicable",
            "gpu_tee": "verified",
            "image_provenance": "verified",
            "model_artifact_provenance": "verified",
            "model_binding": "not_supported",
            "nonce_binding": "verified",
            "request_encryption": "not_applicable",
            "request_key_binding": "not_applicable",
            "response_channel_binding": "verified",
            "response_encryption": "not_applicable",
            "response_key_binding": "not_applicable",
            "response_receipt": "verified",
            "response_signing_key_binding": "verified",
            "request_route_binding": "not_supported",
            "route_binding": "not_supported",
            "route_metadata_binding": "verified",
            "tls_binding": "not_applicable",
        },
        artifacts={
            "source_url": "http://127.0.0.1:33791/v1/private/attestation",
            "tee_measurement": None,
            "report_data": "0" * 128,
            "signing_public_key": "sha256:" + "3" * 64,
            "e2ee_capability": None,
            "model_manifest": None,
            "model_artifacts": [
                {
                    "kind": "provider_model",
                    "name": "local-ionet-llama-3-3-70b",
                    "digest": "sha256:" + "4" * 64,
                }
            ],
        },
    )
    verdict.update(overrides)
    return verdict


def sample_local_ionet_record(
    *,
    cache_hit: bool = False,
    nested_overrides: dict | None = None,
    **overrides,
):
    verdict = sample_local_ionet_verdict(**(nested_overrides or {}))
    record = {
        "provider": verdict["provider"],
        "route_id": verdict["route_id"],
        "requested_model": verdict["requested_model"],
        "provider_model": verdict["provider_model"],
        "canonical_model": verdict["canonical_model"],
        "enforcement": verdict["enforcement"],
        "status": verdict["status"],
        "request_allowed": verdict["request_allowed"],
        "would_block_under_enforce": verdict["would_block_under_enforce"],
        "policy_digest": verdict["policy_digest"],
        "provider_registry_digest": verdict["provider_registry_digest"],
        "registry_version": verdict["registry_version"],
        "registry_source": verdict["registry_source"],
        "registry_sync_completed_at": verdict["registry_sync_completed_at"],
        "registry_signature": verdict["registry_signature"],
        "reference_values_digest": verdict["reference_values_digest"],
        "reference_values_version": verdict["reference_values_version"],
        "reference_values_source": verdict["reference_values_source"],
        "reference_values_signature": verdict["reference_values_signature"],
        "raw_evidence_digest": verdict["raw_evidence_digest"],
        "evidence_digest": verdict["evidence_digest"],
        "verified_at": verdict["verified_at"],
        "expires_at": verdict["expires_at"],
        "freshness_class": verdict["freshness_class"],
        "streaming_allowed": verdict["streaming_allowed"],
        "route_execution_status": verdict["route_execution_status"],
        "chat_executable": verdict["chat_executable"],
        "known_unsupported_modes": verdict["known_unsupported_modes"],
        "cache_hit": cache_hit,
        "errors": verdict["errors"],
        "verdict_json": verdict,
    }
    record.update(overrides)
    return record


def sample_local_live_record(
    *,
    cache_hit: bool = False,
    nested_overrides: dict | None = None,
    **overrides,
):
    verdict = sample_local_live_verdict(**(nested_overrides or {}))
    record = {
        "provider": verdict["provider"],
        "route_id": verdict["route_id"],
        "requested_model": verdict["requested_model"],
        "provider_model": verdict["provider_model"],
        "canonical_model": verdict["canonical_model"],
        "enforcement": verdict["enforcement"],
        "status": verdict["status"],
        "request_allowed": verdict["request_allowed"],
        "would_block_under_enforce": verdict["would_block_under_enforce"],
        "policy_digest": verdict["policy_digest"],
        "provider_registry_digest": verdict["provider_registry_digest"],
        "registry_version": verdict["registry_version"],
        "registry_source": verdict["registry_source"],
        "registry_sync_completed_at": verdict["registry_sync_completed_at"],
        "registry_signature": verdict["registry_signature"],
        "reference_values_digest": verdict["reference_values_digest"],
        "reference_values_version": verdict["reference_values_version"],
        "reference_values_source": verdict["reference_values_source"],
        "reference_values_signature": verdict["reference_values_signature"],
        "raw_evidence_digest": verdict["raw_evidence_digest"],
        "evidence_digest": verdict["evidence_digest"],
        "verified_at": verdict["verified_at"],
        "expires_at": verdict["expires_at"],
        "freshness_class": verdict["freshness_class"],
        "streaming_allowed": verdict["streaming_allowed"],
        "route_execution_status": verdict["route_execution_status"],
        "chat_executable": verdict["chat_executable"],
        "known_unsupported_modes": verdict["known_unsupported_modes"],
        "cache_hit": cache_hit,
        "errors": verdict["errors"],
        "verdict_json": verdict,
    }
    record.update(overrides)
    return record


def sample_metric_records():
    labels = {
        "provider": "demo",
        "route_id": "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p",
        "requested_model": "gpt-oss-120b",
        "provider_model": "e2ee-gpt-oss-120b-p",
        "canonical_model": "gpt-oss-120b",
        "evidence_family": "fixture_dstack",
    }
    return [
        {
            "event": "route_selection",
            "provider": "any",
            "requested_model": "gpt-oss-120b",
            "purpose": "chat",
            "candidate_count": 1,
            "selected_count": 1,
            "duration_ms": 0,
            "outcome": "success",
        },
        {"event": "verification_cache", "labels": labels, "cache_event": "miss"},
        {"event": "verification_cache", "labels": labels, "cache_event": "hit"},
        {
            "event": "latency",
            "labels": labels,
            "step": "evidence_fetch",
            "duration_ms": 0,
            "outcome": "success",
        },
        {
            "event": "latency",
            "labels": labels,
            "step": "evidence_verification",
            "duration_ms": 0,
            "outcome": "success",
        },
        {
            "event": "latency",
            "labels": labels,
            "step": "provider_chat",
            "duration_ms": 0,
            "outcome": "success",
        },
        {
            "event": "verdict",
            "labels": labels,
            "status": "verified",
            "enforcement": "enforce",
            "request_allowed": True,
            "would_block_under_enforce": False,
            "cache_hit": False,
        },
        {
            "event": "verdict",
            "labels": labels,
            "status": "verified",
            "enforcement": "enforce",
            "request_allowed": True,
            "would_block_under_enforce": False,
            "cache_hit": True,
        },
        {
            "event": "streaming_fail_closed",
            "labels": labels,
            "endpoint": "chat_completions",
        },
    ]


def write_jsonl(path: Path, records) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def write_sample_artifacts(root: Path) -> None:
    target = root / "target"
    write_json(
        target / "confidential-demo-active-policy.json",
        sample_active_policy_snapshot(),
    )
    write_json(
        target / "confidential-demo-active-trust-artifacts.json",
        sample_active_trust_artifacts(),
    )
    write_jsonl(target / "confidential-demo-metrics.jsonl", sample_metric_records())
    write_jsonl(
        target / "confidential-demo-audit.jsonl",
        [sample_audit_record(), sample_audit_record(cache_hit=True)],
    )
    write_jsonl(
        target / "confidential-demo-verdicts.jsonl",
        [
            sample_audit_record(include_nested_verdict=True),
            sample_audit_record(include_nested_verdict=True, cache_hit=True),
        ],
    )
    write_jsonl(
        target / "confidential-demo-proxy-verdicts.jsonl",
        [
            sample_audit_record(include_nested_verdict=True),
            sample_audit_record(include_nested_verdict=True, cache_hit=True),
            sample_audit_record(include_nested_verdict=True),
        ],
    )
    phase2_tinfoil = sample_phase2_tinfoil_verdict()
    phase2_venice = sample_phase2_venice_verdict()
    write_jsonl(
        target / "confidential-demo-phase2-fixture-verdicts.jsonl",
        [
            sample_phase2_record(phase2_tinfoil),
            sample_phase2_record(phase2_tinfoil, cache_hit=True),
            sample_phase2_record(phase2_venice),
            sample_phase2_record(phase2_venice),
        ],
    )
    write_jsonl(
        target / "confidential-demo-local-sdk-app-e2ee-verdicts.jsonl",
        [
            sample_local_app_e2ee_record(),
            sample_local_app_e2ee_record(cache_hit=True),
        ],
    )
    write_json(
        target / "confidential-demo-local-sdk-app-e2ee-registry.json",
        sample_local_app_e2ee_registry_envelope(),
    )
    write_json(
        target / "confidential-demo-local-sdk-app-e2ee-compatibility-matrix.json",
        sample_local_app_e2ee_compatibility_matrix_envelope(),
    )
    write_json(
        target / "confidential-demo-local-sdk-app-e2ee-reference-values.json",
        sample_local_app_e2ee_reference_values_envelope(),
    )
    write_jsonl(
        target / "confidential-demo-local-ionet-verdicts.jsonl",
        [
            sample_local_ionet_record(),
            sample_local_ionet_record(cache_hit=True),
        ],
    )
    write_json(
        target / "confidential-demo-local-ionet-registry.json",
        sample_local_ionet_registry_envelope(),
    )
    write_json(
        target / "confidential-demo-local-ionet-compatibility-matrix.json",
        sample_local_ionet_compatibility_matrix_envelope(),
    )
    write_json(
        target / "confidential-demo-local-ionet-reference-values.json",
        sample_local_ionet_reference_values_envelope(),
    )
    write_jsonl(
        target / "confidential-demo-local-live-verdicts.jsonl",
        [
            sample_local_live_record(),
            sample_local_live_record(cache_hit=True),
        ],
    )
    write_json(
        target / "confidential-demo-local-live-registry.json",
        sample_local_live_registry_envelope(),
    )
    write_json(
        target / "confidential-demo-local-live-compatibility-matrix.json",
        sample_local_live_compatibility_matrix_envelope(),
    )
    write_json(
        target / "confidential-demo-local-live-reference-values.json",
        sample_local_live_reference_values_envelope(),
    )


def sample_output(
    verdict=None,
    *,
    omit_label: str | None = None,
    label_overrides: dict | None = None,
) -> str:
    verdict = sample_verdict() if verdict is None else verdict
    labels = {
        "ffi_status_async_handle_abi_available": "true",
        "ffi_status_callbacks_available": "true",
        "ffi_status_readiness_fd_available": "true",
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
        "active_policy_digest": verdict["policy_digest"],
        "active_policy_registry_digest": verdict["provider_registry_digest"],
        "active_policy_reference_values_digest": verdict["reference_values_digest"],
        "active_registry_schema": "confidential-inference.provider-registry.v1",
        "active_reference_values_schema": "confidential-inference.reference-values.v1",
        "active_registry_digest": verdict["provider_registry_digest"],
        "active_reference_values_digest": verdict["reference_values_digest"],
        "active_registry_source": verdict["registry_source"],
        "active_reference_values_source": verdict["reference_values_source"],
        "active_registry_signature_signer": verdict["registry_signature"]["signer"],
        "active_registry_signature_key_id": verdict["registry_signature"]["key_id"],
        "active_registry_signature_alg": verdict["registry_signature"]["alg"],
        "active_reference_values_signature_signer": verdict["reference_values_signature"][
            "signer"
        ],
        "active_reference_values_signature_key_id": verdict["reference_values_signature"][
            "key_id"
        ],
        "active_reference_values_signature_alg": verdict["reference_values_signature"]["alg"],
        "active_registry_signature_value_base64url": "true",
        "active_reference_values_signature_value_base64url": "true",
        "response": (
            "demo confidential response for e2ee-gpt-oss-120b-p: "
            "verify the confidential inference SDK path"
        ),
        "metrics_events": "9",
        "metrics_cache_hits": "1",
        "metrics_verdicts": "2",
        "metrics_streaming_fail_closed": "1",
        "verified_route_model_mismatch_rejected": "true",
        "metrics_jsonl_records": "9",
        "cached_verify_samples": "32",
        "cached_verify_p95_ms": "0",
        "metrics_prometheus_lines": "47",
        "metrics_otlp_resource_metrics": "1",
        "metrics_otlp_scope_metrics": "1",
        "metrics_otlp_metrics": "8",
        "metrics_otlp_data_points": "12",
        "metrics_otlp_http_posted": "true",
        "metrics_log": "target/confidential-demo-metrics.jsonl",
        "audit_records": "2",
        "audit_log": "target/confidential-demo-audit.jsonl",
        "primary_persisted_verdicts": "2",
        "primary_verdict_store": "target/confidential-demo-verdicts.jsonl",
        "tampered_registry_rejected": "true",
        "tampered_reference_values_rejected": "true",
        "signed_invalid_registry_metadata_rejected": "true",
        "signed_invalid_reference_validity_rejected": "true",
        "proxy_chat_status": "200",
        "proxy_chat_body_model": '"e2ee-gpt-oss-120b-p"',
        "proxy_body_without_verdict": "true",
        "proxy_sidecar_prompt_redacted": "true",
        "proxy_verdict_status": "Verified",
        "proxy_verdict_provider": verdict["provider"],
        "proxy_verdict_route_id": verdict["route_id"],
        "proxy_verdict_requested_model": verdict["requested_model"],
        "proxy_verdict_provider_model": verdict["provider_model"],
        "proxy_verdict_canonical_model": verdict["canonical_model"],
        "proxy_verdict_policy_digest": verdict["policy_digest"],
        "proxy_verdict_provider_registry_digest": verdict["provider_registry_digest"],
        "proxy_verdict_reference_values_digest": verdict["reference_values_digest"],
        "proxy_verdict_request_confidentiality_result": verdict[
            "request_confidentiality_result"
        ],
        "proxy_verdict_response_confidentiality_result": verdict[
            "response_confidentiality_result"
        ],
        "proxy_verdict_response_integrity_result": verdict["response_integrity_result"],
        "proxy_route_execution_status": "executable_fixture",
        "proxy_chat_executable": "true",
        "proxy_models_count": "1",
        "proxy_models_contains_demo_model": "true",
        "proxy_confidentiality_route_id": verdict["route_id"],
        "proxy_confidentiality_chat_executable": "true",
        "proxy_confidentiality_unsupported_modes": '["streaming"]',
        "proxy_attestation_status": "Verified",
        "proxy_attestation_route_id": verdict["route_id"],
        "proxy_attestation_policy_digest": verdict["policy_digest"],
        "proxy_attestation_provider_registry_digest": verdict["provider_registry_digest"],
        "proxy_attestation_reference_values_digest": verdict["reference_values_digest"],
        "proxy_attestation_request_confidentiality_result": verdict[
            "request_confidentiality_result"
        ],
        "proxy_attestation_response_confidentiality_result": verdict[
            "response_confidentiality_result"
        ],
        "proxy_attestation_response_integrity_result": verdict["response_integrity_result"],
        "proxy_persisted_verdicts": "3",
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
        "phase2_tinfoil_policy_digest": DIGEST,
        "phase2_tinfoil_provider_registry_digest": DIGEST,
        "phase2_tinfoil_reference_values_digest": DIGEST,
        "phase2_tinfoil_registry_source": "custom",
        "phase2_tinfoil_reference_values_source": "custom",
        "phase2_tinfoil_registry_signature_signer": "confidential-inference",
        "phase2_tinfoil_reference_values_signature_signer": "confidential-inference",
        "phase2_tinfoil_tls_binding": "Some(Verified)",
        "phase2_tinfoil_response": (
            "tinfoil fixture response for llama-3.3-70b: "
            "verify the signed Tinfoil fixture path"
        ),
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
        "phase2_venice_policy_digest": DIGEST,
        "phase2_venice_provider_registry_digest": DIGEST,
        "phase2_venice_reference_values_digest": DIGEST,
        "phase2_venice_registry_source": "custom",
        "phase2_venice_reference_values_source": "custom",
        "phase2_venice_registry_signature_signer": "confidential-inference",
        "phase2_venice_reference_values_signature_signer": "confidential-inference",
        "phase2_venice_tcb_binding": "Some(Verified)",
        "phase2_venice_e2ee_binding": "Some(NotApplicable)",
        "phase2_venice_model_binding": "Some(Verified)",
        "phase2_venice_chat_blocked": "true",
        "phase2_fixture_persisted_verdicts": "4",
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
        "local_sdk_app_e2ee_policy_digest": DIGEST,
        "local_sdk_app_e2ee_provider_registry_digest": LOCAL_APP_E2EE_REGISTRY_DIGEST,
        "local_sdk_app_e2ee_reference_values_digest": LOCAL_APP_E2EE_REFERENCE_DIGEST,
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
        "local_sdk_app_e2ee_response": (
            "local SDK app-E2EE response for e2ee-gpt-oss-120b-p: "
            "verify the local SDK app-E2EE path"
        ),
        "local_sdk_app_e2ee_persisted_verdicts": "2",
        "local_sdk_app_e2ee_verdict_store": (
            "target/confidential-demo-local-sdk-app-e2ee-verdicts.jsonl"
        ),
        "local_sdk_app_e2ee_registry_artifact": (
            "target/confidential-demo-local-sdk-app-e2ee-registry.json"
        ),
        "local_sdk_app_e2ee_registry_artifact_digest": (
            LOCAL_APP_E2EE_REGISTRY_DIGEST
        ),
        "local_sdk_app_e2ee_compatibility_matrix_artifact": (
            "target/confidential-demo-local-sdk-app-e2ee-compatibility-matrix.json"
        ),
        "local_sdk_app_e2ee_compatibility_matrix_artifact_digest": (
            LOCAL_APP_E2EE_COMPATIBILITY_MATRIX_DIGEST
        ),
        "local_sdk_app_e2ee_reference_values_artifact": (
            "target/confidential-demo-local-sdk-app-e2ee-reference-values.json"
        ),
        "local_sdk_app_e2ee_reference_values_artifact_digest": (
            LOCAL_APP_E2EE_REFERENCE_DIGEST
        ),
        "local_ionet_provider": "local-ionet",
        "local_ionet_route_id": "local-ionet:llama-3.3-70b:local-ionet-llama-3-3-70b",
        "local_ionet_requested_model": "llama-3.3-70b",
        "local_ionet_provider_model": "local-ionet-llama-3-3-70b",
        "local_ionet_canonical_model": "llama-3.3-70b",
        "local_ionet_trust_tier": "tee-only",
        "local_ionet_evidence_family": "ionet_confidential",
        "local_ionet_channel_binding_kind": "none",
        "local_ionet_request_confidentiality_result": "unknown",
        "local_ionet_response_confidentiality_result": "unknown",
        "local_ionet_response_integrity_result": "receipt_bound",
        "local_ionet_route_execution_status": "executable",
        "local_ionet_chat_executable": "true",
        "local_ionet_policy_digest": DIGEST,
        "local_ionet_provider_registry_digest": LOCAL_IONET_REGISTRY_DIGEST,
        "local_ionet_reference_values_digest": LOCAL_IONET_REFERENCE_DIGEST,
        "local_ionet_registry_source": "custom",
        "local_ionet_reference_values_source": "custom",
        "local_ionet_registry_signature_signer": "confidential-inference-local-demo",
        "local_ionet_reference_values_signature_signer": "confidential-inference-local-demo",
        "local_ionet_gpu_tee": "Some(Verified)",
        "local_ionet_response_receipt": "Some(Verified)",
        "local_ionet_nonce_binding": "Some(Verified)",
        "local_ionet_response_signing_key_binding": "Some(Verified)",
        "local_ionet_model_binding": "Some(NotSupported)",
        "local_ionet_image_provenance": "Some(Verified)",
        "local_ionet_model_artifact_provenance": "Some(Verified)",
        "local_ionet_response_integrity": "ReceiptBound",
        "local_ionet_response": (
            "local io.net receipt-bound response for local-ionet-llama-3-3-70b: "
            "verify the local io.net receipt-bound path"
        ),
        "local_ionet_persisted_verdicts": "2",
        "local_ionet_verdict_store": "target/confidential-demo-local-ionet-verdicts.jsonl",
        "local_ionet_registry_artifact": (
            "target/confidential-demo-local-ionet-registry.json"
        ),
        "local_ionet_registry_artifact_digest": LOCAL_IONET_REGISTRY_DIGEST,
        "local_ionet_compatibility_matrix_artifact": (
            "target/confidential-demo-local-ionet-compatibility-matrix.json"
        ),
        "local_ionet_compatibility_matrix_artifact_digest": (
            LOCAL_IONET_COMPATIBILITY_MATRIX_DIGEST
        ),
        "local_ionet_reference_values_artifact": (
            "target/confidential-demo-local-ionet-reference-values.json"
        ),
        "local_ionet_reference_values_artifact_digest": LOCAL_IONET_REFERENCE_DIGEST,
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
        "local_live_tinfoil_policy_digest": DIGEST,
        "local_live_tinfoil_provider_registry_digest": LOCAL_LIVE_REGISTRY_DIGEST,
        "local_live_tinfoil_reference_values_digest": LOCAL_LIVE_REFERENCE_DIGEST,
        "local_live_tinfoil_registry_source": "custom",
        "local_live_tinfoil_reference_values_source": "custom",
        "local_live_tinfoil_registry_signature_signer": "confidential-inference-local-demo",
        "local_live_tinfoil_reference_values_signature_signer": "confidential-inference-local-demo",
        "local_live_tinfoil_tls_binding": "Some(Verified)",
        "local_live_tinfoil_model_binding": "Some(Verified)",
        "local_live_tinfoil_image_provenance": "Some(Verified)",
        "local_live_tinfoil_model_artifact_provenance": "Some(Verified)",
        "local_live_tinfoil_response": (
            "local live Tinfoil response for llama-3.3-70b: "
            "verify the local live TLS path"
        ),
        "local_live_tinfoil_persisted_verdicts": "2",
        "local_live_tinfoil_verdict_store": "target/confidential-demo-local-live-verdicts.jsonl",
        "local_live_tinfoil_registry_artifact": (
            "target/confidential-demo-local-live-registry.json"
        ),
        "local_live_tinfoil_registry_artifact_digest": LOCAL_LIVE_REGISTRY_DIGEST,
        "local_live_tinfoil_compatibility_matrix_artifact": (
            "target/confidential-demo-local-live-compatibility-matrix.json"
        ),
        "local_live_tinfoil_compatibility_matrix_artifact_digest": (
            LOCAL_LIVE_COMPATIBILITY_MATRIX_DIGEST
        ),
        "local_live_tinfoil_reference_values_artifact": (
            "target/confidential-demo-local-live-reference-values.json"
        ),
        "local_live_tinfoil_reference_values_artifact_digest": LOCAL_LIVE_REFERENCE_DIGEST,
    }
    if omit_label:
        labels.pop(omit_label)
    if label_overrides:
        labels.update(label_overrides)
    lines = [f"{label}: {value}" for label, value in labels.items()]
    lines.insert(9, "verdict:")
    lines.insert(10, json.dumps(verdict, sort_keys=True, indent=2))
    return "\n".join(lines) + "\n"


class CheckDemoOutputTests(unittest.TestCase):
    def test_valid_sample_transcript_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            output = root / "target" / "demo.out"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        self.assertEqual(report["schema"], "confidential-inference.demo-output-policy.v1")
        self.assertEqual(report["violations"], [])
        self.assertEqual(report["verdict_status"], "verified")

    def test_missing_marker_and_bad_verdict_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            output = root / "target" / "demo.out"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                sample_output(
                    sample_verdict(status="failed", policy_digest="sha256:not-hex"),
                    omit_label="local_ionet_response_receipt",
                ),
                encoding="utf-8",
            )

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("missing marker local_ionet_response_receipt", joined)
        self.assertIn("verdict.status expected 'verified', got 'failed'", joined)
        self.assertIn("verdict.policy_digest must be canonical sha256 hex digest", joined)

    def test_jsonl_artifacts_are_required_and_checked_for_trust_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            audit_path = root / "target" / "confidential-demo-audit.jsonl"
            audit_path.write_text(
                json.dumps(
                    sample_audit_record(policy_digest="sha256:not-hex"),
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        self.assertIn(
            "audit JSONL record 1.policy_digest must be a canonical sha256 hex digest",
            "\n".join(report["violations"]),
        )

    def test_jsonl_artifacts_reject_plaintext_leakage_and_missing_metric_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            metrics_path = root / "target" / "confidential-demo-metrics.jsonl"
            write_jsonl(
                metrics_path,
                [
                    {
                        "event": "route_selection",
                        "provider": "any",
                        "requested_model": "gpt-oss-120b",
                        "purpose": "chat",
                        "outcome": "success",
                        "leak": "verify the confidential inference SDK path",
                    }
                ],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)
            joined = "\n".join(report["violations"])

        self.assertIn("metrics JSONL must not contain plaintext marker", joined)
        self.assertIn("metrics JSONL missing required event types", joined)

    def test_jsonl_artifact_counts_must_match_transcript_markers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            audit_path = root / "target" / "confidential-demo-audit.jsonl"
            with audit_path.open("a", encoding="utf-8") as audit_file:
                audit_file.write(json.dumps(sample_audit_record(), sort_keys=True) + "\n")
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        self.assertIn(
            "audit JSONL has 3 records, expected exactly 2",
            "\n".join(report["violations"]),
        )

    def test_audit_records_must_match_printed_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            audit_path = root / "target" / "confidential-demo-audit.jsonl"
            write_jsonl(
                audit_path,
                [
                    sample_audit_record(policy_digest="sha256:" + "b" * 64),
                    sample_audit_record(cache_hit=True),
                ],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "primary audit record 1.policy_digest must match printed verdict.policy_digest",
            joined,
        )

    def test_active_metadata_markers_must_match_printed_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            output = root / "target" / "demo.out"
            output.write_text(
                sample_output(
                    label_overrides={
                        "active_policy_digest": "sha256:" + "b" * 64,
                        "active_registry_signature_alg": "rsa",
                    }
                ),
                encoding="utf-8",
            )

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            f"active_policy_digest expected '{PRIMARY_POLICY_DIGEST}'",
            joined,
        )
        self.assertIn("active_registry_signature_alg expected 'ed25519', got 'rsa'", joined)

    def test_active_policy_artifact_must_bind_verdict_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            artifact = sample_active_policy_snapshot()
            artifact["policy"]["provider_registry_digest"] = OTHER_DIGEST
            write_json(root / "target" / "confidential-demo-active-policy.json", artifact)
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("active policy artifact.policy_digest expected", joined)
        self.assertIn(
            f"active policy artifact.provider_registry_digest expected "
            f"'{PRIMARY_REGISTRY_DIGEST}', got '{OTHER_DIGEST}'",
            joined,
        )

    def test_active_trust_artifacts_must_verify_bundled_signatures(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            artifact = sample_active_trust_artifacts()
            artifact["registry"]["version"] = "tampered"
            write_json(
                root / "target" / "confidential-demo-active-trust-artifacts.json",
                artifact,
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("active trust artifacts artifact.registry_digest expected", joined)
        self.assertIn("active trust artifacts artifact.registry signature is invalid", joined)

    def test_proxy_markers_must_match_printed_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            output = root / "target" / "demo.out"
            output.write_text(
                sample_output(
                    label_overrides={
                        "proxy_verdict_policy_digest": "sha256:" + "b" * 64,
                        "proxy_attestation_response_integrity_result": "receipt_bound",
                    }
                ),
                encoding="utf-8",
            )

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            f"proxy_verdict_policy_digest expected '{PRIMARY_POLICY_DIGEST}'",
            joined,
        )
        self.assertIn(
            "proxy_attestation_response_integrity_result expected "
            "'channel_bound', got 'receipt_bound'",
            joined,
        )

    def test_proxy_verdict_store_must_preserve_checks_and_cache_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            proxy_path = root / "target" / "confidential-demo-proxy-verdicts.jsonl"
            bad = sample_audit_record(include_nested_verdict=True)
            bad["verdict_json"]["trust_tier"] = "tee-only"
            bad["verdict_json"]["checks"]["model_binding"] = "failed"
            write_jsonl(
                proxy_path,
                [
                    bad,
                    sample_audit_record(include_nested_verdict=True),
                    sample_audit_record(include_nested_verdict=True),
                ],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "proxy verdict JSONL record 1.verdict_json.trust_tier "
            "expected 'app-e2ee', got 'tee-only'",
            joined,
        )
        self.assertIn(
            "proxy verdict JSONL record 1.verdict_json.checks.model_binding "
            "expected 'verified', got 'failed'",
            joined,
        )
        self.assertIn("proxy verdict JSONL must include both fresh and cached records", joined)

    def test_primary_verdict_store_must_preserve_checks_and_cache_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            verdict_path = root / "target" / "confidential-demo-verdicts.jsonl"
            bad = sample_audit_record(include_nested_verdict=True)
            bad["verdict_json"]["trust_tier"] = "tee-only"
            bad["verdict_json"]["checks"]["model_binding"] = "failed"
            write_jsonl(
                verdict_path,
                [
                    bad,
                    sample_audit_record(include_nested_verdict=True),
                ],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "primary verdict JSONL record 1.verdict_json.trust_tier "
            "expected 'app-e2ee', got 'tee-only'",
            joined,
        )
        self.assertIn(
            "primary verdict JSONL record 1.verdict_json.checks.model_binding "
            "expected 'verified', got 'failed'",
            joined,
        )
        self.assertIn("primary verdict JSONL must include both fresh and cached records", joined)

    def test_primary_verdict_store_must_match_printed_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            verdict_path = root / "target" / "confidential-demo-verdicts.jsonl"
            fresh = sample_audit_record(include_nested_verdict=True)
            fresh["policy_digest"] = OTHER_DIGEST
            fresh["verdict_json"]["policy_digest"] = OTHER_DIGEST
            write_jsonl(
                verdict_path,
                [
                    fresh,
                    sample_audit_record(include_nested_verdict=True, cache_hit=True),
                ],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        self.assertIn(
            "primary verdict JSONL record 1.policy_digest must match printed "
            "verdict.policy_digest",
            "\n".join(report["violations"]),
        )

    def test_proxy_markers_must_match_fresh_persisted_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            proxy_path = root / "target" / "confidential-demo-proxy-verdicts.jsonl"
            fresh = sample_audit_record(include_nested_verdict=True)
            fresh["policy_digest"] = OTHER_DIGEST
            fresh["verdict_json"]["policy_digest"] = OTHER_DIGEST
            cached = sample_audit_record(include_nested_verdict=True, cache_hit=True)
            write_jsonl(
                proxy_path,
                [
                    fresh,
                    cached,
                    sample_audit_record(include_nested_verdict=True),
                ],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        self.assertIn(
            "proxy_verdict_policy_digest expected "
            f"'{OTHER_DIGEST}', got '{PRIMARY_POLICY_DIGEST}'",
            "\n".join(report["violations"]),
        )

    def test_local_route_markers_must_preserve_route_trust_and_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            output = root / "target" / "demo.out"
            output.write_text(
                sample_output(
                    label_overrides={
                        "local_sdk_app_e2ee_trust_tier": "app-e2ee",
                        "local_sdk_app_e2ee_policy_digest": "sha256:not-hex",
                        "local_ionet_response_integrity_result": "channel_bound",
                        "local_ionet_reference_values_digest": "not-a-digest",
                    }
                ),
                encoding="utf-8",
            )

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("local_sdk_app_e2ee_trust_tier expected 'tee-only'", joined)
        self.assertIn(
            "local_sdk_app_e2ee_policy_digest must be a canonical sha256 hex digest",
            joined,
        )
        self.assertIn(
            "local_ionet_response_integrity_result expected 'receipt_bound'",
            joined,
        )
        self.assertIn(
            "local_ionet_reference_values_digest must be a canonical sha256 hex digest",
            joined,
        )

    def test_phase2_route_markers_must_preserve_trust_lifecycle_and_digests(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            output = root / "target" / "demo.out"
            output.write_text(
                sample_output(
                    label_overrides={
                        "phase2_tinfoil_channel_binding_kind": "attested_app_e2ee",
                        "phase2_tinfoil_policy_digest": "not-a-digest",
                        "phase2_venice_chat_executable": "true",
                        "phase2_venice_reference_values_digest": "sha256:not-hex",
                    }
                ),
                encoding="utf-8",
            )

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "phase2_tinfoil_channel_binding_kind expected 'tee_terminated_tls'",
            joined,
        )
        self.assertIn(
            "phase2_tinfoil_policy_digest must be a canonical sha256 hex digest",
            joined,
        )
        self.assertIn("phase2_venice_chat_executable expected 'false'", joined)
        self.assertIn(
            "phase2_venice_reference_values_digest must be a canonical sha256 hex digest",
            joined,
        )

    def test_phase2_fixture_store_must_preserve_tinfoil_and_venice_lifecycle(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            phase2_path = root / "target" / "confidential-demo-phase2-fixture-verdicts.jsonl"
            tinfoil = sample_phase2_tinfoil_verdict(
                checks={
                    "cpu_tee": "verified",
                    "e2ee_key_binding": "not_applicable",
                    "model_binding": "not_applicable",
                    "request_encryption": "verified",
                    "request_key_binding": "verified",
                    "response_channel_binding": "verified",
                    "response_encryption": "verified",
                    "response_key_binding": "verified",
                    "route_binding": "verified",
                    "tls_binding": "failed",
                }
            )
            venice = sample_phase2_venice_verdict(
                route_execution_status="executable",
                chat_executable=True,
            )
            write_jsonl(
                phase2_path,
                [
                    sample_phase2_record(tinfoil),
                    sample_phase2_record(tinfoil),
                    sample_phase2_record(venice),
                    sample_phase2_record(venice),
                ],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "phase2 fixture verdict JSONL record 1.verdict_json.checks.tls_binding "
            "expected 'verified', got 'failed'",
            joined,
        )
        self.assertIn(
            "phase2 fixture verdict JSONL record 3.route_execution_status "
            "expected 'verification_only', got 'executable'",
            joined,
        )
        self.assertIn(
            "phase2 fixture verdict JSONL must include Tinfoil fresh and cached records",
            joined,
        )

    def test_phase2_markers_must_match_fresh_persisted_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            phase2_path = root / "target" / "confidential-demo-phase2-fixture-verdicts.jsonl"
            tinfoil_fresh = sample_phase2_tinfoil_verdict(policy_digest=OTHER_DIGEST)
            tinfoil_cached = sample_phase2_tinfoil_verdict()
            venice = sample_phase2_venice_verdict()
            write_jsonl(
                phase2_path,
                [
                    sample_phase2_record(tinfoil_fresh),
                    sample_phase2_record(tinfoil_cached, cache_hit=True),
                    sample_phase2_record(venice),
                    sample_phase2_record(venice),
                ],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        self.assertIn(
            f"phase2_tinfoil_policy_digest expected '{OTHER_DIGEST}', got '{DIGEST}'",
            "\n".join(report["violations"]),
        )

    def test_local_live_route_markers_must_preserve_tls_trust_and_digests(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            output = root / "target" / "demo.out"
            output.write_text(
                sample_output(
                    label_overrides={
                        "local_live_tinfoil_trust_tier": "app-e2ee",
                        "local_live_tinfoil_response_integrity_result": "receipt_bound",
                        "local_live_tinfoil_chat_executable": "false",
                        "local_live_tinfoil_reference_values_digest": "not-a-digest",
                    }
                ),
                encoding="utf-8",
            )

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "local_live_tinfoil_trust_tier expected 'hw-verified-tls'",
            joined,
        )
        self.assertIn(
            "local_live_tinfoil_response_integrity_result expected 'channel_bound'",
            joined,
        )
        self.assertIn("local_live_tinfoil_chat_executable expected 'true'", joined)
        self.assertIn(
            "local_live_tinfoil_reference_values_digest must be a canonical sha256 hex digest",
            joined,
        )

    def test_audit_records_must_cover_fresh_and_cached_verdicts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            audit_path = root / "target" / "confidential-demo-audit.jsonl"
            write_jsonl(
                audit_path,
                [sample_audit_record(), sample_audit_record()],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        self.assertIn(
            "audit JSONL must include both fresh and cached records for the printed verdict route",
            "\n".join(report["violations"]),
        )

    def test_local_live_tinfoil_store_must_preserve_tinfoil_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            local_live_path = root / "target" / "confidential-demo-local-live-verdicts.jsonl"
            first = sample_local_live_record(
                nested_overrides={
                    "trust_tier": "app-e2ee",
                    "checks": {
                        "cpu_tee": "verified",
                        "tls_binding": "failed",
                        "image_provenance": "verified",
                        "model_artifact_provenance": "verified",
                        "model_binding": "verified",
                        "request_encryption": "verified",
                        "request_key_binding": "verified",
                        "response_channel_binding": "verified",
                        "response_encryption": "verified",
                        "response_key_binding": "verified",
                        "route_binding": "verified",
                    },
                }
            )
            write_jsonl(
                local_live_path,
                [first, sample_local_live_record(cache_hit=False)],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "local live verdict JSONL record 1.verdict_json.trust_tier "
            "expected 'hw-verified-tls', got 'app-e2ee'",
            joined,
        )
        self.assertIn(
            "local live verdict JSONL record 1.verdict_json.checks.tls_binding "
            "expected 'verified', got 'failed'",
            joined,
        )
        self.assertIn("local live verdict JSONL must include both fresh and cached records", joined)

    def test_local_app_e2ee_registry_artifact_must_bind_route_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            artifact_path = (
                root / "target" / "confidential-demo-local-sdk-app-e2ee-registry.json"
            )
            payload = sample_local_app_e2ee_registry_payload()
            route = payload["models"]["gpt-oss-120b"]["routes"][0]
            route["request_encryption"] = "not_required"
            route["response_integrity_requirement"] = "not_required"
            write_json(artifact_path, sample_local_app_e2ee_registry_envelope(payload))
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("local_sdk_app_e2ee_registry_artifact_digest expected", joined)
        self.assertIn(
            "local SDK app-E2EE registry artifact.route.request_encryption "
            "expected 'required', got 'not_required'",
            joined,
        )
        self.assertIn(
            "local SDK app-E2EE registry artifact.route.response_integrity_requirement "
            "expected 'any_bound', got 'not_required'",
            joined,
        )

    def test_local_ionet_registry_artifact_must_bind_gpu_and_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            artifact_path = root / "target" / "confidential-demo-local-ionet-registry.json"
            payload = sample_local_ionet_registry_payload()
            route = payload["models"]["llama-3.3-70b"]["routes"][0]
            route["accepted_gpu_tees"] = []
            route["response_integrity_requirement"] = "channel_bound"
            write_json(artifact_path, sample_local_ionet_registry_envelope(payload))
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("local_ionet_registry_artifact_digest expected", joined)
        self.assertIn(
            "local io.net registry artifact.route.accepted_gpu_tees "
            "expected ['nvidia_cc'], got []",
            joined,
        )
        self.assertIn(
            "local io.net registry artifact.route.response_integrity_requirement "
            "expected 'receipt_bound', got 'channel_bound'",
            joined,
        )

    def test_local_live_registry_artifact_must_bind_tls_route(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            artifact_path = root / "target" / "confidential-demo-local-live-registry.json"
            payload = sample_local_live_registry_payload()
            route = payload["models"]["llama-3.3-70b"]["routes"][0]
            route["channel_binding_kind"] = "none"
            route["evidence_endpoint"] = "https://127.0.0.1:33789/v1/confidentiality"
            write_json(artifact_path, sample_local_live_registry_envelope(payload))
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("local_live_tinfoil_registry_artifact_digest expected", joined)
        self.assertIn(
            "local live registry artifact.route.channel_binding_kind "
            "expected 'tee_terminated_tls', got 'none'",
            joined,
        )
        self.assertIn(
            "local live registry artifact.route.evidence_endpoint must use "
            "https://127.0.0.1:*/.well-known/tinfoil-attestation",
            joined,
        )

    def test_local_app_e2ee_compatibility_matrix_must_bind_sdk_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            artifact_path = (
                root
                / "target"
                / "confidential-demo-local-sdk-app-e2ee-compatibility-matrix.json"
            )
            payload = sample_local_app_e2ee_compatibility_matrix_payload()
            provider = payload["providers"]["local-sdk-app-e2ee"]
            provider["request_encryption"] = "not_required"
            provider["sdk_app_e2ee"]["public_key_base64"] = base64.b64encode(
                bytes([9]) * 32
            ).decode("ascii")
            write_json(
                artifact_path,
                sample_local_app_e2ee_compatibility_matrix_envelope(payload),
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "local_sdk_app_e2ee_compatibility_matrix_artifact_digest expected",
            joined,
        )
        self.assertIn(
            "local SDK app-E2EE compatibility matrix artifact.provider.request_encryption "
            "expected 'required', got 'not_required'",
            joined,
        )
        self.assertIn(
            "local SDK app-E2EE compatibility matrix artifact.provider.sdk_app_e2ee."
            "public_key_base64 digest must match fresh local_sdk_app_e2ee verdict report_data",
            joined,
        )

    def test_local_ionet_compatibility_matrix_must_bind_receipt_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            artifact_path = (
                root / "target" / "confidential-demo-local-ionet-compatibility-matrix.json"
            )
            payload = sample_local_ionet_compatibility_matrix_payload()
            provider = payload["providers"]["local-ionet"]
            provider["route_execution_status"] = "verification_only"
            provider["attestation_endpoint_shape"] = "dstack_app_e2ee_local_demo"
            write_json(
                artifact_path,
                sample_local_ionet_compatibility_matrix_envelope(payload),
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("local_ionet_compatibility_matrix_artifact_digest expected", joined)
        self.assertIn(
            "local io.net compatibility matrix artifact.provider.route_execution_status "
            "expected 'executable', got 'verification_only'",
            joined,
        )
        self.assertIn(
            "local io.net compatibility matrix artifact.provider.attestation_endpoint_shape "
            "expected 'ionet_confidential_local_demo', got 'dstack_app_e2ee_local_demo'",
            joined,
        )

    def test_local_live_compatibility_matrix_must_bind_tls_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            artifact_path = (
                root / "target" / "confidential-demo-local-live-compatibility-matrix.json"
            )
            payload = sample_local_live_compatibility_matrix_payload()
            provider = payload["providers"]["local-tinfoil-live"]
            provider["expected_trust_tier"] = "tee-only"
            provider["api_base_url"] = "http://127.0.0.1:33789/v1"
            write_json(
                artifact_path,
                sample_local_live_compatibility_matrix_envelope(payload),
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "local_live_tinfoil_compatibility_matrix_artifact_digest expected",
            joined,
        )
        self.assertIn(
            "local live compatibility matrix artifact.provider.expected_trust_tier "
            "expected 'hw-verified-tls', got 'tee-only'",
            joined,
        )
        self.assertIn(
            "local live compatibility matrix artifact.route.api_base_url must use "
            "https://127.0.0.1:*/v1",
            joined,
        )

    def test_local_live_reference_values_artifact_must_bind_tls_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            artifact_path = (
                root / "target" / "confidential-demo-local-live-reference-values.json"
            )
            payload = sample_local_live_reference_values_payload()
            route = payload["providers"]["local-tinfoil-live"]["routes"][
                "local-tinfoil-live:llama-3.3-70b:llama-3.3-70b"
            ]
            route["tls_spki_sha256"] = OTHER_DIGEST
            route["model_artifacts"] = []
            write_json(artifact_path, sample_local_live_reference_values_envelope(payload))
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "local_live_tinfoil_reference_values_digest expected",
            joined,
        )
        self.assertIn(
            "local live reference-values artifact.route.tls_spki_sha256 must match "
            "fresh local-live verdict signing_public_key",
            joined,
        )
        self.assertIn(
            "local live reference-values artifact.route.model_artifacts must be non-empty",
            joined,
        )

    def test_local_app_e2ee_reference_values_artifact_must_bind_key_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            artifact_path = (
                root
                / "target"
                / "confidential-demo-local-sdk-app-e2ee-reference-values.json"
            )
            payload = sample_local_app_e2ee_reference_values_payload()
            route = payload["providers"]["local-sdk-app-e2ee"]["routes"][
                "local-sdk-app-e2ee:gpt-oss-120b:e2ee-gpt-oss-120b-p"
            ]
            route["e2ee_public_key_digest"] = OTHER_DIGEST
            route["model_artifacts"] = []
            write_json(artifact_path, sample_local_app_e2ee_reference_values_envelope(payload))
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("local_sdk_app_e2ee_reference_values_digest expected", joined)
        self.assertIn(
            "local SDK app-E2EE reference-values artifact.route.e2ee_public_key_digest "
            "must match fresh app-E2EE verdict report_data",
            joined,
        )
        self.assertIn(
            "local SDK app-E2EE reference-values artifact.route.model_artifacts must be non-empty",
            joined,
        )

    def test_local_ionet_reference_values_artifact_must_bind_receipt_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            artifact_path = (
                root / "target" / "confidential-demo-local-ionet-reference-values.json"
            )
            payload = sample_local_ionet_reference_values_payload()
            provider = payload["providers"]["local-ionet"]
            provider["accepted_measurements"] = [OTHER_DIGEST]
            route = provider["routes"][
                "local-ionet:llama-3.3-70b:local-ionet-llama-3-3-70b"
            ]
            route["response_signing_key_digest"] = OTHER_DIGEST
            write_json(artifact_path, sample_local_ionet_reference_values_envelope(payload))
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("local_ionet_reference_values_digest expected", joined)
        self.assertIn(
            "local io.net reference-values artifact.accepted_measurements must be empty",
            joined,
        )
        self.assertIn(
            "local io.net reference-values artifact.route.response_signing_key_digest "
            "must match fresh io.net verdict signing_public_key",
            joined,
        )

    def test_local_live_markers_must_match_fresh_persisted_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            local_live_path = root / "target" / "confidential-demo-local-live-verdicts.jsonl"
            fresh = sample_local_live_record(
                nested_overrides={"policy_digest": OTHER_DIGEST}
            )
            cached = sample_local_live_record(cache_hit=True)
            write_jsonl(local_live_path, [fresh, cached])
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        self.assertIn(
            f"local_live_tinfoil_policy_digest expected '{OTHER_DIGEST}', got '{DIGEST}'",
            "\n".join(report["violations"]),
        )

    def test_local_app_e2ee_store_must_preserve_encryption_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            app_path = root / "target" / "confidential-demo-local-sdk-app-e2ee-verdicts.jsonl"
            first = sample_local_app_e2ee_record(
                nested_overrides={
                    "trust_tier": "app-e2ee",
                    "checks": {
                        "cpu_tee": "verified",
                        "e2ee_key_binding": "verified",
                        "tcb_compose_hash": "verified",
                        "request_encryption": "failed",
                        "response_encryption": "verified",
                        "model_binding": "verified",
                        "image_provenance": "verified",
                        "model_artifact_provenance": "verified",
                        "request_key_binding": "verified",
                        "response_channel_binding": "verified",
                        "response_key_binding": "verified",
                        "route_binding": "verified",
                    },
                }
            )
            write_jsonl(
                app_path,
                [first, sample_local_app_e2ee_record(cache_hit=False)],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "local SDK app-E2EE verdict JSONL record 1.verdict_json.trust_tier "
            "expected 'tee-only', got 'app-e2ee'",
            joined,
        )
        self.assertIn(
            "local SDK app-E2EE verdict JSONL record 1.verdict_json.checks.request_encryption "
            "expected 'not_applicable', got 'failed'",
            joined,
        )
        self.assertIn(
            "local SDK app-E2EE verdict JSONL must include both fresh and cached records",
            joined,
        )

    def test_local_app_e2ee_markers_must_match_fresh_persisted_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            app_path = root / "target" / "confidential-demo-local-sdk-app-e2ee-verdicts.jsonl"
            fresh = sample_local_app_e2ee_record(
                nested_overrides={"policy_digest": OTHER_DIGEST}
            )
            cached = sample_local_app_e2ee_record(cache_hit=True)
            write_jsonl(app_path, [fresh, cached])
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        self.assertIn(
            f"local_sdk_app_e2ee_policy_digest expected '{OTHER_DIGEST}', got '{DIGEST}'",
            "\n".join(report["violations"]),
        )

    def test_local_ionet_store_must_preserve_receipt_bound_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            ionet_path = root / "target" / "confidential-demo-local-ionet-verdicts.jsonl"
            first = sample_local_ionet_record(
                nested_overrides={
                    "trust_tier": "app-e2ee",
                    "checks": {
                        "cpu_tee": "not_applicable",
                        "e2ee_key_binding": "not_applicable",
                        "gpu_tee": "verified",
                        "image_provenance": "verified",
                        "model_artifact_provenance": "verified",
                        "model_binding": "verified",
                        "nonce_binding": "verified",
                        "request_encryption": "not_applicable",
                        "request_key_binding": "verified",
                        "response_channel_binding": "verified",
                        "response_encryption": "not_applicable",
                        "response_key_binding": "verified",
                        "response_receipt": "failed",
                        "response_signing_key_binding": "verified",
                        "route_binding": "verified",
                        "tls_binding": "not_applicable",
                    },
                }
            )
            write_jsonl(
                ionet_path,
                [first, sample_local_ionet_record(cache_hit=False)],
            )
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn(
            "local io.net verdict JSONL record 1.verdict_json.trust_tier "
            "expected 'tee-only', got 'app-e2ee'",
            joined,
        )
        self.assertIn(
            "local io.net verdict JSONL record 1.verdict_json.checks.response_receipt "
            "expected 'verified', got 'failed'",
            joined,
        )
        self.assertIn(
            "local io.net verdict JSONL must include both fresh and cached records",
            joined,
        )

    def test_local_ionet_markers_must_match_fresh_persisted_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            ionet_path = root / "target" / "confidential-demo-local-ionet-verdicts.jsonl"
            fresh = sample_local_ionet_record(
                nested_overrides={"policy_digest": OTHER_DIGEST}
            )
            cached = sample_local_ionet_record(cache_hit=True)
            write_jsonl(ionet_path, [fresh, cached])
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        self.assertIn(
            f"local_ionet_policy_digest expected '{OTHER_DIGEST}', got '{DIGEST}'",
            "\n".join(report["violations"]),
        )

    def test_metrics_counts_and_route_labels_must_match_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            metrics_path = root / "target" / "confidential-demo-metrics.jsonl"
            metrics = sample_metric_records()
            metrics[2]["cache_event"] = "miss"
            metrics[2]["labels"]["provider_model"] = "wrong-provider-model"
            write_jsonl(metrics_path, metrics)
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("metrics_cache_hits marker expected 1 but metrics JSONL has 0", joined)
        self.assertIn("labels must match printed verdict route identity", joined)

    def test_metrics_must_cover_fresh_cached_and_streaming_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sample_artifacts(root)
            metrics_path = root / "target" / "confidential-demo-metrics.jsonl"
            metrics = [
                record
                for record in sample_metric_records()
                if record.get("event") != "streaming_fail_closed"
            ]
            for record in metrics:
                if record.get("event") == "verdict":
                    record["cache_hit"] = False
            write_jsonl(metrics_path, metrics)
            output = root / "target" / "demo.out"
            output.write_text(sample_output(), encoding="utf-8")

            report = check_demo_output.check_demo_output(output)

        joined = "\n".join(report["violations"])
        self.assertIn("metrics JSONL missing required event types", joined)
        self.assertIn("fresh and cached verdict metrics", joined)
        self.assertIn("exactly one streaming_fail_closed event", joined)

    def test_missing_file_and_invalid_json_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / "missing.out"
            self.assertIn("does not exist", check_demo_output.check_demo_output(missing)["violations"][0])

            output = Path(temp) / "demo.out"
            output.write_text("verdict:\n{not json}\n", encoding="utf-8")
            report = check_demo_output.check_demo_output(output)

        self.assertTrue(
            any("printed verdict JSON is invalid" in item for item in report["violations"])
        )


if __name__ == "__main__":
    unittest.main()
