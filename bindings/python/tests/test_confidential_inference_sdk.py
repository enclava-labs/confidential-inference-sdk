import asyncio
import ctypes
import json
import os
import select
import sys
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "bindings" / "python"))

import confidential_inference_sdk as confidential_inference_module  # noqa: E402
from confidential_inference_sdk import Client, ConfidentialInferenceError  # noqa: E402


VALID_DIGEST = "sha256:" + ("0" * 64)
VALID_REGISTRY_SIGNATURE_VALUE = (
    "base64url:"
    "Xwtv2PpYiarqO1ZLC2s_n0b5Cu1-gJyUCnnkHspDlI_sU_uk_WorpQGUN4VvldAz4S0--E0d4_3GN0L3VowrBg"
)
VALID_REFERENCE_VALUES_SIGNATURE_VALUE = (
    "base64url:"
    "ULskkFC98v_FXOt4lBLINcrVnPoMjMOd_Aj4NpvMaqiBxcU-O9ydZ3JgxxBWmnA74vPoKQEgNcmvRmxJJc5nAA"
)


def canonical_digest_or_fixture_digest(payload):
    try:
        return confidential_inference_module.canonical_sha256_digest(payload)
    except ConfidentialInferenceError:
        return VALID_DIGEST


def valid_verdict_stub(**overrides):
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
        "channel_binding_kind": "attested_app_e2ee",
        "model_binding_result": "verified",
        "request_channel_bound": True,
        "request_confidentiality_result": "encrypted_bound",
        "response_confidentiality_result": "encrypted_bound",
        "response_channel_bound": True,
        "response_integrity_result": "channel_bound",
        "policy_digest": VALID_DIGEST,
        "provider_registry_digest": VALID_DIGEST,
        "registry_signature": {
            "signer": "confidential-inference",
            "key_id": "confidential-inference-demo-ed25519-2026",
            "alg": "ed25519",
        },
        "reference_values_digest": VALID_DIGEST,
        "reference_values_signature": {
            "signer": "confidential-inference",
            "key_id": "confidential-inference-demo-ed25519-2026",
            "alg": "ed25519",
        },
        "raw_evidence_digest": VALID_DIGEST,
        "evidence_digest": VALID_DIGEST,
        "expires_at": "2099-01-01T00:00:00Z",
        "expires_at_epoch_ms": 4070908800000,
        "validity": {
            "policy_ttl_until": "2099-01-01T00:00:00Z",
            "collateral_valid_until": "2099-01-01T00:00:00Z",
            "certificate_valid_until": "2099-01-01T00:00:00Z",
            "quote_valid_until": "2099-01-01T00:00:00Z",
            "tcb_valid_until": "2099-01-01T00:00:00Z",
            "reference_values_valid_until": "2099-01-01T00:00:00Z",
            "computed_expires_at": "2099-01-01T00:00:00Z",
        },
        "checks": {
            "model_binding": "verified",
            "request_key_binding": "verified",
            "request_encryption": "verified",
            "response_key_binding": "verified",
            "response_encryption": "verified",
            "response_channel_binding": "verified",
            "response_receipt": "not_applicable",
        },
        "errors": [],
    }
    verdict.update(overrides)
    return verdict


def valid_trust_artifacts_stub(**overrides):
    registry = {"schema": "confidential-inference.provider-registry.v1"}
    reference_values = {"schema": "confidential-inference.reference-values.v1"}
    artifacts = {
        "registry": registry,
        "reference_values": reference_values,
        "registry_digest": canonical_digest_or_fixture_digest(registry),
        "registry_signature": {
            "signer": "confidential-inference-binding-test",
            "key_id": "binding-test-ed25519-2026",
            "alg": "ed25519",
            "value": VALID_REGISTRY_SIGNATURE_VALUE,
        },
        "reference_values_digest": canonical_digest_or_fixture_digest(reference_values),
        "reference_values_signature": {
            "signer": "confidential-inference-binding-test",
            "key_id": "binding-test-ed25519-2026",
            "alg": "ed25519",
            "value": VALID_REFERENCE_VALUES_SIGNATURE_VALUE,
        },
    }
    artifacts.update(overrides)
    if "registry_digest" not in overrides:
        artifacts["registry_digest"] = canonical_digest_or_fixture_digest(artifacts["registry"])
    if "reference_values_digest" not in overrides:
        artifacts["reference_values_digest"] = canonical_digest_or_fixture_digest(
            artifacts["reference_values"]
        )
    return artifacts


def valid_registry_payload_stub(**overrides):
    route = {
        "route_id": "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p",
        "route_status": "active",
        "provider": "demo",
        "provider_model": "e2ee-gpt-oss-120b-p",
        "evidence_family": "fixture_dstack",
        "api_base_url": "http://127.0.0.1/demo/v1",
        "evidence_endpoint": "http://127.0.0.1/demo/v1/confidentiality",
        "adapter_version": "demo-fixture-adapter/0.1.0",
        "freshness_class": "per_session",
        "channel_binding_kind": "attested_app_e2ee",
        "trust_tier": "app-e2ee",
        "request_confidentiality_requirement": "bound_to_attested_workload",
        "response_confidentiality_requirement": "bound_to_attested_workload",
        "response_integrity_requirement": "any_bound",
        "request_encryption": "required",
        "response_decryption": "required",
        "streaming": "unsupported",
        "alias_confidence": "curated",
    }
    registry = {
        "schema": "confidential-inference.provider-registry.v1",
        "version": "2026-07-05-demo",
        "generated_at": "2026-07-05T00:00:00Z",
        "source_sync_run": {
            "completed_at": "2026-07-05T00:00:00Z",
            "status": "success",
            "source": "confidential-inference-sdk-demo-fixture",
        },
        "models": {
            "gpt-oss-120b": {
                "canonical_model": "gpt-oss-120b",
                "display_name": "GPT-OSS 120B",
                "family": "OpenAI GPT",
                "aliases": ["gpt-oss-120b"],
                "routes": [route],
            }
        },
    }
    registry.update(overrides)
    return registry


def valid_reference_values_payload_stub(**overrides):
    reference_values = {
        "schema": "confidential-inference.reference-values.v1",
        "version": "2026-07-05-demo",
        "issuer": "confidential-inference",
        "valid_from": "2026-07-05T00:00:00Z",
        "valid_until": "2099-01-01T00:00:00Z",
        "valid_until_epoch_ms": 4070908800000,
        "revocation_epoch": 1,
        "minimum_acceptable_version": "2026-07-05-demo",
        "providers": {},
    }
    reference_values.update(overrides)
    return reference_values


def valid_reference_values_route_stub(**overrides):
    route = {
        "canonical_model": "gpt-oss-120b",
        "provider_model": "e2ee-gpt-oss-120b-p",
        "evidence_family": "fixture_dstack",
        "channel_binding_kind": "attested_app_e2ee",
        "trust_tier": "app-e2ee",
        "accepted_cpu_tees": ["tdx"],
        "e2ee_public_key_digest": "sha256:demo-e2ee-key",
        "workload_image_digest": "sha256:demo-workload-image",
        "model_artifacts": [
            {
                "kind": "weights",
                "name": "gpt-oss-120b",
                "digest": "sha256:demo-weights",
            }
        ],
        "valid_until": "2099-01-01T00:00:00Z",
        "valid_until_epoch_ms": 4070908800000,
    }
    route.update(overrides)
    return route


def valid_reference_values_payload_with_route(**route_overrides):
    return valid_reference_values_payload_stub(
        providers={
            "demo": {
                "accepted_measurements": ["sha256:demo-tee-measurement"],
                "routes": {
                    "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p": (
                        valid_reference_values_route_stub(**route_overrides)
                    )
                },
            }
        }
    )


def valid_confidential_catalog_stub():
    return [
        {
            "canonical_model": "gpt-oss-120b",
            "display_name": "GPT-OSS 120B",
            "family": "OpenAI GPT",
            "aliases": ["gpt-oss-120b"],
            "routes": [
                {
                    "route_id": "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p",
                    "provider": "demo",
                    "provider_model": "e2ee-gpt-oss-120b-p",
                    "evidence_family": "fixture_dstack",
                    "route_execution_status": "executable_fixture",
                    "chat_executable": True,
                    "known_unsupported_modes": ["streaming"],
                    "trust_tier": "app-e2ee",
                    "channel_binding_kind": "attested_app_e2ee",
                    "request_encryption": "required",
                    "response_decryption": "required",
                    "streaming_allowed": False,
                    "alias_confidence": "curated",
                    "api_endpoint": "http://127.0.0.1/demo/v1",
                    "evidence_endpoint": "http://127.0.0.1/demo/v1/confidentiality",
                    "adapter_version": "demo-fixture-adapter/0.1.0",
                }
            ],
        }
    ]


def valid_active_policy_snapshot_stub(**policy_overrides):
    policy = {
        "schema": "confidential-inference.policy.v1",
        "enforcement": "enforce",
        "hardware": {
            "cpu": {"mode": "any_cpu_tee"},
            "gpu": {"mode": "not_required"},
        },
        "channel_binding_requirement": "attested_app_e2ee",
        "request_confidentiality_requirement": "bound_to_attested_workload",
        "response_confidentiality_requirement": "bound_to_attested_workload",
        "response_integrity_requirement": "any_bound",
        "model_binding_requirement": "if_provider_supports",
        "provenance": {
            "workload_image": False,
            "model_artifacts": False,
            "reproducible_build": False,
            "source_attestation": False,
            "dependency_sbom": False,
        },
        "freshness": {"mode": "per_session"},
        "stale_verdicts": {"mode": "fail_closed"},
        "verdict_ttl_millis": 600_000,
        "provider_registry_digest": VALID_DIGEST,
        "reference_values_digest": VALID_DIGEST,
    }
    policy.update(policy_overrides)
    return {
        "schema": "confidential-inference.active-policy.v1",
        "policy": policy,
        "policy_digest": VALID_DIGEST,
    }


class ConfidentialInferencePythonBindingTests(unittest.TestCase):
    def test_ffi_status_helper_reports_loaded_sdk_capabilities(self):
        module_status = confidential_inference_module.status()
        self.assertIs(confidential_inference_module._validate_ffi_status(module_status), module_status)
        self.assertIs(module_status["async_handle_abi_available"], True)
        self.assertIs(module_status["callbacks_available"], True)
        self.assertIs(module_status["stream_handle_abi_available"], True)
        self.assertIs(module_status["blocking_helpers_available"], True)
        self.assertIsInstance(module_status["readiness_fd_available"], bool)
        self.assertIn("chat, responses, verify", module_status["reason"])

        with Client() as client:
            self.assertEqual(client.status(), module_status)

    def test_binding_rejects_malformed_ffi_status_payloads(self):
        valid = {
            "async_handle_abi_available": True,
            "callbacks_available": True,
            "readiness_fd_available": os.name == "posix",
            "stream_handle_abi_available": True,
            "blocking_helpers_available": True,
            "reason": "capabilities available",
        }
        self.assertIs(confidential_inference_module._validate_ffi_status(valid), valid)

        cases = (
            ({**valid, "reason": ""}, "reason"),
            ({**valid, "callbacks_available": "yes"}, "callbacks_available"),
            ({**valid, "extra": True}, "unsupported field extra"),
        )
        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_ffi_status(payload)
                self.assertEqual(raised.exception.error["code"], "malformed_ffi_status")
                self.assertIn(message, raised.exception.error["message"])

    def test_chat_blocking_matches_normative_verdict_fixture(self):
        expected_verdict = json.loads(
            (ROOT / "fixtures" / "verdict" / "demo-verified.json").read_text()
        )
        request = {
            "model": "gpt-oss-120b",
            "messages": [{"role": "user", "content": "python binding path"}],
        }

        with Client() as client:
            response = client.chat(request, timeout_ms=2_000)

        self.assertEqual(response["provider"], "demo")
        self.assertEqual(response["provider_model"], "e2ee-gpt-oss-120b-p")
        self.assertEqual(response["verdict"], expected_verdict)
        self.assertEqual(response["verdict"]["schema"], "confidential-inference.verdict.v1")
        self.assertEqual(response["verdict"]["status"], "verified")
        self.assertEqual(
            response["response_channel_bound"],
            response["verdict"]["response_channel_bound"],
        )
        self.assertEqual(
            response["response_integrity_result"],
            response["verdict"]["response_integrity_result"],
        )
        self.assertEqual(
            response["response"]["choices"][0]["message"]["content"],
            "demo confidential response for e2ee-gpt-oss-120b-p: python binding path",
        )
        self.assertNotIn("python binding path", json.dumps(response["verdict"]))

    def test_verify_blocking_returns_route_verdict(self):
        with Client() as client:
            verdict = client.verify("demo", "gpt-oss-120b", timeout_ms=2_000)

        self.assertEqual(verdict["schema"], "confidential-inference.verdict.v1")
        self.assertEqual(verdict["status"], "verified")
        self.assertEqual(verdict["route_id"], "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p")
        self.assertEqual(verdict["checks"]["model_binding"], "verified")

    def test_response_blocking_uses_responses_shim_and_verdict(self):
        with Client() as client:
            response = client.create_response(
                {
                    "model": "gpt-oss-120b",
                    "input": "python response binding path",
                    "max_output_tokens": 64,
                },
                timeout_ms=2_000,
            )

        self.assertEqual(response["provider"], "demo")
        self.assertEqual(response["provider_model"], "e2ee-gpt-oss-120b-p")
        self.assertEqual(response["verdict"]["status"], "verified")
        self.assertEqual(
            response["response_channel_bound"],
            response["verdict"]["response_channel_bound"],
        )
        self.assertEqual(
            response["response_integrity_result"],
            response["verdict"]["response_integrity_result"],
        )
        self.assertEqual(response["response"]["object"], "response")
        self.assertEqual(response["response"]["status"], "completed")
        self.assertEqual(
            response["response"]["metadata"]["confidential_inference_compatibility"],
            "responses_to_chat_shim",
        )
        self.assertEqual(
            response["response"]["output_text"],
            "demo confidential response for e2ee-gpt-oss-120b-p: python response binding path",
        )

    def test_model_discovery_and_confidentiality_catalog_use_sdk_state(self):
        with Client() as client:
            models = client.models()
            confidential_models = client.confidential_models()

        self.assertEqual(models["object"], "list")
        self.assertEqual(models["data"][0]["id"], "gpt-oss-120b")
        self.assertEqual(confidential_models[0]["canonical_model"], "gpt-oss-120b")
        self.assertIs(confidential_inference_module._validate_model_list(models), models)
        self.assertIs(
            confidential_inference_module._validate_confidential_models(confidential_models),
            confidential_models,
        )
        route = confidential_models[0]["routes"][0]
        self.assertEqual(route["provider"], "demo")
        self.assertTrue(route["chat_executable"])
        self.assertEqual(route["route_execution_status"], "executable_fixture")
        self.assertEqual(route["known_unsupported_modes"], ["streaming"])

    def test_binding_rejects_malformed_discovery_and_catalog_json(self):
        model_list = {
            "object": "list",
            "data": [{"id": "gpt-oss-120b", "object": "model", "owned_by": "confidential-inference"}],
        }
        catalog = valid_confidential_catalog_stub()
        self.assertIs(confidential_inference_module._validate_model_list(model_list), model_list)
        self.assertIs(confidential_inference_module._validate_confidential_models(catalog), catalog)

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_model_list({"object": "models", "data": []})
        self.assertEqual(raised.exception.error["code"], "malformed_model_discovery")
        self.assertIn("object", raised.exception.error["message"])

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_model_list(
                {
                    "object": "list",
                    "data": [{"id": "", "object": "model", "owned_by": "confidential-inference"}],
                }
            )
        self.assertEqual(raised.exception.error["code"], "malformed_model_discovery")
        self.assertIn("id", raised.exception.error["message"])

        invalid_status = json.loads(json.dumps(catalog))
        invalid_status[0]["routes"][0]["route_execution_status"] = "active"
        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_confidential_models(invalid_status)
        self.assertEqual(raised.exception.error["code"], "malformed_confidential_catalog")
        self.assertIn("route_execution_status", raised.exception.error["message"])

        invalid_trust_tier = json.loads(json.dumps(catalog))
        invalid_trust_tier[0]["routes"][0]["channel_binding_kind"] = "none"
        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_confidential_models(invalid_trust_tier)
        self.assertEqual(raised.exception.error["code"], "malformed_confidential_catalog")
        self.assertIn("trust_tier=app-e2ee", raised.exception.error["message"])

    def test_active_policy_matches_shared_canonical_fixture_and_digest(self):
        expected_policy = json.loads(
            (ROOT / "fixtures" / "policy" / "require_attested_e2ee.json").read_text()
        )
        vectors = json.loads(
            (ROOT / "fixtures" / "policy" / "canonical-vectors.json").read_text()
        )
        expected_vector = next(
            vector
            for vector in vectors["vectors"]
            if vector["id"] == "require-attested-e2ee-demo"
        )

        with Client() as client:
            snapshot = client.active_policy()

        self.assertEqual(snapshot["schema"], "confidential-inference.active-policy.v1")
        self.assertEqual(snapshot["policy"], expected_policy)
        self.assertEqual(snapshot["policy"], expected_vector["policy"])
        self.assertEqual(snapshot["policy_digest"], expected_vector["digest"])

    def test_binding_policy_digest_matches_shared_canonical_vectors(self):
        vectors = json.loads(
            (ROOT / "fixtures" / "policy" / "canonical-vectors.json").read_text()
        )
        vector_by_id = {vector["id"]: vector for vector in vectors["vectors"]}

        for vector in vectors["vectors"]:
            with self.subTest(vector=vector["id"]):
                self.assertEqual(
                    confidential_inference_module.policy_canonical_json(vector["policy"]),
                    vector["canonical_json"],
                )
                self.assertEqual(
                    confidential_inference_module.policy_digest(vector["policy"]),
                    vector["digest"],
                )

        for case in vectors["equivalence_cases"]:
            with self.subTest(case=case["id"]):
                expected = vector_by_id[case["equivalent_to"]]

                self.assertEqual(
                    confidential_inference_module.policy_canonical_json(case["policy"]),
                    expected["canonical_json"],
                )
                self.assertEqual(
                    confidential_inference_module.policy_digest(case["policy"]),
                    expected["digest"],
                )

    def test_binding_canonical_json_orders_keys_by_utf16_code_units(self):
        self.assertEqual(
            confidential_inference_module.canonical_json({"\ue000": 2, "\U00010000": 1}),
            '{"𐀀":1,"":2}',
        )

    def test_binding_policy_digest_rejects_unknown_and_unsafe_policy_values(self):
        vectors = json.loads(
            (ROOT / "fixtures" / "policy" / "canonical-vectors.json").read_text()
        )
        policy = dict(vectors["vectors"][0]["policy"])
        policy["unexpected"] = True

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module.policy_digest(policy)

        self.assertEqual(raised.exception.error["code"], "malformed_policy_digest")
        self.assertIn("unsupported field", raised.exception.error["message"])

        unsafe_policy = dict(vectors["vectors"][0]["policy"])
        unsafe_policy["verdict_ttl_millis"] = confidential_inference_module.MAX_SAFE_JSON_INT + 1

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module.policy_digest(unsafe_policy)

        self.assertEqual(raised.exception.error["code"], "malformed_canonical_json")
        self.assertIn("safe integer", raised.exception.error["message"])

    def test_binding_rejects_unknown_major_active_policy_schema(self):
        snapshot = {
            "schema": "confidential-inference.active-policy.v2",
            "policy": {"schema": "confidential-inference.policy.v1"},
            "policy_digest": "sha256:test",
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_active_policy_snapshot(snapshot)

        self.assertEqual(
            raised.exception.error["code"],
            "incompatible_active_policy_schema",
        )
        self.assertIn("active-policy schema", raised.exception.error["message"])

    def test_binding_rejects_unknown_major_embedded_policy_snapshot_schema(self):
        snapshot = {
            "schema": "confidential-inference.active-policy.v1",
            "policy": {"schema": "confidential-inference.policy.v2"},
            "policy_digest": "sha256:test",
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_active_policy_snapshot(snapshot)

        self.assertEqual(
            raised.exception.error["code"],
            "incompatible_active_policy_schema",
        )
        self.assertIn("policy schema", raised.exception.error["message"])

    def test_binding_rejects_malformed_active_policy_digest_fields(self):
        for field in (
            "policy_digest",
            "provider_registry_digest",
            "reference_values_digest",
        ):
            with self.subTest(field=field):
                snapshot = {
                    "schema": "confidential-inference.active-policy.v1",
                    "policy": {
                        "schema": "confidential-inference.policy.v1",
                        "provider_registry_digest": VALID_DIGEST,
                        "reference_values_digest": VALID_DIGEST,
                    },
                    "policy_digest": VALID_DIGEST,
                }
                if field == "policy_digest":
                    snapshot[field] = "sha256:nothex"
                else:
                    snapshot["policy"][field] = "sha256:" + ("A" * 64)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_policy_snapshot(snapshot)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_active_policy_digest",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_mismatched_active_policy_digest(self):
        vectors = json.loads(
            (ROOT / "fixtures" / "policy" / "canonical-vectors.json").read_text()
        )
        vector = next(
            vector
            for vector in vectors["vectors"]
            if vector["id"] == "require-attested-e2ee-demo"
        )
        snapshot = {
            "schema": "confidential-inference.active-policy.v1",
            "policy": vector["policy"],
            "policy_digest": VALID_DIGEST,
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_active_policy_snapshot(snapshot)

        self.assertEqual(
            raised.exception.error["code"],
            "malformed_active_policy_digest",
        )
        self.assertIn("policy_digest", raised.exception.error["message"])

    def test_binding_rejects_unsafe_active_policy_millisecond_fields(self):
        unsafe_millis = confidential_inference_module.MAX_SAFE_JSON_INT + 1
        cases = {
            "verdict_ttl_millis": {
                "verdict_ttl_millis": unsafe_millis,
            },
            "freshness.millis": {
                "freshness": {
                    "mode": "allow_cached_binding_millis",
                    "millis": unsafe_millis,
                },
            },
            "stale_verdicts.millis": {
                "stale_verdicts": {
                    "mode": "allow_for_millis",
                    "millis": unsafe_millis,
                },
            },
        }
        for field, overrides in cases.items():
            with self.subTest(field=field):
                snapshot = valid_active_policy_snapshot_stub(**overrides)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_policy_snapshot(snapshot)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_active_policy_schema",
                )
                self.assertIn(field, raised.exception.error["message"])
                self.assertIn(
                    "safe integer limit",
                    raised.exception.error["message"],
                )

    def test_binding_rejects_missing_active_policy_tagged_millis_payload(self):
        for field, overrides in {
            "freshness.millis": {
                "freshness": {"mode": "allow_cached_binding_millis"},
            },
            "stale_verdicts.millis": {
                "stale_verdicts": {"mode": "allow_for_millis"},
            },
        }.items():
            with self.subTest(field=field):
                snapshot = valid_active_policy_snapshot_stub(**overrides)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_policy_snapshot(snapshot)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_active_policy_schema",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_malformed_active_policy_enum_fields(self):
        cases = {
            "enforcement": {"enforcement": "audit_only"},
            "request_confidentiality_requirement": {
                "request_confidentiality_requirement": "channel_bound",
            },
            "response_integrity_requirement": {
                "response_integrity_requirement": "unknown",
            },
            "model_binding_requirement": {
                "model_binding_requirement": "provider_catalog_only",
            },
            "hardware.cpu.mode": {
                "hardware": {
                    "cpu": {"mode": "tdx"},
                    "gpu": {"mode": "not_required"},
                },
            },
            "hardware.gpu.allowed": {
                "hardware": {
                    "cpu": {"mode": "any_cpu_tee"},
                    "gpu": {"mode": "one_of", "allowed": ["amd_cc"]},
                },
            },
            "freshness.mode": {"freshness": {"mode": "allow_cached"}},
            "stale_verdicts.mode": {"stale_verdicts": {"mode": "allow_stale"}},
        }
        for field, overrides in cases.items():
            with self.subTest(field=field):
                snapshot = valid_active_policy_snapshot_stub(**overrides)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_policy_snapshot(snapshot)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_active_policy_schema",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_noncanonical_active_policy_tagged_payloads(self):
        cases = {
            "hardware.cpu.allowed": {
                "hardware": {
                    "cpu": {
                        "mode": "one_of",
                        "allowed": ["tdx", "sev_snp", "tdx"],
                    },
                    "gpu": {"mode": "not_required"},
                },
            },
            "hardware.gpu.allowed": {
                "hardware": {
                    "cpu": {"mode": "any_cpu_tee"},
                    "gpu": {"mode": "not_required", "allowed": ["nvidia_cc"]},
                },
            },
            "freshness.millis": {
                "freshness": {"mode": "per_session", "millis": 1000},
            },
            "stale_verdicts.millis": {
                "stale_verdicts": {"mode": "fail_closed", "millis": 1000},
            },
            "provenance.workload_image": {
                "provenance": {
                    "workload_image": "false",
                    "model_artifacts": False,
                    "reproducible_build": False,
                    "source_attestation": False,
                    "dependency_sbom": False,
                },
            },
        }
        for field, overrides in cases.items():
            with self.subTest(field=field):
                snapshot = valid_active_policy_snapshot_stub(**overrides)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_policy_snapshot(snapshot)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_active_policy_schema",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_unknown_required_active_policy_snapshot_field(self):
        snapshot = {
            "schema": "confidential-inference.active-policy.v1.1",
            "policy": {
                "schema": "confidential-inference.policy.v1",
                "provider_registry_digest": VALID_DIGEST,
                "reference_values_digest": VALID_DIGEST,
            },
            "policy_digest": VALID_DIGEST,
            "required": ["future_required_field"],
            "future_required_field": True,
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_active_policy_snapshot(snapshot)

        self.assertEqual(
            raised.exception.error["code"],
            "incompatible_active_policy_schema",
        )
        self.assertIn("future_required_field", raised.exception.error["message"])

    def test_binding_rejects_missing_declared_required_active_policy_payload_field(self):
        snapshot = {
            "schema": "confidential-inference.active-policy.v1",
            "policy": {
                "schema": "confidential-inference.policy.v1.1",
                "provider_registry_digest": VALID_DIGEST,
                "reference_values_digest": VALID_DIGEST,
                "required": ["enforcement"],
            },
            "policy_digest": VALID_DIGEST,
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_active_policy_snapshot(snapshot)

        self.assertEqual(
            raised.exception.error["code"],
            "malformed_active_policy_schema",
        )
        self.assertIn("enforcement", raised.exception.error["message"])

    def test_active_trust_artifacts_expose_signed_sources_and_digests(self):
        vectors = json.loads(
            (ROOT / "fixtures" / "policy" / "canonical-vectors.json").read_text()
        )
        expected_vector = next(
            vector
            for vector in vectors["vectors"]
            if vector["id"] == "require-attested-e2ee-demo"
        )

        with Client() as client:
            artifacts = client.active_trust_artifacts()
        expected_registry = json.loads(
            (ROOT / "fixtures" / "registry" / "demo-registry.json").read_text()
        )
        expected_reference_values = json.loads(
            (ROOT / "fixtures" / "reference-values" / "demo-envelope.json").read_text()
        )

        self.assertEqual(artifacts["registry"]["version"], "2026-07-05-demo")
        self.assertEqual(artifacts["registry"]["generated_at"], "2026-07-05T00:00:00Z")
        self.assertEqual(
            artifacts["registry"]["source_sync_run"]["completed_at"],
            "2026-07-05T00:00:00Z",
        )
        self.assertEqual(artifacts["registry_source"], "bundled")
        self.assertEqual(
            artifacts["registry_digest"],
            expected_vector["policy"]["provider_registry_digest"],
        )
        self.assertEqual(
            artifacts["registry_digest"],
            confidential_inference_module.canonical_sha256_digest(artifacts["registry"]),
        )
        self.assertEqual(artifacts["registry_signature"]["signer"], "confidential-inference")
        self.assertEqual(
            artifacts["registry_signature"],
            expected_registry["signature"],
        )
        self.assertEqual(
            artifacts["reference_values"]["version"],
            "2026-07-05-demo",
        )
        self.assertEqual(
            artifacts["reference_values"]["valid_until_epoch_ms"],
            4070908800000,
        )
        self.assertEqual(artifacts["reference_values_source"], "bundled")
        self.assertEqual(
            artifacts["reference_values_digest"],
            expected_vector["policy"]["reference_values_digest"],
        )
        self.assertEqual(
            artifacts["reference_values_digest"],
            confidential_inference_module.canonical_sha256_digest(artifacts["reference_values"]),
        )
        self.assertEqual(
            artifacts["reference_values_signature"]["signer"],
            "confidential-inference",
        )
        self.assertEqual(
            artifacts["reference_values_signature"],
            expected_reference_values["signature"],
        )

    def test_binding_verifies_known_active_trust_artifact_signatures(self):
        with Client() as client:
            artifacts = client.active_trust_artifacts()

        artifacts["registry"]["version"] = "tampered"
        artifacts["registry_digest"] = confidential_inference_module.canonical_sha256_digest(
            artifacts["registry"]
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_active_trust_artifacts(artifacts)

        self.assertEqual(
            raised.exception.error["code"],
            "malformed_trust_artifacts_signature",
        )
        self.assertIn(
            "registry_signature signature is invalid",
            raised.exception.error["message"],
        )

    def test_binding_rejects_unknown_major_active_registry_schema(self):
        artifacts = valid_trust_artifacts_stub(
            registry={"schema": "confidential-inference.provider-registry.v2"}
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_active_trust_artifacts(artifacts)

        self.assertEqual(
            raised.exception.error["code"],
            "incompatible_trust_artifacts_schema",
        )
        self.assertIn("provider-registry schema", raised.exception.error["message"])

    def test_binding_rejects_unknown_major_active_reference_values_schema(self):
        artifacts = valid_trust_artifacts_stub(
            reference_values={"schema": "confidential-inference.reference-values.v2"}
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_active_trust_artifacts(artifacts)

        self.assertEqual(
            raised.exception.error["code"],
            "incompatible_trust_artifacts_schema",
        )
        self.assertIn("reference-values schema", raised.exception.error["message"])

    def test_binding_rejects_malformed_active_trust_artifact_digest_fields(self):
        for field in ("registry_digest", "reference_values_digest"):
            with self.subTest(field=field):
                artifacts = valid_trust_artifacts_stub()
                artifacts[field] = "sha256:" + ("g" * 64)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_trust_artifacts(artifacts)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_trust_artifacts_digest",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_mismatched_active_trust_artifact_payload_digest(self):
        cases = {
            "registry_digest": valid_trust_artifacts_stub(
                registry=valid_registry_payload_stub(),
                reference_values=valid_reference_values_payload_stub(),
                registry_digest=VALID_DIGEST,
            ),
            "reference_values_digest": valid_trust_artifacts_stub(
                registry=valid_registry_payload_stub(),
                reference_values=valid_reference_values_payload_stub(),
                reference_values_digest=VALID_DIGEST,
            ),
        }
        for field, artifacts in cases.items():
            with self.subTest(field=field):
                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_trust_artifacts(artifacts)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_trust_artifacts_digest",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_malformed_active_registry_freshness_metadata(self):
        cases = {
            "generated_at": {
                "schema": "confidential-inference.provider-registry.v1",
                "generated_at": "2026-07-05T00:00:00+00:00",
            },
            "source_sync_run.completed_at": {
                "schema": "confidential-inference.provider-registry.v1",
                "source_sync_run": {
                    "completed_at": "2026-07-05T00:00:00.0000001Z",
                },
            },
            "source_sync_run": {
                "schema": "confidential-inference.provider-registry.v1",
                "source_sync_run": "2026-07-05T00:00:00Z",
            },
        }
        for field, registry in cases.items():
            with self.subTest(field=field):
                artifacts = valid_trust_artifacts_stub(registry=registry)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_trust_artifacts(artifacts)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_trust_artifacts_schema",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_malformed_active_reference_values_freshness_metadata(self):
        unsafe_int = confidential_inference_module.MAX_SAFE_JSON_INT + 1
        cases = {
            "valid_from": {
                "schema": "confidential-inference.reference-values.v1",
                "valid_from": "2026-07-05T00:00:00+00:00",
            },
            "valid_until": {
                "schema": "confidential-inference.reference-values.v1",
                "valid_until": "2099-01-01 00:00:00Z",
            },
            "valid_until_epoch_ms": {
                "schema": "confidential-inference.reference-values.v1",
                "valid_until": "2099-01-01T00:00:00Z",
                "valid_until_epoch_ms": 1,
            },
            "revocation_epoch": {
                "schema": "confidential-inference.reference-values.v1",
                "revocation_epoch": unsafe_int,
            },
        }
        for field, reference_values in cases.items():
            with self.subTest(field=field):
                artifacts = valid_trust_artifacts_stub(reference_values=reference_values)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_trust_artifacts(artifacts)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_trust_artifacts_schema",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_malformed_active_reference_values_route_metadata(self):
        cases = {
            "providers": valid_reference_values_payload_stub(providers=[]),
            "accepted_measurements": valid_reference_values_payload_stub(
                providers={
                    "demo": {
                        "accepted_measurements": "sha256:measurement",
                        "routes": {},
                    }
                }
            ),
            "routes": valid_reference_values_payload_stub(
                providers={
                    "demo": {
                        "accepted_measurements": ["sha256:measurement"],
                        "routes": [],
                    }
                }
            ),
            "channel_binding_kind": valid_reference_values_payload_with_route(
                channel_binding_kind="none"
            ),
            "accepted_cpu_tees": valid_reference_values_payload_with_route(
                accepted_cpu_tees=["sgx"]
            ),
            "accepted_gpu_tees": valid_reference_values_payload_with_route(
                accepted_gpu_tees=["amd_cc"]
            ),
            "e2ee_public_key_digest": valid_reference_values_payload_with_route(
                e2ee_public_key_digest="demo-e2ee-key"
            ),
            "model_artifacts": valid_reference_values_payload_with_route(
                model_artifacts=[
                    {
                        "kind": "weights",
                        "name": "gpt-oss-120b",
                        "digest": "demo-weights",
                    }
                ]
            ),
            "valid_until_epoch_ms": valid_reference_values_payload_with_route(
                valid_until_epoch_ms=1
            ),
        }
        for field, reference_values in cases.items():
            with self.subTest(field=field):
                artifacts = valid_trust_artifacts_stub(reference_values=reference_values)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_trust_artifacts(artifacts)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_trust_artifacts_schema",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_malformed_active_registry_route_metadata(self):
        def registry_with_route(**route_overrides):
            registry = valid_registry_payload_stub()
            route = registry["models"]["gpt-oss-120b"]["routes"][0]
            route.update(route_overrides)
            return registry

        cases = {
            "route_status": registry_with_route(route_status="candidate"),
            "alias_confidence": registry_with_route(alias_confidence="algorithmic"),
            "channel_binding_kind": registry_with_route(channel_binding_kind="none"),
            "response_integrity_requirement": registry_with_route(
                response_integrity_requirement="unknown"
            ),
            "streaming": registry_with_route(streaming="plaintext_fallback"),
            "accepted_gpu_tees": registry_with_route(accepted_gpu_tees=["amd_cc"]),
        }
        for field, registry in cases.items():
            with self.subTest(field=field):
                artifacts = valid_trust_artifacts_stub(registry=registry)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_trust_artifacts(artifacts)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_trust_artifacts_schema",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_malformed_active_registry_model_metadata(self):
        registry = valid_registry_payload_stub(
            models={
                "gpt-oss-120b": {
                    "canonical_model": "gpt-oss-120b-preview",
                    "aliases": ["gpt-oss-120b"],
                    "routes": [],
                }
            }
        )
        artifacts = valid_trust_artifacts_stub(registry=registry)

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_active_trust_artifacts(artifacts)

        self.assertEqual(
            raised.exception.error["code"],
            "malformed_trust_artifacts_schema",
        )
        self.assertIn("canonical_model", raised.exception.error["message"])

    def test_binding_rejects_unknown_required_active_registry_field(self):
        artifacts = valid_trust_artifacts_stub(
            registry={
                "schema": "confidential-inference.provider-registry.v1.1",
                "required": ["future_required_field"],
                "future_required_field": True,
            }
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_active_trust_artifacts(artifacts)

        self.assertEqual(
            raised.exception.error["code"],
            "incompatible_trust_artifacts_schema",
        )
        self.assertIn("future_required_field", raised.exception.error["message"])

    def test_binding_rejects_missing_declared_required_reference_values_field(self):
        artifacts = valid_trust_artifacts_stub(
            reference_values={
                "schema": "confidential-inference.reference-values.v1.1",
                "required": ["version"],
            }
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_active_trust_artifacts(artifacts)

        self.assertEqual(
            raised.exception.error["code"],
            "malformed_trust_artifacts_schema",
        )
        self.assertIn("version", raised.exception.error["message"])

    def test_binding_rejects_missing_active_trust_artifact_signature_metadata(self):
        for field in ("registry_signature", "reference_values_signature"):
            with self.subTest(field=field):
                artifacts = valid_trust_artifacts_stub()
                artifacts.pop(field)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_trust_artifacts(artifacts)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_trust_artifacts_signature",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_incomplete_active_trust_artifact_signature_metadata(self):
        for field in ("registry_signature", "reference_values_signature"):
            with self.subTest(field=field):
                artifacts = valid_trust_artifacts_stub()
                artifacts[field]["key_id"] = ""

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_trust_artifacts(artifacts)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_trust_artifacts_signature",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_incomplete_active_trust_artifact_signature_value(self):
        for field in ("registry_signature", "reference_values_signature"):
            with self.subTest(field=field):
                artifacts = valid_trust_artifacts_stub()
                artifacts[field]["value"] = "base64url:"

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_trust_artifacts(artifacts)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_trust_artifacts_signature",
                )
                self.assertIn("value", raised.exception.error["message"])

    def test_binding_rejects_malformed_active_trust_artifact_signature_value(self):
        cases = {
            "bad_alphabet": "base64url:abc+123",
            "wrong_length": "base64url:AA",
            "padded": VALID_REGISTRY_SIGNATURE_VALUE + "=",
        }
        for name, value in cases.items():
            for field in ("registry_signature", "reference_values_signature"):
                with self.subTest(case=name, field=field):
                    artifacts = valid_trust_artifacts_stub()
                    artifacts[field]["value"] = value

                    with self.assertRaises(ConfidentialInferenceError) as raised:
                        confidential_inference_module._validate_active_trust_artifacts(artifacts)

                    self.assertEqual(
                        raised.exception.error["code"],
                        "malformed_trust_artifacts_signature",
                    )
                    self.assertIn("signature value", raised.exception.error["message"])

    def test_binding_rejects_unsupported_active_trust_artifact_signature_algorithm(self):
        for field in ("registry_signature", "reference_values_signature"):
            with self.subTest(field=field):
                artifacts = valid_trust_artifacts_stub()
                artifacts[field]["alg"] = "rsa"

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_active_trust_artifacts(artifacts)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_trust_artifacts_signature",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_config_accepts_api_key_env_reference(self):
        env_name = "CONFIDENTIAL_INFERENCE_PYTHON_BINDING_TEST_API_KEY"
        os.environ[env_name] = "sk-python-env-secret"
        try:
            with Client(config={"api_keys": {"demo": {"env": env_name}}}) as client:
                artifacts = client.active_trust_artifacts()
        finally:
            os.environ.pop(env_name, None)

        self.assertEqual(artifacts["registry"]["version"], "2026-07-05-demo")

    def test_config_rejects_inline_api_key_without_echoing_secret(self):
        secret = "sk-python-inline-secret"
        with self.assertRaises(ConfidentialInferenceError) as raised:
            Client(config={"api_keys": {"demo": {"inline": secret}}})

        self.assertEqual(
            raised.exception.error["code"], "inline_credentials_not_allowed"
        )
        self.assertNotIn(secret, str(raised.exception))

    def test_config_accepts_inline_api_key_with_explicit_opt_in(self):
        secret = "sk-python-inline-secret-allowed"
        with Client(
            config={
                "allow_inline_api_keys": True,
                "api_keys": {"demo": {"inline": secret}},
            }
        ) as client:
            artifacts = client.active_trust_artifacts()

        self.assertEqual(artifacts["registry"]["version"], "2026-07-05-demo")

    def test_config_accepts_named_provider_order_and_routes_chat(self):
        with Client(
            config={
                "routing": {
                    "provider_order": {
                        "gpt-oss-120b": ["demo"],
                    }
                }
            }
        ) as client:
            result = client.chat(
                {
                    "model": "gpt-oss-120b",
                    "messages": [
                        {"role": "user", "content": "named provider routing"}
                    ],
                }
            )

        self.assertEqual(result["provider"], "demo")

    def test_config_rejects_duplicate_named_provider_order(self):
        with self.assertRaises(ConfidentialInferenceError) as raised:
            Client(
                config={
                    "routing": {
                        "provider_order": {
                            "gpt-oss-120b": ["demo", "demo"],
                        }
                    }
                }
            )

        self.assertEqual(
            raised.exception.error["code"], "invalid_provider_routing"
        )

    def test_config_rejects_ambiguous_api_key_source_without_echoing_secret(self):
        secret = "sk-python-inline-secret-ambiguous"
        with self.assertRaises(ConfidentialInferenceError) as raised:
            Client(
                config={
                    "allow_inline_api_keys": True,
                    "api_keys": {
                        "demo": {
                            "env": "CONFIDENTIAL_INFERENCE_PYTHON_BINDING_UNUSED_API_KEY",
                            "inline": secret,
                        }
                    },
                }
            )

        self.assertEqual(raised.exception.error["code"], "credential_source_ambiguous")
        self.assertNotIn(secret, str(raised.exception))

    def test_async_chat_uses_operation_handle(self):
        async def run():
            with Client() as client:
                return await client.chat_async(
                    {
                        "model": "gpt-oss-120b",
                        "messages": [
                            {"role": "user", "content": "python async binding path"}
                        ],
                    },
                    timeout_ms=2_000,
                )

        response = asyncio.run(run())

        self.assertEqual(response["verdict"]["status"], "verified")
        self.assertEqual(
            response["response"]["choices"][0]["message"]["content"],
            "demo confidential response for e2ee-gpt-oss-120b-p: python async binding path",
        )

    def test_async_response_uses_operation_handle(self):
        async def run():
            with Client() as client:
                return await client.create_response_async(
                    {
                        "model": "gpt-oss-120b",
                        "input": "python async response binding path",
                    },
                    timeout_ms=2_000,
                )

        response = asyncio.run(run())

        self.assertEqual(response["verdict"]["status"], "verified")
        self.assertEqual(response["response"]["object"], "response")
        self.assertEqual(
            response["response"]["output_text"],
            "demo confidential response for e2ee-gpt-oss-120b-p: python async response binding path",
        )

    def test_operation_poll_validates_state_json(self):
        with Client() as client:
            operation = client.start_verify("demo", "gpt-oss-120b")
            try:
                state = operation.poll()
                self.assertIs(confidential_inference_module._validate_operation_state(state), state)
                self.assertIn(state["status"], {"pending", "ready", "failed", "cancelled"})
            finally:
                operation.cancel()
                operation.close()

    def test_binding_rejects_malformed_operation_states(self):
        failed_state = {
            "status": "failed",
            "result_available": True,
            "error": {
                "status": "failed",
                "error": {
                    "type": "confidential_inference_async_error",
                    "message": "operation failed",
                },
            },
        }
        for state in (
            {"status": "pending"},
            {"status": "ready"},
            {"status": "cancelled"},
            failed_state,
        ):
            with self.subTest(status=state["status"]):
                self.assertIs(confidential_inference_module._validate_operation_state(state), state)

        cases = (
            ({"status": "complete"}, "status"),
            ({"status": "pending", "result_available": False}, "unsupported field"),
            (
                {"status": "failed", "result_available": False, "error": {}},
                "result_available=true",
            ),
            ({"status": "failed", "result_available": True}, "error"),
        )
        for state, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_operation_state(state)
                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_operation_state",
                )
                self.assertIn(message, raised.exception.error["message"])

    def test_binding_rejects_malformed_ffi_error_envelopes(self):
        empty_envelope = {"error": None}
        error_envelope = {
            "error": {
                "type": "confidential_inference_ffi_error",
                "code": "invalid_argument",
                "message": "request JSON is invalid",
            },
        }

        self.assertIs(
            confidential_inference_module._validate_ffi_error_envelope(empty_envelope),
            empty_envelope,
        )
        self.assertIs(
            confidential_inference_module._validate_ffi_error_envelope(error_envelope),
            error_envelope,
        )

        cases = (
            ({}, "missing error"),
            (
                {"error": {"type": "other", "code": "x", "message": "bad"}},
                "type",
            ),
            (
                {
                    "error": {
                        "type": "confidential_inference_ffi_error",
                        "code": "",
                        "message": "bad",
                    }
                },
                "code",
            ),
            (
                {
                    "error": {
                        "type": "confidential_inference_ffi_error",
                        "code": "invalid_argument",
                        "message": "bad",
                        "detail": "unexpected",
                    }
                },
                "unsupported field detail",
            ),
        )
        for envelope, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_ffi_error_envelope(envelope)
                self.assertEqual(raised.exception.error["code"], "malformed_ffi_error")
                self.assertIn(message, raised.exception.error["message"])

    def test_binding_rejects_null_ffi_string_pointer(self):
        native = confidential_inference_module._Native()
        with self.assertRaises(ConfidentialInferenceError) as raised:
            native.take_json_string(ctypes.c_void_p())

        self.assertEqual(raised.exception.status, confidential_inference_module.CONFIDENTIAL_INFERENCE_FFI_INTERNAL)
        self.assertEqual(raised.exception.error["code"], "missing_string")
        self.assertIn("null JSON string pointer", raised.exception.error["message"])

    @unittest.skipUnless(os.name == "posix", "readiness file descriptors are Unix-only")
    def test_async_wait_uses_operation_readiness_fd_without_polling(self):
        async def run():
            with Client() as client:
                operation = client.start_verify("demo", "gpt-oss-120b")
                operation.poll = lambda: self.fail("wait_async should use readiness fd")
                try:
                    return await operation.wait_async(timeout_ms=2_000)
                finally:
                    operation.close()

        verdict = asyncio.run(run())

        self.assertEqual(verdict["status"], "verified")

    @unittest.skipUnless(os.name == "posix", "readiness file descriptors are Unix-only")
    def test_operation_readiness_fd_signals_and_is_one_shot(self):
        with Client() as client:
            operation = client.start_verify("demo", "gpt-oss-120b")
            fd = operation.readiness_fd()
            try:
                with self.assertRaises(ConfidentialInferenceError) as raised:
                    operation.readiness_fd()
                self.assertEqual(raised.exception.status, 3)

                verdict = operation.wait(timeout_ms=2_000)
                readable, _, _ = select.select([fd], [], [], 2.0)
                self.assertIn(fd, readable)
                self.assertEqual(os.read(fd, 1), b"\x01")
            finally:
                os.close(fd)
                operation.close()

        self.assertEqual(verdict["status"], "verified")

    def test_operation_callback_runs_at_terminal_state(self):
        callback_seen = threading.Event()

        with Client() as client:
            operation = client.start_verify("demo", "gpt-oss-120b")
            operation.set_callback(callback_seen.set)
            try:
                verdict = operation.wait(timeout_ms=2_000)
            finally:
                operation.close()

        self.assertEqual(verdict["status"], "verified")
        self.assertTrue(callback_seen.wait(2.0))

    def test_async_wait_cancellation_cancels_operation_handle(self):
        async def run():
            with Client() as client:
                operation = client.start_verify("demo", "gpt-oss-120b")
                operation.readiness_fd = lambda: (_ for _ in ()).throw(
                    ConfidentialInferenceError(
                        5,
                        {
                            "code": "readiness_fd_unsupported",
                            "message": "forced polling fallback",
                        },
                    )
                )
                try:
                    task = asyncio.create_task(operation.wait_async(poll_interval=60.0))
                    await asyncio.sleep(0)
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    self.assertTrue(operation.cancel_requested)
                finally:
                    operation.close()

        asyncio.run(run())

    def test_async_stream_iterator_preserves_fail_closed_event_and_redacts_prompt(self):
        secret = "sk-python-stream-secret"

        async def run():
            with Client() as client:
                return [
                    event
                    async for event in client.stream_async(
                        {
                            "model": "gpt-oss-120b",
                            "messages": [{"role": "user", "content": secret}],
                        },
                        timeout_ms=2_000,
                    )
                ]

        events = asyncio.run(run())

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "error")
        self.assertEqual(events[0]["status"], "failed")
        self.assertIn("streaming is not supported", events[0]["error"]["message"])
        self.assertNotIn(secret, json.dumps(events))

    @unittest.skipUnless(os.name == "posix", "readiness file descriptors are Unix-only")
    def test_stream_callback_and_readiness_fd_signal_fail_closed_event(self):
        callback_seen = threading.Event()

        with Client() as client:
            stream = client.start_stream(
                {
                    "model": "gpt-oss-120b",
                    "messages": [{"role": "user", "content": "stream readiness"}],
                }
            )
            stream.set_callback(callback_seen.set)
            fd = stream.readiness_fd()
            try:
                events = list(stream.events(timeout_ms=2_000))
                readable, _, _ = select.select([fd], [], [], 2.0)
                self.assertIn(fd, readable)
                self.assertEqual(os.read(fd, 1), b"\x01")
            finally:
                os.close(fd)
                stream.close()

        self.assertEqual(events[0]["type"], "error")
        self.assertEqual(events[0]["status"], "failed")
        self.assertTrue(callback_seen.wait(2.0))

    def test_binding_rejects_confidential_response_mirror_conflict(self):
        payload = {
            "provider": "demo",
            "response": {},
            "response_channel_bound": False,
            "response_integrity_result": "channel_bound",
            "verdict": valid_verdict_stub(),
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_confidential_response(payload)

        self.assertEqual(
            raised.exception.error["code"],
            "malformed_confidential_response",
        )
        self.assertIn("response_channel_bound", raised.exception.error["message"])

    def test_binding_rejects_stream_verdict_mirror_conflict(self):
        event = {
            "type": "verdict",
            "response_channel_bound": True,
            "response_integrity_result": "not_bound",
            "verdict": valid_verdict_stub(),
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_stream_event(event)

        self.assertEqual(raised.exception.error["code"], "malformed_stream_verdict")
        self.assertIn("response_integrity_result", raised.exception.error["message"])

    def test_binding_rejects_receipt_bound_opening_stream_verdict(self):
        verdict = valid_verdict_stub(
            status="partial",
            response_channel_bound=False,
            response_confidentiality_result="unknown",
            response_integrity_result="receipt_bound",
        )
        verdict["checks"]["response_receipt"] = "verified"
        event = {
            "type": "verdict",
            "response_channel_bound": False,
            "response_integrity_result": "receipt_bound",
            "verdict": verdict,
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_stream_event(event)

        self.assertEqual(raised.exception.error["code"], "malformed_stream_verdict")
        self.assertIn("opening verdict", raised.exception.error["message"])

    def test_binding_accepts_verified_terminal_stream_receipt_event(self):
        event = {
            "type": "response_receipt",
            "response_integrity_result": "receipt_bound",
            "receipt_verified": True,
            "receipt": {"signature": "base64url:test"},
        }

        self.assertIs(confidential_inference_module._validate_stream_event(event), event)

    def test_binding_accepts_known_stream_control_response_and_error_events(self):
        events = (
            {"type": "response", "response": {"object": "chat.completion"}},
            {"type": "done"},
            {"type": "cancelled"},
            {"type": "closed"},
            {
                "type": "error",
                "status": "failed",
                "error": {
                    "type": "confidential_inference_stream_error",
                    "message": "stream failed",
                },
            },
        )
        for event in events:
            with self.subTest(event_type=event["type"]):
                self.assertIs(confidential_inference_module._validate_stream_event(event), event)

    def test_binding_rejects_malformed_stream_event_envelopes(self):
        cases = (
            ("closed", "object"),
            ({"type": "delta", "delta": {}}, "type"),
            ({"type": "closed", "extra": True}, "unsupported field"),
            ({"type": "response"}, "response object"),
            ({"type": "error", "status": "ok", "error": {}}, "status"),
            (
                {
                    "type": "error",
                    "status": "failed",
                    "error": {"type": "x"},
                },
                "message",
            ),
        )
        for event, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_stream_event(event)
                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_stream_event",
                )
                self.assertIn(message, raised.exception.error["message"])

    def test_binding_rejects_terminal_stream_receipt_without_receipt_bound_result(self):
        event = {
            "type": "response_receipt",
            "response_integrity_result": "unknown",
            "receipt_verified": True,
            "receipt": {"signature": "base64url:test"},
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_stream_event(event)

        self.assertEqual(raised.exception.error["code"], "malformed_stream_receipt")
        self.assertIn("receipt-bound", raised.exception.error["message"])

    def test_binding_rejects_unverified_terminal_stream_receipt(self):
        event = {
            "type": "response_receipt",
            "response_integrity_result": "receipt_bound",
            "receipt_verified": False,
            "receipt": {"signature": "base64url:test"},
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_stream_event(event)

        self.assertEqual(raised.exception.error["code"], "malformed_stream_receipt")
        self.assertIn("receipt_verified=true", raised.exception.error["message"])

    def test_binding_rejects_terminal_stream_receipt_without_metadata(self):
        event = {
            "type": "response_receipt",
            "response_integrity_result": "receipt_bound",
            "receipt_verified": True,
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_stream_event(event)

        self.assertEqual(raised.exception.error["code"], "malformed_stream_receipt")
        self.assertIn("receipt metadata", raised.exception.error["message"])

    def test_binding_rejects_unknown_major_verdict_schema(self):
        verdict = valid_verdict_stub(schema="confidential-inference.verdict.v2")

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "incompatible_verdict_schema")
        self.assertIn("major version 2", raised.exception.error["message"])

    def test_binding_accepts_same_major_minor_verdict_schema(self):
        verdict = valid_verdict_stub(
            schema="confidential-inference.verdict.v1.1",
            policy_schema="confidential-inference.policy.v1.1",
            reference_values_schema="confidential-inference.reference-values.v1.1",
            provider_registry_schema="confidential-inference.provider-registry.v1.1",
        )

        self.assertIs(confidential_inference_module._validate_verdict(verdict), verdict)

    def test_binding_accepts_same_major_optional_unknown_verdict_field(self):
        verdict = valid_verdict_stub(schema="confidential-inference.verdict.v1.1")
        verdict["future_optional_field"] = {"ignored": True}

        self.assertIs(confidential_inference_module._validate_verdict(verdict), verdict)

    def test_binding_validates_structured_outcomes_and_route_attribution(self):
        verdict = valid_verdict_stub(provider="demo")
        verdict["check_outcomes"] = {
            name: {
                "state": state,
                "required": state != "not_applicable",
                "detail": "binding test detail",
                "evidence_refs": [],
            }
            for name, state in verdict["checks"].items()
        }
        verdict["route_attribution"] = {
            "parties": [
                {
                    "role": "inference_provider",
                    "party_id": "demo",
                    "source": "signed_registry",
                    "detail": "signed registry provider",
                    "evidence_refs": ["provider_registry_digest"],
                },
                {
                    "role": "registry_authority",
                    "party_id": "confidential-inference",
                    "source": "signed_registry",
                    "detail": "registry signer",
                    "evidence_refs": ["provider_registry_digest"],
                },
                {
                    "role": "reference_values_authority",
                    "party_id": "confidential-inference",
                    "source": "signed_reference_values",
                    "detail": "reference issuer",
                    "evidence_refs": ["reference_values_digest"],
                },
                {
                    "role": "workload_operator",
                    "source": "unknown",
                    "detail": "not directly asserted",
                    "evidence_refs": [],
                },
                {
                    "role": "tee_platform",
                    "party_id": "tdx",
                    "source": "attested_evidence",
                    "detail": "parsed evidence platform",
                    "evidence_refs": ["raw_evidence_digest"],
                },
                {
                    "role": "cloud_host",
                    "source": "unknown",
                    "detail": "not directly asserted",
                    "evidence_refs": [],
                },
            ]
        }

        self.assertIs(confidential_inference_module._validate_verdict(verdict), verdict)

        mismatched = json.loads(json.dumps(verdict))
        mismatched["check_outcomes"]["model_binding"]["state"] = "failed"
        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(mismatched)
        self.assertEqual(raised.exception.error["code"], "malformed_verdict_checks")

        inferred = json.loads(json.dumps(verdict))
        inferred["route_attribution"]["parties"][0]["party_id"] = "other"
        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(inferred)
        self.assertEqual(
            raised.exception.error["code"], "malformed_verdict_attribution"
        )

    def test_binding_rejects_unknown_required_verdict_field(self):
        verdict = valid_verdict_stub(schema="confidential-inference.verdict.v1.1")
        verdict["required"] = ["future_required_field"]
        verdict["future_required_field"] = True

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "incompatible_verdict_schema")
        self.assertIn("future_required_field", raised.exception.error["message"])

    def test_binding_rejects_missing_declared_required_verdict_field(self):
        verdict = valid_verdict_stub(schema="confidential-inference.verdict.v1.1")
        verdict["required"] = ["policy_digest"]
        del verdict["policy_digest"]

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_schema")
        self.assertIn("policy_digest", raised.exception.error["message"])

    def test_binding_rejects_malformed_verdict_digest_fields(self):
        for field in (
            "policy_digest",
            "provider_registry_digest",
            "reference_values_digest",
            "raw_evidence_digest",
            "evidence_digest",
        ):
            with self.subTest(field=field):
                verdict = valid_verdict_stub()
                verdict[field] = "sha256:" + ("g" * 64)

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_verdict(verdict)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_verdict_digest",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_missing_verdict_signature_metadata(self):
        for field in ("registry_signature", "reference_values_signature"):
            with self.subTest(field=field):
                verdict = valid_verdict_stub()
                del verdict[field]

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_verdict(verdict)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_verdict_signature",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_incomplete_verdict_signature_metadata(self):
        for field in ("registry_signature", "reference_values_signature"):
            with self.subTest(field=field):
                verdict = valid_verdict_stub()
                verdict[field]["key_id"] = ""

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_verdict(verdict)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_verdict_signature",
                )
                self.assertIn("metadata is incomplete", raised.exception.error["message"])

    def test_binding_rejects_unsupported_verdict_signature_algorithm(self):
        for field in ("registry_signature", "reference_values_signature"):
            with self.subTest(field=field):
                verdict = valid_verdict_stub()
                verdict[field]["alg"] = "rsa"

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_verdict(verdict)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_verdict_signature",
                )
                self.assertIn("unsupported signature algorithm", raised.exception.error["message"])

    def test_binding_rejects_expires_at_computed_mismatch(self):
        verdict = valid_verdict_stub(expires_at="2099-01-01T00:00:01Z")

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_validity")
        self.assertIn("computed_expires_at", raised.exception.error["message"])

    def test_binding_rejects_expires_at_epoch_mismatch(self):
        verdict = valid_verdict_stub(expires_at_epoch_ms=4070908800001)

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_validity")
        self.assertIn("expires_at_epoch_ms", raised.exception.error["message"])

    def test_binding_rejects_unsafe_expires_at_epoch(self):
        verdict = valid_verdict_stub(
            expires_at_epoch_ms=confidential_inference_module.MAX_SAFE_JSON_INT + 1
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_validity")
        self.assertIn("expires_at_epoch_ms", raised.exception.error["message"])
        self.assertIn("safe integer limit", raised.exception.error["message"])

    def test_binding_rejects_computed_expiry_after_validity_bound(self):
        verdict = valid_verdict_stub()
        verdict["validity"]["policy_ttl_until"] = "2098-12-31T23:59:59Z"

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_validity")
        self.assertIn("minimum validity bound", raised.exception.error["message"])

    def test_binding_rejects_unknown_major_embedded_policy_schema(self):
        payload = {
            "provider": "demo",
            "response": {},
            "response_channel_bound": True,
            "response_integrity_result": "channel_bound",
            "verdict": valid_verdict_stub(policy_schema="confidential-inference.policy.v2"),
        }

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_confidential_response(payload)

        self.assertEqual(raised.exception.error["code"], "incompatible_verdict_schema")
        self.assertIn("policy schema", raised.exception.error["message"])

    def test_binding_rejects_requirement_value_in_response_integrity_result(self):
        verdict = valid_verdict_stub(response_integrity_result="any_bound")

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_enum")
        self.assertIn("response_integrity_result", raised.exception.error["message"])

    def test_binding_rejects_requirement_value_in_confidentiality_result(self):
        verdict = valid_verdict_stub(
            request_confidentiality_result="bound_to_attested_workload"
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_enum")
        self.assertIn("request_confidentiality_result", raised.exception.error["message"])

    def test_binding_rejects_invalid_check_result_value(self):
        verdict = valid_verdict_stub(checks={"model_binding": "required"})

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_enum")
        self.assertIn("model_binding", raised.exception.error["message"])

    def test_binding_rejects_missing_status_control_booleans(self):
        for field in ("request_allowed", "would_block_under_enforce"):
            with self.subTest(field=field):
                verdict = valid_verdict_stub()
                del verdict[field]

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_verdict(verdict)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_verdict_enum",
                )
                self.assertIn(field, raised.exception.error["message"])

    def test_binding_rejects_model_binding_summary_check_conflict(self):
        verdict = valid_verdict_stub(checks={"model_binding": "failed"})

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("model_binding_result=verified", raised.exception.error["message"])

    def test_binding_rejects_request_channel_confidentiality_conflict(self):
        verdict = valid_verdict_stub(request_confidentiality_result="not_bound")

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("request_channel_bound", raised.exception.error["message"])

    def test_binding_rejects_response_channel_confidentiality_conflict(self):
        verdict = valid_verdict_stub(response_confidentiality_result="unknown")

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("response_channel_bound", raised.exception.error["message"])

    def test_binding_rejects_response_channel_integrity_conflict(self):
        verdict = valid_verdict_stub(response_integrity_result="receipt_bound")
        verdict["checks"]["response_receipt"] = "verified"

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("channel-bound response integrity", raised.exception.error["message"])

    def test_binding_rejects_bound_request_summary_without_verified_checks(self):
        for check_name in ("request_key_binding", "request_encryption"):
            with self.subTest(check_name=check_name):
                verdict = valid_verdict_stub()
                verdict["checks"][check_name] = "failed"

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_verdict(verdict)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_verdict_summary",
                )
                self.assertIn(check_name, raised.exception.error["message"])

    def test_binding_rejects_bound_response_summary_without_verified_checks(self):
        for check_name in (
            "response_key_binding",
            "response_encryption",
            "response_channel_binding",
        ):
            with self.subTest(check_name=check_name):
                verdict = valid_verdict_stub()
                verdict["checks"][check_name] = "failed"

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_verdict(verdict)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_verdict_summary",
                )
                self.assertIn(check_name, raised.exception.error["message"])

    def test_binding_rejects_receipt_integrity_without_verified_receipt_check(self):
        verdict = valid_verdict_stub(
            response_channel_bound=False,
            response_confidentiality_result="unknown",
            response_integrity_result="receipt_bound",
        )
        verdict["checks"]["response_receipt"] = "failed"

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("response_receipt", raised.exception.error["message"])

    def test_binding_rejects_verified_status_with_failed_unsummarized_check(self):
        verdict = valid_verdict_stub(
            enforcement="observe",
            would_block_under_enforce=True,
        )
        verdict["checks"]["image_provenance"] = "failed"

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("status=verified", raised.exception.error["message"])

    def test_binding_rejects_verified_status_with_errors(self):
        verdict = valid_verdict_stub(errors=[{"code": "bad", "message": "failed"}])

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("contains errors", raised.exception.error["message"])

    def test_binding_rejects_verified_status_that_would_block(self):
        verdict = valid_verdict_stub(
            enforcement="observe",
            would_block_under_enforce=True,
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("would_block_under_enforce", raised.exception.error["message"])

    def test_binding_rejects_would_block_without_failed_checks(self):
        verdict = valid_verdict_stub(
            status="partial",
            enforcement="observe",
            would_block_under_enforce=True,
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("no check is failed", raised.exception.error["message"])

    def test_binding_rejects_failed_checks_without_would_block_flag(self):
        verdict = valid_verdict_stub(status="failed")
        verdict["checks"]["image_provenance"] = "failed"

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("would_block_under_enforce=false", raised.exception.error["message"])

    def test_binding_rejects_enforce_would_block_but_request_allowed(self):
        verdict = valid_verdict_stub(
            status="failed",
            request_allowed=True,
            would_block_under_enforce=True,
        )
        verdict["checks"]["image_provenance"] = "failed"

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("request_allowed=true", raised.exception.error["message"])

    def test_binding_rejects_enforce_allowed_policy_but_request_denied(self):
        verdict = valid_verdict_stub(status="partial", request_allowed=False)

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("request_allowed=false", raised.exception.error["message"])

    def test_binding_rejects_non_enforcing_request_denial(self):
        for enforcement, status in (("observe", "partial"), ("disabled", "disabled")):
            with self.subTest(enforcement=enforcement):
                verdict = valid_verdict_stub(
                    enforcement=enforcement,
                    status=status,
                    request_allowed=False,
                )

                with self.assertRaises(ConfidentialInferenceError) as raised:
                    confidential_inference_module._validate_verdict(verdict)

                self.assertEqual(
                    raised.exception.error["code"],
                    "malformed_verdict_summary",
                )
                self.assertIn("non-enforcing", raised.exception.error["message"])

    def test_binding_rejects_disabled_enforcement_without_disabled_status(self):
        verdict = valid_verdict_stub(enforcement="disabled", status="partial")

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("status=disabled", raised.exception.error["message"])

    def test_binding_rejects_disabled_status_without_disabled_enforcement(self):
        verdict = valid_verdict_stub(enforcement="observe", status="disabled")

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("requires disabled enforcement", raised.exception.error["message"])

    def test_binding_rejects_verified_app_e2ee_with_wrong_channel_kind(self):
        verdict = valid_verdict_stub(channel_binding_kind="tee_terminated_tls")

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("trust_tier=app-e2ee", raised.exception.error["message"])

    def test_binding_rejects_verified_app_e2ee_without_bound_response(self):
        verdict = valid_verdict_stub(
            response_channel_bound=False,
            response_confidentiality_result="unknown",
            response_integrity_result="unknown",
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("trust_tier=app-e2ee", raised.exception.error["message"])

    def test_binding_rejects_verified_hw_tls_without_tls_check(self):
        verdict = valid_verdict_stub(
            trust_tier="hw-verified-tls",
            channel_binding_kind="tee_terminated_tls",
            request_confidentiality_result="channel_bound",
            response_confidentiality_result="channel_bound",
        )
        verdict["checks"]["tls_binding"] = "not_applicable"

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("tls_binding", raised.exception.error["message"])

    def test_binding_rejects_verified_tee_only_with_response_channel_binding(self):
        verdict = valid_verdict_stub(
            trust_tier="tee-only",
            channel_binding_kind="none",
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("trust_tier=tee-only", raised.exception.error["message"])

    def test_binding_rejects_verified_none_with_bound_summaries(self):
        verdict = valid_verdict_stub(
            trust_tier="none",
            channel_binding_kind="none",
        )

        with self.assertRaises(ConfidentialInferenceError) as raised:
            confidential_inference_module._validate_verdict(verdict)

        self.assertEqual(raised.exception.error["code"], "malformed_verdict_summary")
        self.assertIn("trust_tier=none", raised.exception.error["message"])

    def test_async_stream_cancellation_cancels_stream_handle(self):
        async def run():
            with Client() as client:
                stream = client.start_stream(
                    {
                        "model": "gpt-oss-120b",
                        "messages": [{"role": "user", "content": "cancel stream"}],
                    }
                )

                def pending_next(timeout_ms=0):
                    raise ConfidentialInferenceError(
                        4,
                        {
                            "code": "stream_pending",
                            "message": "stream event is not ready yet",
                        },
                    )

                stream.next = pending_next
                stream.readiness_fd = lambda: (_ for _ in ()).throw(
                    ConfidentialInferenceError(
                        5,
                        {
                            "code": "readiness_fd_unsupported",
                            "message": "forced polling fallback",
                        },
                    )
                )
                try:
                    task = asyncio.create_task(
                        stream.events_async(poll_interval=60.0).__anext__()
                    )
                    await asyncio.sleep(0)
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    self.assertTrue(stream.cancel_requested)
                finally:
                    stream.close()

        asyncio.run(run())

    def test_sync_error_does_not_echo_secret_bearing_request(self):
        secret = "sk-python-binding-secret"
        with Client() as client:
            with self.assertRaises(ConfidentialInferenceError) as raised:
                client._call_json(
                    client._native.lib.confidential_inference_chat_blocking,
                    (
                        b'{"model":"gpt-oss-120b","messages":[{"role":"user",'
                        + f'"content":"{secret}"'.encode("utf-8")
                    ),
                    timeout_ms=2_000,
                )

        self.assertNotIn(secret, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
