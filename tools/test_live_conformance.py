from __future__ import annotations

import copy
import contextlib
import io
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("live_conformance.py")
TOOLS_DIR = MODULE_PATH.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
SPEC = importlib.util.spec_from_file_location("live_conformance", MODULE_PATH)
assert SPEC is not None
live_conformance = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = live_conformance
SPEC.loader.exec_module(live_conformance)


class FakeHttp:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, headers, timeout_seconds):
        self.calls.append((url, headers, timeout_seconds))
        response = self.responses[url]
        return live_conformance.HttpResult(
            status=response.get("status", 200),
            headers=response.get("headers", {"content-type": "application/json"}),
            body=json.dumps(response["json"]).encode("utf-8"),
        )


def plan_provider(**overrides):
    provider = {
        "id": "local-live-test",
        "enabled": True,
        "model_list_url": "https://inference.tinfoil.sh/v1/models",
        "attestation_url": "https://inference.tinfoil.sh/.well-known/tinfoil-attestation",
        "expected_model_ids": ["model-a"],
        "expected_attestation": {
            "content_type_contains": "application/json",
            "json_fields": ["evidence"],
        },
    }
    provider.update(overrides)
    return {"schema": live_conformance.PLAN_SCHEMA, "providers": [provider]}


def tamper_base64url_value(value: str) -> str:
    prefix_len = len("base64url:")
    replacement = "A" if value[prefix_len] != "A" else "B"
    return value[:prefix_len] + replacement + value[prefix_len + 1 :]


class LiveConformanceTests(unittest.TestCase):
    def test_env_example_covers_every_credentialed_live_provider(self):
        plan = live_conformance.load_plan(
            Path("fixtures/providers/live-conformance-plan.json")
        )
        expected = {
            provider["auth_env"]
            for provider in plan["providers"]
            if provider.get("auth_env")
        }
        configured = {
            line.split("=", 1)[0].strip()
            for line in Path(".env.example").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#") and "=" in line
        }

        self.assertEqual(configured, expected)

    def test_load_env_file_loads_credentials_without_overwriting_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            env_path = Path(temp) / ".env"
            env_path.write_text(
                "# provider credentials\n"
                "CHUTES_API_KEY='chutes-test-key'\n"
                "export NEAR_API_KEY=\"near-test-key\"\n",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {"CHUTES_API_KEY": "process-key"},
                clear=False,
            ):
                os.environ.pop("NEAR_API_KEY", None)

                loaded = live_conformance.load_env_file(env_path)

                self.assertEqual(loaded, ["NEAR_API_KEY"])
                self.assertEqual(os.environ["CHUTES_API_KEY"], "process-key")
                self.assertEqual(os.environ["NEAR_API_KEY"], "near-test-key")

    def test_load_env_file_rejects_invalid_syntax_without_echoing_values(self):
        secret = "secret-that-must-not-leak"
        with tempfile.TemporaryDirectory() as temp:
            env_path = Path(temp) / ".env"
            env_path.write_text(f"INVALID-NAME={secret}\n", encoding="utf-8")

            with self.assertRaises(live_conformance.LiveConformanceError) as raised:
                live_conformance.load_env_file(env_path)

        self.assertNotIn(secret, str(raised.exception))

    def test_python_canonical_json_matches_rust_policy_vector(self):
        vector = json.loads(Path("fixtures/policy/canonical-vectors.json").read_text())[
            "vectors"
        ][0]

        self.assertEqual(
            live_conformance.canonical_json(vector["policy"]),
            vector["canonical_json"],
        )
        self.assertEqual(
            live_conformance.canonical_sha256_digest(vector["policy"]),
            vector["digest"],
        )

    def test_python_canonical_json_rejects_float_and_unsafe_integer_values(self):
        cases = [
            {"millis": live_conformance.MAX_SAFE_JSON_INT + 1},
            {"ratio": 1.0},
            {1: "non-string-key"},
        ]
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(live_conformance.LiveConformanceError):
                    live_conformance.canonical_sha256_digest(value)

    def test_default_plan_validates_and_skips_disabled_providers_without_network(self):
        plan = live_conformance.load_plan(Path("fixtures/providers/live-conformance-plan.json"))

        for provider in plan["providers"]:
            self.assertNotIn("expected_model_ids", provider)
            self.assertTrue(provider["expected_model_ids_from_alias_matrix"])
            self.assertIn("compatibility_provider", provider)

        report = live_conformance.run_conformance(plan)

        self.assertEqual(report["schema"], "confidential-inference.live-conformance-report.v1")
        self.assertRegex(
            report["completed_at"],
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
        )
        self.assertGreaterEqual(report["summary"]["providers"], 1)
        self.assertEqual(report["summary"]["failed"], 0)
        self.assertEqual(report["summary"]["drift"], 0)
        self.assertEqual(report["summary"]["passed"], 0)
        self.assertEqual(report["summary"]["live_checked"], 0)
        self.assertEqual(report["summary"]["providers"], report["summary"]["skipped"])
        self.assertEqual(report["credentialed_live_gate"]["status"], "open")
        self.assertTrue(report["credentialed_live_gate"]["required_for_production"])
        self.assertEqual(
            report["credentialed_live_gate"]["remaining_provider_ids"],
            sorted(provider["id"] for provider in plan["providers"]),
        )
        providers_by_id = {provider["provider"]: provider for provider in report["providers"]}
        for provider in providers_by_id.values():
            self.assertFalse(provider["live_checked"])
            self.assertEqual(provider["expected_model_ids_source"], "model_alias_matrix")
            self.assertGreaterEqual(len(provider["expected_model_ids"]), 1)
            profile = provider["compatibility_profile"]
            self.assertEqual(profile["streaming"], "unsupported")
            self.assertIn("streaming", profile["known_unsupported_modes"])
            self.assertIn("chat_completions", profile["supported_openai_endpoints"])
        self.assertEqual(
            providers_by_id["venice"]["expected_model_ids"],
            ["e2ee-gpt-oss-120b-p"],
        )
        self.assertEqual(
            providers_by_id["venice"]["compatibility_profile"]["provider"],
            "venice-fixture",
        )
        self.assertEqual(
            providers_by_id["venice"]["compatibility_profile"]["request_encryption"],
            "required",
        )
        self.assertEqual(
            providers_by_id["near"]["expected_model_ids"],
            ["openai/gpt-oss-120b"],
        )
        self.assertIn(
            "Qwen/Qwen3-32B-TEE",
            providers_by_id["chutes"]["expected_model_ids"],
        )
        self.assertEqual(
            providers_by_id["chutes"]["compatibility_profile"]["provider"],
            "chutes",
        )
        self.assertEqual(
            providers_by_id["near"]["compatibility_profile"]["provider"],
            "near",
        )
        alias_matrix = report["model_alias_matrix"]
        self.assertEqual(alias_matrix["path"], plan["model_alias_matrix_path"])
        self.assertEqual(
            alias_matrix["digest"],
            live_conformance.canonical_sha256_digest(
                json.loads(Path(plan["model_alias_matrix_path"]).read_text(encoding="utf-8"))
            ),
        )
        self.assertIn("venice", alias_matrix["providers"])
        alias_matrix_envelope = report["model_alias_matrix_envelope"]
        self.assertEqual(
            alias_matrix_envelope["path"],
            plan["model_alias_matrix_envelope_path"],
        )
        self.assertEqual(
            alias_matrix_envelope["payload_digest"],
            alias_matrix["digest"],
        )
        self.assertEqual(
            alias_matrix_envelope["signature"]["key_id"],
            "confidential-inference-alias-matrix-fixture-ed25519-2026",
        )
        compatibility_matrix = report["compatibility_matrix"]
        self.assertEqual(
            compatibility_matrix["path"],
            plan["compatibility_matrix_path"],
        )
        self.assertEqual(
            compatibility_matrix["digest"],
            live_conformance.canonical_sha256_digest(
                json.loads(Path(plan["compatibility_matrix_path"]).read_text(encoding="utf-8"))
            ),
        )
        self.assertIn("venice-fixture", compatibility_matrix["providers"])
        compatibility_matrix_envelope = report["compatibility_matrix_envelope"]
        self.assertEqual(
            compatibility_matrix_envelope["path"],
            plan["compatibility_matrix_envelope_path"],
        )
        self.assertEqual(
            compatibility_matrix_envelope["payload_digest"],
            compatibility_matrix["digest"],
        )
        self.assertEqual(
            compatibility_matrix_envelope["signature"]["key_id"],
            "confidential-inference-compatibility-fixture-ed25519-2026",
        )

    def test_default_plan_imports_expected_model_ids_from_alias_matrix(self):
        plan = live_conformance.load_plan(Path("fixtures/providers/live-conformance-plan.json"))
        provider = copy.deepcopy(next(item for item in plan["providers"] if item["id"] == "venice"))
        provider["enabled"] = True
        provider.pop("auth_env", None)
        scoped_plan = {
            "schema": live_conformance.PLAN_SCHEMA,
            "model_alias_matrix_path": plan["model_alias_matrix_path"],
            "model_alias_matrix_envelope_path": plan["model_alias_matrix_envelope_path"],
            "compatibility_matrix_path": plan["compatibility_matrix_path"],
            "compatibility_matrix_envelope_path": plan["compatibility_matrix_envelope_path"],
            "providers": [provider],
        }
        fake = FakeHttp(
            {
                provider["model_list_url"]: {
                    "json": {"data": [{"id": "e2ee-gpt-oss-120b-p"}]}
                }
            }
        )

        report = live_conformance.run_conformance(scoped_plan, fake, allow_network=True)

        self.assertEqual(report["summary"]["passed"], 1)
        self.assertEqual(report["summary"]["live_checked"], 1)
        self.assertEqual(report["credentialed_live_gate"]["status"], "passed")
        self.assertEqual(report["credentialed_live_gate"]["remaining_provider_ids"], [])
        self.assertEqual(
            report["providers"][0]["expected_model_ids"],
            ["e2ee-gpt-oss-120b-p"],
        )
        self.assertEqual(
            report["providers"][0]["expected_model_ids_source"],
            "model_alias_matrix",
        )

    def test_disabled_provider_can_be_enabled_by_explicit_override(self):
        fake = FakeHttp(
            {
                "https://inference.tinfoil.sh/v1/models": {"json": {"data": [{"id": "model-a"}]}},
                "https://inference.tinfoil.sh/.well-known/tinfoil-attestation": {"json": {"evidence": {"ok": True}}},
            }
        )
        plan = plan_provider(enabled=False)

        report = live_conformance.run_conformance(
            plan,
            fake,
            allow_network=True,
            enable_providers={"local-live-test"},
        )

        self.assertEqual(report["summary"]["passed"], 1)
        self.assertEqual(report["provider_enable_overrides"]["providers"], ["local-live-test"])
        self.assertEqual(report["credentialed_live_gate"]["status"], "passed")
        provider = report["providers"][0]
        self.assertFalse(provider["configured_enabled"])
        self.assertTrue(provider["enabled_by_override"])
        self.assertEqual(provider["status"], "passed")
        self.assertTrue(provider["live_checked"])
        self.assertEqual(len(fake.calls), 2)

    def test_enable_override_still_respects_network_disabled_default(self):
        fake = FakeHttp({})
        plan = plan_provider(enabled=False)

        report = live_conformance.run_conformance(
            plan,
            fake,
            allow_network=False,
            enable_providers={"local-live-test"},
        )

        provider = report["providers"][0]
        self.assertEqual(provider["status"], "skipped_network_disabled")
        self.assertTrue(provider["enabled_by_override"])
        self.assertFalse(provider["live_checked"])
        self.assertEqual(report["summary"]["live_checked"], 0)
        self.assertEqual(report["credentialed_live_gate"]["status"], "open")
        self.assertEqual(
            report["credentialed_live_gate"]["remaining_provider_ids"],
            ["local-live-test"],
        )
        self.assertEqual(fake.calls, [])

    def test_enable_all_providers_overrides_disabled_plan_entries(self):
        fake = FakeHttp(
            {
                "https://inference.tinfoil.sh/v1/models": {"json": {"data": [{"id": "model-a"}]}},
                "https://inference.tinfoil.sh/.well-known/tinfoil-attestation": {"json": {"evidence": {"ok": True}}},
            }
        )
        plan = plan_provider(enabled=False)

        report = live_conformance.run_conformance(
            plan,
            fake,
            allow_network=True,
            enable_all_providers=True,
        )

        self.assertEqual(report["summary"]["passed"], 1)
        self.assertTrue(report["provider_enable_overrides"]["all"])
        self.assertTrue(report["providers"][0]["enabled_by_override"])
        self.assertTrue(report["providers"][0]["live_checked"])

    def test_main_require_credentialed_live_gate_fails_network_disabled_dry_run(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "live-report.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = live_conformance.main(
                    [
                        "--output",
                        str(output),
                        "--require-credentialed-live-gate",
                    ]
                )

            self.assertEqual(code, 3)
            self.assertIn("credentialed live gate is open", stderr.getvalue())
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["credentialed_live_gate"]["status"], "open")
            self.assertEqual(report["summary"]["live_checked"], 0)

    def test_main_require_credentialed_live_gate_passes_when_all_providers_pass(self):
        fake = FakeHttp(
            {
                "https://inference.tinfoil.sh/v1/models": {"json": {"data": [{"id": "model-a"}]}},
                "https://inference.tinfoil.sh/.well-known/tinfoil-attestation": {"json": {"evidence": {"ok": True}}},
            }
        )
        plan = plan_provider(auth_env=None)

        with tempfile.TemporaryDirectory() as temp:
            plan_path = Path(temp) / "plan.json"
            output = Path(temp) / "live-report.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            original_http_client = live_conformance.HttpClient
            live_conformance.HttpClient = lambda: fake
            try:
                code = live_conformance.main(
                    [
                        "--plan",
                        str(plan_path),
                        "--allow-network",
                        "--output",
                        str(output),
                        "--require-credentialed-live-gate",
                    ]
                )
            finally:
                live_conformance.HttpClient = original_http_client

            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["credentialed_live_gate"]["status"], "passed")
            self.assertEqual(report["summary"]["live_checked"], 1)
            self.assertEqual(len(fake.calls), 2)

    def test_unknown_enable_provider_override_fails_before_network(self):
        fake = FakeHttp({})
        plan = plan_provider(enabled=False)

        with self.assertRaises(live_conformance.LiveConformanceError) as context:
            live_conformance.run_conformance(
                plan,
                fake,
                allow_network=True,
                enable_providers={"missing-provider"},
            )

        self.assertIn("missing-provider", str(context.exception))
        self.assertEqual(fake.calls, [])

    def test_live_provider_passes_when_models_and_attestation_shape_match(self):
        fake = FakeHttp(
            {
                "https://inference.tinfoil.sh/v1/models": {
                    "json": {"data": [{"id": "model-a"}, {"model_id": "model-b"}]}
                },
                "https://inference.tinfoil.sh/.well-known/tinfoil-attestation": {"json": {"evidence": {"ok": True}}},
            }
        )
        plan = plan_provider(expected_model_ids=["model-a", "model-b"])

        report = live_conformance.run_conformance(plan, fake, allow_network=True)

        self.assertEqual(report["summary"]["passed"], 1)
        self.assertEqual(report["summary"]["live_checked"], 1)
        self.assertEqual(report["credentialed_live_gate"]["status"], "passed")
        provider = report["providers"][0]
        self.assertEqual(provider["status"], "passed")
        self.assertTrue(provider["live_checked"])
        self.assertEqual(provider["new_unverified"], [])
        self.assertEqual(provider["removed"], [])
        self.assertEqual(provider["expected_model_ids_source"], "plan")
        self.assertTrue(provider["attestation_shape_ok"])
        self.assertEqual(
            provider["model_list_response"]["url"],
            "https://inference.tinfoil.sh/v1/models",
        )
        self.assertEqual(provider["model_list_response"]["status"], 200)
        self.assertEqual(
            provider["model_list_response"]["body_sha256"],
            live_conformance.raw_sha256_digest(
                json.dumps(
                    {"data": [{"id": "model-a"}, {"model_id": "model-b"}]}
                ).encode("utf-8")
            ),
        )
        self.assertEqual(
            provider["attestation_response"]["url"],
            "https://inference.tinfoil.sh/.well-known/tinfoil-attestation",
        )
        self.assertEqual(provider["attestation_response"]["status"], 200)
        self.assertEqual(
            provider["attestation_response"]["body_sha256"],
            live_conformance.raw_sha256_digest(
                json.dumps({"evidence": {"ok": True}}).encode("utf-8")
            ),
        )

    def test_alias_matrix_import_requires_matching_provider_routes(self):
        plan = plan_provider(
            enabled=False,
            expected_model_ids_from_alias_matrix=True,
            expected_model_ids=None,
        )
        plan["model_alias_matrix_path"] = "fixtures/registry/model-alias-matrix.json"
        plan["model_alias_matrix_envelope_path"] = "fixtures/registry/model-alias-matrix-envelope.json"
        plan["providers"][0].pop("expected_model_ids", None)

        with self.assertRaises(live_conformance.LiveConformanceError) as context:
            live_conformance.run_conformance(plan, FakeHttp({}), allow_network=False)

        self.assertIn("has no provider_routes", str(context.exception))

    def test_alias_matrix_import_requires_configured_envelope(self):
        plan = plan_provider(
            enabled=False,
            expected_model_ids_from_alias_matrix=True,
            expected_model_ids=None,
        )
        plan["model_alias_matrix_path"] = "fixtures/registry/model-alias-matrix.json"
        plan["providers"][0].pop("expected_model_ids", None)

        with self.assertRaises(live_conformance.LiveConformanceError) as context:
            live_conformance.run_conformance(plan, FakeHttp({}), allow_network=False)

        self.assertIn("model_alias_matrix_envelope_path", str(context.exception))

    def test_alias_matrix_envelope_must_match_raw_payload(self):
        matrix = json.loads(Path("fixtures/registry/model-alias-matrix.json").read_text())
        envelope = json.loads(Path("fixtures/registry/model-alias-matrix-envelope.json").read_text())
        matrix["models"][0]["aliases"].append("GPT OSS 120B")

        with tempfile.TemporaryDirectory() as temp:
            matrix_path = Path(temp) / "model-alias-matrix.json"
            matrix_path.write_text(json.dumps(matrix), encoding="utf-8")
            envelope_path = Path(temp) / "model-alias-matrix-envelope.json"
            envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
            plan = plan_provider(
                enabled=False,
                expected_model_ids_from_alias_matrix=True,
                expected_model_ids=None,
            )
            plan["model_alias_matrix_path"] = str(matrix_path)
            plan["model_alias_matrix_envelope_path"] = str(envelope_path)
            plan["providers"][0]["id"] = "venice"
            plan["providers"][0].pop("expected_model_ids", None)

            with self.assertRaises(live_conformance.LiveConformanceError) as context:
                live_conformance.run_conformance(plan, FakeHttp({}), allow_network=False)

        self.assertIn("envelope payload does not match", str(context.exception))

    def test_alias_matrix_envelope_signature_must_verify(self):
        envelope = json.loads(Path("fixtures/registry/model-alias-matrix-envelope.json").read_text())
        envelope["signature"]["value"] = tamper_base64url_value(
            envelope["signature"]["value"]
        )

        with tempfile.TemporaryDirectory() as temp:
            envelope_path = Path(temp) / "model-alias-matrix-envelope.json"
            envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
            plan = plan_provider(
                enabled=False,
                expected_model_ids_from_alias_matrix=True,
                expected_model_ids=None,
            )
            plan["model_alias_matrix_path"] = "fixtures/registry/model-alias-matrix.json"
            plan["model_alias_matrix_envelope_path"] = str(envelope_path)
            plan["providers"][0]["id"] = "venice"
            plan["providers"][0].pop("expected_model_ids", None)

            with self.assertRaises(live_conformance.LiveConformanceError) as context:
                live_conformance.run_conformance(plan, FakeHttp({}), allow_network=False)

        self.assertIn("signature is invalid", str(context.exception))

    def test_plan_rejects_copied_and_imported_expected_model_ids_together(self):
        plan = plan_provider(expected_model_ids_from_alias_matrix=True)
        plan["model_alias_matrix_path"] = "fixtures/registry/model-alias-matrix.json"

        with self.assertRaises(live_conformance.LiveConformanceError) as context:
            live_conformance.run_conformance(plan, FakeHttp({}), allow_network=True)

        self.assertIn("must not set both", str(context.exception))

    def test_plan_rejects_null_expected_model_ids(self):
        plan = plan_provider(expected_model_ids=None)

        with self.assertRaises(live_conformance.LiveConformanceError) as context:
            live_conformance.run_conformance(plan, FakeHttp({}), allow_network=True)

        self.assertIn("expected_model_ids", str(context.exception))

    def test_plan_rejects_empty_expected_model_ids(self):
        plan = plan_provider(expected_model_ids=[])

        with self.assertRaises(live_conformance.LiveConformanceError) as context:
            live_conformance.run_conformance(plan, FakeHttp({}), allow_network=True)

        self.assertIn("at least one non-empty string", str(context.exception))

    def test_live_provider_without_expected_model_ids_cannot_pass(self):
        fake = FakeHttp(
            {
                "https://inference.tinfoil.sh/v1/models": {"json": {"data": []}},
                "https://inference.tinfoil.sh/.well-known/tinfoil-attestation": {"json": {"evidence": {"ok": True}}},
            }
        )
        plan = plan_provider()
        plan["providers"][0].pop("expected_model_ids")

        report = live_conformance.run_conformance(plan, fake, allow_network=True)

        self.assertEqual(report["credentialed_live_gate"]["status"], "open")
        self.assertEqual(report["summary"]["passed"], 0)
        provider = report["providers"][0]
        self.assertEqual(provider["status"], "invalid_plan")
        self.assertFalse(provider["live_checked"])
        self.assertEqual(provider["expected_model_ids"], [])
        self.assertEqual(provider["expected_model_ids_source"], "none")
        self.assertIn("expected_model_ids", provider["errors"][0])
        self.assertEqual(fake.calls, [])

    def test_compatibility_profile_requires_configured_matrix(self):
        plan = plan_provider(compatibility_provider="demo")

        with self.assertRaises(live_conformance.LiveConformanceError) as context:
            live_conformance.run_conformance(plan, FakeHttp({}), allow_network=True)

        self.assertIn("compatibility_matrix_path", str(context.exception))

    def test_compatibility_profile_requires_matching_matrix_provider(self):
        plan = plan_provider(enabled=False, compatibility_provider="missing-profile")
        plan["compatibility_matrix_path"] = "fixtures/providers/compatibility-matrix.json"
        plan["compatibility_matrix_envelope_path"] = (
            "fixtures/providers/compatibility-matrix-envelope.json"
        )

        with self.assertRaises(live_conformance.LiveConformanceError) as context:
            live_conformance.run_conformance(plan, FakeHttp({}), allow_network=False)

        self.assertIn("missing from the compatibility matrix", str(context.exception))

    def test_compatibility_profile_requires_configured_envelope(self):
        plan = plan_provider(enabled=False, compatibility_provider="demo")
        plan["compatibility_matrix_path"] = "fixtures/providers/compatibility-matrix.json"

        with self.assertRaises(live_conformance.LiveConformanceError) as context:
            live_conformance.run_conformance(plan, FakeHttp({}), allow_network=False)

        self.assertIn("compatibility_matrix_envelope_path", str(context.exception))

    def test_compatibility_matrix_envelope_must_match_raw_payload(self):
        matrix = json.loads(Path("fixtures/providers/compatibility-matrix.json").read_text())
        envelope = json.loads(
            Path("fixtures/providers/compatibility-matrix-envelope.json").read_text()
        )
        matrix["providers"]["demo"]["streaming"] = "supported"

        with tempfile.TemporaryDirectory() as temp:
            matrix_path = Path(temp) / "compatibility-matrix.json"
            matrix_path.write_text(json.dumps(matrix), encoding="utf-8")
            envelope_path = Path(temp) / "compatibility-matrix-envelope.json"
            envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
            plan = plan_provider(enabled=False, compatibility_provider="demo")
            plan["compatibility_matrix_path"] = str(matrix_path)
            plan["compatibility_matrix_envelope_path"] = str(envelope_path)

            with self.assertRaises(live_conformance.LiveConformanceError) as context:
                live_conformance.run_conformance(plan, FakeHttp({}), allow_network=False)

        self.assertIn("envelope payload does not match", str(context.exception))

    def test_compatibility_matrix_envelope_signature_must_verify(self):
        envelope = json.loads(
            Path("fixtures/providers/compatibility-matrix-envelope.json").read_text()
        )
        envelope["signature"]["value"] = tamper_base64url_value(
            envelope["signature"]["value"]
        )

        with tempfile.TemporaryDirectory() as temp:
            envelope_path = Path(temp) / "compatibility-matrix-envelope.json"
            envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
            plan = plan_provider(enabled=False, compatibility_provider="demo")
            plan["compatibility_matrix_path"] = "fixtures/providers/compatibility-matrix.json"
            plan["compatibility_matrix_envelope_path"] = str(envelope_path)

            with self.assertRaises(live_conformance.LiveConformanceError) as context:
                live_conformance.run_conformance(plan, FakeHttp({}), allow_network=False)

        self.assertIn("signature is invalid", str(context.exception))

    def test_compatibility_matrix_rejects_unsupported_streaming_without_declared_mode(self):
        matrix = json.loads(Path("fixtures/providers/compatibility-matrix.json").read_text())
        matrix["providers"]["demo"]["known_unsupported_modes"] = []
        envelope = json.loads(
            Path("fixtures/providers/compatibility-matrix-envelope.json").read_text()
        )
        envelope["payload"] = matrix

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "compatibility-matrix.json"
            path.write_text(json.dumps(matrix), encoding="utf-8")
            envelope_path = Path(temp) / "compatibility-matrix-envelope.json"
            envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
            plan = plan_provider(enabled=False, compatibility_provider="demo")
            plan["compatibility_matrix_path"] = str(path)
            plan["compatibility_matrix_envelope_path"] = str(envelope_path)

            with self.assertRaises(live_conformance.LiveConformanceError) as context:
                live_conformance.run_conformance(plan, FakeHttp({}), allow_network=False)

        self.assertIn("known_unsupported_modes", str(context.exception))

    def test_live_provider_reports_new_and_removed_model_drift(self):
        fake = FakeHttp(
            {
                "https://inference.tinfoil.sh/v1/models": {"json": {"models": ["model-a", "model-new"]}},
                "https://inference.tinfoil.sh/.well-known/tinfoil-attestation": {"json": {"evidence": {"ok": True}}},
            }
        )
        plan = plan_provider(expected_model_ids=["model-a", "model-removed"])

        report = live_conformance.run_conformance(plan, fake, allow_network=True)

        self.assertEqual(report["summary"]["drift"], 1)
        self.assertEqual(report["summary"]["live_checked"], 1)
        self.assertEqual(report["credentialed_live_gate"]["status"], "open")
        provider = report["providers"][0]
        self.assertEqual(provider["status"], "drift")
        self.assertTrue(provider["live_checked"])
        self.assertEqual(provider["new_unverified"], ["model-new"])
        self.assertEqual(provider["removed"], ["model-removed"])

    def test_auth_env_is_required_without_leaking_secret(self):
        env_name = "CONFIDENTIAL_INFERENCE_LIVE_CONFORMANCE_TEST_KEY"
        os.environ.pop(env_name, None)
        plan = plan_provider(auth_env=env_name)

        report = live_conformance.run_conformance(plan, FakeHttp({}), allow_network=True)

        provider = report["providers"][0]
        self.assertEqual(provider["status"], "skipped_missing_auth_env")
        self.assertEqual(provider["auth_env"], env_name)
        self.assertFalse(provider["live_checked"])
        self.assertEqual(report["summary"]["live_checked"], 0)
        self.assertEqual(report["credentialed_live_gate"]["status"], "open")
        self.assertEqual(provider["expected_model_ids"], ["model-a"])
        self.assertEqual(provider["expected_model_ids_source"], "plan")
        self.assertNotIn("Bearer", json.dumps(provider))

    def test_auth_env_success_reports_non_secret_credential_source(self):
        env_name = "CONFIDENTIAL_INFERENCE_LIVE_CONFORMANCE_TEST_KEY"
        os.environ[env_name] = "super-secret-live-token"
        try:
            fake = FakeHttp(
                {
                    "https://inference.tinfoil.sh/v1/models": {
                        "json": {"data": [{"id": "model-a"}]}
                    },
                    "https://inference.tinfoil.sh/.well-known/tinfoil-attestation": {
                        "json": {"evidence": {"ok": True}}
                    },
                }
            )
            report = live_conformance.run_conformance(
                plan_provider(auth_env=env_name),
                fake,
                allow_network=True,
            )
        finally:
            os.environ.pop(env_name, None)

        provider = report["providers"][0]
        self.assertEqual(provider["status"], "passed")
        self.assertEqual(provider["auth_env"], env_name)
        self.assertEqual(provider["credential_source"], "env")
        self.assertTrue(provider["credential_configured"])
        self.assertNotIn("super-secret-live-token", json.dumps(report))
        self.assertTrue(
            all(
                call_headers.get("Authorization") == "Bearer super-secret-live-token"
                for _url, call_headers, _timeout in fake.calls
            )
        )

    def test_attestation_shape_failure_is_failed_status(self):
        fake = FakeHttp(
            {
                "https://inference.tinfoil.sh/v1/models": {"json": {"data": [{"id": "model-a"}]}},
                "https://inference.tinfoil.sh/.well-known/tinfoil-attestation": {"json": {"unexpected": True}},
            }
        )

        report = live_conformance.run_conformance(plan_provider(), fake, allow_network=True)

        provider = report["providers"][0]
        self.assertEqual(provider["status"], "failed")
        self.assertTrue(provider["live_checked"])
        self.assertEqual(report["credentialed_live_gate"]["status"], "open")
        self.assertIn("missing JSON field", provider["attestation_errors"][0])

    def test_nested_attestation_shape_fields_are_checked(self):
        fake = FakeHttp(
            {
                "https://inference.tinfoil.sh/v1/models": {"json": {"data": [{"id": "model-a"}]}},
                "https://inference.tinfoil.sh/.well-known/tinfoil-attestation": {
                    "json": {"evidence": {"quote": "ok"}}
                },
            }
        )
        plan = plan_provider(
            expected_attestation={
                "content_type_contains": "application/json",
                "json_fields": ["evidence.quote"],
            }
        )

        report = live_conformance.run_conformance(plan, fake, allow_network=True)

        self.assertEqual(report["summary"]["passed"], 1)

    def test_nested_attestation_shape_failure_reports_path(self):
        fake = FakeHttp(
            {
                "https://inference.tinfoil.sh/v1/models": {"json": {"data": [{"id": "model-a"}]}},
                "https://inference.tinfoil.sh/.well-known/tinfoil-attestation": {
                    "json": {"evidence": {"unexpected": True}}
                },
            }
        )
        plan = plan_provider(
            expected_attestation={
                "content_type_contains": "application/json",
                "json_fields": ["evidence.quote"],
            }
        )

        report = live_conformance.run_conformance(plan, fake, allow_network=True)

        provider = report["providers"][0]
        self.assertEqual(provider["status"], "failed")
        self.assertIn("evidence.quote", provider["attestation_errors"][0])

    def test_plan_rejects_malformed_expected_attestation_shape(self):
        cases = {
            "missing": {},
            "not_object": {"expected_attestation": ["evidence"]},
            "empty_content": {
                "expected_attestation": {
                    "content_type_contains": "",
                    "json_fields": ["evidence"],
                }
            },
            "empty_json_fields": {
                "expected_attestation": {
                    "content_type_contains": "application/json",
                    "json_fields": [],
                }
            },
            "bad_json_field_path": {
                "expected_attestation": {
                    "content_type_contains": "application/json",
                    "json_fields": ["evidence..quote"],
                }
            },
        }
        for name, overrides in cases.items():
            with self.subTest(case=name):
                plan = plan_provider(**overrides)
                if name == "missing":
                    plan["providers"][0].pop("expected_attestation")

                with self.assertRaises(live_conformance.LiveConformanceError) as context:
                    live_conformance.run_conformance(plan, FakeHttp({}))

                self.assertIn("expected_attestation", str(context.exception))

    def test_expected_attestation_requires_attestation_url(self):
        plan = plan_provider(attestation_url="")

        with self.assertRaises(live_conformance.LiveConformanceError) as context:
            live_conformance.run_conformance(plan, FakeHttp({}))

        self.assertIn("requires attestation_url", str(context.exception))

    def test_load_plan_rejects_wrong_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "plan.json"
            path.write_text('{"schema":"wrong","providers":[]}', encoding="utf-8")

            with self.assertRaises(live_conformance.LiveConformanceError):
                live_conformance.load_plan(path)

    def test_credentialed_provider_urls_are_rejected_without_leaking_credentials(self):
        plan = plan_provider(
            model_list_url="https://token:secret@inference.tinfoil.sh/v1/models",
            attestation_url="https://inference.tinfoil.sh/.well-known/tinfoil-attestation",
        )

        with self.assertRaises(live_conformance.LiveConformanceError) as context:
            live_conformance.run_conformance(plan, FakeHttp({}), allow_network=True)

        message = str(context.exception)
        self.assertIn("model_list_url must not include URL credentials", message)
        self.assertNotIn("token", message)
        self.assertNotIn("secret", message)
        self.assertNotIn("token:secret@inference.tinfoil.sh", message)

    def test_load_plan_rejects_credentialed_attestation_url_without_leaking_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "plan.json"
            plan = plan_provider(
                model_list_url="https://inference.tinfoil.sh/v1/models",
                attestation_url="https://token:secret@inference.tinfoil.sh/.well-known/tinfoil-attestation",
            )
            path.write_text(json.dumps(plan), encoding="utf-8")

            with self.assertRaises(live_conformance.LiveConformanceError) as context:
                live_conformance.load_plan(path)

        message = str(context.exception)
        self.assertIn("attestation_url must not include URL credentials", message)
        self.assertNotIn("token", message)
        self.assertNotIn("secret", message)
        self.assertNotIn("token:secret@inference.tinfoil.sh", message)

    def test_at_signs_outside_url_authority_are_allowed(self):
        fake = FakeHttp(
            {
                "https://inference.tinfoil.sh/v1/models/@metadata?owner=ops@confidential-inference.dev": {
                    "json": {"data": [{"id": "model-a"}]},
                },
                "https://inference.tinfoil.sh/.well-known/tinfoil-attestation?owner=ops@confidential-inference.dev": {
                    "json": {"evidence": {"ok": True}},
                },
            }
        )
        plan = plan_provider(
            model_list_url="https://inference.tinfoil.sh/v1/models/@metadata?owner=ops@confidential-inference.dev",
            attestation_url="https://inference.tinfoil.sh/.well-known/tinfoil-attestation?owner=ops@confidential-inference.dev",
        )

        report = live_conformance.run_conformance(plan, fake, allow_network=True)

        self.assertEqual(report["summary"]["passed"], 1)


if __name__ == "__main__":
    unittest.main()
