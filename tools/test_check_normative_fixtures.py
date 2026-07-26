from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check_normative_fixtures.py")
TOOLS_DIR = MODULE_PATH.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
SPEC = importlib.util.spec_from_file_location("check_normative_fixtures", MODULE_PATH)
assert SPEC is not None
check_normative_fixtures = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(check_normative_fixtures)


def tamper_base64url_value(value: str) -> str:
    prefix_len = len("base64url:")
    replacement = "A" if value[prefix_len] != "A" else "B"
    return value[:prefix_len] + replacement + value[prefix_len + 1 :]


class CheckNormativeFixturesTests(unittest.TestCase):
    def test_current_normative_fixtures_are_complete(self) -> None:
        report = check_normative_fixtures.check_fixtures(Path("."))

        self.assertEqual(report["schema"], "confidential-inference.normative-fixture-policy.v1")
        self.assertEqual(report["checked_count"], 10)
        self.assertEqual(report["violations"], [])

    def test_verdict_signature_metadata_is_required(self) -> None:
        verdict = check_normative_fixtures.load_json(
            Path("fixtures/verdict/demo-verified.json")
        )
        verdict["registry_signature"] = {
            "signer": "",
            "key_id": "confidential-inference-demo-ed25519-2026",
            "alg": "rsa",
        }

        violations = check_normative_fixtures.validate_verdict_fixture(
            Path("fixtures/verdict/demo-verified.json"),
            verdict,
        )

        joined = "\n".join(violations)
        self.assertIn("registry_signature: signature signer must be non-empty", joined)
        self.assertIn("registry_signature: signature alg must be ed25519", joined)

    def test_registry_routes_must_keep_security_metadata(self) -> None:
        envelope = check_normative_fixtures.load_json(
            Path("fixtures/registry/demo-registry.json")
        )
        route = envelope["payload"]["models"]["gpt-oss-120b"]["routes"][0]
        route.pop("evidence_endpoint")
        route.pop("response_integrity_requirement")

        violations = check_normative_fixtures.validate_registry_fixture(
            Path("fixtures/registry/demo-registry.json"),
            envelope,
        )

        joined = "\n".join(violations)
        self.assertIn("missing evidence_endpoint", joined)
        self.assertIn("missing response_integrity_requirement", joined)

    def test_registry_timestamps_must_be_canonical(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(Path("fixtures/registry/demo-registry.json"))
        )
        envelope["payload"]["generated_at"] = "2026-07-05 00:00:00Z"
        envelope["payload"]["source_sync_run"]["completed_at"] = "not-a-timestamp"

        violations = check_normative_fixtures.validate_registry_fixture(
            Path("fixtures/registry/demo-registry.json"),
            envelope,
        )

        joined = "\n".join(violations)
        self.assertIn("payload.generated_at: must be a canonical UTC RFC3339", joined)
        self.assertIn("source_sync_run.completed_at: must be a canonical UTC RFC3339", joined)

    def test_signed_artifact_signature_value_must_be_ed25519_bytes(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(Path("fixtures/registry/demo-registry.json"))
        )
        envelope["signature"]["value"] = "base64url:not-a-real-signature"

        violations = check_normative_fixtures.validate_registry_fixture(
            Path("fixtures/registry/demo-registry.json"),
            envelope,
        )

        joined = "\n".join(violations)
        self.assertIn("64-byte ed25519 signature", joined)

    def test_signed_artifact_signature_must_cryptographically_verify(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(Path("fixtures/registry/demo-registry.json"))
        )
        envelope["signature"]["value"] = tamper_base64url_value(
            envelope["signature"]["value"]
        )

        violations = check_normative_fixtures.validate_registry_fixture(
            Path("fixtures/registry/demo-registry.json"),
            envelope,
        )

        joined = "\n".join(violations)
        self.assertIn("signature is invalid", joined)

    def test_signed_payloads_must_use_canonical_json_numbers(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(Path("fixtures/registry/demo-registry.json"))
        )
        envelope["payload"]["unsafe_epoch"] = check_normative_fixtures.MAX_SAFE_JSON_INT + 1
        envelope["payload"]["float_value"] = 1.0

        violations = check_normative_fixtures.validate_registry_fixture(
            Path("fixtures/registry/demo-registry.json"),
            envelope,
        )

        joined = "\n".join(violations)
        self.assertIn("exceeds the cross-language safe integer limit", joined)
        self.assertIn("canonical JSON does not permit floating point numbers", joined)

    def test_reference_route_validity_and_artifacts_are_required(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/reference-values/demo-envelope.json")
            )
        )
        route = envelope["payload"]["providers"]["demo"]["routes"][
            "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"
        ]
        route.pop("valid_until_epoch_ms")
        route["model_artifacts"] = []

        violations = check_normative_fixtures.validate_reference_values_fixture(
            Path("fixtures/reference-values/demo-envelope.json"),
            envelope,
        )

        joined = "\n".join(violations)
        self.assertIn("missing valid_until_epoch_ms", joined)
        self.assertIn("model_artifacts must be non-empty", joined)

    def test_reference_values_validity_metadata_must_be_coherent(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/reference-values/demo-envelope.json")
            )
        )
        envelope["payload"]["valid_from"] = envelope["payload"]["valid_until"]
        envelope["payload"]["valid_until_epoch_ms"] += 1
        route = envelope["payload"]["providers"]["demo"]["routes"][
            "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p"
        ]
        route["valid_until"] = "2099-01-01 00:00:00Z"
        route["valid_until_epoch_ms"] += 1

        violations = check_normative_fixtures.validate_reference_values_fixture(
            Path("fixtures/reference-values/demo-envelope.json"),
            envelope,
        )

        joined = "\n".join(violations)
        self.assertIn("payload.valid_until_epoch_ms must match payload.valid_until", joined)
        self.assertIn("payload.valid_from must be before payload.valid_until", joined)
        self.assertIn("route demo:gpt-oss-120b:e2ee-gpt-oss-120b-p", joined)
        self.assertIn("valid_until: must be a canonical UTC RFC3339", joined)

    def test_tinfoil_reference_values_must_not_claim_snp_before_backend_exists(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/reference-values/phase2-fixtures-envelope.json")
            )
        )
        route = envelope["payload"]["providers"]["tinfoil-fixture"]["routes"][
            "tinfoil-fixture:llama-3.3-70b:llama-3.3-70b"
        ]
        route["accepted_cpu_tees"].append("sev_snp")

        violations = check_normative_fixtures.validate_reference_values_fixture(
            Path("fixtures/reference-values/phase2-fixtures-envelope.json"),
            envelope,
        )

        joined = "\n".join(violations)
        self.assertIn("must not accept unsupported production CPU TEEs", joined)
        self.assertIn("sev_snp", joined)

    def test_live_conformance_plan_must_import_reviewed_fixture_contracts(self) -> None:
        plan = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/providers/live-conformance-plan.json")
            )
        )
        plan["providers"][0]["expected_model_ids"] = ["copied-model"]
        plan["providers"][1]["expected_model_ids_from_alias_matrix"] = False
        plan["providers"][2]["compatibility_provider"] = "missing-profile"

        violations = check_normative_fixtures.validate_live_conformance_plan(
            Path("fixtures/providers/live-conformance-plan.json"),
            plan,
            Path("."),
        )

        joined = "\n".join(violations)
        self.assertIn("expected_model_ids must be imported", joined)
        self.assertIn("expected_model_ids_from_alias_matrix must be true", joined)
        self.assertIn("missing from the compatibility matrix", joined)

    def test_live_sync_corpus_must_not_mark_fixture_only_routes_active(self) -> None:
        corpus = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/providers/live-sync-corpus.json")
            )
        )
        case = corpus["cases"][0]
        case["enrichments"][0]["route_status"] = "active"
        case["expected"]["reviewed_routes"][0]["route_status"] = "active"
        case["expected"]["unreviewed_routes"][0]["route_status"] = "active"

        violations = check_normative_fixtures.validate_live_sync_corpus(
            Path("fixtures/providers/live-sync-corpus.json"),
            corpus,
        )

        joined = "\n".join(violations)
        self.assertIn("case venice-openai-model-list-valid: enrichments[0]", joined)
        self.assertIn("expected.reviewed_routes[0]", joined)
        self.assertIn("expected.unreviewed_routes[0]", joined)
        self.assertIn("live-sync fixture routes for Venice dstack app-E2EE", joined)
        self.assertIn("unreviewed live-sync discoveries must remain new_unverified", joined)

    def test_compatibility_matrix_envelope_must_match_raw_matrix(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/providers/compatibility-matrix-envelope.json")
            )
        )
        envelope["payload"]["providers"]["demo"]["streaming"] = "supported"

        violations = check_normative_fixtures.validate_compatibility_matrix_envelope(
            Path("fixtures/providers/compatibility-matrix-envelope.json"),
            envelope,
            Path("."),
        )

        joined = "\n".join(violations)
        self.assertIn("payload must match fixtures/providers/compatibility-matrix.json", joined)

    def test_tinfoil_fixture_profile_must_not_claim_production_live_execution(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/providers/compatibility-matrix-envelope.json")
            )
        )
        tinfoil = envelope["payload"]["providers"]["tinfoil-fixture"]
        tinfoil["route_execution_status"] = "executable"
        tinfoil["known_unsupported_modes"] = ["streaming"]

        violations = check_normative_fixtures.validate_compatibility_matrix_envelope(
            Path("fixtures/providers/compatibility-matrix-envelope.json"),
            envelope,
            Path("."),
        )

        joined = "\n".join(violations)
        self.assertIn("Tinfoil fixture profiles must remain executable_fixture", joined)
        self.assertIn("live_tdx_quote", joined)

    def test_redpill_chutes_profile_must_not_be_marked_executable_before_live_nras(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/providers/compatibility-matrix-envelope.json")
            )
        )
        redpill = envelope["payload"]["providers"]["redpill-fixture"]
        redpill["route_execution_status"] = "executable"
        redpill["known_unsupported_modes"] = ["streaming"]

        violations = check_normative_fixtures.validate_compatibility_matrix_envelope(
            Path("fixtures/providers/compatibility-matrix-envelope.json"),
            envelope,
            Path("."),
        )

        joined = "\n".join(violations)
        self.assertIn("Chutes/Redpill E2EE+GPU profiles must remain", joined)
        self.assertIn("live_execution", joined)

    def test_direct_phala_profile_must_not_be_marked_executable_before_live_artifacts(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/providers/compatibility-matrix-envelope.json")
            )
        )
        phala = envelope["payload"]["providers"]["phala-direct-fixture"]
        phala["route_execution_status"] = "executable"
        phala["known_unsupported_modes"] = ["streaming"]

        violations = check_normative_fixtures.validate_compatibility_matrix_envelope(
            Path("fixtures/providers/compatibility-matrix-envelope.json"),
            envelope,
            Path("."),
        )

        joined = "\n".join(violations)
        self.assertIn("Direct Phala dstack profiles must remain", joined)
        self.assertIn("live_execution", joined)

    def test_ionet_profile_must_not_be_marked_executable_before_live_artifacts(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/providers/compatibility-matrix-envelope.json")
            )
        )
        ionet = envelope["payload"]["providers"]["ionet-confidential-fixture"]
        ionet["route_execution_status"] = "executable"
        ionet["known_unsupported_modes"] = ["streaming"]

        violations = check_normative_fixtures.validate_compatibility_matrix_envelope(
            Path("fixtures/providers/compatibility-matrix-envelope.json"),
            envelope,
            Path("."),
        )

        joined = "\n".join(violations)
        self.assertIn("io.net confidential inference profiles must remain", joined)
        self.assertIn("live_execution", joined)

    def test_venice_profile_must_not_be_marked_executable_before_live_artifacts(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/providers/compatibility-matrix-envelope.json")
            )
        )
        venice = envelope["payload"]["providers"]["venice-fixture"]
        venice["route_execution_status"] = "executable"
        venice["known_unsupported_modes"] = ["streaming"]

        violations = check_normative_fixtures.validate_compatibility_matrix_envelope(
            Path("fixtures/providers/compatibility-matrix-envelope.json"),
            envelope,
            Path("."),
        )

        joined = "\n".join(violations)
        self.assertIn("Venice dstack app-E2EE profiles must remain", joined)
        self.assertIn("live_execution", joined)

    def test_ppq_profile_must_not_be_marked_executable_before_live_artifacts(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/providers/compatibility-matrix-envelope.json")
            )
        )
        ppq = envelope["payload"]["providers"]["ppq-private-fixture"]
        ppq["route_execution_status"] = "executable"
        ppq["known_unsupported_modes"] = ["streaming"]

        violations = check_normative_fixtures.validate_compatibility_matrix_envelope(
            Path("fixtures/providers/compatibility-matrix-envelope.json"),
            envelope,
            Path("."),
        )

        joined = "\n".join(violations)
        self.assertIn("PPQ EHBP profiles must remain", joined)
        self.assertIn("live_execution", joined)

    def test_compatibility_matrix_envelope_signature_must_verify(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/providers/compatibility-matrix-envelope.json")
            )
        )
        envelope["signature"]["value"] = tamper_base64url_value(
            envelope["signature"]["value"]
        )

        violations = check_normative_fixtures.validate_compatibility_matrix_envelope(
            Path("fixtures/providers/compatibility-matrix-envelope.json"),
            envelope,
            Path("."),
        )

        joined = "\n".join(violations)
        self.assertIn("signature is invalid", joined)

    def test_model_alias_matrix_envelope_must_match_raw_matrix(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/registry/model-alias-matrix-envelope.json")
            )
        )
        envelope["payload"]["models"][0]["aliases"].append("GPT OSS 120B")

        violations = check_normative_fixtures.validate_model_alias_matrix_envelope(
            Path("fixtures/registry/model-alias-matrix-envelope.json"),
            envelope,
            Path("."),
        )

        joined = "\n".join(violations)
        self.assertIn("payload must match fixtures/registry/model-alias-matrix.json", joined)

    def test_model_alias_matrix_envelope_signature_must_verify(self) -> None:
        envelope = copy.deepcopy(
            check_normative_fixtures.load_json(
                Path("fixtures/registry/model-alias-matrix-envelope.json")
            )
        )
        envelope["signature"]["value"] = tamper_base64url_value(
            envelope["signature"]["value"]
        )

        violations = check_normative_fixtures.validate_model_alias_matrix_envelope(
            Path("fixtures/registry/model-alias-matrix-envelope.json"),
            envelope,
            Path("."),
        )

        joined = "\n".join(violations)
        self.assertIn("signature is invalid", joined)


if __name__ == "__main__":
    unittest.main()
