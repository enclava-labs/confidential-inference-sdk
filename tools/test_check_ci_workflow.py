from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check_ci_workflow.py")
SPEC = importlib.util.spec_from_file_location("check_ci_workflow", MODULE_PATH)
assert SPEC is not None
check_ci_workflow = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(check_ci_workflow)


class CheckCiWorkflowTests(unittest.TestCase):
    def test_current_workflow_contains_required_offline_gates(self) -> None:
        report = check_ci_workflow.check_workflow(Path(".github/workflows/ci.yml"))

        self.assertEqual(report["schema"], "confidential-inference.ci-workflow-policy.v1")
        self.assertEqual(report["missing"], [])

    def test_missing_workflow_and_missing_command_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / "missing.yml"
            report = check_ci_workflow.check_workflow(missing)
            self.assertIn("does not exist", report["missing"][0])

            workflow = Path(temp) / "ci.yml"
            workflow.write_text(
                "\n".join(check_ci_workflow.REQUIRED_SNIPPETS[:-1]),
                encoding="utf-8",
            )
            report = check_ci_workflow.check_workflow(workflow)
            self.assertEqual(report["missing"], [check_ci_workflow.REQUIRED_SNIPPETS[-1]])

    def test_demo_pipeline_requires_pipefail_in_same_run_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workflow = Path(temp) / "ci.yml"
            workflow.write_text(
                "\n".join(
                    snippet
                    for snippet in check_ci_workflow.REQUIRED_SNIPPETS
                    if snippet != check_ci_workflow.DEMO_PIPEFAIL_SNIPPET
                )
                + "\nset -o pipefail\n",
                encoding="utf-8",
            )

            report = check_ci_workflow.check_workflow(workflow)

            self.assertEqual(
                report["missing"],
                [check_ci_workflow.DEMO_PIPEFAIL_SNIPPET],
            )


if __name__ == "__main__":
    unittest.main()
