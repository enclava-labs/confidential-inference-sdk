from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


BASH = shutil.which("bash")
RUNNER = Path(__file__).with_name("run_offline_gates.sh")


@unittest.skipUnless(os.name == "posix" and BASH, "requires POSIX Bash")
class OfflineGateTests(unittest.TestCase):
    def test_missing_required_python_fails_before_building(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tools").mkdir()
            (root / "bin").mkdir()
            runner = root / "tools" / RUNNER.name
            shutil.copyfile(RUNNER, runner)
            for command in ("dirname", "mkdir"):
                executable = shutil.which(command)
                self.assertIsNotNone(executable)
                (root / "bin" / command).symlink_to(executable)
            result = subprocess.run(
                [BASH, str(runner)],
                env={**os.environ, "PATH": str(root / "bin")},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 1)
            self.assertFalse((root / "target/gate-logs/fmt.log").exists())


if __name__ == "__main__":
    unittest.main()
