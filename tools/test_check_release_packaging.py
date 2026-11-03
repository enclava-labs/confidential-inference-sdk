from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("check_release_packaging.py")
SPEC = importlib.util.spec_from_file_location("check_release_packaging", MODULE_PATH)
assert SPEC is not None
check_release_packaging = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(check_release_packaging)


def write_manifest(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.lstrip(), encoding="utf-8")


class CheckReleasePackagingTests(unittest.TestCase):
    def test_current_workspace_has_publishable_sdk_crates_and_skips_demo(self) -> None:
        report = check_release_packaging.inspect_workspace(Path("."))

        self.assertEqual(report["schema"], "confidential-inference.release-packaging-policy.v1")
        self.assertEqual(report["violations"], [])
        self.assertIn("confidential-inference-sdk", report["release_packages"])
        self.assertIn("confidential-inference-ffi", report["release_packages"])
        self.assertIn("confidential-demo", report["skipped_packages"])

    def test_publishable_path_dependencies_must_have_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_manifest(
                root,
                "Cargo.toml",
                """
[workspace]
members = ["crates/core", "crates/client", "demo/local-demo"]
""",
            )
            write_manifest(
                root,
                "crates/core/Cargo.toml",
                """
[package]
name = "core"
description = "core test crate"
version = "0.1.0"
""",
            )
            write_manifest(
                root,
                "crates/client/Cargo.toml",
                """
[package]
name = "client"
description = "client test crate"
version = "0.1.0"

[dependencies]
core = { path = "../core" }
""",
            )
            write_manifest(
                root,
                "demo/local-demo/Cargo.toml",
                """
[package]
name = "local-demo"
description = "local demo"
version = "0.1.0"
publish = false

[dependencies]
client = { path = "../../crates/client" }
""",
            )

            report = check_release_packaging.inspect_workspace(root)

            self.assertEqual(report["release_packages"], ["core", "client"])
            self.assertEqual(report["skipped_packages"], ["local-demo"])
            self.assertEqual(report["path_dependencies_checked"], 1)
            self.assertIn("path dependency must specify version", report["violations"][0])

    def test_versioned_path_dependencies_pass_manifest_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_manifest(
                root,
                "Cargo.toml",
                """
[workspace]
members = ["crates/core", "crates/client"]
""",
            )
            write_manifest(
                root,
                "crates/core/Cargo.toml",
                """
[package]
name = "core"
description = "core test crate"
version = "0.1.0"
""",
            )
            write_manifest(
                root,
                "crates/client/Cargo.toml",
                """
[package]
name = "client"
description = "client test crate"
version = "0.1.0"

[dependencies]
core = { version = "0.1.0", path = "../core" }
""",
            )

            report = check_release_packaging.inspect_workspace(root)

            self.assertEqual(report["release_packages"], ["core", "client"])
            self.assertEqual(report["violations"], [])

    def test_publishable_crates_require_description(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_manifest(
                root,
                "Cargo.toml",
                """
[workspace]
members = ["crates/core"]
""",
            )
            write_manifest(
                root,
                "crates/core/Cargo.toml",
                """
[package]
name = "core"
version = "0.1.0"
""",
            )

            report = check_release_packaging.inspect_workspace(root)

            self.assertEqual(report["release_packages"], ["core"])
            self.assertIn("package.description is required", report["violations"][0])

    @unittest.skipUnless(shutil.which("cargo"), "requires Cargo")
    def test_repeated_packaging_verifies_current_same_version_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_manifest(root, "Cargo.toml", '[workspace]\nmembers = ["base", "client"]\nresolver = "2"\n')
            for name in ("base", "client"):
                write_manifest(
                    root, f"{name}/Cargo.toml",
                    f'[package]\nname = "packaging-test-{name}"\nversion = "0.1.0"\nedition = "2021"\n'
                    'description = "Packaging regression fixture"\nlicense = "MIT"\n'
                    + ('[dependencies]\npackaging-test-base = { version = "0.1.0", path = "../base" }\n'
                       if name == "client" else ""),
                )
                (root / name / "src").mkdir()
            packages = ["packaging-test-base", "packaging-test-client"]
            environment = {"CARGO_HOME": str(root / "cargo-home"), "CARGO_NET_OFFLINE": "true"}
            if shutil.which("rustup"):
                # Temporary workspaces must retain the repository's selected toolchain.
                environment["RUSTUP_TOOLCHAIN"] = subprocess.check_output(
                    ["rustup", "show", "active-toolchain"], text=True,
                ).split()[0]
            with patch.dict(os.environ, environment):
                for function in ("original", "updated"):
                    source = f"pub fn {function}() -> u8 {{ 1 }}\n"
                    (root / "base/src/lib.rs").write_text(source)
                    (root / "client/src/lib.rs").write_text(f"pub use packaging_test_base::{function};\n")
                    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, check=True)
                    result, _ = check_release_packaging.run_cargo_package(root, packages, True)
                    self.assertEqual(result, 0)
                    with tarfile.open(root / "target/package/packaging-test-base-0.1.0.crate") as archive:
                        member = archive.extractfile("packaging-test-base-0.1.0/src/lib.rs")
                        self.assertIsNotNone(member)
                        self.assertEqual(member.read().decode(), source)

                (root / "client/src/lib.rs").write_text("pub use packaging_test_base::nonexistent;\n")
                result, _ = check_release_packaging.run_cargo_package(root, packages, True)
                self.assertNotEqual(result, 0)

    def test_clean_target_package_archives_removes_hidden_and_normal_crates(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package_dir = root / "target" / "package"
            package_dir.mkdir(parents=True)
            (package_dir / "confidential-inference-sdk-0.1.0.crate").write_bytes(b"crate")
            (package_dir / ".confidential-demo-0.1.0.crate").write_bytes(b"stale")
            (package_dir / "notes.txt").write_text("keep", encoding="utf-8")

            removed = check_release_packaging.clean_target_package_archives(root)

            self.assertEqual(removed, 2)
            self.assertFalse((package_dir / "confidential-inference-sdk-0.1.0.crate").exists())
            self.assertFalse((package_dir / ".confidential-demo-0.1.0.crate").exists())
            self.assertTrue((package_dir / "notes.txt").exists())


if __name__ == "__main__":
    unittest.main()
