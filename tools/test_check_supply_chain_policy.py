from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check_supply_chain_policy.py")
SPEC = importlib.util.spec_from_file_location("check_supply_chain_policy", MODULE_PATH)
assert SPEC is not None
check_supply_chain_policy = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(check_supply_chain_policy)


def write_valid_workspace(root: Path) -> None:
    (root / "crates" / "member").mkdir(parents=True)
    (root / "vendor" / "local").mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        """
[workspace]
members = ["crates/member"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/enclava-labs/confidential-inference-sdk"
rust-version = "1.75"

[workspace.dependencies]
serde = "1"
local = { path = "vendor/local" }
""".lstrip(),
        encoding="utf-8",
    )
    (root / "Cargo.lock").write_text(
        """
version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef"

[[package]]
name = "member"
version = "0.1.0"
""".lstrip(),
        encoding="utf-8",
    )
    (root / "deny.toml").write_text(valid_deny_toml(), encoding="utf-8")
    (root / "vendor" / "local" / "Cargo.toml").write_text(
        "[package]\nname = \"local\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        encoding="utf-8",
    )
    (root / "crates" / "member" / "Cargo.toml").write_text(
        """
[package]
name = "member"
description = "test member"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
serde.workspace = true
local.workspace = true
""".lstrip(),
        encoding="utf-8",
    )


def write_valid_node_binding(root: Path) -> None:
    binding = root / "bindings" / "node"
    binding.mkdir(parents=True)
    package_json = {
        "name": "confidential-inference-sdk",
        "version": "0.1.0",
        "description": "Thin Node.js binding over the Confidential Inference C ABI.",
        "main": "index.js",
        "types": "index.d.ts",
        "license": "MIT",
        "private": True,
        "engines": {"node": ">=22"},
        "scripts": {"test": "node --test test/*.test.js"},
        "dependencies": {"koffi": "3.1.0"},
    }
    package_lock = {
        "name": "confidential-inference-sdk",
        "version": "0.1.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": "confidential-inference-sdk",
                "version": "0.1.0",
                "license": "MIT",
                "dependencies": {"koffi": "3.1.0"},
                "engines": {"node": ">=22"},
            },
            "node_modules/koffi": {
                "version": "3.1.0",
                "resolved": "https://registry.npmjs.org/koffi/-/koffi-3.1.0.tgz",
                "integrity": "sha512-test",
                "license": "MIT",
                "hasInstallScript": True,
                "optionalDependencies": {
                    "@koromix/koffi-linux-x64": "3.1.0",
                },
            },
            "node_modules/@koromix/koffi-linux-x64": {
                "version": "3.1.0",
                "resolved": (
                    "https://registry.npmjs.org/@koromix/koffi-linux-x64/"
                    "-/koffi-linux-x64-3.1.0.tgz"
                ),
                "integrity": "sha512-test-platform",
                "license": "MIT",
                "optional": True,
                "os": ["linux"],
                "cpu": ["x64"],
            },
        },
    }
    (binding / "package.json").write_text(
        json.dumps(package_json, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    (binding / "package-lock.json").write_text(
        json.dumps(package_lock, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


SDK_MEMBERS = (
    "confidential-inference-attestation",
    "confidential-inference-openai",
    "confidential-inference-providers",
    "confidential-inference-sdk",
    "confidential-inference-middleware",
    "confidential-inference-proxy",
    "confidential-inference-ffi",
)


def valid_deny_toml() -> str:
    return """
[advisories]
version = 2
ignore = [
    "RUSTSEC-2025-0134",
]

[licenses]
version = 2
allow = [
    "Apache-2.0",
    "BSD-3-Clause",
    "CDLA-Permissive-2.0",
    "ISC",
    "MIT",
    "Unicode-3.0",
    "Zlib",
]
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
""".lstrip()


def write_sdk_workspace(root: Path) -> None:
    crates = root / "crates"
    for crate in SDK_MEMBERS:
        (crates / crate).mkdir(parents=True)

    members = ", ".join(f'"crates/{crate}"' for crate in SDK_MEMBERS)
    (root / "Cargo.toml").write_text(
        f"""
[workspace]
members = [{members}]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/enclava-labs/confidential-inference-sdk"
rust-version = "1.75"
""".lstrip(),
        encoding="utf-8",
    )
    (root / "Cargo.lock").write_text(
        "version = 4\n\n"
        + "\n".join(
            f'[[package]]\nname = "{crate}"\nversion = "0.1.0"\n'
            for crate in SDK_MEMBERS
        ),
        encoding="utf-8",
    )
    (root / "deny.toml").write_text(valid_deny_toml(), encoding="utf-8")

    dependency_edges = {
        "confidential-inference-attestation": (),
        "confidential-inference-openai": (),
        "confidential-inference-providers": ("confidential-inference-attestation", "confidential-inference-openai"),
        "confidential-inference-sdk": ("confidential-inference-attestation", "confidential-inference-openai", "confidential-inference-providers"),
        "confidential-inference-middleware": ("confidential-inference-sdk", "confidential-inference-openai"),
        "confidential-inference-proxy": ("confidential-inference-sdk", "confidential-inference-openai"),
        "confidential-inference-ffi": ("confidential-inference-sdk",),
    }
    for crate in SDK_MEMBERS:
        dependencies = dependency_edges[crate]
        dependency_text = ""
        if dependencies:
            dependency_text = "\n[dependencies]\n" + "".join(
                f'{dependency} = {{ version = "0.1.0", path = "../{dependency}" }}\n'
                for dependency in dependencies
            )
        (crates / crate / "Cargo.toml").write_text(
            f"""
[package]
name = "{crate}"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
{dependency_text}
""".lstrip(),
            encoding="utf-8",
        )


class CheckSupplyChainPolicyTests(unittest.TestCase):
    def test_valid_workspace_passes_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_valid_workspace(root)

            report = check_supply_chain_policy.check_workspace(root)

            self.assertEqual(report["schema"], "confidential-inference.supply-chain-policy.v1")
            self.assertEqual(report["workspace_rust_version"], "1.75")
            self.assertEqual(report["workspace_member_count"], 1)
            self.assertEqual(report["lock_package_count"], 2)
            self.assertEqual(report["node_binding_dependency_specs_checked"], 0)
            self.assertEqual(report["node_binding_lock_package_count"], 0)
            self.assertEqual(report["sdk_dependency_edges_checked"], 0)
            self.assertEqual(report["violations"], [])

    def test_policy_reports_weakened_cargo_deny_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_valid_workspace(root)
            deny_path = root / "deny.toml"
            deny_path.write_text(
                """
[advisories]
version = 1
ignore = ["untracked-advisory"]

[licenses]
version = 2
allow = ["Apache-2.0", "GPL-3.0"]
confidence-threshold = 0.1

[bans]
multiple-versions = "allow"
wildcards = "allow"

[sources]
unknown-registry = "allow"
unknown-git = "allow"
""".lstrip(),
                encoding="utf-8",
            )

            report = check_supply_chain_policy.check_workspace(root)
            joined = "\n".join(report["violations"])

            self.assertIn("advisories.version must be 2", joined)
            self.assertIn("advisories.ignore must list explicit RUSTSEC ids", joined)
            self.assertIn("licenses.allow must match reviewed SDK license allow-list", joined)
            self.assertIn("licenses.confidence-threshold must be at least 0.8", joined)
            self.assertIn("bans.wildcards must be deny", joined)
            self.assertIn("bans.multiple-versions must be warn or deny", joined)
            self.assertIn("sources.unknown-registry must be deny", joined)
            self.assertIn("sources.unknown-git must be deny", joined)

    def test_valid_node_binding_policy_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_valid_workspace(root)
            write_valid_node_binding(root)

            report = check_supply_chain_policy.check_workspace(root)

            self.assertEqual(report["node_binding_dependency_specs_checked"], 1)
            self.assertEqual(report["node_binding_lock_package_count"], 2)
            self.assertEqual(report["violations"], [])

    def test_policy_reports_node_binding_package_violations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_valid_workspace(root)
            write_valid_node_binding(root)
            package_json_path = root / "bindings" / "node" / "package.json"
            package_json = json.loads(package_json_path.read_text(encoding="utf-8"))
            package_json["dependencies"]["koffi"] = "^3.1.0"
            package_json["scripts"]["postinstall"] = "node install.js"
            package_json["private"] = False
            package_json_path.write_text(
                json.dumps(package_json, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )

            report = check_supply_chain_policy.check_workspace(root)
            joined = "\n".join(report["violations"])

            self.assertIn("private must remain true", joined)
            self.assertIn("scripts must only contain the reviewed test command", joined)
            self.assertIn("dependencies.koffi must use an exact pinned semver", joined)
            self.assertIn("root package dependencies must match", joined)

    def test_policy_reports_node_lockfile_violations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_valid_workspace(root)
            write_valid_node_binding(root)
            lock_path = root / "bindings" / "node" / "package-lock.json"
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
            lock["lockfileVersion"] = 2
            package = lock["packages"]["node_modules/@koromix/koffi-linux-x64"]
            package["version"] = "3.1"
            package["resolved"] = "git+https://github.com/KoffiDev/koffi"
            package["integrity"] = "sha1-weak"
            package["license"] = "GPL-3.0"
            package["hasInstallScript"] = True
            lock_path.write_text(
                json.dumps(lock, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )

            report = check_supply_chain_policy.check_workspace(root)
            joined = "\n".join(report["violations"])

            self.assertIn("lockfileVersion must be 3", joined)
            self.assertIn("version must be exact pinned semver", joined)
            self.assertIn("resolved URL must use https://registry.npmjs.org/", joined)
            self.assertIn("integrity must be a sha512 lock digest", joined)
            self.assertIn("license 'GPL-3.0' is not allowed", joined)
            self.assertIn("has an install script but is not allow-listed", joined)

    def test_valid_sdk_dependency_boundaries_pass_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sdk_workspace(root)

            report = check_supply_chain_policy.check_workspace(root)

            self.assertEqual(report["workspace_member_count"], len(SDK_MEMBERS))
            self.assertEqual(report["sdk_dependency_edges_checked"], 10)
            self.assertEqual(report["violations"], [])

    def test_policy_reports_sdk_dependency_boundary_violations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sdk_workspace(root)
            (root / "crates" / "confidential-inference-attestation" / "Cargo.toml").write_text(
                """
[package]
name = "confidential-inference-attestation"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
client = { package = "confidential-inference-sdk", version = "0.1.0", path = "../confidential-inference-sdk" }
""".lstrip(),
                encoding="utf-8",
            )
            (root / "crates" / "confidential-inference-providers" / "Cargo.toml").write_text(
                """
[package]
name = "confidential-inference-providers"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
confidential-inference-sdk = { version = "0.1.0", path = "../confidential-inference-sdk" }
confidential-inference-openai = { version = "0.1.0", path = "../confidential-inference-openai" }
""".lstrip(),
                encoding="utf-8",
            )

            report = check_supply_chain_policy.check_workspace(root)
            joined = "\n".join(report["violations"])

            self.assertIn(
                "confidential-inference-attestation must not depend on confidential-inference-sdk",
                joined,
            )
            self.assertIn(
                "confidential-inference-providers must not depend on confidential-inference-sdk",
                joined,
            )

    def test_policy_reports_ffi_openai_dependency_boundary_violation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_sdk_workspace(root)
            (root / "crates" / "confidential-inference-ffi" / "Cargo.toml").write_text(
                """
[package]
name = "confidential-inference-ffi"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
confidential-inference-sdk = { version = "0.1.0", path = "../confidential-inference-sdk" }
confidential-inference-openai = { version = "0.1.0", path = "../confidential-inference-openai" }
""".lstrip(),
                encoding="utf-8",
            )

            report = check_supply_chain_policy.check_workspace(root)
            joined = "\n".join(report["violations"])

            self.assertIn(
                "confidential-inference-ffi must not depend on confidential-inference-openai",
                joined,
            )

    def test_policy_reports_relative_path_dependencies_outside_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspace"
            outside = Path(temp) / "foundation-reference"
            write_valid_workspace(root)
            outside.mkdir()
            (outside / "Cargo.toml").write_text(
                "[package]\nname = \"foundation-reference\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                encoding="utf-8",
            )
            (root / "crates" / "member" / "Cargo.toml").write_text(
                """
[package]
name = "member"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
foundation = { path = "../../../foundation-reference" }
""".lstrip(),
                encoding="utf-8",
            )

            report = check_supply_chain_policy.check_workspace(root)
            joined = "\n".join(report["violations"])

            self.assertIn(
                "foundation path dependency escapes workspace root",
                joined,
            )

    def test_policy_reports_msrv_dependency_and_lockfile_violations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_valid_workspace(root)
            (root / "Cargo.lock").write_text(
                """
version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "git-only"
version = "0.1.0"
source = "git+https://github.com/enclava-labs/confidential-inference-sdk"
""".lstrip(),
                encoding="utf-8",
            )
            (root / "crates" / "member" / "Cargo.toml").write_text(
                """
[package]
name = "member"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
wild = "*"
gitdep = { git = "https://github.com/enclava-labs/confidential-inference-sdk" }
missing_version = { default-features = false }
absolute = { path = "/tmp/absolute-dependency" }
""".lstrip(),
                encoding="utf-8",
            )

            report = check_supply_chain_policy.check_workspace(root)
            joined = "\n".join(report["violations"])

            self.assertIn("package.rust-version must inherit", joined)
            self.assertIn("wild uses an unpinned or wildcard version requirement", joined)
            self.assertIn("gitdep uses a git dependency", joined)
            self.assertIn("missing_version is a registry dependency without a version", joined)
            self.assertIn("absolute uses an absolute path dependency", joined)
            self.assertIn("registry package serde 1.0.228 is missing a checksum", joined)
            self.assertIn("git-only 0.1.0 resolves from git source", joined)


if __name__ == "__main__":
    unittest.main()
