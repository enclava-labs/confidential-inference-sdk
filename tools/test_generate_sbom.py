from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("generate_sbom.py")
SPEC = importlib.util.spec_from_file_location("generate_sbom", MODULE_PATH)
assert SPEC is not None
generate_sbom = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(generate_sbom)


WORKSPACE_ID = "path+file:///repo/crates/confidential-inference-openai#0.1.0"
SERDE_ID = "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228"


def fake_metadata() -> dict:
    return {
        "workspace_root": "/repo",
        "workspace_members": [WORKSPACE_ID],
        "packages": [
            {
                "id": SERDE_ID,
                "name": "serde",
                "version": "1.0.228",
                "source": generate_sbom.CRATES_IO_SOURCE,
                "license": "MIT OR Apache-2.0",
                "manifest_path": "/cargo/registry/src/serde/Cargo.toml",
            },
            {
                "id": WORKSPACE_ID,
                "name": "confidential-inference-openai",
                "version": "0.1.0",
                "source": None,
                "license": "Apache-2.0",
                "manifest_path": "/repo/crates/confidential-inference-openai/Cargo.toml",
            },
        ],
        "resolve": {
            "nodes": [
                {
                    "id": WORKSPACE_ID,
                    "deps": [
                        {
                            "name": "serde",
                            "pkg": SERDE_ID,
                            "dep_kinds": [{"kind": None, "target": None}],
                        }
                    ],
                }
            ]
        },
    }


LOCK_BYTES = b"""
version = 4

[[package]]
name = "confidential-inference-openai"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef"
"""


class GenerateSbomTests(unittest.TestCase):
    def test_build_sbom_is_deterministic_and_includes_lock_checksums(self) -> None:
        first = generate_sbom.build_sbom(fake_metadata(), LOCK_BYTES)
        second = generate_sbom.build_sbom(fake_metadata(), LOCK_BYTES)

        self.assertEqual(first, second)
        self.assertEqual(first["schema"], "confidential-inference.sbom.v1")
        self.assertEqual(first["package_count"], 2)
        self.assertEqual(first["dependency_edge_count"], 1)
        self.assertNotIn("generated_at", first)

        packages = {package["name"]: package for package in first["packages"]}
        self.assertEqual(packages["serde"]["checksum"], "0123456789abcdef")
        self.assertFalse(packages["serde"]["workspace_member"])
        self.assertIsNone(packages["confidential-inference-openai"]["checksum"])
        self.assertTrue(packages["confidential-inference-openai"]["workspace_member"])
        self.assertEqual(
            packages["confidential-inference-openai"]["manifest_path"],
            "crates/confidential-inference-openai/Cargo.toml",
        )

        edge = first["dependency_edges"][0]
        self.assertEqual(edge["from_id"], WORKSPACE_ID)
        self.assertEqual(edge["to_id"], SERDE_ID)
        self.assertEqual(edge["kind"], "normal")

    def test_registry_packages_without_lock_checksum_fail_closed(self) -> None:
        lock_without_checksum = b"""
version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""

        with self.assertRaises(generate_sbom.SbomError):
            generate_sbom.build_sbom(fake_metadata(), lock_without_checksum)


if __name__ == "__main__":
    unittest.main()
