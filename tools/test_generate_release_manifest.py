from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("generate_release_manifest.py")
TOOLS_DIR = MODULE_PATH.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
SPEC = importlib.util.spec_from_file_location("generate_release_manifest", MODULE_PATH)
assert SPEC is not None
generate_release_manifest = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(generate_release_manifest)


class GenerateReleaseManifestTests(unittest.TestCase):
    def test_manifest_is_deterministic_and_binds_artifacts_lockfile_and_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.toml").write_text(
                """
[workspace]

[workspace.package]
version = "0.1.0"
rust-version = "1.75"
license = "Apache-2.0"
repository = "https://github.com/enclava-labs/confidential-inference-sdk"
""".lstrip(),
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            dist = root / "dist"
            dist.mkdir()
            (dist / "b.tar.gz").write_bytes(b"second artifact")
            (dist / "a.tar.gz").write_bytes(b"first artifact")
            sbom = root / "target" / "confidential-inference-sbom.json"
            sbom.parent.mkdir()
            sbom.write_text('{"schema":"confidential-inference.sbom.v1"}\n', encoding="utf-8")

            first = generate_release_manifest.build_release_manifest(
                root,
                [Path("dist/b.tar.gz"), Path("dist/a.tar.gz")],
                Path("target/confidential-inference-sbom.json"),
            )
            second = generate_release_manifest.build_release_manifest(
                root,
                [Path("dist/a.tar.gz"), Path("dist/b.tar.gz")],
                Path("target/confidential-inference-sbom.json"),
            )

            self.assertEqual(first, second)
            self.assertEqual(first["schema"], "confidential-inference.release-manifest.v1")
            self.assertEqual(first["workspace_package"]["rust_version"], "1.75")
            self.assertEqual(first["artifact_count"], 2)
            self.assertEqual(
                [artifact["path"] for artifact in first["artifacts"]],
                ["dist/a.tar.gz", "dist/b.tar.gz"],
            )
            self.assertEqual(first["artifacts"][0]["size"], len(b"first artifact"))
            self.assertTrue(first["artifacts"][0]["sha256"].startswith("sha256:"))
            self.assertEqual(first["sbom"]["path"], "target/confidential-inference-sbom.json")
            self.assertIn("cargo_lock_digest", first)
            self.assertNotIn("generated_at", first)

            rendered = generate_release_manifest.render_manifest(first)
            reparsed = json.loads(rendered)
            self.assertEqual(reparsed, first)

            seed = bytes(range(32))
            seed_base64url = generate_release_manifest.encode_unpadded_base64url(seed)
            signature = generate_release_manifest.build_release_manifest_signature(
                root,
                root / "target" / "confidential-inference-release-manifest.json",
                first,
                "confidential-inference-release-test",
                "release-test-key",
                seed_base64url,
            )

            self.assertEqual(
                signature["schema"], "confidential-inference.release-manifest-signature.v1"
            )
            self.assertEqual(
                signature["manifest_path"], "target/confidential-inference-release-manifest.json"
            )
            self.assertEqual(
                signature["manifest_sha256"],
                generate_release_manifest.sha256_digest(rendered.encode("utf-8")),
            )
            self.assertEqual(signature["signature"]["alg"], "ed25519")
            self.assertTrue(signature["signature"]["value"].startswith("base64url:"))
            self.assertEqual(
                signature["public_key_base64url"],
                generate_release_manifest.encode_unpadded_base64url(
                    generate_release_manifest.ed25519_public_key_from_seed(seed)
                ),
            )

            rendered_signature = generate_release_manifest.render_signature(signature)
            self.assertEqual(json.loads(rendered_signature), signature)

    def test_manifest_rejects_missing_duplicate_and_outside_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.toml").write_text(
                "[workspace]\n[workspace.package]\nversion = \"0.1.0\"\n",
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            artifact = root / "dist.tar.gz"
            artifact.write_bytes(b"release")
            outside = Path(temp).parent / "outside-release-artifact"
            outside.write_bytes(b"outside")
            try:
                with self.assertRaises(generate_release_manifest.ReleaseManifestError):
                    generate_release_manifest.build_release_manifest(root, [])
                with self.assertRaises(generate_release_manifest.ReleaseManifestError):
                    generate_release_manifest.build_release_manifest(
                        root, [Path("dist.tar.gz"), Path("dist.tar.gz")]
                    )
                with self.assertRaises(generate_release_manifest.ReleaseManifestError):
                    generate_release_manifest.build_release_manifest(root, [Path("missing.tgz")])
                with self.assertRaises(generate_release_manifest.ReleaseManifestError):
                    generate_release_manifest.build_release_manifest(root, [outside])
            finally:
                outside.unlink(missing_ok=True)

    def test_artifact_globs_expand_deterministically_and_fail_when_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dist = root / "target" / "package"
            dist.mkdir(parents=True)
            (dist / "b.crate").write_bytes(b"second")
            (dist / "a.crate").write_bytes(b"first")
            (dist / ".stale-demo.crate").write_bytes(b"hidden")

            artifacts = generate_release_manifest.expand_artifact_inputs(
                root, [Path("target/manual.crate")], ["target/package/*.crate"]
            )

            self.assertEqual(
                [path.as_posix() for path in artifacts],
                [
                    "target/manual.crate",
                    (dist / "a.crate").as_posix(),
                    (dist / "b.crate").as_posix(),
                ],
            )
            with self.assertRaises(generate_release_manifest.ReleaseManifestError):
                generate_release_manifest.expand_artifact_inputs(
                    root, [], ["target/package/*.missing"]
                )

    def test_signature_generation_requires_valid_signing_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.toml").write_text(
                "[workspace]\n[workspace.package]\nversion = \"0.1.0\"\n",
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            artifact = root / "dist.tar.gz"
            artifact.write_bytes(b"release")
            manifest = generate_release_manifest.build_release_manifest(
                root, [Path("dist.tar.gz")]
            )

            with self.assertRaises(generate_release_manifest.ReleaseManifestError):
                generate_release_manifest.build_release_manifest_signature(
                    root,
                    root / "target" / "confidential-inference-release-manifest.json",
                    manifest,
                    "",
                    "release-test-key",
                    generate_release_manifest.encode_unpadded_base64url(bytes(range(32))),
                )
            with self.assertRaises(generate_release_manifest.ReleaseManifestError):
                generate_release_manifest.build_release_manifest_signature(
                    root,
                    root / "target" / "confidential-inference-release-manifest.json",
                    manifest,
                    "confidential-inference-release-test",
                    "release-test-key",
                    "not-base64url",
                )


if __name__ == "__main__":
    unittest.main()
