#!/usr/bin/env python3
"""Generate a deterministic checksum manifest for release artifacts."""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import stat
import sys
import tomllib
from pathlib import Path
from typing import Any

from artifact_signatures import (
    ArtifactSignatureError,
    decode_unpadded_base64url,
    ed25519_public_key_from_seed,
    encode_unpadded_base64url,
    sign_ed25519,
)


SCHEMA = "confidential-inference.release-manifest.v1"
SIGNATURE_SCHEMA = "confidential-inference.release-manifest-signature.v1"
SIGNING_CANONICALIZATION = "utf8-json-sort-keys-indent-2-trailing-newline"


class ReleaseManifestError(RuntimeError):
    pass


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _relative_path(path: Path, workspace_root: Path) -> str:
    try:
        return path.resolve().relative_to(workspace_root.resolve()).as_posix()
    except ValueError as error:
        raise ReleaseManifestError(
            f"release artifact {path} is outside workspace root {workspace_root}"
        ) from error


def _workspace_package_metadata(workspace_root: Path) -> dict[str, Any]:
    cargo_toml = workspace_root / "Cargo.toml"
    parsed = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    package = parsed.get("workspace", {}).get("package", {})
    return {
        "version": package.get("version"),
        "rust_version": package.get("rust-version"),
        "license": package.get("license"),
        "repository": package.get("repository"),
    }


def _artifact_record(path: Path, workspace_root: Path) -> dict[str, Any]:
    if not path.exists():
        raise ReleaseManifestError(f"release artifact {path} does not exist")
    if not path.is_file():
        raise ReleaseManifestError(f"release artifact {path} is not a regular file")

    data = path.read_bytes()
    mode = stat.S_IMODE(path.stat().st_mode)
    return {
        "path": _relative_path(path, workspace_root),
        "size": len(data),
        "sha256": sha256_digest(data),
        "mode": format(mode, "04o"),
    }


def build_release_manifest(
    workspace_root: Path,
    artifacts: list[Path],
    sbom_path: Path | None = None,
) -> dict[str, Any]:
    workspace_root = workspace_root.resolve()
    cargo_lock = workspace_root / "Cargo.lock"
    if not artifacts:
        raise ReleaseManifestError("at least one release artifact is required")

    seen: set[str] = set()
    artifact_records = []
    for artifact in artifacts:
        path = artifact if artifact.is_absolute() else workspace_root / artifact
        relative = _relative_path(path, workspace_root)
        if relative in seen:
            raise ReleaseManifestError(f"duplicate release artifact path {relative}")
        seen.add(relative)
        artifact_records.append(_artifact_record(path, workspace_root))
    artifact_records.sort(key=lambda record: record["path"])

    manifest = {
        "schema": SCHEMA,
        "workspace_package": _workspace_package_metadata(workspace_root),
        "cargo_lock_digest": sha256_digest(cargo_lock.read_bytes()),
        "artifact_count": len(artifact_records),
        "artifacts": artifact_records,
        "signing_payload": {
            "format": "json",
            "canonicalization": SIGNING_CANONICALIZATION,
            "required_release_signatures": [
                "detached ed25519 signature over canonical manifest bytes"
            ],
        },
    }

    if sbom_path is not None:
        resolved_sbom = sbom_path if sbom_path.is_absolute() else workspace_root / sbom_path
        if not resolved_sbom.exists():
            raise ReleaseManifestError(f"SBOM {resolved_sbom} does not exist")
        manifest["sbom"] = {
            "path": _relative_path(resolved_sbom, workspace_root),
            "sha256": sha256_digest(resolved_sbom.read_bytes()),
        }

    return manifest


def expand_artifact_inputs(
    workspace_root: Path,
    artifacts: list[Path],
    artifact_globs: list[str],
) -> list[Path]:
    expanded = list(artifacts)
    for pattern in artifact_globs:
        if Path(pattern).is_absolute():
            matches = [Path(match) for match in glob.glob(pattern)]
        else:
            matches = list(workspace_root.glob(pattern))
        matches = [path for path in matches if not path.name.startswith(".")]
        if not matches:
            raise ReleaseManifestError(f"artifact glob matched no files: {pattern}")
        expanded.extend(sorted(matches))
    return expanded


def render_manifest(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"


def build_release_manifest_signature(
    workspace_root: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    signer: str,
    key_id: str,
    seed_base64url: str,
) -> dict[str, Any]:
    if not signer:
        raise ReleaseManifestError("release signature signer must not be empty")
    if not key_id:
        raise ReleaseManifestError("release signature key id must not be empty")

    try:
        seed = decode_unpadded_base64url(
            seed_base64url,
            "release signing key seed",
            expected_len=32,
        )
        public_key = ed25519_public_key_from_seed(seed)
        rendered = render_manifest(manifest).encode("utf-8")
        signature = sign_ed25519(seed, rendered)
    except ArtifactSignatureError as error:
        raise ReleaseManifestError(str(error)) from error

    return {
        "schema": SIGNATURE_SCHEMA,
        "manifest_path": _relative_path(manifest_path, workspace_root),
        "manifest_sha256": sha256_digest(rendered),
        "signed_payload": {
            "format": "raw-bytes",
            "canonicalization": SIGNING_CANONICALIZATION,
        },
        "signature": {
            "signer": signer,
            "key_id": key_id,
            "alg": "ed25519",
            "value": "base64url:" + encode_unpadded_base64url(signature),
        },
        "public_key_base64url": encode_unpadded_base64url(public_key),
    }


def render_signature(signature: dict[str, Any]) -> str:
    return json.dumps(signature, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path.cwd(),
        help="Cargo workspace root. Defaults to the current directory.",
    )
    parser.add_argument(
        "--artifact",
        type=Path,
        action="append",
        default=[],
        help="Release artifact to include. May be repeated.",
    )
    parser.add_argument(
        "--artifact-glob",
        action="append",
        default=[],
        help="Workspace-relative or absolute glob of release artifacts to include. May be repeated.",
    )
    parser.add_argument(
        "--sbom",
        type=Path,
        help="Optional SBOM file to bind into the release manifest.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("target/confidential-inference-release-manifest.json"),
        help="Output JSON path. Defaults to target/confidential-inference-release-manifest.json.",
    )
    parser.add_argument(
        "--signature-output",
        type=Path,
        help="Optional detached release-manifest signature output path.",
    )
    parser.add_argument(
        "--signature-key-seed-env",
        help=(
            "Environment variable containing an unpadded base64url 32-byte "
            "Ed25519 seed used to sign --signature-output."
        ),
    )
    parser.add_argument(
        "--signature-signer",
        default="confidential-inference-release",
        help="Signer identity to record in --signature-output.",
    )
    parser.add_argument(
        "--signature-key-id",
        default="confidential-inference-release-ed25519",
        help="Signing key id to record in --signature-output.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the output file already exists and would change.",
    )
    args = parser.parse_args(argv)

    workspace_root = args.workspace_root.resolve()
    try:
        artifacts = expand_artifact_inputs(
            workspace_root, args.artifact, args.artifact_glob
        )
        manifest = build_release_manifest(workspace_root, artifacts, args.sbom)
    except (OSError, ReleaseManifestError, tomllib.TOMLDecodeError) as error:
        print(f"generate_release_manifest.py: {error}", file=sys.stderr)
        return 1

    output = args.output
    if not output.is_absolute():
        output = workspace_root / output
    rendered = render_manifest(manifest)

    if args.check and output.exists() and output.read_text(encoding="utf-8") != rendered:
        print(f"generate_release_manifest.py: {output} is out of date", file=sys.stderr)
        return 1

    signature_output = args.signature_output
    rendered_signature = None
    if signature_output is not None:
        if not args.signature_key_seed_env:
            print(
                "generate_release_manifest.py: --signature-key-seed-env is required "
                "when --signature-output is set",
                file=sys.stderr,
            )
            return 1
        seed_base64url = os.environ.get(args.signature_key_seed_env)
        if not seed_base64url:
            print(
                "generate_release_manifest.py: "
                f"{args.signature_key_seed_env} is not set",
                file=sys.stderr,
            )
            return 1
        if not signature_output.is_absolute():
            signature_output = workspace_root / signature_output
        try:
            rendered_signature = render_signature(
                build_release_manifest_signature(
                    workspace_root,
                    output,
                    manifest,
                    args.signature_signer,
                    args.signature_key_id,
                    seed_base64url,
                )
            )
        except ReleaseManifestError as error:
            print(f"generate_release_manifest.py: {error}", file=sys.stderr)
            return 1
        if (
            args.check
            and signature_output.exists()
            and signature_output.read_text(encoding="utf-8") != rendered_signature
        ):
            print(
                f"generate_release_manifest.py: {signature_output} is out of date",
                file=sys.stderr,
            )
            return 1

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    if signature_output is not None and rendered_signature is not None:
        signature_output.parent.mkdir(parents=True, exist_ok=True)
        signature_output.write_text(rendered_signature, encoding="utf-8")
        print(signature_output)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
