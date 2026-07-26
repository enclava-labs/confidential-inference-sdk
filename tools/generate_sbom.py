#!/usr/bin/env python3
"""Generate a deterministic dependency SBOM from Cargo metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


SCHEMA = "confidential-inference.sbom.v1"
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"


class SbomError(RuntimeError):
    pass


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def parse_lock_checksums(lock_bytes: bytes) -> dict[tuple[str, str, str], str]:
    parsed = tomllib.loads(lock_bytes.decode("utf-8"))
    checksums: dict[tuple[str, str, str], str] = {}
    for package in parsed.get("package", []):
        checksum = package.get("checksum")
        if not checksum:
            continue
        key = (
            str(package["name"]),
            str(package["version"]),
            str(package.get("source") or ""),
        )
        checksums[key] = str(checksum)
    return checksums


def _relative_path(path: str | None, workspace_root: Path) -> str | None:
    if not path:
        return None
    candidate = Path(path)
    try:
        return candidate.resolve().relative_to(workspace_root.resolve()).as_posix()
    except ValueError:
        return candidate.as_posix()


def _package_key(package: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(package["name"]),
        str(package["version"]),
        str(package.get("source") or ""),
    )


def _package_record(
    package: dict[str, Any],
    workspace_root: Path,
    workspace_members: set[str],
    lock_checksums: dict[tuple[str, str, str], str],
) -> dict[str, Any]:
    source = package.get("source")
    checksum = lock_checksums.get(_package_key(package))
    if source == CRATES_IO_SOURCE and not checksum:
        raise SbomError(
            f"registry package {package['name']} {package['version']} is missing a Cargo.lock checksum"
        )

    return {
        "id": package["id"],
        "name": package["name"],
        "version": package["version"],
        "license": package.get("license"),
        "source": source,
        "checksum": checksum,
        "workspace_member": package["id"] in workspace_members,
        "manifest_path": _relative_path(package.get("manifest_path"), workspace_root),
    }


def _dependency_edges(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    resolve = metadata.get("resolve") or {}
    for node in resolve.get("nodes", []):
        from_id = node["id"]
        for dep in node.get("deps", []):
            dep_kinds = dep.get("dep_kinds") or [{"kind": None, "target": None}]
            for dep_kind in dep_kinds:
                edges.append(
                    {
                        "from_id": from_id,
                        "to_id": dep["pkg"],
                        "dependency_name": dep["name"],
                        "kind": dep_kind.get("kind") or "normal",
                        "target": dep_kind.get("target"),
                    }
                )
    return sorted(
        edges,
        key=lambda edge: (
            edge["from_id"],
            edge["to_id"],
            edge["dependency_name"],
            edge["kind"],
            edge["target"] or "",
        ),
    )


def build_sbom(metadata: dict[str, Any], lock_bytes: bytes) -> dict[str, Any]:
    workspace_root = Path(metadata["workspace_root"])
    workspace_members = {str(member) for member in metadata.get("workspace_members", [])}
    lock_checksums = parse_lock_checksums(lock_bytes)
    packages = [
        _package_record(package, workspace_root, workspace_members, lock_checksums)
        for package in metadata.get("packages", [])
    ]
    packages.sort(key=lambda package: (package["name"], package["version"], package["id"]))
    dependency_edges = _dependency_edges(metadata)

    return {
        "schema": SCHEMA,
        "cargo_metadata_format_version": 1,
        "workspace_root": workspace_root.as_posix(),
        "workspace_members": sorted(workspace_members),
        "lockfile_digest": sha256_digest(lock_bytes),
        "package_count": len(packages),
        "dependency_edge_count": len(dependency_edges),
        "packages": packages,
        "dependency_edges": dependency_edges,
    }


def load_metadata(workspace_root: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version=1"],
        cwd=workspace_root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return json.loads(result.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path.cwd(),
        help="Cargo workspace root. Defaults to the current directory.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("target/confidential-inference-sbom.json"),
        help="Output JSON path. Defaults to target/confidential-inference-sbom.json.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the output file already exists and would change.",
    )
    args = parser.parse_args(argv)

    workspace_root = args.workspace_root.resolve()
    lock_path = workspace_root / "Cargo.lock"
    try:
        metadata = load_metadata(workspace_root)
        lock_bytes = lock_path.read_bytes()
        sbom = build_sbom(metadata, lock_bytes)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError, SbomError) as error:
        print(f"generate_sbom.py: {error}", file=sys.stderr)
        return 1

    output = args.output
    if not output.is_absolute():
        output = workspace_root / output

    rendered = json.dumps(sbom, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"
    if args.check and output.exists() and output.read_text(encoding="utf-8") != rendered:
        print(f"generate_sbom.py: {output} is out of date", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
