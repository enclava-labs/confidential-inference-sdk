#!/usr/bin/env python3
"""Validate and build release crate packages for publishable SDK crates."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "confidential-inference.release-packaging-policy.v1"
DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")
BUNDLED_ASSET_MIRRORS = (
    ("fixtures/reference-values/demo-envelope.json", "crates/confidential-inference-attestation/assets/reference-values/demo-envelope.json"),
    ("fixtures/reference-values/phase2-fixtures-envelope.json", "crates/confidential-inference-attestation/assets/reference-values/phase2-fixtures-envelope.json"),
    ("fixtures/providers/compatibility-matrix-envelope.json", "crates/confidential-inference-providers/assets/providers/compatibility-matrix-envelope.json"),
    ("fixtures/evidence/demo-valid.json", "crates/confidential-inference-providers/assets/evidence/demo-valid.json"),
    ("fixtures/evidence/demo-wrong-model.json", "crates/confidential-inference-providers/assets/evidence/demo-wrong-model.json"),
    ("fixtures/evidence/demo-wrong-key.json", "crates/confidential-inference-providers/assets/evidence/demo-wrong-key.json"),
    ("fixtures/evidence/tinfoil-valid.json", "crates/confidential-inference-providers/assets/evidence/tinfoil-valid.json"),
    ("fixtures/evidence/venice-dstack-valid.json", "crates/confidential-inference-providers/assets/evidence/venice-dstack-valid.json"),
    ("fixtures/registry/demo-registry.json", "crates/confidential-inference-providers/assets/registry/demo-registry.json"),
    ("fixtures/registry/phase2-fixtures-registry.json", "crates/confidential-inference-providers/assets/registry/phase2-fixtures-registry.json"),
    ("fixtures/registry/model-alias-matrix-envelope.json", "crates/confidential-inference-providers/assets/registry/model-alias-matrix-envelope.json"),
)


class ReleasePackagingError(RuntimeError):
    pass


def load_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _workspace_members(root_manifest: dict[str, Any]) -> list[str]:
    return [str(member) for member in root_manifest.get("workspace", {}).get("members", [])]


def _dependency_sections(manifest: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for section in DEPENDENCY_SECTIONS:
        deps = manifest.get(section)
        if isinstance(deps, dict):
            yield section, deps
    for target_name, target in manifest.get("target", {}).items():
        if not isinstance(target, dict):
            continue
        for section in DEPENDENCY_SECTIONS:
            deps = target.get(section)
            if isinstance(deps, dict):
                yield f"target.{target_name}.{section}", deps


def _is_publish_disabled(package: dict[str, Any]) -> bool:
    return package.get("publish") is False


def _package_name(manifest_path: Path, manifest: dict[str, Any]) -> str:
    name = manifest.get("package", {}).get("name")
    if not isinstance(name, str) or not name.strip():
        raise ReleasePackagingError(f"{manifest_path}: package.name is required")
    return name


def discover_local_path_patches(
    workspace_root: Path,
    release_packages: list[str],
) -> dict[str, str]:
    """Return crates.io patches needed to package unpublished local dependencies.

    Cargo normalizes path dependencies to registry dependencies while preparing a
    package. Without temporary patches, a workspace cannot package a crate that
    depends on another workspace crate until the dependency has already been
    published. Recursively patching every local dependency keeps the release gate
    useful before the first publish while preserving the normalized archive.
    """

    workspace_root = workspace_root.resolve()
    root_manifest = load_toml(workspace_root / "Cargo.toml")
    workspace_manifests: dict[str, Path] = {}
    for member in _workspace_members(root_manifest):
        manifest_path = (workspace_root / member / "Cargo.toml").resolve()
        manifest = load_toml(manifest_path)
        workspace_manifests[_package_name(manifest_path, manifest)] = manifest_path

    missing = sorted(set(release_packages) - set(workspace_manifests))
    if missing:
        raise ReleasePackagingError(
            "release package manifests are missing from the workspace: " + ", ".join(missing)
        )

    pending = [workspace_manifests[name] for name in release_packages]
    visited: set[Path] = set()
    patch_paths: dict[str, Path] = {}
    while pending:
        manifest_path = pending.pop()
        if manifest_path in visited:
            continue
        visited.add(manifest_path)
        manifest = load_toml(manifest_path)
        for _, dependencies in _dependency_sections(manifest):
            for spec in dependencies.values():
                if not isinstance(spec, dict) or not isinstance(spec.get("path"), str):
                    continue
                dependency_root = (manifest_path.parent / spec["path"]).resolve()
                dependency_manifest_path = dependency_root / "Cargo.toml"
                if not dependency_manifest_path.is_file():
                    raise ReleasePackagingError(
                        f"{manifest_path}: local dependency manifest does not exist: "
                        f"{dependency_manifest_path}"
                    )
                dependency_manifest = load_toml(dependency_manifest_path)
                dependency_name = _package_name(
                    dependency_manifest_path, dependency_manifest
                )
                previous = patch_paths.get(dependency_name)
                if previous is not None and previous != dependency_root:
                    raise ReleasePackagingError(
                        f"local dependency {dependency_name} resolves to both "
                        f"{previous} and {dependency_root}"
                    )
                patch_paths[dependency_name] = dependency_root
                pending.append(dependency_manifest_path)

    patches: dict[str, str] = {}
    for name, path in sorted(patch_paths.items()):
        try:
            patches[name] = path.relative_to(workspace_root).as_posix()
        except ValueError:
            patches[name] = path.as_posix()
    return patches


def _check_path_dependency_versions(
    manifest_path: Path,
    manifest: dict[str, Any],
    violations: list[str],
) -> int:
    checked = 0
    for section, dependencies in _dependency_sections(manifest):
        for name, spec in dependencies.items():
            if not isinstance(spec, dict) or spec.get("path") is None:
                continue
            checked += 1
            version = spec.get("version")
            if not isinstance(version, str) or not version.strip():
                violations.append(
                    f"{manifest_path}:{section}.{name} path dependency must specify version for cargo package"
                )
    return checked


def _check_publishable_package_metadata(
    manifest_path: Path,
    package: dict[str, Any],
    violations: list[str],
) -> None:
    description = package.get("description")
    if not isinstance(description, str) or not description.strip():
        violations.append(f"{manifest_path}:package.description is required for release packaging")


def inspect_workspace(workspace_root: Path) -> dict[str, object]:
    workspace_root = workspace_root.resolve()
    root_manifest_path = workspace_root / "Cargo.toml"
    root_manifest = load_toml(root_manifest_path)
    violations: list[str] = []
    release_packages: list[str] = []
    skipped_packages: list[str] = []
    path_dependencies_checked = 0

    if (workspace_root / "fixtures").is_dir():
        for source_relative, bundled_relative in BUNDLED_ASSET_MIRRORS:
            source = workspace_root / source_relative
            bundled = workspace_root / bundled_relative
            if not source.is_file():
                violations.append(f"{source}: canonical bundled asset source is missing")
            elif not bundled.is_file():
                violations.append(f"{bundled}: packaged bundled asset is missing")
            elif source.read_bytes() != bundled.read_bytes():
                violations.append(
                    f"{bundled}: packaged bundled asset differs from {source_relative}"
                )

    for member in _workspace_members(root_manifest):
        manifest_path = workspace_root / member / "Cargo.toml"
        if not manifest_path.exists():
            violations.append(f"{manifest_path}: workspace member manifest does not exist")
            continue
        manifest = load_toml(manifest_path)
        package = manifest.get("package", {})
        try:
            name = _package_name(manifest_path, manifest)
        except ReleasePackagingError as error:
            violations.append(str(error))
            continue
        if _is_publish_disabled(package):
            skipped_packages.append(name)
            continue
        release_packages.append(name)
        _check_publishable_package_metadata(manifest_path, package, violations)
        path_dependencies_checked += _check_path_dependency_versions(
            manifest_path, manifest, violations
        )

    if not release_packages:
        violations.append("no publishable workspace packages found")

    return {
        "schema": SCHEMA,
        "workspace_root": workspace_root.as_posix(),
        "release_packages": release_packages,
        "release_package_count": len(release_packages),
        "skipped_packages": skipped_packages,
        "path_dependencies_checked": path_dependencies_checked,
        "violations": sorted(violations),
    }


def cargo_package_command(
    packages: list[str],
    allow_dirty: bool,
    path_patches: dict[str, str] | None = None,
) -> list[str]:
    command = ["cargo", "package", "--locked"]
    if allow_dirty:
        command.append("--allow-dirty")
    for name, path in sorted((path_patches or {}).items()):
        command.extend(
            ["--config", f"patch.crates-io.{name}.path={json.dumps(path)}"]
        )
    for package in packages:
        command.extend(["-p", package])
    return command


def clean_target_package_archives(workspace_root: Path) -> int:
    package_dir = workspace_root / "target" / "package"
    if not package_dir.exists():
        return 0
    removed = 0
    for path in package_dir.iterdir():
        if path.is_file() and path.suffix == ".crate":
            path.unlink()
            removed += 1
    return removed


def run_cargo_package(
    workspace_root: Path,
    packages: list[str],
    allow_dirty: bool,
    clean_first: bool = True,
) -> tuple[int, list[str]]:
    if clean_first:
        clean_target_package_archives(workspace_root)
    path_patches = discover_local_path_patches(workspace_root, packages)
    command = cargo_package_command(packages, allow_dirty, path_patches)
    completed = subprocess.run(command, cwd=workspace_root, check=False)
    return completed.returncode, command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path.cwd(),
        help="Cargo workspace root. Defaults to the current directory.",
    )
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="Do not pass --allow-dirty to cargo package.",
    )
    parser.add_argument(
        "--skip-cargo-package",
        action="store_true",
        help="Only inspect manifests; do not run cargo package.",
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Do not remove existing target/package/*.crate archives before packaging.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full validation report as JSON.",
    )
    args = parser.parse_args(argv)

    workspace_root = args.workspace_root.resolve()
    try:
        report = inspect_workspace(workspace_root)
    except (OSError, tomllib.TOMLDecodeError, ReleasePackagingError) as error:
        print(f"check_release_packaging.py: {error}", file=sys.stderr)
        return 1

    if report["violations"]:
        if args.json:
            print(json.dumps(report, sort_keys=True, indent=2, separators=(",", ": ")))
        else:
            for violation in report["violations"]:
                print(f"release packaging policy violation: {violation}", file=sys.stderr)
        return 1

    command: list[str] = []
    if not args.skip_cargo_package:
        try:
            returncode, command = run_cargo_package(
                workspace_root,
                list(report["release_packages"]),
                allow_dirty=not args.require_clean,
                clean_first=not args.no_clean,
            )
        except (OSError, tomllib.TOMLDecodeError, ReleasePackagingError) as error:
            print(f"check_release_packaging.py: {error}", file=sys.stderr)
            return 1
        if returncode != 0:
            print(
                "check_release_packaging.py: cargo package failed: "
                + " ".join(command),
                file=sys.stderr,
            )
            return returncode

    report["cargo_package_command"] = command
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2, separators=(",", ": ")))
    else:
        print(
            "release packaging ok: "
            f"packages={report['release_package_count']} "
            f"path_dependencies={report['path_dependencies_checked']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
