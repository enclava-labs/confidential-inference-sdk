#!/usr/bin/env python3
"""Check Rust baseline, dependency-pinning, and binding package policy."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "confidential-inference.supply-chain-policy.v1"
REGISTRY_SOURCE_PREFIX = "registry+"
GIT_SOURCE_PREFIX = "git+"
NODE_BINDING_RELATIVE = Path("bindings/node")
NODE_BINDING_PACKAGE_NAME = "confidential-inference-sdk"
NODE_BINDING_ALLOWED_LICENSES = {
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MIT",
}
NODE_BINDING_ALLOWED_INSTALL_SCRIPT_PACKAGES = {"node_modules/koffi"}
DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")
WORKSPACE_INHERITED_PACKAGE_FIELDS = (
    "version",
    "edition",
    "license",
    "repository",
    "rust-version",
)
SEMVER_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$")
NODE_EXACT_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
RUSTSEC_ID_RE = re.compile(r"^RUSTSEC-\d{4}-\d{4}$")
SDK_CRATE_ALLOWED_DEPENDENCIES = {
    "confidential-inference-attestation": set(),
    "confidential-inference-openai": set(),
    "confidential-inference-providers": {"confidential-inference-attestation", "confidential-inference-openai"},
    "confidential-inference-sdk": {
        "confidential-inference-attestation",
        "confidential-inference-openai",
        "confidential-inference-providers",
    },
    "confidential-inference-middleware": {"confidential-inference-sdk", "confidential-inference-openai"},
    "confidential-inference-proxy": {"confidential-inference-sdk", "confidential-inference-openai"},
    "confidential-inference-ffi": {"confidential-inference-sdk"},
}
INDEPENDENT_FORK_PACKAGES: set[str] = set()
DENY_ALLOWED_LICENSES = {
    "Apache-2.0",
    "BSD-3-Clause",
    "CDLA-Permissive-2.0",
    "ISC",
    "MIT",
    "Unicode-3.0",
    "Zlib",
}


class SupplyChainPolicyError(RuntimeError):
    pass


def load_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _workspace_package(root_manifest: dict[str, Any]) -> dict[str, Any]:
    return root_manifest.get("workspace", {}).get("package", {})


def _workspace_members(root_manifest: dict[str, Any]) -> list[str]:
    return [str(member) for member in root_manifest.get("workspace", {}).get("members", [])]


def _member_manifest_paths(workspace_root: Path, root_manifest: dict[str, Any]) -> list[Path]:
    paths = []
    for member in _workspace_members(root_manifest):
        manifest_path = workspace_root / member / "Cargo.toml"
        if not manifest_path.exists():
            raise SupplyChainPolicyError(f"workspace member {member} has no Cargo.toml")
        paths.append(manifest_path)
    return sorted(paths)


def _is_workspace_inherited(value: Any) -> bool:
    return isinstance(value, dict) and value.get("workspace") is True


def _is_bad_version_requirement(version: str) -> bool:
    stripped = version.strip()
    return not stripped or stripped == "*" or "*" in stripped


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


def _check_dependency_spec(
    workspace_root: Path,
    manifest_path: Path,
    section: str,
    name: str,
    spec: Any,
    violations: list[str],
) -> None:
    prefix = f"{manifest_path}:{section}.{name}"
    if isinstance(spec, str):
        if _is_bad_version_requirement(spec):
            violations.append(f"{prefix} uses an unpinned or wildcard version requirement")
        return

    if not isinstance(spec, dict):
        violations.append(f"{prefix} uses an unsupported dependency specification")
        return

    if spec.get("git"):
        violations.append(f"{prefix} uses a git dependency instead of a reviewed registry/path input")
    if spec.get("registry"):
        violations.append(f"{prefix} overrides the registry source")
    if spec.get("workspace") is True:
        return

    path = spec.get("path")
    if path is not None:
        path_value = Path(str(path))
        if path_value.is_absolute():
            violations.append(f"{prefix} uses an absolute path dependency")
        resolved = (manifest_path.parent / path_value).resolve()
        if not resolved.exists():
            violations.append(f"{prefix} path dependency does not exist: {path}")
        try:
            resolved.relative_to(workspace_root)
        except ValueError:
            violations.append(f"{prefix} path dependency escapes workspace root: {path}")
        return

    version = spec.get("version")
    if version is None:
        violations.append(f"{prefix} is a registry dependency without a version requirement")
    elif not isinstance(version, str) or _is_bad_version_requirement(version):
        violations.append(f"{prefix} uses an unpinned or wildcard version requirement")


def _check_package_inheritance(manifest_path: Path, manifest: dict[str, Any]) -> list[str]:
    violations = []
    package = manifest.get("package", {})
    for field in WORKSPACE_INHERITED_PACKAGE_FIELDS:
        if not _is_workspace_inherited(package.get(field)):
            violations.append(f"{manifest_path}:package.{field} must inherit workspace.{field}")
    return violations


def _package_name(manifest: dict[str, Any]) -> str | None:
    name = manifest.get("package", {}).get("name")
    return name if isinstance(name, str) else None


def _dependency_package_name(name: str, spec: Any) -> str:
    if isinstance(spec, dict) and isinstance(spec.get("package"), str):
        return spec["package"]
    return name


def _check_sdk_dependency_boundaries(
    manifest_path: Path,
    manifest: dict[str, Any],
) -> tuple[int, list[str]]:
    package_name = _package_name(manifest)
    if package_name not in SDK_CRATE_ALLOWED_DEPENDENCIES:
        return 0, []

    allowed = SDK_CRATE_ALLOWED_DEPENDENCIES[package_name]
    sdk_crates = set(SDK_CRATE_ALLOWED_DEPENDENCIES)
    edges_checked = 0
    violations = []
    for section, dependencies in _dependency_sections(manifest):
        for dependency_name, spec in dependencies.items():
            dependency_package = _dependency_package_name(dependency_name, spec)
            if dependency_package not in sdk_crates:
                continue
            edges_checked += 1
            if dependency_package not in allowed:
                violations.append(
                    f"{manifest_path}:{section}.{dependency_name} violates SDK dependency boundary: "
                    f"{package_name} must not depend on {dependency_package}"
                )
    return edges_checked, violations


def _check_lockfile(lock_path: Path) -> tuple[int, list[str]]:
    parsed = load_toml(lock_path)
    violations = []
    package_count = 0
    for package in parsed.get("package", []):
        package_count += 1
        name = package.get("name")
        version = package.get("version")
        source = str(package.get("source") or "")
        if source.startswith(GIT_SOURCE_PREFIX):
            violations.append(f"{lock_path}: package {name} {version} resolves from git source {source}")
        if source.startswith(REGISTRY_SOURCE_PREFIX) and not package.get("checksum"):
            violations.append(
                f"{lock_path}: registry package {name} {version} is missing a checksum"
            )
    return package_count, violations


def _load_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise SupplyChainPolicyError(f"{path}: JSON root must be an object")
    return loaded


def _is_exact_node_version(version: Any) -> bool:
    return isinstance(version, str) and NODE_EXACT_SEMVER_RE.match(version) is not None


def _node_dependency_sections(package_json: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for section in ("dependencies", "optionalDependencies"):
        dependencies = package_json.get(section, {})
        if dependencies is None:
            continue
        if isinstance(dependencies, dict):
            yield section, dependencies


def _check_node_dependency_specs(
    package_json_path: Path,
    package_json: dict[str, Any],
    violations: list[str],
) -> int:
    checked = 0
    for section, dependencies in _node_dependency_sections(package_json):
        for name, version in dependencies.items():
            checked += 1
            if not _is_exact_node_version(version):
                violations.append(
                    f"{package_json_path}:{section}.{name} must use an exact pinned semver version"
                )
    for section in ("devDependencies", "peerDependencies", "bundledDependencies"):
        if section in package_json:
            violations.append(
                f"{package_json_path}:{section} is not allowed for the Node binding package"
            )
    return checked


def _check_node_lockfile(
    package_json_path: Path,
    package_json: dict[str, Any],
    lock_path: Path,
    violations: list[str],
) -> int:
    if not lock_path.exists():
        violations.append(f"{lock_path}: package-lock.json is required for Node binding pinning")
        return 0

    lock = _load_json(lock_path)
    if lock.get("lockfileVersion") != 3:
        violations.append(f"{lock_path}: lockfileVersion must be 3")
    if lock.get("name") != package_json.get("name"):
        violations.append(f"{lock_path}: top-level name must match {package_json_path}")
    if lock.get("version") != package_json.get("version"):
        violations.append(f"{lock_path}: top-level version must match {package_json_path}")

    packages = lock.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        violations.append(f"{lock_path}: packages object with root entry is required")
        return 0

    root_package = packages[""]
    if not isinstance(root_package, dict):
        violations.append(f"{lock_path}: root package entry must be an object")
        return 0
    for field in ("name", "version", "license", "engines", "dependencies"):
        if root_package.get(field) != package_json.get(field):
            violations.append(f"{lock_path}: root package {field} must match {package_json_path}")

    package_count = 0
    for package_path, package in packages.items():
        if package_path == "":
            continue
        package_count += 1
        if not isinstance(package, dict):
            violations.append(f"{lock_path}:{package_path} lock entry must be an object")
            continue
        version = package.get("version")
        if not _is_exact_node_version(version):
            violations.append(f"{lock_path}:{package_path} version must be exact pinned semver")
        resolved = package.get("resolved")
        if not isinstance(resolved, str) or not resolved.startswith(
            "https://registry.npmjs.org/"
        ):
            violations.append(
                f"{lock_path}:{package_path} resolved URL must use https://registry.npmjs.org/"
            )
        integrity = package.get("integrity")
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            violations.append(f"{lock_path}:{package_path} integrity must be a sha512 lock digest")
        license_id = package.get("license")
        if license_id not in NODE_BINDING_ALLOWED_LICENSES:
            violations.append(
                f"{lock_path}:{package_path} license {license_id!r} is not allowed"
            )
        if package.get("hasInstallScript") and (
            package_path not in NODE_BINDING_ALLOWED_INSTALL_SCRIPT_PACKAGES
        ):
            violations.append(
                f"{lock_path}:{package_path} has an install script but is not allow-listed"
            )
    return package_count


def _check_node_binding_policy(workspace_root: Path) -> tuple[int, int, list[str]]:
    binding_root = workspace_root / NODE_BINDING_RELATIVE
    package_json_path = binding_root / "package.json"
    lock_path = binding_root / "package-lock.json"
    if not binding_root.exists():
        return 0, 0, []

    violations: list[str] = []
    if not package_json_path.exists():
        return 0, 0, [f"{package_json_path}: package.json is required for Node binding policy"]

    package_json = _load_json(package_json_path)
    if package_json.get("name") != NODE_BINDING_PACKAGE_NAME:
        violations.append(
            f"{package_json_path}: name must be {NODE_BINDING_PACKAGE_NAME}"
        )
    if package_json.get("license") != "MIT":
        violations.append(f"{package_json_path}: license must be MIT")
    if package_json.get("private") is not True:
        violations.append(
            f"{package_json_path}: private must remain true until publish policy exists"
        )
    scripts = package_json.get("scripts")
    if scripts != {"test": "node --test test/*.test.js"}:
        violations.append(
            f"{package_json_path}: scripts must only contain the reviewed test command"
        )
    engines = package_json.get("engines")
    if not isinstance(engines, dict) or engines.get("node") != ">=22":
        violations.append(f"{package_json_path}: engines.node must be >=22")

    dependencies_checked = _check_node_dependency_specs(
        package_json_path,
        package_json,
        violations,
    )
    package_count = _check_node_lockfile(package_json_path, package_json, lock_path, violations)
    return dependencies_checked, package_count, violations


def _check_deny_policy(deny_path: Path) -> list[str]:
    if not deny_path.exists():
        return [f"{deny_path}: deny.toml is required for advisory/license/source policy"]

    try:
        deny = load_toml(deny_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{deny_path}: cannot load deny.toml: {error}"]

    violations: list[str] = []
    advisories = deny.get("advisories")
    if not isinstance(advisories, dict):
        violations.append(f"{deny_path}: [advisories] policy is required")
    else:
        if advisories.get("version") != 2:
            violations.append(f"{deny_path}: advisories.version must be 2")
        ignores = advisories.get("ignore", [])
        if not isinstance(ignores, list) or not all(
            isinstance(ignore, str) and RUSTSEC_ID_RE.match(ignore) for ignore in ignores
        ):
            violations.append(
                f"{deny_path}: advisories.ignore must list explicit RUSTSEC ids"
            )

    licenses = deny.get("licenses")
    if not isinstance(licenses, dict):
        violations.append(f"{deny_path}: [licenses] policy is required")
    else:
        if licenses.get("version") != 2:
            violations.append(f"{deny_path}: licenses.version must be 2")
        allow = licenses.get("allow")
        if not isinstance(allow, list) or not all(isinstance(item, str) for item in allow):
            violations.append(f"{deny_path}: licenses.allow must be a string array")
        elif set(allow) != DENY_ALLOWED_LICENSES:
            violations.append(
                f"{deny_path}: licenses.allow must match reviewed SDK license allow-list"
            )
        threshold = licenses.get("confidence-threshold")
        if not isinstance(threshold, (int, float)) or threshold < 0.8:
            violations.append(
                f"{deny_path}: licenses.confidence-threshold must be at least 0.8"
            )

    bans = deny.get("bans")
    if not isinstance(bans, dict):
        violations.append(f"{deny_path}: [bans] policy is required")
    else:
        if bans.get("wildcards") != "deny":
            violations.append(f"{deny_path}: bans.wildcards must be deny")
        if bans.get("multiple-versions") not in {"warn", "deny"}:
            violations.append(
                f"{deny_path}: bans.multiple-versions must be warn or deny"
            )

    sources = deny.get("sources")
    if not isinstance(sources, dict):
        violations.append(f"{deny_path}: [sources] policy is required")
    else:
        if sources.get("unknown-registry") != "deny":
            violations.append(f"{deny_path}: sources.unknown-registry must be deny")
        if sources.get("unknown-git") != "deny":
            violations.append(f"{deny_path}: sources.unknown-git must be deny")

    return violations


def check_workspace(workspace_root: Path) -> dict[str, Any]:
    workspace_root = workspace_root.resolve()
    root_manifest_path = workspace_root / "Cargo.toml"
    lock_path = workspace_root / "Cargo.lock"
    deny_path = workspace_root / "deny.toml"
    root_manifest = load_toml(root_manifest_path)

    violations: list[str] = []
    workspace_package = _workspace_package(root_manifest)
    rust_version = workspace_package.get("rust-version")
    if not isinstance(rust_version, str) or not SEMVER_RE.match(rust_version):
        violations.append(f"{root_manifest_path}: workspace.package.rust-version is missing or invalid")
    if not lock_path.exists():
        violations.append(f"{lock_path}: Cargo.lock is required for release dependency pinning")
    violations.extend(_check_deny_policy(deny_path))

    dependency_specs_checked = 0
    sdk_dependency_edges_checked = 0
    manifest_paths = [root_manifest_path]
    try:
        manifest_paths.extend(_member_manifest_paths(workspace_root, root_manifest))
    except SupplyChainPolicyError as error:
        violations.append(str(error))

    for manifest_path in manifest_paths:
        manifest = root_manifest if manifest_path == root_manifest_path else load_toml(manifest_path)
        if (
            manifest_path != root_manifest_path
            and _package_name(manifest) not in INDEPENDENT_FORK_PACKAGES
        ):
            violations.extend(_check_package_inheritance(manifest_path, manifest))
        edges_checked, boundary_violations = _check_sdk_dependency_boundaries(manifest_path, manifest)
        sdk_dependency_edges_checked += edges_checked
        violations.extend(boundary_violations)
        for section, dependencies in _dependency_sections(manifest):
            for name, spec in dependencies.items():
                dependency_specs_checked += 1
                _check_dependency_spec(
                    workspace_root,
                    manifest_path,
                    section,
                    name,
                    spec,
                    violations,
                )

    lock_package_count = 0
    if lock_path.exists():
        lock_package_count, lock_violations = _check_lockfile(lock_path)
        violations.extend(lock_violations)

    (
        node_dependency_specs_checked,
        node_lock_package_count,
        node_violations,
    ) = _check_node_binding_policy(workspace_root)
    violations.extend(node_violations)

    return {
        "schema": SCHEMA,
        "workspace_root": workspace_root.as_posix(),
        "workspace_rust_version": rust_version,
        "workspace_members": _workspace_members(root_manifest),
        "workspace_member_count": len(_workspace_members(root_manifest)),
        "dependency_specs_checked": dependency_specs_checked,
        "sdk_dependency_edges_checked": sdk_dependency_edges_checked,
        "lock_package_count": lock_package_count,
        "node_binding_dependency_specs_checked": node_dependency_specs_checked,
        "node_binding_lock_package_count": node_lock_package_count,
        "violations": sorted(violations),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path.cwd(),
        help="Cargo workspace root. Defaults to the current directory.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full policy report as JSON.",
    )
    args = parser.parse_args(argv)

    try:
        report = check_workspace(args.workspace_root)
    except (OSError, tomllib.TOMLDecodeError, SupplyChainPolicyError) as error:
        print(f"check_supply_chain_policy.py: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2, separators=(",", ": ")))
    elif report["violations"]:
        for violation in report["violations"]:
            print(f"policy violation: {violation}", file=sys.stderr)
    else:
        print(
            "supply-chain policy ok: "
            f"msrv={report['workspace_rust_version']} "
            f"members={report['workspace_member_count']} "
            f"dependency_specs={report['dependency_specs_checked']} "
            f"sdk_dependency_edges={report['sdk_dependency_edges_checked']} "
            f"lock_packages={report['lock_package_count']} "
            f"node_dependency_specs={report['node_binding_dependency_specs_checked']} "
            f"node_lock_packages={report['node_binding_lock_package_count']}"
        )
    return 1 if report["violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
