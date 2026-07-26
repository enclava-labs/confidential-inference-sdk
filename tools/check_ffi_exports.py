#!/usr/bin/env python3
"""Validate the C ABI export surface and FFI panic-containment contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = "confidential-inference.ffi-export-policy.v1"
EXPORT_RE = re.compile(
    r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+'
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
HEADER_EXPORT_RE = re.compile(r"\b(?:int|void)\s+(?P<name>confidential_inference_[A-Za-z0-9_]+)\s*\(")
BOUNDARY_MARKERS = ("ffi_boundary(", "catch_unwind(")


@dataclass(frozen=True)
class RustExport:
    name: str
    line: int
    body: str


class FfiExportPolicyError(RuntimeError):
    pass


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _find_matching_body(text: str, start: int) -> str:
    open_brace = text.find("{", start)
    if open_brace < 0:
        raise FfiExportPolicyError("exported function is missing an opening body brace")

    depth = 0
    index = open_brace
    state = "code"
    block_comment_depth = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if state == "line_comment":
            if char == "\n":
                state = "code"
            index += 1
            continue

        if state == "block_comment":
            if char == "/" and next_char == "*":
                block_comment_depth += 1
                index += 2
                continue
            if char == "*" and next_char == "/":
                block_comment_depth -= 1
                index += 2
                if block_comment_depth == 0:
                    state = "code"
                continue
            index += 1
            continue

        if state == "string":
            if char == "\\":
                index += 2
                continue
            if char == '"':
                state = "code"
            index += 1
            continue

        if state == "char":
            if char == "\\":
                index += 2
                continue
            if char == "'":
                state = "code"
            index += 1
            continue

        if char == "/" and next_char == "/":
            state = "line_comment"
            index += 2
            continue
        if char == "/" and next_char == "*":
            state = "block_comment"
            block_comment_depth = 1
            index += 2
            continue
        if char == '"':
            state = "string"
            index += 1
            continue
        if char == "'":
            state = "char"
            index += 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace : index + 1]
        index += 1

    raise FfiExportPolicyError("exported function body has unmatched braces")


def _rust_exports(text: str) -> list[RustExport]:
    exports = []
    for match in EXPORT_RE.finditer(text):
        exports.append(
            RustExport(
                name=match.group("name"),
                line=_line_number(text, match.start()),
                body=_find_matching_body(text, match.end()),
            )
        )
    return exports


def _header_exports(text: str) -> list[str]:
    return sorted(set(match.group("name") for match in HEADER_EXPORT_RE.finditer(text)))


def _code_without_comments_and_strings(text: str) -> str:
    output: list[str] = []
    index = 0
    state = "code"
    block_comment_depth = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if state == "line_comment":
            if char == "\n":
                state = "code"
                output.append(char)
            else:
                output.append(" ")
            index += 1
            continue

        if state == "block_comment":
            if char == "/" and next_char == "*":
                block_comment_depth += 1
                output.extend("  ")
                index += 2
                continue
            if char == "*" and next_char == "/":
                block_comment_depth -= 1
                output.extend("  ")
                index += 2
                if block_comment_depth == 0:
                    state = "code"
                continue
            output.append("\n" if char == "\n" else " ")
            index += 1
            continue

        if state == "string":
            if char == "\\":
                output.extend("  ")
                index += 2
                continue
            if char == '"':
                state = "code"
            output.append("\n" if char == "\n" else " ")
            index += 1
            continue

        if state == "char":
            if char == "\\":
                output.extend("  ")
                index += 2
                continue
            if char == "'":
                state = "code"
            output.append("\n" if char == "\n" else " ")
            index += 1
            continue

        if char == "/" and next_char == "/":
            state = "line_comment"
            output.extend("  ")
            index += 2
            continue
        if char == "/" and next_char == "*":
            state = "block_comment"
            block_comment_depth = 1
            output.extend("  ")
            index += 2
            continue
        if char == '"':
            state = "string"
            output.append(" ")
            index += 1
            continue
        if char == "'":
            state = "char"
            output.append(" ")
            index += 1
            continue

        output.append(char)
        index += 1

    return "".join(output)


def _missing_panic_boundaries(exports: Iterable[RustExport]) -> list[str]:
    missing = []
    for export in exports:
        code = _code_without_comments_and_strings(export.body)
        if not any(marker in code for marker in BOUNDARY_MARKERS):
            missing.append(
                f"{export.name} at line {export.line} does not call ffi_boundary or catch_unwind"
            )
    return missing


def check_ffi_exports(rust_source: Path, header: Path) -> dict[str, object]:
    rust_source = rust_source.resolve()
    header = header.resolve()
    rust_text = rust_source.read_text(encoding="utf-8")
    header_text = header.read_text(encoding="utf-8")

    rust_exports = _rust_exports(rust_text)
    rust_names = sorted(export.name for export in rust_exports)
    header_names = _header_exports(header_text)
    missing_from_header = sorted(set(rust_names) - set(header_names))
    missing_from_rust = sorted(set(header_names) - set(rust_names))
    violations = _missing_panic_boundaries(rust_exports)
    violations.extend(
        f"{name} is exported from Rust but missing from {header}"
        for name in missing_from_header
    )
    violations.extend(
        f"{name} is declared in {header} but missing from Rust exports"
        for name in missing_from_rust
    )

    return {
        "schema": SCHEMA,
        "rust_source": rust_source.as_posix(),
        "header": header.as_posix(),
        "rust_export_count": len(rust_names),
        "header_export_count": len(header_names),
        "panic_boundary_count": len(rust_names) - len(_missing_panic_boundaries(rust_exports)),
        "rust_exports": rust_names,
        "header_exports": header_names,
        "violations": sorted(violations),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rust-source",
        type=Path,
        default=Path("crates/confidential-inference-ffi/src/lib.rs"),
        help="Rust FFI source to inspect. Defaults to crates/confidential-inference-ffi/src/lib.rs.",
    )
    parser.add_argument(
        "--header",
        type=Path,
        default=Path("crates/confidential-inference-ffi/include/confidential_inference_ffi.h"),
        help="Public C header to compare. Defaults to crates/confidential-inference-ffi/include/confidential_inference_ffi.h.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full validation report as JSON.",
    )
    args = parser.parse_args(argv)

    try:
        report = check_ffi_exports(args.rust_source, args.header)
    except (OSError, FfiExportPolicyError) as error:
        print(f"check_ffi_exports.py: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2, separators=(",", ": ")))
    elif report["violations"]:
        for violation in report["violations"]:
            print(f"ffi export policy violation: {violation}", file=sys.stderr)
    else:
        print(
            "ffi export policy ok: "
            f"rust_exports={report['rust_export_count']} "
            f"header_exports={report['header_export_count']} "
            f"panic_boundaries={report['panic_boundary_count']}"
        )
    return 1 if report["violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
