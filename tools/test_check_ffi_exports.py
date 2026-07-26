from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check_ffi_exports.py")
SPEC = importlib.util.spec_from_file_location("check_ffi_exports", MODULE_PATH)
assert SPEC is not None
check_ffi_exports = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = check_ffi_exports
SPEC.loader.exec_module(check_ffi_exports)


def write_inputs(root: Path, rust_source: str, header: str) -> tuple[Path, Path]:
    rust_path = root / "lib.rs"
    header_path = root / "confidential_inference_ffi.h"
    rust_path.write_text(rust_source.lstrip(), encoding="utf-8")
    header_path.write_text(header.lstrip(), encoding="utf-8")
    return rust_path, header_path


class CheckFfiExportsTests(unittest.TestCase):
    def test_current_ffi_surface_passes_policy(self) -> None:
        report = check_ffi_exports.check_ffi_exports(
            Path("crates/confidential-inference-ffi/src/lib.rs"),
            Path("crates/confidential-inference-ffi/include/confidential_inference_ffi.h"),
        )

        self.assertEqual(report["schema"], "confidential-inference.ffi-export-policy.v1")
        self.assertEqual(report["violations"], [])
        self.assertIn("confidential_inference_sdk_new", report["rust_exports"])
        self.assertIn("confidential_inference_string_free", report["rust_exports"])

    def test_valid_export_surface_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            rust_path, header_path = write_inputs(
                Path(temp),
                """
#[no_mangle]
pub unsafe extern "C" fn confidential_inference_wrapped() -> c_int {
    let sample = "{";
    // Comments with braces should not end the function: }
    let _ = sample;
    ffi_boundary(|| { 0 })
}

#[no_mangle]
pub unsafe extern "C" fn confidential_inference_string_free(ptr: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        let _ = ptr;
    }));
}
""",
                """
int confidential_inference_wrapped(void);
void confidential_inference_string_free(char *ptr);
""",
            )

            report = check_ffi_exports.check_ffi_exports(rust_path, header_path)

            self.assertEqual(report["rust_export_count"], 2)
            self.assertEqual(report["header_export_count"], 2)
            self.assertEqual(report["panic_boundary_count"], 2)
            self.assertEqual(report["violations"], [])

    def test_missing_panic_boundary_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            rust_path, header_path = write_inputs(
                Path(temp),
                """
#[no_mangle]
pub unsafe extern "C" fn confidential_inference_unwrapped() -> c_int {
    let misleading = "ffi_boundary(";
    // catch_unwind(
    let _ = misleading;
    0
}
""",
                "int confidential_inference_unwrapped(void);\n",
            )

            report = check_ffi_exports.check_ffi_exports(rust_path, header_path)

            self.assertIn(
                "confidential_inference_unwrapped at line 2 does not call ffi_boundary or catch_unwind",
                report["violations"],
            )

    def test_header_and_rust_symbol_drift_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            rust_path, header_path = write_inputs(
                Path(temp),
                """
#[no_mangle]
pub unsafe extern "C" fn confidential_inference_only_rust() -> c_int {
    ffi_boundary(|| 0)
}
""",
                "int confidential_inference_only_header(void);\n",
            )

            report = check_ffi_exports.check_ffi_exports(rust_path, header_path)
            joined = "\n".join(report["violations"])

            self.assertIn("confidential_inference_only_rust is exported from Rust but missing", joined)
            self.assertIn("confidential_inference_only_header is declared", joined)


if __name__ == "__main__":
    unittest.main()
