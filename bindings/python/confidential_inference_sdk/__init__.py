"""Thin Python bindings for the Confidential Inference SDK C ABI.

The Rust FFI owns every attestation/policy/registry/digest/signature decision.
This module only loads the native library, marshals JSON across the ABI, and
applies minimal ABI-shape checks on the way back. Blocking calls are exposed
both synchronously and as asyncio.to_thread wrappers; streams poll stream_next.
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import sys
from pathlib import Path
from typing import Any, AsyncIterator, Callable

CONFIDENTIAL_INFERENCE_FFI_OK = 0
CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT = 1
CONFIDENTIAL_INFERENCE_FFI_PANIC = 2
CONFIDENTIAL_INFERENCE_FFI_BUSY = 3
CONFIDENTIAL_INFERENCE_FFI_PENDING = 4
CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED = 5
CONFIDENTIAL_INFERENCE_FFI_INTERNAL = 6


class ConfidentialInferenceError(RuntimeError):
    def __init__(self, status: int, error: dict[str, Any] | None = None):
        self.status = status
        self.error = error or {}
        code = self.error.get("code", "ffi_error")
        message = self.error.get("message", f"FFI status {status}")
        super().__init__(f"{code}: {message}")


def _json_bytes(value: dict[str, Any] | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _as_dict(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ConfidentialInferenceError(
            CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
            {"code": "malformed_json_object", "message": "expected a JSON object"},
        )
    return payload


def _as_list(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        raise ConfidentialInferenceError(
            CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
            {"code": "malformed_json_array", "message": "expected a JSON array"},
        )
    return payload


class _Native:
    def __init__(self, library_path: str | os.PathLike[str] | None = None):
        self.path = _resolve_library_path(library_path)
        self.lib = ctypes.CDLL(str(self.path))
        self._configure()

    def _configure(self) -> None:
        void_pp = ctypes.POINTER(ctypes.c_void_p)
        c = self.lib
        c.confidential_inference_status.argtypes = [void_pp]
        c.confidential_inference_status.restype = ctypes.c_int
        c.confidential_inference_sdk_new.argtypes = [ctypes.c_char_p, void_pp]
        c.confidential_inference_sdk_new.restype = ctypes.c_int
        c.confidential_inference_sdk_free.argtypes = [ctypes.c_void_p]
        c.confidential_inference_sdk_free.restype = ctypes.c_int
        for name in (
            "confidential_inference_chat_blocking",
            "confidential_inference_response_blocking",
            "confidential_inference_verify_blocking",
        ):
            fn = getattr(c, name)
            fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64, void_pp]
            fn.restype = ctypes.c_int
        for name in (
            "confidential_inference_models_blocking",
            "confidential_inference_confidentiality_blocking",
            "confidential_inference_active_policy_blocking",
            "confidential_inference_active_trust_artifacts_blocking",
        ):
            fn = getattr(c, name)
            fn.argtypes = [ctypes.c_void_p, void_pp]
            fn.restype = ctypes.c_int
        c.confidential_inference_chat_stream_start.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            void_pp,
        ]
        c.confidential_inference_chat_stream_start.restype = ctypes.c_int
        c.confidential_inference_stream_next.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            void_pp,
        ]
        c.confidential_inference_stream_next.restype = ctypes.c_int
        c.confidential_inference_stream_cancel.argtypes = [ctypes.c_void_p]
        c.confidential_inference_stream_cancel.restype = ctypes.c_int
        c.confidential_inference_stream_free.argtypes = [ctypes.c_void_p]
        c.confidential_inference_stream_free.restype = ctypes.c_int
        c.confidential_inference_last_error.argtypes = [void_pp]
        c.confidential_inference_last_error.restype = ctypes.c_int
        c.confidential_inference_string_free.argtypes = [ctypes.c_void_p]
        c.confidential_inference_string_free.restype = None

    def take_json_string(self, ptr: ctypes.c_void_p) -> Any:
        if not ptr:
            raise ConfidentialInferenceError(
                CONFIDENTIAL_INFERENCE_FFI_INTERNAL,
                {"code": "missing_string", "message": "FFI returned a null JSON pointer"},
            )
        try:
            value = ctypes.string_at(ptr).decode("utf-8")
        finally:
            self.lib.confidential_inference_string_free(ptr)
        return json.loads(value)

    def status(self) -> dict[str, Any]:
        out = ctypes.c_void_p()
        code = self.lib.confidential_inference_status(ctypes.byref(out))
        self.raise_for_status(code)
        return _as_dict(self.take_json_string(out))

    def last_error(self) -> dict[str, Any] | None:
        out = ctypes.c_void_p()
        code = self.lib.confidential_inference_last_error(ctypes.byref(out))
        if code != CONFIDENTIAL_INFERENCE_FFI_OK:
            return {"code": "last_error_failed", "message": f"status {code}"}
        return _as_dict(self.take_json_string(out)).get("error")

    def raise_for_status(self, status: int) -> None:
        if status != CONFIDENTIAL_INFERENCE_FFI_OK:
            raise ConfidentialInferenceError(status, self.last_error())


class Stream:
    def __init__(self, native: _Native, handle: ctypes.c_void_p):
        self._native = native
        self._handle = handle

    @property
    def closed(self) -> bool:
        return not self._handle

    def next(self, timeout_ms: int = 0) -> dict[str, Any] | None:
        if not self._handle:
            raise ConfidentialInferenceError(
                CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT,
                {"code": "stream_closed", "message": "stream is closed"},
            )
        out = ctypes.c_void_p()
        status = self._native.lib.confidential_inference_stream_next(
            self._handle, ctypes.c_uint64(timeout_ms), ctypes.byref(out)
        )
        if status == CONFIDENTIAL_INFERENCE_FFI_PENDING:
            return None
        self._native.raise_for_status(status)
        return _as_dict(self._native.take_json_string(out))

    def cancel(self) -> None:
        if self._handle:
            self._native.lib.confidential_inference_stream_cancel(self._handle)

    def close(self) -> None:
        if self._handle:
            # Cancel first so the native handle is never left pending:
            # stream_free refuses (FFI_BUSY) to free a live stream, which
            # would leak it.
            self.cancel()
            status = self._native.lib.confidential_inference_stream_free(self._handle)
            if status == CONFIDENTIAL_INFERENCE_FFI_OK:
                self._handle = ctypes.c_void_p()
            else:
                # Keep the handle so the caller can drain/cancel and retry.
                self._native.raise_for_status(status)

    async def events_async(
        self, timeout_ms: int = 0, poll_interval: float = 0.01
    ) -> AsyncIterator[dict[str, Any]]:
        while True:
            event = await asyncio.to_thread(self.next, timeout_ms)
            if event is None:
                await asyncio.sleep(poll_interval)
                continue
            yield event
            if str(event.get("type")).lower() in {"closed", "done", "cancelled", "error"}:
                break

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class Client:
    def __init__(
        self,
        config: dict[str, Any] | None = None,
        library_path: str | os.PathLike[str] | None = None,
    ):
        self._native = _Native(library_path)
        self._handle = ctypes.c_void_p()
        config_bytes = None
        if config is not None:
            config_bytes = _json_bytes(config)
        status = self._native.lib.confidential_inference_sdk_new(
            config_bytes, ctypes.byref(self._handle)
        )
        self._native.raise_for_status(status)

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if not self._handle else "open"
        return f"Client(state={state!r}, library={str(self._native.path)!r})"

    def close(self) -> None:
        if self._handle:
            status = self._native.lib.confidential_inference_sdk_free(self._handle)
            if status == CONFIDENTIAL_INFERENCE_FFI_OK:
                self._handle = ctypes.c_void_p()
            else:
                # FFI_BUSY means live streams still reference the client; keep
                # the handle so the caller can close them and retry instead of
                # leaking the native client.
                self._native.raise_for_status(status)

    def status(self) -> dict[str, Any]:
        return self._native.status()

    def chat(self, request: dict[str, Any], timeout_ms: int = 0) -> dict[str, Any]:
        return self._call_json(
            self._native.lib.confidential_inference_chat_blocking, request, timeout_ms
        )

    def create_response(
        self, request: dict[str, Any], timeout_ms: int = 0
    ) -> dict[str, Any]:
        return self._call_json(
            self._native.lib.confidential_inference_response_blocking, request, timeout_ms
        )

    def response(self, request: dict[str, Any], timeout_ms: int = 0) -> dict[str, Any]:
        return self.create_response(request, timeout_ms=timeout_ms)

    def verify(self, provider: str, model: str, timeout_ms: int = 0) -> dict[str, Any]:
        return self._call_json(
            self._native.lib.confidential_inference_verify_blocking,
            {"provider": provider, "model": model},
            timeout_ms,
        )

    def models(self) -> dict[str, Any]:
        return self._call_no_request_json(
            self._native.lib.confidential_inference_models_blocking
        )

    def confidential_models(self) -> list[dict[str, Any]]:
        return _as_list(
            self._call_no_request_json(
                self._native.lib.confidential_inference_confidentiality_blocking
            )
        )

    def confidentiality(self) -> list[dict[str, Any]]:
        return self.confidential_models()

    def active_policy(self) -> dict[str, Any]:
        return self._call_no_request_json(
            self._native.lib.confidential_inference_active_policy_blocking
        )

    def active_trust_artifacts(self) -> dict[str, Any]:
        return self._call_no_request_json(
            self._native.lib.confidential_inference_active_trust_artifacts_blocking
        )

    def start_stream(self, request: dict[str, Any]) -> Stream:
        self._require_open()
        out = ctypes.c_void_p()
        status = self._native.lib.confidential_inference_chat_stream_start(
            self._handle, _json_bytes(request), ctypes.byref(out)
        )
        self._native.raise_for_status(status)
        return Stream(self._native, out)

    async def chat_async(
        self, request: dict[str, Any], timeout_ms: int = 0
    ) -> dict[str, Any]:
        return await asyncio.to_thread(self.chat, request, timeout_ms)

    async def create_response_async(
        self, request: dict[str, Any], timeout_ms: int = 0
    ) -> dict[str, Any]:
        return await asyncio.to_thread(self.create_response, request, timeout_ms)

    async def response_async(
        self, request: dict[str, Any], timeout_ms: int = 0
    ) -> dict[str, Any]:
        return await self.create_response_async(request, timeout_ms=timeout_ms)

    async def verify_async(
        self, provider: str, model: str, timeout_ms: int = 0
    ) -> dict[str, Any]:
        return await asyncio.to_thread(self.verify, provider, model, timeout_ms)

    async def stream_async(
        self,
        request: dict[str, Any],
        timeout_ms: int = 0,
        poll_interval: float = 0.01,
    ) -> AsyncIterator[dict[str, Any]]:
        stream = self.start_stream(request)
        try:
            async for event in stream.events_async(
                timeout_ms=timeout_ms, poll_interval=poll_interval
            ):
                yield event
        finally:
            stream.close()

    def _call_json(
        self,
        function: Any,
        request: dict[str, Any] | bytes,
        timeout_ms: int,
    ) -> dict[str, Any]:
        self._require_open()
        out = ctypes.c_void_p()
        status = function(
            self._handle,
            _json_bytes(request),
            ctypes.c_uint64(timeout_ms),
            ctypes.byref(out),
        )
        self._native.raise_for_status(status)
        return _as_dict(self._native.take_json_string(out))

    def _call_no_request_json(self, function: Any) -> Any:
        self._require_open()
        out = ctypes.c_void_p()
        status = function(self._handle, ctypes.byref(out))
        self._native.raise_for_status(status)
        return self._native.take_json_string(out)

    def _require_open(self) -> None:
        if not self._handle:
            raise ConfidentialInferenceError(
                1, {"code": "client_closed", "message": "client is closed"}
            )

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def _library_name() -> str:
    if sys.platform == "darwin":
        return "libconfidential_inference_ffi.dylib"
    if sys.platform.startswith("win"):
        return "confidential_inference_ffi.dll"
    return "libconfidential_inference_ffi.so"


def _resolve_library_path(
    explicit: str | os.PathLike[str] | None = None,
) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(Path(explicit))
    if "CONFIDENTIAL_INFERENCE_FFI_LIBRARY" in os.environ:
        candidates.append(Path(os.environ["CONFIDENTIAL_INFERENCE_FFI_LIBRARY"]))

    library_name = _library_name()
    root = Path(__file__).resolve().parents[3]
    candidates.extend(
        [
            root / "target" / "debug" / library_name,
            root / "target" / "release" / library_name,
            Path.cwd() / "target" / "debug" / library_name,
            Path.cwd() / "target" / "release" / library_name,
        ]
    )

    for candidate in candidates:
        if candidate.exists():
            return candidate

    searched = ", ".join(str(candidate) for candidate in candidates)
    raise ConfidentialInferenceError(
        1,
        {
            "code": "library_not_found",
            "message": f"could not find ConfidentialInference FFI library; searched {searched}",
        },
    )


__all__ = [
    "Client",
    "Stream",
    "ConfidentialInferenceError",
]
