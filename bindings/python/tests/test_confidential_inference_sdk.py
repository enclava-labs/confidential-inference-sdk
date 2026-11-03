"""Tests for the thin Python binding (JSON marshalling + ABI shape checks).

Rust owns attestation/policy/registry/digest/signature decisions; these tests
only exercise the binding against the live FFI built from the workspace demo
provider and assert the JSON shapes that cross the ABI.
"""

import asyncio
import json
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "bindings" / "python"))

from confidential_inference_sdk import (  # noqa: E402
    Client,
    ConfidentialInferenceError,
    Stream,
    _Native,
    CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION,
)


def _embeddings_request(model: str = "gpt-oss-120b") -> dict:
    return {"model": model, "input": "python embeddings binding path"}


def _chat_request(prompt: str = "python binding path") -> dict:
    return {
        "model": "gpt-oss-120b",
        "messages": [{"role": "user", "content": prompt}],
    }


DEMO_CONFIG = {"demo_provider": True}

class ConfidentialInferencePythonBindingTests(unittest.TestCase):
    def test_abi_version_validation_rejects_mismatch(self) -> None:
        with self.assertRaises(ConfidentialInferenceError) as raised:
            _Native._validate_abi_version(
                {"abi_version": CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION + 1}
            )
        self.assertEqual(raised.exception.error["code"], "abi_version_mismatch")
        with self.assertRaises(ConfidentialInferenceError):
            _Native._validate_abi_version({})

    def test_abi_version_validation_accepts_match(self) -> None:
        _Native._validate_abi_version(
            {"abi_version": CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION}
        )

    def test_status_reports_blocking_and_stream_capabilities(self) -> None:
        with Client(DEMO_CONFIG) as client:
            status = client.status()
        self.assertIn("stream_handle_abi_available", status)
        self.assertTrue(status["stream_handle_abi_available"])
        self.assertTrue(status["blocking_helpers_available"])

    def test_chat_blocking_returns_verified_confidential_response(self) -> None:
        expected_verdict = json.loads(
            (ROOT / "fixtures" / "verdict" / "demo-verified.json").read_text()
        )
        with Client(DEMO_CONFIG) as client:
            response = client.chat(_chat_request(), timeout_ms=5_000)
        self.assertEqual(response["provider"], "demo")
        self.assertEqual(response["provider_model"], "e2ee-gpt-oss-120b-p")
        self.assertEqual(response["verdict"], expected_verdict)
        self.assertEqual(response["verdict"]["status"], "verified")
        self.assertEqual(
            response["response"]["choices"][0]["message"]["content"],
            "demo confidential response for e2ee-gpt-oss-120b-p: python binding path",
        )

    def test_embeddings_blocking_returns_verified_response(self) -> None:
        with Client(DEMO_CONFIG) as client:
            response = client.embeddings(_embeddings_request(), timeout_ms=5_000)
        self.assertEqual(response["provider"], "demo")
        self.assertEqual(response["verdict"]["status"], "verified")
        self.assertEqual(response["response"]["object"], "list")
        self.assertTrue(response["response"]["data"])

    def test_verify_blocking_returns_route_verdict(self) -> None:
        with Client(DEMO_CONFIG) as client:
            verdict = client.verify("demo", "gpt-oss-120b", timeout_ms=5_000)
        self.assertEqual(verdict["status"], "verified")
        self.assertEqual(verdict["provider"], "demo")

    def test_response_blocking_returns_responses_shim(self) -> None:
        with Client(DEMO_CONFIG) as client:
            response = client.response(
                {"model": "gpt-oss-120b", "input": "responses path"}, timeout_ms=5_000
            )
        self.assertEqual(response["provider"], "demo")
        self.assertEqual(response["response"]["object"], "response")

    def test_response_manage_preserves_structured_operation_error(self) -> None:
        with Client(DEMO_CONFIG) as client:
            with self.assertRaises(ConfidentialInferenceError) as raised:
                client.response_manage(
                    {
                        "op": "retrieve",
                        "provider": "demo",
                        "provider_response_id": "resp_demo",
                        "params": {},
                    },
                    timeout_ms=5_000,
                )
        self.assertTrue(raised.exception.error.get("code"))

    def test_model_discovery_and_confidentiality_catalog(self) -> None:
        with Client(DEMO_CONFIG) as client:
            models = client.models()
            catalog = client.confidentiality()
        self.assertIsInstance(models["data"], list)
        self.assertIsInstance(catalog, list)

    def test_active_policy_and_trust_artifacts(self) -> None:
        with Client(DEMO_CONFIG) as client:
            policy = client.active_policy()
            artifacts = client.active_trust_artifacts()
        self.assertEqual(policy["schema"], "confidential-inference.active-policy.v1")
        self.assertIn("registry_digest", artifacts)
        self.assertIn("reference_values_digest", artifacts)

    def test_chat_async_runs_blocking_call_in_thread(self) -> None:
        async def main() -> dict:
            async with Client(DEMO_CONFIG) as client:
                return await client.chat_async(_chat_request("async path"), timeout_ms=5_000)

        response = asyncio.run(main())
        self.assertEqual(response["provider"], "demo")
        self.assertEqual(response["verdict"]["status"], "verified")

    def test_cancelled_async_call_drains_worker_before_returning(self) -> None:
        async def main() -> None:
            client = Client(DEMO_CONFIG)
            started = threading.Event()
            release = threading.Event()
            original_chat = client.chat

            def blocking_chat(request: dict, timeout_ms: int = 0) -> dict:
                started.set()
                release.wait()
                return original_chat(request, timeout_ms)

            client.chat = blocking_chat  # type: ignore[method-assign]
            task = asyncio.create_task(client.chat_async(_chat_request(), 5_000))
            await asyncio.to_thread(started.wait)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            client.close()

        asyncio.run(main())


    def test_stream_events_async_fails_closed_with_error_classification(self) -> None:
        async def main() -> None:
            client = Client(DEMO_CONFIG)
            stream = client.start_stream(_chat_request("stream path"))
            events = [event async for event in stream.events_async(timeout_ms=5_000)]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["type"], "error")
            self.assertEqual(events[0]["error"]["code"], "streaming_not_supported")
            self.assertEqual(events[0]["error"]["dispatch"], "not_dispatched")
            self.assertTrue(stream.closed)
            client.close()

        asyncio.run(main())

    def test_closed_client_rejects_calls(self) -> None:
        client = Client(DEMO_CONFIG)
        client.close()
        with self.assertRaises(ConfidentialInferenceError):
            client.models()

    def test_client_repr_reports_state(self) -> None:
        client = Client(DEMO_CONFIG)
        self.assertIn("open", repr(client))
        client.close()
        self.assertIn("closed", repr(client))

    def test_closing_client_with_live_stream_preserves_handle(self) -> None:
        client = Client(DEMO_CONFIG)
        stream = client.start_stream(_chat_request())
        # The pending stream keeps the native client live; freeing must fail
        # without discarding the handle (which would leak both objects).
        with self.assertRaises(ConfidentialInferenceError) as ctx:
            client.close()
        self.assertEqual(ctx.exception.status, 3)  # CONFIDENTIAL_INFERENCE_FFI_BUSY
        self.assertTrue(bool(client._handle), "client handle should be preserved on failed free")
        stream.close()
        client.close()
        self.assertFalse(bool(client._handle), "client should free once streams are closed")

    def test_closing_during_in_flight_call_preserves_handle(self) -> None:
        client = Client(DEMO_CONFIG)
        # Simulate a worker-thread call holding the handle (asyncio.to_thread
        # runs the same guard); close() must refuse rather than free under it.
        client._in_flight += 1
        try:
            with self.assertRaises(ConfidentialInferenceError) as ctx:
                client.close()
            self.assertEqual(ctx.exception.status, 3)
            self.assertEqual(ctx.exception.error["code"], "client_busy")
            self.assertTrue(
                bool(client._handle), "client handle must be preserved while calls run"
            )
        finally:
            client._in_flight -= 1
        client.close()
        self.assertFalse(bool(client._handle), "client frees once in-flight calls settle")

    def test_closing_stream_during_in_flight_next_preserves_handle(self) -> None:
        client = Client(DEMO_CONFIG)
        stream = client.start_stream(_chat_request())
        stream._in_flight += 1
        try:
            with self.assertRaises(ConfidentialInferenceError) as ctx:
                stream.close()
            self.assertEqual(ctx.exception.status, 3)
            self.assertEqual(ctx.exception.error["code"], "stream_busy")
            self.assertTrue(bool(stream._handle))
        finally:
            stream._in_flight -= 1
        stream.close()
        client.close()

    def test_failed_inference_surfaces_native_error_code(self) -> None:
        client = Client(DEMO_CONFIG)
        with self.assertRaises(ConfidentialInferenceError) as ctx:
            client.chat({"nope": True})
        self.assertEqual(ctx.exception.status, 1)
        self.assertEqual(ctx.exception.error["code"], "invalid_request_json")
        self.assertIn("model", ctx.exception.error["message"])
        client.close()
    def test_embeddings_operation_failure_is_classified(self) -> None:
        with Client(DEMO_CONFIG) as client:
            with self.assertRaises(ConfidentialInferenceError) as ctx:
                client.embeddings(_embeddings_request("no-such-model"), timeout_ms=5_000)
        self.assertEqual(ctx.exception.status, 7)
        self.assertEqual(ctx.exception.dispatch, "not_dispatched")
        self.assertEqual(ctx.exception.http_status, None)
        self.assertTrue(ctx.exception.error["code"])
        self.assertTrue(ctx.exception.error["message"])

    def test_concurrent_async_calls_all_resolve(self) -> None:
        async def main() -> None:
            async with Client(DEMO_CONFIG) as client:
                jobs = [
                    asyncio.to_thread(client.chat, _chat_request(f"fanout {i}"), 5_000)
                    for i in range(8)
                ]
                jobs.append(asyncio.to_thread(client.models))
                jobs.append(asyncio.to_thread(client.confidentiality))
                results = await asyncio.gather(*jobs)
                for response in results[:8]:
                    self.assertEqual(response["verdict"]["status"], "verified")

        asyncio.run(main())

    def test_default_config_fails_closed_without_demo_opt_in(self) -> None:
        with self.assertRaises(ConfidentialInferenceError) as ctx:
            Client()
        self.assertEqual(
            ctx.exception.error["code"], "trusted_signing_keys_required"
        )
        with self.assertRaises(ConfidentialInferenceError) as ctx:
            Client(config={})
        self.assertEqual(
            ctx.exception.error["code"], "trusted_signing_keys_required"
        )

    def test_explicit_library_path_is_exclusive_and_must_exist(self) -> None:
        import os

        missing = ROOT / "target" / "release" / "no_such_lib_ffi.so"
        with self.assertRaises(ConfidentialInferenceError) as ctx:
            _Native(missing)
        self.assertEqual(ctx.exception.error["code"], "library_not_found")
        old = os.environ.get("CONFIDENTIAL_INFERENCE_FFI_LIBRARY")
        try:
            os.environ["CONFIDENTIAL_INFERENCE_FFI_LIBRARY"] = str(missing)
            with self.assertRaises(ConfidentialInferenceError) as ctx:
                _Native()
            self.assertEqual(ctx.exception.error["code"], "library_not_found")
        finally:
            if old is None:
                del os.environ["CONFIDENTIAL_INFERENCE_FFI_LIBRARY"]
            else:
                os.environ["CONFIDENTIAL_INFERENCE_FFI_LIBRARY"] = old

    def test_stream_holds_owning_client_reference(self) -> None:
        client = Client(DEMO_CONFIG)
        stream = client.start_stream(_chat_request())
        self.assertIs(stream._owner, client)
        stream.close()
        client.close()


if __name__ == "__main__":
    unittest.main()
