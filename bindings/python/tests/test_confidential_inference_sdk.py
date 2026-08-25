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
)


def _chat_request(prompt: str = "python binding path") -> dict:
    return {
        "model": "gpt-oss-120b",
        "messages": [{"role": "user", "content": prompt}],
    }


class ConfidentialInferencePythonBindingTests(unittest.TestCase):
    def test_status_reports_blocking_and_stream_capabilities(self) -> None:
        with Client() as client:
            status = client.status()
        self.assertIn("stream_handle_abi_available", status)
        self.assertTrue(status["stream_handle_abi_available"])
        self.assertTrue(status["blocking_helpers_available"])

    def test_chat_blocking_returns_verified_confidential_response(self) -> None:
        expected_verdict = json.loads(
            (ROOT / "fixtures" / "verdict" / "demo-verified.json").read_text()
        )
        with Client() as client:
            response = client.chat(_chat_request(), timeout_ms=5_000)
        self.assertEqual(response["provider"], "demo")
        self.assertEqual(response["provider_model"], "e2ee-gpt-oss-120b-p")
        self.assertEqual(response["verdict"], expected_verdict)
        self.assertEqual(response["verdict"]["status"], "verified")
        self.assertEqual(
            response["response"]["choices"][0]["message"]["content"],
            "demo confidential response for e2ee-gpt-oss-120b-p: python binding path",
        )

    def test_verify_blocking_returns_route_verdict(self) -> None:
        with Client() as client:
            verdict = client.verify("demo", "gpt-oss-120b", timeout_ms=5_000)
        self.assertEqual(verdict["status"], "verified")
        self.assertEqual(verdict["provider"], "demo")

    def test_response_blocking_returns_responses_shim(self) -> None:
        with Client() as client:
            response = client.response(
                {"model": "gpt-oss-120b", "input": "responses path"}, timeout_ms=5_000
            )
        self.assertEqual(response["provider"], "demo")
        self.assertEqual(response["response"]["object"], "response")

    def test_model_discovery_and_confidentiality_catalog(self) -> None:
        with Client() as client:
            models = client.models()
            catalog = client.confidentiality()
        self.assertIsInstance(models["data"], list)
        self.assertIsInstance(catalog, list)

    def test_active_policy_and_trust_artifacts(self) -> None:
        with Client() as client:
            policy = client.active_policy()
            artifacts = client.active_trust_artifacts()
        self.assertEqual(policy["schema"], "confidential-inference.active-policy.v1")
        self.assertIn("registry_digest", artifacts)
        self.assertIn("reference_values_digest", artifacts)

    def test_chat_async_runs_blocking_call_in_thread(self) -> None:
        async def main() -> dict:
            async with Client() as client:
                return await client.chat_async(_chat_request("async path"), timeout_ms=5_000)

        response = asyncio.run(main())
        self.assertEqual(response["provider"], "demo")
        self.assertEqual(response["verdict"]["status"], "verified")

    def test_cancelled_async_call_drains_worker_before_returning(self) -> None:
        async def main() -> None:
            client = Client()
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

    def test_stream_fails_closed_for_non_streaming_route(self) -> None:
        with Client() as client:
            stream = client.start_stream(_chat_request("stream path"))
            self.assertIsInstance(stream, Stream)
            events = []
            while True:
                event = stream.next(timeout_ms=5_000)
                if event is None:
                    continue
                events.append(event)
                if event.get("type") in {"done", "closed", "cancelled", "error"}:
                    break
            stream.close()
        # The demo route does not support streaming; the SDK fails closed with
        # a structured error event rather than emitting an unverified stream.
        self.assertEqual(events[0]["type"], "error")
        self.assertEqual(events[0]["status"], "failed")

    def test_closed_client_rejects_calls(self) -> None:
        client = Client()
        client.close()
        with self.assertRaises(ConfidentialInferenceError):
            client.models()

    def test_client_repr_reports_state(self) -> None:
        client = Client()
        self.assertIn("open", repr(client))
        client.close()
        self.assertIn("closed", repr(client))

    def test_closing_client_with_live_stream_preserves_handle(self) -> None:
        client = Client()
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
        client = Client()
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
        client = Client()
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
        client = Client()
        with self.assertRaises(ConfidentialInferenceError) as ctx:
            client.chat({"nope": True})
        self.assertEqual(ctx.exception.status, 1)
        self.assertEqual(ctx.exception.error["code"], "invalid_request_json")
        self.assertIn("model", ctx.exception.error["message"])
        client.close()

    def test_concurrent_async_calls_all_resolve(self) -> None:
        async def main() -> None:
            async with Client() as client:
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


if __name__ == "__main__":
    unittest.main()
