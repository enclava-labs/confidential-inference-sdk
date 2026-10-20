# General-availability readiness ledger

Working ledger of gaps found while integrating the SDK as the upstream
transport of the Enclava Go application (`mini-enclava-go`). Each entry names
the evidence, what the application needs, and the resolution status. Entries
move to **Resolved** only with a passing test or live run named in the row.

Integrator requirements (from the application's inference contract):
OpenAI `models`, Chat Completions with streaming, tool calls and image input,
embeddings, and the Responses API (create, retrieve, cancel, delete,
input items, input token counting, compaction, streaming); per-tenant
credentials; caller cancellation; exact usage for billing; customer-local
(private-origin) and confidential (attested) endpoints behind one client.

## Open

| ID | Area | Gap (evidence) | Integrator impact |
|---|---|---|---|
| GA-01 | OpenAI fidelity | `ChatMessage.content` is `String`; `ChatCompletionRequest` has only model/messages/stream/max_tokens/temperature. Serde does not deny unknown fields, so `tools`, `tool_choice`, image content parts, `response_format`, `stop`, `seed`, `tool_calls`, `tool_call_id` are **silently dropped** (`crates/confidential-inference-openai/src/lib.rs`). | Tool calling and vision silently degrade instead of failing; responses lose `tool_calls`. |
| GA-02 | Embeddings | No embeddings type, client method, adapter method or FFI export. | RAG indexing/query cannot use the SDK. |
| GA-03 | Streaming | `ProviderAdapter` has no streaming method; FFI `chat_stream_start` awaits the full response and emits one `response` event (`crates/confidential-inference-ffi/src/lib.rs` `stream_response_events`). Chutes/NEAR live adapters reject streaming. | No token streaming; time-to-first-token equals full latency. |
| GA-04 | Responses | Text-only compatibility shim over chat; no retrieve/cancel/delete/input_items/input_tokens/compact passthrough. | Responses lifecycle unavailable through the SDK. |
| GA-05 | Operator trust (FFI) | FFI `ClientConfig` accepts operator signing keys but no registry or reference-values envelopes; the Rust builder supports both (`registry`, `reference_values`). With `demo_provider=false` no live route can be loaded from bindings. | Bindings cannot run any live route. |
| GA-06 | Trust tooling | Reference-value generators exist for Tinfoil and app-E2EE only; none for `chutes_live_e2ee` or `near_hw_verified_tls`, and no operator workflow to capture → verify → pin → sign. | Operators cannot produce live trust material without writing Rust. |
| GA-07 | Live profiles | Bundled compatibility matrix has executable live profiles only for `chutes` and `near`; Tinfoil, RedPill, Venice, Phala exist as fixture profiles only. | Most advertised providers are not executable live. |
| GA-08 | NEAR live | Model-direct host `gpt-oss-120b.completions.near.ai` fails the TLS handshake (`SSL_ERROR_SYSCALL`) from curl and the SDK; DNS resolves. | NEAR route unusable; needs provider follow-up or endpoint update. |
| GA-09 | Go binding distribution | `bindings/go` is uncommitted, module path unpublished; consumers need a `replace` directive and a separately built shared library. | No reproducible consumer build. |
| GA-10 | Plain/private endpoints | Unverified OpenAI-compatible routes (customer-local) need an explicit, policy-visible "unattested" route class so one client can serve both. | Integrator keeps a second transport for local endpoints. |

## Resolved

| ID | Resolution | Evidence |
|---|---|---|

## Verified behavior (live)

| Date | Check | Result |
|---|---|---|
| 2026-10-20 | `cargo test -p confidential-inference-providers --test live_chutes_near -- --ignored` with operator Chutes key | `chutes_live_adapter_captures_bound_evidence` passed (TDX/DCAP + NVIDIA NRAS); NEAR failed at TLS handshake (GA-08). |
| 2026-10-20 | `cargo build -p confidential-inference-ffi` + `go test ./...` in `bindings/go` | Pass (offline demo provider). |
