package confidentialinference

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestValidateABIVersion(t *testing.T) {
	if err := validateABIVersion(map[string]any{"abi_version": float64(CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION)}); err != nil {
		t.Fatalf("matching ABI version rejected: %v", err)
	}
	if err := validateABIVersion(map[string]any{"abi_version": float64(CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION + 1)}); err == nil || !strings.Contains(err.Error(), "ABI version mismatch") {
		t.Fatalf("mismatched ABI version was not rejected: %v", err)
	}
}

func phase2Config(t *testing.T) Config {
	t.Helper()
	root := repoRoot(t)
	registry, err := os.ReadFile(filepath.Join(root, "fixtures", "registry", "phase2-fixtures-registry.json"))
	if err != nil {
		t.Fatalf("read registry fixture: %v", err)
	}
	referenceValues, err := os.ReadFile(filepath.Join(root, "fixtures", "reference-values", "phase2-fixtures-envelope.json"))
	if err != nil {
		t.Fatalf("read reference-values fixture: %v", err)
	}
	demo := false
	return Config{
		DemoProvider: &demo,
		TrustedEd25519SigningKeys: []TrustedSigningKey{{
			Signer:             "confidential-inference",
			KeyID:              "confidential-inference-phase2-fixture-ed25519-2026",
			PublicKeyBase64URL: "cN-eInmtvsbRK_KSEYTJIi6yTthSAFv2QBOfUuWc2a4",
		}},
		Registry: registry, ReferenceValues: referenceValues,
	}
}

func TestConfiguredClientOperatorTrustArtifacts(t *testing.T) {
	config := phase2Config(t)
	client, err := NewConfiguredClient(config)
	if err != nil {
		t.Fatalf("new operator client: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close operator client: %v", err)
	}

	demo := true
	config.DemoProvider = &demo
	if _, err := NewConfiguredClient(config); err == nil {
		t.Fatal("accepted artifacts with demo_provider=true")
	}

	config = phase2Config(t)
	config.ReferenceValues = nil
	if _, err := NewConfiguredClient(config); err == nil {
		t.Fatal("accepted incomplete artifact pair")
	}

	config = phase2Config(t)
	config.TrustedEd25519SigningKeys[0].PublicKeyBase64URL = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := NewConfiguredClient(config); err == nil {
		t.Fatal("accepted artifacts from untrusted signer")
	}

	config = phase2Config(t)
	var envelope map[string]any
	if err := json.Unmarshal(config.Registry, &envelope); err != nil {
		t.Fatalf("parse registry fixture: %v", err)
	}
	envelope["payload"].(map[string]any)["version"] = "tampered"
	config.Registry, err = json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal tampered registry: %v", err)
	}
	if _, err := NewConfiguredClient(config); err == nil {
		t.Fatal("accepted tampered registry envelope")
	}
}

func TestConfiguredClientCompatibilityMatrixTrust(t *testing.T) {
	envelope, err := os.ReadFile(filepath.Join(repoRoot(t), "fixtures", "providers", "compatibility-matrix-envelope.json"))
	if err != nil {
		t.Fatalf("read compatibility matrix fixture: %v", err)
	}
	config := phase2Config(t)
	config.TrustedEd25519SigningKeys = append(config.TrustedEd25519SigningKeys, TrustedSigningKey{
		Signer:             "confidential-inference",
		KeyID:              "confidential-inference-compatibility-fixture-ed25519-2026",
		PublicKeyBase64URL: "bjLBl0Hwr4JgYSrpn9E9ijiURyLgiWTdI5c49VKmFTs",
	})
	config.CompatibilityMatrix = envelope
	client, err := NewConfiguredClient(config)
	if err != nil {
		t.Fatalf("new client with signed compatibility matrix: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}

	config.TrustedEd25519SigningKeys[1].PublicKeyBase64URL = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := NewConfiguredClient(config); err == nil {
		t.Fatal("accepted compatibility matrix from untrusted signer")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func chatRequest(prompt string) map[string]any {
	return map[string]any{
		"model":    "gpt-oss-120b",
		"messages": []map[string]any{{"role": "user", "content": prompt}},
	}
}
func embeddingsRequest(model string) map[string]any {
	return map[string]any{"model": model, "input": "hello"}
}

// demoConfig explicitly opts into the offline demo provider (nil config now
// fails closed — demo_provider defaults to false).
var demoConfig = json.RawMessage(`{"demo_provider":true}`)

func asError(t *testing.T, err error) *Error {
	t.Helper()
	var ffiErr *Error
	if !errors.As(err, &ffiErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	return ffiErr
}

func TestStatusReportsCapabilities(t *testing.T) {
	status, err := Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status["blocking_helpers_available"] != true {
		t.Fatalf("blocking_helpers_available = %v", status["blocking_helpers_available"])
	}
	if status["stream_handle_abi_available"] != true {
		t.Fatalf("stream_handle_abi_available = %v", status["stream_handle_abi_available"])
	}
}

func TestChatReturnsVerifiedResponse(t *testing.T) {
	expectedRaw, err := os.ReadFile(filepath.Join(repoRoot(t), "fixtures", "verdict", "demo-verified.json"))
	if err != nil {
		t.Fatalf("read verdict fixture: %v", err)
	}
	var expected map[string]any
	if err := json.Unmarshal(expectedRaw, &expected); err != nil {
		t.Fatalf("parse verdict fixture: %v", err)
	}

	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	response, err := client.Chat(chatRequest("go binding path"), 5*time.Second)
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	if response["provider"] != "demo" {
		t.Fatalf("provider = %v", response["provider"])
	}
	if response["provider_model"] != "e2ee-gpt-oss-120b-p" {
		t.Fatalf("provider_model = %v", response["provider_model"])
	}
	responseVerdict, _ := json.Marshal(response["verdict"])
	expectedVerdict, _ := json.Marshal(expected)
	if string(responseVerdict) != string(expectedVerdict) {
		t.Fatalf("verdict mismatch:\n got %s\nwant %s", responseVerdict, expectedVerdict)
	}
	verdict := response["verdict"].(map[string]any)
	if verdict["status"] != "verified" {
		t.Fatalf("verdict.status = %v", verdict["status"])
	}
	choices := response["response"].(map[string]any)["choices"].([]any)
	content := choices[0].(map[string]any)["message"].(map[string]any)["content"]
	if content != "demo confidential response for e2ee-gpt-oss-120b-p: go binding path" {
		t.Fatalf("content = %v", content)
	}
}
func TestEmbeddingsReturnsResponse(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	result, err := client.Embeddings(embeddingsRequest("gpt-oss-120b"), 5*time.Second)
	if err != nil {
		t.Fatalf("embeddings: %v", err)
	}
	if result["response"].(map[string]any)["object"] != "list" {
		t.Fatalf("object = %v, want list", result["response"].(map[string]any)["object"])
	}
}

func TestVerifyReturnsRouteVerdict(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	verdict, err := client.Verify("demo", "gpt-oss-120b", 5*time.Second)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict["status"] != "verified" || verdict["provider"] != "demo" {
		t.Fatalf("verdict = %v", verdict)
	}
}

func TestResponseReturnsShimObject(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	response, err := client.Response(map[string]any{"model": "gpt-oss-120b", "input": "responses path"}, 5*time.Second)
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	if response["provider"] != "demo" {
		t.Fatalf("provider = %v", response["provider"])
	}
	if response["response"].(map[string]any)["object"] != "response" {
		t.Fatalf("response.object = %v", response["response"])
	}
}
func TestResponseManageReturnsStructuredUnsupportedOperationError(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	_, err = client.ResponseManage(map[string]any{
		"op": "retrieve", "provider": "demo", "provider_response_id": "resp_demo", "params": map[string]any{},
	}, 5*time.Second)
	if err == nil {
		t.Fatal("expected unsupported lifecycle operation")
	}
	if ffiErr := asError(t, err); ffiErr.Code == "" || ffiErr.Dispatch == "" {
		t.Fatalf("response manage error lacks code/dispatch: %+v", ffiErr)
	}
}

func TestModelDiscoveryAndConfidentialityCatalog(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	models, err := client.Models()
	if err != nil {
		t.Fatalf("models: %v", err)
	}
	if _, ok := models["data"].([]any); !ok {
		t.Fatalf("models.data is not an array: %v", models["data"])
	}
	catalog, err := client.Confidentiality()
	if err != nil {
		t.Fatalf("confidentiality: %v", err)
	}
	if len(catalog) == 0 {
		t.Fatal("confidentiality catalog is empty")
	}
}

func TestActivePolicyAndTrustArtifacts(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	policy, err := client.ActivePolicy()
	if err != nil {
		t.Fatalf("active policy: %v", err)
	}
	if policy["schema"] != "confidential-inference.active-policy.v1" {
		t.Fatalf("policy.schema = %v", policy["schema"])
	}
	artifacts, err := client.ActiveTrustArtifacts()
	if err != nil {
		t.Fatalf("active trust artifacts: %v", err)
	}
	for _, key := range []string{"registry_digest", "reference_values_digest"} {
		if _, ok := artifacts[key]; !ok {
			t.Fatalf("artifacts missing %q", key)
		}
	}
}

func TestStreamFailsClosedForNonStreamingRoute(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	var events []map[string]any
	for event, err := range client.Stream(chatRequest("stream path"), 5*time.Second) {
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		events = append(events, event)
	}
	if len(events) != 1 || events[0]["type"] != "error" || events[0]["status"] != "failed" {
		t.Fatalf("events = %v", events)
	}
	detail, _ := events[0]["error"].(map[string]any)
	if detail["code"] != "streaming_not_supported" || detail["dispatch"] != DispatchNotDispatched {
		t.Fatalf("stream error lacks code/dispatch classification: %v", detail)
	}
}

func TestClosedClientRejectsCalls(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := client.Models(); err == nil {
		t.Fatal("models on closed client succeeded")
	} else if ffiErr := asError(t, err); ffiErr.Code != "client_closed" {
		t.Fatalf("error = %v", ffiErr)
	}
}

func TestClientCloseWithLiveStreamFailsAndPreservesHandle(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	stream, err := client.StartStream(chatRequest("live stream"))
	if err != nil {
		t.Fatalf("start stream: %v", err)
	}
	// The pending stream keeps the native client live; freeing must fail
	// without discarding the handle (which would leak both objects).
	err = client.Close()
	ffiErr := asError(t, err)
	if ffiErr.Status != StatusBusy {
		t.Fatalf("close status = %d, want StatusBusy", ffiErr.Status)
	}
	if client.Closed() {
		t.Fatal("client handle discarded on failed free")
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("stream close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if !client.Closed() {
		t.Fatal("client not freed after streams closed")
	}
}

func TestStreamCloseWhileNextInFlightRefusesAndPreservesHandle(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	// Next may return before this goroutine observes it in flight (the demo
	// stream can terminate quickly); retry with a fresh stream until Close
	// provably races a running Next.
	var stream *Stream
	var done chan struct{}
	for observed := false; !observed; {
		stream, err = client.StartStream(chatRequest("busy stream"))
		if err != nil {
			t.Fatalf("start stream: %v", err)
		}
		done = make(chan struct{})
		go func(s *Stream, d chan struct{}) {
			defer close(d)
			_, _ = s.Next(30 * time.Second)
		}(stream, done)
		for {
			stream.mu.Lock()
			inFlight := stream.inFlight
			stream.mu.Unlock()
			if inFlight > 0 {
				observed = true
				break
			}
			select {
			case <-done:
				if err := stream.Close(); err != nil {
					t.Fatalf("close settled stream: %v", err)
				}
			default:
				runtime.Gosched()
				continue
			}
			break
		}
	}
	err = stream.Close()
	ffiErr := asError(t, err)
	if ffiErr.Status != StatusBusy || ffiErr.Code != "stream_busy" {
		t.Fatalf("close error = %v, want stream_busy", ffiErr)
	}
	if stream.Closed() {
		t.Fatal("stream handle discarded while next ran")
	}
	stream.Cancel()
	<-done
	if err := stream.Close(); err != nil {
		t.Fatalf("stream close: %v", err)
	}
}

func TestClientCloseWhileCallInFlightRefusesAndPreservesHandle(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	// The demo call is fast and may finish before this goroutine observes it
	// in flight; retry until Close provably races a running call.
	var done chan error
	for observed := false; !observed; {
		done = make(chan error, 1)
		go func() {
			response, err := client.Chat(chatRequest("in-flight"), 5*time.Second)
			if err == nil && response["verdict"].(map[string]any)["status"] != "verified" {
				err = localError("unexpected_verdict", "chat verdict was not verified")
			}
			done <- err
		}()
		for {
			client.mu.Lock()
			inFlight := client.inFlight
			client.mu.Unlock()
			if inFlight > 0 {
				observed = true
				break
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("chat: %v", err)
				}
			default:
				runtime.Gosched()
				continue
			}
			break
		}
	}
	err = client.Close()
	ffiErr := asError(t, err)
	if ffiErr.Status != StatusBusy || ffiErr.Code != "client_busy" {
		t.Fatalf("close error = %v, want client_busy", ffiErr)
	}
	if client.Closed() {
		t.Fatal("client handle discarded while call ran")
	}
	if err := <-done; err != nil {
		t.Fatalf("chat: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client close after calls settled: %v", err)
	}
}

func TestFailedInferenceSurfacesNativeErrorCode(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	_, err = client.Chat(map[string]any{"nope": true}, 5*time.Second)
	ffiErr := asError(t, err)
	if ffiErr.Status != StatusInvalidArgument {
		t.Fatalf("status = %d, want StatusInvalidArgument", ffiErr.Status)
	}
	if ffiErr.Code != "invalid_request_json" {
		t.Fatalf("code = %q, want invalid_request_json", ffiErr.Code)
	}
	if !strings.Contains(ffiErr.Message, "missing field `model`") {
		t.Fatalf("message = %q", ffiErr.Message)
	}
}

// SDK operation failures must surface as errors, never as a successful result
// map, and must say whether the provider may have processed the request.
func TestOperationFailureIsErrorWithDispatchClassification(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	result, err := client.Chat(map[string]any{
		"model":    "no-such-model",
		"messages": []map[string]any{{"role": "user", "content": "route me"}},
	}, 5*time.Second)
	if result != nil {
		t.Fatalf("failed operation returned a result: %v", result)
	}
	ffiErr := asError(t, err)
	if ffiErr.Status != StatusOperationFailed {
		t.Fatalf("status = %d, want StatusOperationFailed", ffiErr.Status)
	}
	if ffiErr.Dispatch != DispatchNotDispatched || ffiErr.HTTPStatus != 0 {
		t.Fatalf("dispatch = %q http_status = %d, want not_dispatched/0", ffiErr.Dispatch, ffiErr.HTTPStatus)
	}
	if ffiErr.Code == "" || ffiErr.Message == "" {
		t.Fatalf("operation error missing code/message: %+v", ffiErr)
	}
}
func TestEmbeddingsOperationFailureClassified(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	result, err := client.Embeddings(embeddingsRequest("no-such-model"), 5*time.Second)
	if result != nil {
		t.Fatalf("failed operation returned a result: %v", result)
	}
	ffiErr := asError(t, err)
	if ffiErr.Status != StatusOperationFailed || ffiErr.Dispatch != DispatchNotDispatched || ffiErr.HTTPStatus != 0 {
		t.Fatalf("unexpected operation classification: %+v", ffiErr)
	}
	if ffiErr.Code == "" || ffiErr.Message == "" {
		t.Fatalf("operation error missing code/message: %+v", ffiErr)
	}
}

func TestConcurrentFailuresRetainCallSpecificErrors(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	type result struct {
		err error
	}
	results := make(chan result, 2)
	go func() {
		_, err := client.Chat(map[string]any{"nope": true}, 5*time.Second)
		results <- result{err}
	}()
	go func() {
		// Marshal an invalid verify request directly so the error message is
		// verify-specific ("verify request JSON"), matching the Node binding
		// test where undefined fields serialize to {}.
		_, err := client.callJSON(map[string]any{"nope": true}, 5*time.Second, client.native.verifyBlocking)
		results <- result{err}
	}()
	messages := make(map[string]bool)
	for range 2 {
		r := <-results
		if r.err == nil {
			t.Fatal("expected both calls to fail")
		}
		messages[asError(t, r.err).Message] = true
	}
	var hasChat, hasVerify bool
	for message := range messages {
		hasChat = hasChat || strings.Contains(message, "chat request JSON")
		hasVerify = hasVerify || strings.Contains(message, "verify request JSON")
	}
	if !hasChat || !hasVerify {
		t.Fatalf("call-specific messages lost: %v", messages)
	}
}

func TestConcurrentInferenceCallsAllResolve(t *testing.T) {
	client, err := NewClient(demoConfig)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	const fanout = 8
	results := make(chan error, fanout)
	for i := range fanout {
		go func(i int) {
			response, err := client.Chat(chatRequest("fanout"), 5*time.Second)
			if err == nil && response["verdict"].(map[string]any)["status"] != "verified" {
				err = localError("unexpected_verdict", "chat verdict was not verified")
			}
			results <- err
		}(i)
	}
	for i := range fanout {
		if err := <-results; err != nil {
			t.Fatalf("chat %d: %v", i, err)
		}
	}
}

func TestNilConfigFailsClosedWithoutDemoOptIn(t *testing.T) {
	for _, config := range []json.RawMessage{nil, {}, json.RawMessage(`{}`)} {
		_, err := NewClient(config)
		if err == nil {
			t.Fatalf("config %q created a client without demo opt-in", string(config))
		}
		if asError(t, err).Code != "trusted_signing_keys_required" {
			t.Fatalf("config %q: unexpected error %v", string(config), err)
		}
	}
}

func TestExplicitLibraryPathIsExclusiveAndMustExist(t *testing.T) {
	missing := filepath.Join(repoRoot(t), "target", "release", "no_such_lib_ffi.so")
	if _, err := resolveLibraryPath(missing); err == nil {
		t.Fatal("missing explicit path did not fail")
	}
	t.Setenv("CONFIDENTIAL_INFERENCE_FFI_LIBRARY", missing)
	if _, err := resolveLibraryPath(""); err == nil {
		t.Fatal("missing env path did not fail")
	}
	// An existing explicit path resolves to an absolute path.
	tmp := filepath.Join(t.TempDir(), "libconfidential_inference_ffi.so")
	if err := os.WriteFile(tmp, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := resolveLibraryPath(tmp)
	if err != nil {
		t.Fatalf("existing explicit path: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("explicit path not absolute: %s", got)
	}
}
