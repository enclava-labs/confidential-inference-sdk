package confidentialinference

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

	client, err := NewClient(nil)
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

func TestVerifyReturnsRouteVerdict(t *testing.T) {
	client, err := NewClient(nil)
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
	client, err := NewClient(nil)
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

func TestModelDiscoveryAndConfidentialityCatalog(t *testing.T) {
	client, err := NewClient(nil)
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
	client, err := NewClient(nil)
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
	client, err := NewClient(nil)
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
	// The demo route does not support streaming; the SDK fails closed with a
	// structured error event instead of emitting an unverified stream.
	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}
	if events[0]["type"] != "error" || events[0]["status"] != "failed" {
		t.Fatalf("first event = %v", events[0])
	}
}

func TestClosedClientRejectsCalls(t *testing.T) {
	client, err := NewClient(nil)
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
	client, err := NewClient(nil)
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
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	stream, err := client.StartStream(chatRequest("busy stream"))
	if err != nil {
		t.Fatalf("start stream: %v", err)
	}
	// A 30s poll keeps stream_next blocked inside the FFI, so Close observes a
	// deterministically in-flight call once inFlight is bumped.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = stream.Next(30 * time.Second)
	}()
	for {
		stream.mu.Lock()
		inFlight := stream.inFlight
		stream.mu.Unlock()
		if inFlight > 0 {
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
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	done := make(chan error, 1)
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
	client, err := NewClient(nil)
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

func TestConcurrentFailuresRetainCallSpecificErrors(t *testing.T) {
	client, err := NewClient(nil)
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
	client, err := NewClient(nil)
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
