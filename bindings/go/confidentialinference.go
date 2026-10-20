// Package confidentialinference is a thin Go binding for the Confidential
// Inference SDK C ABI. Routing, attestation, policy, digest, and signature
// decisions remain in Rust; this package only moves JSON across the ABI.
//
// The binding loads libconfidential_inference_ffi at run time (no cgo), so
// callers must first build the shared library:
//
//	cargo build -p confidential-inference-ffi --locked
//
// Resolution order matches the Python and Node bindings: an explicit
// WithLibraryPath option, then the CONFIDENTIAL_INFERENCE_FFI_LIBRARY
// environment variable, then target/debug and target/release under the
// repository root and the process working directory.
package confidentialinference

import (
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

// FFI status codes from confidential_inference_ffi.h.
const (
	StatusOK              = 0
	StatusInvalidArgument = 1
	StatusPanic           = 2
	StatusBusy            = 3
	StatusPending         = 4
	StatusUnsupported     = 5
	StatusInternal        = 6
)

// Error is a failure reported by the FFI. Status is one of the Status*
// constants; Code and Message come from the FFI error envelope.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func localError(code, message string) error {
	return &Error{Status: StatusInvalidArgument, Code: code, Message: message}
}

// Option configures NewClient and Status.
type Option func(*options)

type options struct {
	libraryPath string
}

// WithLibraryPath selects an explicit shared library path, overriding
// CONFIDENTIAL_INFERENCE_FFI_LIBRARY and the default search paths.
func WithLibraryPath(path string) Option {
	return func(o *options) { o.libraryPath = path }
}

// native wraps the loaded shared library and its bound functions.
type native struct {
	path   string
	handle uintptr

	status                  func(out *unsafe.Pointer) int32
	sdkNew                  func(configJSON unsafe.Pointer, outClient *unsafe.Pointer) int32
	sdkFree                 func(client unsafe.Pointer) int32
	chatBlocking            func(client unsafe.Pointer, requestJSON unsafe.Pointer, timeoutMS uint64, out *unsafe.Pointer) int32
	responseBlocking        func(client unsafe.Pointer, requestJSON unsafe.Pointer, timeoutMS uint64, out *unsafe.Pointer) int32
	verifyBlocking          func(client unsafe.Pointer, requestJSON unsafe.Pointer, timeoutMS uint64, out *unsafe.Pointer) int32
	modelsBlocking          func(client unsafe.Pointer, out *unsafe.Pointer) int32
	confidentialityBlocking func(client unsafe.Pointer, out *unsafe.Pointer) int32
	activePolicyBlocking    func(client unsafe.Pointer, out *unsafe.Pointer) int32
	activeArtifactsBlocking func(client unsafe.Pointer, out *unsafe.Pointer) int32
	chatStreamStart         func(client unsafe.Pointer, requestJSON unsafe.Pointer, outStream *unsafe.Pointer) int32
	streamNext              func(stream unsafe.Pointer, timeoutMS uint64, out *unsafe.Pointer) int32
	streamCancel            func(stream unsafe.Pointer) int32
	streamFree              func(stream unsafe.Pointer) int32
	lastError               func(out *unsafe.Pointer) int32
	stringFree              func(ptr unsafe.Pointer)
}

func openNative(opts []Option) (*native, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	path, err := resolveLibraryPath(o.libraryPath)
	if err != nil {
		return nil, err
	}
	n := &native{path: path}
	if n.handle, err = openLibrary(path); err != nil {
		return nil, &Error{Status: StatusInvalidArgument, Code: "library_load_failed", Message: err.Error()}
	}
	bindings := map[string]any{
		"confidential_inference_status":                          &n.status,
		"confidential_inference_sdk_new":                         &n.sdkNew,
		"confidential_inference_sdk_free":                        &n.sdkFree,
		"confidential_inference_chat_blocking":                   &n.chatBlocking,
		"confidential_inference_response_blocking":               &n.responseBlocking,
		"confidential_inference_verify_blocking":                 &n.verifyBlocking,
		"confidential_inference_models_blocking":                 &n.modelsBlocking,
		"confidential_inference_confidentiality_blocking":        &n.confidentialityBlocking,
		"confidential_inference_active_policy_blocking":          &n.activePolicyBlocking,
		"confidential_inference_active_trust_artifacts_blocking": &n.activeArtifactsBlocking,
		"confidential_inference_chat_stream_start":               &n.chatStreamStart,
		"confidential_inference_stream_next":                     &n.streamNext,
		"confidential_inference_stream_cancel":                   &n.streamCancel,
		"confidential_inference_stream_free":                     &n.streamFree,
		"confidential_inference_last_error":                      &n.lastError,
		"confidential_inference_string_free":                     &n.stringFree,
	}
	for name, target := range bindings {
		symbol, err := lookupSymbol(n.handle, name)
		if err != nil {
			closeLibrary(n.handle)
			return nil, &Error{Status: StatusInvalidArgument, Code: "library_load_failed", Message: fmt.Sprintf("%s: %v", name, err)}
		}
		purego.RegisterFunc(target, symbol)
	}
	return n, nil
}

// run executes fn on a locked OS thread. The FFI records errors in
// thread-local storage, so a failing call and the error fetch must run on the
// same thread; the Go scheduler may otherwise migrate the goroutine.
func run[T any](fn func() T) T {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return fn()
}

// run2 is run for functions returning two values.
func run2[A any, B any](fn func() (A, B)) (A, B) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return fn()
}

// takeJSON copies a C string returned by the FFI, releases it through
// confidential_inference_string_free, and decodes the JSON into out.
func (n *native) takeJSON(ptr unsafe.Pointer, out any) error {
	if ptr == nil {
		return &Error{Status: StatusInternal, Code: "missing_string", Message: "FFI returned a null JSON pointer"}
	}
	text := goString(ptr)
	n.stringFree(ptr)
	if err := json.Unmarshal([]byte(text), out); err != nil {
		return &Error{Status: StatusInternal, Code: "malformed_json", Message: err.Error()}
	}
	return nil
}

// ffiErrorDetail is the error object inside the FFI error envelope.
type ffiErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// statusError converts a failed FFI status into an error. If out carries the
// call-specific error envelope it is consumed; otherwise the thread-local
// last_error is read. Call only inside run(), on the thread that made the
// failing call.

func (n *native) statusError(status int32, out unsafe.Pointer) error {
	if status == StatusOK {
		return nil
	}
	if out != nil {
		var envelope struct {
			Error *ffiErrorDetail `json:"error"`
		}
		if err := n.takeJSON(out, &envelope); err == nil && envelope.Error != nil {
			return &Error{Status: int(status), Code: envelope.Error.Code, Message: envelope.Error.Message}
		}
	}
	if detail := n.lastErrorDetail(); detail != nil {
		return &Error{Status: int(status), Code: detail.Code, Message: detail.Message}
	}
	return &Error{
		Status:  int(status),
		Code:    "ffi_error",
		Message: fmt.Sprintf("confidential-inference FFI call failed with status %d", status),
	}
}

func (n *native) lastErrorDetail() *ffiErrorDetail {
	var out unsafe.Pointer
	if n.lastError(&out) != StatusOK || out == nil {
		return nil
	}
	var envelope struct {
		Error *ffiErrorDetail `json:"error"`
	}
	if err := n.takeJSON(out, &envelope); err != nil {
		return nil
	}
	return envelope.Error
}

// statusObject calls confidential_inference_status and returns its JSON.
func (n *native) statusObject() (map[string]any, error) {
	return run2(func() (map[string]any, error) {
		var out unsafe.Pointer
		status := n.status(&out)
		if err := n.statusError(status, out); err != nil {
			return nil, err
		}
		var obj map[string]any
		if err := n.takeJSON(out, &obj); err != nil {
			return nil, err
		}
		return obj, nil
	})
}

// Status reports the FFI capability JSON without creating a client.
func Status(opts ...Option) (map[string]any, error) {
	n, err := openNative(opts)
	if err != nil {
		return nil, err
	}
	defer closeLibrary(n.handle)
	return n.statusObject()
}

// Client is a handle to a native ConfidentialInferenceFfiClient. It is safe
// for concurrent use; calls block the calling goroutine only.
type Client struct {
	native   *native
	mu       sync.Mutex
	handle   unsafe.Pointer
	inFlight int
}

// NewClient creates a client from a JSON configuration. Pass nil for the
// default configuration, which installs the offline demo provider. See the
// Python and Node bindings for the configuration schema.
func NewClient(config json.RawMessage, opts ...Option) (*Client, error) {
	n, err := openNative(opts)
	if err != nil {
		return nil, err
	}
	client := &Client{native: n}
	err = run(func() error {
		var cfg unsafe.Pointer
		var buf []byte
		if len(config) > 0 {
			buf = append(append([]byte(nil), config...), 0)
			cfg = unsafe.Pointer(&buf[0])
		}
		var out unsafe.Pointer
		status := n.sdkNew(cfg, &out)
		runtime.KeepAlive(buf)
		if err := n.statusError(status, nil); err != nil {
			return err
		}
		client.handle = out
		return nil
	})
	if err != nil {
		closeLibrary(n.handle)
		return nil, err
	}
	return client, nil
}

// acquire marks the client handle in use for the duration of a call so Close
// cannot free it out from under the FFI.
func (c *Client) acquire() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handle == nil {
		return &Error{Status: StatusInvalidArgument, Code: "client_closed", Message: "client is closed"}
	}
	c.inFlight++
	return nil
}

func (c *Client) release() {
	c.mu.Lock()
	c.inFlight--
	c.mu.Unlock()
}

// Closed reports whether Close has freed the native handle.
func (c *Client) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handle == nil
}

// Close frees the native client. It fails with StatusBusy while any call is
// in flight or any stream from this client is still open; the handle is
// preserved so the call can be retried.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handle == nil {
		return nil
	}
	// Refuse to free while a call still holds the handle: the FFI would drop
	// the allocation under the running call (use-after-free).
	if c.inFlight > 0 {
		return &Error{Status: StatusBusy, Code: "client_busy", Message: "client has in-flight calls; wait for them before closing"}
	}
	status, detail := run2(func() (int32, error) {
		st := c.native.sdkFree(c.handle)
		return st, c.native.statusError(st, nil)
	})
	if status == StatusOK {
		c.handle = nil
		closeLibrary(c.native.handle)
		return nil
	}
	// FFI_BUSY means live streams still reference the client; keep the handle
	// so the caller can close them and retry instead of leaking the client.
	return detail
}

// Status reports the FFI capability JSON.
func (c *Client) Status() (map[string]any, error) {
	return c.native.statusObject()
}

// callJSON runs a blocking (client, requestJSON, timeoutMS, out) FFI call.
func (c *Client) callJSON(request any, timeout time.Duration, fn func(unsafe.Pointer, unsafe.Pointer, uint64, *unsafe.Pointer) int32) (map[string]any, error) {
	if timeout < 0 {
		return nil, localError("invalid_argument", "timeout must not be negative")
	}
	req, err := marshalJSON(request)
	if err != nil {
		return nil, err
	}
	if err := c.acquire(); err != nil {
		return nil, err
	}
	defer c.release()
	return run2(func() (map[string]any, error) {
		var out unsafe.Pointer
		status := fn(c.handle, unsafe.Pointer(&req[0]), uint64(timeout.Milliseconds()), &out)
		runtime.KeepAlive(req)
		if err := c.native.statusError(status, out); err != nil {
			return nil, err
		}
		var obj map[string]any
		if err := c.native.takeJSON(out, &obj); err != nil {
			return nil, err
		}
		return obj, nil
	})
}

// callNoRequestJSON runs a blocking (client, out) FFI call.
func (c *Client) callNoRequestJSON(fn func(unsafe.Pointer, *unsafe.Pointer) int32) (any, error) {
	if err := c.acquire(); err != nil {
		return nil, err
	}
	defer c.release()
	return run2(func() (any, error) {
		var out unsafe.Pointer
		status := fn(c.handle, &out)
		if err := c.native.statusError(status, out); err != nil {
			return nil, err
		}
		var value any
		if err := c.native.takeJSON(out, &value); err != nil {
			return nil, err
		}
		return value, nil
	})
}

// Chat runs a blocking Chat Completions request. request is marshaled to the
// OpenAI-shaped JSON the FFI expects. timeout == 0 waits indefinitely;
// otherwise expiry returns an *Error with Status StatusPending.
func (c *Client) Chat(request any, timeout time.Duration) (map[string]any, error) {
	return c.callJSON(request, timeout, c.native.chatBlocking)
}

// CreateResponse runs a blocking Responses request.
func (c *Client) CreateResponse(request any, timeout time.Duration) (map[string]any, error) {
	return c.callJSON(request, timeout, c.native.responseBlocking)
}

// Response is an alias for CreateResponse.
func (c *Client) Response(request any, timeout time.Duration) (map[string]any, error) {
	return c.CreateResponse(request, timeout)
}

// Verify verifies the route for provider and model and returns the verdict.
func (c *Client) Verify(provider, model string, timeout time.Duration) (map[string]any, error) {
	return c.callJSON(map[string]any{"provider": provider, "model": model}, timeout, c.native.verifyBlocking)
}

// Models returns the model listing object.
func (c *Client) Models() (map[string]any, error) {
	value, err := c.callNoRequestJSON(c.native.modelsBlocking)
	if err != nil {
		return nil, err
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, &Error{Status: StatusInternal, Code: "malformed_json_object", Message: "models response is not a JSON object"}
	}
	return obj, nil
}

// ConfidentialModels returns the confidentiality catalog array.
func (c *Client) ConfidentialModels() ([]any, error) {
	value, err := c.callNoRequestJSON(c.native.confidentialityBlocking)
	if err != nil {
		return nil, err
	}
	list, ok := value.([]any)
	if !ok {
		return nil, &Error{Status: StatusInternal, Code: "malformed_json_array", Message: "confidentiality response is not a JSON array"}
	}
	return list, nil
}

// Confidentiality is an alias for ConfidentialModels.
func (c *Client) Confidentiality() ([]any, error) {
	return c.ConfidentialModels()
}

// ActivePolicy returns the active policy object.
func (c *Client) ActivePolicy() (map[string]any, error) {
	value, err := c.callNoRequestJSON(c.native.activePolicyBlocking)
	if err != nil {
		return nil, err
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, &Error{Status: StatusInternal, Code: "malformed_json_object", Message: "active policy response is not a JSON object"}
	}
	return obj, nil
}

// ActiveTrustArtifacts returns the active trust-artifact digest object.
func (c *Client) ActiveTrustArtifacts() (map[string]any, error) {
	value, err := c.callNoRequestJSON(c.native.activeArtifactsBlocking)
	if err != nil {
		return nil, err
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, &Error{Status: StatusInternal, Code: "malformed_json_object", Message: "active trust artifacts response is not a JSON object"}
	}
	return obj, nil
}

// StartStream opens a chat stream for request. The demo and other
// non-streaming routes still start a stream whose first event is a terminal
// error event; Close it before closing the client.
func (c *Client) StartStream(request any) (*Stream, error) {
	req, err := marshalJSON(request)
	if err != nil {
		return nil, err
	}
	if err := c.acquire(); err != nil {
		return nil, err
	}
	defer c.release()
	return run2(func() (*Stream, error) {
		var out unsafe.Pointer
		status := c.native.chatStreamStart(c.handle, unsafe.Pointer(&req[0]), &out)
		runtime.KeepAlive(req)
		if err := c.native.statusError(status, nil); err != nil {
			return nil, err
		}
		return &Stream{native: c.native, handle: out}, nil
	})
}

// Stream iterates the events of a chat stream until a terminal event
// (closed, done, cancelled, or error) or an error. The stream is closed when
// iteration ends, including early breaks. Non-terminal events arrive with
// err == nil.
func (c *Client) Stream(request any, pollTimeout time.Duration) iter.Seq2[map[string]any, error] {
	return func(yield func(map[string]any, error) bool) {
		stream, err := c.StartStream(request)
		if err != nil {
			yield(nil, err)
			return
		}
		for {
			event, err := stream.Next(pollTimeout)
			if err != nil {
				yield(nil, err)
				_ = stream.Close()
				return
			}
			if event == nil {
				continue
			}
			terminal := isTerminalEvent(event)
			if !yield(event, nil) {
				_ = stream.Close()
				return
			}
			if terminal {
				if err := stream.Close(); err != nil {
					yield(nil, err)
				}
				return
			}
		}
	}
}

// Stream is a handle to a native chat event stream.
type Stream struct {
	native   *native
	mu       sync.Mutex
	handle   unsafe.Pointer
	inFlight int
}

func (s *Stream) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handle == nil
}

// Next waits up to pollTimeout for the next event. It returns (nil, nil)
// when no event is ready within pollTimeout; pollTimeout == 0 is a
// non-blocking poll.
func (s *Stream) Next(pollTimeout time.Duration) (map[string]any, error) {
	if pollTimeout < 0 {
		return nil, localError("invalid_argument", "poll timeout must not be negative")
	}
	s.mu.Lock()
	if s.handle == nil {
		s.mu.Unlock()
		return nil, &Error{Status: StatusInvalidArgument, Code: "stream_closed", Message: "stream is closed"}
	}
	s.inFlight++
	handle := s.handle
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inFlight--
		s.mu.Unlock()
	}()
	return run2(func() (map[string]any, error) {
		var out unsafe.Pointer
		status := s.native.streamNext(handle, uint64(pollTimeout.Milliseconds()), &out)
		if status == StatusPending {
			return nil, nil
		}
		if err := s.native.statusError(status, out); err != nil {
			return nil, err
		}
		var event map[string]any
		if err := s.native.takeJSON(out, &event); err != nil {
			return nil, err
		}
		return event, nil
	})
}

// Cancel requests stream cancellation; the terminal cancelled event is still
// delivered by Next. It is a no-op on a closed stream.
func (s *Stream) Cancel() {
	s.mu.Lock()
	handle := s.handle
	s.mu.Unlock()
	if handle != nil {
		s.native.streamCancel(handle)
	}
}

// Close cancels (if still live) and frees the stream. It fails with
// StatusBusy while a Next call is in flight; the handle is preserved for
// retry. Close it before closing the owning client.
func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return nil
	}
	if s.inFlight > 0 {
		return &Error{Status: StatusBusy, Code: "stream_busy", Message: "stream has in-flight calls; wait for them before closing"}
	}
	// Cancel first so the native handle is never left pending: stream_free
	// refuses (StatusBusy) to free a live stream, which would leak it.
	s.native.streamCancel(s.handle)
	status, detail := run2(func() (int32, error) {
		st := s.native.streamFree(s.handle)
		return st, s.native.statusError(st, nil)
	})
	if status == StatusOK {
		s.handle = nil
		return nil
	}
	return detail
}

// isTerminalEvent reports whether event ends the stream.
func isTerminalEvent(event map[string]any) bool {
	t, _ := event["type"].(string)
	switch strings.ToLower(t) {
	case "closed", "done", "cancelled", "error":
		return true
	}
	return false
}

func marshalJSON(request any) ([]byte, error) {
	req, err := json.Marshal(request)
	if err != nil {
		return nil, localError("invalid_request_json", err.Error())
	}
	if len(req) == 0 {
		return nil, localError("invalid_request_json", "request marshals to empty JSON")
	}
	return append(req, 0), nil
}

// goString copies a NUL-terminated C string. The copy outlives
// confidential_inference_string_free.
func goString(ptr unsafe.Pointer) string {
	if ptr == nil {
		return ""
	}
	p := unsafe.Slice((*byte)(ptr), 1<<30)
	end := 0
	for p[end] != 0 {
		end++
	}
	return string(p[:end])
}

func libraryName() string {
	switch runtime.GOOS {
	case "darwin":
		return "libconfidential_inference_ffi.dylib"
	case "windows":
		return "confidential_inference_ffi.dll"
	default:
		return "libconfidential_inference_ffi.so"
	}
}

// resolveLibraryPath mirrors the Python and Node bindings: explicit option,
// then CONFIDENTIAL_INFERENCE_FFI_LIBRARY, then target/{debug,release} under
// the repository root and the working directory.
func resolveLibraryPath(explicit string) (string, error) {
	var candidates []string
	if explicit != "" {
		candidates = append(candidates, explicit)
	}
	if env := os.Getenv("CONFIDENTIAL_INFERENCE_FFI_LIBRARY"); env != "" {
		candidates = append(candidates, env)
	}
	name := libraryName()
	// Locate the repository root relative to this source file so the binding
	// works before the module is fetched into the module cache.
	_, source, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	for _, root := range []string{repoRoot, "."} {
		candidates = append(candidates, filepath.Join(root, "target", "debug", name))
		candidates = append(candidates, filepath.Join(root, "target", "release", name))
	}
	seen := make(map[string]bool)
	for _, candidate := range candidates {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		if _, err := os.Stat(candidate); err == nil {
			abs, err := filepath.Abs(candidate)
			if err == nil {
				return abs, nil
			}
			return candidate, nil
		}
	}
	searched := make([]string, 0, len(seen))
	for candidate := range seen {
		searched = append(searched, candidate)
	}
	return "", &Error{
		Status:  StatusInvalidArgument,
		Code:    "library_not_found",
		Message: fmt.Sprintf("could not find confidential-inference FFI library; searched %s", strings.Join(searched, ", ")),
	}
}
