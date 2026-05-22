package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"request-validator/internal/policy"
	"request-validator/internal/state"
	"request-validator/internal/state/memory"
)

const baseYAML = `
defaults:
  action: deny
groups:
  - name: yaml-only
    action: allow
    rules:
      - name: any
        match: "true"
`

type captureApplier struct {
	mu      sync.Mutex
	last    *policy.Config
	calls   int
	failErr error
}

func (c *captureApplier) Apply(cfg *policy.Config, source string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failErr != nil {
		return c.failErr
	}
	c.calls++
	c.last = cfg
	return nil
}

func setup(t *testing.T) (*Server, *captureApplier, state.Store, func()) {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := memory.New(memory.Options{Path: filepath.Join(dir, "state.json")})
	if err != nil {
		t.Fatal(err)
	}
	app := &captureApplier{}
	srv, err := New(Options{
		Addr:         ":0",
		TokenFile:    tokenPath,
		Store:        store,
		YAMLProvider: func() []byte { return []byte(baseYAML) },
		Applier:      app,
	})
	if err != nil {
		t.Fatal(err)
	}
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	cleanup := func() { _ = store.Close() }
	return srv, app, store, cleanup
}

func newTestHTTPServer(t *testing.T, s *Server) (*httptest.Server, func()) {
	t.Helper()
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	ts := httptest.NewServer(s.requireBearer(mux))
	return ts, ts.Close
}

func req(t *testing.T, method, url, token, body string) *http.Response {
	t.Helper()
	var rb io.Reader
	if body != "" {
		rb = bytes.NewReader([]byte(body))
	}
	r, err := http.NewRequest(method, url, rb)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestRequiresBearerToken(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	resp := req(t, "GET", ts.URL+"/api/v1/groups", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	resp = req(t, "GET", ts.URL+"/api/v1/groups", "wrong-token", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	resp = req(t, "GET", ts.URL+"/api/v1/groups", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPutGetDeleteGroupRoundTrip(t *testing.T) {
	s, app, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	payload := `{"action":"deny","rules":[{"name":"any","match":"true"}]}`
	resp := req(t, "PUT", ts.URL+"/api/v1/groups/api-block", "s3cret", payload)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT got %d: %s", resp.StatusCode, b)
	}
	if app.calls != 1 {
		t.Fatalf("expected 1 apply, got %d", app.calls)
	}

	resp = req(t, "GET", ts.URL+"/api/v1/groups/api-block", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET got %d", resp.StatusCode)
	}
	var view itemView
	_ = json.NewDecoder(resp.Body).Decode(&view)
	if view.Name != "api-block" {
		t.Fatalf("unexpected view: %+v", view)
	}

	resp = req(t, "DELETE", ts.URL+"/api/v1/groups/api-block", "s3cret", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE got %d", resp.StatusCode)
	}
	resp = req(t, "GET", ts.URL+"/api/v1/groups/api-block", "s3cret", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", resp.StatusCode)
	}
}

func TestPutInvalidGroupRejected(t *testing.T) {
	s, app, store, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	// Invalid: empty rules.
	payload := `{"rules":[]}`
	resp := req(t, "PUT", ts.URL+"/api/v1/groups/broken", "s3cret", payload)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if app.calls != 0 {
		t.Fatalf("expected no Apply on failure, got %d", app.calls)
	}
	// Store must NOT have been touched.
	if _, err := store.Get(context.Background(), state.SectionGroups, "broken"); err == nil {
		t.Fatal("expected broken group not in store after failed PUT")
	}
}

func TestPutDefaultsOverlayApplied(t *testing.T) {
	s, app, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	body := `{"denyBody":"override"}`
	resp := req(t, "PUT", ts.URL+"/api/v1/defaults", "s3cret", body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
	}
	if app.last.Defaults.DenyBody != "override" {
		t.Fatalf("expected override, got %q", app.last.Defaults.DenyBody)
	}

	resp = req(t, "DELETE", ts.URL+"/api/v1/defaults", "s3cret", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE got %d", resp.StatusCode)
	}
}

func TestPathNameMismatch(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()
	body := `{"name":"different","rules":[{"name":"any","match":"true"}]}`
	resp := req(t, "PUT", ts.URL+"/api/v1/groups/intended", "s3cret", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestIfMatchConcurrency(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()
	resp := req(t, "PUT", ts.URL+"/api/v1/groups/foo", "s3cret",
		`{"rules":[{"name":"any","match":"true"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first PUT got %d", resp.StatusCode)
	}

	// Stale If-Match should fail.
	r2, _ := http.NewRequest("PUT", ts.URL+"/api/v1/groups/foo",
		strings.NewReader(`{"rules":[{"name":"any","match":"true"}]}`))
	r2.Header.Set("Authorization", "Bearer s3cret")
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Set("If-Match", `"99999-bogus"`)
	resp2, err := http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", resp2.StatusCode)
	}
}

func TestEffectiveConfigEndpoint(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()
	resp := req(t, "GET", ts.URL+"/api/v1/config", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	var v map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&v)
	groups, ok := v["groups"].([]any)
	if !ok || len(groups) == 0 {
		t.Fatalf("expected groups, got %v", v)
	}
}

func TestClusterEndpointStandalone(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()
	resp := req(t, "GET", ts.URL+"/api/v1/cluster", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	var v map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&v)
	if v["standalone"] != true {
		t.Fatalf("expected standalone=true, got %v", v)
	}
	if v["iAmLeader"] != true {
		t.Fatalf("expected iAmLeader=true (no cluster), got %v", v)
	}
}

func TestTokenReloadOnFileChange(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, _ := memory.New(memory.Options{Path: filepath.Join(dir, "s.json")})
	defer store.Close()
	srv, err := New(Options{
		Addr:         ":0",
		TokenFile:    tokenPath,
		Store:        store,
		YAMLProvider: func() []byte { return []byte(baseYAML) },
		Applier:      &captureApplier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.tokenWatchCancel = cancel
	srv.tokenWatchWG.Add(1)
	go func() {
		defer srv.tokenWatchWG.Done()
		srv.watchTokenFile(ctx)
	}()
	time.Sleep(100 * time.Millisecond)

	if got := srv.currentTokenForTest(); got != "first" {
		t.Fatalf("expected first, got %q", got)
	}
	if err := os.WriteFile(tokenPath, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.currentTokenForTest() == "second" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("token did not reload; got %q", srv.currentTokenForTest())
}

func TestServerListenIntegration(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	s.opts.Addr = addr

	go func() { _ = s.Run() }()
	defer s.Stop()

	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		r, _ := http.NewRequest("GET", "http://"+addr+"/api/v1/config", nil)
		r.Header.Set("Authorization", "Bearer s3cret")
		var dErr error
		resp, dErr = http.DefaultClient.Do(r)
		if dErr == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		code := -1
		if resp != nil {
			code = resp.StatusCode
		}
		t.Fatalf("admin server unreachable: status=%d", code)
	}
}

func TestRouteLabelNormalisation(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/api/v1/groups", "/api/v1/groups"},
		{"/api/v1/groups/anything", "/api/v1/groups/{name}"},
		{"/api/v1/facts/x", "/api/v1/facts/{name}"},
		{"/api/v1/defaults", "/api/v1/defaults"},
		{"/api/v1/cluster", "/api/v1/cluster"},
		{"/api/v1/openapi.json", "/api/v1/openapi.json"},
		{"/healthz", "/healthz"},
	}
	for _, c := range cases {
		if got := routeLabel(c.in); got != c.want {
			t.Errorf("routeLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestReadBodyRejectsLargeContentLength(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	big := bytes.Repeat([]byte("a"), (1<<20)+10)
	r, _ := http.NewRequest("PUT", ts.URL+"/api/v1/groups/big",
		bytes.NewReader(big))
	r.Header.Set("Authorization", "Bearer s3cret")
	r.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestUnknownMethodReturns405(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()
	resp := req(t, "PATCH", ts.URL+"/api/v1/config", "s3cret", "")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestOpenAPISpecExposed(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	resp := req(t, "GET", ts.URL+"/api/v1/openapi.json", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	var v map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v["openapi"] != "3.1.0" {
		t.Fatalf("expected 3.1.0, got %v", v["openapi"])
	}
}

func TestRegisterPutAndDeleteLogging(t *testing.T) {
	s, app, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	// PUT logging override.
	resp := req(t, "PUT", ts.URL+"/api/v1/logging", "s3cret",
		`{"level":"debug"}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
	}
	if app.last.Logging.Level != "debug" {
		t.Fatalf("expected level=debug, got %q", app.last.Logging.Level)
	}

	// GET logging.
	resp = req(t, "GET", ts.URL+"/api/v1/logging", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET logging: %d", resp.StatusCode)
	}

	// DELETE logging.
	resp = req(t, "DELETE", ts.URL+"/api/v1/logging", "s3cret", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE logging: %d", resp.StatusCode)
	}
	// GET after delete: 404.
	resp = req(t, "GET", ts.URL+"/api/v1/logging", "s3cret", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", resp.StatusCode)
	}
}

func TestRegisterPutInvalidJSON(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	resp := req(t, "PUT", ts.URL+"/api/v1/defaults", "s3cret",
		`{"action":"not-a-valid-action"`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestRegisterPutValidationFails(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	// defaults.action must be allow|deny; "yolo" fails validation.
	resp := req(t, "PUT", ts.URL+"/api/v1/defaults", "s3cret",
		`{"action":"yolo"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 from validator, got %d", resp.StatusCode)
	}
}

func TestRegisterDeleteWhenAbsent(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	// Defaults overlay was never set; DELETE should return 404.
	resp := req(t, "DELETE", ts.URL+"/api/v1/defaults", "s3cret", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestRegisterUnknownMethodIs405(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	resp := req(t, "POST", ts.URL+"/api/v1/defaults", "s3cret", `{}`)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestItemPutDeleteFact(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	body := `{"method":"value","value":["1.1.1.1"]}`
	resp := req(t, "PUT", ts.URL+"/api/v1/facts/blocklist", "s3cret", body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT fact: %d %s", resp.StatusCode, b)
	}

	resp = req(t, "GET", ts.URL+"/api/v1/facts", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LIST facts: %d", resp.StatusCode)
	}

	resp = req(t, "DELETE", ts.URL+"/api/v1/facts/blocklist", "s3cret", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE fact: %d", resp.StatusCode)
	}
}

func TestItemDeleteWhenAbsent(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	resp := req(t, "DELETE", ts.URL+"/api/v1/groups/never-existed", "s3cret", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestItemPutEmptyBody(t *testing.T) {
	s, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	// Empty body fails JSON decode → 400.
	resp := req(t, "PUT", ts.URL+"/api/v1/groups/blank", "s3cret", "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestParseIfMatchHelpers(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{`"abc"`, "abc"},
		{`abc`, "abc"},
		{`"42-podA"`, "42-podA"},
		{`"*"`, "*"},
	}
	for _, c := range cases {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("If-Match", c.in)
		got := string(parseIfMatch(r))
		if got != c.want {
			t.Errorf("parseIfMatch(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
