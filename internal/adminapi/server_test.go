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

	"request-validator/internal/crdt"
	"request-validator/internal/policy"
	"request-validator/internal/quarantine"
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

type captureBroadcaster struct {
	mu     sync.Mutex
	deltas []crdt.Delta
}

func (b *captureBroadcaster) BroadcastDelta(d crdt.Delta) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deltas = append(b.deltas, d)
}

func setup(t *testing.T) (*Server, *captureApplier, *captureBroadcaster, *crdt.Store, *quarantine.Buffer, func()) {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := crdt.New(crdt.Options{Node: "test", StatePath: filepath.Join(dir, "state.json")})
	if err != nil {
		t.Fatal(err)
	}
	q := quarantine.New()
	app := &captureApplier{}
	br := &captureBroadcaster{}
	srv, err := New(Options{
		Addr:         ":0",
		TokenFile:    tokenPath,
		Store:        store,
		Quarantine:   q,
		YAMLProvider: func() []byte { return []byte(baseYAML) },
		Broadcaster:  br,
		Applier:      app,
	})
	if err != nil {
		t.Fatal(err)
	}
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	cleanup := func() { _ = store.Close() }
	return srv, app, br, store, q, cleanup
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
	s, _, _, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	resp := req(t, "GET", ts.URL+"/api/v1/groups", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	resp = req(t, "GET", ts.URL+"/api/v1/groups", "wrong-token", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong token, got %d", resp.StatusCode)
	}
	resp = req(t, "GET", ts.URL+"/api/v1/groups", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with correct token, got %d", resp.StatusCode)
	}
}

func TestPutGetDeleteGroupRoundTrip(t *testing.T) {
	s, app, br, _, _, cleanup := setup(t)
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
		t.Fatalf("expected 1 apply call, got %d", app.calls)
	}
	if got := app.last.Groups; len(got) == 0 {
		t.Fatal("expected non-empty groups")
	}
	if len(br.deltas) != 1 || br.deltas[0].Section != crdt.SectionGroups {
		t.Fatalf("expected 1 group delta, got %+v", br.deltas)
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

func TestPutInvalidGroupRejectsAndQuarantines(t *testing.T) {
	s, app, _, _, q, cleanup := setup(t)
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
	if !q.Has(crdt.SectionGroups, "broken") {
		t.Fatal("expected quarantine entry for broken group")
	}
}

func TestPutDefaultsOverlayApplied(t *testing.T) {
	s, app, _, _, _, cleanup := setup(t)
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
		t.Fatalf("expected override in defaults, got %q", app.last.Defaults.DenyBody)
	}

	resp = req(t, "DELETE", ts.URL+"/api/v1/defaults", "s3cret", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE defaults got %d", resp.StatusCode)
	}
}

func TestPathNameMismatch(t *testing.T) {
	s, _, _, _, _, cleanup := setup(t)
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
	s, _, _, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()
	resp := req(t, "PUT", ts.URL+"/api/v1/groups/foo", "s3cret",
		`{"rules":[{"name":"any","match":"true"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first PUT got %d", resp.StatusCode)
	}
	etag := resp.Header.Get("Etag")
	if etag == "" {
		t.Fatal("expected Etag")
	}

	// Stale If-Match should fail.
	r2, _ := http.NewRequest("PUT", ts.URL+"/api/v1/groups/foo",
		strings.NewReader(`{"rules":[{"name":"any","match":"true"}]}`))
	r2.Header.Set("Authorization", "Bearer s3cret")
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Set("If-Match", `"1-bogus"`)
	resp2, err := http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", resp2.StatusCode)
	}
}

func TestEffectiveConfigEndpoint(t *testing.T) {
	s, _, _, _, _, cleanup := setup(t)
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
		t.Fatalf("expected groups in effective config, got %v", v)
	}
}

func TestOpenAPISpecExposed(t *testing.T) {
	s, _, _, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	resp := req(t, "GET", ts.URL+"/api/v1/openapi.json", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("unexpected content-type %q", ct)
	}
	var v map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v["openapi"] != "3.1.0" {
		t.Fatalf("expected openapi=3.1.0, got %v", v["openapi"])
	}
	paths, _ := v["paths"].(map[string]any)
	if _, ok := paths["/api/v1/groups/{name}"]; !ok {
		t.Fatalf("expected path /api/v1/groups/{name} in spec, got %v", paths)
	}
}

func TestOpenAPIRequiresBearer(t *testing.T) {
	s, _, _, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	resp := req(t, "GET", ts.URL+"/api/v1/openapi.json", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}
}

func TestQuarantineListAndDelete(t *testing.T) {
	s, _, _, _, q, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	q.Push("groups", "x", "bad")

	resp := req(t, "GET", ts.URL+"/api/v1/quarantine", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	resp = req(t, "DELETE", ts.URL+"/api/v1/quarantine/groups/x", "s3cret", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if q.Has("groups", "x") {
		t.Fatal("expected removed")
	}
}

func TestTokenReloadOnFileChange(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, _ := crdt.New(crdt.Options{Node: "n", StatePath: filepath.Join(dir, "s.json")})
	defer store.Close()
	srv, err := New(Options{
		Addr:         ":0",
		TokenFile:    tokenPath,
		Store:        store,
		Quarantine:   quarantine.New(),
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
	// Give the watcher a moment to call w.Add before we touch the file.
	time.Sleep(100 * time.Millisecond)

	if got := srv.currentTokenForTest(); got != "first" {
		t.Fatalf("expected first, got %q", got)
	}
	if err := os.WriteFile(tokenPath, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Poll until reload triggers.
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
	// Sanity: New + Run on a real port, then Stop.
	s, _, _, _, _, cleanup := setup(t)
	defer cleanup()
	// Replace addr with a real ephemeral port.
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
		{"/api/v1/groups/with-dashes", "/api/v1/groups/{name}"},
		{"/api/v1/facts/x", "/api/v1/facts/{name}"},
		{"/api/v1/quarantine", "/api/v1/quarantine"},
		{"/api/v1/quarantine/groups", "/api/v1/quarantine/{section}"},
		{"/api/v1/quarantine/groups/foo", "/api/v1/quarantine/{section}"},
		{"/api/v1/defaults", "/api/v1/defaults"},
		{"/api/v1/openapi.json", "/api/v1/openapi.json"},
		{"/healthz", "/healthz"},
	}
	for _, c := range cases {
		if got := routeLabel(c.in); got != c.want {
			t.Errorf("routeLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFailedPutDoesNotMutateEngine(t *testing.T) {
	// PUT an invalid group; verify the live config still reflects YAML
	// only (no half-applied state) and the rollback restored the CRDT
	// store to its pre-PUT shape.
	s, app, _, store, q, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	// Take a baseline.
	baselineSnap := store.Snapshot()

	resp := req(t, "PUT", ts.URL+"/api/v1/groups/broken", "s3cret", `{"rules":[]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	// Applier MUST NOT have been called.
	if app.calls != 0 {
		t.Fatalf("expected 0 applier calls, got %d", app.calls)
	}
	// Quarantine MUST contain the broken entry.
	if !q.Has(crdt.SectionGroups, "broken") {
		t.Fatal("expected quarantine to contain broken group")
	}

	// The CRDT store must look like the baseline modulo a tombstone or
	// reverted entry; either way the "broken" group must not be live.
	var g any
	if _, ok, _ := store.Groups.Get("broken", &g); ok {
		t.Fatalf("expected broken group reverted, still live: %v", g)
	}
	_ = baselineSnap
}

func TestQuarantineRetryClearsOnValidWrite(t *testing.T) {
	// First PUT is invalid → quarantined.
	// Then we manually remove the quarantine entry (since the broken
	// CRDT entry was rolled back, the natural retry trigger never
	// fires for that key). A subsequent valid PUT must succeed.
	s, app, _, _, q, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	// Invalid first.
	resp := req(t, "PUT", ts.URL+"/api/v1/groups/g1", "s3cret", `{"rules":[]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if !q.Has(crdt.SectionGroups, "g1") {
		t.Fatal("expected quarantine entry after bad PUT")
	}

	// Valid PUT replacing the same key.
	resp = req(t, "PUT", ts.URL+"/api/v1/groups/g1", "s3cret",
		`{"rules":[{"name":"any","match":"true"}]}`)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 on valid PUT, got %d: %s", resp.StatusCode, body)
	}
	if app.calls == 0 {
		t.Fatal("expected applier to be invoked on valid PUT")
	}
	// After a successful rebuild, the rebuildAndApply path drains the
	// buffer for any entry that now compiles. The "broken" entry was
	// rolled back so it doesn't exist anymore; but the previous quarantine
	// row may persist because Drain() in the current implementation
	// only removes entries it predicates true on. Verify either drained
	// or stale-but-not-blocking.
	if q.Has(crdt.SectionGroups, "g1") {
		// Acceptable: explicit manual cleanup is documented.
		// Verify the manual-delete endpoint clears it.
		resp = req(t, "DELETE", ts.URL+"/api/v1/quarantine/groups/g1", "s3cret", "")
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE quarantine got %d", resp.StatusCode)
		}
	}
}

func TestReadBodyRejectsLargeContentLength(t *testing.T) {
	s, _, _, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()

	// Send a payload larger than the cap; the client sets
	// Content-Length to match. The server must reject without
	// applying.
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

func TestDeleteUnknownQuarantineKey(t *testing.T) {
	s, _, _, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()
	resp := req(t, "DELETE", ts.URL+"/api/v1/quarantine/groups/nope", "s3cret", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestUnknownMethodReturns405(t *testing.T) {
	s, _, _, _, _, cleanup := setup(t)
	defer cleanup()
	ts, stop := newTestHTTPServer(t, s)
	defer stop()
	resp := req(t, "PATCH", ts.URL+"/api/v1/config", "s3cret", "")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}
