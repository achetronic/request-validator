package httpserver

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"request-validator/internal/policy"
)

func loadPolicy(t *testing.T, src string) *policy.Config {
	t.Helper()
	c, err := policy.LoadBytes([]byte(src))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return c
}

func TestServerAllowsAndDenies(t *testing.T) {
	cfg := loadPolicy(t, `
defaults: { action: deny }
groups:
  - name: allow-foo
    action: allow
    rules:
      - name: get-foo
        match: |
          request.method == 'GET' && request.path.startsWith('/foo')
`)
	s := New(cfg)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	res, _ := http.Get(ts.URL + "/foo/bar")
	if res.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	if res.Header.Get(hdrRule) != "allow-foo/get-foo" {
		t.Fatalf("rule header: %q", res.Header.Get(hdrRule))
	}

	res, _ = http.Post(ts.URL+"/foo/bar", "text/plain", strings.NewReader(""))
	if res.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", res.StatusCode)
	}
}

func TestServerDCREndToEnd(t *testing.T) {
	cfg := loadPolicy(t, `
defaults: { action: deny }
groups:
  - name: dcr
    action: allow
    match: |
      request.method == 'POST' && request.host == 'auth.example-1.com'
    rules:
      - name: antigravity
        match: |
          request.body.jsonOk &&
          request.body.json.redirect_uris.all(u, u.startsWith('https://antigravity.google/'))
`)
	s := New(cfg)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	post := func(host, body string) *http.Response {
		req, _ := http.NewRequest("POST", ts.URL+"/realms/mcp/clients-registrations", bytes.NewReader([]byte(body)))
		req.Host = host
		req.Header.Set("content-type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	good := post("auth.example-1.com", `{"redirect_uris":["https://antigravity.google/cb"]}`)
	if good.StatusCode != 200 {
		b, _ := io.ReadAll(good.Body)
		t.Fatalf("expected 200, got %d %q", good.StatusCode, string(b))
	}
	bad := post("auth.example-1.com", `{"redirect_uris":["https://attacker.com/cb"]}`)
	if bad.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", bad.StatusCode)
	}
}

func TestHotReloadSwap(t *testing.T) {
	initial := loadPolicy(t, `
defaults: { action: deny }
groups:
  - name: noop
    rules:
      - name: never
        match: "false"
`)
	s := New(initial)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	res, _ := http.Get(ts.URL + "/x")
	if res.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", res.StatusCode)
	}

	s.SetPolicy(loadPolicy(t, `
defaults: { action: allow }
groups:
  - name: noop
    rules:
      - name: never
        match: "false"
`))
	res, _ = http.Get(ts.URL + "/x")
	if res.StatusCode != 200 {
		t.Fatalf("after swap expected 200, got %d", res.StatusCode)
	}
}

// TestServerDryRun covers the per-rule and global dry-run combinations,
// including a mixed group where one rule shadows and another enforces.
func TestServerDryRun(t *testing.T) {
	cases := []struct {
		name       string
		policyYAML string
		method     string
		path       string
		wantStatus int
		wantResult string
		wantDryRun string
	}{
		// --- per-rule dryRun ---
		{
			name: "per-rule dryRun: deny rule matches yields 200 shadow deny",
			policyYAML: `
defaults: { action: allow }
groups:
  - name: shadow
    action: deny
    rules:
      - name: would-deny
        dryRun: true
        match: "request.path.startsWith('/forbidden')"
`,
			method:     "GET",
			path:       "/forbidden/x",
			wantStatus: 200,
			wantResult: "deny",
			wantDryRun: "true",
		},
		{
			name: "per-rule dryRun: deny rule does not match, allow normally",
			policyYAML: `
defaults: { action: allow }
groups:
  - name: shadow
    action: deny
    rules:
      - name: would-deny
        dryRun: true
        match: "request.path.startsWith('/forbidden')"
`,
			method:     "GET",
			path:       "/safe/path",
			wantStatus: 200,
			wantResult: "allow",
			wantDryRun: "false",
		},
		// --- global defaults.dryRun ---
		{
			name: "global dryRun: would-deny rule yields 200 shadow deny",
			policyYAML: `
defaults:
  action: deny
  dryRun: true
groups:
  - name: deny-all
    action: deny
    rules:
      - name: block
        match: "true"
`,
			method:     "GET",
			path:       "/anything",
			wantStatus: 200,
			wantResult: "deny",
			wantDryRun: "true",
		},
		{
			name: "global dryRun: allow rule yields 200 allow, dry-run flag still true",
			policyYAML: `
defaults:
  action: allow
  dryRun: true
groups:
  - name: allow-all
    action: allow
    rules:
      - name: pass
        match: "true"
`,
			method:     "GET",
			path:       "/anything",
			wantStatus: 200,
			wantResult: "allow",
			wantDryRun: "true",
		},
		// --- regression: dryRun=false (default) behaves as before ---
		{
			name: "no dryRun: real deny is enforced, 403",
			policyYAML: `
defaults: { action: deny }
groups:
  - name: deny-all
    action: deny
    rules:
      - name: block
        match: "true"
`,
			method:     "GET",
			path:       "/anything",
			wantStatus: 403,
			wantResult: "deny",
			wantDryRun: "false",
		},
		{
			name: "no dryRun: real allow, 200",
			policyYAML: `
defaults: { action: allow }
groups:
  - name: allow-all
    action: allow
    rules:
      - name: pass
        match: "true"
`,
			method:     "GET",
			path:       "/anything",
			wantStatus: 200,
			wantResult: "allow",
			wantDryRun: "false",
		},
		// --- global dryRun overrides a non-dryRun deny rule ---
		{
			name: "global dryRun overrides non-dryRun deny rule",
			policyYAML: `
defaults:
  action: allow
  dryRun: true
groups:
  - name: strict
    action: deny
    rules:
      - name: block-post
        match: "request.method == 'POST'"
`,
			method:     "POST",
			path:       "/api/resource",
			wantStatus: 200,
			wantResult: "deny",
			wantDryRun: "true",
		},
		// --- per-rule dryRun + global dryRun: effectiveDry=true ---
		{
			name: "per-rule dryRun AND global dryRun: shadow deny",
			policyYAML: `
defaults:
  action: deny
  dryRun: true
groups:
  - name: shadow
    action: deny
    rules:
      - name: would-deny
        dryRun: true
        match: "true"
`,
			method:     "GET",
			path:       "/x",
			wantStatus: 200,
			wantResult: "deny",
			wantDryRun: "true",
		},
		// --- mixed group, global off: per-rule dryRun is independent ---
		{
			name: "mixed group: dryRun rule decides yields 200 shadow deny",
			policyYAML: `
defaults: { action: allow }
groups:
  - name: mixed
    action: deny
    rules:
      - name: shadow-admin
        dryRun: true
        match: "request.path.startsWith('/admin')"
      - name: block-internal
        match: "request.path.startsWith('/internal')"
`,
			method:     "GET",
			path:       "/admin/panel",
			wantStatus: 200,
			wantResult: "deny",
			wantDryRun: "true",
		},
		{
			name: "mixed group: non-dryRun rule decides yields enforced 403",
			policyYAML: `
defaults: { action: allow }
groups:
  - name: mixed
    action: deny
    rules:
      - name: shadow-admin
        dryRun: true
        match: "request.path.startsWith('/admin')"
      - name: block-internal
        match: "request.path.startsWith('/internal')"
`,
			method:     "GET",
			path:       "/internal/secret",
			wantStatus: 403,
			wantResult: "deny",
			wantDryRun: "false",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadPolicy(t, tc.policyYAML)
			s := New(cfg)
			ts := httptest.NewServer(http.HandlerFunc(s.handle))
			defer ts.Close()

			req, err := http.NewRequest(tc.method, ts.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tc.wantStatus {
				t.Errorf("status: got %d, want %d", res.StatusCode, tc.wantStatus)
			}
			if got := res.Header.Get(hdrResult); got != tc.wantResult {
				t.Errorf("%s: got %q, want %q", hdrResult, got, tc.wantResult)
			}
			if got := res.Header.Get(hdrDry); got != tc.wantDryRun {
				t.Errorf("%s: got %q, want %q", hdrDry, got, tc.wantDryRun)
			}
		})
	}
}

// errBody is an io.ReadCloser whose Read always fails, used to simulate a
// request body that cannot be read so we can exercise the read-error path.
type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (errBody) Close() error             { return nil }

// TestServerReadBodyError verifies the body-read failure path: fail-closed
// (deny) by default, but pass-through (200) under global dry-run. The error
// must be counted and the dry-run header must reflect the mode either way.
func TestServerReadBodyError(t *testing.T) {
	cases := []struct {
		name       string
		policyYAML string
		wantStatus int
		wantDryRun string
	}{
		{
			name:       "read error fail-closed denies",
			policyYAML: `defaults: { action: allow }
groups:
  - name: g
    rules: [{ name: r, match: "true" }]
`,
			wantStatus: 403,
			wantDryRun: "false",
		},
		{
			name:       "read error under global dryRun passes through",
			policyYAML: `defaults: { action: allow, dryRun: true }
groups:
  - name: g
    rules: [{ name: r, match: "true" }]
`,
			wantStatus: 200,
			wantDryRun: "true",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := New(loadPolicy(t, tc.policyYAML))
			req := httptest.NewRequest(http.MethodPost, "/anything", errBody{})
			rec := httptest.NewRecorder()

			s.handle(rec, req)

			res := rec.Result()
			if res.StatusCode != tc.wantStatus {
				t.Errorf("status: got %d, want %d", res.StatusCode, tc.wantStatus)
			}
			if got := res.Header.Get(hdrResult); got != "deny" {
				t.Errorf("%s: got %q, want %q", hdrResult, got, "deny")
			}
			if got := res.Header.Get(hdrDry); got != tc.wantDryRun {
				t.Errorf("%s: got %q, want %q", hdrDry, got, tc.wantDryRun)
			}
		})
	}
}
