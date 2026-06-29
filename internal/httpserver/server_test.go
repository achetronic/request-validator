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
defaults:
  extAuthz:
    action: deny
groups:
  - name: allow-foo
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: get-foo
        match: |
          request.method == 'GET' && request.path.startsWith('/foo')
        validation:
          action: allow
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
defaults:
  extAuthz:
    action: deny
groups:
  - name: dcr
    parameters:
      engine: extAuthz
      mode: firstMatch
    match: |
      request.method == 'POST' && request.host == 'auth.example-1.com'
    rules:
      - name: antigravity
        match: |
          request.body.jsonOk &&
          request.body.json.redirect_uris.all(u, u.startsWith('https://antigravity.google/'))
        validation:
          action: allow
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
defaults:
  extAuthz:
    action: deny
groups:
  - name: noop
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: never
        match: "false"
        validation:
          action: allow
`)
	s := New(initial)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	res, _ := http.Get(ts.URL + "/x")
	if res.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", res.StatusCode)
	}

	s.SetPolicy(loadPolicy(t, `
defaults:
  extAuthz:
    action: allow
groups:
  - name: noop
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: never
        match: "false"
        validation:
          action: allow
`))
	res, _ = http.Get(ts.URL + "/x")
	if res.StatusCode != 200 {
		t.Fatalf("after swap expected 200, got %d", res.StatusCode)
	}
}

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
		{
			name: "per-rule dryRun: deny rule matches yields 200 shadow deny",
			policyYAML: `
defaults:
  extAuthz:
    action: allow
groups:
  - name: shadow
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: would-deny
        dryRun: true
        match: "request.path.startsWith('/forbidden')"
        validation:
          action: deny
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
defaults:
  extAuthz:
    action: allow
groups:
  - name: shadow
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: would-deny
        dryRun: true
        match: "request.path.startsWith('/forbidden')"
        validation:
          action: deny
`,
			method:     "GET",
			path:       "/safe/path",
			wantStatus: 200,
			wantResult: "allow",
			wantDryRun: "false",
		},
		{
			name: "global dryRun: would-deny rule yields 200 shadow deny",
			policyYAML: `
defaults:
  extAuthz:
    action: deny
  dryRun: true
groups:
  - name: deny-all
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: block
        match: "true"
        validation:
          action: deny
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
  extAuthz:
    action: allow
  dryRun: true
groups:
  - name: allow-all
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: pass
        match: "true"
        validation:
          action: allow
`,
			method:     "GET",
			path:       "/anything",
			wantStatus: 200,
			wantResult: "allow",
			wantDryRun: "true",
		},
		{
			name: "no dryRun: real deny is enforced, 403",
			policyYAML: `
defaults:
  extAuthz:
    action: deny
groups:
  - name: deny-all
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: block
        match: "true"
        validation:
          action: deny
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
defaults:
  extAuthz:
    action: allow
groups:
  - name: allow-all
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: pass
        match: "true"
        validation:
          action: allow
`,
			method:     "GET",
			path:       "/anything",
			wantStatus: 200,
			wantResult: "allow",
			wantDryRun: "false",
		},
		{
			name: "global dryRun overrides non-dryRun deny rule",
			policyYAML: `
defaults:
  extAuthz:
    action: allow
  dryRun: true
groups:
  - name: strict
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: block-post
        match: "request.method == 'POST'"
        validation:
          action: deny
`,
			method:     "POST",
			path:       "/api/resource",
			wantStatus: 200,
			wantResult: "deny",
			wantDryRun: "true",
		},
		{
			name: "per-rule dryRun AND global dryRun: shadow deny",
			policyYAML: `
defaults:
  extAuthz:
    action: deny
  dryRun: true
groups:
  - name: shadow
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: would-deny
        dryRun: true
        match: "true"
        validation:
          action: deny
`,
			method:     "GET",
			path:       "/x",
			wantStatus: 200,
			wantResult: "deny",
			wantDryRun: "true",
		},
		{
			name: "mixed group: dryRun rule decides yields 200 shadow deny",
			policyYAML: `
defaults:
  extAuthz:
    action: allow
groups:
  - name: mixed
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: shadow-admin
        dryRun: true
        match: "request.path.startsWith('/admin')"
        validation:
          action: deny
      - name: block-internal
        match: "request.path.startsWith('/internal')"
        validation:
          action: deny
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
defaults:
  extAuthz:
    action: allow
groups:
  - name: mixed
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: shadow-admin
        dryRun: true
        match: "request.path.startsWith('/admin')"
        validation:
          action: deny
      - name: block-internal
        match: "request.path.startsWith('/internal')"
        validation:
          action: deny
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

type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (errBody) Close() error             { return nil }

func TestServerReadBodyError(t *testing.T) {
	cases := []struct {
		name       string
		policyYAML string
		wantStatus int
		wantDryRun string
	}{
		{
			name: "read error fail-closed denies",
			policyYAML: `
defaults:
  extAuthz:
    action: allow
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules: [{ name: r, match: "true", validation: { action: allow } }]
`,
			wantStatus: 403,
			wantDryRun: "false",
		},
		{
			name: "read error under global dryRun passes through",
			policyYAML: `
defaults:
  extAuthz:
    action: allow
  dryRun: true
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules: [{ name: r, match: "true", validation: { action: allow } }]
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

func TestServerBodyOverflow(t *testing.T) {
	cases := []struct {
		name       string
		policyYAML string
		bodySize   int
		wantStatus int
		wantResult string
		wantDryRun string
	}{
		{
			name: "overflow deny status code 403 and body content",
			policyYAML: `
defaults:
  extAuthz:
    action: allow
    maxBodyBytes: 10
    denyStatus: 403
    denyBody: "Too Large"
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules: [{ name: r, match: "true", validation: { action: allow } }]
`,
			bodySize:   15,
			wantStatus: 403,
			wantResult: "deny",
			wantDryRun: "false",
		},
		{
			name: "overflow under global dryRun yields 200",
			policyYAML: `
defaults:
  extAuthz:
    action: allow
    maxBodyBytes: 10
  dryRun: true
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules: [{ name: r, match: "true", validation: { action: allow } }]
`,
			bodySize:   15,
			wantStatus: 200,
			wantResult: "deny",
			wantDryRun: "true",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := New(loadPolicy(t, tc.policyYAML))
			body := strings.Repeat("A", tc.bodySize)
			req := httptest.NewRequest(http.MethodPost, "/anything", strings.NewReader(body))
			rec := httptest.NewRecorder()

			s.handle(rec, req)

			res := rec.Result()
			if res.StatusCode != tc.wantStatus {
				t.Errorf("status: got %d, want %d", res.StatusCode, tc.wantStatus)
			}
			if got := res.Header.Get(hdrResult); got != tc.wantResult {
				t.Errorf("%s: got %q, want %q", hdrResult, got, tc.wantResult)
			}
			if got := res.Header.Get(hdrDry); got != tc.wantDryRun {
				t.Errorf("%s: got %q, want %q", hdrDry, got, tc.wantDryRun)
			}
			if got := res.Header.Get(hdrRule); got != "<overflow>" {
				t.Errorf("%s: got %q, want %q", hdrRule, got, "<overflow>")
			}
			if got := res.Header.Get(hdrReason); got != "request body too large" {
				t.Errorf("%s: got %q, want %q", hdrReason, got, "request body too large")
			}
			if tc.wantStatus == 403 {
				respBody, _ := io.ReadAll(res.Body)
				if string(respBody) != "Too Large" {
					t.Errorf("expected body %q, got %q", "Too Large", string(respBody))
				}
			}
		})
	}
}

// Canary: the HTTP server serves extAuthz correctly even when the policy also
// carries extProc groups. The presence of extProc groups must not break the
// load nor alter the verdict (the HTTP server only runs extAuthz).
func TestServerIgnoresExtProcGroups(t *testing.T) {
	cfg := loadPolicy(t, `
defaults:
  extAuthz:
    action: deny
groups:
  - name: allow-foo
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: get-foo
        match: "request.method == 'GET' && request.path.startsWith('/foo')"
        validation:
          action: allow
  - name: rewrite-redirect
    parameters:
      engine: extProc
      phase: responseHeaders
      mode: applyAll
    rules:
      - name: stamp
        match: "true"
        mutations:
          - op: setHeader
            name: x-stamped
            value: "'yes'"
`)
	s := New(cfg)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	res, _ := http.Get(ts.URL + "/foo/bar")
	if res.StatusCode != 200 {
		t.Fatalf("extAuthz allow must still work with extProc groups present, got %d", res.StatusCode)
	}
	if res.Header.Get(hdrRule) != "allow-foo/get-foo" {
		t.Fatalf("verdict must come from the extAuthz group, got rule %q", res.Header.Get(hdrRule))
	}

	res, _ = http.Get(ts.URL + "/nope")
	if res.StatusCode != 403 {
		t.Fatalf("non-matching request must fall to default deny, got %d", res.StatusCode)
	}
}
