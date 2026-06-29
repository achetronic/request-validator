package policy

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func mustLoad(t *testing.T, src string) *Config {
	t.Helper()
	c, err := LoadBytes([]byte(src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return c
}

func mkReq(method, host, path, body string, headers map[string]string, remoteIP string) *Request {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &Request{Method: method, Host: host, Path: path, Body: []byte(body), Headers: h, RemoteIP: remoteIP}
}

func ev(c *Config, r *Request) Decision { return c.Evaluate(context.Background(), r) }

func TestDefaultDeny(t *testing.T) {
	c := mustLoad(t, `
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
	d := ev(c, mkReq("GET", "x", "/", "", nil, ""))
	if d.Allowed || d.Rule != "<defaults>" {
		t.Fatalf("expected default deny: %+v", d)
	}
}

func TestFirstMatchExtAuthz(t *testing.T) {
	c := mustLoad(t, `
defaults:
  extAuthz:
    action: deny
groups:
  - name: providers
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: a
        match: "request.host == 'a.example.com'"
        validation:
          action: allow
      - name: b
        match: "request.host == 'b.example.com'"
        validation:
          action: allow
      - name: blocked
        match: "request.host == 'blocked.example.com'"
        validation:
          action: deny
`)

	// a matches -> allows
	if d := ev(c, mkReq("GET", "a.example.com", "/", "", nil, "")); !d.Allowed || d.Rule != "providers/a" {
		t.Fatalf("a: %+v", d)
	}
	// b matches -> allows
	if d := ev(c, mkReq("GET", "b.example.com", "/", "", nil, "")); !d.Allowed || d.Rule != "providers/b" {
		t.Fatalf("b: %+v", d)
	}
	// blocked matches -> denies
	if d := ev(c, mkReq("GET", "blocked.example.com", "/", "", nil, "")); d.Allowed || d.Rule != "providers/blocked" {
		t.Fatalf("blocked: %+v", d)
	}
	// c does not match any rule -> falls through to defaults
	if d := ev(c, mkReq("GET", "c.example.com", "/", "", nil, "")); d.Allowed || d.Rule != "<defaults>" {
		t.Fatalf("c: %+v", d)
	}
}

func TestMatchAllExtAuthz(t *testing.T) {
	c := mustLoad(t, `
defaults:
  extAuthz:
    action: deny
groups:
  - name: admin
    parameters:
      engine: extAuthz
      mode: matchAll
    match: "request.path.startsWith('/admin')"
    rules:
      - name: internal
        match: "inCIDR(request.remoteIp, ['10.0.0.0/8'])"
        validation:
          action: allow
      - name: group
        match: "request.header['x-user-groups'].contains('platform-admins')"
        validation:
          action: allow
`)

	// All match -> allowed
	ok := ev(c, mkReq("GET", "x", "/admin/x", "", map[string]string{"x-user-groups": "platform-admins"}, "10.0.0.1"))
	if !ok.Allowed {
		t.Fatalf("all-pass: %+v", ok)
	}

	// First fails -> deny (canary checks that we do not let it pass if matchAll fails)
	miss := ev(c, mkReq("GET", "x", "/admin/x", "", nil, "10.0.0.1"))
	if miss.Allowed {
		t.Fatalf("missing group should be denied in matchAll: %+v", miss)
	}
	if miss.Rule != "admin/group" {
		t.Fatalf("expected rule to be group-fail, got %q", miss.Rule)
	}

	// Outside path -> falls through (group match guard)
	out := ev(c, mkReq("GET", "x", "/elsewhere", "", map[string]string{"x-user-groups": "platform-admins"}, "10.0.0.1"))
	if out.Allowed {
		t.Fatalf("out of scope: %+v", out)
	}
	if out.Rule != "<defaults>" {
		t.Fatalf("expected defaults rule, got %q", out.Rule)
	}
}

func TestGroupMatchGuard(t *testing.T) {
	c := mustLoad(t, `
defaults:
  extAuthz:
    action: deny
groups:
  - name: skipGroup
    parameters:
      engine: extAuthz
      mode: firstMatch
    match: "request.path == '/special'"
    rules:
      - name: r1
        match: "true"
        validation:
          action: allow
`)

	// Matches guard -> allowed
	d1 := ev(c, mkReq("GET", "x", "/special", "", nil, ""))
	if !d1.Allowed || d1.Rule != "skipGroup/r1" {
		t.Fatalf("expected group match: %+v", d1)
	}

	// Fails guard -> skips group -> default deny
	d2 := ev(c, mkReq("GET", "x", "/other", "", nil, ""))
	if d2.Allowed || d2.Rule != "<defaults>" {
		t.Fatalf("expected skip: %+v", d2)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			"engine missing",
			`
groups:
  - name: g
    parameters:
      mode: firstMatch
    rules:
      - name: r
        match: "true"
        validation: { action: allow }
`,
		},
		{
			"engine invalid",
			`
groups:
  - name: g
    parameters:
      engine: extAuthz2
      mode: firstMatch
    rules:
      - name: r
        match: "true"
        validation: { action: allow }
`,
		},
		{
			"mode invalid for extAuthz",
			`
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: applyAll
    rules:
      - name: r
        match: "true"
        validation: { action: allow }
`,
		},
		{
			"mode invalid for extProc",
			`
groups:
  - name: g
    parameters:
      engine: extProc
      mode: matchAll
      phase: requestHeaders
    rules:
      - name: r
        match: "true"
        mutations: []
`,
		},
		{
			"phase in extAuthz",
			`
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
      phase: requestHeaders
    rules:
      - name: r
        match: "true"
        validation: { action: allow }
`,
		},
		{
			"phase missing in extProc",
			`
groups:
  - name: g
    parameters:
      engine: extProc
      mode: firstMatch
    rules:
      - name: r
        match: "true"
        mutations: []
`,
		},
		{
			"extAuthz rule with mutations",
			`
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: r
        match: "true"
        validation: { action: allow }
        mutations:
          - { op: removeHeader, name: foo }
`,
		},
		{
			"extProc rule with validation",
			`
groups:
  - name: g
    parameters:
      engine: extProc
      mode: firstMatch
      phase: requestHeaders
    rules:
      - name: r
        match: "true"
        validation: { action: allow }
        mutations: []
`,
		},
		{
			"rule match missing",
			`
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: r
        validation: { action: allow }
`,
		},
		{
			"mutation unknown op",
			`
groups:
  - name: g
    parameters:
      engine: extProc
      mode: firstMatch
      phase: requestHeaders
    rules:
      - name: r
        match: "true"
        mutations:
          - { op: dance, name: foo }
`,
		},
		{
			"setStatus in request phase",
			`
groups:
  - name: g
    parameters:
      engine: extProc
      mode: firstMatch
      phase: requestHeaders
    rules:
      - name: r
        match: "true"
        mutations:
          - { op: setStatus, code: "200" }
`,
		},
		{
			"setBody in headers phase",
			`
groups:
  - name: g
    parameters:
      engine: extProc
      mode: firstMatch
      phase: requestHeaders
    rules:
      - name: r
        match: "true"
        mutations:
          - { op: setBody, value: "'foo'" }
`,
		},
		{
			"onBodyOverflow invalid",
			`
defaults:
  extProc:
    onBodyOverflow: explode
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: r
        match: "true"
        validation: { action: allow }
`,
		},
		{
			"action invalid",
			`
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: r
        match: "true"
        validation: { action: explode }
`,
		},
		{
			"matchAll with action deny",
			`
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: matchAll
    rules:
      - name: r
        match: "true"
        validation: { action: deny }
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadBytes([]byte(tc.src))
			if err == nil {
				t.Fatalf("expected error for case %q, but loaded successfully", tc.name)
			}
		})
	}
}

func TestCompilationScope(t *testing.T) {
	// response.status used in responseHeaders compiles OK
	srcOK := `
groups:
  - name: g
    parameters:
      engine: extProc
      mode: firstMatch
      phase: responseHeaders
    rules:
      - name: r
        match: "response.status == 200"
        mutations: []
`
	if _, err := LoadBytes([]byte(srcOK)); err != nil {
		t.Fatalf("expected compilation success: %v", err)
	}

	// response.status used in requestHeaders fails compilation
	srcFail := `
groups:
  - name: g
    parameters:
      engine: extProc
      mode: firstMatch
      phase: requestHeaders
    rules:
      - name: r
        match: "response.status == 200"
        mutations: []
`
	_, err := LoadBytes([]byte(srcFail))
	if err == nil {
		t.Fatal("expected compilation failure due to response variable out of scope, but succeeded")
	}
	if !strings.Contains(err.Error(), "response") && !strings.Contains(err.Error(), "undeclared reference") {
		t.Fatalf("expected error referencing scope or response variable, got: %v", err)
	}
}

func TestDryRun(t *testing.T) {
	c := mustLoad(t, `
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
`)
	d := ev(c, mkReq("GET", "x", "/forbidden/x", "", nil, ""))
	if d.Allowed {
		t.Fatalf("Evaluate must return real deny verdict for dryRun rule: %+v", d)
	}
	if !d.DryRun {
		t.Fatalf("DryRun flag must be set: %+v", d)
	}
	d2 := ev(c, mkReq("GET", "x", "/safe", "", nil, ""))
	if !d2.Allowed {
		t.Fatalf("non-matching path should reach defaults allow: %+v", d2)
	}
	if d2.DryRun {
		t.Fatalf("non-matching path should not carry DryRun flag: %+v", d2)
	}
}

func TestDefaultsDryRunField(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"dryRun true", `
defaults:
  extAuthz:
    action: deny
  dryRun: true
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: r
        match: "true"
        validation: { action: allow }
`, true},
		{"dryRun false explicit", `
defaults:
  extAuthz:
    action: deny
  dryRun: false
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: r
        match: "true"
        validation: { action: allow }
`, false},
		{"dryRun omitted defaults false", `
defaults:
  extAuthz:
    action: deny
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: r
        match: "true"
        validation: { action: allow }
`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := mustLoad(t, tc.src)
			if c.Defaults.DryRun != tc.want {
				t.Fatalf("Defaults.DryRun = %v, want %v", c.Defaults.DryRun, tc.want)
			}
		})
	}
}

func TestBodyJSONAndYAML(t *testing.T) {
	c := mustLoad(t, `
defaults:
  extAuthz:
    action: deny
groups:
  - name: json
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: jsonAmount
        match: "request.body.jsonOk && request.body.json.amount > 100"
        validation: { action: allow }
  - name: yamlGroup
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: yamlKind
        match: "request.body.yamlOk && request.body.yaml.kind == 'Deployment'"
        validation: { action: allow }
`)
	if d := ev(c, mkReq("POST", "x", "/", `{"amount":500}`, nil, "")); !d.Allowed {
		t.Fatalf("json: %+v", d)
	}
	if d := ev(c, mkReq("POST", "x", "/", "kind: Deployment\nname: foo\n", nil, "")); !d.Allowed {
		t.Fatalf("yaml: %+v", d)
	}
	if d := ev(c, mkReq("POST", "x", "/", "garbage bytes", nil, "")); d.Allowed {
		t.Fatalf("garbage: %+v", d)
	}
}

func TestExampleConfigFlow(t *testing.T) {
	c, err := LoadFile("../../examples/policy.yaml")
	if err != nil {
		t.Fatalf("example: %v", err)
	}
	headers := map[string]string{"content-type": "application/json"}

	dcr := func(body, remoteIP string) *Request {
		return mkReq("POST", "auth.example-2.com",
			"/realms/mcp/clients-registrations", body, headers, remoteIP)
	}
	mcpBody := `{"redirect_uris":["https://example.com/cb"]}`

	cases := []struct {
		label    string
		req      *Request
		want     bool
		wantRule string
	}{
		{
			"corporate DCR -> deny",
			mkReq("POST", "keycloak.internal.example-1.com", "/realms/mcp/clients-registrations",
				`{"redirect_uris":["https://x"]}`, headers, "10.5.5.5"),
			false, "dcr-corporate-deny/block-corporate",
		},
		{"internal source allowed", dcr(mcpBody, "10.5.5.5"),
			true, "dcr-internal/from-internal-cidr"},
		{"non-internal source not allowed by internal rule",
			dcr(mcpBody, "8.8.8.8"), false, "<defaults>"},
		{"claude new /21", dcr(mcpBody, "160.79.108.42"),
			true, "dcr-claude/from-claude-cidr"},
		{"claude legacy individual", dcr(mcpBody, "34.162.142.92"),
			true, "dcr-claude/from-claude-cidr"},
		{"random IP not in claude", dcr(mcpBody, "9.9.9.9"),
			false, "<defaults>"},
		{"chatgpt without feed populated falls through to defaults",
			dcr(mcpBody, "13.65.138.115"), false, "<defaults>"},
		{"mistral placeholder not matched", dcr(mcpBody, "1.2.3.4"),
			false, "<defaults>"},
		{
			"antigravity canonical google host",
			dcr(`{"redirect_uris":["https://antigravity.google/oauth-callback"]}`, "203.0.113.5"),
			true, "dcr-antigravity/canonical-google-host",
		},
		{
			"antigravity loopback DCR",
			dcr(`{"redirect_uris":["https://localhost:51234/oauth-callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}`, "203.0.113.5"),
			true, "dcr-antigravity/dcr-loopback-mcp",
		},
		{
			"antigravity loopback DCR without MCP fields (still allowed)",
			dcr(`{"redirect_uris":["https://127.0.0.1:60001/cb"]}`, "203.0.113.5"),
			true, "dcr-antigravity/dcr-loopback-mcp",
		},
		{
			"antigravity loopback DCR with wrong grant_types",
			dcr(`{"redirect_uris":["https://localhost:51234/cb"],"grant_types":["client_credentials"]}`, "203.0.113.5"),
			false, "<defaults>",
		},
		{
			"antigravity HTTP loopback -> deny",
			dcr(`{"redirect_uris":["http://localhost:51234/cb"]}`, "203.0.113.5"),
			false, "<defaults>",
		},
		{
			"antigravity remote host -> deny",
			dcr(`{"redirect_uris":["https://attacker.example.com/cb"]}`, "203.0.113.5"),
			false, "<defaults>",
		},
		{
			"antigravity too many redirects -> deny by belt-and-braces rule",
			dcr(`{"redirect_uris":["https://localhost:1/a","https://localhost:2/b","https://localhost:3/c","https://localhost:4/d","https://localhost:5/e","https://localhost:6/f"]}`, "203.0.113.5"),
			false, "dcr-antigravity/too-many-redirects",
		},
		{
			"antigravity mixed redirect URIs -> deny",
			dcr(`{"redirect_uris":["https://localhost:51234/cb","https://attacker.com/cb"]}`, "203.0.113.5"),
			false, "<defaults>",
		},
		{
			"master realm on public host -> deny",
			mkReq("GET", "auth.example-2.com", "/realms/master/account", "", nil, "8.8.8.8"),
			false, "block-master-realm-public/block",
		},
		{
			"random request -> default deny",
			mkReq("GET", "random.example.com", "/whatever", "", nil, "8.8.8.8"),
			false, "<defaults>",
		},
	}

	for _, tc := range cases {
		d := ev(c, tc.req)
		if d.Allowed != tc.want {
			t.Errorf("%s: allowed=%v want=%v rule=%q reason=%q", tc.label, d.Allowed, tc.want, d.Rule, d.Reason)
		}
		if tc.wantRule != "" && d.Rule != tc.wantRule {
			t.Errorf("%s: rule=%q want=%q", tc.label, d.Rule, tc.wantRule)
		}
	}
}

func TestBytesSizeUnits(t *testing.T) {
	cases := map[string]int64{
		`maxBodyBytes: 1024`:    1024,
		`maxBodyBytes: 1KiB`:    1024,
		`maxBodyBytes: 2MiB`:    2 * 1024 * 1024,
		`maxBodyBytes: 1MB`:     1_000_000,
		`maxBodyBytes: "1024b"`: 1024,
	}
	for src, want := range cases {
		yaml := `
defaults:
  extAuthz:
    action: allow
    ` + src + `
groups:
  - name: dummy
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: any
        match: "true"
        validation: { action: allow }
`
		c, err := LoadBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if c.Defaults.ExtAuthz.MaxBodyBytes.Int64() != want {
			t.Fatalf("%s: got %d want %d", src, c.Defaults.ExtAuthz.MaxBodyBytes.Int64(), want)
		}
	}
}

func TestDirectResponse_ValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantErrSub string
	}{
		{
			name: "directResponse in requestHeaders phase",
			yaml: `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: firstMatch
      phase: requestHeaders
    rules:
      - name: r1
        match: "true"
        mutations:
          - op: directResponse
            status: 200
            headers: '{"a":"b"}'
            body: '"body"'
`,
			wantErrSub: "directResponse is only legal in responseHeaders|responseBody phases",
		},
		{
			name: "directResponse mixed with setHeader (exclusivity)",
			yaml: `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: firstMatch
      phase: responseHeaders
    rules:
      - name: r1
        match: "true"
        mutations:
          - op: directResponse
            status: 200
            headers: '{"a":"b"}'
            body: '"body"'
          - op: setHeader
            name: x-some
            value: '"value"'
`,
			wantErrSub: "directResponse must be the only mutation in the rule",
		},
		{
			name: "directResponse with name present",
			yaml: `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: firstMatch
      phase: responseHeaders
    rules:
      - name: r1
        match: "true"
        mutations:
          - op: directResponse
            status: 200
            name: "forbidden-name"
            headers: '{"a":"b"}'
            body: '"body"'
`,
			wantErrSub: "name must be empty",
		},
		{
			name: "directResponse with value present",
			yaml: `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: firstMatch
      phase: responseHeaders
    rules:
      - name: r1
        match: "true"
        mutations:
          - op: directResponse
            status: 200
            value: "forbidden-value"
            headers: '{"a":"b"}'
            body: '"body"'
`,
			wantErrSub: "value must be empty",
		},
		{
			name: "directResponse with code present",
			yaml: `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: firstMatch
      phase: responseHeaders
    rules:
      - name: r1
        match: "true"
        mutations:
          - op: directResponse
            status: 200
            code: "forbidden-code"
            headers: '{"a":"b"}'
            body: '"body"'
`,
			wantErrSub: "code must be empty",
		},
		{
			name: "directResponse with status 0",
			yaml: `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: firstMatch
      phase: responseHeaders
    rules:
      - name: r1
        match: "true"
        mutations:
          - op: directResponse
            status: 0
            headers: '{"a":"b"}'
            body: '"body"'
`,
			wantErrSub: "status is required, must be a valid HTTP code",
		},
		{
			name: "directResponse with empty headers",
			yaml: `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: firstMatch
      phase: responseHeaders
    rules:
      - name: r1
        match: "true"
        mutations:
          - op: directResponse
            status: 200
            headers: ""
            body: '"body"'
`,
			wantErrSub: "headers is required and cannot be empty",
		},
		{
			name: "directResponse with empty body",
			yaml: `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: firstMatch
      phase: responseHeaders
    rules:
      - name: r1
        match: "true"
        mutations:
          - op: directResponse
            status: 200
            headers: '{"a":"b"}'
            body: ""
`,
			wantErrSub: "body is required and cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadBytes([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrSub)
			}
			if !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErrSub, err)
			}
		})
	}
}
