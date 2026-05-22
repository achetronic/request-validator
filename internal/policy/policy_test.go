package policy

import (
	"context"
	"net/http"
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
defaults: { action: deny }
groups:
  - name: noop
    rules:
      - name: never
        match: "false"
`)
	d := ev(c, mkReq("GET", "x", "/", "", nil, ""))
	if d.Allowed || d.Rule != "<defaults>" {
		t.Fatalf("expected default deny: %+v", d)
	}
}

func TestFirstMatchInheritance(t *testing.T) {
	c := mustLoad(t, `
defaults: { action: deny }
groups:
  - name: providers
    mode: firstMatch
    action: allow
    rules:
      - name: a
        match: "request.host == 'a.example.com'"
      - name: b
        match: "request.host == 'b.example.com'"
`)
	if d := ev(c, mkReq("GET", "a.example.com", "/", "", nil, "")); !d.Allowed || d.Rule != "providers/a" {
		t.Fatalf("a: %+v", d)
	}
	if d := ev(c, mkReq("GET", "b.example.com", "/", "", nil, "")); !d.Allowed || d.Rule != "providers/b" {
		t.Fatalf("b: %+v", d)
	}
	if d := ev(c, mkReq("GET", "c.example.com", "/", "", nil, "")); d.Allowed {
		t.Fatalf("c: %+v", d)
	}
}

func TestRuleActionOverridesGroup(t *testing.T) {
	c := mustLoad(t, `
defaults: { action: deny }
groups:
  - name: providers
    mode: firstMatch
    action: allow
    rules:
      - name: blocked
        action: deny
        match: "size(request.body.json.redirect_uris) > 5"
      - name: ok
        match: "true"
`)
	// Too many redirects -> rule "blocked" denies.
	if d := ev(c, mkReq("POST", "x", "/", `{"redirect_uris":["a","b","c","d","e","f"]}`, map[string]string{"content-type": "application/json"}, "")); d.Allowed {
		t.Fatalf("blocked: %+v", d)
	}
	// Few -> rule "ok" allows.
	if d := ev(c, mkReq("POST", "x", "/", `{"redirect_uris":["a"]}`, map[string]string{"content-type": "application/json"}, "")); !d.Allowed || d.Rule != "providers/ok" {
		t.Fatalf("ok: %+v", d)
	}
}

func TestModeAll(t *testing.T) {
	c := mustLoad(t, `
defaults: { action: deny }
groups:
  - name: admin
    mode: all
    action: allow
    match: "request.path.startsWith('/admin')"
    rules:
      - name: internal
        match: "inCIDR(request.remoteIp, ['10.0.0.0/8'])"
      - name: group
        match: "request.header['x-user-groups'].contains('platform-admins')"
      - name: nodebug
        match: "!has('x-debug', request.headers)"
`)
	ok := ev(c, mkReq("GET", "x", "/admin/x", "", map[string]string{"x-user-groups": "platform-admins"}, "10.0.0.1"))
	if !ok.Allowed {
		t.Fatalf("all-pass: %+v", ok)
	}
	miss := ev(c, mkReq("GET", "x", "/admin/x", "", nil, "10.0.0.1"))
	if miss.Allowed {
		t.Fatalf("missing group: %+v", miss)
	}
	debug := ev(c, mkReq("GET", "x", "/admin/x", "", map[string]string{"x-user-groups": "platform-admins", "x-debug": "1"}, "10.0.0.1"))
	if debug.Allowed {
		t.Fatalf("debug present: %+v", debug)
	}
	out := ev(c, mkReq("GET", "x", "/elsewhere", "", map[string]string{"x-user-groups": "platform-admins"}, "10.0.0.1"))
	if out.Allowed {
		t.Fatalf("out of scope: %+v", out)
	}
	if out.Rule != "<defaults>" {
		t.Fatalf("expected defaults rule, got %q", out.Rule)
	}
}

func TestDryRun(t *testing.T) {
	c := mustLoad(t, `
defaults: { action: allow }
groups:
  - name: shadow
    action: deny
    rules:
      - name: would-deny
        dryRun: true
        match: "request.path.startsWith('/forbidden')"
`)
	d := ev(c, mkReq("GET", "x", "/forbidden/x", "", nil, ""))
	if !d.Allowed {
		t.Fatalf("dryRun must allow: %+v", d)
	}
	if !d.DryRun {
		t.Fatalf("dryRun flag missing: %+v", d)
	}
}

func TestBodyJSONAndYAML(t *testing.T) {
	c := mustLoad(t, `
defaults: { action: deny }
groups:
  - name: json
    action: allow
    rules:
      - name: jsonAmount
        match: "request.body.jsonOk && request.body.json.amount > 100"
  - name: yamlGroup
    action: allow
    rules:
      - name: yamlKind
        match: "request.body.yamlOk && request.body.yaml.kind == 'Deployment'"
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

	// Helper: build a DCR POST against the mcp realm on the public host.
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
		// Corporate hostname is always denied.
		{
			"corporate DCR -> deny",
			mkReq("POST", "keycloak.internal.example-1.com", "/realms/mcp/clients-registrations",
				`{"redirect_uris":["https://x"]}`, headers, "10.5.5.5"),
			false, "dcr-corporate-deny/block-corporate",
		},

		// Internal CIDR.
		{"internal source allowed", dcr(mcpBody, "10.5.5.5"),
			true, "dcr-internal/from-internal-cidr"},
		{"non-internal source not allowed by internal rule",
			dcr(mcpBody, "8.8.8.8"), false, "<defaults>"},

		// Anthropic / Claude.
		{"claude new /21", dcr(mcpBody, "160.79.108.42"),
			true, "dcr-claude/from-claude-cidr"},
		{"claude legacy individual", dcr(mcpBody, "34.162.142.92"),
			true, "dcr-claude/from-claude-cidr"},
		{"random IP not in claude", dcr(mcpBody, "9.9.9.9"),
			false, "<defaults>"},

		// OpenAI / ChatGPT.
		// The ChatGPT rule's match expression includes a guard
		// `facts.chatgptFeed != null && facts.chatgptFeed != ""`, so when
		// the URL feed hasn't been fetched (the case here - no .Start) the
		// whole group is skipped silently. End-to-end coverage of the URL
		// fetch flow lives in policy_facts_test.go.
		{"chatgpt without feed populated falls through to defaults",
			dcr(mcpBody, "13.65.138.115"), false, "<defaults>"},

		// Mistral, declared as dryRun in the example.
		// The dryRun rule logs but should never produce an "allow" verdict -
		// because the placeholder CIDR 0.0.0.0/32 doesn't match any source,
		// no decision is produced; defaults deny applies.
		{"mistral placeholder not matched", dcr(mcpBody, "1.2.3.4"),
			false, "<defaults>"},

		// Google Antigravity.
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

		// Master realm is never reachable through public hosts.
		{
			"master realm on public host -> deny",
			mkReq("GET", "auth.example-2.com", "/realms/master/account", "", nil, "8.8.8.8"),
			false, "block-master-realm-public/block",
		},

		// Defaults catch-all.
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
  action: allow
  ` + src + `
groups:
  - name: dummy
    rules:
      - name: any
        match: "true"
`
		c, err := LoadBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if c.Defaults.MaxBodyBytes.Int64() != want {
			t.Fatalf("%s: got %d want %d", src, c.Defaults.MaxBodyBytes.Int64(), want)
		}
	}
}

func TestPriorityOrdering(t *testing.T) {
	// Three groups declared with priorities that imply a different
	// evaluation order than declaration order. Each rule matches the
	// request, so the first group reached should win.
	c := mustLoad(t, `
defaults: { action: deny }
groups:
  - name: declared-first
    priority: 10
    action: deny
    rules:
      - name: always
        match: "true"
  - name: declared-second
    priority: -5
    action: allow
    rules:
      - name: always
        match: "true"
  - name: declared-third
    priority: 0
    action: deny
    rules:
      - name: always
        match: "true"
`)

	// Expected order after sort: declared-second (-5), declared-third (0),
	// declared-first (10). First match in declared-second is allow.
	if got := c.Groups[0].Name; got != "declared-second" {
		t.Fatalf("expected first group=declared-second, got %q", got)
	}
	if got := c.Groups[1].Name; got != "declared-third" {
		t.Fatalf("expected second group=declared-third, got %q", got)
	}
	if got := c.Groups[2].Name; got != "declared-first" {
		t.Fatalf("expected third group=declared-first, got %q", got)
	}

	d := ev(c, mkReq("GET", "h", "/", "", nil, ""))
	if !d.Allowed || d.Rule != "declared-second/always" {
		t.Fatalf("expected allow by declared-second/always, got %+v", d)
	}
}

func TestPriorityTieKeepsDeclarationOrder(t *testing.T) {
	c := mustLoad(t, `
defaults: { action: deny }
groups:
  - name: a
    priority: 0
    action: allow
    rules:
      - name: any
        match: "true"
  - name: b
    priority: 0
    action: deny
    rules:
      - name: any
        match: "true"
`)
	if c.Groups[0].Name != "a" || c.Groups[1].Name != "b" {
		t.Fatalf("expected declaration order [a, b], got [%s, %s]",
			c.Groups[0].Name, c.Groups[1].Name)
	}
	d := ev(c, mkReq("GET", "h", "/", "", nil, ""))
	if !d.Allowed || d.Rule != "a/any" {
		t.Fatalf("expected allow from a, got %+v", d)
	}
}

func TestPriorityDefaultsToZero(t *testing.T) {
	c := mustLoad(t, `
defaults: { action: deny }
groups:
  - name: g
    rules:
      - name: any
        match: "true"
`)
	if c.Groups[0].Priority != 0 {
		t.Fatalf("expected default priority=0, got %d", c.Groups[0].Priority)
	}
}
