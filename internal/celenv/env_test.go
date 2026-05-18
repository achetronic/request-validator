package celenv

import (
	"context"
	"testing"
)

func evalBool(t *testing.T, env *Env, src string, req map[string]any) bool {
	t.Helper()
	prog, err := env.Compile(src)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	out, err := Eval(context.Background(), prog, req, nil)
	if err != nil {
		t.Fatalf("eval %q: %v", src, err)
	}
	return out
}

func TestEnvSmoke(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}
	req := map[string]any{
		"method":   "POST",
		"host":     "auth.example-1.com",
		"path":     "/realms/mcp/clients-registrations",
		"remoteIp": "10.5.5.5",
		"headers": map[string][]string{
			"content-type":    {"application/json"},
			"x-user-groups":   {"platform-admins"},
			"x-forwarded-for": {"10.5.5.5, 1.1.1.1"},
		},
		"header": map[string]string{
			"content-type":    "application/json",
			"x-user-groups":   "platform-admins",
			"x-forwarded-for": "10.5.5.5, 1.1.1.1",
		},
		"query":   map[string]string{},
		"queries": map[string][]string{},
		"body": map[string]any{
			"raw":         `{"redirect_uris":["https://antigravity.google/cb","https://api.mistral.ai/x"]}`,
			"json":        map[string]any{"redirect_uris": []any{"https://antigravity.google/cb", "https://api.mistral.ai/x"}},
			"jsonOk":      true,
			"yaml":        map[string]any{},
			"yamlOk":      false,
			"size":        int64(74),
			"contentType": "application/json",
		},
	}

	cases := []struct {
		expr string
		want bool
	}{
		{`request.method == "POST"`, true},
		{`request.host in ["auth.example-1.com", "auth.example-2.com"]`, true},
		{`request.path.matches("^/realms/(mcp|api)/clients-registrations(/.*)?$")`, true},
		{`inCIDR(request.remoteIp, ["10.0.0.0/8"])`, true},
		{`inCIDR(request.remoteIp, ["192.168.0.0/16"])`, false},
		{`ipFamily(request.remoteIp) == "ipv4"`, true},
		{`isPrivateIP(request.remoteIp)`, true},
		{`isLoopbackIP("127.0.0.1")`, true},
		{`parseURL("https://api.mistral.ai/cb").host == "api.mistral.ai"`, true},
		{`glob(request.host, "*.example-1.com")`, true},
		{`globAny(request.host, ["*.example-2.com", "*.example-1.com"])`, true},
		{`request.header["content-type"].contains("application/json")`, true},
		{`has("x-user-groups", request.headers)`, true},
		{`has("x-debug", request.headers)`, false},
		{`firstOr(request.header, "x-debug", "fallback") == "fallback"`, true},
		{`request.body.json.redirect_uris.all(u, u.startsWith("https://"))`, true},
		{`request.body.json.redirect_uris.all(u, u.startsWith("https://antigravity.google/"))`, false},
		{`request.body.json.redirect_uris.exists(u, u.startsWith("https://antigravity.google/"))`, true},
		{`size(request.body.json.redirect_uris) == 2`, true},
		{`sha256Hex("hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"`, true},
		{`jsonPath(request.body.json, "redirect_uris[*]").size() == 2`, true},
		{`now() > timestamp("2000-01-01T00:00:00Z")`, true},
	}
	for _, c := range cases {
		if got := evalBool(t, env, c.expr, req); got != c.want {
			t.Errorf("%q => %v, want %v", c.expr, got, c.want)
		}
	}
}
