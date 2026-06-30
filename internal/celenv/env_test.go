// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package celenv

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func sampleRequest() map[string]any {
	return map[string]any{
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
}

func sampleResponse() map[string]any {
	return map[string]any{
		"status": int64(302),
		"headers": map[string][]string{
			"location": {"https://attacker.example/cb"},
		},
		"header": map[string]string{
			"location": "https://attacker.example/cb",
		},
		"body": map[string]any{
			"raw":         "",
			"json":        map[string]any{},
			"jsonOk":      false,
			"yaml":        map[string]any{},
			"yamlOk":      false,
			"size":        int64(0),
			"contentType": "text/html",
		},
	}
}

func requestVars() map[string]any {
	return map[string]any{"request": sampleRequest(), "facts": map[string]any{}}
}

func responseVars() map[string]any {
	return map[string]any{"request": sampleRequest(), "response": sampleResponse(), "facts": map[string]any{}}
}

func evalBool(t *testing.T, env *Env, src string, scope Scope, vars map[string]any) bool {
	t.Helper()
	prog, err := env.Compile(src, scope)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	out, err := Eval(context.Background(), prog, vars)
	if err != nil {
		t.Fatalf("eval %q: %v", src, err)
	}
	return out
}

func TestEnvSmoke_RequestScopeBooleans(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}
	vars := requestVars()
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
		if got := evalBool(t, env, c.expr, ScopeRequest, vars); got != c.want {
			t.Errorf("%q => %v, want %v", c.expr, got, c.want)
		}
	}
}

// Canary: response must NOT be reachable in the request scope. If someone
// declares response globally instead of per-scope, this compile stops failing.
func TestCompile_RejectsResponseVarInRequestScope(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.Compile(`response.status == 302`, ScopeRequest); err == nil {
		t.Fatal("expected compile error referencing response in request scope, got nil")
	} else if !strings.Contains(err.Error(), "response") {
		t.Fatalf("error should mention the undeclared response variable, got: %v", err)
	}
}

func TestCompile_AllowsResponseVarInResponseScope(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if got := evalBool(t, env, `response.status == 302`, ScopeResponse, responseVars()); !got {
		t.Fatal("response.status == 302 should be true with the sample response")
	}
}

// Canary: the cache must not let a source compiled in one scope leak into the
// other. response.status is illegal in request scope and legal in response
// scope; both behaviours must hold regardless of compilation order.
func TestCompile_CacheIsScopeAware(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}
	const src = `response.status == 302`
	if _, err := env.Compile(src, ScopeRequest); err == nil {
		t.Fatal("request scope must reject response.status")
	}
	if _, err := env.Compile(src, ScopeResponse); err != nil {
		t.Fatalf("response scope must accept response.status, got: %v", err)
	}
	if _, err := env.Compile(src, ScopeRequest); err == nil {
		t.Fatal("request scope must still reject response.status after caching in response scope")
	}
}

func TestCompileString_AcceptsStringRejectsBool(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := env.CompileString(`"https://gw/warn?t=" + request.host`, ScopeRequest)
	if err != nil {
		t.Fatalf("compile string expr: %v", err)
	}
	got, err := EvalString(context.Background(), prog, requestVars())
	if err != nil {
		t.Fatalf("eval string: %v", err)
	}
	if got != "https://gw/warn?t=auth.example-1.com" {
		t.Fatalf("unexpected string result: %q", got)
	}
	if _, err := env.CompileString(`request.method == "POST"`, ScopeRequest); err == nil {
		t.Fatal("CompileString must reject a bool expression")
	}
}

func TestCompileInt_AcceptsIntFromStatus(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := env.CompileInt(`response.status`, ScopeResponse)
	if err != nil {
		t.Fatalf("compile int expr: %v", err)
	}
	got, err := EvalInt(context.Background(), prog, responseVars())
	if err != nil {
		t.Fatalf("eval int: %v", err)
	}
	if got != 302 {
		t.Fatalf("want 302, got %d", got)
	}
}

// A dyn-typed expression that resolves to a non-string at runtime must surface
// an error from EvalString rather than a wrong value.
func TestEvalString_ErrorsOnNonStringRuntimeValue(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := env.CompileString(`request.body.json.redirect_uris`, ScopeRequest)
	if err != nil {
		t.Fatalf("compile dyn expr: %v", err)
	}
	if _, err := EvalString(context.Background(), prog, requestVars()); err == nil {
		t.Fatal("EvalString must error when the runtime value is not a string")
	}
}

func TestCompileStringMap_Literal(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}

	expr := `{"content-type": "text/html", "cache-control": "no-store"}`
	prog, err := env.CompileStringMap(expr, ScopeRequest)
	if err != nil {
		t.Fatalf("CompileStringMap failed: %v", err)
	}

	got, err := EvalStringMap(context.Background(), prog, requestVars())
	if err != nil {
		t.Fatalf("EvalStringMap failed: %v", err)
	}

	want := map[string]string{
		"content-type":  "text/html",
		"cache-control": "no-store",
	}

	if len(got) != len(want) {
		t.Fatalf("expected map of size %d, got %d: %+v", len(want), len(got), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q: got %q, want %q", k, got[k], v)
		}
	}
}

func TestCompileStringMap_ResponseHeader(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}

	expr := `response.header`
	prog, err := env.CompileStringMap(expr, ScopeResponse)
	if err != nil {
		t.Fatalf("CompileStringMap for response.header failed: %v", err)
	}

	got, err := EvalStringMap(context.Background(), prog, responseVars())
	if err != nil {
		t.Fatalf("EvalStringMap failed: %v", err)
	}

	want := "https://attacker.example/cb"
	if got["location"] != want {
		t.Errorf("expected location header to be %q, got %q (entire map: %+v)", want, got["location"], got)
	}
}

func TestCompileStringMap_RejectAtCompileTime(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}

	invalidExprs := []string{
		`"hello"`,
		`200`,
	}

	for _, expr := range invalidExprs {
		_, err := env.CompileStringMap(expr, ScopeResponse)
		if err == nil {
			t.Errorf("CompileStringMap should have failed at compile-time for %q", expr)
		} else if !strings.Contains(err.Error(), "must return map(string, string)") {
			t.Errorf("unexpected error message for %q: %v", expr, err)
		}
	}
}

func TestEvalStringMap_Canary_RuntimeTypeError(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}

	// Testing expressions that are dyn at compile-time, but evaluate to a non-string-map at runtime
	invalidExprs := []struct {
		expr  string
		scope Scope
		vars  map[string]any
	}{
		{`request.body.json`, ScopeRequest, requestVars()},
		{`response.headers`, ScopeResponse, responseVars()},
	}

	for _, tc := range invalidExprs {
		prog, err := env.CompileStringMap(tc.expr, tc.scope)
		if err != nil {
			t.Fatalf("CompileStringMap for %q failed: %v", tc.expr, err)
		}

		_, err = EvalStringMap(context.Background(), prog, tc.vars)
		if err == nil {
			t.Fatalf("EvalStringMap should have failed for %q", tc.expr)
		}

		// Check if we get the clear requested error format
		expectedSubstr := "directResponse headers must be map<string,string>"
		if !strings.Contains(err.Error(), expectedSubstr) {
			t.Errorf("expected error to contain %q, got: %v", expectedSubstr, err)
		}
	}
}

func TestEvalStringMap_Canary_RuntimeNonMapError(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}

	// Compile a dyn expression that resolves to a string
	expr := `request.method`
	prog, err := env.CompileStringMap(expr, ScopeRequest)
	if err != nil {
		t.Fatalf("CompileStringMap for %q failed: %v", expr, err)
	}

	_, err = EvalStringMap(context.Background(), prog, requestVars())
	if err == nil {
		t.Fatal("EvalStringMap should have failed for a non-map runtime value")
	}

	expectedSubstr := "expression did not evaluate to a map"
	if !strings.Contains(err.Error(), expectedSubstr) {
		t.Errorf("expected error to contain %q, got: %v", expectedSubstr, err)
	}
}

func TestCompileStringMap_MapMergeNotSupported(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}

	// Try to use '+' operator to merge maps. Let's see if this compiles in CEL.
	// CEL does not natively support map merge with '+', so this should fail to compile.
	expr := `{"content-type": "text/html"} + {"cache-control": "no-store"}`
	_, err = env.CompileStringMap(expr, ScopeRequest)
	if err == nil {
		t.Fatal("expected compilation to fail for map '+' operator, or does this version of cel-go actually support it?")
	} else {
		t.Logf("CompileStringMap for map '+' operator failed as expected: %v", err)
	}
}

// TestBase64EncodeNeedsBytesString is a regression canary for the interstitial
// recipe's `body` expression. base64.encode comes from ext.Encoders() and only
// has a bytes overload; response.header['x'] is a dyn that resolves to a string
// at runtime. So the tempting `base64.encode(response.header['location'])`
// COMPILES (dyn defers the check) but fails at RUNTIME with "no such overload:
// base64.encode(string)", and the directResponse mutation is silently dropped
// (the interstitial never shows). bytes(dyn) does not resolve either. The
// working form needs an explicit string() to type the dyn before bytes():
//
//	base64.encode(bytes(string(response.header['location'])))
//
// If anyone "simplifies" the example/README/DECISIONS recipe back to the bare
// form, this test fails. See examples/policy.yaml.
func TestBase64EncodeNeedsBytesString(t *testing.T) {
	env, err := New()
	if err != nil {
		t.Fatal(err)
	}

	// The working form the docs use: must compile AND evaluate to base64.
	good := `base64.encode(bytes(string(response.header['location'])))`
	prog, err := env.CompileString(good, ScopeResponse)
	if err != nil {
		t.Fatalf("working form must compile: %v", err)
	}
	out, err := EvalString(context.Background(), prog, responseVars())
	if err != nil {
		t.Fatalf("working form must evaluate: %v", err)
	}
	if want := base64.StdEncoding.EncodeToString([]byte("https://attacker.example/cb")); out != want {
		t.Fatalf("base64 mismatch: got %q want %q", out, want)
	}

	// The bare form (the old bug): compiles but must fail at runtime. If a
	// future cel-go grows a string overload and this starts passing, drop the
	// bytes(string(...)) dance from the docs.
	bad := `base64.encode(response.header['location'])`
	prog, err = env.CompileString(bad, ScopeResponse)
	if err != nil {
		t.Skipf("bare form no longer compiles (%v); recipe is safe either way", err)
	}
	if _, err := EvalString(context.Background(), prog, responseVars()); err == nil {
		t.Fatal("bare base64.encode(string) must fail at runtime; if it now works, simplify the interstitial recipe in examples/policy.yaml, README.md and .agents/DECISIONS.md")
	}
}
