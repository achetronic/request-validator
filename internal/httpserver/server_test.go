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
