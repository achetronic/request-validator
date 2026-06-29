package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFactsURLIntegratedWithCEL boots a fake feed server, declares a
// `facts` URL source pointing at it, and exercises a CEL expression.
func TestFactsURLIntegratedWithCEL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"creationTime":"now","prefixes":[{"ipv4Prefix":"10.0.0.0/8"},{"ipv4Prefix":"192.168.0.0/16"}]}`))
	}))
	defer srv.Close()

	c, err := LoadBytes([]byte(`
defaults:
  extAuthz:
    action: deny
facts:
  - name: feed
    method: url
    url:
      address: ` + srv.URL + `
      interval: 10s
      timeout: 2s
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: ok
        match: |
          inCIDR(request.remoteIp,
            parseJSON(facts.feed).prefixes.map(p, p.ipv4Prefix))
        validation:
          action: allow
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer c.Stop()

	if d := c.Evaluate(context.Background(), mkReq("GET", "x", "/", "", nil, "10.5.5.5")); !d.Allowed {
		t.Fatalf("expected allow from URL-fed CIDR: %+v", d)
	}
	if d := c.Evaluate(context.Background(), mkReq("GET", "x", "/", "", nil, "1.1.1.1")); d.Allowed {
		t.Fatalf("expected deny: %+v", d)
	}
}

// TestFactsInlineValue exercises the value method with a literal list.
func TestFactsInlineValue(t *testing.T) {
	c, err := LoadBytes([]byte(`
defaults:
  extAuthz:
    action: deny
facts:
  - name: cidrs
    method: value
    value:
      - 10.0.0.0/8
      - 192.168.0.0/16
groups:
  - name: g
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: ok
        match: inCIDR(request.remoteIp, facts.cidrs)
        validation:
          action: allow
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer c.Stop()

	if d := c.Evaluate(context.Background(), mkReq("GET", "x", "/", "", nil, "10.5.5.5")); !d.Allowed {
		t.Fatalf("expected allow: %+v", d)
	}
	if d := c.Evaluate(context.Background(), mkReq("GET", "x", "/", "", nil, "8.8.8.8")); d.Allowed {
		t.Fatalf("expected deny: %+v", d)
	}
}
