package httpserver

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"request-validator/internal/log"
	"request-validator/internal/policy"
)

func TestMask(t *testing.T) {
	cases := []struct {
		in      string
		reveal  int
		want    string
		comment string
	}{
		{"", 6, "", "empty"},
		{"abc", 6, "***", "shorter than reveal"},
		{"abcdef", 6, "******", "exactly reveal -> fully masked (len<2*n)"},
		{"abcdefghi", 6, "*********", "len 9 < 12, fully masked"},
		{"abcdefghijkl", 6, "abcdef******", "len 12 == 2*n, prefix shown"},
		{"abcdefghijklmno", 6, "abcdef*********", "long enough, prefix shown"},
		{"abcdefghijklmno", 0, "***************", "reveal=0 -> all masked"},
		{"abcdefghijklmno", -3, "***************", "reveal<0 -> all masked"},
	}
	for _, c := range cases {
		if got := mask(c.in, c.reveal); got != c.want {
			t.Errorf("mask(%q,%d) = %q want %q (%s)", c.in, c.reveal, got, c.want, c.comment)
		}
	}
}

func TestAccessLogAttrsExcludeAndRedact(t *testing.T) {
	// Capture log output into a buffer.
	var buf bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Configure(log.Options{}) })

	hdrs := http.Header{}
	hdrs.Set("Content-Type", "application/json")
	hdrs.Set("Authorization", "Bearer eyJxxxxxxxxxxxxxxxx")
	hdrs.Set("X-Api-Key", "abc")
	hdrs.Set("Cookie", "session=verysecret")
	hdrs.Set("User-Agent", "Antigravity/1.15")

	req := &policy.Request{
		Method:   "POST",
		Host:     "auth.example-1.com",
		Path:     "/realms/mcp/clients-registrations",
		RawQuery: "code=abc&debug=1",
		RemoteIP: "203.0.113.5",
		Headers:  hdrs,
		Body:     []byte(`{"redirect_uris":["https://localhost:51234/cb"]}`),
	}
	lg := policy.Logging{
		ExcludeHeaders:    []string{"cookie"},
		RedactHeaders:     []string{"authorization", "x-api-key"},
		RedactReveal:      6,
		RedactQueryParams: []string{"code"},
	}

	log.Logger().Info("test", "decision", "allow", accessLogAttrs(req, lg))

	out := buf.String()
	if !strings.Contains(out, `"decision":"allow"`) {
		t.Fatalf("missing decision: %s", out)
	}
	// Cookie must be gone entirely.
	if strings.Contains(strings.ToLower(out), "cookie") {
		t.Fatalf("cookie should have been excluded: %s", out)
	}
	// Authorization is long enough so we reveal the leading 6 chars then mask.
	if !strings.Contains(out, `"authorization":"Bearer*`) {
		t.Fatalf("authorization not redacted as expected: %s", out)
	}
	// X-Api-Key is shorter than 2*reveal -> fully masked.
	if !strings.Contains(out, `"x-api-key":"***"`) {
		t.Fatalf("x-api-key short value should be fully masked: %s", out)
	}
	// Query: code redacted, debug untouched.
	if !strings.Contains(out, `"query":"code=***&debug=1"`) {
		t.Fatalf("query not redacted as expected: %s", out)
	}
	// Body size is logged, body content is not (logBody=false).
	if !strings.Contains(out, `"size":48`) {
		t.Fatalf("body size missing: %s", out)
	}
	if strings.Contains(out, "redirect_uris") {
		t.Fatalf("body content leaked despite LogBody=false: %s", out)
	}
}

func TestAccessLogAttrsLogBody(t *testing.T) {
	var buf bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Configure(log.Options{}) })

	hdrs := http.Header{}
	hdrs.Set("Content-Type", "application/json")
	req := &policy.Request{
		Method:  "POST",
		Headers: hdrs,
		Body:    []byte(`{"a":1}`),
	}
	lg := policy.Logging{LogBody: true}
	log.Logger().Info("test", accessLogAttrs(req, lg))

	out := buf.String()
	// Parse the JSON to assert structurally (less fragile than substring matching).
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("invalid JSON output: %v -- %s", err, out)
	}
	reqRec, _ := rec["request"].(map[string]any)
	body, _ := reqRec["body"].(map[string]any)
	if body["raw"] != `{"a":1}` {
		t.Fatalf("body.raw missing or wrong: %v", body)
	}
	if int(body["size"].(float64)) != 7 {
		t.Fatalf("body.size wrong: %v", body)
	}
}

// Ensure header keys are always lowercased in the output regardless of how
// they were set on the http.Header (which canonicalises to Title-Case).
func TestAccessLogHeaderKeysLowercased(t *testing.T) {
	var buf bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Configure(log.Options{}) })

	hdrs := http.Header{}
	hdrs.Set("X-Custom-Header", "value")
	req := &policy.Request{Headers: hdrs}
	log.Logger().Info("test", accessLogAttrs(req, policy.Logging{}))

	if !strings.Contains(buf.String(), `"x-custom-header":"value"`) {
		t.Fatalf("expected lowercase key in: %s", buf.String())
	}
}

// Sanity check: console format produces parseable output (no panics).
func TestConsoleFormatProducesLine(t *testing.T) {
	var buf bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatConsole, Writer: &buf}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Configure(log.Options{}) })

	log.Logger().Info("hello", slog.String("k", "v"))

	out := buf.String()
	if !strings.Contains(out, "INFO ") || !strings.Contains(out, "hello") || !strings.Contains(out, "k=v") {
		t.Fatalf("console output unexpected: %q", out)
	}
}
