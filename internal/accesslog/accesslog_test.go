// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package accesslog

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

	log.Logger().Info("test", "decision", "allow", RequestAttrs(req, lg))

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
	log.Logger().Info("test", RequestAttrs(req, lg))

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
	log.Logger().Info("test", RequestAttrs(req, policy.Logging{}))

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

func TestResponseAttrsExcludeAndRedact(t *testing.T) {
	var buf bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Configure(log.Options{}) })

	hdrs := http.Header{}
	hdrs.Set("Content-Type", "application/json")
	hdrs.Set("Set-Cookie", "session=verysecret")
	hdrs.Set("Authorization", "Bearer 0123456789abcdef")
	hdrs.Set("X-Custom", "intact-value")

	resp := &policy.Response{
		Status:  201,
		Headers: hdrs,
		Body:    []byte(`{"status":"created"}`),
	}

	lg := policy.Logging{
		ExcludeHeaders: []string{"set-cookie"},
		RedactHeaders:  []string{"authorization"},
		RedactReveal:   6,
	}

	log.Logger().Info("test_resp", ResponseAttrs(resp, lg))

	out := buf.String()

	// Parse JSON to verify fields
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("invalid JSON output: %v -- %s", err, out)
	}

	respRec, ok := rec["response"].(map[string]any)
	if !ok {
		t.Fatalf("missing response group in log: %s", out)
	}

	if int(respRec["status"].(float64)) != 201 {
		t.Fatalf("status mismatch: %v", respRec["status"])
	}

	headers, ok := respRec["headers"].(map[string]any)
	if !ok {
		t.Fatalf("missing headers in response log: %s", out)
	}

	if _, exists := headers["set-cookie"]; exists {
		t.Fatalf("set-cookie should have been excluded: %v", headers)
	}

	authVal, ok := headers["authorization"].(string)
	if !ok {
		t.Fatalf("authorization missing in headers: %v", headers)
	}
	// "Bearer 0123456789abcdef" is 21 chars. RedactReveal=6.
	// 2*6 = 12 <= 21, so prefix "Bearer" (6 chars) is shown, rest is asterisks.
	if !strings.HasPrefix(authVal, "Bearer") || strings.Contains(authVal, "0123456789") {
		t.Fatalf("authorization not masked correctly: %q", authVal)
	}

	customVal, ok := headers["x-custom"].(string)
	if !ok || customVal != "intact-value" {
		t.Fatalf("x-custom header mismatch: %v", headers)
	}
}

func TestResponseAttrsBodyOnlyWhenLogBody(t *testing.T) {
	// First run: LogBody = false
	{
		var buf bytes.Buffer
		if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf}); err != nil {
			t.Fatal(err)
		}
		resp := &policy.Response{
			Status:  200,
			Headers: http.Header{"Content-Type": []string{"text/plain"}},
			Body:    []byte("my-body-content"),
		}
		lg := policy.Logging{LogBody: false}
		log.Logger().Info("test_resp_no_body", ResponseAttrs(resp, lg))

		var rec map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
			t.Fatalf("invalid JSON output: %v", err)
		}
		respRec := rec["response"].(map[string]any)
		body := respRec["body"].(map[string]any)
		if int(body["size"].(float64)) != len("my-body-content") {
			t.Fatalf("wrong size when logBody is false: %v", body)
		}
		if _, exists := body["raw"]; exists {
			t.Fatalf("body raw should be absent when LogBody is false: %v", body)
		}
	}

	// Second run: LogBody = true
	{
		var buf bytes.Buffer
		if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf}); err != nil {
			t.Fatal(err)
		}
		resp := &policy.Response{
			Status:  200,
			Headers: http.Header{"Content-Type": []string{"text/plain"}},
			Body:    []byte("my-body-content"),
		}
		lg := policy.Logging{LogBody: true}
		log.Logger().Info("test_resp_with_body", ResponseAttrs(resp, lg))

		var rec map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
			t.Fatalf("invalid JSON output: %v", err)
		}
		respRec := rec["response"].(map[string]any)
		body := respRec["body"].(map[string]any)
		if int(body["size"].(float64)) != len("my-body-content") {
			t.Fatalf("wrong size when logBody is true: %v", body)
		}
		raw, ok := body["raw"].(string)
		if !ok || raw != "my-body-content" {
			t.Fatalf("body raw should equal the body string when LogBody is true: %v", body)
		}
	}
}

func TestResponseAttrsNilResponse(t *testing.T) {
	var buf bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Configure(log.Options{}) })

	attr := ResponseAttrs(nil, policy.Logging{})

	log.Logger().Info("test_nil_resp", attr)

	out := buf.String()
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("invalid JSON output: %v -- %s", err, out)
	}

	respRec, ok := rec["response"].(map[string]any)
	if !ok {
		t.Fatalf("missing response group in log: %s", out)
	}

	if int(respRec["status"].(float64)) != 0 {
		t.Fatalf("status mismatch: %v", respRec["status"])
	}

	body, ok := respRec["body"].(map[string]any)
	if !ok {
		t.Fatalf("missing body in response log: %s", out)
	}

	if int(body["size"].(float64)) != 0 {
		t.Fatalf("body size mismatch: %v", body["size"])
	}
}

func TestRedactedQueryPairWithoutEquals(t *testing.T) {
	var buf bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Configure(log.Options{}) })

	req := &policy.Request{
		RawQuery: "code=secret&standalone&id_token=x",
	}
	lg := policy.Logging{
		RedactQueryParams: []string{"code", "id_token"},
	}

	log.Logger().Info("test_query", RequestAttrs(req, lg))

	out := buf.String()
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("invalid JSON output: %v -- %s", err, out)
	}

	reqRec, ok := rec["request"].(map[string]any)
	if !ok {
		t.Fatalf("missing request group in log: %s", out)
	}

	queryVal, ok := reqRec["query"].(string)
	if !ok {
		t.Fatalf("query field missing in request log: %s", out)
	}

	expected := "code=***&standalone&id_token=***"
	if queryVal != expected {
		t.Fatalf("expected query to be %q, got %q", expected, queryVal)
	}
}
