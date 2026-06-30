// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

// TestBuildResponseVar tests that Response variables map to CEL correctly.
func TestBuildResponseVar(t *testing.T) {
	resp := &Response{
		Status: 201,
		Headers: http.Header{
			"Content-Type": []string{"application/json"},
			"X-Custom":     []string{"foo", "bar"},
		},
		Body: []byte(`{"id": 42, "nested": {"val": "hello"}}`),
	}

	got := buildResponseVar(resp)

	if got["status"] != int64(201) {
		t.Errorf("expected status 201, got %v", got["status"])
	}

	headers := got["headers"].(map[string][]string)
	if !reflect.DeepEqual(headers["x-custom"], []string{"foo", "bar"}) {
		t.Errorf("expected headers x-custom, got %v", headers["x-custom"])
	}

	header := got["header"].(map[string]string)
	if header["content-type"] != "application/json" {
		t.Errorf("expected header content-type application/json, got %q", header["content-type"])
	}

	body := got["body"].(map[string]any)
	if body["raw"] != `{"id": 42, "nested": {"val": "hello"}}` {
		t.Errorf("expected raw body, got %q", body["raw"])
	}
	if body["size"] != int64(38) {
		t.Errorf("expected size 38, got %v", body["size"])
	}
	if body["contentType"] != "application/json" {
		t.Errorf("expected contentType application/json, got %v", body["contentType"])
	}
	if body["jsonOk"] != true {
		t.Errorf("expected jsonOk true")
	}

	jsonMap := body["json"].(map[string]any)
	if jsonMap["id"] != float64(42) {
		t.Errorf("expected json id 42, got %v", jsonMap["id"])
	}
}

// TestEvaluateProc_FirstMatch verifies that only the first matching rule applies mutations.
func TestEvaluateProc_FirstMatch(t *testing.T) {
	yamlStr := `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: firstMatch
      phase: requestHeaders
    rules:
      - name: r1
        match: "request.header['x-id'] == '1'"
        mutations:
          - op: setHeader
            name: x-rule1
            value: "'applied-r1'"
      - name: r2
        match: "true"
        mutations:
          - op: setHeader
            name: x-rule2
            value: "'applied-r2'"
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	req := &Request{
		Headers: http.Header{"X-Id": []string{"1"}},
	}

	res := cfg.EvaluateProc(context.Background(), "requestHeaders", req, nil)

	if len(res.Mutations) != 1 {
		t.Fatalf("expected exactly 1 mutation, got %d: %v", len(res.Mutations), res.Mutations)
	}
	if res.Mutations[0].Name != "x-rule1" {
		t.Errorf("expected mutation x-rule1, got %s", res.Mutations[0].Name)
	}
}

// TestEvaluateProc_FirstMatch_EmptyMutations verifies empty mutations stop the group evaluation.
func TestEvaluateProc_FirstMatch_EmptyMutations(t *testing.T) {
	yamlStr := `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: firstMatch
      phase: requestHeaders
    rules:
      - name: r1
        match: "request.header['x-id'] == '1'"
        mutations: []
      - name: r2
        match: "true"
        mutations:
          - op: setHeader
            name: x-rule2
            value: "'applied-r2'"
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	req := &Request{
		Headers: http.Header{"X-Id": []string{"1"}},
	}

	res := cfg.EvaluateProc(context.Background(), "requestHeaders", req, nil)

	if len(res.Mutations) != 0 {
		t.Fatalf("expected 0 mutations since firstMatch matched empty mutations, got %v", res.Mutations)
	}
}

// TestEvaluateProc_ApplyAll verifies multiple matching rules apply in order.
func TestEvaluateProc_ApplyAll(t *testing.T) {
	yamlStr := `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    rules:
      - name: r1
        match: "true"
        mutations:
          - op: setHeader
            name: x-header
            value: "'value-r1'"
      - name: r2
        match: "true"
        mutations:
          - op: setHeader
            name: x-header
            value: "'value-r2'"
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	req := &Request{}
	res := cfg.EvaluateProc(context.Background(), "requestHeaders", req, nil)

	if len(res.Mutations) != 2 {
		t.Fatalf("expected 2 mutations, got %d", len(res.Mutations))
	}

	if res.Mutations[0].Name != "x-header" || res.Mutations[0].Value != "value-r1" {
		t.Errorf("expected first mutation to be value-r1, got %v", res.Mutations[0])
	}
	if res.Mutations[1].Name != "x-header" || res.Mutations[1].Value != "value-r2" {
		t.Errorf("expected second mutation to be value-r2 (last write wins), got %v", res.Mutations[1])
	}
}

// TestEvaluateProc_ResponseHeaders phase with response object properties.
func TestEvaluateProc_ResponseHeaders(t *testing.T) {
	yamlStr := `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: applyAll
      phase: responseHeaders
    rules:
      - name: r1
        match: "response.status == 200"
        mutations:
          - op: setHeader
            name: x-custom
            value: "response.header['x-original'] + '-suffixed'"
          - op: setStatus
            code: "201"
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	req := &Request{}
	resp := &Response{
		Status:  200,
		Headers: http.Header{"X-Original": []string{"hello"}},
	}

	res := cfg.EvaluateProc(context.Background(), "responseHeaders", req, resp)

	if len(res.Mutations) != 2 {
		t.Fatalf("expected 2 mutations, got %d", len(res.Mutations))
	}

	m0 := res.Mutations[0]
	if m0.Op != "setHeader" || m0.Name != "x-custom" || m0.Value != "hello-suffixed" {
		t.Errorf("unexpected m0: %+v", m0)
	}

	m1 := res.Mutations[1]
	if m1.Op != "setStatus" || m1.Status != 201 {
		t.Errorf("unexpected m1: %+v", m1)
	}
}

// TestEvaluateProc_PhaseFiltering verifies groups outside current phase are skipped.
func TestEvaluateProc_PhaseFiltering(t *testing.T) {
	yamlStr := `
groups:
  - name: g_req
    parameters:
      engine: extProc
      mode: firstMatch
      phase: requestHeaders
    rules:
      - name: r_req
        match: "true"
        mutations:
          - op: setHeader
            name: x-phase
            value: "'request'"
  - name: g_resp
    parameters:
      engine: extProc
      mode: firstMatch
      phase: responseHeaders
    rules:
      - name: r_resp
        match: "true"
        mutations:
          - op: setHeader
            name: x-phase
            value: "'response'"
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	req := &Request{}

	res := cfg.EvaluateProc(context.Background(), "requestHeaders", req, nil)
	if len(res.Mutations) != 1 || res.Mutations[0].Name != "x-phase" || res.Mutations[0].Value != "request" {
		t.Errorf("expected only request group to apply, got: %v", res.Mutations)
	}
}

// TestEvaluateProc_GroupMatchGuard verifies that group is skipped when match is false.
func TestEvaluateProc_GroupMatchGuard(t *testing.T) {
	yamlStr := `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    match: "request.header['x-enabled'] == 'true'"
    rules:
      - name: r1
        match: "true"
        mutations:
          - op: setHeader
            name: x-header
            value: "'yes'"
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	req := &Request{
		Headers: http.Header{"X-Enabled": []string{"false"}},
	}
	res := cfg.EvaluateProc(context.Background(), "requestHeaders", req, nil)

	if len(res.Mutations) != 0 {
		t.Errorf("expected group to be skipped, but got: %v", res.Mutations)
	}
}

// TestEvaluateProc_DryRun verifies rules carry correct dry-run flag.
func TestEvaluateProc_DryRun(t *testing.T) {
	yamlStr := `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    rules:
      - name: r1
        match: "true"
        dryRun: true
        mutations:
          - op: setHeader
            name: x-dry
            value: "'dry'"
      - name: r2
        match: "true"
        dryRun: false
        mutations:
          - op: setHeader
            name: x-wet
            value: "'wet'"
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	req := &Request{}
	res := cfg.EvaluateProc(context.Background(), "requestHeaders", req, nil)

	if len(res.Mutations) != 2 {
		t.Fatalf("expected 2 mutations, got %d", len(res.Mutations))
	}

	if !res.Mutations[0].DryRun {
		t.Errorf("expected first mutation to have DryRun: true")
	}
	if res.Mutations[1].DryRun {
		t.Errorf("expected second mutation to have DryRun: false")
	}
}

// TestEvaluateProc_FailSafe verifies mutation is omitted when dynamic CEL eval fails.
func TestEvaluateProc_FailSafe(t *testing.T) {
	yamlStr := `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    rules:
      - name: r1
        match: "true"
        mutations:
          - op: setHeader
            name: x-first
            value: "'first'"
          - op: setHeader
            name: x-failing
            value: "request.headers['non-existent'][10]"
          - op: setHeader
            name: x-last
            value: "'last'"
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	req := &Request{}
	res := cfg.EvaluateProc(context.Background(), "requestHeaders", req, nil)

	if len(res.Mutations) != 2 {
		t.Fatalf("expected exactly 2 mutations after omitting the failed one, got %d: %v", len(res.Mutations), res.Mutations)
	}

	if res.Mutations[0].Name != "x-first" || res.Mutations[1].Name != "x-last" {
		t.Errorf("unexpected mutations sequence: %v", res.Mutations)
	}
}

func TestDirectResponse_Success(t *testing.T) {
	yamlStr := `
groups:
  - name: g1
    parameters:
      engine: extProc
      mode: firstMatch
      phase: responseHeaders
    rules:
      - name: r1
        match: "response.status == 302"
        mutations:
          - op: directResponse
            status: 200
            headers: '{"content-type": "text/html", "x-orig-location": response.header["location"]}'
            body: '"hi redirect to " + response.header["location"]'
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	req := &Request{}
	resp := &Response{
		Status:  302,
		Headers: http.Header{"Location": []string{"https://example.com"}},
	}

	res := cfg.EvaluateProc(context.Background(), "responseHeaders", req, resp)

	if len(res.Mutations) != 1 {
		t.Fatalf("expected exactly 1 mutation, got %d", len(res.Mutations))
	}

	m := res.Mutations[0]
	if m.Op != "directResponse" {
		t.Errorf("expected op directResponse, got %q", m.Op)
	}
	if m.RespStatus != 200 {
		t.Errorf("expected RespStatus 200, got %d", m.RespStatus)
	}
	expectedHeaders := map[string]string{
		"content-type":    "text/html",
		"x-orig-location": "https://example.com",
	}
	if !reflect.DeepEqual(m.RespHeaders, expectedHeaders) {
		t.Errorf("expected RespHeaders %v, got %v", expectedHeaders, m.RespHeaders)
	}
	if m.RespBody != "hi redirect to https://example.com" {
		t.Errorf("expected RespBody, got %q", m.RespBody)
	}
}

func TestDirectResponse_HeadersFromResponse(t *testing.T) {
	yamlStr := `
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
            headers: 'response.header'
            body: '"body"'
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	req := &Request{}
	resp := &Response{
		Status:  200,
		Headers: http.Header{"X-Test-Header": []string{"some-value"}},
	}

	res := cfg.EvaluateProc(context.Background(), "responseHeaders", req, resp)

	if len(res.Mutations) != 1 {
		t.Fatalf("expected exactly 1 mutation, got %d", len(res.Mutations))
	}

	m := res.Mutations[0]
	if m.RespHeaders["x-test-header"] != "some-value" {
		t.Errorf("expected headers to carry x-test-header: some-value, got %v", m.RespHeaders)
	}
}

func TestDirectResponse_FailSafe_Canary(t *testing.T) {
	yamlStr := `
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
            headers: 'response.headers'
            body: '"body"'
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed loading policy: %v", err)
	}

	req := &Request{}
	resp := &Response{
		Status:  200,
		Headers: http.Header{"X-Test-Header": []string{"some-value"}},
	}

	res := cfg.EvaluateProc(context.Background(), "responseHeaders", req, resp)

	if len(res.Mutations) != 0 {
		t.Fatalf("expected directResponse to be omitted due to type mismatch in headers, but got: %v", res.Mutations)
	}
}

// Canary: in a policy mixing both engines, each engine must only see its own
// groups. extAuthz Evaluate must ignore extProc groups (and never treat them
// as deciding), and EvaluateProc must ignore extAuthz groups. A regression
// that lets one engine pick up the other's groups breaks this.
func TestEngineIsolation_MixedPolicy(t *testing.T) {
	yamlStr := `
defaults:
  extAuthz:
    action: deny
groups:
  - name: authz-allow-internal
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: allow-it
        match: "request.path == '/ok'"
        validation:
          action: allow
  - name: proc-stamp-response
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
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("load mixed policy: %v", err)
	}

	// extAuthz side: the extProc group must not interfere with the verdict.
	allow := cfg.Evaluate(context.Background(), &Request{Path: "/ok"})
	if !allow.Allowed || allow.Rule != "authz-allow-internal/allow-it" {
		t.Fatalf("extAuthz should allow via its own group only, got %+v", allow)
	}
	deny := cfg.Evaluate(context.Background(), &Request{Path: "/other"})
	if deny.Allowed || deny.Rule != "<defaults>" {
		t.Fatalf("extAuthz should fall to defaults, never decide via an extProc group, got %+v", deny)
	}

	// extProc side: only the extProc group runs; the extAuthz group is invisible.
	res := cfg.EvaluateProc(context.Background(), "responseHeaders",
		&Request{Path: "/ok"}, &Response{Status: 200, Headers: http.Header{}})
	if len(res.Mutations) != 1 || res.Mutations[0].Name != "x-stamped" {
		t.Fatalf("extProc should run only its own group, got %+v", res.Mutations)
	}
}

// Canary: EvaluateProc must only run groups bound to the requested phase. A
// responseHeaders group must not fire when Envoy is at the requestHeaders phase.
func TestEvaluateProc_OnlyRunsRequestedPhase(t *testing.T) {
	yamlStr := `
groups:
  - name: on-response
    parameters:
      engine: extProc
      phase: responseHeaders
      mode: applyAll
    rules:
      - name: stamp
        match: "true"
        mutations:
          - op: setHeader
            name: x-resp
            value: "'1'"
`
	cfg, err := LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	atRequest := cfg.EvaluateProc(context.Background(), "requestHeaders", &Request{}, nil)
	if len(atRequest.Mutations) != 0 {
		t.Fatalf("responseHeaders group must not fire at requestHeaders phase, got %+v", atRequest.Mutations)
	}
	atResponse := cfg.EvaluateProc(context.Background(), "responseHeaders",
		&Request{}, &Response{Status: 200, Headers: http.Header{}})
	if len(atResponse.Mutations) != 1 {
		t.Fatalf("responseHeaders group must fire at its own phase, got %+v", atResponse.Mutations)
	}
}
