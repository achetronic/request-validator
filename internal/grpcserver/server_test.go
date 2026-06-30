// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package grpcserver

import (
	"context"
	"io"
	"strconv"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	epb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"

	"request-validator/internal/policy"
)

type fakeStream struct {
	grpc.ServerStream
	ctx      context.Context
	incoming []*epb.ProcessingRequest
	outgoing []*epb.ProcessingResponse
}

func (f *fakeStream) Context() context.Context {
	if f.ctx != nil {
		return f.ctx
	}
	return context.Background()
}

func (f *fakeStream) Recv() (*epb.ProcessingRequest, error) {
	if len(f.incoming) == 0 {
		return nil, io.EOF
	}
	req := f.incoming[0]
	f.incoming = f.incoming[1:]
	return req, nil
}

func (f *fakeStream) Send(resp *epb.ProcessingResponse) error {
	f.outgoing = append(f.outgoing, resp)
	return nil
}

func mustLoadConfig(t *testing.T, yamlStr string) *policy.Config {
	t.Helper()
	c, err := policy.LoadBytes([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	return c
}

func makeHeaderMap(headers map[string]string) *corev3.HeaderMap {
	var list []*corev3.HeaderValue
	for k, v := range headers {
		list = append(list, &corev3.HeaderValue{
			Key:   k,
			Value: v,
		})
	}
	return &corev3.HeaderMap{Headers: list}
}

// TestResponseHeadersLocation checks:
// - responseHeaders: a policy that reescribes Location in an 302 produce un ProcessingResponse_ResponseHeaders con SetHeaders conteniendo location con el valor esperado y AppendAction OVERWRITE. CANARIO del caso de uso real (Keycloak redirect).
func TestResponseHeadersLocation(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: keycloak-redirect
    parameters:
      engine: extProc
      mode: applyAll
      phase: responseHeaders
    match: "true"
    rules:
      - name: rewrite-location
        match: "response.status == 302"
        mutations:
          - op: setHeader
            name: Location
            value: "'https://new-location.com'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":status":  "302",
							"Location": "http://old-location.com",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rh, ok := resp.Response.(*epb.ProcessingResponse_ResponseHeaders)
	if !ok {
		t.Fatalf("expected ProcessingResponse_ResponseHeaders, got %T", resp.Response)
	}

	hm := rh.ResponseHeaders.Response.HeaderMutation
	if hm == nil {
		t.Fatalf("expected header mutations to be non-nil")
	}

	found := false
	for _, h := range hm.SetHeaders {
		if strings.ToLower(h.Header.Key) == "location" {
			found = true
			if string(h.Header.RawValue) != "https://new-location.com" {
				t.Errorf("expected Location value to be 'https://new-location.com', got %q", string(h.Header.RawValue))
			}
			if h.AppendAction != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
				t.Errorf("expected OVERWRITE_IF_EXISTS_OR_ADD, got %v", h.AppendAction)
			}
		}
	}
	if !found {
		t.Errorf("Location header mutation not found")
	}
}

// TestSetHeaderOverwriteAndAppend checks:
// - setHeader OVERWRITE vs appendHeader APPEND: AppendAction correcto en cada uno.
// - removeHeader: aparece en RemoveHeaders.
func TestSetHeaderOverwriteAndAppend(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: test-headers
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    match: "true"
    rules:
      - name: modify-headers
        match: "true"
        mutations:
          - op: setHeader
            name: X-Overwrite
            value: "'overwritten'"
          - op: appendHeader
            name: X-Append
            value: "'appended'"
          - op: removeHeader
            name: X-To-Remove
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestHeaders{
					RequestHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":method":     "GET",
							":path":       "/",
							"X-Overwrite": "old",
							"X-Append":    "old",
							"X-To-Remove": "old",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rh, ok := resp.Response.(*epb.ProcessingResponse_RequestHeaders)
	if !ok {
		t.Fatalf("expected ProcessingResponse_RequestHeaders, got %T", resp.Response)
	}

	hm := rh.RequestHeaders.Response.HeaderMutation
	if hm == nil {
		t.Fatalf("expected header mutations to be non-nil")
	}

	// Verify overwrite
	var foundOverwrite, foundAppend bool
	for _, h := range hm.SetHeaders {
		if strings.ToLower(h.Header.Key) == "x-overwrite" {
			foundOverwrite = true
			if string(h.Header.RawValue) != "overwritten" {
				t.Errorf("expected 'overwritten', got %q", string(h.Header.RawValue))
			}
			if h.AppendAction != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
				t.Errorf("expected OVERWRITE_IF_EXISTS_OR_ADD, got %v", h.AppendAction)
			}
		}
		if strings.ToLower(h.Header.Key) == "x-append" {
			foundAppend = true
			if string(h.Header.RawValue) != "appended" {
				t.Errorf("expected 'appended', got %q", string(h.Header.RawValue))
			}
			if h.AppendAction != corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD {
				t.Errorf("expected APPEND_IF_EXISTS_OR_ADD, got %v", h.AppendAction)
			}
		}
	}

	if !foundOverwrite {
		t.Errorf("X-Overwrite mutation not found")
	}
	if !foundAppend {
		t.Errorf("X-Append mutation not found")
	}

	// Verify remove
	foundRemove := false
	for _, r := range hm.RemoveHeaders {
		if strings.ToLower(r) == "x-to-remove" {
			foundRemove = true
		}
	}
	if !foundRemove {
		t.Errorf("X-To-Remove not found in RemoveHeaders")
	}
}

// TestSetBodyAndContentLength checks:
// - setBody: BodyMutation.Body correcto Y content-length recalculado en SetHeaders.
func TestSetBodyAndContentLength(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: test-body
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestBody
    match: "true"
    rules:
      - name: rewrite-body
        match: "true"
        mutations:
          - op: setBody
            value: "'new-body-content'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestBody{
					RequestBody: &epb.HttpBody{
						Body: []byte("old-body"),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rb, ok := resp.Response.(*epb.ProcessingResponse_RequestBody)
	if !ok {
		t.Fatalf("expected ProcessingResponse_RequestBody, got %T", resp.Response)
	}

	bm := rb.RequestBody.Response.BodyMutation
	if bm == nil {
		t.Fatalf("expected body mutation to be non-nil")
	}

	bodyText := bm.GetBody()
	if string(bodyText) != "new-body-content" {
		t.Errorf("expected body 'new-body-content', got %q", string(bodyText))
	}

	hm := rb.RequestBody.Response.HeaderMutation
	if hm == nil {
		t.Fatalf("expected header mutations to be non-nil for content-length recalculation")
	}

	foundCL := false
	for _, h := range hm.SetHeaders {
		if strings.ToLower(h.Header.Key) == "content-length" {
			foundCL = true
			expectedLen := strconv.Itoa(len("new-body-content"))
			if string(h.Header.RawValue) != expectedLen {
				t.Errorf("expected content-length %q, got %q", expectedLen, string(h.Header.RawValue))
			}
			if h.AppendAction != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
				t.Errorf("expected OVERWRITE_IF_EXISTS_OR_ADD, got %v", h.AppendAction)
			}
		}
	}

	if !foundCL {
		t.Errorf("content-length header mutation not found")
	}
}

// TestSetStatus checks:
// - setStatus: :status en SetHeaders con el codigo.
func TestSetStatus(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: test-status
    parameters:
      engine: extProc
      mode: applyAll
      phase: responseHeaders
    match: "true"
    rules:
      - name: rewrite-status
        match: "true"
        mutations:
          - op: setStatus
            code: "418"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":status": "200",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rh, ok := resp.Response.(*epb.ProcessingResponse_ResponseHeaders)
	if !ok {
		t.Fatalf("expected ProcessingResponse_ResponseHeaders, got %T", resp.Response)
	}

	hm := rh.ResponseHeaders.Response.HeaderMutation
	if hm == nil {
		t.Fatalf("expected header mutations to be non-nil")
	}

	foundStatus := false
	for _, h := range hm.SetHeaders {
		if h.Header.Key == ":status" {
			foundStatus = true
			if string(h.Header.RawValue) != "418" {
				t.Errorf("expected status '418', got %q", string(h.Header.RawValue))
			}
			if h.AppendAction != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
				t.Errorf("expected OVERWRITE, got %v", h.AppendAction)
			}
		}
	}

	if !foundStatus {
		t.Errorf(":status mutation not found")
	}
}

// TestDryRunGlobal checks:
// - dry-run global: una policy con mutaciones produce CONTINUE SIN mutaciones (canario: debe fallar si se aplican bajo dry-run).
func TestDryRunGlobal(t *testing.T) {
	yamlStr := `
defaults:
  dryRun: true
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: test-dry-run-global
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    match: "true"
    rules:
      - name: dry-run-rule
        match: "true"
        mutations:
          - op: setHeader
            name: X-Dry
            value: "'not-applied'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestHeaders{
					RequestHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":method": "GET",
							":path":   "/",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rh, ok := resp.Response.(*epb.ProcessingResponse_RequestHeaders)
	if !ok {
		t.Fatalf("expected ProcessingResponse_RequestHeaders, got %T", resp.Response)
	}

	hm := rh.RequestHeaders.Response.HeaderMutation
	if hm != nil {
		t.Errorf("expected header mutations to be nil under global dry-run, got %v", hm)
	}
}

// TestDryRunPerRule checks:
// - dry-run por regla: una mutacion de regla dryRun no se aplica, otra normal si.
func TestDryRunPerRule(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: test-dry-run-rule
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    match: "true"
    rules:
      - name: normal-rule
        match: "true"
        mutations:
          - op: setHeader
            name: X-Normal
            value: "'yes'"
      - name: dry-rule
        match: "true"
        dryRun: true
        mutations:
          - op: setHeader
            name: X-Dry
            value: "'no'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestHeaders{
					RequestHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":method": "GET",
							":path":   "/",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rh, ok := resp.Response.(*epb.ProcessingResponse_RequestHeaders)
	if !ok {
		t.Fatalf("expected ProcessingResponse_RequestHeaders, got %T", resp.Response)
	}

	hm := rh.RequestHeaders.Response.HeaderMutation
	if hm == nil {
		t.Fatalf("expected header mutations to be non-nil")
	}

	for _, h := range hm.SetHeaders {
		if strings.ToLower(h.Header.Key) == "x-dry" {
			t.Errorf("X-Dry should NOT be present (dryRun rule)")
		}
	}

	foundNormal := false
	for _, h := range hm.SetHeaders {
		if strings.ToLower(h.Header.Key) == "x-normal" {
			foundNormal = true
			if string(h.Header.RawValue) != "yes" {
				t.Errorf("expected 'yes', got %q", string(h.Header.RawValue))
			}
		}
	}

	if !foundNormal {
		t.Errorf("X-Normal should be present")
	}
}

// TestOverflowSkip checks:
// - overflow body skip: body mayor que MaxBodyBytes -> CONTINUE sin mutaciones.
func TestOverflowSkip(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 10
    onBodyOverflow: skip
groups:
  - name: test-body-overflow
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestBody
    match: "true"
    rules:
      - name: rewrite-body
        match: "true"
        mutations:
          - op: setBody
            value: "'new-body'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestBody{
					RequestBody: &epb.HttpBody{
						Body: []byte("this is more than 10 bytes!"),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rb, ok := resp.Response.(*epb.ProcessingResponse_RequestBody)
	if !ok {
		t.Fatalf("expected ProcessingResponse_RequestBody, got %T", resp.Response)
	}

	if rb.RequestBody.Response.BodyMutation != nil {
		t.Errorf("expected body mutation to be nil on overflow skip")
	}
	if rb.RequestBody.Response.HeaderMutation != nil {
		t.Errorf("expected header mutation to be nil on overflow skip")
	}
}

// TestOverflowFail checks:
// - overflow body fail: -> ImmediateResponse 500. Y bajo dry-run global -> CONTINUE (canario).
func TestOverflowFail(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 10
    onBodyOverflow: fail
groups:
  - name: test-body-overflow
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestBody
    match: "true"
    rules:
      - name: rewrite-body
        match: "true"
        mutations:
          - op: setBody
            value: "'new-body'"
`
	// 1. Without dry-run: should fail with ImmediateResponse 500
	cfg1 := mustLoadConfig(t, yamlStr)
	srv1 := New(cfg1)

	stream1 := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestBody{
					RequestBody: &epb.HttpBody{
						Body: []byte("this is more than 10 bytes!"),
					},
				},
			},
		},
	}

	err := srv1.Process(stream1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream1.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream1.outgoing))
	}

	resp1 := stream1.outgoing[0]
	ir, ok := resp1.Response.(*epb.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ProcessingResponse_ImmediateResponse, got %T", resp1.Response)
	}

	if ir.ImmediateResponse.Status.Code != typev3.StatusCode(500) {
		t.Errorf("expected status code 500, got %v", ir.ImmediateResponse.Status.Code)
	}
	if ir.ImmediateResponse.Details != "ext_proc body overflow" {
		t.Errorf("expected details 'ext_proc body overflow', got %q", ir.ImmediateResponse.Details)
	}

	// 2. With global dry-run: should CONTINUE with no mutations (canario)
	yamlStrDry := `
defaults:
  dryRun: true
  extProc:
    maxBodyBytes: 10
    onBodyOverflow: fail
groups:
  - name: test-body-overflow
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestBody
    match: "true"
    rules:
      - name: rewrite-body
        match: "true"
        mutations:
          - op: setBody
            value: "'new-body'"
`
	cfg2 := mustLoadConfig(t, yamlStrDry)
	srv2 := New(cfg2)

	stream2 := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestBody{
					RequestBody: &epb.HttpBody{
						Body: []byte("this is more than 10 bytes!"),
					},
				},
			},
		},
	}

	err = srv2.Process(stream2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream2.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream2.outgoing))
	}

	resp2 := stream2.outgoing[0]
	rb, ok := resp2.Response.(*epb.ProcessingResponse_RequestBody)
	if !ok {
		t.Fatalf("expected ProcessingResponse_RequestBody, got %T", resp2.Response)
	}

	if rb.RequestBody.Response.BodyMutation != nil {
		t.Errorf("expected body mutation to be nil under global dry run")
	}
}

// TestPseudoHeadersParsing checks:
// - parseo de pseudo-headers: ":method"/":path"/":authority"/":status" se reflejan en el policy.Request/Response que ve la policy (verificable via una policy cuyo match use request.method/path o response.status y mute en consecuencia).
func TestPseudoHeadersParsing(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: check-pseudo-headers
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    match: "true"
    rules:
      - name: match-path
        match: "request.path == '/secure' && request.method == 'POST' && request.host == 'example.com' && request.query['a'] == 'b'"
        mutations:
          - op: setHeader
            name: X-Matched-Pseudo
            value: "'yes'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestHeaders{
					RequestHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":method":    "POST",
							":path":      "/secure?a=b",
							":authority": "example.com",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rh, ok := resp.Response.(*epb.ProcessingResponse_RequestHeaders)
	if !ok {
		t.Fatalf("expected ProcessingResponse_RequestHeaders, got %T", resp.Response)
	}

	hm := rh.RequestHeaders.Response.HeaderMutation
	if hm == nil {
		t.Fatalf("expected header mutations to be non-nil")
	}

	foundMatched := false
	for _, h := range hm.SetHeaders {
		if strings.ToLower(h.Header.Key) == "x-matched-pseudo" {
			foundMatched = true
			if string(h.Header.RawValue) != "yes" {
				t.Errorf("expected 'yes', got %q", string(h.Header.RawValue))
			}
		}
	}

	if !foundMatched {
		t.Errorf("X-Matched-Pseudo was not set (pseudo-headers might not have been correctly parsed/used)")
	}
}

// TestNoMatchingGroups checks:
// - fase sin grupos aplicables -> CONTINUE vacio.
func TestNoMatchingGroups(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: test-headers
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    match: "true"
    rules:
      - name: modify-headers
        match: "request.path == '/something-else'"
        mutations:
          - op: setHeader
            name: X-Overwrite
            value: "'overwritten'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestHeaders{
					RequestHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":method": "GET",
							":path":   "/",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rh, ok := resp.Response.(*epb.ProcessingResponse_RequestHeaders)
	if !ok {
		t.Fatalf("expected ProcessingResponse_RequestHeaders, got %T", resp.Response)
	}

	if rh.RequestHeaders.Response.HeaderMutation != nil {
		t.Errorf("expected nil HeaderMutation when rules do not match")
	}
}

// TestDirectResponseInResponseHeaders checks:
//   - directResponse in responseHeaders: una policy que ante un 302 hace directResponse(200, {content-type: text/html}, body "hola")
//     produce un ProcessingResponse_ImmediateResponse con Status.Code==200, Body=="hola" y un header content-type=text/html.
func TestDirectResponseInResponseHeaders(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: direct-resp-group
    parameters:
      engine: extProc
      mode: applyAll
      phase: responseHeaders
    match: "true"
    rules:
      - name: direct-resp-rule
        match: "response.status == 302"
        mutations:
          - op: directResponse
            status: 200
            headers: '{"content-type": "text/html"}'
            body: "'hola'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":status": "302",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	ir, ok := resp.Response.(*epb.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ProcessingResponse_ImmediateResponse, got %T", resp.Response)
	}

	if ir.ImmediateResponse.Status.Code != typev3.StatusCode(200) {
		t.Errorf("expected status 200, got %v", ir.ImmediateResponse.Status.Code)
	}

	if string(ir.ImmediateResponse.Body) != "hola" {
		t.Errorf("expected body 'hola', got %q", string(ir.ImmediateResponse.Body))
	}

	hm := ir.ImmediateResponse.Headers
	if hm == nil {
		t.Fatalf("expected headers to be non-nil")
	}

	found := false
	for _, h := range hm.SetHeaders {
		if strings.ToLower(h.Header.Key) == "content-type" {
			found = true
			if string(h.Header.RawValue) != "text/html" {
				t.Errorf("expected content-type to be 'text/html', got %q", string(h.Header.RawValue))
			}
			if h.AppendAction != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
				t.Errorf("expected OVERWRITE_IF_EXISTS_OR_ADD, got %v", h.AppendAction)
			}
		}
	}
	if !found {
		t.Errorf("content-type header not found in immediate response")
	}
}

// TestDirectResponseCortocircuito checks:
//   - cortocircuito: una regla applyAll/firstMatch donde ademas del directResponse hubiera (en otra regla del mismo grupo en applyAll)
//     un setHeader: el resultado es ImmediateResponse y el setHeader NO aparece (no es CommonResponse).
func TestDirectResponseCortocircuito(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: direct-resp-group
    parameters:
      engine: extProc
      mode: applyAll
      phase: responseHeaders
    match: "true"
    rules:
      - name: direct-resp-rule
        match: "response.status == 302"
        mutations:
          - op: directResponse
            status: 200
            headers: '{"content-type": "text/html"}'
            body: "'hola'"
      - name: set-header-rule
        match: "true"
        mutations:
          - op: setHeader
            name: X-Should-Not-Exist
            value: "'somevalue'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":status": "302",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	ir, ok := resp.Response.(*epb.ProcessingResponse_ImmediateResponse)
	if !ok {
		t.Fatalf("expected ProcessingResponse_ImmediateResponse, got %T", resp.Response)
	}

	if ir.ImmediateResponse.Headers != nil {
		for _, h := range ir.ImmediateResponse.Headers.SetHeaders {
			if strings.ToLower(h.Header.Key) == "x-should-not-exist" {
				t.Errorf("found X-Should-Not-Exist header, but directResponse should have ignored all other mutations")
			}
		}
	}
}

// TestDirectResponseDryRunGlobal checks:
// - dry-run global: misma policy con defaults.dryRun: true -> NO ImmediateResponse; debe ser CONTINUE (CommonResponse) sin mutaciones.
func TestDirectResponseDryRunGlobal(t *testing.T) {
	yamlStr := `
defaults:
  dryRun: true
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: direct-resp-group
    parameters:
      engine: extProc
      mode: applyAll
      phase: responseHeaders
    match: "true"
    rules:
      - name: direct-resp-rule
        match: "response.status == 302"
        mutations:
          - op: directResponse
            status: 200
            headers: '{"content-type": "text/html"}'
            body: "'hola'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":status": "302",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rh, ok := resp.Response.(*epb.ProcessingResponse_ResponseHeaders)
	if !ok {
		t.Fatalf("expected ProcessingResponse_ResponseHeaders, got %T", resp.Response)
	}

	if rh.ResponseHeaders.Response.Status != epb.CommonResponse_CONTINUE {
		t.Errorf("expected Status CONTINUE, got %v", rh.ResponseHeaders.Response.Status)
	}

	if rh.ResponseHeaders.Response.HeaderMutation != nil {
		t.Errorf("expected nil HeaderMutation, got %v", rh.ResponseHeaders.Response.HeaderMutation)
	}
}

// TestDirectResponseDryRunPorRegla checks:
// - dry-run por regla: la regla del directResponse con dryRun: true -> no se sirve (CONTINUE).
func TestDirectResponseDryRunPorRegla(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: direct-resp-group
    parameters:
      engine: extProc
      mode: applyAll
      phase: responseHeaders
    match: "true"
    rules:
      - name: direct-resp-rule
        dryRun: true
        match: "response.status == 302"
        mutations:
          - op: directResponse
            status: 200
            headers: '{"content-type": "text/html"}'
            body: "'hola'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":status": "302",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rh, ok := resp.Response.(*epb.ProcessingResponse_ResponseHeaders)
	if !ok {
		t.Fatalf("expected ProcessingResponse_ResponseHeaders, got %T", resp.Response)
	}

	if rh.ResponseHeaders.Response.Status != epb.CommonResponse_CONTINUE {
		t.Errorf("expected Status CONTINUE, got %v", rh.ResponseHeaders.Response.Status)
	}

	if rh.ResponseHeaders.Response.HeaderMutation != nil {
		t.Errorf("expected nil HeaderMutation, got %v", rh.ResponseHeaders.Response.HeaderMutation)
	}
}

// TestDirectResponseSinDirectResponse checks:
// - sin directResponse: una policy solo con setHeader sigue produciendo CommonResponse con el header (no se rompio el flujo viejo).
func TestDirectResponseSinDirectResponse(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: keycloak-redirect
    parameters:
      engine: extProc
      mode: applyAll
      phase: responseHeaders
    match: "true"
    rules:
      - name: rewrite-location
        match: "response.status == 302"
        mutations:
          - op: setHeader
            name: Location
            value: "'https://new-location.com'"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":status":  "302",
							"Location": "http://old-location.com",
						}),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.outgoing) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.outgoing))
	}

	resp := stream.outgoing[0]
	rh, ok := resp.Response.(*epb.ProcessingResponse_ResponseHeaders)
	if !ok {
		t.Fatalf("expected ProcessingResponse_ResponseHeaders, got %T", resp.Response)
	}

	hm := rh.ResponseHeaders.Response.HeaderMutation
	if hm == nil {
		t.Fatalf("expected header mutations to be non-nil")
	}

	found := false
	for _, h := range hm.SetHeaders {
		if strings.ToLower(h.Header.Key) == "location" {
			found = true
			if string(h.Header.RawValue) != "https://new-location.com" {
				t.Errorf("expected Location value to be 'https://new-location.com', got %q", string(h.Header.RawValue))
			}
		}
	}
	if !found {
		t.Errorf("Location header mutation not found")
	}
}
