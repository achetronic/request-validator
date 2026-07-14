// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package grpcserver

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	epb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"request-validator/internal/log"
)

func TestProcessLogsRequestHeadersAccess(t *testing.T) {
	var buf bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Configure(log.Options{}) })

	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
logging:
  excludeHeaders:
    - cookie
  redactHeaders:
    - authorization
  redactReveal: 6
groups:
  - name: test-group
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    match: "true"
    rules:
      - name: dummy
        match: "true"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestHeaders{
					RequestHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":method":         "GET",
							":path":           "/hello",
							":scheme":         "http",
							":authority":      "localhost",
							"x-pikaso-client": "plugin:test",
							"Cookie":          "session=secret",
							"Authorization":   "Bearer eyJ1234567890",
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

	out := buf.String()
	if !strings.Contains(out, `"extProc access"`) {
		t.Fatalf("expected 'extProc access' log record, got: %s", out)
	}
	if !strings.Contains(out, `"phase":"requestHeaders"`) {
		t.Fatalf("expected phase:requestHeaders, got: %s", out)
	}
	if !strings.Contains(out, `"x-pikaso-client":"plugin:test"`) {
		t.Fatalf("expected x-pikaso-client in logs, got: %s", out)
	}
	if strings.Contains(strings.ToLower(out), "cookie") || strings.Contains(out, "session=secret") {
		t.Fatalf("cookie or its value should have been excluded, got: %s", out)
	}
	if !strings.Contains(out, `"authorization":"Bearer*`) {
		t.Fatalf("authorization should be redacted Bearer*, got: %s", out)
	}
}

func TestProcessLogsResponsePhases(t *testing.T) {
	var buf bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Configure(log.Options{}) })

	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
logging:
  logBody: true
groups:
  - name: test-group
    parameters:
      engine: extProc
      mode: applyAll
      phase: responseHeaders
    match: "true"
    rules:
      - name: dummy
        match: "true"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":status":      "200",
							"Content-Type": "application/json",
						}),
					},
				},
			},
			{
				Request: &epb.ProcessingRequest_ResponseBody{
					ResponseBody: &epb.HttpBody{
						Body: []byte(`{"response_key":"response_val"}`),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"extProc access"`) {
		t.Fatalf("expected 'extProc access' log record, got: %s", out)
	}
	if !strings.Contains(out, `"status":200`) {
		t.Fatalf("expected response.status:200, got: %s", out)
	}
	if !strings.Contains(out, `"phase":"responseHeaders"`) {
		t.Fatalf("expected phase:responseHeaders log, got: %s", out)
	}
	if !strings.Contains(out, `"phase":"responseBody"`) {
		t.Fatalf("expected phase:responseBody log, got: %s", out)
	}
	if !strings.Contains(out, `"raw":"{\"response_key\":\"response_val\"}"`) {
		t.Fatalf("expected response body raw to be logged, got: %s", out)
	}
}

func TestStreamIDSharedAcrossPhases(t *testing.T) {
	var buf bytes.Buffer
	if err := log.Configure(log.Options{Level: "debug", Format: log.FormatJSON, Writer: &buf}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Configure(log.Options{}) })

	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: headers-req
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    match: "true"
    rules:
      - name: r1
        match: "true"
  - name: body-req
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestBody
    match: "true"
    rules:
      - name: r2
        match: "true"
  - name: headers-resp
    parameters:
      engine: extProc
      mode: applyAll
      phase: responseHeaders
    match: "true"
    rules:
      - name: r3
        match: "true"
  - name: body-resp
    parameters:
      engine: extProc
      mode: applyAll
      phase: responseBody
    match: "true"
    rules:
      - name: r4
        match: "true"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	stream := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestHeaders{
					RequestHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":method":    "GET",
							":path":      "/hello",
							":scheme":    "http",
							":authority": "localhost",
						}),
					},
				},
			},
			{
				Request: &epb.ProcessingRequest_RequestBody{
					RequestBody: &epb.HttpBody{
						Body: []byte(`{"request_key":"request_val"}`),
					},
				},
			},
			{
				Request: &epb.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":status":      "200",
							"Content-Type": "application/json",
						}),
					},
				},
			},
			{
				Request: &epb.ProcessingRequest_ResponseBody{
					ResponseBody: &epb.HttpBody{
						Body: []byte(`{"response_key":"response_val"}`),
					},
				},
			},
		},
	}

	err := srv.Process(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var records []map[string]any
	lines := strings.Split(buf.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Logf("failed to unmarshal log line %q: %v", line, err)
			continue
		}
		records = append(records, record)
	}

	var streamIDsFound []string
	var phaseEvaluatedStreamIDs []string
	for _, rec := range records {
		msg, _ := rec["msg"].(string)
		if msg == "extProc access" {
			sid, _ := rec["stream_id"].(string)
			if sid == "" {
				t.Errorf("expected non-empty stream_id in extProc access log: %v", rec)
			} else {
				streamIDsFound = append(streamIDsFound, sid)
			}
		} else if msg == "extProc phase evaluated" {
			sid, _ := rec["stream_id"].(string)
			if sid == "" {
				t.Errorf("expected non-empty stream_id in extProc phase evaluated log: %v", rec)
			} else {
				phaseEvaluatedStreamIDs = append(phaseEvaluatedStreamIDs, sid)
			}
		}
	}

	if len(streamIDsFound) != 4 {
		t.Fatalf("expected exactly 4 extProc access logs, got %d", len(streamIDsFound))
	}
	if len(phaseEvaluatedStreamIDs) != 4 {
		t.Fatalf("expected exactly 4 extProc phase evaluated logs, got %d", len(phaseEvaluatedStreamIDs))
	}

	// Assert all of them are equal to the first one
	firstID := streamIDsFound[0]
	for _, id := range streamIDsFound {
		if id != firstID {
			t.Errorf("expected all extProc access stream_ids to be equal (%s), but got %s", firstID, id)
		}
	}
	for _, id := range phaseEvaluatedStreamIDs {
		if id != firstID {
			t.Errorf("expected all extProc phase evaluated stream_ids to match access stream_id (%s), but got %s", firstID, id)
		}
	}
}

func TestStreamIDDiffersBetweenStreams(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: test-group
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    match: "true"
    rules:
      - name: dummy
        match: "true"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	// Stream 1
	var buf1 bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf1}); err != nil {
		t.Fatal(err)
	}
	stream1 := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestHeaders{
					RequestHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":method":    "GET",
							":path":      "/hello",
							":scheme":    "http",
							":authority": "localhost",
						}),
					},
				},
			},
		},
	}
	if err := srv.Process(stream1); err != nil {
		t.Fatal(err)
	}

	// Stream 2
	var buf2 bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf2}); err != nil {
		t.Fatal(err)
	}
	stream2 := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestHeaders{
					RequestHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":method":    "GET",
							":path":      "/hello",
							":scheme":    "http",
							":authority": "localhost",
						}),
					},
				},
			},
		},
	}
	if err := srv.Process(stream2); err != nil {
		t.Fatal(err)
	}

	// Restore logger
	_ = log.Configure(log.Options{})

	// Parse stream 1 ID
	id1 := extractStreamID(t, buf1.String())
	// Parse stream 2 ID
	id2 := extractStreamID(t, buf2.String())

	if id1 == "" || id2 == "" {
		t.Fatalf("expected non-empty stream IDs, got stream1=%q, stream2=%q", id1, id2)
	}
	if id1 == id2 {
		t.Errorf("expected different stream IDs for different streams, but both were %s", id1)
	}
}

func extractStreamID(t *testing.T, logOutput string) string {
	t.Helper()
	lines := strings.Split(logOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if record["msg"] == "extProc access" {
			if sid, ok := record["stream_id"].(string); ok {
				return sid
			}
		}
	}
	return ""
}

func TestRequestIDPromotedFromHeader(t *testing.T) {
	yamlStr := `
defaults:
  extProc:
    maxBodyBytes: 1024
    onBodyOverflow: fail
groups:
  - name: test-group
    parameters:
      engine: extProc
      mode: applyAll
      phase: requestHeaders
    match: "true"
    rules:
      - name: dummy
        match: "true"
`
	cfg := mustLoadConfig(t, yamlStr)
	srv := New(cfg)

	// Case 1: with header "x-request-id"
	var buf1 bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf1}); err != nil {
		t.Fatal(err)
	}
	stream1 := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestHeaders{
					RequestHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":method":      "GET",
							":path":        "/hello",
							":scheme":      "http",
							":authority":   "localhost",
							"x-request-id": "req-abc-123",
						}),
					},
				},
			},
		},
	}
	if err := srv.Process(stream1); err != nil {
		t.Fatal(err)
	}

	// Case 2: without header "x-request-id"
	var buf2 bytes.Buffer
	if err := log.Configure(log.Options{Level: "info", Format: log.FormatJSON, Writer: &buf2}); err != nil {
		t.Fatal(err)
	}
	stream2 := &fakeStream{
		incoming: []*epb.ProcessingRequest{
			{
				Request: &epb.ProcessingRequest_RequestHeaders{
					RequestHeaders: &epb.HttpHeaders{
						Headers: makeHeaderMap(map[string]string{
							":method":    "GET",
							":path":      "/hello",
							":scheme":    "http",
							":authority": "localhost",
						}),
					},
				},
			},
		},
	}
	if err := srv.Process(stream2); err != nil {
		t.Fatal(err)
	}

	_ = log.Configure(log.Options{})

	// Check buf1 has "request_id":"req-abc-123"
	foundReqID := false
	for _, line := range strings.Split(buf1.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if record["msg"] == "extProc access" {
			reqID, exists := record["request_id"]
			if exists {
				foundReqID = true
				if reqID != "req-abc-123" {
					t.Errorf("expected request_id req-abc-123, got %v", reqID)
				}
			}
		}
	}
	if !foundReqID {
		t.Errorf("expected request_id to be present in logs, but it wasn't")
	}

	// Check buf2 has NO "request_id" key
	for _, line := range strings.Split(buf2.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if record["msg"] == "extProc access" {
			if _, exists := record["request_id"]; exists {
				t.Errorf("expected no request_id field when header is absent, but got %v", record["request_id"])
			}
		}
	}
}
