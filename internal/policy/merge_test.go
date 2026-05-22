package policy

import (
	"context"
	"encoding/json"
	"testing"

	"request-validator/internal/state"
)

func TestMergeNoOverlayReturnsYAMLBehaviour(t *testing.T) {
	yaml := []byte(`
defaults: { action: deny }
groups:
  - name: allow-true
    action: allow
    rules:
      - name: any
        match: "true"
`)
	c, err := MergeFromYAML(yaml, state.Snapshot{})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	d := c.Evaluate(context.Background(), &Request{Method: "GET", Host: "h", Path: "/"})
	if !d.Allowed {
		t.Fatalf("expected allow, got %+v", d)
	}
}

func TestMergeOverridesGroupByName(t *testing.T) {
	yaml := []byte(`
defaults: { action: deny }
groups:
  - name: g1
    action: allow
    rules:
      - name: any
        match: "true"
`)
	overlay := state.Snapshot{
		Groups: map[string]json.RawMessage{
			"g1": json.RawMessage(`{"name":"g1","action":"deny","rules":[{"name":"any","match":"true"}]}`),
		},
	}
	c, err := MergeFromYAML(yaml, overlay)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if c.Groups[0].Action != "deny" || c.Groups[0].Source != SourceAPI {
		t.Fatalf("expected API override, got %+v", c.Groups[0])
	}
	d := c.Evaluate(context.Background(), &Request{Method: "GET", Host: "h", Path: "/"})
	if d.Allowed {
		t.Fatalf("expected deny after override, got %+v", d)
	}
}

func TestMergePriorityAcrossSources(t *testing.T) {
	yaml := []byte(`
defaults: { action: deny }
groups:
  - name: yaml-late
    priority: 100
    action: allow
    rules:
      - name: any
        match: "true"
`)
	overlay := state.Snapshot{
		Groups: map[string]json.RawMessage{
			"api-early": json.RawMessage(`{"name":"api-early","priority":-10,"action":"deny","rules":[{"name":"any","match":"true"}]}`),
		},
	}
	c, err := MergeFromYAML(yaml, overlay)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if c.Groups[0].Name != "api-early" {
		t.Fatalf("expected api-early first, got %s", c.Groups[0].Name)
	}
	d := c.Evaluate(context.Background(), &Request{Method: "GET", Host: "h", Path: "/"})
	if d.Allowed {
		t.Fatalf("expected deny from api-early, got %+v", d)
	}
}

func TestMergeDefaultsOverlay(t *testing.T) {
	yaml := []byte(`
defaults:
  action: deny
  denyStatus: 403
  denyBody: "Forbidden YAML"
groups:
  - name: g
    rules:
      - name: never
        match: "false"
`)
	overlay := state.Snapshot{
		Defaults: json.RawMessage(`{"denyBody":"API-deny"}`),
	}
	c, err := MergeFromYAML(yaml, overlay)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if c.Defaults.DenyBody != "API-deny" {
		t.Fatalf("denyBody not overridden: %q", c.Defaults.DenyBody)
	}
	if c.Defaults.Action != "deny" || c.Defaults.DenyStatus != 403 {
		t.Fatalf("unintended override: %+v", c.Defaults)
	}
}

func TestMergeLoggingOverlay(t *testing.T) {
	yaml := []byte(`
defaults: { action: deny }
logging:
  level: info
  format: json
groups:
  - name: g
    rules:
      - name: x
        match: "true"
`)
	overlay := state.Snapshot{
		Logging: json.RawMessage(`{"level":"debug"}`),
	}
	c, err := MergeFromYAML(yaml, overlay)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if c.Logging.Level != "debug" {
		t.Fatalf("level not overridden: %q", c.Logging.Level)
	}
	if c.Logging.Format != "json" {
		t.Fatalf("format unintentionally changed: %q", c.Logging.Format)
	}
}

func TestMergeRejectsInvalidGroupPayload(t *testing.T) {
	yaml := []byte(`
defaults: { action: deny }
groups: []
`)
	overlay := state.Snapshot{
		Groups: map[string]json.RawMessage{
			"broken": json.RawMessage(`{"name":"broken","rules":[]}`),
		},
	}
	if _, err := MergeFromYAML(yaml, overlay); err == nil {
		t.Fatal("expected merge error for empty group")
	}
}

func TestMergeFromYAMLEmptyYAML(t *testing.T) {
	overlay := state.Snapshot{
		Groups: map[string]json.RawMessage{
			"api-only": json.RawMessage(`{"name":"api-only","action":"allow","rules":[{"name":"any","match":"true"}]}`),
		},
		Defaults: json.RawMessage(`{"action":"deny"}`),
	}
	c, err := MergeFromYAML(nil, overlay)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(c.Groups) != 1 || c.Groups[0].Name != "api-only" {
		t.Fatalf("expected api-only, got %+v", c.Groups)
	}
}

func TestMergePayloadNameMismatch(t *testing.T) {
	overlay := state.Snapshot{
		Groups: map[string]json.RawMessage{
			"real-key": json.RawMessage(`{"name":"other","rules":[{"name":"x","match":"true"}]}`),
		},
	}
	_, err := MergeFromYAML([]byte("groups: []"), overlay)
	if err == nil {
		t.Fatal("expected merge error for name mismatch")
	}
}

func TestMergeFactsOverride(t *testing.T) {
	yaml := []byte(`
defaults: { action: deny }
facts:
  - name: ips
    method: value
    value: ["1.1.1.1"]
groups:
  - name: g
    rules:
      - name: x
        match: 'request.remoteIp in facts.ips'
`)
	overlay := state.Snapshot{
		Facts: map[string]json.RawMessage{
			"ips": json.RawMessage(`{"name":"ips","method":"value","value":["2.2.2.2"]}`),
		},
	}
	c, err := MergeFromYAML(yaml, overlay)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	d := c.Evaluate(context.Background(), &Request{Method: "GET", Host: "h", Path: "/", RemoteIP: "2.2.2.2"})
	if !d.Allowed {
		t.Fatalf("expected allow with overridden ips, got %+v", d)
	}
	d = c.Evaluate(context.Background(), &Request{Method: "GET", Host: "h", Path: "/", RemoteIP: "1.1.1.1"})
	if d.Allowed {
		t.Fatalf("expected deny after override hides YAML ip, got %+v", d)
	}
}
