package policy

import (
	"context"
	"testing"

	"request-validator/internal/crdt"
)

func newStore(t *testing.T, node string) *crdt.Store {
	t.Helper()
	s, err := crdt.New(crdt.Options{Node: node})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMergeNoCRDTReturnsYAMLBehaviour(t *testing.T) {
	yaml := []byte(`
defaults: { action: deny }
groups:
  - name: allow-true
    action: allow
    rules:
      - name: any
        match: "true"
`)
	store := newStore(t, "n1")
	c, err := MergeFromYAML(yaml, store.Snapshot())
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
	store := newStore(t, "n1")
	// API replaces "g1" with a deny version.
	if _, err := store.PutGroup("g1", map[string]any{
		"name":   "g1",
		"action": "deny",
		"rules": []map[string]any{
			{"name": "any", "match": "true"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	c, err := MergeFromYAML(yaml, store.Snapshot())
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

func TestMergeTombstoneHidesYAMLGroup(t *testing.T) {
	yaml := []byte(`
defaults: { action: deny }
groups:
  - name: g1
    action: allow
    rules:
      - name: any
        match: "true"
`)
	store := newStore(t, "n1")
	store.DeleteGroup("g1")
	c, err := MergeFromYAML(yaml, store.Snapshot())
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(c.Groups) != 0 {
		t.Fatalf("expected no groups (yaml tombstoned), got %d", len(c.Groups))
	}
	d := c.Evaluate(context.Background(), &Request{Method: "GET", Host: "h", Path: "/"})
	if d.Allowed || d.Rule != "<defaults>" {
		t.Fatalf("expected default deny, got %+v", d)
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
	store := newStore(t, "n1")
	// API group with lower priority -> evaluated first.
	if _, err := store.PutGroup("api-early", map[string]any{
		"name":     "api-early",
		"priority": -10,
		"action":   "deny",
		"rules": []map[string]any{
			{"name": "any", "match": "true"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	c, err := MergeFromYAML(yaml, store.Snapshot())
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
	store := newStore(t, "n1")
	// Only denyBody is overridden; action and denyStatus must remain from YAML.
	if _, err := store.SetDefaults(map[string]any{"denyBody": "API-deny"}); err != nil {
		t.Fatal(err)
	}
	c, err := MergeFromYAML(yaml, store.Snapshot())
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
	store := newStore(t, "n1")
	if _, err := store.SetLogging(map[string]any{"level": "debug"}); err != nil {
		t.Fatal(err)
	}
	c, err := MergeFromYAML(yaml, store.Snapshot())
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
	store := newStore(t, "n1")
	// Invalid: empty rules slice.
	if _, err := store.PutGroup("broken", map[string]any{
		"name":  "broken",
		"rules": []any{},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := MergeFromYAML(yaml, store.Snapshot()); err == nil {
		t.Fatal("expected merge error for empty group")
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
	store := newStore(t, "n1")
	// API replaces fact "ips" with a different list.
	if _, err := store.PutFact("ips", map[string]any{
		"name":   "ips",
		"method": "value",
		"value":  []string{"2.2.2.2"},
	}); err != nil {
		t.Fatal(err)
	}
	c, err := MergeFromYAML(yaml, store.Snapshot())
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

func TestMergeFromYAMLEmptyYAML(t *testing.T) {
	store := newStore(t, "n1")
	// CRDT contributes the only group; YAML is empty.
	if _, err := store.PutGroup("api-only", map[string]any{
		"name":   "api-only",
		"action": "allow",
		"rules": []map[string]any{
			{"name": "any", "match": "true"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetDefaults(map[string]any{"action": "deny"}); err != nil {
		t.Fatal(err)
	}
	c, err := MergeFromYAML(nil, store.Snapshot())
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(c.Groups) != 1 || c.Groups[0].Name != "api-only" {
		t.Fatalf("expected api-only, got %+v", c.Groups)
	}
}

func TestMergeRejectsBadJSONPayload(t *testing.T) {
	store := newStore(t, "n1")
	// Inject a payload that decodes but is not a valid group shape.
	store.Groups.PutRaw("weird", crdt.MapEntry{
		Stamp:   crdt.Stamp{TS: 1, Node: "n1"},
		Payload: []byte(`"a string, not an object"`),
	})
	if _, err := MergeFromYAML([]byte("groups: []"), store.Snapshot()); err == nil {
		t.Fatal("expected error decoding non-object payload")
	}
}

func TestMergePayloadNameMismatch(t *testing.T) {
	store := newStore(t, "n1")
	// Payload claims a different name than the key.
	store.Groups.PutRaw("real-key", crdt.MapEntry{
		Stamp:   crdt.Stamp{TS: 1, Node: "n1"},
		Payload: []byte(`{"name":"other","rules":[{"name":"x","match":"true"}]}`),
	})
	_, err := MergeFromYAML([]byte("groups: []"), store.Snapshot())
	if err == nil {
		t.Fatal("expected merge error for name mismatch")
	}
}

func TestMergeDefaultsClearRestoresYAML(t *testing.T) {
	yaml := []byte(`
defaults:
  action: deny
  denyBody: "from-yaml"
groups:
  - name: g
    rules: [{name: x, match: "true"}]
`)
	store := newStore(t, "n1")
	if _, err := store.SetDefaults(map[string]any{"denyBody": "from-api"}); err != nil {
		t.Fatal(err)
	}
	store.ClearDefaults()
	c, err := MergeFromYAML(yaml, store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if c.Defaults.DenyBody != "from-yaml" {
		t.Fatalf("expected YAML restored after clear, got %q", c.Defaults.DenyBody)
	}
}
