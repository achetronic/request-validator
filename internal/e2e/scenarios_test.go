//go:build !e2e

package e2e

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"request-validator/internal/crdt"
)

const baseYAML = `
defaults:
  action: allow
  denyStatus: 403
groups:
  - name: yaml-allow-everything
    action: allow
    rules:
      - name: any
        match: "true"
`

// TestE2E_AdminPutReplicates is the smoke test: a group PUT on A is
// eventually visible in B's effective config (D-015, D-016, D-018).
func TestE2E_AdminPutReplicates(t *testing.T) {
	a := startNode(t, "A", []byte(baseYAML), nil)
	b := startNode(t, "B", []byte(baseYAML), []string{a.clusterAddr})

	putGroup(t, a, "api-only", map[string]any{
		"name":     "api-only",
		"priority": -50,
		"action":   "deny",
		"rules": []map[string]any{
			{"name": "block-residential", "match": "request.remoteIp == \"203.0.113.5\""},
		},
	})

	if !hasGroup(t, a, "api-only") {
		t.Fatal("A: missing api-only immediately after PUT")
	}
	eventually(t, 15*time.Second, "B sees api-only via gossip", func() bool {
		return hasGroup(t, b, "api-only")
	})
}

// TestE2E_ExtAuthzReflectsCRDTChange validates that a CRDT mutation
// performed via the admin API on A modifies the *runtime* decisions
// the ext-authz endpoint on B emits.
func TestE2E_ExtAuthzReflectsCRDTChange(t *testing.T) {
	a := startNode(t, "A", []byte(baseYAML), nil)
	b := startNode(t, "B", []byte(baseYAML), []string{a.clusterAddr})

	// Baseline: B allows anything.
	if got := extAuthzCheck(t, b, "GET", "host.example", "/", "203.0.113.5", nil); got != http.StatusOK {
		t.Fatalf("baseline B should allow, got %d", got)
	}

	// Admin push on A: block that specific IP at higher priority.
	putGroup(t, a, "block-by-ip", map[string]any{
		"name":     "block-by-ip",
		"priority": -100,
		"action":   "deny",
		"rules": []map[string]any{
			{"name": "x", "match": "request.remoteIp == \"203.0.113.5\""},
		},
	})

	// Gossip convergence under -race can take noticeably longer than
	// without; give it room.
	eventually(t, 20*time.Second, "B denies 203.0.113.5", func() bool {
		return extAuthzCheck(t, b, "GET", "host.example", "/", "203.0.113.5", nil) == http.StatusForbidden
	})
	// Other IPs still pass.
	if got := extAuthzCheck(t, b, "GET", "host.example", "/", "8.8.8.8", nil); got != http.StatusOK {
		t.Fatalf("unrelated IP should still pass on B, got %d", got)
	}
}

// TestE2E_ExtAuthzReflectsCRDTDelete: tombstone propagation removes
// the previously-installed deny rule.
func TestE2E_ExtAuthzReflectsCRDTDelete(t *testing.T) {
	a := startNode(t, "A", []byte(baseYAML), nil)
	b := startNode(t, "B", []byte(baseYAML), []string{a.clusterAddr})

	putGroup(t, a, "block-by-ip", map[string]any{
		"name":     "block-by-ip",
		"priority": -100,
		"action":   "deny",
		"rules": []map[string]any{
			{"name": "x", "match": "request.remoteIp == \"203.0.113.5\""},
		},
	})
	eventually(t, 15*time.Second, "B starts denying", func() bool {
		return extAuthzCheck(t, b, "GET", "host.example", "/", "203.0.113.5", nil) == http.StatusForbidden
	})

	deleteGroup(t, a, "block-by-ip")

	eventually(t, 15*time.Second, "B stops denying after delete", func() bool {
		return extAuthzCheck(t, b, "GET", "host.example", "/", "203.0.113.5", nil) == http.StatusOK
	})
	if hasGroup(t, b, "block-by-ip") {
		t.Fatal("expected group hidden by tombstone on B")
	}
}

// TestE2E_DefaultsOverlayReplicates: the singleton register flow.
func TestE2E_DefaultsOverlayReplicates(t *testing.T) {
	// YAML allows; we'll override defaults via API to deny + custom
	// status, and assert B picks it up.
	yaml := `
defaults:
  action: allow
groups:
  - name: no-op
    rules:
      - name: never
        match: "false"
`
	a := startNode(t, "A", []byte(yaml), nil)
	b := startNode(t, "B", []byte(yaml), []string{a.clusterAddr})

	// Baseline: B uses defaults.allow → 200.
	if got := extAuthzCheck(t, b, "GET", "h", "/", "1.1.1.1", nil); got != http.StatusOK {
		t.Fatalf("baseline B should 200, got %d", got)
	}

	putDefaults(t, a, map[string]any{
		"action":     "deny",
		"denyStatus": 418,
	})

	eventually(t, 15*time.Second, "B denies with 418 via overlay", func() bool {
		return extAuthzCheck(t, b, "GET", "h", "/", "1.1.1.1", nil) == 418
	})
}

// TestE2E_QuarantineOnMissingFact verifies the runtime behaviour when
// a group references a fact that doesn't exist anywhere in the cluster.
//
// CEL is duck-typed on `facts` (declared as `dyn`), so a reference to
// `facts.missing` *compiles* fine: validation cannot reject the PUT,
// and the broadcast happens. At evaluation time, every request hitting
// that group errors out — the configured fail-closed default
// (allowOnError=false) turns it into a 403 with rule="<name>", and
// the engine increments the error counter.
//
// This is documented behaviour, not a bug: the operator is expected
// to put the fact in place before publishing the group. The
// quarantine kicks in only when validation *does* fail (e.g. a
// downstream rule references an absent rule type, or two groups with
// the same name clash) — those scenarios are covered in the unit tests.
func TestE2E_QuarantineOnMissingFact(t *testing.T) {
	yaml := `
defaults: { action: allow, allowOnError: false }
groups:
  - name: trivial
    rules: [{name: any, match: "true"}]
`
	a := startNode(t, "A", []byte(yaml), nil)
	b := startNode(t, "B", []byte(yaml), []string{a.clusterAddr})

	// Push a group that references a fact that doesn't exist anywhere.
	// PUT succeeds (CEL compiles, validate passes), broadcast happens.
	putGroup(t, a, "needs-fact", map[string]any{
		"name":     "needs-fact",
		"priority": -10,
		"action":   "deny",
		"rules":    []map[string]any{{"name": "x", "match": `"foo" in facts.missing`}},
	})

	// On B, the group is in the effective config (gossip arrived).
	eventually(t, 15*time.Second, "B sees needs-fact", func() bool {
		return hasGroup(t, b, "needs-fact")
	})

	// And on B, hitting the engine triggers a runtime CEL error; the
	// fail-closed default kicks in and the response is 403.
	if got := extAuthzCheck(t, b, "GET", "h", "/", "1.2.3.4", nil); got != http.StatusForbidden {
		t.Fatalf("expected 403 fail-closed on B (missing fact), got %d", got)
	}
}

// TestE2E_QuarantineDrainsOnFactArrival: the realistic recovery
// pattern — A pushes a fact + a group that uses it; depending on
// gossip arrival order, B may quarantine the group briefly, then
// drain it once the fact arrives. We assert eventual consistency
// either way: both ext-authz endpoints converge on the same verdict.
func TestE2E_QuarantineDrainsOnFactArrival(t *testing.T) {
	yaml := `
defaults: { action: allow }
groups:
  - name: trivial
    rules: [{name: any, match: "true"}]
`
	a := startNode(t, "A", []byte(yaml), nil)
	b := startNode(t, "B", []byte(yaml), []string{a.clusterAddr})

	// Push fact first, then group that uses it.
	putFact(t, a, "blocklist", map[string]any{
		"name":   "blocklist",
		"method": "value",
		"value":  []string{"203.0.113.5"},
	})
	putGroup(t, a, "uses-fact", map[string]any{
		"name":     "uses-fact",
		"priority": -100,
		"action":   "deny",
		"rules":    []map[string]any{{"name": "x", "match": `request.remoteIp in facts.blocklist`}},
	})

	// Eventually B serves a deny on the listed IP.
	eventually(t, 15*time.Second, "B denies via gossiped fact+group", func() bool {
		return extAuthzCheck(t, b, "GET", "h", "/", "203.0.113.5", nil) == http.StatusForbidden
	})
	// And B's quarantine is empty for this key.
	for _, e := range quarantineEntries(t, b) {
		if e.Section == crdt.SectionGroups && e.Key == "uses-fact" {
			t.Fatalf("uses-fact still quarantined on B: %+v", e)
		}
	}
}

// TestE2E_ConcurrentRequestsDuringReload: while A is performing
// admin writes, a steady stream of ext-authz requests on B should
// never see a half-applied state. They should all be answered with
// either the previous or the new verdict, never something in
// between.
func TestE2E_ConcurrentRequestsDuringReload(t *testing.T) {
	yaml := `
defaults: { action: allow }
groups:
  - name: yaml
    rules: [{name: any, match: "true"}]
`
	a := startNode(t, "A", []byte(yaml), nil)
	b := startNode(t, "B", []byte(yaml), []string{a.clusterAddr})

	stop := make(chan struct{})
	var good, bad int64
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				code := extAuthzCheck(t, b, "GET", "h", "/", "8.8.8.8", nil)
				// 200 and 403 are both valid depending on which
				// Config snapshot serves the request; anything else
				// is a bug (502, timeout, partial response).
				if code == 200 || code == 403 {
					atomic.AddInt64(&good, 1)
				} else {
					atomic.AddInt64(&bad, 1)
					t.Errorf("unexpected status %d during reload window", code)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}

	for i := 0; i < 5; i++ {
		putGroup(t, a, fmt.Sprintf("g%d", i), map[string]any{
			"name":     fmt.Sprintf("g%d", i),
			"priority": -i,
			"action":   "deny",
			"rules":    []map[string]any{{"name": "any", "match": "false"}},
		})
		time.Sleep(60 * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	if good == 0 {
		t.Fatal("no successful requests; did the server crash?")
	}
	if bad > 0 {
		t.Fatalf("got %d unexpected statuses during reload", bad)
	}
}

// TestE2E_NodeRestartRecoversFromPeer: B is wiped and rebooted; it
// should pick up A's state via anti-entropy push/pull.
func TestE2E_NodeRestartRecoversFromPeer(t *testing.T) {
	yaml := `
defaults: { action: allow }
groups:
  - name: yaml
    rules: [{name: any, match: "true"}]
`
	a := startNode(t, "A", []byte(yaml), nil)
	b1 := startNode(t, "B", []byte(yaml), []string{a.clusterAddr})

	// Seed via A.
	putGroup(t, a, "seeded", map[string]any{
		"name":   "seeded",
		"action": "deny",
		"rules":  []map[string]any{{"name": "any", "match": "false"}},
	})
	eventually(t, 15*time.Second, "B sees seeded", func() bool {
		return hasGroup(t, b1, "seeded")
	})

	// Stop B abruptly and start a brand-new B with empty state.
	b1.stop()
	b2 := startNode(t, "B2", []byte(yaml), []string{a.clusterAddr})

	eventually(t, 20*time.Second, "B2 recovers seeded via anti-entropy", func() bool {
		return hasGroup(t, b2, "seeded")
	})
}
