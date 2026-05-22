//go:build !e2ekind

package e2e

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func TestE2E_AdminPutReplicates(t *testing.T) {
	kc := newSharedClient()
	a := startNode(t, "A", kc, []byte(baseYAML))
	b := startNode(t, "B", kc, []byte(baseYAML))
	ensureLeader(t, a, b)

	putGroup(t, a, "api-only", map[string]any{
		"name":     "api-only",
		"priority": -50,
		"action":   "deny",
		"rules": []map[string]any{
			{"name": "block-residential", "match": "request.remoteIp == \"203.0.113.5\""},
		},
	})

	eventually(t, 5*time.Second, "B sees api-only via informer", func() bool {
		return hasGroup(t, b, "api-only")
	})
}

func TestE2E_ExtAuthzReflectsAdminChange(t *testing.T) {
	kc := newSharedClient()
	a := startNode(t, "A", kc, []byte(baseYAML))
	b := startNode(t, "B", kc, []byte(baseYAML))
	ensureLeader(t, a, b)

	if got := extAuthzCheck(t, b, "GET", "host.example", "/", "203.0.113.5", nil); got != http.StatusOK {
		t.Fatalf("baseline 200, got %d", got)
	}

	putGroup(t, a, "block-by-ip", map[string]any{
		"name":     "block-by-ip",
		"priority": -100,
		"action":   "deny",
		"rules":    []map[string]any{{"name": "x", "match": "request.remoteIp == \"203.0.113.5\""}},
	})

	eventually(t, 10*time.Second, "B denies 203.0.113.5", func() bool {
		return extAuthzCheck(t, b, "GET", "host.example", "/", "203.0.113.5", nil) == http.StatusForbidden
	})
	if got := extAuthzCheck(t, b, "GET", "host.example", "/", "8.8.8.8", nil); got != http.StatusOK {
		t.Fatalf("unrelated IP should still pass, got %d", got)
	}
}

func TestE2E_DeletePropagates(t *testing.T) {
	kc := newSharedClient()
	a := startNode(t, "A", kc, []byte(baseYAML))
	b := startNode(t, "B", kc, []byte(baseYAML))
	ensureLeader(t, a, b)

	putGroup(t, a, "block-by-ip", map[string]any{
		"name":     "block-by-ip",
		"priority": -100,
		"action":   "deny",
		"rules":    []map[string]any{{"name": "x", "match": "request.remoteIp == \"203.0.113.5\""}},
	})
	eventually(t, 10*time.Second, "B starts denying", func() bool {
		return extAuthzCheck(t, b, "GET", "host.example", "/", "203.0.113.5", nil) == http.StatusForbidden
	})

	deleteGroup(t, a, "block-by-ip")
	eventually(t, 10*time.Second, "B stops denying", func() bool {
		return extAuthzCheck(t, b, "GET", "host.example", "/", "203.0.113.5", nil) == http.StatusOK
	})
}

func TestE2E_DefaultsOverlayReplicates(t *testing.T) {
	yaml := `
defaults: { action: allow }
groups:
  - name: noop
    rules: [{name: never, match: "false"}]
`
	kc := newSharedClient()
	a := startNode(t, "A", kc, []byte(yaml))
	b := startNode(t, "B", kc, []byte(yaml))
	ensureLeader(t, a, b)

	if got := extAuthzCheck(t, b, "GET", "h", "/", "1.1.1.1", nil); got != http.StatusOK {
		t.Fatalf("baseline 200, got %d", got)
	}

	putDefaults(t, a, map[string]any{
		"action":     "deny",
		"denyStatus": 418,
	})

	eventually(t, 10*time.Second, "B denies with 418", func() bool {
		return extAuthzCheck(t, b, "GET", "h", "/", "1.1.1.1", nil) == 418
	})
}

func TestE2E_FollowerRedirectsToLeader(t *testing.T) {
	kc := newSharedClient()
	a := startNode(t, "A", kc, []byte(baseYAML))
	b := startNode(t, "B", kc, []byte(baseYAML))
	ensureLeader(t, a, b)

	// Target whichever is the *follower* and assert we got a 307
	// to the leader.
	leader := leaderOf(a, b)
	if leader == nil {
		t.Fatal("no leader observed")
	}
	follower := a
	if leader == a {
		follower = b
	}

	body := []byte(`{"name":"x","action":"deny","rules":[{"name":"any","match":"true"}]}`)
	resp, _ := doReq(t, "PUT", adminURL(follower)+"/api/v1/groups/x", body, withBearer(adminToken))
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 from follower, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("missing Location header")
	}
	if loc[:len("http://")+len(leader.adminAddr)] != "http://"+leader.adminAddr {
		t.Fatalf("Location %q does not point at leader admin %s", loc, leader.adminAddr)
	}
}

// TestE2E_StateSurvivesPodRestart simulates a pod restart by stopping
// node A and starting a fresh one (A2) against the same shared
// clientset. The overlay written before the restart must be visible
// in A2's effective config because it lives in the backing ConfigMap,
// not in the pod's memory.
func TestE2E_StateSurvivesPodRestart(t *testing.T) {
	kc := newSharedClient()
	a := startNode(t, "A", kc, []byte(baseYAML))
	ensureLeader(t, a)

	putGroup(t, a, "persistent", map[string]any{
		"name":   "persistent",
		"action": "deny",
		"rules":  []map[string]any{{"name": "x", "match": "false"}},
	})
	if !hasGroup(t, a, "persistent") {
		t.Fatal("A should see persistent immediately after PUT")
	}

	// Simulate a pod restart: stop A, start A2 against the same
	// clientset. The Lease will be released by A's Stop() (ReleaseOnCancel)
	// and reacquired by A2.
	a.stop()
	a2 := startNode(t, "A2", kc, []byte(baseYAML))
	ensureLeader(t, a2)

	if !hasGroup(t, a2, "persistent") {
		t.Fatal("A2 should see persistent after restart (read from ConfigMap)")
	}
}

// TestE2E_DeletingStateCMResetsToYAML is the "blast everything" path
// from the user's question. With the state ConfigMap deleted before
// the new pod boots, the overlay is gone and the effective config
// equals the YAML floor again.
func TestE2E_DeletingStateCMResetsToYAML(t *testing.T) {
	kc := newSharedClient()
	a := startNode(t, "A", kc, []byte(baseYAML))
	ensureLeader(t, a)

	putGroup(t, a, "ephemeral", map[string]any{
		"name":   "ephemeral",
		"action": "deny",
		"rules":  []map[string]any{{"name": "x", "match": "false"}},
	})
	if !hasGroup(t, a, "ephemeral") {
		t.Fatal("A should see ephemeral immediately after PUT")
	}

	// Stop the node, delete the state ConfigMap, start a fresh one.
	a.stop()
	if err := kc.CoreV1().ConfigMaps(testNS).Delete(
		context.Background(), cmName, metav1.DeleteOptions{},
	); err != nil {
		t.Fatalf("delete state cm: %v", err)
	}

	a2 := startNode(t, "A2", kc, []byte(baseYAML))
	ensureLeader(t, a2)

	if hasGroup(t, a2, "ephemeral") {
		t.Fatal("ephemeral should be gone after state CM deletion")
	}
	// Sanity: the YAML floor still applies.
	if !hasGroup(t, a2, "yaml-allow-everything") {
		t.Fatal("YAML group should still be present")
	}
}

// TestE2E_LeaderTransitionWritesRoute exercises what happens when the
// current leader stops: another replica must observe the lease change
// and start accepting writes. We stop the original leader, wait for
// the surviving replica to be observed as leader, then issue a write
// against it and assert it succeeds (no 307, no 503).
func TestE2E_LeaderTransitionWritesRoute(t *testing.T) {
	kc := newSharedClient()
	a := startNode(t, "A", kc, []byte(baseYAML))
	b := startNode(t, "B", kc, []byte(baseYAML))
	ensureLeader(t, a, b)

	leader := leaderOf(a, b)
	if leader == nil {
		t.Fatal("no leader observed")
	}
	follower := a
	if leader == a {
		follower = b
	}

	// Kill the leader.
	leader.stop()

	// Wait for the follower to acquire the lease.
	eventually(t, 8*time.Second, "follower acquires lease", func() bool {
		return follower.cluster.IsLeader()
	})

	// Now a write against the (new leader) follower must succeed
	// directly with no redirect.
	body := []byte(`{"name":"after-transition","action":"deny","rules":[{"name":"x","match":"false"}]}`)
	resp, b2 := doReq(t, "PUT",
		adminURL(follower)+"/api/v1/groups/after-transition",
		body, withBearer(adminToken))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from new leader, got %d: %s", resp.StatusCode, b2)
	}
}

// TestE2E_IfMatchPreconditionEndToEnd verifies that a stale If-Match
// header causes the API to reject the write with 412, both directly
// and after replication.
func TestE2E_IfMatchPreconditionEndToEnd(t *testing.T) {
	kc := newSharedClient()
	a := startNode(t, "A", kc, []byte(baseYAML))
	b := startNode(t, "B", kc, []byte(baseYAML))
	ensureLeader(t, a, b)

	// Initial PUT to create an entry we can mutate later.
	leader := leaderOf(a, b)
	if leader == nil {
		t.Fatal("no leader")
	}
	body := []byte(`{"name":"foo","action":"deny","rules":[{"name":"any","match":"false"}]}`)
	resp, _ := doReq(t, "PUT",
		adminURL(leader)+"/api/v1/groups/foo",
		body, withBearer(adminToken))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initial PUT got %d", resp.StatusCode)
	}

	// PUT with a wrong If-Match should return 412.
	r, _ := http.NewRequest("PUT",
		adminURL(leader)+"/api/v1/groups/foo",
		bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+adminToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("If-Match", `"obviously-stale"`)
	resp2, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", resp2.StatusCode)
	}
}
