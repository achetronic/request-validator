//go:build !e2ekind

// Package e2e contains end-to-end tests that exercise the whole
// request-validator stack in-process: two nodes sharing the same
// fake Kubernetes API, each running its own ConfigMap-backed state
// store, leader election lease, admin API and ext-authz HTTP server.
//
// The fake client is the only realistic shortcut: it simulates the
// API server's CRUD semantics (including resourceVersion-based
// optimistic concurrency) without needing Kind. For a full
// real-cluster check use the //go:build e2ekind suite which boots
// an actual Kind cluster.

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"request-validator/internal/adminapi"
	"request-validator/internal/cluster"
	"request-validator/internal/httpserver"
	"request-validator/internal/policy"
	"request-validator/internal/state"
	"request-validator/internal/state/configmap"
)

const (
	adminToken = "e2e-token"
	testNS     = "rv-e2e"
	cmName     = "rv-state"
	leaseName  = "rv-leader"
)

// node is one full request-validator instance, in-process. It mirrors
// the wiring done by cmd/main.go on a smaller surface.
type node struct {
	name     string
	store    state.Store
	cluster  *cluster.Cluster
	httpSrv  *httpserver.Server
	adminSrv *adminapi.Server

	extAddr   string
	adminAddr string

	tokenFile string
	yamlMu    sync.RWMutex
	yamlBytes []byte
	rebuildMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	stopOnce sync.Once
}

// startNode brings up a single full-stack instance against the shared
// fake clientset.
func startNode(t *testing.T, name string, kc kubernetes.Interface, yamlBytes []byte) *node {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte(adminToken), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// In the in-process E2E we share a fake clientset between two
	// nodes. fake's watch propagation between informers backed by
	// the same client is unreliable across goroutines; a short
	// ResyncPeriod sidesteps it by polling the cached object. Real
	// Kubernetes is fine without this; the Kind-based E2E uses
	// the default.
	cmStore, err := configmap.New(ctx, configmap.Options{
		Client: kc, Namespace: testNS, Name: cmName,
		ResyncPeriod: 200 * time.Millisecond,
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}

	n := &node{
		name:      name,
		store:     cmStore,
		tokenFile: tokenPath,
		yamlBytes: yamlBytes,
		ctx:       ctx,
		cancel:    cancel,
	}

	// Compute the addresses up front; we pre-bind to grab a free
	// port, close immediately, then let the actual server re-bind by
	// addr. Tiny race window in tests, acceptable.
	n.extAddr = mustFreeTCP(t)
	n.adminAddr = mustFreeTCP(t)

	snap, _ := cmStore.Snapshot(ctx)
	cfg, err := policy.MergeFromYAML(yamlBytes, snap)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cfg.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	n.httpSrv = httpserver.New(cfg)

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		_ = n.httpSrv.Run(n.extAddr)
	}()

	rebuild := func(source string) error {
		n.rebuildMu.Lock()
		defer n.rebuildMu.Unlock()
		n.yamlMu.RLock()
		yb := n.yamlBytes
		n.yamlMu.RUnlock()
		snap, err := cmStore.Snapshot(ctx)
		if err != nil {
			return err
		}
		newCfg, err := policy.MergeFromYAML(yb, snap)
		if err != nil {
			return err
		}
		if err := newCfg.Start(ctx); err != nil {
			newCfg.Stop()
			return err
		}
		old := n.httpSrv.SetPolicy(newCfg)
		if old != nil {
			old.Stop()
		}
		return nil
	}

	// Cluster (leader election against the shared fake client).
	cl, err := cluster.Bootstrap(ctx, cluster.Options{
		Client:        kc,
		Namespace:     testNS,
		LeaseName:     leaseName,
		PodName:       name,
		AdminURL:      "http://" + n.adminAddr,
		LeaseDuration: 2 * time.Second,
		RenewDeadline: time.Second,
		RetryPeriod:   200 * time.Millisecond,
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	n.cluster = cl

	// Store watcher triggers a rebuild on every replica.
	go func() {
		ch, err := cmStore.Watch(ctx)
		if err != nil {
			return
		}
		for range ch {
			_ = rebuild("store")
		}
	}()

	applier := &applierFunc{apply: func(_ *policy.Config, src string) error { return rebuild(src) }}
	adminSrv, err := adminapi.New(adminapi.Options{
		Addr:      n.adminAddr,
		TokenFile: tokenPath,
		Store:     cmStore,
		Cluster:   cl,
		YAMLProvider: func() []byte {
			n.yamlMu.RLock()
			defer n.yamlMu.RUnlock()
			out := make([]byte, len(n.yamlBytes))
			copy(out, n.yamlBytes)
			return out
		},
		Applier: applier,
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	n.adminSrv = adminSrv

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		_ = adminSrv.Run()
	}()

	t.Cleanup(n.stop)

	waitForHTTP(t, "http://"+n.extAddr+"/healthz", 3*time.Second, nil)
	waitForHTTP(t, "http://"+n.adminAddr+"/api/v1/config", 3*time.Second, withBearer(adminToken))
	return n
}

func (n *node) stop() {
	n.stopOnce.Do(func() {
		if n.adminSrv != nil {
			n.adminSrv.Stop()
		}
		if n.httpSrv != nil {
			n.httpSrv.Stop()
			if p := n.httpSrv.Policy(); p != nil {
				p.Stop()
			}
		}
		if n.cluster != nil {
			n.cluster.Stop()
		}
		if n.store != nil {
			_ = n.store.Close()
		}
		n.cancel()
		n.wg.Wait()
	})
}

// --- helpers ---

type applierFunc struct {
	apply func(*policy.Config, string) error
}

func (a *applierFunc) Apply(c *policy.Config, s string) error { return a.apply(c, s) }

func mustFreeTCP(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

type reqOpt func(*http.Request)

func withBearer(tok string) reqOpt {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

func doReq(t *testing.T, method, url string, body []byte, opts ...reqOpt) (*http.Response, []byte) {
	t.Helper()
	var rb io.Reader
	if body != nil {
		rb = bytes.NewReader(body)
	}
	r, err := http.NewRequest(method, url, rb)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(r)
	}
	// Disable redirect-following so tests can observe 307s when they
	// want; per-test helpers can use a different client if they
	// prefer to follow.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func waitForHTTP(t *testing.T, url string, timeout time.Duration, opts ...reqOpt) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range opts {
			if o != nil {
				o(r)
			}
		}
		resp, err := http.DefaultClient.Do(r)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("waitForHTTP: %s never became 200 within %s", url, timeout)
}

func eventually(t *testing.T, timeout time.Duration, msg string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("eventually(%q): never true within %s", msg, timeout)
}

func adminURL(n *node) string { return "http://" + n.adminAddr }
func extURL(n *node) string   { return "http://" + n.extAddr }

func getEffectiveGroups(t *testing.T, n *node) []string {
	t.Helper()
	resp, body := doReq(t, "GET", adminURL(n)+"/api/v1/config", nil, withBearer(adminToken))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/config on %s: %d %s", n.name, resp.StatusCode, body)
	}
	var v struct {
		Groups []struct {
			Name string `json:"name"`
		} `json:"groups"`
	}
	_ = json.Unmarshal(body, &v)
	out := make([]string, 0, len(v.Groups))
	for _, g := range v.Groups {
		out = append(out, g.Name)
	}
	return out
}

func hasGroup(t *testing.T, n *node, name string) bool {
	for _, g := range getEffectiveGroups(t, n) {
		if g == name {
			return true
		}
	}
	return false
}

func extAuthzCheck(t *testing.T, n *node, method, host, path, ip string, body []byte) int {
	t.Helper()
	r, _ := http.NewRequest(method, extURL(n)+path, bytes.NewReader(body))
	r.Host = host
	if ip != "" {
		r.Header.Set("X-Forwarded-For", ip)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// putGroup sends a PUT and follows a single 307 redirect so the test
// can target any node and still hit the leader.
func putGroup(t *testing.T, n *node, name string, payload map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	url := adminURL(n) + "/api/v1/groups/" + name
	for attempt := 0; attempt < 2; attempt++ {
		resp, b := doReq(t, "PUT", url, body, withBearer(adminToken))
		if resp.StatusCode == http.StatusTemporaryRedirect {
			url = resp.Header.Get("Location")
			if url == "" {
				t.Fatalf("307 without Location header")
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT group %q on %s: %d %s", name, n.name, resp.StatusCode, b)
		}
		return
	}
	t.Fatalf("PUT %s: too many redirects", name)
}

func deleteGroup(t *testing.T, n *node, name string) {
	t.Helper()
	url := adminURL(n) + "/api/v1/groups/" + name
	for attempt := 0; attempt < 2; attempt++ {
		resp, b := doReq(t, "DELETE", url, nil, withBearer(adminToken))
		if resp.StatusCode == http.StatusTemporaryRedirect {
			url = resp.Header.Get("Location")
			continue
		}
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE group %q on %s: %d %s", name, n.name, resp.StatusCode, b)
		}
		return
	}
	t.Fatalf("DELETE %s: too many redirects", name)
}

func putDefaults(t *testing.T, n *node, payload map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	url := adminURL(n) + "/api/v1/defaults"
	for attempt := 0; attempt < 2; attempt++ {
		resp, b := doReq(t, "PUT", url, body, withBearer(adminToken))
		if resp.StatusCode == http.StatusTemporaryRedirect {
			url = resp.Header.Get("Location")
			continue
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT defaults: %d %s", resp.StatusCode, b)
		}
		return
	}
	t.Fatalf("PUT defaults: too many redirects")
}

// newSharedClient returns a fake clientset that both nodes share so
// they really do see each other through the API.
func newSharedClient() kubernetes.Interface {
	return fake.NewClientset()
}

func ensureLeader(t *testing.T, nodes ...*node) {
	t.Helper()
	eventually(t, 5*time.Second, "some node holds the lease", func() bool {
		for _, n := range nodes {
			if n.cluster.IsLeader() {
				return true
			}
		}
		return false
	})
}

func leaderOf(nodes ...*node) *node {
	for _, n := range nodes {
		if n.cluster.IsLeader() {
			return n
		}
	}
	return nil
}

// unused-helper guard so changes to imports don't silently break.
