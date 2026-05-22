// Package e2e contains end-to-end tests that exercise the whole
// request-validator stack in-process: two nodes, each running the CRDT
// store, the cluster gossip layer, the admin API and the ext-authz HTTP
// server, talking to each other over real (loopback) TCP/UDP.
//
// These are NOT unit tests: they spin up listeners, perform real HTTP
// requests, wait for eventual consistency, and assert behaviour at the
// edge a real Envoy / operator would see. Use them to validate that
// the wiring in cmd/main.go is mirrored faithfully here when adding
// new features.
//
// The harness here is in-process (default build). A separate set
// (in this same package, the `binary_test.go` file, behind build
// tag `e2e`) exercises the actual binary via os/exec.

//go:build !e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"request-validator/internal/adminapi"
	"request-validator/internal/cluster"
	"request-validator/internal/crdt"
	"request-validator/internal/httpserver"
	"request-validator/internal/policy"
	"request-validator/internal/quarantine"
)

// node is one full request-validator instance, in-process. It mirrors
// the wiring done by cmd/main.go but exposes the moving parts so tests
// can poke at them directly.
type node struct {
	name string

	store     *crdt.Store
	quar      *quarantine.Buffer
	httpSrv   *httpserver.Server
	adminSrv  *adminapi.Server
	clusterN  *cluster.Node

	extAddr   string // ext-authz HTTP listen addr
	adminAddr string // admin HTTP listen addr
	clusterAddr string // memberlist bind addr

	tokenFile string
	yamlBytes []byte
	yamlMu    sync.RWMutex

	rebuildMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	stopOnce sync.Once
}

const adminToken = "e2e-token"

// startNode brings up a single full-stack request-validator instance.
// `peers` is the list of host:port memberlist seeds to join; pass nil
// for the first node.
func startNode(t *testing.T, name string, yamlBytes []byte, peers []string) *node {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte(adminToken), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := crdt.New(crdt.Options{
		Node:      name,
		StatePath: filepath.Join(dir, "state.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	q := quarantine.New()

	n := &node{
		name:      name,
		store:     store,
		quar:      q,
		tokenFile: tokenPath,
		yamlBytes: yamlBytes,
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())

	// Initial Config.
	cfg, err := policy.MergeFromYAML(yamlBytes, store.Snapshot())
	if err != nil {
		t.Fatalf("initial merge: %v", err)
	}
	if err := cfg.Start(n.ctx); err != nil {
		t.Fatalf("facts start: %v", err)
	}

	// ext-authz server on an ephemeral port.
	n.httpSrv = httpserver.New(cfg)
	extLis := mustListenTCP(t)
	n.extAddr = extLis.Addr().String()
	extLis.Close() // release; the http server will re-bind by addr
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		_ = n.httpSrv.Run(n.extAddr)
	}()

	// Centralised rebuild. Mirrors cmd/main.go::rebuild.
	rebuild := func(source string) error {
		n.rebuildMu.Lock()
		defer n.rebuildMu.Unlock()
		n.yamlMu.RLock()
		yb := n.yamlBytes
		n.yamlMu.RUnlock()

		newCfg, err := policy.MergeFromYAML(yb, store.Snapshot())
		if err != nil {
			return err
		}
		if err := newCfg.Start(n.ctx); err != nil {
			newCfg.Stop()
			return err
		}
		old := n.httpSrv.SetPolicy(newCfg)
		if old != nil {
			old.Stop()
		}
		return nil
	}

	// Admin API on its own ephemeral port.
	adminLis := mustListenTCP(t)
	n.adminAddr = adminLis.Addr().String()
	adminLis.Close()

	applier := &applierFunc{apply: func(_ *policy.Config, source string) error {
		return rebuild(source)
	}}

	// Cluster on its own ephemeral port.
	clusterPort := mustFreeUDPPort(t)
	n.clusterAddr = fmt.Sprintf("127.0.0.1:%d", clusterPort)

	clusterN, err := cluster.New(cluster.Options{
		NodeName:       name,
		BindAddr:       n.clusterAddr,
		Peers:          peers,
		Store:          store,
		OnDeltaApplied: func() { _ = rebuild("gossip") },
		OnApplyError: func(d crdt.Delta, err error) {
			q.Push(d.Section, d.Key, err.Error())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := clusterN.Start(); err != nil {
		t.Fatal(err)
	}
	n.clusterN = clusterN

	adminSrv, err := adminapi.New(adminapi.Options{
		Addr:       n.adminAddr,
		TokenFile:  tokenPath,
		Store:      store,
		Quarantine: q,
		YAMLProvider: func() []byte {
			n.yamlMu.RLock()
			defer n.yamlMu.RUnlock()
			out := make([]byte, len(n.yamlBytes))
			copy(out, n.yamlBytes)
			return out
		},
		Broadcaster: &broadcastAdapter{node: clusterN},
		Applier:     applier,
	})
	if err != nil {
		t.Fatal(err)
	}
	n.adminSrv = adminSrv
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		_ = adminSrv.Run()
	}()

	t.Cleanup(func() { n.stop() })

	waitForHTTP(t, "http://"+n.extAddr+"/healthz", 3*time.Second)
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
		if n.clusterN != nil {
			n.clusterN.Stop()
		}
		if n.store != nil {
			_ = n.store.Close()
		}
		n.cancel()
		n.wg.Wait()
	})
}

// adminURL returns the base URL for the admin API on this node.
func (n *node) adminURL() string { return "http://" + n.adminAddr }

// extURL returns the base URL for the ext-authz endpoint on this node.
func (n *node) extURL() string { return "http://" + n.extAddr }

// --- helpers ---

type applierFunc struct {
	apply func(*policy.Config, string) error
}

func (a *applierFunc) Apply(cfg *policy.Config, src string) error {
	return a.apply(cfg, src)
}

type broadcastAdapter struct {
	node *cluster.Node
}

func (b *broadcastAdapter) BroadcastDelta(d crdt.Delta) {
	b.node.BroadcastDelta(d)
}

func mustListenTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func mustFreeUDPPort(t *testing.T) int {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	return udp.LocalAddr().(*net.UDPAddr).Port
}

type reqOpt func(*http.Request)

func withBearer(tok string) reqOpt {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

func withHeader(k, v string) reqOpt {
	return func(r *http.Request) { r.Header.Set(k, v) }
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
	resp, err := http.DefaultClient.Do(r)
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
			o(r)
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
	t.Fatalf("eventually(%q): never became true within %s", msg, timeout)
}

// getEffectiveGroups returns the names of groups in the effective
// config served by the node's admin API.
func getEffectiveGroups(t *testing.T, n *node) []string {
	t.Helper()
	resp, body := doReq(t, "GET", n.adminURL()+"/api/v1/config", nil, withBearer(adminToken))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/config on %s: %d %s", n.name, resp.StatusCode, body)
	}
	var v struct {
		Groups []struct {
			Name string `json:"name"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(v.Groups))
	for _, g := range v.Groups {
		out = append(out, g.Name)
	}
	return out
}

// hasGroup reports whether `name` is in the effective config of n.
func hasGroup(t *testing.T, n *node, name string) bool {
	for _, g := range getEffectiveGroups(t, n) {
		if g == name {
			return true
		}
	}
	return false
}

// extAuthzCheck does a single ext-authz POST and returns the HTTP
// status the node would have Envoy enforce.
func extAuthzCheck(t *testing.T, n *node, method, host, path, ip string, body []byte) int {
	t.Helper()
	r, _ := http.NewRequest(method, n.extURL()+path, bytes.NewReader(body))
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

// putGroup is a convenience helper for the admin API.
func putGroup(t *testing.T, n *node, name string, payload map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	resp, b := doReq(t, "PUT", n.adminURL()+"/api/v1/groups/"+name, body, withBearer(adminToken))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT group %q on %s: %d %s", name, n.name, resp.StatusCode, b)
	}
}

func deleteGroup(t *testing.T, n *node, name string) {
	t.Helper()
	resp, b := doReq(t, "DELETE", n.adminURL()+"/api/v1/groups/"+name, nil, withBearer(adminToken))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE group %q on %s: %d %s", name, n.name, resp.StatusCode, b)
	}
}

func putFact(t *testing.T, n *node, name string, payload map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	resp, b := doReq(t, "PUT", n.adminURL()+"/api/v1/facts/"+name, body, withBearer(adminToken))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT fact %q on %s: %d %s", name, n.name, resp.StatusCode, b)
	}
}

func putDefaults(t *testing.T, n *node, payload map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	resp, b := doReq(t, "PUT", n.adminURL()+"/api/v1/defaults", body, withBearer(adminToken))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT defaults on %s: %d %s", n.name, resp.StatusCode, b)
	}
}

// quarantineEntries returns the list of quarantined items on a node.
func quarantineEntries(t *testing.T, n *node) []quarantine.Entry {
	t.Helper()
	resp, body := doReq(t, "GET", n.adminURL()+"/api/v1/quarantine", nil, withBearer(adminToken))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET quarantine on %s: %d %s", n.name, resp.StatusCode, body)
	}
	var v struct {
		Items []quarantine.Entry `json:"items"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	return v.Items
}
