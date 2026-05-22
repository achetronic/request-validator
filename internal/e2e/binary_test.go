//go:build e2e

// Binary-level end-to-end tests. They build cmd/request-validator
// into a temp dir, launch two real processes on loopback ports, and
// drive them through the same scenarios the in-process suite covers.
// Slower but validate flag wiring, signal handling and filesystem
// behaviour the in-process harness skips.
//
// Run with: go test -tags e2e -timeout 5m ./internal/e2e/...
// Or:        make e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const binToken = "bin-e2e-token"

const binYAML = `
defaults:
  action: allow
  denyStatus: 403
groups:
  - name: yaml-allow
    action: allow
    rules:
      - name: any
        match: "true"
`

// binaryPath is the location of the compiled request-validator,
// set once by TestMain so individual tests reuse the same artefact.
var binaryPath string

func TestMain(m *testing.M) {
	// Compile once. tempdir survives the whole test binary lifetime.
	dir, err := os.MkdirTemp("", "rv-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mktemp:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "request-validator")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", binaryPath, "../../cmd")
	build.Env = os.Environ()
	out, err := build.CombinedOutput()
	if err != nil {
		fmt.Fprintln(os.Stderr, "build failed:", err)
		fmt.Fprintln(os.Stderr, string(out))
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// binNode is a request-validator subprocess plus the ports it listens
// on and the tempdir holding its config + token + state.
type binNode struct {
	name string

	cmd        *exec.Cmd
	dir        string
	extPort    int
	adminPort  int
	gossipPort int

	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

// startBin spawns a request-validator subprocess.
func startBin(t *testing.T, name, yaml string, peers []string) *binNode {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	tokPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokPath, []byte(binToken), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")

	ext := freeTCPPort(t)
	admin := freeTCPPort(t)
	gossip := freeUDPPort(t)

	args := []string{
		"--config", cfgPath,
		"--port", fmt.Sprintf("%d", ext),
		"--admin-port", fmt.Sprintf("%d", admin),
		"--admin-token-file", tokPath,
		"--state-file", statePath,
		"--cluster-bind", fmt.Sprintf("127.0.0.1:%d", gossip),
		"--cluster-advertise", fmt.Sprintf("127.0.0.1:%d", gossip),
		"--log-format", "json",
		"--log-level", "warn",
	}
	if len(peers) > 0 {
		args = append(args, "--cluster-peers", strings.Join(peers, ","))
	}

	cmd := exec.Command(binaryPath, args...)
	cmd.Env = append(os.Environ(), "HOSTNAME="+name)
	// Use a process group so we can clean up children with Kill on the
	// whole group, defending against any rogue goroutine that might
	// have escaped.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}

	n := &binNode{
		name:       name,
		cmd:        cmd,
		dir:        dir,
		extPort:    ext,
		adminPort:  admin,
		gossipPort: gossip,
		stdout:     stdout,
		stderr:     stderr,
	}

	t.Cleanup(func() { n.stop(t) })

	// Wait for readiness via /readyz on the ext-authz port.
	if err := waitReady(fmt.Sprintf("http://127.0.0.1:%d/readyz", ext), 10*time.Second); err != nil {
		t.Logf("stdout: %s", stdout.String())
		t.Logf("stderr: %s", stderr.String())
		t.Fatalf("%s not ready: %v", name, err)
	}
	// And admin API responsive.
	if err := waitAdmin(fmt.Sprintf("http://127.0.0.1:%d/api/v1/config", admin), 5*time.Second); err != nil {
		t.Logf("stdout: %s", stdout.String())
		t.Logf("stderr: %s", stderr.String())
		t.Fatalf("%s admin not ready: %v", name, err)
	}

	return n
}

func (n *binNode) stop(t *testing.T) {
	if n.cmd == nil || n.cmd.Process == nil {
		return
	}
	// Send SIGTERM to the process group.
	_ = syscall.Kill(-n.cmd.Process.Pid, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- n.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-n.cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
}

func (n *binNode) extURL() string   { return fmt.Sprintf("http://127.0.0.1:%d", n.extPort) }
func (n *binNode) adminURL() string { return fmt.Sprintf("http://127.0.0.1:%d", n.adminPort) }
func (n *binNode) clusterAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", n.gossipPort)
}

func waitReady(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("%s never returned 200 within %s", url, timeout)
}

func waitAdmin(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+binToken)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("admin %s never returned 200 within %s", url, timeout)
}

// binPutGroup is the binary-test equivalent of putGroup.
func binPutGroup(t *testing.T, n *binNode, name string, payload map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("PUT", n.adminURL()+"/api/v1/groups/"+name, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+binToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("PUT %s on %s: %d %s", name, n.name, resp.StatusCode, b)
	}
}

func binHasGroup(t *testing.T, n *binNode, name string) bool {
	t.Helper()
	req, _ := http.NewRequest("GET", n.adminURL()+"/api/v1/config", nil)
	req.Header.Set("Authorization", "Bearer "+binToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var v struct {
		Groups []struct {
			Name string `json:"name"`
		} `json:"groups"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&v)
	for _, g := range v.Groups {
		if g.Name == name {
			return true
		}
	}
	return false
}

func binExtCheck(t *testing.T, n *binNode, host, path, ip string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", n.extURL()+path, nil)
	req.Host = host
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func binEventually(t *testing.T, timeout time.Duration, msg string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(80 * time.Millisecond)
	}
	t.Fatalf("eventually(%q): never true within %s", msg, timeout)
}

// --- scenarios ---

func TestBinaryE2E_AdminPutReplicates(t *testing.T) {
	a := startBin(t, "A", binYAML, nil)
	b := startBin(t, "B", binYAML, []string{a.clusterAddr()})

	binPutGroup(t, a, "api-only", map[string]any{
		"name":     "api-only",
		"priority": -10,
		"action":   "deny",
		"rules": []map[string]any{
			{"name": "x", "match": "request.remoteIp == \"203.0.113.5\""},
		},
	})
	binEventually(t, 10*time.Second, "B sees api-only", func() bool {
		return binHasGroup(t, b, "api-only")
	})
}

func TestBinaryE2E_ExtAuthzReflectsCRDTChange(t *testing.T) {
	a := startBin(t, "A", binYAML, nil)
	b := startBin(t, "B", binYAML, []string{a.clusterAddr()})

	if got := binExtCheck(t, b, "host.example", "/", "203.0.113.5"); got != 200 {
		t.Fatalf("baseline 200, got %d", got)
	}

	binPutGroup(t, a, "block", map[string]any{
		"name":     "block",
		"priority": -100,
		"action":   "deny",
		"rules": []map[string]any{
			{"name": "x", "match": "request.remoteIp == \"203.0.113.5\""},
		},
	})

	binEventually(t, 10*time.Second, "B denies via binary", func() bool {
		return binExtCheck(t, b, "host.example", "/", "203.0.113.5") == 403
	})
}

func TestBinaryE2E_TwoNodesStandalone(t *testing.T) {
	// Sanity: each node boots correctly on its own with the full flag
	// set; readiness probe and admin API both come up.
	a := startBin(t, "solo", binYAML, nil)
	if got := binExtCheck(t, a, "h", "/", "1.1.1.1"); got != 200 {
		t.Fatalf("standalone expected 200, got %d", got)
	}
}
