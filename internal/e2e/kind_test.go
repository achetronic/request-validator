//go:build e2ekind

// Binary-level end-to-end tests against a real Kind cluster.
//
// They:
//
//   1. Build cmd/request-validator into a temp dir (inside TestMain).
//   2. Build a small container image from that binary.
//   3. Boot a Kind cluster (or reuse one if KIND_CLUSTER is set).
//   4. Load the image, apply the manifests, expose admin via port-forward.
//   5. Run scenarios against the real API surface.
//
// Slow (~30-60 s of setup) and require `kind`, `docker`, `kubectl` in
// PATH. Hence opt-in via:
//
//   go test -tags e2ekind ./internal/e2e/...
//
// Or use `make e2e-kind`.

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	kindClusterName  = "rv-e2e-kind"
	kindImageName    = "rv-e2e:latest"
	kindManifestsDir = "testdata/kind"
	kindAdminToken   = "kind-e2e-token"
	kindNamespace    = "default"
)

var (
	binaryPath  string
	portForward *exec.Cmd
	adminPort   = 18081
	extPort     = 18080
)

func TestMain(m *testing.M) {
	if err := checkKindPrereqs(); err != nil {
		// Local runs (developer laptop, no Kind installed): just
		// skip the whole suite quietly. CI sets RV_KIND_REQUIRE_PREREQS
		// to force a hard failure so we never silently pass when
		// the environment is broken.
		if os.Getenv("RV_KIND_REQUIRE_PREREQS") != "" {
			fmt.Fprintln(os.Stderr, "Kind E2E prereqs missing in a CI-required environment:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "skipping Kind E2E:", err)
		os.Exit(0)
	}
	if err := setupKind(); err != nil {
		fmt.Fprintln(os.Stderr, "kind setup failed:", err)
		teardownKind()
		os.Exit(1)
	}
	code := m.Run()
	teardownKind()
	os.Exit(code)
}

func checkKindPrereqs() error {
	for _, bin := range []string{"kind", "docker", "kubectl"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("%s not found in PATH", bin)
		}
	}
	return nil
}

func setupKind() error {
	dir, err := os.MkdirTemp("", "rv-kind-")
	if err != nil {
		return err
	}
	binaryPath = filepath.Join(dir, "request-validator")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", binaryPath, "../../cmd")
	build.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH=amd64",
	)
	out, err := build.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build: %v\n%s", err, out)
	}

	// Build the image using a tiny inline Dockerfile so we don't
	// depend on the repo's prod Dockerfile.
	dockerfile := `FROM gcr.io/distroless/static:nonroot
COPY request-validator /request-validator
USER 65532:65532
ENTRYPOINT ["/request-validator"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		return err
	}
	if out, err := run("docker", "build", "-t", kindImageName, dir); err != nil {
		return fmt.Errorf("docker build: %v\n%s", err, out)
	}

	if out, err := run("kind", "create", "cluster", "--name", kindClusterName, "--wait", "60s"); err != nil {
		return fmt.Errorf("kind create: %v\n%s", err, out)
	}
	if out, err := run("kind", "load", "docker-image", kindImageName, "--name", kindClusterName); err != nil {
		return fmt.Errorf("kind load: %v\n%s", err, out)
	}

	// Apply the manifests.
	if out, err := run("kubectl", "apply", "-f", kindManifestsDir); err != nil {
		return fmt.Errorf("kubectl apply: %v\n%s", err, out)
	}

	// Wait for deployment to be ready.
	if out, err := run("kubectl", "rollout", "status", "deploy/request-validator", "--timeout=120s"); err != nil {
		return fmt.Errorf("rollout: %v\n%s", err, out)
	}

	// Start port-forward to one of the pods for admin and ext-authz.
	portForward = exec.Command("kubectl", "port-forward",
		"svc/request-validator", fmt.Sprintf("%d:8080", extPort), fmt.Sprintf("%d:8081", adminPort))
	if err := portForward.Start(); err != nil {
		return fmt.Errorf("port-forward start: %v", err)
	}

	// Wait for the port-forward to be usable.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", extPort)); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("port-forward never became ready")
}

func teardownKind() {
	if portForward != nil && portForward.Process != nil {
		_ = portForward.Process.Kill()
		_ = portForward.Wait()
	}
	_, _ = run("kind", "delete", "cluster", "--name", kindClusterName)
}

func run(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func TestKindE2E_HealthOK(t *testing.T) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", extPort))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestKindE2E_PutAndExtAuthz(t *testing.T) {
	// PUT a deny rule via admin API; assert ext-authz reflects it.
	body := map[string]any{
		"name":     "kind-block",
		"priority": -100,
		"action":   "deny",
		"rules":    []map[string]any{{"name": "x", "match": "request.remoteIp == \"9.9.9.9\""}},
	}
	b, _ := json.Marshal(body)
	url := fmt.Sprintf("http://127.0.0.1:%d/api/v1/groups/kind-block", adminPort)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+kindAdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT got %d: %s", resp.StatusCode, out)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", extPort), nil)
		r.Header.Set("X-Forwarded-For", "9.9.9.9")
		resp, err := http.DefaultClient.Do(r)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusForbidden {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("ext-authz never started denying 9.9.9.9")
}

// silence unused-import linter when this file is the only one in the
// build with `e2ekind`.
var _ = context.Background
var _ = strings.HasPrefix
