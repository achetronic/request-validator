package configwatch

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor polls the counter until it reaches at least `want` or `timeout`
// elapses; returns the observed final value.
func waitFor(c *atomic.Int32, want int32, timeout time.Duration) int32 {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.Load() >= want {
			return c.Load()
		}
		time.Sleep(20 * time.Millisecond)
	}
	return c.Load()
}

func TestInPlaceWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	var n atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, path, 50*time.Millisecond, func() { n.Add(1) }) }()
	time.Sleep(100 * time.Millisecond)

	for i := 0; i < 3; i++ {
		if err := os.WriteFile(path, []byte("v"+string(rune('2'+i))), 0o600); err != nil {
			t.Fatal(err)
		}
		// Sleep longer than the debounce window so each write produces a
		// separate callback.
		time.Sleep(150 * time.Millisecond)
	}

	got := waitFor(&n, 3, 2*time.Second)
	if got < 3 {
		t.Fatalf("expected >=3 reloads, got %d", got)
	}
}

func TestSaveViaRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	var n atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, path, 50*time.Millisecond, func() { n.Add(1) }) }()
	time.Sleep(100 * time.Millisecond)

	// Simulate editor save-via-rename: write to tmp, rename over target.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}

	if got := waitFor(&n, 1, 2*time.Second); got < 1 {
		t.Fatalf("expected at least 1 reload after rename, got %d", got)
	}
}

func TestKubeletConfigMapSwap(t *testing.T) {
	// Reproduce the kubelet projection layout:
	//   <dir>/policy.yaml -> ..data/policy.yaml
	//   <dir>/..data      -> ..2024_01_01_00_00_00.111
	//   <dir>/..2024_01_01_00_00_00.111/policy.yaml
	dir := t.TempDir()

	mkVersion := func(stamp, content string) string {
		vdir := filepath.Join(dir, stamp)
		if err := os.MkdirAll(vdir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(vdir, "policy.yaml"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return vdir
	}

	v1 := mkVersion("..2026_01_01_00_00_00.001", "v1")
	if err := os.Symlink(filepath.Base(v1), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..data/policy.yaml", filepath.Join(dir, "policy.yaml")); err != nil {
		t.Fatal(err)
	}

	var n atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	policy := filepath.Join(dir, "policy.yaml")
	go func() { _ = Run(ctx, policy, 50*time.Millisecond, func() { n.Add(1) }) }()
	time.Sleep(100 * time.Millisecond)

	// Apply a kubelet-style atomic swap: new version dir + atomic rename of ..data.
	v2 := mkVersion("..2026_01_01_00_00_01.002", "v2")
	tmp := filepath.Join(dir, "..data_new")
	if err := os.Symlink(filepath.Base(v2), tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}

	if got := waitFor(&n, 1, 2*time.Second); got < 1 {
		t.Fatalf("expected at least 1 reload after kubelet swap, got %d", got)
	}
}

func TestDebounceCollapsesBurst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	_ = os.WriteFile(path, []byte("v1"), 0o600)

	var n atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, path, 250*time.Millisecond, func() { n.Add(1) }) }()
	time.Sleep(100 * time.Millisecond)

	// Hammer it with 10 writes within a debounce window.
	for i := 0; i < 10; i++ {
		_ = os.WriteFile(path, []byte("v"+string(rune('a'+i))), 0o600)
		time.Sleep(15 * time.Millisecond)
	}
	// Wait past the debounce window plus generous slack.
	time.Sleep(700 * time.Millisecond)

	got := n.Load()
	if got == 0 {
		t.Fatalf("expected at least 1 reload, got %d", got)
	}
	if got > 2 {
		t.Fatalf("debounce should collapse the burst into 1-2 reloads, got %d", got)
	}
}
