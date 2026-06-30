// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package facts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInlineValue(t *testing.T) {
	r, err := New([]Spec{
		{Name: "x", Method: "value", Value: []any{"10.0.0.0/8"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	snap := r.Snapshot()
	if got := snap["x"]; got == nil {
		t.Fatalf("snapshot missing x: %#v", snap)
	}
	r.Stop()
}

func TestFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.yaml")
	if err := os.WriteFile(path, []byte("- 10.0.0.0/8\n- 192.168.0.0/16\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := New([]Spec{{Name: "f", Method: "file", File: &File{Path: path}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	v := r.Snapshot()["f"]
	s, ok := v.(string)
	if !ok {
		t.Fatalf("want string, got %T", v)
	}
	if !strings.Contains(s, "10.0.0.0/8") {
		t.Fatalf("body missing CIDR: %q", s)
	}
	r.Stop()
}

func TestURLFetchAndRefresh(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"version":` + itoa(int(n)) + `,"cidrs":["10.0.0.0/8"]}`))
	}))
	defer srv.Close()

	r, err := New([]Spec{{
		Name:   "u",
		Method: "url",
		URL:    &URL{Address: srv.URL, Interval: 80 * time.Millisecond, Timeout: 2 * time.Second},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first, _ := r.Snapshot()["u"].(string)
	if first == "" {
		t.Fatalf("initial fetch should populate value")
	}
	if !strings.Contains(first, "\"version\":1") {
		t.Fatalf("initial body: %q", first)
	}
	// Wait long enough to see at least one refresh tick.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s, _ := r.Snapshot()["u"].(string)
		if strings.Contains(s, "\"version\":2") {
			r.Stop()
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	r.Stop()
	t.Fatalf("expected refresh to update the value, got hits=%d", hits.Load())
}

func TestURLFailureKeepsPrevious(t *testing.T) {
	// First call returns OK; subsequent calls fail. The registry should keep
	// serving the previous good body.
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`OK`))
	}))
	defer srv.Close()

	r, err := New([]Spec{{
		Name:   "u",
		Method: "url",
		URL:    &URL{Address: srv.URL, Interval: 50 * time.Millisecond, Timeout: 2 * time.Second},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // let failed refreshes happen
	v, _ := r.Snapshot()["u"].(string)
	if v != "OK" {
		t.Fatalf("expected previous value kept, got %q", v)
	}
	r.Stop()
}

func TestValidationDuplicates(t *testing.T) {
	if _, err := New([]Spec{
		{Name: "a", Method: "value", Value: 1},
		{Name: "a", Method: "value", Value: 2},
	}); err == nil {
		t.Fatal("expected duplicate-name error")
	}
}

func TestValidationMissingFields(t *testing.T) {
	if _, err := New([]Spec{{Name: "x", Method: "file"}}); err == nil {
		t.Fatal("file without path should fail")
	}
	if _, err := New([]Spec{{Name: "x", Method: "url"}}); err == nil {
		t.Fatal("url without address should fail")
	}
	if _, err := New([]Spec{{Name: "x", Method: "wat"}}); err == nil {
		t.Fatal("unknown method should fail")
	}
}

// itoa avoids dragging strconv into a one-place spot.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	out := ""
	for n > 0 {
		out = string(rune('0'+n%10)) + out
		n /= 10
	}
	return out
}
