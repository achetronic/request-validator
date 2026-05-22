package memory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"request-validator/internal/state"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPutGetRoundTrip(t *testing.T) {
	s := newStore(t)
	defer s.Close()
	ctx := context.Background()
	payload := json.RawMessage(`{"name":"g1","rules":[]}`)
	if _, err := s.Put(ctx, state.SectionGroups, "g1", payload, ""); err != nil {
		t.Fatal(err)
	}
	e, err := s.Get(ctx, state.SectionGroups, "g1")
	if err != nil {
		t.Fatal(err)
	}
	if string(e.Payload) != string(payload) {
		t.Fatalf("payload mismatch: %s", e.Payload)
	}
}

func TestGetNotFound(t *testing.T) {
	s := newStore(t)
	defer s.Close()
	_, err := s.Get(context.Background(), state.SectionGroups, "nope")
	if !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPutIfMatchWildcardOnExistingFails(t *testing.T) {
	s := newStore(t)
	defer s.Close()
	ctx := context.Background()
	if _, err := s.Put(ctx, state.SectionGroups, "g", json.RawMessage(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, state.SectionGroups, "g", json.RawMessage(`{}`), "*"); !errors.Is(err, state.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestPutIfMatchWildcardOnNewSucceeds(t *testing.T) {
	s := newStore(t)
	defer s.Close()
	if _, err := s.Put(context.Background(), state.SectionGroups, "g", json.RawMessage(`{}`), "*"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestPutIfMatchExactRevision(t *testing.T) {
	s := newStore(t)
	defer s.Close()
	ctx := context.Background()
	rev1, _ := s.Put(ctx, state.SectionGroups, "g", json.RawMessage(`{}`), "")
	// Conflict with wrong revision.
	if _, err := s.Put(ctx, state.SectionGroups, "g", json.RawMessage(`{}`), "999"); !errors.Is(err, state.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	// OK with correct revision.
	if _, err := s.Put(ctx, state.SectionGroups, "g", json.RawMessage(`{}`), rev1); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	s := newStore(t)
	defer s.Close()
	ctx := context.Background()
	_, _ = s.Put(ctx, state.SectionGroups, "g", json.RawMessage(`{}`), "")
	if err := s.Delete(ctx, state.SectionGroups, "g", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, state.SectionGroups, "g"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	// Re-delete: not found.
	if err := s.Delete(ctx, state.SectionGroups, "g", ""); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSingletonsDefaultsAndLogging(t *testing.T) {
	s := newStore(t)
	defer s.Close()
	ctx := context.Background()
	if _, err := s.Put(ctx, state.SectionDefaults, "", json.RawMessage(`{"action":"deny"}`), ""); err != nil {
		t.Fatal(err)
	}
	e, err := s.Get(ctx, state.SectionDefaults, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(e.Payload) != `{"action":"deny"}` {
		t.Fatalf("unexpected: %s", e.Payload)
	}
	if err := s.Delete(ctx, state.SectionDefaults, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, state.SectionDefaults, ""); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSnapshotIsConsistent(t *testing.T) {
	s := newStore(t)
	defer s.Close()
	ctx := context.Background()
	_, _ = s.Put(ctx, state.SectionGroups, "a", json.RawMessage(`{"name":"a"}`), "")
	_, _ = s.Put(ctx, state.SectionFacts, "f", json.RawMessage(`{"name":"f"}`), "")
	_, _ = s.Put(ctx, state.SectionDefaults, "", json.RawMessage(`{}`), "")
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap.Groups["a"]; !ok {
		t.Fatal("missing groups.a")
	}
	if _, ok := snap.Facts["f"]; !ok {
		t.Fatal("missing facts.f")
	}
	if snap.Defaults == nil {
		t.Fatal("missing defaults")
	}
}

func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s1, err := New(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, _ = s1.Put(ctx, state.SectionGroups, "g1", json.RawMessage(`{"name":"g1"}`), "")
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := New(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	e, err := s2.Get(ctx, state.SectionGroups, "g1")
	if err != nil {
		t.Fatalf("expected to find g1: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(e.Payload, &got); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if got["name"] != "g1" {
		t.Fatalf("expected name=g1, got %v", got)
	}
}

func TestWatchReceivesEvent(t *testing.T) {
	s := newStore(t)
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := s.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = s.Put(ctx, state.SectionGroups, "x", json.RawMessage(`{}`), "")
	}()
	select {
	case ev := <-ch:
		if ev.Revision == "" {
			t.Fatal("expected non-empty revision")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not deliver")
	}
}

func TestLoadCorruptStateReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Path: path}); err == nil {
		t.Fatal("expected error on corrupt state")
	}
}
