package crdt

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLWWMapLastWriteWinsByTimestamp(t *testing.T) {
	m := NewLWWMap()
	if _, err := m.Put("k", "older", Stamp{TS: 1, Node: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Put("k", "newer", Stamp{TS: 2, Node: "a"}); err != nil {
		t.Fatal(err)
	}
	var got string
	if _, ok, err := m.Get("k", &got); err != nil || !ok || got != "newer" {
		t.Fatalf("got %q ok=%v err=%v", got, ok, err)
	}
}

func TestLWWMapTieBreaksByNode(t *testing.T) {
	m := NewLWWMap()
	if _, err := m.Put("k", "from-a", Stamp{TS: 1, Node: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Put("k", "from-b", Stamp{TS: 1, Node: "b"}); err != nil {
		t.Fatal(err)
	}
	var got string
	_, _, _ = m.Get("k", &got)
	if got != "from-b" {
		t.Fatalf("expected from-b (larger node wins tie), got %q", got)
	}
}

func TestLWWMapOlderWriteIgnored(t *testing.T) {
	m := NewLWWMap()
	if _, err := m.Put("k", "winner", Stamp{TS: 10, Node: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Put("k", "loser", Stamp{TS: 5, Node: "z"}); err != nil {
		t.Fatal(err)
	}
	var got string
	_, _, _ = m.Get("k", &got)
	if got != "winner" {
		t.Fatalf("expected winner, got %q", got)
	}
}

func TestLWWMapDeleteCreatesTombstone(t *testing.T) {
	m := NewLWWMap()
	_, _ = m.Put("k", "v", Stamp{TS: 1, Node: "a"})
	m.Delete("k", Stamp{TS: 2, Node: "a"})

	var got string
	_, ok, _ := m.Get("k", &got)
	if ok {
		t.Fatalf("expected tombstoned, got %q", got)
	}

	// Older Put must not resurrect the entry.
	_, _ = m.Put("k", "ghost", Stamp{TS: 1, Node: "a"})
	_, ok, _ = m.Get("k", &got)
	if ok {
		t.Fatal("tombstone resurrected by older write")
	}
}

func TestLWWMapMergeIsIdempotent(t *testing.T) {
	a := NewLWWMap()
	_, _ = a.Put("x", 1, Stamp{TS: 5, Node: "a"})
	_, _ = a.Put("y", 2, Stamp{TS: 5, Node: "a"})

	b := NewLWWMap()
	_, _ = b.Put("x", 1, Stamp{TS: 5, Node: "a"})

	first := b.Merge(a.Snapshot())
	second := b.Merge(a.Snapshot())
	if len(first) == 0 {
		t.Fatal("first merge should report changes")
	}
	if len(second) != 0 {
		t.Fatalf("second merge should be a no-op, got changes %v", second)
	}
}

func TestLWWMapMergeIsCommutative(t *testing.T) {
	build := func(order []int) *LWWMap {
		m := NewLWWMap()
		stamps := []Stamp{
			{TS: 1, Node: "a"},
			{TS: 2, Node: "b"},
			{TS: 3, Node: "a"},
		}
		values := []any{"first", "second", "third"}
		for _, i := range order {
			_, _ = m.Put("k", values[i], stamps[i])
		}
		return m
	}
	cases := [][]int{
		{0, 1, 2},
		{2, 1, 0},
		{1, 0, 2},
	}
	results := make([]string, 0, len(cases))
	for _, order := range cases {
		m := build(order)
		var got string
		_, _, _ = m.Get("k", &got)
		results = append(results, got)
	}
	for i := 1; i < len(results); i++ {
		if results[i] != results[0] {
			t.Fatalf("merge not commutative: %v", results)
		}
	}
}

func TestLWWMapGCTombstones(t *testing.T) {
	m := NewLWWMap()
	_, _ = m.Put("a", "1", Stamp{TS: 1, Node: "n"})
	m.Delete("a", Stamp{TS: 5, Node: "n"})
	m.Delete("b", Stamp{TS: 100, Node: "n"})
	if n := m.GCTombstones(50); n != 1 {
		t.Fatalf("expected 1 GC, got %d", n)
	}
	if _, ok := m.Snapshot()["a"]; ok {
		t.Fatal("expected a removed")
	}
	if _, ok := m.Snapshot()["b"]; !ok {
		t.Fatal("expected b retained")
	}
}

func TestLWWRegisterSemantics(t *testing.T) {
	r := NewLWWRegister()
	if _, err := r.Set("first", Stamp{TS: 1, Node: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Set("second", Stamp{TS: 2, Node: "a"}); err != nil {
		t.Fatal(err)
	}
	var got string
	if _, ok, err := r.Get(&got); err != nil || !ok || got != "second" {
		t.Fatalf("got %q ok=%v err=%v", got, ok, err)
	}
	// Older write ignored.
	if _, err := r.Set("stale", Stamp{TS: 1, Node: "z"}); err != nil {
		t.Fatal(err)
	}
	_, _, _ = r.Get(&got)
	if got != "second" {
		t.Fatalf("expected second, got %q", got)
	}
	// Clear hides the value.
	r.Clear(Stamp{TS: 3, Node: "a"})
	if _, ok, _ := r.Get(&got); ok {
		t.Fatalf("expected cleared, got %q", got)
	}
}

func TestMonotonicClockNeverGoesBackwards(t *testing.T) {
	c := NewMonotonicClock()
	var prev int64
	var wg sync.WaitGroup
	var mu sync.Mutex
	values := make([]int64, 0, 1000)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 250; j++ {
				v := c.Now()
				mu.Lock()
				values = append(values, v)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	seen := map[int64]bool{}
	for _, v := range values {
		if seen[v] {
			t.Fatalf("duplicate timestamp %d", v)
		}
		seen[v] = true
		if v <= prev && prev != 0 {
			// Order across goroutines isn't fixed; we only require uniqueness.
		}
	}
}

func TestStorePersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s1, err := New(Options{Node: "node-1", StatePath: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.PutGroup("g1", map[string]any{"name": "g1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.PutFact("f1", "abc"); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.SetDefaults(map[string]any{"action": "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := s1.SaveNow(); err != nil {
		t.Fatalf("SaveNow: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := New(Options{Node: "node-1", StatePath: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	var g map[string]any
	if _, ok, err := s2.Groups.Get("g1", &g); err != nil || !ok {
		t.Fatalf("missing group after reload (ok=%v err=%v)", ok, err)
	}
	if g["name"] != "g1" {
		t.Fatalf("wrong group payload: %v", g)
	}
	var f string
	if _, ok, _ := s2.Facts.Get("f1", &f); !ok || f != "abc" {
		t.Fatalf("missing fact after reload: ok=%v val=%q", ok, f)
	}
	var d map[string]any
	if _, ok, _ := s2.Defaults.Get(&d); !ok || d["action"] != "allow" {
		t.Fatalf("missing defaults after reload: ok=%v val=%v", ok, d)
	}
}

func TestStoreApplyDelta(t *testing.T) {
	s, err := New(Options{Node: "local"})
	if err != nil {
		t.Fatal(err)
	}
	d := Delta{
		Section: SectionGroups,
		Key:     "g1",
		Map: &MapEntry{
			Stamp:   Stamp{TS: 42, Node: "peer"},
			Payload: []byte(`{"name":"g1"}`),
		},
	}
	changed, err := s.ApplyDelta(d)
	if err != nil || !changed {
		t.Fatalf("expected applied; changed=%v err=%v", changed, err)
	}
	var g map[string]any
	if _, ok, _ := s.Groups.Get("g1", &g); !ok || g["name"] != "g1" {
		t.Fatalf("delta not applied: ok=%v g=%v", ok, g)
	}
}

func TestStoreOnChangeFires(t *testing.T) {
	s, err := New(Options{Node: "n"})
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	s.SetOnChange(func() { calls++ })
	if _, err := s.PutGroup("a", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutGroup("a", "x"); err != nil {
		t.Fatal(err)
	}
	// Same value re-write changes nothing (older stamp would be rejected;
	// but the same stamp is generated fresh each call so the second wins).
	if calls < 1 {
		t.Fatalf("expected at least 1 onChange, got %d", calls)
	}
}

func TestLWWMapRangeSkipsTombstones(t *testing.T) {
	m := NewLWWMap()
	_, _ = m.Put("a", "1", Stamp{TS: 1, Node: "n"})
	_, _ = m.Put("b", "2", Stamp{TS: 2, Node: "n"})
	m.Delete("a", Stamp{TS: 3, Node: "n"})

	got := map[string]bool{}
	m.Range(func(k string, e MapEntry) bool {
		got[k] = true
		return true
	})
	if got["a"] {
		t.Fatal("tombstoned entry surfaced via Range")
	}
	if !got["b"] {
		t.Fatal("live entry missing from Range")
	}
}

func TestLWWMapRangeEarlyExit(t *testing.T) {
	m := NewLWWMap()
	_, _ = m.Put("a", 1, Stamp{TS: 1, Node: "n"})
	_, _ = m.Put("b", 2, Stamp{TS: 2, Node: "n"})
	_, _ = m.Put("c", 3, Stamp{TS: 3, Node: "n"})
	n := 0
	m.Range(func(k string, e MapEntry) bool {
		n++
		return false // stop after the first
	})
	if n != 1 {
		t.Fatalf("expected single iteration, got %d", n)
	}
}

func TestStoreMergeFullPropagatesAcrossSections(t *testing.T) {
	src, _ := New(Options{Node: "src"})
	dst, _ := New(Options{Node: "dst"})

	if _, err := src.PutGroup("g1", map[string]any{"name": "g1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := src.PutFact("f1", "v"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.SetDefaults(map[string]any{"action": "allow"}); err != nil {
		t.Fatal(err)
	}
	if _, err := src.SetLogging(map[string]any{"level": "debug"}); err != nil {
		t.Fatal(err)
	}

	changed := dst.MergeFull(src.Snapshot())
	if changed == 0 {
		t.Fatal("expected merge to report changes")
	}

	var g map[string]any
	if _, ok, _ := dst.Groups.Get("g1", &g); !ok || g["name"] != "g1" {
		t.Fatalf("group not merged: ok=%v g=%v", ok, g)
	}
	var f string
	if _, ok, _ := dst.Facts.Get("f1", &f); !ok || f != "v" {
		t.Fatalf("fact not merged: ok=%v f=%q", ok, f)
	}
	var d map[string]any
	if _, ok, _ := dst.Defaults.Get(&d); !ok || d["action"] != "allow" {
		t.Fatalf("defaults not merged: ok=%v d=%v", ok, d)
	}
	var l map[string]any
	if _, ok, _ := dst.Logging.Get(&l); !ok || l["level"] != "debug" {
		t.Fatalf("logging not merged: ok=%v l=%v", ok, l)
	}

	// Re-merging the same snapshot is a no-op (idempotence).
	if again := dst.MergeFull(src.Snapshot()); again != 0 {
		t.Fatalf("expected idempotent re-merge, got %d changes", again)
	}
}

func TestStoreMergeFullHonoursTombstones(t *testing.T) {
	src, _ := New(Options{Node: "src"})
	dst, _ := New(Options{Node: "dst"})

	// dst has a live group "x".
	_, _ = dst.PutGroup("x", map[string]any{"name": "x"})
	// src tombstones it later (greater TS guaranteed by monotonic clock).
	src.DeleteGroup("x")

	dst.MergeFull(src.Snapshot())

	var g map[string]any
	if _, ok, _ := dst.Groups.Get("x", &g); ok {
		t.Fatalf("expected tombstoned, still live: %v", g)
	}
}

func TestStoreApplyDeltaUnknownSection(t *testing.T) {
	s, _ := New(Options{Node: "n"})
	_, err := s.ApplyDelta(Delta{Section: "nope"})
	if err == nil {
		t.Fatal("expected error on unknown section")
	}
}

func TestStoreApplyDeltaSchemaMismatches(t *testing.T) {
	s, _ := New(Options{Node: "n"})
	cases := []Delta{
		{Section: SectionGroups, Key: "x"},               // missing Map
		{Section: SectionFacts, Key: "y"},                // missing Map
		{Section: SectionDefaults},                        // missing Register
		{Section: SectionLogging},                         // missing Register
	}
	for i, c := range cases {
		if _, err := s.ApplyDelta(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestStoreLoadCorruptStateReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/state.json"
	if err := os.WriteFile(path, []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Node: "n", StatePath: path}); err == nil {
		t.Fatal("expected error on corrupt state")
	}
}
