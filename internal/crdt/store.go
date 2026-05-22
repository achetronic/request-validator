package crdt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Section names used across the admin API, gossip envelopes and the
// persistence file. Kept as exported constants so other packages don't
// hand-stamp strings.
const (
	SectionGroups   = "groups"
	SectionFacts    = "facts"
	SectionDefaults = "defaults"
	SectionLogging  = "logging"
)

// Store aggregates every CRDT used by the policy engine, together
// with persistence to a local JSON file.
type Store struct {
	node  string
	clock Clock

	Groups *LWWMap // keyed by group name
	Facts  *LWWMap // keyed by fact name

	Defaults *LWWRegister
	Logging  *LWWRegister

	// onChange is invoked (without holding any lock) whenever the
	// in-memory state mutates. Set via SetOnChange.
	onChange atomic.Pointer[func()]

	// persistence
	statePath  string
	saveDelay  time.Duration
	saveTimer  *time.Timer
	saveMu     sync.Mutex
	saveCtx    context.Context
	saveCancel context.CancelFunc
	saveWG     sync.WaitGroup
}

// Options configure a fresh Store.
type Options struct {
	// Node is the stable identifier of this replica; used as the LWW
	// tiebreaker. Must NOT change across restarts.
	Node string

	// Clock supplies timestamps for local writes. Defaults to a
	// monotonic clock if nil.
	Clock Clock

	// StatePath is the file backing the local snapshot. Empty disables
	// persistence (in-memory only, useful for tests).
	StatePath string

	// SaveDelay debounces Save() calls. Defaults to 1 s.
	SaveDelay time.Duration
}

// New returns a Store. If opts.StatePath is non-empty and the file
// exists, the state is restored before returning; missing/corrupt
// files are logged by the caller (Load returns the error).
func New(opts Options) (*Store, error) {
	if opts.Node == "" {
		return nil, errors.New("crdt: Options.Node required")
	}
	if opts.Clock == nil {
		opts.Clock = NewMonotonicClock()
	}
	if opts.SaveDelay <= 0 {
		opts.SaveDelay = 1 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Store{
		node:       opts.Node,
		clock:      opts.Clock,
		Groups:     NewLWWMap(),
		Facts:      NewLWWMap(),
		Defaults:   NewLWWRegister(),
		Logging:    NewLWWRegister(),
		statePath:  opts.StatePath,
		saveDelay:  opts.SaveDelay,
		saveCtx:    ctx,
		saveCancel: cancel,
	}
	if opts.StatePath != "" {
		if err := s.loadFromDisk(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return s, nil
}

// Node returns the node identifier this store stamps writes with.
func (s *Store) Node() string { return s.node }

// Stamp produces a fresh local stamp from the configured clock.
func (s *Store) Stamp() Stamp { return Stamp{TS: s.clock.Now(), Node: s.node} }

// SetOnChange registers a callback invoked after every mutation. The
// callback runs synchronously on the writer's goroutine and must be
// quick; queue work to another goroutine if needed.
func (s *Store) SetOnChange(fn func()) {
	if fn == nil {
		s.onChange.Store(nil)
		return
	}
	cp := fn
	s.onChange.Store(&cp)
}

func (s *Store) notify() {
	if p := s.onChange.Load(); p != nil {
		(*p)()
	}
	s.scheduleSave()
}

// PutGroup upserts a group with a fresh local stamp.
func (s *Store) PutGroup(name string, value any) (Stamp, error) {
	stamp := s.Stamp()
	changed, err := s.Groups.Put(name, value, stamp)
	if err != nil {
		return Stamp{}, err
	}
	if changed {
		s.notify()
	}
	return stamp, nil
}

// DeleteGroup writes a tombstone with a fresh local stamp.
func (s *Store) DeleteGroup(name string) Stamp {
	stamp := s.Stamp()
	if s.Groups.Delete(name, stamp) {
		s.notify()
	}
	return stamp
}

// PutFact upserts a fact with a fresh local stamp.
func (s *Store) PutFact(name string, value any) (Stamp, error) {
	stamp := s.Stamp()
	changed, err := s.Facts.Put(name, value, stamp)
	if err != nil {
		return Stamp{}, err
	}
	if changed {
		s.notify()
	}
	return stamp, nil
}

// DeleteFact tombstones a fact with a fresh local stamp.
func (s *Store) DeleteFact(name string) Stamp {
	stamp := s.Stamp()
	if s.Facts.Delete(name, stamp) {
		s.notify()
	}
	return stamp
}

// SetDefaults writes the defaults register.
func (s *Store) SetDefaults(value any) (Stamp, error) {
	stamp := s.Stamp()
	changed, err := s.Defaults.Set(value, stamp)
	if err != nil {
		return Stamp{}, err
	}
	if changed {
		s.notify()
	}
	return stamp, nil
}

// ClearDefaults clears the defaults register.
func (s *Store) ClearDefaults() Stamp {
	stamp := s.Stamp()
	if s.Defaults.Clear(stamp) {
		s.notify()
	}
	return stamp
}

// SetLogging writes the logging register.
func (s *Store) SetLogging(value any) (Stamp, error) {
	stamp := s.Stamp()
	changed, err := s.Logging.Set(value, stamp)
	if err != nil {
		return Stamp{}, err
	}
	if changed {
		s.notify()
	}
	return stamp, nil
}

// ClearLogging clears the logging register.
func (s *Store) ClearLogging() Stamp {
	stamp := s.Stamp()
	if s.Logging.Clear(stamp) {
		s.notify()
	}
	return stamp
}

// Delta is the payload broadcast over gossip for a single mutation.
// Exactly one of MapEntry / Register is populated; the other is
// distinguished by Section.
type Delta struct {
	Section  string         `json:"section"`
	Key      string         `json:"key,omitempty"`
	Map      *MapEntry      `json:"map,omitempty"`
	Register *RegisterEntry `json:"register,omitempty"`
}

// ApplyDelta folds an incoming gossiped delta into the store. Returns
// true if the local state changed. Unknown sections yield an error.
func (s *Store) ApplyDelta(d Delta) (bool, error) {
	changed := false
	switch d.Section {
	case SectionGroups:
		if d.Map == nil {
			return false, errors.New("crdt: groups delta missing map entry")
		}
		changed = s.Groups.PutRaw(d.Key, *d.Map)
	case SectionFacts:
		if d.Map == nil {
			return false, errors.New("crdt: facts delta missing map entry")
		}
		changed = s.Facts.PutRaw(d.Key, *d.Map)
	case SectionDefaults:
		if d.Register == nil {
			return false, errors.New("crdt: defaults delta missing register entry")
		}
		changed = s.Defaults.SetRaw(*d.Register)
	case SectionLogging:
		if d.Register == nil {
			return false, errors.New("crdt: logging delta missing register entry")
		}
		changed = s.Logging.SetRaw(*d.Register)
	default:
		return false, fmt.Errorf("crdt: unknown section %q", d.Section)
	}
	if changed {
		s.notify()
	}
	return changed, nil
}

// FullState is the wire and on-disk representation of the entire store.
type FullState struct {
	Version  int                      `json:"v"`
	Node     string                   `json:"node"`
	Groups   map[string]MapEntry      `json:"groups,omitempty"`
	Facts    map[string]MapEntry      `json:"facts,omitempty"`
	Defaults *RegisterSnapshot        `json:"defaults,omitempty"`
	Logging  *RegisterSnapshot        `json:"logging,omitempty"`
}

// RegisterSnapshot is FullState's view of an LWWRegister.
type RegisterSnapshot struct {
	Entry RegisterEntry `json:"entry"`
	Set   bool          `json:"set"`
}

// Snapshot returns a FullState that captures every entry, tombstones
// included. Safe for persistence and anti-entropy gossip exchanges.
func (s *Store) Snapshot() FullState {
	defaultsEntry, defaultsSet := s.Defaults.Snapshot()
	loggingEntry, loggingSet := s.Logging.Snapshot()
	full := FullState{
		Version: 1,
		Node:    s.node,
		Groups:  s.Groups.Snapshot(),
		Facts:   s.Facts.Snapshot(),
	}
	if defaultsSet {
		full.Defaults = &RegisterSnapshot{Entry: defaultsEntry, Set: true}
	}
	if loggingSet {
		full.Logging = &RegisterSnapshot{Entry: loggingEntry, Set: true}
	}
	return full
}

// MergeFull folds another FullState into the store (used by gossip
// anti-entropy push/pull). Returns the count of mutated sections.
func (s *Store) MergeFull(other FullState) int {
	changed := 0
	if g := s.Groups.Merge(other.Groups); len(g) > 0 {
		changed++
	}
	if f := s.Facts.Merge(other.Facts); len(f) > 0 {
		changed++
	}
	if other.Defaults != nil {
		if s.Defaults.Merge(other.Defaults.Entry, other.Defaults.Set) {
			changed++
		}
	}
	if other.Logging != nil {
		if s.Logging.Merge(other.Logging.Entry, other.Logging.Set) {
			changed++
		}
	}
	if changed > 0 {
		s.notify()
	}
	return changed
}

// GC drops tombstones older than `keep` ago.
func (s *Store) GC(keep time.Duration) int {
	cutoff := time.Now().Add(-keep).UnixNano()
	n := s.Groups.GCTombstones(cutoff)
	n += s.Facts.GCTombstones(cutoff)
	return n
}

// SaveNow forces an immediate flush to the state file (if configured).
func (s *Store) SaveNow() error {
	if s.statePath == "" {
		return nil
	}
	return s.writeToDisk()
}

// scheduleSave debounces persistence writes by saveDelay.
func (s *Store) scheduleSave() {
	if s.statePath == "" {
		return
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.saveTimer != nil {
		// Cancel the pending timer; if it had not fired yet we must
		// balance the saveWG.Add we registered when we created it.
		if s.saveTimer.Stop() {
			s.saveWG.Done()
		}
	}
	s.saveWG.Add(1)
	s.saveTimer = time.AfterFunc(s.saveDelay, func() {
		defer s.saveWG.Done()
		if err := s.writeToDisk(); err != nil {
			// We intentionally don't import internal/log here to keep
			// the package dependency-free. Callers wiring the store
			// can subscribe to errors via a future error channel; for
			// now the error path is reachable only by tests via
			// SaveNow.
			_ = err
		}
	})
}

// Close flushes any pending debounced save and stops background work.
func (s *Store) Close() error {
	s.saveMu.Lock()
	if s.saveTimer != nil {
		if s.saveTimer.Stop() {
			s.saveWG.Done()
		}
		s.saveTimer = nil
	}
	s.saveMu.Unlock()
	s.saveCancel()
	s.saveWG.Wait()
	return s.SaveNow()
}

func (s *Store) writeToDisk() error {
	full := s.Snapshot()
	buf, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		return fmt.Errorf("crdt: marshal state: %w", err)
	}
	dir := filepath.Dir(s.statePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("crdt: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".state-*.json.tmp")
	if err != nil {
		return fmt.Errorf("crdt: create tmp: %w", err)
	}
	tmpName := tmp.Name()
	cleaned := false
	defer func() {
		if !cleaned {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return fmt.Errorf("crdt: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("crdt: fsync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("crdt: close tmp: %w", err)
	}
	if err := os.Rename(tmpName, s.statePath); err != nil {
		return fmt.Errorf("crdt: rename: %w", err)
	}
	cleaned = true
	// Best-effort directory fsync so the rename is durable across
	// crashes. Errors here are not fatal because the rename itself
	// already happened.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (s *Store) loadFromDisk() error {
	buf, err := os.ReadFile(s.statePath)
	if err != nil {
		return err
	}
	var full FullState
	if err := json.Unmarshal(buf, &full); err != nil {
		return fmt.Errorf("crdt: parse state: %w", err)
	}
	if full.Version != 0 && full.Version != 1 {
		return fmt.Errorf("crdt: unsupported state version %d", full.Version)
	}
	s.Groups.Merge(full.Groups)
	s.Facts.Merge(full.Facts)
	if full.Defaults != nil {
		s.Defaults.Merge(full.Defaults.Entry, full.Defaults.Set)
	}
	if full.Logging != nil {
		s.Logging.Merge(full.Logging.Entry, full.Logging.Set)
	}
	return nil
}
