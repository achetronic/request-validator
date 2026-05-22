// Package crdt implements the conflict-free replicated data types used by
// the admin API and the gossip layer.
//
// Two flavours are provided:
//
//   - LWWMap[V] (Last-Write-Wins keyed map): a string-keyed map where
//     each entry carries a hybrid timestamp + node ID stamp. Deletes
//     leave behind tombstones so a stale Put cannot resurrect a removed
//     entry; tombstones are garbage-collected after a TTL.
//   - LWWRegister[V] (Last-Write-Wins register): a single optional
//     value with the same stamp semantics, used for singleton sections
//     (defaults, logging).
//
// Both types' Merge operations are commutative, associative and
// idempotent, so the order in which gossip delivers deltas does not
// matter: every replica that has observed the same set of updates
// converges to the same state.
//
// The package intentionally knows nothing about HTTP, gossip transport
// or the policy compiler. Callers above (admin API, cluster) decide
// when to call Put / Delete / Merge; callers below (policy) consume
// Store.Snapshot() to produce an effective *Config.
package crdt

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Stamp identifies the causal ordering of a write. Higher TS wins; on
// ties, lexicographically larger Node wins. This is the standard LWW
// tiebreaker that makes the merge deterministic across replicas.
type Stamp struct {
	TS   int64  `json:"ts"`
	Node string `json:"node"`
}

// Less returns true if s is strictly older than other.
func (s Stamp) Less(other Stamp) bool {
	if s.TS != other.TS {
		return s.TS < other.TS
	}
	return s.Node < other.Node
}

// Equal reports whether two stamps are byte-equal.
func (s Stamp) Equal(other Stamp) bool { return s.TS == other.TS && s.Node == other.Node }

// Clock produces monotonically increasing timestamps unique within a
// process. Implementations must be safe for concurrent use.
type Clock interface {
	Now() int64
}

// NewMonotonicClock returns a wall-clock-backed clock that never moves
// backwards: if the wall clock regresses (NTP step, suspend/resume)
// the returned value is still strictly greater than the previous one.
// The unit is nanoseconds.
func NewMonotonicClock() Clock { return &monoClock{} }

type monoClock struct {
	mu   sync.Mutex
	last int64
}

func (c *monoClock) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UnixNano()
	if now <= c.last {
		now = c.last + 1
	}
	c.last = now
	return now
}

// MapEntry is the wire and on-disk representation of one LWWMap value.
// Payload is the JSON-encoded value (or nil for tombstones); callers
// decode it into the concrete type they expect.
type MapEntry struct {
	Stamp     Stamp           `json:"stamp"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Tombstone bool            `json:"tombstone,omitempty"`
}

// LWWMap is a string-keyed map with last-write-wins semantics.
type LWWMap struct {
	mu      sync.RWMutex
	entries map[string]MapEntry
}

// NewLWWMap returns an empty LWWMap.
func NewLWWMap() *LWWMap { return &LWWMap{entries: map[string]MapEntry{}} }

// Put stores value under key with the given stamp. The write is applied
// only if the incoming stamp is newer than the existing one (or no
// existing entry exists). Returns true when the local state changed.
func (m *LWWMap) Put(key string, value any, stamp Stamp) (bool, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("crdt: marshal: %w", err)
	}
	return m.apply(key, MapEntry{Stamp: stamp, Payload: payload}), nil
}

// PutRaw is Put without the JSON encoding step (used when applying a
// gossiped MapEntry verbatim).
func (m *LWWMap) PutRaw(key string, entry MapEntry) bool { return m.apply(key, entry) }

// Delete writes a tombstone for key at the given stamp. Returns true
// when the local state changed.
func (m *LWWMap) Delete(key string, stamp Stamp) bool {
	return m.apply(key, MapEntry{Stamp: stamp, Tombstone: true})
}

func (m *LWWMap) apply(key string, e MapEntry) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.entries[key]
	if ok && !cur.Stamp.Less(e.Stamp) {
		// Existing stamp wins (or ties on equal stamps, in which case
		// the entry is already what we'd write).
		return false
	}
	m.entries[key] = e
	return true
}

// Get returns the decoded value for key into dst, the entry's stamp,
// and whether a live (non-tombstoned) entry exists.
func (m *LWWMap) Get(key string, dst any) (Stamp, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[key]
	if !ok || e.Tombstone {
		return Stamp{}, false, nil
	}
	if dst != nil {
		if err := json.Unmarshal(e.Payload, dst); err != nil {
			return Stamp{}, false, fmt.Errorf("crdt: unmarshal %q: %w", key, err)
		}
	}
	return e.Stamp, true, nil
}

// Range iterates every live (non-tombstoned) entry. The callback gets
// the raw payload and stamp; stop iteration by returning false.
func (m *LWWMap) Range(fn func(key string, e MapEntry) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.entries))
	for k := range m.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := m.entries[k]
		if e.Tombstone {
			continue
		}
		if !fn(k, e) {
			return
		}
	}
}

// Snapshot returns a deep copy of the underlying entry map (tombstones
// included) suitable for persistence or gossip anti-entropy.
func (m *LWWMap) Snapshot() map[string]MapEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]MapEntry, len(m.entries))
	for k, v := range m.entries {
		out[k] = v
	}
	return out
}

// Merge folds every entry from other into m. Returns the set of keys
// whose local state changed, so callers can react (rebuild config,
// emit metrics, etc.).
func (m *LWWMap) Merge(other map[string]MapEntry) []string {
	if len(other) == 0 {
		return nil
	}
	var changed []string
	m.mu.Lock()
	for k, in := range other {
		cur, ok := m.entries[k]
		if ok && !cur.Stamp.Less(in.Stamp) {
			continue
		}
		m.entries[k] = in
		changed = append(changed, k)
	}
	m.mu.Unlock()
	sort.Strings(changed)
	return changed
}

// GCTombstones drops tombstones older than the cutoff. Live entries are
// always kept. Returns the number of tombstones removed.
func (m *LWWMap) GCTombstones(cutoff int64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, e := range m.entries {
		if e.Tombstone && e.Stamp.TS < cutoff {
			delete(m.entries, k)
			n++
		}
	}
	return n
}

// RegisterEntry is the wire and on-disk representation of an LWWRegister
// value. Empty Payload + Cleared=true means "no value" (the register
// was explicitly cleared).
type RegisterEntry struct {
	Stamp   Stamp           `json:"stamp"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Cleared bool            `json:"cleared,omitempty"`
}

// LWWRegister is a single optional value with last-write-wins semantics.
type LWWRegister struct {
	mu    sync.RWMutex
	entry RegisterEntry
	set   bool
}

// NewLWWRegister returns an empty register.
func NewLWWRegister() *LWWRegister { return &LWWRegister{} }

// Set writes value at the given stamp. Returns true if the local state
// changed.
func (r *LWWRegister) Set(value any, stamp Stamp) (bool, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("crdt: marshal: %w", err)
	}
	return r.apply(RegisterEntry{Stamp: stamp, Payload: payload}), nil
}

// SetRaw is Set without the JSON encoding step.
func (r *LWWRegister) SetRaw(e RegisterEntry) bool { return r.apply(e) }

// Clear writes a "no value" stamp; subsequent Get returns has=false.
// Returns true if the local state changed.
func (r *LWWRegister) Clear(stamp Stamp) bool {
	return r.apply(RegisterEntry{Stamp: stamp, Cleared: true})
}

func (r *LWWRegister) apply(e RegisterEntry) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.set && !r.entry.Stamp.Less(e.Stamp) {
		return false
	}
	r.entry = e
	r.set = true
	return true
}

// Get decodes the current value into dst and returns the entry's stamp
// and whether a live (non-cleared) value exists.
func (r *LWWRegister) Get(dst any) (Stamp, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.set || r.entry.Cleared {
		return r.entry.Stamp, false, nil
	}
	if dst != nil {
		if err := json.Unmarshal(r.entry.Payload, dst); err != nil {
			return Stamp{}, false, fmt.Errorf("crdt: unmarshal: %w", err)
		}
	}
	return r.entry.Stamp, true, nil
}

// Snapshot returns the current entry plus whether the register has
// ever been written.
func (r *LWWRegister) Snapshot() (RegisterEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entry, r.set
}

// Merge folds other into r. Returns true if the local state changed.
func (r *LWWRegister) Merge(other RegisterEntry, otherSet bool) bool {
	if !otherSet {
		return false
	}
	return r.apply(other)
}
