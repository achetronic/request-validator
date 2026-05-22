// Package quarantine buffers CRDT entries that arrived through gossip
// (or were inserted locally via the admin API) but currently fail to
// produce a valid effective *Config when merged with the rest of the
// state.
//
// Entries stay in the buffer until a subsequent rebuild succeeds for
// them, until they are manually deleted via the admin API, or until
// they are superseded by a newer CRDT entry on the same key.
//
// Quarantine is local per node. Different replicas may legitimately
// quarantine different items depending on the state they hold; the
// gossiped CRDT is the source of truth, this buffer only defers the
// local apply.
package quarantine

import (
	"sort"
	"sync"
	"time"
)

// Entry describes one quarantined CRDT key.
type Entry struct {
	Section    string    `json:"section"`
	Key        string    `json:"key,omitempty"`
	Reason     string    `json:"reason"`
	Since      time.Time `json:"since"`
	LastRetry  time.Time `json:"lastRetry"`
	RetryCount int       `json:"retryCount"`
}

// Buffer is a small, thread-safe collection of Entry values.
type Buffer struct {
	mu      sync.RWMutex
	entries map[string]Entry
	now     func() time.Time
}

// New returns an empty buffer.
func New() *Buffer {
	return &Buffer{
		entries: map[string]Entry{},
		now:     time.Now,
	}
}

// SetClock replaces the time source (test hook).
func (b *Buffer) SetClock(fn func() time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = fn
}

func id(section, key string) string {
	if key == "" {
		return section
	}
	return section + "/" + key
}

// Push records or refreshes a quarantined entry. The Since timestamp
// is preserved on subsequent calls for the same (section, key).
func (b *Buffer) Push(section, key, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	k := id(section, key)
	if cur, ok := b.entries[k]; ok {
		cur.Reason = reason
		cur.LastRetry = now
		cur.RetryCount++
		b.entries[k] = cur
		return
	}
	b.entries[k] = Entry{
		Section:   section,
		Key:       key,
		Reason:    reason,
		Since:     now,
		LastRetry: now,
	}
}

// Remove drops the entry; returns true if something was removed.
func (b *Buffer) Remove(section, key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := id(section, key)
	if _, ok := b.entries[k]; !ok {
		return false
	}
	delete(b.entries, k)
	return true
}

// Has reports whether the given (section, key) is currently buffered.
func (b *Buffer) Has(section, key string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.entries[id(section, key)]
	return ok
}

// List returns every buffered entry, ordered by (section, key) for
// determinism.
func (b *Buffer) List() []Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Entry, 0, len(b.entries))
	for _, e := range b.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Section != out[j].Section {
			return out[i].Section < out[j].Section
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// Len reports the number of buffered entries.
func (b *Buffer) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
}

// Drain removes entries that the predicate returns true for, returning
// the removed entries. Use it inside a successful rebuild to drop
// any item that now compiles.
func (b *Buffer) Drain(keep func(Entry) bool) []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	removed := make([]Entry, 0)
	for k, e := range b.entries {
		if keep(e) {
			continue
		}
		removed = append(removed, e)
		delete(b.entries, k)
	}
	sort.Slice(removed, func(i, j int) bool {
		if removed[i].Section != removed[j].Section {
			return removed[i].Section < removed[j].Section
		}
		return removed[i].Key < removed[j].Key
	})
	return removed
}
