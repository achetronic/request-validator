// Package state owns the replicated portion of the policy: the
// "admin overlay" that the operator can read and mutate via the admin
// API. It is the floor of code that sits between the admin handlers
// and the storage backend (a Kubernetes ConfigMap in production, an
// in-memory shim in standalone mode).
//
// The package deliberately does not depend on Kubernetes types: the
// Store interface speaks bytes, sections and revisions. Concrete
// implementations live in subpackages (state/configmap, state/memory).
// That keeps the engine and the admin API trivially testable against
// the in-memory backend.
package state

import (
	"context"
	"encoding/json"
	"errors"
)

// Section names used both by the admin API URLs and by the Store
// internals. Anything in the system that ships an overlay value
// references one of these.
const (
	SectionGroups   = "groups"
	SectionFacts    = "facts"
	SectionDefaults = "defaults"
	SectionLogging  = "logging"
)

// Revision opaquely identifies a version of an entry. With the
// ConfigMap backend this is the ConfigMap's resourceVersion; with
// the in-memory backend it's a monotonic counter. Either way callers
// use it for If-Match concurrency without caring about the format.
type Revision string

// Entry is the wire shape of one stored value.
type Entry struct {
	Section  string          `json:"section"`
	Key      string          `json:"key,omitempty"` // empty for singletons
	Payload  json.RawMessage `json:"payload"`
	Revision Revision        `json:"revision"`
}

// Snapshot is the read view returned by Store.Snapshot. It is what
// policy.Merge consumes to build the effective Config.
type Snapshot struct {
	Groups   map[string]json.RawMessage `json:"groups,omitempty"`
	Facts    map[string]json.RawMessage `json:"facts,omitempty"`
	Defaults json.RawMessage            `json:"defaults,omitempty"`
	Logging  json.RawMessage            `json:"logging,omitempty"`

	// Revision is the global revision identifier for the snapshot.
	// Used for ETag computation on whole-state reads and to debounce
	// duplicate change notifications.
	Revision Revision `json:"revision"`
}

// ErrConflict is returned by Put / Delete when the supplied
// IfMatch revision does not match the current one. Translated to
// HTTP 412 Precondition Failed by the admin API.
var ErrConflict = errors.New("state: revision conflict")

// ErrNotFound is returned when Get is invoked on a key that has no
// live value (never written, or already deleted).
var ErrNotFound = errors.New("state: not found")

// ChangeEvent is what callers Watch for. The watcher fans out into
// the rebuild goroutine: when a change arrives, the engine rebuilds
// the effective *policy.Config from the new Snapshot.
//
// A ChangeEvent does not carry the new value; the consumer is
// expected to call Snapshot to read the current state. That keeps
// the channel cheap and avoids stale fan-out.
type ChangeEvent struct {
	Revision Revision
}

// Store is the abstraction the admin API and the engine see. Two
// implementations exist:
//
//   - configmap.Store: backed by a single ConfigMap in Kubernetes,
//     replicated across replicas by kube-apiserver. Writes go
//     through optimistic concurrency on resourceVersion; reads use
//     a shared informer.
//   - memory.Store: backed by a JSON file on local disk; used in
//     standalone mode (no Kubernetes) and in tests.
//
// Both honour the same contract: writers see linearisable
// last-writer-wins semantics, readers see a consistent snapshot
// per call.
type Store interface {
	// Snapshot returns the entire state. Safe to call from any
	// goroutine; cheap with the informer-backed implementation.
	Snapshot(ctx context.Context) (Snapshot, error)

	// Get returns one entry by section and key. For singleton
	// sections (Defaults, Logging) pass key = "".
	Get(ctx context.Context, section, key string) (Entry, error)

	// Put upserts a value. If ifMatch is non-empty the operation
	// returns ErrConflict when the current revision differs.
	// Pass "*" as ifMatch to require "does not currently exist".
	Put(ctx context.Context, section, key string, payload json.RawMessage, ifMatch Revision) (Revision, error)

	// Delete tombstones a key (collections) or clears the value
	// (singletons). Same If-Match semantics as Put.
	Delete(ctx context.Context, section, key string, ifMatch Revision) error

	// Watch returns a channel that receives a ChangeEvent whenever
	// the snapshot changes (from this process or a peer). Cancel the
	// context to release the subscription.
	Watch(ctx context.Context) (<-chan ChangeEvent, error)

	// Close releases resources (informer, file handles, …).
	Close() error
}
