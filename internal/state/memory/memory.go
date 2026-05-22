// Package memory is the in-memory backend for internal/state.
//
// Two use cases:
//
//   - Standalone mode (no Kubernetes available): the daemon runs as a
//     single replica and persists its overlay to a local JSON file.
//     This is the path exercised by `go run`, local dev, and the
//     in-process E2E suite.
//   - Tests: anywhere we need a Store without touching kube-apiserver.
//
// The implementation is intentionally trivial: a struct guarded by a
// mutex, a monotonic counter as the global Revision, and (optionally)
// an atomic-rename JSON persistence with a debounced writer. Same
// contract as the Kubernetes backend; nothing outside this package
// should be able to tell them apart.
package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"request-validator/internal/state"
)

// Store is the in-memory implementation of state.Store.
type Store struct {
	mu       sync.RWMutex
	groups   map[string]json.RawMessage
	facts    map[string]json.RawMessage
	defaults json.RawMessage
	logging  json.RawMessage
	rev      uint64

	// persistence (optional)
	path      string
	saveDelay time.Duration
	saveMu    sync.Mutex
	saveTimer *time.Timer
	saveWG    sync.WaitGroup

	// watchers
	watchersMu sync.Mutex
	watchers   map[chan state.ChangeEvent]struct{}
}

// Options configure a Store.
type Options struct {
	// Path is the file used for persistence. Empty disables it.
	Path string

	// SaveDelay debounces writes. Defaults to 1 s.
	SaveDelay time.Duration
}

// New constructs an in-memory Store. If opts.Path is non-empty and
// the file exists, the state is restored before returning.
func New(opts Options) (*Store, error) {
	if opts.SaveDelay <= 0 {
		opts.SaveDelay = time.Second
	}
	s := &Store{
		groups:    map[string]json.RawMessage{},
		facts:     map[string]json.RawMessage{},
		path:      opts.Path,
		saveDelay: opts.SaveDelay,
		watchers:  map[chan state.ChangeEvent]struct{}{},
	}
	if opts.Path != "" {
		if err := s.loadFromDisk(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) currentRevision() state.Revision {
	return state.Revision(strconv.FormatUint(s.rev, 10))
}

// Snapshot returns the current state. Holds the read lock for the
// minimum time needed to copy the maps.
func (s *Store) Snapshot(_ context.Context) (state.Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := state.Snapshot{Revision: s.currentRevision()}
	if len(s.groups) > 0 {
		out.Groups = make(map[string]json.RawMessage, len(s.groups))
		for k, v := range s.groups {
			out.Groups[k] = clone(v)
		}
	}
	if len(s.facts) > 0 {
		out.Facts = make(map[string]json.RawMessage, len(s.facts))
		for k, v := range s.facts {
			out.Facts[k] = clone(v)
		}
	}
	if s.defaults != nil {
		out.Defaults = clone(s.defaults)
	}
	if s.logging != nil {
		out.Logging = clone(s.logging)
	}
	return out, nil
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Get returns one entry. For singletons (key == "") the entry's Key
// is left empty.
func (s *Store) Get(_ context.Context, section, key string) (state.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch section {
	case state.SectionGroups:
		if v, ok := s.groups[key]; ok {
			return state.Entry{Section: section, Key: key, Payload: clone(v), Revision: s.currentRevision()}, nil
		}
	case state.SectionFacts:
		if v, ok := s.facts[key]; ok {
			return state.Entry{Section: section, Key: key, Payload: clone(v), Revision: s.currentRevision()}, nil
		}
	case state.SectionDefaults:
		if s.defaults != nil {
			return state.Entry{Section: section, Payload: clone(s.defaults), Revision: s.currentRevision()}, nil
		}
	case state.SectionLogging:
		if s.logging != nil {
			return state.Entry{Section: section, Payload: clone(s.logging), Revision: s.currentRevision()}, nil
		}
	default:
		return state.Entry{}, fmt.Errorf("unknown section %q", section)
	}
	return state.Entry{}, state.ErrNotFound
}

// Put upserts a value. If ifMatch is "*" the entry must NOT already
// exist; if non-empty otherwise, it must match the current revision.
func (s *Store) Put(_ context.Context, section, key string, payload json.RawMessage, ifMatch state.Revision) (state.Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkPrecondition(section, key, ifMatch); err != nil {
		return "", err
	}
	cp := clone(payload)
	switch section {
	case state.SectionGroups:
		s.groups[key] = cp
	case state.SectionFacts:
		s.facts[key] = cp
	case state.SectionDefaults:
		s.defaults = cp
	case state.SectionLogging:
		s.logging = cp
	default:
		return "", fmt.Errorf("unknown section %q", section)
	}
	s.bump()
	return s.currentRevision(), nil
}

// Delete removes a value. Same If-Match semantics as Put.
func (s *Store) Delete(_ context.Context, section, key string, ifMatch state.Revision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkPrecondition(section, key, ifMatch); err != nil {
		return err
	}
	switch section {
	case state.SectionGroups:
		if _, ok := s.groups[key]; !ok {
			return state.ErrNotFound
		}
		delete(s.groups, key)
	case state.SectionFacts:
		if _, ok := s.facts[key]; !ok {
			return state.ErrNotFound
		}
		delete(s.facts, key)
	case state.SectionDefaults:
		if s.defaults == nil {
			return state.ErrNotFound
		}
		s.defaults = nil
	case state.SectionLogging:
		if s.logging == nil {
			return state.ErrNotFound
		}
		s.logging = nil
	default:
		return fmt.Errorf("unknown section %q", section)
	}
	s.bump()
	return nil
}

// checkPrecondition implements the If-Match semantics shared between
// Put and Delete.
func (s *Store) checkPrecondition(section, key string, ifMatch state.Revision) error {
	if ifMatch == "" {
		return nil
	}
	exists := false
	switch section {
	case state.SectionGroups:
		_, exists = s.groups[key]
	case state.SectionFacts:
		_, exists = s.facts[key]
	case state.SectionDefaults:
		exists = s.defaults != nil
	case state.SectionLogging:
		exists = s.logging != nil
	}
	if ifMatch == "*" {
		if exists {
			return state.ErrConflict
		}
		return nil
	}
	cur := s.currentRevision()
	if !exists {
		// If we say "I expect this revision", a missing entry is a
		// mismatch.
		return state.ErrConflict
	}
	if ifMatch != cur {
		return state.ErrConflict
	}
	return nil
}

// bump advances the revision and fans out to watchers. Caller holds
// s.mu (write).
func (s *Store) bump() {
	s.rev++
	rev := s.currentRevision()
	s.scheduleSave()
	go s.broadcast(rev)
}

func (s *Store) broadcast(rev state.Revision) {
	s.watchersMu.Lock()
	chs := make([]chan state.ChangeEvent, 0, len(s.watchers))
	for c := range s.watchers {
		chs = append(chs, c)
	}
	s.watchersMu.Unlock()
	for _, c := range chs {
		select {
		case c <- state.ChangeEvent{Revision: rev}:
		default:
			// Drop if the watcher is slow; they will catch up on
			// the next event via Snapshot anyway.
		}
	}
}

// Watch returns a channel that receives ChangeEvents. The channel is
// closed when ctx is cancelled.
func (s *Store) Watch(ctx context.Context) (<-chan state.ChangeEvent, error) {
	ch := make(chan state.ChangeEvent, 4)
	s.watchersMu.Lock()
	s.watchers[ch] = struct{}{}
	s.watchersMu.Unlock()
	go func() {
		<-ctx.Done()
		s.watchersMu.Lock()
		delete(s.watchers, ch)
		s.watchersMu.Unlock()
		close(ch)
	}()
	return ch, nil
}

// Close flushes pending writes to disk and releases resources.
func (s *Store) Close() error {
	s.saveMu.Lock()
	if s.saveTimer != nil {
		if s.saveTimer.Stop() {
			s.saveWG.Done()
		}
		s.saveTimer = nil
	}
	s.saveMu.Unlock()
	s.saveWG.Wait()
	if s.path == "" {
		return nil
	}
	return s.writeToDisk()
}

// scheduleSave debounces persistence by saveDelay. Caller holds s.mu
// (write).
func (s *Store) scheduleSave() {
	if s.path == "" {
		return
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.saveTimer != nil {
		if s.saveTimer.Stop() {
			s.saveWG.Done()
		}
	}
	s.saveWG.Add(1)
	s.saveTimer = time.AfterFunc(s.saveDelay, func() {
		defer s.saveWG.Done()
		_ = s.writeToDisk()
	})
}

// onDiskState is the structure persisted to disk.
type onDiskState struct {
	Version  int                        `json:"version"`
	Rev      uint64                     `json:"rev"`
	Groups   map[string]json.RawMessage `json:"groups,omitempty"`
	Facts    map[string]json.RawMessage `json:"facts,omitempty"`
	Defaults json.RawMessage            `json:"defaults,omitempty"`
	Logging  json.RawMessage            `json:"logging,omitempty"`
}

func (s *Store) writeToDisk() error {
	s.mu.RLock()
	d := onDiskState{
		Version:  1,
		Rev:      s.rev,
		Groups:   cloneMap(s.groups),
		Facts:    cloneMap(s.facts),
		Defaults: clone(s.defaults),
		Logging:  clone(s.logging),
	}
	s.mu.RUnlock()
	buf, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.json.tmp")
	if err != nil {
		return err
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
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	cleaned = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func cloneMap(m map[string]json.RawMessage) map[string]json.RawMessage {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		out[k] = clone(v)
	}
	return out
}

func (s *Store) loadFromDisk() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var d onDiskState
	if err := json.Unmarshal(b, &d); err != nil {
		return fmt.Errorf("memory: parse state: %w", err)
	}
	if d.Version != 1 && d.Version != 0 {
		return fmt.Errorf("memory: unsupported state version %d", d.Version)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rev = d.Rev
	if d.Groups != nil {
		s.groups = d.Groups
	}
	if d.Facts != nil {
		s.facts = d.Facts
	}
	s.defaults = d.Defaults
	s.logging = d.Logging
	return nil
}
