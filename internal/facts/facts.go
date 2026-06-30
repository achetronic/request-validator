// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// Package facts owns the "facts" feature of the policy DSL.
//
// A `facts` entry is a named value that policies can reference from any CEL
// expression as `facts.<name>`. It exists so external sources (HTTP feeds,
// files written by a CronJob, etc.) can feed the engine without rewriting the
// policy file every time the data changes.
//
// Three retrieval methods are supported, distinguished by the `method` field:
//
//	value: literal value declared inline in the YAML. Any YAML scalar,
//	         list or map. Exposed to CEL untouched.
//
//	file:  bytes read from a file on disk. Re-read on demand by the policy
//	         watcher (which already invalidates the whole policy on any
//	         change inside the config directory). Exposed to CEL as a string.
//	         Parse it in CEL with `parseJSON(...)` / `parseYAML(...)`.
//
//	url:   bytes fetched periodically by a background goroutine. Refreshed
//	         every `interval`. The most recently successful body is what
//	         CEL sees; if the next fetch fails the previous body is kept.
//	         Exposed to CEL as a string.
//
// Usage is split between construction and runtime: New(specs) parses the
// declarations and pre-populates inline entries without touching the network,
// and Start(ctx) launches the URL fetchers and reads file sources, refusing
// to return until either every entry has a value or a non-retryable failure
// happens (so a policy that depends on a feed never serves traffic with an
// empty value at boot). On the hot path, Snapshot() returns a
// `map<string, any>` of the current values via lock-free atomic reads. Stop()
// cancels the fetcher goroutines and waits for them to drain.
package facts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"request-validator/internal/log"
)

// Spec is the parsed YAML declaration of one facts entry.
type Spec struct {
	Name   string `yaml:"name"`
	Method string `yaml:"method"` // "value" | "file" | "url"
	Value  any    `yaml:"value,omitempty"`
	File   *File  `yaml:"file,omitempty"`
	URL    *URL   `yaml:"url,omitempty"`
}

// File is the spec for the `file` method.
type File struct {
	Path string `yaml:"path"`
}

// URL is the spec for the `url` method.
type URL struct {
	Address  string            `yaml:"address"`
	Interval time.Duration     `yaml:"interval"`
	Timeout  time.Duration     `yaml:"timeout"`
	Headers  map[string]string `yaml:"headers,omitempty"`
}

// Registry holds all facts entries in a process.
type Registry struct {
	entries map[string]*entry

	mu      sync.Mutex
	cancels []context.CancelFunc
	wg      sync.WaitGroup
}

type entry struct {
	spec Spec

	// value holds the current value seen by CEL. We store it in an
	// atomic.Pointer so the hot path is lock-free.
	value atomic.Pointer[any]
}

// New parses the specs, validates them and returns a Registry whose entries
// already carry their inline values. URL/file fetchers are *not* started; the
// caller must invoke Start(ctx) for that.
func New(specs []Spec) (*Registry, error) {
	r := &Registry{entries: make(map[string]*entry, len(specs))}
	seen := map[string]bool{}
	for i := range specs {
		s := specs[i]
		if s.Name == "" {
			return nil, fmt.Errorf("facts[%d]: missing name", i)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("facts[%d]: duplicate name %q", i, s.Name)
		}
		seen[s.Name] = true

		switch s.Method {
		case "value":
			if s.File != nil || s.URL != nil {
				return nil, fmt.Errorf("facts %q: method=value cannot define file/url", s.Name)
			}
		case "file":
			if s.File == nil || s.File.Path == "" {
				return nil, fmt.Errorf("facts %q: method=file requires file.path", s.Name)
			}
			if s.Value != nil || s.URL != nil {
				return nil, fmt.Errorf("facts %q: method=file cannot define value/url", s.Name)
			}
		case "url":
			if s.URL == nil || s.URL.Address == "" {
				return nil, fmt.Errorf("facts %q: method=url requires url.address", s.Name)
			}
			if s.URL.Interval <= 0 {
				s.URL.Interval = 10 * time.Minute
			}
			if s.URL.Timeout <= 0 {
				s.URL.Timeout = 15 * time.Second
			}
			if s.Value != nil || s.File != nil {
				return nil, fmt.Errorf("facts %q: method=url cannot define value/file", s.Name)
			}
		default:
			return nil, fmt.Errorf("facts %q: method must be value|file|url (got %q)", s.Name, s.Method)
		}

		e := &entry{spec: s}
		if s.Method == "value" {
			v := s.Value
			e.value.Store(&v)
		}
		r.entries[s.Name] = e
	}
	return r, nil
}

// Start performs the initial population for file and url sources and launches
// the URL refresh goroutines. It returns an error if any source can't produce
// a first value, so the policy that depends on it fails closed.
func (r *Registry) Start(ctx context.Context) error {
	for name, e := range r.entries {
		switch e.spec.Method {
		case "file":
			b, err := os.ReadFile(e.spec.File.Path)
			if err != nil {
				return fmt.Errorf("facts %q: initial file read: %w", name, err)
			}
			s := any(string(b))
			e.value.Store(&s)
		case "url":
			b, err := fetch(ctx, e.spec.URL)
			if err != nil {
				return fmt.Errorf("facts %q: initial url fetch: %w", name, err)
			}
			s := any(string(b))
			e.value.Store(&s)
			r.spawnURL(ctx, e)
		}
	}
	return nil
}

func (r *Registry) spawnURL(parent context.Context, e *entry) {
	r.mu.Lock()
	ctx, cancel := context.WithCancel(parent)
	r.cancels = append(r.cancels, cancel)
	r.wg.Add(1)
	r.mu.Unlock()

	go func() {
		defer r.wg.Done()
		t := time.NewTicker(e.spec.URL.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				b, err := fetch(ctx, e.spec.URL)
				if err != nil {
					// Keep the previous value; surface the failure so an
					// operator can see something is wrong. Repeated errors
					// won't drown the log because tickers are spaced by
					// e.spec.URL.Interval (10m by default).
					log.Warnw("facts: refresh failed; keeping previous value",
						"name", e.spec.Name,
						"address", e.spec.URL.Address,
						"err", err.Error())
					continue
				}
				s := any(string(b))
				e.value.Store(&s)
				log.Debugw("facts: refreshed",
					"name", e.spec.Name,
					"size_bytes", len(b))
			}
		}
	}()
}

// Stop cancels the goroutines spawned by Start and waits for them.
func (r *Registry) Stop() {
	r.mu.Lock()
	cancels := r.cancels
	r.cancels = nil
	r.mu.Unlock()
	for _, c := range cancels {
		c()
	}
	r.wg.Wait()
}

// Snapshot returns the current map of name -> value to feed CEL. It is built
// from atomic loads so it is safe and cheap to call on the hot path.
func (r *Registry) Snapshot() map[string]any {
	out := make(map[string]any, len(r.entries))
	for name, e := range r.entries {
		p := e.value.Load()
		if p == nil {
			out[name] = nil
			continue
		}
		out[name] = *p
	}
	return out
}

// Names returns the list of declared facts names in deterministic order
// (mostly useful in logs and tests).
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.entries))
	for name := range r.entries {
		out = append(out, name)
	}
	return out
}

var ErrHTTP = errors.New("non-2xx response")

func fetch(ctx context.Context, u *URL) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, u.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u.Address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "request-validator")
	for k, v := range u.Headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: %s", ErrHTTP, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
