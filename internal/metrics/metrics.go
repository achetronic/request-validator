// Package metrics holds the small set of process-wide counters that
// are surfaced by the existing /metrics endpoint in httpserver.
//
// Counters live here (not in httpserver) so cluster, adminapi and
// quarantine can mutate them without importing httpserver and
// creating a dependency cycle. The /metrics handler reads through
// `Render` and prints them in the Prometheus text format.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
)

var (
	AdminRequests = newLabelled("request_validator_admin_requests_total",
		"Admin API requests, labelled by method/path/status.")
	GossipMessages = newLabelled("request_validator_gossip_messages_total",
		"Gossip messages broken down by direction (in|out) and type.")
	QuarantineSize = newGauge("request_validator_quarantine_size",
		"Quarantined CRDT entries by section.")
	Rebuilds = newLabelled("request_validator_rebuilds_total",
		"Effective-Config rebuilds triggered, by source (yaml|sighup|crdt|gossip).")
	RebuildErrors = newCounter("request_validator_rebuild_errors_total",
		"Effective-Config rebuilds that failed validation/compile.")
	ClusterMembers = newGauge("request_validator_cluster_members",
		"Cluster members observed by this node, by state.")
)

func newCounter(name, help string) *Counter {
	c := &Counter{name: name, help: help}
	return c
}

// Counter is a single-line monotonic counter.
type Counter struct {
	name, help string
	val        atomic.Uint64
}

func (c *Counter) Inc() { c.val.Add(1) }

// LabelledCounter holds N counters keyed by an arbitrary label tuple.
type LabelledCounter struct {
	name, help string
	mu         sync.RWMutex
	vals       map[string]*atomic.Uint64
}

func newLabelled(name, help string) *LabelledCounter {
	return &LabelledCounter{name: name, help: help, vals: map[string]*atomic.Uint64{}}
}

// Inc increments the counter identified by labels. Labels are emitted
// in the order they're passed; do not interleave key orderings.
func (c *LabelledCounter) Inc(labels string) {
	c.mu.RLock()
	v, ok := c.vals[labels]
	c.mu.RUnlock()
	if !ok {
		c.mu.Lock()
		if v, ok = c.vals[labels]; !ok {
			v = new(atomic.Uint64)
			c.vals[labels] = v
		}
		c.mu.Unlock()
	}
	v.Add(1)
}

// Gauge is a settable, observable value with optional labels.
type Gauge struct {
	name, help string
	mu         sync.RWMutex
	vals       map[string]int64
}

func newGauge(name, help string) *Gauge {
	return &Gauge{name: name, help: help, vals: map[string]int64{}}
}

// Set replaces the value for the given label tuple.
func (g *Gauge) Set(labels string, value int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.vals[labels] = value
}

// Render writes the Prometheus text representation of every counter
// declared above. The caller is expected to invoke this from the HTTP
// /metrics handler after writing its own decision counters.
func Render(w io.Writer) {
	for _, c := range []*Counter{RebuildErrors} {
		fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
		fmt.Fprintf(w, "# TYPE %s counter\n", c.name)
		fmt.Fprintf(w, "%s %d\n", c.name, c.val.Load())
	}
	for _, lc := range []*LabelledCounter{AdminRequests, GossipMessages, Rebuilds} {
		fmt.Fprintf(w, "# HELP %s %s\n", lc.name, lc.help)
		fmt.Fprintf(w, "# TYPE %s counter\n", lc.name)
		lc.mu.RLock()
		keys := make([]string, 0, len(lc.vals))
		for k := range lc.vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "%s{%s} %d\n", lc.name, k, lc.vals[k].Load())
		}
		lc.mu.RUnlock()
	}
	for _, g := range []*Gauge{QuarantineSize, ClusterMembers} {
		fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
		fmt.Fprintf(w, "# TYPE %s gauge\n", g.name)
		g.mu.RLock()
		keys := make([]string, 0, len(g.vals))
		for k := range g.vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "" {
				fmt.Fprintf(w, "%s %d\n", g.name, g.vals[k])
				continue
			}
			fmt.Fprintf(w, "%s{%s} %d\n", g.name, k, g.vals[k])
		}
		g.mu.RUnlock()
	}
}
