// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package httpserver

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// metrics holds simple counters exposed at /metrics in Prometheus text format.
// Implemented in-tree to keep zero external dependencies.
type metrics struct {
	totalAllowed atomic.Uint64
	totalDenied  atomic.Uint64
	totalErrors  atomic.Uint64

	mu      sync.RWMutex
	perRule map[ruleKey]*ruleCounters
}

type ruleKey struct {
	rule    string
	outcome string // allow|deny
	dryRun  bool
}

type ruleCounters struct {
	count atomic.Uint64
}

func newMetrics() *metrics {
	return &metrics{perRule: make(map[ruleKey]*ruleCounters)}
}

func (m *metrics) record(rule, outcome string, dryRun bool) {
	switch outcome {
	case "allow":
		m.totalAllowed.Add(1)
	case "deny":
		m.totalDenied.Add(1)
	case "error":
		m.totalErrors.Add(1)
	}
	k := ruleKey{rule, outcome, dryRun}
	m.mu.RLock()
	c, ok := m.perRule[k]
	m.mu.RUnlock()
	if !ok {
		m.mu.Lock()
		if c, ok = m.perRule[k]; !ok {
			c = &ruleCounters{}
			m.perRule[k] = c
		}
		m.mu.Unlock()
	}
	c.count.Add(1)
}

func (m *metrics) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP request_validator_decisions_total Total decisions emitted.\n")
		fmt.Fprintf(w, "# TYPE request_validator_decisions_total counter\n")
		fmt.Fprintf(w, "request_validator_decisions_total{outcome=\"allow\"} %d\n", m.totalAllowed.Load())
		fmt.Fprintf(w, "request_validator_decisions_total{outcome=\"deny\"} %d\n", m.totalDenied.Load())
		fmt.Fprintf(w, "request_validator_decisions_total{outcome=\"error\"} %d\n", m.totalErrors.Load())

		fmt.Fprintf(w, "# HELP request_validator_rule_decisions_total Decisions broken down by rule.\n")
		fmt.Fprintf(w, "# TYPE request_validator_rule_decisions_total counter\n")
		m.mu.RLock()
		keys := make([]ruleKey, 0, len(m.perRule))
		for k := range m.perRule {
			keys = append(keys, k)
		}
		m.mu.RUnlock()
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].rule != keys[j].rule {
				return keys[i].rule < keys[j].rule
			}
			return keys[i].outcome < keys[j].outcome
		})
		for _, k := range keys {
			m.mu.RLock()
			c := m.perRule[k]
			m.mu.RUnlock()
			fmt.Fprintf(w, "request_validator_rule_decisions_total{rule=%q,outcome=%q,dry_run=%q} %d\n",
				k.rule, k.outcome, boolStr(k.dryRun), c.count.Load())
		}
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
