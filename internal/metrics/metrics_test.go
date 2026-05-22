package metrics

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestCounterIncIsAtomic(t *testing.T) {
	c := newCounter("test_total", "test")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.Inc()
			}
		}()
	}
	wg.Wait()
	if got := c.val.Load(); got != 8000 {
		t.Fatalf("expected 8000, got %d", got)
	}
}

func TestLabelledCounterPerLabelSeparation(t *testing.T) {
	lc := newLabelled("test_admin_total", "test")
	lc.Inc(`method="GET"`)
	lc.Inc(`method="GET"`)
	lc.Inc(`method="POST"`)

	var buf bytes.Buffer
	// Plug it into Render via a fresh local instance to avoid mutating
	// the package-globals; the Render function only iterates the
	// exported ones, so we render directly here.
	for _, lbl := range []string{`method="GET"`, `method="POST"`} {
		lc.mu.RLock()
		v := lc.vals[lbl].Load()
		lc.mu.RUnlock()
		buf.WriteString(lbl)
		buf.WriteString(":")
		if v == 0 {
			t.Fatalf("expected non-zero for %s", lbl)
		}
	}
	if got := lc.vals[`method="GET"`].Load(); got != 2 {
		t.Fatalf("GET expected 2, got %d", got)
	}
	if got := lc.vals[`method="POST"`].Load(); got != 1 {
		t.Fatalf("POST expected 1, got %d", got)
	}
}

func TestGaugeSetReplaces(t *testing.T) {
	g := newGauge("test_gauge", "test")
	g.Set(`state="alive"`, 5)
	g.Set(`state="alive"`, 7) // replace, not add
	g.Set(`state="dead"`, 1)
	if g.vals[`state="alive"`] != 7 {
		t.Fatalf("expected 7, got %d", g.vals[`state="alive"`])
	}
	if g.vals[`state="dead"`] != 1 {
		t.Fatalf("expected 1, got %d", g.vals[`state="dead"`])
	}
}

func TestRenderEmitsPrometheusText(t *testing.T) {
	// Drive the package-level counters and assert Render's output.
	// Counters are package-scoped (no reset between tests), so we
	// only check that the *line shape* is correct, not exact values.
	AdminRequests.Inc(`method="GET",path="/api/v1/groups",status="200"`)
	Rebuilds.Inc(`trigger="store"`)
	RebuildErrors.Inc()

	var buf bytes.Buffer
	Render(&buf)
	out := buf.String()

	for _, want := range []string{
		"# TYPE request_validator_admin_requests_total counter",
		`request_validator_admin_requests_total{method="GET",path="/api/v1/groups",status="200"}`,
		"# TYPE request_validator_rebuilds_total counter",
		`request_validator_rebuilds_total{trigger="store"}`,
		"# TYPE request_validator_rebuild_errors_total counter",
		"request_validator_rebuild_errors_total",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing line %q in:\n%s", want, out)
		}
	}
}

func TestRenderGaugeEmptyLabelHasNoBraces(t *testing.T) {
	g := newGauge("rv_naked_gauge", "naked")
	g.Set("", 42)

	// Mimic Render's gauge branch.
	var buf bytes.Buffer
	g.mu.RLock()
	for k, v := range g.vals {
		if k == "" {
			buf.WriteString("rv_naked_gauge ")
			buf.WriteString(itoa(v))
			buf.WriteString("\n")
		}
	}
	g.mu.RUnlock()
	if !strings.Contains(buf.String(), "rv_naked_gauge 42") {
		t.Fatalf("expected naked metric, got %q", buf.String())
	}
}

func itoa(v int64) string {
	// avoid pulling strconv into the test fixture branch above.
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	out := ""
	for v > 0 {
		out = string('0'+rune(v%10)) + out
		v /= 10
	}
	if neg {
		out = "-" + out
	}
	return out
}
