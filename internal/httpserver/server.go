// Package httpserver exposes the ext-authz HTTP endpoint.
//
// Envoy/Istio is expected to forward the original downstream request to this
// service as a regular HTTP request, including the body if configured via the
// `with_request_body` setting on the ext-authz filter. We accept any path and
// inspect the request through our policy engine.
//
// Response contract:
//   - 200 OK         -> request allowed (Envoy passes it through)
//   - 4xx (default 403) -> request denied (Envoy returns the configured body)
//   - 200 OK with x-rv-dry-run=true header -> rule marked dryRun: matched a
//     deny rule but request was let through; useful for shadow testing.
//
// Diagnostic response headers (all prefixed `x-rv-`):
//   x-rv-result      allow|deny
//   x-rv-rule        name of the rule that decided (or "<defaults>")
//   x-rv-reason      short explanation
//   x-rv-dry-run     true|false
package httpserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"request-validator/internal/log"
	"request-validator/internal/policy"
)

const (
	hdrResult = "x-rv-result"
	hdrRule   = "x-rv-rule"
	hdrReason = "x-rv-reason"
	hdrDry    = "x-rv-dry-run"
)

// Server is the ext-authz HTTP server.
type Server struct {
	policy  atomic.Pointer[policy.Config]
	metrics *metrics
	srv     *http.Server
}

// New builds a server bound to the given initial policy.
func New(initial *policy.Config) *Server {
	s := &Server{metrics: newMetrics()}
	s.policy.Store(initial)
	return s
}

// SetPolicy atomically swaps the active policy (used for hot-reload). It
// returns the previously installed policy so the caller can release any
// resources it owns (such as facts goroutines).
func (s *Server) SetPolicy(c *policy.Config) *policy.Config { return s.policy.Swap(c) }

// Policy returns the currently installed policy. Useful at shutdown so the
// caller can release resources owned by the active policy.
func (s *Server) Policy() *policy.Config { return s.policy.Load() }

// Run starts the HTTP listener and blocks until Stop or fatal error.
func (s *Server) Run(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.policy.Load() == nil {
			http.Error(w, "no policy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/metrics", s.metrics.handler())
	mux.HandleFunc("/", s.handle)

	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Infow("starting http server", "addr", addr)
	err := s.srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() {
	if s.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	p := s.policy.Load()
	if p == nil {
		s.metrics.record("<noconfig>", "error", false)
		http.Error(w, "no policy loaded", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, p.Defaults.MaxBodyBytes.Int64()))
	if err != nil {
		s.metrics.record("<read>", "error", false)
		log.Errorw("read body failed", "err", err.Error())
		s.deny(w, p, "<read>", "read body failed", false)
		return
	}

	req := &policy.Request{
		Method:   r.Method,
		Scheme:   firstNonEmpty(r.Header.Get("X-Forwarded-Proto"), r.URL.Scheme, "http"),
		Host:     hostOnly(r.Host),
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		RemoteIP: clientIP(r),
		Headers:  r.Header,
		Body:     body,
	}

	d := p.Evaluate(r.Context(), req)

	w.Header().Set(hdrRule, d.Rule)
	w.Header().Set(hdrReason, d.Reason)
	if d.DryRun {
		w.Header().Set(hdrDry, "true")
	} else {
		w.Header().Set(hdrDry, "false")
	}

	if d.Allowed {
		s.metrics.record(d.Rule, "allow", d.DryRun)
		w.Header().Set(hdrResult, "allow")
		w.WriteHeader(http.StatusOK)
	} else {
		s.deny(w, p, d.Rule, d.Reason, d.DryRun)
	}

	// One access-log record per request. Level mirrors the verdict.
	logger := log.Logger()
	rec := []any{
		"decision", verdictLabel(d.Allowed),
		"rule", d.Rule,
		"reason", d.Reason,
		"dry_run", d.DryRun,
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000.0,
		accessLogAttrs(req, p.Logging),
	}
	switch {
	case d.Allowed:
		logger.Info("request decided", rec...)
	default:
		logger.Warn("request decided", rec...)
	}
}

func verdictLabel(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

func (s *Server) deny(w http.ResponseWriter, p *policy.Config, rule, reason string, dryRun bool) {
	s.metrics.record(rule, "deny", dryRun)
	w.Header().Set(hdrResult, "deny")
	w.WriteHeader(p.Defaults.DenyStatus)
	_, _ = w.Write([]byte(p.Defaults.DenyBody))
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
