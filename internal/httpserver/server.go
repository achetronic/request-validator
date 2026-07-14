// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// Package httpserver exposes the ext-authz HTTP endpoint.
//
// Envoy/Istio is expected to forward the original downstream request to this
// service as a regular HTTP request, including the body if configured via the
// `with_request_body` setting on the ext-authz filter. We accept any path and
// inspect the request through our policy engine.
//
// Response contract:
//   - 200 OK              -> request allowed; Envoy passes it through.
//   - 4xx (default 403)   -> request denied; Envoy returns the configured body
//     to the downstream client.
//   - 200 OK + x-rv-dry-run:true + x-rv-result:deny
//     -> the verdict was deny but enforcement is suppressed by dry-run mode,
//     set per-rule with dryRun:true or globally with defaults.dryRun:true.
//     Envoy still passes the request through, and operators can observe
//     shadow denies in the access log and metrics before enabling enforcement.
//
// Diagnostic response headers (all prefixed `x-rv-`):
//
//	x-rv-result    allow|deny  the verdict the policy produced
//	x-rv-rule      name of the rule that decided (or "<defaults>")
//	x-rv-reason    short explanation
//	x-rv-dry-run   true|false  true when enforcement is suppressed
//	               (effectiveDry = defaults.dryRun OR the deciding rule's dryRun)
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

	"request-validator/internal/accesslog"
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

	limit := p.Defaults.ExtAuthz.MaxBodyBytes.Int64()
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		// Reading the body failed: the policy cannot be evaluated, so the
		// default is fail-closed. Under global dry-run the request still passes
		// through with HTTP 200 while the error is logged and counted.
		s.metrics.record("<read>", "error", p.Defaults.DryRun)
		log.Errorw("read body failed", "err", err.Error(), "dry_run", p.Defaults.DryRun)
		w.Header().Set(hdrResult, "deny")
		if p.Defaults.DryRun {
			w.Header().Set(hdrDry, "true")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set(hdrDry, "false")
		w.WriteHeader(p.Defaults.ExtAuthz.DenyStatus)
		_, _ = w.Write([]byte(p.Defaults.ExtAuthz.DenyBody))
		return
	}

	if int64(len(body)) > limit {
		// Overflow: request body exceeded the maximum configured limit.
		truncatedBody := body[:limit]
		req := &policy.Request{
			Method:   r.Method,
			Scheme:   firstNonEmpty(r.Header.Get("X-Forwarded-Proto"), r.URL.Scheme, "http"),
			Host:     hostOnly(r.Host),
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			RemoteIP: clientIP(r),
			Headers:  r.Header,
			Body:     truncatedBody,
		}

		dry := p.Defaults.DryRun
		w.Header().Set(hdrRule, "<overflow>")
		w.Header().Set(hdrReason, "request body too large")
		w.Header().Set(hdrResult, "deny")
		if dry {
			w.Header().Set(hdrDry, "true")
		} else {
			w.Header().Set(hdrDry, "false")
		}

		s.metrics.record("<overflow>", "deny", dry)

		if dry {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(p.Defaults.ExtAuthz.DenyStatus)
			_, _ = w.Write([]byte(p.Defaults.ExtAuthz.DenyBody))
		}

		logger := log.Logger()
		rec := []any{
			"decision", "deny",
			"rule", "<overflow>",
			"reason", "request body too large",
			"dry_run", dry,
			"duration_ms", float64(time.Since(start).Microseconds()) / 1000.0,
			accesslog.RequestAttrs(req, p.Logging),
		}
		logger.Warn("request decided", rec...)
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

	// effectiveDry is true when enforcement should be suppressed: either the
	// global switch is on (defaults.dryRun) or the deciding rule is dryRun.
	effectiveDry := p.Defaults.DryRun || d.DryRun

	// Diagnostic response headers, set before WriteHeader.
	w.Header().Set(hdrRule, d.Rule)
	w.Header().Set(hdrReason, d.Reason)
	w.Header().Set(hdrResult, verdictLabel(d.Allowed))
	if effectiveDry {
		w.Header().Set(hdrDry, "true")
	} else {
		w.Header().Set(hdrDry, "false")
	}

	// Record exactly one decision metric per evaluated request. The outcome
	// is the verdict the policy produced; dry_run reflects effectiveDry so
	// both per-rule and global dry-run show up consistently in the
	// time-series.
	s.metrics.record(d.Rule, verdictLabel(d.Allowed), effectiveDry)

	// Enforce (or shadow) the decision.
	if d.Allowed || effectiveDry {
		// Real allow, or dry-run suppression: Envoy passes the request through.
		w.WriteHeader(http.StatusOK)
	} else {
		// Real deny, not shadowed: Envoy returns the configured error.
		w.WriteHeader(p.Defaults.ExtAuthz.DenyStatus)
		_, _ = w.Write([]byte(p.Defaults.ExtAuthz.DenyBody))
	}

	// One access-log record per request. Log level mirrors the verdict:
	// WARN for deny including shadow denies so they stand out, INFO for allow.
	logger := log.Logger()
	rec := []any{
		"decision", verdictLabel(d.Allowed),
		"rule", d.Rule,
		"reason", d.Reason,
		"dry_run", effectiveDry,
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000.0,
		accesslog.RequestAttrs(req, p.Logging),
	}
	if d.Allowed {
		logger.Info("request decided", rec...)
	} else {
		logger.Warn("request decided", rec...)
	}
}

func verdictLabel(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
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
