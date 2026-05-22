// Package adminapi exposes the CRUD HTTP surface that lets operators
// inspect and mutate the CRDT-backed sections of the policy: groups,
// facts, defaults and logging.
//
// The server listens on its own port (typically 8081), separate from
// the ext-authz endpoint, and requires a bearer token loaded from a
// file (--admin-token-file). The token file is watched with fsnotify
// so rotating it never restarts the process.
//
// Writes are serialised through a process-wide mutex. Every successful
// write:
//
//   1. is applied to a copy of the CRDT store,
//   2. drives a rebuild of the effective *policy.Config via
//      policy.MergeFromYAML,
//   3. on success, is committed to the live store, broadcast to the
//      cluster (when configured) and the new *Config is installed via
//      the supplied Apply callback.
//
// A failed compile or validate is surfaced as a 400 with a useful
// error message; the store is not mutated.
package adminapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"request-validator/internal/crdt"
	"request-validator/internal/log"
	rvmetrics "request-validator/internal/metrics"
	"request-validator/internal/policy"
	"request-validator/internal/quarantine"
)

// Broadcaster is the minimal surface adminapi needs from the cluster
// layer to gossip a freshly accepted delta. A nil Broadcaster is
// valid (standalone mode); writes still succeed locally.
type Broadcaster interface {
	BroadcastDelta(d crdt.Delta)
}

// Applier installs a freshly compiled *Config on the running engine.
// Typically wired to httpserver.Server.SetPolicy plus the previous
// Config's Stop() so background fetchers are released.
type Applier interface {
	Apply(newCfg *policy.Config, source string) error
}

// YAMLProvider returns the current raw YAML bytes used as the merge
// floor. The handler invokes it on every write so a concurrent
// fsnotify reload of the YAML file is honoured.
type YAMLProvider func() []byte

// Options configures the admin server.
type Options struct {
	Addr         string                  // ":8081" by default
	TokenFile    string                  // required; without it New returns nil server
	Store        *crdt.Store             // required
	Quarantine   *quarantine.Buffer      // required
	YAMLProvider YAMLProvider            // required
	Broadcaster  Broadcaster             // optional, nil in standalone mode
	Applier      Applier                 // required
	NowFn        func() time.Time        // test hook
}

// Server runs the admin HTTP API.
type Server struct {
	opts   Options
	token  atomic.Pointer[string]
	srv    *http.Server
	writeMu sync.Mutex

	tokenWatchCancel context.CancelFunc
	tokenWatchWG     sync.WaitGroup
}

// New constructs a Server. If opts.TokenFile is empty the admin API
// is considered disabled and a nil Server is returned with no error.
func New(opts Options) (*Server, error) {
	if opts.TokenFile == "" {
		return nil, nil
	}
	if opts.Store == nil {
		return nil, errors.New("adminapi: Options.Store required")
	}
	if opts.Quarantine == nil {
		return nil, errors.New("adminapi: Options.Quarantine required")
	}
	if opts.YAMLProvider == nil {
		return nil, errors.New("adminapi: Options.YAMLProvider required")
	}
	if opts.Applier == nil {
		return nil, errors.New("adminapi: Options.Applier required")
	}
	if opts.Addr == "" {
		opts.Addr = ":8081"
	}
	if opts.NowFn == nil {
		opts.NowFn = time.Now
	}
	s := &Server{opts: opts}
	tok, err := readTokenFile(opts.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("adminapi: read token: %w", err)
	}
	s.token.Store(&tok)
	return s, nil
}

// Run starts the listener and blocks until Stop or fatal error.
func (s *Server) Run() error {
	if s == nil {
		return nil
	}
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	ctx, cancel := context.WithCancel(context.Background())
	s.tokenWatchCancel = cancel
	s.tokenWatchWG.Add(1)
	go func() {
		defer s.tokenWatchWG.Done()
		s.watchTokenFile(ctx)
	}()

	s.srv = &http.Server{
		Addr:              s.opts.Addr,
		Handler:           s.requireBearer(s.withMetrics(mux)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Infow("starting admin api", "addr", s.opts.Addr)
	err := s.srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Stop gracefully shuts down the admin server.
func (s *Server) Stop() {
	if s == nil {
		return
	}
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
	}
	if s.tokenWatchCancel != nil {
		s.tokenWatchCancel()
	}
	s.tokenWatchWG.Wait()
}

// withMetrics increments rvmetrics.AdminRequests per response. The
// status code is captured via a small wrapper.
func (s *Server) withMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		rvmetrics.AdminRequests.Inc(fmt.Sprintf(
			"method=%q,path=%q,status=%q",
			r.Method, routeLabel(r.URL.Path), fmt.Sprintf("%d", sw.status),
		))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

// routeLabel normalises /api/v1/groups/<name> to /api/v1/groups/{name}
// so the Prometheus cardinality stays bounded.
func routeLabel(p string) string {
	if !strings.HasPrefix(p, "/api/v1/") {
		return p
	}
	rest := strings.TrimPrefix(p, "/api/v1/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) == 1 {
		return "/api/v1/" + parts[0]
	}
	switch parts[0] {
	case "groups", "facts":
		return "/api/v1/" + parts[0] + "/{name}"
	case "quarantine":
		if len(parts) == 1 || parts[1] == "" {
			return "/api/v1/quarantine"
		}
		return "/api/v1/quarantine/{section}"
	}
	return p
}

// requireBearer wraps the mux with a constant-time bearer-token check.
func (s *Server) requireBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := s.token.Load()
		if want == nil || *want == "" {
			http.Error(w, "admin api not configured", http.StatusInternalServerError)
			return
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		got := strings.TrimSpace(auth[len(prefix):])
		if subtle.ConstantTimeCompare([]byte(got), []byte(*want)) != 1 {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func readTokenFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return tok, nil
}

// watchTokenFile watches the directory containing the token file and
// reloads the token on any relevant change. We watch the directory
// (not the file) so atomic rename rotations and Kubernetes Secret
// projections (which use the same `..data` symlink trick as
// ConfigMaps) are picked up.
func (s *Server) watchTokenFile(ctx context.Context) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Errorw("admin: cannot create token watcher", "err", err.Error())
		return
	}
	defer w.Close()

	dir := filepath.Dir(s.opts.TokenFile)
	name := filepath.Base(s.opts.TokenFile)
	if err := w.Add(dir); err != nil {
		log.Errorw("admin: watch token dir failed", "dir", dir, "err", err.Error())
		return
	}

	reload := func() {
		tok, err := readTokenFile(s.opts.TokenFile)
		if err != nil {
			log.Errorw("admin: token reload failed; keeping previous",
				"err", err.Error())
			return
		}
		s.token.Store(&tok)
		log.Infow("admin: token reloaded")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			base := filepath.Base(ev.Name)
			if base != name && base != "..data" {
				continue
			}
			if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Chmod) == 0 {
				continue
			}
			reload()
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			log.Warnw("admin: token watcher error", "err", err.Error())
		}
	}
}

// writeJSON serialises v as JSON with a 200 status (or the provided
// status if non-zero) and a fixed Content-Type.
func writeJSON(w http.ResponseWriter, status int, v any) {
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// writeError emits a JSON error envelope.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func etagFor(stamp crdt.Stamp) string {
	return fmt.Sprintf("\"%d-%s\"", stamp.TS, stamp.Node)
}

// parseIfMatch returns the stamp encoded in an `If-Match` header, or
// nil if the header is missing.
func parseIfMatch(r *http.Request) *crdt.Stamp {
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	if v == "" {
		return nil
	}
	v = strings.Trim(v, "\"")
	idx := strings.Index(v, "-")
	if idx <= 0 {
		return nil
	}
	var ts int64
	if _, err := fmt.Sscanf(v[:idx], "%d", &ts); err != nil {
		return nil
	}
	return &crdt.Stamp{TS: ts, Node: v[idx+1:]}
}

// Helpers exposed for tests.

func (s *Server) currentTokenForTest() string {
	if p := s.token.Load(); p != nil {
		return *p
	}
	return ""
}

// rebuildAndApply runs the merge/validate/compile pipeline against
// the supplied store snapshot and installs the result through the
// Applier. It is the single place that touches the engine, so all
// write paths share its error handling. quarantineKey, when non-empty,
// is pushed to the quarantine buffer on failure.
func (s *Server) rebuildAndApply(snap crdt.FullState, source string) error {
	yamlBytes := s.opts.YAMLProvider()
	cfg, err := policy.MergeFromYAML(yamlBytes, snap)
	if err != nil {
		return err
	}
	if err := s.opts.Applier.Apply(cfg, source); err != nil {
		return err
	}
	// Re-evaluate the quarantine buffer: any entry that compiles now
	// is removed and integrated.
	removed := s.opts.Quarantine.Drain(func(e quarantine.Entry) bool {
		// Decide based on whether the current snapshot would still
		// fail for that key. For simplicity we just re-run the merge
		// in-memory; the cost is negligible at admin frequency.
		_, err := policy.MergeFromYAML(yamlBytes, snap)
		return err != nil
	})
	for _, e := range removed {
		log.Infow("admin: quarantine drained",
			"section", e.Section, "key", e.Key, "reason", e.Reason)
	}
	return nil
}
