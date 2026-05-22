// Package adminapi exposes the CRUD HTTP surface that lets operators
// inspect and mutate the four overlay sections of the policy:
// groups, facts, defaults and logging.
//
// The server listens on its own port (typically 8081), separate from
// the ext-authz endpoint, and requires a bearer token loaded from a
// file (--admin-token-file). The token file is watched with fsnotify
// so rotating it never restarts the process.
//
// Writes are only accepted by the cluster leader. Followers respond
// with a 307 Temporary Redirect carrying the leader's admin URL in
// `Location`. Reads (GET) are served locally on any replica from the
// informer's cached view; the read-your-writes guarantee is provided
// by HTTP clients following 307s back to the leader.
//
// Every successful write:
//
//  1. Validates the resulting effective *Config by running
//     policy.MergeFromYAML on a hypothetical snapshot. A failure
//     returns 400 and the store is untouched.
//  2. Calls state.Store.Put / Delete with the current revision as
//     If-Match (when supplied), surfacing 412 on conflict.
//  3. Schedules a rebuild via the Applier callback so the engine
//     swaps to the new config atomically. The same rebuild fires on
//     every replica via the store's watcher.
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

	"request-validator/internal/cluster"
	"request-validator/internal/log"
	rvmetrics "request-validator/internal/metrics"
	"request-validator/internal/policy"
	"request-validator/internal/state"
)

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
	// Addr is the listen address. Defaults to ":8081".
	Addr string

	// TokenFile holds the bearer token. Without it New returns
	// (nil, nil) and no admin server is started.
	TokenFile string

	// Store is the replicated state backend.
	Store state.Store

	// Cluster owns leader election. May be nil in single-replica
	// in-memory setups; in that case all writes are accepted
	// locally.
	Cluster *cluster.Cluster

	// YAMLProvider returns the current YAML floor.
	YAMLProvider YAMLProvider

	// Applier swaps the new compiled *Config into the engine.
	Applier Applier

	// NowFn is a test hook for time. Defaults to time.Now.
	NowFn func() time.Time
}

// Server runs the admin HTTP API.
type Server struct {
	opts    Options
	token   atomic.Pointer[string]
	srv     *http.Server
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

// withMetrics increments rvmetrics.AdminRequests per response.
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

// etagFor formats a state.Revision as a quoted ETag value.
func etagFor(rev state.Revision) string {
	return `"` + string(rev) + `"`
}

// parseIfMatch returns the trimmed If-Match value, or "" if missing.
// The wildcard "*" is preserved as-is so Store.Put can apply
// "must-not-exist" semantics.
func parseIfMatch(r *http.Request) state.Revision {
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	if v == "" {
		return ""
	}
	v = strings.Trim(v, "\"")
	return state.Revision(v)
}

// ensureLeaderOrRedirect serves a 307 to the current leader when this
// replica is not the leader, or a 503 when no leader is known yet.
// Returns true when the caller should proceed (we are the leader, or
// no cluster is configured).
func (s *Server) ensureLeaderOrRedirect(w http.ResponseWriter, r *http.Request) bool {
	if s.opts.Cluster == nil || s.opts.Cluster.Standalone() {
		return true
	}
	l := s.opts.Cluster.Leader()
	if l.Self {
		return true
	}
	if l.AdminURL == "" {
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusServiceUnavailable, "no leader currently elected; retry shortly")
		return false
	}
	loc := strings.TrimRight(l.AdminURL, "/") + r.URL.RequestURI()
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusTemporaryRedirect)
	return false
}

// rebuildAndApply runs the merge/validate/compile pipeline against
// the supplied snapshot and installs the result through the Applier.
// It is the single place that touches the engine.
func (s *Server) rebuildAndApply(snap state.Snapshot, source string) error {
	yamlBytes := s.opts.YAMLProvider()
	cfg, err := policy.MergeFromYAML(yamlBytes, snap)
	if err != nil {
		return err
	}
	return s.opts.Applier.Apply(cfg, source)
}

// previewMerge tries to build a *Config without committing it, used
// to validate a candidate snapshot before persisting it. The
// resulting Config is discarded (its facts registry is never started)
// so this is cheap.
func (s *Server) previewMerge(snap state.Snapshot) error {
	yamlBytes := s.opts.YAMLProvider()
	_, err := policy.MergeFromYAML(yamlBytes, snap)
	return err
}

// currentTokenForTest is a test hook.
func (s *Server) currentTokenForTest() string {
	if p := s.token.Load(); p != nil {
		return *p
	}
	return ""
}
