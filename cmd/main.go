// request-validator is a generic ext-authz HTTP service that decides
// allow / deny for incoming requests based on a declarative YAML policy.
//
// Designed to plug behind Envoy/Istio (with `with_request_body` enabled when
// the policy inspects the body).
//
//	@title						request-validator admin API
//	@version					v1
//	@description				CRUD over the CRDT-backed sections of the policy: groups, facts, defaults, logging. The YAML loaded at boot is the floor; admin writes overlay it per-key and are gossiped to peer replicas. Every write rebuilds the effective config and either applies it atomically or quarantines the offending entry.
//	@BasePath					/
//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				Send 'Bearer <token>'. The token is the contents of --admin-token-file on the server.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"request-validator/internal/adminapi"
	"request-validator/internal/cluster"
	"request-validator/internal/configwatch"
	"request-validator/internal/crdt"
	"request-validator/internal/httpserver"
	"request-validator/internal/log"
	rvmetrics "request-validator/internal/metrics"
	"request-validator/internal/policy"
	"request-validator/internal/quarantine"
)

// version is injected at build time via -ldflags="-X main.version=<semver>".
var version = "dev"

func main() {
	var (
		port            = flag.Int("port", 8080, "HTTP server port (ext-authz)")
		configPath      = flag.String("config", "policy.yaml", "Path to the policy file")
		level           = flag.String("log-level", "", "Override logging.level from the policy file (debug|info|warn|error)")
		format          = flag.String("log-format", "", "Override logging.format from the policy file (json|console)")
		watch           = flag.Bool("watch", true, "Auto-reload the policy when the config file changes")
		watchDebounceMs = flag.Int("watch-debounce-ms", 200, "Debounce window for the config file watcher")

		adminPort      = flag.Int("admin-port", 8081, "Admin API port (only enabled if --admin-token-file is set)")
		adminTokenFile = flag.String("admin-token-file", "", "Path to a file containing the admin API bearer token; without it the admin API is disabled")
		stateFile      = flag.String("state-file", "", "Path to the CRDT state file; empty disables persistence (in-memory only)")

		clusterBind      = flag.String("cluster-bind", "", "Memberlist gossip bind addr (host:port); empty disables clustering")
		clusterAdvertise = flag.String("cluster-advertise", "", "Memberlist advertise addr (host:port); defaults to --cluster-bind")
		clusterPeers     = flag.String("cluster-peers", "", "Comma-separated host:port seed peers to join at boot")
		clusterDNS       = flag.String("cluster-discovery-dns", "", "DNS name to resolve periodically for peer discovery (e.g. a Kubernetes headless Service)")
		clusterDNSEvery  = flag.Duration("cluster-discovery-interval", 30*time.Second, "How often to re-resolve --cluster-discovery-dns")

		showVersion = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Raw YAML bytes are kept current via fsnotify so every rebuild (the
	// CRDT path, SIGHUP, fsnotify itself) sees the latest policy file.
	var yamlMu sync.RWMutex
	var yamlBytes []byte
	readYAML := func() ([]byte, error) {
		raw, err := os.ReadFile(*configPath)
		if err != nil {
			return nil, err
		}
		return []byte(os.ExpandEnv(string(raw))), nil
	}
	initialYAML, err := readYAML()
	if err != nil {
		log.Fatalf("read policy: %v", err)
	}
	yamlBytes = initialYAML

	// CRDT store: persist when --state-file is given.
	nodeID, err := resolveNodeID(*stateFile)
	if err != nil {
		log.Fatalf("resolve node id: %v", err)
	}
	store, err := crdt.New(crdt.Options{
		Node:      nodeID,
		StatePath: *stateFile,
	})
	if err != nil {
		log.Fatalf("crdt store: %v", err)
	}

	// Quarantine for changes that fail to compile when applied.
	q := quarantine.New()

	// Build the initial *Config via Merge so even the first load sees
	// any state that was restored from disk.
	cfg, err := policy.MergeFromYAML(initialYAML, store.Snapshot())
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	applyLogging(cfg.Logging, *level, *format)
	if err := cfg.Start(ctx); err != nil {
		log.Fatalf("start facts: %v", err)
	}
	logLoaded("policy loaded", *configPath, cfg)

	srv := httpserver.New(cfg)

	// Centralised rebuild + atomic swap. Used by every reload trigger.
	var rebuildMu sync.Mutex
	rebuild := func(source string) error {
		rebuildMu.Lock()
		defer rebuildMu.Unlock()
		rvmetrics.Rebuilds.Inc(fmt.Sprintf("trigger=%q", source))

		yamlMu.RLock()
		yb := yamlBytes
		yamlMu.RUnlock()

		newCfg, err := policy.MergeFromYAML(yb, store.Snapshot())
		if err != nil {
			rvmetrics.RebuildErrors.Inc()
			return fmt.Errorf("merge: %w", err)
		}
		if err := newCfg.Start(ctx); err != nil {
			rvmetrics.RebuildErrors.Inc()
			newCfg.Stop()
			return fmt.Errorf("start facts: %w", err)
		}
		applyLogging(newCfg.Logging, *level, *format)
		old := srv.SetPolicy(newCfg)
		if old != nil {
			old.Stop()
		}
		logLoaded("policy reloaded", *configPath, newCfg, "source", source)
		// Refresh the quarantine size gauge so /metrics reflects the
		// outcome of this rebuild attempt.
		rvmetrics.QuarantineSize.Set(`section="total"`, int64(q.Len()))
		return nil
	}

	// Adapt rebuild() for the adminapi.Applier interface. The admin API
	// already validated the merged Config; we still go through rebuild
	// so the YAML floor is fresh and the facts lifecycle is owned by
	// main.
	applier := &applierFunc{
		apply: func(_ *policy.Config, source string) error { return rebuild(source) },
	}

	// SIGHUP reload.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if err := rebuild("sighup"); err != nil {
					log.Errorw("reload failed; keeping previous policy",
						"source", "sighup", "err", err.Error())
				}
			}
		}
	}()

	// fsnotify reload: refresh yamlBytes first, then rebuild.
	if *watch {
		go func() {
			debounce := time.Duration(*watchDebounceMs) * time.Millisecond
			err := configwatch.Run(ctx, *configPath, debounce, func() {
				raw, rerr := readYAML()
				if rerr != nil {
					log.Errorw("reload failed; keeping previous policy",
						"source", "fsnotify", "err", rerr.Error())
					return
				}
				yamlMu.Lock()
				yamlBytes = raw
				yamlMu.Unlock()
				if err := rebuild("fsnotify"); err != nil {
					log.Errorw("reload failed; keeping previous policy",
						"source", "fsnotify", "err", err.Error())
				}
			})
			if err != nil {
				log.Errorw("config watcher stopped",
					"err", err.Error(),
					"hint", "send SIGHUP to reload manually")
			}
		}()
	}

	// Optional cluster.
	var clusterNode *cluster.Node
	var clusterAdapter *clusterBroadcastAdapter
	if *clusterBind != "" || *clusterDNS != "" {
		bind := *clusterBind
		if bind == "" {
			bind = "0.0.0.0:7946"
		}
		peers := splitNonEmpty(*clusterPeers)
		n, err := cluster.New(cluster.Options{
			NodeName:          nodeID,
			BindAddr:          bind,
			AdvertiseAddr:     *clusterAdvertise,
			Peers:             peers,
			DiscoveryDNS:      *clusterDNS,
			DiscoveryInterval: *clusterDNSEvery,
			Store:             store,
			OnDeltaApplied: func() {
				if err := rebuild("gossip"); err != nil {
					log.Warnw("rebuild after gossip delta failed; quarantining",
						"err", err.Error())
				}
			},
			OnApplyError: func(d crdt.Delta, err error) {
				q.Push(d.Section, d.Key, err.Error())
			},
		})
		if err != nil {
			log.Fatalf("cluster init: %v", err)
		}
		if err := n.Start(); err != nil {
			log.Fatalf("cluster start: %v", err)
		}
		clusterNode = n
		clusterAdapter = &clusterBroadcastAdapter{node: n}
		log.Infow("cluster: started", "node", nodeID, "addr", n.LocalAddr())
	}

	// Optional admin API.
	var adminSrv *adminapi.Server
	if *adminTokenFile != "" {
		var broadcaster adminapi.Broadcaster
		if clusterAdapter != nil {
			broadcaster = clusterAdapter
		}
		adminSrv, err = adminapi.New(adminapi.Options{
			Addr:       fmt.Sprintf(":%d", *adminPort),
			TokenFile:  *adminTokenFile,
			Store:      store,
			Quarantine: q,
			YAMLProvider: func() []byte {
				yamlMu.RLock()
				defer yamlMu.RUnlock()
				out := make([]byte, len(yamlBytes))
				copy(out, yamlBytes)
				return out
			},
			Broadcaster: broadcaster,
			Applier:     applier,
		})
		if err != nil {
			log.Fatalf("admin api init: %v", err)
		}
		if adminSrv != nil {
			go func() {
				if err := adminSrv.Run(); err != nil {
					log.Errorw("admin api stopped", "err", err.Error())
				}
			}()
		}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(fmt.Sprintf(":%d", *port)) }()

	select {
	case <-stop:
		log.Infow("shutting down")
		if adminSrv != nil {
			adminSrv.Stop()
		}
		srv.Stop()
		if clusterNode != nil {
			clusterNode.Stop()
		}
		if p := srv.Policy(); p != nil {
			p.Stop()
		}
		if err := store.Close(); err != nil {
			log.Warnw("crdt store flush failed", "err", err.Error())
		}
	case err := <-errCh:
		if err != nil {
			log.Errorw("server crashed", "err", err.Error())
			if adminSrv != nil {
				adminSrv.Stop()
			}
			if clusterNode != nil {
				clusterNode.Stop()
			}
			_ = store.Close()
			os.Exit(1)
		}
	}
}

// resolveNodeID derives a stable per-replica identifier. It tries, in
// order: a UUID persisted next to the state file; otherwise a fresh
// hostname-based one stamped into that directory; otherwise an
// in-memory random ID for stateless runs.
func resolveNodeID(stateFile string) (string, error) {
	host, _ := os.Hostname()
	if host == "" {
		host = "rv"
	}
	if stateFile == "" {
		return host + "-" + randomHex(4), nil
	}
	idFile := filepath.Join(filepath.Dir(stateFile), ".node-id")
	if b, err := os.ReadFile(idFile); err == nil {
		id := strings.TrimSpace(string(b))
		if id != "" {
			return id, nil
		}
	}
	id := host + "-" + randomHex(4)
	if err := os.MkdirAll(filepath.Dir(idFile), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(idFile, []byte(id), 0o644); err != nil {
		return "", err
	}
	return id, nil
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// Deterministic fallback; collisions are tolerable as a tie-
		// breaker for a single-process boot.
		for i := range buf {
			buf[i] = byte(i)
		}
	}
	return hex.EncodeToString(buf)
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// applierFunc adapts a closure to adminapi.Applier.
type applierFunc struct {
	apply func(newCfg *policy.Config, source string) error
}

func (a *applierFunc) Apply(newCfg *policy.Config, source string) error {
	return a.apply(newCfg, source)
}

// clusterBroadcastAdapter bridges adminapi.Broadcaster to *cluster.Node.
type clusterBroadcastAdapter struct {
	node *cluster.Node
}

func (a *clusterBroadcastAdapter) BroadcastDelta(d crdt.Delta) {
	a.node.BroadcastDelta(d)
}

// logLoaded emits a single consistent log line for both the initial load and
// subsequent reloads. Extra key/value pairs are appended verbatim.
func logLoaded(msg, path string, cfg *policy.Config, extra ...any) {
	rules := 0
	for _, g := range cfg.Groups {
		rules += len(g.Rules)
	}
	kv := []any{
		"version", version,
		"path", path,
		"groups", len(cfg.Groups),
		"rules", rules,
		"default", cfg.Defaults.Action,
	}
	kv = append(kv, extra...)
	log.Infow(msg, kv...)
}

// applyLogging rebuilds the global logger from the policy's logging block.
// The CLI flags --log-level / --log-format override the file values when
// they are non-empty so an operator can crank up verbosity at runtime
// without editing the ConfigMap.
func applyLogging(lg policy.Logging, levelFlag, formatFlag string) {
	lvl := lg.Level
	if levelFlag != "" {
		lvl = levelFlag
	}
	fmtName := lg.Format
	if formatFlag != "" {
		fmtName = formatFlag
	}
	opts := log.Options{Level: lvl, Format: log.Format(fmtName)}
	if err := log.Configure(opts); err != nil {
		log.Errorw("invalid logging configuration; keeping previous",
			"err", err.Error())
	}
}

// silence unused linter when builds disable some paths.
