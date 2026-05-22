// request-validator is a generic ext-authz HTTP service that decides
// allow / deny for incoming requests based on a declarative YAML policy.
//
// Designed to plug behind Envoy/Istio (with `with_request_body` enabled when
// the policy inspects the body).
//
//	@title						request-validator admin API
//	@version					v1
//	@description				CRUD over the overlay sections of the policy (groups, facts, defaults, logging). The YAML loaded at boot is the floor; admin writes overlay it per-key and are replicated to peer replicas via a Kubernetes ConfigMap + Lease.
//	@BasePath					/
//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				Send 'Bearer <token>'. The token is the contents of --admin-token-file on the server.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"request-validator/internal/adminapi"
	"request-validator/internal/cluster"
	"request-validator/internal/configwatch"
	"request-validator/internal/httpserver"
	"request-validator/internal/log"
	rvmetrics "request-validator/internal/metrics"
	"request-validator/internal/policy"
	"request-validator/internal/state"
	"request-validator/internal/state/configmap"
	"request-validator/internal/state/memory"
)

// version is injected at build time via -ldflags="-X main.version=<semver>".
var version = "dev"

func main() {
	var (
		port            = flag.Int("port", 8080, "ext-authz HTTP port")
		configPath      = flag.String("config", "policy.yaml", "Path to the policy file")
		level           = flag.String("log-level", "", "Override logging.level (debug|info|warn|error)")
		format          = flag.String("log-format", "", "Override logging.format (json|console)")
		watch           = flag.Bool("watch", true, "Auto-reload the policy on file changes (default true)")
		watchDebounceMs = flag.Int("watch-debounce-ms", 200, "Debounce window for the config file watcher")

		adminPort      = flag.Int("admin-port", 8081, "Admin API port; only started if --admin-token-file is set")
		adminTokenFile = flag.String("admin-token-file", "", "File holding the admin API bearer token; empty disables the admin API")

		namespace      = flag.String("namespace", "", "Kubernetes namespace for the state ConfigMap and Lease; defaults to in-pod namespace")
		stateConfigMap = flag.String("state-configmap", "request-validator-state", "Name of the ConfigMap that holds the admin overlay")
		leaderLease    = flag.String("leader-lease", "request-validator-leader", "Name of the Lease used for leader election")
		kubeconfig     = flag.String("kubeconfig", "", "Path to a kubeconfig file (empty = in-cluster config)")
		noKubernetes   = flag.Bool("no-kubernetes", false, "Disable all Kubernetes integration; use in-memory state with optional --state-file")
		stateFile      = flag.String("state-file", "", "Local JSON file for state persistence in standalone mode")

		showVersion = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Read the policy YAML up front so we have something to merge
	// against even before kube initialization completes.
	var yamlMu sync.RWMutex
	readYAML := func() ([]byte, error) {
		raw, err := os.ReadFile(*configPath)
		if err != nil {
			return nil, err
		}
		return []byte(os.ExpandEnv(string(raw))), nil
	}
	yamlBytes, err := readYAML()
	if err != nil {
		log.Fatalf("read policy: %v", err)
	}

	// Build the state store. Kubernetes when available, in-memory
	// otherwise (also forced by --no-kubernetes for tests / dev).
	var (
		store       state.Store
		clusterNode *cluster.Cluster
		kubeClient  kubernetes.Interface
		resolvedNS  string
	)
	if *noKubernetes || (*kubeconfig == "" && os.Getenv("KUBERNETES_SERVICE_HOST") == "") {
		log.Infow("starting in standalone mode (no kubernetes)")
		s, err := memory.New(memory.Options{Path: *stateFile})
		if err != nil {
			log.Fatalf("memory store: %v", err)
		}
		store = s
	} else {
		cfg, ns, err := buildKubeConfig(*kubeconfig, *namespace)
		if err != nil {
			log.Fatalf("kube config: %v", err)
		}
		resolvedNS = ns
		kubeClient, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			log.Fatalf("kube client: %v", err)
		}
		s, err := configmap.New(ctx, configmap.Options{
			Client:    kubeClient,
			Namespace: resolvedNS,
			Name:      *stateConfigMap,
		})
		if err != nil {
			log.Fatalf("configmap store: %v", err)
		}
		store = s
		log.Infow("kubernetes mode",
			"namespace", resolvedNS, "configmap", *stateConfigMap, "lease", *leaderLease)
	}

	// First compile of the effective config (YAML + whatever the
	// store already holds).
	initialSnap, err := store.Snapshot(ctx)
	if err != nil {
		log.Fatalf("initial snapshot: %v", err)
	}
	cfg, err := policy.MergeFromYAML(yamlBytes, initialSnap)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	applyLogging(cfg.Logging, *level, *format)
	if err := cfg.Start(ctx); err != nil {
		log.Fatalf("start facts: %v", err)
	}
	logLoaded("policy loaded", *configPath, cfg)

	srv := httpserver.New(cfg)

	// Centralised rebuild + atomic swap. Used by every reload trigger
	// (YAML fsnotify, SIGHUP, store watcher, admin write).
	var rebuildMu sync.Mutex
	rebuild := func(source string) error {
		rebuildMu.Lock()
		defer rebuildMu.Unlock()
		rvmetrics.Rebuilds.Inc(fmt.Sprintf("trigger=%q", source))

		yamlMu.RLock()
		yb := yamlBytes
		yamlMu.RUnlock()

		snap, err := store.Snapshot(ctx)
		if err != nil {
			rvmetrics.RebuildErrors.Inc()
			return fmt.Errorf("snapshot: %w", err)
		}
		newCfg, err := policy.MergeFromYAML(yb, snap)
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
		return nil
	}

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

	// Store watcher: trigger a rebuild every time the snapshot
	// changes (could be us, could be another replica).
	go func() {
		ch, err := store.Watch(ctx)
		if err != nil {
			log.Errorw("store watch failed", "err", err.Error())
			return
		}
		for ev := range ch {
			if err := rebuild("store"); err != nil {
				log.Errorw("rebuild after store change failed; keeping previous policy",
					"revision", string(ev.Revision), "err", err.Error())
			}
		}
	}()

	// Cluster (leader election). Skipped if no kube client.
	podName := os.Getenv("HOSTNAME")
	if podName == "" {
		podName = "rv-local"
	}
	adminURL := fmt.Sprintf("http://%s:%d", podName, *adminPort)
	clusterNode, err = cluster.Bootstrap(ctx, cluster.Options{
		Client:    kubeClient,
		Namespace: resolvedNS,
		LeaseName: *leaderLease,
		PodName:   podName,
		AdminURL:  adminURL,
	})
	if err != nil {
		log.Fatalf("cluster bootstrap: %v", err)
	}

	// Admin API (optional).
	var adminSrv *adminapi.Server
	if *adminTokenFile != "" {
		adminSrv, err = adminapi.New(adminapi.Options{
			Addr:      fmt.Sprintf(":%d", *adminPort),
			TokenFile: *adminTokenFile,
			Store:     store,
			Cluster:   clusterNode,
			YAMLProvider: func() []byte {
				yamlMu.RLock()
				defer yamlMu.RUnlock()
				out := make([]byte, len(yamlBytes))
				copy(out, yamlBytes)
				return out
			},
			Applier: applier,
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
		_ = store.Close()
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

// buildKubeConfig returns a kube rest.Config plus the namespace to
// use. Order of preference:
//
//  1. --kubeconfig flag if non-empty.
//  2. In-cluster config (uses the pod's service account).
//
// The namespace falls back to /var/run/secrets/.../namespace when
// running in-cluster, then to the --namespace flag, then to "default".
func buildKubeConfig(kubeconfigPath, nsOverride string) (*rest.Config, string, error) {
	if kubeconfigPath != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, "", err
		}
		ns := nsOverride
		if ns == "" {
			ns = "default"
		}
		return cfg, ns, nil
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, "", err
	}
	ns := nsOverride
	if ns == "" {
		if b, rerr := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); rerr == nil {
			ns = strings.TrimSpace(string(b))
		}
	}
	if ns == "" {
		ns = "default"
	}
	return cfg, ns, nil
}

type applierFunc struct {
	apply func(*policy.Config, string) error
}

func (a *applierFunc) Apply(c *policy.Config, src string) error { return a.apply(c, src) }

// logLoaded emits a single consistent log line for both the initial
// load and subsequent reloads.
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

// applyLogging rebuilds the global logger from the policy's logging
// block. The CLI flags --log-level / --log-format override the file
// values when non-empty.
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
