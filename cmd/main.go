// request-validator is a generic ext-authz HTTP service that decides
// allow / deny for incoming requests based on a declarative YAML policy.
//
// Designed to plug behind Envoy/Istio (with `with_request_body` enabled when
// the policy inspects the body).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"request-validator/internal/configwatch"
	"request-validator/internal/httpserver"
	"request-validator/internal/log"
	"request-validator/internal/policy"
)

// version is injected at build time via -ldflags="-X main.version=<semver>".
var version = "dev"

func main() {
	var (
		port            = flag.Int("port", 8080, "HTTP server port")
		configPath      = flag.String("config", "policy.yaml", "Path to the policy file")
		level           = flag.String("log-level", "", "Override logging.level from the policy file (debug|info|warn|error)")
		format          = flag.String("log-format", "", "Override logging.format from the policy file (json|console)")
		watch           = flag.Bool("watch", true, "Auto-reload the policy when the config file changes")
		watchDebounceMs = flag.Int("watch-debounce-ms", 200, "Debounce window for the config file watcher")
		showVersion     = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := policy.LoadFile(*configPath)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	applyLogging(cfg.Logging, *level, *format)
	if err := cfg.Start(ctx); err != nil {
		log.Fatalf("start facts: %v", err)
	}
	logLoaded("policy loaded", *configPath, cfg)

	srv := httpserver.New(cfg)

	// Single function used by every reload trigger (SIGHUP and fsnotify).
	// The new config replaces the old one atomically; the old facts
	// registry is stopped after the swap so in-flight requests still see
	// a consistent view of the previous data.
	reload := func(source string) {
		newCfg, err := policy.LoadFile(*configPath)
		if err != nil {
			log.Errorw("reload failed; keeping previous policy",
				"source", source, "err", err.Error())
			return
		}
		if err := newCfg.Start(ctx); err != nil {
			log.Errorw("reload failed; keeping previous policy",
				"source", source, "err", err.Error())
			return
		}
		applyLogging(newCfg.Logging, *level, *format)
		old := srv.SetPolicy(newCfg)
		if old != nil {
			old.Stop()
		}
		logLoaded("policy reloaded", *configPath, newCfg, "source", source)
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
				reload("sighup")
			}
		}
	}()

	// Auto-reload on config file change (default on; opt-out with --watch=false).
	if *watch {
		go func() {
			debounce := time.Duration(*watchDebounceMs) * time.Millisecond
			err := configwatch.Run(ctx, *configPath, debounce, func() { reload("fsnotify") })
			if err != nil {
				log.Errorw("config watcher stopped",
					"err", err.Error(),
					"hint", "send SIGHUP to reload manually")
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(fmt.Sprintf(":%d", *port)) }()

	select {
	case <-stop:
		log.Infow("shutting down")
		srv.Stop()
		// Stop the shared-source goroutines belonging to the policy that
		// was current at shutdown time.
		if p := srv.Policy(); p != nil {
			p.Stop()
		}
	case err := <-errCh:
		if err != nil {
			log.Errorw("server crashed", "err", err.Error())
			os.Exit(1)
		}
	}
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
