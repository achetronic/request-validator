// Package log is a thin wrapper around log/slog that gives the rest of the
// project a single, opinionated logger.
//
// We wrap slog so the handler can be rebuilt at runtime (the policy file may
// toggle json/console and the log level on reload), so the short
// key/value entry points the codebase already uses (Infow, Errorw, etc.)
// keep working without slog ceremony, and so there is exactly one global
// logger that doesn't need to be threaded through every constructor.
//
// Output goes to stdout. Configure() is safe to call from any goroutine and
// every subsequent log call sees the new handler immediately.
package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Format chooses how log records are rendered.
type Format string

const (
	FormatJSON    Format = "json"
	FormatConsole Format = "console"
)

// Options drive the active logger configuration.
type Options struct {
	Level  string    // debug|info|warn|error (default "info")
	Format Format    // json|console (default json)
	Writer io.Writer // default os.Stdout
}

var (
	// levelVar lets us change the threshold without rebuilding the handler.
	levelVar = new(slog.LevelVar)

	// current holds the active slog.Logger behind an atomic pointer so the
	// hot path doesn't take any locks when emitting a record.
	current atomic.Pointer[slog.Logger]

	mu sync.Mutex
)

func init() {
	_ = Configure(Options{}) // boot with sane defaults
}

// Configure rebuilds the global logger with the given options. Safe to call
// from any goroutine; subsequent log calls see the new handler immediately.
func Configure(opts Options) error {
	mu.Lock()
	defer mu.Unlock()

	lvl, err := parseLevel(opts.Level)
	if err != nil {
		return err
	}
	levelVar.Set(lvl)

	w := opts.Writer
	if w == nil {
		w = os.Stdout
	}

	var h slog.Handler
	switch opts.Format {
	case FormatConsole:
		h = newConsoleHandler(w, levelVar)
	case "", FormatJSON:
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level: levelVar,
			ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
				// Render time as RFC3339 with millisecond precision for
				// easier reading. slog.JSONHandler defaults to RFC3339Nano.
				if a.Key == slog.TimeKey {
					return slog.String("time", a.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z"))
				}
				return a
			},
		})
	default:
		return fmt.Errorf("unknown log format %q (want json|console)", opts.Format)
	}

	current.Store(slog.New(h))
	return nil
}

// SetLevel changes the verbosity at runtime without rebuilding the handler.
func SetLevel(name string) error {
	lvl, err := parseLevel(name)
	if err != nil {
		return err
	}
	levelVar.Set(lvl)
	return nil
}

func parseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want debug|info|warn|error)", name)
}

// Logger returns the active slog.Logger. Use it when the caller wants the
// richer API (Attrs, With(), groups, etc.).
func Logger() *slog.Logger { return current.Load() }

// Short helpers that mirror the old key/value API used across the codebase.

func Debugw(msg string, kv ...any) { current.Load().Debug(msg, kv...) }
func Infow(msg string, kv ...any)  { current.Load().Info(msg, kv...) }
func Warnw(msg string, kv ...any)  { current.Load().Warn(msg, kv...) }
func Errorw(msg string, kv ...any) { current.Load().Error(msg, kv...) }

// Fatalf logs at error level and exits the process. Reserved for boot-time
// fatal conditions; never call it on the request path.
func Fatalf(format string, args ...any) {
	current.Load().Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// consoleHandler is a tiny, dependency-free renderer for terminal output.
// One line per record, with key=value pairs after the message. Time is
// HH:MM:SS.mmm.

type consoleHandler struct {
	w     io.Writer
	level *slog.LevelVar
	mu    *sync.Mutex
	group string
	attrs []slog.Attr
}

func newConsoleHandler(w io.Writer, level *slog.LevelVar) slog.Handler {
	return &consoleHandler{w: w, level: level, mu: &sync.Mutex{}}
}

func (h *consoleHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *consoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &cp
}

func (h *consoleHandler) WithGroup(name string) slog.Handler {
	cp := *h
	if h.group != "" {
		cp.group = h.group + "." + name
	} else {
		cp.group = name
	}
	return &cp
}

func (h *consoleHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Time.UTC().Format("15:04:05.000"))
	b.WriteByte(' ')
	b.WriteString(levelTag(r.Level))
	b.WriteByte(' ')
	b.WriteString(r.Message)

	for _, a := range h.attrs {
		writeAttr(&b, h.group, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, h.group, a)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func writeAttr(b *strings.Builder, prefix string, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		gp := prefix
		if a.Key != "" {
			if gp != "" {
				gp += "."
			}
			gp += a.Key
		}
		for _, sub := range a.Value.Group() {
			writeAttr(b, gp, sub)
		}
		return
	}
	b.WriteByte(' ')
	if prefix != "" {
		b.WriteString(prefix)
		b.WriteByte('.')
	}
	b.WriteString(a.Key)
	b.WriteByte('=')
	b.WriteString(formatValue(a.Value))
}

func formatValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if strings.ContainsAny(s, " =\t\n\"") {
			return fmt.Sprintf("%q", s)
		}
		return s
	case slog.KindInt64:
		return fmt.Sprintf("%d", v.Int64())
	case slog.KindUint64:
		return fmt.Sprintf("%d", v.Uint64())
	case slog.KindFloat64:
		return fmt.Sprintf("%g", v.Float64())
	case slog.KindBool:
		if v.Bool() {
			return "true"
		}
		return "false"
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("%v", v.Any())
}

func levelTag(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARN "
	case l >= slog.LevelInfo:
		return "INFO "
	default:
		return "DEBUG"
	}
}
