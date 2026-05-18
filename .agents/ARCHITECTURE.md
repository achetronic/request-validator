# ARCHITECTURE.md

How the project is laid out, how a request flows through it, and how
state evolves over the process's lifetime.

## Packages and what each one owns

```
cmd/                  main.go: flag parsing, signal handling, lifecycle
internal/
  log/                slog wrapper, dynamic level + json/console handlers
  celenv/             CEL environment, custom functions, program cache
  jsonpath/           tiny JSONPath subset (used by `jsonPath` CEL fn)
  facts/              facts registry: inline values, file reads, URL fetchers
  policy/             config types, YAML parser, evaluator
  configwatch/        fsnotify wrapper, debounce, k8s ConfigMap-aware
  httpserver/         /healthz, /readyz, /metrics, ext-authz endpoint
```

The dependency graph is acyclic and one-directional:

```
cmd  ──►  policy ──►  facts
              │        │
              ├──►  celenv  ──►  jsonpath
              │
cmd  ──►  httpserver  ──►  policy
cmd  ──►  configwatch
cmd  ──►  log         (everyone else also imports log)
```

`log` is the only package every other one depends on. It must stay
dependency-free of the rest.

## Config types (at runtime)

`policy.Config` is the parsed YAML plus compiled state:

```
Config{
  Defaults  Defaults                  // action, denyStatus, denyBody, maxBodyBytes, allowOnError
  Logging   Logging                   // level, format, exclude/redact headers, etc.
  Facts     []facts.Spec              // declared facts
  Groups    []Group                   // ordered list of rule buckets

  // not in YAML, set during LoadBytes:
  env       *celenv.Env               // shared CEL env + program cache
  registry  *facts.Registry           // facts runtime (with URL fetchers etc.)
}
```

A `Group` carries its compiled `matchProg cel.Program`, and each `Rule`
carries its own. Compilation happens once in `LoadBytes()`; the request
path only executes already-compiled programs.

## Request lifecycle

```
                    ┌──────────────┐
   incoming HTTP ──►│ httpserver.  │
                    │ handle()     │
                    └──────┬───────┘
                           │  1. load atomic policy pointer
                           │  2. read body up to maxBodyBytes
                           │  3. build policy.Request{...}
                           ▼
                    ┌──────────────┐
                    │ policy.      │  4. snapshot facts (atomic per-entry)
                    │ Evaluate()   │  5. build CEL activation map
                    └──────┬───────┘     {request: ..., facts: ...}
                           │
              ┌────────────┴────────────┐
              │ for each Group, in order│
              └────────────┬────────────┘
                           │ 6. group.matchProg → bool
                           │    (skip silently if false)
                           ▼
              ┌──────────────────────────┐
              │ Group.Mode == firstMatch │  every rule:
              │   or == all              │    rule.matchProg → bool
              └──────────────┬───────────┘    + action inheritance
                             ▼                + dryRun + fallthrough
                       ┌──────────┐
                       │ Decision │
                       │ {Allowed,│
                       │  Rule,   │
                       │  Reason, │
                       │  DryRun} │
                       └─────┬────┘
                             │ 7. set x-rv-* response headers
                             │ 8. emit one access-log record
                             ▼
                       200 OK / 403 (configurable)
```

There is exactly **one** access-log record per request, level `INFO` for
allow / `WARN` for deny. The CEL programs were compiled at policy load,
so the only per-request cost is body read + map build + a few CEL calls.

## CEL environment (`internal/celenv`)

Built once per policy load, in `celenv.New()`:

- Variables declared: `request` (dyn) and `facts` (dyn).
- Standard library + these extensions enabled:
  `ext.Strings()`, `ext.Encoders()`, `ext.Lists()`, `ext.Sets()`,
  `ext.Math()`, `ext.Bindings()`.
- Custom functions split by family across files:
  - `net.go` - `inCIDR`, `ipFamily`, `isPrivateIP`, `isLoopbackIP`, `parseURL`
  - `strings.go` - `glob`, `globAny` (RE2 under the hood, cached)
  - `encoding.go`- `sha256Hex`, `parseJWTUnverified`
  - `time.go` - `now()`
  - `data.go` - `jsonPath`, `parseJSON`, `parseYAML`
  - `http.go` - `has(name, bucket)`, `firstOr(bucket, name, default)`

Compiled programs are cached by source string in `Env.cache`. The cache
is process-lifetime; on policy reload a fresh `Env` is built and the old
one is GC'd along with the old `Config`.

When adding a new function, follow the per-family file layout. Each lib
implements `cel.SingletonLibrary` so they're easy to plug into
`cel.NewEnv` via `cel.Lib(...)`.

## Facts lifecycle

Facts are values that CEL reads as `facts.<name>`. Three methods:

| Method | When loaded                                           | Type seen by CEL |
| ------ | ----------------------------------------------------- | ---------------- |
| value  | At `LoadBytes`, parsed from YAML inline               | as declared      |
| file   | At `Start()` (path read once into a string)           | string           |
| url    | At `Start()` (initial fetch) + every `interval` in bg | string           |

```
policy.LoadFile
   │
   ▼
policy.LoadBytes
   ├─ yaml.Unmarshal → Config{Defaults, Logging, Facts, Groups}
   ├─ applyDefaults
   ├─ validate
   ├─ celenv.New        ← every Compile() is cached
   ├─ facts.New(Facts)  ← builds Registry, value entries already populated
   └─ compile           ← turn match strings into cel.Program

cfg.Start(ctx)
   └─ for each fact:
         file → os.ReadFile  → store as string
         url  → http GET     → store as string + spawn goroutine
                                with time.Ticker(interval)
```

On each request, the evaluator calls `registry.Snapshot()` which builds
a `map[string]any` by reading every entry's `atomic.Pointer[any]`. This
is O(N) over the number of facts but lock-free.

A URL fetch failure **after** the initial success is logged at `WARN` and
the previous value is kept. The initial URL fetch failing **rejects the
policy load** - `Start()` returns an error and the caller keeps the
previous policy. This is fail-closed by design (see `DECISIONS.md`).

## Hot reload

Two triggers, same code path:

- **fsnotify** (default, on by default): the parent directory of the
  config file is watched. `configwatch.relevant()` reacts to events on
  the file itself OR on the `..data` symlink that Kubernetes flips when
  a ConfigMap projection is updated. Events are debounced (200 ms by
  default) and converge into a single reload.
- **SIGHUP**: classic, useful when fsnotify doesn't deliver (NFS, FUSE).

A reload performs:

1. `policy.LoadFile(path)` - parse + compile + build fresh facts registry.
2. `newCfg.Start(ctx)` - initial fetch of URL facts.
3. If step 1 or 2 fails, **log error and keep previous policy**.
4. `srv.SetPolicy(newCfg)` - atomic swap; returns the previous `*Config`.
5. `oldCfg.Stop()` - cancel the previous fetcher goroutines.

In-flight requests started before the swap still see the old `Config` via
the pointer they captured; new requests see the new one. The
`logger` is reconfigured separately in `cmd/main.go::applyLogging` so
level/format changes apply on reload too.

## Logging

`internal/log` wraps `log/slog`. Public API:

```
log.Configure(Options{Level, Format, Writer})  // build the global logger
log.SetLevel(name)                              // change level dynamically
log.Logger()                                    // get *slog.Logger
log.Debugw|Infow|Warnw|Errorw(msg, key, val...) // sugared helpers
log.Fatalf(format, args...)                     // for boot-time fatals
```

The handler is stored in `atomic.Pointer[slog.Logger]`. `Configure()` is
safe to call from any goroutine. Levels are managed via a shared
`slog.LevelVar` so SetLevel doesn't rebuild the handler.

The per-request access log is built in `httpserver/access.go`. Headers
are normalised to lowercase, excluded headers dropped, redacted ones
masked. The redaction policy: a value of length `< 2 * redactReveal` is
fully masked; otherwise the first `redactReveal` characters are shown
and the rest replaced with `*`.

## HTTP server endpoints

| Path       | Purpose                                                                 |
| ---------- | ----------------------------------------------------------------------- |
| `/`        | ext-authz check. Envoy POSTs the original request here.                 |
| `/healthz` | always 200 once the process is up.                                      |
| `/readyz`  | 200 only after the first policy is installed (used as readiness probe). |
| `/metrics` | Prometheus text format. Counters per (rule, outcome, dry_run).          |

`/` accepts any method and path; it inspects whatever Envoy forwarded.

## Build & ship

- `Dockerfile` produces a `gcr.io/distroless/static:nonroot` image with
  the static binary at `/request-validator`. Multi-arch with
  `docker buildx`, fed by `--platform=$BUILDPLATFORM` in build stage.
- `Makefile` exposes `build`, `package`, `package-signature`,
  `docker-build`, `docker-buildx`, `test`, `race`.
- `.github/workflows/`:
  - `ci.yaml` - runs on every push/PR (`vet`, `test`, `test -race`, build).
  - `release-binaries.yaml` - matrix `linux/darwin × amd64/arm64`,
    uploads tarballs + md5 + sha256 to the GitHub Release.
  - `release-docker-images.yaml` - multi-arch image to GHCR.
    Both release workflows accept `workflow_dispatch` with a
    `checkout_master` toggle so artefacts can be re-cut from `master`
    without moving the tag.
