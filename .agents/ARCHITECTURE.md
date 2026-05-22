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
  policy/             config types, YAML parser, evaluator, Merge(YAML + overlay)
  configwatch/        fsnotify wrapper, debounce, k8s ConfigMap-aware
  httpserver/         /healthz, /readyz, /metrics, ext-authz endpoint
  state/              Store interface for the replicated admin overlay
  state/memory/       in-memory Store (standalone mode + tests); optional JSON file
  state/configmap/    Kubernetes ConfigMap Store with shared informer + If-Match
  cluster/            leader election via Kubernetes Lease (client-go/tools/leaderelection)
  adminapi/           CRUD HTTP API on a separate port, bearer-token auth,
                      surfaces /api/v1/{groups,facts,defaults,logging,config,cluster}
  metrics/            small Prometheus counter registry used by httpserver/metrics.go
```

The dependency graph is acyclic and one-directional:

```
cmd  ──►  policy   ──►  facts
              │           │
              ├──►  celenv  ──►  jsonpath
              │
cmd  ──►  httpserver  ──►  policy
cmd  ──►  configwatch
cmd  ──►  state    ──►  state/memory | state/configmap
cmd  ──►  cluster
cmd  ──►  adminapi ──►  state, cluster, policy
cmd  ──►  log         (everyone else also imports log)
```

`log` and `metrics` are the only packages every other one may depend
on. They must stay dependency-free of the rest.

## Config types (at runtime)

`policy.Config` is the parsed YAML plus compiled state, possibly merged
with overrides from the state store:

```
Config{
  Defaults  Defaults                  // action, denyStatus, denyBody, maxBodyBytes, allowOnError
  Logging   Logging                   // level, format, exclude/redact headers, etc.
  Facts     []facts.Spec              // declared facts
  Groups    []Group                   // ordered list of rule buckets (priority asc, declaration as tiebreaker)

  // not in YAML, set during LoadBytes / Merge:
  env       *celenv.Env               // shared CEL env + program cache
  registry  *facts.Registry           // facts runtime (with URL fetchers etc.)
}
```

A `Group` carries a `Priority int` (default 0; smaller = evaluated
earlier; ties broken by stable order of declaration, with YAML groups
preceding API-provided ones on equal priority). It also carries its
compiled `matchProg cel.Program`, and each `Rule` carries its own.
Compilation happens once in `LoadBytes()` / `Merge()`; the request
path only executes already-compiled programs.

### Effective config (YAML + state overrides)

The engine never sees the raw YAML or the replicated state in isolation; it
sees an **effective** `*Config` produced by merging both:

```
LoadBytes(yaml)  ─┐
                  ├──► Merge(yaml, store.Snapshot()) ──► validate ──► compile ──► atomic.Swap
store.Snapshot() ─┘
```

Merge rules (uniform across all sections):

- `groups` and `facts`: the union of YAML and overlay entries, keyed by
  `name`. If a name exists in both, the **state entry wins** (override).
  Deletes hide the YAML entry with the same name.
- `defaults` and `logging`: per-field override. Any field present in
  the state register replaces the YAML value; absent fields keep
  the YAML value. Unsetting a field via API (PUT with the field absent
  / null) restores the YAML value.

The merged Group list is then sorted by `(priority asc, source order)`
before compilation, so the evaluator iterates a single deterministic
sequence.

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

Three triggers, same code path:

- **fsnotify** (default, on by default): the parent directory of the
  policy file is watched. `configwatch.relevant()` reacts to events on
  the file itself OR on the `..data` symlink that Kubernetes flips when
  a ConfigMap projection is updated. Events are debounced (200 ms by
  default) and converge into a single reload.
- **SIGHUP**: classic, useful when fsnotify doesn't deliver (NFS, FUSE).
- **State watch**: a successful admin API write on the leader, or a
  ConfigMap revision observed by the local informer (any replica),
  triggers a rebuild via the same function.

A reload performs:

1. Read the current YAML bytes (already cached in `cmd/main.go`).
2. `policy.MergeFromYAML(yaml, store.Snapshot())` - apply API
   overrides on top.
3. `newCfg.Start(ctx)` - initial fetch of URL facts.
4. If any step fails, **log error and keep previous policy**.
5. `srv.SetPolicy(newCfg)` - atomic swap; returns the previous `*Config`.
6. `oldCfg.Stop()` - cancel the previous fetcher goroutines.

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

### ext-authz port (default 8080)

| Path       | Purpose                                                                 |
| ---------- | ----------------------------------------------------------------------- |
| `/`        | ext-authz check. Envoy POSTs the original request here.                 |
| `/healthz` | always 200 once the process is up.                                      |
| `/readyz`  | 200 only after the first policy is installed (used as readiness probe). |
| `/metrics` | Prometheus text format. Counters per (rule, outcome, dry_run).          |

`/` accepts any method and path; it inspects whatever Envoy forwarded.
The ext-authz port MUST NOT serve admin endpoints.

### admin port (default 8081, disabled if no token configured)

See "Admin API" below for the full surface.

## Replication model

The admin API mutates a small piece of replicated state shared by every
replica: the "admin overlay". In Kubernetes deployments this lives in
a single ConfigMap; in standalone mode (no Kubernetes available) it
falls back to an in-memory store with optional JSON persistence.

Leader election is delegated to a `Lease` in the
`coordination.k8s.io/v1` API. The k8s API server arbitrates which pod
holds the Lease at any moment; everyone else is a follower. The
holder identity we publish into the Lease is `<podName>|<adminURL>`,
so followers can compute the redirect Location for incoming writes
without an extra round-trip.

### State store (`internal/state`)

`state.Store` is the abstraction the admin API and the engine consume:

```
type Store interface {
    Snapshot(ctx)                       (Snapshot, error)
    Get(ctx, section, key)              (Entry, error)
    Put(ctx, section, key, payload, ifMatch) (Revision, error)
    Delete(ctx, section, key, ifMatch)  error
    Watch(ctx)                          (<-chan ChangeEvent, error)
    Close()                             error
}
```

Two implementations live under `internal/state/`:

- **`memory.Store`** (subpackage `memory`): a map + RWMutex, with
  optional persistence to a local JSON file written via
  `tmp → fsync → rename → fsync(dir)`. Used in standalone mode and
  in tests. Watch emits in-process notifications.
- **`configmap.Store`** (subpackage `configmap`): backed by a single
  ConfigMap in a configurable namespace, with a key
  `state.json` holding the full overlay payload. Reads come from a
  SharedIndexInformer cache; writes do `Update` against the API
  server with `resourceVersion` as the optimistic concurrency
  token (a 409 from kube-apiserver becomes `state.ErrConflict`,
  which the admin API surfaces as 412 Precondition Failed). Watch
  fans out informer Updates plus a low-frequency poll backstop
  (every 500 ms) so a missed watch event never leaves a replica
  stuck on a stale view.

### Cluster (`internal/cluster`)

`cluster.Cluster` is a thin wrapper over
`k8s.io/client-go/tools/leaderelection`. Owns:

- The Lease lifecycle: acquire, renew, release on context cancel.
- A `Leader()` snapshot readable from the admin API's hot path
  (atomic pointer, no locks).
- A standalone fallback: when the cluster is constructed with a nil
  client, `IsLeader()` always returns true and `Standalone()` is
  true. Useful for `go run` and tests.

Bootstrap is a single call: `cluster.Bootstrap(ctx, opts)`. There is
no concept of "first replica" or `--cluster-bootstrap`: the Lease is
created lazily by whoever wins the first acquisition. Joining is
implicit (the kubelet's pod IP makes the pod reachable; the Lease
identity carries the admin URL).

## Admin API (`internal/adminapi`)

CRUD over the state store. Listens on the admin port. Auth: a single
bearer token read from `--admin-token-file`; the file is watched with
fsnotify and re-read on change. No token configured → admin API is not
started at all.

| Method | Path                                  | Notes                                                    |
| ------ | ------------------------------------- | -------------------------------------------------------- |
| GET    | `/api/v1/groups`                      | list of overlay-managed groups                           |
| GET    | `/api/v1/groups/{name}`               | single group; carries `Etag` for `If-Match`              |
| PUT    | `/api/v1/groups/{name}`               | upsert; **leader only**, followers reply 307             |
| DELETE | `/api/v1/groups/{name}`               | tombstone; **leader only**                               |
| GET    | `/api/v1/facts[/{name}]`              | idem for facts                                           |
| PUT    | `/api/v1/facts/{name}`                | **leader only**                                          |
| DELETE | `/api/v1/facts/{name}`                | **leader only**                                          |
| GET    | `/api/v1/defaults`                    | current overlay defaults (404 if unset)                  |
| PUT    | `/api/v1/defaults`                    | replace; **leader only**                                 |
| DELETE | `/api/v1/defaults`                    | clear; YAML defaults take over again; **leader only**    |
| GET    | `/api/v1/logging`                     | idem                                                     |
| PUT    | `/api/v1/logging`                     | **leader only**                                          |
| DELETE | `/api/v1/logging`                     | **leader only**                                          |
| GET    | `/api/v1/config`                      | effective `*Config` currently serving traffic            |
| GET    | `/api/v1/cluster`                     | who is leader, am I leader, lease until, standalone bool |
| GET    | `/api/v1/openapi.json`                | generated OpenAPI 3.1 spec of this API                   |

Write semantics on the leader:

1. Process-wide write mutex serialises concurrent PUTs.
2. Build a hypothetical `Snapshot` with the change applied to a copy.
3. Run `policy.MergeFromYAML(yaml, hypothetical)`; on failure, 400.
4. Commit to the real store with `If-Match` honoured (412 on mismatch).
5. Trigger a local rebuild + atomic Config swap so the caller has
   read-your-writes immediately. Other replicas pick up the change
   via the store's Watch.

Write semantics on a follower:

- Reply with 307 Temporary Redirect and `Location` set to the
  leader's `adminURL + r.URL.RequestURI()`.
- If no leader is known yet (just after a Lease transition),
  respond 503 with `Retry-After: 2`.

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
