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
  crdt/               LWW-Map (groups, facts) + LWW-Register (defaults, logging),
                      local JSON persistence with debounce + fsync
  cluster/            hashicorp/memberlist wrapper: peer discovery, broadcast,
                      anti-entropy sync, delta application
  adminapi/           CRUD HTTP API on a separate port, bearer-token auth,
                      surfaces /api/v1/{groups,facts,defaults,logging,config,quarantine}
  quarantine/         buffer for gossiped or local changes that fail validation;
                      re-evaluated on every Config rebuild
```

The dependency graph is acyclic and one-directional:

```
cmd  ──►  policy ──►  facts
              │        │
              ├──►  celenv  ──►  jsonpath
              │
cmd  ──►  httpserver  ──►  policy
cmd  ──►  configwatch
cmd  ──►  crdt
cmd  ──►  cluster      ──►  crdt
cmd  ──►  adminapi     ──►  crdt, policy, quarantine
cmd  ──►  quarantine
cmd  ──►  log          (everyone else also imports log)
```

`log` is the only package every other one depends on. It must stay
dependency-free of the rest.

## Config types (at runtime)

`policy.Config` is the parsed YAML plus compiled state, possibly merged
with overrides from the CRDT store:

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
preceding CRDT-provided ones on equal priority). It also carries its
compiled `matchProg cel.Program`, and each `Rule` carries its own.
Compilation happens once in `LoadBytes()` / `Merge()`; the request
path only executes already-compiled programs.

### Effective config (YAML + CRDT overrides)

The engine never sees the raw YAML or the raw CRDT in isolation; it
sees an **effective** `*Config` produced by merging both:

```
LoadBytes(yaml) ─┐
                 ├──► Merge(yaml, crdt.Snapshot()) ──► validate ──► compile ──► atomic.Swap
crdt.Snapshot() ─┘
```

Merge rules (uniform across all sections):

- `groups` and `facts`: the union of YAML and CRDT entries, keyed by
  `name`. If a name exists in both, the **CRDT entry wins** (override).
  Tombstoned CRDT entries hide the YAML entry with the same name.
- `defaults` and `logging`: per-field override. Any field present in
  the CRDT LWW-Register replaces the YAML value; absent fields keep
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
  config file is watched. `configwatch.relevant()` reacts to events on
  the file itself OR on the `..data` symlink that Kubernetes flips when
  a ConfigMap projection is updated. Events are debounced (200 ms by
  default) and converge into a single reload.
- **SIGHUP**: classic, useful when fsnotify doesn't deliver (NFS, FUSE).
- **CRDT mutation**: a successful admin API write, or a gossiped delta
  applied to the local CRDT store, also triggers a rebuild via the same
  function. Debounced (50 ms) so bursts of gossip deltas converge into
  one rebuild.

A reload performs:

1. `policy.LoadFile(path)` - parse + compile + build fresh facts registry.
2. `policy.Merge(yamlCfg, crdt.Snapshot())` - apply API overrides.
3. `newCfg.Start(ctx)` - initial fetch of URL facts.
4. If any step fails, **log error and keep previous policy**. If the
   trigger was a CRDT delta, push the offending entries into
   `internal/quarantine`.
5. `srv.SetPolicy(newCfg)` - atomic swap; returns the previous `*Config`.
6. `oldCfg.Stop()` - cancel the previous fetcher goroutines.
7. Re-evaluate the quarantine buffer: any item that now compiles is
   removed; the rest stays until the next rebuild.

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

## Cluster (`internal/cluster`)

A thin wrapper over `github.com/hashicorp/memberlist`. Owns:

- **Peer discovery**: a list of seed addresses (`--cluster-peers`) or a
  DNS name (`--cluster-discovery-dns`, intended for a Kubernetes
  headless Service). Resolution is repeated periodically so new
  replicas joining a Deployment are picked up.
- **Broadcast queue**: outgoing deltas are appended to a `TransmitLimitedQueue`
  with retransmit factor tuned to the cluster size memberlist reports.
- **Anti-entropy**: memberlist's push/pull sync (every 30 s by default)
  exchanges full state digests, so a node missing deltas recovers.
- **Delta application**: incoming user messages are decoded and applied
  to the local `crdt.Store`. A successful apply triggers a debounced
  Config rebuild; a validation failure pushes the offending key into
  `internal/quarantine`.
- **Node identity**: `NodeID` is the memberlist node name, stable across
  the process lifetime. Used as the LWW tiebreaker.

The cluster package is optional. When `--cluster-peers` and
`--cluster-discovery-dns` are both empty, the node runs **standalone**:
the CRDT store still works, gossip is just not started. This keeps
single-replica deployments and tests trivial.

## CRDT store (`internal/crdt`)

Three CRDTs, all conflict-free and composable:

- **`LWWMap[K comparable, V any]`** - used by `groups` and `facts`. Each
  entry carries `{value V, ts int64, node string, tombstone bool}`.
  Merge per key: higher `ts` wins; on tie, lexicographic `node` wins.
  Deletes write a tombstone instead of removing the entry; tombstones
  GC after a configurable TTL (default 24 h).
- **`LWWRegister[V any]`** - used by `defaults` and `logging`. A single
  `{value V, ts int64, node string}`. Setting any field replaces the
  whole register (callers are expected to read-modify-write, then PUT).
- **Composite `Store`** - aggregates the four CRDTs above plus a
  `Snapshot()` method that returns a stable, copy-on-read view used by
  `policy.Merge`.

### Persistence

The store snapshots to a single JSON file (`--state-file`, default
`/var/lib/request-validator/state.json`). Writes use:

1. `write(tmp)` to a sibling tempfile.
2. `f.Sync()` (fsync of the file).
3. `os.Rename(tmp, final)` (atomic on POSIX).
4. fsync the parent directory.

Writes are debounced at 1 s. On boot, the file is read into the store
before gossip starts; gossip then fills any gaps from peers. If the
file is missing or corrupt, the node starts with an empty store and
relies on peers; if no peers respond within the discovery window, the
store stays empty and the YAML alone governs (fail-stable).

### Concurrency

Each map / register is guarded by a `sync.RWMutex`. Reads (`Snapshot`)
take RLock; writes take Lock. This is *not* the hot path - the hot path
sees the already-built `*policy.Config`, not the CRDT - so the lock is
acceptable. CRDT writes happen at admin-API frequency (low) and gossip
apply frequency (low-to-moderate).

## Admin API (`internal/adminapi`)

CRUD over the CRDT store. Listens on the admin port. Auth: a single
bearer token read from `--admin-token-file`; the file is watched with
fsnotify and re-read on change. No token configured → admin API is not
started at all.

| Method | Path                                  | Body / Effect                                              |
| ------ | ------------------------------------- | ---------------------------------------------------------- |
| GET    | `/api/v1/groups`                      | list of CRDT-managed groups                                |
| GET    | `/api/v1/groups/{name}`               | single group + `source` (`api`) + `quarantined` flag       |
| PUT    | `/api/v1/groups/{name}`               | upsert; body is the same shape as a YAML group             |
| DELETE | `/api/v1/groups/{name}`               | tombstone (hides the YAML-side homonym, if any)            |
| GET    | `/api/v1/facts`                       | idem for facts                                             |
| GET    | `/api/v1/facts/{name}`                |                                                            |
| PUT    | `/api/v1/facts/{name}`                |                                                            |
| DELETE | `/api/v1/facts/{name}`                |                                                            |
| GET    | `/api/v1/defaults`                    | current CRDT-side defaults (may be empty)                  |
| PUT    | `/api/v1/defaults`                    | replace the defaults register                              |
| DELETE | `/api/v1/defaults`                    | clear the register (YAML defaults take over again)         |
| GET    | `/api/v1/logging`                     | idem                                                       |
| PUT    | `/api/v1/logging`                     |                                                            |
| DELETE | `/api/v1/logging`                     |                                                            |
| GET    | `/api/v1/config`                      | the effective `*Config` currently serving traffic          |
| GET    | `/api/v1/quarantine`                  | list quarantined items with reasons                        |
| DELETE | `/api/v1/quarantine/{section}/{name}` | drop a quarantined entry without retrying                  |

Write semantics:

1. Acquire a process-wide write mutex (so concurrent PUTs serialise).
2. Apply the change to a *copy* of the CRDT store.
3. Build a candidate `*Config` via `policy.Merge` + validate + compile.
4. On failure: 400 with the validator error. The real store is untouched.
5. On success: commit to the real store, broadcast the delta via cluster,
   schedule a Config rebuild + atomic swap.

All write responses include the resulting object plus `Etag` derived
from `(name, ts, node)` for optimistic concurrency. PUTs accept an
`If-Match` header; mismatch → 412.

## Quarantine (`internal/quarantine`)

A small typed buffer:

```
type Entry struct {
    Section    string    // "groups" | "facts" | "defaults" | "logging"
    Name       string    // empty for singletons
    Payload    []byte    // raw CRDT value bytes
    Reason     string    // validator/compile error message
    Since      time.Time
    LastRetry  time.Time
    RetryCount int
}
```

Entries are pushed when:

- A gossiped delta arrives whose resulting `*Config` fails to compile.
- A rebuild attempt finds an inconsistency (e.g. group references a
  fact that no longer exists locally).

Re-evaluation happens on every Config rebuild (any rebuild, regardless
of trigger). Items that now compile are removed and integrated. Items
that still fail stay; `RetryCount` and `LastRetry` are updated.

The quarantine is *local per node*. It is **not** gossiped, because
each node may quarantine different items depending on what state it
holds. This is intentional - the gossiped CRDT remains the source of
truth; quarantine is just a deferred-apply queue.

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
