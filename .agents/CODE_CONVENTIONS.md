# CODE_CONVENTIONS.md

Conventions specific to this repo. Standard Go style applies; this file
only lists the points where we have a house preference or a hard rule.

## Go version and modules

- Track Go 1.23. Bumps are fine when they bring something we need;
  update `go.mod`, the `Dockerfile`, and the CI workflow at the same
  time.
- All app code lives under `internal/`. No `pkg/` directory - we have
  no public Go API to expose; the contract is the HTTP service + the
  YAML schema.
- `cmd/main.go` is intentionally short: flag parsing, logger setup,
  policy load, signal wiring, shutdown. Anything more complex moves
  into a package under `internal/`.

## Packages

- Package names are short, lowercase, no underscores: `policy`,
  `httpserver`, `celenv`, `facts`, `configwatch`, `log`, `jsonpath`.
- Each package has one job; if a package starts containing
  unrelated things, split it.
- Avoid `util/`, `helpers/`, `common/` - put helpers next to their use
  site or give them a meaningful package name.
- The dependency graph stays acyclic; see `ARCHITECTURE.md` for the
  current shape.

## Naming

- Types: `Config`, `Group`, `Rule`, `Decision`, `Spec`, `Registry`.
  Not `*T` (we used to; we don't anymore).
- Methods that mutate state are verbs: `Start`, `Stop`, `SetPolicy`,
  `Reload`. Methods that read are nouns: `Policy()`, `Snapshot()`.
- Errors are sentinel `Err*` only when callers will type-assert on
  them (`facts.ErrHTTP`). Otherwise use `fmt.Errorf("context: %w", err)`.

## Error handling

- Wrap with context: `fmt.Errorf("loading %q: %w", path, err)`. Never
  return a raw error from a deep call site without context.
- On the request hot path, an internal error becomes a `deny` (or
  `allow` if `defaults.allowOnError`). Never panic.
- `log.Fatalf` is reserved for boot-time fatal conditions in
  `cmd/main.go`. Anywhere else, return the error.

## Logging

- Always through `internal/log`. Never `fmt.Println` for diagnostics,
  never a second logger.
- One line per event. Key/value pairs, lowercase snake_case keys:
  `"remote_ip"`, `"rule"`, `"duration_ms"`.
- Levels:
  - `DEBUG` - verbose internal events (e.g. successful fact refresh).
  - `INFO` - normal operations (boot, reload, allow).
  - `WARN` - denied request, fact refresh failure, recoverable issue.
  - `ERROR` - invariant violated, crash imminent (handler-level).
- The per-request access log already covers the request shape. Don't
  duplicate that info in other lines.
- Never log secret material directly. The redaction rules in
  `httpserver/access.go` apply to headers and query params; when
  emitting custom logs from new code, follow the same pattern.

## Concurrency

- Hot paths (request handling, snapshot reads) use `atomic.Pointer[T]`
  for swap-on-reload. Avoid `sync.RWMutex` on per-request data.
- Background goroutines (fact fetchers, watchers) are owned by a
  `context.Context` cancelled by the owner (`Registry.Stop`,
  `configwatch.Run`'s ctx). Always have an exit path.
- Channels are sized to the work they carry: signal channels are
  buffered `1`, never `0` (avoid blocking the signal source).
- Tests with concurrency must run cleanly under `go test -race`.

## YAML and the policy DSL

- New top-level sections require:
  1. Updating `policy.Config` with a YAML tag.
  2. A default value in `applyDefaults` if appropriate.
  3. Validation in `validate`.
  4. An entry in `.agents/POLICY_DSL.md`.
  5. A line or short block in `examples/policy.yaml`.
  6. A test that loads it.
- Keep YAML keys camelCase to match the rest of the schema
  (`maxBodyBytes`, `denyStatus`, `redactReveal`).
- Numeric durations use Go duration syntax (`10m`, `5s`).
  Byte sizes use the `BytesSize` type (`1MiB`, `512KiB`, `1MB`,
  or plain bytes).

## CEL functions

- Implement in `internal/celenv/<family>.go`. One file per family
  (`net`, `strings`, `encoding`, `time`, `data`, `http`).
- Each library is a struct implementing `cel.SingletonLibrary`
  (i.e. `LibraryName`, `CompileOptions`, `ProgramOptions`).
- Function names follow camelCase: `inCIDR`, `parseJSON`, `headerHas`.
- Side-effect-free: deterministic, no I/O, no allocation surprises.
  If the function might fail (`parseURL` on bad input), return a
  sensible zero value, never panic.
- Register the function in `env.go::New()` alongside the other libs.
- Document it in `.agents/POLICY_DSL.md` and the README's function
  reference table.

## Tests

- File next to the code: `foo.go` ↔ `foo_test.go`.
- Use `httptest.NewServer` for HTTP server tests, never bind a real
  port.
- For fsnotify tests, use `t.TempDir()` so the test cleans up itself.
- Table-driven tests when the same logic is exercised with several
  inputs. Use the column headers `name`, `in`, `want`.
- An assertion that depends on a timestamp or a counter should be
  bounded with `waitFor(...)` / polling with a deadline, not a
  fixed `time.Sleep` (flaky in CI).

## Style points

- `gofmt`/`goimports` always. CI enforces it.
- Group imports: stdlib first, third party next, our own packages last.
  An empty line between groups.
- Doc comments on every exported identifier; the first sentence is a
  single line summary.
- 100 columns soft limit. Don't fight it - break long expressions for
  readability.

## What not to do

- **No** new top-level Go module. We're a single binary.
- **No** TLS termination in the binary. Envoy/Istio do that; we serve
  plain HTTP behind them.
- **No** dynamic library loading or plugin system (`plugin` package).
- **No** SQL, no Redis, no message brokers. The hot path is pure
  in-memory CEL evaluation; new external dependencies need a decision
  in `DECISIONS.md`.
- **No** corporate hostnames in tests/examples/fixtures/docs.
  See AGENTS.md hard rule #4.
- **No** admin endpoints on the ext-authz port. The CRUD API lives on
  its own listener; mixing them defeats the auth model.

## State, cluster and admin API

When touching `internal/{state,cluster,adminapi}`:

- **`state.Store` is the only contract the rest of the code knows**.
  Both backends (`memory` and `configmap`) implement the same
  interface; new backends should follow it without leaking
  Kubernetes / filesystem details to the admin API.
- **Reads from the hot path use cached snapshots, not the API
  server**: `Store.Snapshot()` returns the informer's view (for
  the ConfigMap backend) so per-request cost stays O(1) lookups.
- **Every store mutation routes through `policy.MergeFromYAML +
  Compile`**: never skip validation for "trusted" inputs. The
  validator is the only thing keeping the live `*Config` safe. The
  admin API validates against a *hypothetical* snapshot before
  committing to the real store.
- **Admin API handlers are thin**: parse → leader check (or 307) →
  validate → `state.Store.Put/Delete` → rebuild. Business logic
  stays out of HTTP handlers.
- **Auth is centralised in middleware**: every admin handler is
  wrapped by `requireBearer`; never check the token inline.
- **The cluster package depends only on `client-go`**. Do not pull
  the kube types into other packages; introduce a small wrapper
  type if you need to expose new state.
- **Followers serve reads, never writes**. New write endpoints must
  call `ensureLeaderOrRedirect` before mutating the store.
- **Tests for replicated logic** spin up two in-process nodes
  sharing a fake clientset and assert eventual convergence with a
  polling helper (see `TESTING.md`). Full-cluster verification
  uses `make e2e-kind`.
