# TESTING.md

How tests are organised and how to run them.

## Layered test pyramid

```
                  ┌──────────────────────┐
                  │  manual E2E (rare)   │
                  └──────────────────────┘
                ┌──────────────────────────┐
                │  integration (in repo)   │     httptest + facts URL + bufconn
                └──────────────────────────┘
              ┌────────────────────────────────┐
              │  unit (per package)            │     table-driven, small
              └────────────────────────────────┘
```

Most coverage lives in the unit/integration layers. The CI workflow
runs both. Manual E2E (with a real binary against a fake feed) is what
you do when paranoid - see "Manual end-to-end recipe" below.

## Running

```bash
# the three commands CI runs:
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
```

The Makefile aliases these:

```bash
make vet
make test
make race
```

Tests are deterministic. A flaky test is a bug; fix it before the bug
becomes invisible.

## Layout

- One `_test.go` per source file when the test is unit-scope.
- Cross-package tests (e.g. `policy_facts_test.go`) live in the
  package that owns the orchestration, not the dependency.
- `t.TempDir()` for any test that touches the filesystem.
- `httptest.NewServer` for HTTP collaborators. Never bind a real port.

## What each package's tests cover

| Package       | What's covered                                                                                                                  |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `celenv`      | Smoke test of every custom function (inCIDR, glob, parseJSON, parseURL, sha256Hex, jsonPath, now, has, firstOr, isPrivateIP...) |
| `configwatch`       | In-place write, save-via-rename, kubelet `..data` swap, debounce of bursts                                                              |
| `facts`             | inline values, file source, URL fetch + refresh, URL fetch failure keeps previous value, validation (dupes, missing fields)             |
| `httpserver`        | Allow/deny end-to-end, DCR body validation, hot-reload swap, access log (exclude/redact headers, query redact, console + json)          |
| `policy`            | Evaluator (firstMatch / all / dryRun / fallthrough / action inheritance / priority order), Merge(YAML + overlay), URL fact integration  |
| `state/memory`      | Put/Get/Delete round-trip, If-Match (`*` and exact), persist + reload, Watch fires on mutation                                          |
| `state/configmap`   | ConfigMap auto-creation, optimistic concurrency via resourceVersion (and apierrors.IsConflict surfaced as ErrConflict), informer cache  |
| `cluster`           | Standalone always-leader, leader election against a fake clientset acquires the Lease, identity encode/decode                            |
| `adminapi`          | CRUD per section, bearer auth (missing/invalid/rotated token), validation error → 400, If-Match → 412, effective `/config`, `/cluster`  |

## Replicated-logic tests

For anything touching `cluster` or `state/configmap` convergence we
use `k8s.io/client-go/kubernetes/fake` and share the clientset
between the two test "nodes" so they see each other through the
fake API server. The store's poll backstop (every 500 ms) papers
over fake-clientset watch flakiness; real clusters use the informer
watch directly.

```go
// pseudo:
kc := fake.NewClientset()
a  := startNode(t, "A", kc, yaml)
b  := startNode(t, "B", kc, yaml)
ensureLeader(t, a, b)

putGroup(t, a, "foo", grp)        // follows the 307 if A is not leader

eventually(t, 5*time.Second, func() bool {
    return hasGroup(t, b, "foo")  // B observes via informer cache
})
```

Use `t.TempDir()` for any local file fixtures (token, in-memory state
files) and a polling helper, never `time.Sleep`. All goroutines drain
via `t.Cleanup`.

## End-to-end tests (`internal/e2e`)

Two layers, in the same package, gated by build tags:

| Layer          | Tag        | What it boots                                | Cost     | Run with                              |
| -------------- | ---------- | -------------------------------------------- | -------- | ------------------------------------- |
| in-process     | default    | two stacks sharing a fake k8s clientset      | ~3 s     | `go test ./internal/e2e/...`          |
| against Kind   | `e2cekind` | a real kind cluster, real ConfigMap + Lease  | ~60 s    | `make e2e-kind`                       |

The in-process layer (`harness_test.go` + `scenarios_test.go`) is
part of the default test run and validates the wiring between the
admin API, the state store, the leader-election fallback and the
ext-authz engine. The Kind layer (`kind_test.go`) is the catch-all
for "did we really break the manifests, the RBAC, or the deployment
shape" and is opt-in.

Scenarios in the in-process suite:

- Admin PUT replicates to the other replica via the ConfigMap.
- ext-authz endpoint on the *other* node reflects an overlay change
  (allow → deny by IP, group delete restores allow, defaults
  overlay swaps the deny status).
- Follower replies 307 Temporary Redirect to the leader on writes.
- **State survives a pod restart**: stop the leader, start a fresh
  replica against the same backing ConfigMap, the overlay is still
  there.
- **Deleting the state ConfigMap resets to the YAML floor**: stop
  the leader, delete the ConfigMap, start a fresh replica — only
  the YAML groups remain.
- **Leader transition routes writes**: kill the current leader, wait
  for the follower to acquire the Lease, then issue a write against
  it without redirects.
- **If-Match preconditions**: stale `If-Match` returns 412.

The Kind suite verifies that the manifests under
`internal/e2e/testdata/kind/` deploy, that the Deployment becomes
Ready (RBAC is correct: list+watch namespace-scoped, mutations
resourceName-scoped), that a PUT through `kubectl port-forward` is
honoured, and that the ext-authz endpoint reflects the change. It
needs `kind`, `docker` and `kubectl` in `PATH`.

## How to add a test

1. **Pick the package.** If the change is local to a function, the
   unit test goes next to it. If it crosses packages, put it in the
   highest-level one (typically `policy` or `httpserver`).
2. **Use table-driven shape** when several inputs hit the same logic:

   ```go
   cases := []struct {
       name string
       in   X
       want Y
   }{
       {"empty", X{}, Y{}},
       {"happy", X{...}, Y{...}},
       {"edge",  X{...}, Y{...}},
   }
   for _, tc := range cases {
       t.Run(tc.name, func(t *testing.T) {
           got := fn(tc.in)
           if got != tc.want { t.Fatalf("got %v want %v", got, tc.want) }
       })
   }
   ```

3. **Time-based assertions** use a polling helper, not a fixed
   `time.Sleep`:

   ```go
   deadline := time.Now().Add(2 * time.Second)
   for time.Now().Before(deadline) {
       if c.Load() >= 1 { return }
       time.Sleep(20 * time.Millisecond)
   }
   t.Fatal("expected ≥1, got", c.Load())
   ```

4. **HTTP tests** spawn an `httptest.NewServer` and pass the URL.
   The server stops automatically with `defer ts.Close()`.

5. **Race-sensitive code** must pass `go test -race`. If it doesn't,
   the fix is real (data race), not papering over.

## Manual end-to-end recipe

Useful when you want to see real logs against the actual binary and a
realistic policy. The session record at `examples/policy.yaml` covers
30+ canonical cases when paired with the script below.

```bash
# 1. build
make build VERSION=dev

# 2. run with the bundled example
./bin/$(go env GOOS)/$(go env GOARCH)/request-validator \
    --config examples/policy.yaml \
    --port 18080 \
    --log-level info \
    --log-format console &
SRV=$!

# 3. probe - adjust X-Forwarded-For to your scenario
curl -i -X POST \
  -H 'Host: auth.example-1.com' \
  -H 'Content-Type: application/json' \
  -H 'X-Forwarded-For: 160.79.108.42' \
  --data '{"redirect_uris":["https://x"]}' \
  http://127.0.0.1:18080/realms/mcp/clients-registrations

# 4. stop
kill $SRV
```

For tests that need a URL fact, run a tiny fake feed in background:

```go
http.HandleFunc("/feed.json", func(w http.ResponseWriter, _ *http.Request) {
    w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"99.99.99.0/24"}]}`))
})
http.ListenAndServe("127.0.0.1:19000", nil)
```

…and point a `facts:` entry at `http://127.0.0.1:19000/feed.json`.

## CI

`.github/workflows/ci.yaml` runs on every push and PR. It:

1. Reads the Go version from `go.mod`.
2. Runs `go vet ./...`.
3. Runs `go test ./...`.
4. Runs `go test -race ./...`.
5. Builds the binary (smoke compile).

Release workflows (`release-binaries`, `release-docker-images`) trigger
on a GitHub Release event or manual `workflow_dispatch` with a
`checkout_master` toggle. See `.github/workflows/`.

## Coverage

Not enforced today. We rely on the test pyramid and review. If you want
a quick local view:

```bash
go test -coverprofile=/tmp/c.out ./...
go tool cover -html=/tmp/c.out
```

If you find code that's hard to test, that's usually a design signal
(too many concerns in one function, hidden global state, etc.). Fix
the design first; the tests will follow.
