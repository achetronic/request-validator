# TODOs - feat/priority-and-admin-api

Persistent checklist for the multi-step feature branch. Tick items as
they land. If a session breaks, pick up from the first unchecked box.
Last section (final testing) must run green before opening the PR.

> Reference docs: `.agents/AGENTS.md`, `.agents/ARCHITECTURE.md`,
> `.agents/POLICY_DSL.md`, `.agents/DECISIONS.md` (D-014..D-019),
> `.agents/OPERATIONS.md`, `.agents/TESTING.md`, `.agents/GLOSSARY.md`.

## Phase 1 - `priority` on groups

- [x] Add `Priority int` (YAML tag `priority`) to `policy.Group`.
- [x] Default `priority` to `0` in `applyDefaults`.
- [x] Sort `Config.Groups` by `(priority asc, source-order)` in
      `LoadBytes` after validation.
- [x] Document the field in `examples/policy.yaml`.
- [x] Unit tests: mixed priorities, negatives, ties preserve order.
- [x] Update README's policy reference snippet (if any).

## Phase 2 - CRDT store (`internal/crdt`)

- [x] `LWWMap[K, V]` with `Put`, `Delete` (tombstone), `Get`, `Range`,
      `Merge(other)`, `Snapshot()`.
- [x] `LWWRegister[V]` with `Set`, `Clear`, `Get`, `Merge`.
- [x] `Store` composite: groups + facts (maps) + defaults + logging
      (registers) + `node` ID + clock source.
- [x] `Store.Snapshot()` returns a deep-copied, read-stable view used
      by `policy.Merge`.
- [x] JSON persistence: `Save(path)` with `write tmp → fsync → rename
      → fsync parent`, debounced at 1 s.
- [x] `Load(path)` on boot tolerates missing/corrupt files (start
      empty, log WARN).
- [x] Tombstone TTL with periodic GC.
- [x] Unit tests:
  - [x] LWW conflict resolution by `(ts, node)`.
  - [x] Merge is commutative + associative + idempotent (property-style).
  - [x] Tombstones hide entries; resurrection by older `Put` is blocked.
  - [x] Persist + reload round-trip.
  - [x] Atomic rename observed by a concurrent reader.

## Phase 3 - `policy.Merge` + atomic rebuild integration

- [x] `policy.Merge(yamlCfg *Config, snap crdt.Snapshot) (*Config, error)`:
      per-section override; produces a candidate `*Config` and runs
      the existing `validate + compile` pipeline.
- [x] Wire `Merge` into the boot path and the reload path; the
      `*Config` the engine sees is always the merged one.
- [x] Debounced rebuild trigger (50 ms) shared by fsnotify, SIGHUP and
      CRDT mutations.
- [x] Update `cmd/main.go::reload` to call `Merge` after `LoadFile`.
- [x] Tests:
  - [x] YAML-only path unchanged.
  - [x] CRDT override of a group (same name) replaces the YAML one.
  - [x] CRDT tombstone hides the YAML group with the same name.
  - [x] `defaults` / `logging` per-field override.
  - [x] Effective group order is `(priority, source-order)`.

## Phase 4 - Cluster (`internal/cluster`)

- [x] Thin wrapper around `github.com/hashicorp/memberlist`.
- [x] Config: bind addr, advertise addr, seed peers, DNS discovery
      name, refresh interval.
- [x] Outgoing broadcast: typed envelope `{v: 1, section, key, payload}`
      via `TransmitLimitedQueue`.
- [x] Incoming delegate: decode → `Store.Apply(delta)` → trigger
      rebuild.
- [x] Anti-entropy push/pull: full snapshot exchange on state sync.
- [x] Node ID: hostname + persisted UUID (in state file).
- [x] Standalone fallback when no peers/DNS configured: cluster
      package is a no-op.
- [x] Tests with 2-3 in-process nodes on loopback:
  - [x] PUT converges to all nodes within 5 s.
  - [x] Delete (tombstone) converges; resurrect-attempt is rejected.
  - [x] Node restart picks up state from peer (anti-entropy).
  - [x] Unknown envelope version is dropped with WARN.

## Phase 5 - Quarantine (`internal/quarantine`)

- [x] `Entry` struct (section, name, payload, reason, since,
      lastRetry, retryCount).
- [x] `Buffer.Push(entry)`, `Buffer.List()`, `Buffer.Delete(section, name)`.
- [x] `Buffer.Retry(merge func) error` called from each rebuild;
      drops entries that now compile.
- [x] Wire into both `cluster` delta application and `policy.Merge`
      so any compile failure caused by a CRDT entry funnels here.
- [x] Tests: push → next rebuild succeeds → entry removed; push →
      still failing → kept; manual `Delete`.

## Phase 6 - Admin API (`internal/adminapi`)

- [x] Separate `http.Server` on `--admin-port` (default 8081); not
      started if `--admin-token-file` is empty.
- [x] Bearer-token middleware reading the token from the file,
      reloaded via fsnotify on change.
- [x] Routes:
  - [x] `GET    /api/v1/groups`
  - [x] `GET    /api/v1/groups/{name}`
  - [x] `PUT    /api/v1/groups/{name}` (with `If-Match`, validation,
        broadcast on success)
  - [x] `DELETE /api/v1/groups/{name}`
  - [x] `GET/PUT/DELETE /api/v1/facts[/{name}]`
  - [x] `GET/PUT/DELETE /api/v1/defaults`
  - [x] `GET/PUT/DELETE /api/v1/logging`
  - [x] `GET    /api/v1/config` (effective)
  - [x] `GET    /api/v1/quarantine`
  - [x] `DELETE /api/v1/quarantine/{section}/{name}`
- [x] JSON in, JSON out; `Etag` derived from `(ts, node)`.
- [x] Strict body decoding (`DisallowUnknownFields`).
- [x] Process-wide write mutex so concurrent PUTs serialise.
- [x] Validation: build candidate `*Config`, compile, return 400 with
      a useful error on failure.
- [x] Tests:
  - [x] Missing / invalid / rotated token (401 → 200).
  - [x] Round-trip of every section (PUT → GET → DELETE → GET 404).
  - [x] Validation error path (CEL syntax, references missing fact).
  - [x] `If-Match` mismatch → 412.
  - [x] `/api/v1/config` reflects YAML + CRDT merge.

## Phase 7 - CLI flags & lifecycle wiring (`cmd/main.go`)

- [x] New flags: `--admin-port`, `--admin-token-file`, `--cluster-bind`,
      `--cluster-advertise`, `--cluster-peers`, `--cluster-discovery-dns`,
      `--state-file`.
- [x] Boot order: load YAML → load CRDT state file → start cluster (if
      enabled) → wait for initial gossip sync window → first rebuild →
      mark `/readyz` ready → start ext-authz server → start admin
      server (if token file set).
- [x] Shutdown: stop admin → stop ext-authz → stop cluster (leave
      gracefully) → flush CRDT to disk → stop facts → exit.
- [x] Signal handling unchanged (SIGHUP still triggers rebuild).

## Phase 8 - Observability

- [x] Metrics:
  - [x] `request_validator_cluster_members{state="alive|suspect|dead"}`
  - [x] `request_validator_gossip_messages_total{direction,type}`
  - [x] `request_validator_admin_requests_total{method,path,status}`
  - [x] `request_validator_quarantine_size{section}`
  - [x] `request_validator_rebuilds_total{trigger="yaml|sighup|crdt"}`
  - [x] `request_validator_rebuild_errors_total`
- [x] Structured logs:
  - [x] `cluster: peer joined`, `cluster: peer left`, `cluster: delta applied`
  - [x] `admin: write accepted`, `admin: write rejected`
  - [x] `quarantine: pushed`, `quarantine: drained`
- [x] Docs: update OPERATIONS.md PromQL table with the new metrics.

## Phase 9 - Examples & docs

- [x] `examples/policy.yaml` shows a `priority` example.
- [x] New `examples/admin-api/` with `curl` snippets for the common
      operations.
- [x] README: short section linking to OPERATIONS.md and POLICY_DSL.md
      for the new surfaces.

## Phase 10 - Final testing round

- [x] `go vet ./...`
- [x] `go test -count=1 ./...`
- [x] `go test -race -count=1 ./...`
- [x] Manual smoke: build, run with `examples/policy.yaml`, exercise
      a CRDT PUT via curl, observe convergence between two local
      instances on different ports.
- [x] CI green on the branch.
- [x] Grep audit: no corporate hostnames added by the new code (see
      AGENTS.md hard rule #4).
- [x] `.agents/*.md` cross-checked against final code; update where
      reality diverged.
