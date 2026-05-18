# DECISIONS.md

A log of significant choices made while building request-validator, in
the spirit of lightweight ADRs. Each entry is one decision with context,
options considered, the call we made, and consequences. Keep them in
chronological order; do not edit history once a decision is logged -
supersede with a new entry instead.

## D-001 - CEL as the policy language (instead of a bespoke DSL)

**Context.** The first iteration of the project had a YAML DSL with
typed matchers (`prefix:`, `suffix:`, `regex:`, `cidr:`, `allRegex:`...)
and boolean composition via `all`/`any`/`not`. It grew confusingly
quickly: every new shape needed a new operator, list-of-matchers
semantics got ambiguous, and headers/queries required ad-hoc shortcuts.

**Options considered.**

- Stay with the bespoke DSL and keep adding operators.
- Use [Open Policy Agent / Rego](https://www.openpolicyagent.org/).
- Use [Cedar](https://www.cedarpolicy.com/).
- Use **CEL** (Common Expression Language).

**Decision.** CEL.

**Reasoning.**

- CEL is the same language Istio `AuthorizationPolicy` conditions,
  Kubernetes `ValidatingAdmissionPolicy` and GCP IAM Conditions use.
  Operators already know it.
- It's a single expression language, not a logic programming language
  like Rego - simpler mental model for the "boolean decision per
  request" use case.
- It's sandboxed and guaranteed to terminate; safe to run user input.
- The cel-go library is mature and maintained by the spec authors.
- The "verbosity" of writing a full boolean is, in practice, less
  verbose than the DSL we had - `request.host in [...]` reads better
  than three nested `host: { in: [...] }` blocks.

**Consequences.**

- Binary grew from ~6 MB to ~13 MB. Acceptable for our deployment shape.
- We had to write a tiny set of custom CEL functions for things CEL
  doesn't include out of the box (CIDR, glob, parseJSON, etc.).
  See `internal/celenv/*.go`.
- The error messages on policy-load failure are CEL-flavoured; that has
  proven good enough.

## D-002 - Single concept `groups`, no top-level `rules`

**Context.** An intermediate design had both `groups:` (named buckets)
and `rules:` (top-level standalone rules). They served identical roles
in the evaluator.

**Decision.** Only `groups:`. A "standalone rule" is just a group with
a single rule inside.

**Reasoning.** Two concepts doing the same thing always invites
"which one should I use?" decisions and inconsistent style. Removing the
duplication keeps the grammar minimal without losing expressive power.

**Consequences.** Every example and rule lives inside a named group,
which makes the metric labels and access-log `rule` field uniformly
`group/rule` - easier to filter in Grafana / Loki.

## D-003 - `match` (single keyword) instead of `when`/`require`

**Context.** Early designs separated a rule's **scope** (`when:`) from
its **extra conditions** (`require:`). Two different meanings, two
different defaults for `fallthrough`. Confusing.

**Decision.** A single `match:` per rule. CEL composes booleans
naturally, so the user expresses "scope AND extra" with `&&` if they
want. A group can declare its own `match:` to factor out a common
prefix.

**Reasoning.** Less concepts, simpler defaults, harder to misuse.

**Consequences.** The user writes slightly longer expressions sometimes,
but CEL's `&&` reads fine.

## D-004 - `action` is inherited from group to rule

**Context.** A group typically has all rules of the same kind (a list
of "providers that may DCR"). Repeating `action: allow` on every rule
was noise.

**Decision.** A rule's effective action is its own when set, otherwise
the group's, otherwise `allow`. Rules can override (e.g. one `deny`
rule in a group of `allow`s for anomaly detection).

**Consequences.** Trivial inheritance, very common pattern.

## D-005 - Two modes per group: `firstMatch` and `all`

**Context.** Most groups want first-match semantics (a list of allowed
providers; the first whose rule matches wins). A minority want
defence-in-depth (every rule must hold).

**Decision.** Group `mode: firstMatch | all`. Default `firstMatch`.

**Reasoning.** Covers >95% of real cases with two well-defined
semantics. More modes (e.g. `majority`, `weighted`) were considered and
rejected as YAGNI.

**Consequences.** Inside `firstMatch` the default rule `fallthrough` is
`next` (try the next rule of the group). Inside `all` `fallthrough` is
unused.

## D-006 - Facts: declarative external values referenced as `facts.<name>`

**Context.** Many real-world policies depend on data that changes more
often than the policy itself: published CIDR feeds (ChatGPT, Anthropic),
allow-lists maintained by a CronJob, etc. Hardcoding them in the YAML
forces a redeploy on every change.

**Decision.** A `facts:` section at the top of the policy. Each entry
has a `name`, a `method` (`value` / `file` / `url`), and a method-specific
sub-block. CEL sees them as a single top-level variable `facts`.

**Reasoning.** Separation of policy (intent) from data (volatile lists).
The same policy file can live for months while feeds and lists change
underneath.

**Consequences.**

- We added a CEL variable `facts` and three handler implementations.
- `url` facts are fetched in a background goroutine and refreshed at a
  configurable `interval`. The hot path does **not** fetch.
- `file` and `url` expose raw strings to CEL. Parsing happens in CEL via
  `parseJSON(...)` / `parseYAML(...)`, so the YAML stays format-agnostic.

## D-007 - Fail-closed on initial fact load, fail-stable on refresh

**Context.** A URL fact backing a critical allow rule could fail to
fetch.

**Decision.**

- The **initial fetch** at `Start()` blocking-loops. If it fails, the
  policy load is rejected. The previous policy stays active.
- A **subsequent refresh** that fails keeps the last good value and
  emits a `WARN` log. The policy keeps serving with the stale data.

**Reasoning.** On boot, we don't want to serve traffic with empty
allow-lists (would deny everyone or open everything depending on rules).
At steady state, an OpenAI outage shouldn't take us down - stale data
is overwhelmingly preferable.

**Consequences.** First-time deployments where the feed is unreachable
get a clear error in the log and the pod stays unready. Existing
deployments survive transient outages of feed providers.

## D-008 - HTTP ext-authz, not gRPC (for now)

**Context.** Envoy supports both `envoyExtAuthzHttp` and
`envoyExtAuthzGrpc`. gRPC gives you all headers by default plus mTLS
peer identity and Envoy filter metadata; HTTP requires listing every
header in `includeRequestHeadersInCheck` and exposes less context.

**Decision.** HTTP ext-authz only.

**Reasoning.**

- Simpler tests (`httptest.Server`), simpler debug (`curl`), smaller
  binary (no gRPC + Envoy protos).
- Our current use cases (Keycloak DCR, etc.) don't need mTLS peer
  identity or filter metadata.
- The migration cost to add gRPC later is bounded and the policy DSL
  doesn't change.

**Consequences.** When (if) we need `request.peer.principal` for mTLS-
authenticated callers, we'll revisit. See the conversation history for
the explicit comparison.

## D-009 - `slog` for logging, with a thin wrapper

**Context.** Started with a homegrown JSON logger to avoid pulling
zap/zerolog. With Go 1.21+ shipping `log/slog`, the cost/benefit changed.

**Decision.** Wrap `log/slog` in `internal/log`. JSON handler by
default; small console handler we maintain in-tree (~80 LoC, no extra
dep).

**Reasoning.**

- Zero extra deps (slog is stdlib).
- We get the standard `slog.Attr` / `slog.Group` ecosystem for free.
- The wrapper exists only to (a) own a single global logger that can be
  swapped on policy reload, (b) keep the short `Infow/Warnw/Errorw`
  call sites we already had.

**Consequences.** Anything that wants structured logging uses the same
package; one access-log record per request, with redaction handled in
`httpserver/access.go`.

## D-010 - Atomic policy swap; `*Config` carries lifecycle

**Context.** Hot reload must not race with in-flight requests, and the
previous facts registry must keep working until those requests finish.

**Decision.**

- `httpserver.Server.policy` is `atomic.Pointer[policy.Config]`.
- `SetPolicy(new)` does `Swap()` and returns the old pointer.
- The caller (`cmd/main.go::reload`) calls `oldCfg.Stop()` after the swap
  to cancel the old fetcher goroutines.
- `policy.Config.Stop()` is idempotent.

**Reasoning.** No locks on the hot path. Old requests run to completion
against the policy snapshot they captured.

**Consequences.** Memory peaks during a reload until the previous
config is GC'd. Acceptable for our sizes.

## D-011 - fsnotify with directory watch + `..data` symlink awareness

**Context.** Kubernetes ConfigMap projections update via an atomic
symlink swap (`..data -> ..2024_01_15_...`). Watching the visible file
directly is useless: the watch holds a stale inode after the swap.

**Decision.** Watch the **directory** of the policy file. React to
events whose target basename is the file's name OR `..data`. Debounce
events into a single reload (200 ms window by default).

**Reasoning.** Covers in-place writes (vim `:w`), save-via-rename (most
modern editors), and Kubernetes projections, with a single mechanism.

**Consequences.** `internal/configwatch` is the single owner of this
logic. Tests reproduce all three scenarios.

## D-012 - Example domains: `example-1.com` and `example-2.com`

**Context.** During development a previous version of the example leaked
real corporate hostnames. We grep for those continuously.

**Decision.** Two parallel example domains, `example-1.com` and
`example-2.com`, plus `keycloak.internal.example-1.com` for the internal
Keycloak. Anything else is `random.example.com` / `attacker.com`.

**Consequences.** A grep for the historical corporate names returning
anything other than empty is a CI-blocking issue. The names are kept
out of the repo on purpose, including this very document - the regex
hint lives in AGENTS.md only.

## D-013 - No Helm chart; deploy via bjw-s/app-template (or anything else)

**Context.** The project shipped a small Helm chart for a while. The
user's clusters use [bjw-s/app-template](https://github.com/bjw-s-labs/
helm-charts/tree/main/charts/other/app-template), so the chart was
duplicating effort.

**Decision.** Drop the chart. Ship only the OCI image; document a
minimal `app-template` HelmRelease in the README.

**Consequences.** One less moving part. Other deployers just use the
image. The Helm release workflow was removed from `.github/workflows`.
