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

## D-014 - Global dry-run switch

**Context.** Operators want to preview a whole policy against live traffic
before it can block anything. A per-rule `dryRun` already covers single
rules, but it suppresses the verdict inside the evaluator, so the access log
records `allow` for a rule that would deny. That hides what the operator
needs to see, and shadowing a whole policy means setting `dryRun` on every
rule.

**Decision.** Add `defaults.dryRun` (bool, default `false`). Enforcement
suppression lives in the `httpserver` layer; the evaluator returns the
verdict the policy produced. `dry_run` carries one meaning everywhere:
evaluated but not enforced, whether set per-rule or globally. A shadowed deny
is logged at `WARN` with `decision: deny` and `dry_run: true`. Under global
dry-run a body-read failure also passes through with HTTP 200. YAML only, no
CLI flag.

**Reasoning.** Decoupling the verdict from its enforcement keeps the
evaluator pure and lets the access log and metrics report what a policy
would do. The server layer already owns the HTTP response, so the
suppression check belongs there.

**Consequences.** A per-rule `dryRun` deny is logged with `decision: deny` at
`WARN`. Shadow denies are queryable in metrics as
`request_validator_rule_decisions_total{outcome="deny",dry_run="true"}`. One
decision metric per request, with `dry_run` reflecting whether enforcement
was suppressed.


## D-015 - Two engines: ext_authz (decide) and ext_proc (mutate)

**Context.** The service was a pure ext-authz: read a request, return
allow/deny. A new need appeared: intercept the response Keycloak emits
during DCR with remote MCPs and, for untrusted redirect targets, rewrite
the `Location` header so the user lands on an interstitial warning page
instead of a risky destination. The same applies more broadly to
inspecting and rewriting traffic, not just admitting it. Doing this with
an Envoy Lua filter that embeds HTML in the data plane is a mess.

**Decision.** Add a second engine, `extProc`, served over Envoy's
`ext_proc` gRPC API, living next to the existing HTTP ext-authz. One
binary, two listeners, one shared policy and hot-reload. This supersedes
the "HTTP only, no gRPC" stance of D-008 by adding gRPC for a different
filter, not by replacing the HTTP ext-authz.

**Reasoning.**

- ext_authz is a binary gatekeeper (pass/deny). ext_proc is the only
  Envoy hook that can mutate headers, body and status of live traffic
  in both directions. The redirect-rewrite case needs mutation.
- Keeping both in one process means one policy language, one facts
  registry, one reload path. Operators learn one tool.
- The HTML for the interstitial is loaded as a `file`/`url` fact and
  injected via a `setBody` mutation. The HTML never lives in code or in
  the data plane.

**Consequences.** The binary now links the Envoy ext_proc protos and a
gRPC server. The policy grammar grows an explicit engine selector and a
mutation vocabulary (D-016..D-021).

## D-016 - Explicit `engine` per group, inside `parameters`

**Context.** A group must declare whether it programs the ext_authz
filter or the ext_proc filter. They are different Envoy filters with
different contracts. Hiding which one a group targets (or inferring it
from the rule contents) is exactly the confusion to avoid.

**Decision.** Every group carries a `parameters` block. `parameters.engine`
is `extAuthz | extProc`, required, no default. Engine-specific knobs live
inside `parameters` too: `mode` (both engines) and `phase` (extProc only).

```yaml
groups:
  - name: ...
    parameters:
      engine: extAuthz | extProc
      mode: ...
      phase: ...        # extProc only
    match: ...          # group guard, optional
    rules: [...]
```

**Reasoning.** `engine` is the vocabulary the platform team already speaks
(they read `EnvoyFilter`/`WasmPlugin` daily). An explicit discriminator
beats magic. `parameters` separates "engine wiring" from policy logic
(`match`, `rules`).

**Consequences.** The loader validates engine-specific coherence (D-017,
D-018, D-021). A group is unambiguously routed to the HTTP server
(extAuthz) or the gRPC server (extProc) by `engine` alone.

## D-017 - Mode names are engine-specific to avoid a colliding `all`

**Context.** Both engines compose rules, but the composition means
different things. extAuthz composes verdicts; extProc composes mutations.
Reusing `mode: all` for both would make one keyword mean "every rule must
hold (logical AND, else deny)" in one engine and "apply the mutations of
every matching rule" in the other.

**Decision.** Distinct names per engine:

- extAuthz: `mode: firstMatch | matchAll`
- extProc:  `mode: firstMatch | applyAll`

`firstMatch` means the same on both (first rule whose `match` is true
decides/applies, then stop). `matchAll` is the logical-AND verdict mode
(every rule must match or the group denies). `applyAll` accumulates the
mutations of every matching rule, in declaration order.

**Reasoning.** Same word, same meaning; different behaviour, different
word. The verb in the name tells the user what the group does.

**Consequences.** The loader rejects any mode not valid for the group's
engine. `firstMatch` is the only shared value.

## D-018 - Homogeneous rule body: `validation` (singular) XOR `mutations`

**Context.** A rule must read clearly as either "this decides" or "this
mutates". The two engines never mix in v1.

**Decision.**

- A rule's `match` is a **mandatory** CEL bool. There is no implicit
  `true` default any more, and `fallthrough` is removed. In `firstMatch`
  the first rule whose `match` is true wins; if none match, the group
  produces no verdict and evaluation falls through to the next group /
  `defaults`.
- An extAuthz rule carries `validation: { action: allow | deny }`. It is
  a singular object, not a list: a rule produces exactly one verdict.
  Group-to-rule action inheritance (old D-004) is removed; each rule
  states its own verdict.
- An extProc rule carries `mutations: [ ... ]`, a real list (a rule may
  legitimately apply several mutations). An empty `mutations: []` is a
  valid "matched but change nothing" that still stops a `firstMatch`
  group.

**Reasoning.** `validation`/`mutations` name the intent. Mandatory
`match` and no inheritance remove the invisible-default footguns that
D-003/D-004 still allowed. One rule = one condition = one effect (verdict
or a set of mutations); several conditional effects are several rules.
This supersedes the default-`true` of D-003, the inheritance of D-004 and
the `fallthrough` of D-005.

**Consequences.** Examples get slightly longer (explicit `match: 'true'`
for a fallback rule, explicit `action` on every extAuthz rule) in
exchange for zero hidden behaviour.

## D-019 - Mutation ops: explicit `op` discriminator, fixed catalogue

**Context.** Each item in `mutations` needs a clear, validatable shape.

**Decision.** Each mutation is an object with an explicit `op` field and
its operands. v1 catalogue:

| op             | fields       | legal phases                  | semantics                                  |
| -------------- | ------------ | ----------------------------- | ------------------------------------------ |
| `setHeader`    | name, value  | all                           | upsert: overwrite if present, else create  |
| `appendHeader` | name, value  | all                           | add a value, keep existing ones            |
| `removeHeader` | name         | all                           | delete the header; no-op if absent         |
| `setBody`      | value        | requestBody, responseBody     | replace the body; recomputes Content-Length|
| `setStatus`    | code         | responseHeaders, responseBody | set the response status code               |

`value`/`code` are CEL expressions (string for header/body, int for
status). On `applyAll`, when two matching rules write the same header the
last one in declaration order wins.

**Reasoning.** Explicit `op` is a clean switch in Go, easy to validate,
no "map with a single key" trick. `setHeader` as upsert is the least
surprising default. `removeHeader` is idempotent. `setBody` owns
Content-Length recomputation because making the user maintain it by hand
is a trap; Content-Type stays the user's responsibility.

**Consequences.** `setStatus`/`setBody` legality depends on the group's
`phase`; the loader enforces it. Body-rewriting phases require Envoy to
buffer the body (D-021).

## D-020 - CEL `response` variable; typed mutation expressions

**Context.** Response-phase policies need to see the upstream response.
Mutation expressions return strings/ints, not booleans.

**Decision.**

- Add a CEL variable `response` (headers/header, status, body.json/yaml/raw),
  shaped like `request`. Live variables depend on the phase:
  - request phases (`requestHeaders`, `requestBody`): `request`, `facts`.
  - response phases (`responseHeaders`, `responseBody`): `request`,
    `response`, `facts`.
- `match` expressions are compiled and checked as bool (as today).
  Mutation `value`/`code` expressions are a second kind of program,
  checked for string/int output type at load time. A rule that references
  `response` in a request phase fails to compile, not at runtime.

**Reasoning.** Deriving live variables from the phase makes the
variable contract impossible to violate silently. Output-type checking at
load turns a class of runtime errors into load errors.

**Consequences.** `celenv.Compile` gains a typed variant (or a parameter)
for non-bool expressions. The env is built per-phase or the variables are
registered and the loader rejects out-of-phase references.

## D-021 - Per-engine `defaults`; ext_authz body overflow is fixed deny

**Context.** `defaults.action` and `defaults.denyStatus` only make sense
for ext_authz; ext_proc does not "deny", it mutates. A flat `defaults`
mixing both engines breeds orphan fields. Body buffering limits matter to
both engines but can want different values.

**Decision.** Split defaults per engine; each block is self-contained:

```yaml
defaults:
  extAuthz:
    action: deny
    denyStatus: 403
    denyBody: "Forbidden"
    allowOnError: false
    maxBodyBytes: 1MiB
  extProc:
    maxBodyBytes: 1MiB
    onBodyOverflow: skip | fail
  dryRun: false        # global, both engines (D-022)
```

- `onBodyOverflow` exists **only** for extProc (`skip`: don't mutate, let
  the original body pass; `fail`: immediate-response, fail-closed). There
  is no `truncate`.
- ext_authz body overflow is **not configurable**: it is a fixed
  fail-closed deny. A gatekeeper that cannot read the whole request does
  not admit it. (This changes the old behaviour of truncating and
  evaluating with a partial body.)

**Reasoning.** Per-engine blocks make every knob's scope obvious and let
the gatekeeper and the surgeon tune body limits independently. Truncate
is dropped everywhere because a partial body yields wrong matches and
half-rewritten bodies.

**Consequences.** Flat `defaults.action`/`maxBodyBytes`/etc. no longer
exist; they move under `defaults.extAuthz`. This is a breaking config
change with no migration shim (intentional).

## D-022 - Dry-run stays global and suppresses every enforcing path

**Context.** Operators want to shadow the whole policy (both engines)
before it can affect traffic.

**Decision.** `defaults.dryRun` stays a single global switch (no
per-engine split for now). Per-rule `dryRun` also stays. When dry-run is
on, no path touches traffic:

- extAuthz: a `deny` verdict is logged/metered as "would deny" but
  returns 200. A body-overflow that would deny also passes with 200.
- extProc: mutations are computed and logged ("would setHeader ...") but
  the gRPC stream responds CONTINUE with no mutation. An overflow that
  would `fail` is logged as "would fail" and passes.

**Reasoning.** Shadow mode must be observe-only on every branch, not just
the happy path, or the preview lies.

**Consequences.** Both servers route their enforcement through a single
`effectiveDry` check before emitting the verdict/mutation, mirroring the
existing httpserver pattern (D-014).


## D-023 - `directResponse` op: short-circuit and serve a response

**Context.** The flagship case (intercept Keycloak's DCR `302` to an
untrusted destination and show the user a warning page) is not a header
mutation: it is replacing the upstream response entirely with our own.
Expressing it as `setStatus` + `setHeader` + `setBody` has two problems:
`setBody` is illegal in `responseHeaders` (D-019) and the `responseBody`
phase never fires for a bodiless `302`, so the only phase that runs is
`responseHeaders`, where the incremental mutation ops cannot build a full
response. It is also three coupled mutations that only make sense
together.

**Decision.** A dedicated extProc op, `directResponse`, that maps to
Envoy's `ImmediateResponse`: it discards the upstream response and serves
the one the rule builds. Shape:

```yaml
- op: directResponse
  status: 200            # int literal
  headers: |             # CEL expression evaluating to map<string,string>
    {"content-type": "text/html"}
  body: |                # CEL expression evaluating to string
    facts.interstitialHtml.replace('__TARGET_B64__', base64.encode(response.header['location']))
```

- `status` is an int literal (a CEL-computed status is YAGNI and less
  readable).
- `headers` is a CEL expression returning `map<string,string>`. This is
  the single mechanism for every header need: a map literal for fixed
  values, `response.header` to carry over all of the original headers
  ("give me all of them"), and filter/merge expressions for any subset or
  override. There is no inherit-by-default; the response is built from
  scratch, which is faithful to the op's name. Header values are single
  strings (no multi-value output); the rare multi-value case is out of
  scope for v1.
- `body` is a CEL expression returning a string.

`directResponse` is legal in `responseHeaders` and `responseBody`. In
`responseHeaders` it works even when upstream sent no body, which is the
`302` case. It is self-contained: a rule carrying `directResponse` must
not also carry any incremental op (setHeader/appendHeader/removeHeader/
setBody/setStatus). The loader rejects the mix. In `applyAll`, the first
rule that fires a `directResponse` wins and stops the group (you cannot
short-circuit twice).

**Reasoning.** What the user wants is "abort and serve this", which is an
ImmediateResponse, not a mutation. Treating `headers` as data built by a
CEL expression (like `body` already is) keeps one paradigm across the DSL
and removes the earlier dead ends (a `headers` map of CEL strings forced
`"'text/html'"` per entry; a list with value/expr/from/all/remove verbs
was a sub-language nobody wanted). "Give me all the original headers" is
just the expression `response.header`.

**Consequences.**

- celenv gains a fourth compiled kind: `CompileStringMap` /
  `EvalStringMap` (output `map<string,string>`), same pattern as the bool/
  string/int variants. Output type is checked at load; a runtime value
  that is not a string map is fail-safe (the directResponse is not
  emitted).
- The resolved-mutation model grows a variant carrying status + headers +
  body. The gRPC server maps it to `ImmediateResponse{Status, Headers,
  Body}` instead of a `CommonResponse` mutation.
- Under global or per-rule dry-run, `directResponse` is computed and
  logged ("would directRespond") but not served; the stream responds
  CONTINUE.
- Security note for the interstitial recipe: the original `Location` is
  attacker-controlled (untrusted DCR client). It must be encoded before
  being placed in the page (base64 in CEL, decoded by the button's JS) to
  avoid HTML injection. The example uses `base64.encode(...)` and a
  `__TARGET_B64__` placeholder.
