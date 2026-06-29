# GLOSSARY.md

Project-specific terms. Stick to these when writing code, docs and
commit messages so the vocabulary stays consistent.

## Core concepts

**Policy**
The YAML file the engine consumes. Lives in `examples/policy.yaml`
as a sample; in production it ships as a Kubernetes ConfigMap mounted
into the pod.

**Engine**
Which Envoy filter a group programs, set in `parameters.engine`:
`extAuthz` (HTTP ext-authz, produces allow/deny) or `extProc` (gRPC
ext_proc, mutates traffic or serves a direct response). The in-memory
runtime lives in `internal/policy` (`Evaluate` for extAuthz, `EvaluateProc`
for extProc).

**Group**
A named bucket of rules in the policy. Carries `parameters` (engine, mode,
and for extProc a phase) and an optional `match` (its scope). Groups are
evaluated in declared order.

**Rule**
The leaf of a decision. Always has a mandatory `match` (CEL boolean) plus
either a `validation` (extAuthz verdict) or a list of `mutations`
(extProc).

**Mode**
How a group composes its rules. Engine-specific:

- extAuthz: `firstMatch` (first rule whose `match` is true decides) or
  `matchAll` (every rule must match, else deny).
- extProc: `firstMatch` (first matching rule applies its mutations and
  stops) or `applyAll` (every matching rule applies its mutations, in
  order, last write wins per header).

**Action**
The verdict an extAuthz rule produces, in `validation.action`: `allow` or
`deny`. Each rule states its own; there is no inheritance.

**Match**
The CEL boolean expression at the group or rule level. The group's `match`
is the scope; the rule's `match` is the condition. The rule `match` is
mandatory.

**Phase** (extProc only)
Which ext_proc hook a group runs on: `requestHeaders`, `requestBody`,
`responseHeaders`, `responseBody`. Determines the live CEL variables
(`response` is only available in response phases).

**Mutation**
An extProc traffic change in a rule's `mutations` list. Incremental ops:
`setHeader`, `appendHeader`, `removeHeader`, `setBody`, `setStatus`.

**directResponse**
The extProc op that discards the upstream response and serves one the
rule builds (`status`, `headers` as a CEL map, `body` as a CEL string),
mapping to Envoy's ImmediateResponse. Exclusive in its rule.

**DryRun**
A rule with `dryRun: true`, or the global `defaults.dryRun`, is evaluated
and logged but never enforced: extAuthz passes 200, extProc responds
CONTINUE without mutations.

**Default action**
The extAuthz verdict when no group decides. Configured under
`defaults.extAuthz.action`; defaults to `deny` (fail-closed).

## Facts subsystem

**Fact**
A named external value the policy can reference as `facts.<name>`
from CEL. Each fact has a single `method` (`value`, `file`, `url`)
and is loaded accordingly.

**Method**
The strategy for loading a fact:

- `value` - inline literal in the YAML.
- `file` - bytes read from disk at `Start()`.
- `url` - bytes fetched periodically by a background goroutine.

**Source / Spec**
Same thing, different name in different files. `facts.Spec` is the
Go struct; "source" is the prose term ("URL source", "file source").
Prefer "method" when you mean the kind of fact.

**Registry**
The runtime that owns the facts. Built once per policy load, with a
`Start(ctx)` for fetchers and a `Stop()` to cancel them.

**Snapshot**
A point-in-time `map[string]any` of every fact's current value.
Built per request via `Registry.Snapshot()`. Lock-free under the
hood (atomic pointers per entry).

**Refresh tick**
The periodic background fetch of a URL fact, scheduled by
`time.Ticker(interval)`. A tick that fails keeps the previous value
and logs a `WARN`.

**Initial fetch**
The first fetch performed when `Start()` runs. A failure here rejects
the whole policy load (fail-closed boot).

## Request side

**Request**
The normalised view of an incoming HTTP request the engine evaluates
against. `policy.Request` in Go; `request` in CEL.

**`request.body`**
A group containing `raw`, `size`, `contentType`, `json`/`jsonOk`,
`yaml`/`yamlOk`. The body is parsed eagerly into both JSON and YAML
shapes; whichever succeeds populates the corresponding fields.

**ext-authz**
Envoy's "External Authorization" filter. We implement the HTTP variant
(`envoyExtAuthzHttp`). Envoy POSTs the original request to us, we return
200 or a non-2xx with the configured body. Served by `internal/httpserver`.

**ext_proc**
Envoy's "External Processing" filter (gRPC). Envoy streams the request and
response phases to us; we reply with mutations, a direct response, or
CONTINUE. Served by `internal/grpcserver`.

**Decision**
The Go struct (`policy.Decision`) carrying the extAuthz verdict, the
winning rule name, a short `reason`, and the `dry_run` flag. Becomes the
HTTP response status + headers.

**ResolvedMutation**
The Go struct (`policy.ResolvedMutation`) an extProc evaluation produces:
an op with its CEL values already evaluated, ready for the gRPC server to
translate into Envoy protos.

## Lifecycle

**Boot**
Process startup. Reads flags, configures the logger, loads the
policy, starts the HTTP server. If the initial policy load or fact
fetches fail, the process exits with an error.

**Reload**
A live policy swap, triggered by fsnotify or SIGHUP. A failed reload
keeps the previous policy. Successful reloads emit `policy reloaded`
in the log with the trigger source.

**Hot path**
The code that runs per request. Must not block, allocate excessively,
or take locks. See `httpserver/server.go::handle` and
`policy/policy.go::Evaluate`.

**Atomic swap**
The mechanism that exchanges the active `*Config` without locking
readers, using `atomic.Pointer[T]`. Old config is `Stop()`'d after
the swap.

## Logging

**Access log**
The single line emitted per request, with the decision, the rule that
decided, and a `request.*` group describing what came in.

**Redact**
Replace a value with asterisks (`***`) or a prefix+`***`. Applied to
sensitive header and query values listed in `logging.redactHeaders`
and `logging.redactQueryParams`.

**Exclude**
Drop a header from the log entirely. Applied to `logging.excludeHeaders`
(default: `cookie`, `set-cookie`).

**Redact reveal**
Number of leading characters to keep when redacting; the rest is
replaced with `*`. Values shorter than `2 * redactReveal` are fully
masked.

**Log format**
`json` (slog JSON handler) for production parsers, `console` (a tiny
human-friendly handler we maintain) for `kubectl logs -f`.

## CEL terms

**CEL**
Common Expression Language. A spec-defined, sandbox-safe boolean
expression language. https://github.com/google/cel-spec.

**Activation**
The set of variables CEL sees when evaluating a program. `request` and
`facts` in request phases; `request`, `response` and `facts` in response
phases.

**Program**
A compiled CEL expression ready to be evaluated. Cached by source
string in `Env.cache`, so a given `match` is compiled at most once.

**Macro**
The CEL built-ins like `xs.all(x, pred)`, `xs.exists(x, pred)`,
`xs.map(x, expr)`, `cel.bind(name, value, expr)`. We rely on these
heavily.

## Other

**Corporate hostname**
Anything that would identify the deploying organisation. Forbidden
in fixtures, tests, examples and docs. We use `example-1.com`,
`example-2.com`, `keycloak.internal.example-1.com`.

**Fail-closed**
The pessimistic default: on any error, deny the request (or reject
the policy load). Override per-policy with `defaults.allowOnError:
true`.

**MCP**
Model Context Protocol. The reason we have a Keycloak realm called
`mcp` in the example - AI clients perform Dynamic Client Registration
against it.

**DCR**
Dynamic Client Registration (RFC 7591). The Keycloak endpoint
`POST /realms/<realm>/clients-registrations/openid-connect` we
mostly want to protect.
