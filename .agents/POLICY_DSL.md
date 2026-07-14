# POLICY_DSL.md

Reference for the YAML policy file. The user-facing version lives in the
project README; this one is denser, no preamble, and is the source of
truth for what the parser accepts.

The service runs two engines from one policy file:

- **extAuthz**: HTTP ext-authz. A binary gatekeeper. Reads a request,
  produces allow/deny.
- **extProc**: gRPC ext_proc. Inspects and mutates live traffic (request
  or response headers/body) and can short-circuit with an immediate
  response.

Each group declares which engine it programs. See DECISIONS.md D-015..D-022.

## Top-level structure

```yaml
defaults: # engine-wide knobs, split per engine
logging:  # access-log shape and redaction
facts:    # named external values referenced as facts.<name>
groups:   # ordered list of rule buckets, each bound to one engine
```

All sections are optional except `groups`, which must contain at least
one entry with at least one rule.

## `defaults`

Split per engine. Each block is self-contained.

```yaml
defaults:
  extAuthz:
    action: deny          # allow | deny       default: deny
    denyStatus: 403       # int                default: 403
    denyBody: "Forbidden" # string             default: "Forbidden"
    allowOnError: false   # bool               default: false
    maxBodyBytes: 1MiB    # BytesSize          default: 1MiB
  extProc:
    maxBodyBytes: 1MiB    # BytesSize          default: 1MiB
    onBodyOverflow: fail  # skip | fail        default: fail
  dryRun: false           # bool, global       default: false
```

`BytesSize` accepts plain integers (bytes) and human strings: `1024`,
`1KiB`, `2MiB`, `1GiB`, `1KB`, `1MB`, `1024b`.

`extAuthz.allowOnError` flips the fail-closed behaviour: when a CEL
evaluation hits an error mid-request, the verdict becomes `allow` instead
of `deny`. Used rarely, with care.

`extAuthz` body overflow (request body larger than `maxBodyBytes`) is a
fixed fail-closed deny; it is not configurable. A gatekeeper that cannot
read the whole request does not admit it.

`extProc.onBodyOverflow` controls a body larger than `maxBodyBytes` in a
body phase: `skip` lets the original body pass unmutated; `fail` returns
an immediate fail-closed response. There is no `truncate`.

`dryRun` is global and applies to both engines. When true the service
evaluates everything but enforces nothing: extAuthz denies pass with HTTP
200; extProc mutations are computed and logged but the stream responds
CONTINUE with no mutation. Overflow paths that would deny/fail also pass.
The access log and metrics record what the policy would have done.

## `logging`

```yaml
logging:
  level: info     # debug|info|warn|error    default: info
  format: json    # json|console             default: json
  logBody: false  # bool                     default: false
  redactReveal: 6 # int                      default: 6
  excludeHeaders: [cookie, set-cookie]
  redactHeaders: [authorization, proxy-authorization, x-api-key, x-auth-token]
  redactQueryParams: [access_token, id_token, code]
```

The logging block applies to BOTH engines:

- extAuthz emits one access record per delegated request ("request decided").
- extProc emits one access record per phase message at INFO ("extProc access"). The request and/or response body appears in extProc logs only when Envoy's processing_mode actually sends the body AND logBody is true. extProc records carry a stream_id shared by all phases of one HTTP request (one ext_proc stream = one request) and a request_id copied from the x-request-id header when present.

Behaviour:

- Header keys are normalised to lowercase before exclude/redact checks.
- Redaction: if a value's length is at least `2 * redactReveal`, the
  first `redactReveal` chars are kept and the rest replaced with `*`.
  Otherwise the value is fully masked. With `redactReveal: 0` every
  redacted value is fully masked.
- `logBody: true` adds the body to the access log. Off by default because
  DCR payloads carry secrets.
- `--log-level` / `--log-format` CLI flags override the YAML values when
  set.

## `facts`

A list of named external values. CEL sees them as `facts.<name>`.

```yaml
facts:
  - name: <identifier>      # required, unique across facts
    method: value | file | url
    value: <any YAML shape> # required when method=value
    file:                   # required when method=file
      path: /abs/or/rel/path
    url:                    # required when method=url
      address: https://...
      interval: 10m         # optional, default 10m
      timeout: 15s          # optional, default 15s
      headers:              # optional
        Authorization: "Bearer $TOKEN"
```

| Method | Loaded                                               | Type seen by CEL |
| ------ | ---------------------------------------------------- | ---------------- |
| value  | At YAML parse; the value is used verbatim            | as declared      |
| file   | At Start(), the file is read once into a string      | string           |
| url    | At Start() (initial) plus every interval afterwards  | string           |

URL fact failure modes:

- Initial fetch fails: policy load is rejected. The previous policy (if
  any) keeps running.
- Refresh fails: previous value retained, WARN log emitted.

The interstitial HTML for the redirect-rewrite case is a `file` or `url`
fact, injected into a response via a `setBody` mutation. It never lives
in code.

CEL helpers for parsing the raw string into structured data:

```cel
parseJSON(facts.chatgptFeed).prefixes.map(p, p.ipv4Prefix)
parseYAML(facts.mistralCidrs)
```

Both return an empty map `{}` on null/empty/invalid input, so the
expression stays safe before the first successful fetch.

## `groups`

A list of named buckets. Evaluated in declared order. Each group is bound
to one engine via `parameters.engine`. extAuthz groups are served by the
HTTP listener; extProc groups by the gRPC listener.

```yaml
groups:
  - name: <identifier>     # required, unique across groups
    description: ...       # optional
    parameters:
      engine: extAuthz | extProc      # required, no default
      mode: <see below>               # required
      phase: <see below>              # required iff engine=extProc, forbidden otherwise
    match: |               # optional CEL bool, group guard
      <expression>
    rules:                 # required, non-empty
      - <rule>
```

Group `match` is evaluated once per request. If false, the whole group is
skipped silently. It factors out a common scope (e.g. `response.status == 302`).

### `parameters.mode`

Per engine. The loader rejects a mode not valid for the group's engine.

- extAuthz: `firstMatch | matchAll`
  - `firstMatch`: the first rule whose `match` is true decides. If none
    match, the group produces no verdict and evaluation continues.
  - `matchAll`: every rule must match. The first failure produces a deny.
    Defence-in-depth.
- extProc: `firstMatch | applyAll`
  - `firstMatch`: the first rule whose `match` is true applies its
    mutations and stops. An empty `mutations: []` is a valid "matched,
    change nothing" that still stops the group.
  - `applyAll`: every matching rule applies its mutations, in declaration
    order. When two matching rules write the same header, the last one
    wins.

### `parameters.phase` (extProc only, required)

`requestHeaders | requestBody | responseHeaders | responseBody`

Determines which Envoy ext_proc hook the group runs on and which CEL
variables are live:

| phase           | live CEL variables          |
| --------------- | --------------------------- |
| requestHeaders  | request, facts              |
| requestBody     | request, facts              |
| responseHeaders | request, response, facts    |
| responseBody    | request, response, facts    |

A rule that references `response` in a request phase fails to compile.

### Rule

```yaml
- name: <identifier>   # required, unique within the group
  description: ...     # optional
  match: |             # required CEL bool expression
    <expression>
  # extAuthz rules carry exactly this:
  validation:
    action: allow | deny
  # extProc rules carry exactly this instead:
  mutations:
    - { op: setHeader,    name: <string>, value: <CEL string> }
    - { op: appendHeader, name: <string>, value: <CEL string> }
    - { op: removeHeader, name: <string> }
    - { op: setBody,      value: <CEL string> }
    - { op: setStatus,    code: <CEL int> }
    - { op: directResponse, status: <int>, headers: <CEL map<string,string>>, body: <CEL string> }
  dryRun: false        # bool, default false
```

- `match` is mandatory. There is no implicit `true`. For a fallback rule
  write `match: 'true'` explicitly.
- An extAuthz rule has `validation` (a singular object), never
  `mutations`. An extProc rule has `mutations` (a list), never
  `validation`. The loader rejects the wrong one for the engine.
- There is no `action` inheritance from the group and no `fallthrough`.
- `dryRun: true` shadows the rule: the verdict/mutations are computed,
  logged and metered with `dry_run: true`, enforcement suppressed.

### Mutation ops

Two kinds. The incremental ops mutate the upstream response in place.
`directResponse` is different: it discards the upstream response and
serves one the rule builds (Envoy ImmediateResponse). A rule carrying
`directResponse` must not carry any incremental op; the loader rejects the
mix. In `applyAll` the first rule that fires a `directResponse` wins and
stops the group.

| op             | fields      | legal phases                  | semantics                                   |
| -------------- | ----------- | ----------------------------- | ------------------------------------------- |
| `setHeader`    | name, value | all                           | upsert: overwrite if present, else create   |
| `appendHeader` | name, value | all                           | add a value, keep existing ones             |
| `removeHeader` | name        | all                           | delete the header; no-op if absent          |
| `setBody`      | value       | requestBody, responseBody     | replace the body; recomputes Content-Length |
| `setStatus`    | code        | responseHeaders, responseBody | set the response status code                |
| `directResponse` | status, headers, body | responseHeaders, responseBody | discard the upstream response, serve this one |

`value` is a CEL expression returning a string; `code` a CEL expression
returning an int. These are checked for output type at load time, unlike
`match` which is checked as bool. `setBody` recomputes Content-Length;
Content-Type stays the user's responsibility (set it with `setHeader`).

`directResponse` builds a full response from scratch and short-circuits
(maps to Envoy ImmediateResponse). Its fields:

- `status`: int literal (e.g. 200).
- `headers`: a CEL expression returning `map<string,string>`, checked for
  output type at load. A map literal sets fixed headers
  (`{"content-type": "text/html"}`); `response.header` carries over every
  original header ("give me all of them"); filter/merge expressions pick a
  subset or override. There is no inherit-by-default. Single-string
  values only (no multi-value output in v1).
- `body`: a CEL expression returning a string.

It works in `responseHeaders` even when upstream sent no body (the
bodiless `302` case). A rule with `directResponse` cannot carry any
incremental op. Under dry-run it is logged ("would directRespond") but not
served.

### Decision flow (extAuthz, pseudo-code)

```
for each extAuthz group in order:
    if group.match is false: continue
    switch group.mode:
        case firstMatch:
            for each rule in order:
                if rule.match is true: return rule.validation.action
            continue        # no rule matched, try next group
        case matchAll:
            for each rule in order:
                if rule.match is false: return deny
            return allow    # whichever action makes the group hold
return defaults.extAuthz.action
```

### Mutation flow (extProc, pseudo-code)

```
for each extProc group bound to the current phase, in order:
    if group.match is false: continue
    switch group.mode:
        case firstMatch:
            for each rule in order:
                if rule.match is true:
                    apply rule.mutations (may be empty); stop
        case applyAll:
            for each rule in order:
                if rule.match is true: accumulate rule.mutations
            apply accumulated mutations (last write wins per header)
respond to Envoy with the accumulated mutations, or CONTINUE if none
```

## CEL environment

Variables visible to an expression depend on the phase (see the table
above). `request` and `response` are shaped the same way:

- `method`, `scheme`, `host`, `path`, `remoteIp` (request only),
  `headers` (map of lists), `header` (map of first values), `queries`,
  `query`, `body` (`raw`, `size`, `contentType`, `json`/`jsonOk`,
  `yaml`/`yamlOk`).
- `response` additionally exposes `status` (int).

Enabled CEL extensions: `ext.Strings()`, `ext.Encoders()`, `ext.Lists()`,
`ext.Sets()`, `ext.Math()`, `ext.Bindings()`.

Project-specific functions (full docs in the README):

| Family   | Functions                                                       |
| -------- | --------------------------------------------------------------- |
| Network  | `inCIDR`, `ipFamily`, `isPrivateIP`, `isLoopbackIP`, `parseURL` |
| Strings  | `glob`, `globAny`                                               |
| Encoding | `sha256Hex`, `parseJWTUnverified`                               |
| Time     | `now`                                                           |
| Data     | `parseJSON`, `parseYAML`, `jsonPath`                            |
| HTTP     | `has`, `firstOr`                                                |

## What gets logged for a decision

```json
{
  "time": "...",
  "level": "INFO or WARN",
  "msg": "request decided or response processed",
  "engine": "extAuthz or extProc",
  "decision": "allow or deny",
  "mutations": ["setHeader location", "..."],
  "rule": "<group>/<rule> or <defaults>",
  "reason": "matched or no group matched or ...",
  "dry_run": false,
  "duration_ms": 0.31,
  "request": { ... }
}
```

- extAuthz records `decision`; extProc records the `mutations` it applied
  (or would apply under dry-run).
- `decision`/`mutations` always reflect what the policy produced, even
  when shadow mode suppresses enforcement.
- `dry_run: true` means evaluated but not enforced.
- Log level is WARN for any `deny`, including a shadowed one, INFO
  otherwise.

## Response headers emitted to Envoy (extAuthz)

| Header         | Value                                            |
| -------------- | ------------------------------------------------ |
| `x-rv-result`  | `allow` or `deny`                                |
| `x-rv-rule`    | rule that decided (`group/rule` or `<defaults>`) |
| `x-rv-reason`  | short, human-readable                            |
| `x-rv-dry-run` | `true` if the rule was in shadow mode            |

These are for debugging; Envoy acts on the HTTP status code (200 = allow,
anything else = deny).

## Errors that stop policy load

- YAML doesn't parse.
- A group missing `parameters.engine`, or `engine` not in {extAuthz, extProc}.
- `mode` missing or not valid for the engine (extAuthz: firstMatch|matchAll;
  extProc: firstMatch|applyAll).
- `phase` present on an extAuthz group, or missing/invalid on an extProc group.
- An extAuthz rule carrying `mutations`, or an extProc rule carrying `validation`.
- A rule missing `match`.
- `validation.action` not in {allow, deny}.
- A mutation with an unknown `op`, missing operands, or an op used in an
  illegal phase (`setStatus` outside response phases, `setBody` outside
  body phases, `directResponse` outside response phases).
- A rule mixing `directResponse` with any incremental op.
- A `match` expression that does not compile to bool, a mutation
  `value`/`code` expression that does not compile to string/int, a
  `directResponse.headers` expression that does not compile to
  `map<string,string>`, or any expression referencing a variable not live
  in its phase.
- `defaults.extAuthz.action` not in {allow, deny}.
- `defaults.extProc.onBodyOverflow` not in {skip, fail}.
- Duplicate group name, or duplicate rule name within a group.
- Empty group (no rules).
- Fact spec missing required fields, duplicate name, unknown method.
- Initial fetch failure for a `url` method fact.

Any of these makes `policy.LoadBytes` return an error. The caller
(`cmd/main.go`) keeps the previous policy on a reload, or fails to start
on initial boot.
