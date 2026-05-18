# POLICY_DSL.md

Reference for the YAML policy file. The user-facing version lives in
the project README; this one is denser, no preamble, and is the source
of truth for what the parser accepts.

## Top-level structure

```yaml
defaults: # engine-wide knobs
logging: # access-log shape and redaction
facts: # named external values referenced as facts.<name>
groups: # ordered list of rule buckets
```

All sections are optional **except** `groups`, which must contain at
least one entry with at least one rule.

## `defaults`

```yaml
defaults:
  action: deny # allow | deny             default: deny
  denyStatus: 403 # int                      default: 403
  denyBody: "Forbidden" # string                   default: "Forbidden"
  maxBodyBytes: 1MiB # BytesSize                default: 1MiB
  allowOnError: false # bool                     default: false
```

`BytesSize` accepts plain integers (bytes) and human strings:
`1024`, `1KiB`, `2MiB`, `1GiB`, `1KB`, `1MB`, `1024b`.

`allowOnError` flips the default fail-closed behaviour: when a CEL
evaluation hits an error mid-request, the verdict becomes `allow`
instead of `deny`. Used rarely, with care.

## `logging`

```yaml
logging:
  level: info # debug|info|warn|error    default: info
  format: json # json|console             default: json
  logBody: false # bool                     default: false
  redactReveal: 6 # int                      default: 6
  excludeHeaders: [cookie, set-cookie]
  redactHeaders: [authorization, proxy-authorization, x-api-key, x-auth-token]
  redactQueryParams: [access_token, id_token, code]
```

Behaviour:

- Header keys are normalised to lowercase before exclude/redact checks.
- Redaction: if a value's length is `>= 2 * redactReveal`, the first
  `redactReveal` chars are kept and the rest replaced with `*`.
  Otherwise the value is fully masked. With `redactReveal: 0` every
  redacted value is fully masked.
- `logBody: true` adds `request.body.raw` to the access log. Off by
  default because DCR payloads carry secrets.
- `--log-level` / `--log-format` CLI flags override the YAML values
  when set.

## `facts`

A list of named external values. CEL sees them as `facts.<name>`.

```yaml
facts:
  - name: <identifier> # required, unique across facts
    method: value | file | url
    value: <any YAML shape> # required when method=value
    file: # required when method=file
      path: /abs/or/rel/path
    url: # required when method=url
      address: https://...
      interval: 10m # optional, default 10m
      timeout: 15s # optional, default 15s
      headers: # optional
        Authorization: "Bearer $TOKEN"
```

Method semantics:

| Method | Loaded                                               | Type seen by CEL |
| ------ | ---------------------------------------------------- | ---------------- |
| value  | At YAML parse; the value is used verbatim            | as declared      |
| file   | At `Start()`, the file is read once into a string    | `string`         |
| url    | At `Start()` (initial) + every `interval` afterwards | `string`         |

URL fact failure modes:

- Initial fetch fails → policy load is rejected. The previous policy
  (if any) keeps running.
- Refresh fails → previous value retained, `WARN` log emitted.

CEL helpers for parsing the raw string into structured data:

```cel
parseJSON(facts.chatgptFeed).prefixes.map(p, p.ipv4Prefix)
parseYAML(facts.mistralCidrs)
```

Both return an empty map `{}` on null/empty/invalid input, so the
expression stays safe before the first successful fetch.

## `groups`

A list of named buckets. Evaluated in declared order; the first group
that produces a verdict wins. If none decide, `defaults.action` applies.

```yaml
groups:
  - name: <identifier> # required, unique across groups
    description: ... # optional
    mode: firstMatch | all # optional, default firstMatch
    action: allow | deny # optional, default allow; inherited by rules
    match: | # optional CEL expression (default: true)
      <CEL bool expression>
    rules: # required, non-empty
      - <rule>
      - <rule>
```

Group `match` is evaluated **once** per request. If false, the whole
group is skipped silently.

### Modes

- **`firstMatch`** (default): the first rule whose `match` evaluates
  true decides. Use for "this request is allowed if ANY of these rules
  matches".
- **`all`**: every rule must match. The first failure produces the
  opposite of the group's `action`. Use for defence-in-depth where every
  predicate must hold.

### Rule

```yaml
- name: <identifier>          # required, unique within the group
  description: ...            # optional
  action: allow | deny        # optional; inherited from group when omitted
  match: |                    # CEL bool expression (default: true)
    <expression>
  fallthrough: next|allow|deny# default: next (only used in firstMatch groups)
  dryRun: false               # bool, default false
```

- A rule's effective `action` is its own when set, else the group's,
  else `allow`.
- `fallthrough` controls what happens in a `firstMatch` group when this
  rule's `match` is false: `next` tries the next rule; `allow`/`deny`
  short-circuits with that verdict.
- `dryRun: true` evaluates and logs the rule, but suppresses a `deny`
  decision (request is allowed through). The access log carries
  `dry_run: true` so an operator can see what _would_ have been denied.

### Decision flow (pseudo-code)

```
for each group in order:
    if group.match is false: continue
    switch group.mode:
        case firstMatch:
            for each rule in order:
                if rule.match is true:
                    return decision(rule.action XOR dryRun)
                else: apply rule.fallthrough
        case all:
            for each rule in order:
                if rule.match is false:
                    return decision(NOT group.action)
            return decision(group.action)
return decision(defaults.action)
```

## CEL environment

Two variables visible to every expression:

- **`request`** - built per request. See README "The `request` object"
  for the full table.
- **`facts`** - the snapshot of the facts registry. `facts.<name>` is
  whatever the source returned (a CEL list/map for `value`, a string
  for `file`/`url`).

Enabled CEL extensions: `ext.Strings()`, `ext.Encoders()`,
`ext.Lists()`, `ext.Sets()`, `ext.Math()`, `ext.Bindings()`.

Project-specific functions are documented in the README. Quick
reference:

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
  "level": "INFO" or "WARN",
  "msg": "request decided",
  "decision": "allow" or "deny",
  "rule": "<group>/<rule>" or "<defaults>",
  "reason": "matched" or "no group matched" or "...",
  "dry_run": false,
  "duration_ms": 0.31,
  "request": { ... }
}
```

`rule == "<defaults>"` means no group produced a verdict and the
`defaults.action` fired.

## Response headers emitted to Envoy

| Header         | Value                                            |
| -------------- | ------------------------------------------------ |
| `x-rv-result`  | `allow` or `deny`                                |
| `x-rv-rule`    | rule that decided (`group/rule` or `<defaults>`) |
| `x-rv-reason`  | short, human-readable                            |
| `x-rv-dry-run` | `true` if the rule was in shadow mode            |

These are mostly for debugging; Envoy itself only acts on the HTTP
status code (200 = allow, anything else = deny).

## Errors that stop policy load

- YAML doesn't parse.
- `defaults.action` not in {allow, deny}.
- Duplicate group name, or duplicate rule name within a group.
- Empty group (no `rules`).
- `mode` not in {firstMatch, all}.
- `action` not in {allow, deny}.
- `fallthrough` not in {next, allow, deny}.
- CEL compilation error on any `match` expression.
- Fact spec missing required fields, duplicate name, unknown method.
- Initial fetch failure for a `url` method fact.

Any of these makes `policy.LoadBytes` return an error. The caller
(`cmd/main.go`) keeps the previous policy on a reload, or fails to
start on initial boot.
