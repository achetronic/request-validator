# request-validator

A small Envoy / Istio **ext-authz** service that says `allow` or `deny`
for every request, based on a YAML policy you write in
[CEL](https://github.com/google/cel-spec).

It exists for the cases plain `AuthorizationPolicy` cannot reach:
inspecting the request body, mixing CIDRs and JWT claims with JSON
contents, validating OAuth `redirect_uris`, blocking specific paths
during certain hours, and other things that don't fit the
"method + path + header" model.

## Two-minute tour

The shortest meaningful policy: a single rule that allows POST requests
to a Keycloak Dynamic Client Registration endpoint when the client IP
sits in a small private range.

```yaml
defaults:
  action: deny

groups:
  - name: dcr-internal
    action: allow
    rules:
      - name: from-internal-cidr
        match: |
          request.method == 'POST' &&
          request.path.startsWith('/realms/mcp/clients-registrations') &&
          inCIDR(request.remoteIp, ['10.0.0.0/8'])
```

The pieces:

- `defaults.action` runs when nothing else decides. We default to
  `deny`, so missing a case never accidentally lets a request through.
- A `group` is a small bucket of rules with a shared verdict
  (`action: allow`). Rules inside a group inherit it.
- Each `rule` has a CEL boolean expression in `match`. When it
  evaluates to `true` the rule fires and the verdict is applied.
- `inCIDR(...)` is one of the small set of helper functions
  request-validator adds on top of CEL.

That is the whole shape of the language. The rest of the README
introduces it piece by piece with realistic examples.

## A few realistic recipes

### 1. Allow an admin endpoint from an office subnet during work hours

```yaml
groups:
  - name: admin-business-hours
    action: allow
    rules:
      - name: office-during-the-day
        match: |
          request.path.startsWith('/admin') &&
          inCIDR(request.remoteIp, ['203.0.113.0/24']) &&
          now().getHours('UTC') >= 7 &&
          now().getHours('UTC') < 19
```

`now()` returns the current UTC time. CEL's timestamp accessors
(`getHours`, `getDayOfWeek`, `getMonth`...) cover the typical
schedule checks without dragging in cron.

### 2. Require a header on a specific path

```yaml
groups:
  - name: webhook-needs-signature
    action: allow
    rules:
      - name: signed-with-x-hub-signature
        match: |
          request.path.startsWith('/hooks/github') &&
          has('x-hub-signature-256', request.headers) &&
          request.header['x-hub-signature-256'].startsWith('sha256=')
```

`has('x-hub-signature-256', request.headers)` is a small helper:
the header must exist and have a non-empty value. After that we look
at the first value directly via `request.header[...]`.

### 3. Block a sensitive realm on public hostnames

```yaml
groups:
  - name: keep-master-realm-private
    action: deny
    rules:
      - name: no-master-on-public-hosts
        match: |
          request.host in ['auth.example-1.com', 'auth.example-2.com'] &&
          request.path.startsWith('/realms/master')
```

A whole group declared as `action: deny` keeps the intent obvious at
a glance.

### 4. Decide based on what the JSON body says

This is the kind of check Istio's `AuthorizationPolicy` cannot make
on its own. Here we only allow Dynamic Client Registration when every
`redirect_uri` in the body belongs to an approved provider:

```yaml
groups:
  - name: dcr-trusted-redirects
    action: allow
    match: |
      request.method == 'POST' &&
      request.path.matches('^/realms/mcp/clients-registrations(/.*)?$') &&
      request.body.jsonOk
    rules:
      - name: antigravity
        match: |
          request.body.json.redirect_uris.all(u,
            u.startsWith('https://antigravity.google/'))

      - name: chatgpt
        match: |
          request.body.json.redirect_uris.all(u,
            u.matches('^https://([a-z0-9-]+\\.)?openai\\.com/.+$'))
```

The group's `match` plays the role of a shared filter (POST, the right
path, parseable JSON body). Each rule below adds the provider-specific
test on top of that.

### 5. Defence in depth for an admin area

When you want several independent conditions to all hold, set the
group's `mode` to `all`:

```yaml
groups:
  - name: admin-defence-in-depth
    action: allow
    mode: all
    match: |
      request.path.startsWith('/admin')
    rules:
      - name: from-internal-network
        match: inCIDR(request.remoteIp, ['10.0.0.0/8', '192.168.0.0/16'])
      - name: has-admin-claim
        match: request.header['x-user-groups'].contains('platform-admins')
      - name: no-debug-header
        match: '!has("x-debug", request.headers)'
```

In `all` mode, one rule failing causes the group to deny. It is the
"every box on this checklist must be ticked" idiom.

A larger example with several groups, facts and the real DCR
flow lives in [`examples/policy.yaml`](examples/policy.yaml). Have a
read once you've gone through the rest of this document.

## How the engine picks a verdict

Groups are evaluated in order. Each group decides on its own and the
**first** group that produces a verdict wins; if none do,
`defaults.action` takes over.

Inside a group, the optional `match` at the group level is a
"do I apply to this request at all?" filter. If it returns false the
group is skipped silently. Otherwise the group's `mode` runs:

- **`firstMatch`** (the default): the first rule whose `match`
  evaluates to true decides. Use it for "any of these rules is enough".
- **`all`**: every rule must return true. The first failing rule
  causes the group to deny.

A rule's effective `action` is its own when declared, otherwise the
group's, otherwise `allow`. This lets a whole group of allow rules
keep one outlier that flips to `deny` for an anomaly check.

For `firstMatch` groups, a rule whose `match` returned false moves on
to the next rule by default (`fallthrough: next`). Setting
`fallthrough` to `allow` or `deny` short-circuits the group with that
verdict.

A rule can also be marked `dryRun: true`. It is still evaluated and
logged exactly like a real rule, but a `deny` verdict it would
produce is suppressed (the request goes through). Useful for trying a
tightening in production before flipping it on.

## What CEL sees about a request

Every CEL expression has access to two top-level variables: `request`
(the incoming HTTP request, populated for each call) and `facts`
(see the next section).

| Field                      | Type                        | Notes                                                  |
| -------------------------- | --------------------------- | ------------------------------------------------------ |
| `request.method`           | `string`                    | HTTP verb                                              |
| `request.scheme`           | `string`                    | http / https (from X-Forwarded-Proto)                  |
| `request.host`             | `string`                    | request authority, no port                             |
| `request.path`             | `string`                    | URL path                                               |
| `request.remoteIp`         | `string`                    | client IP (X-Forwarded-For first hop, else RemoteAddr) |
| `request.headers`          | `map<string, list<string>>` | all headers, keys lowercased                           |
| `request.header`           | `map<string, string>`       | first value per header (lowercased keys)               |
| `request.queries`          | `map<string, list<string>>` | all query parameters                                   |
| `request.query`            | `map<string, string>`       | first value per query parameter                        |
| `request.body.raw`         | `string`                    | full body, capped at `defaults.maxBodyBytes`           |
| `request.body.size`        | `int`                       | bytes                                                  |
| `request.body.contentType` | `string`                    | shortcut for `request.header['content-type']`          |
| `request.body.json`        | `dyn`                       | parsed JSON, or `{}` when not JSON                     |
| `request.body.jsonOk`      | `bool`                      | body parsed successfully as JSON                       |
| `request.body.yaml`        | `dyn`                       | parsed YAML, or `{}` when not YAML                     |
| `request.body.yamlOk`      | `bool`                      | body parsed successfully as YAML                       |

For the body to arrive at all, Envoy needs to be told to forward it
(see "Plugging into Istio" below).

## Facts: data that changes more often than the policy

Sometimes the data your policy depends on changes too often to keep
inline. The set of CIDRs OpenAI publishes for ChatGPT actions is the
canonical example: it can change every few weeks. Hardcoding the list
into the policy file means a redeploy each time.

`facts` solves this. You declare a named value at the top of the file
and reference it from CEL as `facts.<name>`. Three ways to load one:

| Method  | When                                                 | What CEL sees    |
| ------- | ---------------------------------------------------- | ---------------- |
| `value` | Inline in YAML, parsed at load time                  | The value as declared |
| `file`  | Read from disk at startup or reload                  | A string with the file contents |
| `url`   | Fetched periodically by a background goroutine       | A string with the last successful body |

A small example with all three:

```yaml
facts:
  - name: internalCidrs
    method: value
    value:
      - 10.0.0.0/8
      - 192.168.0.0/16

  - name: trustedClients
    method: file
    file:
      path: /etc/policy/lists/trusted-clients.yaml

  - name: chatgptFeed
    method: url
    url:
      address: https://openai.com/chatgpt-actions.json
      interval: 10m
      timeout: 15s
      headers:                # optional, for private feeds
        Authorization: "Bearer $TOKEN"
```

Using them from CEL is just dotted access:

```cel
inCIDR(request.remoteIp, facts.internalCidrs)
```

`file` and `url` facts arrive as raw strings, so you parse them
on the spot:

```cel
inCIDR(request.remoteIp,
  parseJSON(facts.chatgptFeed).prefixes.map(p, p.ipv4Prefix))
```

`parseJSON` and `parseYAML` return an empty map `{}` if the input is
empty, null or malformed. That keeps expressions safe before the
first fetch lands. Typical pattern is to guard the group's `match`:

```yaml
match: |
  request.path.startsWith('/api') &&
  facts.chatgptFeed != null && facts.chatgptFeed != ""
```

If the first fetch of a `url` fact fails outright, the **policy load
is rejected** and the previous policy stays active. Subsequent failed
refreshes log a warning and keep serving the last good value. This is
intentional: we'd rather hold on to stale data than open or close the
gate based on an empty feed.

## Logging

`request-validator` emits one structured log record per request. It
also logs internal events (boot, reload, fact fetch failures) through
the same logger.

```yaml
logging:
  level: info               # debug | info | warn | error
  format: json              # json | console
  logBody: false            # opt-in: include the request body
  redactReveal: 6           # leading chars kept when masking a value
  excludeHeaders:           # never appear in the log
    - cookie
    - set-cookie
  redactHeaders:            # appear with their value masked
    - authorization
    - proxy-authorization
    - x-api-key
    - x-auth-token
  redactQueryParams:        # same treatment for query params
    - access_token
    - id_token
    - code
```

The whole `logging` block is optional with sensible defaults. The CLI
flags `--log-level` and `--log-format` override the file when set,
so you can crank up verbosity at runtime without editing the
ConfigMap.

A typical allow line in JSON:

```json
{
  "time": "2026-05-19T12:14:59.845Z",
  "level": "INFO",
  "msg": "request decided",
  "decision": "allow",
  "rule": "dcr-trusted-redirects/antigravity",
  "reason": "matched",
  "dry_run": false,
  "duration_ms": 0.31,
  "request": {
    "method": "POST",
    "host": "auth.example-1.com",
    "path": "/realms/mcp/clients-registrations",
    "query": "code=***&debug=1",
    "remote_ip": "203.0.113.5",
    "headers": {
      "content-type": "application/json",
      "authorization": "Bearer*********************************",
      "x-api-key": "***"
    },
    "body": { "size": 48, "content_type": "application/json" }
  }
}
```

Notes on the redaction:

- `cookie` is configured as excluded, so it doesn't appear at all.
- `authorization` is long enough that we keep the first 6 characters
  visible (here `Bearer`) and mask the rest with `*`.
- `x-api-key` is short, so it gets fully masked.
- The query parameter `code` is in `redactQueryParams`, so it shows
  as `code=***`. `debug=1` stays untouched.

Values shorter than `2 * redactReveal` are always fully masked so
short tokens don't leak half of themselves.

The `console` format produces the same information laid out as a
single dense `key=value` line. It is meant for `kubectl logs -f`
during development, not for ingestion. Use `json` in production.

## CEL function reference

CEL itself comes with a small standard library; we enable
`ext.Strings()`, `ext.Encoders()`, `ext.Lists()`, `ext.Sets()`,
`ext.Math()` and `ext.Bindings()` on top of that. The following
project-specific functions are also registered.

### Network

| Function       | Signature                                         | Description                                                                                     |
| -------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `inCIDR`       | `inCIDR(ip: string, cidrs: list<string>) -> bool` | True if `ip` belongs to any of the listed CIDRs. Plain IPs are accepted (auto-`/32` or `/128`). |
| `ipFamily`     | `ipFamily(ip: string) -> string`                  | `"ipv4"`, `"ipv6"` or `""`.                                                                     |
| `isPrivateIP`  | `isPrivateIP(ip: string) -> bool`                 | RFC1918, RFC4193, link-local.                                                                   |
| `isLoopbackIP` | `isLoopbackIP(ip: string) -> bool`                | `127.0.0.0/8`, `::1`.                                                                           |
| `parseURL`     | `parseURL(s: string) -> map<string, dyn>`         | Returns `{scheme, host, port, path, query, fragment, username, password}`.                      |

### Strings (glob)

| Function  | Signature                                            | Description                                                                                                       |
| --------- | ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `glob`    | `glob(s: string, pattern: string) -> bool`           | Shell-style globs. `*` matches anything except `/`, `**` matches everything, `?` is one char, `[abc]` is a class. |
| `globAny` | `globAny(s: string, patterns: list<string>) -> bool` | True if any glob in the list matches.                                                                             |

For substring, replace, split, lower, upper and similar, use CEL's
`ext.Strings()` directly: `s.lower()`, `s.split(',')`, etc.

### Encoding and hashing

| Function             | Signature                                               | Description                                                                                                              |
| -------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `sha256Hex`          | `sha256Hex(s: string) -> string`                        | Lowercase hex of SHA-256(s).                                                                                             |
| `parseJWTUnverified` | `parseJWTUnverified(token: string) -> map<string, dyn>` | Returns `{header, payload}` parsed JSON. **Does not** verify the signature; use only when another component already did. |

`base64.encode` and `base64.decode` come from `ext.Encoders()`.

### Time

| Function | Signature            | Description                                                            |
| -------- | -------------------- | ---------------------------------------------------------------------- |
| `now`    | `now() -> timestamp` | Current UTC time. CEL accessors (`getHours`, `getDayOfWeek`...) apply. |

### Structured data

| Function    | Signature                                        | Description                                                                                             |
| ----------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| `parseJSON` | `parseJSON(v: dyn) -> dyn`                       | Parse a JSON string; returns `{}` on null/empty/invalid input.                                          |
| `parseYAML` | `parseYAML(v: dyn) -> dyn`                       | Parse a YAML string; returns `{}` on null/empty/invalid input.                                          |
| `jsonPath`  | `jsonPath(root: dyn, expr: string) -> list<dyn>` | Apply a JSONPath-lite subset (`$.a.b[*]`, `$..name`, `$[0]`, `$['key']`). Use when the path is dynamic. |

### HTTP shortcuts

| Function  | Signature                                                       | Description                                                                                                                  |
| --------- | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `has`     | `has(name: string, bucket: map) -> bool`                        | True if `name` is a key in `bucket` AND has at least one non-empty value. Works for `request.headers` and `request.queries`. |
| `firstOr` | `firstOr(bucket: map, name: string, default: string) -> string` | First value for `name` (string or list bucket), or `default` when missing/empty.                                             |

A handful of common idioms become very short:

```cel
has('x-api-key', request.headers)
firstOr(request.header, 'x-debug', 'no') == 'yes'
request.query['debug'] == '1'
request.headers['x-forwarded-for'].exists(v, inCIDR(v, ['10.0.0.0/8']))
```

## Running it

From source, with the bundled example:

```bash
go run ./cmd --config examples/policy.yaml --log-level debug --log-format console
```

The project also ships an OCI image at
`ghcr.io/achetronic/request-validator:<semver>`. Deploy it with
whatever templating you already use. We use
[`bjw-s` app-template](https://github.com/bjw-s-labs/helm-charts/tree/main/charts/other/app-template);
a minimal HelmRelease values block looks like:

```yaml
controllers:
  main:
    containers:
      main:
        image:
          repository: ghcr.io/achetronic/request-validator
          tag: v0.1.0
        args:
          - --config=/etc/policy/policy.yaml
        probes:
          liveness:  { type: HTTP, custom: true, spec: { httpGet: { path: /healthz, port: 8080 } } }
          readiness: { type: HTTP, custom: true, spec: { httpGet: { path: /readyz,  port: 8080 } } }
service:
  main: { controller: main, ports: { http: { port: 8080 } } }
persistence:
  policy:
    type: configMap
    name: request-validator-policy
    globalMounts: [ { path: /etc/policy } ]
```

### Endpoints

| Endpoint   | Purpose                                              |
| ---------- | ---------------------------------------------------- |
| `/`        | ext-authz endpoint; everything else lands here       |
| `/healthz` | liveness                                             |
| `/readyz`  | readiness; false until a policy is loaded            |
| `/metrics` | Prometheus counters, broken down by group and rule   |

### Hot reload

The policy file is reloaded automatically as soon as it changes on
disk. This covers three realistic scenarios:

- A plain in-place write picks up immediately.
- A save-via-rename (vim's `:w`, IntelliJ's atomic write, etc.) is
  also recognised.
- Kubernetes ConfigMap updates trigger an in-process reload too: the
  watcher tracks the `..data` symlink kubelet flips atomically when
  it publishes a new projection.

Multiple events within a short window (default 200 ms) are debounced
into a single reload. If the new policy fails to load (parse error,
fact fetch failure, etc.) it is rejected and the previous policy
stays active.

If fsnotify can't deliver events (NFS, FUSE), sending `SIGHUP`
to the process triggers the same reload code path.

### Flags

```
--port               HTTP port (default 8080)
--config             Path to the YAML policy (default policy.yaml)
--log-level          Override logging.level (debug|info|warn|error)
--log-format         Override logging.format (json|console)
--watch              Auto-reload on config file changes (default true)
--watch-debounce-ms  Debounce window for the watcher in ms (default 200)
--version            Print version and exit
```

The config file is run through `os.ExpandEnv` before parsing, so you
can use `$VAR` and `${VAR}` placeholders that get substituted from
environment variables.

## Response headers

Every response carries a few diagnostic headers so you can see which
rule produced the verdict:

| Header         | Value                                                       |
| -------------- | ----------------------------------------------------------- |
| `x-rv-result`  | `allow` or `deny`                                           |
| `x-rv-rule`    | rule that decided, formatted `group/rule` (or `<defaults>`) |
| `x-rv-reason`  | short, human-readable reason                                |
| `x-rv-dry-run` | `true` if the rule that decided was in shadow mode          |

Useful both during development and as a way for the protected service
to log "this request was let through by rule X" if it wants to.

## Plugging into Istio

Two pieces of Istio configuration:

1. Register the validator as an extension provider in `MeshConfig`.
   This is mesh-wide; one entry per validator deployment.

   ```yaml
   # Ref: https://istio.io/latest/docs/reference/config/istio.mesh.v1alpha1/
   meshConfig:
     extensionProviders:
       - name: request-validator
         envoyExtAuthzHttp:
           service: request-validator.<NAMESPACE>.svc.cluster.local
           port: 8080
           failOpen: false
           timeout: 2s
           # Forward the body so policies can inspect it. Only
           # maxRequestBytes and allowPartialMessage apply here;
           # packAsBytes is gRPC-only.
           includeRequestBodyInCheck:
             maxRequestBytes: 1048576
             allowPartialMessage: false
           headersToDownstreamOnDeny: [content-type, x-rv-result, x-rv-rule, x-rv-reason, x-rv-dry-run]
           headersToUpstreamOnAllow:  [x-rv-result, x-rv-rule, x-rv-reason, x-rv-dry-run]
           includeRequestHeadersInCheck:
             - authorization
             - content-type
             - cookie
             - x-api-key
             - x-user-groups
             - x-forwarded-for
             - x-forwarded-proto
   ```

2. Point an `AuthorizationPolicy` with `action: CUSTOM` at it. Only
   the matched traffic is delegated to the validator; the rest stays
   on whatever Istio policies you had before.

   ```yaml
   apiVersion: security.istio.io/v1
   kind: AuthorizationPolicy
   metadata:
     name: keycloak-dcr-ext-authz
     namespace: keycloak
   spec:
     selector:
       matchLabels:
         app.kubernetes.io/name: keycloak
     action: CUSTOM
     provider:
       name: request-validator
     rules:
       - to:
           - operation:
               hosts: [auth.example-1.com, auth.example-2.com]
               paths:
                 - /realms/*/clients-registrations
                 - /realms/*/clients-registrations/*
   ```

If you find yourself adding to `includeRequestHeadersInCheck` every
time a policy starts looking at a new header, there is a more
flexible alternative: an `EnvoyFilter` that pins the ext-authz
filter's `allowed_headers` to `.*` on the protected workload's
sidecar. See [`examples/config-for-istio.yaml`](examples/config-for-istio.yaml)
for the full pattern.

## License

Apache-2.0.
