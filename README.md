# request-validator

A small Envoy / Istio service implementing both HTTP **ext-authz** (admit or deny requests) and gRPC **ext_proc** (inspect and mutate live traffic), guided by a single declarative YAML policy written in [CEL](https://github.com/google/cel-spec).

It exists for cases that plain `AuthorizationPolicy` cannot reach. On the deciding side: inspecting the request body, mixing CIDRs and JWT claims with JSON contents, validating OAuth `redirect_uris`, or blocking specific paths during certain hours. On the rewriting side: turning an untrusted redirect into a warning page, stripping internal headers off a response, injecting a header before it reaches the upstream, or replacing a body or status code in transit.

## Table of contents

- [The two engines](#the-two-engines)
- [Engine 1: extAuthz (deciding)](#engine-1-extauthz-deciding)
  - [A two-minute tour](#a-two-minute-tour)
  - [Recipes](#recipes)
  - [How extAuthz picks a verdict](#how-extauthz-picks-a-verdict)
  - [extAuthz defaults](#extauthz-defaults)
- [Engine 2: extProc (mutating)](#engine-2-extproc-mutating)
  - [Phases and modes](#phases-and-modes)
  - [Mutations](#mutations)
  - [The directResponse operation](#the-directresponse-operation)
  - [extProc defaults](#extproc-defaults)
  - [Small recipes](#small-recipes)
  - [Recipe: rewrite an untrusted redirect into a warning page](#recipe-rewrite-an-untrusted-redirect-into-a-warning-page)
- [Common to both engines](#common-to-both-engines)
  - [Global dry-run](#global-dry-run)
  - [What CEL sees](#what-cel-sees)
  - [Facts](#facts)
  - [CEL function reference](#cel-function-reference)
  - [Logging](#logging)
- [Operating the service](#operating-the-service)
  - [Running it](#running-it)
  - [Endpoints](#endpoints)
  - [Hot reload](#hot-reload)
  - [Flags](#flags)
  - [Response headers](#response-headers)
  - [Plugging into Istio](#plugging-into-istio)
- [License](#license)

## The two engines

request-validator runs two engines from one policy file. Every group picks which one it programs with `parameters.engine`. They solve different problems; use either or both.

**extAuthz (HTTP, the gatekeeper).** Envoy asks "should this request go through?" and we answer `allow` or `deny`. Reach for it to admit or block traffic: let only known clients hit an endpoint, reject a DCR body that declares a wildcard `redirect_uri`, close a realm on a public hostname. It never changes the request or the response, it only decides.

**extProc (gRPC, the surgeon).** Envoy streams the request and the response through us, and we can inspect and rewrite them: set or drop headers, replace a body, change a status code, or discard the upstream response and serve our own. Reach for it when deciding is not enough and you need to change what flows: rewrite an untrusted redirect into a warning page, strip leaking internal headers off a response, add a header before it reaches the upstream.

Rule of thumb: if the answer is yes or no, it is extAuthz; if you need to touch headers, body or status, it is extProc.

How they differ at a glance:

| | extAuthz | extProc |
| --- | --- | --- |
| Envoy filter | HTTP ext-authz | gRPC ext_proc |
| Listens on | `--port` (8080) | `--grpc-port` (9090) |
| Produces | a verdict (`allow` / `deny`) | mutations, or a direct response |
| Acts on | the request | the request and the response |
| Rule body | `validation` | `mutations` |
| Group modes | `firstMatch`, `matchAll` | `firstMatch`, `applyAll` |

This README documents extAuthz in full first, then extProc in full, then the parts both engines share. Read the engine you need; the common sections at the end apply to both, and call out where the two behave differently.

## Engine 1: extAuthz (deciding)

The extAuthz engine answers one question per request: `allow` or `deny`. Envoy forwards the request to us over HTTP ext-authz, we evaluate the policy, and Envoy enforces the verdict. This engine never changes the request; it only decides.

### A two-minute tour

The shortest meaningful policy: a single rule that allows POST requests to a Keycloak Dynamic Client Registration endpoint when the client IP sits in a small private range.

```yaml
defaults:
  extAuthz:
    action: deny

groups:
  - name: dcr-internal
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: from-internal-cidr
        match: |
          request.method == 'POST' &&
          request.path.startsWith('/realms/mcp/clients-registrations') &&
          inCIDR(request.remoteIp, ['10.0.0.0/8'])
        validation:
          action: allow
```

The pieces:

- `defaults.extAuthz.action` runs when no rule decides. We default to `deny`, so missing a case never accidentally lets a request through.
- A `group` matches requests and binds them to an engine (`parameters.engine: extAuthz`) with a decision mode (`parameters.mode: firstMatch`).
- Each `rule` has a mandatory CEL boolean expression in `match`. When it evaluates to `true` the rule fires and its `validation.action` is returned.
- `inCIDR(...)` is one of the helper functions request-validator adds on top of CEL.

That is the shape of the language for this engine. The recipes below build on it.

### Recipes

Every recipe here uses `engine: extAuthz`, so each one returns a verdict.

#### 1. Allow an admin endpoint from an office subnet during work hours

```yaml
groups:
  - name: admin-business-hours
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: office-during-the-day
        match: |
          request.path.startsWith('/admin') &&
          inCIDR(request.remoteIp, ['203.0.113.0/24']) &&
          now().getHours('UTC') >= 7 &&
          now().getHours('UTC') < 19
        validation:
          action: allow
```

`now()` returns the current UTC time. CEL's timestamp accessors (`getHours`, `getDayOfWeek`, `getMonth`...) cover the typical schedule checks without dragging in cron.

#### 2. Require a header on a specific path

```yaml
groups:
  - name: webhook-needs-signature
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: signed-with-x-hub-signature
        match: |
          request.path.startsWith('/hooks/github') &&
          has('x-hub-signature-256', request.headers) &&
          request.header['x-hub-signature-256'].startsWith('sha256=')
        validation:
          action: allow
```

`has('x-hub-signature-256', request.headers)` is a helper: the header must exist and have a non-empty value. After that we look at the first value directly via `request.header[...]`.

#### 3. Block a sensitive realm on public hostnames

```yaml
groups:
  - name: keep-master-realm-private
    parameters:
      engine: extAuthz
      mode: firstMatch
    rules:
      - name: no-master-on-public-hosts
        match: |
          request.host in ['auth.example-1.com', 'auth.example-2.com'] &&
          request.path.startsWith('/realms/master')
        validation:
          action: deny
```

Explicit validation actions on each rule keep the intent clear at a glance.

#### 4. Decide based on what the JSON body says

This is the kind of check Istio's `AuthorizationPolicy` cannot make on its own. Here we only allow Dynamic Client Registration when every `redirect_uri` in the body belongs to an approved provider:

```yaml
groups:
  - name: dcr-trusted-redirects
    parameters:
      engine: extAuthz
      mode: firstMatch
    match: |
      request.method == 'POST' &&
      request.path.matches('^/realms/mcp/clients-registrations(/.*)?$') &&
      request.body.jsonOk
    rules:
      - name: antigravity
        match: |
          request.body.json.redirect_uris.all(u,
            u.startsWith('https://antigravity.google/'))
        validation:
          action: allow

      - name: chatgpt
        match: |
          request.body.json.redirect_uris.all(u,
            u.matches('^https://([a-z0-9-]+\\.)?openai\\.com/.+$'))
        validation:
          action: allow
```

The group's `match` plays the role of a shared filter (POST, the right path, parseable JSON body). Each rule below adds the provider-specific test on top of that.

#### 5. Defence in depth for an admin area

When you want several independent conditions to all hold, set the group's `mode` to `matchAll`:

```yaml
groups:
  - name: admin-defence-in-depth
    parameters:
      engine: extAuthz
      mode: matchAll
    match: |
      request.path.startsWith('/admin')
    rules:
      - name: from-internal-network
        match: inCIDR(request.remoteIp, ['10.0.0.0/8', '192.168.0.0/16'])
        validation:
          action: allow
      - name: has-admin-claim
        match: request.header['x-user-groups'].contains('platform-admins')
        validation:
          action: allow
      - name: no-debug-header
        match: '!has("x-debug", request.headers)'
        validation:
          action: allow
```

In `matchAll` mode, every rule in the group must match. The first failure causes the group to immediately produce a deny verdict.

A larger example with several groups, facts, and the real DCR flow lives in [`examples/policy.yaml`](examples/policy.yaml). Have a read once you've gone through the rest of this document.

### How extAuthz picks a verdict

Groups are evaluated in declared order. Only groups with `engine: extAuthz` take part here; `extProc` groups are ignored by this engine. The first extAuthz group that produces a verdict wins. If no group produces one, the fallback in `defaults.extAuthz.action` applies.

Inside a group, the optional `match` expression filters incoming requests. If it evaluates to false, the group is silently skipped. Otherwise, the group's `parameters.mode` runs:

- **`firstMatch`**: the first rule whose `match` evaluates to true decides. The group produces that rule's `validation.action` and evaluation stops. If no rule matches, the group produces no verdict and evaluation proceeds to the next group.
- **`matchAll`**: every rule in the group must match. The first rule that fails to match makes the group produce a `deny` verdict immediately. If all rules match, the group produces an `allow` verdict.

A rule's `match` expression is mandatory. A fallback rule must spell out `match: 'true'`. There is no inheritance of actions and no fallthrough between rules: each rule states its own `validation.action`.

### extAuthz defaults

The extAuthz engine reads its defaults from `defaults.extAuthz`:

```yaml
defaults:
  extAuthz:
    action: deny # Fallback verdict when no group decides (allow | deny)
    denyStatus: 403 # HTTP status returned on deny
    denyBody: "Forbidden" # HTTP body returned on deny
    allowOnError: false # If true, a CEL evaluation error allows instead of denies
    maxBodyBytes: 1MiB # Max request body buffered for inspection
```

`BytesSize` values accept plain integers (bytes) or human strings: `1024`, `1KiB`, `2MiB`, `1GiB`, `1KB`, `1MB`, `1024b`.

Two behaviours worth knowing:

- **`allowOnError`**: by default any evaluation error (a missing key, a type error) fails closed to `deny`. Set this to `true` to fail open to `allow` instead. Use it sparingly.
- **Body overflow is a fixed fail-closed deny**: if the request body is larger than `maxBodyBytes`, the engine denies, full stop. This is not configurable: a gatekeeper that cannot read the whole request must not admit it.

There is also a global `defaults.dryRun` that affects both engines, covered in [Global dry-run](#global-dry-run).

## Engine 2: extProc (mutating)

The extProc engine is the other half. Instead of deciding, it inspects and rewrites traffic. It runs as a gRPC Envoy `ext_proc` server: Envoy streams the request and the response through it, and the policy can set or drop headers, replace a body, change a status code, or discard the upstream response and serve its own.

A minimal extProc group, which stamps a header onto every response:

```yaml
groups:
  - name: stamp-a-header
    parameters:
      engine: extProc
      phase: responseHeaders
      mode: applyAll
    rules:
      - name: add-marker
        match: "true"
        mutations:
          - op: setHeader
            name: x-processed-by
            value: "'request-validator'"
```

Two things are new compared to extAuthz: a `phase` (extProc acts at a specific point in the request/response lifecycle) and a `mutations` block instead of `validation` (the rule changes traffic instead of returning a verdict). Note also that header values are CEL expressions: `"'request-validator'"` is a CEL string literal, quotes included.

### Phases and modes

An extProc group must declare a `phase` in addition to `engine` and `mode`.

**`parameters.phase`** is the Envoy processing stage the group runs at. It also fixes which CEL variables are live and which mutation ops are legal:

| Phase             | Runs on            | Live CEL variables             |
| ----------------- | ------------------ | ------------------------------ |
| `requestHeaders`  | request headers    | `request`, `facts`             |
| `requestBody`     | request body       | `request`, `facts`             |
| `responseHeaders` | response headers   | `request`, `response`, `facts` |
| `responseBody`    | response body      | `request`, `response`, `facts` |

The `response` variable only exists in the response phases. An expression that references `response` in a request phase fails to compile at policy load.

**`parameters.mode`** for extProc:

- **`firstMatch`**: applies the mutations of the first rule whose `match` is true, then stops the group. An empty list `mutations: []` is valid: it counts as a match that changes nothing but still halts the group.
- **`applyAll`**: every rule that matches contributes its mutations, in declaration order. If two rules write the same header, the last write wins.

(The extAuthz modes are `firstMatch` and `matchAll`; extProc's second mode is `applyAll`. The names differ because the behaviour differs: `matchAll` is a verdict conjunction, `applyAll` is a mutation accumulation.)

### Mutations

Rules in an extProc group carry a `mutations` list instead of a `validation`:

```yaml
rules:
  - name: modify-headers
    match: "true"
    mutations:
      - op: setHeader
        name: x-custom-header
        value: "request.host + '/custom'"
```

| Operation        | Fields                      | Legal phases                      | Semantics                                                                |
| ---------------- | --------------------------- | --------------------------------- | ------------------------------------------------------------------------ |
| `setHeader`      | `name`, `value`             | all                               | Overwrites the header if present, creates it if absent.                  |
| `appendHeader`   | `name`, `value`             | all                               | Adds the value as an extra header entry, keeping existing ones.          |
| `removeHeader`   | `name`                      | all                               | Deletes the header. Idempotent (no-op if absent).                        |
| `setBody`        | `value`                     | `requestBody`, `responseBody`     | Replaces the whole payload and recomputes Content-Length.                |
| `setStatus`      | `code`                      | `responseHeaders`, `responseBody` | Overrides the HTTP response status code.                                 |
| `directResponse` | `status`, `headers`, `body` | `responseHeaders`, `responseBody` | Discards the upstream response and serves a custom one. See below.       |

`value` is a CEL expression returning a string; `code` is a CEL expression returning an integer. Both are type-checked at policy load. `setBody` recomputes Content-Length, but not Content-Type: if the payload format changes, set `content-type` yourself with `setHeader`.

### The directResponse operation

`directResponse` does not mutate the upstream response; it throws it away and serves a brand-new one (mapping to Envoy's `ImmediateResponse`). It is the right tool when you want to stop the upstream response and show your own, for example turning a redirect into a warning page.

It is legal in `responseHeaders` and `responseBody`. It works in `responseHeaders` even when the upstream sent no body (the bodiless `302` case), which `setBody` cannot do because the body phase never fires for an empty body.

A rule with `directResponse` is exclusive: it must be the only mutation in that rule. Mixing it with `setHeader`, `setBody`, etc. is rejected at load, because those incremental ops would mutate a response that is being discarded anyway. In `applyAll`, the first `directResponse` that fires wins and short-circuits the rest.

Fields:

- `status`: an integer literal (e.g. `200`).
- `headers`: a CEL expression returning `map<string,string>`. Use a map literal for fixed headers (`{"content-type": "text/html"}`), or `response.header` to carry over every original header. Map merging is not available in this CEL build, so it is one or the other, not "all of the originals plus an override".
- `body`: a CEL expression returning a string.

Under dry-run (global or per-rule) a `directResponse` is computed and logged ("would directRespond") but not served; the stream continues.

### extProc defaults

The extProc engine reads its defaults from `defaults.extProc`:

```yaml
defaults:
  extProc:
    maxBodyBytes: 1MiB # Max request/response body buffered for a body phase
    onBodyOverflow: fail # What to do when a body exceeds maxBodyBytes (skip | fail)
```

When a body in a body phase exceeds `maxBodyBytes`:

- `skip`: the original body passes through unmutated (the policy does not run on it).
- `fail`: the engine returns an immediate fail-closed response.

Unlike extAuthz, where overflow is a fixed deny, here you choose. `skip` favours not breaking large responses; `fail` favours not letting an uninspected body through. There is no `truncate` option, because acting on half a body is worse than either.

There is also a global `defaults.dryRun` that affects both engines, covered in [Global dry-run](#global-dry-run).

### Small recipes

Short, single-purpose examples. Each uses `engine: extProc`.

#### Strip internal headers off every response

Keep server fingerprints and internal hints from leaking to clients. `applyAll` so every matching rule contributes, and `match: "true"` so it always fires.

```yaml
groups:
  - name: strip-leaky-headers
    parameters:
      engine: extProc
      phase: responseHeaders
      mode: applyAll
    rules:
      - name: drop-fingerprints
        match: "true"
        mutations:
          - op: removeHeader
            name: server
          - op: removeHeader
            name: x-powered-by
```

#### Add security headers to every response

```yaml
groups:
  - name: security-headers
    parameters:
      engine: extProc
      phase: responseHeaders
      mode: applyAll
    rules:
      - name: harden
        match: "true"
        mutations:
          - op: setHeader
            name: x-frame-options
            value: "'DENY'"
          - op: setHeader
            name: x-content-type-options
            value: "'nosniff'"
          - op: setHeader
            name: strict-transport-security
            value: "'max-age=63072000; includeSubDomains'"
```

#### Inject a header before the upstream sees it

Runs on `requestHeaders`, so only `request` and `facts` are live (no `response` yet). Useful to pass a derived value to the backend.

```yaml
groups:
  - name: tag-upstream-request
    parameters:
      engine: extProc
      phase: requestHeaders
      mode: firstMatch
    rules:
      - name: forward-client-network
        match: inCIDR(request.remoteIp, ['10.0.0.0/8'])
        mutations:
          - op: setHeader
            name: x-client-tier
            value: "'internal'"
```

#### Normalise an upstream error status

Map a leaky upstream `500` to a generic `503` without touching the body. `setStatus` only takes the integer code; pair it with a `setHeader` if you also want to mark it.

```yaml
groups:
  - name: mask-5xx
    parameters:
      engine: extProc
      phase: responseHeaders
      mode: firstMatch
    rules:
      - name: five-hundred-to-503
        match: "response.status == 500"
        mutations:
          - op: setStatus
            code: "503"
          - op: setHeader
            name: x-rv-normalised
            value: "'true'"
```

#### Append a value without clobbering existing ones

`appendHeader` adds an entry and keeps the ones already there, unlike `setHeader` which overwrites. Handy for multi-valued headers.

```yaml
groups:
  - name: extra-vary
    parameters:
      engine: extProc
      phase: responseHeaders
      mode: firstMatch
    rules:
      - name: vary-on-language
        match: "true"
        mutations:
          - op: appendHeader
            name: vary
            value: "'Accept-Language'"
```

#### Match on the response body, rewrite a header

Body phases (`responseBody` here) need Envoy to buffer the body (see [Plugging into Istio](#plugging-into-istio)). Once buffered, `response.body.json` is available.

```yaml
groups:
  - name: flag-error-payloads
    parameters:
      engine: extProc
      phase: responseBody
      mode: firstMatch
    rules:
      - name: tag-json-errors
        match: |
          response.body.jsonOk &&
          has('error', response.body.json)
        mutations:
          - op: setHeader
            name: x-rv-upstream-error
            value: "response.body.json.error"
```

### Recipe: rewrite an untrusted redirect into a warning page

The flagship extProc use case. During Dynamic Client Registration, Keycloak may answer with a `302` redirect whose `Location` points to an untrusted domain. Instead of letting the browser follow it, we discard the redirect and serve a warning page (HTTP `200`) that asks the user to confirm before leaving. The user reaches the original destination only if they click through.

Why `200` and not the original `302`: while the response is a redirect, the browser follows it and never renders a body. Turning it into a `200` with HTML is what makes the browser show the page; the real redirect becomes a deliberate click.

Why base64: the original `Location` is supplied by an untrusted DCR client, so it is attacker input. Embedding it raw in the HTML would open an XSS hole. We base64-encode it in the CEL expression (`base64.encode`) and the page's button decodes it client-side (`atob`).

```yaml
facts:
  - name: trustedRedirectDomains
    method: value
    value:
      - example-1.com
      - example-2.com

  - name: interstitialHtml
    method: file
    file:
      path: /etc/policy/interstitial.html

groups:
  - name: keycloak-302-interceptor
    parameters:
      engine: extProc
      phase: responseHeaders
      mode: firstMatch
    match: |
      response.status == 302 &&
      has('location', response.headers)
    rules:
      - name: redirect-to-warning
        match: |
          !facts.trustedRedirectDomains.exists(d,
            parseURL(response.header['location']).host == d ||
            parseURL(response.header['location']).host.endsWith('.' + d)
          )
        mutations:
          - op: directResponse
            status: 200
            headers: '{"content-type": "text/html"}'
            body: "facts.interstitialHtml.replace('__TARGET_B64__', base64.encode(response.header['location']))"
```

The interstitial HTML is loaded once as a `file` fact and carries a `__TARGET_B64__` placeholder that the `body` expression fills in. A minimal page lives in [`examples/interstitial.html`](examples/interstitial.html). The Istio wiring for this engine is in [`examples/config-for-istio-extproc.yaml`](examples/config-for-istio-extproc.yaml).

## Common to both engines

Everything below applies to both engines. Where the two behave differently, it is called out.

### Global dry-run

`defaults.dryRun: true` puts the whole policy in shadow mode: every rule is evaluated and logged, but nothing is enforced. It applies to both engines, with the engine-appropriate meaning:

- **extAuthz**: a `deny` verdict is logged as if it fired, but the request is allowed through with HTTP `200`. A body overflow that would deny also passes.
- **extProc**: mutations (including `directResponse`) are computed and logged ("would mutate", "would directRespond"), but the gRPC stream returns CONTINUE without applying anything. A body overflow that would `fail` does not block the stream.

There is also a per-rule `dryRun: true` that shadows a single rule instead of the whole policy. In both cases the logs and metrics record what the rule would have done, so you can preview a change against live traffic before enforcing it.

```yaml
defaults:
  dryRun: false # shadow mode for both engines (default false)
```

### What CEL sees

Every CEL expression (a `match`, a mutation `value`/`code`, a `directResponse.headers`/`body`) reads from a small set of variables:

- `request`: the incoming HTTP request. Always available.
- `response`: the upstream HTTP response. Available only in the response phases of the extProc engine.
- `facts`: external datasets you declare (see [Facts](#facts)).

Which variables are live depends on context. extAuthz always sees `request` and `facts`. extProc sees them too, plus `response` in response phases:

| Context                       | Live CEL variables             |
| ----------------------------- | ------------------------------ |
| extAuthz (any rule)           | `request`, `facts`             |
| extProc `requestHeaders`      | `request`, `facts`             |
| extProc `requestBody`         | `request`, `facts`             |
| extProc `responseHeaders`     | `request`, `response`, `facts` |
| extProc `responseBody`        | `request`, `response`, `facts` |

An expression that references `response` where it is not live fails to compile at policy load.

`request` and `response` share a similar schema. `request` has the request-specific fields (method, host, path, query, remoteIp); `response` adds `status`. Both have `headers`/`header`/`body`.

| Field                       | Type                        | Context  | Notes                                                         |
| --------------------------- | --------------------------- | -------- | ------------------------------------------------------------- |
| `request.method`            | `string`                    | Request  | HTTP verb                                                     |
| `request.scheme`            | `string`                    | Request  | http or https (from X-Forwarded-Proto)                        |
| `request.host`              | `string`                    | Request  | Request authority, no port                                    |
| `request.path`              | `string`                    | Request  | URL path                                                      |
| `request.remoteIp`          | `string`                    | Request  | Client IP (X-Forwarded-For first hop, else RemoteAddr)        |
| `request.headers`           | `map<string, list<string>>` | Request  | All headers, keys lowercased                                  |
| `request.header`            | `map<string, string>`       | Request  | First value per header (lowercased keys)                      |
| `request.queries`           | `map<string, list<string>>` | Request  | All query parameters                                          |
| `request.query`             | `map<string, string>`       | Request  | First value per query parameter                               |
| `request.body.raw`          | `string`                    | Request  | Full body, capped at `defaults.extAuthz.maxBodyBytes`         |
| `request.body.size`         | `int`                       | Request  | Bytes                                                         |
| `request.body.contentType`  | `string`                    | Request  | Shortcut for `request.header['content-type']`                 |
| `request.body.json`         | `dyn`                       | Request  | Parsed JSON, or `{}` when not JSON                            |
| `request.body.jsonOk`       | `bool`                      | Request  | Body parsed successfully as JSON                              |
| `request.body.yaml`         | `dyn`                       | Request  | Parsed YAML, or `{}` when not YAML                            |
| `request.body.yamlOk`       | `bool`                      | Request  | Body parsed successfully as YAML                              |
| `response.status`           | `int`                       | Response | Upstream HTTP status code                                     |
| `response.headers`          | `map<string, list<string>>` | Response | All response headers, keys lowercased                         |
| `response.header`           | `map<string, string>`       | Response | First value per response header (lowercased keys)             |
| `response.body.raw`         | `string`                    | Response | Full response body, capped at `defaults.extProc.maxBodyBytes` |
| `response.body.size`        | `int`                       | Response | Bytes                                                         |
| `response.body.contentType` | `string`                    | Response | Shortcut for `response.header['content-type']`                |
| `response.body.json`        | `dyn`                       | Response | Parsed JSON, or `{}` when not JSON                            |
| `response.body.jsonOk`      | `bool`                      | Response | Body parsed successfully as JSON                              |
| `response.body.yaml`        | `dyn`                       | Response | Parsed YAML, or `{}` when not YAML                            |
| `response.body.yamlOk`      | `bool`                      | Response | Body parsed successfully as YAML                              |

For a body (request or response) to be present at all, Envoy must be configured to buffer and forward it. See [Plugging into Istio](#plugging-into-istio).

### Facts

Sometimes the data your policy depends on changes too often to keep inline. The set of CIDRs OpenAI publishes for ChatGPT actions is the canonical example: it can change every few weeks. Hardcoding the list into the policy file means a redeploy each time.

`facts` solves this. You declare a named value at the top of the file and reference it from CEL as `facts.<name>`. Facts are shared by both engines. Three ways to load one:

| Method  | When                                           | What CEL sees                          |
| ------- | ---------------------------------------------- | -------------------------------------- |
| `value` | Inline in YAML, parsed at load time            | The value as declared                  |
| `file`  | Read from disk at startup or reload            | A string with the file contents        |
| `url`   | Fetched periodically by a background goroutine | A string with the last successful body |

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
      headers: # optional, for private feeds
        Authorization: "Bearer $TOKEN"
```

Using them from CEL is just dotted access:

```cel
inCIDR(request.remoteIp, facts.internalCidrs)
```

`file` and `url` facts arrive as raw strings, so you parse them on the spot:

```cel
inCIDR(request.remoteIp,
  parseJSON(facts.chatgptFeed).prefixes.map(p, p.ipv4Prefix))
```

`parseJSON` and `parseYAML` return an empty map `{}` if the input is empty, null or malformed. That keeps expressions safe before the first fetch lands. The typical pattern is to guard the group's `match`:

```yaml
match: |
  request.path.startsWith('/api') &&
  facts.chatgptFeed != null && facts.chatgptFeed != ""
```

If the first fetch of a `url` fact fails outright, the **policy load is rejected** and the previous policy stays active. Subsequent failed refreshes log a warning and keep serving the last good value. This is intentional: we would rather hold on to stale data than open or close the gate based on an empty feed.

### CEL function reference

CEL ships a small standard library; we enable `ext.Strings()`, `ext.Encoders()`, `ext.Lists()`, `ext.Sets()`, `ext.Math()` and `ext.Bindings()` on top of it. These are available to every expression in both engines. The project also registers the functions below.

#### Network

| Function       | Signature                                         | Description                                                                                     |
| -------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `inCIDR`       | `inCIDR(ip: string, cidrs: list<string>) -> bool` | True if `ip` belongs to any of the listed CIDRs. Plain IPs are accepted (auto-`/32` or `/128`). |
| `ipFamily`     | `ipFamily(ip: string) -> string`                  | `"ipv4"`, `"ipv6"` or `""`.                                                                      |
| `isPrivateIP`  | `isPrivateIP(ip: string) -> bool`                 | RFC1918, RFC4193, link-local.                                                                    |
| `isLoopbackIP` | `isLoopbackIP(ip: string) -> bool`                | `127.0.0.0/8`, `::1`.                                                                            |
| `parseURL`     | `parseURL(s: string) -> map<string, dyn>`         | Returns `{scheme, host, port, path, query, fragment, username, password}`.                      |

#### Strings (glob)

| Function  | Signature                                            | Description                                                                                                        |
| --------- | ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `glob`    | `glob(s: string, pattern: string) -> bool`           | Shell-style globs. `*` matches anything except `/`, `**` matches everything, `?` is one char, `[abc]` is a class. |
| `globAny` | `globAny(s: string, patterns: list<string>) -> bool` | True if any glob in the list matches.                                                                             |

For substring, replace, split, lower, upper and similar, use CEL's `ext.Strings()` directly: `s.lower()`, `s.split(',')`, `s.replace(a, b)`, etc.

#### Encoding and hashing

| Function             | Signature                                               | Description                                                                                                              |
| -------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `sha256Hex`          | `sha256Hex(s: string) -> string`                        | Lowercase hex of SHA-256(s).                                                                                             |
| `parseJWTUnverified` | `parseJWTUnverified(token: string) -> map<string, dyn>` | Returns `{header, payload}` parsed JSON. **Does not** verify the signature; use only when another component already did. |

`base64.encode` and `base64.decode` come from `ext.Encoders()`.

#### Time

| Function | Signature            | Description                                                            |
| -------- | -------------------- | ---------------------------------------------------------------------- |
| `now`    | `now() -> timestamp` | Current UTC time. CEL accessors (`getHours`, `getDayOfWeek`...) apply. |

#### Structured data

| Function    | Signature                                        | Description                                                                                             |
| ----------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| `parseJSON` | `parseJSON(v: dyn) -> dyn`                       | Parse a JSON string; returns `{}` on null/empty/invalid input.                                          |
| `parseYAML` | `parseYAML(v: dyn) -> dyn`                       | Parse a YAML string; returns `{}` on null/empty/invalid input.                                          |
| `jsonPath`  | `jsonPath(root: dyn, expr: string) -> list<dyn>` | Apply a JSONPath-lite subset (`$.a.b[*]`, `$..name`, `$[0]`, `$['key']`). Use when the path is dynamic. |

#### HTTP shortcuts

| Function  | Signature                                                       | Description                                                                                                                  |
| --------- | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `has`     | `has(name: string, bucket: map) -> bool`                        | True if `name` is a key in `bucket` AND has a non-empty value. Works for `headers` and `queries` of request and response.    |
| `firstOr` | `firstOr(bucket: map, name: string, default: string) -> string` | First value for `name` (string or list bucket), or `default` when missing/empty.                                             |

A handful of common idioms become very short:

```cel
has('x-api-key', request.headers)
firstOr(request.header, 'x-debug', 'no') == 'yes'
request.query['debug'] == '1'
request.headers['x-forwarded-for'].exists(v, inCIDR(v, ['10.0.0.0/8']))
```

### Logging

`request-validator` emits one structured log record per evaluation, plus internal events (boot, reload, fact fetch failures) through the same logger. extAuthz logs the verdict it produced; extProc logs the mutations it applied (or, under dry-run, would have applied).

```yaml
logging:
  level: info # debug | info | warn | error
  format: json # json | console
  logBody: false # opt-in: include the request body
  redactReveal: 6 # leading chars kept when masking a value
  excludeHeaders: # never appear in the log
    - cookie
    - set-cookie
  redactHeaders: # appear with their value masked
    - authorization
    - proxy-authorization
    - x-api-key
    - x-auth-token
  redactQueryParams: # same treatment for query params
    - access_token
    - id_token
    - code
```

The whole `logging` block is optional with sensible defaults. The CLI flags `--log-level` and `--log-format` override the file when set, so you can crank up verbosity at runtime without editing the ConfigMap.

A typical extAuthz allow line in JSON:

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

- `cookie` is configured as excluded, so it does not appear at all.
- `authorization` is long enough that we keep the first 6 characters visible (here `Bearer`) and mask the rest with `*`.
- `x-api-key` is short, so it gets fully masked.
- The query parameter `code` is in `redactQueryParams`, so it shows as `code=***`. `debug=1` stays untouched.

Values shorter than `2 * redactReveal` are always fully masked so short tokens do not leak half of themselves.

The `console` format produces the same information laid out as a single dense `key=value` line. It is meant for `kubectl logs -f` during development, not for ingestion. Use `json` in production.

## Operating the service

### Running it

From source, with the bundled example:

```bash
go run ./cmd --config examples/policy.yaml --log-level debug --log-format console
```

The project also ships an OCI image at `ghcr.io/achetronic/request-validator:<semver>`. Deploy it with whatever templating you already use. We use [`bjw-s` app-template](https://github.com/bjw-s-labs/helm-charts/tree/main/charts/other/app-template); a minimal HelmRelease values block looks like:

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
          liveness:
            {
              type: HTTP,
              custom: true,
              spec: { httpGet: { path: /healthz, port: 8080 } },
            }
          readiness:
            {
              type: HTTP,
              custom: true,
              spec: { httpGet: { path: /readyz, port: 8080 } },
            }
service:
  # If you use the extProc engine, the gRPC port name MUST start with
  # `grpc-` or `http2-` so Istio negotiates HTTP/2 on its cluster.
  main: { controller: main, ports: { http: { port: 8080 }, grpc-extproc: { port: 9090 } } }
persistence:
  policy:
    type: configMap
    name: request-validator-policy
    globalMounts: [{ path: /etc/policy }]
```

### Endpoints

The HTTP server (`--port`, default 8080) hosts the extAuthz engine and the operational endpoints:

| Endpoint   | Purpose                                                              |
| ---------- | -------------------------------------------------------------------- |
| `/`        | extAuthz check; Envoy posts the request here, everything lands here  |
| `/healthz` | Liveness probe                                                       |
| `/readyz`  | Readiness probe; false until a policy is successfully loaded         |
| `/metrics` | Prometheus counters, broken down by group and rule                   |

The gRPC server (`--grpc-port`, default 9090) hosts the extProc engine: it serves Envoy's `ext_proc` `ExternalProcessor` service. Both servers share the same policy and reload together.

### Hot reload

The policy file is reloaded automatically as soon as it changes on disk, for both engines at once. This covers three realistic scenarios:

- A plain in-place write picks up immediately.
- A save-via-rename (vim's `:w`, IntelliJ's atomic write, etc.) is also recognised.
- Kubernetes ConfigMap updates trigger an in-process reload too: the watcher tracks the `..data` symlink kubelet flips atomically when it publishes a new projection.

Multiple events within a short window (default 200 ms) are debounced into a single reload. If the new policy fails to load (parse error, fact fetch failure, etc.) it is rejected and the previous policy stays active.

If fsnotify cannot deliver events (NFS, FUSE), sending `SIGHUP` to the process triggers the same reload code path.

### Flags

```
--port               HTTP port for the extAuthz engine (default 8080)
--grpc-port          gRPC port for the extProc engine (default 9090)
--config             Path to the YAML policy (default policy.yaml)
--log-level          Override logging.level (debug|info|warn|error)
--log-format         Override logging.format (json|console)
--watch              Auto-reload on config file changes (default true)
--watch-debounce-ms  Debounce window for the watcher in ms (default 200)
--version            Print version and exit
```

The config file is run through `os.ExpandEnv` before parsing, so you can use `$VAR` and `${VAR}` placeholders that get substituted from environment variables.

### Response headers

The extAuthz engine stamps a few diagnostic headers on its response so you can see which rule produced the verdict (extProc instead rewrites traffic per your policy and does not add these):

| Header         | Value                                                                                                   |
| -------------- | ------------------------------------------------------------------------------------------------------- |
| `x-rv-result`  | `allow` or `deny`                                                                                       |
| `x-rv-rule`    | rule that decided, formatted `group/rule` (or `<defaults>`)                                             |
| `x-rv-reason`  | short, human-readable reason                                                                            |
| `x-rv-dry-run` | `true` when enforcement was suppressed, by the deciding rule's `dryRun` or the global `defaults.dryRun` |

Useful during development and as a way for the protected service to log "this request was let through by rule X" if it wants to.

### Plugging into Istio

The two engines wire into Istio differently. Full, copy-ready manifests live in [`examples/config-for-istio-extauthz.yaml`](examples/config-for-istio-extauthz.yaml) and [`examples/config-for-istio-extproc.yaml`](examples/config-for-istio-extproc.yaml). The shape of each:

**extAuthz** uses a MeshConfig `extensionProvider` plus an `AuthorizationPolicy`:

1. Register the validator as an HTTP ext-authz provider in `MeshConfig` (mesh-wide):

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
           includeRequestBodyInCheck:
             maxRequestBytes: 1048576
             allowPartialMessage: false
           headersToDownstreamOnDeny:
             [content-type, x-rv-result, x-rv-rule, x-rv-reason, x-rv-dry-run]
           headersToUpstreamOnAllow:
             [x-rv-result, x-rv-rule, x-rv-reason, x-rv-dry-run]
   ```

2. Point an `AuthorizationPolicy` with `action: CUSTOM` at that provider, scoped to the traffic you want gated:

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

**extProc** has no MeshConfig extensionProvider in Istio, so it is wired with an `EnvoyFilter` that inserts the `ext_proc` HTTP filter on the target workload's sidecar, pointing at the validator's gRPC port. The gRPC port on the validator Service must be named `grpc-*` or `http2-*` for Istio to negotiate HTTP/2. See [`examples/config-for-istio-extproc.yaml`](examples/config-for-istio-extproc.yaml) for the full filter, including the `processing_mode` block that selects which phases Envoy streams to the validator.

If you find yourself adding to `includeRequestHeadersInCheck` every time a policy starts reading a new header, the extAuthz example also shows a more flexible alternative: an `EnvoyFilter` that pins the ext-authz filter's `allowed_headers` to `.*` on the workload's sidecar.

## License

Apache-2.0.
