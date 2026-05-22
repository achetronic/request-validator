# OPERATIONS.md

Notes for running request-validator in production.

## What gets deployed

A single static binary inside `gcr.io/distroless/static:nonroot`. UID
`65532:65532`. Multi-arch (linux/amd64, linux/arm64). The image is
published at `ghcr.io/achetronic/request-validator:<semver>` plus a
floating `:latest` for the most recent stable release.

The CI workflows accept a `workflow_dispatch` toggle
(`checkout_master: true|false`) so you can cut an artefact named for a
specific SemVer tag from current `master` without moving the tag. The
artefact (binary tarball or image) gets the SemVer name; the code is
whichever ref you chose.

## Deploying

The repo ships a ready-to-apply example under
[`examples/kubernetes/`](../examples/kubernetes/). It is the
canonical reference for what a real deployment looks like (RBAC,
Service, Deployment, PDB, Secret with token, policy ConfigMap, +
Istio integration). Use it directly with `kubectl apply -k` or
copy individual files into your own templating.

We don't ship a Helm chart. Use whatever templating fits your cluster.
A minimal [bjw-s/app-template](https://github.com/bjw-s-labs/helm-charts)
`HelmRelease` looks like:

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
  main: { controller: main, ports: { http: { port: 8080 } } }
persistence:
  policy:
    type: configMap
    name: request-validator-policy
    globalMounts: [{ path: /etc/policy }]
```

Two pods minimum. Roll one at a time; both the readiness probe and the
fail-closed boot semantics protect you from going live with a broken
policy.

## Wiring into Istio

`request-validator` is an Envoy ext-authz HTTP service. Two pieces of
Istio config are needed:

1. **`extensionProvider`** in `MeshConfig` (one-off, mesh-wide):

   ```yaml
   meshConfig:
     extensionProviders:
       - name: request-validator
         envoyExtAuthzHttp:
           service: rv-request-validator.request-validator.svc.cluster.local
           port: 8080
           includeRequestBodyInCheck:
             maxRequestBytes: 1048576
             allowPartialMessage: false
           headersToDownstreamOnDeny:
             [content-type, x-rv-result, x-rv-rule, x-rv-reason, x-rv-dry-run]
           headersToUpstreamOnAllow: [x-rv-rule, x-rv-reason, x-rv-dry-run]
           includeRequestHeadersInCheck:
             - authorization
             - content-type
             - cookie
             - x-api-key
             - x-user-groups
             - x-forwarded-for
             - x-forwarded-proto
   ```

   Caveat: `packAsBytes` is **gRPC-only** in Istio; don't set it here.
   See https://istio.io/latest/docs/reference/config/istio.mesh.v1alpha1/.

2. **`AuthorizationPolicy` with `action: CUSTOM`** for the traffic you
   want to delegate:

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

   Only matched traffic hits the validator. The rest stays on your
   existing Istio policies.

## Observability

### Logs

One JSON line per request goes to stdout. Level `INFO` on allow,
`WARN` on deny. Internal events (boot, reload, fact fetch failure)
share the same logger.

The relevant fields when reading in Loki / kibana:

| Field                      | Meaning                               |
| -------------------------- | ------------------------------------- |
| `decision`                 | `allow` / `deny`                      |
| `rule`                     | `<group>/<rule>` or `<defaults>`      |
| `reason`                   | short human description               |
| `dry_run`                  | `true` if a shadow rule fired         |
| `duration_ms`              | end-to-end latency of the decision    |
| `request.method/host/path` | the request that was evaluated        |
| `request.remote_ip`        | client IP (X-Forwarded-For first hop) |
| `request.headers.*`        | every header, lowercased keys         |
| `request.body.size`        | body bytes received (capped)          |

Headers in `excludeHeaders` (default: `cookie`, `set-cookie`) never
appear. Headers in `redactHeaders` (default: `authorization`,
`proxy-authorization`, `x-api-key`, `x-auth-token`) are masked. Same
treatment for sensitive query params (`access_token`, `id_token`,
`code` by default).

To temporarily crank verbosity without editing the ConfigMap, exec
into the pod and `kill -HUP 1` after `kubectl edit configmap` - or use
the CLI override (only if you control the pod args).

### Metrics

`/metrics` exposes Prometheus text format:

```
request_validator_decisions_total{outcome="allow"}              N
request_validator_decisions_total{outcome="deny"}               N
request_validator_decisions_total{outcome="error"}              N
request_validator_rule_decisions_total{rule="...", outcome="...", dry_run="..."} N
```

Useful queries (PromQL):

```promql
# RPS by outcome
sum by (outcome) (rate(request_validator_decisions_total[5m]))

# Top denying rules
topk(5, rate(request_validator_rule_decisions_total{outcome="deny"}[5m]))

# Dry-run hits (about-to-be-denied if we promote them)
rate(request_validator_rule_decisions_total{dry_run="true"}[5m])
```

### Health and readiness

| Endpoint   | Returns                                                                  |
| ---------- | ------------------------------------------------------------------------ |
| `/healthz` | 200 once the process is up. Liveness probe target.                       |
| `/readyz`  | 200 only after the first successful policy load. Readiness probe target. |

If `/readyz` is 503 long after startup, check the logs for policy
parse errors or fact fetch failures.

## Hot reload

Two ways to trigger:

- **fsnotify** (default): the watcher subscribes to the parent
  directory of the policy file. It reacts to in-place writes,
  save-via-rename (most editors), and Kubernetes' atomic `..data`
  symlink swap. Events are debounced to 200 ms.
- **SIGHUP**: `kubectl exec ... -- kill -HUP 1` if fsnotify doesn't
  deliver (e.g. config on NFS).

A reload that fails parsing or initial fact fetch is **rejected**.
The previous policy stays active and the failure is logged at `ERROR`.

## Common operations

### Add a CIDR to a static fact

1. Edit the ConfigMap.
2. Kubelet updates the projection.
3. fsnotify triggers a reload within ~1 s.
4. Next request sees the new CIDR. Confirm in the next access log line.

### Add a new AI provider via published feed

1. Add a `facts:` entry with `method: url` pointing at the JSON.
2. Add a group whose `match` includes a guard
   `facts.<name> != null && facts.<name> != ""` and references the
   parsed payload via `parseJSON(facts.<name>).prefixes.map(p, p.ipv4Prefix)`
   or whatever shape the feed has.
3. Commit, deploy, watch the access log for the new rule name.

### Promote a `dryRun` rule

1. Flip `dryRun: true` to `false` (or remove the key).
2. fsnotify reload.
3. The next access log line that hits the rule now shows
   `decision=deny`. Metric `dry_run="false"` count starts growing.

### Roll back a bad policy

1. The previous policy already stays active if the new one is
   rejected.
2. If a syntactically-valid but semantically-wrong policy was loaded,
   `kubectl apply` the previous YAML. fsnotify picks it up. Or
   restart the pod - `/readyz` will hold traffic off until it loads.

## Troubleshooting

| Symptom                                     | First place to look                                                                     |
| ------------------------------------------- | --------------------------------------------------------------------------------------- |
| `/readyz` stuck at 503                      | Logs at `ERROR`: parse error, fact URL unreachable, invalid CEL expression              |
| Every request denies with `rule=<defaults>` | A `match` guard is false (frequent: a fact URL hasn't been fetched yet - check WARNs)   |
| Metric `error` counter increases            | CEL eval error mid-request; check the access log `reason` field                         |
| ConfigMap update doesn't seem to apply      | Run `kubectl exec ... -- ls /etc/policy` (the symlink should change `..data` target)    |
| A rule "fires" for the wrong request        | The `match` expression is too broad. Use `dryRun: true` temporarily to observe in logs  |
| Latency spike per request                   | Body parsing on giant payloads. Lower `maxBodyBytes` or stop parsing JSON if not needed |
| URL fact returns stale data                 | Check `interval` and the `WARN facts: refresh failed` lines in the log                  |

## Resource sizing

- Memory: a few tens of MB resting; peaks during reload while the
  previous and new `Config` coexist. 128 MiB requests are comfortable
  for the example policy.
- CPU: dominated by CEL evaluation. Around 0.1–0.5 ms p99 per request
  for the example. Scale horizontally.
- File descriptors: one per URL fact fetcher keepalive + the HTTP
  listener. Default limits are fine.

## Upgrading

- Read `DECISIONS.md` for breaking changes intent.
- The YAML schema is forward-compatible: new optional fields are
  ignored by older binaries (which is fine in a roll-forward), and
  newer binaries continue to accept old policies.
- Bump the image tag; the readiness probe ensures the new pod loads
  the policy before traffic hits it.

## Cluster mode (Kubernetes Lease + ConfigMap)

Replication is automatic when the pod runs inside Kubernetes: the
daemon discovers the API server through the in-cluster config,
creates (or joins) a single ConfigMap holding the admin overlay,
and elects a leader via a Lease in `coordination.k8s.io/v1`. No
gossip ports, no static peer lists, no PVC.

Minimum RBAC for the pod's ServiceAccount:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: request-validator }
rules:
  # list+watch ConfigMaps in the namespace (informer needs this; the
  # informer's field selector then narrows the cache to ours).
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["list", "watch", "create"]
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["request-validator-state"]
    verbs: ["get", "update", "patch"]
  # Same shape for the Lease used for leader election.
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["list", "watch", "create"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    resourceNames: ["request-validator-leader"]
    verbs: ["get", "update", "patch"]
```

Required Deployment additions (the rest is the standard ext-authz
shape):

```yaml
spec:
  template:
    spec:
      serviceAccountName: request-validator
      containers:
        - name: main
          args:
            - --config=/etc/policy/policy.yaml
            - --admin-port=8081
            - --admin-token-file=/etc/rv/admin-token
            # all other flags pick sensible defaults
          ports:
            - { name: extauthz, containerPort: 8080 }
            - { name: admin,    containerPort: 8081 }
          volumeMounts:
            - { name: admin-token, mountPath: /etc/rv, readOnly: true }
            - { name: policy,      mountPath: /etc/policy, readOnly: true }
      volumes:
        - name: admin-token
          secret:
            secretName: request-validator-admin
            items: [{ key: token, path: admin-token }]
        - name: policy
          configMap:
            name: request-validator-policy
```

The state ConfigMap (`request-validator-state` by default) is
created automatically the first time a pod boots. **Do not** manage
it from Git; it is owned by the running cluster.

### Operational notes

- Convergence is sub-second under normal load: the leader writes the
  ConfigMap, the API server returns the new `resourceVersion`, all
  pods' informers receive the Update and rebuild their effective
  config.
- The Lease holds for ~15 s by default; on leader pod loss another
  pod takes over within ~1-2 lease intervals. During that window,
  writes get HTTP 503 with `Retry-After: 2`.
- Total cluster restart (all pods at once): the ConfigMap survives
  in etcd, so the first pod up reads it and serves traffic
  immediately. The Lease may show a stale holder for one lease
  duration before being claimed by whoever boots first.
- For dev / bare-metal / `go run` use `--no-kubernetes`. Replication
  is disabled but the admin API still works on top of an in-memory
  store (optionally persisted via `--state-file`).

## Admin API

Listens on `--admin-port` (default 8081). Required:

- `--admin-token-file=/etc/rv/admin-token` containing a single token
  string (newline trimmed). Without this flag, the admin server is
  not started.
- The token file is watched with fsnotify; rotation is live.

Mount the token as a Secret:

```yaml
volumes:
  - name: admin-token
    secret:
      secretName: request-validator-admin
      items: [{ key: token, path: admin-token }]
```

### Common admin operations

```bash
TOKEN=$(kubectl -n ns get secret request-validator-admin -o jsonpath='{.data.token}' | base64 -d)
RV=http://127.0.0.1:8081   # via `kubectl port-forward svc/request-validator 8081:8081`

# Add a group via API (works against any pod; followers redirect 307)
curl -sLf -X PUT "$RV/api/v1/groups/temporary-block" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "priority": -100,
        "mode": "firstMatch",
        "action": "deny",
        "rules": [{"name": "block-bad-ip", "match": "request.remoteIp == \"203.0.113.5\""}]
      }'

# Inspect the effective config
curl -sLf -H "Authorization: Bearer $TOKEN" "$RV/api/v1/config" | jq .

# See who is leader right now
curl -sLf -H "Authorization: Bearer $TOKEN" "$RV/api/v1/cluster" | jq .

# Fetch the OpenAPI 3.1 spec
curl -sLf -H "Authorization: Bearer $TOKEN" "$RV/api/v1/openapi.json" > openapi.json
```

### Troubleshooting (cluster / admin)

| Symptom                                      | First place to look                                                                  |
| -------------------------------------------- | ------------------------------------------------------------------------------------ |
| API write returns 307 over and over          | Client must follow redirects; use `curl -L` or set `If-Match` and retry              |
| API write returns 503 `Retry-After: 2`       | No leader currently elected (typically lease transition). Wait and retry.            |
| API write returns 412                        | Stale `If-Match`; `GET` again to read the fresh `Etag`                               |
| Other pods don't reflect a write             | Check `kubectl get cm request-validator-state -o yaml`; is the change there?         |
| Pod can't start: "forbidden: cannot create"  | RBAC missing the `coordination.k8s.io/leases create` or ConfigMap permissions        |
| Admin port refuses connections               | `--admin-token-file` not set or unreadable; admin server is disabled by design       |
