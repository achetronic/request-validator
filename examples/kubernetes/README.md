# Kubernetes deployment example

A working set of manifests to run `request-validator` on a real
cluster. Pick what you need, copy it into your own configuration
management (Flux, Argo, Helm, plain `kubectl`, whatever), and adjust.

```
.
├── 00-namespace.yaml            isolated namespace
├── 10-rbac.yaml                 ServiceAccount + Role + RoleBinding
├── 20-admin-token-secret.yaml   bearer token for the admin API
├── 30-policy-configmap.yaml     the YAML policy floor
├── 40-deployment.yaml           Deployment (2 replicas) + Service + PDB
├── istio/
│   ├── 00-extension-provider.yaml   MeshConfig snippet (one-off, mesh-wide)
│   └── 10-authorization-policy.yaml CUSTOM AuthorizationPolicy example
└── kustomization.yaml           kubectl apply -k for the whole core set
```

## Quick start

1. **Generate a real admin token** and overwrite the placeholder in
   `20-admin-token-secret.yaml`, or skip the file and create the
   Secret directly:

   ```bash
   kubectl create namespace request-validator
   kubectl -n request-validator create secret generic request-validator-admin \
     --from-literal=token=$(openssl rand -hex 32)
   ```

2. **Edit the policy** in `30-policy-configmap.yaml` so it reflects
   what you actually want to enforce. The default contents are a
   deny-everything placeholder; useful as a smoke test, useless in
   production.

3. **Apply the core manifests:**

   ```bash
   kubectl apply -k examples/kubernetes/
   ```

4. **Wait for the Deployment to be Ready:**

   ```bash
   kubectl -n request-validator rollout status deploy/request-validator
   ```

5. **Verify the admin API:**

   ```bash
   TOKEN=$(kubectl -n request-validator get secret request-validator-admin \
     -o jsonpath='{.data.token}' | base64 -d)

   kubectl -n request-validator port-forward svc/request-validator 8081:8081 &

   curl -sf -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:8081/api/v1/cluster | jq .
   ```

   You should see one pod reporting `iAmLeader: true` and the other
   `false`, both pointing at the same `leader.podName`.

## Connecting Envoy / Istio

If you run Istio, apply the two files under `istio/` to wire the
daemon as an ext-authz provider. The first one is a
mesh-wide config change (it goes into your istiod's `MeshConfig`);
the second one is a per-service `AuthorizationPolicy` that picks
which traffic gets delegated. Read the comments in each file —
they explain how to adapt the snippets to your setup.

If you run plain Envoy (no Istio), point an `envoy.filters.http.ext_authz`
HTTP filter at the `request-validator` Service on port 8080. Same
contract; just no Istio CRDs.

## Common operations

### Roll a new policy

```bash
kubectl -n request-validator edit configmap request-validator-policy
# Or:
kubectl -n request-validator apply -f your-policy.yaml
```

The daemons pick up the change via fsnotify within ~200 ms. Admin
API overrides keep winning per key.

### Push a hot rule via the admin API

Writes (`PUT`, `DELETE`) are only accepted by the cluster leader.
When a write lands on a follower, the daemon replies with
**HTTP 307 Temporary Redirect** and a `Location:` header pointing at
the leader's admin URL. The `curl -L` below follows that redirect
automatically — without `-L` you get a 307 and nothing else. Any
HTTP client that follows redirects (most do by default) just works.

```bash
curl -sLf -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "priority": -100,
    "action": "deny",
    "rules": [{"name": "x", "match": "request.remoteIp == \"203.0.113.5\""}]
  }' \
  "http://127.0.0.1:8081/api/v1/groups/temporary-block"
```

The leader applies the write atomically, then the followers see the
ConfigMap update via their informers and rebuild their effective
config locally. Convergence is sub-second.

### Roll back to the YAML floor for a key

```bash
curl -sLf -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8081/api/v1/groups/temporary-block"
```

### Inspect what is actually being evaluated

```bash
curl -sLf -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8081/api/v1/config" | jq '.groups[].name'
```

## What survives what

| Action                                           | State preserved? |
| ------------------------------------------------ | ---------------- |
| Pod restart / rolling update / node reschedule  | yes (state ConfigMap lives in etcd) |
| `kubectl scale deploy ... --replicas=0` then up | yes |
| `kubectl delete cm request-validator-state`     | no — pods recreate it empty; admin overrides gone |
| `kubectl delete cm request-validator-policy`    | the engine keeps running with the last loaded policy until it crashes; you should re-apply quickly |

The YAML in Git is the **declarative floor**. The state ConfigMap is
**runtime mutable state** owned by the cluster — do not put it under
GitOps with `prune: true` or you will fight yourself.

## Observability

The ext-authz port (8080) also serves `/metrics` in Prometheus text
format. Scrape it with whatever you use:

```yaml
# Example PodMonitor (requires the Prometheus operator).
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: request-validator
  namespace: request-validator
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: request-validator
  podMetricsEndpoints:
    - port: extauthz
      path: /metrics
      interval: 15s
```

Decision counters (`request_validator_decisions_total{outcome=…}`),
per-rule labels, admin request counters, gossip/rebuild counters and
the cluster member state are all exposed there. Full list is in
`.agents/OPERATIONS.md`.

## Running outside Kubernetes (dev only)

For local dev or testing without a cluster, pass `--no-kubernetes`.
Replication and leader election become no-ops; the admin API still
works on top of an in-memory store, optionally persisted to a JSON
file with `--state-file`. Don't use this in production — there's no
HA, no replication, no shared state.

```bash
go run ./cmd \
  --config examples/policy.yaml \
  --admin-token-file <(echo dev-token) \
  --no-kubernetes \
  --state-file /tmp/rv-state.json \
  --log-format console --log-level debug
```
