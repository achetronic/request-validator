# AGENTS.md - request-validator

This file is the entry point for any AI agent or new contributor working on
this codebase. Read it first, then jump to the document that matches what
you came to do.

## What this project is

`request-validator` is a generic Envoy / Istio policy service with two
engines driven by one **CEL-based** YAML policy:

- **extAuthz** (HTTP ext-authz): Envoy forwards a request, we say `allow`
  or `deny`, Envoy enforces.
- **extProc** (gRPC ext_proc): we inspect and mutate live traffic
  (request or response headers and body), or short-circuit and serve our
  own response.

It was built to cover the cases plain Istio `AuthorizationPolicy` cannot
(inspecting request bodies, combining CIDRs with JSON contents, validating
OAuth `redirect_uris`, rewriting an untrusted DCR redirect into a warning
page, etc.).

## When you arrive, read this first

Take 5 minutes to load the mental model:

1. **`.agents/ARCHITECTURE.md`** - packages, request lifecycle, how the
   pieces connect.
2. **`.agents/POLICY_DSL.md`** - the YAML grammar (`defaults`, `logging`,
   `facts`, `groups`) and CEL functions registered for it.
3. **`examples/policy.yaml`** at the repo root - a realistic policy with
   every feature exercised.

Only after that, drill into:

- **`.agents/DECISIONS.md`** - _why_ the project looks the way it does
  (CEL over a custom DSL, fail-closed semantics, in-process feed fetching,
  the two-engine split, the mutation and directResponse model, etc.).
- **`.agents/CODE_CONVENTIONS.md`** - house style for Go in this repo.
- **`.agents/TESTING.md`** - how to run the test suite and the E2E recipe.
- **`.agents/OPERATIONS.md`** - deploy notes, observability, troubleshooting.
- **`.agents/GLOSSARY.md`** - short definitions of terms used throughout.

## Repo layout

```
.
├── cmd/main.go                   entry point; flag parsing + lifecycle
├── internal/
│   ├── celenv/                   CEL environment + custom functions
│   ├── configwatch/              fsnotify wrapper for policy hot-reload
│   ├── facts/                    facts registry (inline/file/url sources)
│   ├── httpserver/               extAuthz HTTP endpoint + metrics
│   ├── grpcserver/               extProc gRPC endpoint (Envoy ext_proc)
│   ├── jsonpath/                 tiny JSONPath subset used by the engine
│   ├── log/                      slog wrapper (json | console handlers)
│   └── policy/                   policy types, parser, evaluator
├── examples/policy.yaml          fully annotated sample policy
├── .github/workflows/            CI + release-binaries + release-image
├── Dockerfile                    distroless multi-arch image
├── Makefile                      build / test / run / docker targets
├── README.md                     user-facing documentation
└── .agents/                      this directory
```

## Common tasks: where to start

| You want to...                                   | Read                                                          | Touch                                       |
| ------------------------------------------------ | ------------------------------------------------------------- | ------------------------------------------- |
| Add a new CEL function (e.g. `b64Url`)           | `ARCHITECTURE.md` ("CEL environment"), `CODE_CONVENTIONS.md`   | `internal/celenv/<family>.go`               |
| Add a new source method for `facts:`             | `ARCHITECTURE.md` ("Facts lifecycle")                         | `internal/facts/facts.go`                   |
| Tweak the access log shape or redaction rules    | `POLICY_DSL.md` ("logging"), `ARCHITECTURE.md` ("Logging")     | `internal/httpserver/access.go` + `policy/` |
| Add a new top-level YAML section                 | `POLICY_DSL.md`, `ARCHITECTURE.md` ("Config types")           | `internal/policy/policy.go`                 |
| Add or change an extProc mutation op             | `POLICY_DSL.md` ("Mutation ops"), `DECISIONS.md` (D-019/D-023) | `internal/policy/` + `internal/grpcserver/` |
| Speed up the request hot path                    | `ARCHITECTURE.md` ("Request lifecycle")                       | `internal/httpserver/server.go`             |
| Change deploy/observability behaviour            | `OPERATIONS.md`                                               | Dockerfile, `.github/workflows/`, README    |
| Understand a past decision                       | `DECISIONS.md`                                                | -                                           |

## Hard rules - do not break

1. **Fail-closed on errors.** A CEL evaluation error, an invalid policy
   reload, or a missing initial fact fetch must never silently allow. The
   default is `deny`. The only escape hatch is `defaults.allowOnError: true`
   and it is a deliberate, per-policy opt-in.

2. **No I/O on the request hot path.** Facts are fetched in the background;
   the request goroutine only reads atomic pointers. Anything that takes a
   lock or hits the network for a single request is a bug.

3. **Atomic policy swaps.** Hot-reload uses `atomic.Pointer[policy.Config]`.
   The previous policy is `Stop()`'d only **after** the swap, so in-flight
   requests always see a consistent view.

4. **No corporate hostnames or PII anywhere.** Examples, tests, fixtures
   and docs use `example-1.com` / `example-2.com` / `keycloak.internal.
example-1.com`. The CI greps for the historical corporate names
   (`free` + `pik`, `magni` + `fic`, `fpk` + `mon` - never substitute
   them back together in code, examples or docs); a match is a
   blocker.

5. **No magic logger.** Everything goes through `internal/log`, which wraps
   `log/slog`. Don't import `fmt.Printf` for logging; don't add a second
   logger package.

6. **Tests must build and pass on every PR.** `go vet`, `go test`,
   `go test -race` and `helm` were removed but the CI workflow still runs
   the first three. See `TESTING.md`.

## Workflow expected from an agent

1. **Read** the relevant `.agents/*.md` files for the area you're touching.
2. **Plan** before editing if the change spans more than one package.
3. **Edit** while honouring the hard rules above.
4. **Test** locally: `go vet ./...`, `go test ./...`, `go test -race ./...`.
5. **Update** the `.agents/` files when a change invalidates them
   (especially `DECISIONS.md` when you make a non-obvious call).
6. **Never** commit unless the user explicitly asks.

## When something is unclear

The source of truth is **the code**. The `.agents/` files describe
intent and conventions; if they disagree with the code, the code wins and
the docs are stale - fix the docs.
