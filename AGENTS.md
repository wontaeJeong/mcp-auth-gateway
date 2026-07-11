# PROJECT KNOWLEDGE BASE

**Generated:** 2026-07-11 13:52:33 +0900
**Commit:** 70bf3fd
**Branch:** main

## OVERVIEW

Stateless Go 1.26 gateway that validates Keycloak access tokens, applies path-scoped MCP policy, and replaces external credentials with a short-lived gateway-signed backend identity JWT.

## STRUCTURE

```text
./
├── cmd/gateway/       # Process entrypoint and shutdown lifecycle
├── internal/auth/     # OIDC discovery, JWKS caching, access-token policy
├── internal/config/   # Strict YAML schema, defaults, validation
├── internal/identity/ # Backend identity JWT minting
├── internal/proxy/    # Streaming reverse proxy and path rewrite
├── internal/server/   # HTTP routes and request-flow orchestration
├── scripts/           # BuildKit image build and image security checks
└── tests/             # Shell contract tests with fake Docker
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Change startup or shutdown | `cmd/gateway/main.go` | `main` -> `run`; JSON `slog`; 15s warm-up/shutdown windows |
| Change routes or request flow | `internal/server/server.go` | Origin gate -> bearer verification -> identity mint -> proxy |
| Change token verification | `internal/auth/verifier.go` | Issuer, RSA method, audience, claims, scopes, groups |
| Change OIDC/JWKS behavior | `internal/auth/jwks.go` | Refresh coalescing, origin pinning, cooldowns, stale grace |
| Change configuration | `internal/config/config.go` | Defaults and validation are part of the runtime contract |
| Change backend identity claims | `internal/identity/identity.go` | HS256, 32-byte secret minimum, 5m hard TTL cap |
| Change proxy rewrite/headers | `internal/proxy/proxy.go` | Immediate flushing and spoofable-header stripping |
| Verify gateway behavior | `internal/server/server_test.go` | Black-box integration harness with fake OIDC/backend |
| Verify container pipeline | `tests/container-pipeline-test.sh` | TAP-style shell tests against `tests/fake-docker` |

## CODE MAP

| Symbol | Type | Location | Refs | Role |
|--------|------|----------|------|------|
| `run` | function | `cmd/gateway/main.go:35` | entry-local | Builds dependencies and serves HTTP |
| `config.Load` | function | `internal/config/config.go:116` | 5 | Strictly decodes, defaults, validates YAML |
| `auth.NewKeyCache` | function | `internal/auth/jwks.go:87` | 16 | Creates lazy OIDC/JWKS cache |
| `auth.Verifier.Verify` | method | `internal/auth/verifier.go:88` | 2 | Main external-token auth gate |
| `identity.Signer.Sign` | method | `internal/identity/identity.go:54` | 4 | Mints trusted backend JWT |
| `proxy.New` | function | `internal/proxy/proxy.go:38` | 2 | Builds streaming path-rewriting reverse proxy |
| `server.New` | function | `internal/server/server.go:41` | 3 | Composes the top-level HTTP handler |
| `Gateway.protect` | method | `internal/server/server.go:175` | route-local | Enforces the full protected-request pipeline |

Reference counts include declarations and test references reported by `gopls`; codegraph tooling was unavailable during generation.

## CONVENTIONS

- Keep packages application-internal; there is no public `pkg/` API surface.
- Treat `config.yaml` plus `internal/config` validation as one contract. Unknown YAML keys and extra YAML documents must fail.
- Keep URL inputs absolute HTTP(S) references without credentials, query, or fragment. Local HTTP remains valid.
- Keep origins as exact serialized `scheme://host` values. A present malformed, duplicate, or unlisted `Origin` fails before auth.
- Accept bearer credentials only through one `Authorization` header. Do not add query-token support.
- Return structured JSON errors; expose OAuth error values only through the existing Bearer challenge behavior.
- Keep process logs structured through `log/slog`; avoid logging raw JWTs, secrets, proxy values, or provider response bodies.
- Colocate Go tests with packages. Use `package server_test` for cross-package request contracts and same-package tests for internals.

## ANTI-PATTERNS (THIS PROJECT)

- Do not forward the Keycloak token or trust client-supplied `X-MCP-*` identity headers.
- Do not treat debug headers (`X-MCP-LoginID`, `X-MCP-Subject`) as the trust boundary; only `X-MCP-Identity` is trusted.
- Do not buffer MCP/SSE proxy responses; `FlushInterval: -1` is intentional.
- Do not broaden OIDC discovery/JWKS redirects beyond the configured discovery origin.
- Do not fail process startup solely because JWKS warm-up failed; `/readyz` owns degraded readiness and retry.
- Do not add DB, Redis, session storage, or server-side login state; the gateway is intentionally stateless.
- Do not use mutable image tags in pipeline scripts; `IMAGE_TAG` must be a 7-64 character hexadecimal git SHA.
- Do not place CA or proxy values in Docker layers, labels, output, or final image environment.

## UNIQUE STYLES

- Per-server routing policy travels together in `config.MCPServer`: paths, public resource, audience, backend, scopes, origins, groups.
- Security failures are fail-closed and covered at boundaries: entropy failure, malformed headers, provider redirects, stale keys, strict config.
- JWKS refresh survives caller cancellation, coalesces concurrent work, and retains last-known-good keys only within bounded stale grace.
- Container scripts use POSIX `sh`, validate all inputs before Docker, and print immutable digest references.

## COMMANDS

```bash
go test ./...
sh tests/container-pipeline-test.sh
MCP_INTERNAL_JWT_SECRET="$(openssl rand -base64 32)" go run ./cmd/gateway -config config.yaml
REGISTRY=registry.example.com IMAGE_TAG=<git-sha> CA_CERT_FILE=/path/to/ca.pem sh scripts/build-and-push.sh
REGISTRY=registry.example.com IMAGE_TAG=<git-sha> CA_CERT_FILE=/path/to/ca.pem sh scripts/test-image.sh
```

## NOTES

- `/readyz` performs a bounded JWKS refresh when the cache is not ready; it may do network I/O.
- Docker builds require BuildKit secret support and mount `system_ca` during both module download and compilation.
- `.dockerignore` intentionally excludes `scripts/`, `tests/`, VCS data, local env files, and certificate/key material.
- No repository-local GitHub workflow or Makefile exists; the scripts above are the pipeline contract.
