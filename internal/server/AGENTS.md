# SERVER PACKAGE KNOWLEDGE BASE

## OVERVIEW

HTTP orchestration hub that binds health/readiness, RFC 9728 metadata, Origin policy, bearer auth, backend identity, and reverse proxying.

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add/change routes | `server.go` | `routes` registers method-aware Go 1.22+ patterns |
| Change readiness | `server.go` | `handleReadyz` retries JWKS refresh with a 5s request-bound context |
| Change metadata/CORS | `server.go` | `metadataHandler`, `metadataPreflightHandler`, `setMetadataCORS` |
| Change protected flow | `server.go` | `protect` preserves ordering of Origin, auth, request ID, signing, stripping, proxy |
| Change challenges/errors | `server.go` | `writeAuthError`, `wwwAuthenticate` |
| Verify user-visible behavior | `server_test.go` | Black-box fake OIDC and capturing backend |
| Verify entropy failure | `request_id_test.go` | Same-package test for `newRequestID` |

## CONVENTIONS

- Apply Origin policy before token verification and proxying; absent Origin remains allowed.
- Reject multiple `Authorization` headers explicitly. A non-empty malformed scheme is `invalid_token`, not missing credentials.
- Generate a 128-bit random request ID and fail closed if entropy fails.
- Strip all spoofable identity headers before setting the gateway-owned identity, request ID, login ID, and subject headers.
- Construct `WWW-Authenticate` from the public resource origin plus metadata path and configured scopes.
- Keep `/healthz` purely local; `/readyz` may perform bounded provider I/O to self-heal a cold cache.
- Log server, login ID, request ID, and path for proxied requests; never log either JWT.

## ANTI-PATTERNS

- Do not reorder the protected pipeline so authentication or backend work happens before Origin rejection.
- Do not proxy the original `Authorization` header or retain any inbound `X-MCP-*` identity value.
- Do not mint an internal identity token before external verification succeeds.
- Do not convert unknown routes into a catch-all proxy; unmatched path prefixes must remain `404`.
- Do not move JWKS refresh into `New`; construction stays network-free, while `WarmUp` and `/readyz` own cache refresh.
- Do not expose internal signing/provider errors in JSON responses.

## TESTING

```bash
go test ./internal/server
go test -race ./internal/server
```

Extend `server_test.go` for externally observable request contracts; use same-package tests only for otherwise unreachable internals.
