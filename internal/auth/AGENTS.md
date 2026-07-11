# AUTH PACKAGE KNOWLEDGE BASE

## OVERVIEW

Security-critical external-token boundary: OIDC discovery/JWKS lifecycle in `jwks.go`, Keycloak claim enforcement in `verifier.go`.

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Change discovery/JWKS fetch | `jwks.go` | Provider-origin pinning, body cap, redirect cap, RSA parsing |
| Change refresh/cache behavior | `jwks.go` | `KeyCache.reloadIfCurrent`, `executeRefresh`, `keyByIDForAlgorithm` |
| Change claim policy | `verifier.go` | `Verifier.Verify` is the only external-token verification path |
| Change auth response classification | `verifier.go` | `AuthError` feeds server status/body/challenge behavior |
| Verify concurrency and stale keys | `jwks_test.go` | Cancellation, coalescing, cooldown, generation, stale grace |

## CONVENTIONS

- Keep accepted token algorithms limited to RSA `RS256`, `RS384`, and `RS512`; enforce both JWT method and JWK `alg` when declared.
- Sanitize JWT library failures before returning user-visible messages. Never surface raw parser/provider details to clients.
- Missing credentials and invalid tokens are `401`; insufficient scope and disallowed groups are `403`.
- Require non-empty `sub` and configured login ID claim. Audience must contain the exact server audience; every required scope must exist.
- Keep provider requests bounded: HTTP timeout, 1 MiB body limit, same-origin redirects, and maximum redirect count.
- Refresh state is shared across callers. Preserve coalescing and do not let one caller's cancellation cancel the shared refresh.

## ANTI-PATTERNS

- Do not accept symmetric, EC, `none`, or undeclared arbitrary signing methods for external access tokens.
- Do not follow discovery redirects or `jwks_uri` to another origin, including default-port normalization bypasses.
- Do not cache unknown KIDs after a failed refresh; the negative cache starts only after successful refresh proves absence.
- Do not remove bounds on unknown KIDs, refresh retry, stale-if-error, response size, RSA modulus, or redirects.
- Do not use stale keys outside the one-hour post-expiry grace, and only enable that grace after refresh failure.
- Do not log or embed raw access tokens, JWK bodies, or detailed signature failures in `AuthError` messages.

## TESTING

```bash
go test ./internal/auth
go test ./internal/server
go test -race ./internal/auth
```

Use `internal/auth` tests for cache generations, internal clocks/state, static provider helpers, and JWKS edge cases. Run `internal/server` tests for `Verifier.Verify` claim-policy or `AuthError` changes because request outcomes and Bearer challenges are covered there.
