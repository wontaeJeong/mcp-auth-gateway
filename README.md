# mcp-auth-gateway

Path-based authentication gateway for Mock MCP. It verifies a Keycloak access
token, proxies `/mock/mcp` to an internal `mock-mcp-server`, and forwards a
short-lived, **gateway-signed** identity token to the backend instead of the
original Keycloak token.

The gateway is stateless: no DB, no Redis, no session store.

## Responsibilities

1. Serve MCP OAuth Protected Resource Metadata (RFC 9728).
2. Verify `Authorization: Bearer <Keycloak access token>`.
3. Validate `iss` / `aud` / `exp` / `nbf` / `scope` / `sub` / `loginid`.
4. Enforce the per-server Origin allowlist when an `Origin` header is present.
5. Strip client-supplied `X-MCP-*` / `X-MCP-Identity` headers.
6. Mint a gateway-signed internal identity token (`X-MCP-Identity`).
7. Reverse-proxy to the backend Mock MCP server.
8. Preserve Streamable HTTP / SSE responses (immediate flush, no buffering).

## Endpoints

| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/healthz` | Liveness. |
| GET | `/readyz` | Readiness: config loaded, OIDC discovery + JWKS ready, internal secret present. |
| GET | `/.well-known/oauth-protected-resource/mock/mcp` | Protected Resource Metadata for Mock MCP. |
| ANY | `/mock/mcp` | Authenticated MCP endpoint (proxied to backend `/mcp`). |
| ANY | `/mock/mcp/*` | Authenticated MCP subtree (proxied to backend `/mcp/*`). |

Unknown path prefixes return `404`.

The protected resource metadata includes `resource_name: "mock"` and advertises
`bearer_methods_supported: ["header"]`. Bearer tokens are accepted only from the
`Authorization` header; query-string access tokens and requests with duplicate
`Authorization` headers are not accepted.

### Public / backend mapping

```
External:  https://gateway.mcp.aidev.samsungds.net/mock/mcp
Backend:   http://mock-mcp-server.mcp-gateway.svc.cluster.local:8080/mcp

/mock/mcp      -> /mcp
/mock/mcp/...  -> /mcp/...
```

The `/mock` external prefix is stripped before proxying.

## Authentication

Requests to `/mock/mcp` require a valid Keycloak access token.

Verified against the Keycloak OIDC discovery document and JWKS:

- `iss` == `https://auth.mcp.aidev.samsungds.net/realms/mcp`
- `exp` / `nbf` valid
- `aud` contains `https://gateway.mcp.aidev.samsungds.net/mock/mcp`
- `scope` (space-delimited) contains `mcp:mock:use`
- `sub` is a non-empty string
- `loginid` claim exists and is non-empty

Concurrent JWKS refreshes are coalesced, provider redirects and `jwks_uri` stay
on the configured discovery origin, and a JWK's declared RSA algorithm is
enforced. Unknown key IDs use a bounded cache and 30s refresh cooldown only
after successful refresh; failures back off for 5s. Last-known-good keys remain
usable for at most 1h beyond cache expiry when refresh fails.

### Origin policy

Requests without an `Origin` header are accepted. When the header is present,
it must contain exactly one serialized origin (scheme and host only) that
exactly matches the server's `allowed_origins`. Empty, `null`, malformed,
path-bearing, multiple, and unlisted origins receive `403 Forbidden` before
authentication or proxying. The Mock MCP allowlist contains:

```text
https://gateway.mcp.aidev.samsungds.net
```

### Failure responses

| Condition | Status |
| --------- | ------ |
| Missing credentials | `401 Unauthorized` |
| Malformed or invalid token, including invalid required claims | `401 Unauthorized` |
| Valid token but missing required scope | `403 Forbidden` |
| Present but invalid or unlisted Origin | `403 Forbidden` |

Missing credentials produce a Bearer challenge without an OAuth error value:

```http
WWW-Authenticate: Bearer realm="mcp", resource_metadata="https://gateway.mcp.aidev.samsungds.net/.well-known/oauth-protected-resource/mock/mcp", scope="mcp:mock:use"
```

Invalid tokens use `error="invalid_token"`; a valid token without the required
scope receives `403 Forbidden` with `error="insufficient_scope"`:

```http
WWW-Authenticate: Bearer realm="mcp", resource_metadata="https://gateway.mcp.aidev.samsungds.net/.well-known/oauth-protected-resource/mock/mcp", scope="mcp:mock:use", error="invalid_token"

WWW-Authenticate: Bearer realm="mcp", resource_metadata="https://gateway.mcp.aidev.samsungds.net/.well-known/oauth-protected-resource/mock/mcp", scope="mcp:mock:use", error="insufficient_scope"
```

The existing JSON response shape is retained, for example:

```json
{ "error": "unauthorized", "message": "Bearer access token is required" }
```

## Internal identity token

The gateway does **not** pass the original Keycloak Bearer token to the backend.
Instead it strips every client-supplied identity header and mints a fresh,
short-lived internal JWT.

Removed from the inbound request before proxying:

```
Authorization
X-MCP-Identity   X-MCP-Subject   X-MCP-LoginID   X-MCP-Username
X-MCP-Email      X-MCP-Groups    X-MCP-Scopes    X-MCP-Request-ID
```

Set by the gateway on the outbound request:

```http
X-MCP-Identity: <gateway-signed internal JWT>
X-MCP-Request-ID: <request id>
X-MCP-LoginID: <loginid>     # debug convenience; trust X-MCP-Identity
X-MCP-Subject: <sub>         # debug convenience; trust X-MCP-Identity
```

The **trust boundary is `X-MCP-Identity`.** It is an HS256 JWT (MVP) whose
secret is shared only between the gateway and the backend:

```json
{
  "iss": "mcp-auth-gateway",
  "aud": "mock-mcp-server",
  "sub": "<keycloak sub>",
  "loginid": "<loginid>",
  "username": "<preferred_username>",
  "email": "<email>",
  "groups": ["..."],
  "scopes": ["mcp:mock:use"],
  "request_id": "<request id>",
  "iat": 1710000000,
  "nbf": 1710000000,
  "exp": 1710000060
}
```

Default TTL is 60s and the configured TTL may not exceed 5m. The backend
verifies HS256, `iss == mcp-auth-gateway`, `aud == mock-mcp-server`, `nbf`, and
`exp`.

## Configuration

See [`config.yaml`](./config.yaml). Key sections: `auth` (Keycloak/OIDC),
`internal_identity` (signing), and `servers` (path-based routing).
`allowed_groups: []` means no group restriction (scope + loginid still required).
Each server requires a non-empty `backend_identity_audience` and at least one
non-empty, unique `required_scopes` entry. `allowed_origins` contains exact
scheme-and-host origins permitted when a request supplies `Origin`; requests
without that header remain supported.

Configuration rejects unknown YAML fields and additional YAML documents. URL
fields must be structurally valid absolute HTTP(S) URLs without credentials,
queries, or fragments. HTTP remains supported for local development; HTTPS is
not imposed globally. Durations accept positive Go-style strings (`"10m"`,
`"60s"`); `internal_identity.ttl` is capped at 5m.

## Environment variables

| Variable | Purpose |
| -------- | ------- |
| `MCP_INTERNAL_JWT_SECRET` | HS256 secret for the internal identity token. Must contain at least 32 raw bytes. Injected in GitOps from Secret `mcp-internal-signing` key `jwt-secret`. Required. |

`MCP_INTERNAL_JWT_TTL` is expressed via `internal_identity.ttl` in config.

## Running

```bash
export MCP_INTERNAL_JWT_SECRET="$(openssl rand -base64 32)"
go run ./cmd/gateway -config config.yaml
```

## Testing

```bash
go test ./...
```

Tests use a mock OIDC discovery + JWKS server and a capturing backend, so no
real Keycloak is needed. They cover metadata, all auth-failure paths, path
rewrite, header stripping/replacement, and backend verification of the internal
identity token.
