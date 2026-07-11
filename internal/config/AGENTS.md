# CONFIG PACKAGE KNOWLEDGE BASE

## OVERVIEW

Defines the complete YAML contract, defaults, derived paths, environment-secret lookup, and fail-fast security validation.

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add/change YAML fields | `config.go` | Update struct tags, defaults, validation, checked-in YAML, and tests together |
| Change server route derivation | `config.go` | `ExternalBasePath`, `MetadataPath` |
| Change URL/origin rules | `config.go` | `parseHTTPReference`, `IsSerializedHTTPOrigin` |
| Change duration rules | `config.go` | `Duration.UnmarshalYAML`, positive TTL checks, 5m identity cap |
| Verify checked-in deployment config | `config_test.go` | `TestCheckedInConfigLoads` resolves root `config.yaml` |

## CONVENTIONS

- Decode YAML with `KnownFields(true)` and require EOF after the first document.
- Apply defaults before validation; defaulted behavior is externally observable and must stay tested.
- Keep `required_scopes` normalized by trimming each entry during validation, then reject empty, duplicate, or non-token values.
- Require each server's `allowed_origins` to include the exact origin of `public_resource`.
- Reject duplicate derived external MCP paths, not merely duplicate raw prefixes.
- Read the signing secret only through the configured environment-variable name; never serialize secret material into config.
- Accept local HTTP for development. Do not impose HTTPS globally in structural URL validation.

## ANTI-PATTERNS

- Do not permit unknown YAML keys, compatibility fields for obsolete names, or multiple YAML documents.
- Do not accept URL userinfo, query strings, fragments, opaque URLs, relative URLs, or whitespace-padded values.
- Do not accept origin paths, `null`, multiple serialized origins, duplicates, or canonicalization that changes the configured string.
- Do not allow an empty server list, empty backend identity audience, empty scope list, or empty origin list.
- Do not let `internal_identity.ttl` exceed `MaxInternalIdentityTTL` or silently default an explicitly supplied zero duration.
- Do not move policy validation downstream into `server`; invalid deployments must fail during `Load`.

## TESTING

```bash
go test ./internal/config
```

Use table-driven validation cases and retain a test that loads the checked-in `config.yaml`.
