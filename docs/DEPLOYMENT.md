# Deployment notes

This repository is a reference implementation. These notes say what a deployment has to provide; they are not a hardened production recipe.

## Shape

```
client --HTTPS--> [TLS-terminating proxy] --HTTP, loopback or private network--> hardened_mcp (uvicorn)
                                                                      |
                                                                      +--HTTPS--> identity provider (JWKS only)
```

The server binds to `127.0.0.1:8080` by default. It does not speak TLS itself and does not trust `X-Forwarded-*` headers (`proxy_headers=False`). Configure the proxy to pass the original `Host` header, because the Host check is the DNS-rebinding defense; set `HMCP_ALLOWED_HOSTS` if the public host name differs from `HMCP_RESOURCE_URL`.

## Configuration (environment, prefix `HMCP_`)

| Variable | Default | Notes |
|---|---|---|
| `RESOURCE_URL` | required | Canonical URL of the MCP endpoint, e.g. `https://mcp.example.com/mcp`. No trailing slash, fragment, query or credentials. HTTPS except loopback. This is the expected token audience unless `AUDIENCE` is set. |
| `ISSUER` | required | The authorization server's issuer, matched exactly against `iss`. |
| `JWKS_URL` or `JWKS_FILE` | exactly one | HTTPS URL (the only outbound request) or a local file that is reloaded on change. |
| `AUDIENCE` | `RESOURCE_URL` | Override only if the provider cannot mint the resource URL as audience. |
| `ALGORITHMS` | `RS256,ES256` | Asymmetric only; startup refuses anything else. |
| `CLOCK_SKEW_SECONDS` / `MAX_TOKEN_LIFETIME_SECONDS` | 30 / 3600 | Bounded at startup. |
| `MAX_BODY_BYTES` / `RATE_PER_MINUTE` | 65536 / 60 | Per request / per principal. |
| `TEAM_CLAIM` | `team` | Claim holding the caller's team. Must be set by the provider, not by users. |
| `ALLOWED_HOSTS` / `ALLOWED_ORIGINS` | resource host / none | Comma-separated. No wildcards. Browser clients are not expected; leave origins empty unless you need one. |
| `AUDIT_PATH` | stdout | File is created with mode 0600. Ship it to an append-only store. |
| `BIND_HOST` / `BIND_PORT` | `127.0.0.1` / 8080 | Keep loopback behind a proxy. |

Invalid configuration prevents startup with a specific error.

## What the identity provider must do

- Issue **asymmetrically signed** JWT access tokens (RS256 or ES256) with a `kid`.
- Include `iss`, `sub`, `iat`, `exp`, `jti`, and an `aud` containing the MCP server's resource URL (RFC 8707 resource indicators, or an audience mapper).
- Put granted scopes in `scope` (space-separated) or `scp` (list). Use `findings:read` and `findings:write`.
- Put the caller's team in the `team` claim (a short `[A-Za-z0-9_.:-]` string), set by the provider.
- Keep access tokens short-lived (five to fifteen minutes).

`deploy/keycloak` shows one configuration that does this. It has not been run live.

## Operating

- Alert on audit events with `decision: "deny"` and on spikes of `request_rejected`; the `reason` codes distinguish probing from misconfiguration.
- Run `python -m hardened_mcp.manifest` in CI so tool descriptions cannot change silently. After a deliberate change, run it with `--update` and review the diff to `manifest.lock.json`.
- The seeded in-memory findings are fictional demo data. Replace `data.py` with a real store, keep the team filter inside it, and keep the rule that absent and forbidden look identical.
