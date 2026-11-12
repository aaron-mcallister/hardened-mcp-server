# Example: trying the server with Keycloak

This is an **example**, not a recommendation of a particular identity provider, and **not validated**: it has not been run against a live Keycloak (see `docs/VALIDATION.md`). `tests/test_deploy_example.py` checks offline that the realm file matches what the server expects. Everything the server requires of an identity provider is listed in `docs/DEPLOYMENT.md`; any standards-compliant authorization server that can issue those tokens works.

What the realm file sets up (throwaway credentials, loopback only):

- Two machine clients, `agent-payments` and `agent-platform`, using the client credentials grant only (no password grant, no implicit flow). Each carries a hardcoded `team` claim, which the server uses for object-level access.
- Scopes `findings:read` (default) and `findings:write` (optional, requested only when needed: step-up).
- An audience mapper that puts `http://127.0.0.1:8080/mcp` in `aud`, which is what the server checks.
- Five-minute access tokens, RS256.

```bash
docker compose up            # Keycloak on http://localhost:9000, realm "hms" imported

export HMCP_RESOURCE_URL=http://127.0.0.1:8080/mcp
export HMCP_ISSUER=http://localhost:9000/realms/hms
export HMCP_JWKS_URL=http://localhost:9000/realms/hms/protocol/openid-connect/certs
python -m hardened_mcp       # in another terminal, from the repository root

# a read token for the payments team
TOKEN=$(curl -s http://localhost:9000/realms/hms/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=agent-payments \
  -d client_secret=agent-payments-secret-demo-only | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
```

Then POST a JSON-RPC `tools/call` to `http://127.0.0.1:8080/mcp` with `Authorization: Bearer $TOKEN`, `Content-Type: application/json`, `Accept: application/json, text/event-stream`, and the routing headers `Mcp-Method` / `Mcp-Name` that the 2026-07-28 revision requires. Asking for `add_triage_note` with this read-only token returns `403` with a `WWW-Authenticate` challenge naming `findings:write`; request the optional scope (`-d scope=findings:write`) to step up.

The image tag is pinned to a version, not a digest, because the author could not pull it. For anything beyond a local try-out, pin a digest and change every credential.
