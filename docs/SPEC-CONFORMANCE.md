# Conformance to the MCP authorization specification

Pinned to **MCP specification revision 2026-07-28** (authorization and security best practices pages), with RFC 6750 (bearer tokens), RFC 8707 (resource indicators), RFC 9728 (protected resource metadata) and OAuth 2.1 (draft) as the specification references them. This server is an OAuth **resource server** only. It never issues tokens, never proxies to another authorization server, and calls no other service except to fetch signing keys.

Every row names the test that fails if the behaviour is removed. `tools/mutation_check.py` additionally breaks the implementation of most rows and requires the named tests to notice (see `docs/VALIDATION.md`).

Authorization is optional in MCP and applies to HTTP transports only. This server is HTTP-only and always requires it. Over stdio the specification says to take credentials from the environment instead; this project does not provide a stdio mode.

| Requirement | Where it is met | Tests |
|---|---|---|
| MUST publish protected resource metadata (RFC 9728) naming its authorization server | `challenge.protected_resource_metadata`, served by `McpGuard` without authentication | `test_spec_conformance.py::test_protected_resource_metadata_is_public_and_correct`, `::test_metadata_is_get_only` |
| The `WWW-Authenticate` challenge MUST point to that metadata (`resource_metadata`) | `challenge.www_authenticate` (every 401 and 403) | `::test_metadata_url_in_every_challenge_resolves_to_the_document`; `test_jwt_attacks.py::test_no_credentials_gets_a_challenge_without_an_error_code` |
| No credentials presented: challenge without an `error` code (RFC 6750 section 3.1) | `McpGuard`, missing or non-Bearer `Authorization` | `test_jwt_attacks.py::test_no_credentials_gets_a_challenge_without_an_error_code`, `::test_another_auth_scheme_is_treated_as_no_credentials` |
| Invalid or expired token: 401 `invalid_token` | `McpGuard` with `TokenVerifier` reasons mapped to one generic description | `test_jwt_attacks.py::test_bad_token_is_refused_with_a_generic_challenge` (every failure class) |
| MUST validate that the token was issued for this server (audience, RFC 8707) | `jwt_verify.TokenVerifier`: `aud` must contain the configured resource | `test_jwt_attacks.py` (wrong audience, audience list, missing audience cases) |
| MUST NOT accept tokens issued for other resources; MUST NOT pass tokens through | Audience check above; the server makes no downstream calls with the caller's token (there are none) | same, plus `test_audit_and_limits.py::test_tokens_never_appear_in_the_log_or_in_python_logging` |
| Tokens ONLY in the `Authorization` header, never the query string | `McpGuard` reads only the header | `test_jwt_attacks.py::test_a_token_in_the_query_string_is_never_read` |
| Insufficient scope: 403 `insufficient_scope`, `scope` listing all scopes required, `resource_metadata` present | `authz.decide`, `challenge.www_authenticate` | `test_spec_conformance.py::test_insufficient_scope_is_a_403_with_the_full_required_scope_set`, `test_authz.py::test_tool_by_scope_matrix` |
| Step-up: the client can retry with the new scope | write scope absent from `scopes_supported`, required by the write tool | `::test_step_up_succeeds_with_the_new_scope`, `::test_metadata_advertises_only_the_minimal_scope` |
| Servers MUST account for scope hierarchies | `authz.HIERARCHY` (`findings:write` implies `findings:read`) | `test_authz.py::test_tool_by_scope_matrix` (write-only token can read) |
| Scope minimisation: advertise the minimum; elevate by step-up | `scopes_supported` is `findings:read` only | `::test_metadata_advertises_only_the_minimal_scope` |
| DNS rebinding: validate `Host` and `Origin` on HTTP transports | Guard checks first; SDK protection also enabled with explicit values (the SDK default is off off-loopback) | `::test_unexpected_host_header_is_refused_before_authentication`, `::test_cross_origin_requests_are_refused`, `::test_configured_origin_is_allowed` |
| Session or state handles, if any, must not be guessable or usable by another user | The server is stateless and returns no handles; pagination and resource handles are not implemented | n/a (absent by design) |
| 2026-07-28 routing headers (`Mcp-Method`, `Mcp-Name`) MUST match the body | `McpGuard` rejects mismatches (400, JSON-RPC -32020) and never authorizes from the headers | `::test_header_naming_a_harmless_method_cannot_smuggle_a_privileged_call`, `::test_header_naming_a_permitted_tool_cannot_smuggle_a_forbidden_one` |
| Clients on the previous revision (handshake) still work | SDK stateless mode; the guard authenticates every message including `initialize` | `::test_legacy_handshake_requests_work_and_are_authenticated` |

## Not applicable, because this is a resource server

- **Confused deputy** (the spec's concern for MCP servers that proxy to third-party authorization servers with static client IDs): no proxying, no consent screens, no client registration here.
- **Client ID Metadata Documents, Dynamic Client Registration, PKCE, the authorization and token endpoints, the RFC 9207 `iss` response parameter:** these are client and authorization-server behaviours. The example realm in `deploy/keycloak` does not exercise them; it uses the client-credentials grant.
- **SSRF through authorization-server discovery:** the server's only outbound request is the signing-key fetch from an operator-configured HTTPS URL (no redirects, size and time limits, rate-limited refresh). See `test_keys_and_config.py`.

## Findings from probing the official SDK (version 2.3.0)

These shaped the design (details in `docs/VALIDATION.md`): the SDK's built-in 401 includes `error="invalid_token"` even when no credentials were sent; audience validation is off by default; DNS-rebinding protection is off by default except on loopback; and its auth layer supports one blanket `required_scopes`, not per-tool step-up. This project therefore puts its own guard in front of the SDK and treats the SDK's auth as unconfigured.
