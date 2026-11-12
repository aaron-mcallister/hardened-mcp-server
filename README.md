# hardened-mcp-server

[![CI](https://github.com/aaron-mcallister/hardened-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/aaron-mcallister/hardened-mcp-server/actions/workflows/ci.yml)

A small [Model Context Protocol](https://modelcontextprotocol.io) server in Python that exists to show what a **secure** MCP server looks like in practice: every security control is a behavior with a test, mapped to the authorization specification, and the tests themselves are checked by deliberately breaking each control.

The domain is a read-mostly "security findings" service (list, get, search, and add a triage note), with fictional data. The point is not the findings; it is the controls around them.

> Personal project. Not official guidance from, or the position of, any employer or vendor. The identity provider example is just an example.

## What it demonstrates

| Area | What is implemented | Where |
|---|---|---|
| Authentication | OAuth 2.1 **resource server**: JWT validation with algorithm allow-list, pinned issuer, required claims, audience bound to this server (RFC 8707), key confusion and `jku`/`x5u`/`jwk` header attacks refused | `jwt_verify.py`, `keys.py` |
| Discovery | RFC 9728 protected resource metadata, correct `WWW-Authenticate` challenges (401 vs 403, `insufficient_scope` with the full scope set) | `challenge.py`, `middleware.py` |
| Authorization | Per-tool scopes, step-up for the write scope, scope hierarchy, deny by default for unknown methods and tools, handlers re-check (defense in depth), **object-level** team isolation with no existence oracle | `authz.py`, `data.py` |
| Transport hygiene | Host and Origin checks (DNS rebinding), POST only, content type, declared and streamed body caps, strict JSON-RPC shape, routing headers must match the body and are never trusted | `middleware.py` |
| Untrusted data | Free text from findings is treated as hostile: invisible and bidi characters stripped, markup defanged, per-response random boundary and notice | `sanitize.py` |
| Tool integrity | Tool descriptions are static, linted, hashed and pinned; the server will not start if a tool lacks an access policy | `manifest.py`, `server.py` |
| Accountability | Hash-chained audit log that never records tokens or note contents; per-principal rate limit | `audit.py`, `ratelimit.py` |
| Verification | 268 tests, a spec-conformance map, and a mutation check that breaks 45 controls and requires the suite to notice | `tests/`, `tools/mutation_check.py` |

## Start here

- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md): what it defends against, and, just as important, what it does not.
- [`docs/SPEC-CONFORMANCE.md`](docs/SPEC-CONFORMANCE.md): each requirement of MCP revision 2026-07-28 mapped to code and tests.
- [`docs/VALIDATION.md`](docs/VALIDATION.md): what was run, what was found, and what was **not** validated (no live client, no live identity provider).
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) and [`deploy/keycloak`](deploy/keycloak): configuration and an example identity provider setup.

## Run the tests

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest
python tools/mutation_check.py     # about a minute on two cores
```

Python 3.11 and 3.13 are covered in CI. Requires Python 3.10 or newer (the SDK's minimum).

## Run the server

The server is configured through `HMCP_*` environment variables (see `docs/DEPLOYMENT.md`) and refuses to start with an unsafe configuration. It listens on loopback and expects a TLS-terminating proxy in front for anything else.

## Related

Part of a small set of vendor-neutral security projects: [`agent-security-evals`](https://github.com/aaron-mcallister/agent-security-evals) (testing agents against attacks) and [`claude-code-governance`](https://github.com/aaron-mcallister/claude-code-governance) (managed-settings policy for coding agents, with a linter and tests).

MIT licensed. Built with the help of an AI coding assistant; reviewed, tested and owned by the author.
