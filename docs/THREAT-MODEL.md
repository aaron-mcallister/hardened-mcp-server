# Threat model

A short, honest model of what this server defends against, how, and what it does not. "Test" columns refer to files in `tests/`; the control catalogue is mutation-tested (`tools/mutation_check.py`).

## Assets and actors

- **Assets:** security findings (confidential, team-scoped); the ability to add triage notes (integrity of the record); the audit log; the availability of the service; the identity provider's signing keys (read only).
- **Callers:** AI agents and clients acting for a user or service. A caller may be compromised, confused, or manipulated by content it read earlier.
- **Data is untrusted too.** Finding titles, descriptions and notes are written by other people (and by other agents). They reach a model through this server, so they are an input channel for **indirect prompt injection**.

## Threats and controls

| Threat | Control | Tests |
|---|---|---|
| Forged or tampered token (alg `none`, HS256-with-public-key confusion, unknown key, bad signature) | Asymmetric algorithms only (RS256/ES256), algorithm allow-list, key chosen by `kid` and algorithm family, signature verified, configuration refuses symmetric algorithms | `test_jwt_attacks.py`, `test_keys_and_config.py` |
| Header tricks (`jku`, `x5u`, `jwk`, `x5c`) pointing the verifier at attacker keys | Refused outright; keys come only from the configured JWKS | `test_jwt_attacks.py` |
| Token for a different service replayed here (confused deputy at the token level) | Audience must contain this server's canonical resource URL; issuer pinned | `test_jwt_attacks.py` |
| Long-lived or replayable tokens | `exp`, `iat`, `jti` required; lifetime capped; small clock-skew allowance | `test_jwt_attacks.py` |
| Over-privileged callers | Per-tool scopes, deny by default for unknown methods and tool names, write scope obtained by step-up | `test_authz.py` |
| Reading another team's findings, or learning they exist | Team comes only from the verified token; absent and forbidden are indistinguishable; search never counts other teams' data | `test_authz.py` (object-level tests) |
| Authorization bypass by editing routing headers | Headers must match the body and are never trusted for the decision | `test_spec_conformance.py` |
| Defect in the HTTP layer exposing a handler | Each handler re-checks scope itself (defence in depth) | `test_authz.py::test_a_tool_refuses_a_principal_without_the_scope_even_when_the_http_guard_is_bypassed` |
| Indirect prompt injection and exfiltration through finding text | Output hardening: invisible, bidirectional, and tag-block characters stripped; markup, links, images and HTML defanged; every free-text field wrapped in a per-response random boundary with a notice that the text is data | `test_output_hardening.py` |
| Tool poisoning / "rug pull" (descriptions that change after approval) | Descriptions are static, linted, and pinned by hash in `manifest.lock.json`; CI fails on drift | `test_manifest.py` |
| Tool and policy drifting apart (a tool shipped with no access rule) | Start-up refuses to run if served tools and declared policies differ | `test_manifest.py` |
| DNS rebinding against a local server | Host and Origin allow-lists, checked before authentication | `test_spec_conformance.py` |
| Resource exhaustion | Body-size cap (declared and streamed), JSON-RPC shape checks, per-principal token bucket with bounded memory, bounded notes, input length limits | `test_spec_conformance.py`, `test_audit_and_limits.py` |
| Hammering the identity provider through junk tokens | Signing-key refresh is rate-limited; stale keys are kept through outages; a request for an unknown key id cannot cause more than one fetch per interval | `test_keys_and_config.py` |
| SSRF through the key fetch | Operator-configured HTTPS URL only, no redirects, size and time caps | `test_keys_and_config.py` |
| Secrets in logs | Tokens never logged; the audit writer refuses credential-shaped field names; arguments are logged as shapes only; note text is never logged | `test_audit_and_limits.py` |
| Undetected log tampering | Hash-chained audit records detect edits, deletions and reordering | `test_audit_and_limits.py` |
| Information leaks in errors | One generic 401 description for every token failure; reason codes go to the audit log, not the client | `test_jwt_attacks.py` |

## What this does not protect against (read this before relying on it)

1. **Prompt injection cannot be solved on the server.** Output hardening removes known carrier techniques and marks untrusted text, but a model may still follow instructions embedded in a finding. The mitigations that matter are on the client: least-privilege tools, human confirmation for writes, and not combining this server with tools that can exfiltrate data. This server's write tool is narrow (a bounded note on a finding the caller's team owns) for that reason.
2. **The audit chain is tamper-evident, not tamper-proof.** Anyone who can rewrite the whole file can rebuild the chain, and truncating the tail is undetectable without an external anchor (a test documents this). Ship records to an append-only store.
3. **No TLS.** Terminate TLS in front of the server (`docs/DEPLOYMENT.md`). The server binds to loopback by default.
4. **The rate limiter is per process.** Several replicas each keep their own buckets.
5. **Authorization quality depends on the identity provider.** If it issues tokens with the wrong audience mapping or an attacker-controlled `team` claim, this server will trust them. The `team` claim must be set by the provider, never by the user.
6. **Tool listing is visible to any authenticated caller**, regardless of scope, by design (the descriptions are public in this repository).
7. **Not tested against a live Claude client or a live identity provider.** See `docs/VALIDATION.md`.
8. **Supply chain** is addressed by pinned CI actions, Dependabot, `pip-audit` and a small dependency set, not by a signed-release process. This is a reference implementation, not a published package.
