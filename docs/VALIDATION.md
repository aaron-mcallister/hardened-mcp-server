# Validation: what was checked, and what was not

Claims in this repository are only as good as the evidence for them. This page says what that evidence is.

## What was run

| Check | Result |
|---|---|
| Test suite, Python 3.13 and 3.11 | 268 passed on both, locally. CI runs the same matrix. |
| `ruff check` and `ruff format --check` | clean |
| `pip-audit` | no known vulnerabilities at the time of writing |
| Pinned tool manifest (`python -m hardened_mcp.manifest`) | matches `manifest.lock.json` |
| Mutation check (`tools/mutation_check.py`) | 45 deliberate breakages of security controls: 44 caught by the tests, 1 documented equivalent, 0 unexplained |

Versions used: `mcp` 2.3.0 (the official Python SDK), PyJWT 2.15, Starlette 1.10, uvicorn 0.54. Python 3.10 is declared as the minimum (the SDK's requirement) but was **not** run.

## What the mutation check means

For each mutation the harness copies the repository, changes one line (for example: skip the audience check, accept symmetric algorithms, drop the Host check, let one team read another's findings, stop stripping tag characters, stop hash-chaining the audit log), runs the tests, and requires a failure. This is what separates "there is a control" from "there is a control that something would miss if it broke".

Two things the first full run found, which is why the check exists:

- Two controls (the Origin check and the up-front Content-Length check) were silently backed by another layer (the SDK's own check, and the streamed-size check), so the tests could not tell whether the guard's own check existed. The tests now assert the guard's own audit reason, and the up-front check is tested with a request whose body is never read.
- While the tests were being written, they exposed that the pinned manifest silently omitted input schemas and annotations (a serialization alias bug), which would have made the "descriptions are pinned" claim weaker than stated. Fixed, and covered by `test_tool_inputs_are_constrained` and `test_write_tool_is_not_marked_read_only_and_read_tools_are`.

**Documented equivalent mutant:** `keys-kty-not-matched-to-alg`. PyJWT already rejects a key whose type does not match the algorithm, so our explicit check cannot be observed. It is kept as a second line of defense against a library change.

Mutation testing has limits: it tests the mutations someone thought of. It is evidence that the listed controls are covered, not that no other flaw exists.

## Findings from probing the SDK (2.3.0)

1. The SDK's 401 for a request with no credentials includes `error="invalid_token"`; the specification's example omits the error code for that case (RFC 6750). This server sends its own challenge.
2. The SDK's audience check (`validate_token_resource`) defaults to off with only a warning, so audience validation has to be the token verifier's job.
3. DNS-rebinding protection is off by default except on loopback. This server enables it explicitly, and also checks Host and Origin before authentication.
4. The SDK's auth layer supports one blanket `required_scopes`, which cannot express per-tool scopes or step-up. Hence the guard in front.
5. A first probe negotiated protocol 2025-11-25 until requests used the 2026-07-28 single-exchange format (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `_meta`). Both formats are tested.
6. Tests use `httpx`; the SDK itself uses `httpx2`.

## What was NOT validated

- **No live Claude (or other) MCP client.** Requests in the tests are hand-built to the 2026-07-28 wire format. Interoperability with real clients' OAuth flows (metadata discovery, client registration, PKCE, step-up) is untested here.
- **No live identity provider.** Tokens come from a test fixture that mints RS256/ES256 tokens, including malicious variants. `deploy/keycloak` was **not run** (no container runtime was available where this was built); `tests/test_deploy_example.py` only checks the realm file offline against the server's expectations. Treat it as an example to adapt, and verify the token claims (`aud`, `scope`, `team`, `jti`) from your own provider.
- **No TLS, no proxy, no multi-replica behavior**, no load or performance testing, no fuzzing beyond the malformed-input cases in the tests.
- **Prompt-injection resistance of any model.** Tests verify that the server's output is sanitized and delimited as designed. They cannot show that a model will not follow instructions in text that remains.
- **No independent security review.** This is one person's work, assisted by an AI tool, and should be reviewed as such.
- **Python 3.10** (declared minimum) and non-Linux platforms.

## Reproducing

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
pytest
python -m hardened_mcp.manifest
python tools/mutation_check.py
pip-audit
```
