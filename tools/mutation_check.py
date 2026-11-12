#!/usr/bin/env python3
"""Prove the tests are guarding something: break each security control and require the suite to fail.

Each mutation edits one line of the server in a temporary copy of the repository, runs the tests there, and
expects at least one failure ("killed"). A mutation that the suite does not notice ("survived") means a
control exists that nothing would miss, which is either a missing test or a control that does nothing.

Usage: python tools/mutation_check.py [--jobs N] [--only SUBSTRING]
Exit status: 0 if every mutation was killed, 1 if any survived.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
J = "hardened_mcp/jwt_verify.py"
M = "hardened_mcp/middleware.py"

# Mutations that cannot be observed because another layer produces the same behaviour. Keeping the redundant
# control is deliberate (defence in depth); listing it here, with the reason, keeps that honest and visible.
EQUIVALENT: dict[str, str] = {
    "keys-kty-not-matched-to-alg": "PyJWT's PyJWK already rejects a key whose type does not match the algorithm "
    "(InvalidKeyError), so our explicit check is a second line of defence against a library change.",
}

MUTATIONS: list[tuple[str, str, str, str]] = [
    # --- token validation
    ("jwt-audience-not-checked", J, '"sub", "jti"]},', '"sub", "jti"], "verify_aud": False},'),
    ("jwt-issuer-not-checked", J, "issuer=self._s.issuer,", "issuer=None,"),
    ("jwt-signature-not-checked", J, '"sub", "jti"]},', '"sub", "jti"], "verify_signature": False},'),
    (
        "jwt-alg-allowlist-removed",
        J,
        "if not isinstance(alg, str) or alg not in self._s.algorithms:",
        "if not isinstance(alg, str):",
    ),
    (
        "jwt-forbidden-headers-allowed",
        J,
        "if any(name in header for name in _FORBIDDEN_HEADERS):",
        "if False:",
    ),
    (
        "jwt-lifetime-cap-removed",
        J,
        'if claims["exp"] - claims["iat"] > self._s.max_token_lifetime_seconds:',
        "if False:",
    ),
    (
        "jwt-exp-not-required",
        J,
        '["exp", "iat", "iss", "aud", "sub", "jti"]',
        '["iat", "iss", "aud", "sub", "jti"]',
    ),
    ("jwt-leeway-unbounded", J, "leeway=self._s.clock_skew_seconds,", "leeway=10**9,"),
    (
        "keys-wrong-use-accepted",
        "hardened_mcp/keys.py",
        'if jwk.get("use") not in (None, "sig"):',
        "if False:",
    ),
    (
        "keys-kty-not-matched-to-alg",
        "hardened_mcp/keys.py",
        'if alg.startswith("ES") and kty != "EC":',
        "if False:",
    ),
    (
        "keys-refresh-not-rate-limited",
        "hardened_mcp/keys.py",
        "can_retry = self._last_attempt is None or now - self._last_attempt >= self._min_interval",
        "can_retry = True",
    ),
    (
        "config-symmetric-algs-allowed",
        "hardened_mcp/config.py",
        '{"RS256", "RS384"',
        '{"HS256", "RS256", "RS384"',
    ),
    # --- HTTP guard
    (
        "guard-host-not-checked",
        M,
        "if host not in {h.lower() for h in self.s.effective_allowed_hosts}:",
        "if False:",
    ),
    (
        "guard-origin-not-checked",
        M,
        "if origin and not set(origin) <= set(self.s.allowed_origins):",
        "if False:",
    ),
    ("guard-method-not-restricted", M, 'if scope["method"] != "POST":', "if False:"),
    (
        "guard-rate-limit-removed",
        M,
        "allowed, wait = self.limiter.allow(principal.subject)",
        "allowed, wait = True, 0.0",
    ),
    (
        "guard-content-type-not-checked",
        M,
        'if not (hdrs.get("content-type") or [""])[0].lower().startswith("application/json"):',
        "if False:",
    ),
    ("guard-streamed-size-not-checked", M, "if size > self.s.max_body_bytes:", "if False:"),
    (
        "guard-declared-size-not-checked",
        M,
        "if declared is not None and (not declared.isdigit() or int(declared) > self.s.max_body_bytes):",
        "if False:",
    ),
    (
        "guard-header-body-mismatch-allowed",
        M,
        "if (hdr_method and hdr_method != [method]) or",
        "if False and (hdr_method and hdr_method != [method]) or",
    ),
    ("guard-leaks-failure-reason", M, 'description="The access token is invalid"', "description=exc.reason"),
    (
        "guard-responses-cacheable",
        M,
        '_NO_STORE = [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")]',
        "_NO_STORE = []",
    ),
    (
        "guard-batch-accepted-as-object-check-removed",
        M,
        'not isinstance(message, dict)\n            or message.get("jsonrpc") != "2.0"',
        'False\n            or message.get("jsonrpc") != "2.0"',
    ),
    # --- authorization
    (
        "authz-scope-check-removed",
        "hardened_mcp/authz.py",
        'if policy.required_scopes <= effective_scopes(principal.scopes):\n        return Decision(True, "scope_ok")',
        'if True:\n        return Decision(True, "scope_ok")',
    ),
    (
        "authz-unknown-methods-allowed",
        "hardened_mcp/authz.py",
        'if method != "tools/call":\n        return Decision(False, "method_not_permitted")',
        'if method != "tools/call":\n        return Decision(True, "method_not_permitted")',
    ),
    (
        "authz-unknown-tools-allowed",
        "hardened_mcp/authz.py",
        'if policy is None:\n        return Decision(False, "unknown_tool")',
        'if policy is None:\n        return Decision(True, "unknown_tool")',
    ),
    (
        "authz-hierarchy-removed",
        "hardened_mcp/authz.py",
        "HIERARCHY: dict[str, frozenset[str]] = {SCOPE_WRITE: frozenset({SCOPE_READ})}",
        "HIERARCHY: dict[str, frozenset[str]] = {}",
    ),
    (
        "authz-handler-check-removed",
        "hardened_mcp/authz.py",
        "if not policy.required_scopes <= effective_scopes(principal.scopes):\n                raise ToolDenied",
        "if False:\n                raise ToolDenied",
    ),
    (
        "authz-challenge-omits-scope",
        "hardened_mcp/authz.py",
        'return Decision(False, "insufficient_scope", policy.required_scopes)',
        'return Decision(False, "insufficient_scope", frozenset())',
    ),
    ("registry-mismatch-allowed", "hardened_mcp/server.py", "if served != declared:", "if False:"),
    # --- object level
    (
        "data-cross-team-read-allowed",
        "hardened_mcp/data.py",
        "if team is None or finding is None or finding.team != team:",
        "if team is None or finding is None:",
    ),
    (
        "data-search-crosses-teams",
        "hardened_mcp/data.py",
        "for f in self.list_for(team)\n",
        "for f in self._by_id.values()\n",
    ),
    (
        "data-note-limit-removed",
        "hardened_mcp/data.py",
        "if len(finding.notes) >= MAX_NOTES_PER_FINDING:",
        "if False:",
    ),
    # --- output hardening
    (
        "sanitize-tag-chars-kept",
        "hardened_mcp/sanitize.py",
        '"\\U000e0000-\\U000e007f"  # tag characters (invisible text smuggling)',
        '""',
    ),
    (
        "sanitize-bidi-kept",
        "hardened_mcp/sanitize.py",
        '"\u202a-\u202e"  # bidirectional embedding and override',
        '""',
    ),
    ("sanitize-links-kept", "hardened_mcp/sanitize.py", 'text = text.replace("](", "] (")', "pass"),
    (
        "sanitize-html-kept",
        "hardened_mcp/sanitize.py",
        "text = _HTML_TAG.sub(",
        "text = text  # _HTML_TAG.sub(",
    ),
    (
        "sanitize-marker-chars-kept",
        "hardened_mcp/sanitize.py",
        "text = text.translate(_MARKER_CHARS)",
        "pass",
    ),
    ("sanitize-length-uncapped", "hardened_mcp/sanitize.py", "if len(text) > max_len:", "if False:"),
    (
        "sanitize-boundary-predictable",
        "hardened_mcp/sanitize.py",
        "return secrets.token_hex(6)",
        'return "000000000000"',
    ),
    # --- audit
    (
        "audit-credential-fields-allowed",
        "hardened_mcp/audit.py",
        "if key.lower() in FORBIDDEN_KEYS:",
        "if False:",
    ),
    ("audit-chain-broken", "hardened_mcp/audit.py", 'self._prev = record["hash"]', "self._prev = GENESIS"),
    (
        "audit-denials-not-logged",
        M,
        'self.audit.emit("authn", decision="deny", reason=exc.reason, token_present=True, **base)',
        "pass",
    ),
    (
        "audit-args-logged-raw",
        "hardened_mcp/audit.py",
        "return {str(k)[:64]: len(json.dumps(v, default=str)) for k, v in list(arguments.items())[:32]}",
        "return {str(k)[:64]: v for k, v in list(arguments.items())[:32]}",
    ),
    # --- rate limiter
    (
        "ratelimit-memory-unbounded",
        "hardened_mcp/ratelimit.py",
        "while len(self._buckets) > self._max_keys:",
        "while False:",
    ),
]


def run_one(item: tuple[str, str, str, str]) -> tuple[str, str]:
    name, rel, old, new = item
    with tempfile.TemporaryDirectory(prefix="mut-") as tmp:
        work = pathlib.Path(tmp) / "repo"
        shutil.copytree(
            ROOT,
            work,
            ignore=shutil.ignore_patterns(
                ".git", "__pycache__", ".pytest_cache", ".ruff_cache", "*.egg-info"
            ),
        )
        target = work / rel
        text = target.read_text(encoding="utf-8")
        if text.count(old) != 1:
            return name, f"ERROR: pattern occurs {text.count(old)} times in {rel}"
        target.write_text(text.replace(old, new), encoding="utf-8")
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argument list
                [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "tests"],
                cwd=work,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return name, "killed (timeout)"
        return name, "killed" if proc.returncode != 0 else "SURVIVED"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    items = [m for m in MUTATIONS if args.only in m[0]]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(run_one, items))
    bad = [(n, r) for n, r in results if not r.startswith("killed") and n not in EQUIVALENT]
    for name, result in results:
        note = (
            f"  (documented equivalent: {EQUIVALENT[name]})"
            if name in EQUIVALENT and not result.startswith("killed")
            else ""
        )
        print(f"{result:<18} {name}{note}")
    killed = sum(1 for _, r in results if r.startswith("killed"))
    equivalent = sum(1 for n, r in results if n in EQUIVALENT and not r.startswith("killed"))
    print(
        f"\n{killed}/{len(results)} mutations killed, {equivalent} documented equivalent, {len(bad)} unexplained"
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
