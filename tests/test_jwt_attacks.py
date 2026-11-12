"""Every way we know to present a bad token, and the proof that each one is refused.

For each case: HTTP 401, a generic `invalid_token` challenge (no hint about WHY), and a specific reason code
in the audit log, so an operator can see what was attempted without the caller learning what to fix.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest
from conftest import ISSUER, READ, RESOURCE, call_tool, result_of, rpc
from cryptography.hazmat.primitives import serialization


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _claims(**over):
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "sub": "mallory",
        "aud": RESOURCE,
        "iat": now,
        "exp": now + 300,
        "jti": "x1",
        "scope": f"{READ} findings:write",
        "team": "payments",
    }
    base.update(over)
    return base


def alg_none(idp):
    header = _b64(json.dumps({"alg": "none", "kid": "rsa-1", "typ": "JWT"}).encode())
    return f"{header}.{_b64(json.dumps(_claims()).encode())}."


def hs256_signed_with_public_key(idp):
    """Classic key-confusion: sign with HMAC using the (public) RSA key as the secret."""
    pem = idp.rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = _b64(json.dumps({"alg": "HS256", "kid": "rsa-1", "typ": "JWT"}).encode())
    body = _b64(json.dumps(_claims()).encode())
    sig = hmac.new(pem, f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64(sig)}"


CASES = {
    "alg_none": (alg_none, {"alg_not_allowed"}),
    "hs256_key_confusion": (hs256_signed_with_public_key, {"alg_not_allowed"}),
    "signed_by_unknown_key_same_kid": (lambda i: i.mint(key=i.other_key), {"bad_signature"}),
    "unknown_kid": (lambda i: i.mint(kid="no-such-key"), {"key_not_found"}),
    "no_kid": (lambda i: i.mint(kid=None), {"kid_missing"}),
    "alg_not_on_allow_list": (lambda i: i.mint(alg="RS512"), {"alg_not_allowed"}),
    "ec_kid_presented_with_rs256": (lambda i: i.mint(kid="ec-1"), {"key_not_found"}),
    "wrong_issuer": (lambda i: i.mint(iss="https://evil.test"), {"bad_issuer"}),
    "issuer_trailing_slash": (lambda i: i.mint(iss=ISSUER + "/"), {"bad_issuer"}),
    "wrong_audience": (lambda i: i.mint(aud="https://other.test/mcp"), {"bad_audience"}),
    "audience_list_without_us": (
        lambda i: i.mint(aud=["https://a.test", "https://b.test"]),
        {"bad_audience"},
    ),
    "audience_trailing_slash": (lambda i: i.mint(aud=RESOURCE + "/"), {"bad_audience"}),
    "expired": (lambda i: i.mint(exp_in=-120), {"expired"}),
    "not_before_in_future": (lambda i: i.mint(nbf_offset=600), {"not_yet_valid"}),
    "issued_in_future": (lambda i: i.mint(iat_offset=600), {"not_yet_valid"}),
    "missing_exp": (lambda i: i.mint(drop=("exp",)), {"missing_claim"}),
    "missing_iat": (lambda i: i.mint(drop=("iat",)), {"missing_claim"}),
    "missing_jti": (lambda i: i.mint(drop=("jti",)), {"missing_claim"}),
    "missing_sub": (lambda i: i.mint(drop=("sub",)), {"missing_claim"}),
    "missing_aud": (lambda i: i.mint(drop=("aud",)), {"missing_claim"}),
    "missing_iss": (lambda i: i.mint(drop=("iss",)), {"missing_claim"}),
    "lifetime_too_long": (lambda i: i.mint(exp_in=86400), {"lifetime_too_long"}),
    "jku_header": (
        lambda i: i.mint(headers={"jku": "https://attacker.test/jwks.json"}),
        {"forbidden_header"},
    ),
    "x5u_header": (lambda i: i.mint(headers={"x5u": "https://attacker.test/cert.pem"}), {"forbidden_header"}),
    "embedded_jwk_header": (
        lambda i: i.mint(headers={"jwk": {"kty": "RSA", "n": "AQAB", "e": "AQAB"}}),
        {"forbidden_header"},
    ),
    "non_string_subject": (lambda i: i.mint(claims={"sub": 12345}), {"invalid", "bad_claim_type"}),
    "non_numeric_exp": (
        lambda i: i.mint(claims={"exp": "never"}),
        {"invalid", "bad_claim_type", "malformed"},
    ),
    "oversized_token": (lambda i: "a." + "b" * 9000 + ".c", {"malformed"}),
    "not_a_jwt": (lambda i: "not.a.jwt", {"malformed", "invalid"}),
    "only_two_segments": (lambda i: "abc.def", {"malformed"}),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_bad_token_is_refused_with_a_generic_challenge(env, idp, name):
    build, reasons = CASES[name]
    response = call_tool(env.client, "list_findings", token=build(idp))
    assert response.status_code == 401, name
    challenge = response.headers["www-authenticate"]
    assert 'error="invalid_token"' in challenge
    assert "resource_metadata=" in challenge
    # the caller learns nothing about which check failed
    assert response.json() == {"error": "invalid_token"}
    for hint in ("audience", "issuer", "signature", "expired", "algorithm", "kid", "jku"):
        assert hint not in challenge.lower() and hint not in response.text.lower()
    # the operator does
    denials = [r for r in env.events("authn") if r["decision"] == "deny"]
    assert len(denials) == 1 and denials[0]["reason"] in reasons, (name, denials)


def test_a_valid_token_is_accepted(env, idp):
    result = result_of(call_tool(env.client, "list_findings", token=idp.mint()))
    assert result["isError"] is False


def test_es256_token_is_accepted(env, idp):
    result = result_of(call_tool(env.client, "list_findings", token=idp.mint(alg="ES256", kid="ec-1")))
    assert result["isError"] is False


def test_audience_may_be_a_list_that_contains_this_server(env, idp):
    token = idp.mint(aud=["https://other.test", RESOURCE])
    assert result_of(call_tool(env.client, "list_findings", token=token))["isError"] is False


def test_small_clock_skew_is_tolerated_but_not_large(env, idp):
    assert call_tool(env.client, "list_findings", token=idp.mint(exp_in=-10)).status_code == 200
    assert call_tool(env.client, "list_findings", token=idp.mint(exp_in=-90)).status_code == 401


# ---- how the credential is presented -------------------------------------------------------------------


def test_no_credentials_gets_a_challenge_without_an_error_code(env):
    response = call_tool(env.client, "list_findings", token=None)
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert "error=" not in challenge  # RFC 6750 section 3.1: no error code when no credentials were sent
    assert 'resource_metadata="https://mcp.test/.well-known/oauth-protected-resource/mcp"' in challenge
    assert 'scope="findings:read"' in challenge


def test_a_token_in_the_query_string_is_never_read(env, idp):
    token = idp.mint()
    response = rpc(env.client, "tools/list", path=f"/mcp?access_token={token}")
    assert response.status_code == 401


def test_two_authorization_headers_are_rejected_as_ambiguous(env, idp):
    token = idp.mint()
    response = env.client.post(
        "/mcp",
        content=b"{}",
        headers=[
            ("Authorization", f"Bearer {token}"),
            ("Authorization", f"Bearer {token}"),
            ("Content-Type", "application/json"),
        ],
    )
    assert response.status_code == 400
    assert 'error="invalid_request"' in response.headers["www-authenticate"]


def test_another_auth_scheme_is_treated_as_no_credentials(env):
    response = rpc(env.client, "tools/list", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code == 401
    assert "error=" not in response.headers["www-authenticate"]


def test_bearer_scheme_is_case_insensitive(env, idp):
    response = rpc(env.client, "tools/list", headers={"Authorization": f"bearer {idp.mint()}"})
    assert response.status_code == 200


@pytest.mark.parametrize(
    "credential", ["Bearer ", "Bearer    ", "Bearer a b", "Bearer \u0000x", "Bearer <script>"]
)
def test_malformed_bearer_values_are_refused(env, credential):
    response = rpc(env.client, "tools/list", headers={"Authorization": credential})
    assert response.status_code in (400, 401)
    assert response.status_code != 200
