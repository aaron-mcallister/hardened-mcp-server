"""Key sources (the one outbound request) and start-up configuration."""

from __future__ import annotations

import asyncio
import json
import urllib.request

import pytest
from conftest import ISSUER, RESOURCE, FakeClock

from hardened_mcp.config import ConfigError, Settings
from hardened_mcp.keys import (
    FileKeySource,
    HttpsKeySource,
    KeyFetchError,
    StaticKeySource,
    fetch_https,
    jwk_to_key,
)


def run(coro):
    return asyncio.run(coro)


# ---- JWKS handling ------------------------------------------------------------------------------------


def test_static_source_returns_the_right_key_for_the_right_algorithm(idp):
    src = StaticKeySource(idp.jwks())
    assert run(src.get_key("rsa-1", "RS256")) is not None
    assert run(src.get_key("ec-1", "ES256")) is not None
    assert run(src.get_key("rsa-1", "ES256")) is None  # wrong key family for the algorithm
    assert run(src.get_key("ec-1", "RS256")) is None
    assert run(src.get_key("missing", "RS256")) is None


@pytest.mark.parametrize("patch", [{"use": "enc"}, {"alg": "RS512"}, {"key_ops": ["encrypt"]}])
def test_jwks_entries_not_meant_for_verification_are_ignored(idp, patch):
    jwk = {**idp.jwks()["keys"][0], **patch}
    assert jwk_to_key(jwk, "RS256") is None


def test_malformed_jwks_is_rejected():
    with pytest.raises(KeyFetchError):
        StaticKeySource({"keys": "nope"})
    with pytest.raises(KeyFetchError):
        StaticKeySource([])  # type: ignore[arg-type]


def test_file_source_picks_up_rotation(tmp_path, idp):
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps({"keys": []}))
    src = FileKeySource(str(path))
    assert run(src.get_key("rsa-1", "RS256")) is None
    path.write_text(json.dumps(idp.jwks()))
    import os

    os.utime(path, (path.stat().st_atime + 5, path.stat().st_mtime + 5))
    assert run(src.get_key("rsa-1", "RS256")) is not None


def test_file_source_fails_closed_on_missing_file(tmp_path):
    assert run(FileKeySource(str(tmp_path / "absent.json")).get_key("k", "RS256")) is None


# ---- HTTPS source: SSRF-shaped and amplification-shaped behaviours ------------------------------------


def test_https_source_refuses_plain_http_off_loopback():
    with pytest.raises(ValueError):
        HttpsKeySource("http://as.test/jwks")
    HttpsKeySource("https://as.test/jwks")
    HttpsKeySource("http://127.0.0.1:9000/jwks")  # loopback development


def test_fetch_helper_refuses_non_https_schemes():
    for url in ("file:///etc/passwd", "ftp://as.test/jwks", "http://as.test/jwks", "gopher://x"):
        with pytest.raises(KeyFetchError):
            fetch_https(url)


def test_redirects_are_never_followed():
    handler = [
        h
        for h in urllib.request.build_opener(
            __import__("hardened_mcp.keys", fromlist=["_NoRedirect"])._NoRedirect
        ).handlers
        if h.__class__.__name__ == "_NoRedirect"
    ][0]
    assert handler.redirect_request(None, None, 302, "Found", {}, "http://169.254.169.254/") is None


def test_junk_tokens_cannot_make_the_server_hammer_the_identity_provider(idp):
    clock, calls = FakeClock(), []

    def fetch(url):
        calls.append(url)
        return json.dumps(idp.jwks()).encode()

    src = HttpsKeySource("https://as.test/jwks", fetch=fetch, clock=clock, min_refresh_interval=60)
    for i in range(500):  # 500 tokens naming 500 different unknown key ids
        assert run(src.get_key(f"junk-{i}", "RS256")) is None
    assert len(calls) == 1  # one fetch, not 500
    clock.advance(61)
    run(src.get_key("junk-again", "RS256"))
    assert len(calls) == 2  # and again only after the interval


def test_a_new_key_is_found_after_rotation_without_waiting_for_the_ttl(idp):
    clock = FakeClock()
    state = {"keys": {"keys": []}}
    src = HttpsKeySource(
        "https://as.test/jwks", fetch=lambda u: json.dumps(state["keys"]).encode(), clock=clock
    )
    assert run(src.get_key("rsa-1", "RS256")) is None
    state["keys"] = idp.jwks()
    clock.advance(61)
    assert run(src.get_key("rsa-1", "RS256")) is not None


def test_cached_keys_survive_an_identity_provider_outage(idp):
    clock, up = FakeClock(), {"ok": True}

    def fetch(url):
        if not up["ok"]:
            raise KeyFetchError("down")
        return json.dumps(idp.jwks()).encode()

    src = HttpsKeySource("https://as.test/jwks", fetch=fetch, clock=clock, ttl=300)
    assert run(src.get_key("rsa-1", "RS256")) is not None
    up["ok"] = False
    clock.advance(1000)  # past the TTL, provider down
    assert run(src.get_key("rsa-1", "RS256")) is not None  # keep serving the last good key set


def test_jwks_with_too_many_or_odd_entries_is_bounded(idp):
    jwks = {"keys": [{"kty": "RSA", "kid": f"k{i}"} for i in range(500)] + [{"kty": "RSA"}, "x", 5]}
    src = StaticKeySource(jwks)
    assert len(src._keys) <= 64


# ---- Settings -----------------------------------------------------------------------------------------

GOOD = {"resource_url": RESOURCE, "issuer": ISSUER, "jwks_url": "https://as.test/jwks"}


def test_a_good_configuration_validates():
    s = Settings(**GOOD).validate()
    assert s.expected_audience == RESOURCE and s.mcp_path == "/mcp"
    assert s.metadata_path == "/.well-known/oauth-protected-resource/mcp"
    assert s.effective_allowed_hosts == ("mcp.test",)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"resource_url": "http://mcp.example.com/mcp"}, "https"),
        ({"resource_url": "https://mcp.test/mcp/"}, "slash"),
        ({"resource_url": "https://mcp.test/mcp#frag"}, "fragment"),
        ({"resource_url": "https://mcp.test/mcp?x=1"}, "query"),
        ({"resource_url": "https://u:p@mcp.test/mcp"}, "credentials"),
        ({"resource_url": "mcp.test/mcp"}, "absolute"),
        ({"issuer": "http://as.example.com"}, "https"),
        ({"audience": "ftp://x"}, "http"),
        ({"jwks_url": None}, "exactly one"),
        ({"jwks_url": "https://as.test/jwks", "jwks_file": "/x"}, "exactly one"),
        ({"jwks_url": "http://as.example.com/jwks"}, "https"),
        ({"algorithms": ()}, "at least one"),
        ({"algorithms": ("HS256",)}, "not permitted"),
        ({"algorithms": ("none",)}, "not permitted"),
        ({"algorithms": ("RS256", "HS512")}, "not permitted"),
        ({"clock_skew_seconds": 3600}, "clock_skew"),
        ({"max_token_lifetime_seconds": 10**7}, "lifetime"),
        ({"max_body_bytes": 10**9}, "max_body_bytes"),
        ({"rate_per_minute": 0}, "rate_per_minute"),
        ({"allowed_hosts": ("*.example.com",)}, "wildcards"),
        ({"allowed_origins": ("*",)}, "origins"),
        ({"allowed_origins": ("app.example",)}, "origins"),
        ({"team_claim": "not a name"}, "team_claim"),
    ],
)
def test_unsafe_configuration_is_rejected(override, message):
    with pytest.raises(ConfigError, match=message):
        Settings(**{**GOOD, **override}).validate()


def test_plain_http_is_allowed_for_loopback_development_only():
    Settings(
        resource_url="http://127.0.0.1:8080/mcp", issuer="http://localhost:9000", jwks_file="/k"
    ).validate()


def test_settings_from_environment():
    env = {
        "HMCP_RESOURCE_URL": RESOURCE,
        "HMCP_ISSUER": ISSUER,
        "HMCP_JWKS_URL": "https://as.test/jwks",
        "HMCP_ALGORITHMS": "ES256",
        "HMCP_RATE_PER_MINUTE": "10",
        "HMCP_ALLOWED_ORIGINS": "https://a.example, https://b.example",
    }
    s = Settings.from_env(env)
    assert (
        s.algorithms == ("ES256",)
        and s.rate_per_minute == 10
        and s.allowed_origins == ("https://a.example", "https://b.example")
    )


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"HMCP_RESOURCE_URL": RESOURCE},
        {"HMCP_RESOURCE_URL": RESOURCE, "HMCP_ISSUER": ISSUER},
        {
            "HMCP_RESOURCE_URL": RESOURCE,
            "HMCP_ISSUER": ISSUER,
            "HMCP_JWKS_URL": "https://a/j",
            "HMCP_RATE_PER_MINUTE": "ten",
        },
    ],
)
def test_missing_or_bad_environment_is_a_clear_error(env):
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_the_app_will_not_start_with_an_invalid_configuration(idp):
    from hardened_mcp.keys import StaticKeySource as K
    from hardened_mcp.server import build_app

    bad = Settings(**{**GOOD, "algorithms": ("HS256",)})
    with pytest.raises(ConfigError):
        build_app(bad, key_source=K(idp.jwks()))
