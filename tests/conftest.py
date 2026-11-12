"""Test support: a fake identity provider, an app factory, and a helper that speaks the 2026-07-28 wire format."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from starlette.testclient import TestClient

from hardened_mcp.audit import AuditLog
from hardened_mcp.config import SCOPE_READ, SCOPE_WRITE, Settings
from hardened_mcp.data import FindingStore, seed_store
from hardened_mcp.keys import StaticKeySource
from hardened_mcp.server import build_app

RESOURCE = "https://mcp.test/mcp"
ISSUER = "https://as.test"
HOST = "mcp.test"
READ, WRITE = SCOPE_READ, SCOPE_WRITE

META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "conformance-tests", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_key_other():
    """A key the server has never heard of: stands in for an attacker's key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


@dataclass
class IdP:
    """Mints tokens. Every claim and header can be overridden or dropped to build an attack."""

    rsa_key: Any
    ec_key: Any
    other_key: Any

    def jwks(self) -> dict[str, Any]:
        rsa_jwk = json.loads(RSAAlgorithm.to_jwk(self.rsa_key.public_key()))
        ec_jwk = json.loads(ECAlgorithm.to_jwk(self.ec_key.public_key()))
        return {
            "keys": [
                {**rsa_jwk, "kid": "rsa-1", "use": "sig", "alg": "RS256"},
                {**ec_jwk, "kid": "ec-1", "use": "sig", "alg": "ES256"},
            ]
        }

    def mint(
        self,
        *,
        sub: str = "alice",
        scopes: tuple[str, ...] | None = (READ,),
        team: str | None = "payments",
        aud: Any = RESOURCE,
        iss: str = ISSUER,
        exp_in: int = 300,
        iat_offset: int = 0,
        nbf_offset: int | None = None,
        alg: str = "RS256",
        kid: str | None = "rsa-1",
        key: Any = None,
        claims: dict[str, Any] | None = None,
        drop: tuple[str, ...] = (),
        headers: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": iss,
            "sub": sub,
            "aud": aud,
            "iat": now + iat_offset,
            "exp": now + iat_offset + exp_in,
            "jti": uuid.uuid4().hex,
        }
        if scopes is not None:
            payload["scope"] = " ".join(scopes)
        if team is not None:
            payload["team"] = team
        if nbf_offset is not None:
            payload["nbf"] = now + nbf_offset
        payload.update(claims or {})
        for name in drop:
            payload.pop(name, None)
        hdrs = dict(headers or {})
        if kid is not None:
            hdrs.setdefault("kid", kid)
        if key is None:
            key = self.ec_key if alg.startswith("ES") else self.rsa_key
        return jwt.encode(payload, key, algorithm=alg, headers=hdrs)


@pytest.fixture
def idp(rsa_key, ec_key, rsa_key_other):
    return IdP(rsa_key, ec_key, rsa_key_other)


class Env:
    def __init__(self, idp: IdP, settings: Settings, store: FindingStore, clock) -> None:
        self.idp, self.settings, self.store, self.clock = idp, settings, store, clock
        self.audit_lines: list[str] = []
        audit = AuditLog(self.audit_lines.append)
        self.app = build_app(
            settings, key_source=StaticKeySource(idp.jwks()), store=store, audit=audit, clock=clock
        )
        self.client = TestClient(self.app, base_url="https://mcp.test", raise_server_exceptions=False)

    def audit(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.audit_lines]

    def events(self, name: str) -> list[dict[str, Any]]:
        return [r for r in self.audit() if r["event"] == name]


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def base_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {"resource_url": RESOURCE, "issuer": ISSUER, "jwks_file": "/unused/jwks.json"}
    values.update(overrides)
    return Settings(**values).validate()


@pytest.fixture
def make_env(idp):
    created: list[Env] = []

    def factory(**overrides: Any) -> Env:
        env = Env(idp, base_settings(**overrides), seed_store(), FakeClock())
        env.client.__enter__()  # runs the app lifespan
        created.append(env)
        return env

    yield factory
    for env in created:
        env.client.__exit__(None, None, None)


@pytest.fixture
def env(make_env) -> Env:
    return make_env()


def rpc(
    client: TestClient,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    token: str | None = None,
    headers: dict[str, str] | None = None,
    rid: int = 1,
    raw: bytes | None = None,
    path: str = "/mcp",
):
    """POST one 2026-07-28 request: no handshake, routing headers matching the body."""
    p = dict(params or {})
    p["_meta"] = META
    body = {"jsonrpc": "2.0", "id": rid, "method": method, "params": p}
    h = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
    }
    if method == "tools/call":
        h["Mcp-Name"] = str(p.get("name"))
    if token:
        h["Authorization"] = f"Bearer {token}"
    h.update(headers or {})
    if raw is not None:
        return client.post(path, content=raw, headers=h)
    return client.post(path, json=body, headers=h)


def call_tool(
    client: TestClient, name: str, arguments: dict[str, Any] | None = None, *, token: str | None, **kw
):
    return rpc(client, "tools/call", {"name": name, "arguments": arguments or {}}, token=token, **kw)


def result_of(response) -> dict[str, Any]:
    assert response.status_code == 200, (response.status_code, response.text)
    body = response.json()
    assert "result" in body, body
    return body["result"]


ALL_TOOLS = ("list_findings", "get_finding", "search_findings", "add_triage_note")
