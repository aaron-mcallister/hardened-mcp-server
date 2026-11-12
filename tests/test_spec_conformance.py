"""Behaviors the MCP authorization spec (revision 2026-07-28) and RFCs 6750, 8707 and 9728 require of a
protected MCP server, plus the transport-level checks that protect it. Section references are in
docs/SPEC-CONFORMANCE.md."""

from __future__ import annotations

import json

import pytest
from conftest import ISSUER, READ, RESOURCE, WRITE, call_tool, rpc

# ---- RFC 9728: protected resource metadata -------------------------------------------------------------


def test_protected_resource_metadata_is_public_and_correct(env):
    response = env.client.get("/.well-known/oauth-protected-resource/mcp")  # no credentials
    assert response.status_code == 200
    doc = response.json()
    assert doc["resource"] == RESOURCE
    assert doc["authorization_servers"] == [ISSUER]
    assert doc["bearer_methods_supported"] == ["header"]


def test_metadata_advertises_only_the_minimal_scope(env):
    """Scope minimization: the write scope is obtained by step-up, not advertised up front."""
    doc = env.client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert doc["scopes_supported"] == [READ]
    assert WRITE not in json.dumps(doc)


def test_metadata_url_in_every_challenge_resolves_to_the_document(env, idp):
    header = call_tool(env.client, "list_findings", token=None).headers["www-authenticate"]
    url = header.split('resource_metadata="')[1].split('"')[0]
    assert url == "https://mcp.test/.well-known/oauth-protected-resource/mcp"
    assert env.client.get(url.replace("https://mcp.test", "")).json()["resource"] == RESOURCE


def test_metadata_is_get_only(env):
    assert env.client.post("/.well-known/oauth-protected-resource/mcp").status_code == 405


# ---- RFC 6750 / spec: 401 and 403 challenges -----------------------------------------------------------


def test_insufficient_scope_is_a_403_with_the_full_required_scope_set(env, idp):
    token = idp.mint(scopes=(READ,))
    response = call_tool(env.client, "add_triage_note", {"finding_id": "F-1001", "note": "x"}, token=token)
    assert response.status_code == 403
    challenge = response.headers["www-authenticate"]
    assert 'error="insufficient_scope"' in challenge
    assert 'scope="findings:write"' in challenge
    assert "resource_metadata=" in challenge


def test_step_up_succeeds_with_the_new_scope(env, idp):
    assert (
        call_tool(
            env.client,
            "add_triage_note",
            {"finding_id": "F-1001", "note": "x"},
            token=idp.mint(scopes=(READ,)),
        ).status_code
        == 403
    )
    again = call_tool(
        env.client,
        "add_triage_note",
        {"finding_id": "F-1001", "note": "x"},
        token=idp.mint(scopes=(READ, WRITE)),
    )
    assert again.status_code == 200 and again.json()["result"]["isError"] is False


def test_responses_are_never_cacheable(env, idp):
    for response in (
        call_tool(env.client, "list_findings", token=None),
        call_tool(env.client, "list_findings", token=idp.mint()),
    ):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"


# ---- Host / Origin (DNS rebinding) ---------------------------------------------------------------------


def test_unexpected_host_header_is_refused_before_authentication(env, idp):
    response = rpc(env.client, "tools/list", token=idp.mint(), headers={"Host": "attacker.example"})
    assert response.status_code == 421
    assert "www-authenticate" not in response.headers  # no authentication state is revealed


def test_cross_origin_requests_are_refused(env, idp):
    response = rpc(env.client, "tools/list", token=idp.mint(), headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    # Refused by our guard (and audited), not merely by the SDK's own transport check behind it.
    assert response.json() == {"error": "forbidden_origin"}
    assert env.events("request_rejected")[-1]["reason"] == "bad_origin"


def test_configured_origin_is_allowed(make_env, idp):
    env = make_env(allowed_origins=("https://app.example",))
    ok = rpc(env.client, "tools/list", token=idp.mint(), headers={"Origin": "https://app.example"})
    assert ok.status_code == 200
    assert (
        rpc(
            env.client, "tools/list", token=idp.mint(), headers={"Origin": "https://app.example.evil"}
        ).status_code
        == 403
    )


def test_requests_without_an_origin_are_allowed(env, idp):
    assert rpc(env.client, "tools/list", token=idp.mint()).status_code == 200


# ---- Transport hygiene ---------------------------------------------------------------------------------


@pytest.mark.parametrize("verb", ["GET", "PUT", "DELETE", "PATCH"])
def test_only_post_carries_mcp_messages(env, idp, verb):
    response = env.client.request(verb, "/mcp", headers={"Authorization": f"Bearer {idp.mint()}"})
    assert response.status_code == 405 and response.headers["allow"] == "POST"


def test_unknown_paths_are_404(env, idp):
    assert env.client.post("/admin", headers={"Authorization": f"Bearer {idp.mint()}"}).status_code == 404


def test_wrong_content_type_is_415(env, idp):
    response = rpc(env.client, "tools/list", token=idp.mint(), headers={"Content-Type": "text/plain"})
    assert response.status_code == 415


def test_oversized_body_is_413_without_reading_it_all(env, idp):
    big = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"pad": "x" * 70_000}}
    ).encode()
    assert rpc(env.client, "tools/list", token=idp.mint(), raw=big).status_code == 413


def test_oversized_streaming_body_without_content_length_is_413(env, idp):
    def chunks():
        for _ in range(100):  # 100 KiB, sent chunked: there is no Content-Length to check up front
            yield b" " * 1024

    response = env.client.post(
        "/mcp",
        content=chunks(),
        headers={
            "Authorization": f"Bearer {idp.mint()}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert response.status_code == 413


def test_declared_oversize_is_refused_without_reading_the_body(env, idp):
    """A Content-Length above the cap is rejected up front: the guard never asks for the body at all."""
    import asyncio

    reads: list[int] = []
    sent: list[dict] = []

    async def receive():
        reads.append(1)
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "scheme": "https",
        "headers": [
            (b"host", b"mcp.test"),
            (b"authorization", f"Bearer {idp.mint()}".encode()),
            (b"content-type", b"application/json"),
            (b"content-length", b"1000000"),
        ],
    }
    asyncio.run(env.app(scope, receive, send))
    assert sent[0]["status"] == 413
    assert reads == []


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b'[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]',
        b"null",
        b"{}",
        b'{"jsonrpc":"1.0","method":"tools/list"}',
        b'{"jsonrpc":"2.0","method":5}',
    ],
)
def test_malformed_json_rpc_is_400_and_batches_are_not_accepted(env, idp, body):
    response = rpc(env.client, "tools/list", token=idp.mint(), raw=body)
    assert response.status_code == 400


def test_deeply_nested_json_does_not_crash_the_server(env, idp):
    body = b"[" * 20_000 + b"]" * 20_000
    assert rpc(env.client, "tools/list", token=idp.mint(), raw=body).status_code == 400


# ---- Routing headers are hints, never authority --------------------------------------------------------


def test_header_naming_a_harmless_method_cannot_smuggle_a_privileged_call(env, idp):
    """Header says tools/list, body says add_triage_note, token is read-only: refused, and not authorized by the header."""
    response = rpc(
        env.client,
        "tools/call",
        {"name": "add_triage_note", "arguments": {"finding_id": "F-1001", "note": "x"}},
        token=idp.mint(scopes=(READ,)),
        headers={"Mcp-Method": "tools/list"},
    )
    assert response.status_code == 400
    assert env.store.get_for("payments", "F-1001").notes == []
    assert env.events("request_rejected")[-1]["reason"] == "header_body_mismatch"


def test_header_naming_a_permitted_tool_cannot_smuggle_a_forbidden_one(env, idp):
    response = rpc(
        env.client,
        "tools/call",
        {"name": "add_triage_note", "arguments": {"finding_id": "F-1001", "note": "x"}},
        token=idp.mint(scopes=(READ,)),
        headers={"Mcp-Name": "list_findings"},
    )
    assert response.status_code == 400
    assert env.store.get_for("payments", "F-1001").notes == []


def test_legacy_handshake_requests_work_and_are_authenticated(env, idp):
    """A client on the previous revision sends initialize first; it still has to present a valid token."""
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "c", "version": "1"},
        },
    }
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    assert env.client.post("/mcp", json=body, headers=headers).status_code == 401
    ok = env.client.post("/mcp", json=body, headers={**headers, "Authorization": f"Bearer {idp.mint()}"})
    assert ok.status_code == 200 and ok.json()["result"]["serverInfo"]["name"] == "findings"
