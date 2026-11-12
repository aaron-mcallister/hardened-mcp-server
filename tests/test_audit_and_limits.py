"""Audit logging, tamper evidence, secrecy of the log, rate limiting, and identity isolation under concurrency."""

from __future__ import annotations

import asyncio
import json
import logging

import httpx
import pytest
from conftest import META, READ, WRITE, Env, FakeClock, base_settings, call_tool, rpc

from hardened_mcp.audit import AuditError, AuditLog, arg_shape, verify_chain
from hardened_mcp.data import seed_store
from hardened_mcp.ratelimit import RateLimiter

SECRET_NOTE = "customer-ssn-123-45-6789-do-not-log"


# ---- what is recorded ---------------------------------------------------------------------------------


def test_each_kind_of_outcome_leaves_a_record(env, idp):
    rpc(env.client, "tools/list")  # 401 no credentials
    rpc(env.client, "tools/list", token=idp.mint(iss="https://evil.test"))  # 401 bad token
    call_tool(env.client, "add_triage_note", {"finding_id": "F-1001", "note": "x"}, token=idp.mint())  # 403
    call_tool(env.client, "list_findings", token=idp.mint())  # allowed
    rpc(env.client, "tools/list", token=idp.mint(), headers={"Host": "evil.example"})  # 421
    seen = {(e["event"], e.get("decision"), e.get("reason")) for e in env.audit()}
    assert ("authn", "deny", "no_credentials") in seen
    assert ("authn", "deny", "bad_issuer") in seen
    assert ("authz", "deny", "insufficient_scope") in seen
    assert ("authz", "allow", "scope_ok") in seen
    assert ("request_rejected", None, "bad_host") in seen
    assert any(e["event"] == "request_completed" and e["status"] == 200 for e in env.audit())


def test_records_identify_who_what_and_when(env, idp):
    call_tool(
        env.client, "get_finding", {"finding_id": "F-1001"}, token=idp.mint(sub="alice", team="payments")
    )
    allow = env.events("authz")[0]
    assert allow["subject"] == "alice" and allow["team"] == "payments" and allow["tool"] == "get_finding"
    assert allow["token_id"] and allow["request_id"] and allow["ts"].endswith("+00:00")
    assert env.events("request_completed")[0]["request_id"] == allow["request_id"]


def test_write_actions_are_logged_without_their_content(env, idp):
    call_tool(
        env.client,
        "add_triage_note",
        {"finding_id": "F-1001", "note": SECRET_NOTE},
        token=idp.mint(scopes=(WRITE,)),
    )
    assert env.events("triage_note_added")[0]["note_chars"] == len(SECRET_NOTE)
    assert SECRET_NOTE not in "\n".join(env.audit_lines)


def test_arguments_are_logged_as_shape_only(env, idp):
    call_tool(env.client, "search_findings", {"query": SECRET_NOTE}, token=idp.mint())
    assert env.events("authz")[0]["arg_shape"] == {"query": len(json.dumps(SECRET_NOTE))}
    assert SECRET_NOTE not in "\n".join(env.audit_lines)


def test_tokens_never_appear_in_the_log_or_in_python_logging(env, idp, caplog):
    caplog.set_level(logging.DEBUG)
    good, bad = idp.mint(), idp.mint(iss="https://evil.test")
    for token in (good, bad):
        call_tool(env.client, "list_findings", token=token)
    blob = "\n".join(env.audit_lines) + "\n".join(r.getMessage() for r in caplog.records)
    for token in (good, bad):
        assert (
            token not in blob and token.split(".")[1] not in blob
        )  # neither the token nor its payload segment


def test_the_log_refuses_to_record_credential_shaped_fields():
    log = AuditLog(lambda _l: None)
    for key in ("token", "Authorization", "access_token", "password", "secret", "cookie"):
        with pytest.raises(AuditError):
            log.emit("x", **{key: "v"})


def test_arg_shape_describes_without_revealing():
    assert arg_shape({"a": "hello", "b": [1, 2, 3]}) == {"a": 7, "b": 9}
    assert arg_shape(None) == {} and arg_shape("str") == {}  # type: ignore[arg-type]


# ---- tamper evidence ----------------------------------------------------------------------------------


def _lines(env, idp):
    for i in range(4):
        call_tool(env.client, "list_findings", token=idp.mint(sub=f"u{i}"))
    return list(env.audit_lines)


def test_an_intact_chain_verifies(env, idp):
    assert verify_chain(_lines(env, idp)) == (True, None)


def test_editing_a_record_is_detected(env, idp):
    lines = _lines(env, idp)
    record = json.loads(lines[2])
    record["subject"] = "someone-else"
    lines[2] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    assert verify_chain(lines) == (False, 2)


def test_deleting_a_record_is_detected(env, idp):
    lines = _lines(env, idp)
    del lines[3]
    ok, where = verify_chain(lines)
    assert not ok and where == 3


def test_reordering_records_is_detected(env, idp):
    lines = _lines(env, idp)
    lines[1], lines[2] = lines[2], lines[1]
    assert not verify_chain(lines)[0]


def test_truncating_the_tail_is_not_detectable_without_an_external_anchor():
    """Documented limit: a prefix of a valid chain is a valid chain. Ship lines off-box to close this."""
    log_lines: list[str] = []
    log = AuditLog(log_lines.append)
    for i in range(5):
        log.emit("e", n=i)
    assert verify_chain(log_lines[:3]) == (True, None)


def test_the_audit_file_is_created_private(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog.to_file(str(path))
    log.emit("hello")
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert verify_chain(path.read_text().splitlines()) == (True, None)


# ---- rate limiting ------------------------------------------------------------------------------------


def test_requests_over_the_limit_get_429_with_retry_after(make_env, idp):
    env = make_env(rate_per_minute=5)
    token = idp.mint()
    codes = [call_tool(env.client, "list_findings", token=token).status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and set(codes[5:]) == {429}
    limited = call_tool(env.client, "list_findings", token=token)
    assert int(limited.headers["retry-after"]) >= 1
    assert env.events("rate_limited")


def test_the_limit_is_per_principal(make_env, idp):
    env = make_env(rate_per_minute=2)
    for _ in range(3):
        call_tool(env.client, "list_findings", token=idp.mint(sub="noisy"))
    assert call_tool(env.client, "list_findings", token=idp.mint(sub="quiet")).status_code == 200


def test_denied_requests_also_consume_budget(make_env, idp):
    env = make_env(rate_per_minute=3)
    token = idp.mint(scopes=(READ,))
    codes = [
        call_tool(
            env.client, "add_triage_note", {"finding_id": "F-1001", "note": "x"}, token=token
        ).status_code
        for _ in range(5)
    ]
    assert codes == [403, 403, 403, 429, 429]


def test_the_bucket_refills_over_time():
    clock = FakeClock()
    limiter = RateLimiter(60, clock=clock)
    assert all(limiter.allow("a")[0] for _ in range(60)) and not limiter.allow("a")[0]
    clock.advance(1.0)
    assert limiter.allow("a")[0] and not limiter.allow("a")[0]


def test_limiter_memory_is_bounded():
    limiter = RateLimiter(10, max_keys=100, clock=FakeClock())
    for i in range(10_000):
        limiter.allow(f"user-{i}")
    assert len(limiter) <= 100


# ---- identity isolation under concurrency -------------------------------------------------------------


def test_concurrent_requests_never_see_each_others_identity(idp):
    """Fifty overlapping requests from two teams: each must get exactly its own team's data."""
    env = Env(
        idp, base_settings(rate_per_minute=10_000), seed_store(), FakeClock()
    )  # own app: its lifespan runs once
    expect = {"payments": "F-1001", "platform": "F-2001"}
    tokens = {team: idp.mint(sub=f"user-{team}", team=team) for team in expect}

    async def run():
        transport = httpx.ASGITransport(app=env.app)
        async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as client:

            async def one(i: int):
                team = "payments" if i % 2 else "platform"
                r = await client.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": i,
                        "method": "tools/call",
                        "params": {"name": "list_findings", "arguments": {}, "_meta": META},
                    },
                    headers={
                        "Authorization": f"Bearer {tokens[team]}",
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                        "MCP-Protocol-Version": "2026-07-28",
                        "Mcp-Method": "tools/call",
                        "Mcp-Name": "list_findings",
                    },
                )
                return team, r.json()["result"]["structuredContent"]["findings"]

            return await asyncio.gather(*[one(i) for i in range(50)])

    async def with_lifespan():
        async with env.app.inner.router.lifespan_context(env.app.inner):
            return await run()

    for team, findings in asyncio.run(with_lifespan()):
        ids = {f["id"] for f in findings}
        assert expect[team] in ids
        assert (
            all(i.startswith("F-1") for i in ids)
            if team == "payments"
            else all(i.startswith("F-2") for i in ids)
        )
