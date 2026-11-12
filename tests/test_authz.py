"""Authorization: tool x scope matrix, deny-by-default for unknown methods and tools, scope hierarchy, and the
object-level (team) boundary."""

from __future__ import annotations

import itertools

import pytest
from conftest import ALL_TOOLS, READ, WRITE, call_tool, result_of, rpc

ARGS = {
    "list_findings": {},
    "get_finding": {"finding_id": "F-1001"},
    "search_findings": {"query": "TLS"},
    "add_triage_note": {"finding_id": "F-1001", "note": "looking into this"},
}
REQUIRES = {"list_findings": READ, "get_finding": READ, "search_findings": READ, "add_triage_note": WRITE}
SCOPE_SETS = {
    "none": (),
    "read": (READ,),
    "write": (WRITE,),  # write implies read (hierarchy)
    "read+write": (READ, WRITE),
    "unrelated": ("billing:read",),
    "wildcard": ("*",),
    "admin": ("findings:admin",),
    "overbroad": ("findings",),
}


def allowed(scopes: tuple[str, ...], tool: str) -> bool:
    granted = set(scopes)
    if WRITE in granted:
        granted.add(READ)
    return REQUIRES[tool] in granted


@pytest.mark.parametrize(("tool", "set_name"), list(itertools.product(ALL_TOOLS, SCOPE_SETS)))
def test_tool_by_scope_matrix(env, idp, tool, set_name):
    scopes = SCOPE_SETS[set_name]
    response = call_tool(env.client, tool, ARGS[tool], token=idp.mint(scopes=scopes))
    if allowed(scopes, tool):
        assert response.status_code == 200 and response.json()["result"]["isError"] is False
    else:
        assert response.status_code == 403
        assert 'error="insufficient_scope"' in response.headers["www-authenticate"]
        assert REQUIRES[tool] in response.headers["www-authenticate"]


def test_token_without_a_scope_claim_can_authenticate_but_not_call_tools(env, idp):
    token = idp.mint(scopes=None)  # e.g. an ID token or a client-credentials token with no scope
    assert rpc(env.client, "tools/list", token=token).status_code == 200
    assert call_tool(env.client, "list_findings", token=token).status_code == 403


def test_scp_list_claim_is_understood(env, idp):
    token = idp.mint(scopes=None, claims={"scp": [READ]})
    assert call_tool(env.client, "list_findings", token=token).status_code == 200


def test_malformed_scope_values_grant_nothing(env, idp):
    token = idp.mint(scopes=None, claims={"scope": 12345})
    assert call_tool(env.client, "list_findings", token=token).status_code == 403


# ---- deny by default ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "resources/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "logging/setLevel",
        "subscriptions/listen",
        "tasks/list",
        "tasks/get",
        "sampling/createMessage",
        "roots/list",
        "elicitation/create",
        "totally/made-up",
    ],
)
def test_unimplemented_and_unknown_methods_are_denied(env, idp, method):
    response = rpc(env.client, method, token=idp.mint(scopes=(READ, WRITE)))
    assert response.status_code == 403
    assert response.json() == {"error": "forbidden"}


@pytest.mark.parametrize(
    "name", ["", "nope", "LIST_FINDINGS", "list_findings ", "../list_findings", "list_findings\u0000"]
)
def test_unknown_tool_names_are_denied(env, idp, name):
    response = call_tool(env.client, name, token=idp.mint(scopes=(READ, WRITE)))
    assert response.status_code in (400, 403)
    assert response.status_code != 200


def test_tool_name_must_be_a_string(env, idp):
    response = rpc(
        env.client,
        "tools/call",
        {"name": ["list_findings"], "arguments": {}},
        token=idp.mint(),
        headers={"Mcp-Name": "list_findings"},
    )
    assert response.status_code == 400


def test_every_decision_is_audited_including_denials(env, idp):
    call_tool(env.client, "add_triage_note", ARGS["add_triage_note"], token=idp.mint(scopes=(READ,)))
    call_tool(env.client, "list_findings", token=idp.mint(scopes=(READ,)))
    decisions = [(e["decision"], e["reason"]) for e in env.events("authz")]
    assert decisions == [("deny", "insufficient_scope"), ("allow", "scope_ok")]


# ---- object-level authorization -------------------------------------------------------------------------


def _text(response):
    return response.json()["result"]["structuredContent"] if response.status_code == 200 else None


def test_a_team_sees_only_its_own_findings(env, idp):
    payments = result_of(call_tool(env.client, "list_findings", token=idp.mint(team="payments")))
    platform = result_of(call_tool(env.client, "list_findings", token=idp.mint(team="platform")))
    assert {f["id"] for f in payments["structuredContent"]["findings"]} == {
        "F-1001",
        "F-1002",
        "F-1003",
        "F-1004",
    }
    assert {f["id"] for f in platform["structuredContent"]["findings"]} == {"F-2001", "F-2002", "F-2003"}


def test_reading_another_teams_finding_looks_exactly_like_a_missing_one(env, idp):
    token = idp.mint(team="platform")
    other_teams = result_of(call_tool(env.client, "get_finding", {"finding_id": "F-1001"}, token=token))
    nonexistent = result_of(call_tool(env.client, "get_finding", {"finding_id": "F-9999"}, token=token))
    assert other_teams["isError"] and nonexistent["isError"]
    assert other_teams["content"] == nonexistent["content"]  # no existence oracle


def test_search_cannot_reveal_another_teams_data_by_hit_count(env, idp):
    result = result_of(
        call_tool(env.client, "search_findings", {"query": "SQL injection"}, token=idp.mint(team="platform"))
    )
    assert result["structuredContent"]["count"] == 0


def test_writing_a_note_on_another_teams_finding_is_refused_and_has_no_effect(env, idp):
    result = result_of(
        call_tool(
            env.client,
            "add_triage_note",
            {"finding_id": "F-1001", "note": "pwned"},
            token=idp.mint(scopes=(WRITE,), team="platform"),
        )
    )
    assert result["isError"]
    assert env.store.get_for("payments", "F-1001").notes == []


def test_a_token_with_no_team_sees_nothing(env, idp):
    token = idp.mint(team=None)
    assert result_of(call_tool(env.client, "list_findings", token=token))["structuredContent"]["count"] == 0
    assert result_of(call_tool(env.client, "get_finding", {"finding_id": "F-1001"}, token=token))["isError"]


@pytest.mark.parametrize(
    "team",
    ["", " payments", "payments ", "pay ments", "payments;platform", "../payments", "x" * 65, "pay\nments"],
)
def test_malformed_team_claims_mean_no_team(env, idp, team):
    token = idp.mint(team=None, claims={"team": team})
    assert result_of(call_tool(env.client, "list_findings", token=token))["structuredContent"]["count"] == 0


def test_team_claim_must_be_a_string(env, idp):
    token = idp.mint(team=None, claims={"team": ["payments", "platform"]})
    assert result_of(call_tool(env.client, "list_findings", token=token))["structuredContent"]["count"] == 0


def test_the_team_comes_from_the_token_never_from_arguments(env, idp):
    result = rpc(
        env.client,
        "tools/call",
        {"name": "list_findings", "arguments": {"team": "payments"}},
        token=idp.mint(team="platform"),
    )
    body = result.json()["result"]
    ids = [f["id"] for f in body["structuredContent"]["findings"]] if not body["isError"] else []
    assert not any(i.startswith("F-1") for i in ids)


@pytest.mark.parametrize(
    "bad", ["F-1", "f-1001", "F-1001 ", "F-1001;", "F-100000000", "../etc", "F-1001\n", "' OR 1=1 --"]
)
def test_finding_ids_are_validated_strictly(env, idp, bad):
    result = result_of(call_tool(env.client, "get_finding", {"finding_id": bad}, token=idp.mint()))
    assert result["isError"] is True


def test_note_length_and_count_are_bounded(env, idp):
    token = idp.mint(scopes=(WRITE,))
    assert result_of(
        call_tool(env.client, "add_triage_note", {"finding_id": "F-1001", "note": "x" * 1001}, token=token)
    )["isError"]
    for _ in range(50):
        assert not result_of(
            call_tool(env.client, "add_triage_note", {"finding_id": "F-1002", "note": "n"}, token=token)
        )["isError"]
    assert result_of(
        call_tool(
            env.client, "add_triage_note", {"finding_id": "F-1002", "note": "one too many"}, token=token
        )
    )["isError"]


# ---- defence in depth: the handlers protect themselves -------------------------------------------------


def _call_directly(principal, name, arguments):
    """Invoke a tool through the MCP implementation with NO HTTP guard in front, as if it were mounted elsewhere."""
    import asyncio

    from hardened_mcp.authz import PolicyRegistry
    from hardened_mcp.data import seed_store
    from hardened_mcp.principal import reset_principal, set_principal
    from hardened_mcp.server import build_server

    store = seed_store()
    server = build_server(store, PolicyRegistry())

    async def go():
        token = set_principal(principal) if principal else None
        try:
            return await server.call_tool(name, arguments)
        finally:
            if token:
                reset_principal(token)

    try:
        return store, asyncio.run(go())
    except Exception as exc:  # noqa: BLE001
        return store, exc


def test_a_tool_refuses_a_principal_without_the_scope_even_when_the_http_guard_is_bypassed():
    from conftest import ISSUER

    from hardened_mcp.principal import Principal

    weak = Principal("eve", frozenset({READ}), "payments", "j1", ISSUER)
    store, outcome = _call_directly(weak, "add_triage_note", {"finding_id": "F-1001", "note": "x"})
    assert isinstance(outcome, Exception)
    assert store.get_for("payments", "F-1001").notes == []


def test_a_tool_with_no_authenticated_principal_fails_closed():
    store, outcome = _call_directly(None, "list_findings", {})
    assert isinstance(outcome, Exception)
