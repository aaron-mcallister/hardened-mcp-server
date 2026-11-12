from conftest import READ, call_tool, result_of, rpc


def test_authenticated_tool_call_works_end_to_end(env, idp):
    token = idp.mint(scopes=(READ,), team="payments")
    result = result_of(call_tool(env.client, "list_findings", token=token))
    assert result["isError"] is False
    ids = [f["id"] for f in result["structuredContent"]["findings"]]
    assert ids == ["F-1001", "F-1002", "F-1003", "F-1004"]


def test_tools_list_requires_only_authentication(env, idp):
    result = result_of(rpc(env.client, "tools/list", token=idp.mint(scopes=())))
    assert {t["name"] for t in result["tools"]} == {
        "list_findings",
        "get_finding",
        "search_findings",
        "add_triage_note",
    }
