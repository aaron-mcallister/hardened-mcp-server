"""The Keycloak example is not run in CI (it needs Docker and a pulled image), but it must not drift away from
the server it is an example for. These checks are offline consistency checks, not a substitute for running it."""

from __future__ import annotations

import json
import pathlib

from hardened_mcp.config import SCOPE_READ, SCOPE_WRITE

REALM = json.loads(
    (pathlib.Path(__file__).resolve().parent.parent / "deploy/keycloak/realm-hms.json").read_text()
)
EXAMPLE_RESOURCE = "http://127.0.0.1:8080/mcp"


def _scope(name):
    return next(s for s in REALM["clientScopes"] if s["name"] == name)


def test_realm_defines_exactly_the_scopes_the_server_uses():
    names = {s["name"] for s in REALM["clientScopes"]}
    assert {SCOPE_READ, SCOPE_WRITE} <= names


def test_audience_mapper_targets_the_resource_url_not_a_wildcard():
    mapper = _scope("mcp-audience")["protocolMappers"][0]
    assert mapper["protocolMapper"] == "oidc-audience-mapper"
    assert mapper["config"]["included.custom.audience"] == EXAMPLE_RESOURCE


def test_read_is_default_and_write_is_step_up_only():
    for client in REALM["clients"]:
        assert SCOPE_READ in client["defaultClientScopes"]
        assert SCOPE_WRITE not in client["defaultClientScopes"]
        assert SCOPE_WRITE in client["optionalClientScopes"]


def test_clients_use_client_credentials_only_and_carry_a_team_claim():
    teams = set()
    for client in REALM["clients"]:
        assert client["serviceAccountsEnabled"] is True
        assert client["standardFlowEnabled"] is False
        assert client["implicitFlowEnabled"] is False
        assert client["directAccessGrantsEnabled"] is False  # no password grant
        assert client["fullScopeAllowed"] is False
        assert "demo-only" in client["secret"]  # throwaway, and says so
        mapper = next(m for m in client["protocolMappers"] if m["config"]["claim.name"] == "team")
        teams.add(mapper["config"]["claim.value"])
    assert teams == {"payments", "platform"}  # the two teams in the seeded data


def test_token_lifetime_is_short():
    assert REALM["accessTokenLifespan"] <= 600
