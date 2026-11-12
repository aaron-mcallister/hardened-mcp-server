"""RFC 6750 / RFC 9728 response building. Values come from configuration, never from the request."""

from __future__ import annotations

import json
from typing import Any

from .config import SCOPE_READ, Settings


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def www_authenticate(
    settings: Settings,
    *,
    error: str | None = None,
    description: str | None = None,
    scope: frozenset[str] | None = None,
) -> str:
    """Build a Bearer challenge.

    With no credentials the error code is omitted (RFC 6750 section 3.1). Every challenge carries the
    protected-resource-metadata URL, and a `scope` parameter naming what the operation needs.
    """
    params: list[str] = []
    if error:
        params.append(f"error={_quote(error)}")
    if description:
        params.append(f"error_description={_quote(description)}")
    params.append(f"resource_metadata={_quote(settings.metadata_url)}")
    scopes = scope if scope else frozenset({SCOPE_READ})
    params.append(f"scope={_quote(' '.join(sorted(scopes)))}")
    return "Bearer " + ", ".join(params)


def protected_resource_metadata(settings: Settings) -> dict[str, Any]:
    """RFC 9728 document. `scopes_supported` is the minimal set: write access is requested by step-up."""
    return {
        "resource": settings.resource_url,
        "authorization_servers": [settings.issuer],
        "scopes_supported": [SCOPE_READ],
        "bearer_methods_supported": ["header"],
        "resource_name": "Findings MCP server (reference)",
    }


def metadata_json(settings: Settings) -> bytes:
    return json.dumps(protected_resource_metadata(settings), sort_keys=True).encode()
