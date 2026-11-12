"""Authorization policy: deny by default.

Two layers use this module. The HTTP guard decides before the request reaches the MCP implementation (so it
can answer with the spec's 403 + WWW-Authenticate challenge). Each tool then re-checks its own policy inside
the handler, so a tool is still protected if it is ever mounted behind a different front end.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .config import SCOPE_READ, SCOPE_WRITE
from .principal import Principal, require_principal

# A broader scope implies narrower ones (spec: servers MUST account for scope hierarchies).
HIERARCHY: dict[str, frozenset[str]] = {SCOPE_WRITE: frozenset({SCOPE_READ})}

# Protocol methods any authenticated caller may use. Everything else is denied, including methods the
# server does not implement (resources, prompts, subscriptions, tasks, logging, completion).
AUTHENTICATED_METHODS = frozenset(
    {
        "ping",
        "initialize",
        "server/discover",
        "notifications/initialized",
        "notifications/cancelled",
        "tools/list",
    }
)


class ToolDenied(Exception):
    """Raised inside a tool when the caller may not perform it. The message is deliberately generic."""


def effective_scopes(granted: frozenset[str]) -> frozenset[str]:
    out = set(granted)
    for scope in granted:
        out |= HIERARCHY.get(scope, frozenset())
    return frozenset(out)


@dataclass(frozen=True)
class ToolPolicy:
    name: str
    required_scopes: frozenset[str]
    risk: str  # "read" or "write"

    def __post_init__(self) -> None:
        if not self.required_scopes:
            raise ValueError(f"tool {self.name!r} must require at least one scope")
        if self.risk not in ("read", "write"):
            raise ValueError("risk must be 'read' or 'write'")


class PolicyRegistry:
    def __init__(self) -> None:
        self._policies: dict[str, ToolPolicy] = {}

    def add(self, policy: ToolPolicy) -> None:
        if policy.name in self._policies:
            raise ValueError(f"duplicate policy for tool {policy.name!r}")
        self._policies[policy.name] = policy

    def get(self, name: str) -> ToolPolicy | None:
        return self._policies.get(name)

    def names(self) -> frozenset[str]:
        return frozenset(self._policies)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str  # stable machine-readable code, used in the audit log
    required_scopes: frozenset[str] = frozenset()  # for an insufficient_scope challenge


def decide(method: str, tool_name: str | None, principal: Principal, registry: PolicyRegistry) -> Decision:
    if method in AUTHENTICATED_METHODS:
        return Decision(True, "authenticated_method")
    if method != "tools/call":
        return Decision(False, "method_not_permitted")
    if not tool_name:
        return Decision(False, "tool_not_named")
    policy = registry.get(tool_name)
    if policy is None:
        return Decision(False, "unknown_tool")
    if policy.required_scopes <= effective_scopes(principal.scopes):
        return Decision(True, "scope_ok")
    # Report every scope the operation needs, in one challenge, so the client can step up once.
    return Decision(False, "insufficient_scope", policy.required_scopes)


def guarded(policy: ToolPolicy) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Wrap a tool so it re-checks its policy against the verified principal before running."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            principal = require_principal()
            if not policy.required_scopes <= effective_scopes(principal.scopes):
                raise ToolDenied("not permitted")
            return fn(*args, **kwargs)

        return wrapper

    return decorator
