"""The authenticated caller, carried in a context variable for the duration of one request."""

from __future__ import annotations

import contextvars
from dataclasses import dataclass


class NotAuthenticated(RuntimeError):
    """A handler ran without a verified principal. This is a bug, and it fails closed."""


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]
    team: str | None  # None means "no team": the caller can see no team-owned data
    token_id: str
    issuer: str


_current: contextvars.ContextVar[Principal | None] = contextvars.ContextVar(
    "hardened_mcp_principal", default=None
)


def set_principal(principal: Principal) -> contextvars.Token:
    return _current.set(principal)


def reset_principal(token: contextvars.Token) -> None:
    _current.reset(token)


def require_principal() -> Principal:
    principal = _current.get()
    if principal is None:
        raise NotAuthenticated("no authenticated principal in this context")
    return principal
