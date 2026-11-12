"""The HTTP guard: everything that must be decided before a request reaches the MCP implementation.

Order of checks for the MCP endpoint, cheapest and least informative first:

  Host -> Origin -> method -> credentials -> token validity -> rate limit -> content type -> body size ->
  JSON shape -> header/body consistency -> authorization -> (set principal) -> MCP implementation

Authorization is decided from the request BODY. The `Mcp-Method` and `Mcp-Name` routing headers are
untrusted hints: if they disagree with the body the request is refused, and they are never used to decide
anything. The access token is read only from the Authorization header, never from the query string.

This is a plain ASGI class rather than framework middleware so that the order above is explicit and the
body can be replayed to the inner application exactly as received.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from collections import defaultdict
from typing import Any

from .audit import AuditLog, arg_shape
from .authz import PolicyRegistry, decide
from .challenge import metadata_json, www_authenticate
from .config import Settings
from .jwt_verify import AuthError, TokenVerifier
from .principal import Principal, reset_principal, set_principal
from .ratelimit import RateLimiter

_B64TOKEN = re.compile(r"^[A-Za-z0-9\-._~+/]+=*$")
_NO_STORE = [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")]

# JSON-RPC error codes (and the SDK's header-mismatch code for the 2026-07-28 wire format)
PARSE_ERROR, INVALID_REQUEST, HEADER_MISMATCH = -32700, -32600, -32020


class _TooLarge(Exception):
    pass


class _Disconnected(Exception):
    pass


def _headers(scope: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for name, value in scope.get("headers", []):
        out[name.decode("latin-1").lower()].append(value.decode("latin-1"))
    return out


class McpGuard:
    def __init__(
        self,
        inner: Any,
        settings: Settings,
        verifier: TokenVerifier,
        registry: PolicyRegistry,
        audit: AuditLog,
        limiter: RateLimiter,
    ) -> None:
        self.inner = inner
        self.s = settings
        self.verifier = verifier
        self.registry = registry
        self.audit = audit
        self.limiter = limiter

    # ---- ASGI entry ----------------------------------------------------------------------------------
    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self.inner(scope, receive, send)
            return
        if scope["type"] != "http":
            return  # websockets and anything else are not supported; the connection is dropped
        path = scope.get("path", "")
        if path == self.s.metadata_path:
            await self._metadata(scope, send)
        elif path == self.s.mcp_path:
            await self._mcp(scope, receive, send)
        else:
            await self._json(send, 404, {"error": "not_found"})

    # ---- helpers -------------------------------------------------------------------------------------
    async def _json(
        self, send: Any, status: int, body: Any, extra: list[tuple[bytes, bytes]] | None = None
    ) -> None:
        raw = json.dumps(body).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(raw)).encode()),
            *_NO_STORE,
        ]
        await send({"type": "http.response.start", "status": status, "headers": headers + (extra or [])})
        await send({"type": "http.response.body", "body": raw})

    async def _rpc_error(self, send: Any, status: int, code: int, message: str) -> None:
        await self._json(
            send, status, {"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}}
        )

    async def _challenge(self, send: Any, status: int, header: str, body: dict[str, Any]) -> None:
        await self._json(send, status, body, [(b"www-authenticate", header.encode())])

    async def _metadata(self, scope: dict[str, Any], send: Any) -> None:
        if scope["method"] not in ("GET", "HEAD"):
            await self._json(send, 405, {"error": "method_not_allowed"}, [(b"allow", b"GET, HEAD")])
            return
        raw = metadata_json(self.s)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(raw)).encode()),
                    (b"cache-control", b"public, max-age=300"),
                    (b"x-content-type-options", b"nosniff"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"" if scope["method"] == "HEAD" else raw})

    # ---- the MCP endpoint ----------------------------------------------------------------------------
    async def _mcp(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        request_id = uuid.uuid4().hex
        client_ip = (scope.get("client") or ("unknown", 0))[0]
        hdrs = _headers(scope)
        base = {"request_id": request_id, "client_ip": client_ip, "http_method": scope["method"]}

        # 1. Host and Origin (DNS-rebinding defence). Done first, before any authentication state is revealed.
        host = (hdrs.get("host") or [""])[0].lower()
        if host not in {h.lower() for h in self.s.effective_allowed_hosts}:
            self.audit.emit("request_rejected", reason="bad_host", **base)
            await self._json(send, 421, {"error": "misdirected_request"})
            return
        origin = hdrs.get("origin")
        if origin and not set(origin) <= set(self.s.allowed_origins):
            self.audit.emit("request_rejected", reason="bad_origin", **base)
            await self._json(send, 403, {"error": "forbidden_origin"})
            return

        # 2. Only POST carries MCP messages in this deployment (stateless; no server-initiated streams).
        if scope["method"] != "POST":
            self.audit.emit("request_rejected", reason="method_not_allowed", **base)
            await self._json(send, 405, {"error": "method_not_allowed"}, [(b"allow", b"POST")])
            return

        # 3. Credentials. Header only; a token in the query string is never read.
        auth = hdrs.get("authorization", [])
        if len(auth) > 1:
            self.audit.emit("authn", decision="deny", reason="multiple_authorization_headers", **base)
            await self._challenge(
                send, 400, www_authenticate(self.s, error="invalid_request"), {"error": "invalid_request"}
            )
            return
        scheme, _, credential = (auth[0] if auth else "").partition(" ")
        if scheme.lower() != "bearer":
            self.audit.emit(
                "authn", decision="deny", reason="no_credentials", token_present=bool(auth), **base
            )
            await self._challenge(send, 401, www_authenticate(self.s), {"error": "unauthorized"})
            return

        # 4. Token validity.
        principal: Principal | None = None
        try:
            if not _B64TOKEN.match(credential.strip()):
                raise AuthError("malformed")
            principal = await self.verifier.verify(credential.strip())
        except AuthError as exc:
            self.audit.emit("authn", decision="deny", reason=exc.reason, token_present=True, **base)
            await self._challenge(
                send,
                401,
                www_authenticate(self.s, error="invalid_token", description="The access token is invalid"),
                {"error": "invalid_token"},
            )
            return
        who = {"subject": principal.subject, "token_id": principal.token_id, "team": principal.team}

        # 5. Rate limit per principal. Counts denied requests too, so probing is not free.
        allowed, wait = self.limiter.allow(principal.subject)
        if not allowed:
            self.audit.emit("rate_limited", decision="deny", **who, **base)
            await self._json(
                send, 429, {"error": "rate_limited"}, [(b"retry-after", str(max(1, int(wait) + 1)).encode())]
            )
            return

        # 6. Content type and body.
        if not (hdrs.get("content-type") or [""])[0].lower().startswith("application/json"):
            self.audit.emit("request_rejected", reason="unsupported_media_type", **who, **base)
            await self._json(send, 415, {"error": "unsupported_media_type"})
            return
        declared = (hdrs.get("content-length") or [None])[0]
        if declared is not None and (not declared.isdigit() or int(declared) > self.s.max_body_bytes):
            self.audit.emit("request_rejected", reason="body_too_large", **who, **base)
            await self._json(send, 413, {"error": "payload_too_large"})
            return
        try:
            raw = await self._read_body(receive)
        except _TooLarge:
            self.audit.emit("request_rejected", reason="body_too_large", **who, **base)
            await self._json(send, 413, {"error": "payload_too_large"})
            return
        except _Disconnected:
            return
        try:
            message = json.loads(raw)
        except (ValueError, RecursionError):
            self.audit.emit("request_rejected", reason="invalid_json", **who, **base)
            await self._rpc_error(send, 400, PARSE_ERROR, "Parse error")
            return
        if (
            not isinstance(message, dict)
            or message.get("jsonrpc") != "2.0"
            or not isinstance(message.get("method"), str)
        ):
            self.audit.emit("request_rejected", reason="invalid_request_shape", **who, **base)
            await self._rpc_error(send, 400, INVALID_REQUEST, "Invalid request")
            return
        method: str = message["method"]
        params = message.get("params")
        arguments = params.get("arguments") if isinstance(params, dict) else None
        tool_name = params.get("name") if (method == "tools/call" and isinstance(params, dict)) else None
        if tool_name is not None and not isinstance(tool_name, str):
            self.audit.emit("request_rejected", reason="invalid_request_shape", **who, **base)
            await self._rpc_error(send, 400, INVALID_REQUEST, "Invalid request")
            return

        # 7. Routing headers must agree with the body. They never decide anything themselves.
        hdr_method = hdrs.get("mcp-method")
        hdr_name = hdrs.get("mcp-name")
        if (hdr_method and hdr_method != [method]) or (
            hdr_name and method == "tools/call" and hdr_name != [tool_name]
        ):
            self.audit.emit(
                "request_rejected", reason="header_body_mismatch", mcp_method=method, **who, **base
            )
            await self._rpc_error(send, 400, HEADER_MISMATCH, "Routing headers do not match the request body")
            return

        # 8. Authorization.
        decision = decide(method, tool_name, principal, self.registry)
        if not decision.allowed:
            self.audit.emit(
                "authz",
                decision="deny",
                reason=decision.reason,
                mcp_method=method,
                tool=tool_name if isinstance(tool_name, str) else None,
                **who,
                **base,
            )
            if decision.reason == "insufficient_scope":
                await self._challenge(
                    send,
                    403,
                    www_authenticate(
                        self.s,
                        error="insufficient_scope",
                        scope=decision.required_scopes,
                        description="Additional permission is required for this operation",
                    ),
                    {"error": "insufficient_scope"},
                )
            else:
                await self._json(send, 403, {"error": "forbidden"})
            return

        # 9. Allowed: record intent, run with the principal in context, record the outcome.
        self.audit.emit(
            "authz",
            decision="allow",
            reason=decision.reason,
            mcp_method=method,
            tool=tool_name,
            arg_shape=arg_shape(arguments) if tool_name else None,
            **who,
            **base,
        )
        status_box: dict[str, int] = {}
        started = time.monotonic()

        async def send_wrapper(event: dict[str, Any]) -> None:
            if event["type"] == "http.response.start":
                status_box["status"] = event["status"]
                names = {name for name, _ in event.get("headers", [])}
                extra = [h for h in _NO_STORE if h[0] not in names]
                event = {**event, "headers": [*event.get("headers", []), *extra]}
            await send(event)

        replayed = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return await receive()

        token = set_principal(principal)
        try:
            await self.inner(scope, replay_receive, send_wrapper)
        finally:
            reset_principal(token)
            self.audit.emit(
                "request_completed",
                mcp_method=method,
                tool=tool_name,
                status=status_box.get("status"),
                duration_ms=int((time.monotonic() - started) * 1000),
                **who,
                **base,
            )

    async def _read_body(self, receive: Any) -> bytes:
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                raise _Disconnected
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.s.max_body_bytes:
                raise _TooLarge
            chunks.append(chunk)
            if not message.get("more_body"):
                return b"".join(chunks)
