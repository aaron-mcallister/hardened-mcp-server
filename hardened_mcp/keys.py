"""Signing-key sources.

The only network request this server ever makes is the optional fetch of the authorization server's JWKS,
from a URL fixed by the operator. It is not influenced by the token: `jku`, `x5u`, `jwk` and `x5c` headers
are never consulted (the verifier rejects tokens that carry them). The fetch is https-only, does not follow
redirects, is size-capped and time-boxed, and an unknown `kid` can trigger at most one refresh per interval,
so a stream of junk tokens cannot turn this server into a request cannon aimed at the identity provider.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol

import anyio
from jwt import PyJWK

from .config import LOOPBACK_HOSTS


class KeyFetchError(RuntimeError):
    pass


class KeySource(Protocol):
    async def get_key(self, kid: str, alg: str) -> Any | None: ...


def jwk_to_key(jwk: dict[str, Any], alg: str) -> Any | None:
    """Return a verification key only if the JWK is a signing key suitable for `alg`."""
    kty = jwk.get("kty")
    if alg.startswith(("RS", "PS")) and kty != "RSA":
        return None
    if alg.startswith("ES") and kty != "EC":
        return None
    if jwk.get("use") not in (None, "sig"):
        return None
    if "alg" in jwk and jwk["alg"] != alg:
        return None
    ops = jwk.get("key_ops")
    if ops is not None and "verify" not in ops:
        return None
    try:
        return PyJWK.from_dict(jwk, algorithm=alg).key
    except Exception:
        return None


def _index(jwks: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise KeyFetchError("JWKS is not a key set")
    out: dict[str, dict[str, Any]] = {}
    for jwk in jwks["keys"][:64]:
        if isinstance(jwk, dict) and isinstance(jwk.get("kid"), str):
            out[jwk["kid"]] = jwk
    return out


class StaticKeySource:
    def __init__(self, jwks: dict[str, Any]) -> None:
        self._keys = _index(jwks)

    async def get_key(self, kid: str, alg: str) -> Any | None:
        jwk = self._keys.get(kid)
        return jwk_to_key(jwk, alg) if jwk else None


class FileKeySource:
    """Reads a JWKS file and picks up changes (key rotation) by modification time."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._mtime = -1.0
        self._keys: dict[str, dict[str, Any]] = {}

    def _reload(self) -> None:
        mtime = os.stat(self._path).st_mtime
        if mtime != self._mtime:
            with open(self._path, encoding="utf-8") as handle:
                self._keys = _index(json.load(handle))
            self._mtime = mtime

    async def get_key(self, kid: str, alg: str) -> Any | None:
        try:
            self._reload()
        except (OSError, ValueError, KeyFetchError):
            return None
        jwk = self._keys.get(kid)
        return jwk_to_key(jwk, alg) if jwk else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # refuse every redirect
        return None


def fetch_https(url: str, *, timeout: float = 3.0, max_bytes: int = 65536) -> bytes:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS):
        raise KeyFetchError("JWKS URL must be https")
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310 - scheme checked above
    try:
        with opener.open(request, timeout=timeout) as response:  # noqa: S310
            if response.status != 200:
                raise KeyFetchError(f"JWKS endpoint returned {response.status}")
            data = response.read(max_bytes + 1)
    except OSError as exc:
        raise KeyFetchError("JWKS fetch failed") from exc
    if len(data) > max_bytes:
        raise KeyFetchError("JWKS response too large")
    return data


class HttpsKeySource:
    def __init__(
        self,
        url: str,
        *,
        fetch: Callable[[str], bytes] = fetch_https,
        ttl: float = 300.0,
        min_refresh_interval: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS):
            raise ValueError("JWKS URL must be https")
        self._url = url
        self._fetch = fetch
        self._ttl = ttl
        self._min_interval = min_refresh_interval
        self._clock = clock
        self._keys: dict[str, dict[str, Any]] = {}
        self._loaded_at: float | None = None
        self._last_attempt: float | None = None
        self._lock = asyncio.Lock()
        self.fetch_count = 0

    async def _refresh(self) -> None:
        self._last_attempt = self._clock()
        self.fetch_count += 1
        try:
            raw = await anyio.to_thread.run_sync(self._fetch, self._url)
            self._keys = _index(json.loads(raw))
            self._loaded_at = self._clock()
        except (KeyFetchError, ValueError):
            pass  # keep serving the keys we already have; the interval limiter prevents hammering

    async def get_key(self, kid: str, alg: str) -> Any | None:
        async with self._lock:
            now = self._clock()
            expired = self._loaded_at is None or now - self._loaded_at > self._ttl
            can_retry = self._last_attempt is None or now - self._last_attempt >= self._min_interval
            if (expired or kid not in self._keys) and can_retry:
                await self._refresh()
            jwk = self._keys.get(kid)
        return jwk_to_key(jwk, alg) if jwk else None
