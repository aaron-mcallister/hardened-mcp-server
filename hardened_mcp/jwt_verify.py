"""Access-token validation (this server is an OAuth 2.1 resource server and never issues tokens).

What is checked, in order, and why:

1. size and shape, before any parsing work;
2. the header: `alg` must be on the operator's asymmetric allow-list (never taken from the token as a
   suggestion), `kid` must be present, and `jku`/`x5u`/`jwk`/`x5c` are refused outright;
3. the signature, against a key chosen by `kid` AND suitable for that algorithm;
4. `iss` (exact match), `aud` (must contain this server's canonical URI: RFC 8707 audience binding, the
   control against token passthrough and confused-deputy reuse), `exp`, `iat`, `nbf`, `sub`, `jti`;
5. a maximum token lifetime, so a long-lived token is not accepted even if the issuer mints one;
6. scopes and the team claim are parsed defensively. A missing or malformed team means "no team".

Failures raise `AuthError` with a stable reason code for the audit log. The caller sees only a generic
`invalid_token`: the precise reason is not an oracle for an attacker.
"""

from __future__ import annotations

import re
from typing import Any

import jwt

from .config import Settings
from .keys import KeySource
from .principal import Principal

MAX_TOKEN_CHARS = 8192
_FORBIDDEN_HEADERS = ("jku", "x5u", "jwk", "x5c")
_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]{1,128}$")  # RFC 6749 section 3.3
_TEAM = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_KID = re.compile(r"^[A-Za-z0-9_.:+/=-]{1,128}$")


class AuthError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _parse_scopes(claims: dict[str, Any]) -> frozenset[str]:
    raw: Any = claims.get("scope")
    items: list[Any]
    if isinstance(raw, str):
        items = raw.split()
    elif isinstance(claims.get("scp"), list):
        items = claims["scp"]
    else:
        items = []
    return frozenset(s for s in items[:64] if isinstance(s, str) and _SCOPE_TOKEN.match(s))


class TokenVerifier:
    def __init__(self, settings: Settings, keys: KeySource) -> None:
        self._s = settings
        self._keys = keys

    async def verify(self, token: str) -> Principal:
        if not token or len(token) > MAX_TOKEN_CHARS or token.count(".") != 2:
            raise AuthError("malformed")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthError("malformed") from exc
        if any(name in header for name in _FORBIDDEN_HEADERS):
            raise AuthError("forbidden_header")
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self._s.algorithms:
            raise AuthError("alg_not_allowed")
        kid = header.get("kid")
        if not isinstance(kid, str) or not _KID.match(kid):
            raise AuthError("kid_missing")

        key = await self._keys.get_key(kid, alg)
        if key is None:
            raise AuthError("key_not_found")

        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                audience=self._s.expected_audience,
                issuer=self._s.issuer,
                leeway=self._s.clock_skew_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "jti"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise AuthError("not_yet_valid") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthError("bad_audience") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthError("bad_issuer") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise AuthError("missing_claim") from exc
        except jwt.InvalidSignatureError as exc:
            raise AuthError("bad_signature") from exc
        except jwt.InvalidAlgorithmError as exc:
            raise AuthError("alg_not_allowed") from exc
        except jwt.InvalidKeyError as exc:
            raise AuthError("bad_key_type") from exc
        except jwt.PyJWTError as exc:
            raise AuthError("invalid") from exc

        subject, jti = claims["sub"], claims["jti"]
        if not (
            isinstance(subject, str)
            and 0 < len(subject) <= 256
            and isinstance(jti, str)
            and 0 < len(jti) <= 128
        ):
            raise AuthError("bad_claim_type")
        if not (isinstance(claims["exp"], int | float) and isinstance(claims["iat"], int | float)):
            raise AuthError("bad_claim_type")
        if claims["exp"] - claims["iat"] > self._s.max_token_lifetime_seconds:
            raise AuthError("lifetime_too_long")

        team = claims.get(self._s.team_claim)
        return Principal(
            subject=subject,
            scopes=_parse_scopes(claims),
            team=team if isinstance(team, str) and _TEAM.match(team) else None,
            token_id=jti,
            issuer=claims["iss"],
        )
