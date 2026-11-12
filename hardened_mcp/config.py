"""Configuration: strict, explicit, and fail-closed.

Everything is read from environment variables (prefix HMCP_). A configuration that would weaken a control
(plain HTTP off loopback, a symmetric or "none" algorithm, no audience) is rejected at start-up rather than
accepted with a warning.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

# Asymmetric algorithms only. HS* is excluded on purpose: a symmetric algorithm lets anyone who can read
# the verification key (it is public) mint tokens. "none" is never acceptable.
ALLOWED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
)
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

SCOPE_READ = "findings:read"
SCOPE_WRITE = "findings:write"


class ConfigError(ValueError):
    """The configuration is unsafe or malformed."""


def _check_url(name: str, url: str, *, allow_path: bool = True) -> tuple[str, str, str]:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ConfigError(f"{name} must be an absolute http(s) URL")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
        raise ConfigError(f"{name} must use https (plain http is allowed only for loopback development)")
    if parts.fragment or parts.query:
        raise ConfigError(f"{name} must not contain a query or fragment")
    if parts.username or parts.password:
        raise ConfigError(f"{name} must not contain credentials")
    if not allow_path and parts.path not in ("", "/"):
        raise ConfigError(f"{name} must not have a path")
    return parts.scheme, parts.netloc, parts.path


@dataclass(frozen=True)
class Settings:
    resource_url: str  # canonical URI of this server; also the expected token audience
    issuer: str  # authorization server issuer, compared by exact string match
    jwks_url: str | None = None
    jwks_file: str | None = None
    audience: str | None = None  # defaults to resource_url
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    clock_skew_seconds: int = 30
    max_token_lifetime_seconds: int = 3600
    max_body_bytes: int = 65536
    rate_per_minute: int = 60
    team_claim: str = "team"
    allowed_hosts: tuple[str, ...] = ()
    allowed_origins: tuple[str, ...] = ()
    audit_path: str | None = None
    bind_host: str = "127.0.0.1"
    bind_port: int = 8080

    # ---- derived -------------------------------------------------------------------------------------
    @property
    def expected_audience(self) -> str:
        return self.audience or self.resource_url

    @property
    def mcp_path(self) -> str:
        return urlsplit(self.resource_url).path or "/"

    @property
    def metadata_path(self) -> str:
        """RFC 9728 section 3.1: the well-known segment goes between the host and the resource path."""
        path = self.mcp_path.rstrip("/")
        return "/.well-known/oauth-protected-resource" + path

    @property
    def metadata_url(self) -> str:
        parts = urlsplit(self.resource_url)
        return f"{parts.scheme}://{parts.netloc}{self.metadata_path}"

    @property
    def effective_allowed_hosts(self) -> tuple[str, ...]:
        return self.allowed_hosts or (urlsplit(self.resource_url).netloc,)

    # ---- validation ----------------------------------------------------------------------------------
    def validate(self) -> Settings:
        _, _, path = _check_url("resource_url", self.resource_url)
        if len(path) > 1 and path.endswith("/"):
            raise ConfigError("resource_url must not end with a slash (use the canonical form)")
        _check_url("issuer", self.issuer)
        if self.audience:
            _check_url("audience", self.audience)
        if bool(self.jwks_url) == bool(self.jwks_file):
            raise ConfigError("set exactly one of jwks_url and jwks_file")
        if self.jwks_url:
            _check_url("jwks_url", self.jwks_url)
        if not self.algorithms:
            raise ConfigError("at least one signing algorithm must be allowed")
        bad = [a for a in self.algorithms if a not in ALLOWED_ALGORITHMS]
        if bad:
            raise ConfigError(f"algorithms not permitted: {', '.join(bad)} (asymmetric algorithms only)")
        if not 0 <= self.clock_skew_seconds <= 120:
            raise ConfigError("clock_skew_seconds must be between 0 and 120")
        if not 60 <= self.max_token_lifetime_seconds <= 86400:
            raise ConfigError("max_token_lifetime_seconds must be between 60 and 86400")
        if not 1024 <= self.max_body_bytes <= 1_048_576:
            raise ConfigError("max_body_bytes must be between 1 KiB and 1 MiB")
        if not 1 <= self.rate_per_minute <= 10_000:
            raise ConfigError("rate_per_minute must be between 1 and 10000")
        for host in self.allowed_hosts:
            if "*" in host:
                raise ConfigError("wildcards are not allowed in allowed_hosts")
        for origin in self.allowed_origins:
            if "*" in origin or not origin.startswith(("https://", "http://")):
                raise ConfigError("allowed_origins must be exact origins without wildcards")
        if not self.team_claim.isidentifier():
            raise ConfigError("team_claim must be a simple claim name")
        return self

    # ---- construction --------------------------------------------------------------------------------
    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Settings:
        def get(name: str, default: str | None = None) -> str | None:
            value = env.get("HMCP_" + name, default)
            return value if value not in ("", None) else default

        def req(name: str) -> str:
            value = get(name)
            if value is None:
                raise ConfigError(f"HMCP_{name} is required")
            return value

        def csv(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
            raw = get(name)
            return tuple(p.strip() for p in raw.split(",") if p.strip()) if raw else default

        def num(name: str, default: int) -> int:
            raw = get(name)
            try:
                return int(raw) if raw is not None else default
            except ValueError as exc:
                raise ConfigError(f"HMCP_{name} must be an integer") from exc

        return cls(
            resource_url=req("RESOURCE_URL"),
            issuer=req("ISSUER"),
            jwks_url=get("JWKS_URL"),
            jwks_file=get("JWKS_FILE"),
            audience=get("AUDIENCE"),
            algorithms=csv("ALGORITHMS", ("RS256", "ES256")),
            clock_skew_seconds=num("CLOCK_SKEW_SECONDS", 30),
            max_token_lifetime_seconds=num("MAX_TOKEN_LIFETIME_SECONDS", 3600),
            max_body_bytes=num("MAX_BODY_BYTES", 65536),
            rate_per_minute=num("RATE_PER_MINUTE", 60),
            team_claim=get("TEAM_CLAIM", "team") or "team",
            allowed_hosts=csv("ALLOWED_HOSTS", ()),
            allowed_origins=csv("ALLOWED_ORIGINS", ()),
            audit_path=get("AUDIT_PATH"),
            bind_host=get("BIND_HOST", "127.0.0.1") or "127.0.0.1",
            bind_port=num("BIND_PORT", 8080),
        ).validate()
