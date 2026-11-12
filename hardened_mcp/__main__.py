"""Run the server: `python -m hardened_mcp` (configuration from HMCP_* environment variables)."""

from __future__ import annotations

import os
import sys

import uvicorn

from .config import ConfigError, Settings
from .server import build_app


def main() -> int:
    try:
        settings = Settings.from_env(os.environ)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    app = build_app(settings)
    # Loopback by default. Put a TLS-terminating proxy in front for anything else; see docs/DEPLOYMENT.md.
    uvicorn.run(
        app,
        host=settings.bind_host,
        port=settings.bind_port,
        server_header=False,
        proxy_headers=False,
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
