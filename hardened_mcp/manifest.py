"""The tool manifest, pinned.

A malicious or compromised server can change a tool's description after a user has approved it (a "rug
pull"), or smuggle instructions into a description (tool poisoning). The server-side defence is to make
descriptions static and reviewed: the manifest below is hashed, the hash is committed in `manifest.lock.json`,
and a test fails if anything changes without a deliberate `--update`. Clients that want the same protection
can pin the hash on their side.

Only stable facts are hashed (name, description, annotations, and each input's name, type, constraints and
whether it is required) so that a library upgrade that merely re-titles a schema field does not churn
the lock.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any

from .audit import AuditLog
from .authz import PolicyRegistry
from .data import FindingStore
from .server import _run_sync, build_server

LOCK_PATH = pathlib.Path(__file__).resolve().parent.parent / "manifest.lock.json"
_KEEP = {
    "type",
    "enum",
    "pattern",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "default",
    "anyOf",
    "items",
}


def _normalise(node: Any) -> Any:
    if isinstance(node, dict):
        return {
            k: _normalise(v)
            for k, v in sorted(node.items())
            if k == "properties" or k in _KEEP or k == "required"
        }
    if isinstance(node, list):
        return [_normalise(v) for v in node]
    return node


def _schema(schema: dict[str, Any]) -> dict[str, Any]:
    props = {name: _normalise(spec) for name, spec in sorted(schema.get("properties", {}).items())}
    return {"properties": props, "required": sorted(schema.get("required", []))}


def build_manifest() -> list[dict[str, Any]]:
    server = build_server(FindingStore([]), PolicyRegistry(), AuditLog(lambda _line: None))
    tools = _run_sync(server.list_tools())
    out = []
    for tool in sorted(tools, key=lambda t: t.name):
        data = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
        out.append(
            {
                "name": data["name"],
                "description": data.get("description", ""),
                "annotations": data.get("annotations", {}),
                "input": _schema(data.get("inputSchema", {})),
            }
        )
    return out


def manifest_hash(manifest: list[dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check or update the pinned tool manifest.")
    parser.add_argument(
        "--update", action="store_true", help="rewrite manifest.lock.json (a deliberate change)"
    )
    args = parser.parse_args(argv)
    manifest = build_manifest()
    current = {"sha256": manifest_hash(manifest), "tools": manifest}
    if args.update:
        LOCK_PATH.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("updated", LOCK_PATH, current["sha256"])
        return 0
    locked = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    if locked != current:
        print(
            "tool manifest differs from manifest.lock.json; review the change, then run with --update",
            file=sys.stderr,
        )
        return 1
    print("manifest ok", current["sha256"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
