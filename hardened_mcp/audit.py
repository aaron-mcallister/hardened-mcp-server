"""Structured, tamper-evident audit log.

One JSON object per line. Every authentication result, authorization decision, rate-limit hit and tool call
is recorded, including the denials. Records never contain credentials or argument values: only the names and
sizes of arguments. Each record carries the hash of the previous one, so edits, deletions and reordering are
detectable by `verify_chain`.

Limit, stated plainly: a hash chain is tamper-EVIDENT, not tamper-proof. Someone who can rewrite the whole
file can recompute the chain. For real assurance ship the lines to an append-only store as they are written
and anchor the latest hash somewhere the writer cannot reach.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

GENESIS = "0" * 64
FORBIDDEN_KEYS = frozenset(
    {"token", "access_token", "authorization", "password", "secret", "cookie", "bearer"}
)


class AuditError(RuntimeError):
    pass


def _digest(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self, sink: Callable[[str], None], clock: Callable[[], datetime] | None = None) -> None:
        self._sink = sink
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._prev = GENESIS
        self._seq = 0

    @classmethod
    def to_file(cls, path: str) -> AuditLog:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        handle = os.fdopen(fd, "a", encoding="utf-8")

        def write(line: str) -> None:
            handle.write(line + "\n")
            handle.flush()

        return cls(write)

    @classmethod
    def to_stdout(cls) -> AuditLog:
        import sys

        def write(line: str) -> None:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

        return cls(write)

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        for key in fields:
            if key.lower() in FORBIDDEN_KEYS:
                raise AuditError(f"refusing to log a field named {key!r}")
        with self._lock:
            self._seq += 1
            record: dict[str, Any] = {
                "ts": self._clock().isoformat(timespec="milliseconds"),
                "seq": self._seq,
                "event": event,
                **{k: v for k, v in fields.items() if v is not None},
                "prev": self._prev,
            }
            record["hash"] = _digest(record)
            self._prev = record["hash"]
            self._sink(json.dumps(record, sort_keys=True, separators=(",", ":")))
            return record


def verify_chain(lines: Iterable[str]) -> tuple[bool, int | None]:
    """Return (True, None) for an intact chain, else (False, index of the first bad record)."""
    prev = GENESIS
    expected_seq = 1
    for index, line in enumerate(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return False, index
        if (
            record.get("prev") != prev
            or record.get("seq") != expected_seq
            or record.get("hash") != _digest(record)
        ):
            return False, index
        prev = record["hash"]
        expected_seq += 1
    return True, None


def arg_shape(arguments: dict[str, Any] | None) -> dict[str, int]:
    """Describe arguments without recording them: name -> length of the serialised value."""
    if not isinstance(arguments, dict):
        return {}
    return {str(k)[:64]: len(json.dumps(v, default=str)) for k, v in list(arguments.items())[:32]}
