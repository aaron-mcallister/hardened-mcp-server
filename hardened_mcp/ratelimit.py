"""Per-principal token bucket with bounded memory."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self,
        per_minute: int,
        *,
        burst: int | None = None,
        max_keys: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._rate = per_minute / 60.0
        self._capacity = float(burst if burst is not None else per_minute)
        self._max_keys = max_keys
        self._clock = clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()  # key -> (tokens, last)
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        """Return (allowed, seconds to wait before retrying)."""
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.pop(key, (self._capacity, now))
            tokens = min(self._capacity, tokens + (now - last) * self._rate)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > self._max_keys:  # evict the least recently used key
                self._buckets.popitem(last=False)
            wait = 0.0 if allowed else (1.0 - tokens) / self._rate
            return allowed, wait

    def __len__(self) -> int:
        return len(self._buckets)
