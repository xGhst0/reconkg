"""Per-principal token bucket for the evidence ingress.

RC-15: payloads were bounded and retention was bounded; request *rate* was
not. A scanner credential in a loop could fill the graph, the event log and
every analyst's queue faster than anyone could read them.

Per-principal rather than per-IP on purpose: a lab has a handful of scanner
boxes behind one address, and rate-limiting them collectively would punish
the honest ones for the noisy one. The principal is already authenticated by
the time we get here, so it is the more precise key.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass
class Bucket:
    capacity: float
    refill_per_second: float
    tokens: float = field(init=False)
    updated: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        self.tokens = self.capacity

    def take(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity,
                          self.tokens + elapsed * self.refill_per_second)
        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True

    def retry_after(self, cost: float = 1.0) -> float:
        if self.refill_per_second <= 0:
            return float("inf")
        deficit = max(0.0, cost - self.tokens)
        return round(deficit / self.refill_per_second, 2)


class RateLimiter:
    """Token buckets keyed by principal name."""

    def __init__(self, capacity: float = 60.0,
                 refill_per_second: float = 2.0,
                 max_principals: int = 10_000) -> None:
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.max_principals = max_principals
        self._buckets: dict[str, Bucket] = {}

    def check(self, principal: str, cost: float = 1.0) -> tuple[bool, float]:
        """Returns (allowed, retry_after_seconds)."""
        bucket = self._buckets.get(principal)
        if bucket is None:
            if len(self._buckets) >= self.max_principals:
                self._evict()
            bucket = self._buckets[principal] = Bucket(
                self.capacity, self.refill_per_second)
        if bucket.take(cost):
            return True, 0.0
        wait = bucket.retry_after(cost)
        log.warning("rate limit hit by %s; retry in %.2fs", principal, wait)
        return False, wait

    def _evict(self) -> None:
        """Drop the least recently used half.

        The bucket table is itself unbounded state keyed by an attacker-
        influenced value, which is the mistake RC-03 was about; a limiter
        that leaks memory is not a defence.
        """
        ordered = sorted(self._buckets.items(), key=lambda kv: kv[1].updated)
        for name, _ in ordered[: len(ordered) // 2 or 1]:
            self._buckets.pop(name, None)

    def reset(self, principal: str | None = None) -> None:
        if principal is None:
            self._buckets.clear()
        else:
            self._buckets.pop(principal, None)
