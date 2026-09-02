"""
CTI Rate Limiter
Bounds the rate of outbound CTI lookups so attacker-controlled traffic
(e.g. a flood of distinct spoofed source IPs, each a "new" indicator that
bypasses the enrichment cache) cannot force unlimited external lookups.

Master repair prompt, Section 27:
    "Rate-limit CTI lookups. Cache results. Prevent attacker-controlled
    traffic from creating unlimited external lookups."

This is deliberately a plain sliding-window counter (stdlib `time` only,
no extra dependencies) rather than anything fancier -- the goal here is a
hard, predictable cap, not smart throttling.
"""

import time
import logging
from collections import deque
from typing import Optional

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Raised when a caller asks the limiter to raise instead of returning a bool."""
    pass


class CTIRateLimiter:
    """
    Sliding-window rate limiter for CTI lookups.

    `max_requests` lookups are allowed within any `window_seconds`-wide
    rolling window. This is process-local state (an in-memory deque of
    timestamps) -- correct for a single enrichment process, not a
    distributed guarantee across multiple workers.

    A limiter with max_requests <= 0 is invalid (that's "always block",
    which almost certainly indicates a misconfiguration rather than an
    intentional choice -- disable CTI entirely via provider config
    instead of a zero-request limiter).
    """

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0):
        if max_requests <= 0:
            raise ValueError("max_requests must be positive; to disable CTI, remove/disable providers instead")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque = deque()
        # Explicit, observable counters -- never silently swallow a
        # rate-limit decision (Section 35: system health must be real).
        self.allowed_count = 0
        self.rejected_count = 0

    def _evict_expired(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()

    def allow(self, now: Optional[float] = None) -> bool:
        """
        Check (and, if allowed, consume) one slot in the current window.

        Returns True if the lookup may proceed, False if it must be
        skipped because the rate limit is currently exceeded. Does NOT
        raise -- callers that want a hard failure should check the
        return value and raise RateLimitExceeded themselves, since a CTI
        rate-limit hit is an expected, not exceptional, condition in an
        adversarial traffic environment.
        """
        now = time.time() if now is None else now
        self._evict_expired(now)

        if len(self._timestamps) >= self.max_requests:
            self.rejected_count += 1
            return False

        self._timestamps.append(now)
        self.allowed_count += 1
        return True

    def current_load(self, now: Optional[float] = None) -> int:
        """Number of lookups counted in the current window (for health/status reporting)."""
        now = time.time() if now is None else now
        self._evict_expired(now)
        return len(self._timestamps)

    def get_status(self) -> dict:
        """CTI health snapshot -- see Section 35 (system health must be real, never hidden)."""
        return {
            "max_requests": self.max_requests,
            "window_seconds": self.window_seconds,
            "current_load": self.current_load(),
            "allowed_count": self.allowed_count,
            "rejected_count": self.rejected_count,
        }
