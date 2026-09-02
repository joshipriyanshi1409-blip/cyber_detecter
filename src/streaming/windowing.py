"""
Bounded sliding-window primitives for incremental traffic analysis.

This module deliberately depends only on the standard library. A flow is
assigned to a window using its bidirectional_first_seen_ms timestamp (with
common first_seen_ms/timestamp fallbacks). The active window is a deque, so
expired flows are removed from the left and memory stays bounded by the
configured observation horizon.

The classes here do not make detection decisions. They provide deterministic
window snapshots and source-churn evidence for detectors/features.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple


def flow_timestamp_ms(flow: Any) -> Optional[int]:
    """Return the best available traffic timestamp in milliseconds."""
    for name in (
        "bidirectional_first_seen_ms",
        "first_seen_ms",
        "timestamp_ms",
        "timestamp",
    ):
        value = getattr(flow, name, None)
        if value is None:
            continue
        try:
            value = float(value)
        except (TypeError, ValueError):
            continue
        # A plain timestamp is normally seconds; *_ms fields are milliseconds.
        if name == "timestamp" and abs(value) < 10_000_000_000:
            value *= 1000.0
        return int(value)
    return None


@dataclass(frozen=True)
class WindowSnapshot:
    window_id: int
    start_ms: int
    end_ms: int
    flows: Tuple[Any, ...]
    source_ips: frozenset
    expired_count: int

    @property
    def duration_ms(self) -> int:
        return max(0, self.end_ms - self.start_ms)

    @property
    def source_count(self) -> int:
        return len(self.source_ips)


class SlidingWindow:
    """A bounded time-based window of flows.

    The window is event-time based, not wall-clock based. This makes replayed
    PCAPs deterministic and prevents processing speed from changing evidence.
    Flows with missing timestamps are retained separately and are not allowed
    to distort window boundaries.
    """

    def __init__(self, window_seconds: float = 10.0, slide_seconds: float = 1.0, max_untimestamped: int = 10000):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if slide_seconds <= 0:
            raise ValueError("slide_seconds must be positive")
        if slide_seconds > window_seconds:
            raise ValueError("slide_seconds cannot exceed window_seconds")

        if max_untimestamped <= 0:
            raise ValueError("max_untimestamped must be positive")
        self.window_ms = int(round(window_seconds * 1000))
        self.slide_ms = int(round(slide_seconds * 1000))
        self._flows: Deque[Tuple[int, int, Any]] = deque()
        self._untimestamped: Deque[Tuple[int, Any]] = deque()
        self.max_untimestamped = max_untimestamped
        self._next_window_id = 0
        self._last_emit_ms: Optional[int] = None
        self._expired_total = 0
        self._sequence = 0

    def add(self, flow: Any, timestamp_ms: Optional[int] = None) -> List[WindowSnapshot]:
        """Add one flow and return snapshots due after this event."""
        ts = flow_timestamp_ms(flow) if timestamp_ms is None else int(timestamp_ms)
        if ts is None:
            self._sequence += 1
            self._untimestamped.append((self._sequence, flow))
            while len(self._untimestamped) > self.max_untimestamped:
                self._untimestamped.popleft()
            return []

        self._sequence += 1
        self._flows.append((ts, self._sequence, flow))
        return self._advance(ts)

    def add_many(self, flows: Iterable[Any]) -> List[WindowSnapshot]:
        """Add flows in event order and return all snapshots due."""
        snapshots: List[WindowSnapshot] = []
        for flow in flows:
            snapshots.extend(self.add(flow))
        return snapshots

    def snapshot(self, end_ms: Optional[int] = None) -> WindowSnapshot:
        """Return the current bounded event-time snapshot."""
        if end_ms is None:
            if not self._flows:
                raise ValueError("cannot snapshot an empty timestamped window")
            end_ms = self._flows[-1][0]
        self._expire(int(end_ms))
        start_ms = int(end_ms) - self.window_ms
        active = tuple(item[2] for item in self._flows)
        sources = frozenset(
            getattr(flow, "source_ip", None)
            for flow in active
            if getattr(flow, "source_ip", None) is not None
        )
        snap = WindowSnapshot(
            window_id=self._next_window_id,
            start_ms=start_ms,
            end_ms=int(end_ms),
            flows=active,
            source_ips=sources,
            expired_count=self._expired_total,
        )
        return snap

    def flush(self) -> Optional[WindowSnapshot]:
        """Emit the current window once, useful at end-of-stream."""
        if not self._flows:
            return None
        end_ms = self._flows[-1][0]
        self._expire(end_ms)
        snap = self.snapshot(end_ms)
        self._next_window_id += 1
        self._last_emit_ms = end_ms
        return snap

    def active_flows(self) -> Tuple[Any, ...]:
        return tuple(item[2] for item in self._flows)

    def size(self) -> int:
        return len(self._flows)

    @property
    def untimestamped_count(self) -> int:
        return len(self._untimestamped)

    @property
    def expired_total(self) -> int:
        return self._expired_total

    def _advance(self, event_ms: int) -> List[WindowSnapshot]:
        self._expire(event_ms)
        if self._last_emit_ms is None:
            self._last_emit_ms = event_ms
            return []

        due: List[WindowSnapshot] = []
        while event_ms - self._last_emit_ms >= self.slide_ms:
            end_ms = self._last_emit_ms + self.slide_ms
            # Don't emit a future-looking window; its end must be <= event time.
            if end_ms > event_ms:
                break
            snap = self.snapshot(end_ms)
            due.append(snap)
            self._next_window_id += 1
            self._last_emit_ms = end_ms
        return due

    def _expire(self, end_ms: int) -> None:
        cutoff = end_ms - self.window_ms
        while self._flows and self._flows[0][0] < cutoff:
            self._flows.popleft()
            self._expired_total += 1


class WindowAggregator:
    """Maintains a SlidingWindow and derives source churn between windows."""

    def __init__(self, window_seconds: float = 10.0, slide_seconds: float = 1.0, max_untimestamped: int = 10000):
        self.window = SlidingWindow(window_seconds, slide_seconds)
        self.previous_sources: Optional[frozenset] = None

    def add(self, flow: Any) -> List[Dict[str, Any]]:
        return [self._decorate(s) for s in self.window.add(flow)]

    def add_many(self, flows: Iterable[Any]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for flow in flows:
            results.extend(self.add(flow))
        return results

    def flush(self) -> Optional[Dict[str, Any]]:
        snap = self.window.flush()
        return self._decorate(snap) if snap else None

    def _decorate(self, snapshot: WindowSnapshot) -> Dict[str, Any]:
        current = snapshot.source_ips
        if self.previous_sources is None:
            churn = None
            churn_reason = "no_previous_window"
        else:
            union = self.previous_sources | current
            churn = (
                len(self.previous_sources ^ current) / len(union)
                if union else 0.0
            )
            churn_reason = None

        result = {
            "window_id": snapshot.window_id,
            "window_start_ms": snapshot.start_ms,
            "window_end_ms": snapshot.end_ms,
            "window_duration_ms": snapshot.duration_ms,
            "flows": snapshot.flows,
            "source_ips": current,
            "source_count": snapshot.source_count,
            "source_churn": churn,
            "source_churn_reason": churn_reason,
            "expired_count": snapshot.expired_count,
        }
        self.previous_sources = current
        return result
