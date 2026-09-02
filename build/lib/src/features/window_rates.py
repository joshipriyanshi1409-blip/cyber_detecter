"""
Window-Based Rate Calculation
==============================
Dedicated, independently-tested functions for aggregate traffic rate
calculation (packets/sec, bytes/sec, flows/sec) over a shared observation
window.

This module exists specifically to fix a class of bug found during audit:
computing an aggregate rate as `total_packets / sum(flow.duration)` instead
of `total_packets / (window_end - window_start)`.

Those two denominators are NOT the same thing. If 100 flows each last
100ms but occur SIMULTANEOUSLY, the shared observation window is still
only ~100ms wide -- but summing each flow's own duration gives 10,000ms
(10 seconds), understating the true aggregate rate by up to 100x.

Worked example (this exact scenario is covered in test_window_rates.py):
    100 flows, each 100ms long, each carrying 1,000 packets, all
    simultaneous.
    - WRONG (sum of durations):  100,000 packets / 10.0s   =    10,000 pps
    - RIGHT (shared window):     100,000 packets / 0.1s    = 1,000,000 pps

None of the functions here fabricate zero traffic when timestamps are
missing or degenerate. See `calculate_window_rates` docstring for the
missing-vs-zero distinction (Rule 28).
"""

import logging
from typing import Any, Dict, Iterable, Optional, Tuple

logger = logging.getLogger(__name__)

# When a window's measured width is smaller than this, treat traffic as
# "effectively instantaneous" and clamp to this floor rather than dividing
# by (near) zero or fabricating an infinite rate. This is a documented
# prototype calibration choice, not a physical constant -- see Rule 11.
MIN_WINDOW_SECONDS = 0.001  # 1 millisecond


def compute_window_bounds(flows: Iterable[Any]) -> Tuple[Optional[int], Optional[int]]:
    """
    Derive the shared observation window (in milliseconds) spanned by a set
    of flows, from their own first_seen / last_seen timestamps.

    This is the traffic-time window -- when the packets were actually seen
    on the wire -- not a processing-time window. See Rule 4.

    Returns:
        (window_start_ms, window_end_ms), or (None, None) if no flow in the
        set has usable timestamp data. Callers must NOT treat (None, None)
        as a zero-width window -- it means the window is unknown, which is
        a different thing from a window of zero duration.
    """
    first_seen_values = [
        f.bidirectional_first_seen_ms for f in flows
        if getattr(f, "bidirectional_first_seen_ms", None) is not None
    ]
    last_seen_values = [
        f.bidirectional_last_seen_ms for f in flows
        if getattr(f, "bidirectional_last_seen_ms", None) is not None
    ]

    if not first_seen_values or not last_seen_values:
        return None, None

    window_start_ms = min(first_seen_values)
    window_end_ms = max(last_seen_values)

    if window_end_ms < window_start_ms:
        # Malformed input (end before start). Don't silently swap or drop --
        # surface it so the caller/logs can catch a real data bug upstream.
        logger.warning(
            "compute_window_bounds: window_end_ms (%s) < window_start_ms (%s); "
            "flow timestamps may be inconsistent", window_end_ms, window_start_ms
        )
        return None, None

    return window_start_ms, window_end_ms


def calculate_window_rates(
    total_packets: int,
    total_bytes: int,
    total_flows: int,
    window_start_ms: Optional[int],
    window_end_ms: Optional[int],
) -> Dict[str, Any]:
    """
    Calculate packets/sec, bytes/sec, and flows/sec over a shared
    observation window.

    Missing vs. zero (Rule 28): if the window bounds are unavailable
    (None), the rates are reported as None ("unavailable"), NOT 0.
    A caller that silently treats None as 0 risks concluding "no traffic"
    when the real situation is "we don't know the window width" -- these
    must stay distinguishable downstream (e.g. in alert evidence).

    Zero/tiny windows: if packets were observed but the window is
    narrower than MIN_WINDOW_SECONDS, the window is clamped to that floor
    rather than fabricating an infinite or undefined rate. `window_clamped`
    in the result indicates when this happened, so callers/alerts can be
    transparent about it rather than presenting an inflated rate as if it
    were an exact measurement.
    """
    if window_start_ms is None or window_end_ms is None:
        return {
            "packets_per_second": None,
            "bytes_per_second": None,
            "flows_per_second": None,
            "window_seconds": None,
            "window_clamped": False,
            "reason": "window_unavailable",
        }

    raw_window_seconds = (window_end_ms - window_start_ms) / 1000.0
    window_clamped = raw_window_seconds < MIN_WINDOW_SECONDS
    window_seconds = MIN_WINDOW_SECONDS if window_clamped else raw_window_seconds

    return {
        "packets_per_second": total_packets / window_seconds,
        "bytes_per_second": total_bytes / window_seconds,
        "flows_per_second": total_flows / window_seconds,
        "window_seconds": window_seconds,
        "window_clamped": window_clamped,
        "reason": None,
    }


def calculate_rates_for_flows(flows: Iterable[Any]) -> Dict[str, Any]:
    """
    Convenience wrapper: derive the window from the flows themselves, then
    calculate rates. This is what most detectors should call.
    """
    flows = list(flows)
    total_packets = sum(f.bidirectional_packets for f in flows)
    total_bytes = sum(f.bidirectional_bytes for f in flows)
    total_flows = len(flows)

    window_start_ms, window_end_ms = compute_window_bounds(flows)
    result = calculate_window_rates(
        total_packets, total_bytes, total_flows, window_start_ms, window_end_ms
    )
    result["total_packets"] = total_packets
    result["total_bytes"] = total_bytes
    result["total_flows"] = total_flows
    result["window_start_ms"] = window_start_ms
    result["window_end_ms"] = window_end_ms
    return result
