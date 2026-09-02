"""
Tests for src.features.window_rates

Covers the rate-calculation cases required by the DDoS audit: zero-duration
flows, simultaneous flows, overlapping flows, sequential flows, one flow,
many flows, tiny windows -- and explicitly, the regression scenario that
must never again pass silently (Section 26 of the audit spec).
"""
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.features.window_rates import (
    compute_window_bounds,
    calculate_window_rates,
    calculate_rates_for_flows,
    MIN_WINDOW_SECONDS,
)


@dataclass
class FakeFlow:
    """Minimal stand-in for FlowRecord -- avoids needing nfstream/scapy for these tests."""
    bidirectional_packets: int
    bidirectional_bytes: int
    bidirectional_first_seen_ms: Optional[int]
    bidirectional_last_seen_ms: Optional[int]


def make_flows(n, packets_each, bytes_each, first_seen_ms, last_seen_ms):
    return [
        FakeFlow(packets_each, bytes_each, first_seen_ms, last_seen_ms)
        for _ in range(n)
    ]


def test_thE_section_26_regression_case():
    """
    THE test this whole module exists to protect: 100 simultaneous flows,
    each lasting 100ms, each carrying 1,000 packets.
    Correct aggregate rate: 1,000,000 pps. A regression to the old
    sum-of-durations bug would report 10,000 pps -- 100x too low.
    """
    flows = make_flows(n=100, packets_each=1000, bytes_each=40000,
                        first_seen_ms=1_000_000, last_seen_ms=1_000_100)
    result = calculate_rates_for_flows(flows)

    assert result["total_packets"] == 100_000
    assert result["window_seconds"] == 0.1
    assert abs(result["packets_per_second"] - 1_000_000) < 1.0, (
        f"Expected ~1,000,000 pps, got {result['packets_per_second']} "
        f"-- this is the exact regression the audit was meant to catch."
    )
    print("PASS: Section 26 regression case gives correct 1,000,000 pps")


def test_one_flow():
    flows = make_flows(1, 100, 5000, 0, 1000)  # 1 second duration
    result = calculate_rates_for_flows(flows)
    assert result["packets_per_second"] == 100.0
    print("PASS: single flow")


def test_many_sequential_flows_non_overlapping():
    """Flows that occur one after another should use the FULL span, not sum of each duration (same effect either way here since they're contiguous, but verifies window derivation from min/max)."""
    flows = [
        FakeFlow(100, 1000, 0, 100),
        FakeFlow(100, 1000, 100, 200),
        FakeFlow(100, 1000, 200, 300),
    ]
    result = calculate_rates_for_flows(flows)
    # window = 0 to 300ms = 0.3s; total packets = 300
    assert result["window_seconds"] == 0.3
    assert abs(result["packets_per_second"] - 1000.0) < 1e-6
    print("PASS: sequential non-overlapping flows")


def test_overlapping_flows():
    flows = [
        FakeFlow(1000, 10000, 0, 500),
        FakeFlow(1000, 10000, 200, 700),
    ]
    result = calculate_rates_for_flows(flows)
    # window = 0 to 700ms = 0.7s
    assert result["window_seconds"] == 0.7
    assert result["total_packets"] == 2000
    print("PASS: overlapping flows")


def test_zero_duration_flow_does_not_fabricate_zero_traffic():
    """A single flow with first_seen == last_seen (instantaneous) must not
    report 0 pps -- that would hide a real burst of traffic. Window should
    clamp to MIN_WINDOW_SECONDS instead."""
    flows = make_flows(1, 500, 20000, 5000, 5000)
    result = calculate_rates_for_flows(flows)
    assert result["window_clamped"] is True
    assert result["packets_per_second"] == 500 / MIN_WINDOW_SECONDS
    assert result["packets_per_second"] > 0
    print("PASS: zero-duration flow does not fabricate zero traffic")


def test_missing_timestamps_reports_unavailable_not_zero():
    """Rule 28: missing must not silently become zero."""
    flows = [FakeFlow(100, 1000, None, None)]
    result = calculate_rates_for_flows(flows)
    assert result["packets_per_second"] is None, (
        "Missing timestamps must yield None (unavailable), not 0"
    )
    print("PASS: missing timestamps -> None, not 0")


def test_many_flows_tiny_window():
    flows = make_flows(n=1000, packets_each=10, bytes_each=500,
                        first_seen_ms=0, last_seen_ms=1)  # 1ms window
    result = calculate_rates_for_flows(flows)
    assert result["window_clamped"] is False  # 1ms == MIN_WINDOW_SECONDS boundary case
    assert result["total_packets"] == 10000
    print("PASS: many flows, tiny (but valid) window")


def test_empty_flows():
    result = calculate_rates_for_flows([])
    assert result["packets_per_second"] is None
    assert result["total_flows"] == 0
    print("PASS: empty flow list")


def test_malformed_window_end_before_start():
    window_start, window_end = compute_window_bounds(
        [FakeFlow(10, 100, 5000, 1000)]  # last_seen < first_seen
    )
    assert window_start is None and window_end is None
    print("PASS: malformed end-before-start window detected, not silently swapped")


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
