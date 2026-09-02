"""
Tests for src.features.rate.FlowRateCalculator

Dependency-free (no scapy/nfstream/pytest needed): the existing
tests/test_features.py imports scapy at module level and can't be run
in this sandbox at all, so FlowRateCalculator.get_aggregate_rates() had
NO working test coverage in this environment before this file. Run
standalone with `python3 tests/test_rate_calculator.py`.
"""
import sys
from pathlib import Path
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.features.rate import FlowRateCalculator


@dataclass
class FakeFlow:
    bidirectional_first_seen_ms: int
    bidirectional_last_seen_ms: int
    bidirectional_packets: int
    bidirectional_bytes: int
    bidirectional_duration_ms: int
    src2dst_packets: int = 0
    dst2src_packets: int = 0
    source_ip: str = "10.0.0.1"
    destination_ip: str = "192.168.1.1"


def test_empty_calculator_returns_empty_rates():
    calc = FlowRateCalculator()
    rates = calc.get_aggregate_rates()
    assert rates["total_flows"] == 0
    assert rates["packets_per_second"] == 0
    print("PASS: empty calculator -> empty rates, no crash")


def test_aggregate_rates_not_diluted_by_out_of_window_flows():
    """
    Regression test for the end_time bug: end_time must be computed
    from the flows actually being aggregated (window_flows), not from
    self.flows as a whole. Before the fix, a single flow far outside
    the requested window silently inflated the computed time span
    toward the window_seconds cap, under-reporting the rate by ~30x in
    this exact scenario (reproduced and recorded in
    docs/AUDIT_PROGRESS.md).
    """
    calc = FlowRateCalculator()
    # 100 flows tightly packed into ~1 real second.
    for i in range(100):
        calc.add_flow(FakeFlow(
            bidirectional_first_seen_ms=i * 10,
            bidirectional_last_seen_ms=i * 10 + 5,
            bidirectional_packets=10,
            bidirectional_bytes=1000,
            bidirectional_duration_ms=5,
        ))
    # One flow far outside any reasonable window (simulating a
    # long-running capture session where old flow objects are still
    # referenced elsewhere).
    calc.add_flow(FakeFlow(
        bidirectional_first_seen_ms=600_000,
        bidirectional_last_seen_ms=600_100,
        bidirectional_packets=1,
        bidirectional_bytes=100,
        bidirectional_duration_ms=100,
    ))

    rates = calc.get_aggregate_rates(window_seconds=60)

    # window_flows should be the 100 tightly-packed flows only (the
    # far-outside flow's last_seen_ms is way past start_time + 60s).
    assert rates["total_flows"] == 100, f"expected 100 in-window flows, got {rates['total_flows']}"
    # The real in-window span is ~0.995s (995ms), not 60s -- so the
    # reported rate should be in the hundreds/thousands, not ~16.7
    # (the old buggy value for this exact scenario).
    assert rates["packets_per_second"] > 400, (
        f"packets_per_second suspiciously low ({rates['packets_per_second']}) -- "
        f"looks like the out-of-window flow is still diluting the time span"
    )
    assert rates["window_seconds"] < 5, (
        f"window_seconds ({rates['window_seconds']}) should reflect the ~1s "
        f"actual span of the in-window flows, not be inflated toward the 60s cap"
    )
    print(f"PASS: rate not diluted by out-of-window flow "
          f"(packets_per_second={rates['packets_per_second']:.1f}, "
          f"window_seconds={rates['window_seconds']:.3f})")


def test_all_flows_within_window_uses_full_span():
    """When every flow genuinely falls within the window, the computed
    time span should reflect their actual spread, not silently default
    to the full window_seconds."""
    calc = FlowRateCalculator()
    for i in range(10):
        calc.add_flow(FakeFlow(
            bidirectional_first_seen_ms=i * 1000,
            bidirectional_last_seen_ms=i * 1000 + 100,
            bidirectional_packets=5,
            bidirectional_bytes=500,
            bidirectional_duration_ms=100,
        ))
    rates = calc.get_aggregate_rates(window_seconds=60)
    # Flows span from t=0 to t=9100ms -> ~9.1s actual span.
    assert 8.5 < rates["window_seconds"] < 9.5, (
        f"expected window_seconds near the real ~9.1s span, got {rates['window_seconds']}"
    )
    assert rates["total_flows"] == 10
    print(f"PASS: full-span flows -> window_seconds reflects actual spread "
          f"({rates['window_seconds']:.2f}s)")


def test_single_flow_falls_back_to_window_seconds_cleanly():
    """A single flow has zero span between its own first/last (or a
    tiny one) -- must not divide by zero or blow up."""
    calc = FlowRateCalculator()
    calc.add_flow(FakeFlow(
        bidirectional_first_seen_ms=0,
        bidirectional_last_seen_ms=0,
        bidirectional_packets=3,
        bidirectional_bytes=300,
        bidirectional_duration_ms=0,
    ))
    rates = calc.get_aggregate_rates(window_seconds=60)
    assert rates["total_flows"] == 1
    assert rates["window_seconds"] == 60, (
        "zero-duration single flow should fall back to the requested window_seconds"
    )
    assert rates["packets_per_second"] == 3 / 60
    print("PASS: single zero-duration flow -> clean fallback to window_seconds, no crash")


def test_source_destination_ratio_and_unique_ips_unaffected():
    """These two methods intentionally use the FULL flow history (not
    just the window) -- confirm the end_time fix didn't change that."""
    calc = FlowRateCalculator()
    calc.add_flow(FakeFlow(0, 5, 10, 1000, 5, src2dst_packets=8, dst2src_packets=2,
                            source_ip="10.0.0.1", destination_ip="192.168.1.1"))
    calc.add_flow(FakeFlow(600_000, 600_100, 1, 100, 100, src2dst_packets=1, dst2src_packets=1,
                            source_ip="10.0.0.2", destination_ip="192.168.1.2"))
    ratio = calc.get_source_destination_ratio()
    assert ratio == 9 / 3, f"expected 3.0, got {ratio}"
    ips = calc.get_unique_ips_count()
    assert ips == {"unique_sources": 2, "unique_destinations": 2}
    print("PASS: source/destination ratio and unique-IP counts still use full history, unchanged")


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
        except Exception as e:
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
