"""
Tests for src.features.source_stats

Covers: empty input, single dominant source, perfectly even distribution,
skewed/one-packet-source-heavy distribution (typical of spoofed-source
DDoS), degenerate zero-packet flows, and a direct regression check that
`calculate_concentration` reproduces the exact HHI figures the old
`DDoSDetector._calculate_concentration` produced (values extracted, not
reimplemented from scratch).

Dependency-free: runs standalone with `python3 tests/test_source_stats.py`,
no pytest/scapy/nfstream required.
"""
import sys
from pathlib import Path
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.features.source_stats import (
    calculate_concentration,
    shannon_entropy_normalized,
    calculate_source_packet_distribution,
    calculate_source_byte_distribution,
    calculate_source_stats,
)


@dataclass
class FakeFlow:
    """Minimal stand-in for FlowRecord -- avoids needing nfstream/scapy."""
    source_ip: str
    bidirectional_packets: int
    bidirectional_bytes: int


def test_empty_input_returns_none_not_zero():
    """Rule 28: empty input must report None for undefined stats, not 0."""
    stats = calculate_source_stats([])
    assert stats["unique_source_count"] == 0
    assert stats["total_packets"] == 0
    assert stats["top_source_ip"] is None
    assert stats["top_source_fraction"] is None
    assert stats["source_entropy"] is None
    assert stats["source_concentration"] == 0.0  # concentration IS defined as 0 for no data
    assert stats["one_packet_source_ratio"] is None
    assert stats["source_churn"] is None
    assert stats["source_churn_reason"] == "requires_streaming_window"
    print("PASS: empty input distinguishes None (undefined) from 0 (defined)")


def test_single_source_full_concentration_zero_entropy():
    """One source dominating everything: concentration=1.0, entropy=0.0."""
    flows = [FakeFlow("10.0.0.1", 100, 6000) for _ in range(5)]
    stats = calculate_source_stats(flows)
    assert stats["unique_source_count"] == 1
    assert stats["top_source_ip"] == "10.0.0.1"
    assert stats["top_source_fraction"] == 1.0
    assert stats["source_entropy"] == 0.0
    assert stats["source_concentration"] == 1.0
    print("PASS: single source -> concentration 1.0, entropy 0.0")


def test_perfectly_even_distribution_high_entropy_low_concentration():
    """10 sources, identical packet volume each: max entropy, near-zero HHI concentration."""
    flows = [FakeFlow(f"10.0.0.{i}", 100, 6000) for i in range(10)]
    stats = calculate_source_stats(flows)
    assert stats["unique_source_count"] == 10
    assert abs(stats["source_entropy"] - 1.0) < 1e-9, stats["source_entropy"]
    # Normalized HHI over 10 equally-sized flow-occurrence categories -> 0.0
    assert abs(stats["source_concentration"] - 0.0) < 1e-9, stats["source_concentration"]
    assert abs(stats["top_source_fraction"] - 0.1) < 1e-9
    print("PASS: perfectly even distribution -> entropy ~1.0, concentration ~0.0")


def test_dominant_source_plus_many_one_packet_sources():
    """
    Typical spoofed-source DDoS shape: one huge real flow, plus a long
    tail of sources contributing exactly 1 packet each.
    """
    flows = [FakeFlow("10.0.0.1", 10_000, 600_000)]
    flows += [FakeFlow(f"192.168.1.{i}", 1, 60) for i in range(1, 51)]  # 50 one-packet sources
    stats = calculate_source_stats(flows)

    assert stats["unique_source_count"] == 51
    assert stats["top_source_ip"] == "10.0.0.1"
    # 10,000 / (10,000 + 50) ~= 0.995
    assert stats["top_source_fraction"] > 0.99
    assert stats["one_packet_source_count"] == 50
    assert abs(stats["one_packet_source_ratio"] - 50 / 51) < 1e-9
    # Entropy should be low (heavily skewed toward the dominant source)
    assert stats["source_entropy"] < 0.3, stats["source_entropy"]
    print("PASS: dominant-source-plus-one-packet-tail shape captured correctly")


def test_degenerate_zero_packet_flows_do_not_fabricate_fraction():
    """Flows exist but carry zero packets -- top_source_fraction must stay None."""
    flows = [FakeFlow("10.0.0.1", 0, 0), FakeFlow("10.0.0.2", 0, 0)]
    stats = calculate_source_stats(flows)
    assert stats["unique_source_count"] == 2
    assert stats["total_packets"] == 0
    assert stats["top_source_ip"] is None
    assert stats["top_source_fraction"] is None
    assert stats["source_entropy"] is None  # shannon_entropy_normalized([0,0]) -> no nonzero counts
    print("PASS: degenerate zero-packet flows don't fabricate a fraction/entropy")


def test_concentration_matches_original_ddos_py_hhi_values():
    """
    Direct regression check against known HHI results, matching the
    pre-refactor DDoSDetector._calculate_concentration behavior exactly
    (same algorithm, just relocated -- see module docstring).
    """
    # 4 equal categories -> HHI = 4*(0.25**2) = 0.25; normalized:
    # (0.25 - 0.25) / (1 - 0.25) = 0.0
    values = ["a", "b", "c", "d"]
    assert abs(calculate_concentration(values) - 0.0) < 1e-9

    # One value repeated -> single category -> concentration = 1.0
    assert calculate_concentration(["a", "a", "a"]) == 1.0

    # Empty -> 0.0 (matches original private method's behavior)
    assert calculate_concentration([]) == 0.0

    # Skewed: 8 of "a", 1 each of "b","c" (10 total)
    # HHI = 0.8^2 + 0.1^2 + 0.1^2 = 0.64 + 0.01 + 0.01 = 0.66
    # n=3 -> normalized = (0.66 - 1/3) / (1 - 1/3) = (0.66-0.3333)/(0.6667) ~= 0.49
    values = ["a"] * 8 + ["b", "c"]
    result = calculate_concentration(values)
    assert abs(result - 0.49) < 0.01, result
    print("PASS: calculate_concentration reproduces expected HHI figures")


def test_shannon_entropy_normalized_edge_cases():
    assert shannon_entropy_normalized([]) is None
    assert shannon_entropy_normalized([0, 0, 0]) is None
    assert shannon_entropy_normalized([5]) == 0.0
    assert abs(shannon_entropy_normalized([1, 1]) - 1.0) < 1e-9
    assert abs(shannon_entropy_normalized([1, 1, 1, 1]) - 1.0) < 1e-9
    # Skewed 2-category case must be strictly between 0 and 1
    skewed = shannon_entropy_normalized([99, 1])
    assert 0.0 < skewed < 1.0, skewed
    print("PASS: shannon_entropy_normalized edge cases correct")


def test_distribution_helpers_sum_correctly():
    flows = [
        FakeFlow("10.0.0.1", 10, 500),
        FakeFlow("10.0.0.1", 5, 300),
        FakeFlow("10.0.0.2", 7, 400),
    ]
    packets = calculate_source_packet_distribution(flows)
    byte_dist = calculate_source_byte_distribution(flows)
    assert packets == {"10.0.0.1": 15, "10.0.0.2": 7}
    assert byte_dist == {"10.0.0.1": 800, "10.0.0.2": 400}
    print("PASS: distribution helpers aggregate multiple flows per source correctly")


if __name__ == "__main__":
    tests = [
        test_empty_input_returns_none_not_zero,
        test_single_source_full_concentration_zero_entropy,
        test_perfectly_even_distribution_high_entropy_low_concentration,
        test_dominant_source_plus_many_one_packet_sources,
        test_degenerate_zero_packet_flows_do_not_fabricate_fraction,
        test_concentration_matches_original_ddos_py_hhi_values,
        test_shannon_entropy_normalized_edge_cases,
        test_distribution_helpers_sum_correctly,
    ]
    failures = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failures += 1
            print(f"FAIL: {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    if failures:
        sys.exit(1)
