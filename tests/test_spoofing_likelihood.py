"""
Tests for src.features.spoofing_likelihood

Covers: empty input, too-few-sources (insufficient_data), a
classic spoofed-source-flood shape (many one-packet sources all hitting
one destination), ordinary distributed traffic (many real sources,
many destinations -- should score low despite high source diversity),
and that source_churn is always reported as unavailable (since the
streaming/windowing mechanism it needs doesn't exist yet).

Dependency-free: runs standalone with
`python3 tests/test_spoofing_likelihood.py`, no pytest/scapy/nfstream
required.
"""
import sys
from pathlib import Path
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.features.spoofing_likelihood import (
    calculate_spoofing_likelihood,
    MIN_SOURCES_FOR_SCORE,
)


@dataclass
class FakeFlow:
    """Minimal stand-in for FlowRecord -- avoids needing nfstream/scapy."""
    source_ip: str
    destination_ip: str
    bidirectional_packets: int
    bidirectional_bytes: int


def test_empty_input_is_insufficient_data_not_zero():
    result = calculate_spoofing_likelihood([])
    assert result["spoofing_likelihood"] is None
    assert result["spoofing_likelihood_label"] == "insufficient_data"
    assert result["unique_source_count"] == 0
    assert "source_churn" in result["signals_unavailable"]
    print("PASS: empty input -> insufficient_data, not a fabricated low score")


def test_too_few_sources_is_insufficient_data():
    """Fewer than MIN_SOURCES_FOR_SCORE distinct sources -> can't score."""
    flows = [
        FakeFlow(f"10.0.0.{i}", "9.9.9.9", 1, 60)
        for i in range(MIN_SOURCES_FOR_SCORE - 1)
    ]
    result = calculate_spoofing_likelihood(flows)
    assert result["spoofing_likelihood"] is None
    assert result["spoofing_likelihood_label"] == "insufficient_data"
    assert result["unique_source_count"] == MIN_SOURCES_FOR_SCORE - 1
    print("PASS: too few distinct sources -> insufficient_data")


def test_classic_spoofed_flood_shape_scores_high():
    """
    Many sources, each contributing exactly one packet, all hitting a
    single destination -- the textbook spoofed-source-flood shape.
    Should score meaningfully high.
    """
    flows = [
        FakeFlow(f"203.0.113.{i}", "198.51.100.1", 1, 60)
        for i in range(1, 101)
    ]
    result = calculate_spoofing_likelihood(flows)
    assert result["spoofing_likelihood"] is not None
    assert result["spoofing_likelihood"] >= 0.7, result["spoofing_likelihood"]
    assert result["spoofing_likelihood_label"] == "high"
    assert result["evidence"]["one_packet_source_ratio"] == 1.0
    assert result["evidence"]["destination_concentration"] == 1.0
    assert "one_packet_source_ratio" in result["signals_used"]
    print("PASS: classic spoofed-flood shape scores high")


def test_ordinary_distributed_traffic_scores_low():
    """
    Many real, persistent sources (multiple packets each, not one-packet
    drive-bys), spread across many DIFFERENT destinations -- looks like
    ordinary Internet traffic, not a targeted flood. Should score low
    even though source diversity/entropy alone is high.
    """
    flows = []
    for i in range(1, 31):
        # Each "source" is a real host with a normal multi-packet
        # conversation, and each talks to a DIFFERENT destination.
        flows.append(FakeFlow(f"192.168.1.{i}", f"10.20.30.{i}", 50, 3000))
    result = calculate_spoofing_likelihood(flows)
    assert result["spoofing_likelihood"] is not None
    assert result["spoofing_likelihood"] < 0.4, result["spoofing_likelihood"]
    assert result["evidence"]["one_packet_source_ratio"] == 0.0
    assert result["evidence"]["destination_concentration"] < 0.1
    print("PASS: ordinary distributed traffic (many destinations) scores low")


def test_high_entropy_alone_does_not_dominate_without_destination_concentration():
    """
    Sanity check on the weighting rationale in the module docstring:
    the SAME high-entropy/high-one-packet-ratio source pattern scores
    meaningfully lower when destinations are spread out than when they
    are concentrated on one target.
    """
    spread_flows = [
        FakeFlow(f"203.0.113.{i}", f"198.51.100.{i}", 1, 60)
        for i in range(1, 51)
    ]
    concentrated_flows = [
        FakeFlow(f"203.0.113.{i}", "198.51.100.1", 1, 60)
        for i in range(1, 51)
    ]
    spread_result = calculate_spoofing_likelihood(spread_flows)
    concentrated_result = calculate_spoofing_likelihood(concentrated_flows)
    assert spread_result["spoofing_likelihood"] < concentrated_result["spoofing_likelihood"], (
        spread_result["spoofing_likelihood"], concentrated_result["spoofing_likelihood"]
    )
    print("PASS: destination concentration meaningfully changes the score, as documented")


def test_source_churn_always_reported_unavailable():
    """source_churn must always show up as unavailable until item 6 (streaming) exists."""
    flows = [FakeFlow(f"203.0.113.{i}", "198.51.100.1", 1, 60) for i in range(1, 21)]
    result = calculate_spoofing_likelihood(flows)
    assert "source_churn" in result["signals_unavailable"]
    assert result["signals_unavailable"]["source_churn"] == "requires_streaming_window"
    assert "source_churn" not in result["signals_used"]
    print("PASS: source_churn consistently flagged as unavailable, not silently dropped")


def test_score_always_bounded_zero_to_one():
    import random
    random.seed(42)
    for _ in range(20):
        n_sources = random.randint(MIN_SOURCES_FOR_SCORE, 60)
        n_dests = random.randint(1, 20)
        flows = [
            FakeFlow(
                f"10.0.{random.randint(0,255)}.{i}",
                f"9.9.9.{random.randint(1, n_dests)}",
                random.randint(1, 500),
                random.randint(60, 60000),
            )
            for i in range(n_sources)
        ]
        result = calculate_spoofing_likelihood(flows)
        if result["spoofing_likelihood"] is not None:
            assert 0.0 <= result["spoofing_likelihood"] <= 1.0, result["spoofing_likelihood"]
    print("PASS: score always bounded in [0, 1] across randomized inputs")


if __name__ == "__main__":
    tests = [
        test_empty_input_is_insufficient_data_not_zero,
        test_too_few_sources_is_insufficient_data,
        test_classic_spoofed_flood_shape_scores_high,
        test_ordinary_distributed_traffic_scores_low,
        test_high_entropy_alone_does_not_dominate_without_destination_concentration,
        test_source_churn_always_reported_unavailable,
        test_score_always_bounded_zero_to_one,
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
