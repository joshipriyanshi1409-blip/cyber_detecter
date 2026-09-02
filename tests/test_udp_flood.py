"""
Tests for src.detectors.udp_flood

Covers: normal UDP traffic, a UDP flood (volumetric + concentration),
a UDP-heavy-but-legitimate workload (single factor insufficient),
reflection-like traffic (amplification ratio + port + source diversity),
a legitimate large-response exchange that must NOT be flagged as
reflection (ratio alone insufficient), the minimum-reply-bytes floor,
and non-UDP filtering.

Dependency-free: runs standalone with `python3 tests/test_udp_flood.py`.
"""
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detectors.udp_flood import UDPFloodDetector, UDP_PROTOCOL


@dataclass
class FakeFlow:
    """Minimal stand-in for FlowRecord -- only the fields UDPFloodDetector
    and the feature modules it calls actually read."""
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: int
    bidirectional_packets: int
    bidirectional_bytes: int
    src2dst_packets: int
    src2dst_bytes: int
    dst2src_packets: int
    dst2src_bytes: int
    bidirectional_first_seen_ms: Optional[int]
    bidirectional_last_seen_ms: Optional[int]


def make_udp_flow(source_ip, destination_ip, destination_port, first_ms, last_ms,
                   req_bytes=100, reply_bytes=100, req_packets=1, reply_packets=1,
                   source_port=54321):
    return FakeFlow(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=UDP_PROTOCOL,
        bidirectional_packets=req_packets + reply_packets,
        bidirectional_bytes=req_bytes + reply_bytes,
        src2dst_packets=req_packets,
        src2dst_bytes=req_bytes,
        dst2src_packets=reply_packets,
        dst2src_bytes=reply_bytes,
        bidirectional_first_seen_ms=first_ms,
        bidirectional_last_seen_ms=last_ms,
    )


def test_normal_udp_traffic_no_detection():
    """Ordinary, low-rate, well-distributed UDP traffic: no factor
    should cross threshold."""
    detector = UDPFloodDetector()
    flows = [
        make_udp_flow(f"10.0.0.{i}", f"192.168.1.{i % 20}", 443, 0, 5000)
        for i in range(10)
    ]
    results = detector.detect(flows)
    assert results == [], f"Expected no detections for normal UDP traffic, got {results}"
    print("PASS: normal UDP traffic -> no detection")


def test_udp_flood_detected():
    """High-rate UDP traffic aimed at one destination from many
    one-flow sources: rate + source-diversity (and/or destination
    concentration) should combine to flag UDP_FLOOD."""
    detector = UDPFloodDetector()
    flows = [
        make_udp_flow(f"203.0.113.{i}", "192.168.1.10", 33434, 0, 100,
                       req_bytes=50, reply_bytes=0, req_packets=1, reply_packets=0)
        for i in range(300)
    ]
    results = detector.detect(flows)
    flood_results = [r for r in results if r.threat_type == "UDP_FLOOD"]
    dest_results = [r for r in flood_results if r.destination_ip == "192.168.1.10"]
    assert dest_results, f"Expected a UDP_FLOOD detection for the flooded destination, got {results}"
    result = dest_results[0]
    assert result.confidence > 0
    assert result.ml_probability is None
    assert result.rule_score == result.confidence
    print(f"PASS: UDP flood detected (confidence={result.confidence:.2f}, severity={result.severity})")


def test_udp_heavy_legitimate_workload_not_flagged():
    """A busy but healthy UDP service: high packet rate, but spread
    across many destinations/ports with no concentration or
    source-diversity evidence. Only the rate factor could ever cross
    threshold -- the >=2-factor rule must prevent a detection."""
    detector = UDPFloodDetector()
    flows = [
        make_udp_flow(f"10.0.0.{i % 50}", f"192.168.1.{i % 30}", 8000 + (i % 30), 0, 100)
        for i in range(400)
    ]
    results = detector.detect(flows)
    flood_results = [r for r in results if r.threat_type == "UDP_FLOOD"]
    assert flood_results == [], (
        f"Expected no UDP_FLOOD detection for a high-rate but low-concentration, "
        f"low-diversity workload, got {flood_results}"
    )
    print("PASS: UDP-heavy legitimate workload -> no UDP_FLOOD detection")


def test_reflection_like_detected():
    """Classic amplification shape: tiny requests, huge replies, from
    many distinct query sources, on a well-known reflection-prone port
    (DNS, 53). Should be flagged UDP_REFLECTION_LIKE."""
    detector = UDPFloodDetector()
    flows = [
        make_udp_flow(f"203.0.113.{i}", "198.51.100.53", destination_port=53,
                       first_ms=0, last_ms=1000, req_bytes=60, reply_bytes=4000,
                       req_packets=1, reply_packets=3)
        for i in range(50)
    ]
    results = detector.detect(flows)
    reflection_results = [r for r in results if r.threat_type == "UDP_REFLECTION_LIKE"]
    assert reflection_results, f"Expected a UDP_REFLECTION_LIKE detection, got {results}"
    result = reflection_results[0]
    assert result.details["queried_port"] == 53
    assert result.details["amplification_ratio"] > 5.0
    assert "caveat" in result.details, "Reflection-like results must always carry the interpretive caveat"
    assert result.ml_probability is None
    print(f"PASS: reflection-like traffic detected (confidence={result.confidence:.2f}, "
          f"ratio={result.details['amplification_ratio']:.1f})")


def test_single_legitimate_large_response_not_flagged():
    """One-off legitimate exchange with a big response (e.g. a single
    large DNS answer) on a non-reflection-prone port, from too few
    distinct sources to show diversity evidence, and below the
    minimum-flows floor for the group. Amplification ratio ALONE must
    not be sufficient."""
    detector = UDPFloodDetector()
    flows = [
        make_udp_flow("10.0.0.5", "192.168.1.20", destination_port=9999,
                       first_ms=0, last_ms=100, req_bytes=40, reply_bytes=2000)
        for _ in range(3)  # below reflection_min_flows (5)
    ]
    results = detector.detect(flows)
    reflection_results = [r for r in results if r.threat_type == "UDP_REFLECTION_LIKE"]
    assert reflection_results == [], (
        f"Expected no reflection detection below the minimum-flows floor, got {reflection_results}"
    )
    print("PASS: single legitimate large response -> no reflection-like detection (below min flows)")


def test_reflection_ratio_alone_insufficient_even_with_enough_flows():
    """Enough flows and a high ratio, but non-reflection-prone port and
    too few distinct query sources (all from the same single source) --
    only ONE factor (amplification ratio) can cross threshold. The
    >=2-factor rule must still apply here, same as UDP_FLOOD."""
    detector = UDPFloodDetector()
    flows = [
        make_udp_flow("10.0.0.5", "192.168.1.30", destination_port=9999,
                       first_ms=i * 10, last_ms=i * 10 + 5,
                       req_bytes=40, reply_bytes=2000, source_port=50000 + i)
        for i in range(10)
    ]
    results = detector.detect(flows)
    reflection_results = [r for r in results if r.threat_type == "UDP_REFLECTION_LIKE"]
    assert reflection_results == [], (
        f"Expected amplification ratio alone (no port evidence, single source) "
        f"to be insufficient, got {reflection_results}"
    )
    print("PASS: high ratio alone (single source, non-reflection port) -> no detection")


def test_reflection_min_reply_bytes_floor():
    """Tiny absolute volumes should never qualify regardless of ratio
    (a 10-byte request and 60-byte reply is a 6x ratio but trivial in
    absolute terms)."""
    detector = UDPFloodDetector()
    flows = [
        make_udp_flow(f"203.0.113.{i}", "198.51.100.10", destination_port=53,
                       first_ms=0, last_ms=100, req_bytes=10, reply_bytes=60)
        for i in range(50)
    ]
    results = detector.detect(flows)
    reflection_results = [r for r in results if r.threat_type == "UDP_REFLECTION_LIKE"]
    assert reflection_results == [], (
        f"Expected trivial absolute reply volume to be excluded by the minimum-reply-bytes "
        f"floor regardless of ratio, got {reflection_results}"
    )
    print("PASS: trivial absolute volume -> excluded by min_reply_bytes floor")


def test_zero_request_bytes_does_not_crash_and_reports_none_ratio():
    """A group with reply bytes but literally zero request bytes must
    not divide by zero, and must report amplification_ratio as None
    (insufficient data), not an invented infinite/huge ratio."""
    detector = UDPFloodDetector()
    flows = [
        make_udp_flow(f"203.0.113.{i}", "198.51.100.20", destination_port=53,
                       first_ms=0, last_ms=100, req_bytes=0, reply_bytes=6000, req_packets=0)
        for i in range(20)
    ]
    results = detector.detect(flows)  # must not raise
    reflection_results = [r for r in results if r.threat_type == "UDP_REFLECTION_LIKE"]
    for r in reflection_results:
        assert r.details["amplification_ratio"] is None or r.details["request_bytes"] > 0
    print("PASS: zero request bytes -> no crash, ratio reported as None when undefined")


def test_non_udp_flows_produce_no_detections():
    """TCP-only flows carry no UDP semantics and must be filtered out
    cleanly."""
    detector = UDPFloodDetector()
    flows = [
        FakeFlow(
            source_ip=f"10.0.0.{i}", destination_ip="192.168.1.40",
            source_port=1234, destination_port=80, protocol=6,  # TCP
            bidirectional_packets=10, bidirectional_bytes=1000,
            src2dst_packets=5, src2dst_bytes=500, dst2src_packets=5, dst2src_bytes=500,
            bidirectional_first_seen_ms=0, bidirectional_last_seen_ms=100,
        )
        for i in range(20)
    ]
    results = detector.detect(flows)
    assert results == [], "Non-UDP flows must never produce a UDP detection"
    print("PASS: non-UDP flows -> no detection, no crash")


def test_get_udp_statistics_handles_empty_and_non_udp():
    detector = UDPFloodDetector()
    empty_stats = detector.get_udp_statistics([])
    assert empty_stats["packets_per_second"] is None
    assert empty_stats["total_udp_flows"] == 0

    tcp_only = [
        FakeFlow(
            source_ip="10.0.0.1", destination_ip="192.168.1.60",
            source_port=1234, destination_port=80, protocol=6,
            bidirectional_packets=10, bidirectional_bytes=500,
            src2dst_packets=5, src2dst_bytes=250, dst2src_packets=5, dst2src_bytes=250,
            bidirectional_first_seen_ms=0, bidirectional_last_seen_ms=10,
        )
    ]
    tcp_stats = detector.get_udp_statistics(tcp_only)
    assert tcp_stats["total_udp_flows"] == 0
    assert tcp_stats["packets_per_second"] is None
    print("PASS: get_udp_statistics handles empty input and non-UDP-only input")


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
