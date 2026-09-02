"""
Tests for src.detectors.syn_flood

Covers the scenarios required by docs/NEXT_AGENT_PROMPT.md item 3:
normal handshake traffic, a SYN flood, a SYN-heavy-but-legitimate
workload, SYN-only traffic, SYN-ACK-heavy traffic, and RST-heavy
traffic -- plus the "never decide on a single ratio alone" combination
rule and the missing-vs-zero (Rule 28) behavior of the underlying
metrics.

Dependency-free: runs standalone with `python3 tests/test_syn_flood.py`,
no pytest/scapy/nfstream required. Uses a FakeFlow dataclass (only the
fields SynFloodDetector actually reads) instead of a real FlowRecord,
following the pattern established in tests/test_window_rates.py and
tests/test_spoofing_likelihood.py.
"""
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detectors.syn_flood import SynFloodDetector, TCP_PROTOCOL


@dataclass
class FakeFlow:
    """Minimal stand-in for FlowRecord -- avoids needing nfstream/scapy
    for these tests. Only carries the fields SynFloodDetector and the
    feature modules it calls (window_rates, source_stats,
    spoofing_likelihood) actually read."""
    source_ip: str
    destination_ip: str
    protocol: int
    syn_only_packets: int
    syn_ack_packets: int
    ack_packets: int
    rst_packets: int
    bidirectional_packets: int
    bidirectional_bytes: int
    bidirectional_first_seen_ms: Optional[int]
    bidirectional_last_seen_ms: Optional[int]


def make_handshake_flow(source_ip, destination_ip, first_ms, last_ms, packets=4):
    """A single, ordinary, fully-completed TCP handshake: one client
    SYN, one server SYN-ACK, one client ACK (+ a little more traffic)."""
    return FakeFlow(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=TCP_PROTOCOL,
        syn_only_packets=1,
        syn_ack_packets=1,
        ack_packets=2,  # ACK of the SYN-ACK, plus at least one more ACK
        rst_packets=0,
        bidirectional_packets=packets,
        bidirectional_bytes=packets * 500,
        bidirectional_first_seen_ms=first_ms,
        bidirectional_last_seen_ms=last_ms,
    )


def make_half_open_flow(source_ip, destination_ip, first_ms, last_ms):
    """A single half-open TCP flow: client SYN sent, nothing else
    observed at all (no SYN-ACK, no ACK, no RST) -- the classic SYN
    flood / backlog-exhaustion signature."""
    return FakeFlow(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=TCP_PROTOCOL,
        syn_only_packets=1,
        syn_ack_packets=0,
        ack_packets=0,
        rst_packets=0,
        bidirectional_packets=1,
        bidirectional_bytes=60,
        bidirectional_first_seen_ms=first_ms,
        bidirectional_last_seen_ms=last_ms,
    )


def make_rst_refused_flow(source_ip, destination_ip, first_ms, last_ms):
    """SYN sent, RST received back -- actively refused, not silently
    dropped. Distinguishable from make_half_open_flow via rst_packets,
    matching the scan.py failure-signature fix this detector reuses the
    same underlying fields from."""
    return FakeFlow(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=TCP_PROTOCOL,
        syn_only_packets=1,
        syn_ack_packets=0,
        ack_packets=0,
        rst_packets=1,
        bidirectional_packets=2,
        bidirectional_bytes=120,
        bidirectional_first_seen_ms=first_ms,
        bidirectional_last_seen_ms=last_ms,
    )


def test_normal_handshake_traffic_no_detection():
    """Ordinary traffic: modest rate, every handshake completes fully.
    No factor should cross its threshold, so no detection at all."""
    detector = SynFloodDetector()
    flows = [
        make_handshake_flow(f"10.0.0.{i}", "192.168.1.10", 0, 1000)
        for i in range(1, 8)
    ]
    results = detector.detect(flows)
    assert results == [], f"Expected no detections for normal handshake traffic, got {results}"
    print("PASS: normal handshake traffic -> no detection")


def test_syn_flood_detected():
    """Classic SYN flood shape: high SYN-only rate, essentially no
    completions, aimed at a single destination, from many one-packet
    sources (spoofing-likelihood evidence). Should trigger at least the
    per-destination detection."""
    detector = SynFloodDetector()
    # 300 half-open flows from 300 distinct sources, all in a 100ms
    # window (window clamps to MIN_WINDOW_SECONDS=1ms floor -- either
    # way this is a very high syn_only_packets_per_second).
    flows = [
        make_half_open_flow(f"203.0.113.{i}", "192.168.1.10", 0, 100)
        for i in range(300)
    ]
    # source_ip values just need to be distinct strings; calculate_concentration/
    # source_stats only care about string identity, not IP validity, so
    # octet values above 255 here are harmless.
    results = detector.detect(flows)
    assert len(results) >= 1, "Expected at least one SYN-flood detection"
    dest_results = [r for r in results if r.destination_ip == "192.168.1.10"]
    assert dest_results, "Expected a detection for the flooded destination"
    result = dest_results[0]
    assert result.threat_type == "SYN_FLOOD"
    assert result.confidence > 0
    assert result.rule_score == result.confidence, (
        "rule_score and confidence must match when no ML contributes"
    )
    assert result.ml_probability is None, (
        "ml_probability must stay None, never fabricated as 0.0, since no "
        "ML model is wired into this detector"
    )
    assert result.details["ack_completion_ratio"] == 0.0, (
        "0.0 completion is a real, meaningful measurement here (every "
        "SYN-only flow got no ACK at all), not a missing value"
    )
    print(f"PASS: SYN flood detected (confidence={result.confidence:.2f}, "
          f"severity={result.severity})")


def test_syn_heavy_legitimate_workload_not_flagged():
    """A busy but healthy server: high SYN volume, but every handshake
    completes normally and traffic is spread across many destinations
    with no spoofing evidence. Only ONE factor (rate) could ever cross
    threshold -- the combination rule (>= 2 factors) must keep this from
    being flagged."""
    detector = SynFloodDetector()
    flows = [
        make_handshake_flow(f"10.0.0.{i % 50}", f"192.168.1.{i % 20}", 0, 50)
        for i in range(200)
    ]
    results = detector.detect(flows)
    assert results == [], (
        f"Expected no detections for a syn-heavy but fully-completing, "
        f"low-concentration workload (single-factor rate spike alone "
        f"must not trigger a detection), got {results}"
    )
    print("PASS: SYN-heavy legitimate workload -> no detection (single factor insufficient)")


def test_syn_only_traffic_contributes_rate_and_completion_factors():
    """SYN-only traffic (no SYN-ACKs, no ACKs at all) concentrated on
    one destination should cross both the rate and completion-ratio
    factors -- two independent factors -- and be flagged even without
    needing the destination-concentration/spoofing factor."""
    detector = SynFloodDetector()
    flows = [
        make_half_open_flow(f"198.51.100.{i}", "192.168.1.20", 0, 50)
        for i in range(150)
    ]
    results = detector.detect(flows)
    assert any(r.destination_ip == "192.168.1.20" for r in results), (
        "Expected SYN-only traffic to be flagged via rate + completion evidence"
    )
    result = [r for r in results if r.destination_ip == "192.168.1.20"][0]
    assert "syn_only_packets_per_second" in result.details["evidence"]
    assert "ack_completion_ratio" in result.details["evidence"]
    print("PASS: SYN-only traffic -> flagged via rate + completion factors")


def test_syn_ack_heavy_traffic_not_flagged_as_flood():
    """Traffic dominated by SYN-ACKs (server replies) rather than
    client SYN-onlys should not look like a SYN flood -- SYN-only rate
    stays low even if raw SYN-flag volume (the legacy conflated field,
    not used by this detector) is high."""
    detector = SynFloodDetector()
    flows = []
    for i in range(20):
        flows.append(FakeFlow(
            source_ip="192.168.1.10",  # the "server" replying
            destination_ip=f"10.0.0.{i}",
            protocol=TCP_PROTOCOL,
            syn_only_packets=0,
            syn_ack_packets=5,
            ack_packets=5,
            rst_packets=0,
            bidirectional_packets=10,
            bidirectional_bytes=2000,
            bidirectional_first_seen_ms=0,
            bidirectional_last_seen_ms=100,
        ))
    results = detector.detect(flows)
    assert results == [], (
        f"Expected no detection for SYN-ACK-heavy (not SYN-only-heavy) "
        f"traffic, got {results}"
    )
    print("PASS: SYN-ACK-heavy traffic -> no detection")


def test_rst_heavy_traffic_evidence_reported_but_not_double_counted():
    """RST-heavy traffic (many actively-refused connection attempts)
    should surface in rst_ratio for transparency, but rst_ratio itself
    is not one of the weighted confidence factors (it's not a strong,
    independent SYN-flood signal on its own -- a busy firewall
    refusing connections looks similar). Combined with a high SYN-only
    rate and low completion it can still be flagged via those two
    factors, exactly like the SYN-only case."""
    detector = SynFloodDetector()
    flows = [
        make_rst_refused_flow(f"198.51.100.{i}", "192.168.1.30", 0, 50)
        for i in range(150)
    ]
    results = detector.detect(flows)
    dest_results = [r for r in results if r.destination_ip == "192.168.1.30"]
    assert dest_results, "Expected RST-heavy half-open traffic to still be flagged"
    result = dest_results[0]
    assert result.details["rst_ratio"] == 1.0, "rst_ratio should reflect all-RST traffic"
    assert "rst_ratio" not in result.details["evidence"], (
        "rst_ratio is reported for transparency but must not itself be a "
        "weighted confidence factor"
    )
    print("PASS: RST-heavy traffic -> evidence reported, still flagged via rate+completion")


def test_non_tcp_flows_produce_no_detections():
    """UDP/ICMP-only flows carry no SYN/ACK/RST semantics; the detector
    must filter them out rather than dividing by zero or fabricating
    ratios from nonsense fields."""
    detector = SynFloodDetector()
    flows = [
        FakeFlow(
            source_ip=f"10.0.0.{i}", destination_ip="192.168.1.40",
            protocol=17,  # UDP
            syn_only_packets=0, syn_ack_packets=0, ack_packets=0, rst_packets=0,
            bidirectional_packets=100, bidirectional_bytes=5000,
            bidirectional_first_seen_ms=0, bidirectional_last_seen_ms=50,
        )
        for i in range(20)
    ]
    results = detector.detect(flows)
    assert results == [], "Non-TCP flows must never produce a SYN-flood detection"
    print("PASS: non-TCP flows -> no detection, no crash")


def test_combination_rule_requires_at_least_two_factors():
    """Directly exercises the >=2-factors rule via the aggregate
    statistics helper: a set of flows engineered so that ONLY the
    destination-concentration factor could ever cross threshold (SYN
    rate low, completion healthy) must not be flagged, confirming the
    rule isn't accidentally satisfied by a single strong factor."""
    detector = SynFloodDetector()
    # All aimed at one destination (concentration = 1.0), but low SYN
    # rate and full completion -- only the destination-concentration
    # factor could ever fire.
    flows = [
        make_handshake_flow(f"10.0.0.{i}", "192.168.1.50", 0, 100000)  # very wide window -> low pps
        for i in range(6)
    ]
    results = detector.detect(flows)
    assert results == [], (
        f"A single strong factor (destination concentration) must not be "
        f"sufficient on its own, got {results}"
    )
    print("PASS: single strong factor (destination concentration alone) -> no detection")


def test_get_syn_flood_statistics_handles_empty_and_non_tcp():
    detector = SynFloodDetector()
    empty_stats = detector.get_syn_flood_statistics([])
    assert empty_stats["syn_only_packets_per_second"] is None
    assert empty_stats["total_tcp_flows"] == 0

    udp_only = [
        FakeFlow(
            source_ip="10.0.0.1", destination_ip="192.168.1.60", protocol=17,
            syn_only_packets=0, syn_ack_packets=0, ack_packets=0, rst_packets=0,
            bidirectional_packets=10, bidirectional_bytes=500,
            bidirectional_first_seen_ms=0, bidirectional_last_seen_ms=10,
        )
    ]
    udp_stats = detector.get_syn_flood_statistics(udp_only)
    assert udp_stats["total_tcp_flows"] == 0
    assert udp_stats["syn_only_packets_per_second"] is None
    print("PASS: get_syn_flood_statistics handles empty input and non-TCP-only input")


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
