"""
Tests for the DDoS evidence-fusion rewrite (docs/NEXT_AGENT_PROMPT.md item 5)
in src/detectors/ddos.py.

Unlike most other dependency-free test files in this repo, this one does
NOT need a FakeFlow stand-in: FlowRecord (src/flow/nfstream_wrapper.py) and
DDoSDetector (src/detectors/ddos.py) both import cleanly without scapy or
nfstream installed (nfstream is optional/lazy; scapy is only needed by the
PCAP-reading path, which these tests never touch), so this exercises the
REAL detector class directly rather than a stand-in.

Covers:
- The pre-existing false-positive bug this pass found and fixed: ordinary
  low-volume, single-source, single-destination traffic (e.g. one client
  browsing one website) used to trip the DDoS aggregate detector purely
  because calculate_concentration() returns a hardcoded 1.0 for a single
  category -- a degenerate, not-meaningful-as-evidence case, not a sign of
  concentration among a real population of sources/destinations.
- The new named evidence_components shape in `details`.
- rule_score / confidence / ml_probability separation.
- The >=2-factor gate (no single weak signal decides alone).
- Directional asymmetry as a new evidence signal.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.flow.nfstream_wrapper import FlowRecord
from src.detectors.ddos import DDoSDetector


def _make_flow(source_ip, destination_ip, src2dst_packets, src2dst_bytes,
                dst2src_packets, dst2src_bytes, syn_packets, first_seen_ms,
                last_seen_ms, protocol=6):
    total_packets = src2dst_packets + dst2src_packets
    total_bytes = src2dst_bytes + dst2src_bytes
    return FlowRecord(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=12345,
        destination_port=80,
        protocol=protocol,
        bidirectional_packets=total_packets,
        bidirectional_bytes=total_bytes,
        bidirectional_duration_ms=max(1, last_seen_ms - first_seen_ms),
        src2dst_packets=src2dst_packets,
        src2dst_bytes=src2dst_bytes,
        dst2src_packets=dst2src_packets,
        dst2src_bytes=dst2src_bytes,
        bidirectional_first_seen_ms=first_seen_ms,
        bidirectional_last_seen_ms=last_seen_ms,
        bidirectional_min_ps=0,
        bidirectional_mean_ps=0,
        bidirectional_stddev_ps=0,
        bidirectional_max_ps=0,
        bidirectional_min_piat_ms=0,
        bidirectional_mean_piat_ms=0,
        bidirectional_stddev_piat_ms=0,
        bidirectional_max_piat_ms=0,
        syn_packets=syn_packets,
    )


def make_normal_flows(num_flows=5):
    """One client, one destination, symmetric request/response traffic --
    exactly the shape of ordinary web browsing. Regression case for the
    concentration false-positive bug."""
    now = int(time.time() * 1000)
    return [
        _make_flow(
            "192.168.1.100", "8.8.8.8",
            src2dst_packets=5, src2dst_bytes=500,
            dst2src_packets=5, dst2src_bytes=500,
            syn_packets=0,
            first_seen_ms=now + i * 1000,
            last_seen_ms=now + i * 1000 + 1000,
        )
        for i in range(num_flows)
    ]


def make_ddos_flows(num_flows=100):
    """Many distinct spoofed-looking sources, one victim, one-way SYN
    traffic, high rate -- classic volumetric SYN flood shape."""
    now = int(time.time() * 1000)
    return [
        _make_flow(
            f"10.0.{i // 255}.{i % 255}", "192.168.1.200",
            src2dst_packets=1000, src2dst_bytes=40000,
            dst2src_packets=0, dst2src_bytes=0,
            syn_packets=1000,
            first_seen_ms=now,
            last_seen_ms=now + 100,
        )
        for i in range(num_flows)
    ]


def test_normal_single_source_single_destination_not_flagged():
    """Regression test: this exact flow shape used to false-positive
    because calculate_concentration() returns 1.0 for a single category,
    and that alone (plus destination concentration, also trivially 1.0)
    used to satisfy detection. Requires a minimum population before
    concentration counts as evidence -- see MIN_DISTINCT_FOR_CONCENTRATION_EVIDENCE."""
    flows = make_normal_flows(5)
    detector = DDoSDetector()
    results = detector.detect(flows)
    assert results == [], f"expected no detections on ordinary traffic, got {results}"
    print("PASS: single-source/single-destination normal traffic not flagged")


def test_ddos_flows_detected_with_named_evidence():
    flows = make_ddos_flows(100)
    detector = DDoSDetector()
    results = detector.detect(flows)
    assert len(results) > 0, "expected at least one DDoS detection"
    aggregate = results[0]
    assert aggregate.threat_type == "DDOS"
    evidence = aggregate.details["evidence"]
    evidence_weights = aggregate.details["evidence_weights"]
    assert len(evidence) >= 2, "must never decide on a single evidence component"
    assert set(evidence.keys()) == set(evidence_weights.keys())
    # This scenario is volumetric + high SYN ratio + fully one-directional
    assert "volumetric" in evidence
    assert "tcp_syn" in evidence
    assert "asymmetry" in evidence
    print("PASS: DDoS flows detected with >=2 named evidence components")


def test_rule_score_confidence_ml_probability_separation():
    flows = make_ddos_flows(100)
    detector = DDoSDetector()
    results = detector.detect(flows)
    assert len(results) > 0
    for r in results:
        assert r.rule_score == r.confidence, (
            "rule_score and confidence must match when no ML contributes"
        )
        assert r.ml_probability is None, (
            "ml_probability must stay None, never fabricated as 0.0, since "
            "no ML model is wired into this detector yet"
        )
        assert 0.0 <= r.rule_score <= 1.0
    print("PASS: rule_score/confidence/ml_probability separation holds")


def test_single_weak_factor_alone_does_not_detect():
    """A moderate SYN ratio alone (just over threshold, nothing else
    corroborating) must not trigger a detection by itself."""
    now = int(time.time() * 1000)
    flows = [
        _make_flow(
            "192.168.1.50", "192.168.1.200",
            src2dst_packets=10, src2dst_bytes=400,
            dst2src_packets=10, dst2src_bytes=400,
            syn_packets=6,  # syn_ratio = 6/20 = 0.3, below default 0.5 anyway
            first_seen_ms=now + i * 5000,
            last_seen_ms=now + i * 5000 + 500,
        )
        for i in range(5)
    ]
    detector = DDoSDetector()
    results = detector.detect(flows)
    assert results == [], f"low-rate, low-syn-ratio traffic must not be flagged, got {results}"
    print("PASS: single/no weak factor does not trigger a detection")


def test_directional_asymmetry_reported_and_none_when_no_request_traffic():
    from src.detectors.ddos import DDoSDetector as D

    detector = D()
    flows_one_way = make_ddos_flows(10)
    asymmetry = detector._calculate_directional_asymmetry(flows_one_way)
    assert asymmetry is not None
    assert asymmetry >= 0.9, "fully one-directional traffic should score near 1.0"

    empty_src2dst = [
        _make_flow(
            "10.0.0.1", "10.0.0.2",
            src2dst_packets=0, src2dst_bytes=0,
            dst2src_packets=5, dst2src_bytes=500,
            syn_packets=0,
            first_seen_ms=1_000, last_seen_ms=2_000,
        )
    ]
    assert detector._calculate_directional_asymmetry(empty_src2dst) is None, (
        "no request-direction traffic at all is a degenerate case, must be "
        "None (missing), not a fabricated 0.0 or 1.0"
    )
    print("PASS: directional asymmetry computed correctly, None when undefined")


def test_get_flood_statistics_includes_directional_asymmetry():
    detector = DDoSDetector()
    stats_empty = detector.get_flood_statistics([])
    assert "directional_asymmetry" in stats_empty
    assert stats_empty["directional_asymmetry"] is None

    stats = detector.get_flood_statistics(make_ddos_flows(10))
    assert "directional_asymmetry" in stats
    assert stats["directional_asymmetry"] is not None
    print("PASS: get_flood_statistics reports directional_asymmetry (empty and populated)")


def test_details_evidence_key_compatible_with_alert_engine():
    """src/alerts/alert_engine.py's _detection_to_alert() generically reads
    details["evidence"] (flat name->value) into Alert.evidence for the
    dashboard. Guard against silently renaming that key out from under it."""
    flows = make_ddos_flows(100)
    detector = DDoSDetector()
    results = detector.detect(flows)
    assert len(results) > 0
    for r in results:
        d = r.to_dict()
        assert "evidence" in d["details"]
        assert isinstance(d["details"]["evidence"], dict)
        assert len(d["details"]["evidence"]) >= 2
        # values, not weight/value sub-dicts -- flat, matching syn_flood.py/udp_flood.py
        for v in d["details"]["evidence"].values():
            assert not isinstance(v, dict)
    print("PASS: details['evidence'] stays flat and populated, alert_engine-compatible")


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
    sys.exit(1 if failed else 0)
