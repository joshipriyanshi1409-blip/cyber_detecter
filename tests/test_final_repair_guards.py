from dataclasses import dataclass
from datetime import datetime, timezone

from src.alerts.alert_models import Alert
from src.detectors.detector_factory import DetectorFactory
from src.detectors.dga import DGADetector
from src.flow.nfstream_wrapper import FlowRecord, IncrementalScapyFlowAggregator
from src.risk.authoritative_risk import Evidence, calculate_risk


def make_flow(**kwargs):
    data = dict(
        source_ip="10.0.0.1", destination_ip="10.0.0.2",
        source_port=1234, destination_port=443, protocol=6,
        bidirectional_packets=2, bidirectional_bytes=100,
        bidirectional_duration_ms=1000,
        src2dst_packets=1, src2dst_bytes=50,
        dst2src_packets=1, dst2src_bytes=50,
        bidirectional_first_seen_ms=1000,
        bidirectional_last_seen_ms=2000,
        bidirectional_min_ps=2, bidirectional_mean_ps=2,
        bidirectional_stddev_ps=0, bidirectional_max_ps=2,
        bidirectional_min_piat_ms=1000, bidirectional_mean_piat_ms=1000,
        bidirectional_stddev_piat_ms=0, bidirectional_max_piat_ms=1000,
        syn_packets=1, ack_packets=1, fin_packets=0, rst_packets=0,
        syn_only_packets=1, syn_ack_packets=0,
        icmp_packets=0, icmp_bytes=0, icmp_type_counts=None,
        application_name="unknown", application_category="unknown",
        flow_id=7, timestamp=2.0,
        dns_query=None, dns_response_code=None, dns_nxdomain=None,
    )
    data.update(kwargs)
    return FlowRecord(**data)


def test_flow_record_has_single_canonical_dns_fields():
    f = make_flow()
    canonical = f.canonical_dict()
    assert canonical["src_ip"] == "10.0.0.1"
    assert canonical["total_packets"] == 2
    assert canonical["dns_nxdomain"] is None
    assert f.event_start_time == 1.0
    assert f.event_end_time == 2.0


def test_authoritative_risk_breakdown_reproduces_score():
    result = calculate_risk([
        Evidence("rule", "ddos", "rule_score", 0.8, None, 80, "rule", datetime.now(timezone.utc)),
        Evidence("cti", "cti", "indicator", True, None, 10, "malicious", datetime.now(timezone.utc)),
    ])
    assert result.score == 90
    assert sum(item["contribution"] for item in result.breakdown) == 90


def test_alert_separates_rule_ml_cti_fields():
    alert = Alert(
        threat_type="TEST", source_ip="10.0.0.1", destination_ip="10.0.0.2",
        risk_score=50, confidence=0.5, detector="test",
        rule_score=0.5, rule_confidence=0.5, ml_probability=0.8, cti_score=10,
    )
    assert alert.rule_score == 0.5
    assert alert.ml_probability == 0.8
    assert alert.cti_score == 10


def test_detector_factory_respects_enabled_configuration():
    factory = DetectorFactory(["dga"])
    assert set(dtype.value for dtype in factory.detectors) == {"dga"}


def test_incremental_flow_aggregator_has_bounded_state():
    agg = IncrementalScapyFlowAggregator(max_flows=2)
    assert agg.max_flows == 2
    assert agg.size() == 0
