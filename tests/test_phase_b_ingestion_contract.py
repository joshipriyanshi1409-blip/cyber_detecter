from datetime import datetime, timezone

from src.flow_normalization import normalize_flow
from src.flow.ingestion_status import IngestionCode, IngestionError, IngestionResult


def test_empty_capture_is_not_a_parser_failure():
    result = IngestionResult(status=IngestionCode.EMPTY, flows=[])
    assert result.ok
    assert not result.failed


def test_parser_failure_is_not_an_empty_result():
    result = IngestionResult(
        status=IngestionCode.PCAP_PARSE_ERROR,
        errors=("bad pcap",),
    )
    assert result.failed
    assert result.flows == []


def test_canonical_flow_preserves_tcp_handshake_metadata():
    flow = normalize_flow(
        {
            "flow_id": "tcp-1",
            "syn_packets": 10,
            "syn_only_packets": 8,
            "syn_ack_packets": 2,
            "ack_packets": 3,
            "rst_packets": 1,
        }
    )
    assert flow["syn_packets"] == 10
    assert flow["syn_only_packets"] == 8
    assert flow["syn_ack_packets"] == 2
    assert flow["ack_packets"] == 3
    assert flow["rst_packets"] == 1


def test_canonical_flow_preserves_icmp_and_dns_metadata():
    flow = normalize_flow(
        {
            "icmp_packets": 4,
            "icmp_bytes": 400,
            "icmp_types": [8, 0],
            "dns_query": "example.test",
            "dns_response_code": 3,
        }
    )
    assert flow["icmp_packets"] == 4
    assert flow["icmp_bytes"] == 400
    assert flow["icmp_types"] == [8, 0]
    assert flow["dns_query"] == "example.test"
    assert flow["dns_nxdomain"] is True
