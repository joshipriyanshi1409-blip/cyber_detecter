from datetime import datetime, timezone

from src.flow_normalization import canonical_flow_dict, normalize_flow


def test_normalize_preserves_missing_directional_values():
    flow = {
        "flow_id": "f1",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": "TCP",
        "fwd_packets": 5,
        "bwd_packets": None,
        "fwd_bytes": 500,
        "bwd_bytes": None,
    }

    result = normalize_flow(flow)

    assert result["fwd_packets"] == 5
    assert result["bwd_packets"] is None
    assert result["total_packets"] is None
    assert result["fwd_bytes"] == 500
    assert result["bwd_bytes"] is None
    assert result["total_bytes"] is None


def test_normalize_derives_totals_only_when_both_directions_exist():
    result = normalize_flow({
        "fwd_packets": 5,
        "bwd_packets": 7,
        "fwd_bytes": 500,
        "bwd_bytes": 700,
    })

    assert result["total_packets"] == 12
    assert result["total_bytes"] == 1200


def test_normalize_derives_duration_from_utc_timestamps():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc)

    result = normalize_flow({"start_time": start, "end_time": end})

    assert result["duration"] == 2.0


def test_dns_nxdomain_is_derived_from_response_code():
    result = normalize_flow({"dns_query": "example.test", "dns_response_code": 3})

    assert result["dns_query"] == "example.test"
    assert result["dns_nxdomain"] is True


def test_canonical_output_has_stable_schema():
    result = canonical_flow_dict({"flow_id": "f1"})

    assert list(result) == [
        "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "start_time", "end_time", "duration", "fwd_packets", "bwd_packets",
        "total_packets", "fwd_bytes", "bwd_bytes", "total_bytes",
        "syn_packets", "syn_only_packets", "syn_ack_packets", "ack_packets",
        "rst_packets", "icmp_packets", "icmp_bytes", "icmp_types",
        "dns_query", "dns_response_code", "dns_nxdomain",
        "tls_metadata", "quic_metadata", "ja3", "ja3s", "ja4",
    ]
