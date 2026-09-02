"""
Phase A canonical flow normalization.

This module deliberately does not replace existing extractors. It provides a
single boundary for converting extractor-specific objects/mappings into the
canonical FlowRecord semantics used by downstream components.

Missing directional/metadata fields remain None rather than being fabricated
as zero.
"""
from __future__ import annotations

from dataclasses import asdict, fields, is_dataclass
from datetime import datetime, timezone
from typing import Any, Mapping


_CANONICAL_FIELDS = (
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "start_time",
    "end_time",
    "duration",
    "fwd_packets",
    "bwd_packets",
    "total_packets",
    "fwd_bytes",
    "bwd_bytes",
    "total_bytes",
    "syn_packets",
    "syn_only_packets",
    "syn_ack_packets",
    "ack_packets",
    "rst_packets",
    "icmp_packets",
    "icmp_bytes",
    "icmp_types",
    "dns_query",
    "dns_response_code",
    "dns_nxdomain",
    "tls_metadata",
    "quic_metadata",
    "ja3",
    "ja3s",
    "ja4",
)


def _get(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _first(source: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        value = _get(source, name, None)
        if value is not None:
            return value
    return default


def _utc_datetime(value: Any) -> Any:
    if value is None or isinstance(value, datetime):
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return value
    return value


def normalize_flow(source: Any, *, flow_id: str | None = None) -> dict[str, Any]:
    """
    Return a canonical, JSON-friendly flow mapping.

    The function preserves None for unavailable directional or protocol metadata.
    It never turns parser/extractor absence into fabricated zero measurements.
    """
    if source is None:
        raise ValueError("flow source cannot be None")

    result = {
        "flow_id": flow_id or _first(source, "flow_id", "id"),
        "src_ip": _first(source, "src_ip", "source_ip", "src_ip_address"),
        "dst_ip": _first(source, "dst_ip", "destination_ip", "dst_ip_address"),
        "src_port": _first(source, "src_port", "source_port"),
        "dst_port": _first(source, "dst_port", "destination_port"),
        "protocol": _first(source, "protocol", "protocol_name"),
        "start_time": _utc_datetime(_first(source, "start_time", "first_seen")),
        "end_time": _utc_datetime(_first(source, "end_time", "last_seen")),
        "duration": _first(source, "duration", "duration_seconds"),
        "fwd_packets": _first(source, "fwd_packets", "forward_packets"),
        "bwd_packets": _first(source, "bwd_packets", "backward_packets"),
        "total_packets": _first(source, "total_packets", "packets"),
        "fwd_bytes": _first(source, "fwd_bytes", "forward_bytes"),
        "bwd_bytes": _first(source, "bwd_bytes", "backward_bytes"),
        "total_bytes": _first(source, "total_bytes", "bytes"),
        "syn_packets": _first(source, "syn_packets"),
        "syn_only_packets": _first(source, "syn_only_packets"),
        "syn_ack_packets": _first(source, "syn_ack_packets"),
        "ack_packets": _first(source, "ack_packets"),
        "rst_packets": _first(source, "rst_packets"),
        "icmp_packets": _first(source, "icmp_packets"),
        "icmp_bytes": _first(source, "icmp_bytes"),
        "icmp_types": _first(source, "icmp_types", "icmp_type"),
        "dns_query": _first(source, "dns_query", "dns_domain", "query_name"),
        "dns_response_code": _first(
            source, "dns_response_code", "dns_rcode", "response_code"
        ),
        "dns_nxdomain": _first(source, "dns_nxdomain"),
        "tls_metadata": _first(source, "tls_metadata"),
        "quic_metadata": _first(source, "quic_metadata"),
        "ja3": _first(source, "ja3"),
        "ja3s": _first(source, "ja3s"),
        "ja4": _first(source, "ja4"),
    }

    # Derive only totals that are mathematically implied by BOTH directions.
    # Missing directions remain missing.
    if result["total_packets"] is None:
        if result["fwd_packets"] is not None and result["bwd_packets"] is not None:
            result["total_packets"] = result["fwd_packets"] + result["bwd_packets"]

    if result["total_bytes"] is None:
        if result["fwd_bytes"] is not None and result["bwd_bytes"] is not None:
            result["total_bytes"] = result["fwd_bytes"] + result["bwd_bytes"]

    if result["duration"] is None:
        start, end = result["start_time"], result["end_time"]
        if isinstance(start, datetime) and isinstance(end, datetime):
            result["duration"] = max(0.0, (end - start).total_seconds())

    # DNS NXDOMAIN can be normalized from the DNS response code without
    # inventing DNS data when no response code exists.
    if result["dns_nxdomain"] is None and result["dns_response_code"] is not None:
        code = result["dns_response_code"]
        result["dns_nxdomain"] = str(code).upper() in {"3", "NXDOMAIN"}

    return result


def canonical_flow_dict(source: Any, *, flow_id: str | None = None) -> dict[str, Any]:
    """Return only the authoritative canonical fields in stable order."""
    normalized = normalize_flow(source, flow_id=flow_id)
    return {name: normalized.get(name) for name in _CANONICAL_FIELDS}


def validate_canonical_flow(source: Any) -> dict[str, Any]:
    """Validate that a flow crosses the canonical boundary before detection.

    This is intentionally non-destructive: downstream detectors still receive
    the typed FlowRecord, while the canonical mapping is the authoritative
    contract used to validate field names and missing-value semantics.
    """
    result = canonical_flow_dict(source)
    required = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")
    missing = [name for name in required if result.get(name) in (None, "")]
    if missing:
        raise ValueError(f"canonical flow missing required fields: {', '.join(missing)}")
    return result
