"""Versioned feature schema shared by PCAP, replay and live ML paths."""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence
import math

@dataclass(frozen=True)
class FeatureSchema:
    schema_version: str
    feature_names: tuple[str, ...]
    types: tuple[str, ...]
    units: tuple[str, ...]
    missing_behavior: str = "unknown numeric features are represented by 0 only where zero is semantically valid"

FEATURE_SCHEMA = FeatureSchema(
    schema_version="network-v2",
    feature_names=(
        "bidirectional_packets","bidirectional_bytes","duration_s",
        "src2dst_packets","dst2src_packets","src2dst_bytes","dst2src_bytes",
        "packets_per_second","bytes_per_second","mean_packet_size",
        "mean_piat_ms","packet_asymmetry","byte_asymmetry","syn_ratio",
        "syn_only_ratio","rst_ratio","icmp_ratio",
    ),
    types=("int","int","float","int","int","int","int","float","float","float","float","float","float","float","float","float","float"),
    units=("packets","bytes","seconds","packets","packets","bytes","bytes","packets/s","bytes/s","bytes","ms","ratio","ratio","ratio","ratio","ratio","ratio"),
)

def feature_schema_dict() -> Dict[str, Any]:
    return {
        "schema_version": FEATURE_SCHEMA.schema_version,
        "feature_names": list(FEATURE_SCHEMA.feature_names),
        "types": list(FEATURE_SCHEMA.types),
        "units": list(FEATURE_SCHEMA.units),
        "missing_behavior": FEATURE_SCHEMA.missing_behavior,
        "valid_ranges": {
            "duration_s": [0, None], "packets_per_second": [0, None],
            "bytes_per_second": [0, None], "mean_packet_size": [0, None],
            "mean_piat_ms": [0, None],
            "packet_asymmetry": [0, 1], "byte_asymmetry": [0, 1],
            "syn_ratio": [0, 1], "syn_only_ratio": [0, 1],
            "rst_ratio": [0, 1], "icmp_ratio": [0, 1],
        },
    }

def extract_features(flows: Sequence[Any]) -> List[List[float]]:
    """Single feature engine used by both ML models."""
    rows=[]
    for f in flows:
        packets=max(int(getattr(f,"bidirectional_packets",0) or 0),0)
        bytes_total=max(int(getattr(f,"bidirectional_bytes",0) or 0),0)
        duration_s=max(float(getattr(f,"bidirectional_duration_ms",0) or 0)/1000.0,0.0)
        pps=packets/duration_s if duration_s>0 else 0.0
        bps=bytes_total/duration_s if duration_s>0 else 0.0
        mean_ps=bytes_total/packets if packets else 0.0
        piat=float(getattr(f,"bidirectional_mean_piat_ms",0) or 0.0)
        src_p=int(getattr(f,"src2dst_packets",0) or 0); dst_p=int(getattr(f,"dst2src_packets",0) or 0)
        src_b=int(getattr(f,"src2dst_bytes",0) or 0); dst_b=int(getattr(f,"dst2src_bytes",0) or 0)
        packet_asym=abs(src_p-dst_p)/packets if packets else 0.0
        byte_asym=abs(src_b-dst_b)/bytes_total if bytes_total else 0.0
        syn=int(getattr(f,"syn_packets",0) or 0); syn_only=int(getattr(f,"syn_only_packets",0) or 0)
        rst=int(getattr(f,"rst_packets",0) or 0); icmp=int(getattr(f,"icmp_packets",0) or 0)
        rows.append([
            packets,bytes_total,duration_s,src_p,dst_p,src_b,dst_b,pps,bps,mean_ps,piat,
            packet_asym,byte_asym,syn/packets if packets else 0.0,
            syn_only/packets if packets else 0.0,rst/packets if packets else 0.0,
            icmp/packets if packets else 0.0,
        ])
    return rows
