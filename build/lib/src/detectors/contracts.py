"""Canonical detector contract and adapters."""
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

@dataclass
class DetectionResult:
    detector: str
    detected: bool
    attack_type: str
    attack_subtype: Optional[str] = None
    flow_ids: Tuple[str, ...] = ()
    window_id: Optional[int] = None
    event_start_time: Optional[float] = None
    event_end_time: Optional[float] = None
    source_ip: str = ""
    destination_ip: str = ""
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[int] = None
    rule_score: float = 0.0
    rule_confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    observation_quality: str = "GOOD"
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data=asdict(self)
        data["flow_ids"]=list(self.flow_ids)
        data["threat_type"]=self.attack_type
        data["timestamp"]=self.event_end_time
        data["risk_score"]=self.rule_score*100.0
        data["confidence"]=self.rule_confidence
        data["rule_score"]=self.rule_score
        data["rule_confidence"]=self.rule_confidence
        data["details"]={**self.details, "evidence": self.evidence}
        return data

def flow_window_fields(flows):
    ids=tuple(str(getattr(f,"flow_id")) for f in flows if getattr(f,"flow_id",None) is not None)
    times=[getattr(f,"timestamp",None) for f in flows if getattr(f,"timestamp",None) is not None]
    return ids, (min(times) if times else None), (max(times) if times else None)
