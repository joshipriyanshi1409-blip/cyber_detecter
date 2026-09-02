"""
Risk Scoring Module
Combines evidence from multiple sources to calculate unified risk scores.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
import json

from src.alerts.alert_models import Alert, AlertSeverity

try:
    from src.utils.config import config_manager
except ImportError:
    from src.utils.config_simple import config_manager

logger = logging.getLogger(__name__)


@dataclass
class RiskScoreResult:
    """Standardized risk score result"""
    risk_score: float = 0.0
    severity: str = "LOW"
    confidence: float = 0.0
    evidence_sources: List[str] = None
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.evidence_sources is None:
            self.evidence_sources = []
        if self.details is None:
            self.details = {}
        # Ensure severity is uppercase
        self.severity = self.severity.upper()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class RiskScoreCalculator:
    """Deprecated compatibility adapter over the single authoritative risk engine.

    This module no longer contains a second scoring algorithm. All final
    calculations delegate to ``src.risk.authoritative_risk.calculate_risk``.
    """

    def __init__(self):
        self.weights={"rule_based":1.0,"anomaly_score":0.15,"ml_confidence":0.20,"cti_enrichment":1.0}
        self.severity_mapping={"LOW":(0,30),"MEDIUM":(31,60),"HIGH":(61,80),"CRITICAL":(81,100)}

    def calculate_rule_based_score(self,detection: Any)->float:
        if detection is None: return 0.0
        value=getattr(detection,"rule_score",None)
        if value is None or float(value or 0.0) <= 0:
            value=float(getattr(detection,"risk_score",0.0))/100.0
        return max(0.0,min(100.0,float(value)*100.0))

    def calculate_anomaly_score(self,anomaly_score: float)->float:
        return max(0.0,min(100.0,float(anomaly_score)*100.0))

    def calculate_ml_score(self,ml_confidence: float,predicted_class: str="")->float:
        # Compatibility API preserves the historical descriptive scale; the
        # authoritative engine never uses this 0-100 value as final risk.
        multipliers={"DDOS":1.2,"PORT_SCAN":1.0,"DGA":0.9,"NORMAL":0.1}
        return min(100.0,max(0.0,float(ml_confidence)*100.0*multipliers.get(predicted_class.upper(),0.5)))

    def calculate_combined_score(self,rule_based_score: float=0.0,anomaly_score: float=0.0,
                                 ml_confidence: float=0.0,predicted_class: str="",
                                 cti_score: float=0.0)->RiskScoreResult:
        from datetime import datetime, timezone
        from src.risk.authoritative_risk import Evidence, calculate_risk
        evidence=[]
        if rule_based_score:
            evidence.append(Evidence(source="rule",detector="legacy_adapter",feature="rule_score",
                raw_value=float(rule_based_score)/100.0,threshold=None,
                contribution=float(rule_based_score),reason="Compatibility adapter",timestamp=datetime.now(timezone.utc)))
        if anomaly_score:
            evidence.append(Evidence(source="ml",detector="legacy_adapter",feature="ml_anomaly_score",
                raw_value=float(anomaly_score),threshold=None,
                contribution=max(0.0,min(100.0,float(anomaly_score)*15.0)),reason="Compatibility adapter",timestamp=datetime.now(timezone.utc)))
        if ml_confidence:
            evidence.append(Evidence(source="ml",detector="legacy_adapter",feature="ml_probability",
                raw_value=float(ml_confidence),threshold=None,
                contribution=max(0.0,min(100.0,float(ml_confidence)*20.0)),reason="Compatibility adapter",timestamp=datetime.now(timezone.utc)))
        if cti_score:
            evidence.append(Evidence(source="cti",detector="legacy_adapter",feature="cti_score",
                raw_value=float(cti_score),threshold=None,contribution=float(cti_score),
                reason="Compatibility adapter",timestamp=datetime.now(timezone.utc)))
        result=calculate_risk(evidence)
        if result.score>=81: sev="CRITICAL"
        elif result.score>=61: sev="HIGH"
        elif result.score>=31: sev="MEDIUM"
        else: sev="LOW"
        legacy_sources=[]
        for e in evidence:
            if e.feature=="rule_score": name="rule_based"
            elif e.feature=="ml_anomaly_score": name="anomaly_detection"
            elif e.feature=="ml_probability": name="machine_learning"
            else: name=e.source
            legacy_sources.append(name)
        return RiskScoreResult(risk_score=result.score,severity=sev,
            confidence=max(0.0,min(1.0,float(rule_based_score)/100.0)),
            evidence_sources=legacy_sources,
            details={"risk_breakdown":list(result.breakdown),"authoritative":True})

    def score_detection(self,detection: Any, anomaly_score: float=0.0, ml_prediction: Optional[Dict[str,Any]]=None)->RiskScoreResult:
        ml_prediction=ml_prediction or {}
        return self.calculate_combined_score(
            rule_based_score=self.calculate_rule_based_score(detection),
            anomaly_score=anomaly_score,
            ml_confidence=float(ml_prediction.get("confidence",0.0) or 0.0),
            predicted_class=str(ml_prediction.get("predicted_class","") or ""),
            cti_score=float(getattr(detection,"cti_score",0.0) or 0.0),
        )

    def score_alert(self, alert: Alert)->Alert:
        result=self.calculate_alert_risk(alert)
        alert.risk_score=result.risk_score
        alert.severity=result.severity
        alert.details["risk_breakdown"]=result.details.get("risk_breakdown",[])
        return alert

    def get_severity(self,risk_score: float)->str:
        score=max(0,min(100,float(risk_score)))
        if score>=81: return "CRITICAL"
        if score>=61: return "HIGH"
        if score>=31: return "MEDIUM"
        return "LOW"

    def get_risk_breakdown(self,result: RiskScoreResult)->Dict[str,Any]:
        return result.to_dict()

    def update_weights(self,new_weights: Dict[str,float])->None:
        self.weights.update({str(k):float(v) for k,v in new_weights.items()})

    def calculate_alert_risk(self,alert: Alert)->RiskScoreResult:
        return self.calculate_combined_score(
            rule_based_score=float(getattr(alert,"rule_score",0.0) or 0.0)*100.0,
            anomaly_score=float(getattr(alert,"ml_anomaly_score",0.0) or 0.0),
            ml_confidence=float(getattr(alert,"ml_probability",0.0) or 0.0),
            predicted_class=str(getattr(alert,"ml_label","") or ""),
            cti_score=float(getattr(alert,"cti_score",0.0) or 0.0),
        )
