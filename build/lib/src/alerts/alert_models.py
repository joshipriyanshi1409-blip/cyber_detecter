"""
Alert Models Module
Defines standardized alert structures for all detection outputs.
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
import uuid
import json

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """Standardized alert structure for all detections"""
    
    # Required fields
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    threat_type: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    severity: str = "LOW"
    risk_score: float = 0.0
    confidence: float = 0.0
    detector: str = ""

    # First-class security/correlation fields.
    event_time: Optional[str] = None
    processing_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    flow_id: Optional[str] = None
    window_id: Optional[int] = None
    attack_type: Optional[str] = None
    attack_subtype: Optional[str] = None
    rule_score: Optional[float] = None
    rule_confidence: Optional[float] = None
    decision_confidence: float = 0.0
    ml_probability: Optional[float] = None
    ml_label: Optional[str] = None
    ml_anomaly_score: Optional[float] = None
    ml_model_version: Optional[str] = None
    cti_score: Optional[float] = None
    incident_id: Optional[str] = None
    observation_quality: str = "GOOD"
    degradation_reasons: List[str] = field(default_factory=list)
    cti_status: str = "NOT_RUN"
    ml_ran: bool = False
    schema_version: str = "alert-v2"
    risk_breakdown: List[Dict[str, Any]] = field(default_factory=list)

    # Optional fields
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    status: str = "NEW"
    category: str = ""
    recommendation: str = ""
    
    def __post_init__(self):
        """Validate and normalize alert fields after initialization"""
        # Normalize severity to uppercase
        self.severity = self.severity.upper()
        
        # Validate severity
        valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if self.severity not in valid_severities:
            logger.warning(f"Invalid severity '{self.severity}', defaulting to LOW")
            self.severity = "LOW"
        
        # Ensure risk score is within range
        self.risk_score = max(0.0, min(100.0, self.risk_score))
        
        # Ensure confidence is within range
        self.confidence = max(0.0, min(1.0, self.confidence))
        
        # Set category if not provided
        if not self.category:
            self.category = self._infer_category()
        
        # Set description if not provided
        if not self.description:
            self.description = self._generate_description()
    
    def _infer_category(self) -> str:
        """Infer alert category from threat type"""
        category_map = {
            "PORT_SCAN": "RECONNAISSANCE",
            "DDOS": "AVAILABILITY",
            "DGA_SUSPICIOUS_DOMAIN": "COMMAND_AND_CONTROL",
            "ANOMALY": "BEHAVIORAL",
            "MALWARE": "MALWARE"
        }
        return category_map.get(self.threat_type, "UNKNOWN")
    
    def _generate_description(self) -> str:
        """Generate human-readable description"""
        descriptions = {
            "PORT_SCAN": f"Port scan detected from {self.source_ip} targeting {self.destination_ip}",
            "DDOS": f"DDoS attack detected targeting {self.destination_ip}",
            "DGA_SUSPICIOUS_DOMAIN": f"Suspicious DGA domain detected: {self.details.get('domain', 'unknown')}",
            "ANOMALY": f"Anomalous traffic detected from {self.source_ip}",
            "MALWARE": f"Potential malware activity from {self.source_ip}"
        }
        return descriptions.get(self.threat_type, f"{self.threat_type} detected")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2, default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """Create Alert from dictionary"""
        # Filter out unknown fields
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)
    
    def update_status(self, new_status: str):
        """Update alert status"""
        valid_statuses = ["NEW", "ACKNOWLEDGED", "ESCALATED", "RESOLVED", "FALSE_POSITIVE", "SUPPRESSED", "DEGRADED"]
        if new_status in valid_statuses:
            self.status = new_status
        else:
            logger.warning(f"Invalid status '{new_status}'")


@dataclass
class AlertBatch:
    """Batch of alerts for bulk operations"""
    
    alerts: List[Alert] = field(default_factory=list)
    batch_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def add_alert(self, alert: Alert):
        """Add alert to batch"""
        self.alerts.append(alert)
    
    def to_list(self) -> List[Dict[str, Any]]:
        """Convert to list of dictionaries"""
        return [alert.to_dict() for alert in self.alerts]
    
    def size(self) -> int:
        """Get batch size"""
        return len(self.alerts)
    
    def clear(self):
        """Clear all alerts"""
        self.alerts.clear()


class AlertSeverity:
    """Alert severity constants"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    
    @classmethod
    def get_all(cls) -> List[str]:
        """Get all severity levels"""
        return [cls.LOW, cls.MEDIUM, cls.HIGH, cls.CRITICAL]
    
    @classmethod
    def get_priority(cls, severity: str) -> int:
        """Get priority number for severity (higher = more severe)"""
        priority_map = {
            cls.LOW: 0,
            cls.MEDIUM: 1,
            cls.HIGH: 2,
            cls.CRITICAL: 3
        }
        return priority_map.get(severity, 0)


class AlertCategory:
    """Alert category constants"""
    RECONNAISSANCE = "RECONNAISSANCE"
    AVAILABILITY = "AVAILABILITY"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    BEHAVIORAL = "BEHAVIORAL"
    MALWARE = "MALWARE"
    UNKNOWN = "UNKNOWN"