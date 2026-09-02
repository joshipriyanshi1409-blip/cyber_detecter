"""
Alert Validation Module
Validates alert structure and content.
"""

import logging
from typing import Dict, Any, List, Optional
import ipaddress
import re

from src.alerts.alert_models import Alert, AlertSeverity

logger = logging.getLogger(__name__)


class AlertValidator:
    """Validates alert structure and content"""
    
    def __init__(self):
        """Initialize validator"""
        self.validation_rules = []
        logger.info("Initialized AlertValidator")
    
    def validate_alert(self, alert: Alert) -> Dict[str, Any]:
        """
        Validate an alert
        
        Args:
            alert: Alert object to validate
            
        Returns:
            Dictionary with validation results
        """
        validation_result = {
            "is_valid": True,
            "errors": [],
            "warnings": []
        }
        
        # Check required fields
        required_fields = ["alert_id", "timestamp", "threat_type", "severity"]
        for field in required_fields:
            if not getattr(alert, field, None):
                validation_result["is_valid"] = False
                validation_result["errors"].append(f"Missing required field: {field}")
        
        # Validate severity
        if alert.severity not in AlertSeverity.get_all():
            validation_result["is_valid"] = False
            validation_result["errors"].append(f"Invalid severity: {alert.severity}")
        
        # Validate risk score
        if not (0 <= alert.risk_score <= 100):
            validation_result["is_valid"] = False
            validation_result["errors"].append(f"Risk score out of range: {alert.risk_score}")
        
        # Validate authoritative score fields. `confidence` is only the
        # backward-compatible alias of rule_confidence.
        for field_name in ("rule_score","rule_confidence","ml_probability","ml_anomaly_score","cti_score"):
            value=getattr(alert, field_name, None)
            if value is not None and not (0 <= float(value) <= (1 if field_name != "cti_score" else 100)):
                validation_result["is_valid"]=False
                validation_result["errors"].append(f"{field_name} out of range: {value}")
        if alert.observation_quality not in {"GOOD","DEGRADED","INSUFFICIENT"}:
            validation_result["is_valid"]=False
            validation_result["errors"].append(f"Invalid observation_quality: {alert.observation_quality}")
        if alert.processing_time is None:
            validation_result["is_valid"]=False
            validation_result["errors"].append("Missing processing_time")
        
        # Validate IP addresses if present
        if alert.source_ip and not self._is_valid_ip(alert.source_ip):
            validation_result["warnings"].append(f"Invalid source IP: {alert.source_ip}")
        
        if alert.destination_ip and not self._is_valid_ip(alert.destination_ip):
            validation_result["warnings"].append(f"Invalid destination IP: {alert.destination_ip}")
        
        return validation_result
    
    def validate_alerts(self, alerts: List[Alert]) -> Dict[str, Any]:
        """
        Validate multiple alerts
        
        Args:
            alerts: List of alerts to validate
            
        Returns:
            Dictionary with validation summary
        """
        summary = {
            "total_alerts": len(alerts),
            "valid_alerts": 0,
            "invalid_alerts": 0,
            "errors": [],
            "warnings": []
        }
        
        for alert in alerts:
            result = self.validate_alert(alert)
            
            if result["is_valid"]:
                summary["valid_alerts"] += 1
            else:
                summary["invalid_alerts"] += 1
                summary["errors"].extend(result["errors"])
            
            summary["warnings"].extend(result["warnings"])
        
        return summary
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def add_validation_rule(self, rule_func):
        """Add custom validation rule"""
        self.validation_rules.append(rule_func)
    
    def run_custom_rules(self, alert: Alert) -> List[str]:
        """Run custom validation rules"""
        errors = []
        
        for rule in self.validation_rules:
            try:
                result = rule(alert)
                if result:
                    errors.append(result)
            except Exception as e:
                logger.error(f"Validation rule failed: {e}")
        
        return errors