"""
Alert Engine Module
Processes detection results and creates standardized alerts.
"""

import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timezone
import uuid
import hashlib
from collections import defaultdict

from src.alerts.alert_models import Alert, AlertBatch, AlertSeverity, AlertCategory
from src.detectors.scan import PortScanResult
from src.detectors.ddos import DDoSResult
from src.detectors.dga import DGAResult

logger = logging.getLogger(__name__)


class AlertEngine:
    """Processes detections and creates standardized alerts"""
    
    def __init__(self, deduplication_window: int = 300, max_history_entries: int = 10000):
        """
        Initialize alert engine
        
        Args:
            deduplication_window: Time window in seconds for deduplication
        """
        self.deduplication_window = deduplication_window
        self.alert_history = defaultdict(list)
        self.max_history_entries = max_history_entries
        self.alert_counter = 0
        logger.info(f"Initialized AlertEngine with {deduplication_window}s dedup window")
    
    def process_detection(self, detection: Any) -> Optional[Alert]:
        """
        Process a single detection result into an alert
        
        Args:
            detection: Detection result from any detector
            
        Returns:
            Alert object or None if should be deduplicated
        """
        if detection is None:
            return None
        
        # Convert detection to alert
        alert = self._detection_to_alert(detection)
        
        # Check for deduplication. A higher-severity alert is an escalation,
        # not a duplicate of an earlier lower-severity alert.
        duplicate=self._find_duplicate(alert)
        if duplicate is not None:
            if AlertSeverity.get_priority(alert.severity) > AlertSeverity.get_priority(duplicate.severity):
                alert.status="ESCALATED"
                duplicate.status="ESCALATED"
            else:
                logger.debug(f"Deduplicated alert: {alert.alert_id}")
                return None
        
        # Add to history
        self._add_to_history(alert)
        self.alert_counter += 1
        
        return alert
    
    def process_detections(self, detections: List[Any]) -> List[Alert]:
        """
        Process multiple detections into alerts
        
        Args:
            detections: List of detection results
            
        Returns:
            List of Alert objects
        """
        alerts = []
        
        for detection in detections:
            alert = self.process_detection(detection)
            if alert:
                alerts.append(alert)
        
        logger.info(f"Processed {len(detections)} detections, created {len(alerts)} alerts")
        return alerts
    
    def process_detection_dict(self, detection_dict: Dict[str, Any]) -> Optional[Alert]:
        """
        Process detection dictionary into alert
        
        Args:
            detection_dict: Detection result as dictionary
            
        Returns:
            Alert object or None
        """
        try:
            details = dict(detection_dict.get("details") or {})
            alert = Alert(
                threat_type=detection_dict.get("threat_type", ""),
                source_ip=detection_dict.get("source_ip", ""),
                destination_ip=detection_dict.get("destination_ip", ""),
                severity=detection_dict.get("severity", "LOW"),
                risk_score=detection_dict.get("risk_score", 0.0),
                confidence=detection_dict.get("rule_confidence", detection_dict.get("confidence", 0.0)),
                detector=detection_dict.get("detector", "unknown"),
                details=details,
                evidence=detection_dict.get("evidence", details.get("evidence", {})),
                flow_id=str(detection_dict.get("flow_id")) if detection_dict.get("flow_id") is not None else None,
                window_id=detection_dict.get("window_id"),
                rule_score=detection_dict.get("rule_score"),
                rule_confidence=detection_dict.get("rule_confidence", detection_dict.get("confidence")),
                ml_probability=details.get("ml_probability"),
                ml_label=details.get("ml_prediction"),
                ml_anomaly_score=details.get("anomaly_score"),
            )
            
            if self._is_duplicate(alert):
                return None
            
            self._add_to_history(alert)
            self.alert_counter += 1
            return alert
            
        except (TypeError, ValueError, KeyError) as e:
            logger.error("Invalid detection dictionary: %s", e)
            return None
    
    def _detection_to_alert(self, detection: Any) -> Alert:
        """Convert detection result to Alert"""
        if hasattr(detection, 'to_dict'):
            detection_dict = detection.to_dict()
        elif isinstance(detection, dict):
            detection_dict = detection
        else:
            logger.error(f"Unsupported detection type: {type(detection)}")
            return None
        
        # Extract common fields
        alert = Alert(
            threat_type=detection_dict.get("threat_type", ""),
            source_ip=detection_dict.get("source_ip", ""),
            destination_ip=detection_dict.get("destination_ip", ""),
            severity=detection_dict.get("severity", "LOW"),
            risk_score=detection_dict.get("risk_score", 0.0),
            confidence=detection_dict.get("confidence", 0.0),
            detector=detection_dict.get("detector", "unknown"),
            details=detection_dict.get("details", {}),
            evidence=detection_dict.get("details", {}).get("evidence", {}),
            flow_id=str(detection_dict.get("flow_id")) if detection_dict.get("flow_id") is not None else None,
            window_id=detection_dict.get("window_id"),
            rule_score=detection_dict.get("rule_score"),
            rule_confidence=detection_dict.get("confidence"),
            ml_probability=detection_dict.get("ml_probability", detection_dict.get("details", {}).get("ml_probability")),
            ml_label=detection_dict.get("ml_label", detection_dict.get("details", {}).get("ml_prediction")),
            ml_anomaly_score=detection_dict.get("ml_anomaly_score", detection_dict.get("details", {}).get("anomaly_score")),
        )
        
        # Add specific evidence if available
        if "details" in detection_dict:
            alert.evidence = detection_dict["details"].get("evidence", {})
        alert.attack_type = detection_dict.get("attack_type", detection_dict.get("threat_type", alert.threat_type))
        alert.attack_subtype = detection_dict.get("attack_subtype", detection_dict.get("details", {}).get("attack_subtype"))
        raw_flow_ids=detection_dict.get("flow_ids") or []
        if detection_dict.get("flow_id") is not None:
            raw_flow_ids=[detection_dict.get("flow_id")]
        alert.flow_id = str(raw_flow_ids[0]) if len(raw_flow_ids)==1 else None
        if raw_flow_ids:
            alert.details["flow_ids"]=[str(x) for x in raw_flow_ids]
        alert.window_id = detection_dict.get("window_id")
        alert.rule_score = detection_dict.get("rule_score", detection_dict.get("risk_score",0.0)/100.0)
        alert.rule_confidence = detection_dict.get("rule_confidence", detection_dict.get("confidence",0.0))
        alert.confidence = float(alert.rule_confidence or 0.0)
        alert.observation_quality = detection_dict.get("observation_quality", "GOOD")
        alert.ml_probability = detection_dict.get("ml_probability")
        alert.ml_anomaly_score = detection_dict.get("ml_anomaly_score")
        alert.ml_ran = bool(detection_dict.get("ml_ran", False))
        
        # Add domain for DGA alerts
        if "domain" in detection_dict:
            alert.details["domain"] = detection_dict["domain"]
        elif isinstance(alert.evidence, dict) and alert.evidence.get("domain"):
            alert.details["domain"] = alert.evidence["domain"]
        
        # Prefer traffic/event timestamps from detector window evidence.
        event_timestamp = (
            detection_dict.get("event_time")
            or detection_dict.get("window_end_ms")
            or detection_dict.get("timestamp")
        )
        if event_timestamp:
            try:
                if isinstance(event_timestamp, (int, float)) and event_timestamp > 10_000_000_000:
                    event_timestamp = event_timestamp / 1000.0
                alert.timestamp = (
                    event_timestamp if isinstance(event_timestamp, str)
                    else datetime.fromtimestamp(event_timestamp, tz=timezone.utc).isoformat()
                )
                alert.event_time = alert.timestamp
            except (TypeError, ValueError, OverflowError) as exc:
                logger.warning("Invalid detection event timestamp: %s", exc)
        
        return alert
    
    def _find_duplicate(self, alert: Alert) -> Optional[Alert]:
        alert_key=self._get_alert_key(alert)
        recent=self.alert_history.get(alert_key, [])
        now=datetime.now(timezone.utc)
        recent=[a for a in recent if self._is_within_window(a, now)]
        self.alert_history[alert_key]=recent
        return recent[-1] if recent else None

    def _is_duplicate(self, alert: Alert) -> bool:
        return self._find_duplicate(alert) is not None

    def _get_alert_key(self, alert: Alert) -> str:
        """Strong alert identity; includes attack subtype, protocol/port and flow/window."""
        parts=[
            alert.threat_type or alert.attack_type or "",
            alert.attack_subtype or "",
            alert.source_ip or "", alert.destination_ip or "",
            str(alert.details.get("protocol","")),
            str(alert.details.get("source_port","")),
            str(alert.details.get("destination_port","")),
            str(alert.flow_id or ""),
            str(alert.window_id or "") if alert.flow_id else "",
            str(alert.details.get("domain","")),
        ]
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()

    def _is_within_window(self, alert: Alert, current_time: datetime) -> bool:
        """Deduplicate on processing time; preserve traffic event time separately."""
        try:
            value = getattr(alert, "processing_time", None) or alert.timestamp
            alert_time = datetime.fromisoformat(value)
            if alert_time.tzinfo is None:
                alert_time = alert_time.replace(tzinfo=timezone.utc)
            time_diff = (current_time - alert_time).total_seconds()
            return 0 <= time_diff <= self.deduplication_window
        except (TypeError, ValueError, OverflowError):
            return False
    
    def _add_to_history(self, alert: Alert):
        """Add alert to bounded deduplication history."""
        alert_key = self._get_alert_key(alert)
        self.alert_history[alert_key].append(alert)

        total = sum(len(items) for items in self.alert_history.values())
        if total > self.max_history_entries:
            all_alerts = [
                (key, item)
                for key, items in self.alert_history.items()
                for item in items
            ]
            all_alerts.sort(key=lambda pair: pair[1].timestamp, reverse=True)
            bounded = defaultdict(list)
            for key, item in all_alerts[:self.max_history_entries]:
                bounded[key].append(item)
            self.alert_history = bounded
    
    def create_batch(self, detections: List[Any]) -> AlertBatch:
        """
        Create alert batch from detections
        
        Args:
            detections: List of detection results
            
        Returns:
            AlertBatch object
        """
        batch = AlertBatch()
        
        for detection in detections:
            alert = self.process_detection(detection)
            if alert:
                batch.add_alert(alert)
        
        logger.info(f"Created batch with {batch.size()} alerts")
        return batch
    
    def filter_alerts(self, alerts: List[Alert], **criteria) -> List[Alert]:
        """
        Filter alerts based on criteria
        
        Args:
            alerts: List of alerts to filter
            **criteria: Field-value pairs to filter on
            
        Returns:
            Filtered list of alerts
        """
        filtered = alerts
        
        for field, value in criteria.items():
            if field == "severity":
                filtered = [a for a in filtered if a.severity == value]
            elif field == "threat_type":
                filtered = [a for a in filtered if a.threat_type == value]
            elif field == "source_ip":
                filtered = [a for a in filtered if a.source_ip == value]
            elif field == "destination_ip":
                filtered = [a for a in filtered if a.destination_ip == value]
            elif field == "min_risk_score":
                filtered = [a for a in filtered if a.risk_score >= value]
            elif field == "min_confidence":
                filtered = [a for a in filtered if a.confidence >= value]
        
        return filtered
    
    def sort_alerts(self, alerts: List[Alert], by: str = "risk_score", reverse: bool = True) -> List[Alert]:
        """
        Sort alerts by field
        
        Args:
            alerts: List of alerts to sort
            by: Field to sort by
            reverse: Sort in reverse order
            
        Returns:
            Sorted list of alerts
        """
        if by == "risk_score":
            return sorted(alerts, key=lambda a: a.risk_score, reverse=reverse)
        elif by == "confidence":
            return sorted(alerts, key=lambda a: a.confidence, reverse=reverse)
        elif by == "timestamp":
            return sorted(alerts, key=lambda a: a.timestamp, reverse=reverse)
        elif by == "severity":
            return sorted(
                alerts,
                key=lambda a: AlertSeverity.get_priority(a.severity),
                reverse=reverse
            )
        else:
            return alerts
    
    def get_statistics(self, alerts: List[Alert]) -> Dict[str, Any]:
        """
        Get statistics about alerts
        
        Args:
            alerts: List of alerts
            
        Returns:
            Dictionary with alert statistics
        """
        stats = {
            "total_alerts": len(alerts),
            "by_severity": defaultdict(int),
            "by_type": defaultdict(int),
            "by_detector": defaultdict(int),
            "by_source": defaultdict(int),
            "average_risk_score": 0,
            "average_confidence": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0
        }
        
        if not alerts:
            return dict(stats)
        
        total_risk = 0
        total_confidence = 0
        
        for alert in alerts:
            # Count by severity
            stats["by_severity"][alert.severity] += 1
            
            # Count by type
            stats["by_type"][alert.threat_type] += 1
            
            # Count by detector
            stats["by_detector"][alert.detector] += 1
            
            # Count by source
            stats["by_source"][alert.source_ip] += 1
            
            # Sum for averages
            total_risk += alert.risk_score
            total_confidence += alert.confidence
            
            # Count by severity level
            if alert.severity == "CRITICAL":
                stats["critical_count"] += 1
            elif alert.severity == "HIGH":
                stats["high_count"] += 1
            elif alert.severity == "MEDIUM":
                stats["medium_count"] += 1
            else:
                stats["low_count"] += 1
        
        # Calculate averages
        stats["average_risk_score"] = total_risk / len(alerts)
        stats["average_confidence"] = total_confidence / len(alerts)
        
        # Convert defaultdict to dict
        stats["by_severity"] = dict(stats["by_severity"])
        stats["by_type"] = dict(stats["by_type"])
        stats["by_detector"] = dict(stats["by_detector"])
        stats["by_source"] = dict(stats["by_source"])
        
        return stats
    
    def generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        return f"ALT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"
    
    def clear_history(self):
        """Clear alert history"""
        self.alert_history.clear()
        self.alert_counter = 0
        logger.info("Alert history cleared")


class AlertProcessor:
    """Processes alerts for storage and display"""
    
    def __init__(self):
        """Initialize alert processor"""
        self.engine = AlertEngine()
        logger.info("Initialized AlertProcessor")
    
    def process_detection_results(self, results: Dict[str, List[Any]]) -> List[Alert]:
        """
        Process all detection results into alerts
        
        Args:
            results: Dictionary with detector results
            
        Returns:
            List of processed alerts
        """
        all_alerts = []
        
        for detector_name, detections in results.items():
            alerts = self.engine.process_detections(detections)
            all_alerts.extend(alerts)
        
        logger.info(f"Processed {len(all_alerts)} total alerts")
        return all_alerts
    
    def process_flat_detections(self, detections: List[Any]) -> List[Alert]:
        """
        Process flat list of detections into alerts
        
        Args:
            detections: List of detection results
            
        Returns:
            List of processed alerts
        """
        return self.engine.process_detections(detections)