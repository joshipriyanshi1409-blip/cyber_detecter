"""
Tests for Alert Engine
"""

import pytest
import time
from datetime import datetime, timezone
import json

from src.alerts.alert_models import Alert, AlertBatch, AlertSeverity, AlertCategory
from src.alerts.alert_engine import AlertEngine, AlertProcessor
from src.alerts.alert_validator import AlertValidator
from src.detectors.scan import PortScanResult
from src.detectors.ddos import DDoSResult
from src.detectors.dga import DGAResult


@pytest.fixture
def sample_port_scan_result():
    """Create sample port scan detection"""
    return PortScanResult(
        source_ip="192.168.1.100",
        destination_ip="192.168.1.200",
        confidence=0.8,
        severity="HIGH",
        risk_score=80.0,
        details={
            "unique_ports": 50,
            "evidence": {"syn_only_ratio": 0.9}
        }
    )


@pytest.fixture
def sample_ddos_result():
    """Create sample DDoS detection"""
    return DDoSResult(
        source_ip="multiple_sources",
        destination_ip="192.168.1.200",
        confidence=0.9,
        severity="CRITICAL",
        risk_score=90.0,
        details={
            "packets_per_second": 5000,
            "evidence": {"syn_ratio": 0.85}
        }
    )


@pytest.fixture
def sample_dga_result():
    """Create sample DGA detection"""
    return DGAResult(
        source_ip="192.168.1.150",
        domain="x8j2k9lqpz12345.com",
        confidence=0.75,
        severity="MEDIUM",
        risk_score=75.0,
        details={
            "features": {"entropy": 3.8, "digit_ratio": 0.25}
        }
    )


# Test Alert Model
class TestAlertModel:
    def test_create_alert(self):
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test"
        )
        
        assert alert.alert_id is not None
        assert alert.timestamp is not None
        assert alert.threat_type == "PORT_SCAN"
        assert alert.severity == "HIGH"
        assert alert.category == "RECONNAISSANCE"
    
    def test_alert_validation(self):
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="INVALID",  # Should default to LOW
            risk_score=150.0,  # Should be capped at 100
            confidence=1.5,  # Should be capped at 1.0
            detector="test"
        )
        
        assert alert.severity == "LOW"
        assert alert.risk_score == 100.0
        assert alert.confidence == 1.0
    
    def test_alert_to_dict(self):
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test"
        )
        
        alert_dict = alert.to_dict()
        assert isinstance(alert_dict, dict)
        assert alert_dict["threat_type"] == "PORT_SCAN"
        assert alert_dict["severity"] == "HIGH"
    
    def test_alert_to_json(self):
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test"
        )
        
        json_str = alert.to_json()
        assert isinstance(json_str, str)
        
        # Parse back
        data = json.loads(json_str)
        assert data["threat_type"] == "PORT_SCAN"
    
    def test_alert_from_dict(self):
        alert_data = {
            "threat_type": "PORT_SCAN",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.200",
            "severity": "HIGH",
            "risk_score": 80.0,
            "confidence": 0.8,
            "detector": "test"
        }
        
        alert = Alert.from_dict(alert_data)
        assert alert.threat_type == "PORT_SCAN"
        assert alert.source_ip == "192.168.1.100"


# Test Alert Engine
class TestAlertEngine:
    def test_process_detection(self, sample_port_scan_result):
        engine = AlertEngine()
        alert = engine.process_detection(sample_port_scan_result)
        
        assert alert is not None
        assert alert.threat_type == "PORT_SCAN"
        assert alert.source_ip == "192.168.1.100"
        assert alert.severity == "HIGH"
    
    def test_process_multiple_detections(self, sample_port_scan_result, sample_ddos_result):
        engine = AlertEngine()
        detections = [sample_port_scan_result, sample_ddos_result]
        alerts = engine.process_detections(detections)
        
        assert len(alerts) == 2
        assert alerts[0].threat_type == "PORT_SCAN"
        assert alerts[1].threat_type == "DDOS"
    
    def test_deduplication(self, sample_port_scan_result):
        engine = AlertEngine(deduplication_window=60)
        
        # Process same detection twice
        alert1 = engine.process_detection(sample_port_scan_result)
        alert2 = engine.process_detection(sample_port_scan_result)
        
        assert alert1 is not None
        assert alert2 is None  # Should be deduplicated
    
    def test_filter_alerts(self, sample_port_scan_result, sample_ddos_result):
        engine = AlertEngine()
        alerts = engine.process_detections([sample_port_scan_result, sample_ddos_result])
        
        # Filter by severity
        high_alerts = engine.filter_alerts(alerts, severity="HIGH")
        assert len(high_alerts) == 1
        assert high_alerts[0].threat_type == "PORT_SCAN"
        
        # Filter by threat type
        ddos_alerts = engine.filter_alerts(alerts, threat_type="DDOS")
        assert len(ddos_alerts) == 1
        assert ddos_alerts[0].severity == "CRITICAL"
    
    def test_sort_alerts(self, sample_port_scan_result, sample_ddos_result):
        engine = AlertEngine()
        alerts = engine.process_detections([sample_port_scan_result, sample_ddos_result])
        
        # Sort by risk score        
        sorted_alerts = engine.sort_alerts(alerts, by="risk_score", reverse=True)
        
        assert sorted_alerts[0].risk_score >= sorted_alerts[1].risk_score
        assert sorted_alerts[0].threat_type == "DDOS"  # Higher risk
    
    def test_get_statistics(self, sample_port_scan_result, sample_ddos_result):
        engine = AlertEngine()
        alerts = engine.process_detections([sample_port_scan_result, sample_ddos_result])
        
        stats = engine.get_statistics(alerts)
        
        assert stats["total_alerts"] == 2
        assert stats["critical_count"] == 1
        assert stats["high_count"] == 1
        assert stats["average_risk_score"] == 85.0


# Test Alert Validator
class TestAlertValidator:
    def test_validate_valid_alert(self):
        validator = AlertValidator()
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test"
        )
        
        result = validator.validate_alert(alert)
        assert result["is_valid"] == True
        assert len(result["errors"]) == 0
    
    def test_validate_invalid_alert(self):
        validator = AlertValidator()
        alert = Alert(
            threat_type="",  # Missing threat type
            source_ip="invalid_ip",
            destination_ip="",
            severity="INVALID",
            risk_score=150.0,
            confidence=1.5,
            detector=""
        )
        
        result = validator.validate_alert(alert)
        assert result["is_valid"] == False
        assert len(result["errors"]) > 0
    
    def test_validate_alerts(self, sample_port_scan_result):
        engine = AlertEngine()
        alert = engine.process_detection(sample_port_scan_result)
        
        validator = AlertValidator()
        summary = validator.validate_alerts([alert])
        
        assert summary["total_alerts"] == 1
        assert summary["valid_alerts"] == 1


# Test Alert Processor
class TestAlertProcessor:
    def test_process_detection_results(self, sample_port_scan_result, sample_ddos_result, sample_dga_result):
        processor = AlertProcessor()
        
        results = {
            "port_scan": [sample_port_scan_result],
            "ddos": [sample_ddos_result],
            "dga": [sample_dga_result]
        }
        
        alerts = processor.process_detection_results(results)
        
        assert len(alerts) == 3
        assert all(isinstance(alert, Alert) for alert in alerts)
    
    def test_process_flat_detections(self, sample_port_scan_result, sample_ddos_result):
        processor = AlertProcessor()
        detections = [sample_port_scan_result, sample_ddos_result]
        
        alerts = processor.process_flat_detections(detections)
        
        assert len(alerts) == 2
        assert all(isinstance(alert, Alert) for alert in alerts)


# Test Alert Batch
class TestAlertBatch:
    def test_create_batch(self):
        batch = AlertBatch()
        assert batch.size() == 0
        
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test"
        )
        
        batch.add_alert(alert)
        assert batch.size() == 1
    
    def test_batch_to_list(self):
        batch = AlertBatch()
        
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test"
        )
        
        batch.add_alert(alert)
        alert_list = batch.to_list()
        
        assert len(alert_list) == 1
        assert alert_list[0]["threat_type"] == "PORT_SCAN"