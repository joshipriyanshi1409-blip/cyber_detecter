"""
Tests for Database Module
"""

import pytest
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
import json

from src.storage.database import DatabaseManager, AlertRecord, FlowStatisticsRecord
from src.alerts.alert_models import Alert


@pytest.fixture
def db_manager(tmp_path):
    """Create database manager with test database"""
    db_path = tmp_path / "test_alerts.db"
    db = DatabaseManager(str(db_path))
    yield db
    # Cleanup
    db.clear_all_alerts()


@pytest.fixture
def sample_alert():
    """Create sample alert"""
    return Alert(
        threat_type="PORT_SCAN",
        source_ip="192.168.1.100",
        destination_ip="192.168.1.200",
        severity="HIGH",
        risk_score=80.0,
        confidence=0.8,
        detector="test_detector",
        description="Test alert",
        details={"key": "value"}
    )


class TestDatabaseManager:
    def test_initialization(self, db_manager):
        """Test database initialization"""
        assert db_manager is not None
        assert db_manager.db_path.exists()
    
    def test_add_alert(self, db_manager, sample_alert):
        """Test adding alert"""
        result = db_manager.add_alert(sample_alert)
        assert result == True
        
        # Verify alert was added
        retrieved = db_manager.get_alert(sample_alert.alert_id)
        assert retrieved is not None
        assert retrieved.alert_id == sample_alert.alert_id
        assert retrieved.threat_type == "PORT_SCAN"
    
    def test_add_multiple_alerts(self, db_manager):
        """Test adding multiple alerts"""
        alerts = []
        for i in range(5):
            alert = Alert(
                threat_type=f"TEST_TYPE_{i}",
                source_ip=f"192.168.1.{i}",
                destination_ip="192.168.1.200",
                severity="HIGH",
                risk_score=70.0 + i,
                confidence=0.7,
                detector="test"
            )
            alerts.append(alert)
        
        count = db_manager.add_alerts(alerts)
        assert count == 5
        
        # Verify all alerts added
        all_alerts = db_manager.get_alerts(limit=10)
        assert len(all_alerts) == 5
    
    def test_get_alerts(self, db_manager):
        """Test getting alerts"""
        # Add alerts
        for i in range(3):
            alert = Alert(
                threat_type="PORT_SCAN",
                source_ip=f"192.168.1.{i}",
                destination_ip="192.168.1.200",
                severity="HIGH",
                risk_score=80.0,
                confidence=0.8,
                detector="test"
            )
            db_manager.add_alert(alert)
        
        # Get alerts
        alerts = db_manager.get_alerts(limit=10)
        assert len(alerts) == 3
    
    def test_get_alerts_by_severity(self, db_manager):
        """Test getting alerts by severity"""
        # Add alerts with different severities
        severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for severity in severities:
            alert = Alert(
                threat_type="PORT_SCAN",
                source_ip="192.168.1.100",
                destination_ip="192.168.1.200",
                severity=severity,
                risk_score=80.0,
                confidence=0.8,
                detector="test"
            )
            db_manager.add_alert(alert)
        
        # Get critical alerts
        critical = db_manager.get_alerts_by_severity("CRITICAL")
        assert len(critical) == 1
        assert critical[0].severity == "CRITICAL"
    
    def test_get_alerts_by_type(self, db_manager):
        """Test getting alerts by type"""
        # Add alerts with different types
        types = ["PORT_SCAN", "DDOS", "DGA_SUSPICIOUS_DOMAIN"]
        for threat_type in types:
            alert = Alert(
                threat_type=threat_type,
                source_ip="192.168.1.100",
                destination_ip="192.168.1.200",
                severity="HIGH",
                risk_score=80.0,
                confidence=0.8,
                detector="test"
            )
            db_manager.add_alert(alert)
        
        # Get port scan alerts
        port_scan = db_manager.get_alerts_by_type("PORT_SCAN")
        assert len(port_scan) == 1
        assert port_scan[0].threat_type == "PORT_SCAN"
    
    def test_update_alert_status(self, db_manager, sample_alert):
        """Test updating alert status"""
        db_manager.add_alert(sample_alert)
        
        # Update status
        result = db_manager.update_alert_status(sample_alert.alert_id, "ACKNOWLEDGED")
        assert result == True
        
        # Verify update
        updated = db_manager.get_alert(sample_alert.alert_id)
        assert updated.status == "ACKNOWLEDGED"
    
    def test_delete_alert(self, db_manager, sample_alert):
        """Test deleting alert"""
        db_manager.add_alert(sample_alert)
        
        # Delete alert
        result = db_manager.delete_alert(sample_alert.alert_id)
        assert result == True
        
        # Verify deletion
        deleted = db_manager.get_alert(sample_alert.alert_id)
        assert deleted is None
    
    def test_get_statistics(self, db_manager):
        """Test getting statistics"""
        # Add various alerts
        for i in range(10):
            severity = "HIGH" if i % 2 == 0 else "LOW"
            alert = Alert(
                threat_type="PORT_SCAN" if i % 3 == 0 else "DDOS",
                source_ip=f"192.168.1.{i}",
                destination_ip="192.168.1.200",
                severity=severity,
                risk_score=75.0,
                confidence=0.75,
                detector="test"
            )
            db_manager.add_alert(alert)
        
        # Get statistics
        stats = db_manager.get_statistics()
        
        assert stats["total_alerts"] == 10
        assert stats["high_count"] == 5
        assert stats["low_count"] == 5
        assert stats["average_risk_score"] == 75.0
    
    def test_get_recent_alerts(self, db_manager):
        """Test getting recent alerts"""
        # Add alert with current timestamp
        recent_alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test"
        )
        db_manager.add_alert(recent_alert)
        
        # Get recent alerts
        recent = db_manager.get_recent_alerts(hours=1)
        assert len(recent) >= 1
    
    def test_clear_all_alerts(self, db_manager):
        """Test clearing all alerts"""
        # Add alerts
        for i in range(5):
            alert = Alert(
                threat_type="TEST",
                source_ip=f"192.168.1.{i}",
                destination_ip="192.168.1.200",
                severity="LOW",
                risk_score=10.0,
                confidence=0.1,
                detector="test"
            )
            db_manager.add_alert(alert)
        
        # Clear alerts
        count = db_manager.clear_all_alerts()
        assert count == 5
        
        # Verify empty
        stats = db_manager.get_statistics()
        assert stats["total_alerts"] == 0


class TestAlertRecord:
    def test_to_dict(self):
        """Test converting to dictionary"""
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test",
            details={"key": "value"}
        )
        
        record = AlertRecord.from_alert(alert)
        record_dict = record.to_dict()
        
        assert record_dict["threat_type"] == "PORT_SCAN"
        assert record_dict["severity"] == "HIGH"
        assert record_dict["details"]["key"] == "value"
    
    def test_from_alert(self):
        """Test creating from Alert"""
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test"
        )
        
        record = AlertRecord.from_alert(alert)
        
        assert record.alert_id == alert.alert_id
        assert record.threat_type == "PORT_SCAN"
        assert record.severity == "HIGH"
    
    def test_to_alert(self):
        """Test converting back to Alert"""
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test"
        )
        
        record = AlertRecord.from_alert(alert)
        converted_alert = record.to_alert()
        
        assert converted_alert.alert_id == alert.alert_id
        assert converted_alert.threat_type == alert.threat_type
        assert converted_alert.severity == alert.severity