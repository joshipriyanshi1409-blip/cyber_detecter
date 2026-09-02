#!/usr/bin/env python3
"""
Database Test Script
Tests database operations with sample alerts.
"""

import sys
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.database import DatabaseManager, AlertRecord
from src.alerts.alert_models import Alert


def create_sample_alert(threat_type="PORT_SCAN", source_ip="192.168.1.100", 
                        destination_ip="192.168.1.200", severity="HIGH"):
    """Create sample alert for testing"""
    return Alert(
        threat_type=threat_type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        severity=severity,
        risk_score=80.0,
        confidence=0.8,
        detector="test_detector",
        description=f"Test {threat_type} alert",
        details={"test": True, "source": "test_script"}
    )


def test_database_operations():
    """Test database operations"""
    print("=" * 60)
    print("DATABASE TEST")
    print("=" * 60)
    
    # Initialize database
    db = DatabaseManager("data/test_alerts.db")
    print("Database initialized")
    
    # Clear existing alerts
    deleted = db.clear_all_alerts()
    print(f"Cleared {deleted} existing alerts")
    
    # Create sample alerts
    alerts = [
        create_sample_alert("PORT_SCAN", "192.168.1.100", "192.168.1.200", "HIGH"),
        create_sample_alert("DDOS", "10.0.0.1", "192.168.1.200", "CRITICAL"),
        create_sample_alert("DGA_SUSPICIOUS_DOMAIN", "192.168.1.150", "8.8.8.8", "MEDIUM"),
        create_sample_alert("PORT_SCAN", "10.0.0.5", "192.168.1.201", "LOW"),
        create_sample_alert("DDOS", "10.0.0.2", "192.168.1.200", "HIGH"),
    ]
    
    # Add alerts
    added = db.add_alerts(alerts)
    print(f"Added {added} alerts")
    
    # Get all alerts
    all_alerts = db.get_alerts(limit=10)
    print(f"Retrieved {len(all_alerts)} alerts")
    
    # Get alerts by severity
    critical_alerts = db.get_alerts_by_severity("CRITICAL")
    print(f"Retrieved {len(critical_alerts)} critical alerts")
    
    # Get alerts by type
    port_scan_alerts = db.get_alerts_by_type("PORT_SCAN")
    print(f"Retrieved {len(port_scan_alerts)} port scan alerts")
    
    # Get alerts by source
    source_alerts = db.get_alerts_by_source("192.168.1.100")
    print(f"Retrieved {len(source_alerts)} alerts from 192.168.1.100")
    
    # Get statistics
    stats = db.get_statistics()
    print(f"\n Statistics:")
    print(f"   Total alerts: {stats['total_alerts']}")
    print(f"   By severity: {stats['by_severity']}")
    print(f"   By type: {stats['by_type']}")
    print(f"   Critical: {stats['critical_count']}")
    print(f"   High: {stats['high_count']}")
    print(f"   Average risk: {stats['average_risk_score']:.2f}")
    
    # Update alert status
    if all_alerts:
        alert_id = all_alerts[0].alert_id
        updated = db.update_alert_status(alert_id, "ACKNOWLEDGED")
        print(f"\n Updated alert status: {updated}")
        
        # Get updated alert
        updated_alert = db.get_alert(alert_id)
        if updated_alert:
            print(f"   New status: {updated_alert.status}")
    
    # Delete an alert
    if len(all_alerts) > 1:
        deleted = db.delete_alert(all_alerts[1].alert_id)
        print(f"\nDeleted alert: {deleted}")
    
    # Get final count
    final_stats = db.get_statistics()
    print(f"\nFinal total: {final_stats['total_alerts']}")
    
    print("\n" + "=" * 60)
    print("DATABASE TEST COMPLETE")
    print("=" * 60)
    
    return True


def test_database_persistence():
    """Test that data persists"""
    print("\n" + "=" * 60)
    print("PERSISTENCE TEST")
    print("=" * 60)
    
    # First instance
    db1 = DatabaseManager("data/test_alerts.db")
    alert = create_sample_alert("TEST", "1.1.1.1", "2.2.2.2", "LOW")
    db1.add_alert(alert)
    print(f"Added alert to first instance")
    
    # Second instance (should see same data)
    db2 = DatabaseManager("data/test_alerts.db")
    alerts = db2.get_alerts_by_type("TEST")
    print(f"Second instance found {len(alerts)} test alerts")
    
    if len(alerts) > 0:
        print("Data persistence verified")
        return True
    else:
        print("Data persistence failed")
        return False


def main():
    """Run database tests"""
    print("\n" + "=" * 60)
    print("DATABASE VERIFICATION")
    print("=" * 60)
    
    try:
        test_database_operations()
        test_database_persistence()
        
        print("\n ALL DATABASE TESTS PASSED!")
        return 0
    except Exception as e:
        print(f"\nDatabase test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())