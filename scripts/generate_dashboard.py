#!/usr/bin/env python3
"""
Generate Dashboard Sample Data
Creates sample alerts for dashboard demonstration.
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
import random

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.database import DatabaseManager
from src.alerts.alert_models import Alert


def generate_sample_alerts(num_alerts=50):
    """Generate sample alerts for dashboard"""
    alerts = []
    
    threat_types = ['PORT_SCAN', 'DDOS', 'DGA_SUSPICIOUS_DOMAIN']
    severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    source_ips = [f'192.168.1.{i}' for i in range(1, 20)]
    destination_ips = ['192.168.1.200', '8.8.8.8', '1.1.1.1', '10.0.0.1']
    
    now = datetime.now(timezone.utc)
    
    for i in range(num_alerts):
        # Random properties
        threat_type = random.choice(threat_types)
        severity = random.choice(severities)
        source_ip = random.choice(source_ips)
        destination_ip = random.choice(destination_ips)
        
        # Risk score based on severity
        risk_ranges = {
            'LOW': (0, 30),
            'MEDIUM': (31, 60),
            'HIGH': (61, 80),
            'CRITICAL': (81, 100)
        }
        risk_score = random.uniform(*risk_ranges[severity])
        
        # Confidence
        confidence = random.uniform(0.5, 1.0)
        
        # Timestamp within last 24 hours
        timestamp = now - timedelta(
            hours=random.uniform(0, 24),
            minutes=random.uniform(0, 60)
        )
        
        alert = Alert(
            threat_type=threat_type,
            source_ip=source_ip,
            destination_ip=destination_ip,
            severity=severity,
            risk_score=round(risk_score, 2),
            confidence=round(confidence, 2),
            detector=f"sample_{threat_type.lower()}",
            description=f"Sample {threat_type} alert from {source_ip}",
            details={
                'sample': True,
                'generated_at': now.isoformat(),
                'random_id': i
            }
        )
        
        # Override timestamp
        alert.timestamp = timestamp.isoformat()
        
        alerts.append(alert)
    
    return alerts


def main():
    """Generate and store sample alerts"""
    print("=" * 60)
    print("GENERATING DASHBOARD SAMPLE DATA")
    print("=" * 60)
    
    # Initialize database
    db = DatabaseManager("data/threats.db")
    print(" Database initialized")
    
    # Clear existing alerts
    deleted = db.clear_all_alerts()
    print(f" Cleared {deleted} existing alerts")
    
    # Generate sample alerts
    alerts = generate_sample_alerts(50)
    print(f" Generated {len(alerts)} sample alerts")
    
    # Store alerts
    added = db.add_alerts(alerts)
    print(f" Stored {added} alerts in database")
    
    # Display statistics
    stats = db.get_statistics()
    print("\n Database Statistics:")
    print(f"   Total alerts: {stats['total_alerts']}")
    print(f"   Critical: {stats['critical_count']}")
    print(f"   High: {stats['high_count']}")
    print(f"   Medium: {stats['medium_count']}")
    print(f"   Low: {stats['low_count']}")
    
    print("\n Sample data generated successfully!")
    print("\nRun the dashboard with:")
    print("  python scripts/run_dashboard.py")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())