#!/usr/bin/env python3
"""
Hash Chain Test Script
Tests hash chain functionality with sample alerts.
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timezone

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.blockchain.hash_chain import HashChain, HashChainEntry
from src.alerts.alert_models import Alert


def create_sample_alerts(num_alerts=5):
    """Create sample alerts for testing"""
    alerts = []
    
    for i in range(num_alerts):
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip=f"192.168.1.{i + 10}",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test_detector",
            description=f"Test alert {i}",
            details={'test': True, 'index': i}
        )
        alerts.append(alert)
    
    return alerts


def test_hash_chain():
    """Test hash chain operations"""
    print("=" * 60)
    print("HASH CHAIN TEST")
    print("=" * 60)
    
    # Create chain
    chain = HashChain()
    print("✅ Hash chain initialized")
    
    # Create sample alerts
    alerts = create_sample_alerts(5)
    print(f"✅ Created {len(alerts)} sample alerts")
    
    # Append alerts to chain
    for alert in alerts:
        entry = chain.append_alert(alert)
        print(f"✅ Appended alert {alert.alert_id} at index {entry.index}")
    
    # Display chain
    print(f"\n📊 Chain Statistics:")
    stats = chain.get_chain_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # Validate chain
    print(f"\n🔍 Validating chain...")
    validation = chain.validate_chain()
    print(f"   Is valid: {validation['is_valid']}")
    print(f"   Valid entries: {validation['valid_entries']}/{validation['total_entries']}")
    
    # Test alert validation
    print(f"\n🔍 Validating individual alerts...")
    for alert in alerts:
        result = chain.validate_alert(alert)
        status = "✅" if result['is_valid'] else "❌"
        print(f"   {status} Alert {alert.alert_id}: {'valid' if result['is_valid'] else 'invalid'}")
    
    return chain, alerts


def test_tampering(chain, alerts):
    """Test tampering detection"""
    print("\n" + "=" * 60)
    print("TAMPERING DETECTION TEST")
    print("=" * 60)
    
    if not alerts:
        print(" No alerts to test")
        return False
    
    # Get first alert
    original_alert = alerts[0]
    print(f"\nOriginal alert: {original_alert.alert_id}")
    print(f"   Risk score: {original_alert.risk_score}")
    
    # Create modified version
    modified_alert = Alert(
        alert_id=original_alert.alert_id,
        timestamp=original_alert.timestamp,
        threat_type=original_alert.threat_type,
        source_ip=original_alert.source_ip,
        destination_ip=original_alert.destination_ip,
        severity=original_alert.severity,
        risk_score=99.0,  # Modified!
        confidence=original_alert.confidence,
        detector=original_alert.detector,
        description=original_alert.description,
        details=original_alert.details
    )
    
    print(f"Modified alert risk score: {modified_alert.risk_score}")
    
    # Validate modified alert
    result = chain.validate_alert(modified_alert)
    
    print(f"\n🔍 Tampering detection result:")
    print(f"   Is valid: {result['is_valid']}")
    
    if not result['is_valid']:
        print(f"Tampering detected!")
        if 'original_hash' in result:
            print(f"   Original hash: {result['original_hash'][:32]}...")
        if 'current_hash' in result:
            print(f"   Current hash: {result['current_hash'][:32]}...")
        return True
    else:
        print(f"Tampering NOT detected (should have been)")
        return False


def test_chain_integrity(chain):
    """Test chain integrity by modifying a chain entry"""
    print("\n" + "=" * 60)
    print("CHAIN INTEGRITY TEST")
    print("=" * 60)
    
    if len(chain.chain) < 2:
        print("Not enough entries to test")
        return False
    
    # Validate original chain
    original_validation = chain.validate_chain()
    print(f"\nOriginal chain valid: {original_validation['is_valid']}")
    
    # Modify a chain entry
    modified_entry = chain.chain[1]
    print(f"\nModifying entry at index {modified_entry.index}...")
    modified_entry.data_hash = "0" * 64  # Tamper with hash
    
    # Validate chain after modification
    tampered_validation = chain.validate_chain()
    print(f"Chain valid after tampering: {tampered_validation['is_valid']}")
    
    if not tampered_validation['is_valid']:
        print(f"Tampering detected in chain!")
        print(f"   Invalid entries: {tampered_validation['invalid_entries']}")
        return True
    else:
        print(f"Tampering NOT detected")
        return False


def main():
    """Main test function"""
    print("\n" + "=" * 60)
    print("SHA-256 HASH CHAIN VERIFICATION")
    print("=" * 60)
    
    try:
        # Test basic hash chain
        chain, alerts = test_hash_chain()
        
        # Test tampering detection
        tampering_result = test_tampering(chain, alerts)
        
        # Test chain integrity
        integrity_result = test_chain_integrity(chain)
        
        # Summary
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"✅ Hash chain operations: PASS")
        print(f"{' if tampering_result else '} Tampering detection: {'PASS' if tampering_result else 'FAIL'}")
        print(f"{'if integrity_result else '} Chain integrity: {'PASS' if integrity_result else 'FAIL'}")
        
        all_passed = tampering_result and integrity_result
        
        print("\n" + "=" * 60)
        if all_passed:
            print("ALL HASH CHAIN TESTS PASSED!")
        else:
            print("SOME TESTS FAILED")
        print("=" * 60)
        
        return 0 if all_passed else 1
        
    except Exception as e:
        print(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
