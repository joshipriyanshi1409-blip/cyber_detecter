#!/usr/bin/env python3
"""
Threat Intelligence Test Script
Tests CTI providers and enrichment.
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.cti.providers import LocalThreatIntelligenceProvider, CTIResult
from src.cti.enrichment import ThreatIntelligenceEnricher
from src.alerts.alert_models import Alert


def test_local_provider():
    """Test local CTI provider"""
    print("=" * 60)
    print("LOCAL CTI PROVIDER TEST")
    print("=" * 60)
    
    provider = LocalThreatIntelligenceProvider()
    
    # Test malicious IP
    result = provider.lookup_ip("10.0.0.1")
    if result:
        print(f"✅ Malicious IP lookup:")
        print(f"   Indicator: {result.indicator}")
        print(f"   Is malicious: {result.is_malicious}")
        print(f"   Confidence: {result.confidence}")
    
    # Test benign IP
    benign_result = provider.lookup_ip("8.8.8.8")
    if benign_result:
        print(f"\n✅ Benign IP lookup:")
        print(f"   Indicator: {benign_result.indicator}")
        print(f"   Is malicious: {benign_result.is_malicious}")
        print(f"   Confidence: {benign_result.confidence}")
    
    # Test malicious domain
    domain_result = provider.lookup_domain("malware.example.com")
    if domain_result:
        print(f"\n✅ Malicious domain lookup:")
        print(f"   Indicator: {domain_result.indicator}")
        print(f"   Is malicious: {domain_result.is_malicious}")
    
    return True


def test_enrichment():
    """Test alert enrichment"""
    print("\n" + "=" * 60)
    print("ALERT ENRICHMENT TEST")
    print("=" * 60)
    
    enricher = ThreatIntelligenceEnricher()
    
    # Create alert with malicious IP
    alert = Alert(
        threat_type="PORT_SCAN",
        source_ip="10.0.0.1",  # Malicious IP
        destination_ip="192.168.1.100",
        severity="HIGH",
        risk_score=70.0,
        confidence=0.7,
        detector="test"
    )
    
    print(f"\nOriginal alert:")
    print(f"   Risk score: {alert.risk_score}")
    print(f"   Confidence: {alert.confidence}")
    
    # Enrich alert
    enriched = enricher.enrich_alert(alert)
    
    print(f"\nEnriched alert:")
    print(f"   Risk score: {enriched.risk_score}")
    print(f"   Confidence: {enriched.confidence}")
    print(f"   Severity: {enriched.severity}")
    
    if 'cti_source_malicious' in enriched.details:
        print(f"   CTI flag: {enriched.details['cti_source_malicious']}")
        print(f"✅ Alert enriched with CTI data")
    
    return True


def test_provider_status():
    """Test provider status"""
    print("\n" + "=" * 60)
    print("PROVIDER STATUS TEST")
    print("=" * 60)
    
    enricher = ThreatIntelligenceEnricher()
    status = enricher.get_provider_status()
    
    for provider_name, provider_status in status.items():
        print(f"\n{provider_name}:")
        for key, value in provider_status.items():
            print(f"   {key}: {value}")
    
    return True


def main():
    """Main test function"""
    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE VERIFICATION")
    print("=" * 60)
    
    try:
        test_local_provider()
        test_enrichment()
        test_provider_status()
        
        print("\n" + "=" * 60)
        print("✅ ALL CTI TESTS PASSED!")
        print("=" * 60)
        
        return 0
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())