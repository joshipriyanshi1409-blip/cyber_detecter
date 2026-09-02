"""
Tests for Threat Intelligence Enrichment
"""

import pytest
import time
from pathlib import Path

from src.cti.providers import (
    ThreatIntelligenceProvider,
    CTIResult,
    LocalThreatIntelligenceProvider
)
from src.cti.enrichment import ThreatIntelligenceEnricher
from src.alerts.alert_models import Alert


@pytest.fixture
def local_provider():
    """Create local CTI provider"""
    return LocalThreatIntelligenceProvider()


@pytest.fixture
def enricher():
    """Create threat intelligence enricher"""
    return ThreatIntelligenceEnricher()


@pytest.fixture
def malicious_alert():
    """Create alert with malicious indicators"""
    return Alert(
        threat_type="PORT_SCAN",
        source_ip="10.0.0.1",  # Malicious IP
        destination_ip="192.168.1.100",
        severity="HIGH",
        risk_score=70.0,
        confidence=0.7,
        detector="test"
    )


@pytest.fixture
def benign_alert():
    """Create alert with benign indicators"""
    return Alert(
        threat_type="PORT_SCAN",
        source_ip="8.8.8.8",  # Benign IP
        destination_ip="1.1.1.1",
        severity="HIGH",
        risk_score=70.0,
        confidence=0.7,
        detector="test"
    )


class TestLocalProvider:
    def test_initialization(self, local_provider):
        """Test provider initialization"""
        assert local_provider is not None
        assert local_provider.name == "LocalCTI"
        assert len(local_provider.malicious_ips) > 0
        assert len(local_provider.malicious_domains) > 0
    
    def test_lookup_malicious_ip(self, local_provider):
        """Test looking up malicious IP"""
        result = local_provider.lookup_ip("10.0.0.1")
        
        assert result is not None
        assert isinstance(result, CTIResult)
        assert result.is_malicious == True
        assert result.confidence > 0.5
    
    def test_lookup_benign_ip(self, local_provider):
        """Test looking up benign IP"""
        result = local_provider.lookup_ip("8.8.8.8")
        
        assert result is not None
        assert result.is_malicious == False
        assert result.confidence < 0.5
    
    def test_lookup_malicious_domain(self, local_provider):
        """Test looking up malicious domain"""
        result = local_provider.lookup_domain("malware.example.com")
        
        assert result is not None
        assert result.is_malicious == True
    
    def test_lookup_benign_domain(self, local_provider):
        """Test looking up benign domain"""
        result = local_provider.lookup_domain("google.com")
        
        assert result is not None
        assert result.is_malicious == False
    
    def test_generic_lookup(self, local_provider):
        """Test generic lookup"""
        # IP lookup
        ip_result = local_provider.lookup("10.0.0.1")
        assert ip_result is not None
        assert ip_result.indicator_type == "ip"
        
        # Domain lookup
        domain_result = local_provider.lookup("malware.example.com")
        assert domain_result is not None
        assert domain_result.indicator_type == "domain"


class TestCTIResult:
    def test_to_dict(self):
        """Test CTI result serialization"""
        result = CTIResult(
            indicator="10.0.0.1",
            indicator_type="ip",
            is_malicious=True,
            confidence=0.9,
            source="test"
        )
        
        result_dict = result.to_dict()
        
        assert result_dict['indicator'] == "10.0.0.1"
        assert result_dict['is_malicious'] == True
        assert result_dict['confidence'] == 0.9


class TestEnricher:
    def test_initialization(self, enricher):
        """Test enricher initialization"""
        assert enricher is not None
        assert enricher.enabled == True
        assert len(enricher.providers) > 0
    
    def test_enrich_malicious_alert(self, enricher, malicious_alert):
        """Test enriching alert with malicious IP"""
        original_score = malicious_alert.risk_score
        
        enriched = enricher.enrich_alert(malicious_alert)
        
        assert enriched.details["cti_risk_contribution"] > 0
        assert enriched.cti_score == enriched.details["cti_risk_contribution"]
        assert 'cti_source_malicious' in enriched.details
        assert enriched.details['cti_source_malicious'] == True
    
    def test_enrich_benign_alert(self, enricher, benign_alert):
        """Test enriching alert with benign IP"""
        original_score = benign_alert.risk_score
        
        enriched = enricher.enrich_alert(benign_alert)
        
        # Score should not increase significantly
        assert enriched.risk_score <= original_score + 1
    
    def test_lookup_indicator(self, enricher):
        """Test looking up indicator"""
        result = enricher.lookup_indicator("10.0.0.1", "ip")
        
        assert result is not None
        assert result.is_malicious == True
    
    def test_lookup_caching(self, enricher):
        """Test lookup caching"""
        # First lookup
        result1 = enricher.lookup_indicator("10.0.0.1", "ip")
        
        # Second lookup (should use cache)
        result2 = enricher.lookup_indicator("10.0.0.1", "ip")
        
        assert result1 is not None
        assert result2 is not None
        assert result1.is_malicious == result2.is_malicious
    
    def test_batch_enrich(self, enricher, malicious_alert, benign_alert):
        """Test batch enrichment"""
        alerts = [malicious_alert, benign_alert]
        
        enriched = enricher.batch_enrich(alerts)
        
        assert len(enriched) == 2
        assert enriched[0].details.get('cti_source_malicious') == True
        assert enriched[1].details.get('cti_source_malicious') is None
    
    def test_provider_status(self, enricher):
        """Test provider status"""
        status = enricher.get_provider_status()
        
        assert isinstance(status, dict)
        assert len(status) > 0
        
        for provider_name, provider_status in status.items():
            if provider_name == "_rate_limiter":
                assert "max_requests" in provider_status
                continue
            assert 'enabled' in provider_status or 'available' in provider_status
            assert 'available' in provider_status
    
    def test_clear_cache(self, enricher):
        """Test clearing cache"""
        # Populate cache
        enricher.lookup_indicator("10.0.0.1", "ip")
        assert len(enricher.cache) > 0
        
        # Clear cache
        enricher.clear_cache()
        assert len(enricher.cache) == 0


class TestOfflineOperation:
    def test_no_network_required(self):
        """Test that local provider works without network"""
        provider = LocalThreatIntelligenceProvider()
        
        # This should work without any network access
        result = provider.lookup_ip("10.0.0.1")
        assert result is not None
        assert result.is_malicious == True
    
    def test_enricher_offline(self):
        """Test enricher works offline"""
        enricher = ThreatIntelligenceEnricher()
        
        alert = Alert(
            threat_type="TEST",
            source_ip="10.0.0.1",
            destination_ip="8.8.8.8",
            severity="LOW",
            risk_score=10.0,
            confidence=0.1,
            detector="test"
        )
        
        # Enrichment should work without network
        enriched = enricher.enrich_alert(alert)
        
        assert enriched is not None
        assert enriched.details["cti_risk_contribution"] > 0
        assert enriched.cti_status in {"CHECKED", "CACHE_HIT"}
        