"""
Tests for Risk Score Calculator
"""

import pytest
import time
from src.scoring.risk_score import RiskScoreCalculator, RiskScoreResult
from src.alerts.alert_models import Alert
from src.detectors.scan import PortScanResult
from src.detectors.ddos import DDoSResult
from src.detectors.dga import DGAResult


@pytest.fixture
def risk_calculator():
    """Create risk score calculator"""
    return RiskScoreCalculator()


@pytest.fixture
def sample_port_scan():
    """Create sample port scan detection"""
    return PortScanResult(
        source_ip="192.168.1.100",
        destination_ip="192.168.1.200",
        confidence=0.8,
        severity="HIGH",
        risk_score=80.0,
        details={"unique_ports": 50}
    )


@pytest.fixture
def sample_ddos():
    """Create sample DDoS detection"""
    return DDoSResult(
        source_ip="multiple_sources",
        destination_ip="192.168.1.200",
        confidence=0.9,
        severity="CRITICAL",
        risk_score=90.0,
        details={"packets_per_second": 5000}
    )


class TestRiskScoreCalculator:
    def test_initialization(self, risk_calculator):
        """Test initialization"""
        assert risk_calculator is not None
        assert "rule_based" in risk_calculator.weights
        assert "anomaly_score" in risk_calculator.weights
        assert "ml_confidence" in risk_calculator.weights
    
    def test_calculate_rule_based_score(self, risk_calculator, sample_port_scan):
        """Test rule-based score calculation"""
        score = risk_calculator.calculate_rule_based_score(sample_port_scan)
        
        assert score > 0
        assert 0 <= score <= 100
    
    def test_calculate_anomaly_score(self, risk_calculator):
        """Test anomaly score calculation"""
        # Low anomaly
        low_score = risk_calculator.calculate_anomaly_score(0.1)
        assert low_score == 10.0
        
        # High anomaly
        high_score = risk_calculator.calculate_anomaly_score(0.9)
        assert high_score == 90.0
        
        # Out of range
        assert risk_calculator.calculate_anomaly_score(1.5) == 100.0
        assert risk_calculator.calculate_anomaly_score(-0.5) == 0.0
    
    def test_calculate_ml_score(self, risk_calculator):
        """Test ML score calculation"""
        # High confidence DDOS
        score = risk_calculator.calculate_ml_score(0.9, "DDOS")
        assert score > 80
        
        # Low confidence NORMAL
        score = risk_calculator.calculate_ml_score(0.1, "NORMAL")
        assert score < 20
    
    def test_calculate_combined_score(self, risk_calculator):
        """Test combined score calculation"""
        result = risk_calculator.calculate_combined_score(
            rule_based_score=80.0,
            anomaly_score=0.7,
            ml_confidence=0.8,
            predicted_class="DDOS"
        )
        
        assert isinstance(result, RiskScoreResult)
        assert 0 <= result.risk_score <= 100
        assert result.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert len(result.evidence_sources) > 0
    
    def test_combined_score_no_evidence(self, risk_calculator):
        """Test combined score with no evidence"""
        result = risk_calculator.calculate_combined_score()
        
        assert result.risk_score == 0.0
        assert result.severity == "LOW"
        assert len(result.evidence_sources) == 0
    
    def test_get_severity(self, risk_calculator):
        """Test severity mapping"""
        assert risk_calculator.get_severity(0) == "LOW"
        assert risk_calculator.get_severity(15) == "LOW"
        assert risk_calculator.get_severity(30) == "LOW"
        assert risk_calculator.get_severity(31) == "MEDIUM"
        assert risk_calculator.get_severity(45) == "MEDIUM"
        assert risk_calculator.get_severity(60) == "MEDIUM"
        assert risk_calculator.get_severity(61) == "HIGH"
        assert risk_calculator.get_severity(70) == "HIGH"
        assert risk_calculator.get_severity(80) == "HIGH"
        assert risk_calculator.get_severity(81) == "CRITICAL"
        assert risk_calculator.get_severity(95) == "CRITICAL"
        assert risk_calculator.get_severity(100) == "CRITICAL"
    
    def test_score_alert(self, risk_calculator):
        """Test scoring an alert"""
        alert = Alert(
            threat_type="DDOS",
            source_ip="10.0.0.1",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=70.0,
            confidence=0.7,
            detector="test"
        )
        
        scored_alert = risk_calculator.score_alert(alert)
        
        assert scored_alert.risk_score >= 0
        assert scored_alert.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert 'risk_breakdown' in scored_alert.details
    
    def test_score_detection(self, risk_calculator, sample_port_scan):
        """Test scoring a detection"""
        result = risk_calculator.score_detection(
            sample_port_scan,
            anomaly_score=0.5,
            ml_prediction={'confidence': 0.7, 'predicted_class': 'PORT_SCAN'}
        )
        
        assert isinstance(result, RiskScoreResult)
        assert result.risk_score > 0
        assert len(result.evidence_sources) >= 2
    
    def test_get_risk_breakdown(self, risk_calculator):
        """Test getting risk breakdown"""
        result = risk_calculator.calculate_combined_score(
            rule_based_score=75.0,
            anomaly_score=0.6
        )
        
        breakdown = risk_calculator.get_risk_breakdown(result)
        
        assert isinstance(breakdown, dict)
        assert 'risk_score' in breakdown
        assert 'severity' in breakdown
        assert 'evidence_sources' in breakdown
        assert 'details' in breakdown
    
    def test_update_weights(self, risk_calculator):
        """Test updating weights"""
        new_weights = {
            "rule_based": 0.5,
            "anomaly_score": 0.3,
            "ml_confidence": 0.2
        }
        
        risk_calculator.update_weights(new_weights)
        
        assert risk_calculator.weights["rule_based"] == 0.5
        assert risk_calculator.weights["anomaly_score"] == 0.3


class TestRiskScoreIntegration:
    def test_full_pipeline(self, risk_calculator, sample_ddos):
        """Test full risk scoring pipeline"""
        # Score the detection
        result = risk_calculator.score_detection(
            sample_ddos,
            anomaly_score=0.8,
            ml_prediction={'confidence': 0.9, 'predicted_class': 'DDOS'}
        )
        
        assert result.risk_score > 70
        assert result.severity in ["HIGH", "CRITICAL"]
        assert "rule_based" in result.evidence_sources
        assert "anomaly_detection" in result.evidence_sources
        assert "machine_learning" in result.evidence_sources
    
    def test_boundary_values(self, risk_calculator):
        """Test boundary values"""
        # Minimum score
        min_result = risk_calculator.calculate_combined_score(
            rule_based_score=0,
            anomaly_score=0,
            ml_confidence=0
        )
        assert min_result.risk_score == 0
        assert min_result.severity == "LOW"
        
        # Maximum score
        max_result = risk_calculator.calculate_combined_score(
            rule_based_score=100,
            anomaly_score=1.0,
            ml_confidence=1.0,
            predicted_class="DDOS"
        )
        assert max_result.risk_score <= 100
        assert max_result.severity == "CRITICAL"
        