"""
Tests for SHA-256 Hash Chain
"""

import pytest
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

from src.blockchain.hash_chain import HashChain, HashChainEntry
from src.alerts.alert_models import Alert


@pytest.fixture
def hash_chain():
    """Create hash chain"""
    return HashChain()


@pytest.fixture
def hash_chain_with_file(tmp_path):
    """Create hash chain with file storage"""
    chain_file = tmp_path / "test_chain.json"
    return HashChain(str(chain_file))


@pytest.fixture
def sample_alerts():
    """Create sample alerts"""
    alerts = []
    for i in range(5):
        alert = Alert(
            threat_type="TEST",
            source_ip=f"192.168.1.{i}",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test",
            details={'index': i}
        )
        alerts.append(alert)
    return alerts


class TestHashChain:
    def test_initialization(self, hash_chain):
        """Test initialization"""
        assert hash_chain is not None
        assert len(hash_chain.chain) == 0
    
    def test_calculate_hash(self, hash_chain):
        """Test hash calculation"""
        hash1 = hash_chain.calculate_hash("test data")
        hash2 = hash_chain.calculate_hash("test data")
        hash3 = hash_chain.calculate_hash("different data")
        
        assert hash1 == hash2  # Same input = same hash
        assert hash1 != hash3  # Different input = different hash
        assert len(hash1) == 64  # SHA-256 produces 64 character hex
    
    def test_append_alert(self, hash_chain, sample_alerts):
        """Test appending alert"""
        alert = sample_alerts[0]
        entry = hash_chain.append_alert(alert)
        
        assert entry is not None
        assert entry.index == 0
        assert entry.alert_id == alert.alert_id
        assert len(entry.current_hash) == 64
        assert len(hash_chain.chain) == 1
    
    def test_append_multiple_alerts(self, hash_chain, sample_alerts):
        """Test appending multiple alerts"""
        count = hash_chain.append_alerts(sample_alerts)
        
        assert count == len(sample_alerts)
        assert len(hash_chain.chain) == len(sample_alerts)
    
    def test_chain_linking(self, hash_chain, sample_alerts):
        """Test that entries are properly linked"""
        hash_chain.append_alerts(sample_alerts)
        
        for i in range(1, len(hash_chain.chain)):
            current = hash_chain.chain[i]
            previous = hash_chain.chain[i - 1]
            
            assert current.previous_hash == previous.current_hash
    
    def test_get_last_hash(self, hash_chain, sample_alerts):
        """Test getting last hash"""
        assert hash_chain.get_last_hash() is None  # Empty chain
        
        hash_chain.append_alert(sample_alerts[0])
        assert hash_chain.get_last_hash() is not None
        assert len(hash_chain.get_last_hash()) == 64
    
    def test_validate_chain(self, hash_chain, sample_alerts):
        """Test chain validation"""
        hash_chain.append_alerts(sample_alerts)
        
        validation = hash_chain.validate_chain()
        
        assert validation['is_valid'] == True
        assert validation['total_entries'] == len(sample_alerts)
        assert validation['valid_entries'] == len(sample_alerts)
    
    def test_validate_alert(self, hash_chain, sample_alerts):
        """Test alert validation"""
        alert = sample_alerts[0]
        hash_chain.append_alert(alert)
        
        result = hash_chain.validate_alert(alert)
        
        assert result['is_valid'] == True
        assert result['alert_id'] == alert.alert_id
    
    def test_detect_tampering(self, hash_chain, sample_alerts):
        """Test tampering detection"""
        original_alert = sample_alerts[0]
        hash_chain.append_alert(original_alert)
        
        # Create modified alert
        modified_alert = Alert(
            alert_id=original_alert.alert_id,
            timestamp=original_alert.timestamp,
            threat_type=original_alert.threat_type,
            source_ip=original_alert.source_ip,
            destination_ip=original_alert.destination_ip,
            severity=original_alert.severity,
            risk_score=99.0,  # Modified value
            confidence=original_alert.confidence,
            detector=original_alert.detector
        )
        
        result = hash_chain.detect_tampering(modified_alert)
        
        assert result['tampering_detected'] == True
        assert result['is_valid'] == False
    
    def test_chain_file_persistence(self, hash_chain_with_file, sample_alerts):
        """Test chain file persistence"""
        hash_chain_with_file.append_alerts(sample_alerts)
        
        # Verify file exists
        assert hash_chain_with_file.chain_path.exists()
        
        # Load new chain from same file
        new_chain = HashChain(str(hash_chain_with_file.chain_path))
        
        assert len(new_chain.chain) == len(sample_alerts)
    
    def test_export_chain(self, hash_chain, sample_alerts, tmp_path):
        """Test chain export"""
        hash_chain.append_alerts(sample_alerts)
        
        export_path = tmp_path / "exported_chain.json"
        result = hash_chain.export_chain(str(export_path))
        
        assert result == True
        assert export_path.exists()
        
        # Verify exported data
        with open(export_path, 'r') as f:
            data = json.load(f)
            assert 'chain' in data
            assert len(data['chain']) == len(sample_alerts)
    
    def test_clear_chain(self, hash_chain, sample_alerts):
        """Test clearing chain"""
        hash_chain.append_alerts(sample_alerts)
        assert len(hash_chain.chain) > 0
        
        hash_chain.clear_chain()
        assert len(hash_chain.chain) == 0
    
    def test_get_entry_by_alert_id(self, hash_chain, sample_alerts):
        """Test getting entry by alert ID"""
        alert = sample_alerts[0]
        hash_chain.append_alert(alert)
        
        entry = hash_chain.get_entry_by_alert_id(alert.alert_id)
        
        assert entry is not None
        assert entry.alert_id == alert.alert_id


class TestHashChainEntry:
    def test_to_dict(self):
        """Test converting to dictionary"""
        entry = HashChainEntry(
            index=0,
            timestamp="2024-01-01T00:00:00",
            alert_id="test-id",
            data_hash="a" * 64,
            previous_hash="0" * 64,
            current_hash="b" * 64
        )
        
        entry_dict = entry.to_dict()
        
        assert entry_dict['index'] == 0
        assert entry_dict['alert_id'] == "test-id"
        assert len(entry_dict['data_hash']) == 64
    
    def test_to_json(self):
        """Test converting to JSON"""
        entry = HashChainEntry(
            index=0,
            timestamp="2024-01-01T00:00:00",
            alert_id="test-id",
            data_hash="a" * 64,
            previous_hash="0" * 64,
            current_hash="b" * 64
        )
        
        json_str = entry.to_json()
        
        assert isinstance(json_str, str)
        data = json.loads(json_str)
        assert data['index'] == 0
        