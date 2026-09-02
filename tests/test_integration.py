"""
Integration Tests
Tests the complete pipeline end-to-end.
"""

import pytest
import time
from pathlib import Path
import json

from src.streaming.pipeline import ThreatDetectionPipeline
from src.storage.database import DatabaseManager
from src.blockchain.hash_chain import HashChain
from src.alerts.alert_models import Alert


@pytest.fixture
def pipeline():
    """Create pipeline instance"""
    return ThreatDetectionPipeline()


@pytest.fixture
def sample_pcap(tmp_path):
    """Create sample PCAP for testing"""
    from scapy.all import Ether, IP, TCP, wrpcap
    
    packets = []
    for i in range(50):
        packet = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/TCP(
            sport=10000 + i, dport=i, flags="S"
        )
        packet.time = time.time() - (50 - i) * 0.001
        packets.append(packet)
    
    pcap_file = tmp_path / "test.pcap"
    wrpcap(str(pcap_file), packets)
    return pcap_file


class TestPipeline:
    def test_pipeline_initialization(self, pipeline):
        """Test pipeline initialization"""
        assert pipeline is not None
        assert pipeline.flow_extractor is not None
        assert pipeline.detector_factory is not None
        assert pipeline.alert_processor is not None
        assert pipeline.risk_calculator is not None
        assert pipeline.hash_chain is not None
        assert pipeline.database is not None
    
    def test_pipeline_status(self, pipeline):
        """Test getting pipeline status"""
        status = pipeline.get_pipeline_status()
        
        assert 'stats' in status
        assert 'components' in status
        assert status['components']['flow_extractor'] == True
        assert status['components']['database'] == True
    
    def test_pipeline_process_pcap(self, pipeline, sample_pcap):
        """Test processing PCAP through pipeline"""
        results = pipeline.process_pcap(str(sample_pcap))
        
        assert 'pcap_file' in results
        assert 'flows' in results
        assert 'detections' in results
        assert 'alerts' in results
        assert 'statistics' in results
        
        # Check pipeline stats
        stats = results.get('pipeline_stats', {})
        assert stats.get('flows_processed', 0) > 0
    
    def test_pipeline_export(self, pipeline, sample_pcap, tmp_path):
        """Test exporting pipeline results"""
        results = pipeline.process_pcap(str(sample_pcap))
        
        output_file = tmp_path / "results.json"
        success = pipeline.export_results(results, str(output_file))
        
        assert success == True
        assert output_file.exists()
        
        # Verify JSON content
        with open(output_file, 'r') as f:
            data = json.load(f)
            assert 'alerts' in data
            assert 'statistics' in data


class TestFullIntegration:
    def test_complete_flow(self, tmp_path):
        """Test complete flow from detection to storage"""
        # Create fresh pipeline with test database
        db_path = tmp_path / "test_integration.db"
        chain_path = tmp_path / "test_chain.json"
        
        pipeline = ThreatDetectionPipeline({
            'database_path': str(db_path),
            'hash_chain_file': str(chain_path)
        })
        
        # Create sample alert
        alert = Alert(
            threat_type="PORT_SCAN",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            severity="HIGH",
            risk_score=80.0,
            confidence=0.8,
            detector="test"
        )
        
        # Store in database
        stored = pipeline.database.add_alert(alert)
        assert stored == True
        
        # Add to hash chain
        entry = pipeline.hash_chain.append_alert(alert)
        assert entry is not None
        
        # Verify database
        retrieved = pipeline.database.get_alert(alert.alert_id)
        assert retrieved is not None
        assert retrieved.alert_id == alert.alert_id
        
        # Verify hash chain
        validation = pipeline.hash_chain.validate_chain()
        assert validation['is_valid'] == True
        
        # Verify alert in chain
        alert_validation = pipeline.hash_chain.validate_alert(alert)
        assert alert_validation['is_valid'] == True
    
    def test_tampering_detection_integration(self, tmp_path):
        """Test tampering detection in full flow"""
        chain_path = tmp_path / "test_chain2.json"
        chain = HashChain(str(chain_path))
        
        # Create and add alert
        alert = Alert(
            threat_type="TEST",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            severity="LOW",
            risk_score=10.0,
            confidence=0.1,
            detector="test"
        )
        
        chain.append_alert(alert)
        
        # Modify alert
        modified_alert = Alert(
            alert_id=alert.alert_id,
            timestamp=alert.timestamp,
            threat_type="TEST",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            severity="CRITICAL",  # Modified!
            risk_score=99.0,  # Modified!
            confidence=1.0,  # Modified!
            detector="test"
        )
        
        # Detect tampering
        result = chain.detect_tampering(modified_alert)
        
        assert result['tampering_detected'] == True
        assert result['is_valid'] == False


class TestComponentIntegration:
    def test_detection_to_alert_to_database(self, tmp_path):
        """Test detection → alert → database flow"""
        from src.detectors.scan import PortScanDetector
        from src.flow.nfstream_wrapper import FlowRecord
        from src.alerts.alert_engine import AlertEngine
        
        db_path = tmp_path / "test_flow.db"
        db = DatabaseManager(str(db_path))
        
        # Create flows
        flows = []
        for i in range(20):
            flow = FlowRecord(
                source_ip="192.168.1.100",
                destination_ip="192.168.1.200",
                source_port=10000 + i,
                destination_port=i,
                protocol=6,
                bidirectional_packets=1,
                bidirectional_bytes=40,
                bidirectional_duration_ms=10,
                src2dst_packets=1,
                src2dst_bytes=40,
                dst2src_packets=0,
                dst2src_bytes=0,
                bidirectional_first_seen_ms=int(time.time() * 1000),
                bidirectional_last_seen_ms=int(time.time() * 1000) + 10,
                bidirectional_min_ps=0,
                bidirectional_mean_ps=100,
                bidirectional_stddev_ps=0,
                bidirectional_max_ps=100,
                bidirectional_min_piat_ms=0,
                bidirectional_mean_piat_ms=10,
                bidirectional_stddev_piat_ms=0,
                bidirectional_max_piat_ms=10,
                syn_packets=1,
                ack_packets=0,
                fin_packets=0,
                rst_packets=0,
                application_name="unknown",
                application_category="unknown",
                timestamp=time.time()
            )
            flows.append(flow)
        
        # Detect
        detector = PortScanDetector()
        detections = detector.detect(flows)
        
        assert len(detections) > 0
        
        # Create alert
        engine = AlertEngine()
        alert = engine.process_detection(detections[0])
        
        assert alert is not None
        
        # Store in database
        stored = db.add_alert(alert)
        assert stored == True
        
        # Verify
        retrieved = db.get_alert(alert.alert_id)
        assert retrieved is not None
        assert retrieved.threat_type == "PORT_SCAN"