"""
Tests for feature engineering modules
"""

import pytest
import math
import time
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap

from src.features.rate import RateCalculator, FlowRateCalculator
from src.features.entropy import EntropyCalculator, DomainEntropyAnalyzer
from src.features.network_features import NetworkFeatureExtractor, FeaturePipeline
from src.flow.nfstream_wrapper import FlowExtractor, FlowRecord


@pytest.fixture
def sample_flows_pcap(tmp_path):
    """Create PCAP with known flows"""
    packets = []
    
    # Create TCP flow
    for i in range(10):
        packet = Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(
            sport=12345, dport=80, flags="S" if i == 0 else "A"
        )
        packet.time = time.time() - (10 - i) * 0.1
        packets.append(packet)
    
    # Create UDP flow with DNS
    for i in range(5):
        dns_query = DNSQR(qname="example.com")
        packet = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(
            sport=12346, dport=53
        )/DNS(qd=dns_query)
        packet.time = time.time() - (5 - i) * 0.1
        packets.append(packet)
    
    pcap_file = tmp_path / "features.pcap"
    wrpcap(str(pcap_file), packets)
    return pcap_file


@pytest.fixture
def extracted_flows(sample_flows_pcap):
    """Extract flows from sample PCAP"""
    extractor = FlowExtractor()
    return extractor.extract_from_pcap(str(sample_flows_pcap))


# Test Rate Calculator
class TestRateCalculator:
    def test_initialization(self):
        calc = RateCalculator(window_size=10)
        assert calc.window_size == 10
        assert calc.get_packets_per_second() == 0
        assert calc.get_bytes_per_second() == 0
    
    def test_add_packets(self):
        calc = RateCalculator(window_size=10)
        
        # Add packets
        calc.add_packet(100, timestamp=0)
        calc.add_packet(100, timestamp=1)
        calc.add_packet(100, timestamp=2)
        
        assert calc.total_packets == 3
        assert calc.total_bytes == 300
    
    def test_packets_per_second(self):
        calc = RateCalculator(window_size=10)
        
        # Add packets over 2 seconds
        calc.add_packet(100, timestamp=0)
        calc.add_packet(100, timestamp=1)
        calc.add_packet(100, timestamp=2)
        
        pps = calc.get_packets_per_second()
        assert pps == 1.5  # 3 packets / 2 seconds
    
    def test_bytes_per_second(self):
        calc = RateCalculator(window_size=10)
        
        # Add packets with known sizes
        calc.add_packet(100, timestamp=0)
        calc.add_packet(200, timestamp=1)
        
        bps = calc.get_bytes_per_second()
        assert bps == 300  # 300 bytes / 1 second
    
    def test_window_cleanup(self):
        calc = RateCalculator(window_size=2)
        
        # Add packets
        calc.add_packet(100, timestamp=0)
        calc.add_packet(100, timestamp=5)  # Should trigger cleanup
        
        assert calc.total_packets == 1
    
    def test_burstiness(self):
        calc = RateCalculator(window_size=10)
        
        # Regular traffic
        calc.add_packet(100, timestamp=0)
        calc.add_packet(100, timestamp=1)
        calc.add_packet(100, timestamp=2)
        
        burstiness = calc.get_burstiness()
        assert burstiness >= 0


# Test Entropy Calculator
class TestEntropyCalculator:
    def test_empty_string(self):
        assert EntropyCalculator.shannon_entropy("") == 0
    
    def test_single_char(self):
        assert EntropyCalculator.shannon_entropy("a") == 0
    
    def test_uniform_distribution(self):
        # "ab" has one 'a' and one 'b'
        entropy = EntropyCalculator.shannon_entropy("ab")
        assert entropy == pytest.approx(1.0, abs=0.01)  # 1 bit for 2 equally likely chars
    
    def test_biased_distribution(self):
        # "aaa" has only 'a'
        entropy = EntropyCalculator.shannon_entropy("aaa")
        assert entropy == 0
    
    def test_normalized_entropy(self):
        # Random string should have high normalized entropy
        entropy = EntropyCalculator.normalized_entropy("x7k2m9p4q")
        assert 0 <= entropy <= 1
    
    def test_digit_ratio(self):
        assert DomainEntropyAnalyzer.calculate_digit_ratio("abc123") == 0.5
        assert DomainEntropyAnalyzer.calculate_digit_ratio("abc") == 0
        assert DomainEntropyAnalyzer.calculate_digit_ratio("123") == 1


# Test Domain Analyzer
class TestDomainAnalyzer:
    def setup_method(self):
        self.analyzer = DomainEntropyAnalyzer()
    
    def test_normal_domain(self):
        features = self.analyzer.analyze_domain("example.com")
        
        assert features["length"] == 11
        assert features["entropy"] > 0
        assert features["has_digits"] == False
        assert features["is_common_tld"] == True
    
    def test_dga_like_domain(self):
        features = self.analyzer.analyze_domain("x8j2k9lqpz.example.com")
        
        assert features["length"] > 20
        assert features["has_digits"] == True
        assert features["digit_ratio"] > 0
        assert features["entropy"] > 3  # High entropy for DGA
    
    def test_clean_domain(self):
        # Test with protocol
        features = self.analyzer.analyze_domain("http://example.com/path")
        assert features["domain"] == "example.com"
    
    def test_ngram_features(self):
        features = self.analyzer.calculate_ngram_features("example")
        
        assert "ngram_score" in features
        assert "unique_ngrams" in features
        assert features["unique_ngrams"] > 0


# Test Network Feature Extractor
class TestNetworkFeatureExtractor:
    def test_extract_flow_features(self, extracted_flows):
        extractor = NetworkFeatureExtractor()
        
        for flow in extracted_flows:
            features = extractor.extract_flow_features(flow)
            
            # Check required features exist
            assert "packet_count" in features
            assert "byte_count" in features
            assert "packets_per_second" in features
            assert "bytes_per_second" in features
            assert "syn_ratio" in features
            assert "flow_duration" in features
    
    def test_extract_aggregate_features(self, extracted_flows):
        extractor = NetworkFeatureExtractor()
        features = extractor.extract_aggregate_features(extracted_flows)
        
        assert features["total_flows"] == len(extracted_flows)
        assert features["total_packets"] > 0
        assert features["total_bytes"] > 0
        assert features["unique_sources"] >= 1
        assert features["unique_destinations"] >= 1
    
    def test_extract_detection_features(self, extracted_flows):
        extractor = NetworkFeatureExtractor()
        features = extractor.extract_detection_features(extracted_flows)
        
        assert "port_scan_score" in features
        assert "failed_connection_ratio" in features
        assert "syn_flood_score" in features
        assert "traffic_burstiness" in features
        assert "behavior_anomaly_score" in features
        
        # Check ranges
        assert 0 <= features["port_scan_score"] <= 1
        assert 0 <= features["failed_connection_ratio"] <= 1
        assert 0 <= features["syn_flood_score"] <= 1
    
    def test_empty_flows(self):
        extractor = NetworkFeatureExtractor()
        features = extractor.extract_aggregate_features([])
        
        assert features["total_flows"] == 0
        assert features["total_packets"] == 0


# Test Feature Pipeline
class TestFeaturePipeline:
    def test_process_flows(self, extracted_flows):
        pipeline = FeaturePipeline()
        features = pipeline.process_flows(extracted_flows)
        
        assert "flow_features" in features
        assert "aggregate_features" in features
        assert "detection_features" in features
        assert len(features["flow_features"]) == len(extracted_flows)
    
    def test_process_domain(self):
        pipeline = FeaturePipeline()
        features = pipeline.process_domain("example.com")
        
        assert "entropy" in features
        assert "length" in features
        assert "digit_ratio" in features


# Test edge cases
class TestEdgeCases:
    def test_rate_calculator_no_packets(self):
        calc = RateCalculator()
        assert calc.get_packets_per_second() == 0
        assert calc.get_bytes_per_second() == 0
        assert calc.get_burstiness() == 0
    
    def test_entropy_special_chars(self):
        entropy = EntropyCalculator.shannon_entropy("!@#$%^&*")
        assert entropy > 0
    
    def test_domain_with_numbers(self):
        analyzer = DomainEntropyAnalyzer()
        features = analyzer.analyze_domain("test123.example.com")
        assert features["has_digits"] == True
        assert 0 < features["digit_ratio"] < 1