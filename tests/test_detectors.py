"""
Tests for rule-based detectors
"""

import pytest
import time
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap

from src.detectors.scan import PortScanDetector, PortScanResult
from src.detectors.ddos import DDoSDetector, DDoSResult
from src.detectors.dga import DGADetector, DGAResult
from src.detectors.detector_factory import DetectorFactory, DetectorType
from src.flow.nfstream_wrapper import FlowExtractor, FlowRecord


def create_port_scan_flows(num_ports=50):
    """Create flow records simulating port scan"""
    flows = []
    source_ip = "192.168.1.100"
    target_ip = "192.168.1.200"
    
    for port in range(1, num_ports + 1):
        flow = FlowRecord(
            source_ip=source_ip,
            destination_ip=target_ip,
            source_port=10000 + port,
            destination_port=port,
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
    
    return flows


def create_ddos_flows(num_flows=100):
    """Create flow records simulating DDoS with HIGH packet rates"""
    flows = []
    target_ip = "192.168.1.200"
    
    for i in range(num_flows):
        flow = FlowRecord(
            source_ip=f"10.0.{i//255}.{i%255}",
            destination_ip=target_ip,
            source_port=20000 + i,
            destination_port=80,
            protocol=6,
            bidirectional_packets=1000,  # Increased packet count
            bidirectional_bytes=40000,   # Increased byte count
            bidirectional_duration_ms=100,  # Short duration = high rate
            src2dst_packets=1000,
            src2dst_bytes=40000,
            dst2src_packets=0,
            dst2src_bytes=0,
            bidirectional_first_seen_ms=int(time.time() * 1000),
            bidirectional_last_seen_ms=int(time.time() * 1000) + 100,
            bidirectional_min_ps=0,
            bidirectional_mean_ps=10000,  # 10000 packets per second
            bidirectional_stddev_ps=0,
            bidirectional_max_ps=10000,
            bidirectional_min_piat_ms=0,
            bidirectional_mean_piat_ms=0.1,
            bidirectional_stddev_piat_ms=0,
            bidirectional_max_piat_ms=0.1,
            syn_packets=1000,
            ack_packets=0,
            fin_packets=0,
            rst_packets=0,
            application_name="unknown",
            application_category="unknown",
            timestamp=time.time()
        )
        flows.append(flow)
    
    return flows


def create_normal_flows(num_flows=5):
    """Create normal flow records"""
    flows = []
    for i in range(num_flows):
        flow = FlowRecord(
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            source_port=10000 + i,
            destination_port=80,
            protocol=6,
            bidirectional_packets=10,
            bidirectional_bytes=1000,
            bidirectional_duration_ms=1000,
            src2dst_packets=5,
            src2dst_bytes=500,
            dst2src_packets=5,
            dst2src_bytes=500,
            bidirectional_first_seen_ms=int(time.time() * 1000),
            bidirectional_last_seen_ms=int(time.time() * 1000) + 1000,
            bidirectional_min_ps=0,
            bidirectional_mean_ps=10,
            bidirectional_stddev_ps=0,
            bidirectional_max_ps=10,
            bidirectional_min_piat_ms=0,
            bidirectional_mean_piat_ms=100,
            bidirectional_stddev_piat_ms=0,
            bidirectional_max_piat_ms=100,
            syn_packets=0,
            ack_packets=10,
            fin_packets=1,
            rst_packets=0,
            application_name="HTTP",
            application_category="Web",
            timestamp=time.time()
        )
        flows.append(flow)
    
    return flows


# Test Port Scan Detector
class TestPortScanDetector:
    def test_initialization(self):
        detector = PortScanDetector()
        assert detector is not None
        assert "min_unique_destination_ports" in detector.thresholds
    
    def test_detect_port_scan(self):
        flows = create_port_scan_flows(50)
        detector = PortScanDetector()
        results = detector.detect(flows)
        
        assert len(results) > 0
        assert all(isinstance(r, PortScanResult) for r in results)
        assert all(r.threat_type == "PORT_SCAN" for r in results)
    
    def test_no_scan_detection(self):
        flows = create_normal_flows(5)
        detector = PortScanDetector()
        results = detector.detect(flows)
        assert len(results) == 0
    
    def test_statistics(self):
        flows = create_port_scan_flows(30)
        detector = PortScanDetector()
        stats = detector.get_scan_statistics(flows)
        assert "total_flows" in stats
        assert stats["total_flows"] == 30


# Test DDoS Detector
class TestDDoSDetector:
    def test_initialization(self):
        detector = DDoSDetector()
        assert detector is not None
        assert "min_packets_per_second" in detector.thresholds
    
    def test_detect_ddos(self):
        flows = create_ddos_flows(100)
        detector = DDoSDetector()
        results = detector.detect(flows)
        
        assert len(results) > 0, "DDoS should be detected with high packet rates"
        assert all(isinstance(r, DDoSResult) for r in results)
        assert all(r.threat_type == "DDOS" for r in results)
    
    def test_no_ddos_detection(self):
        flows = create_normal_flows(5)
        detector = DDoSDetector()
        results = detector.detect(flows)
        assert len(results) == 0
    
    def test_statistics(self):
        flows = create_ddos_flows(100)
        detector = DDoSDetector()
        stats = detector.get_flood_statistics(flows)
        assert "packets_per_second" in stats
        assert stats["packets_per_second"] > 1000


# Test DGA Detector
class TestDGADetector:
    def test_initialization(self):
        detector = DGADetector()
        assert detector is not None
        assert "entropy_threshold" in detector.thresholds
    
    def test_detect_dga_domains(self):
        detector = DGADetector()
        dga_domains = [
            "x8j2k9lqpz12345.com",
            "m4n7b2vxwq98765.net",
            "p9q3r7s5t23456.org"
        ]
        
        results = detector.detect_from_domains(dga_domains, "192.168.1.150")
        assert len(results) > 0
    
    def test_no_dga_in_normal_domains(self):
        detector = DGADetector()
        normal_domains = [
            "google.com",
            "facebook.com",
            "amazon.com",
            "microsoft.com"
        ]
        
        results = detector.detect_from_domains(normal_domains, "192.168.1.100")
        assert len(results) == 0, f"Normal domains should not be flagged: {[r.domain for r in results]}"
    
    def test_domain_analysis(self):
        detector = DGADetector()
        result = detector.analyze_domain("x8j2k9lqpz12345.com", "192.168.1.150")
        assert result is not None
        
        normal_result = detector.analyze_domain("google.com", "192.168.1.100")
        assert normal_result is None
    
    def test_statistics(self):
        detector = DGADetector()
        domains = [
            "google.com",
            "x8j2k9lqpz12345.com",
            "facebook.com",
            "m4n7b2vxwq98765.net"
        ]
        
        stats = detector.get_domain_statistics(domains)
        assert stats["total_domains"] == 4


# Test Detector Factory
class TestDetectorFactory:
    def test_initialization(self):
        factory = DetectorFactory()
        assert factory is not None
        assert len(factory.detectors) == 3
    
    def test_get_detector(self):
        factory = DetectorFactory()
        assert isinstance(factory.get_detector(DetectorType.PORT_SCAN), PortScanDetector)
        assert isinstance(factory.get_detector(DetectorType.DDOS), DDoSDetector)
        assert isinstance(factory.get_detector(DetectorType.DGA), DGADetector)
    
    def test_run_all_detectors(self):
        flows = create_port_scan_flows(50)
        factory = DetectorFactory()
        results = factory.run_all_detectors(flows)
        
        assert "port_scan" in results
        assert "ddos" in results
        assert "dga" in results
        assert len(results["port_scan"]) > 0