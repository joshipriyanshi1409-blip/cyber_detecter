"""
Tests for NFStream flow extraction
"""

import pytest
import time
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, wrpcap

from src.flow.nfstream_wrapper import FlowExtractor, FlowRecord
from src.flow.flow_analyzer import FlowAnalyzer


@pytest.fixture
def sample_pcap_with_flows(tmp_path):
    """Create a PCAP file with multiple flows"""
    packets = []
    
    # Flow 1: HTTP traffic (192.168.1.100 -> 93.184.216.34)
    for i in range(20):
        packet = Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(
            sport=12345 + i, dport=80
        )
        packet.time = time.time() - (20 - i) * 0.1
        packets.append(packet)
    
    # Flow 2: HTTPS traffic (192.168.1.100 -> 8.8.8.8)
    for i in range(15):
        packet = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/TCP(
            sport=23456 + i, dport=443
        )
        packet.time = time.time() - (15 - i) * 0.1
        packets.append(packet)
    
    # Flow 3: DNS traffic (192.168.1.100 -> 1.1.1.1)
    for i in range(10):
        packet = Ether()/IP(src="192.168.1.100", dst="1.1.1.1")/UDP(
            sport=34567 + i, dport=53
        )
        packet.time = time.time() - (10 - i) * 0.1
        packets.append(packet)
    
    # Save to PCAP
    pcap_file = tmp_path / "flows.pcap"
    wrpcap(str(pcap_file), packets)
    
    return pcap_file


@pytest.fixture
def flow_extractor(sample_pcap_with_flows):
    """Create and populate flow extractor"""
    extractor = FlowExtractor()
    flows = extractor.extract_from_pcap(str(sample_pcap_with_flows))
    return extractor


def test_extract_flows(sample_pcap_with_flows):
    """Test basic flow extraction"""
    extractor = FlowExtractor()
    flows = extractor.extract_from_pcap(str(sample_pcap_with_flows))
    
    assert len(flows) > 0
    assert all(isinstance(flow, FlowRecord) for flow in flows)


def test_flow_5tuple(sample_pcap_with_flows):
    """Test 5-tuple extraction"""
    extractor = FlowExtractor()
    flows = extractor.extract_from_pcap(str(sample_pcap_with_flows))
    
    for flow in flows:
        # Check 5-tuple components
        assert flow.source_ip != ''
        assert flow.destination_ip != ''
        assert flow.source_port >= 0
        assert flow.destination_port >= 0
        assert flow.protocol in [1, 6, 17]  # ICMP, TCP, UDP
        
        # Check 5-tuple method
        tuple_5 = flow.get_5tuple()
        assert len(tuple_5) == 5
        assert tuple_5[0] == flow.source_ip
        assert tuple_5[1] == flow.destination_ip
        assert tuple_5[2] == flow.source_port
        assert tuple_5[3] == flow.destination_port
        assert tuple_5[4] == flow.protocol


def test_flow_statistics(sample_pcap_with_flows):
    """Test flow statistics extraction"""
    extractor = FlowExtractor()
    flows = extractor.extract_from_pcap(str(sample_pcap_with_flows))
    
    for flow in flows:
        # Check basic statistics
        assert flow.bidirectional_packets > 0
        assert flow.bidirectional_bytes > 0
        assert flow.bidirectional_duration_ms >= 0
        
        # Check directional stats
        assert flow.src2dst_packets > 0
        assert flow.src2dst_bytes > 0
        assert flow.dst2src_packets >= 0
        assert flow.dst2src_bytes >= 0


def test_flow_calculations(sample_pcap_with_flows):
    """Test flow rate calculations"""
    extractor = FlowExtractor()
    flows = extractor.extract_from_pcap(str(sample_pcap_with_flows))
    
    for flow in flows:
        # Test packets per second
        pps = flow.get_packets_per_second()
        assert pps >= 0
        
        # Test bytes per second
        bps = flow.get_bytes_per_second()
        assert bps >= 0
        
        # Test SYN ratio
        syn_ratio = flow.get_syn_ratio()
        assert 0 <= syn_ratio <= 1


def test_flow_dataframe_conversion(flow_extractor):
    """Test conversion to DataFrame"""
    df = flow_extractor.get_flows_dataframe()
    
    assert not df.empty
    assert 'source_ip' in df.columns
    assert 'destination_ip' in df.columns
    assert 'bidirectional_packets' in df.columns


def test_flow_statistics_summary(flow_extractor):
    """Test flow statistics summary"""
    stats = flow_extractor.get_flow_statistics()
    
    assert stats['total_flows'] > 0
    assert stats['total_packets'] > 0
    assert stats['total_bytes'] > 0
    assert stats['unique_sources'] >= 1
    assert stats['unique_destinations'] >= 1
    assert 'TCP' in stats['protocols'] or 'UDP' in stats['protocols']


def test_filter_flows(flow_extractor):
    """Test flow filtering"""
    # Filter by protocol
    tcp_flows = flow_extractor.filter_flows(protocol=6)
    assert all(flow.protocol == 6 for flow in tcp_flows)
    
    # Filter by source IP
    flows_by_source = flow_extractor.filter_flows(source_ip="192.168.1.100")
    assert all(flow.source_ip == "192.168.1.100" for flow in flows_by_source)


def test_flow_analyzer_grouping(flow_extractor):
    """Test flow analyzer grouping"""
    analyzer = FlowAnalyzer(flow_extractor.flows)
    
    # Test grouping by source
    by_source = analyzer.group_by_source()
    assert len(by_source) > 0
    assert "192.168.1.100" in by_source
    
    # Test grouping by destination
    by_dest = analyzer.group_by_destination()
    assert len(by_dest) > 0
    
    # Test grouping by protocol
    by_protocol = analyzer.group_by_protocol()
    assert len(by_protocol) > 0


def test_flow_analyzer_top_talkers(flow_extractor):
    """Test top talkers calculation"""
    analyzer = FlowAnalyzer(flow_extractor.flows)
    top_talkers = analyzer.get_top_talkers(n=5)
    
    assert len(top_talkers) > 0
    assert 'ip' in top_talkers[0]
    assert 'bytes' in top_talkers[0]
    assert 'packets' in top_talkers[0]
    
    # Check sorting
    bytes_list = [t['bytes'] for t in top_talkers]
    assert bytes_list == sorted(bytes_list, reverse=True)


def test_flow_analyzer_port_stats(flow_extractor):
    """Test port statistics"""
    analyzer = FlowAnalyzer(flow_extractor.flows)
    port_stats = analyzer.get_port_statistics()
    
    assert 'unique_source_ports' in port_stats
    assert 'unique_destination_ports' in port_stats
    assert port_stats['unique_source_ports'] > 0
    assert port_stats['unique_destination_ports'] > 0


def test_export_csv(flow_extractor, tmp_path):
    """Test CSV export"""
    csv_file = tmp_path / "flows.csv"
    flow_extractor.export_to_csv(str(csv_file))
    
    assert csv_file.exists()
    assert csv_file.stat().st_size > 0