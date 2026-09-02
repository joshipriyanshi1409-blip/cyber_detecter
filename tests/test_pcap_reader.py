"""
Tests for PCAP reader module
"""

import pytest
import time
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, wrpcap, rdpcap

from src.ingest.pcap_reader import PcapReaderModule, PacketMetadata, create_sample_pcap


@pytest.fixture
def sample_pcap(tmp_path):
    """Create a sample PCAP file for testing"""
    # Create test packets
    packets = []
    
    # TCP packet
    tcp_packet = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/TCP(sport=12345, dport=80)
    tcp_packet.time = time.time()
    packets.append(tcp_packet)
    
    # UDP packet
    udp_packet = Ether()/IP(src="192.168.1.100", dst="1.1.1.1")/UDP(sport=12346, dport=53)
    udp_packet.time = time.time() + 0.1
    packets.append(udp_packet)
    
    # Another TCP packet
    tcp_packet2 = Ether()/IP(src="10.0.0.5", dst="192.168.1.1")/TCP(sport=54321, dport=443)
    tcp_packet2.time = time.time() + 0.2
    packets.append(tcp_packet2)
    
    # Save to PCAP
    pcap_file = tmp_path / "test.pcap"
    wrpcap(str(pcap_file), packets)
    
    return pcap_file


def test_pcap_reader_initialization(sample_pcap):
    """Test PCAP reader initialization"""
    reader = PcapReaderModule(str(sample_pcap))
    assert reader.filepath == sample_pcap
    assert reader.packet_count == 0


def test_load_packets(sample_pcap):
    """Test loading packets from PCAP"""
    reader = PcapReaderModule(str(sample_pcap))
    packets = reader.load_packets()
    
    assert len(packets) == 3
    assert reader.packet_count == 3


def test_pcap_reader_file_not_found():
    """Test initialization with non-existent file"""
    with pytest.raises(FileNotFoundError):
        PcapReaderModule("nonexistent.pcap")


def test_extract_packet_metadata(sample_pcap):
    """Test packet metadata extraction"""
    reader = PcapReaderModule(str(sample_pcap))
    packets = reader.load_packets()
    
    # Test TCP packet
    metadata = reader.extract_packet_metadata(packets[0])
    assert metadata.source_ip == "192.168.1.100"
    assert metadata.destination_ip == "8.8.8.8"
    assert metadata.source_port == 12345
    assert metadata.destination_port == 80
    assert metadata.protocol == "TCP"
    assert metadata.packet_length > 0
    assert metadata.tcp_flags is not None
    
    # Test UDP packet
    metadata_udp = reader.extract_packet_metadata(packets[1])
    assert metadata_udp.protocol == "UDP"
    assert metadata_udp.source_port == 12346
    assert metadata_udp.destination_port == 53


def test_stream_packets(sample_pcap):
    """Test streaming packets"""
    reader = PcapReaderModule(str(sample_pcap))
    packets = list(reader.stream_packets())
    
    assert len(packets) == 3
    assert reader.packet_count == 3


def test_stream_packets_with_delay(sample_pcap):
    """Test streaming with delay"""
    reader = PcapReaderModule(str(sample_pcap))
    
    start_time = time.time()
    packets = list(reader.stream_packets(delay=0.01))
    elapsed_time = time.time() - start_time
    
    assert len(packets) == 3
    assert elapsed_time >= 0.02  # At least 2 delays of 0.01s


def test_batch_process(sample_pcap):
    """Test batch processing"""
    reader = PcapReaderModule(str(sample_pcap))
    
    def callback(packet):
        """Simple callback that returns packet length"""
        return len(packet)
    
    results = reader.batch_process(callback, batch_size=2)
    
    assert len(results) == 3
    assert all(result > 0 for result in results)


def test_get_statistics(sample_pcap):
    """Test getting PCAP statistics"""
    reader = PcapReaderModule(str(sample_pcap))
    stats = reader.get_statistics()
    
    assert stats["total_packets"] == 3
    assert len(stats["unique_source_ips"]) == 2
    assert len(stats["unique_dest_ips"]) == 3
    assert stats["file_size_bytes"] > 0


def test_create_sample_pcap(tmp_path):
    """Test creating sample PCAP"""
    output_file = tmp_path / "sample.pcap"
    create_sample_pcap(str(output_file), num_packets=10)
    
    assert output_file.exists()
    reader = PcapReaderModule(str(output_file))
    packets = reader.load_packets()
    assert len(packets) == 10


def test_metadata_to_dict(sample_pcap):
    """Test metadata dictionary conversion"""
    reader = PcapReaderModule(str(sample_pcap))
    packets = reader.load_packets()
    
    metadata = reader.extract_packet_metadata(packets[0])
    metadata_dict = metadata.to_dict()
    
    assert isinstance(metadata_dict, dict)
    assert "source_ip" in metadata_dict
    assert "destination_ip" in metadata_dict
    assert "source_port" in metadata_dict
    assert "destination_port" in metadata_dict
    assert "protocol" in metadata_dict
    assert "packet_length" in metadata_dict


def test_get_packet_summary(sample_pcap):
    """Test packet summary generation"""
    reader = PcapReaderModule(str(sample_pcap))
    packets = reader.load_packets()
    
    summary = reader.get_packet_summary(packets[0])
    
    assert isinstance(summary, dict)
    assert summary["source_ip"] == "192.168.1.100"
    assert summary["destination_ip"] == "8.8.8.8"