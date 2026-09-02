import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

"""
PCAP Reader Module
Reads network packets from PCAP files using Scapy.
Provides packet iteration, metadata extraction, and batch processing.
"""

import logging
from typing import Dict, Any, Iterator, Optional, List, Generator
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import time

from scapy.all import rdpcap, PcapReader, IP, TCP, UDP, ICMP, DNS, Raw
from scapy.packet import Packet

logger = logging.getLogger(__name__)


@dataclass
class PacketMetadata:
    """Standardized packet metadata structure"""
    timestamp: float
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    packet_length: int
    tcp_flags: Optional[str]
    dns_query: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return asdict(self)


class PcapReaderModule:
    """Reads and processes PCAP files"""
    
    def __init__(self, filepath: str):
        """
        Initialize PCAP reader
        
        Args:
            filepath: Path to PCAP file
        """
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        
        self.packets = None
        self.packet_count = 0
        self.current_packet = None
        
        logger.info(f"Initialized PCAP reader for {self.filepath}")
    
    def load_packets(self) -> List[Packet]:
        """
        Load all packets from PCAP file into memory
        
        Returns:
            List of Scapy packets
        """
        logger.info(f"Loading packets from {self.filepath}")
        
        try:
            self.packets = rdpcap(str(self.filepath))
            self.packet_count = len(self.packets)
            logger.info(f"Loaded {self.packet_count} packets")
            return self.packets
        except Exception as e:
            logger.error(f"Failed to load PCAP file: {e}")
            raise
    
    def stream_packets(self, delay: float = 0.0) -> Iterator[Packet]:
        """
        Stream packets one at a time (for replay capability)
        
        Args:
            delay: Time delay between packets in seconds (0 for no delay)
            
        Yields:
            Individual Scapy packets
        """
        logger.info(f"Streaming packets from {self.filepath}")
        
        try:
            with PcapReader(str(self.filepath)) as pcap_reader:
                for packet in pcap_reader:
                    self.current_packet = packet
                    self.packet_count += 1
                    yield packet
                    
                    if delay > 0:
                        time.sleep(delay)
        
        except Exception as e:
            logger.error(f"Error streaming packets: {e}")
            raise
    
    def extract_packet_metadata(self, packet: Packet) -> PacketMetadata:
        """
        Extract standardized metadata from a Scapy packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            PacketMetadata object with extracted information
        """
        # Initialize with None values
        metadata = PacketMetadata(
            timestamp=float(packet.time),
            source_ip=None,
            destination_ip=None,
            source_port=None,
            destination_port=None,
            protocol="UNKNOWN",
            packet_length=len(packet),
            tcp_flags=None,
            dns_query=None
        )
        
        # Extract IP layer information
        if IP in packet:
            metadata.source_ip = packet[IP].src
            metadata.destination_ip = packet[IP].dst
            metadata.protocol = packet[IP].proto  # Protocol number
            
            # Map protocol numbers to names
            protocol_map = {
                1: "ICMP",
                6: "TCP",
                17: "UDP"
            }
            metadata.protocol = protocol_map.get(packet[IP].proto, f"PROTO_{packet[IP].proto}")
            
            # Extract TCP information
            if TCP in packet:
                metadata.source_port = packet[TCP].sport
                metadata.destination_port = packet[TCP].dport
                metadata.tcp_flags = str(packet[TCP].flags)
                
                # Check for DNS on TCP (rare)
                if packet[TCP].dport == 53 or packet[TCP].sport == 53:
                    if DNS in packet:
                        if packet[DNS].qr == 0:  # Query
                            if packet[DNS].qd:
                                metadata.dns_query = packet[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            
            # Extract UDP information
            elif UDP in packet:
                metadata.source_port = packet[UDP].sport
                metadata.destination_port = packet[UDP].dport
                
                # Check for DNS on UDP
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    if DNS in packet:
                        if packet[DNS].qr == 0:  # Query
                            if packet[DNS].qd:
                                metadata.dns_query = packet[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            
            # Extract ICMP information
            elif ICMP in packet:
                metadata.source_port = None
                metadata.destination_port = None
        
        return metadata
    
    def get_packet_summary(self, packet: Packet) -> Dict[str, Any]:
        """
        Get a human-readable summary of a packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary with packet summary information
        """
        metadata = self.extract_packet_metadata(packet)
        return metadata.to_dict()
    
    def batch_process(self, callback: callable, batch_size: int = 1000) -> List[Any]:
        """
        Process packets in batches with a callback function
        
        Args:
            callback: Function to process each packet
            batch_size: Number of packets per batch
            
        Returns:
            List of results from callback
        """
        results = []
        batch = []
        
        for i, packet in enumerate(self.stream_packets()):
            batch.append(packet)
            
            # Process batch when it reaches batch_size
            if len(batch) >= batch_size:
                for p in batch:
                    result = callback(p)
                    if result is not None:
                        results.append(result)
                batch = []
                
                logger.info(f"Processed {i + 1} packets")
        
        # Process remaining packets
        if batch:
            for p in batch:
                result = callback(p)
                if result is not None:
                    results.append(result)
        
        logger.info(f"Batch processing complete. Total results: {len(results)}")
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get basic statistics about the PCAP file
        
        Returns:
            Dictionary with statistics
        """
        if self.packets is None:
            self.load_packets()
        
        stats = {
            "file_path": str(self.filepath),
            "file_size_bytes": self.filepath.stat().st_size,
            "total_packets": self.packet_count,
            "protocols": {},
            "unique_source_ips": set(),
            "unique_dest_ips": set(),
            "time_start": None,
            "time_end": None
        }
        
        for packet in self.packets:
            if IP in packet:
                # Count protocols
                proto = packet[IP].proto
                stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
                
                # Track IPs
                stats["unique_source_ips"].add(packet[IP].src)
                stats["unique_dest_ips"].add(packet[IP].dst)
                
                # Track time
                if stats["time_start"] is None or packet.time < stats["time_start"]:
                    stats["time_start"] = packet.time
                if stats["time_end"] is None or packet.time > stats["time_end"]:
                    stats["time_end"] = packet.time
        
        # Convert sets to lists for JSON serialization
        stats["unique_source_ips"] = list(stats["unique_source_ips"])
        stats["unique_dest_ips"] = list(stats["unique_dest_ips"])
        
        return stats


class PcapBatchReader:
    """Reads multiple PCAP files from a directory"""
    
    def __init__(self, directory: str):
        """
        Initialize batch reader for a directory of PCAP files
        
        Args:
            directory: Path to directory containing PCAP files
        """
        self.directory = Path(directory)
        if not self.directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        
        self.pcap_files = sorted(self.directory.glob("*.pcap")) + sorted(self.directory.glob("*.pcapng"))
        logger.info(f"Found {len(self.pcap_files)} PCAP files in {directory}")
    
    def process_all(self, callback: callable) -> Dict[str, Any]:
        """
        Process all PCAP files in the directory
        
        Args:
            callback: Function to process each file's packets
            
        Returns:
            Dictionary with results per file
        """
        results = {}
        
        for pcap_file in self.pcap_files:
            logger.info(f"Processing {pcap_file}")
            
            try:
                reader = PcapReaderModule(str(pcap_file))
                results[pcap_file.name] = reader.batch_process(callback)
            except Exception as e:
                logger.error(f"Failed to process {pcap_file}: {e}")
                results[pcap_file.name] = {"error": str(e)}
        
        return results


def create_sample_pcap(output_file: str = "demo/sample_traffic.pcap", num_packets: int = 100):
    """
    Create a sample PCAP file for testing purposes.
    Uses Scapy to generate synthetic packets.
    
    Args:
        output_file: Path to save the PCAP file
        num_packets: Number of packets to generate
    """
    from scapy.all import Ether, IP, TCP, UDP, wrpcap
    import random
    
    logger.info(f"Creating sample PCAP with {num_packets} packets")
    
    packets = []
    sources = ["192.168.1.10", "192.168.1.20", "10.0.0.15", "172.16.0.5"]
    destinations = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1"]
    
    for i in range(num_packets):
        src = random.choice(sources)
        dst = random.choice(destinations)
        sport = random.randint(1024, 65535)
        dport = random.randint(1, 1024)
        
        # Alternate between TCP and UDP
        if i % 2 == 0:
            packet = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport)
        else:
            packet = Ether()/IP(src=src, dst=dst)/UDP(sport=sport, dport=dport)
        
        packet.time = time.time() + i * 0.1  # Set timestamp
        packets.append(packet)
    
    # Save to PCAP
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    
    logger.info(f"Sample PCAP saved to {output_path}")
    return output_path
