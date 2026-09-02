#!/usr/bin/env python3
"""
Generate Test PCAP Files
Creates sample PCAP files for testing different detection scenarios.
All traffic is synthetic and safe for testing.

Usage:
    python scripts/generate_test_data.py
"""

import time
import random
import logging
from pathlib import Path
from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, 
    wrpcap, RandIP, RandShort
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get project root
PROJECT_ROOT = Path(__file__).parent.parent
DEMO_DIR = PROJECT_ROOT / "demo"


def generate_normal_traffic(filename="normal.pcap", num_packets=1000):
    """Generate normal network traffic"""
    logger.info(f"Generating normal traffic: {filename}")
    
    packets = []
    servers = ["8.8.8.8", "1.1.1.1", "93.184.216.34"]  # DNS, Cloudflare, example.com
    clients = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
    
    for i in range(num_packets):
        client = random.choice(clients)
        server = random.choice(servers)
        
        # Mix of protocols
        if i % 3 == 0:
            # HTTP traffic
            packet = Ether()/IP(src=client, dst=server)/TCP(sport=RandShort(), dport=80)
        elif i % 3 == 1:
            # HTTPS traffic
            packet = Ether()/IP(src=client, dst=server)/TCP(sport=RandShort(), dport=443)
        else:
            # DNS queries
            dns_query = DNSQR(qname="example.com")
            packet = Ether()/IP(src=client, dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(qd=dns_query)
        
        packet.time = time.time() - (num_packets - i) * 0.01  # Spread over time
        packets.append(packet)
    
    output_file = DEMO_DIR / filename
    output_file.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_file), packets)
    logger.info(f"Saved {num_packets} packets to {output_file}")
    return output_file


def generate_port_scan_traffic(filename="port_scan.pcap", num_ports=100):
    """Generate port scan traffic (synthetic, for testing)"""
    logger.info(f"Generating port scan traffic: {filename}")
    
    packets = []
    source_ip = "192.168.1.200"  # Scanning host
    target_ip = "192.168.1.100"  # Victim host
    
    for i in range(num_ports):
        port = 1 + i  # Scan ports sequentially
        # SYN packets (no response)
        packet = Ether()/IP(src=source_ip, dst=target_ip)/TCP(
            sport=RandShort(), 
            dport=port,
            flags="S"  # SYN flag
        )
        packet.time = time.time() - (num_ports - i) * 0.001
        packets.append(packet)
    
    output_file = DEMO_DIR / filename
    output_file.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_file), packets)
    logger.info(f"Saved {num_ports} packets to {output_file}")
    return output_file


def generate_ddos_traffic(filename="ddos.pcap", num_packets=5000):
    """Generate DDoS-like traffic (synthetic, for testing)"""
    logger.info(f"Generating DDoS traffic: {filename}")
    
    packets = []
    target_ip = "192.168.1.100"  # Victim
    target_port = 80
    
    # Multiple source IPs to simulate botnet
    source_ips = [f"10.0.{i//255}.{i%255}" for i in range(50)]
    
    for i in range(num_packets):
        source = random.choice(source_ips)
        # SYN flood
        packet = Ether()/IP(src=source, dst=target_ip)/TCP(
            sport=RandShort(),
            dport=target_port,
            flags="S"
        )
        packet.time = time.time() - (num_packets - i) * 0.0001  # Very fast
        packets.append(packet)
    
    output_file = DEMO_DIR / filename
    output_file.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_file), packets)
    logger.info(f"Saved {num_packets} packets to {output_file}")
    return output_file


def generate_dga_traffic(filename="dga.pcap", num_queries=200):
    """Generate DGA-like traffic (synthetic, for testing)"""
    logger.info(f"Generating DGA traffic: {filename}")
    
    packets = []
    source_ip = "192.168.1.150"  # Infected host
    dns_server = "8.8.8.8"
    
    # DGA-like domain patterns
    dga_domains = [
        "x8j2k9lqpz.example.com",
        "m4n7b2vxwq.example.org",
        "p9q3r7s5t2.example.net",
        "k7h2j9m4n6.example.com",
        "w5e8r1t9y7.example.biz",
        "a3s6d9f2g5.example.info",
        "z1x4c7v8b2.example.com",
        "q5w8e9r7t1.example.net",
        "h3j6k9l2m5.example.org",
        "t7y8u9i4o2.example.com"
    ]
    
    for i in range(num_queries):
        domain = random.choice(dga_domains)
        dns_query = DNSQR(qname=domain)
        packet = Ether()/IP(src=source_ip, dst=dns_server)/UDP(
            sport=RandShort(),
            dport=53
        )/DNS(qd=dns_query)
        
        packet.time = time.time() - (num_queries - i) * 0.1
        packets.append(packet)
    
    output_file = DEMO_DIR / filename
    output_file.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_file), packets)
    logger.info(f"Saved {num_queries} packets to {output_file}")
    return output_file


def generate_all_test_data():
    """Generate all test PCAP files"""
    logger.info("Generating all test data...")
    
    files = {}
    files["normal"] = generate_normal_traffic()
    files["port_scan"] = generate_port_scan_traffic()
    files["ddos"] = generate_ddos_traffic()
    files["dga"] = generate_dga_traffic()
    
    logger.info("\n" + "=" * 50)
    logger.info("TEST DATA GENERATION COMPLETE")
    logger.info("=" * 50)
    for name, filepath in files.items():
        logger.info(f"{name}: {filepath}")
    
    return files


if __name__ == "__main__":
    generate_all_test_data()