#!/usr/bin/env python3
"""
Flow Processing Script
Extracts flows from PCAP files and saves results.

Usage:
    python scripts/process_flows.py <pcap_file> [--output output.csv]
"""

import argparse
import logging
import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.flow.nfstream_wrapper import FlowExtractor
from src.utils.logging import setup_logging


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Extract flows from PCAP file"
    )
    parser.add_argument(
        "pcap_file",
        help="Path to PCAP file"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output CSV file path"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )
    
    return parser.parse_args()


def print_flow_details(flow, index):
    """Print formatted flow information"""
    print(f"\nFlow #{index}")
    print(f"  5-tuple: {flow.source_ip}:{flow.source_port} -> "
          f"{flow.destination_ip}:{flow.destination_port} "
          f"(Protocol: {flow.protocol})")
    print(f"  Packets: {flow.bidirectional_packets}")
    print(f"  Bytes: {flow.bidirectional_bytes}")
    print(f"  Duration: {flow.bidirectional_duration_ms} ms")
    print(f"  Packets/sec: {flow.get_packets_per_second():.2f}")
    print(f"  Bytes/sec: {flow.get_bytes_per_second():.2f}")
    print(f"  Application: {flow.application_name}")


def main():
    """Main flow processing function"""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(level=args.log_level)
    
    # Validate PCAP file
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        logger.error(f"PCAP file not found: {args.pcap_file}")
        sys.exit(1)
    
    logger.info(f"Processing flows from {pcap_path}")
    
    try:
        # Initialize extractor
        extractor = FlowExtractor()
        
        # Extract flows
        flows = extractor.extract_from_pcap(str(pcap_path))
        
        # Display flow statistics
        stats = extractor.get_flow_statistics()
        
        print("\n" + "=" * 50)
        print("FLOW EXTRACTION RESULTS")
        print("=" * 50)
        print(f"Total Flows: {stats['total_flows']}")
        print(f"Total Packets: {stats['total_packets']}")
        print(f"Total Bytes: {stats['total_bytes']}")
        print(f"Average Duration: {stats['avg_duration_ms']:.2f} ms")
        print(f"Unique Sources: {stats['unique_sources']}")
        print(f"Unique Destinations: {stats['unique_destinations']}")
        
        print("\nProtocol Distribution:")
        for proto, count in stats['protocols'].items():
            print(f"  {proto}: {count}")
        
        print("\nApplication Distribution:")
        for app, count in list(stats['applications'].items())[:10]:
            print(f"  {app}: {count}")
        
        # Show first few flows
        print("\nFirst 5 Flows:")
        for i, flow in enumerate(flows[:5]):
            print_flow_details(flow, i + 1)
        
        # Export if requested
        if args.output:
            extractor.export_to_csv(args.output)
            print(f"\nFlows exported to {args.output}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Flow processing failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
    