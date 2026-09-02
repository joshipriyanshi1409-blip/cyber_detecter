#!/usr/bin/env python3
"""
PCAP Replay Script
Replays packets from a PCAP file with configurable delay.
Used for testing and demonstration purposes.

Usage:
    python scripts/replay_pcap.py <pcap_file> [--delay 0.1] [--max-packets 100]
"""

import argparse
import logging
import sys
import time
import sys
from pathlib import Path

# Add project root directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.ingest.pcap_reader import PcapReaderModule
from src.utils.logging import setup_logging


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Replay packets from a PCAP file"
    )
    parser.add_argument(
        "pcap_file",
        help="Path to PCAP file to replay"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay between packets in seconds (default: 0.0)"
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Maximum number of packets to replay (default: all)"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: INFO)"
    )
    
    return parser.parse_args()


def print_packet_info(metadata, packet_num):
    """Print formatted packet information"""
    print(f"\nPacket #{packet_num}")
    print(f"  Timestamp: {metadata.timestamp}")
    print(f"  Source: {metadata.source_ip}:{metadata.source_port}")
    print(f"  Destination: {metadata.destination_ip}:{metadata.destination_port}")
    print(f"  Protocol: {metadata.protocol}")
    if metadata.dns_query:
        print(f"  DNS Query: {metadata.dns_query}")


def main():
    """Main replay function"""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(level=args.log_level)
    
    # Validate PCAP file
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        logger.error(f"PCAP file not found: {args.pcap_file}")
        sys.exit(1)
    
    logger.info(f"Starting PCAP replay for {pcap_path}")
    logger.info(f"Delay: {args.delay}s | Max packets: {args.max_packets or 'all'}")
    
    try:
        # Initialize reader
        reader = PcapReaderModule(str(pcap_path))
        
        # Get file statistics first
        stats = reader.get_statistics()
        logger.info(f"Total packets in file: {stats['total_packets']}")
        logger.info(f"Time range: {stats['time_start']} to {stats['time_end']}")
        
        # Stream packets
        packets_replayed = 0
        start_time = time.time()
        
        for packet in reader.stream_packets(delay=args.delay):
            # Check max packets limit
            if args.max_packets and packets_replayed >= args.max_packets:
                logger.info(f"Reached max packets limit ({args.max_packets})")
                break
            
            # Extract metadata
            metadata = reader.extract_packet_metadata(packet)
            
            # Display packet info
            print_packet_info(metadata, packets_replayed + 1)
            
            packets_replayed += 1
            
            # Log progress every 10 packets
            if packets_replayed % 10 == 0:
                logger.info(f"Replayed {packets_replayed} packets")
        
        # Calculate statistics
        elapsed_time = time.time() - start_time
        replay_rate = packets_replayed / elapsed_time if elapsed_time > 0 else 0
        
        logger.info("\n" + "=" * 50)
        logger.info("REPLAY COMPLETE")
        logger.info("=" * 50)
        logger.info(f"Total packets replayed: {packets_replayed}")
        logger.info(f"Elapsed time: {elapsed_time:.2f} seconds")
        logger.info(f"Replay rate: {replay_rate:.2f} packets/second")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("\nReplay interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Error during replay: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())