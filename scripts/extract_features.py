#!/usr/bin/env python3
"""
Feature Extraction Script
Extracts features from PCAP files and displays/saves results.

Usage:
    python scripts/extract_features.py <pcap_file> [--output output.json]
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.flow.nfstream_wrapper import FlowExtractor
from src.features.network_features import FeaturePipeline, NetworkFeatureExtractor
from src.utils.logging import setup_logging


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Extract features from PCAP file"
    )
    parser.add_argument(
        "pcap_file",
        help="Path to PCAP file"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON file path"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )
    
    return parser.parse_args()


def print_features(features, indent=0):
    """Print features in readable format"""
    prefix = "  " * indent
    
    if isinstance(features, dict):
        for key, value in features.items():
            if isinstance(value, (dict, list)):
                print(f"{prefix}{key}:")
                print_features(value, indent + 1)
            else:
                print(f"{prefix}{key}: {value}")
    elif isinstance(features, list):
        if features and isinstance(features[0], dict):
            # Print first few items
            for i, item in enumerate(features[:3]):
                print(f"{prefix}Item {i + 1}:")
                print_features(item, indent + 1)
            if len(features) > 3:
                print(f"{prefix}... ({len(features)} total items)")
        else:
            print(f"{prefix}{features}")


def main():
    """Main feature extraction function"""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(level=args.log_level)
    
    # Validate PCAP file
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        logger.error(f"PCAP file not found: {args.pcap_file}")
        sys.exit(1)
    
    logger.info(f"Extracting features from {pcap_path}")
    
    try:
        # Extract flows
        flow_extractor = FlowExtractor()
        flows = flow_extractor.extract_from_pcap(str(pcap_path))
        
        logger.info(f"Extracted {len(flows)} flows")
        
        # Create feature pipeline
        pipeline = FeaturePipeline()
        
        # Process flows
        features = pipeline.process_flows(flows)
        
        # Display results
        print("\n" + "=" * 60)
        print("FEATURE EXTRACTION RESULTS")
        print("=" * 60)
        
        print("\nAggregate Features:")
        print_features(features["aggregate_features"])
        
        print("\nDetection Features:")
        print_features(features["detection_features"])
        
        print("\nSample Flow Features (first 3):")
        for i, flow_features in enumerate(features["flow_features"][:3]):
            print(f"\nFlow {i + 1}:")
            print_features(flow_features)
        
        # Save to JSON if requested
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert to JSON-serializable format
            json_features = features.copy()
            
            with open(output_path, 'w') as f:
                json.dump(json_features, f, indent=2, default=str)
            
            logger.info(f"Features saved to {output_path}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Feature extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())