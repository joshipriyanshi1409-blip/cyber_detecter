#!/usr/bin/env python3
"""
Run Detection Script
Runs all detectors on PCAP file and displays results.

Usage:
    python scripts/run_detection.py <pcap_file>
"""

import argparse
import logging
import sys
from pathlib import Path
import json

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.flow.nfstream_wrapper import FlowExtractor
from src.detectors.detector_factory import DetectorFactory, DetectorType

# Updated import with fallback
try:
    from src.utils.logging import setup_logging
except ImportError:
    # Fallback to basic logging
    def setup_logging(level="INFO"):
        logging.basicConfig(level=getattr(logging, level.upper()))
        return logging.getLogger()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Run threat detection on PCAP file"
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


def print_detection_results(results):
    """Print detection results in readable format"""
    print("\n" + "=" * 60)
    print("DETECTION RESULTS")
    print("=" * 60)
    
    for detector_type, detections in results.items():
        print(f"\n{detector_type.upper()} Detections: {len(detections)}")
        print("-" * 40)
        
        for i, detection in enumerate(detections):
            print(f"\n  Detection #{i + 1}:")
            detection_dict = detection.to_dict()
            
            for key, value in detection_dict.items():
                if key == 'details':
                    print(f"    {key}: (see below)")
                    for detail_key, detail_value in value.items():
                        print(f"      {detail_key}: {detail_value}")
                else:
                    print(f"    {key}: {value}")


def main():
    """Main detection function"""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(level=args.log_level)
    
    # Validate PCAP file
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        logger.error(f"PCAP file not found: {args.pcap_file}")
        sys.exit(1)
    
    logger.info(f"Running detection on {pcap_path}")
    
    try:
        # Extract flows
        logger.info("Extracting flows...")
        flow_extractor = FlowExtractor()
        flows = flow_extractor.extract_from_pcap(str(pcap_path))
        
        logger.info(f"Extracted {len(flows)} flows")
        
        # Run detectors
        logger.info("Running detectors...")
        detector_factory = DetectorFactory()
        results = detector_factory.run_all_detectors(flows)
        
        # Print results
        print_detection_results(results)
        
        # Save to JSON if requested
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            json_results = {}
            for detector_type, detections in results.items():
                json_results[detector_type] = [
                    detection.to_dict() for detection in detections
                ]
            
            with open(output_path, 'w') as f:
                json.dump(json_results, f, indent=2, default=str)
            
            logger.info(f"Results saved to {output_path}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Detection failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())