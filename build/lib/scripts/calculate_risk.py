#!/usr/bin/env python3
"""
Risk Score Calculation Script
Calculates risk scores for detections and alerts.

Usage:
    python scripts/calculate_risk.py <pcap_file> [--output output.json]
"""

import argparse
import logging
import sys
from pathlib import Path
import json

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.flow.nfstream_wrapper import FlowExtractor
from src.detectors.detector_factory import DetectorFactory
from src.alerts.alert_engine import AlertEngine
from src.scoring.risk_score import RiskScoreCalculator

try:
    from src.utils.logging import setup_logging
except ImportError:
    def setup_logging(level="INFO"):
        logging.basicConfig(level=getattr(logging, level.upper()))
        return logging.getLogger()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Calculate risk scores")
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("--output", default=None, help="Output JSON file")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    return parser.parse_args()


def main():
    """Main risk calculation function"""
    args = parse_arguments()
    logger = setup_logging(level=args.log_level)
    
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        logger.error(f"PCAP file not found: {args.pcap_file}")
        return 1
    
    logger.info(f"Calculating risk scores for {pcap_path}")
    
    try:
        # Extract flows
        logger.info("Extracting flows...")
        extractor = FlowExtractor()
        flows = extractor.extract_from_pcap(str(pcap_path))
        logger.info(f"Extracted {len(flows)} flows")
        
        # Run detectors
        logger.info("Running detectors...")
        factory = DetectorFactory()
        detection_results = factory.run_all_detectors(flows)
        
        # Initialize risk calculator
        risk_calculator = RiskScoreCalculator()
        
        # Process detections and calculate risk scores
        all_results = []
        
        for detector_name, detections in detection_results.items():
            for detection in detections:
                # Calculate risk score
                risk_result = risk_calculator.score_detection(detection)
                
                # Combine detection and risk score
                result = {
                    'detector': detector_name,
                    'detection': detection.to_dict() if hasattr(detection, 'to_dict') else str(detection),
                    'risk_score': risk_result.risk_score,
                    'severity': risk_result.severity,
                    'confidence': risk_result.confidence,
                    'evidence_sources': risk_result.evidence_sources
                }
                
                all_results.append(result)
        
        # Display results
        print("\n" + "=" * 60)
        print("RISK SCORE RESULTS")
        print("=" * 60)
        
        for i, result in enumerate(all_results):
            print(f"\nDetection #{i + 1}:")
            print(f"  Detector: {result['detector']}")
            print(f"  Risk Score: {result['risk_score']}")
            print(f"  Severity: {result['severity']}")
            print(f"  Confidence: {result['confidence']}")
            print(f"  Evidence: {', '.join(result['evidence_sources'])}")
        
        # Save to JSON if requested
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(all_results, f, indent=2, default=str)
            
            logger.info(f"Results saved to {output_path}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Risk calculation failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())