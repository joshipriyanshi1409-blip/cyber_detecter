#!/usr/bin/env python3
"""
Alert Management Script
Process detections and manage alerts.

Usage:
    python scripts/manage_alerts.py <pcap_file>
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
from src.alerts.alert_engine import AlertEngine, AlertProcessor
from src.alerts.alert_validator import AlertValidator
from src.alerts.alert_models import Alert, AlertBatch

try:
    from src.utils.logging import setup_logging
except ImportError:
    def setup_logging(level="INFO"):
        logging.basicConfig(level=getattr(logging, level.upper()))
        return logging.getLogger()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Process detections and manage alerts"
    )
    parser.add_argument(
        "pcap_file",
        help="Path to PCAP file"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON file for alerts"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )
    
    return parser.parse_args()


def print_alert(alert, index):
    """Print alert in readable format"""
    print(f"\nAlert #{index}")
    print(f"  ID: {alert.alert_id}")
    print(f"  Timestamp: {alert.timestamp}")
    print(f"  Type: {alert.threat_type}")
    print(f"  Category: {alert.category}")
    print(f"  Severity: {alert.severity}")
    print(f"  Risk Score: {alert.risk_score:.2f}")
    print(f"  Confidence: {alert.confidence:.2f}")
    print(f"  Source: {alert.source_ip}")
    print(f"  Destination: {alert.destination_ip}")
    print(f"  Detector: {alert.detector}")
    print(f"  Status: {alert.status}")
    print(f"  Description: {alert.description}")
    
    if alert.details:
        print(f"  Details:")
        for key, value in alert.details.items():
            print(f"    {key}: {value}")


def main():
    """Main alert management function"""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(level=args.log_level)
    
    # Validate PCAP file
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        logger.error(f"PCAP file not found: {args.pcap_file}")
        sys.exit(1)
    
    logger.info(f"Processing alerts from {pcap_path}")
    
    try:
        # Extract flows
        logger.info("Extracting flows...")
        flow_extractor = FlowExtractor()
        flows = flow_extractor.extract_from_pcap(str(pcap_path))
        logger.info(f"Extracted {len(flows)} flows")
        
        # Run detectors
        logger.info("Running detectors...")
        detector_factory = DetectorFactory()
        detection_results = detector_factory.run_all_detectors(flows)
        
        # Process alerts
        logger.info("Processing alerts...")
        alert_processor = AlertProcessor()
        alerts = alert_processor.process_detection_results(detection_results)
        
        # Validate alerts
        logger.info("Validating alerts...")
        validator = AlertValidator()
        validation_summary = validator.validate_alerts(alerts)
        
        # Display results
        print("\n" + "=" * 60)
        print("ALERT PROCESSING RESULTS")
        print("=" * 60)
        
        print(f"\nTotal Alerts: {len(alerts)}")
        print(f"Valid Alerts: {validation_summary['valid_alerts']}")
        print(f"Invalid Alerts: {validation_summary['invalid_alerts']}")
        
        if validation_summary['warnings']:
            print(f"\nWarnings:")
            for warning in validation_summary['warnings'][:5]:
                print(f"  - {warning}")
        
        # Print alerts
        print("\n" + "=" * 60)
        print("ALERT DETAILS")
        print("=" * 60)
        
        for i, alert in enumerate(alerts):
            print_alert(alert, i + 1)
        
        # Get statistics
        alert_engine = AlertEngine()
        stats = alert_engine.get_statistics(alerts)
        
        print("\n" + "=" * 60)
        print("ALERT STATISTICS")
        print("=" * 60)
        
        print(f"\nTotal Alerts: {stats['total_alerts']}")
        print(f"Average Risk Score: {stats['average_risk_score']:.2f}")
        print(f"Average Confidence: {stats['average_confidence']:.2f}")
        
        print(f"\nBy Severity:")
        for severity, count in stats['by_severity'].items():
            print(f"  {severity}: {count}")
        
        print(f"\nBy Threat Type:")
        for threat_type, count in stats['by_type'].items():
            print(f"  {threat_type}: {count}")
        
        # Save to JSON if requested
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            alert_data = {
                "alerts": [alert.to_dict() for alert in alerts],
                "statistics": stats,
                "validation": validation_summary
            }
            
            with open(output_path, 'w') as f:
                json.dump(alert_data, f, indent=2, default=str)
            
            logger.info(f"Alerts saved to {output_path}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Alert processing failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
    