#!/usr/bin/env python3
"""
Complete Pipeline Runner
Runs the complete threat detection pipeline on a PCAP file.

Usage:
    python scripts/run_pipeline.py <pcap_file> [--output results.json]
"""

import argparse
import logging
import sys
from pathlib import Path
import time
import json

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.streaming.pipeline import ThreatDetectionPipeline

try:
    from src.utils.logging import setup_logging
except ImportError:
    def setup_logging(level="INFO"):
        logging.basicConfig(level=getattr(logging, level.upper()))
        return logging.getLogger()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Run complete threat detection pipeline")
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("--output", default=None, help="Output JSON file")
    parser.add_argument("--models", action="store_true", help="Load ML models if available")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    return parser.parse_args()


def print_results(results):
    """Print pipeline results"""
    print("\n" + "=" * 60)
    print("PIPELINE RESULTS")
    print("=" * 60)
    
    print(f"\nPCAP File: {results.get('pcap_file')}")
    print(f" Flows processed: {results.get('pipeline_stats', {}).get('flows_processed', 0)}")
    print(f" Detections found: {results.get('pipeline_stats', {}).get('detections_found', 0)}")
    print(f" Alerts created: {results.get('pipeline_stats', {}).get('alerts_created', 0)}")
    print(f"Alerts stored: {results.get('pipeline_stats', {}).get('alerts_stored', 0)}")
    
    # Print detections breakdown
    detections = results.get('detections', {})
    if detections:
        print(f"\nDetection Breakdown:")
        for detector_name, detector_results in detections.items():
            print(f"   {detector_name}: {len(detector_results)} detections")
    
    # Print alerts
    alerts = results.get('alerts', [])
    if alerts:
        print(f"\nTop Alerts:")
        for alert in alerts[:5]:
            print(f"   [{alert.severity}] {alert.threat_type} - {alert.source_ip} → {alert.destination_ip}")
            print(f"      Risk: {alert.risk_score:.2f} | Confidence: {alert.confidence:.2f}")
    
    # Print statistics
    stats = results.get('statistics', {})
    if stats.get('database'):
        db_stats = stats['database']
        print(f"\nDatabase Statistics:")
        print(f"   Total alerts: {db_stats.get('total_alerts', 0)}")
        print(f"   Critical: {db_stats.get('critical_count', 0)}")
        print(f"   High: {db_stats.get('high_count', 0)}")


def main():
    """Main pipeline function"""
    args = parse_arguments()
    logger = setup_logging(level=args.log_level)
    
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        logger.error(f"PCAP file not found: {args.pcap_file}")
        return 1
    
    logger.info(f"Starting pipeline for {pcap_path}")
    
    try:
        # Initialize pipeline
        pipeline = ThreatDetectionPipeline()
        
        # Load ML models if requested
        if args.models:
            pipeline.load_models(
                isolation_forest_path='models/isolation_forest.joblib',
                random_forest_path='models/random_forest.joblib'
            )
        
        # Process PCAP
        start_time = time.time()
        results = pipeline.process_pcap(str(pcap_path))
        elapsed_time = time.time() - start_time
        
        # Add elapsed time
        results['pipeline_stats']['elapsed_seconds'] = elapsed_time
        
        # Print results
        print_results(results)
        
        print(f"\nPipeline completed in {elapsed_time:.2f} seconds")

        status = results.get("status", "UNKNOWN")
        if status not in {"OK", "OK_EMPTY"}:
            logger.error("Pipeline returned failure status: %s", status)
            if args.output:
                pipeline.export_results(results, args.output)
            return 2

        # Export if requested
        if args.output:
            pipeline.export_results(results, args.output)
            print(f"Results exported to {args.output}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())