#!/usr/bin/env python3
"""
Model Training Script
Trains Isolation Forest and Random Forest models on flow data.

Usage:
    python scripts/train_model.py [--pcap_file <path>] [--model_type <type>]
"""

import argparse
import logging
import sys
from pathlib import Path
import time
import json

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.flow.nfstream_wrapper import FlowExtractor
from src.models.isolation_forest import IsolationForestAnomalyDetector
from src.models.random_forest import RandomForestThreatClassifier

try:
    from src.utils.logging import setup_logging
except ImportError:
    def setup_logging(level="INFO"):
        logging.basicConfig(level=getattr(logging, level.upper()))
        return logging.getLogger()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Train ML models")
    parser.add_argument("--pcap_file", help="PCAP file for training data")
    parser.add_argument("--model_type", choices=["isolation_forest", "random_forest", "both"],
                       default="both", help="Type of model to train")
    parser.add_argument("--output_dir", default="models", help="Output directory for models")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    return parser.parse_args()


def train_isolation_forest(flows, output_dir):
    """Train Isolation Forest model"""
    print("\n" + "=" * 60)
    print("TRAINING ISOLATION FOREST")
    print("=" * 60)
    
    detector = IsolationForestAnomalyDetector(
        contamination=0.1,
        random_state=42,
        n_estimators=100
    )
    
    # Train model
    start_time = time.time()
    detector.fit(flows)
    training_time = time.time() - start_time
    
    print(f"✅ Training completed in {training_time:.2f} seconds")
    
    # Save model
    model_path = Path(output_dir) / "isolation_forest.joblib"
    detector.save_model(str(model_path))
    print(f"✅ Model saved to {model_path}")
    
    # Test predictions
    predictions = detector.predict(flows[:10])
    stats = detector.get_anomaly_statistics(predictions)
    
    print(f"\n📊 Anomaly Statistics (on training data):")
    print(f"   Total flows analyzed: {stats['total_flows']}")
    print(f"   Anomalies detected: {stats['anomalies_detected']}")
    print(f"   Anomaly rate: {stats['anomaly_rate']:.2%}")
    print(f"   Average anomaly score: {stats['avg_anomaly_score']:.3f}")
    
    return detector


def generate_labels(flows):
    """Generate synthetic labels for demonstration"""
    # This is a placeholder - in real scenario, you'd have labeled data
    labels = []
    for flow in flows:
        # Simple heuristic labeling
        if flow.get_packets_per_second() > 100:
            labels.append("DDOS")
        elif flow.get_syn_ratio() > 0.7 and flow.bidirectional_packets < 5:
            labels.append("PORT_SCAN")
        else:
            labels.append("NORMAL")
    return labels


def train_random_forest(flows, output_dir):
    """Train Random Forest model"""
    print("\n" + "=" * 60)
    print("TRAINING RANDOM FOREST")
    print("=" * 60)
    
    # Generate synthetic labels (replace with real labels when available)
    labels = generate_labels(flows)
    
    print(f"📊 Label distribution:")
    from collections import Counter
    label_counts = Counter(labels)
    for label, count in label_counts.items():
        print(f"   {label}: {count}")
    
    classifier = RandomForestThreatClassifier(
        n_estimators=100,
        random_state=42
    )
    
    # Split data
    split_idx = int(len(flows) * 0.8)
    train_flows = flows[:split_idx]
    train_labels = labels[:split_idx]
    test_flows = flows[split_idx:]
    test_labels = labels[split_idx:]
    
    # Train model
    start_time = time.time()
    classifier.fit(train_flows, train_labels)
    training_time = time.time() - start_time
    
    print(f"✅ Training completed in {training_time:.2f} seconds")
    
    # Evaluate model
    if test_flows:
        evaluation = classifier.evaluate(test_flows, test_labels)
        print(f"\n📊 Model Evaluation:")
        print(f"   Accuracy: {evaluation['accuracy']:.2%}")
        print(f"   Classes: {evaluation['classes']}")
    
    # Feature importance
    importance = classifier.get_feature_importance()
    if importance:
        print(f"\n📊 Top Features:")
        sorted_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:5]
        for feature, imp in sorted_features:
            print(f"   {feature}: {imp:.3f}")
    
    # Save model
    model_path = Path(output_dir) / "random_forest.joblib"
    classifier.save_model(str(model_path))
    print(f"\n✅ Model saved to {model_path}")
    
    return classifier


def main():
    """Main training function"""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(level=args.log_level)
    
    print("=" * 60)
    print("MODEL TRAINING")
    print("=" * 60)
    
    # Get training data
    flows = []
    
    if args.pcap_file:
        # Extract flows from PCAP
        pcap_path = Path(args.pcap_file)
        if not pcap_path.exists():
            print(f"❌ PCAP file not found: {args.pcap_file}")
            return 1
        
        print(f"Extracting flows from {pcap_path}...")
        extractor = FlowExtractor()
        flows = extractor.extract_from_pcap(str(pcap_path))
    else:
        # Use sample data
        print("No PCAP file provided. Generating sample flows...")
        from src.flow.nfstream_wrapper import FlowRecord
        import random
        
        for i in range(200):
            # Generate random flow
            flow = FlowRecord(
                source_ip=f"192.168.1.{random.randint(1, 50)}",
                destination_ip=f"10.0.0.{random.randint(1, 10)}",
                source_port=random.randint(1024, 65535),
                destination_port=random.choice([80, 443, 53, 22, 8080]),
                protocol=random.choice([6, 17]),
                bidirectional_packets=random.randint(1, 1000),
                bidirectional_bytes=random.randint(40, 100000),
                bidirectional_duration_ms=random.randint(10, 10000),
                src2dst_packets=random.randint(1, 500),
                src2dst_bytes=random.randint(20, 50000),
                dst2src_packets=random.randint(0, 500),
                dst2src_bytes=random.randint(0, 50000),
                bidirectional_first_seen_ms=int(time.time() * 1000),
                bidirectional_last_seen_ms=int(time.time() * 1000) + random.randint(10, 10000),
                bidirectional_min_ps=0,
                bidirectional_mean_ps=random.uniform(0, 100),
                bidirectional_stddev_ps=random.uniform(0, 50),
                bidirectional_max_ps=random.uniform(0, 200),
                bidirectional_min_piat_ms=0,
                bidirectional_mean_piat_ms=random.uniform(0, 100),
                bidirectional_stddev_piat_ms=random.uniform(0, 50),
                bidirectional_max_piat_ms=random.uniform(0, 200),
                syn_packets=random.randint(0, 10),
                ack_packets=random.randint(0, 100),
                fin_packets=random.randint(0, 5),
                rst_packets=random.randint(0, 5),
                application_name="unknown",
                application_category="unknown",
                timestamp=time.time()
            )
            flows.append(flow)
    
    if len(flows) < 10:
        print(f"❌ Not enough flows for training (got {len(flows)}, need at least 10)")
        return 1
    
    print(f"✅ Got {len(flows)} flows for training")
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Train models
    try:
        if args.model_type in ["isolation_forest", "both"]:
            train_isolation_forest(flows, output_dir)
        
        if args.model_type in ["random_forest", "both"]:
            train_random_forest(flows, output_dir)
        
        print("\n" + "=" * 60)
        print("✅ MODEL TRAINING COMPLETE")
        print("=" * 60)
        print(f"Models saved to: {output_dir}")
        
        return 0
        
    except Exception as e:
        print(f"❌ Training failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())