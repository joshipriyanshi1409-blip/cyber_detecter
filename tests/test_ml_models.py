"""
Tests for Machine Learning Models
"""

import pytest
import time
import numpy as np
import warnings
from pathlib import Path
from sklearn.model_selection import train_test_split
from collections import Counter

# Suppress NumPy deprecation warnings from joblib
warnings.filterwarnings('ignore', category=DeprecationWarning, module='joblib')
warnings.filterwarnings('ignore', category=DeprecationWarning, message='.*Setting the shape on a NumPy array.*')

from src.models.isolation_forest import IsolationForestAnomalyDetector
from src.models.random_forest import RandomForestThreatClassifier
from src.flow.nfstream_wrapper import FlowRecord


@pytest.fixture
def sample_flows():
    """Create sample flows for testing with diverse traffic patterns"""
    flows = []
    
    # Create normal flows (HTTP-like traffic)
    for i in range(60):
        flow = FlowRecord(
            source_ip=f"192.168.1.{i % 10}",
            destination_ip="8.8.8.8",
            source_port=10000 + i,
            destination_port=80,
            protocol=6,
            bidirectional_packets=10,
            bidirectional_bytes=1000,
            bidirectional_duration_ms=1000,
            src2dst_packets=5,
            src2dst_bytes=500,
            dst2src_packets=5,
            dst2src_bytes=500,
            bidirectional_first_seen_ms=int(time.time() * 1000),
            bidirectional_last_seen_ms=int(time.time() * 1000) + 1000,
            bidirectional_min_ps=0,
            bidirectional_mean_ps=10,
            bidirectional_stddev_ps=0,
            bidirectional_max_ps=10,
            bidirectional_min_piat_ms=0,
            bidirectional_mean_piat_ms=100,
            bidirectional_stddev_piat_ms=0,
            bidirectional_max_piat_ms=100,
            syn_packets=1,
            ack_packets=9,
            fin_packets=0,
            rst_packets=0,
            application_name="HTTP",
            application_category="Web",
            timestamp=time.time()
        )
        flows.append(flow)
    
    # Add port scan-like flows (SYN only, many ports)
    for i in range(20):
        flow = FlowRecord(
            source_ip="10.0.0.1",
            destination_ip="192.168.1.100",
            source_port=20000 + i,
            destination_port=1000 + i,
            protocol=6,
            bidirectional_packets=1,
            bidirectional_bytes=40,
            bidirectional_duration_ms=10,
            src2dst_packets=1,
            src2dst_bytes=40,
            dst2src_packets=0,
            dst2src_bytes=0,
            bidirectional_first_seen_ms=int(time.time() * 1000),
            bidirectional_last_seen_ms=int(time.time() * 1000) + 10,
            bidirectional_min_ps=0,
            bidirectional_mean_ps=100,
            bidirectional_stddev_ps=0,
            bidirectional_max_ps=100,
            bidirectional_min_piat_ms=0,
            bidirectional_mean_piat_ms=10,
            bidirectional_stddev_piat_ms=0,
            bidirectional_max_piat_ms=10,
            syn_packets=1,
            ack_packets=0,
            fin_packets=0,
            rst_packets=0,
            application_name="unknown",
            application_category="unknown",
            timestamp=time.time()
        )
        flows.append(flow)
    
    # Add DDoS-like flows (high rate, SYN flood)
    for i in range(20):
        flow = FlowRecord(
            source_ip=f"10.0.1.{i}",
            destination_ip="192.168.1.200",
            source_port=30000 + i,
            destination_port=80,
            protocol=6,
            bidirectional_packets=100,
            bidirectional_bytes=4000,
            bidirectional_duration_ms=100,
            src2dst_packets=100,
            src2dst_bytes=4000,
            dst2src_packets=0,
            dst2src_bytes=0,
            bidirectional_first_seen_ms=int(time.time() * 1000),
            bidirectional_last_seen_ms=int(time.time() * 1000) + 100,
            bidirectional_min_ps=0,
            bidirectional_mean_ps=1000,
            bidirectional_stddev_ps=0,
            bidirectional_max_ps=1000,
            bidirectional_min_piat_ms=0,
            bidirectional_mean_piat_ms=1,
            bidirectional_stddev_piat_ms=0,
            bidirectional_max_piat_ms=1,
            syn_packets=100,
            ack_packets=0,
            fin_packets=0,
            rst_packets=0,
            application_name="unknown",
            application_category="unknown",
            timestamp=time.time()
        )
        flows.append(flow)
    
    return flows


def generate_labels(flows):
    """Generate labels for sample flows based on traffic patterns"""
    labels = []
    for flow in flows:
        pps = flow.get_packets_per_second()
        syn_ratio = flow.get_syn_ratio()
        
        if pps > 500 and syn_ratio > 0.9:
            labels.append("DDOS")
        elif pps > 50 and syn_ratio > 0.9 and flow.bidirectional_packets < 3:
            labels.append("PORT_SCAN")
        else:
            labels.append("NORMAL")
    return labels


class TestIsolationForest:
    def test_initialization(self):
        detector = IsolationForestAnomalyDetector()
        assert detector is not None
        assert detector.contamination == 0.1
        assert detector.n_estimators == 100
        assert detector.is_trained == False
    
    def test_extract_features(self, sample_flows):
        detector = IsolationForestAnomalyDetector()
        features = detector.extract_features(sample_flows)
        
        assert features.shape[0] == len(sample_flows)
        assert features.shape[1] > 0
        assert not np.any(np.isnan(features))
        assert not np.any(np.isinf(features))
    
    def test_fit(self, sample_flows):
        detector = IsolationForestAnomalyDetector()
        detector.fit(sample_flows)
        
        assert detector.is_trained == True
    
    def test_predict(self, sample_flows):
        detector = IsolationForestAnomalyDetector()
        detector.fit(sample_flows)
        
        predictions = detector.predict(sample_flows[:20])
        
        assert len(predictions) == 20
        assert all('is_anomaly' in p for p in predictions)
        assert all('anomaly_score' in p for p in predictions)
        assert all('source_ip' in p for p in predictions)
    
    def test_predict_single(self, sample_flows):
        detector = IsolationForestAnomalyDetector()
        detector.fit(sample_flows)
        
        result = detector.predict_single(sample_flows[0])
        
        assert 'is_anomaly' in result
        assert 'anomaly_score' in result
    
    def test_save_load_model(self, sample_flows, tmp_path):
        detector = IsolationForestAnomalyDetector()
        detector.fit(sample_flows)
        
        # Save model
        model_path = tmp_path / "isolation_forest.joblib"
        detector.save_model(str(model_path))
        assert model_path.exists()
        
        # Load model
        new_detector = IsolationForestAnomalyDetector()
        result = new_detector.load_model(str(model_path))
        assert result == True
        assert new_detector.is_trained == True
        
        # Verify loaded model works
        predictions = new_detector.predict(sample_flows[:5])
        assert len(predictions) == 5
    
    def test_anomaly_statistics(self, sample_flows):
        detector = IsolationForestAnomalyDetector()
        detector.fit(sample_flows)
        
        predictions = detector.predict(sample_flows)
        stats = detector.get_anomaly_statistics(predictions)
        
        assert stats['total_flows'] == len(sample_flows)
        assert stats['anomalies_detected'] >= 0
        assert 0 <= stats['anomaly_rate'] <= 1
        assert stats['max_anomaly_score'] >= stats['min_anomaly_score']
    
    def test_get_model_info(self, sample_flows):
        detector = IsolationForestAnomalyDetector()
        detector.fit(sample_flows)
        
        info = detector.get_model_info()
        
        assert info['is_trained'] == True
        assert info['contamination'] == 0.1
        assert len(info['feature_columns']) > 0


class TestRandomForest:
    def test_initialization(self):
        classifier = RandomForestThreatClassifier()
        assert classifier is not None
        assert classifier.n_estimators == 100
        assert classifier.is_trained == False
    
    def test_fit(self, sample_flows):
        labels = generate_labels(sample_flows)
        
        # Check we have multiple classes
        assert len(set(labels)) >= 2, f"Need at least 2 classes, got: {set(labels)}"
        
        classifier = RandomForestThreatClassifier()
        classifier.fit(sample_flows, labels)
        
        assert classifier.is_trained == True
        assert len(classifier.classes) > 0
        assert len(classifier.feature_columns) > 0
    
    def test_predict(self, sample_flows):
        labels = generate_labels(sample_flows)
        
        classifier = RandomForestThreatClassifier()
        classifier.fit(sample_flows, labels)
        
        predictions = classifier.predict(sample_flows[:10])
        
        assert len(predictions) == 10
        assert all('predicted_class' in p for p in predictions)
        assert all('confidence' in p for p in predictions)
        assert all('probabilities' in p for p in predictions)
        assert all(0 <= p['confidence'] <= 1 for p in predictions)
    
    def test_predict_single(self, sample_flows):
        labels = generate_labels(sample_flows)
        
        classifier = RandomForestThreatClassifier()
        classifier.fit(sample_flows, labels)
        
        result = classifier.predict_single(sample_flows[0])
        
        assert 'predicted_class' in result
        assert 'confidence' in result
    
    def test_evaluate(self, sample_flows):
        labels = generate_labels(sample_flows)
        
        # Use stratified split
        indices = list(range(len(sample_flows)))
        label_counts = Counter(labels)
        min_class_count = min(label_counts.values())
        
        if min_class_count >= 2:
            train_indices, test_indices = train_test_split(
                indices, test_size=0.2, random_state=42, stratify=labels
            )
        else:
            train_indices, test_indices = train_test_split(
                indices, test_size=0.2, random_state=42
            )
        
        train_flows = [sample_flows[i] for i in train_indices]
        train_labels = [labels[i] for i in train_indices]
        test_flows = [sample_flows[i] for i in test_indices]
        test_labels = [labels[i] for i in test_indices]
        
        classifier = RandomForestThreatClassifier()
        classifier.fit(train_flows, train_labels)
        
        # Evaluate
        evaluation = classifier.evaluate(test_flows, test_labels)
        
        assert 'accuracy' in evaluation
        assert 0 <= evaluation['accuracy'] <= 1
        
        if 'warning' not in evaluation:
            assert evaluation['valid_samples'] > 0
            assert 'classification_report' in evaluation
            assert 'confusion_matrix' in evaluation
    
    def test_cross_validate(self, sample_flows):
        labels = generate_labels(sample_flows)
        
        classifier = RandomForestThreatClassifier()
        classifier.fit(sample_flows, labels)
        
        # Cross-validate on subset
        cv_results = classifier.cross_validate(sample_flows[:50], labels[:50], cv=3)
        
        if cv_results:
            assert 'cv_scores' in cv_results
            assert 'mean_score' in cv_results
            assert 0 <= cv_results['mean_score'] <= 1
    
    def test_feature_importance(self, sample_flows):
        labels = generate_labels(sample_flows)
        
        classifier = RandomForestThreatClassifier()
        classifier.fit(sample_flows, labels)
        
        importance = classifier.get_feature_importance()
        
        assert len(importance) > 0
        assert all(imp >= 0 for imp in importance.values())
        
        # Check sum of importance is approximately 1
        total_importance = sum(importance.values())
        assert abs(total_importance - 1.0) < 0.1
    
    def test_save_load_model(self, sample_flows, tmp_path):
        labels = generate_labels(sample_flows)
        
        classifier = RandomForestThreatClassifier()
        classifier.fit(sample_flows, labels)
        
        # Save
        model_path = tmp_path / "random_forest.joblib"
        classifier.save_model(str(model_path))
        assert model_path.exists()
        
        # Load
        new_classifier = RandomForestThreatClassifier()
        result = new_classifier.load_model(str(model_path))
        assert result == True
        assert new_classifier.is_trained == True
        assert new_classifier.classes == classifier.classes
        
        # Verify loaded model works
        predictions = new_classifier.predict(sample_flows[:5])
        assert len(predictions) == 5
    
    def test_get_model_info(self, sample_flows):
        labels = generate_labels(sample_flows)
        
        classifier = RandomForestThreatClassifier()
        classifier.fit(sample_flows, labels)
        
        info = classifier.get_model_info()
        
        assert info['is_trained'] == True
        assert info['n_estimators'] == 100
        assert len(info['classes']) > 0
        assert len(info['feature_columns']) > 0