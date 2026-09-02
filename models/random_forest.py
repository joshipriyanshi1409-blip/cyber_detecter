"""
Random Forest Classification Module
Classifies network threats using Random Forest algorithm.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib
from pathlib import Path
import time

from src.flow.nfstream_wrapper import FlowRecord

logger = logging.getLogger(__name__)


class RandomForestThreatClassifier:
    """Classifies network threats using Random Forest"""
    
    def __init__(self, n_estimators: int = 100, random_state: int = 42):
        """
        Initialize Random Forest classifier
        
        Args:
            n_estimators: Number of trees
            random_state: Random seed
        """
        self.n_estimators = n_estimators
        self.random_state = random_state
        
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1,
            class_weight='balanced'
        )
        
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        self.classes = []
        self.is_trained = False
        
        logger.info(f"Initialized RandomForestClassifier with {n_estimators} trees")
    
    def extract_features(self, flows: List[FlowRecord]) -> np.ndarray:
        """
        Extract features for classification
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Feature matrix
        """
        features = []
        
        self.feature_columns = [
            'bidirectional_packets',
            'bidirectional_bytes',
            'bidirectional_duration_ms',
            'src2dst_packets',
            'dst2src_packets',
            'src2dst_bytes',
            'dst2src_bytes',
            'packets_per_second',
            'bytes_per_second',
            'packet_asymmetry',
            'byte_asymmetry',
            'syn_ratio',
            'unique_ports_ratio',
            'flow_rate'
        ]
        
        for flow in flows:
            packets_per_second = flow.get_packets_per_second()
            bytes_per_second = flow.get_bytes_per_second()
            syn_ratio = flow.get_syn_ratio()
            
            total_packets = flow.src2dst_packets + flow.dst2src_packets
            packet_asymmetry = abs(flow.src2dst_packets - flow.dst2src_packets) / total_packets if total_packets > 0 else 0
            
            total_bytes = flow.src2dst_bytes + flow.dst2src_bytes
            byte_asymmetry = abs(flow.src2dst_bytes - flow.dst2src_bytes) / total_bytes if total_bytes > 0 else 0
            
            features.append([
                flow.bidirectional_packets,
                flow.bidirectional_bytes,
                flow.bidirectional_duration_ms,
                flow.src2dst_packets,
                flow.dst2src_packets,
                flow.src2dst_bytes,
                flow.dst2src_bytes,
                packets_per_second,
                bytes_per_second,
                packet_asymmetry,
                byte_asymmetry,
                syn_ratio,
                0,  # unique_ports_ratio placeholder
                0   # flow_rate placeholder
            ])
        
        return np.array(features)
    
    def fit(self, flows: List[FlowRecord], labels: List[str]):
        """
        Train the Random Forest classifier
        
        Args:
            flows: List of FlowRecord objects
            labels: List of labels (e.g., 'NORMAL', 'DDOS', 'PORT_SCAN')
        """
        if len(flows) < 20:
            logger.warning("Too few samples for training (minimum 20 required)")
            return
        
        if len(flows) != len(labels):
            logger.error("Number of flows and labels must match")
            return
        
        # Extract features
        X = self.extract_features(flows)
        
        # Encode labels
        y = self.label_encoder.fit_transform(labels)
        self.classes = self.label_encoder.classes_
        
        # Train model
        self.model.fit(X, y)
        self.is_trained = True
        
        logger.info(f"Trained Random Forest on {len(flows)} samples")
        logger.info(f"Classes: {self.classes}")
    
    def predict(self, flows: List[FlowRecord]) -> List[Dict[str, Any]]:
        """
        Predict threat classes for flows
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            List of prediction results
        """
        if not self.is_trained:
            logger.warning("Model not trained. Call fit() first.")
            return []
        
        # Extract features
        X = self.extract_features(flows)
        
        # Predict
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        
        results = []
        for i, flow in enumerate(flows):
            predicted_label = self.label_encoder.inverse_transform([predictions[i]])[0]
            confidence = float(np.max(probabilities[i]))
            
            results.append({
                'flow': flow,
                'predicted_class': predicted_label,
                'confidence': confidence,
                'probabilities': {
                    label: float(prob)
                    for label, prob in zip(self.classes, probabilities[i])
                },
                'source_ip': flow.source_ip,
                'destination_ip': flow.destination_ip
            })
        
        return results
    
    def evaluate(self, flows: List[FlowRecord], labels: List[str]) -> Dict[str, Any]:
        """
        Evaluate model performance on test data
        
        Args:
            flows: Test flows
            labels: True labels
            
        Returns:
            Dictionary with evaluation metrics
        """
        if not self.is_trained:
            logger.warning("Model not trained. Cannot evaluate.")
            return {}
        
        X = self.extract_features(flows)
        y_true = self.label_encoder.transform(labels)
        y_pred = self.model.predict(X)
        
        accuracy = accuracy_score(y_true, y_pred)
        report = classification_report(y_true, y_pred, target_names=self.classes, output_dict=True)
        conf_matrix = confusion_matrix(y_true, y_pred)
        
        return {
            'accuracy': accuracy,
            'classification_report': report,
            'confusion_matrix': conf_matrix.tolist(),
            'classes': self.classes.tolist()
        }
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores"""
        if not self.is_trained:
            return {}
        
        importance = self.model.feature_importances_
        return {
            feature: float(imp)
            for feature, imp in zip(self.feature_columns, importance)
        }
    
    def save_model(self, filepath: str):
        """Save model to file"""
        if not self.is_trained:
            logger.warning("Model not trained. Nothing to save.")
            return
        
        model_data = {
            'model': self.model,
            'label_encoder': self.label_encoder,
            'feature_columns': self.feature_columns,
            'classes': self.classes,
            'is_trained': self.is_trained,
            'n_estimators': self.n_estimators,
            'random_state': self.random_state
        }
        
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        joblib.dump(model_data, path)
        logger.info(f"Saved Random Forest model to {path}")
    
    def load_model(self, filepath: str) -> bool:
        """Load model from file"""
        path = Path(filepath)
        if not path.exists():
            logger.error(f"Model file not found: {filepath}")
            return False
        
        model_data = joblib.load(path)
        
        self.model = model_data['model']
        self.label_encoder = model_data['label_encoder']
        self.feature_columns = model_data['feature_columns']
        self.classes = model_data['classes']
        self.is_trained = model_data['is_trained']
        self.n_estimators = model_data['n_estimators']
        self.random_state = model_data['random_state']
        
        logger.info(f"Loaded Random Forest model from {path}")
        return True