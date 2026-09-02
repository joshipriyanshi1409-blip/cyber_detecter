"""
Isolation Forest Anomaly Detection Module
Detects anomalous network traffic using Isolation Forest algorithm.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path
import time
import warnings

from src.flow.nfstream_wrapper import FlowRecord

logger = logging.getLogger(__name__)


class IsolationForestAnomalyDetector:
    """Detects anomalies in network flows using Isolation Forest"""
    
    def __init__(self, contamination: float = 0.1, random_state: int = 42,
                 n_estimators: int = 100):
        """
        Initialize Isolation Forest detector
        
        Args:
            contamination: Expected proportion of anomalies
            random_state: Random seed for reproducibility
            n_estimators: Number of trees in the forest
        """
        self.contamination = contamination
        self.random_state = random_state
        self.n_estimators = n_estimators
        
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=n_estimators,
            n_jobs=-1
        )
        
        self.scaler = StandardScaler()
        self.feature_columns = []
        self.is_trained = False
        self.model_version = "in-memory-unversioned"
        
        logger.info(f"Initialized IsolationForest with contamination={contamination}")
    
    def extract_features(self, flows: List[FlowRecord]) -> np.ndarray:
        """Extract features using the versioned canonical feature engine."""
        from src.features.schema import FEATURE_SCHEMA, extract_features
        self.feature_columns = list(FEATURE_SCHEMA.feature_names)
        return np.asarray(extract_features(flows), dtype=float)

    def fit(self, flows: List[FlowRecord]):
        """
        Train the Isolation Forest model on flow data
        
        Args:
            flows: List of FlowRecord objects for training
        """
        if len(flows) < 10:
            logger.warning("Too few flows for training (minimum 10 required)")
            return
        
        # Extract features
        X = self.extract_features(flows)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        self.is_trained = True
        
        logger.info(f"Trained Isolation Forest on {len(flows)} flows")
    
    def predict(self, flows: List[FlowRecord]) -> List[Dict[str, Any]]:
        """
        Predict anomalies in flows
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            List of prediction results with anomaly scores
        """
        if not self.is_trained:
            logger.warning("Model not trained. Call fit() first.")
            return []
        
        # Extract features
        X = self.extract_features(flows)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict
        predictions = self.model.predict(X_scaled)  # -1 for anomaly, 1 for normal
        scores = self.model.score_samples(X_scaled)  # Higher = more normal
        
        results = []
        for i, flow in enumerate(flows):
            is_anomaly = predictions[i] == -1
            anomaly_score = float(scores[i])
            
            # Normalize anomaly score to 0-1 range (higher = more anomalous)
            normalized_score = max(0, min(1, 1 - (anomaly_score + 0.5)))
            
            results.append({
                'flow': flow,
                'is_anomaly': is_anomaly,
                'anomaly_score': normalized_score,
                'raw_score': anomaly_score,
                'model_name': "isolation_forest",
                'model_version': self.model_version,
                'feature_schema_version': __import__("src.features.schema", fromlist=["FEATURE_SCHEMA"]).FEATURE_SCHEMA.schema_version,
                'flow_id': str(flow.flow_id),
                'source_ip': flow.source_ip,
                'destination_ip': flow.destination_ip,
                'protocol': flow.protocol
            })
        
        # Sort by anomaly score (most anomalous first)
        results.sort(key=lambda x: x['anomaly_score'], reverse=True)
        
        return results
    
    def predict_single(self, flow: FlowRecord) -> Dict[str, Any]:
        """
        Predict anomaly for a single flow
        
        Args:
            flow: FlowRecord object
            
        Returns:
            Prediction result
        """
        results = self.predict([flow])
        return results[0] if results else {}
    
    def get_anomaly_threshold(self) -> float:
        """Get the anomaly threshold"""
        if hasattr(self.model, 'offset_'):
            return float(self.model.offset_)
        return 0.0
    
    def save_model(self, filepath: str):
        """
        Save model to file
        
        Args:
            filepath: Path to save model
        """
        if not self.is_trained:
            logger.warning("Model not trained. Nothing to save.")
            return
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns,
            'is_trained': self.is_trained,
            'contamination': self.contamination,
            'random_state': self.random_state,
            'n_estimators': self.n_estimators
        }
        
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Suppress NumPy deprecation warnings during save
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', category=DeprecationWarning)
            joblib.dump(model_data, path)
        
        logger.info(f"Saved Isolation Forest model to {path}")
    
    def load_model(self, filepath: str) -> bool:
        """
        Load model from file
        
        Args:
            filepath: Path to model file
            
        Returns:
            True if successful, False otherwise
        """
        path = Path(filepath)
        if not path.exists():
            logger.error(f"Model file not found: {filepath}")
            return False
        
        try:
            # Suppress NumPy deprecation warnings during load
            with warnings.catch_warnings():
                warnings.filterwarnings('ignore', category=DeprecationWarning)
                model_data = joblib.load(path)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_columns = model_data['feature_columns']
            self.is_trained = model_data['is_trained']
            self.contamination = model_data['contamination']
            self.random_state = model_data['random_state']
            self.n_estimators = model_data['n_estimators']
            
            logger.info(f"Loaded Isolation Forest model from {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def get_anomaly_statistics(self, predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get statistics about anomaly predictions
        
        Args:
            predictions: List of prediction results
            
        Returns:
            Dictionary with statistics
        """
        if not predictions:
            return {
                'total_flows': 0,
                'anomalies_detected': 0,
                'anomaly_rate': 0,
                'avg_anomaly_score': 0,
                'max_anomaly_score': 0,
                'min_anomaly_score': 0
            }
        
        anomaly_count = sum(1 for p in predictions if p['is_anomaly'])
        scores = [p['anomaly_score'] for p in predictions]
        
        return {
            'total_flows': len(predictions),
            'anomalies_detected': anomaly_count,
            'anomaly_rate': anomaly_count / len(predictions),
            'avg_anomaly_score': float(np.mean(scores)),
            'max_anomaly_score': float(np.max(scores)),
            'min_anomaly_score': float(np.min(scores))
        }
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information"""
        return {
            'is_trained': self.is_trained,
            'contamination': self.contamination,
            'n_estimators': self.n_estimators,
            'random_state': self.random_state,
            'feature_columns': self.feature_columns,
            'num_features': len(self.feature_columns)
        }