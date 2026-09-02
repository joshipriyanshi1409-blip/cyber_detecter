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
import warnings
from collections import Counter

from src.flow.nfstream_wrapper import FlowRecord

logger = logging.getLogger(__name__)


class RandomForestThreatClassifier:
    """Classifies network threats using Random Forest"""
    
    def __init__(self, n_estimators: int = 100, random_state: int = 42, test_size: float = 0.2,
                 class_weight: str = "balanced"):

        """
        Initialize Random Forest classifier
        
        Args:
            n_estimators: Number of trees
            random_state: Random seed
        """
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.test_size = test_size
        self.class_weight = class_weight
        self.training_metrics = {}
        self.model_version = "in-memory-unversioned"
        
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1,
            class_weight=class_weight
        )
        
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        self.classes = []
        self.is_trained = False
        
        logger.info(f"Initialized RandomForestClassifier with {n_estimators} trees")
    
    def extract_features(self, flows: List[FlowRecord]) -> np.ndarray:
        """Extract features using the versioned canonical feature engine."""
        from src.features.schema import FEATURE_SCHEMA, extract_features
        self.feature_columns = list(FEATURE_SCHEMA.feature_names)
        return np.asarray(extract_features(flows), dtype=float)

    def fit(self, flows: List[FlowRecord], labels: List[str]):
        """
        Train the Random Forest classifier
        
        Args:
            flows: List of FlowRecord objects
            labels: List of labels (e.g., 'NORMAL', 'DDOS', 'PORT_SCAN')
        """
        if len(flows) < 10:
            logger.warning("Too few samples for training (minimum 10 required)")
            return
        
        if len(flows) != len(labels):
            logger.error("Number of flows and labels must match")
            return
        
        # Extract features
        X = self.extract_features(flows)
        
        # Encode labels
        y = self.label_encoder.fit_transform(labels)
        self.classes = self.label_encoder.classes_.tolist()
        
        # Train model
        self.model.fit(X, y)
        self.is_trained = True
        
        logger.info(f"Trained Random Forest on {len(flows)} samples")
        logger.info(f"Classes: {self.classes}")
        
        # Log class distribution
        label_counts = Counter(labels)
        for label, count in label_counts.items():
            logger.info(f"  {label}: {count} samples")
    
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
            
            # Get probability for each class
            prob_dict = {}
            for j, cls in enumerate(self.classes):
                prob_dict[cls] = float(probabilities[i][j])
            
            results.append({
                'flow': flow,
                'predicted_class': str(predicted_label),
                'confidence': confidence,
                'probabilities': prob_dict,
                'model_name': "random_forest",
                'model_version': self.model_version,
                'feature_schema_version': __import__("src.features.schema", fromlist=["FEATURE_SCHEMA"]).FEATURE_SCHEMA.schema_version,
                'flow_id': str(flow.flow_id),
                'source_ip': flow.source_ip,
                'destination_ip': flow.destination_ip
            })
        
        return results
    
    def predict_single(self, flow: FlowRecord) -> Dict[str, Any]:
        """
        Predict threat class for a single flow
        
        Args:
            flow: FlowRecord object
            
        Returns:
            Prediction result
        """
        results = self.predict([flow])
        return results[0] if results else {}
    
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
        
        if len(flows) != len(labels):
            logger.error("Number of flows and labels must match")
            return {}
        
        # Filter out samples with labels not seen during training
        valid_indices = []
        valid_labels = []
        
        for i, label in enumerate(labels):
            if label in self.classes:
                valid_indices.append(i)
                valid_labels.append(label)
        
        if not valid_indices:
            logger.warning("No valid test samples with known labels")
            return {
                'accuracy': 0,
                'classification_report': {},
                'confusion_matrix': [],
                'classes': self.classes,
                'valid_samples': 0,
                'total_samples': len(flows),
                'warning': 'No valid test samples with labels seen during training'
            }
        
        # Filter flows and labels
        valid_flows = [flows[i] for i in valid_indices]
        X_valid = self.extract_features(valid_flows)
        y_true = self.label_encoder.transform(valid_labels)
        y_pred = self.model.predict(X_valid)
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        
        # Classification report
        try:
            report = classification_report(
                y_true, 
                y_pred, 
                target_names=self.classes, 
                output_dict=True,
                zero_division=0
            )
        except Exception as e:
            logger.warning(f"Could not generate classification report: {e}")
            report = {}
        
        # Confusion matrix
        conf_matrix = confusion_matrix(y_true, y_pred, labels=range(len(self.classes)))
        
        logger.info(f"Evaluation complete - Accuracy: {accuracy:.2%}")
        
        return {
            'accuracy': float(accuracy),
            'classification_report': report,
            'confusion_matrix': conf_matrix.tolist(),
            'classes': self.classes,
            'valid_samples': len(valid_flows),
            'total_samples': len(flows)
        }
    
    def cross_validate(self, flows: List[FlowRecord], labels: List[str], cv: int = 5) -> Dict[str, Any]:
        """
        Perform cross-validation
        
        Args:
            flows: All flows
            labels: All labels
            cv: Number of cross-validation folds
            
        Returns:
            Dictionary with cross-validation results
        """
        if len(flows) < cv:
            logger.warning(f"Not enough samples for {cv}-fold cross-validation")
            return {}
        
        # Extract features
        X = self.extract_features(flows)
        y = self.label_encoder.fit_transform(labels)
        
        # Perform cross-validation
        scores = cross_val_score(self.model, X, y, cv=cv)
        
        return {
            'cv_scores': scores.tolist(),
            'mean_score': float(np.mean(scores)),
            'std_score': float(np.std(scores)),
            'cv_folds': cv
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
        
        # Suppress NumPy deprecation warnings during save
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', category=DeprecationWarning)
            joblib.dump(model_data, path)
        
        logger.info(f"Saved Random Forest model to {path}")
    
    def load_model(self, filepath: str) -> bool:
        """Load model from file"""
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
            self.label_encoder = model_data['label_encoder']
            self.feature_columns = model_data['feature_columns']
            self.classes = model_data['classes']
            self.is_trained = model_data['is_trained']
            self.n_estimators = model_data['n_estimators']
            self.random_state = model_data['random_state']
            
            logger.info(f"Loaded Random Forest model from {path}")
            logger.info(f"Classes: {self.classes}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information"""
        return {
            'is_trained': self.is_trained,
            'n_estimators': self.n_estimators,
            'random_state': self.random_state,
            'classes': self.classes,
            'feature_columns': self.feature_columns,
            'num_features': len(self.feature_columns)
        }