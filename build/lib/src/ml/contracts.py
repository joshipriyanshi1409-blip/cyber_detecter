"""Typed ML inference contract shared by supervised and anomaly models."""
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

@dataclass(frozen=True)
class MLPrediction:
    flow_ids: Tuple[str, ...]
    window_id: Optional[int]
    model_name: str
    model_version: str
    feature_schema_version: str
    label: Optional[str] = None
    class_probabilities: Dict[str, float] = field(default_factory=dict)
    ml_probability: Optional[float] = None
    ml_anomaly_score: Optional[float] = None
    is_anomaly: Optional[bool] = None
    inference_time_ms: float = 0.0
