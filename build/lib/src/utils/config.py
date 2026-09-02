"""
Configuration management for the Cyber Threat Detection Platform.
Loads YAML configuration files and provides typed access to settings.
"""

import os
import yaml
from typing import Any, Dict, Optional
from pathlib import Path

class ConfigManager:
    """Manages configuration loading and access."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_dir: Path to configuration directory. Defaults to project config/ directory.
        """
        if config_dir is None:
            # Navigate up from src/utils/ to project root, then to config/
            self.config_dir = Path(__file__).parent.parent.parent / "config"
        else:
            self.config_dir = Path(config_dir)
        
        self.configs: Dict[str, Dict[str, Any]] = {}
        self._load_all_configs()
    
    def _load_all_configs(self) -> None:
        """Load all YAML configuration files from the config directory."""
        # Initialize with defaults
        self.configs = {
            'main': self._get_default_main_config(),
            'thresholds': self._get_default_thresholds()
        }
        
        try:
            # Load main config
            main_config_path = self.config_dir / "config.yaml"
            if main_config_path.exists():
                try:
                    with open(main_config_path, 'r') as f:
                        loaded_config = yaml.safe_load(f)
                        if loaded_config and isinstance(loaded_config, dict):
                            self.configs['main'] = loaded_config
                        else:
                            print(f"Warning: Main config is empty or invalid, using defaults")
                except yaml.YAMLError as e:
                    print(f"Warning: Could not parse config.yaml: {e}")
                    print("Using default configuration")
            else:
                print(f"Warning: Main config not found at {main_config_path}")
            
            # Load thresholds config
            thresholds_path = self.config_dir / "thresholds.yaml"
            if thresholds_path.exists():
                try:
                    with open(thresholds_path, 'r') as f:
                        loaded_thresholds = yaml.safe_load(f)
                        if loaded_thresholds and isinstance(loaded_thresholds, dict):
                            self.configs['thresholds'] = loaded_thresholds
                        else:
                            print(f"Warning: Thresholds config is empty or invalid, using defaults")
                except yaml.YAMLError as e:
                    print(f"Warning: Could not parse thresholds.yaml: {e}")
                    print("Using default thresholds")
            else:
                print(f"Warning: Thresholds config not found at {thresholds_path}")
                    
        except Exception as e:
            print(f"Warning: Could not load configuration files: {e}")
            print("Using default configuration")
    
    def _get_default_main_config(self) -> Dict[str, Any]:
        """Get default main configuration"""
        return {
            "app": {
                "name": "Cyber Threat Detection Platform",
                "version": "0.1.0",
                "environment": "development"
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file": "logs/app.log"
            },
            "database": {
                "path": "data/threats.db",
                "echo": False
            },
            "paths": {
                "data_dir": "data",
                "raw_pcaps": "data/raw",
                "processed_data": "data/processed",
                "models_dir": "models",
                "database_path": "data/threats.db"
            },
            "detection": {
                "enabled_detectors": ["port_scan", "ddos", "dga"]
            },
            "ml": {
                "isolation_forest": {
                    "contamination": 0.1,
                    "random_state": 42,
                    "n_estimators": 100
                },
                "random_forest": {
                    "n_estimators": 100,
                    "random_state": 42,
                    "test_size": 0.2
                },
                "model_integrity": {"require_hash": True}
            },
            "streaming": {
                "batch_size": 100,
                "window_seconds": 60,
                "windowing": {
                    "enabled": True,
                    "window_seconds": 10,
                    "slide_seconds": 1,
                    "max_buffered_flows": 100000,
                },
                "resources": {
                    "max_retained_packets": 10000,
                    "max_alerts_per_window": 1000,
                    "max_cti_lookups_per_window": 60,
                },
            }
        }
    
    def _get_default_thresholds(self) -> Dict[str, Any]:
        """Get default thresholds"""
        return {
            "port_scan": {
                "min_unique_ports": 10,
                "min_unique_hosts": 5,
                "min_failed_ratio": 0.5,
                "min_syn_ratio": 0.7,
                "window_seconds": 60,
                "min_flows": 5
            },
            "ddos": {
                "min_pps": 1000,
                "min_bps": 100000,
                "min_syn_ratio": 0.7,
                "source_concentration": 0.5,
                "window_seconds": 10,
                "min_flows": 10
            },
            "dga": {
                "min_length": 8,
                "max_length": 64,
                "min_entropy": 3.5,
                "max_digit_ratio": 0.3,
                "ngram_score": 0.1,
                "min_queries": 3
            },
            "risk_scoring": {
                "severity_mapping": {
                    "low": [0, 30],
                    "medium": [31, 60],
                    "high": [61, 80],
                    "critical": [81, 100]
                },
                "weights": {
                    "rule_based": 0.6,
                    "anomaly_score": 0.2,
                    "ml_confidence": 0.2
                }
            }
        }
    
    def get(self, config_name: str, *keys: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            config_name: Name of the config file ('main' or 'thresholds')
            *keys: Key path to the value
            default: Default value if key not found
            
        Returns:
            The configuration value or default
        """
        config = self.configs.get(config_name, {})
        value = config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def get_threshold(self, detector: str, param: str, default: Any = None) -> Any:
        """
        Get a detection threshold value.
        
        Args:
            detector: Detector name (e.g., 'port_scan', 'ddos', 'dga')
            param: Parameter name (e.g., 'min_unique_destination_ports')
            default: Default value if not found
            
        Returns:
            The threshold value or default
        """
        return self.get('thresholds', detector, param, default=default)
    
    def reload(self) -> None:
        """Reload all configuration files."""
        self.configs.clear()
        self._load_all_configs()


# Create singleton instance for easy access
config_manager = ConfigManager()