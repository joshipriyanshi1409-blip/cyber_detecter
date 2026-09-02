#!/usr/bin/env python3
"""
Test configuration loading
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

print("Python path:", sys.path[:3])
print("Current directory:", Path.cwd())

# Test config import
try:
    from src.utils.config import ConfigManager, config_manager
    print("Config import successful")
    
    # Test getting values
    threshold = config_manager.get_threshold("port_scan", "min_unique_ports", default=10)
    print(f"Port scan threshold: {threshold}")
    
    dga_threshold = config_manager.get_threshold("dga", "min_entropy", default=3.5)
    print(f"DGA entropy threshold: {dga_threshold}")
    
except ImportError as e:
    print(f"Config import failed: {e}")
    sys.exit(1)

# Test detector import
try:
    from src.detectors.scan import PortScanDetector
    detector = PortScanDetector()
    print("PortScanDetector import successful")
    print(f"Detector thresholds: {detector.thresholds}")
    
except ImportError as e:
    print(f" Detector import failed: {e}")
    sys.exit(1)

print("\n All tests passed!")