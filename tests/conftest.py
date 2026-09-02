"""
Pytest Configuration
Global test configuration and fixtures.
"""

import warnings
import pytest
import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))


def pytest_configure(config):
    """Configure pytest before tests run"""
    # Suppress specific deprecation warnings
    warnings.filterwarnings('ignore', category=DeprecationWarning, module='joblib')
    warnings.filterwarnings('ignore', category=DeprecationWarning, module='sklearn')
    warnings.filterwarnings('ignore', category=DeprecationWarning, message='.*Setting the shape on a NumPy array.*')
    
    # Add custom markers
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "ml: marks machine learning tests"
    )


@pytest.fixture(scope="session")
def project_root():
    """Return project root directory"""
    return Path(__file__).parent.parent