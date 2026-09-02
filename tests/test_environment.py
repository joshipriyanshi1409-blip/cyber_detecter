"""
Basic environment tests
Run: pytest tests/test_environment.py -v
"""

import sys
import pytest

def test_python_version():
    """Test Python version is 3.11+"""
    assert sys.version_info.major >= 3
    assert sys.version_info.minor >= 11

def test_import_scapy():
    """Test Scapy imports"""
    import scapy
    assert scapy is not None

def test_import_nfstream():
    """Test NFStream imports"""
    import nfstream
    assert nfstream is not None

def test_import_numpy():
    """Test NumPy imports"""
    import numpy as np
    assert np.__version__ >= "1.24.0"

def test_import_pandas():
    """Test Pandas imports"""
    import pandas as pd
    assert pd.__version__ >= "2.0.0"

def test_import_sklearn():
    """Test scikit-learn imports"""
    import sklearn
    assert sklearn.__version__ >= "1.3.0"

def test_import_sqlalchemy():
    """Test SQLAlchemy imports"""
    import sqlalchemy
    assert sqlalchemy.__version__ >= "2.0.0"

def test_import_streamlit():
    """Test Streamlit imports"""
    import streamlit as st
    assert st is not None

def test_import_plotly():
    """Test Plotly imports"""
    import plotly
    assert plotly is not None

def test_import_yaml():
    """Test PyYAML imports"""
    import yaml
    assert yaml is not None

def test_import_joblib():
    """Test Joblib imports"""
    import joblib
    assert joblib is not None