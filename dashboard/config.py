"""
Dashboard Configuration
Configuration settings for the Streamlit dashboard.
"""

import streamlit as st
from pathlib import Path
import sys

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Dashboard settings
DASHBOARD_TITLE = "Cyber Threat Detection Platform"
DASHBOARD_ICON = "🛡️"

# Database settings
DATABASE_PATH = "data/threats.db"

# Refresh settings
DEFAULT_REFRESH_INTERVAL = 10  # seconds
MIN_REFRESH_INTERVAL = 5
MAX_REFRESH_INTERVAL = 60

# Alert display settings
DEFAULT_ALERT_LIMIT = 100
MAX_ALERT_LIMIT = 1000

# Color scheme
SEVERITY_COLORS = {
    'CRITICAL': '#ff0000',
    'HIGH': '#ff6600',
    'MEDIUM': '#ffcc00',
    'LOW': '#00cc00'
}

# Chart settings
CHART_HEIGHT = 400
PIE_CHART_HOLE_SIZE = 0.4

# Table settings
TABLE_HEIGHT = 400