"""
Dashboard Utilities
Helper functions for the dashboard.
"""

import streamlit as st
import pandas as pd
from pathlib import Path
import sys
from datetime import datetime, timedelta
import plotly.graph_objects as go

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.database import DatabaseManager


def get_database_manager():
    """Get database manager instance"""
    db_path = Path("data/threats.db")
    return DatabaseManager(str(db_path))


def load_data(limit=100):
    """Load alerts and statistics from database"""
    db = get_database_manager()
    
    alerts = db.get_alerts(limit=limit)
    stats = db.get_statistics()
    
    return alerts, stats


def alerts_to_dataframe(alerts):
    """Convert alerts to DataFrame"""
    if not alerts:
        return pd.DataFrame()
    
    data = []
    for alert in alerts:
        data.append({
            'alert_id': alert.alert_id,
            'timestamp': alert.timestamp,
            'threat_type': alert.threat_type,
            'severity': alert.severity,
            'risk_score': alert.risk_score,
            'confidence': alert.confidence,
            'source_ip': alert.source_ip,
            'destination_ip': alert.destination_ip,
            'detector': alert.detector,
            'status': alert.status,
            'category': alert.category,
            'description': alert.description
        })
    
    df = pd.DataFrame(data)
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    return df


def create_gauge_chart(value, title, max_value=100):
    """Create a gauge chart for metrics"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={'text': title},
        gauge={
            'axis': {'range': [0, max_value]},
            'bar': {'color': "#1f77b4"},
            'steps': [
                {'range': [0, max_value*0.3], 'color': "lightgray"},
                {'range': [max_value*0.3, max_value*0.7], 'color': "gray"},
                {'range': [max_value*0.7, max_value], 'color': "darkgray"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': max_value*0.8
            }
        }
    ))
    
    fig.update_layout(height=300)
    return fig


def format_timestamp(timestamp_str):
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp_str)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError, KeyError):
        return timestamp_str


def get_severity_emoji(severity):
    """Get emoji for severity"""
    emojis = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢'
    }
    return emojis.get(severity, '⚪')


def filter_dataframe(df, severity=None, threat_type=None, min_risk=0):
    """Filter DataFrame based on criteria"""
    filtered = df.copy()
    
    if severity:
        filtered = filtered[filtered['severity'].isin(severity)]
    
    if threat_type:
        filtered = filtered[filtered['threat_type'].isin(threat_type)]
    
    if min_risk > 0:
        filtered = filtered[filtered['risk_score'] >= min_risk]
    
    return filtered