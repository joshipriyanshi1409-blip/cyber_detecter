#!/usr/bin/env python3
"""
Cyber Threat Detection Dashboard
Streamlit dashboard for displaying alerts and statistics.
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta, timezone
import time
import uuid

from src.storage.database import DatabaseManager
from src.alerts.alert_models import Alert, AlertSeverity

# --- PCAP upload settings -----------------------------------------------
# Uploaded files are never trusted with their original name/path: we
# generate our own filename and confine writes to this directory to avoid
# path traversal, and we cap size to avoid a single upload exhausting
# memory/disk (rdpcap() loads the whole file into RAM downstream).
PCAP_UPLOAD_DIR = Path("data/uploads")
MAX_PCAP_UPLOAD_MB = 200
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng"}



def require_dashboard_auth() -> None:
    """Require an application password before exposing security telemetry."""
    import os
    import hmac

    configured = os.getenv("DASHBOARD_PASSWORD", "")
    if not configured:
        st.error(
            "Dashboard authentication is not configured. Set DASHBOARD_PASSWORD "
            "before exposing the dashboard."
        )
        st.stop()

    if st.session_state.get("authenticated"):
        return

    st.title("Cyber Detecter — Authentication Required")
    supplied = st.text_input("Dashboard password", type="password")
    if st.button("Sign in", type="primary"):
        if hmac.compare_digest(supplied, configured):
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Invalid password.")
    st.stop()


# Page configuration
st.set_page_config(
    page_title="Cyber Threat Detection Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

require_dashboard_auth()

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #f0f2f6, #ffffff, #f0f2f6);
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
    }
    .alert-critical {
        color: #ff0000;
        font-weight: bold;
    }
    .alert-high {
        color: #ff6600;
        font-weight: bold;
    }
    .alert-medium {
        color: #ffcc00;
        font-weight: bold;
    }
    .alert-low {
        color: #00cc00;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


# Initialize database connection
@st.cache_resource
def get_database():
    """Get database manager instance"""
    db_path = Path("data/threats.db")
    return DatabaseManager(str(db_path))


def load_alerts(limit: int = 100) -> pd.DataFrame:
    """Load alerts from database into DataFrame"""
    db = get_database()
    alerts = db.get_alerts(limit=limit)
    
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


def load_statistics() -> dict:
    """Load statistics from database"""
    db = get_database()
    return db.get_statistics()


def get_severity_color(severity: str) -> str:
    """Get color for severity level"""
    colors = {
        'CRITICAL': '#ff0000',
        'HIGH': '#ff6600',
        'MEDIUM': '#ffcc00',
        'LOW': '#00cc00'
    }
    return colors.get(severity, '#999999')


def display_summary_metrics(stats: dict):
    """Display summary metrics at top of dashboard"""
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            label="Total Alerts",
            value=stats.get('total_alerts', 0),
            delta=None
        )
    
    with col2:
        st.metric(
            label="Critical Alerts",
            value=stats.get('critical_count', 0),
            delta=None
        )
    
    with col3:
        st.metric(
            label="High Alerts",
            value=stats.get('high_count', 0),
            delta=None
        )
    
    with col4:
        st.metric(
            label="Medium Alerts",
            value=stats.get('medium_count', 0),
            delta=None
        )
    
    with col5:
        st.metric(
            label="Low Alerts",
            value=stats.get('low_count', 0),
            delta=None
        )


def display_alerts_table(df: pd.DataFrame):
    """Display alerts in a table format"""
    if df.empty:
        st.info("No alerts available in the database.")
        return
    
    # Filter options
    st.subheader("🔍 Filter Alerts")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        severity_filter = st.multiselect(
            "Severity",
            options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        )
    
    with col2:
        threat_types = df['threat_type'].unique().tolist()
        type_filter = st.multiselect(
            "Threat Type",
            options=threat_types,
            default=threat_types
        )
    
    with col3:
        statuses = df['status'].unique().tolist()
        status_filter = st.multiselect(
            "Status",
            options=statuses,
            default=statuses
        )
    
    with col4:
        min_risk = st.slider(
            "Minimum Risk Score",
            min_value=0,
            max_value=100,
            value=0,
            step=5
        )
    
    # Apply filters
    filtered_df = df[
        (df['severity'].isin(severity_filter)) &
        (df['threat_type'].isin(type_filter)) &
        (df['status'].isin(status_filter)) &
        (df['risk_score'] >= min_risk)
    ]
    
    # Display filtered table
    st.subheader(f"📋 Alerts ({len(filtered_df)} total)")
    
    # Format DataFrame for display
    display_df = filtered_df.copy()
    display_df['timestamp'] = display_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    display_df['risk_score'] = display_df['risk_score'].round(2)
    display_df['confidence'] = display_df['confidence'].round(2)
    
    # Color code severity
    def color_severity(val):
        color = get_severity_color(val)
        return f'color: {color}; font-weight: bold'
    
    styled_df = display_df.style.applymap(
        color_severity,
        subset=['severity']
    )
    
    st.dataframe(
        styled_df,
        use_container_width=True,
        height=400
    )


def display_threat_distribution(df: pd.DataFrame):
    """Display threat type distribution"""
    if df.empty:
        return
    
    st.subheader("📊 Threat Distribution")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Pie chart for threat types
        threat_counts = df['threat_type'].value_counts()
        fig_pie = px.pie(
            values=threat_counts.values,
            names=threat_counts.index,
            title="Threat Types",
            hole=0.4
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # Bar chart for severity
        severity_counts = df['severity'].value_counts()
        fig_bar = px.bar(
            x=severity_counts.index,
            y=severity_counts.values,
            title="Alerts by Severity",
            color=severity_counts.index,
            color_discrete_map={
                'CRITICAL': '#ff0000',
                'HIGH': '#ff6600',
                'MEDIUM': '#ffcc00',
                'LOW': '#00cc00'
            }
        )
        fig_bar.update_layout(
            xaxis_title="Severity",
            yaxis_title="Count",
            showlegend=False
        )
        st.plotly_chart(fig_bar, use_container_width=True)


def display_timeline(df: pd.DataFrame):
    """Display alert timeline"""
    if df.empty:
        return
    
    st.subheader("📈 Alert Timeline")
    
    # Create time series data
    df_sorted = df.sort_values('timestamp')
    df_sorted['hour'] = df_sorted['timestamp'].dt.floor('H')
    
    timeline_data = df_sorted.groupby(['hour', 'severity']).size().reset_index(name='count')
    
    fig_timeline = px.line(
        timeline_data,
        x='hour',
        y='count',
        color='severity',
        title="Alerts Over Time",
        color_discrete_map={
            'CRITICAL': '#ff0000',
            'HIGH': '#ff6600',
            'MEDIUM': '#ffcc00',
            'LOW': '#00cc00'
        }
    )
    fig_timeline.update_layout(
        xaxis_title="Time",
        yaxis_title="Alert Count",
        legend_title="Severity"
    )
    st.plotly_chart(fig_timeline, use_container_width=True)


def display_top_sources(df: pd.DataFrame):
    """Display top source IPs"""
    if df.empty:
        return
    
    st.subheader("🔝 Top Source IPs")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Bar chart for top sources
        source_counts = df['source_ip'].value_counts().head(10)
        fig_sources = px.bar(
            x=source_counts.index,
            y=source_counts.values,
            title="Top Source IPs",
            labels={'x': 'Source IP', 'y': 'Alert Count'}
        )
        st.plotly_chart(fig_sources, use_container_width=True)
    
    with col2:
        # Bar chart for top destinations
        dest_counts = df['destination_ip'].value_counts().head(10)
        fig_dest = px.bar(
            x=dest_counts.index,
            y=dest_counts.values,
            title="Top Destination IPs",
            labels={'x': 'Destination IP', 'y': 'Alert Count'}
        )
        st.plotly_chart(fig_dest, use_container_width=True)


def display_risk_analysis(df: pd.DataFrame):
    """Display risk score analysis"""
    if df.empty:
        return
    
    st.subheader("🎯 Risk Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Histogram of risk scores
        fig_hist = px.histogram(
            df,
            x='risk_score',
            nbins=20,
            title="Risk Score Distribution",
            color='severity',
            color_discrete_map={
                'CRITICAL': '#ff0000',
                'HIGH': '#ff6600',
                'MEDIUM': '#ffcc00',
                'LOW': '#00cc00'
            }
        )
        st.plotly_chart(fig_hist, use_container_width=True)
    
    with col2:
        # Scatter plot of risk vs confidence
        fig_scatter = px.scatter(
            df,
            x='confidence',
            y='risk_score',
            color='severity',
            size='risk_score',
            hover_data=['threat_type', 'source_ip'],
            title="Risk Score vs Confidence",
            color_discrete_map={
                'CRITICAL': '#ff0000',
                'HIGH': '#ff6600',
                'MEDIUM': '#ffcc00',
                'LOW': '#00cc00'
            }
        )
        st.plotly_chart(fig_scatter, use_container_width=True)


def display_alert_details(df: pd.DataFrame):
    """Display detailed alert information"""
    if df.empty:
        return
    
    st.subheader("🔍 Alert Details")
    
    # Select alert to view details
    selected_alert_id = st.selectbox(
        "Select Alert",
        options=df['alert_id'].tolist(),
        format_func=lambda x: f"{x} - {df[df['alert_id'] == x]['threat_type'].iloc[0]}"
    )
    
    if selected_alert_id:
        db = get_database()
        alert = db.get_alert(selected_alert_id)
        
        if alert:
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Basic Information**")
                st.write(f"**Alert ID:** {alert.alert_id}")
                st.write(f"**Timestamp:** {alert.timestamp}")
                st.write(f"**Threat Type:** {alert.threat_type}")
                st.write(f"**Category:** {alert.category}")
                st.write(f"**Status:** {alert.status}")
                
                severity_color = get_severity_color(alert.severity)
                st.markdown(f"**Severity:** <span style='color:{severity_color};font-weight:bold'>{alert.severity}</span>", unsafe_allow_html=True)
            
            with col2:
                st.markdown("**Network Information**")
                st.write(f"**Source IP:** {alert.source_ip}")
                st.write(f"**Destination IP:** {alert.destination_ip}")
                st.write(f"**Detector:** {alert.detector}")
                st.write(f"**Risk Score:** {alert.risk_score:.2f}")
                st.write(f"**Confidence:** {alert.confidence:.2f}")
            
            if alert.description:
                st.markdown("**Description**")
                st.info(alert.description)
            
            if alert.details:
                st.markdown("**Details**")
                st.json(alert.details)
            
            if alert.evidence:
                st.markdown("**Evidence**")
                st.json(alert.evidence)


def handle_pcap_upload():
    """
    Sidebar widget: let the user add a PCAP file and run it through the
    detection pipeline. Kept isolated from the query/display helpers above
    so a bad upload can't affect anything already on screen.
    """
    st.subheader("📤 Add PCAP")

    uploaded_file = st.file_uploader(
        "Upload a .pcap / .pcapng file to analyze",
        type=["pcap", "pcapng"],
        help=f"Max size: {MAX_PCAP_UPLOAD_MB} MB. Analyzed with the same "
             f"detection pipeline as the CLI (scripts/run_pipeline.py).",
    )

    if uploaded_file is None:
        return

    # Size check — uploaded_file.size is provided by Streamlit without
    # reading the whole file into our own memory first.
    size_mb = uploaded_file.size / (1024 * 1024)
    if size_mb > MAX_PCAP_UPLOAD_MB:
        st.error(
            f"'{uploaded_file.name}' is {size_mb:.1f} MB, which exceeds the "
            f"{MAX_PCAP_UPLOAD_MB} MB limit. Split it or use the CLI "
            f"pipeline (scripts/run_pipeline.py) for large captures."
        )
        return

    # Extension check. This is a shallow check (not a magic-byte / format
    # validation) — the pipeline call below is expected to fail cleanly
    # on a non-PCAP file, and that failure is surfaced to the user rather
    # than silently swallowed.
    suffix = Path(uploaded_file.name).suffix.lower()
    if suffix not in ALLOWED_PCAP_EXTENSIONS:
        st.error(f"Unsupported file type '{suffix}'. Upload a .pcap or .pcapng file.")
        return

    # Never trust the uploaded filename for the on-disk path (path
    # traversal / collision risk) — generate our own name and keep the
    # original only for display.
    PCAP_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe_path = PCAP_UPLOAD_DIR / f"{uuid.uuid4().hex}{suffix}"

    try:
        with open(safe_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        with st.spinner(f"Analyzing {uploaded_file.name}..."):
            from src.streaming.pipeline import ThreatDetectionPipeline

            pipeline = ThreatDetectionPipeline(
                config={"database_path": str(Path("data/threats.db"))}
            )
            results = pipeline.process_pcap(str(safe_path))

        stats = results.get("pipeline_stats", {})
        st.success(
            f"Processed '{uploaded_file.name}': "
            f"{stats.get('flows_processed', 0)} flows, "
            f"{stats.get('alerts_stored', 0)} alerts stored."
        )
        # Clear cached DB handle / stats so the new alerts show up.
        get_database.clear()
        st.rerun()

    except Exception as e:
        logger_msg = f"Failed to process uploaded PCAP {uploaded_file.name}: {e}"
        st.error(
            "Could not process that file — it may not be a valid PCAP, or "
            "an internal error occurred. Check the file and try again."
        )
        st.caption(logger_msg)
    finally:
        # Don't keep uploaded capture files around longer than needed.
        try:
            safe_path.unlink(missing_ok=True)
        except Exception:
            pass


def main():
    """Main dashboard function"""
    # Header
    st.markdown('<div class="main-header">🛡️ Cyber Threat Detection Platform</div>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("Dashboard Controls")
        
        # Refresh button
        if st.button("🔄 Refresh Data"):
            st.rerun()

        st.divider()

        # "corner" to add PCAP files for on-demand analysis
        handle_pcap_upload()

        st.divider()

        # Auto-refresh
        auto_refresh = st.checkbox("Auto Refresh", value=False)
        refresh_interval = st.slider(
            "Refresh Interval (seconds)",
            min_value=5,
            max_value=60,
            value=10,
            disabled=not auto_refresh
        )
        
        # Alert limit
        alert_limit = st.slider(
            "Number of Alerts",
            min_value=10,
            max_value=1000,
            value=100,
            step=10
        )
        
        st.divider()
        
        # Display current time
        st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Load data
    try:
        stats = load_statistics()
        alerts_df = load_alerts(limit=alert_limit)
        
        # Display summary metrics
        display_summary_metrics(stats)
        
        st.divider()
        
        # Create tabs for different views
        tab1, tab2, tab3, tab4 = st.tabs([
            "📋 Alerts",
            "📊 Statistics",
            "🔍 Details",
            "📈 Analysis"
        ])
        
        with tab1:
            display_alerts_table(alerts_df)
        
        with tab2:
            if alerts_df.empty:
                st.info("No alerts/data available")
            else:
                display_threat_distribution(alerts_df)
                st.divider()
                display_timeline(alerts_df)
        
        with tab3:
            display_alert_details(alerts_df)
        
        with tab4:
            if alerts_df.empty:
                st.info("No alerts/data available")
            else:
                display_top_sources(alerts_df)
                st.divider()
                display_risk_analysis(alerts_df)
        
        # Auto refresh
        if auto_refresh:
            time.sleep(refresh_interval)
            st.rerun()
            
    except Exception as e:
        st.error(f"Error loading dashboard: {e}")
        st.info("Please ensure the database is initialized and contains data.")
        st.code("""
# Initialize database with sample data:
python scripts/test_database.py
        """)


if __name__ == "__main__":
    main()