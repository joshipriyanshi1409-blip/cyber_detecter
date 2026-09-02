#!/usr/bin/env python3
"""
Run Dashboard Script
Launches the Streamlit dashboard.
"""

import subprocess
import sys
from pathlib import Path

def main():
    """Launch Streamlit dashboard"""
    dashboard_path = Path("dashboard/app.py")
    
    if not dashboard_path.exists():
        print(f" Dashboard not found: {dashboard_path}")
        return 1
    
    print("=" * 60)
    print("LAUNCHING CYBER THREAT DETECTION DASHBOARD")
    print("=" * 60)
    print(f"Dashboard: {dashboard_path}")
    print("URL: http://localhost:8501")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run",
            str(dashboard_path),
            "--server.port", "8501",
            "--server.address", "localhost",
            "--browser.gatherUsageStats", "false"
        ])
        return 0
    except KeyboardInterrupt:
        print("\nDashboard stopped")
        return 0
    except Exception as e:
        print(f"Failed to launch dashboard: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())