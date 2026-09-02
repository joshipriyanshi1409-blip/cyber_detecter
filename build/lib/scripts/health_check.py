#!/usr/bin/env python3
"""
Health check script to verify environment setup
Run: python scripts/health_check.py
"""

import sys
import importlib

def check_python_version():
    """Check Python version is 3.11+"""
    print("\n=== Python Version Check ===")
    version = sys.version_info
    print(f"Python version: {sys.version}")
    if version.major >= 3 and version.minor >= 11:
        print("PASS: Python 3.11+ detected")
        return True
    else:
        print("FAIL: Python 3.11+ required")
        return False

def check_packages():
    """Check required packages are installed"""
    print("\n=== Package Installation Check ===")
    packages = [
        'scapy',
        'nfstream',
        'numpy',
        'pandas',
        'sklearn',
        'sqlalchemy',
        'streamlit',
        'plotly',
        'yaml',
        'joblib',
        'pytest',
        'dotenv',
        'requests'
    ]
    
    all_installed = True
    for package in packages:
        try:
            importlib.import_module(package)
            print(f"{package}")
        except ImportError:
            print(f"{package} - NOT INSTALLED")
            all_installed = False
    
    return all_installed

def check_tshark():
    """Check if tshark is available"""
    print("\n=== TShark Check ===")
    import subprocess
    try:
        result = subprocess.run(['tshark', '--version'], 
                              capture_output=True, 
                              text=True,
                              timeout=5)
        if result.returncode == 0:
            print("tshark is available")
            print(f"   Version: {result.stdout.split()[1] if len(result.stdout.split()) > 1 else 'unknown'}")
            return True
        else:
            print("WARNING: tshark found but returned an error")
            return False
    except FileNotFoundError:
        print("WARNING: tshark not found in PATH (optional)")
        print("   Install Wireshark and add tshark to PATH for full functionality")
        return False

def check_directories():
    """Check project structure exists"""
    print("\n=== Directory Structure Check ===")
    import os
    required_dirs = [
        'config', 'data', 'models', 'src', 'dashboard', 
        'scripts', 'tests', 'docs', 'demo',
        'data/raw', 'data/processed', 'data/samples',
        'src/ingest', 'src/flow', 'src/features', 'src/detectors',
        'src/models', 'src/streaming', 'src/alerts', 'src/scoring',
        'src/blockchain', 'src/storage', 'src/utils'
    ]
    
    all_exist = True
    for dir_path in required_dirs:
        if os.path.exists(dir_path):
            print(f"{dir_path}")
        else:
            print(f"{dir_path} - MISSING")
            all_exist = False
    
    return all_exist

def main():
    """Run all checks"""
    print("=" * 50)
    print("CYBER THREAT DETECTION - HEALTH CHECK")
    print("=" * 50)
    
    checks = [
        check_python_version(),
        check_packages(),
        check_tshark(),
        check_directories()
    ]
    
    print("\n" + "=" * 50)
    print("HEALTH CHECK SUMMARY")
    print("=" * 50)
    
    if all(checks):
        print("ALL CHECKS PASSED - Environment is ready!")
        print("\nNext step: Proceed to Phase 2 - Traffic Ingestion")
        return 0
    else:
        print("SOME CHECKS FAILED - Please fix the issues above")
        return 1

if __name__ == "__main__":
    sys.exit(main())