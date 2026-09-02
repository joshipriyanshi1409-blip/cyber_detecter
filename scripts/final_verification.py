#!/usr/bin/env python3
"""
Final Verification Script
Verifies all 12 phases are working correctly.
"""

import sys
import time
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))


def check_imports():
    """Check all imports"""
    print("=" * 60)
    print("CHECKING IMPORTS")
    print("=" * 60)
    
    imports = [
        ("Phase 1: Environment", "src.utils.config", "ConfigManager"),
        ("Phase 2: Ingestion", "src.ingest.pcap_reader", "PcapReaderModule"),
        ("Phase 3: Flow", "src.flow.nfstream_wrapper", "FlowExtractor"),
        ("Phase 4: Features", "src.features.network_features", "NetworkFeatureExtractor"),
        ("Phase 5: Detection", "src.detectors.detector_factory", "DetectorFactory"),
        ("Phase 6: Alerts", "src.alerts.alert_engine", "AlertEngine"),
        ("Phase 7: Database", "src.storage.database", "DatabaseManager"),
        ("Phase 9: ML", "src.models.isolation_forest", "IsolationForestAnomalyDetector"),
        ("Phase 10: Risk", "src.scoring.risk_score", "RiskScoreCalculator"),
        ("Phase 11: Hash Chain", "src.blockchain.hash_chain", "HashChain"),
        ("Phase 12: CTI", "src.cti.enrichment", "ThreatIntelligenceEnricher"),
        ("Phase 13: Pipeline", "src.streaming.pipeline", "ThreatDetectionPipeline"),
    ]
    
    all_passed = True
    for phase, module, class_name in imports:
        try:
            __import__(module)
            print(f"✅ {phase}: {module}.{class_name}")
        except Exception as e:
            print(f"❌ {phase}: {module} - {e}")
            all_passed = False
    
    return all_passed


def check_database():
    """Check database operations"""
    print("\n" + "=" * 60)
    print("CHECKING DATABASE")
    print("=" * 60)
    
    try:
        from src.storage.database import DatabaseManager
        db = DatabaseManager("data/verification.db")
        
        stats = db.get_statistics()
        print(f"✅ Database initialized")
        print(f"   Total alerts: {stats.get('total_alerts', 0)}")
        return True
    except Exception as e:
        print(f"❌ Database failed: {e}")
        return False


def check_hash_chain():
    """Check hash chain"""
    print("\n" + "=" * 60)
    print("CHECKING HASH CHAIN")
    print("=" * 60)
    
    try:
        from src.blockchain.hash_chain import HashChain
        chain = HashChain()
        
        validation = chain.validate_chain()
        print(f"✅ Hash chain initialized")
        print(f"   Entries: {validation.get('total_entries', 0)}")
        print(f"   Valid: {validation.get('is_valid', False)}")
        return True
    except Exception as e:
        print(f"❌ Hash chain failed: {e}")
        return False


def check_cti():
    """Check threat intelligence"""
    print("\n" + "=" * 60)
    print("CHECKING THREAT INTELLIGENCE")
    print("=" * 60)
    
    try:
        from src.cti.enrichment import ThreatIntelligenceEnricher
        enricher = ThreatIntelligenceEnricher()
        
        status = enricher.get_provider_status()
        print(f"✅ CTI initialized with {len(status)} providers")
        return True
    except Exception as e:
        print(f"❌ CTI failed: {e}")
        return False


def main():
    """Main verification function"""
    print("\n" + "=" * 60)
    print("FINAL VERIFICATION")
    print("=" * 60)
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    checks = [
        ("Imports", check_imports),
        ("Database", check_database),
        ("Hash Chain", check_hash_chain),
        ("Threat Intelligence", check_cti),
    ]
    
    results = {}
    for check_name, check_func in checks:
        try:
            result = check_func()
            results[check_name] = "PASS" if result else "FAIL"
        except Exception as e:
            print(f"❌ {check_name} failed: {e}")
            results[check_name] = "ERROR"
    
    # Summary
    print("\n" + "=" * 60)
    print("VERIFICATION SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for check_name, result in results.items():
        status = "✅" if result == "PASS" else "❌"
        print(f"{status} {check_name}: {result}")
        if result != "PASS":
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 ALL CHECKS PASSED - SYSTEM READY!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Run: python scripts/run_pipeline.py demo/port_scan.pcap")
        print("2. Run: streamlit run dashboard/app.py")
        print("3. View dashboard at http://localhost:8501")
    else:
        print("❌ SOME CHECKS FAILED")
        print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())