# Repair Baseline

- Source archive: cyber_detecter_repaired_complete.zip
- Python runtime: 3.13.5
- Baseline pytest command: `python -m pytest -q`
- Baseline collection: 216 tests collected, 4 collection errors, 1 skipped.
- Blocking baseline error: `ModuleNotFoundError: No module named 'scapy'` in tests/test_detectors.py, test_features.py, test_flow_extraction.py, test_pcap_reader.py.
- Existing detector factory entries: port_scan, ddos, dga, syn_flood, udp_flood.
- Existing ML modules: Random Forest, Isolation Forest; no serialized model artifacts were present in the archive.
- Existing pipeline: PCAP and live paths existed but did not share one complete ML/evidence/risk processing function.
- Existing alert model: contained rule/ML/CTI fields but still retained ambiguous `confidence` semantics and lacked observation-quality/incident fields.
- Existing FlowRecord: contained TCP/ICMP/DNS metadata, but had duplicate DNS fields and duplicate `normalized()` methods; live feature calculation incorrectly used packets/sec as packet-size statistics and duration/N for PIAT.
- Configuration default enabled detectors were `port_scan`, `ddos`, `dga`, so the complete required threat taxonomy was not enabled by default.
- No dedicated C2 beaconing, encrypted-session metadata, or exfiltration detector modules were present.
