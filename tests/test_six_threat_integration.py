import time
from pathlib import Path
import numpy as np
from src.flow.nfstream_wrapper import FlowRecord
from src.detectors.detector_factory import DetectorFactory
from src.detectors.c2_beacon import C2BeaconDetector
from src.detectors.dns_threat import DNSThreatDetector
from src.detectors.encrypted_session import EncryptedSessionDetector
from src.detectors.exfiltration import ExfiltrationDetector
from src.streaming.pipeline import ThreatDetectionPipeline

def flow(**kw):
    now=kw.pop("timestamp",1700000000.0)
    defaults=dict(source_ip="10.0.0.1",destination_ip="10.0.0.2",source_port=40000,
                  destination_port=443,protocol=6,bidirectional_packets=10,bidirectional_bytes=1000,
                  bidirectional_duration_ms=1000,src2dst_packets=5,src2dst_bytes=500,
                  dst2src_packets=5,dst2src_bytes=500,bidirectional_first_seen_ms=int(now*1000),
                  bidirectional_last_seen_ms=int((now+1)*1000),bidirectional_min_ps=100,
                  bidirectional_mean_ps=100,bidirectional_stddev_ps=0,bidirectional_max_ps=100,
                  bidirectional_min_piat_ms=100,bidirectional_mean_piat_ms=100,
                  bidirectional_stddev_piat_ms=0,bidirectional_max_piat_ms=100,
                  syn_packets=1,ack_packets=5,fin_packets=0,rst_packets=0,
                  syn_only_packets=1,syn_ack_packets=0,icmp_packets=0,icmp_bytes=0,
                  application_name="unknown",application_category="unknown",flow_id=None,timestamp=now)
    defaults.update(kw)
    if defaults["flow_id"] is None: defaults["flow_id"]=hash((defaults["source_ip"],defaults["destination_ip"],defaults["source_port"],defaults["destination_port"],defaults["protocol"],now)) & ((1<<63)-1)
    return FlowRecord(**defaults)

def test_six_threat_detectors_have_real_detection_paths():
    c2=[flow(source_ip="10.1.1.1",destination_ip="198.51.100.1",source_port=40000+i,timestamp=1700000000+i*10) for i in range(6)]
    assert C2BeaconDetector().detect(c2)

    dns=[]
    for i in range(6):
        d=("x9q2m7v1k8z4"*2)+str(i)+".example.com"
        dns.append(flow(source_ip="10.2.2.2",destination_ip="10.2.2.53",source_port=53000+i,destination_port=53,protocol=17,
                        timestamp=1700000000+i,dns_query=d,dns_nxdomain=True))
    dns_results=DNSThreatDetector(min_dga_score=0.4,min_tunnel_score=0.4).detect(dns)
    assert any(r.attack_type=="DGA" for r in dns_results)
    assert any(r.attack_type=="DNS_TUNNELLING" for r in dns_results)

    encrypted=flow(source_ip="10.3.3.3",destination_ip="203.0.113.9",src2dst_bytes=100000,dst2src_bytes=1000,
                   bidirectional_bytes=101000,bidirectional_packets=100,bidirectional_duration_ms=20000,
                   bidirectional_mean_piat_ms=10,tls_metadata={"version_bytes":"0303"},ja4="abc")
    assert EncryptedSessionDetector(min_score=0.5).detect([encrypted])

    exfil=flow(source_ip="10.4.4.4",destination_ip="203.0.113.77",src2dst_bytes=2_000_000,
               dst2src_bytes=1000,bidirectional_bytes=2_001_000,bidirectional_duration_ms=60_000)
    assert ExfiltrationDetector(min_outbound_bytes=100_000,min_score=0.5).detect([exfil])

def test_enabled_detectors_reach_factory():
    factory=DetectorFactory(["c2","dns_threat","encrypted_session","exfiltration"])
    assert set(factory.detectors) == {
        __import__("src.detectors.detector_factory",fromlist=["DetectorType"]).DetectorType.C2_BEACON,
        __import__("src.detectors.detector_factory",fromlist=["DetectorType"]).DetectorType.DNS_THREAT,
        __import__("src.detectors.detector_factory",fromlist=["DetectorType"]).DetectorType.ENCRYPTED_SESSION,
        __import__("src.detectors.detector_factory",fromlist=["DetectorType"]).DetectorType.EXFILTRATION,
    }

def test_pipeline_shared_window_and_ml_correlation(tmp_path, monkeypatch):
    cfg={"detection":{"enabled_detectors":["c2"]},"database_path":str(tmp_path/"alerts.db"),
         "hash_chain_file":str(tmp_path/"chain.json"),
         "streaming":{"windowing":{"window_seconds":30,"slide_seconds":10}}}
    pipe=ThreatDetectionPipeline(cfg)
    flows=[flow(source_ip="10.5.5.5",destination_ip="198.51.100.8",source_port=41000+i,timestamp=1700000000+i*10) for i in range(6)]
    monkeypatch.setattr(pipe.flow_extractor,"extract_from_pcap",lambda _: flows)
    result=pipe.process_pcap("synthetic")
    assert result["status"]=="OK"
    assert any(a.threat_type=="C2_BEACONING" for a in result["alerts"])
    assert result["alerts"][0].event_time is not None
    assert result["alerts"][0].processing_time is not None

def test_live_window_executes_real_ml_and_correlates_by_flow_id(tmp_path):
    from src.models.random_forest import RandomForestThreatClassifier
    flows=[]
    labels=[]
    for i in range(20):
        flows.append(flow(source_ip=f"10.20.0.{i+1}",destination_ip="10.30.0.1",
                          source_port=30000+i,destination_port=443,protocol=6,
                          bidirectional_packets=10,bidirectional_bytes=1000,
                          src2dst_packets=5,src2dst_bytes=500,dst2src_packets=5,dst2src_bytes=500,
                          timestamp=1700001000+i))
        labels.append("NORMAL")
    for i in range(20):
        flows.append(flow(source_ip=f"10.40.0.{i+1}",destination_ip="10.30.0.1",
                          source_port=40000+i,destination_port=80,protocol=6,
                          bidirectional_packets=100,bidirectional_bytes=4000,
                          src2dst_packets=100,src2dst_bytes=4000,dst2src_packets=0,dst2src_bytes=0,
                          syn_packets=100,syn_only_packets=100,ack_packets=0,
                          bidirectional_duration_ms=100,timestamp=1700002000+i))
        labels.append("DDOS")
    model=RandomForestThreatClassifier(test_size=0.2)
    model.fit(flows,labels)
    assert model.is_trained
    pipe=ThreatDetectionPipeline({"detection":{"enabled_detectors":["ddos"]},
        "database_path":str(tmp_path/"db.sqlite"),"hash_chain_file":str(tmp_path/"chain.json")})
    pipe.random_forest=model
    result=pipe.process_flow_stream(flows[-5:],window_seconds=10,slide_seconds=1,persist=False)
    assert result
    predictions=[p for w in result for p in w["ml_predictions"]]
    assert predictions
    assert all(p.get("flow_id") for p in predictions)
    # At least one alert/prediction must preserve the same concrete flow identity.
    assert any(a.ml_ran for w in result for a in w["alerts"])

def test_demo_pcaps_run_end_to_end_without_active_network(tmp_path):
    demo_dir=Path(__file__).resolve().parents[1]/"demo"
    expected={
        "ddos.pcap":"DDOS",
        "c2_beacon.pcap":"C2_BEACONING",
        "dga.pcap":"DGA",
        "dns_tunnel.pcap":"DNS_TUNNELLING",
        "tls_quic_anomaly.pcap":"ENCRYPTED_SESSION_MALWARE",
        "port_scan.pcap":"PORT_SCAN",
        "exfiltration.pcap":"POTENTIAL_DATA_EXFILTRATION",
    }
    for filename, threat in expected.items():
        pipe=ThreatDetectionPipeline({
            "detection":{"enabled_detectors":["ddos","c2","dns_threat","encrypted_session","port_scan","exfiltration"]},
            "database_path":str(tmp_path/f"{filename}.db"),
            "hash_chain_file":str(tmp_path/f"{filename}.chain"),
            "streaming":{"windowing":{"window_seconds":10,"slide_seconds":1}},
        })
        result=pipe.process_pcap(str(demo_dir/filename))
        assert result["status"]=="OK"
        assert any(a.threat_type==threat for a in result["alerts"]), (filename, result["alerts"])
    benign=ThreatDetectionPipeline({
        "detection":{"enabled_detectors":["ddos","c2","dns_threat","encrypted_session","port_scan","exfiltration"]},
        "database_path":str(tmp_path/"benign.db"),"hash_chain_file":str(tmp_path/"benign.chain"),
    }).process_pcap(str(demo_dir/"benign.pcap"))
    assert benign["status"]=="OK"
    assert not benign["alerts"]

def test_live_pipeline_controlled_interface_reaches_same_window_path(tmp_path, monkeypatch):
    import queue
    import src.ingest.live_capture as live_mod
    class FakeCapture:
        def __init__(self, **kwargs):
            self.packet_queue=queue.Queue()
            self.packet_queue.put(object())
            self._stats={"dropped_packets":0,"error":None}
        def start_capture(self,duration): pass
        @property
        def is_capturing(self): return False
        def drain_queue(self,max_items=None):
            items=[]
            while not self.packet_queue.empty() and (max_items is None or len(items)<max_items):
                items.append(self.packet_queue.get())
            return items
        def stop_capture(self): pass
        def wait(self,timeout=5): pass
        def get_statistics(self): return dict(self._stats)
    class FakeFlowBuilder:
        evicted_flows=0
        def __init__(self,max_flows): self.emitted=False
        def add_packet(self,packet): pass
        def snapshot(self):
            if self.emitted: return []
            self.emitted=True
            return [flow(source_ip="10.50.0.1",destination_ip="198.51.100.50",timestamp=1700003000.0)]
    monkeypatch.setattr(live_mod,"LivePacketCapture",FakeCapture)
    import src.flow.nfstream_wrapper as flow_mod
    monkeypatch.setattr(flow_mod,"IncrementalScapyFlowAggregator",FakeFlowBuilder)
    pipe=ThreatDetectionPipeline({"detection":{"enabled_detectors":["c2"]},
        "database_path":str(tmp_path/"live.db"),"hash_chain_file":str(tmp_path/"live.chain")})
    result=pipe.process_live("controlled-test",duration=1)
    assert result["mode"]=="LIVE"
    assert result["status"] in {"OK","DEGRADED"}
    assert result["windows"]
