"""Passive TLS/QUIC encrypted-session anomaly detector; never decrypts payloads."""
from collections import defaultdict
from typing import List
from src.detectors.contracts import DetectionResult, flow_window_fields
from src.flow.nfstream_wrapper import FlowRecord

class EncryptedSessionDetector:
    def __init__(self, min_bytes=50000, min_duration_s=10.0, min_score=0.70):
        self.min_bytes=min_bytes; self.min_duration_s=min_duration_s; self.min_score=min_score

    def detect(self, flows: List[FlowRecord]):
        candidates=[f for f in flows if f.destination_port in (443,8443) or f.source_port in (443,8443)
                    or getattr(f,"tls_metadata",None) or getattr(f,"quic_metadata",None)]
        if not candidates: return []
        dest_counts=defaultdict(int)
        for f in candidates: dest_counts[f.destination_ip]+=1
        out=[]
        for f in candidates:
            encrypted=bool(f.tls_metadata or f.quic_metadata)
            if not encrypted: continue
            duration=max(f.duration,0.0); outbound=f.src2dst_bytes; inbound=f.dst2src_bytes
            asym=outbound/max(inbound,1)
            score=0.0
            if outbound>=self.min_bytes: score+=0.35
            if duration>=self.min_duration_s: score+=0.15
            if asym>=5: score+=0.20
            if dest_counts[f.destination_ip]<=1: score+=0.15
            if getattr(f,"ja4",None) or getattr(f,"ja3",None): score+=0.05
            if f.bidirectional_mean_piat_ms>0 and f.bidirectional_mean_piat_ms<20: score+=0.10
            if score<self.min_score: continue
            ids,start,end=flow_window_fields([f])
            kind="TLS" if f.tls_metadata else "QUIC"
            evidence={"session_type":kind,"outbound_bytes":outbound,"inbound_bytes":inbound,
                      "outbound_inbound_ratio":asym,"duration_s":duration,
                      "destination_rarity":1/max(dest_counts[f.destination_ip],1),
                      "fingerprint_available":bool(getattr(f,"ja4",None) or getattr(f,"ja3",None))}
            out.append(DetectionResult(detector="encrypted_session",detected=True,
                attack_type="ENCRYPTED_SESSION_MALWARE",attack_subtype=f"{kind.lower()}_metadata_anomaly",
                flow_ids=ids,source_ip=f.source_ip,destination_ip=f.destination_ip,
                source_port=f.source_port,destination_port=f.destination_port,protocol=f.protocol,
                event_start_time=start,event_end_time=end,rule_score=min(score,1.0),
                rule_confidence=min(score,1.0),evidence=evidence,
                details={"payload_decryption":False,"fingerprints":{"ja3":f.ja3,"ja3s":f.ja3s,"ja4":f.ja4}}))
        return out
