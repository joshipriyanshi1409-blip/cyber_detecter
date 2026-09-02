"""Potential data-exfiltration detector using passive outbound-volume heuristics."""
from collections import defaultdict
from statistics import mean
from typing import List
from src.detectors.contracts import DetectionResult, flow_window_fields
from src.flow.nfstream_wrapper import FlowRecord

class ExfiltrationDetector:
    def __init__(self, min_outbound_bytes=1_000_000, min_ratio=5.0, min_duration_s=30.0, min_score=0.70):
        self.min_outbound_bytes=min_outbound_bytes; self.min_ratio=min_ratio
        self.min_duration_s=min_duration_s; self.min_score=min_score
        self.baseline=defaultdict(lambda: {"samples":0,"mean":0.0})

    def detect(self, flows: List[FlowRecord]):
        if not flows: return []
        by_src=defaultdict(list)
        for f in flows: by_src[f.source_ip].append(f)
        dest_global=defaultdict(int)
        for f in flows: dest_global[f.destination_ip]+=1
        out=[]
        for src, items in by_src.items():
            outbound=[max(f.src2dst_bytes,0) for f in items]
            baseline_mean=mean(outbound) if outbound else 0.0
            for f in items:
                out_b=max(f.src2dst_bytes,0); in_b=max(f.dst2src_bytes,0)
                ratio=out_b/max(in_b,1); duration=max(f.duration,0.0)
                score=0.0
                if out_b>=self.min_outbound_bytes: score+=0.35
                if ratio>=self.min_ratio: score+=0.20
                if duration>=self.min_duration_s: score+=0.15
                if dest_global[f.destination_ip]<=1: score+=0.15
                if baseline_mean>0 and out_b>=max(self.min_outbound_bytes,baseline_mean*5): score+=0.15
                if score<self.min_score: continue
                ids,start,end=flow_window_fields([f])
                out.append(DetectionResult(detector="exfiltration",detected=True,
                    attack_type="POTENTIAL_DATA_EXFILTRATION",attack_subtype="large_outbound_transfer",
                    flow_ids=ids,source_ip=src,destination_ip=f.destination_ip,
                    source_port=f.source_port,destination_port=f.destination_port,protocol=f.protocol,
                    event_start_time=start,event_end_time=end,rule_score=min(score,1.0),
                    rule_confidence=min(score,1.0),
                    evidence={"outbound_bytes":out_b,"inbound_bytes":in_b,
                              "outbound_inbound_ratio":ratio,"duration_s":duration,
                              "destination_rarity":1/max(dest_global[f.destination_ip],1),
                              "source_window_mean_outbound_bytes":baseline_mean},
                    details={"classification":"potential","payload_inspection":False}))
        return out
