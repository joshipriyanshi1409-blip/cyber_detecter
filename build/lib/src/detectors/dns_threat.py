"""Dedicated DNS threat detector: DGA and DNS tunnelling are separate subtypes."""
import math, re
from collections import defaultdict, deque
from statistics import mean
from typing import List
from src.detectors.contracts import DetectionResult, flow_window_fields
from src.flow.nfstream_wrapper import FlowRecord

class DNSThreatDetector:
    def __init__(self, min_dga_score=0.65, min_tunnel_score=0.70, history_limit=10000):
        self.min_dga_score=min_dga_score; self.min_tunnel_score=min_tunnel_score
        self.history=defaultdict(lambda: deque(maxlen=history_limit))

    @staticmethod
    def _entropy(s):
        if not s: return 0.0
        counts={c:s.count(c) for c in set(s)}
        n=len(s)
        return -sum((v/n)*math.log2(v/n) for v in counts.values())

    def detect(self, flows: List[FlowRecord]):
        dns=[f for f in flows if (f.destination_port==53 or f.source_port==53) and f.dns_query]
        by_src=defaultdict(list)
        for f in dns: by_src[f.source_ip].append(f)
        out=[]
        for src, items in by_src.items():
            domains=[str(f.dns_query).lower().rstrip(".") for f in items]
            nxd=sum(1 for f in items if f.dns_nxdomain is True)
            for f,domain in zip(items,domains):
                label=domain.split(".")[0] if "." in domain else domain
                ent=self._entropy(label)
                digits=sum(ch.isdigit() for ch in label)/len(label) if label else 0.0
                vowels=sum(ch in "aeiou" for ch in label)/len(label) if label else 0.0
                long_label=len(label)>=30
                unique_rate=len(set(domains))/max(len(domains),1)
                nxd_rate=nxd/max(len(items),1)
                char_anomaly=(ent/5.0)*0.55 + min(digits*2,1.0)*0.20 + (1-vowels)*0.15 + (0.10 if len(label)>=20 else 0)
                dga_score=min(1.0,char_anomaly+0.20*nxd_rate)
                if dga_score>=self.min_dga_score:
                    ids,start,end=flow_window_fields([f])
                    out.append(DetectionResult(
                        detector="dns_threat",detected=True,attack_type="DGA",
                        attack_subtype="dga_domain",flow_ids=ids,source_ip=src,
                        destination_ip=f.destination_ip,destination_port=f.destination_port,protocol=f.protocol,
                        event_start_time=start,event_end_time=end,rule_score=dga_score,rule_confidence=dga_score,
                        evidence={"domain":domain,"domain_length":len(domain),"label_entropy":ent,
                                  "digit_ratio":digits,"vowel_ratio":vowels,"nxdomain_rate":nxd_rate,
                                  "unique_domain_rate":unique_rate},
                        details={"indicators":["entropy","character_distribution","nxdomain_behavior"]}))
                tunnel_score=0.0
                if len(label)>=30: tunnel_score+=0.30
                if ent>=3.5: tunnel_score+=0.20
                if len(domain)>=45: tunnel_score+=0.15
                if unique_rate>=0.8 and len(items)>=5: tunnel_score+=0.15
                if len(items)>=10: tunnel_score+=0.10
                if nxd_rate>=0.5: tunnel_score+=0.10
                if tunnel_score>=self.min_tunnel_score:
                    ids,start,end=flow_window_fields(items)
                    out.append(DetectionResult(
                        detector="dns_threat",detected=True,attack_type="DNS_TUNNELLING",
                        attack_subtype="encoded_high_entropy_query_stream",flow_ids=ids,source_ip=src,
                        destination_ip=f.destination_ip,destination_port=f.destination_port,protocol=f.protocol,
                        event_start_time=start,event_end_time=end,rule_score=min(tunnel_score,1.0),
                        rule_confidence=min(tunnel_score,1.0),
                        evidence={"long_label":long_label,"label_entropy":ent,"query_count":len(items),
                                  "unique_label_rate":unique_rate,"nxdomain_rate":nxd_rate,
                                  "query_name_length":len(domain)},
                        details={"payload_inspection":False,"record_type":None}))
        return out
