"""Passive C2 beaconing detector using timing periodicity and destination concentration."""
from collections import defaultdict, deque
from statistics import mean, median, pstdev
from typing import List
from src.detectors.contracts import DetectionResult, flow_window_fields
from src.flow.nfstream_wrapper import FlowRecord

class C2BeaconDetector:
    def __init__(self, min_repeats=4, max_cv=0.20, min_interval_s=5.0, max_interval_s=300.0, history_limit=10000):
        self.min_repeats=min_repeats; self.max_cv=max_cv; self.min_interval_s=min_interval_s; self.max_interval_s=max_interval_s
        self.history=defaultdict(lambda: deque(maxlen=history_limit))

    def detect(self, flows: List[FlowRecord]):
        groups=defaultdict(list)
        for f in flows:
            if f.timestamp is not None:
                key=(f.source_ip,f.destination_ip,f.destination_port,f.protocol)
                groups[key].append(f)
                self.history[key].append(f)
        results=[]
        for key, items in groups.items():
            # Beacon evidence is inherently temporal; retain a bounded history
            # across short rolling windows so a 60s cadence is detectable even
            # when the configured detector window is 10s.
            items=sorted(list(self.history[key]),key=lambda x:x.timestamp)[-self.history[key].maxlen:]
            if len(items)<self.min_repeats: continue
            intervals=[b.timestamp-a.timestamp for a,b in zip(items,items[1:]) if b.timestamp>a.timestamp]
            if len(intervals)<self.min_repeats-1: continue
            m=mean(intervals); sd=pstdev(intervals) if len(intervals)>1 else 0.0
            cv=sd/m if m else 1.0
            jitter=sd
            periodicity=max(0.0, min(1.0, 1.0-cv))
            if m<self.min_interval_s or m>self.max_interval_s or cv>self.max_cv: continue
            ids,start,end=flow_window_fields(items)
            score=min(1.0, 0.45*periodicity + 0.25*min(len(items)/20.0,1.0)+0.20+0.10*(1.0 if len({f.destination_ip for f in items})==1 else 0))
            results.append(DetectionResult(
                detector="c2_beacon", detected=True, attack_type="C2_BEACONING",
                attack_subtype="periodic_beacon", flow_ids=ids, source_ip=key[0],
                destination_ip=key[1], destination_port=key[2], protocol=key[3],
                event_start_time=start,event_end_time=end,rule_score=score,rule_confidence=score,
                evidence={"repeat_count":len(items),"mean_interval_s":m,"median_interval_s":median(intervals),
                          "stddev_interval_s":sd,"coefficient_of_variation":cv,
                          "periodicity_score":periodicity,"jitter_s":jitter,
                          "destination_concentration":1.0},
                details={"timing_model":"periodicity+CV"}))
        return results
