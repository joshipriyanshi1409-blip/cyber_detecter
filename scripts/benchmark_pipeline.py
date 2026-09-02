#!/usr/bin/env python3
"""Measure the integrated window-processing path without generating network traffic."""
import argparse, time, tempfile
from src.streaming.pipeline import ThreatDetectionPipeline
from src.flow.nfstream_wrapper import FlowRecord

def make_flow(i):
    ts=1700000000.0+(i/1000.0)
    return FlowRecord(
        source_ip=f"10.10.{(i//250)%250}.{(i%250)+1}", destination_ip="10.20.0.1",
        source_port=10000+(i%50000), destination_port=443, protocol=6,
        bidirectional_packets=10,bidirectional_bytes=1000,bidirectional_duration_ms=1000,
        src2dst_packets=5,src2dst_bytes=500,dst2src_packets=5,dst2src_bytes=500,
        bidirectional_first_seen_ms=int(ts*1000),bidirectional_last_seen_ms=int((ts+1)*1000),
        bidirectional_min_ps=100,bidirectional_mean_ps=100,bidirectional_stddev_ps=0,bidirectional_max_ps=100,
        bidirectional_min_piat_ms=111.1,bidirectional_mean_piat_ms=111.1,bidirectional_stddev_piat_ms=0,bidirectional_max_piat_ms=111.1,
        syn_packets=1,ack_packets=5,fin_packets=0,rst_packets=0,syn_only_packets=1,syn_ack_packets=0,
        icmp_packets=0,icmp_bytes=0,application_name="unknown",application_category="unknown",
        flow_id=i+1,timestamp=ts)

def run(count=5000):
    with tempfile.TemporaryDirectory() as td:
        pipe=ThreatDetectionPipeline({"detection":{"enabled_detectors":["ddos"]},
                                      "database_path":f"{td}/alerts.db","hash_chain_file":f"{td}/chain.json"})
        flows=[make_flow(i) for i in range(count)]
        t0=time.perf_counter()
        result=pipe.process_flow_stream(flows,window_seconds=10,slide_seconds=1,persist=False)
        elapsed=time.perf_counter()-t0
        fps=count/elapsed if elapsed else 0
        alerts=sum(len(x["alerts"]) for x in result)
        latencies=[float(w.get("processing_latency_ms",0)) for w in result]
        print({"flows":count,"elapsed_seconds":elapsed,"flows_per_second":fps,
               "windows":len(result),"alerts":alerts,"max_window_processing_latency_ms":max(latencies or [0]),
               "mean_window_processing_latency_ms":sum(latencies)/len(latencies) if latencies else 0,
               "target_flows_per_second":1000,"target_max_alert_latency_seconds":10})
if __name__=="__main__":
    run()
