"""
Flow Analysis Utilities
Provides additional flow analysis and aggregation functions.
"""

import logging
from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime, timedelta

from .nfstream_wrapper import FlowRecord, FlowExtractor

logger = logging.getLogger(__name__)


class FlowAnalyzer:
    """Analyzes and aggregates flow records"""
    
    def __init__(self, flows: Optional[List[FlowRecord]] = None):
        """
        Initialize flow analyzer
        
        Args:
            flows: List of FlowRecord objects to analyze
        """
        self.flows = flows or []
        logger.info(f"Initialized FlowAnalyzer with {len(self.flows)} flows")
    
    def group_by_source(self) -> Dict[str, List[FlowRecord]]:
        """Group flows by source IP"""
        groups = defaultdict(list)
        for flow in self.flows:
            groups[flow.source_ip].append(flow)
        return dict(groups)
    
    def group_by_destination(self) -> Dict[str, List[FlowRecord]]:
        """Group flows by destination IP"""
        groups = defaultdict(list)
        for flow in self.flows:
            groups[flow.destination_ip].append(flow)
        return dict(groups)
    
    def group_by_protocol(self) -> Dict[int, List[FlowRecord]]:
        """Group flows by protocol"""
        groups = defaultdict(list)
        for flow in self.flows:
            groups[flow.protocol].append(flow)
        return dict(groups)
    
    def group_by_application(self) -> Dict[str, List[FlowRecord]]:
        """Group flows by application"""
        groups = defaultdict(list)
        for flow in self.flows:
            groups[flow.application_name].append(flow)
        return dict(groups)
    
    def get_top_talkers(self, n: int = 10) -> List[Dict[str, Any]]:
        """
        Get top N talkers by byte count
        
        Args:
            n: Number of top talkers to return
            
        Returns:
            List of dictionaries with talker statistics
        """
        talkers = defaultdict(lambda: {"packets": 0, "bytes": 0, "flows": 0})
        
        for flow in self.flows:
            # Count source traffic
            talkers[flow.source_ip]["packets"] += flow.src2dst_packets
            talkers[flow.source_ip]["bytes"] += flow.src2dst_bytes
            talkers[flow.source_ip]["flows"] += 1
            
            # Count destination traffic
            talkers[flow.destination_ip]["packets"] += flow.dst2src_packets
            talkers[flow.destination_ip]["bytes"] += flow.dst2src_bytes
            talkers[flow.destination_ip]["flows"] += 1
        
        # Sort by bytes
        sorted_talkers = sorted(
            talkers.items(),
            key=lambda x: x[1]["bytes"],
            reverse=True
        )
        
        # Format results
        results = []
        for ip, stats in sorted_talkers[:n]:
            results.append({
                "ip": ip,
                "packets": stats["packets"],
                "bytes": stats["bytes"],
                "flows": stats["flows"]
            })
        
        return results
    
    def get_time_series(self, window_seconds: int = 60) -> List[Dict[str, Any]]:
        """
        Generate time series data for flow rates
        
        Args:
            window_seconds: Time window in seconds
            
        Returns:
            List of time series data points
        """
        if not self.flows:
            return []
        
        # Sort flows by timestamp
        sorted_flows = sorted(self.flows, key=lambda f: f.timestamp or 0)
        
        # Create time windows
        time_series = []
        window_start = sorted_flows[0].timestamp
        current_window = {
            "timestamp": window_start,
            "flow_count": 0,
            "packet_count": 0,
            "byte_count": 0
        }
        
        for flow in sorted_flows:
            flow_time = flow.timestamp or 0
            
            # Check if flow belongs in current window
            if flow_time - window_start <= window_seconds:
                current_window["flow_count"] += 1
                current_window["packet_count"] += flow.bidirectional_packets
                current_window["byte_count"] += flow.bidirectional_bytes
            else:
                # Save current window and start new one
                time_series.append(current_window)
                window_start = flow_time
                current_window = {
                    "timestamp": window_start,
                    "flow_count": 1,
                    "packet_count": flow.bidirectional_packets,
                    "byte_count": flow.bidirectional_bytes
                }
        
        # Add last window
        time_series.append(current_window)
        
        return time_series
    
    def get_port_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about port usage
        
        Returns:
            Dictionary with port statistics
        """
        source_ports = defaultdict(int)
        dest_ports = defaultdict(int)
        
        for flow in self.flows:
            source_ports[flow.source_port] += 1
            dest_ports[flow.destination_port] += 1
        
        return {
            "unique_source_ports": len(source_ports),
            "unique_destination_ports": len(dest_ports),
            "most_common_source_ports": sorted(
                source_ports.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "most_common_destination_ports": sorted(
                dest_ports.items(), key=lambda x: x[1], reverse=True
            )[:10]
        }
    
    def detect_anomalous_flows(self, threshold_std: float = 3.0) -> List[FlowRecord]:
        """
        Detect anomalous flows based on statistical deviation
        
        Args:
            threshold_std: Number of standard deviations for anomaly threshold
            
        Returns:
            List of anomalous FlowRecord objects
        """
        if len(self.flows) < 10:
            logger.warning("Too few flows for statistical analysis")
            return []
        
        import numpy as np
        
        # Calculate statistics for key metrics
        packets_list = [f.bidirectional_packets for f in self.flows]
        bytes_list = [f.bidirectional_bytes for f in self.flows]
        duration_list = [f.bidirectional_duration_ms for f in self.flows]
        
        packets_mean = np.mean(packets_list)
        packets_std = np.std(packets_list)
        
        bytes_mean = np.mean(bytes_list)
        bytes_std = np.std(bytes_list)
        
        duration_mean = np.mean(duration_list)
        duration_std = np.std(duration_list)
        
        anomalous = []
        
        for flow in self.flows:
            # Check if any metric is anomalous
            is_anomalous = False
            
            if packets_std > 0:
                packets_zscore = abs(flow.bidirectional_packets - packets_mean) / packets_std
                if packets_zscore > threshold_std:
                    is_anomalous = True
            
            if bytes_std > 0:
                bytes_zscore = abs(flow.bidirectional_bytes - bytes_mean) / bytes_std
                if bytes_zscore > threshold_std:
                    is_anomalous = True
            
            if duration_std > 0:
                duration_zscore = abs(flow.bidirectional_duration_ms - duration_mean) / duration_std
                if duration_zscore > threshold_std:
                    is_anomalous = True
            
            if is_anomalous:
                anomalous.append(flow)
        
        logger.info(f"Detected {len(anomalous)} anomalous flows")
        return anomalous