"""
Rate-based Feature Extraction Module
Calculates rate features from network flows and packets.
"""

import logging
import time
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta

import numpy as np

logger = logging.getLogger(__name__)


class RateCalculator:
    """Calculates rate-based features from network traffic"""
    
    def __init__(self, window_size: int = 60):
        """
        Initialize rate calculator
        
        Args:
            window_size: Time window in seconds for rate calculations
        """
        self.window_size = window_size
        self.packet_timestamps = deque()
        self.byte_counts = deque()
        self.flow_count = 0
        self.total_packets = 0
        self.total_bytes = 0
        
        logger.info(f"Initialized RateCalculator with {window_size}s window")
    
    def add_packet(self, packet_size: int, timestamp: Optional[float] = None):
        """
        Add a packet for rate calculation
        
        Args:
            packet_size: Size of packet in bytes
            timestamp: Packet timestamp (defaults to current time)
        """
        if timestamp is None:
            timestamp = time.time()
        
        self.packet_timestamps.append((timestamp, packet_size))
        self.byte_counts.append(packet_size)
        self.total_packets += 1
        self.total_bytes += packet_size
        
        # Remove old packets outside window
        self._cleanup_old_packets(timestamp)
    
    def add_flow(self, flow_packets: int, flow_bytes: int):
        """
        Add flow-level data for rate calculation
        
        Args:
            flow_packets: Number of packets in flow
            flow_bytes: Total bytes in flow
        """
        self.flow_count += 1
        self.total_packets += flow_packets
        self.total_bytes += flow_bytes
    
    def _cleanup_old_packets(self, current_time: float):
        """Remove packets outside the time window"""
        cutoff_time = current_time - self.window_size
        
        # Remove old packets from deque
        while self.packet_timestamps and self.packet_timestamps[0][0] < cutoff_time:
            old_timestamp, old_size = self.packet_timestamps.popleft()
            self.total_packets -= 1
            self.total_bytes -= old_size
    
    def get_packets_per_second(self) -> float:
        """Calculate current packets per second rate"""
        if not self.packet_timestamps:
            return 0.0
        
        if len(self.packet_timestamps) == 1:
            return 1.0 / self.window_size
        
        time_span = self.packet_timestamps[-1][0] - self.packet_timestamps[0][0]
        if time_span == 0:
            return float(len(self.packet_timestamps))
        
        return len(self.packet_timestamps) / time_span
    
    def get_bytes_per_second(self) -> float:
        """Calculate current bytes per second rate"""
        if not self.packet_timestamps:
            return 0.0
        
        if len(self.packet_timestamps) == 1:
            return self.packet_timestamps[0][1] / self.window_size
        
        time_span = self.packet_timestamps[-1][0] - self.packet_timestamps[0][0]
        if time_span == 0:
            return float(sum(b for _, b in self.packet_timestamps))
        
        total_bytes = sum(b for _, b in self.packet_timestamps)
        return total_bytes / time_span
    
    def get_flow_rate(self) -> float:
        """Calculate flow rate (flows per second)"""
        if self.window_size == 0:
            return 0.0
        return self.flow_count / self.window_size
    
    def get_burstiness(self) -> float:
        """
        Calculate traffic burstiness (coefficient of variation)
        Returns 0 for perfectly regular traffic, higher values for bursty traffic
        """
        if not self.packet_timestamps or len(self.packet_timestamps) < 2:
            return 0.0
        
        # Calculate inter-packet gaps
        timestamps = [t for t, _ in self.packet_timestamps]
        gaps = np.diff(timestamps)
        
        if len(gaps) == 0:
            return 0.0
        
        mean_gap = np.mean(gaps)
        std_gap = np.std(gaps)
        
        if mean_gap == 0:
            return float('inf') if std_gap > 0 else 0.0
        
        return std_gap / mean_gap
    
    def get_packet_size_stats(self) -> Dict[str, float]:
        """Get packet size statistics"""
        if not self.packet_timestamps:
            return {"mean": 0, "std": 0, "min": 0, "max": 0}
        
        sizes = [s for _, s in self.packet_timestamps]
        return {
            "mean": float(np.mean(sizes)),
            "std": float(np.std(sizes)),
            "min": float(np.min(sizes)),
            "max": float(np.max(sizes))
        }
    
    def reset(self):
        """Reset all counters"""
        self.packet_timestamps.clear()
        self.byte_counts.clear()
        self.flow_count = 0
        self.total_packets = 0
        self.total_bytes = 0


class FlowRateCalculator:
    """Calculates rate features from flow records.

    NOTE (found during audit, not fixed as a drive-by -- see
    docs/NEXT_AGENT_PROMPT.md item 6, streaming/windowing mechanism):
    `self.flows` is append-only and never trimmed. `get_source_destination_ratio()`
    and `get_unique_ips_count()` below intentionally rely on the FULL
    accumulated history, so simply trimming this list would silently
    change their behavior too -- that's why this wasn't "fixed" here.
    But it does mean `get_aggregate_rates()`'s `start_time` stays
    anchored to the very FIRST flow this instance ever saw, not a
    sliding recent window -- so as more traffic accumulates over a long
    capture session, `get_aggregate_rates()` increasingly reports
    "rate over the first window_seconds after this instance was
    created", not "current rate right now", even though callers like
    `NetworkFeatureExtractor.extract_flow_features()` call it after
    every single flow expecting something rolling. This needs the real
    streaming/windowing mechanism (item 6) to fix properly, not a patch
    here.
    """
    
    def __init__(self):
        """Initialize flow rate calculator"""
        self.flows = []
        logger.info("Initialized FlowRateCalculator")
    
    def add_flow(self, flow):
        """Add a flow record"""
        self.flows.append(flow)
    
    def get_aggregate_rates(self, window_seconds: int = 60) -> Dict[str, Any]:
        """
        Calculate aggregate rate features from flows
        
        Args:
            window_seconds: Time window for aggregation
            
        Returns:
            Dictionary with rate features
        """
        if not self.flows:
            return self._empty_rates()
        
        # Sort flows by timestamp
        sorted_flows = sorted(self.flows, key=lambda f: f.bidirectional_first_seen_ms)
        
        # Calculate time window boundaries
        start_time = sorted_flows[0].bidirectional_first_seen_ms
        
        # Filter flows within window
        window_flows = [
            f for f in sorted_flows
            if f.bidirectional_last_seen_ms <= start_time + (window_seconds * 1000)
        ]
        
        if not window_flows:
            return self._empty_rates()

        # BUGFIX: end_time must come from window_flows (the data actually
        # being aggregated below), not from the full sorted_flows list.
        # self.flows is never trimmed (add_flow() is called on every
        # extract_flow_features() call and nothing ever removes old
        # entries -- see the module-level note above), so
        # sorted_flows[-1] is frequently a flow from long after this
        # window closed. Using its bidirectional_last_seen_ms as
        # end_time inflated actual_duration toward (or past) the
        # window_seconds cap regardless of how tightly clustered the
        # in-window flows actually were, silently UNDER-reporting rates
        # by an order of magnitude or more once any out-of-window flow
        # existed in self.flows. Reproduced: 100 flows tightly packed
        # into ~2 real seconds reported ~16.7 pkts/sec instead of the
        # correct ~500 pkts/sec once a single flow from 600s later was
        # also present in self.flows -- a ~30x underestimate.
        end_time = max(f.bidirectional_last_seen_ms for f in window_flows)

        # Calculate rates
        total_packets = sum(f.bidirectional_packets for f in window_flows)
        total_bytes = sum(f.bidirectional_bytes for f in window_flows)
        total_duration = sum(f.bidirectional_duration_ms for f in window_flows)
        
        time_span_seconds = window_seconds
        if total_duration > 0:
            # Use actual flow duration if available
            actual_duration = (end_time - start_time) / 1000
            if actual_duration > 0:
                time_span_seconds = min(actual_duration, window_seconds)
        
        return {
            "packets_per_second": total_packets / time_span_seconds if time_span_seconds > 0 else 0,
            "bytes_per_second": total_bytes / time_span_seconds if time_span_seconds > 0 else 0,
            "flows_per_second": len(window_flows) / time_span_seconds if time_span_seconds > 0 else 0,
            "avg_packet_size": total_bytes / total_packets if total_packets > 0 else 0,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_flows": len(window_flows),
            "window_seconds": time_span_seconds
        }
    
    def get_source_destination_ratio(self) -> float:
        """
        Calculate source-to-destination packet ratio
        High values indicate asymmetric traffic (potential scanning)
        """
        if not self.flows:
            return 0.0
        
        total_src2dst = sum(f.src2dst_packets for f in self.flows)
        total_dst2src = sum(f.dst2src_packets for f in self.flows)
        
        if total_dst2src == 0:
            return float('inf') if total_src2dst > 0 else 0.0
        
        return total_src2dst / total_dst2src
    
    def get_unique_ips_count(self) -> Dict[str, int]:
        """Count unique source and destination IPs"""
        unique_sources = set()
        unique_destinations = set()
        
        for flow in self.flows:
            unique_sources.add(flow.source_ip)
            unique_destinations.add(flow.destination_ip)
        
        return {
            "unique_sources": len(unique_sources),
            "unique_destinations": len(unique_destinations)
        }
    
    def _empty_rates(self) -> Dict[str, Any]:
        """Return empty rate dictionary"""
        return {
            "packets_per_second": 0,
            "bytes_per_second": 0,
            "flows_per_second": 0,
            "avg_packet_size": 0,
            "total_packets": 0,
            "total_bytes": 0,
            "total_flows": 0,
            "window_seconds": 0
        }