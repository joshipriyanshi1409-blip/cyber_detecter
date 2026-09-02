"""
Network Feature Extraction Module
Extracts comprehensive features from network flows for detection.
"""

import logging
from typing import Dict, Any, List, Optional, Union
from collections import defaultdict
import math

import numpy as np

from src.flow.nfstream_wrapper import FlowRecord
from src.features.rate import RateCalculator, FlowRateCalculator
from src.features.entropy import EntropyCalculator, DomainEntropyAnalyzer
from src.features.source_stats import calculate_concentration

logger = logging.getLogger(__name__)


class NetworkFeatureExtractor:
    """Extracts features from network flows for detection"""
    
    def __init__(self):
        """Initialize feature extractor"""
        self.rate_calculator = FlowRateCalculator()
        self.domain_analyzer = DomainEntropyAnalyzer()
        logger.info("Initialized NetworkFeatureExtractor")
    
    def extract_flow_features(self, flow: FlowRecord) -> Dict[str, Any]:
        """
        Extract comprehensive features from a single flow
        
        Args:
            flow: FlowRecord object
            
        Returns:
            Dictionary with flow features
        """
        features = {
            # Basic flow features
            "flow_id": flow.flow_id,
            "timestamp": flow.timestamp,
            
            # 5-tuple
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "source_port": flow.source_port,
            "destination_port": flow.destination_port,
            "protocol": flow.protocol,
            
            # Flow statistics
            "packet_count": flow.bidirectional_packets,
            "byte_count": flow.bidirectional_bytes,
            "flow_duration": flow.bidirectional_duration_ms,
            
            # Rate features
            "packets_per_second": flow.get_packets_per_second(),
            "bytes_per_second": flow.get_bytes_per_second(),
            
            # Direction features
            "src2dst_packets": flow.src2dst_packets,
            "dst2src_packets": flow.dst2src_packets,
            "src2dst_bytes": flow.src2dst_bytes,
            "dst2src_bytes": flow.dst2src_bytes,
            
            # Asymmetry features
            "packet_asymmetry": self._calculate_asymmetry(
                flow.src2dst_packets, flow.dst2src_packets
            ),
            "byte_asymmetry": self._calculate_asymmetry(
                flow.src2dst_bytes, flow.dst2src_bytes
            ),
            
            # TCP features
            "syn_ratio": flow.get_syn_ratio(),
            "syn_packets": flow.syn_packets,
            "ack_packets": flow.ack_packets,
            "fin_packets": flow.fin_packets,
            "rst_packets": flow.rst_packets,
            
            # Statistical features
            "packet_size_mean": self._safe_mean([
                flow.src2dst_bytes / flow.src2dst_packets if flow.src2dst_packets > 0 else 0,
                flow.dst2src_bytes / flow.dst2src_packets if flow.dst2src_packets > 0 else 0
            ]),
            "packet_size_std": self._safe_std([
                flow.src2dst_bytes / flow.src2dst_packets if flow.src2dst_packets > 0 else 0,
                flow.dst2src_bytes / flow.dst2src_packets if flow.dst2src_packets > 0 else 0
            ]),
            
            # Application features
            "application_name": flow.application_name,
            "application_category": flow.application_category,
        }
        
        # Add rate window features
        self.rate_calculator.add_flow(flow)
        aggregate_rates = self.rate_calculator.get_aggregate_rates()
        features.update(aggregate_rates)
        
        return features
    
    def extract_aggregate_features(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Extract aggregate features from multiple flows
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Dictionary with aggregate features
        """
        if not flows:
            return self._empty_aggregate_features()
        
        features = {
            # Flow counts
            "total_flows": len(flows),
            "total_packets": sum(f.bidirectional_packets for f in flows),
            "total_bytes": sum(f.bidirectional_bytes for f in flows),
            "total_duration": sum(f.bidirectional_duration_ms for f in flows),
            
            # Unique counts
            "unique_sources": len(set(f.source_ip for f in flows)),
            "unique_destinations": len(set(f.destination_ip for f in flows)),
            "unique_source_ports": len(set(f.source_port for f in flows)),
            "unique_destination_ports": len(set(f.destination_port for f in flows)),
            
            # Protocol distribution
            "protocol_distribution": self._get_protocol_distribution(flows),
            
            # Application distribution
            "application_distribution": self._get_application_distribution(flows),
            
            # Rate features
            "avg_packets_per_flow": np.mean([f.bidirectional_packets for f in flows]),
            "avg_bytes_per_flow": np.mean([f.bidirectional_bytes for f in flows]),
            "avg_duration_per_flow": np.mean([f.bidirectional_duration_ms for f in flows]),
            
            # Statistical features
            "packets_per_flow_std": np.std([f.bidirectional_packets for f in flows]),
            "bytes_per_flow_std": np.std([f.bidirectional_bytes for f in flows]),
            "duration_per_flow_std": np.std([f.bidirectional_duration_ms for f in flows]),
            
            # Concentration metrics
            "source_concentration": calculate_concentration(
                [f.source_ip for f in flows]
            ),
            "destination_concentration": calculate_concentration(
                [f.destination_ip for f in flows]
            ),
            "port_concentration": calculate_concentration(
                [f.destination_port for f in flows]
            ),
        }
        
        # Add time-based features
        if flows[0].timestamp:
            features["time_span"] = max(f.timestamp for f in flows) - min(f.timestamp for f in flows)
        
        return features
    
    def extract_detection_features(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Extract features specifically for detection algorithms
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Dictionary with detection-specific features
        """
        features = self.extract_aggregate_features(flows)
        
        # Add detection-specific features
        features.update({
            # Port scan indicators
            "port_scan_score": self._calculate_port_scan_score(flows),
            "failed_connection_ratio": self._calculate_failed_connection_ratio(flows),
            
            # DDoS indicators
            "syn_flood_score": self._calculate_syn_flood_score(flows),
            "traffic_burstiness": self._calculate_burstiness(flows),
            
            # Anomaly indicators
            "behavior_anomaly_score": self._calculate_behavior_anomaly(flows),
        })
        
        return features
    
    def _calculate_asymmetry(self, value1: int, value2: int) -> float:
        """Calculate asymmetry between two values (0 = symmetric, 1 = fully asymmetric)"""
        if value1 + value2 == 0:
            return 0.0
        return abs(value1 - value2) / (value1 + value2)
    
    def _safe_mean(self, values: List[float]) -> float:
        """Calculate mean safely"""
        if not values:
            return 0.0
        return float(np.mean(values))
    
    def _safe_std(self, values: List[float]) -> float:
        """Calculate standard deviation safely"""
        if not values:
            return 0.0
        return float(np.std(values))
    
    def _get_protocol_distribution(self, flows: List[FlowRecord]) -> Dict[str, int]:
        """Get protocol distribution"""
        dist = defaultdict(int)
        for flow in flows:
            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(flow.protocol, f"PROTO_{flow.protocol}")
            dist[proto_name] += 1
        return dict(dist)
    
    def _get_application_distribution(self, flows: List[FlowRecord]) -> Dict[str, int]:
        """Get application distribution"""
        dist = defaultdict(int)
        for flow in flows:
            dist[flow.application_name] += 1
        return dict(dist)
    
    def _calculate_port_scan_score(self, flows: List[FlowRecord]) -> float:
        """
        Calculate port scan likelihood score
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Score between 0 (no scan) and 1 (likely scan)
        """
        if not flows:
            return 0.0
        
        # Group flows by source IP
        source_flows = defaultdict(list)
        for flow in flows:
            source_flows[flow.source_ip].append(flow)
        
        max_scan_score = 0.0
        
        for src_ip, src_flows in source_flows.items():
            if len(src_flows) < 5:  # Too few flows
                continue
            
            unique_ports = len(set(f.destination_port for f in src_flows))
            unique_hosts = len(set(f.destination_ip for f in src_flows))
            
            # Calculate ratios
            port_ratio = unique_ports / len(src_flows)
            host_ratio = unique_hosts / len(src_flows)
            
            # Calculate SYN ratio
            syn_ratio = np.mean([f.get_syn_ratio() for f in src_flows])
            
            # Combine into scan score
            scan_score = (port_ratio * 0.4 + host_ratio * 0.3 + syn_ratio * 0.3)
            max_scan_score = max(max_scan_score, scan_score)
        
        return max_scan_score
    
    def _calculate_failed_connection_ratio(self, flows: List[FlowRecord]) -> float:
        """
        Calculate ratio of failed connections (SYN without ACK)
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Ratio between 0 and 1
        """
        if not flows:
            return 0.0
        
        failed_count = 0
        total_connections = 0
        
        for flow in flows:
            if flow.protocol == 6:  # TCP
                total_connections += 1
                if flow.syn_packets > 0 and flow.ack_packets == 0:
                    failed_count += 1
        
        return failed_count / total_connections if total_connections > 0 else 0.0
    
    def _calculate_syn_flood_score(self, flows: List[FlowRecord]) -> float:
        """
        Calculate SYN flood attack score
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Score between 0 and 1
        """
        if not flows:
            return 0.0
        
        # Calculate overall SYN ratio
        total_packets = sum(f.bidirectional_packets for f in flows)
        total_syn = sum(f.syn_packets for f in flows)
        
        if total_packets == 0:
            return 0.0
        
        overall_syn_ratio = total_syn / total_packets
        
        # Calculate destination concentration
        dest_concentration = calculate_concentration([f.destination_ip for f in flows])
        
        # Calculate rate
        avg_pps = np.mean([f.get_packets_per_second() for f in flows])
        rate_score = min(avg_pps / 1000, 1.0)  # Normalize to 1000 pps
        
        # Combine scores
        return (overall_syn_ratio * 0.4 + dest_concentration * 0.3 + rate_score * 0.3)
    
    def _calculate_burstiness(self, flows: List[FlowRecord]) -> float:
        """
        Calculate traffic burstiness
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Burstiness score (0 = smooth, >1 = bursty)
        """
        if not flows:
            return 0.0
        
        # Calculate inter-flow gaps
        timestamps = sorted(f.timestamp for f in flows if f.timestamp)
        
        if len(timestamps) < 2:
            return 0.0
        
        gaps = np.diff(timestamps)
        mean_gap = np.mean(gaps)
        std_gap = np.std(gaps)
        
        if mean_gap == 0:
            return 0.0
        
        return std_gap / mean_gap
    
    def _calculate_behavior_anomaly(self, flows: List[FlowRecord]) -> float:
        """
        Calculate behavior anomaly score using statistical methods
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Anomaly score between 0 and 1
        """
        if len(flows) < 10:
            return 0.0
        
        # Extract features for anomaly detection
        feature_matrix = []
        for flow in flows:
            feature_matrix.append([
                flow.bidirectional_packets,
                flow.bidirectional_bytes,
                flow.bidirectional_duration_ms,
                flow.get_packets_per_second(),
                flow.get_bytes_per_second()
            ])
        
        feature_matrix = np.array(feature_matrix)
        
        # Calculate z-scores
        means = np.mean(feature_matrix, axis=0)
        stds = np.std(feature_matrix, axis=0)
        stds[stds == 0] = 1  # Avoid division by zero
        
        z_scores = np.abs((feature_matrix - means) / stds)
        
        # Calculate average z-score
        avg_z_score = np.mean(z_scores)
        
        # Normalize to 0-1 range (tanh function)
        return float(np.tanh(avg_z_score / 3))  # 3 std deviations = 1
    
    def _empty_aggregate_features(self) -> Dict[str, Any]:
        """Return empty aggregate features"""
        return {
            "total_flows": 0,
            "total_packets": 0,
            "total_bytes": 0,
            "total_duration": 0,
            "unique_sources": 0,
            "unique_destinations": 0,
            "unique_source_ports": 0,
            "unique_destination_ports": 0,
            "protocol_distribution": {},
            "application_distribution": {},
            "avg_packets_per_flow": 0,
            "avg_bytes_per_flow": 0,
            "avg_duration_per_flow": 0,
            "packets_per_flow_std": 0,
            "bytes_per_flow_std": 0,
            "duration_per_flow_std": 0,
            "source_concentration": 0,
            "destination_concentration": 0,
            "port_concentration": 0
        }


class FeaturePipeline:
    """Pipeline for feature extraction from raw traffic"""
    
    def __init__(self):
        """Initialize feature pipeline"""
        self.network_features = NetworkFeatureExtractor()
        self.domain_analyzer = DomainEntropyAnalyzer()
        self.rate_calculator = RateCalculator()
        logger.info("Initialized FeaturePipeline")
    
    def process_flows(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Process flows through complete feature extraction pipeline
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Dictionary with all extracted features
        """
        features = {
            "flow_features": [],
            "aggregate_features": {},
            "detection_features": {}
        }
        
        # Extract individual flow features
        for flow in flows:
            flow_features = self.network_features.extract_flow_features(flow)
            features["flow_features"].append(flow_features)
        
        # Extract aggregate features
        features["aggregate_features"] = self.network_features.extract_aggregate_features(flows)
        
        # Extract detection features
        features["detection_features"] = self.network_features.extract_detection_features(flows)
        
        return features
    
    def process_domain(self, domain: str) -> Dict[str, Any]:
        """
        Process domain through feature extraction
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Dictionary with domain features
        """
        return self.domain_analyzer.analyze_domain(domain)