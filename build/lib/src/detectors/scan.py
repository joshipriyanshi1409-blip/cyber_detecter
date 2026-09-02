"""
Port Scan Detection Module
Detects port scanning behavior using flow-based features.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import time

from src.flow.nfstream_wrapper import FlowRecord

# Fixed import with fallback
try:
    from src.utils.config import config_manager
except ImportError:
    from src.utils.config_simple import config_manager

logger = logging.getLogger(__name__)


@dataclass
class PortScanResult:
    """Standardized port scan detection result"""
    threat_type: str = "PORT_SCAN"
    source_ip: str = ""
    destination_ip: str = ""
    confidence: float = 0.0
    severity: str = "LOW"
    risk_score: float = 0.0
    detector: str = "rule_based_scan"
    details: Dict[str, Any] = None
    timestamp: float = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
        if self.details is None:
            self.details = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class PortScanDetector:
    """Detects port scanning behavior"""
    
    def __init__(self):
        """Initialize port scan detector"""
        self.thresholds = self._load_thresholds()
        self.flow_history = defaultdict(list)
        logger.info(f"Initialized PortScanDetector with thresholds: {self.thresholds}")
    
    def _load_thresholds(self) -> Dict[str, Any]:
        """Load detection thresholds from config"""
        # Default thresholds
        defaults = {
            "min_unique_destination_ports": 10,
            "min_unique_destination_hosts": 5,
            "failed_connection_ratio": 0.5,
            "syn_only_ratio": 0.7,
            "window_seconds": 60,
            "min_flows": 5
        }
        
        try:
            # Try to load from config manager
            thresholds = {
                "min_unique_destination_ports": config_manager.get_threshold(
                    "port_scan", "min_unique_ports", default=defaults["min_unique_destination_ports"]
                ),
                "min_unique_destination_hosts": config_manager.get_threshold(
                    "port_scan", "min_unique_hosts", default=defaults["min_unique_destination_hosts"]
                ),
                "failed_connection_ratio": config_manager.get_threshold(
                    "port_scan", "min_failed_ratio", default=defaults["failed_connection_ratio"]
                ),
                "syn_only_ratio": config_manager.get_threshold(
                    "port_scan", "min_syn_ratio", default=defaults["syn_only_ratio"]
                ),
                "window_seconds": config_manager.get_threshold(
                    "port_scan", "window_seconds", default=defaults["window_seconds"]
                ),
                "min_flows": config_manager.get_threshold(
                    "port_scan", "min_flows", default=defaults["min_flows"]
                )
            }
            return thresholds
        except Exception as e:
            logger.warning(f"Failed to load thresholds from config: {e}. Using defaults.")
            return defaults
    
    def detect(self, flows: List[FlowRecord]) -> List[PortScanResult]:
        """
        Detect port scanning from flows
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            List of PortScanResult objects
        """
        if not flows:
            return []
        
        detections = []
        
        # Group flows by source IP
        flows_by_source = self._group_flows_by_source(flows)
        
        for source_ip, source_flows in flows_by_source.items():
            result = self._analyze_source_flows(source_ip, source_flows)
            if result:
                detections.append(result)
        
        logger.info(f"PortScanDetector: Detected {len(detections)} potential port scans")
        return detections
    
    def _group_flows_by_source(self, flows: List[FlowRecord]) -> Dict[str, List[FlowRecord]]:
        """Group flows by source IP"""
        groups = defaultdict(list)
        for flow in flows:
            groups[flow.source_ip].append(flow)
        return dict(groups)
    
    def _analyze_source_flows(self, source_ip: str, flows: List[FlowRecord]) -> Optional[PortScanResult]:
        """
        Analyze flows from a single source for scanning behavior
        
        Args:
            source_ip: Source IP address
            flows: Flows from this source
            
        Returns:
            PortScanResult if scan detected, None otherwise
        """
        if len(flows) < self.thresholds["min_flows"]:
            return None
        
        # Calculate scan indicators
        unique_ports = set()
        unique_hosts = set()
        syn_only_count = 0
        failed_connections = 0
        total_connections = 0
        total_packets = 0
        total_syn_packets = 0
        
        for flow in flows:
            unique_ports.add(flow.destination_port)
            unique_hosts.add(flow.destination_ip)
            
            if flow.protocol == 6:  # TCP
                total_connections += 1
                total_packets += flow.bidirectional_packets
                total_syn_packets += flow.syn_packets
                
                # Two distinct failure signatures for a scanned port (Rule 7/
                # audit item 7): the original code had an `elif` with the
                # SAME condition as the `if` above it, making it unreachable
                # dead code. The two real, distinguishable signatures are:
                #   1. SYN sent, no ACK and no RST -- no response at all.
                #      This is the classic "filtered"/silently-dropped-port
                #      signature typical of stealth scanning.
                #   2. SYN sent, RST received (regardless of ACK) -- the
                #      port actively refused the connection ("closed port").
                #      This is a different failure mode from (1) and is
                #      NOT counted toward syn_only_count, only toward
                #      failed_connections, since a real reply was received.
                if flow.syn_packets > 0 and flow.ack_packets == 0 and flow.rst_packets == 0:
                    syn_only_count += 1
                    failed_connections += 1
                elif flow.syn_packets > 0 and flow.rst_packets > 0:
                    failed_connections += 1
        
        # Calculate ratios
        unique_port_ratio = len(unique_ports) / len(flows) if len(flows) > 0 else 0
        unique_host_ratio = len(unique_hosts) / len(flows) if len(flows) > 0 else 0
        syn_only_ratio = syn_only_count / len(flows) if len(flows) > 0 else 0
        failed_ratio = failed_connections / total_connections if total_connections > 0 else 0
        
        # Check thresholds
        scan_detected = False
        confidence_factors = []
        evidence = {}
        
        # Check unique ports
        if len(unique_ports) >= self.thresholds["min_unique_destination_ports"]:
            scan_detected = True
            confidence_factors.append(0.4)
            evidence["unique_ports_count"] = len(unique_ports)
            evidence["unique_port_ratio"] = unique_port_ratio
        
        # Check unique hosts
        if len(unique_hosts) >= self.thresholds["min_unique_destination_hosts"]:
            scan_detected = True
            confidence_factors.append(0.3)
            evidence["unique_hosts_count"] = len(unique_hosts)
            evidence["unique_host_ratio"] = unique_host_ratio
        
        # Check SYN-only ratio
        if syn_only_ratio >= self.thresholds["syn_only_ratio"]:
            scan_detected = True
            confidence_factors.append(0.3)
            evidence["syn_only_ratio"] = syn_only_ratio
            evidence["syn_only_count"] = syn_only_count
        
        # Check failed connection ratio
        if failed_ratio >= self.thresholds["failed_connection_ratio"]:
            scan_detected = True
            confidence_factors.append(0.2)
            evidence["failed_connection_ratio"] = failed_ratio
            evidence["failed_connections"] = failed_connections
        
        if not scan_detected:
            return None
        
        # Calculate confidence (weighted sum of detected factors)
        confidence = sum(confidence_factors)
        confidence = min(confidence, 1.0)  # Cap at 1.0
        
        # Determine severity
        severity = self._determine_severity(
            len(unique_ports),
            len(unique_hosts),
            syn_only_ratio,
            confidence
        )
        
        # Calculate risk score
        risk_score = confidence * 100
        
        # Get main target (most scanned host)
        target_ips = [f.destination_ip for f in flows]
        destination_ip = max(set(target_ips), key=target_ips.count) if target_ips else ""
        
        return PortScanResult(
            source_ip=source_ip,
            destination_ip=destination_ip,
            confidence=confidence,
            severity=severity,
            risk_score=risk_score,
            details={
                "total_flows": len(flows),
                "unique_ports": len(unique_ports),
                "unique_hosts": len(unique_hosts),
                "syn_only_count": syn_only_count,
                "failed_connections": failed_connections,
                "evidence": evidence,
                "thresholds": self.thresholds
            }
        )
    
    def _determine_severity(self, unique_ports: int, unique_hosts: int, 
                           syn_ratio: float, confidence: float) -> str:
        """Determine scan severity based on indicators"""
        if unique_ports >= 100 or unique_hosts >= 20:
            return "CRITICAL"
        elif unique_ports >= 50 or unique_hosts >= 10:
            return "HIGH"
        elif unique_ports >= 20 or unique_hosts >= 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def analyze_single_flow(self, flow: FlowRecord) -> Optional[PortScanResult]:
        """
        Analyze a single flow for scanning behavior (for real-time detection)
        
        Args:
            flow: FlowRecord object
            
        Returns:
            PortScanResult if suspicious, None otherwise
        """
        source_ip = flow.source_ip
        
        # Add to history
        self.flow_history[source_ip].append({
            "flow": flow,
            "timestamp": time.time()
        })
        
        # Clean old flows
        self._cleanup_history(source_ip)
        
        # Check if we have enough flows
        if len(self.flow_history[source_ip]) < self.thresholds["min_flows"]:
            return None
        
        # Get recent flows
        recent_flows = [
            entry["flow"] for entry in self.flow_history[source_ip]
        ]
        
        # Analyze flows
        return self._analyze_source_flows(source_ip, recent_flows)
    
    def _cleanup_history(self, source_ip: str):
        """Remove old flows from history"""
        cutoff = time.time() - self.thresholds["window_seconds"]
        self.flow_history[source_ip] = [
            entry for entry in self.flow_history[source_ip]
            if entry["timestamp"] >= cutoff
        ]
    
    def get_scan_statistics(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Get scan-related statistics from flows
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Dictionary with scan statistics
        """
        stats = {
            "total_flows": len(flows),
            "sources_analyzed": 0,
            "potential_scanners": 0,
            "total_unique_ports": len(set(f.destination_port for f in flows)),
            "total_unique_hosts": len(set(f.destination_ip for f in flows)),
            "scan_sources": []
        }
        
        flows_by_source = self._group_flows_by_source(flows)
        stats["sources_analyzed"] = len(flows_by_source)
        
        for source_ip, source_flows in flows_by_source.items():
            unique_ports = len(set(f.destination_port for f in source_flows))
            unique_hosts = len(set(f.destination_ip for f in source_flows))
            
            if unique_ports >= self.thresholds["min_unique_destination_ports"]:
                stats["potential_scanners"] += 1
                stats["scan_sources"].append({
                    "ip": source_ip,
                    "unique_ports": unique_ports,
                    "unique_hosts": unique_hosts,
                    "flows": len(source_flows)
                })
        
        return stats