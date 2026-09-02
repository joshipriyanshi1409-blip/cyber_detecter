"""
DDoS/Flooding Detection Module
Detects DDoS attacks and traffic flooding using rate-based features.

## Evidence fusion (docs/NEXT_AGENT_PROMPT.md item 5)

Detection is driven by named evidence components -- volumetric (packet
rate), byte rate, TCP/SYN ratio, source-diversity (source concentration),
destination-concentration (is aggregate traffic piling onto one victim),
and directional asymmetry (one-way traffic with little/no reply, typical
of spoofed floods that never complete a handshake) -- rather than an
anonymous list of numbers. Each component that fires is recorded by name
in `details["evidence"]` (flat name -> value, same convention as
`syn_flood.py`/`udp_flood.py`, and what `alert_engine.py` generically
extracts into `Alert.evidence` for the dashboard), with the weight each
one contributed alongside in `details["evidence_weights"]`, so a human
(or the dashboard) can see *why* a detection fired, not just that it did.
Same >=2-factor-combination discipline as
`src/detectors/syn_flood.py` / `src/detectors/udp_flood.py`: a single
weak signal (e.g. destination concentration alone, which is trivially
true any time one destination happens to dominate a capture) never
triggers a detection by itself.

## rule_score vs ml_probability

Same discipline as `syn_flood.py`/`udp_flood.py`: no ML model is wired
into this detector. `rule_score` is the deterministic weighted
combination of evidence components; `confidence` currently equals
`rule_score` since nothing else contributes yet; `ml_probability` is
always `None` (never fabricated as `0.0`) until a real model is wired
in and actually contributes to the decision.
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import time
import numpy as np

from src.flow.nfstream_wrapper import FlowRecord
from src.features.window_rates import calculate_rates_for_flows
from src.features.source_stats import calculate_concentration

try:
    from src.utils.config import config_manager
except ImportError:
    from src.utils.config_simple import config_manager

logger = logging.getLogger(__name__)


@dataclass
class DDoSResult:
    """Standardized DDoS detection result"""
    threat_type: str = "DDOS"
    source_ip: str = ""
    destination_ip: str = ""
    confidence: float = 0.0
    severity: str = "HIGH"
    risk_score: float = 0.0
    detector: str = "rule_based_ddos"
    # rule_score: deterministic weighted-evidence score (see module
    # docstring). ml_probability: always None until a real model is wired
    # in -- never fabricated as 0.0, per Rule 28 (missing != zero).
    rule_score: float = 0.0
    ml_probability: Optional[float] = None
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


class DDoSDetector:
    """Detects DDoS and flooding attacks"""

    # calculate_concentration() returns a hardcoded 1.0 whenever there is
    # only one distinct category present (see its docstring) -- this is
    # mathematically correct (100% of traffic IS in that one category) but
    # is a degenerate, not-meaningful-as-evidence case: a single client
    # making a handful of requests to one website also produces exactly
    # this "fully concentrated" 1.0, with nothing anomalous going on.
    # Require a minimum population before treating concentration as flood
    # evidence -- same discipline as src/features/spoofing_likelihood.py's
    # MIN_SOURCES_FOR_SCORE=5 gate, applied here to both directions
    # (source concentration and destination concentration).
    MIN_DISTINCT_FOR_CONCENTRATION_EVIDENCE = 5

    def __init__(self):
        """Initialize DDoS detector"""
        self.thresholds = self._load_thresholds()
        self.traffic_history = defaultdict(list)
        logger.info(f"Initialized DDoSDetector with thresholds: {self.thresholds}")
    
    def _load_thresholds(self) -> Dict[str, Any]:
        """Load detection thresholds from config"""
        defaults = {
            "min_packets_per_second": 500,
            "min_bytes_per_second": 50000,
            "syn_ratio_threshold": 0.5,
            "source_concentration_threshold": 0.3,
            "window_seconds": 10,
            "min_flows": 5
        }
        
        try:
            thresholds = {
                "min_packets_per_second": config_manager.get_threshold(
                    "ddos", "min_pps", default=defaults["min_packets_per_second"]
                ),
                "min_bytes_per_second": config_manager.get_threshold(
                    "ddos", "min_bps", default=defaults["min_bytes_per_second"]
                ),
                "syn_ratio_threshold": config_manager.get_threshold(
                    "ddos", "min_syn_ratio", default=defaults["syn_ratio_threshold"]
                ),
                "source_concentration_threshold": config_manager.get_threshold(
                    "ddos", "source_concentration", default=defaults["source_concentration_threshold"]
                ),
                "window_seconds": config_manager.get_threshold(
                    "ddos", "window_seconds", default=defaults["window_seconds"]
                ),
                "min_flows": config_manager.get_threshold(
                    "ddos", "min_flows", default=defaults["min_flows"]
                )
            }
            return thresholds
        except Exception as e:
            logger.warning(f"Failed to load thresholds from config: {e}. Using defaults.")
            return defaults
    
    def detect(self, flows: List[FlowRecord]) -> List[DDoSResult]:
        """
        Detect DDoS attacks from flows
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            List of DDoSResult objects
        """
        if not flows:
            return []
        
        detections = []
        
        # Analyze aggregate traffic
        aggregate_result = self._analyze_aggregate_traffic(flows)
        if aggregate_result:
            detections.append(aggregate_result)
        
        # Analyze per-destination traffic
        flows_by_destination = self._group_flows_by_destination(flows)
        for dest_ip, dest_flows in flows_by_destination.items():
            result = self._analyze_destination_flows(dest_ip, dest_flows)
            if result:
                # Avoid duplicate detection for same destination
                if not aggregate_result or result.destination_ip != aggregate_result.destination_ip:
                    detections.append(result)
        
        logger.info(f"DDoSDetector: Detected {len(detections)} potential DDoS attacks")
        return detections
    
    def _group_flows_by_destination(self, flows: List[FlowRecord]) -> Dict[str, List[FlowRecord]]:
        """Group flows by destination IP"""
        groups = defaultdict(list)
        for flow in flows:
            groups[flow.destination_ip].append(flow)
        return dict(groups)

    def _calculate_directional_asymmetry(self, flows: List[FlowRecord]) -> Optional[float]:
        """
        Measure how one-directional traffic is: src2dst bytes vs. dst2src
        bytes, summed across flows. Returns a value in [0, 1] where 1.0
        means "entirely one-way" (no reply traffic at all -- consistent
        with a spoofed/never-completed flood where the victim's replies
        go nowhere or never arrive) and values near 0 mean traffic is
        roughly symmetric (consistent with ordinary completed sessions).

        Returns None (not 0.0) when there is no src2dst traffic to reason
        about at all, since "no request traffic" is a different, degenerate
        situation from "fully asymmetric request/response traffic" -- see
        Rule 28 (missing != zero) applied elsewhere in this repo, e.g.
        src/features/window_rates.py.
        """
        total_src2dst = sum(f.src2dst_bytes for f in flows)
        total_dst2src = sum(f.dst2src_bytes for f in flows)

        if total_src2dst <= 0:
            return None

        # 1.0 when there is no reply traffic at all, falling toward 0 as
        # reply volume approaches request volume.
        return max(0.0, 1.0 - (total_dst2src / total_src2dst))
    
    def _analyze_aggregate_traffic(self, flows: List[FlowRecord]) -> Optional[DDoSResult]:
        """
        Analyze aggregate traffic for DDoS indicators
        
        Args:
            flows: All flow records
            
        Returns:
            DDoSResult if attack detected, None otherwise
        """
        if len(flows) < self.thresholds["min_flows"]:
            return None
        
        # Rate calculation over the SHARED observation window (window_end -
        # window_start), not the sum of each flow's own duration. See
        # src/features/window_rates.py for why that distinction matters --
        # summing durations understates the rate by up to Nx for N
        # simultaneous flows.
        rates = calculate_rates_for_flows(flows)
        total_packets = rates["total_packets"]
        total_bytes = rates["total_bytes"]

        if rates["packets_per_second"] is None:
            # Window unavailable (no usable timestamps) -- this is a
            # different situation from "no traffic detected" and must not
            # be silently treated as zero (Rule 28). Without a window we
            # cannot evaluate rate-based thresholds at all.
            logger.warning(
                "DDoS aggregate analysis: observation window unavailable "
                "(flows lack usable timestamps); skipping rate-based checks"
            )
            packets_per_second = None
            bytes_per_second = None
        else:
            packets_per_second = rates["packets_per_second"]
            bytes_per_second = rates["bytes_per_second"]
        
        # Calculate SYN ratio
        total_syn = sum(f.syn_packets for f in flows)
        syn_ratio = total_syn / total_packets if total_packets > 0 else 0
        
        # Calculate source concentration (how concentrated are the sources)
        distinct_sources = set(f.source_ip for f in flows)
        source_concentration = calculate_concentration([f.source_ip for f in flows])

        # Calculate destination concentration (is aggregate traffic piling
        # onto one victim, vs. spread across many destinations -- routine
        # for a busy network segment)
        distinct_destinations = set(f.destination_ip for f in flows)
        destination_concentration = calculate_concentration([f.destination_ip for f in flows])

        # Directional asymmetry (one-way traffic with little/no reply)
        directional_asymmetry = self._calculate_directional_asymmetry(flows)

        # Named evidence components (docs/NEXT_AGENT_PROMPT.md item 5):
        # each component is (weight, value_if_fired, evidence_dict_entry).
        # Weights sum to 1.0 across all six components; a detection still
        # requires >=2 components to fire (see below) so no single weak
        # signal decides the outcome alone.
        evidence_components: Dict[str, Dict[str, Any]] = {}

        if packets_per_second is not None and packets_per_second >= self.thresholds["min_packets_per_second"]:
            evidence_components["volumetric"] = {"weight": 0.30, "value": packets_per_second}

        if bytes_per_second is not None and bytes_per_second >= self.thresholds["min_bytes_per_second"]:
            evidence_components["byte_rate"] = {"weight": 0.15, "value": bytes_per_second}

        if (syn_ratio >= self.thresholds["syn_ratio_threshold"] and
                packets_per_second is not None and
                packets_per_second >= self.thresholds["min_packets_per_second"] * 0.2):
            evidence_components["tcp_syn"] = {"weight": 0.25, "value": syn_ratio}

        if (len(distinct_sources) >= self.MIN_DISTINCT_FOR_CONCENTRATION_EVIDENCE
                and source_concentration >= self.thresholds["source_concentration_threshold"]):
            evidence_components["source_concentration"] = {"weight": 0.10, "value": source_concentration}

        if (len(distinct_destinations) >= self.MIN_DISTINCT_FOR_CONCENTRATION_EVIDENCE
                and destination_concentration >= self.thresholds["source_concentration_threshold"]):
            evidence_components["destination_concentration"] = {"weight": 0.10, "value": destination_concentration}

        if directional_asymmetry is not None and directional_asymmetry >= 0.9:
            evidence_components["asymmetry"] = {"weight": 0.10, "value": directional_asymmetry}

        # Never decide on a single factor alone -- same discipline as
        # syn_flood.py/udp_flood.py. One dominant destination or one
        # concentrated source, by itself, is common in ordinary traffic
        # (e.g. a busy internal service) and is not enough evidence alone.
        if len(evidence_components) < 2:
            return None

        rule_score = min(sum(c["weight"] for c in evidence_components.values()), 1.0)
        confidence = rule_score

        # Determine severity
        severity = self._determine_severity(
            packets_per_second or 0, bytes_per_second or 0, syn_ratio
        )
        
        # Get main target (most common destination)
        target_ips = [f.destination_ip for f in flows]
        main_target = max(set(target_ips), key=target_ips.count) if target_ips else ""

        unique_sources = len(set(f.source_ip for f in flows))

        # "evidence": flat name -> value, matching the convention used by
        # src/detectors/syn_flood.py and src/detectors/udp_flood.py -- this
        # is what src/alerts/alert_engine.py's _detection_to_alert()
        # generically reads via details["evidence"] into Alert.evidence for
        # the dashboard. "evidence_weights" carries the same names mapped
        # to the weight each contributed, for anyone who wants the fuller
        # audit trail without breaking that existing generic extraction.
        evidence = {name: c["value"] for name, c in evidence_components.items()}
        evidence_weights = {name: c["weight"] for name, c in evidence_components.items()}

        return DDoSResult(
            source_ip="multiple_sources",
            destination_ip=main_target,
            confidence=confidence,
            severity=severity,
            risk_score=confidence * 100,
            rule_score=rule_score,
            ml_probability=None,
            details={
                "total_flows": len(flows),
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "packets_per_second": packets_per_second,
                "bytes_per_second": bytes_per_second,
                "syn_ratio": syn_ratio,
                "source_concentration": source_concentration,
                "destination_concentration": destination_concentration,
                "directional_asymmetry": directional_asymmetry,
                "source_count": unique_sources,
                "window_seconds": rates["window_seconds"],
                "window_clamped": rates.get("window_clamped", False),
                "evidence": evidence,
                "evidence_weights": evidence_weights,
                "thresholds": self.thresholds
            }
        )
    
    def _analyze_destination_flows(self, dest_ip: str, flows: List[FlowRecord]) -> Optional[DDoSResult]:
        """
        Analyze flows to a specific destination for DDoS
        
        Args:
            dest_ip: Destination IP address
            flows: Flows to this destination
            
        Returns:
            DDoSResult if attack detected, None otherwise
        """
        if len(flows) < 3:
            return None
        
        rates = calculate_rates_for_flows(flows)
        total_packets = rates["total_packets"]
        total_bytes = rates["total_bytes"]
        packets_per_second = rates["packets_per_second"]
        bytes_per_second = rates["bytes_per_second"]

        if packets_per_second is None:
            return None  # window unavailable; cannot evaluate rate threshold

        # Named evidence components, same discipline as the aggregate
        # analysis above: rate alone is not enough, corroborate with
        # source-diversity and/or directional asymmetry among the sources
        # hitting THIS destination specifically.
        total_syn = sum(f.syn_packets for f in flows)
        syn_ratio = total_syn / total_packets if total_packets > 0 else 0
        source_concentration = calculate_concentration([f.source_ip for f in flows])
        directional_asymmetry = self._calculate_directional_asymmetry(flows)

        evidence_components: Dict[str, Dict[str, Any]] = {}

        if packets_per_second >= self.thresholds["min_packets_per_second"]:
            evidence_components["volumetric"] = {"weight": 0.40, "value": packets_per_second}

        if bytes_per_second is not None and bytes_per_second >= self.thresholds["min_bytes_per_second"]:
            evidence_components["byte_rate"] = {"weight": 0.20, "value": bytes_per_second}

        if (syn_ratio >= self.thresholds["syn_ratio_threshold"] and
                packets_per_second >= self.thresholds["min_packets_per_second"] * 0.2):
            evidence_components["tcp_syn"] = {"weight": 0.20, "value": syn_ratio}

        if directional_asymmetry is not None and directional_asymmetry >= 0.9:
            evidence_components["asymmetry"] = {"weight": 0.20, "value": directional_asymmetry}

        if len(evidence_components) < 2:
            return None

        rule_score = min(sum(c["weight"] for c in evidence_components.values()), 1.0)
        confidence = rule_score
        unique_sources = len(set(f.source_ip for f in flows))

        evidence = {name: c["value"] for name, c in evidence_components.items()}
        evidence_weights = {name: c["weight"] for name, c in evidence_components.items()}

        return DDoSResult(
            source_ip="multiple_sources",
            destination_ip=dest_ip,
            confidence=confidence,
            severity="HIGH" if confidence > 0.5 else "MEDIUM",
            risk_score=confidence * 100,
            rule_score=rule_score,
            ml_probability=None,
            details={
                "total_flows": len(flows),
                "packets_per_second": packets_per_second,
                "bytes_per_second": bytes_per_second,
                "syn_ratio": syn_ratio,
                "source_concentration": source_concentration,
                "directional_asymmetry": directional_asymmetry,
                "source_count": unique_sources,
                "window_seconds": rates["window_seconds"],
                "window_clamped": rates.get("window_clamped", False),
                "evidence": evidence,
                "evidence_weights": evidence_weights,
                "targeted_attack": True,
            }
        )
    
    def _determine_severity(self, pps: float, bps: float, syn_ratio: float) -> str:
        """Determine attack severity based on rates"""
        if pps >= 5000 or bps >= 5000000:
            return "CRITICAL"
        elif pps >= 2000 or bps >= 2000000:
            return "HIGH"
        elif pps >= 1000 or bps >= 1000000:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_flood_statistics(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Get flooding-related statistics from flows
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Dictionary with flood statistics
        """
        if not flows:
            return {
                "total_flows": 0,
                "packets_per_second": None,
                "bytes_per_second": None,
                "total_packets": 0,
                "total_bytes": 0,
                "syn_ratio": 0,
                "source_concentration": 0,
                "destination_concentration": 0,
                "directional_asymmetry": None
            }
        
        rates = calculate_rates_for_flows(flows)
        total_packets = rates["total_packets"]
        total_bytes = rates["total_bytes"]

        total_syn = sum(f.syn_packets for f in flows)
        
        return {
            "total_flows": len(flows),
            "packets_per_second": rates["packets_per_second"],
            "bytes_per_second": rates["bytes_per_second"],
            "window_seconds": rates["window_seconds"],
            "window_clamped": rates.get("window_clamped", False),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "syn_ratio": total_syn / total_packets if total_packets > 0 else 0,
            "source_concentration": calculate_concentration([f.source_ip for f in flows]),
            "destination_concentration": calculate_concentration([f.destination_ip for f in flows]),
            "directional_asymmetry": self._calculate_directional_asymmetry(flows)
        }