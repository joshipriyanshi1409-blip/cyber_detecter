"""
SYN-Flood-Specific Detection Module
=====================================
Detects SYN-flood-style TCP flooding using the direction-aware SYN
fields added during the flow-model audit (`syn_only_packets` /
`syn_ack_packets` on `FlowRecord` -- see docs/AUDIT_PROGRESS.md item 5 /
docs/NEXT_AGENT_PROMPT.md item 3). Nothing consumed these fields before
this module.

## Why this is a separate detector from DDoSDetector

`src/detectors/ddos.py` still uses the legacy, direction-blind
`syn_packets` field (ANY packet with the SYN flag, including SYN-ACK
replies) as one volumetric factor among several. That's a reasonable
coarse signal for generic flooding, but it can't distinguish "lots of
completed handshakes" from "lots of half-open connections", which is
the actual signature of a SYN flood. This module uses the newer,
direction-aware fields to make that distinction explicit.

## What "SYN flood" evidence looks like from passive flow data

A SYN flood is characterized by a burst of TCP SYNs that mostly never
complete a 3-way handshake -- either because the attacker never intends
to ACK a SYN-ACK (classic SYN flood) or because the target's backlog is
exhausted and stops replying. From passive, single-vantage-point flow
data we can observe:

- An elevated rate of client-initiated SYNs (`syn_only_packets`).
- A low ratio of server SYN-ACK replies to those SYNs, OR a low ratio of
  completed (ACKed) handshakes to SYNs -- either indicates handshakes
  are not completing normally.
- (Aggregate-level) traffic concentrated on a small number of
  destinations -- floods target something specific.
- (Per-destination level) a high proportion of sources that only ever
  sent one packet -- consistent with, though not proof of, spoofed or
  botnet source addresses. This reuses
  `src/features/source_stats.py`'s `one_packet_source_ratio` output
  rather than reimplementing source-diversity scoring a 4th time (see
  docs/NEXT_AGENT_PROMPT.md item 1's warning about that trap) -- but
  does NOT call `spoofing_likelihood.calculate_spoofing_likelihood`
  wholesale (nor recombine its other signals), because that function's
  other signals are unreliable once flows are already grouped down to a
  single destination: `destination_concentration` is trivially 1.0, and
  `source_entropy` alone is too weak/noisy at typical single-destination
  sample sizes (see `_per_destination_spoofing_evidence` for the full
  explanation, including a false-positive this caused during
  verification and why it was fixed by dropping entropy rather than
  just re-weighting it).

**None of this proves an attack.** A saturated but legitimate server, a
misconfigured client retrying aggressively, or an asymmetric capture
point (only seeing one direction of traffic) can all produce similar
low-completion-ratio readings. This detector reports rule-based
`confidence`/`rule_score` evidence, never a certainty -- consistent with
the "never fabricate cybersecurity capabilities" rule carried over from
the original audit brief.

## rule_score vs ml_probability

No ML model is wired into this detector. `rule_score` is the weighted,
deterministic combination of the rule-based factors below; `confidence`
currently equals `rule_score` since nothing else contributes yet;
`ml_probability` is always `None` (not `0.0` -- see Rule 28 / missing-
vs-zero) and must stay that way until a real model is actually wired in.
Do not let a future change silently copy one field into the other.
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

from src.flow.nfstream_wrapper import FlowRecord
from src.features.window_rates import compute_window_bounds, calculate_window_rates
from src.features.source_stats import calculate_concentration, calculate_source_stats

# NOTE: deliberately NOT importing/calling calculate_spoofing_likelihood
# for use at the per-destination level -- see
# _per_destination_spoofing_evidence below for why the full function
# (and even a re-weighted combination of its signals) is unsuitable once
# flows are already filtered to a single destination.

try:
    from src.utils.config import config_manager
except ImportError:
    from src.utils.config_simple import config_manager

logger = logging.getLogger(__name__)

# TCP protocol number (IANA). Only TCP flows carry meaningful SYN/ACK/RST
# semantics; non-TCP flows are excluded before any ratio is computed.
TCP_PROTOCOL = 6


@dataclass
class SynFloodResult:
    """Standardized SYN-flood detection result. Same shape as
    DDoSResult/PortScanResult (threat_type/source_ip/destination_ip/
    confidence/severity/risk_score/detector/details/timestamp) so it
    flows through the existing generic `AlertEngine._detection_to_alert`
    path unchanged -- see src/alerts/alert_engine.py, which only relies
    on `to_dict()` / dict-shaped access and doesn't special-case
    per-detector result types.
    """
    threat_type: str = "SYN_FLOOD"
    source_ip: str = ""
    destination_ip: str = ""
    confidence: float = 0.0
    severity: str = "HIGH"
    risk_score: float = 0.0
    detector: str = "rule_based_syn_flood"
    # Kept explicitly separate per the audit's non-negotiable rule: never
    # copy one into the other, never fabricate a 0.0 for "no ML".
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


class SynFloodDetector:
    """Detects SYN-flood-style TCP flooding using direction-aware SYN
    fields, corroborated with destination concentration (aggregate
    level) and source-diversity/spoofing-likelihood evidence
    (per-destination level). Never decides on a single ratio alone."""

    def __init__(self):
        """Initialize SYN-flood detector"""
        self.thresholds = self._load_thresholds()
        logger.info(f"Initialized SynFloodDetector with thresholds: {self.thresholds}")

    def _load_thresholds(self) -> Dict[str, Any]:
        """Load detection thresholds from config, falling back to
        documented prototype defaults (same pattern as ddos.py/scan.py)
        if the config lookup itself fails for any reason."""
        defaults = {
            "min_flows": 5,
            "min_syn_only_pps": 100.0,
            "max_ack_completion_ratio": 0.3,
            "destination_concentration_threshold": 0.5,
            "min_spoofing_likelihood": 0.4,
        }

        try:
            thresholds = {
                "min_flows": config_manager.get_threshold(
                    "syn_flood", "min_flows", default=defaults["min_flows"]
                ),
                "min_syn_only_pps": config_manager.get_threshold(
                    "syn_flood", "min_syn_only_pps", default=defaults["min_syn_only_pps"]
                ),
                "max_ack_completion_ratio": config_manager.get_threshold(
                    "syn_flood", "max_ack_completion_ratio",
                    default=defaults["max_ack_completion_ratio"]
                ),
                "destination_concentration_threshold": config_manager.get_threshold(
                    "syn_flood", "destination_concentration_threshold",
                    default=defaults["destination_concentration_threshold"]
                ),
                "min_spoofing_likelihood": config_manager.get_threshold(
                    "syn_flood", "min_spoofing_likelihood",
                    default=defaults["min_spoofing_likelihood"]
                ),
            }
            return thresholds
        except Exception as e:
            logger.warning(f"Failed to load thresholds from config: {e}. Using defaults.")
            return defaults

    def detect(self, flows: List[FlowRecord]) -> List[SynFloodResult]:
        """
        Detect SYN-flood-style attacks from flows.

        Only TCP flows (protocol == 6) carry SYN/ACK/RST semantics; all
        other flows are ignored here (they simply can't provide SYN-flood
        evidence either way -- this is a filter, not a "no evidence found"
        result for those flows).

        Args:
            flows: List of FlowRecord objects

        Returns:
            List of SynFloodResult objects
        """
        tcp_flows = [f for f in flows if f.protocol == TCP_PROTOCOL]
        if not tcp_flows:
            return []

        detections = []

        aggregate_result = self._analyze_aggregate_traffic(tcp_flows)
        if aggregate_result:
            detections.append(aggregate_result)

        flows_by_destination = self._group_flows_by_destination(tcp_flows)
        for dest_ip, dest_flows in flows_by_destination.items():
            result = self._analyze_destination_flows(dest_ip, dest_flows)
            if result:
                # Avoid duplicate detection for the same destination the
                # aggregate result already flagged (same pattern as
                # DDoSDetector.detect).
                if not aggregate_result or result.destination_ip != aggregate_result.destination_ip:
                    detections.append(result)

        logger.info(f"SynFloodDetector: Detected {len(detections)} potential SYN floods")
        return detections

    def _group_flows_by_destination(self, flows: List[FlowRecord]) -> Dict[str, List[FlowRecord]]:
        """Group flows by destination IP"""
        groups = defaultdict(list)
        for flow in flows:
            groups[flow.destination_ip].append(flow)
        return dict(groups)

    def _compute_syn_metrics(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Compute the direction-aware SYN/ACK/RST ratios and the
        SYN-only packet rate for a set of (already TCP-filtered) flows.

        Missing vs. zero (Rule 28): ratios whose denominator is zero
        (e.g. no SYN-only packets observed at all) are reported as
        `None`, not `0.0` -- a 0.0 completion ratio is a real, meaningful
        "nothing completed" measurement; `None` means "no SYNs to even
        judge completion against" and must not be treated as evidence
        either way.
        """
        total_syn_only = sum(f.syn_only_packets for f in flows)
        total_syn_ack = sum(f.syn_ack_packets for f in flows)
        total_ack = sum(f.ack_packets for f in flows)
        total_rst = sum(f.rst_packets for f in flows)

        # Flow-level incomplete-handshake ratio: flows where the client
        # sent a SYN but the flow record shows no ACK at all (no reply
        # observed AND no completed handshake), regardless of RST. This
        # mirrors the flow-level "no response" signature already
        # established in src/detectors/scan.py's failure-signature fix,
        # but here it's about SATURATION evidence within one flow's
        # lifetime, not about scan breadth across many destinations.
        incomplete_flows = sum(
            1 for f in flows if f.syn_only_packets > 0 and f.ack_packets == 0
        )
        incomplete_flow_ratio = incomplete_flows / len(flows) if flows else None

        syn_ack_ratio = (
            total_syn_ack / total_syn_only if total_syn_only > 0 else None
        )
        ack_completion_ratio = (
            total_ack / total_syn_only if total_syn_only > 0 else None
        )
        rst_ratio = (
            total_rst / total_syn_only if total_syn_only > 0 else None
        )

        window_start_ms, window_end_ms = compute_window_bounds(flows)
        # Reuse the tested window-rate clamping logic from
        # window_rates.py rather than reimplementing it. We only care
        # about the packets_per_second figure here (for SYN-only
        # packets); the bytes_per_second this returns is meaningless
        # (FlowRecord has no per-direction SYN-only byte count) and is
        # deliberately NOT surfaced in this detector's evidence/details.
        syn_rate_result = calculate_window_rates(
            total_packets=total_syn_only,
            total_bytes=0,
            total_flows=len(flows),
            window_start_ms=window_start_ms,
            window_end_ms=window_end_ms,
        )

        return {
            "total_syn_only": total_syn_only,
            "total_syn_ack": total_syn_ack,
            "total_ack": total_ack,
            "total_rst": total_rst,
            "incomplete_flow_ratio": incomplete_flow_ratio,
            "syn_ack_ratio": syn_ack_ratio,
            "ack_completion_ratio": ack_completion_ratio,
            "rst_ratio": rst_ratio,
            "syn_only_packets_per_second": syn_rate_result["packets_per_second"],
            "window_seconds": syn_rate_result["window_seconds"],
            "window_clamped": syn_rate_result.get("window_clamped", False),
        }

    def _analyze_aggregate_traffic(self, tcp_flows: List[FlowRecord]) -> Optional[SynFloodResult]:
        """
        Aggregate-level analysis: is TCP SYN traffic, taken as a whole,
        showing flood-like volume + low handshake completion + traffic
        concentrated on a small number of destinations?

        Destination concentration is the corroborating signal at THIS
        level (not source diversity -- with many destinations mixed
        together, source-diversity-per-destination isn't meaningful
        yet; that's what `_analyze_destination_flows` is for).
        """
        if len(tcp_flows) < self.thresholds["min_flows"]:
            return None

        metrics = self._compute_syn_metrics(tcp_flows)
        destination_concentration = calculate_concentration(
            [f.destination_ip for f in tcp_flows]
        )

        confidence_factors = []
        evidence = {}

        syn_only_pps = metrics["syn_only_packets_per_second"]
        if syn_only_pps is not None and syn_only_pps >= self.thresholds["min_syn_only_pps"]:
            confidence_factors.append(0.4)
            evidence["syn_only_packets_per_second"] = syn_only_pps

        ack_completion_ratio = metrics["ack_completion_ratio"]
        if (
            ack_completion_ratio is not None
            and ack_completion_ratio <= self.thresholds["max_ack_completion_ratio"]
        ):
            confidence_factors.append(0.3)
            evidence["ack_completion_ratio"] = ack_completion_ratio

        if destination_concentration >= self.thresholds["destination_concentration_threshold"]:
            confidence_factors.append(0.3)
            evidence["destination_concentration"] = destination_concentration

        # Per docs/NEXT_AGENT_PROMPT.md item 3: never decide "SYN flood"
        # on a single ratio alone. A high SYN rate by itself can just be
        # a busy legitimate server; low completion by itself can be an
        # asymmetric capture point; high destination concentration by
        # itself is normal for any single-server workload. Require at
        # least TWO independent, corroborating factors before flagging.
        if len(confidence_factors) < 2:
            return None

        # Rule-based confidence only -- no ML model contributes here.
        rule_score = min(sum(confidence_factors), 1.0)
        confidence = rule_score

        severity = self._determine_severity(syn_only_pps or 0, ack_completion_ratio)

        target_ips = [f.destination_ip for f in tcp_flows]
        main_target = max(set(target_ips), key=target_ips.count) if target_ips else ""
        unique_sources = len(set(f.source_ip for f in tcp_flows))

        return SynFloodResult(
            source_ip="multiple_sources",
            destination_ip=main_target,
            confidence=confidence,
            severity=severity,
            risk_score=confidence * 100,
            rule_score=rule_score,
            ml_probability=None,
            details={
                "total_flows": len(tcp_flows),
                "total_syn_only": metrics["total_syn_only"],
                "total_syn_ack": metrics["total_syn_ack"],
                "total_ack": metrics["total_ack"],
                "total_rst": metrics["total_rst"],
                "incomplete_flow_ratio": metrics["incomplete_flow_ratio"],
                "syn_ack_ratio": metrics["syn_ack_ratio"],
                "ack_completion_ratio": ack_completion_ratio,
                "rst_ratio": metrics["rst_ratio"],
                "syn_only_packets_per_second": syn_only_pps,
                "window_seconds": metrics["window_seconds"],
                "window_clamped": metrics["window_clamped"],
                "destination_concentration": destination_concentration,
                "source_count": unique_sources,
                "evidence": evidence,
                "thresholds": self.thresholds,
            },
        )

    def _per_destination_spoofing_evidence(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Source-diversity evidence for a set of flows already filtered to
        ONE destination.

        This deliberately does NOT call
        `spoofing_likelihood.calculate_spoofing_likelihood(flows)`
        wholesale: that function's weighted score includes
        `destination_concentration` as one of its signals, computed as
        `calculate_concentration([f.destination_ip for f in flows])`.
        When `flows` has already been grouped down to a single
        destination (as it always is here -- see `_group_flows_by_destination`
        in `detect()`), that concentration is trivially 1.0 for every
        single group, regardless of actual source-diversity evidence --
        silently inflating the score every time. (Caught by
        `tests/test_syn_flood.py::test_syn_heavy_legitimate_workload_not_flagged`
        during verification of this detector -- an earlier version of
        this method called `calculate_spoofing_likelihood` directly and
        that test failed for exactly this reason.)

        Deliberately uses ONLY `one_packet_source_ratio` from
        `source_stats.calculate_source_stats`, NOT `source_entropy`.
        `source_entropy` alone -- without a corroborating
        `destination_concentration` signal spanning MULTIPLE
        destinations, which is exactly what's unavailable here -- is too
        weak and noisy to trust at the small sample sizes typical of one
        destination's traffic: a perfectly ordinary handful of real
        clients sending evenly-distributed legitimate traffic to one
        server also produces entropy near 1.0 (maximally "even"), which
        would falsely read as evidence of spoofing. `one_packet_source_ratio`
        does not have this problem -- real, persistent hosts essentially
        never show up as exactly one packet in a window, so it stays a
        meaningful, specific signal even alone. (An earlier version of
        this method combined entropy and one_packet_source_ratio with
        `spoofing_likelihood.SIGNAL_WEIGHTS`'s relative weighting, and
        `tests/test_syn_flood.py::test_syn_heavy_legitimate_workload_not_flagged`
        still false-positived on exactly this "5 real clients, evenly
        distributed" shape -- confirming entropy needed to be dropped
        here entirely, not just down-weighted.)

        Reuses `MIN_SOURCES_FOR_SCORE`-style insufficient-data handling:
        below `self.thresholds["min_flows"]` distinct sources the
        underlying ratio is too small a sample to mean anything, so this
        returns `None`/"insufficient_data" rather than a noisy score.
        """
        source_stats = calculate_source_stats(flows)
        unique_source_count = source_stats["unique_source_count"]

        if unique_source_count < self.thresholds["min_flows"]:
            return {
                "spoofing_likelihood": None,
                "spoofing_likelihood_label": "insufficient_data",
                "unique_source_count": unique_source_count,
            }

        one_packet_source_ratio = source_stats["one_packet_source_ratio"]
        if one_packet_source_ratio is None:
            return {
                "spoofing_likelihood": None,
                "spoofing_likelihood_label": "insufficient_data",
                "unique_source_count": unique_source_count,
            }

        score = one_packet_source_ratio

        if score >= 0.7:
            label = "high"
        elif score >= 0.4:
            label = "medium"
        elif score >= 0.15:
            label = "low"
        else:
            label = "minimal"

        return {
            "spoofing_likelihood": score,
            "spoofing_likelihood_label": label,
            "unique_source_count": unique_source_count,
        }

    def _analyze_destination_flows(
        self, dest_ip: str, flows: List[FlowRecord]
    ) -> Optional[SynFloodResult]:
        """
        Per-destination analysis: for TCP flows aimed at ONE destination,
        is SYN volume/low-completion evidence corroborated by
        source-diversity / spoofing-likelihood evidence (rather than
        destination concentration, which is trivially 1.0 here since the
        group is already filtered to one destination)?
        """
        if len(flows) < self.thresholds["min_flows"]:
            return None

        metrics = self._compute_syn_metrics(flows)
        spoofing = self._per_destination_spoofing_evidence(flows)

        confidence_factors = []
        evidence = {}

        syn_only_pps = metrics["syn_only_packets_per_second"]
        if syn_only_pps is not None and syn_only_pps >= self.thresholds["min_syn_only_pps"]:
            confidence_factors.append(0.4)
            evidence["syn_only_packets_per_second"] = syn_only_pps

        ack_completion_ratio = metrics["ack_completion_ratio"]
        if (
            ack_completion_ratio is not None
            and ack_completion_ratio <= self.thresholds["max_ack_completion_ratio"]
        ):
            confidence_factors.append(0.3)
            evidence["ack_completion_ratio"] = ack_completion_ratio

        spoofing_likelihood = spoofing["spoofing_likelihood"]
        if (
            spoofing_likelihood is not None
            and spoofing_likelihood >= self.thresholds["min_spoofing_likelihood"]
        ):
            confidence_factors.append(0.3)
            evidence["spoofing_likelihood"] = spoofing_likelihood
            evidence["spoofing_likelihood_label"] = spoofing["spoofing_likelihood_label"]

        # Same combination rule as the aggregate analysis above -- see
        # the comment there. `spoofing_likelihood` being `None`
        # ("insufficient_data", e.g. too few distinct sources) simply
        # can't contribute a factor; it is NOT treated as evidence
        # against a flood either.
        if len(confidence_factors) < 2:
            return None

        rule_score = min(sum(confidence_factors), 1.0)
        confidence = rule_score

        severity = self._determine_severity(syn_only_pps or 0, ack_completion_ratio)
        unique_sources = len(set(f.source_ip for f in flows))

        return SynFloodResult(
            source_ip="multiple_sources",
            destination_ip=dest_ip,
            confidence=confidence,
            severity=severity,
            risk_score=confidence * 100,
            rule_score=rule_score,
            ml_probability=None,
            details={
                "total_flows": len(flows),
                "total_syn_only": metrics["total_syn_only"],
                "total_syn_ack": metrics["total_syn_ack"],
                "total_ack": metrics["total_ack"],
                "total_rst": metrics["total_rst"],
                "incomplete_flow_ratio": metrics["incomplete_flow_ratio"],
                "syn_ack_ratio": metrics["syn_ack_ratio"],
                "ack_completion_ratio": ack_completion_ratio,
                "rst_ratio": metrics["rst_ratio"],
                "syn_only_packets_per_second": syn_only_pps,
                "window_seconds": metrics["window_seconds"],
                "window_clamped": metrics["window_clamped"],
                "source_count": unique_sources,
                "spoofing_likelihood": spoofing_likelihood,
                "spoofing_likelihood_label": spoofing["spoofing_likelihood_label"],
                "evidence": evidence,
                "thresholds": self.thresholds,
            },
        )

    def _determine_severity(
        self, syn_only_pps: float, ack_completion_ratio: Optional[float]
    ) -> str:
        """Determine attack severity based on SYN-only rate, escalated
        one notch if handshake completion is very low (strong evidence
        of a saturated/half-open backlog rather than merely busy
        traffic)."""
        if syn_only_pps >= 5000:
            severity = "CRITICAL"
        elif syn_only_pps >= 2000:
            severity = "HIGH"
        elif syn_only_pps >= 500:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if ack_completion_ratio is not None and ack_completion_ratio < 0.05:
            escalation = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}
            severity = escalation[severity]

        return severity

    def get_syn_flood_statistics(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Get SYN-flood-related statistics from flows, independent of
        whether any threshold was crossed (mirrors
        DDoSDetector.get_flood_statistics / PortScanDetector.get_scan_statistics).

        Args:
            flows: List of FlowRecord objects

        Returns:
            Dictionary with SYN-flood statistics
        """
        tcp_flows = [f for f in flows if f.protocol == TCP_PROTOCOL]
        if not tcp_flows:
            return {
                "total_flows": 0,
                "total_tcp_flows": 0,
                "syn_only_packets_per_second": None,
                "ack_completion_ratio": None,
                "syn_ack_ratio": None,
                "destination_concentration": 0.0,
            }

        metrics = self._compute_syn_metrics(tcp_flows)
        destination_concentration = calculate_concentration(
            [f.destination_ip for f in tcp_flows]
        )

        return {
            "total_flows": len(flows),
            "total_tcp_flows": len(tcp_flows),
            "total_syn_only": metrics["total_syn_only"],
            "total_syn_ack": metrics["total_syn_ack"],
            "total_ack": metrics["total_ack"],
            "total_rst": metrics["total_rst"],
            "incomplete_flow_ratio": metrics["incomplete_flow_ratio"],
            "syn_ack_ratio": metrics["syn_ack_ratio"],
            "ack_completion_ratio": metrics["ack_completion_ratio"],
            "rst_ratio": metrics["rst_ratio"],
            "syn_only_packets_per_second": metrics["syn_only_packets_per_second"],
            "window_seconds": metrics["window_seconds"],
            "window_clamped": metrics["window_clamped"],
            "destination_concentration": destination_concentration,
        }
