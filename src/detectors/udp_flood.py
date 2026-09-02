"""
UDP Flood + Reflection-Like Detection Module
==============================================
Implements docs/NEXT_AGENT_PROMPT.md item 4. Two related but distinct
threat types, both produced by `UDPFloodDetector.detect()`:

- **UDP_FLOOD**: a high volume of UDP traffic aimed at one or few
  destinations, corroborated by destination-port concentration
  (aggregate level) or source diversity (per-destination level).
  Structurally the same two-level, >=2-factor-combination approach as
  `src/detectors/syn_flood.py` -- see that module's docstring for the
  full rationale; not repeated here.

- **UDP_REFLECTION_LIKE**: flows showing the byte/packet asymmetry
  characteristic of reflection/amplification abuse (a tiny request
  followed by a much larger reply). Deliberately named `_LIKE` and
  never asserted as certain -- see "Why reflection can only ever be
  '_LIKE' from passive one-way data" below.

## Why reflection can only ever be "_LIKE" from passive one-way data

A real reflection/amplification attack has three parties: an attacker
who spoofs a victim's source IP, a reflector (a UDP service that
replies to unauthenticated requests, e.g. open DNS/NTP/memcached/SSDP/
CLDAP), and the victim who receives the (often much larger) reply. From
a single passive vantage point capturing ordinary bidirectional flow
records, we can only ever observe ONE side of this: a flow where the
reply direction carries far more bytes/packets than the request
direction. That asymmetry is genuinely consistent with reflection abuse
-- but it is EXACTLY what a normal, legitimate UDP request/response
protocol looks like too (a DNS query for a large record, an NTP
sync, an SSDP discovery response, a game-server status query). We have
no way to know, from this data alone:
- whether the "request" packet was actually sent by the address it
  claims to be from (spoofing is invisible to a flow record -- there is
  no cryptographic or path validation happening at this layer), or
- whether the reply volume is anomalous for this specific service, or
  just how that service normally behaves.

So this detector reports amplification-*shaped* evidence (`_LIKE`) with
a rule-based confidence, corroborated by whether the smaller-volume
side's port is a commonly-abused reflection service port (itself only
weak, corroborating evidence -- plenty of legitimate DNS/NTP traffic
exists) and by a minimum absolute volume floor (so a single idle DNS
lookup doesn't get flagged just because the response happened to be a
few times bigger than the query). It never claims to have detected an
actual reflection attack, only a traffic shape consistent with one.

## rule_score vs ml_probability

Same discipline as `syn_flood.py`: no ML model is wired in here.
`rule_score` is the deterministic weighted combination below;
`confidence` currently equals `rule_score`; `ml_probability` is always
`None` (never fabricated as `0.0`) until a real model is wired in.
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

from src.flow.nfstream_wrapper import FlowRecord
from src.features.window_rates import compute_window_bounds, calculate_window_rates
from src.features.source_stats import calculate_concentration, calculate_source_stats

try:
    from src.utils.config import config_manager
except ImportError:
    from src.utils.config_simple import config_manager

logger = logging.getLogger(__name__)

# UDP protocol number (IANA). Only UDP flows are considered here.
UDP_PROTOCOL = 17

# Commonly-abused reflection/amplification service ports. This is
# WEAK, corroborating evidence only (see module docstring) -- plenty of
# legitimate traffic uses these same ports. Never used as a sole
# deciding factor.
REFLECTION_PRONE_PORTS = {
    53,     # DNS
    123,    # NTP
    1900,   # SSDP
    389,    # CLDAP / LDAP
    11211,  # memcached
    19,     # CharGEN
    17,     # QOTD
    161,    # SNMP
}


@dataclass
class UDPFloodResult:
    """Standardized result for both UDP_FLOOD and UDP_REFLECTION_LIKE
    detections. Same shape as DDoSResult/PortScanResult/SynFloodResult
    (threat_type/source_ip/destination_ip/confidence/severity/
    risk_score/detector/details/timestamp) so it flows through the
    existing generic AlertEngine._detection_to_alert path unchanged."""
    threat_type: str = "UDP_FLOOD"
    source_ip: str = ""
    destination_ip: str = ""
    confidence: float = 0.0
    severity: str = "HIGH"
    risk_score: float = 0.0
    detector: str = "rule_based_udp_flood"
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


class UDPFloodDetector:
    """Detects UDP-flood-style traffic and reflection/amplification-shaped
    traffic asymmetry. Never decides UDP_FLOOD on a single factor alone
    (same >=2-factor combination rule as SynFloodDetector); never
    asserts UDP_REFLECTION_LIKE as a certain finding (see module
    docstring)."""

    def __init__(self):
        """Initialize UDP flood detector"""
        self.thresholds = self._load_thresholds()
        logger.info(f"Initialized UDPFloodDetector with thresholds: {self.thresholds}")

    def _load_thresholds(self) -> Dict[str, Any]:
        """Load detection thresholds from config, falling back to
        documented prototype defaults if the config lookup fails."""
        defaults = {
            "min_flows": 5,
            "min_udp_pps": 500.0,
            "dest_port_concentration_threshold": 0.5,
            "destination_concentration_threshold": 0.5,
            "min_one_packet_source_ratio": 0.5,
            "reflection_min_amplification_ratio": 5.0,
            "reflection_min_flows": 5,
            "reflection_min_reply_bytes": 5000,
        }
        try:
            return {
                key: config_manager.get_threshold("udp_flood", key, default=default)
                for key, default in defaults.items()
            }
        except Exception as e:
            logger.warning(f"Failed to load thresholds from config: {e}. Using defaults.")
            return defaults

    def detect(self, flows: List[FlowRecord]) -> List[UDPFloodResult]:
        """
        Detect UDP floods and reflection-like traffic from flows.

        Args:
            flows: List of FlowRecord objects

        Returns:
            List of UDPFloodResult objects (mixing UDP_FLOOD and
            UDP_REFLECTION_LIKE threat_type entries)
        """
        udp_flows = [f for f in flows if f.protocol == UDP_PROTOCOL]
        if not udp_flows:
            return []

        detections: List[UDPFloodResult] = []

        aggregate_result = self._analyze_aggregate_traffic(udp_flows)
        if aggregate_result:
            detections.append(aggregate_result)

        flows_by_destination = self._group_flows(udp_flows, key="destination_ip")
        for dest_ip, dest_flows in flows_by_destination.items():
            result = self._analyze_destination_flows(dest_ip, dest_flows)
            if result:
                if not aggregate_result or result.destination_ip != aggregate_result.destination_ip:
                    detections.append(result)

        detections.extend(self._analyze_reflection_like(udp_flows))

        logger.info(f"UDPFloodDetector: Detected {len(detections)} potential UDP threats")
        return detections

    def _group_flows(self, flows: List[FlowRecord], key: str) -> Dict[str, List[FlowRecord]]:
        """Group flows by an arbitrary FlowRecord attribute name."""
        groups = defaultdict(list)
        for flow in flows:
            groups[getattr(flow, key)].append(flow)
        return dict(groups)

    def _compute_udp_metrics(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Compute UDP PPS/BPS, flow rate, and average packet size for a
        set of (already UDP-filtered) flows, reusing the tested
        window-rate clamping logic from window_rates.py rather than
        reimplementing it.
        """
        total_packets = sum(f.bidirectional_packets for f in flows)
        total_bytes = sum(f.bidirectional_bytes for f in flows)

        window_start_ms, window_end_ms = compute_window_bounds(flows)
        rate_result = calculate_window_rates(
            total_packets=total_packets,
            total_bytes=total_bytes,
            total_flows=len(flows),
            window_start_ms=window_start_ms,
            window_end_ms=window_end_ms,
        )

        avg_packet_size = total_bytes / total_packets if total_packets > 0 else None

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "packets_per_second": rate_result["packets_per_second"],
            "bytes_per_second": rate_result["bytes_per_second"],
            "flows_per_second": rate_result["flows_per_second"],
            "avg_packet_size": avg_packet_size,
            "window_seconds": rate_result["window_seconds"],
            "window_clamped": rate_result.get("window_clamped", False),
        }

    def _analyze_aggregate_traffic(self, udp_flows: List[FlowRecord]) -> Optional[UDPFloodResult]:
        """
        Aggregate-level UDP_FLOOD analysis: high UDP packet rate,
        corroborated by destination-port concentration (a flood aimed
        at one or few services/ports) and destination-IP concentration
        (aimed at one or few targets). Requires >=2 of these 3 factors,
        same discipline as SynFloodDetector -- a high UDP rate by
        itself can just be a busy legitimate service (e.g. a DNS
        resolver, an NTP pool member).
        """
        if len(udp_flows) < self.thresholds["min_flows"]:
            return None

        metrics = self._compute_udp_metrics(udp_flows)
        dest_port_concentration = calculate_concentration(
            [f.destination_port for f in udp_flows]
        )
        destination_concentration = calculate_concentration(
            [f.destination_ip for f in udp_flows]
        )

        confidence_factors = []
        evidence = {}

        udp_pps = metrics["packets_per_second"]
        if udp_pps is not None and udp_pps >= self.thresholds["min_udp_pps"]:
            confidence_factors.append(0.4)
            evidence["packets_per_second"] = udp_pps

        if dest_port_concentration >= self.thresholds["dest_port_concentration_threshold"]:
            confidence_factors.append(0.3)
            evidence["destination_port_concentration"] = dest_port_concentration

        if destination_concentration >= self.thresholds["destination_concentration_threshold"]:
            confidence_factors.append(0.3)
            evidence["destination_concentration"] = destination_concentration

        if len(confidence_factors) < 2:
            return None

        rule_score = min(sum(confidence_factors), 1.0)
        confidence = rule_score
        severity = self._determine_flood_severity(udp_pps or 0)

        target_ips = [f.destination_ip for f in udp_flows]
        main_target = max(set(target_ips), key=target_ips.count) if target_ips else ""
        unique_sources = len(set(f.source_ip for f in udp_flows))
        unique_dest_ports = len(set(f.destination_port for f in udp_flows))

        return UDPFloodResult(
            threat_type="UDP_FLOOD",
            source_ip="multiple_sources",
            destination_ip=main_target,
            confidence=confidence,
            severity=severity,
            risk_score=confidence * 100,
            rule_score=rule_score,
            ml_probability=None,
            details={
                "total_flows": len(udp_flows),
                "total_packets": metrics["total_packets"],
                "total_bytes": metrics["total_bytes"],
                "packets_per_second": udp_pps,
                "bytes_per_second": metrics["bytes_per_second"],
                "flows_per_second": metrics["flows_per_second"],
                "avg_packet_size": metrics["avg_packet_size"],
                "window_seconds": metrics["window_seconds"],
                "window_clamped": metrics["window_clamped"],
                "destination_port_concentration": dest_port_concentration,
                "destination_concentration": destination_concentration,
                "source_count": unique_sources,
                "unique_destination_ports": unique_dest_ports,
                "evidence": evidence,
                "thresholds": self.thresholds,
            },
        )

    def _analyze_destination_flows(
        self, dest_ip: str, flows: List[FlowRecord]
    ) -> Optional[UDPFloodResult]:
        """
        Per-destination UDP_FLOOD analysis: high UDP packet rate aimed
        at ONE destination, corroborated by source diversity (a high
        proportion of sources that only ever sent one packet). Requires
        >=2 of the possible factors.

        Uses `one_packet_source_ratio` from `source_stats.calculate_source_stats`
        directly rather than `source_entropy` -- for the exact same
        reason documented in
        `syn_flood.py::_per_destination_spoofing_evidence`: entropy
        alone is too weak/noisy a signal once flows are already
        filtered to a single destination (a handful of real clients
        evenly sharing one server also produces near-1.0 entropy). Not
        re-deriving that reasoning here; see that docstring for the
        full explanation and the false-positive it caught.
        """
        if len(flows) < self.thresholds["min_flows"]:
            return None

        metrics = self._compute_udp_metrics(flows)
        source_stats = calculate_source_stats(flows)
        one_packet_source_ratio = source_stats["one_packet_source_ratio"]
        unique_source_count = source_stats["unique_source_count"]

        confidence_factors = []
        evidence = {}

        udp_pps = metrics["packets_per_second"]
        if udp_pps is not None and udp_pps >= self.thresholds["min_udp_pps"]:
            confidence_factors.append(0.4)
            evidence["packets_per_second"] = udp_pps

        if (
            unique_source_count >= self.thresholds["min_flows"]
            and one_packet_source_ratio is not None
            and one_packet_source_ratio >= self.thresholds["min_one_packet_source_ratio"]
        ):
            confidence_factors.append(0.3)
            evidence["one_packet_source_ratio"] = one_packet_source_ratio

        dest_port_concentration = calculate_concentration([f.destination_port for f in flows])
        if dest_port_concentration >= self.thresholds["dest_port_concentration_threshold"]:
            confidence_factors.append(0.3)
            evidence["destination_port_concentration"] = dest_port_concentration

        if len(confidence_factors) < 2:
            return None

        rule_score = min(sum(confidence_factors), 1.0)
        confidence = rule_score
        severity = self._determine_flood_severity(udp_pps or 0)

        return UDPFloodResult(
            threat_type="UDP_FLOOD",
            source_ip="multiple_sources",
            destination_ip=dest_ip,
            confidence=confidence,
            severity=severity,
            risk_score=confidence * 100,
            rule_score=rule_score,
            ml_probability=None,
            details={
                "total_flows": len(flows),
                "total_packets": metrics["total_packets"],
                "total_bytes": metrics["total_bytes"],
                "packets_per_second": udp_pps,
                "bytes_per_second": metrics["bytes_per_second"],
                "avg_packet_size": metrics["avg_packet_size"],
                "window_seconds": metrics["window_seconds"],
                "window_clamped": metrics["window_clamped"],
                "one_packet_source_ratio": one_packet_source_ratio,
                "destination_port_concentration": dest_port_concentration,
                "source_count": unique_source_count,
                "evidence": evidence,
                "thresholds": self.thresholds,
            },
        )

    def _analyze_reflection_like(self, udp_flows: List[FlowRecord]) -> List[UDPFloodResult]:
        """
        Per-flow-group UDP_REFLECTION_LIKE analysis. Groups already-UDP
        flows by (destination_ip, source_port) -- i.e. by "the service
        being queried" -- and looks for a strong reply-heavier-than-request
        byte asymmetry across that group, above a minimum absolute
        volume floor (so a single small legitimate exchange never
        qualifies just because a percentage ratio happened to be high).

        Grouping by (destination_ip, source_port) rather than just
        destination_ip: `destination_ip` is who was queried, and
        `source_port` on a UDP flow is normally the SERVICE port on the
        querying side's request... actually for a request FROM a client
        TO a service, `destination_port` is the service port (e.g. 53
        for DNS) and `source_port` is the client's ephemeral port. So
        the service port to check against REFLECTION_PRONE_PORTS is
        `destination_port` (what's being asked), not `source_port`.
        Grouping is therefore by (destination_ip, destination_port).
        """
        groups = defaultdict(list)
        for flow in udp_flows:
            groups[(flow.destination_ip, flow.destination_port)].append(flow)

        results = []
        for (dest_ip, dest_port), flows in groups.items():
            if len(flows) < self.thresholds["reflection_min_flows"]:
                continue

            # "Request" direction = src2dst (from whoever sent the first
            # packet, toward the queried destination); "reply" direction
            # = dst2src. See module docstring: we cannot verify the
            # request side wasn't spoofed, only observe the shape.
            request_bytes = sum(f.src2dst_bytes for f in flows)
            reply_bytes = sum(f.dst2src_bytes for f in flows)
            request_packets = sum(f.src2dst_packets for f in flows)
            reply_packets = sum(f.dst2src_packets for f in flows)

            if reply_bytes < self.thresholds["reflection_min_reply_bytes"]:
                # Missing vs. zero: this is a real, small volume, not an
                # unknown one -- correctly excluded, not "no evidence".
                continue

            if request_bytes <= 0:
                # No request bytes observed at all in this group -- can't
                # compute a meaningful amplification RATIO (would be a
                # division by zero, not "infinite amplification"; treat
                # as insufficient data for this specific factor rather
                # than fabricating an extreme ratio).
                amplification_ratio = None
            else:
                amplification_ratio = reply_bytes / request_bytes

            confidence_factors = []
            evidence = {}

            if (
                amplification_ratio is not None
                and amplification_ratio >= self.thresholds["reflection_min_amplification_ratio"]
            ):
                confidence_factors.append(0.5)
                evidence["amplification_ratio"] = amplification_ratio

            if dest_port in REFLECTION_PRONE_PORTS:
                confidence_factors.append(0.2)
                evidence["reflection_prone_port"] = dest_port

            unique_query_sources = len(set(f.source_ip for f in flows))
            if unique_query_sources >= self.thresholds["min_flows"]:
                confidence_factors.append(0.3)
                evidence["unique_query_sources"] = unique_query_sources

            # Same >=2-factor discipline as UDP_FLOOD/SYN_FLOOD above --
            # a big reply-to-request ratio alone (e.g. one legitimate
            # large DNS response to a small query) is completely
            # ordinary and must not be sufficient by itself.
            if len(confidence_factors) < 2:
                continue

            rule_score = min(sum(confidence_factors), 1.0)
            confidence = rule_score

            results.append(UDPFloodResult(
                threat_type="UDP_REFLECTION_LIKE",
                source_ip="multiple_sources",
                destination_ip=dest_ip,
                confidence=confidence,
                severity=self._determine_reflection_severity(amplification_ratio),
                risk_score=confidence * 100,
                rule_score=rule_score,
                ml_probability=None,
                details={
                    "total_flows": len(flows),
                    "queried_port": dest_port,
                    "request_bytes": request_bytes,
                    "reply_bytes": reply_bytes,
                    "request_packets": request_packets,
                    "reply_packets": reply_packets,
                    "amplification_ratio": amplification_ratio,
                    "unique_query_sources": unique_query_sources,
                    "evidence": evidence,
                    "thresholds": self.thresholds,
                    "caveat": (
                        "UDP_REFLECTION_LIKE describes a traffic SHAPE "
                        "consistent with reflection/amplification abuse, "
                        "observed from one passive vantage point. It does "
                        "NOT confirm request spoofing or that this "
                        "specific volume is anomalous for the service in "
                        "question -- see module docstring."
                    ),
                },
            ))

        return results

    def _determine_flood_severity(self, udp_pps: float) -> str:
        """Determine UDP_FLOOD severity from packet rate. Same banding
        style as syn_flood.py/ddos.py."""
        if udp_pps >= 10000:
            return "CRITICAL"
        elif udp_pps >= 3000:
            return "HIGH"
        elif udp_pps >= 800:
            return "MEDIUM"
        return "LOW"

    def _determine_reflection_severity(self, amplification_ratio: Optional[float]) -> str:
        """Determine UDP_REFLECTION_LIKE severity from amplification
        ratio. `None` (no request bytes observed) maps to the most
        conservative (LOW) banding rather than being treated as
        unknown-therefore-severe."""
        if amplification_ratio is None:
            return "LOW"
        if amplification_ratio >= 50:
            return "CRITICAL"
        elif amplification_ratio >= 20:
            return "HIGH"
        elif amplification_ratio >= 10:
            return "MEDIUM"
        return "LOW"

    def get_udp_statistics(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Get UDP-related statistics from flows, independent of whether
        any threshold was crossed (mirrors
        SynFloodDetector.get_syn_flood_statistics).
        """
        udp_flows = [f for f in flows if f.protocol == UDP_PROTOCOL]
        if not udp_flows:
            return {
                "total_flows": 0,
                "total_udp_flows": 0,
                "packets_per_second": None,
                "bytes_per_second": None,
                "avg_packet_size": None,
                "destination_port_concentration": 0.0,
                "destination_concentration": 0.0,
            }

        metrics = self._compute_udp_metrics(udp_flows)
        dest_port_concentration = calculate_concentration(
            [f.destination_port for f in udp_flows]
        )
        destination_concentration = calculate_concentration(
            [f.destination_ip for f in udp_flows]
        )

        return {
            "total_flows": len(flows),
            "total_udp_flows": len(udp_flows),
            "total_packets": metrics["total_packets"],
            "total_bytes": metrics["total_bytes"],
            "packets_per_second": metrics["packets_per_second"],
            "bytes_per_second": metrics["bytes_per_second"],
            "flows_per_second": metrics["flows_per_second"],
            "avg_packet_size": metrics["avg_packet_size"],
            "window_seconds": metrics["window_seconds"],
            "window_clamped": metrics["window_clamped"],
            "destination_port_concentration": dest_port_concentration,
            "destination_concentration": destination_concentration,
        }
