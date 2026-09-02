"""
Detector Factory Module
Provides unified interface for all detectors.
"""

import logging
from typing import Dict, Any, List, Optional
from enum import Enum

from src.flow.nfstream_wrapper import FlowRecord
from src.detectors.scan import PortScanDetector, PortScanResult
from src.detectors.ddos import DDoSDetector, DDoSResult
from src.detectors.dga import DGADetector, DGAResult
from src.detectors.syn_flood import SynFloodDetector, SynFloodResult
from src.detectors.udp_flood import UDPFloodDetector, UDPFloodResult
from src.detectors.c2_beacon import C2BeaconDetector
from src.detectors.dns_threat import DNSThreatDetector
from src.detectors.encrypted_session import EncryptedSessionDetector
from src.detectors.exfiltration import ExfiltrationDetector
from src.detectors.contracts import DetectionResult

logger = logging.getLogger(__name__)


class DetectorType(Enum):
    """Enumeration of detector types"""
    PORT_SCAN = "port_scan"
    DDOS = "ddos"
    DGA = "dga"
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    C2_BEACON = "c2"
    DNS_THREAT = "dns_threat"
    ENCRYPTED_SESSION = "encrypted_session"
    EXFILTRATION = "exfiltration"


class DetectorFactory:
    """Factory for creating and managing detectors"""
    
    def __init__(self, enabled_detectors=None):
        """Initialize only the detectors explicitly enabled by configuration."""
        all_detectors = {
            DetectorType.PORT_SCAN: PortScanDetector,
            DetectorType.DDOS: DDoSDetector,
            DetectorType.DGA: DNSThreatDetector,
            DetectorType.SYN_FLOOD: SynFloodDetector,
            DetectorType.UDP_FLOOD: UDPFloodDetector,
            DetectorType.C2_BEACON: C2BeaconDetector,
            DetectorType.DNS_THREAT: DNSThreatDetector,
            DetectorType.ENCRYPTED_SESSION: EncryptedSessionDetector,
            DetectorType.EXFILTRATION: ExfiltrationDetector,
        }
        if enabled_detectors is None:
            enabled = list(all_detectors)
        else:
            normalized = {str(x).lower() for x in enabled_detectors}
            aliases = {"c2_beaconing":"c2","c2_beacon":"c2",
                       "dns_tunnelling":"dns_threat","dns_tunnel":"dns_threat",
                       "tls_quic":"encrypted_session","encrypted":"encrypted_session",
                       "data_exfiltration":"exfiltration","recon":"port_scan"}
            normalized = {aliases.get(x, x) for x in normalized}
            enabled = [dtype for dtype in all_detectors if dtype.value in normalized]

        self.detectors = {}
        self.initialization_errors = {}
        for detector_type in enabled:
            try:
                self.detectors[detector_type] = all_detectors[detector_type]()
            except Exception as exc:
                self.initialization_errors[detector_type.value] = str(exc)
                logger.error("Failed to initialize detector %s: %s", detector_type.value, exc)

        if self.initialization_errors:
            logger.warning("Detector factory is DEGRADED: %s", self.initialization_errors)
    
    def get_detector(self, detector_type: DetectorType):
        """Get a specific detector"""
        return self.detectors.get(detector_type)
    
    def run_detector(self, detector_type: DetectorType, flows: List[FlowRecord]) -> List[Any]:
        """
        Run a specific detector on flows
        
        Args:
            detector_type: Type of detector to run
            flows: List of FlowRecord objects
            
        Returns:
            List of detection results
        """
        detector = self.get_detector(detector_type)
        if detector is None:
            raise RuntimeError(f"Detector unavailable: {detector_type.value}")
        
        try:
            raw_results=detector.detect(flows)
            return [self._to_contract(item, flows, detector_type.value) for item in raw_results]
        except Exception as e:
            logger.error(f"Detector {detector_type} failed: {e}")
            raise RuntimeError(f"Detector {detector_type.value} failed") from e
    
    @staticmethod
    def _to_contract(item: Any, flows: List[FlowRecord], detector_name: str) -> DetectionResult:
        """Adapt legacy result objects to the single canonical DetectionResult contract."""
        if isinstance(item, DetectionResult):
            return item
        data=item.to_dict() if hasattr(item,"to_dict") else dict(item)
        details=dict(data.get("details") or {})
        evidence=dict(details.get("evidence") or {})
        source=data.get("source_ip",""); destination=data.get("destination_ip","")
        candidates=[f for f in flows if (not source or source in {"multiple_sources",getattr(f,"source_ip","")})
                    and (not destination or not destination or destination==getattr(f,"destination_ip",""))]
        if not candidates: candidates=flows
        ids=tuple(str(getattr(f,"flow_id")) for f in candidates if getattr(f,"flow_id",None) is not None)
        times=[getattr(f,"timestamp",None) for f in candidates if getattr(f,"timestamp",None) is not None]
        attack_type=data.get("attack_type") or data.get("threat_type") or "UNKNOWN"
        subtype=details.get("attack_subtype")
        if detector_name=="udp_flood" and evidence.get("reflection_likely"):
            subtype="udp_reflection"
        if detector_name=="ddos" and evidence.get("icmp_packets"):
            subtype="icmp_flood"
        return DetectionResult(detector=detector_name,detected=True,attack_type=attack_type,
            attack_subtype=subtype,flow_ids=ids,source_ip=source,destination_ip=destination,
            source_port=data.get("source_port"),destination_port=data.get("destination_port"),
            protocol=data.get("protocol"),event_start_time=min(times) if times else data.get("timestamp"),
            event_end_time=max(times) if times else data.get("timestamp"),
            rule_score=float(data.get("rule_score",float(data.get("risk_score",0))/100.0) or 0.0),
            rule_confidence=float(data.get("rule_confidence",data.get("confidence",0.0)) or 0.0),
            evidence=evidence,details=details)

    def run_all_detectors(self, flows: List[FlowRecord]) -> Dict[str, List[Any]]:
        """
        Run all detectors on flows
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Dictionary with results from each detector
        """
        results = {}
        
        for detector_type in DetectorType:
            if detector_type in self.detectors:
                detector_results = self.run_detector(detector_type, flows)
                results[detector_type.value] = detector_results
            else:
                results[detector_type.value] = []
        
        return results
    
    def run_all_detectors_flat(self, flows: List[FlowRecord]) -> List[Any]:
        """
        Run all detectors and return flat list of results
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Flat list of all detection results
        """
        all_results = []
        
        for detector_type in self.detectors:
            detector_results = self.run_detector(detector_type, flows)
            all_results.extend(detector_results)
        
        return all_results
    
    def get_detector_statistics(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """
        Get statistics from all detectors
        
        Args:
            flows: List of FlowRecord objects
            
        Returns:
            Dictionary with detector statistics
        """
        stats = {}
        
        if DetectorType.PORT_SCAN in self.detectors:
            stats["port_scan"] = self.detectors[DetectorType.PORT_SCAN].get_scan_statistics(flows)
        
        if DetectorType.DDOS in self.detectors:
            stats["ddos"] = self.detectors[DetectorType.DDOS].get_flood_statistics(flows)

        if DetectorType.SYN_FLOOD in self.detectors:
            stats["syn_flood"] = self.detectors[DetectorType.SYN_FLOOD].get_syn_flood_statistics(flows)

        if DetectorType.UDP_FLOOD in self.detectors:
            stats["udp_flood"] = self.detectors[DetectorType.UDP_FLOOD].get_udp_statistics(flows)

        return stats