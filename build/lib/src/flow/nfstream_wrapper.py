from src.flow_normalization import normalize_flow
from src.flow.ingestion_status import IngestionCode, IngestionError
"""
NFStream Flow Extraction Module
Converts raw packets into network flows using NFStream.
Provides flow statistics and feature extraction for detection.
"""

import logging
from typing import Dict, Any, Optional, List, Iterator
from dataclasses import dataclass, asdict
from pathlib import Path
import time
from datetime import datetime
from collections import defaultdict

import pandas as pd

# NFStream is an optional dependency: this module also provides a Scapy-based
# fallback path (see FlowExtractor._extract_with_scapy) specifically so flow
# extraction still works when NFStream isn't installed (e.g. on Windows,
# where NFStream's underlying libraries are harder to install). Importing it
# unconditionally at module load time defeated that fallback's purpose, since
# it made this whole module - including the plain FlowRecord dataclass -
# unimportable without NFStream. Import lazily instead.
try:
    from nfstream import NFStreamer, NFPlugin
    NFSTREAM_AVAILABLE = True
except ImportError:
    NFStreamer = None
    NFPlugin = object  # harmless base class so CustomFlowPlugin below can still be defined
    NFSTREAM_AVAILABLE = False

logger = logging.getLogger(__name__)

def stable_flow_id(source_ip: str, destination_ip: str, source_port: int,
                   destination_port: int, protocol: int, start_time: Optional[float] = None) -> int:
    """Deterministic flow identity stable across observation windows."""
    import hashlib
    start_token="" if start_time is None else f"{float(start_time):.6f}"
    canonical=f"{source_ip}|{destination_ip}|{int(source_port)}|{int(destination_port)}|{int(protocol)}|{start_token}"
    return int.from_bytes(hashlib.sha256(canonical.encode("utf-8")).digest()[:8],"big",signed=False)

if not NFSTREAM_AVAILABLE:
    logger.warning(
        "nfstream is not installed; FlowExtractor will use the Scapy-based "
        "fallback for PCAP extraction. Live capture via NFStream is unavailable."
    )


@dataclass
class FlowRecord:
    """Standardized flow record structure."""
    # 5-tuple
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: int
    
    # Flow statistics
    bidirectional_packets: int
    bidirectional_bytes: int
    bidirectional_duration_ms: int
    
    # Direction-specific stats
    src2dst_packets: int
    src2dst_bytes: int
    dst2src_packets: int
    dst2src_bytes: int
    
    # Timing information
    bidirectional_first_seen_ms: int
    bidirectional_last_seen_ms: int
    
    # Additional features
    bidirectional_min_ps: float
    bidirectional_mean_ps: float
    bidirectional_stddev_ps: float
    bidirectional_max_ps: float
    
    bidirectional_min_piat_ms: float
    bidirectional_mean_piat_ms: float
    bidirectional_stddev_piat_ms: float
    bidirectional_max_piat_ms: float
    
    # TCP-specific features
    # NOTE on semantics: syn_packets follows NFStream convention — ANY packet
    # with the SYN flag set, including SYN-ACK. It is intentionally NOT
    # "SYN-only". Use syn_only_packets / syn_ack_packets below when a detector
    # needs to distinguish a client-initiated SYN from a server's SYN-ACK
    # reply (see Rule 7 in the DDoS audit: conflating the two produces false
    # positives on ordinary handshake-heavy legitimate traffic).
    syn_packets: int = 0
    ack_packets: int = 0
    fin_packets: int = 0
    rst_packets: int = 0
    syn_only_packets: int = 0   # SYN set, ACK not set (client-initiated)
    syn_ack_packets: int = 0    # SYN set AND ACK set (server reply)

    # ICMP-specific features (protocol 1). Populated only for ICMP flows;
    # zero for TCP/UDP flows.
    icmp_packets: int = 0
    icmp_bytes: int = 0
    icmp_type_counts: Optional[Dict[int, int]] = None

    # Application info
    application_name: str = "unknown"
    application_category: str = "unknown"
    
    # Metadata
    flow_id: Optional[int] = None
    # Traffic-time timestamp: when this flow's traffic was actually observed
    # on the wire (derived from packet capture times), NOT when the software
    # processed it. See Rule 4 — never substitute time.time() for this.
    timestamp: Optional[float] = None

    dns_query: Optional[str] = None
    dns_response_code: Optional[int] = None
    dns_nxdomain: Optional[bool] = None
    tls_metadata: Optional[Dict[str, Any]] = None
    quic_metadata: Optional[Dict[str, Any]] = None
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    ja4: Optional[str] = None

    def normalized(self):
        """Return the authoritative canonical JSON-friendly representation."""
        return normalize_flow(self)

    def canonical_dict(self) -> Dict[str, Any]:
        """Return only the canonical Phase-A fields used for audit/serialization."""
        normalized = normalize_flow(self)
        fields = (
            "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "start_time", "end_time", "duration", "fwd_packets", "bwd_packets",
            "total_packets", "fwd_bytes", "bwd_bytes", "total_bytes",
            "syn_packets", "syn_only_packets", "syn_ack_packets", "ack_packets",
            "rst_packets", "icmp_packets", "icmp_bytes", "icmp_types",
            "dns_query", "dns_response_code", "dns_nxdomain",
            "tls_metadata", "quic_metadata", "ja3", "ja3s", "ja4",
        )
        return {name: normalized.get(name) for name in fields}

    @property
    def event_start_time(self) -> Optional[float]:
        return (
            self.bidirectional_first_seen_ms / 1000.0
            if self.bidirectional_first_seen_ms is not None else None
        )

    @property
    def event_end_time(self) -> Optional[float]:
        return (
            self.bidirectional_last_seen_ms / 1000.0
            if self.bidirectional_last_seen_ms is not None else None
        )

    @property
    def total_packets(self) -> int:
        return self.bidirectional_packets

    @property
    def total_bytes(self) -> int:
        return self.bidirectional_bytes

    @property
    def duration(self) -> float:
        return self.bidirectional_duration_ms / 1000.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def get_5tuple(self) -> tuple:
        """Get the 5-tuple representation"""
        return (
            self.source_ip,
            self.destination_ip,
            self.source_port,
            self.destination_port,
            self.protocol
        )
    
    def get_packets_per_second(self) -> float:
        """Calculate packets per second"""
        if self.bidirectional_duration_ms > 0:
            return self.bidirectional_packets / (self.bidirectional_duration_ms / 1000)
        return 0.0
    
    def get_bytes_per_second(self) -> float:
        """Calculate bytes per second"""
        if self.bidirectional_duration_ms > 0:
            return self.bidirectional_bytes / (self.bidirectional_duration_ms / 1000)
        return 0.0
    
    def get_syn_ratio(self) -> float:
        """Calculate SYN packet ratio"""
        if self.bidirectional_packets > 0:
            return self.syn_packets / self.bidirectional_packets
        return 0.0



class IncrementalScapyFlowAggregator:
    """Bounded event-time flow builder for true live processing.

    This is intentionally small and deterministic: it tracks the same
    canonical counters as the Scapy PCAP fallback, but consumes packets as
    they arrive instead of waiting for a PCAP to finish.
    """

    def __init__(self, max_flows: int = 100000):
        from collections import OrderedDict
        if max_flows <= 0:
            raise ValueError("max_flows must be positive")
        self.max_flows = max_flows
        self._flows = OrderedDict()
        self._flow_identity = OrderedDict()
        self.evicted_flows = 0

    @staticmethod
    def _packet_key(packet):
        from scapy.all import IP, TCP, UDP, ICMP
        if IP not in packet:
            return None
        src, dst = packet[IP].src, packet[IP].dst
        if TCP in packet:
            proto, sport, dport = 6, int(packet[TCP].sport), int(packet[TCP].dport)
        elif UDP in packet:
            proto, sport, dport = 17, int(packet[UDP].sport), int(packet[UDP].dport)
        elif ICMP in packet:
            proto, sport, dport = 1, 0, 0
        else:
            return None
        a=(src,sport); b=(dst,dport)
        return (a,b,proto) if a <= b else (b,a,proto)

    def add_packet(self, packet):
        from collections import defaultdict
        from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR
        key=self._packet_key(packet)
        if key is None:
            return []
        now=float(packet.time)
        (a,b,proto)=key
        src,dst=packet[IP].src,packet[IP].dst
        if TCP in packet: sport,dport=int(packet[TCP].sport),int(packet[TCP].dport)
        elif UDP in packet: sport,dport=int(packet[UDP].sport),int(packet[UDP].dport)
        else: sport,dport=0,0
        state=self._flows.get(key)
        if state is None:
            state={
                "source_ip":src,"destination_ip":dst,"source_port":sport,"destination_port":dport,
                "protocol":proto,"packets":0,"bytes":0,"start":now,"end":now,
                "src_packets":0,"src_bytes":0,"dst_packets":0,"dst_bytes":0,
                "syn":0,"syn_only":0,"syn_ack":0,"ack":0,"fin":0,"rst":0,
                "icmp_packets":0,"icmp_bytes":0,"icmp_types":defaultdict(int),
                "dns_query":None,"dns_response_code":None,"dns_nxdomain":None,
                "tls_metadata":None,"quic_metadata":None,"ja3":None,"ja3s":None,"ja4":None,
            }
            self._flows[key]=state
            if key not in self._flow_identity:
                self._flow_identity[key]=stable_flow_id(src,dst,sport,dport,proto,now)
        state["end"]=now
        plen=len(packet); state["packets"]+=1; state["bytes"]+=plen
        if src==state["source_ip"] and sport==state["source_port"]:
            state["src_packets"]+=1; state["src_bytes"]+=plen
        else:
            state["dst_packets"]+=1; state["dst_bytes"]+=plen

        if TCP in packet:
            flags=str(packet[TCP].flags)
            has_syn="S" in flags; has_ack="A" in flags
            if has_syn:
                state["syn"]+=1
                state["syn_ack"] += int(has_ack)
                state["syn_only"] += int(not has_ack)
            state["ack"] += int(has_ack); state["fin"] += int("F" in flags); state["rst"] += int("R" in flags)
        elif ICMP in packet:
            state["icmp_packets"]+=1; state["icmp_bytes"]+=plen
            state["icmp_types"][int(packet[ICMP].type)]+=1

        # Passive TLS/QUIC metadata only; payloads are never decrypted.
        try:
            raw_layer = packet.payload.payload.payload if hasattr(packet.payload, "payload") else None
            raw_bytes = bytes(raw_layer) if raw_layer is not None else b""
            if TCP in packet and dport == 443 and raw_bytes[:1] == b"\\x16":
                state["tls_metadata"] = {
                    "record_type": int(raw_bytes[0]),
                    "version_bytes": raw_bytes[1:3].hex() if len(raw_bytes) >= 3 else None,
                    "client_hello_sha256": __import__("hashlib").sha256(raw_bytes[:4096]).hexdigest(),
                }
                state["ja4"] = state["tls_metadata"]["client_hello_sha256"][:32]
            elif UDP in packet and dport == 443 and len(raw_bytes) >= 5:
                version = int.from_bytes(raw_bytes[1:5], "big")
                if raw_bytes[0] & 0x80:
                    state["quic_metadata"] = {"version": version, "long_header": True}
                else:
                    state["quic_metadata"] = {"version": None, "long_header": False}
        except Exception:
            # Metadata unavailable is explicit; packet processing continues.
            pass

        if DNS in packet:
            try:
                dns=packet[DNS]
                if dns.qd is not None and DNSQR in dns.qd:
                    state["dns_query"]=dns.qd.qname.decode(errors="replace").rstrip(".")
                state["dns_response_code"]=int(dns.rcode)
                state["dns_nxdomain"]=int(dns.rcode)==3
            except Exception:
                # Malformed DNS is evidence of an ingestion problem; the
                # packet remains in the flow with DNS fields unavailable.
                state["dns_query"]=None

        while len(self._flows) > self.max_flows:
            evicted_key,_ = self._flows.popitem(last=False)
            self._flow_identity.pop(evicted_key, None)
            self.evicted_flows += 1
        return []

    def snapshot(self):
        """Materialize current flows and clear state for the next live window."""
        records=[]
        for idx,state in enumerate(self._flows.values()):
            duration_ms=max(0,int((state["end"]-state["start"])*1000))
            packets = state["packets"]
            bytes_total = state["bytes"]
            pps=packets/(duration_ms/1000) if duration_ms else 0.0
            mean_ps=bytes_total/packets if packets else 0.0
            # N packets produce N-1 inter-arrival intervals.
            mean_piat=(duration_ms/(packets-1)) if packets > 1 else 0.0
            records.append(FlowRecord(
                source_ip=state["source_ip"], destination_ip=state["destination_ip"],
                source_port=state["source_port"], destination_port=state["destination_port"],
                protocol=state["protocol"], bidirectional_packets=state["packets"],
                bidirectional_bytes=state["bytes"], bidirectional_duration_ms=duration_ms,
                src2dst_packets=state["src_packets"], src2dst_bytes=state["src_bytes"],
                dst2src_packets=state["dst_packets"], dst2src_bytes=state["dst_bytes"],
                bidirectional_first_seen_ms=int(state["start"]*1000),
                bidirectional_last_seen_ms=int(state["end"]*1000),
                bidirectional_min_ps=0.0,bidirectional_mean_ps=pps,
                bidirectional_stddev_ps=0.0,bidirectional_max_ps=pps,
                bidirectional_min_piat_ms=0.0,
                bidirectional_mean_piat_ms=(duration_ms/state["packets"] if state["packets"] else 0.0),
                bidirectional_stddev_piat_ms=0.0,bidirectional_max_piat_ms=0.0,
                syn_packets=state["syn"],ack_packets=state["ack"],
                fin_packets=state["fin"],rst_packets=state["rst"],
                syn_only_packets=state["syn_only"],syn_ack_packets=state["syn_ack"],
                icmp_packets=state["icmp_packets"],icmp_bytes=state["icmp_bytes"],
                icmp_type_counts=dict(state["icmp_types"]) or None,
                application_name="unknown",application_category="unknown",
                flow_id=idx,timestamp=state["end"],
                dns_query=state["dns_query"],
                dns_response_code=state["dns_response_code"],
                dns_nxdomain=state["dns_nxdomain"],
            ))
        self._flows.clear()
        return records

    def size(self):
        return len(self._flows)


class FlowExtractor:
    """NFStream-based flow extraction with Scapy fallback"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize flow extractor
        
        Args:
            config: Configuration dictionary for NFStream
        """
        self.config = config or {}
        self.flows: List[FlowRecord] = []
        self.nfstreamer = None
        
        logger.info("Initialized FlowExtractor")
    
    def extract_from_pcap(
        self,
        pcap_file: str,
        statistical_analysis: bool = True,
        splt_analysis: int = 0,
        n_meters: int = 0
    ) -> List[FlowRecord]:
        """
        Extract flows from a PCAP file
        
        Args:
            pcap_file: Path to PCAP file
            statistical_analysis: Enable statistical analysis
            splt_analysis: Sequence of Packet Length and Time analysis
            n_meters: Number of parallel meters (0 = auto)
            
        Returns:
            List of FlowRecord objects
        """
        logger.info(f"Extracting flows from {pcap_file}")

        if not NFSTREAM_AVAILABLE:
            logger.info("nfstream not installed; using dependency-free PCAP parser")
            return self._extract_with_stdlib(pcap_file)

        # Try NFStream first
        try:
            # Configure NFStreamer
            self.nfstreamer = NFStreamer(
                source=pcap_file,
                statistical_analysis=statistical_analysis,
                splt_analysis=splt_analysis,
                n_meters=n_meters,
                **self.config
            )
            
            # Convert to pandas DataFrame
            flows_df = self.nfstreamer.to_pandas()
            
            # Check if DataFrame is valid
            if flows_df is not None and not flows_df.empty:
                # Convert DataFrame to FlowRecord list
                self.flows = self._dataframe_to_flow_records(flows_df)
                
                logger.info(f"Extracted {len(self.flows)} flows using NFStream")
                return self.flows
            else:
                logger.warning("NFStream returned no flows, trying Scapy fallback")
                return self._extract_with_scapy(pcap_file)
                
        except Exception as e:
            logger.warning(f"NFStream extraction failed: {e}")
            logger.info("Attempting fallback extraction with Scapy...")
            return self._extract_with_scapy(pcap_file)
    
    def _extract_with_stdlib(self, pcap_file: str) -> List[FlowRecord]:
        """Dependency-free Ethernet/IPv4 PCAP extraction for portable replay."""
        from collections import defaultdict
        from src.flow.pcap_stdlib import iter_packets, PcapFormatError
        flows={}
        def state_for(key, pkt):
            return {
                "source_ip":pkt["src"],"destination_ip":pkt["dst"],"source_port":pkt["sport"],"destination_port":pkt["dport"],
                "protocol":pkt["protocol"],"packets":0,"bytes":0,"start":pkt["timestamp"],"end":pkt["timestamp"],
                "src_packets":0,"src_bytes":0,"dst_packets":0,"dst_bytes":0,"syn":0,"syn_only":0,"syn_ack":0,
                "ack":0,"fin":0,"rst":0,"icmp_packets":0,"icmp_bytes":0,"icmp_types":defaultdict(int),
                "dns_query":None,"dns_response_code":None,"dns_nxdomain":None,
                "tls_metadata":None,"quic_metadata":None,"ja3":None,"ja3s":None,"ja4":None,
                "initiator":(pkt["src"],pkt["sport"])
            }
        for pkt in iter_packets(pcap_file):
            key=((pkt["src"],pkt["sport"]),(pkt["dst"],pkt["dport"]),pkt["protocol"])
            reverse=((pkt["dst"],pkt["dport"]),(pkt["src"],pkt["sport"]),pkt["protocol"])
            key=min(key,reverse)
            st=flows.setdefault(key,state_for(key,pkt))
            st["end"]=pkt["timestamp"]; st["packets"]+=1; st["bytes"]+=pkt["length"]
            if (pkt["src"],pkt["sport"])==st["initiator"]:
                st["src_packets"]+=1; st["src_bytes"]+=pkt["length"]
            else:
                st["dst_packets"]+=1; st["dst_bytes"]+=pkt["length"]
            if pkt["protocol"]==6:
                flags=pkt["flags"]; st["syn"]+=int(bool(flags&0x02)); st["syn_ack"]+=int(bool(flags&0x12)==0x12)
                st["syn_only"]+=int(bool(flags&0x02) and not bool(flags&0x10)); st["ack"]+=int(bool(flags&0x10))
                st["fin"]+=int(bool(flags&0x01)); st["rst"]+=int(bool(flags&0x04))
                if pkt["dport"]==443 and pkt["payload"][:1]==b"\x16":
                    st["tls_metadata"]={"record_type":22,"version_bytes":pkt["payload"][1:3].hex() if len(pkt["payload"])>=3 else None,
                                       "client_hello_sha256":__import__("hashlib").sha256(pkt["payload"][:4096]).hexdigest()}
                    st["ja4"]=st["tls_metadata"]["client_hello_sha256"][:32]
            elif pkt["protocol"]==1:
                st["icmp_packets"]+=1; st["icmp_bytes"]+=pkt["length"]
            elif pkt["protocol"]==17:
                if pkt["dport"]==443 and len(pkt["payload"])>=5 and pkt["payload"][0]&0x80:
                    st["quic_metadata"]={"version":int.from_bytes(pkt["payload"][1:5],"big"),"long_header":True}
                if pkt["dns"]:
                    st["dns_query"]=pkt["dns"]["query"]; st["dns_response_code"]=pkt["dns"]["response_code"]; st["dns_nxdomain"]=pkt["dns"]["nxdomain"]
        records=[]
        for key,st in flows.items():
            duration_ms=max(0,int((st["end"]-st["start"])*1000)); n=st["packets"]
            mean_ps=st["bytes"]/n if n else 0.0; mean_piat=duration_ms/(n-1) if n>1 else 0.0
            rec=FlowRecord(source_ip=st["source_ip"],destination_ip=st["destination_ip"],
                source_port=st["source_port"],destination_port=st["destination_port"],protocol=st["protocol"],
                bidirectional_packets=n,bidirectional_bytes=st["bytes"],bidirectional_duration_ms=duration_ms,
                src2dst_packets=st["src_packets"],src2dst_bytes=st["src_bytes"],dst2src_packets=st["dst_packets"],dst2src_bytes=st["dst_bytes"],
                bidirectional_first_seen_ms=int(st["start"]*1000),bidirectional_last_seen_ms=int(st["end"]*1000),
                bidirectional_min_ps=mean_ps,bidirectional_mean_ps=mean_ps,bidirectional_stddev_ps=0,bidirectional_max_ps=mean_ps,
                bidirectional_min_piat_ms=mean_piat,bidirectional_mean_piat_ms=mean_piat,bidirectional_stddev_piat_ms=0,bidirectional_max_piat_ms=mean_piat,
                syn_packets=st["syn"],ack_packets=st["ack"],fin_packets=st["fin"],rst_packets=st["rst"],
                syn_only_packets=st["syn_only"],syn_ack_packets=st["syn_ack"],icmp_packets=st["icmp_packets"],icmp_bytes=st["icmp_bytes"],
                icmp_type_counts=dict(st["icmp_types"]) or None,application_name="unknown",application_category="unknown",
                flow_id=stable_flow_id(st["source_ip"],st["destination_ip"],st["source_port"],st["destination_port"],st["protocol"],st["start"]),
                timestamp=st["end"],dns_query=st["dns_query"],dns_response_code=st["dns_response_code"],dns_nxdomain=st["dns_nxdomain"],
                tls_metadata=st["tls_metadata"],quic_metadata=st["quic_metadata"],ja3=st["ja3"],ja3s=st["ja3s"],ja4=st["ja4"])
            records.append(rec)
        self.flows=records
        return records

    def _extract_with_scapy(self, pcap_file: str) -> List[FlowRecord]:
        """
        Fallback flow extraction using Scapy
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            List of FlowRecord objects
        """
        from scapy.all import PcapReader, IP, TCP, UDP, ICMP, DNS, DNSQR

        logger.info(f"Using Scapy fallback extraction for {pcap_file}")

        try:
            packets = PcapReader(pcap_file)

            def new_flow_data():
                return {
                    "packets": 0,
                    "bytes": 0,
                    "start_time": None,
                    "end_time": None,
                    "syn_packets": 0,
                    "syn_only_packets": 0,
                    "syn_ack_packets": 0,
                    "ack_packets": 0,
                    "fin_packets": 0,
                    "rst_packets": 0,
                    "icmp_packets": 0,
                    "icmp_bytes": 0,
                    "icmp_type_counts": defaultdict(int),
                    # Direction is tracked relative to whichever endpoint was
                    # observed as the source of the FIRST packet in this flow
                    # (the "initiator" for this canonical key). This lets A->B
                    # and B->A packets accumulate into a single true
                    # bidirectional flow instead of two separate ones.
                    "initiator_ip": None,
                    "initiator_port": None,
                    "init_to_resp_packets": 0,
                    "init_to_resp_bytes": 0,
                    "resp_to_init_packets": 0,
                    "resp_to_init_bytes": 0,
                    "dns_query": None,
                    "dns_response_code": None,
                    "dns_nxdomain": None,
                    "tls_metadata": None,
                    "quic_metadata": None,
                    "ja3": None,
                    "ja3s": None,
                    "ja4": None,
                }

            flows_dict = defaultdict(new_flow_data)

            for packet in packets:
                if IP not in packet:
                    continue

                pkt_src = packet[IP].src
                pkt_dst = packet[IP].dst
                pkt_len = len(packet)
                pkt_time = float(packet.time)

                if TCP in packet:
                    proto = 6
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = str(packet[TCP].flags)
                elif UDP in packet:
                    proto = 17
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    flags = ""
                elif ICMP in packet:
                    proto = 1
                    src_port = 0
                    dst_port = 0
                    flags = ""
                else:
                    continue

                # Metadata-only TLS/QUIC fingerprints. No payload decryption.
                try:
                    raw_bytes = bytes(packet.payload.payload.payload) if hasattr(packet.payload, "payload") else b""
                    if TCP in packet and int(dst_port) == 443 and raw_bytes[:1] == b"\\x16":
                        flow_tls = {
                            "record_type": int(raw_bytes[0]),
                            "version_bytes": raw_bytes[1:3].hex() if len(raw_bytes) >= 3 else None,
                            "client_hello_sha256": __import__("hashlib").sha256(raw_bytes[:4096]).hexdigest(),
                        }
                    else:
                        flow_tls = None
                    if UDP in packet and int(dst_port) == 443 and len(raw_bytes) >= 5 and raw_bytes[0] & 0x80:
                        flow_quic = {"version": int.from_bytes(raw_bytes[1:5], "big"), "long_header": True}
                    else:
                        flow_quic = None
                except Exception:
                    flow_tls, flow_quic = None, None

                dns_query = None
                dns_response_code = None
                dns_nxdomain = None
                if DNS in packet:
                    try:
                        if packet[DNS].qd is not None and DNSQR in packet[DNS].qd:
                            dns_query = packet[DNS].qd.qname.decode(errors="replace").rstrip(".")
                        dns_response_code = int(packet[DNS].rcode)
                        dns_nxdomain = dns_response_code == 3
                    except Exception as dns_error:
                        raise IngestionError(
                            IngestionCode.DNS_PARSE_ERROR,
                            f"DNS parse failed for {pcap_file}: {dns_error}",
                            cause=dns_error,
                        ) from dns_error

                # Canonicalize the flow key so both directions of the same
                # conversation map to one entry, regardless of which endpoint
                # sent a given packet.
                endpoint_a = (pkt_src, src_port)
                endpoint_b = (pkt_dst, dst_port)
                if endpoint_a <= endpoint_b:
                    flow_key = (pkt_src, pkt_dst, src_port, dst_port, proto)
                else:
                    flow_key = (pkt_dst, pkt_src, dst_port, src_port, proto)

                flow_data = flows_dict[flow_key]
                if flow_tls is not None:
                    flow_data["tls_metadata"] = flow_tls
                    flow_data["ja4"] = flow_tls["client_hello_sha256"][:32]
                if flow_quic is not None:
                    flow_data["quic_metadata"] = flow_quic
                if dns_query is not None:
                    flow_data["dns_query"] = dns_query
                if dns_response_code is not None:
                    flow_data["dns_response_code"] = dns_response_code
                    flow_data["dns_nxdomain"] = dns_nxdomain

                if flow_data["initiator_ip"] is None:
                    flow_data["initiator_ip"] = pkt_src
                    flow_data["initiator_port"] = src_port

                flow_data["packets"] += 1
                flow_data["bytes"] += pkt_len

                if flow_data["start_time"] is None:
                    flow_data["start_time"] = pkt_time
                flow_data["end_time"] = pkt_time

                is_from_initiator = (
                    pkt_src == flow_data["initiator_ip"]
                    and src_port == flow_data["initiator_port"]
                )
                if is_from_initiator:
                    flow_data["init_to_resp_packets"] += 1
                    flow_data["init_to_resp_bytes"] += pkt_len
                else:
                    flow_data["resp_to_init_packets"] += 1
                    flow_data["resp_to_init_bytes"] += pkt_len

                if TCP in packet:
                    has_syn = "S" in flags
                    has_ack = "A" in flags
                    if has_syn:
                        flow_data["syn_packets"] += 1
                        if has_ack:
                            flow_data["syn_ack_packets"] += 1
                        else:
                            flow_data["syn_only_packets"] += 1
                    if has_ack:
                        flow_data["ack_packets"] += 1
                    if "F" in flags:
                        flow_data["fin_packets"] += 1
                    if "R" in flags:
                        flow_data["rst_packets"] += 1
                elif ICMP in packet:
                    flow_data["icmp_packets"] += 1
                    flow_data["icmp_bytes"] += pkt_len
                    icmp_type = int(packet[ICMP].type)
                    flow_data["icmp_type_counts"][icmp_type] += 1

            packets.close()

            # Convert to FlowRecord objects. source_ip/destination_ip on the
            # record reflect the flow's initiator (first packet observed),
            # matching NFStream's convention; direction-specific counters are
            # tracked relative to that same initiator so they are never
            # silently zeroed for one side.
            flows = []
            for flow_key, flow_data in flows_dict.items():
                key_ip_a, key_ip_b, key_port_a, key_port_b, proto = flow_key

                if flow_data["initiator_ip"] == key_ip_a:
                    src_ip, dst_ip = key_ip_a, key_ip_b
                    src_port, dst_port = key_port_a, key_port_b
                else:
                    src_ip, dst_ip = key_ip_b, key_ip_a
                    src_port, dst_port = key_port_b, key_port_a

                duration_ms = 0
                if flow_data["start_time"] is not None and flow_data["end_time"] is not None:
                    duration_ms = int((flow_data["end_time"] - flow_data["start_time"]) * 1000)

                pps = flow_data["packets"] / (duration_ms / 1000) if duration_ms > 0 else 0
                mean_ps = flow_data["bytes"] / flow_data["packets"] if flow_data["packets"] else 0.0
                mean_piat = duration_ms / (flow_data["packets"] - 1) if flow_data["packets"] > 1 else 0.0

                # Traffic-time timestamp: use the flow's last-observed packet
                # time (capture time), not wall-clock processing time.
                traffic_timestamp = flow_data["end_time"] if flow_data["end_time"] is not None else None

                flow = FlowRecord(
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol=proto,
                    bidirectional_packets=flow_data["packets"],
                    bidirectional_bytes=flow_data["bytes"],
                    bidirectional_duration_ms=duration_ms,
                    src2dst_packets=flow_data["init_to_resp_packets"],
                    src2dst_bytes=flow_data["init_to_resp_bytes"],
                    dst2src_packets=flow_data["resp_to_init_packets"],
                    dst2src_bytes=flow_data["resp_to_init_bytes"],
                    bidirectional_first_seen_ms=int(flow_data["start_time"] * 1000) if flow_data["start_time"] else 0,
                    bidirectional_last_seen_ms=int(flow_data["end_time"] * 1000) if flow_data["end_time"] else 0,
                    bidirectional_min_ps=mean_ps,
                    bidirectional_mean_ps=mean_ps,
                    bidirectional_stddev_ps=0,
                    bidirectional_max_ps=mean_ps,
                    bidirectional_min_piat_ms=mean_piat,
                    bidirectional_mean_piat_ms=mean_piat,
                    bidirectional_stddev_piat_ms=0,
                    bidirectional_max_piat_ms=mean_piat,
                    syn_packets=flow_data["syn_packets"],
                    ack_packets=flow_data["ack_packets"],
                    fin_packets=flow_data["fin_packets"],
                    rst_packets=flow_data["rst_packets"],
                    syn_only_packets=flow_data["syn_only_packets"],
                    syn_ack_packets=flow_data["syn_ack_packets"],
                    icmp_packets=flow_data["icmp_packets"],
                    icmp_bytes=flow_data["icmp_bytes"],
                    icmp_type_counts=dict(flow_data["icmp_type_counts"]) or None,
                    application_name="unknown",
                    application_category="unknown",
                    flow_id=stable_flow_id(src_ip, dst_ip, src_port, dst_port, proto, flow_data["start_time"]),
                    timestamp=traffic_timestamp,
                    dns_query=flow_data["dns_query"],
                    dns_response_code=flow_data["dns_response_code"],
                    dns_nxdomain=flow_data["dns_nxdomain"],
                    tls_metadata=flow_data["tls_metadata"], quic_metadata=flow_data["quic_metadata"],
                    ja3=flow_data["ja3"], ja3s=flow_data["ja3s"], ja4=flow_data["ja4"],
                )
                flows.append(flow)

            self.flows = flows
            logger.info(f"Scapy fallback extracted {len(flows)} flows")
            return flows

        except IngestionError:
            self.flows = []
            raise
        except Exception as e:
            logger.error(f"Scapy fallback also failed: {e}")
            self.flows = []
            raise IngestionError(
                IngestionCode.PCAP_PARSE_ERROR,
                f"Scapy fallback failed for {pcap_file}: {e}",
                cause=e,
            ) from e
    
    def extract_from_live(
        self,
        interface: str,
        duration: Optional[int] = None,
        statistical_analysis: bool = True
    ) -> Iterator[FlowRecord]:
        """
        Extract flows from live network capture
        
        Args:
            interface: Network interface name
            duration: Capture duration in seconds
            statistical_analysis: Enable statistical analysis
            
        Yields:
            FlowRecord objects as they are generated
        """
        logger.info(f"Starting live flow extraction on {interface}")

        if not NFSTREAM_AVAILABLE:
            raise RuntimeError(
                "Live flow extraction requires nfstream, which is not installed. "
                "There is no Scapy fallback for live capture (only PCAP extraction "
                "has one). Install nfstream, or use PCAP replay mode instead."
            )

        try:
            self.nfstreamer = NFStreamer(
                source=interface,
                statistical_analysis=statistical_analysis,
                **self.config
            )
            
            for flow in self.nfstreamer:
                flow_record = self._nfstream_flow_to_record(flow)
                self.flows.append(flow_record)
                yield flow_record
                
        except Exception as e:
            logger.error(f"Live flow extraction failed: {e}")
            raise
    
    def _dataframe_to_flow_records(self, df: pd.DataFrame) -> List[FlowRecord]:
        """Convert pandas DataFrame to FlowRecord list"""
        flow_records = []
        
        for idx, row in df.iterrows():
            flow_record = FlowRecord(
                # 5-tuple
                source_ip=row.get('src_ip', ''),
                destination_ip=row.get('dst_ip', ''),
                source_port=int(row.get('src_port', 0)),
                destination_port=int(row.get('dst_port', 0)),
                protocol=int(row.get('protocol', 0)),
                
                # Flow statistics
                bidirectional_packets=int(row.get('bidirectional_packets', 0)),
                bidirectional_bytes=int(row.get('bidirectional_bytes', 0)),
                bidirectional_duration_ms=int(row.get('bidirectional_duration_ms', 0)),
                
                # Direction-specific stats
                src2dst_packets=int(row.get('src2dst_packets', 0)),
                src2dst_bytes=int(row.get('src2dst_bytes', 0)),
                dst2src_packets=int(row.get('dst2src_packets', 0)),
                dst2src_bytes=int(row.get('dst2src_bytes', 0)),
                
                # Timing information
                bidirectional_first_seen_ms=int(row.get('bidirectional_first_seen_ms', 0)),
                bidirectional_last_seen_ms=int(row.get('bidirectional_last_seen_ms', 0)),
                
                # Statistical features
                bidirectional_min_ps=float(row.get('bidirectional_min_ps', 0)),
                bidirectional_mean_ps=float(row.get('bidirectional_mean_ps', 0)),
                bidirectional_stddev_ps=float(row.get('bidirectional_stddev_ps', 0)),
                bidirectional_max_ps=float(row.get('bidirectional_max_ps', 0)),
                
                bidirectional_min_piat_ms=float(row.get('bidirectional_min_piat_ms', 0)),
                bidirectional_mean_piat_ms=float(row.get('bidirectional_mean_piat_ms', 0)),
                bidirectional_stddev_piat_ms=float(row.get('bidirectional_stddev_piat_ms', 0)),
                bidirectional_max_piat_ms=float(row.get('bidirectional_max_piat_ms', 0)),
                
                # TCP flags
                syn_packets=int(row.get('syn_packets', 0)),
                ack_packets=int(row.get('ack_packets', 0)),
                fin_packets=int(row.get('fin_packets', 0)),
                rst_packets=int(row.get('rst_packets', 0)),
                
                # Application info
                application_name=row.get('application_name', 'unknown'),
                application_category=row.get('application_category', 'unknown'),
                
                # Metadata
                flow_id=int(row.get('id', 0)) if 'id' in row else None,
                # Traffic-time, not processing time: derive from the flow's
                # own last-seen capture timestamp rather than time.time().
                timestamp=int(row.get('bidirectional_last_seen_ms', 0)) / 1000
                if row.get('bidirectional_last_seen_ms') else None,
            )
            flow_records.append(flow_record)
        
        return flow_records
    
    def _nfstream_flow_to_record(self, flow) -> FlowRecord:
        """Convert NFStream flow object to FlowRecord"""
        return FlowRecord(
            # 5-tuple
            source_ip=flow.src_ip,
            destination_ip=flow.dst_ip,
            source_port=flow.src_port,
            destination_port=flow.dst_port,
            protocol=flow.protocol,
            
            # Flow statistics
            bidirectional_packets=flow.bidirectional_packets,
            bidirectional_bytes=flow.bidirectional_bytes,
            bidirectional_duration_ms=flow.bidirectional_duration_ms,
            
            # Direction-specific stats
            src2dst_packets=flow.src2dst_packets,
            src2dst_bytes=flow.src2dst_bytes,
            dst2src_packets=flow.dst2src_packets,
            dst2src_bytes=flow.dst2src_bytes,
            
            # Timing information
            bidirectional_first_seen_ms=flow.bidirectional_first_seen_ms,
            bidirectional_last_seen_ms=flow.bidirectional_last_seen_ms,
            
            # Statistical features
            bidirectional_min_ps=flow.bidirectional_min_ps if hasattr(flow, 'bidirectional_min_ps') else 0,
            bidirectional_mean_ps=flow.bidirectional_mean_ps if hasattr(flow, 'bidirectional_mean_ps') else 0,
            bidirectional_stddev_ps=flow.bidirectional_stddev_ps if hasattr(flow, 'bidirectional_stddev_ps') else 0,
            bidirectional_max_ps=flow.bidirectional_max_ps if hasattr(flow, 'bidirectional_max_ps') else 0,
            
            bidirectional_min_piat_ms=flow.bidirectional_min_piat_ms if hasattr(flow, 'bidirectional_min_piat_ms') else 0,
            bidirectional_mean_piat_ms=flow.bidirectional_mean_piat_ms if hasattr(flow, 'bidirectional_mean_piat_ms') else 0,
            bidirectional_stddev_piat_ms=flow.bidirectional_stddev_piat_ms if hasattr(flow, 'bidirectional_stddev_piat_ms') else 0,
            bidirectional_max_piat_ms=flow.bidirectional_max_piat_ms if hasattr(flow, 'bidirectional_max_piat_ms') else 0,
            
            # TCP flags
            syn_packets=flow.syn_packets if hasattr(flow, 'syn_packets') else 0,
            ack_packets=flow.ack_packets if hasattr(flow, 'ack_packets') else 0,
            fin_packets=flow.fin_packets if hasattr(flow, 'fin_packets') else 0,
            rst_packets=flow.rst_packets if hasattr(flow, 'rst_packets') else 0,
            
            # Application info
            application_name=flow.application_name if hasattr(flow, 'application_name') else 'unknown',
            application_category=flow.application_category if hasattr(flow, 'application_category') else 'unknown',
            
            # Metadata
            flow_id=flow.id,
            # Traffic-time: NFStream's own last-seen timestamp for this flow,
            # not wall-clock processing time.
            timestamp=flow.bidirectional_last_seen_ms / 1000
            if getattr(flow, "bidirectional_last_seen_ms", None) else None,
        )
    
    def get_flows_dataframe(self) -> pd.DataFrame:
        """Convert flows to pandas DataFrame"""
        if not self.flows:
            return pd.DataFrame()
        
        return pd.DataFrame([flow.to_dict() for flow in self.flows])
    
    def get_flow_statistics(self) -> Dict[str, Any]:
        """Get statistics about extracted flows"""
        if not self.flows:
            return {
                "total_flows": 0,
                "total_packets": 0,
                "total_bytes": 0,
                "avg_duration_ms": 0,
                "protocols": {},
                "applications": {}
            }
        
        stats = {
            "total_flows": len(self.flows),
            "total_packets": sum(f.bidirectional_packets for f in self.flows),
            "total_bytes": sum(f.bidirectional_bytes for f in self.flows),
            "avg_duration_ms": sum(f.bidirectional_duration_ms for f in self.flows) / len(self.flows),
            "protocols": {},
            "applications": {},
            "unique_sources": len(set(f.source_ip for f in self.flows)),
            "unique_destinations": len(set(f.destination_ip for f in self.flows))
        }
        
        # Count protocols
        for flow in self.flows:
            proto_name = self._get_protocol_name(flow.protocol)
            stats["protocols"][proto_name] = stats["protocols"].get(proto_name, 0) + 1
            
            # Count applications
            stats["applications"][flow.application_name] = \
                stats["applications"].get(flow.application_name, 0) + 1
        
        return stats
    
    @staticmethod
    def _get_protocol_name(protocol_num: int) -> str:
        """Convert protocol number to name"""
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }
        return protocol_map.get(protocol_num, f"PROTO_{protocol_num}")
    
    def filter_flows(self, **criteria) -> List[FlowRecord]:
        """
        Filter flows based on criteria
        
        Args:
            **criteria: Field-value pairs to filter on
            
        Returns:
            Filtered list of FlowRecord objects
        """
        filtered = self.flows
        
        for field, value in criteria.items():
            filtered = [f for f in filtered if getattr(f, field, None) == value]
        
        return filtered
    
    def export_to_csv(self, filepath: str):
        """Export flows to CSV file"""
        df = self.get_flows_dataframe()
        if df.empty:
            logger.warning("No flows to export")
            return
        
        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        logger.info(f"Exported {len(df)} flows to {output_path}")


class CustomFlowPlugin(NFPlugin):
    """Custom NFStream plugin for additional flow features"""
    
    def on_update(self, obs, entry):
        """Called on each packet update"""
        pass
    
    def on_expire(self, flow):
        """Called when flow expires"""
        pass