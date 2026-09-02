"""
Live Network Capture Module
Captures packets from live network interfaces.
NOTE: Only for use in controlled lab environments with permission.
"""

import logging
from typing import Optional, Iterator
from pathlib import Path
from datetime import datetime
import threading
import queue

try:
    from scapy.all import sniff, wrpcap, PcapWriter
    from scapy.packet import Packet
    SCAPY_AVAILABLE=True
except ImportError:
    sniff = wrpcap = PcapWriter = None
    Packet = object
    SCAPY_AVAILABLE=False

logger = logging.getLogger(__name__)


class LivePacketCapture:
    """Captures packets from a live network interface"""
    
    def __init__(
        self,
        interface: str = "eth0",
        packet_filter: str = "",
        packet_limit: Optional[int] = None,
        queue_size: int = 5000,
        drop_on_full: bool = True,
        retain_packets: bool = False,
        max_retained_packets: int = 10000
    ):
        """
        Initialize live capture
        
        Args:
            interface: Network interface to capture from
            packet_filter: BPF filter string (e.g., "tcp port 80")
            packet_limit: Maximum packets to capture (None for unlimited)
        """
        self.interface = interface
        self.packet_filter = packet_filter
        if queue_size <= 0:
            raise ValueError("queue_size must be positive")
        self.packet_limit = packet_limit
        if max_retained_packets <= 0:
            raise ValueError("max_retained_packets must be positive")
        self.max_retained_packets = max_retained_packets
        self.captured_packets = []
        self.is_capturing = False
        self.packet_queue = queue.Queue(maxsize=queue_size)
        self.drop_on_full = drop_on_full
        self.retain_packets = retain_packets
        self._stop_event = threading.Event()
        self._capture_thread = None
        self._capture_error = None
        self._lock = threading.Lock()
        self._received_packets = 0
        self._dropped_packets = 0
        self._retention_dropped_packets = 0
        self._processed_packets = 0
        
        logger.info(f"Initialized live capture on {interface}")
    
    def start_capture(self, duration: Optional[int] = None):
        """Start capture with bounded buffering and explicit drop accounting."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("live packet capture requires Scapy/libpcap in the provisioned runtime")
        if self.is_capturing:
            raise RuntimeError("Capture is already running")
        self.is_capturing = True
        self._stop_event.clear()
        self._capture_error = None

        def packet_callback(packet):
            with self._lock:
                self._received_packets += 1
                received = self._received_packets

            if self.retain_packets:
                if len(self.captured_packets) < self.max_retained_packets:
                    self.captured_packets.append(packet)
                else:
                    with self._lock:
                        self._retention_dropped_packets += 1

            try:
                if self.drop_on_full:
                    self.packet_queue.put_nowait(packet)
                else:
                    self.packet_queue.put(packet, timeout=1.0)
            except queue.Full:
                with self._lock:
                    self._dropped_packets += 1
                return

            if self.packet_limit and received >= self.packet_limit:
                self._stop_event.set()

        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(packet_callback, duration),
            daemon=True,
            name="live-packet-capture"
        )
        self._capture_thread.start()

    def _capture_loop(self, callback, duration):
        """Internal capture loop"""
        try:
            sniff(
                iface=self.interface,
                filter=self.packet_filter,
                prn=callback,
                timeout=duration,
                stop_filter=lambda p: self._stop_event.is_set()
            )
        except Exception as e:
            self._capture_error = e
            logger.error(f"Capture error: {e}")
        finally:
            self.is_capturing = False
            logger.info("Capture stopped")
    
    def stop_capture(self):
        """Stop capturing packets"""
        self._stop_event.set()
        self.is_capturing = False
        logger.info("Stopping capture")
    
    def wait(self, timeout: Optional[float] = None) -> None:
        """Wait for the capture worker to finish."""
        if self._capture_thread is not None:
            self._capture_thread.join(timeout=timeout)

    def drain_queue(self, max_items: Optional[int] = None) -> list:
        """Drain queued packets without blocking."""
        items = []
        while max_items is None or len(items) < max_items:
            try:
                items.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        with self._lock:
            self._processed_packets += len(items)
        return items

    def save_queue_to_pcap(self, filepath: str) -> Optional[Path]:
        """Write queued packets directly to PCAP without retaining them all."""
        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        writer = PcapWriter(str(output_path), append=False, sync=True)
        written = 0
        try:
            while True:
                try:
                    packet = self.packet_queue.get_nowait()
                except queue.Empty:
                    break
                writer.write(packet)
                written += 1
        finally:
            writer.close()
        with self._lock:
            self._processed_packets += written
        if written == 0:
            try:
                output_path.unlink()
            except FileNotFoundError:
                pass
            return None
        return output_path

    def save_to_pcap(self, filepath: str) -> Path:
        """
        Save captured packets to PCAP file
        
        Args:
            filepath: Path to save PCAP file
            
        Returns:
            Path to saved file
        """
        if not self.captured_packets:
            logger.warning("No packets to save")
            return None
        
        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        wrpcap(str(output_path), self.captured_packets)
        logger.info(f"Saved {len(self.captured_packets)} packets to {output_path}")
        
        return output_path
    
    def get_packet_generator(self) -> Iterator[Packet]:
        """Get a generator for captured packets"""
        for packet in self.captured_packets:
            yield packet
    
    def get_statistics(self) -> dict:
        """Get capture statistics"""
        return {
            "interface": self.interface,
            "packet_filter": self.packet_filter,
            "total_packets": self._received_packets,
            "received_packets": self._received_packets,
            "dropped_packets": self._dropped_packets,
            "retention_dropped_packets": self._retention_dropped_packets,
            "processed_packets": self._processed_packets,
            "is_capturing": self.is_capturing,
            "queue_size": self.packet_queue.qsize(),
            "queue_capacity": self.packet_queue.maxsize,
            "retained_packets": len(self.captured_packets),
            "max_retained_packets": self.max_retained_packets,
            "backpressure_ratio": (
                self._dropped_packets / self._received_packets
                if self._received_packets else 0.0
            ),
            "error": str(self._capture_error) if self._capture_error else None
        }