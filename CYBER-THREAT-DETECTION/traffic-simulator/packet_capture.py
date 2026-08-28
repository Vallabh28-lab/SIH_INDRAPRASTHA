#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 3: Telemetry Ingestion
Module: packet_capture.py
Description: Thread-safe continuous packet capture engine with sliding memory buffer.
"""

from collections import deque
from dataclasses import asdict, dataclass, field
import logging
import sys
import threading
import time
from typing import Any, Deque, Dict, List, Optional

# Structured logging configuration
logger = logging.getLogger("PacketCaptureEngine")

try:
    # pyrefly: ignore [missing-import]
    from scapy.all import ICMP, IP, TCP, UDP, AsyncSniffer, Raw, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning(
        "Scapy is not installed. Native L2/L3 packet sniffing is disabled; telemetry buffer injection mode active."
    )


@dataclass
class PacketMetadata:
    """Structured telemetry metadata extracted from a single network frame."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    tcp_flags: List[str] = field(default_factory=list)
    payload_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PacketCaptureEngine:
    """Thread-safe continuous packet sniffer storing structured telemetry in a sliding memory buffer."""

    # Map Scapy TCP flag characters to readable names
    TCP_FLAG_MAP = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }

    def __init__(
        self,
        interface: str = "eth0",
        buffer_capacity: int = 10000,
        bpf_filter: Optional[str] = None,
    ):
        self.interface = interface
        self.buffer_capacity = max(100, buffer_capacity)
        self.bpf_filter = bpf_filter

        self._buffer: Deque[PacketMetadata] = deque(maxlen=self.buffer_capacity)
        self._lock = threading.Lock()
        self._sniffer: Optional[AsyncSniffer] = None
        self._is_active = False

        self._total_packets_captured = 0
        self._start_time: Optional[float] = None
        self._stop_time: Optional[float] = None

    @property
    def is_running(self) -> bool:
        """Return True if the packet capture thread is actively running."""
        return self._is_active and self._sniffer is not None and self._sniffer.running

    def _parse_tcp_flags(self, flags_val) -> List[str]:
        """Extract readable flag names from Scapy TCP flags attribute."""
        flags_str = str(flags_val)
        return [self.TCP_FLAG_MAP[char] for char in flags_str if char in self.TCP_FLAG_MAP]

    def _packet_callback(self, pkt) -> None:
        """Callback invoked by Scapy AsyncSniffer for every captured packet."""
        if IP not in pkt:
            return  # Filter out non-IPv4 frames (ARP, IPv6 if unneeded)

        timestamp = float(pkt.time) if hasattr(pkt, "time") else time.time()
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        frame_len = len(pkt)

        src_port = 0
        dst_port = 0
        protocol = "OTHER"
        tcp_flags: List[str] = []
        payload_size = 0

        if TCP in pkt:
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_flags = self._parse_tcp_flags(pkt[TCP].flags)
        elif UDP in pkt:
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif ICMP in pkt:
            protocol = "ICMP"

        if Raw in pkt:
            payload_size = len(pkt[Raw].load)

        record = PacketMetadata(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=frame_len,
            tcp_flags=tcp_flags,
            payload_size=payload_size,
        )

        with self._lock:
            self._buffer.append(record)
            self._total_packets_captured += 1

    def start_capture(self, bpf_filter: Optional[str] = None) -> None:
        """Start asynchronous packet sniffing on the configured interface."""
        if self.is_running:
            logger.warning("Packet capture is already active on interface '%s'", self.interface)
            return

        active_filter = bpf_filter or self.bpf_filter
        logger.info(
            "Starting Async Packet Sniffer on interface '%s' (BPF Filter: '%s', Buffer Capacity: %d)",
            self.interface,
            active_filter or "None (All IP)",
            self.buffer_capacity,
        )

        self._start_time = time.time()
        self._stop_time = None
        self._is_active = True

        if not SCAPY_AVAILABLE:
            logger.info("Scapy is not present. Operating in non-blocking memory buffer ingestion mode.")
            return

        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=active_filter,
                prn=self._packet_callback,
                store=False,
            )
            self._sniffer.start()
            logger.info("Packet capture engine successfully started.")
        except PermissionError:
            self._is_active = False
            logger.critical("Permission denied. Raw packet sniffing requires root or CAP_NET_ADMIN.")
            raise
        except Exception as exc:
            self._is_active = False
            logger.error("Failed to initialize AsyncSniffer: %s", exc)
            raise

    def stop_capture(self) -> Dict[str, Any]:
        """Stop active packet sniffing and return session summary statistics."""
        if not self._is_active or self._sniffer is None:
            logger.warning("Packet capture is not currently running.")
            return {"status": "STOPPED", "captured_count": len(self._buffer)}

        logger.info("Stopping packet capture engine on interface '%s'...", self.interface)
        try:
            self._sniffer.stop()
        except Exception as exc:
            logger.warning("Exception during sniffer termination: %s", exc)

        self._is_active = False
        self._stop_time = time.time()
        duration = max(self._stop_time - (self._start_time or self._stop_time), 0.001)

        with self._lock:
            buffer_count = len(self._buffer)
            total_captured = self._total_packets_captured

        summary = {
            "status": "STOPPED",
            "interface": self.interface,
            "duration_sec": round(duration, 3),
            "total_packets_captured": total_captured,
            "packets_currently_buffered": buffer_count,
            "capture_rate_pps": round(total_captured / duration, 2),
        }
        logger.info("Capture stopped. Total packets: %d (%.2f pps)", total_captured, summary["capture_rate_pps"])
        return summary

    def get_buffered_packets(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retrieve a copy of structured packet dictionaries currently in the sliding buffer."""
        with self._lock:
            if limit is not None and limit > 0:
                # Return most recent N packets
                records = list(self._buffer)[-limit:]
            else:
                records = list(self._buffer)
        return [rec.to_dict() for rec in records]

    def get_buffer_size(self) -> int:
        """Return the current number of packets stored in the buffer."""
        with self._lock:
            return len(self._buffer)

    def clear_buffer(self) -> int:
        """Flush the sliding buffer and return the number of cleared records."""
        with self._lock:
            cleared_count = len(self._buffer)
            self._buffer.clear()
        logger.info("Cleared %d packets from the telemetry buffer.", cleared_count)
        return cleared_count
