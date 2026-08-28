#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 2: Traffic Generator Engine
Module: packet_generator.py
Description: Modular Scapy-backed Layer 3/4 packet generation and performance metering engine.
"""

import logging
import math
import sys
import time
from typing import Any, Dict, List, Optional, Union

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("PacketGenerator")

try:
    # pyrefly: ignore [missing-import]
    from scapy.all import ICMP, IP, TCP, UDP, Raw, conf, send
except ImportError:
    logger.critical(
        "Scapy is not installed. Please install dependencies via 'pip install -r requirements.txt'."
    )
    sys.exit(1)


class PacketGenerator:
    """Configurable packet synthesis and transmission engine for network simulation & telemetry benchmark."""

    # Map friendly flag strings to Scapy flag characters
    TCP_FLAG_MAP = {
        "F": "F",
        "FIN": "F",
        "S": "S",
        "SYN": "S",
        "R": "R",
        "RST": "R",
        "P": "P",
        "PSH": "P",
        "A": "A",
        "ACK": "A",
        "U": "U",
        "URG": "U",
        "E": "E",
        "ECE": "E",
        "C": "C",
        "CWR": "C",
    }

    def __init__(
        self,
        source_ip: str = "192.168.10.10",
        destination_ip: str = "192.168.10.20",
        protocol: str = "TCP",
        source_port: int = 44332,
        destination_port: int = 80,
        packet_count: int = 100,
        packet_size: Optional[int] = None,
        iat: float = 0.01,
        tcp_flags: Optional[List[str]] = None,
        payload_data: Optional[Union[str, bytes]] = None,
        verbose: bool = False,
    ):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol.upper()
        self.source_port = source_port
        self.destination_port = destination_port
        self.packet_count = max(1, packet_count)
        self.packet_size = packet_size
        self.iat = max(0.0, iat)
        self.tcp_flags = tcp_flags if tcp_flags is not None else ["SYN"]
        self.payload_data = payload_data
        self.verbose = verbose

    def _resolve_tcp_flags(self) -> str:
        """Convert list of flag names to Scapy compact flag string (e.g. ['SYN', 'ACK'] -> 'SA')."""
        scapy_flags = ""
        for flag in self.tcp_flags:
            flag_clean = flag.strip().upper()
            if flag_clean in self.TCP_FLAG_MAP:
                char = self.TCP_FLAG_MAP[flag_clean]
                if char not in scapy_flags:
                    scapy_flags += char
            else:
                logger.warning("Unrecognized TCP flag '%s', skipping.", flag)
        return scapy_flags if scapy_flags else "S"

    def _calculate_payload_padding(self, base_headers_len: int) -> bytes:
        """Construct payload bytes padded to reach target total packet size."""
        if self.payload_data:
            if isinstance(self.payload_data, str):
                raw_bytes = self.payload_data.encode("utf-8")
            else:
                raw_bytes = self.payload_data
        else:
            raw_bytes = b"NTRO_ENGINE_PKT"

        if self.packet_size is not None and self.packet_size > base_headers_len:
            required_padding = self.packet_size - base_headers_len
            if len(raw_bytes) < required_padding:
                raw_bytes = raw_bytes + (b"X" * (required_padding - len(raw_bytes)))
            elif len(raw_bytes) > required_padding:
                raw_bytes = raw_bytes[:required_padding]

        return raw_bytes

    def build_packet(self, dest_port_override: Optional[int] = None):
        """Construct a single Scapy packet based on instance configuration."""
        # 1. Layer 3 (IP)
        ip_layer = IP(src=self.source_ip, dst=self.destination_ip)
        dst_port = dest_port_override if dest_port_override is not None else self.destination_port

        # 2. Layer 4 (Transport / ICMP)
        if self.protocol == "TCP":
            flags_str = self._resolve_tcp_flags()
            l4_layer = TCP(sport=self.source_port, dport=dst_port, flags=flags_str)
            base_header_size = 20 + 20  # IP (20) + TCP (20)
        elif self.protocol == "UDP":
            l4_layer = UDP(sport=self.source_port, dport=dst_port)
            base_header_size = 20 + 8   # IP (20) + UDP (8)
        elif self.protocol == "ICMP":
            l4_layer = ICMP(type=8, code=0)  # Echo Request
            base_header_size = 20 + 8   # IP (20) + ICMP (8)
        else:
            raise ValueError(f"Unsupported protocol '{self.protocol}'. Supported: TCP, UDP, ICMP")

        # 3. Layer 7 / Payload
        payload_bytes = self._calculate_payload_padding(base_header_size)
        raw_layer = Raw(load=payload_bytes)

        return ip_layer / l4_layer / raw_layer

    def run(self, port_list: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Execute packet transmission sequence and return performance telemetry metrics.
        
        :param port_list: Optional sequence of destination ports (e.g. for sweeping).
        """
        logger.info(
            "Starting traffic generation | Protocol: %s | Count: %d | Target: %s:%s | IAT: %.4fs",
            self.protocol,
            self.packet_count,
            self.destination_ip,
            "MULTI" if port_list else str(self.destination_port),
            self.iat,
        )

        total_bytes_transmitted = 0
        packets_transmitted = 0
        start_time = time.perf_counter()

        try:
            for i in range(self.packet_count):
                current_dst_port = port_list[i % len(port_list)] if port_list else None
                pkt = self.build_packet(dest_port_override=current_dst_port)
                pkt_len = len(pkt)

                send(pkt, count=1, verbose=False)

                total_bytes_transmitted += pkt_len
                packets_transmitted += 1

                if self.iat > 0 and i < self.packet_count - 1:
                    time.sleep(self.iat)

        except KeyboardInterrupt:
            logger.warning("Transmission interrupted by user after %d packets.", packets_transmitted)
        except PermissionError:
            logger.critical("Permission denied. Raw socket access requires CAP_NET_ADMIN or root.")
            raise
        except Exception as exc:
            logger.error("Transmission error at packet #%d: %s", packets_transmitted + 1, exc)
            raise

        end_time = time.perf_counter()
        total_duration = max(end_time - start_time, 0.0001)

        actual_pps = packets_transmitted / total_duration
        throughput_kbps = (total_bytes_transmitted * 8) / (total_duration * 1000.0)

        metrics = {
            "status": "COMPLETED",
            "protocol": self.protocol,
            "source_endpoint": f"{self.source_ip}:{self.source_port}",
            "destination_ip": self.destination_ip,
            "target_destination_port": "MULTI" if port_list else self.destination_port,
            "packets_requested": self.packet_count,
            "packets_transmitted": packets_transmitted,
            "total_bytes_sent": total_bytes_transmitted,
            "total_duration_sec": round(total_duration, 4),
            "actual_packets_per_sec": round(actual_pps, 2),
            "throughput_kbps": round(throughput_kbps, 2),
            "configured_iat_sec": self.iat,
        }

        logger.info(
            "Transmission finished: %d packets | %d bytes | Duration: %.4fs | Throughput: %.2f Kbps (%.1f pps)",
            packets_transmitted,
            total_bytes_transmitted,
            total_duration,
            throughput_kbps,
            actual_pps,
        )

        return metrics
