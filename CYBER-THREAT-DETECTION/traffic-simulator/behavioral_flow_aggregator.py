#!/usr/bin/env python3
"""
====================================================================================================
Cyber Threat Detection & Telemetry Simulation System - Phase 3: Behavioral Flow Aggregator
Module: behavioral_flow_aggregator.py
Description: Logic mapper and synthetic telemetry generator that translates target request context
             into complete 5-tuple flow statistical records. Dynamically injects high-threat
             statistical anomalies (high PPS, massive SYN counts, zero ACKs, low IATs) when
             flagged as security attack tests, and constructs Pydantic-compliant flow dictionaries.
====================================================================================================
"""

import argparse
import json
import logging
import random
import time
from typing import Any, Dict, Optional, Union

# Import flow schema for schema enforcement and validation
try:
    from flow_schema import FlowRecordSchema
except ImportError:
    FlowRecordSchema = None  # type: ignore

# Optional integration with parser and DNS resolver
try:
    from http_input_parser import parse_http_input
    from dns_resolver import resolve_domain
except ImportError:
    parse_http_input = None
    resolve_domain = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("BehavioralFlowAggregator")


# Canonical traffic profile types
TRAFFIC_PROFILES = ("normal", "syn_flood", "port_scan", "udp_flood")


def generate_behavioral_flow(
    target_host_or_ip: str,
    source_ip: Optional[str] = None,
    traffic_type: str = "normal",
    is_attack: bool = False,
    attack_type: Optional[str] = None,
    destination_port: Optional[int] = None,
    source_port: Optional[int] = None,
    protocol: Optional[str] = None,
    validate_schema: bool = True,
) -> Dict[str, Any]:
    """
    Generates a structured, mathematically coherent JSON flow record matching all 5-tuple
    statistical features expected by the FastAPI ingestion endpoint and AI threat engine.

    If marked as an attack simulation (is_attack=True or traffic_type in attack categories),
    it dynamically injects characteristic high-risk parameters:
      - SYN Flood: Elevated PPS (300-2000), massive syn_count (200-1000), 0 ACKs, ultra-low iat_mean (~0.001s).
      - Port Scan: 1 packet, syn_count=1, ack_count=0, duration=0.0s, high instantaneous burst rate.
      - UDP Flood: Large packet payload (1024 bytes), high byte throughput (400KB-1.5MB/s), UDP protocol.
      - Normal: Balanced forward/backward handshakes, high ACK ratio (~0.95+), realistic human IAT (0.05-0.20s).

    :param target_host_or_ip: Destination IP or hostname/URL to resolve.
    :param source_ip: Optional source IP (defaults to realistic randomized/spoofed IP).
    :param traffic_type: Category ('normal', 'syn_flood', 'port_scan', 'udp_flood').
    :param is_attack: Boolean flag indicating if this is an active attack security test.
    :param attack_type: Specific attack override ('syn_flood', 'port_scan', 'udp_flood').
    :param destination_port: Target port (default: 80 for HTTP, 443 for HTTPS, 53 for DNS, etc.).
    :param source_port: Ephemeral source port (default: random 49152-65535).
    :param protocol: L4 protocol ('TCP', 'UDP', 'ICMP').
    :param validate_schema: If True, validates dictionary with FlowRecordSchema.
    :return: Complete Pydantic-compliant dictionary ready for REST API ingestion.
    """
    # 1. Resolve Target IP if hostname/URL is passed
    if resolve_domain is not None and parse_http_input is not None:
        try:
            parsed_host = parse_http_input(target_host_or_ip)
            dst_ip = resolve_domain(parsed_host)
        except Exception:
            dst_ip = resolve_domain(target_host_or_ip) if resolve_domain else target_host_or_ip
    elif resolve_domain is not None:
        dst_ip = resolve_domain(target_host_or_ip)
    else:
        dst_ip = target_host_or_ip.strip()

    # Determine final active profile
    resolved_type = "normal"
    if attack_type:
        resolved_type = attack_type.strip().lower()
    elif is_attack:
        resolved_type = "syn_flood" if traffic_type == "normal" else traffic_type.strip().lower()
    else:
        resolved_type = traffic_type.strip().lower()

    if resolved_type not in TRAFFIC_PROFILES:
        resolved_type = "normal"

    # Assign source port if not provided
    src_port = source_port if source_port is not None else random.randint(49152, 65535)

    # ----------------------------------------------------------------------------------------------
    # PROFILE 1: High-Velocity TCP SYN Flood Attack (Volumetric Connection Exhaustion)
    # ----------------------------------------------------------------------------------------------
    if resolved_type == "syn_flood":
        src_ip = source_ip or f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
        dst_port = destination_port or 80
        proto = "TCP"

        packet_count = random.randint(250, 1000)
        mean_pkt_size = 64.0
        total_bytes = int(packet_count * mean_pkt_size)
        duration = round(random.uniform(0.2, 0.9), 4)

        pps = round(packet_count / max(duration, 0.001), 2)
        bps = round(total_bytes / max(duration, 0.001), 2)

        iat_mean = round(random.uniform(0.0005, 0.0018), 6)
        iat_std = round(random.uniform(0.00005, 0.0003), 6)

        syn_count = packet_count
        ack_count = 0
        syn_ratio = 1.0
        ack_ratio = 0.0

    # ----------------------------------------------------------------------------------------------
    # PROFILE 2: Reconnaissance Port Probe (Single-Packet Port Scan Sweep)
    # ----------------------------------------------------------------------------------------------
    elif resolved_type == "port_scan":
        src_ip = source_ip or "172.16.5.99"
        dst_port = destination_port or random.choice([21, 22, 23, 25, 80, 443, 8080, 8443, 3306, 5432])
        proto = "TCP"

        packet_count = 1
        mean_pkt_size = 60.0
        total_bytes = 60
        duration = 0.0

        pps = 10000.0
        bps = 600000.0

        iat_mean = 0.0
        iat_std = 0.0

        syn_count = 1
        ack_count = 0
        syn_ratio = 1.0
        ack_ratio = 0.0

    # ----------------------------------------------------------------------------------------------
    # PROFILE 3: High-Bandwidth Volumetric UDP Flood Attack (Datagram Blast)
    # ----------------------------------------------------------------------------------------------
    elif resolved_type == "udp_flood":
        src_ip = source_ip or "198.51.100.45"
        dst_port = destination_port or random.choice([53, 123, 1900, 9999, 11211])
        proto = "UDP"

        packet_count = random.randint(300, 1200)
        mean_pkt_size = 1024.0
        total_bytes = int(packet_count * mean_pkt_size)
        duration = round(random.uniform(0.3, 1.2), 4)

        pps = round(packet_count / max(duration, 0.001), 2)
        bps = round(total_bytes / max(duration, 0.001), 2)

        iat_mean = round(random.uniform(0.0008, 0.0035), 6)
        iat_std = round(random.uniform(0.0001, 0.0007), 6)

        syn_count = 0
        ack_count = 0
        syn_ratio = 0.0
        ack_ratio = 0.0

    # ----------------------------------------------------------------------------------------------
    # PROFILE 4: Legitimate Background Traffic (Benign Web / App Telemetry)
    # ----------------------------------------------------------------------------------------------
    else:
        src_ip = source_ip or f"192.168.10.{random.randint(12, 19)}"
        dst_port = destination_port or random.choice([80, 443, 8080])
        proto = protocol or "TCP"

        packet_count = random.randint(20, 65)
        duration = round(random.uniform(1.8, 5.5), 4)

        mean_pkt_size = round(random.uniform(280.0, 650.0), 2)
        std_pkt_size = round(random.uniform(120.0, 350.0), 2)
        total_bytes = int(packet_count * mean_pkt_size)

        pps = round(packet_count / max(duration, 0.001), 2)
        bps = round(total_bytes / max(duration, 0.001), 2)

        iat_mean = round(random.uniform(0.04, 0.18), 6)
        iat_std = round(random.uniform(0.01, 0.07), 6)

        syn_count = 1
        ack_count = max(packet_count - 1, 0)
        syn_ratio = round(syn_count / max(packet_count, 1), 4)
        ack_ratio = round(ack_count / max(packet_count, 1), 4)

    # Construct the complete composite flow dictionary
    flow_record: Dict[str, Any] = {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": proto,
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "flow_duration": duration,
        "packets_per_second": pps,
        "bytes_per_second": bps,
        "mean_packet_size": mean_pkt_size,
        "std_packet_size": std_pkt_size if "std_pkt_size" in locals() else 0.0,
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "syn_count": syn_count,
        "ack_count": ack_count,
        "syn_ratio": syn_ratio,
        "ack_ratio": ack_ratio,
    }

    # Validate against Pydantic schema if available and requested
    if validate_schema and FlowRecordSchema is not None:
        validated_schema = FlowRecordSchema(**flow_record)
        return validated_schema.model_dump()

    return flow_record


def main() -> None:
    """CLI execution tool for behavioral flow aggregation."""
    parser = argparse.ArgumentParser(
        description="Phase 3: Behavioral Flow Aggregator - Generate Pydantic flow metrics from request context"
    )
    parser.add_argument(
        "target",
        type=str,
        nargs="?",
        default="collector.internal",
        help="Target IP, URL, or domain to attack or simulate traffic against (default: collector.internal)",
    )
    parser.add_argument(
        "--type",
        "-t",
        type=str,
        default="normal",
        choices=["normal", "syn_flood", "port_scan", "udp_flood"],
        help="Traffic profile type (default: normal)",
    )
    parser.add_argument(
        "--attack",
        "-a",
        action="store_true",
        help="Flag as malicious security test (triggers high-risk parameter injection)",
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=None,
        help="Optional destination target port",
    )
    parser.add_argument(
        "--source-ip",
        "-s",
        type=str,
        default=None,
        help="Optional custom source IP",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw formatted JSON flow record",
    )
    args = parser.parse_args()

    flow = generate_behavioral_flow(
        target_host_or_ip=args.target,
        source_ip=args.source_ip,
        traffic_type=args.type,
        is_attack=args.attack,
        destination_port=args.port,
    )

    if args.json:
        print(json.dumps(flow, indent=2))
    else:
        print("=" * 80)
        print(" NTRO CYBER DEFENSE - BEHAVIORAL FLOW AGGREGATION RECORD")
        print("=" * 80)
        print(f" Target Endpoint    : {flow['destination_ip']}:{flow['destination_port']} ({flow['protocol']})")
        print(f" Source Endpoint    : {flow['source_ip']}:{flow['source_port']}")
        print(f" Flow Profile       : {args.type.upper()} {'[SECURITY ATTACK TEST]' if args.attack else ''}")
        print(f" Packet Count       : {flow['packet_count']:,} packets")
        print(f" Byte Throughput    : {flow['total_bytes']:,} bytes ({flow['bytes_per_second']:,.2f} B/s)")
        print(f" Packet Velocity    : {flow['packets_per_second']:,.2f} pkts/sec")
        print(f" Mean IAT Interval  : {flow['iat_mean']:.6f} seconds")
        print(f" Flag Distribution  : SYN = {flow['syn_count']} ({flow['syn_ratio']*100:.1f}%) | ACK = {flow['ack_count']} ({flow['ack_ratio']*100:.1f}%)")
        print("=" * 80)
        print("\nComplete Schema JSON:")
        print(json.dumps(flow, indent=2))


if __name__ == "__main__":
    main()
