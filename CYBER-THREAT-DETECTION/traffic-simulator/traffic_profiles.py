#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 2: Traffic Generator Engine
Module: traffic_profiles.py
Description: Pre-configured baseline telemetry and stress benchmark traffic profiles.
"""

import logging
from typing import Any, Dict, List, Optional
from packet_generator import PacketGenerator

logger = logging.getLogger("TrafficProfiles")


def generate_normal_traffic(
    source_ip: str = "192.168.10.10",
    destination_ip: str = "192.168.10.20",
    destination_port: int = 80,
    packet_count: int = 50,
    iat: float = 0.1,
) -> Dict[str, Any]:
    """
    Profile 1: Normal Simulated Web/Application Session Traffic.
    Constructs TCP stream with PSH/ACK flags, standard HTTP-sized payload, and human-like inter-arrival timing.
    """
    logger.info("Executing Profile: Normal Traffic [TCP PSH+ACK]")
    generator = PacketGenerator(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="TCP",
        source_port=52341,
        destination_port=destination_port,
        packet_count=packet_count,
        packet_size=320,  # Standard web segment size
        iat=iat,
        tcp_flags=["PSH", "ACK"],
        payload_data="GET /api/v1/telemetry HTTP/1.1\r\nHost: 192.168.10.20\r\nUser-Agent: NTRO-Agent/1.0\r\n\r\n",
    )
    return generator.run()


def generate_high_velocity_tcp(
    source_ip: str = "192.168.10.10",
    destination_ip: str = "192.168.10.20",
    destination_port: int = 80,
    packet_count: int = 200,
    iat: float = 0.005,
) -> Dict[str, Any]:
    """
    Profile 2: High-Velocity TCP SYN Handshake Benchmark.
    Simulates rapid connection initialization bursts with minimal payload and ultra-low IAT.
    """
    logger.info("Executing Profile: High-Velocity TCP Benchmark [TCP SYN]")
    generator = PacketGenerator(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="TCP",
        source_port=49152,
        destination_port=destination_port,
        packet_count=packet_count,
        packet_size=64,  # Minimal SYN packet footprint
        iat=iat,
        tcp_flags=["SYN"],
        payload_data=b"",
    )
    return generator.run()


def generate_port_sweep(
    source_ip: str = "192.168.10.10",
    destination_ip: str = "192.168.10.20",
    start_port: int = 20,
    end_port: int = 70,
    iat: float = 0.02,
) -> Dict[str, Any]:
    """
    Profile 3: Port Range Sweep & Discovery Simulation.
    Iterates sequentially across a range of destination ports to test multi-port ingestion and detection.
    """
    target_ports = list(range(start_port, end_port + 1))
    total_count = len(target_ports)

    logger.info("Executing Profile: Port Sweep across %d ports (%d -> %d)", total_count, start_port, end_port)
    generator = PacketGenerator(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="TCP",
        source_port=58000,
        destination_port=start_port,
        packet_count=total_count,
        packet_size=64,
        iat=iat,
        tcp_flags=["SYN"],
        payload_data=b"",
    )
    return generator.run(port_list=target_ports)


def generate_high_volume_udp(
    source_ip: str = "192.168.10.10",
    destination_ip: str = "192.168.10.20",
    destination_port: int = 9999,
    packet_count: int = 150,
    packet_size: int = 1024,
    iat: float = 0.002,
) -> Dict[str, Any]:
    """
    Profile 4: High-Volume UDP Datagram Benchmark.
    Transmits large payload UDP packets at a high transmission frequency to evaluate bandwidth capacity.
    """
    logger.info("Executing Profile: High-Volume UDP Datagram Benchmark [UDP %d bytes]", packet_size)
    generator = PacketGenerator(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="UDP",
        source_port=44550,
        destination_port=destination_port,
        packet_count=packet_count,
        packet_size=packet_size,
        iat=iat,
        payload_data=b"NTRO_HIGH_VOLUME_STREAM_DATA_CHUNK",
    )
    return generator.run()
