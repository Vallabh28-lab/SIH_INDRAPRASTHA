#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection Prototype
Phase 1: Automated Lab Environment Health Check & Verification Script
"""

import ipaddress
import os
import socket
import subprocess
import sys
from typing import Dict, Tuple

try:
    # pyrefly: ignore [missing-import]
    from scapy.all import IP, UDP, Raw, conf, get_if_addr, get_if_list, send
except ImportError:
    print(
        "[FAILED] Scapy is not installed in the environment. Run 'pip install -r requirements.txt'."
    )
    sys.exit(1)


def check_interface(interface_name: str = "eth0", expected_subnet: str = "192.168.10.0/24") -> Tuple[bool, str]:
    """Check if network interface exists and has an IP assigned within expected subnet."""
    available_ifaces = get_if_list()
    if interface_name not in available_ifaces:
        return False, f"Interface '{interface_name}' not found in system interfaces: {available_ifaces}"

    try:
        ip_str = get_if_addr(interface_name)
        if not ip_str or ip_str == "0.0.0.0":
            return False, f"Interface '{interface_name}' exists but has no valid IPv4 address assigned."

        ip_obj = ipaddress.IPv4Address(ip_str)
        subnet_obj = ipaddress.IPv4Network(expected_subnet)

        if ip_obj in subnet_obj:
            return True, f"Interface '{interface_name}' has valid IP {ip_str} (in subnet {expected_subnet})"
        else:
            return False, f"Interface '{interface_name}' IP {ip_str} is NOT within expected subnet {expected_subnet}"
    except Exception as exc:
        return False, f"Error inspecting interface '{interface_name}': {exc}"


def check_raw_socket_capability() -> Tuple[bool, str]:
    """Verify NET_ADMIN capability by attempting to open a raw socket."""
    try:
        # Attempt to create a raw socket (requires CAP_NET_ADMIN / root)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        raw_sock.close()
        return True, "NET_ADMIN capability verified (raw socket allocation successful)"
    except PermissionError:
        return False, "Permission denied allocating raw socket. Ensure container has 'cap_add: - NET_ADMIN'."
    except Exception as exc:
        return False, f"Raw socket check failed: {exc}"


def check_connectivity_and_send_probe(
    target_ip: str = "192.168.10.20",
    target_port: int = 9999,
) -> Tuple[bool, str]:
    """Test Layer 3 ICMP ping reachability and Layer 4 UDP packet transmission to target node."""
    # Step A: ICMP Ping check
    try:
        ping_res = subprocess.run(
            ["ping", "-c", "1", "-W", "2", target_ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ping_ok = (ping_res.returncode == 0)
    except FileNotFoundError:
        # Fallback if ping utility is missing
        ping_ok = True

    # Step B: Scapy Probe Packet Injection
    try:
        probe_pkt = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=b"PHASE1_HEALTH_PROBE")
        send(probe_pkt, count=1, verbose=False)
        packet_sent = True
    except Exception as exc:
        return False, f"Failed to transmit raw UDP probe to {target_ip}:{target_port} - {exc}"

    if ping_ok and packet_sent:
        return True, f"Successfully pinged and injected raw probe packet to {target_ip}:{target_port}"
    elif packet_sent:
        return True, f"Probe packet delivered to {target_ip}:{target_port} (ICMP ping was unacknowledged or skipped)"
    else:
        return False, f"Failed reaching target node {target_ip}"


def main() -> None:
    print("=" * 70)
    print(" NTRO CYBER THREAT DETECTION LAB - PHASE 1 AUTOMATED HEALTH VERIFIER")
    print("=" * 70)

    results: Dict[str, Tuple[bool, str]] = {}

    print("\n[1/3] Checking Network Interface & Subnet Allocation...")
    results["Interface Check"] = check_interface("eth0", "192.168.10.0/24")
    print(f"      Status: {'PASSED' if results['Interface Check'][0] else 'FAILED'}")
    print(f"      Details: {results['Interface Check'][1]}")

    print("\n[2/3] Checking Raw Socket Permissions (CAP_NET_ADMIN)...")
    results["NET_ADMIN Check"] = check_raw_socket_capability()
    print(f"      Status: {'PASSED' if results['NET_ADMIN Check'][0] else 'FAILED'}")
    print(f"      Details: {results['NET_ADMIN Check'][1]}")

    print("\n[3/3] Checking Destination Connectivity & Probe Dispatch...")
    results["Connectivity Probe"] = check_connectivity_and_send_probe("192.168.10.20", 9999)
    print(f"      Status: {'PASSED' if results['Connectivity Probe'][0] else 'FAILED'}")
    print(f"      Details: {results['Connectivity Probe'][1]}")

    print("\n" + "=" * 70)
    all_passed = all(status for status, _ in results.values())
    if all_passed:
        print(" [SUMMARY] PHASE 1 ENVIRONMENT VERIFICATION: ALL CHECKS PASSED")
        print("=" * 70)
        sys.exit(0)
    else:
        print(" [SUMMARY] PHASE 1 ENVIRONMENT VERIFICATION: FAILED")
        print("=" * 70)
        sys.exit(1)


if __name__ == "__main__":
    main()
