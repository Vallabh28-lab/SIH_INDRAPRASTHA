#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection Prototype
Phase 1: Controlled Traffic Environment - Packet Generation & Listening Tool
"""

import argparse
import sys
from typing import Optional

try:
    # pyrefly: ignore [missing-import]
    from scapy.all import IP, TCP, UDP, Raw, conf, get_if_list, send, sniff
except ImportError:
    print(
        "[ERROR] Scapy is not installed. Please install dependencies using 'pip install -r requirements.txt'."
    )
    sys.exit(1)


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for sender and listener modes."""
    parser = argparse.ArgumentParser(
        description="NTRO Cyber Threat Detection - Traffic Simulator & Connectivity Verifier"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Mode of operation: 'listen' (packet capture) or 'send' (packet transmission)",
    )

    # Sub-parser for listening mode
    listen_parser = subparsers.add_parser(
        "listen", help="Listen and sniff incoming packets on a specified interface and port"
    )
    listen_parser.add_argument(
        "--interface",
        "-i",
        type=str,
        default="eth0",
        help="Network interface to bind and sniff on (default: eth0)",
    )
    listen_parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=9999,
        help="Port to filter and listen on (default: 9999)",
    )
    listen_parser.add_argument(
        "--protocol",
        type=str,
        choices=["udp", "tcp", "ip"],
        default="udp",
        help="Protocol filter: 'udp', 'tcp', or 'ip' (default: udp)",
    )
    listen_parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=0,
        help="Number of matching packets to capture before exiting (0 = infinite, default: 0)",
    )

    # Sub-parser for sending mode
    send_parser = subparsers.add_parser(
        "send", help="Craft and send raw Layer 3 / Layer 4 UDP or TCP test packets"
    )
    send_parser.add_argument(
        "--dst",
        "-d",
        type=str,
        default="192.168.10.20",
        help="Destination IPv4 address (default: 192.168.10.20)",
    )
    send_parser.add_argument(
        "--src",
        "-s",
        type=str,
        default=None,
        help="Optional spoofed/explicit Source IPv4 address (default: auto-assigned by interface)",
    )
    send_parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=9999,
        help="Destination port (default: 9999)",
    )
    send_parser.add_argument(
        "--protocol",
        type=str,
        choices=["UDP", "TCP", "udp", "tcp"],
        default="UDP",
        help="Transport protocol: 'UDP' or 'TCP' (default: UDP)",
    )
    send_parser.add_argument(
        "--payload",
        type=str,
        default="NTRO_PHASE1_TEST",
        help="Payload string to transmit (default: 'NTRO_PHASE1_TEST')",
    )
    send_parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=1,
        help="Number of packets to send (default: 1)",
    )
    send_parser.add_argument(
        "--interval",
        type=float,
        default=0.1,
        help="Interval in seconds between packets if count > 1 (default: 0.1)",
    )

    return parser.parse_args()


def packet_handler(pkt) -> None:
    """Callback function executed on every captured packet matching the BPF filter."""
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto_name = "IP"
        src_port = "?"
        dst_port = "?"

        if UDP in pkt:
            proto_name = "UDP"
            src_port = str(pkt[UDP].sport)
            dst_port = str(pkt[UDP].dport)
        elif TCP in pkt:
            proto_name = "TCP"
            src_port = str(pkt[TCP].sport)
            dst_port = str(pkt[TCP].dport)

        # Extract payload if Raw layer exists
        if Raw in pkt:
            payload = pkt[Raw].load
            try:
                decoded_payload = payload.decode("utf-8")
            except UnicodeDecodeError:
                decoded_payload = repr(payload)
        else:
            decoded_payload = "<EMPTY_PAYLOAD>"

        print(
            f"[SUCCESS] Captured {proto_name} packet from {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Payload: {decoded_payload}"
        )
        sys.stdout.flush()


def run_listener(interface: str, port: int, protocol: str, count: int) -> None:
    """Start sniffing traffic on the specified network interface, protocol, and port."""
    print(f"[*] Initializing Listener on Interface '{interface}', Protocol '{protocol.upper()}', Port {port}...")

    available_interfaces = get_if_list()
    if interface not in available_interfaces:
        print(
            f"[WARNING] Interface '{interface}' not explicitly found in available interfaces: {available_interfaces}"
        )
        print("[*] Proceeding with standard socket binding...")

    if protocol.lower() == "ip":
        bpf_filter = f"ip and port {port}"
    else:
        bpf_filter = f"{protocol.lower()} and port {port}"

    print(f"[*] BPF Filter active: '{bpf_filter}'")
    print("[*] Awaiting incoming unidirectional traffic (Press Ctrl+C to terminate)...\n")

    try:
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=packet_handler,
            count=count,
            store=0,
        )
    except KeyboardInterrupt:
        print("\n[*] Listener terminated by user.")
    except PermissionError:
        print(
            "\n[ERROR] Permission denied: Raw socket sniffing requires root / CAP_NET_ADMIN privileges."
        )
        sys.exit(1)
    except Exception as exc:
        print(f"\n[ERROR] Failed to start sniffer: {exc}")
        sys.exit(1)


def run_sender(
    dst_ip: str,
    src_ip: Optional[str],
    dst_port: int,
    protocol: str,
    payload_str: str,
    count: int,
    interval: float,
) -> None:
    """Construct and transmit raw L3/L4 packets using Scapy."""
    payload_bytes = payload_str.encode("utf-8")
    proto_upper = protocol.upper()

    # Construct Layer 3 IP layer
    if src_ip:
        ip_layer = IP(src=src_ip, dst=dst_ip)
        print(f"[*] Crafting custom IP layer (Source: {src_ip} -> Destination: {dst_ip})")
    else:
        ip_layer = IP(dst=dst_ip)
        print(f"[*] Crafting standard IP layer (Destination: {dst_ip})")

    # Construct Layer 4 Transport layer
    if proto_upper == "UDP":
        transport_layer = UDP(dport=dst_port)
    elif proto_upper == "TCP":
        transport_layer = TCP(dport=dst_port, flags="S")
    else:
        print(f"[ERROR] Unsupported protocol: {protocol}")
        sys.exit(1)

    raw_layer = Raw(load=payload_bytes)
    packet = ip_layer / transport_layer / raw_layer

    print(f"[*] Protocol        : {proto_upper}")
    print(f"[*] Target Endpoint : {dst_ip}:{dst_port}")
    print(f"[*] Raw Payload     : {payload_bytes} ({len(payload_bytes)} bytes)")
    print(f"[*] Packet Count    : {count} (Interval: {interval}s)")
    print("[*] Transmitting packet(s)...")

    try:
        send(packet, count=count, inter=interval, verbose=False)
        print(f"[SUCCESS] Transmitted {count} {proto_upper} packet(s) successfully to {dst_ip}:{dst_port}.")
    except PermissionError:
        print(
            "\n[ERROR] Permission denied: Raw packet injection requires root / CAP_NET_ADMIN privileges."
        )
        sys.exit(1)
    except Exception as exc:
        print(f"\n[ERROR] Packet transmission failed: {exc}")
        sys.exit(1)


def main() -> None:
    args = parse_arguments()

    if args.command == "listen":
        run_listener(
            interface=args.interface,
            port=args.port,
            protocol=args.protocol,
            count=args.count,
        )
    elif args.command == "send":
        run_sender(
            dst_ip=args.dst,
            src_ip=args.src,
            dst_port=args.port,
            protocol=args.protocol,
            payload_str=args.payload,
            count=args.count,
            interval=args.interval,
        )
    else:
        print("[ERROR] Invalid command mode specified.")
        sys.exit(1)


if __name__ == "__main__":
    main()
