#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 3: Telemetry Ingestion
Module: test_capture.py
Description: Standalone CLI verification script for continuous packet capture and buffer inspection.
"""

import argparse
from collections import Counter
import json
import logging
import sys
import time
from packet_capture import PacketCaptureEngine

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("TestCaptureCLI")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NTRO Phase 3: Test Packet Capture Engine & Sliding Buffer"
    )
    parser.add_argument(
        "--interface",
        "-i",
        type=str,
        default="eth0",
        help="Network interface to sniff on (default: eth0)",
    )
    parser.add_argument(
        "--duration",
        "-d",
        type=int,
        default=10,
        help="Capture duration in seconds (default: 10)",
    )
    parser.add_argument(
        "--filter",
        "-f",
        type=str,
        default=None,
        help="Optional BPF filter (e.g. 'tcp or udp')",
    )
    parser.add_argument(
        "--buffer-size",
        type=int,
        default=10000,
        help="Maximum buffer capacity (default: 10000)",
    )
    parser.add_argument(
        "--preview-limit",
        "-l",
        type=int,
        default=5,
        help="Number of sample packet records to preview in output (default: 5)",
    )

    args = parser.parse_args()

    engine = PacketCaptureEngine(
        interface=args.interface,
        buffer_capacity=args.buffer_size,
        bpf_filter=args.filter,
    )

    print("=" * 70)
    print(" NTRO CYBER THREAT DETECTION - PACKET CAPTURE & BUFFER TEST")
    print("=" * 70)
    print(f"[*] Interface       : {args.interface}")
    print(f"[*] Capture Duration: {args.duration} seconds")
    print(f"[*] BPF Filter      : {args.filter or 'All IP Traffic'}")
    print(f"[*] Buffer Capacity : {args.buffer_size} frames")
    print("=" * 70)

    try:
        engine.start_capture()
    except Exception as exc:
        print(f"[CRITICAL] Could not start packet capture: {exc}")
        sys.exit(1)

    print(f"[*] Sniffer actively running. Waiting {args.duration}s for incoming frames...")

    start_t = time.time()
    try:
        while time.time() - start_t < args.duration:
            time.sleep(0.5)
            sys.stdout.write(
                f"\r[*] Capturing... Elapsed: {int(time.time() - start_t)}s | Buffered: {engine.get_buffer_size()} packets"
            )
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted early by user.")

    print("\n\n[*] Stopping capture engine and processing buffer...")
    stop_summary = engine.stop_capture()

    # Extract all buffered packets
    buffered_packets = engine.get_buffered_packets()

    # Compute protocol distribution
    proto_counter = Counter(p["protocol"] for p in buffered_packets)
    src_ip_counter = Counter(p["src_ip"] for p in buffered_packets)

    preview_records = buffered_packets[: args.preview_limit]

    output_report = {
        "capture_session_summary": stop_summary,
        "telemetry_metrics": {
            "total_buffered_records": len(buffered_packets),
            "protocol_distribution": dict(proto_counter),
            "top_source_ips": dict(src_ip_counter.most_common(5)),
        },
        f"first_{len(preview_records)}_packet_preview": preview_records,
    }

    print("\n" + "=" * 70)
    print(" INGESTION & BUFFER TELEMETRY REPORT")
    print("=" * 70)
    print(json.dumps(output_report, indent=2))
    print("=" * 70)


if __name__ == "__main__":
    main()
