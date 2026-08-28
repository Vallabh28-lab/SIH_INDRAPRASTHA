#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 3: Telemetry Ingestion
Module: test_phase3.py
Description: End-to-end verification script for packet capture, 5-tuple flow aggregation, and feature extraction.
"""

import argparse
import json
import logging
import sys
import time
from flow_aggregator import FlowAggregator
from packet_capture import PacketCaptureEngine

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("TestPhase3CLI")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NTRO Phase 3: End-to-End Packet Capture & Flow Feature Aggregation"
    )
    parser.add_argument(
        "--interface",
        "-i",
        type=str,
        default="eth0",
        help="Network interface to sniff on (default: eth0)",
    )
    parser.add_argument(
        "--target-count",
        "-c",
        type=int,
        default=1000,
        help="Target number of packets to collect before aggregating (default: 1000)",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=int,
        default=15,
        help="Maximum capture window in seconds (default: 15)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of Pandas DataFrame table",
    )

    args = parser.parse_args()

    print("=" * 80)
    print(" NTRO CYBER THREAT DETECTION - PHASE 3 FLOW FEATURE EXTRACTION PIPELINE")
    print("=" * 80)
    print(f"[*] Interface     : {args.interface}")
    print(f"[*] Target Packets: {args.target_count}")
    print(f"[*] Max Timeout   : {args.timeout} seconds")
    print("=" * 80)

    # 1. Initialize Packet Capture Engine
    capture_engine = PacketCaptureEngine(
        interface=args.interface,
        buffer_capacity=max(args.target_count * 2, 10000),
    )

    try:
        capture_engine.start_capture()
    except Exception as exc:
        print(f"[CRITICAL] Could not start packet capture: {exc}")
        sys.exit(1)

    print(f"[*] Sniffer active. Awaiting up to {args.target_count} packets or {args.timeout}s timeout...")

    start_time = time.time()
    try:
        while True:
            buffered_count = capture_engine.get_buffer_size()
            elapsed = time.time() - start_time

            sys.stdout.write(
                f"\r[*] Ingestion Progress: {buffered_count}/{args.target_count} packets collected ({elapsed:.1f}s)"
            )
            sys.stdout.flush()

            if buffered_count >= args.target_count or elapsed >= args.timeout:
                break
            time.sleep(0.2)

    except KeyboardInterrupt:
        print("\n[*] Capture interrupted early by user.")

    print("\n[*] Stopping capture engine and transferring buffer to FlowAggregator...")
    capture_engine.stop_capture()

    # 2. Extract Raw Packet Telemetry
    raw_packets = capture_engine.get_buffered_packets()

    if not raw_packets:
        print("\n[WARNING] No packets were intercepted during the capture window.")
        print("Tip: Transmit traffic from another container (e.g., 'python test_generator.py --profile all')")
        sys.exit(0)

    # 3. Flow Aggregation & Feature Extraction
    aggregator = FlowAggregator(raw_packets=raw_packets)
    flow_records = aggregator.aggregate()
    summary_metrics = aggregator.summary()

    print("\n" + "=" * 80)
    print(" 5-TUPLE FLOW AGGREGATION & STATISTICAL FEATURE VECTORS")
    print("=" * 80)
    print(f"  Total Raw Packets Processed : {summary_metrics['total_raw_packets']}")
    print(f"  Distinct 5-Tuple Flows       : {summary_metrics['unique_flows_count']}")
    print(f"  Total Aggregated Bytes       : {summary_metrics['total_bytes_aggregated']}")
    print(f"  Detected Protocols           : {summary_metrics['detected_protocols']}")
    print("=" * 80)

    if args.json:
        print(json.dumps(flow_records, indent=2))
    else:
        df = aggregator.to_dataframe()
        if hasattr(df, "to_string"):
            # Configure pandas display settings for clean table formatting
            import pandas as pd
            pd.set_option("display.max_columns", 15)
            pd.set_option("display.width", 1000)
            print("\n" + df.to_string(index=False))
        else:
            print(json.dumps(flow_records, indent=2))

    print("\n" + "=" * 80)
    print(" [SUCCESS] PHASE 3 FEATURE EXTRACTION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
