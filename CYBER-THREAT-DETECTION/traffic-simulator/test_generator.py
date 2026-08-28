#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 2: Traffic Generator Engine
Module: test_generator.py
Description: Standalone CLI testing harness to trigger and meter traffic profiles.
"""

import argparse
import json
import logging
import sys
from traffic_profiles import (
    generate_high_velocity_tcp,
    generate_high_volume_udp,
    generate_normal_traffic,
    generate_port_sweep,
)

logger = logging.getLogger("TestGeneratorCLI")


def format_metrics_table(metrics: dict) -> str:
    """Format execution metrics dictionary into an aligned summary table."""
    lines = [
        "",
        "=" * 60,
        f" TRAFFIC EXECUTION TELEMETRY REPORT - PROFILE COMPLETED",
        "=" * 60,
    ]
    for key, value in metrics.items():
        key_formatted = key.replace("_", " ").title()
        lines.append(f"  {key_formatted:<28} : {value}")
    lines.append("=" * 60)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NTRO Phase 2: Traffic Generation Profile Testing Harness"
    )
    parser.add_argument(
        "--profile",
        "-p",
        type=str,
        choices=["normal", "high_velocity_tcp", "port_sweep", "high_volume_udp", "all"],
        default="normal",
        help="Traffic profile to execute (default: normal)",
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
        "--count",
        "-c",
        type=int,
        default=None,
        help="Override packet count for selected profile",
    )
    parser.add_argument(
        "--iat",
        type=float,
        default=None,
        help="Override inter-arrival time in seconds",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON metrics instead of formatted table",
    )

    args = parser.parse_args()

    profiles_to_run = []
    if args.profile == "all":
        profiles_to_run = ["normal", "high_velocity_tcp", "port_sweep", "high_volume_udp"]
    else:
        profiles_to_run = [args.profile]

    for prof in profiles_to_run:
        logger.info(">>> Launching Profile: '%s' <<<", prof)
        metrics = {}

        if prof == "normal":
            kwargs = {"source_ip": args.src, "destination_ip": args.dst}
            if args.count:
                kwargs["packet_count"] = args.count
            if args.iat is not None:
                kwargs["iat"] = args.iat
            metrics = generate_normal_traffic(**kwargs)

        elif prof == "high_velocity_tcp":
            kwargs = {"source_ip": args.src, "destination_ip": args.dst}
            if args.count:
                kwargs["packet_count"] = args.count
            if args.iat is not None:
                kwargs["iat"] = args.iat
            metrics = generate_high_velocity_tcp(**kwargs)

        elif prof == "port_sweep":
            kwargs = {"source_ip": args.src, "destination_ip": args.dst}
            if args.iat is not None:
                kwargs["iat"] = args.iat
            metrics = generate_port_sweep(**kwargs)

        elif prof == "high_volume_udp":
            kwargs = {"source_ip": args.src, "destination_ip": args.dst}
            if args.count:
                kwargs["packet_count"] = args.count
            if args.iat is not None:
                kwargs["iat"] = args.iat
            metrics = generate_high_volume_udp(**kwargs)

        if args.json:
            print(json.dumps(metrics, indent=2))
        else:
            print(format_metrics_table(metrics))


if __name__ == "__main__":
    main()
