#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 4: Telemetry Transmitter
Module: send_flow.py
Description: Client transmitter script that formats and dispatches synthetic or captured
             aggregated flow records (e.g., SYN Flood, UDP Flood, Port Scan, Normal)
             to the FastAPI Threat Ingestion Gateway (POST /api/traffic).
"""

import argparse
import json
import sys
from typing import Any, Dict
import requests

DEFAULT_URL = "http://192.168.10.10:8000/api/traffic"
FALLBACK_URL = "http://127.0.0.1:8000/api/traffic"

SAMPLE_PROFILES: Dict[str, Dict[str, Any]] = {
    "syn_flood": {
        "source_ip": "192.168.10.10",
        "destination_ip": "10.0.20.10",
        "protocol": "TCP",
        "packet_count": 1000,
        "total_bytes": 1200000,
        "packets_per_second": 500.0,
        "bytes_per_second": 600000.0,
        "iat_mean": 0.002,
        "syn_count": 1000,
        "ack_count": 0,
    },
    "udp_flood": {
        "source_ip": "198.51.100.45",
        "destination_ip": "10.0.20.10",
        "protocol": "UDP",
        "packet_count": 800,
        "total_bytes": 819200,
        "packets_per_second": 400.0,
        "bytes_per_second": 409600.0,
        "iat_mean": 0.0025,
        "syn_count": 0,
        "ack_count": 0,
    },
    "port_scan": {
        "source_ip": "172.16.5.99",
        "destination_ip": "10.0.20.10",
        "protocol": "TCP",
        "packet_count": 3,
        "total_bytes": 180,
        "packets_per_second": 300.0,
        "bytes_per_second": 18000.0,
        "iat_mean": 0.0033,
        "syn_count": 3,
        "ack_count": 0,
    },
    "normal": {
        "source_ip": "192.168.10.15",
        "destination_ip": "10.0.20.10",
        "protocol": "TCP",
        "packet_count": 50,
        "total_bytes": 28000,
        "packets_per_second": 10.0,
        "bytes_per_second": 5600.0,
        "iat_mean": 0.100,
        "syn_count": 2,
        "ack_count": 48,
    },
}


def dispatch_flow_telemetry(target_url: str = DEFAULT_URL, attack_type: str = "syn_flood") -> None:
    """
    Format flow payload and dispatch POST HTTP request to FastAPI Gateway.
    """
    flow_payload = SAMPLE_PROFILES.get(attack_type.lower(), SAMPLE_PROFILES["syn_flood"])
    headers = {"Content-Type": "application/json"}

    print("=" * 80)
    print(" NTRO CYBER THREAT DETECTION - FLOW TELEMETRY TRANSMITTER")
    print("=" * 80)
    print(f"[*] Target Endpoint : {target_url}")
    print(f"[*] Payload Type    : {attack_type.upper()}")
    print(f"[*] Flow 5-Tuple    : {flow_payload['source_ip']} -> {flow_payload['destination_ip']} ({flow_payload['protocol']})")
    print(f"[*] Flow Metrics    : Packets={flow_payload['packet_count']}, SYN={flow_payload['syn_count']}, ACK={flow_payload['ack_count']}, PPS={flow_payload['packets_per_second']}")
    print("-" * 80)

    try:
        response = requests.post(target_url, json=flow_payload, headers=headers, timeout=5)
        _handle_response(response)
    except requests.exceptions.ConnectionError:
        # If default IP is unreachable, try fallback to 127.0.0.1 for local execution
        if target_url == DEFAULT_URL:
            print(f"[!] Unable to reach {target_url}. Attempting local gateway at {FALLBACK_URL}...")
            try:
                response = requests.post(FALLBACK_URL, json=flow_payload, headers=headers, timeout=5)
                _handle_response(response)
                return
            except requests.exceptions.ConnectionError:
                pass
        print(f"[ERROR] Could not connect to the FastAPI gateway at {target_url}.")
        print("        Ensure the API server is running (e.g. 'python api.py' or 'uvicorn api:app').")
    except Exception as exc:
        print(f"[ERROR] Unexpected request error: {exc}")


def _handle_response(response: requests.Response) -> None:
    """Print formatted API response and threat intelligence breakdown."""
    if response.status_code == 201:
        data = response.json()
        print("\n[SUCCESS] Flow telemetry accepted and evaluated by backend (HTTP 201):")
        print("=" * 80)
        print(f" Threat Classification : {data.get('prediction')} (Confidence: {float(data.get('confidence', 0))*100:.1f}%)")
        print(f" Anomaly Score (IF)    : {data.get('anomaly_score')} (Rating: 0.00 to 1.00)")
        print(f" Security Status       : {'[ALERT: MALICIOUS]' if data.get('is_malicious') else '[STATUS: BENIGN]'}")
        
        print("\nExplainable AI (XAI) Justifications:")
        for reason in data.get("xai_explanations", []):
            print(f"   {reason}")

        print("\nThreat Intelligence Context:")
        src_intel = data.get("threat_intel", {}).get("source_ip", {})
        print(f"   Source ASN      : {src_intel.get('asn')}")
        print(f"   Organization    : {src_intel.get('organization')}")
        print(f"   Geo Location    : {src_intel.get('city')}, {src_intel.get('country')}")
        print(f"   Reputation Score: {src_intel.get('reputation_score')}/100 [Risk: {src_intel.get('risk_level')}]")
        print(f"   Threat Tags     : {', '.join(src_intel.get('threat_tags', []))}")
        print("=" * 80)
    else:
        print(f"\n[FAILED] Server responded with status {response.status_code}: {response.text}")


def main() -> None:
    parser = argparse.ArgumentParser(description="NTRO Flow Telemetry Transmitter Client")
    parser.add_argument(
        "--url",
        "-u",
        type=str,
        default=DEFAULT_URL,
        help=f"Target FastAPI gateway URL (default: {DEFAULT_URL})",
    )
    parser.add_argument(
        "--type",
        "-t",
        type=str,
        choices=["syn_flood", "udp_flood", "port_scan", "normal"],
        default="syn_flood",
        help="Type of flow profile to transmit (default: syn_flood)",
    )
    args = parser.parse_args()
    dispatch_flow_telemetry(target_url=args.url, attack_type=args.type)


if __name__ == "__main__":
    main()
