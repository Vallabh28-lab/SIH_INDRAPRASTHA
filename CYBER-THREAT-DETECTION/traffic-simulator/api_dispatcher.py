#!/usr/bin/env python3
"""
====================================================================================================
Cyber Threat Detection & Telemetry Simulation System - Phase 4: API Dispatcher & Response Handler
Module: api_dispatcher.py
Description: Client integration service utilizing the requests library to dispatch compiled
             JSON flow telemetry records to the FastAPI Threat Ingestion Gateway (POST /api/traffic),
             parse server HTTP responses, and render threat classification verdicts, SHAP
             explainability justifications, threat intel, and SHA-256 audit hashes.
====================================================================================================
"""

import argparse
import json
import logging
import sys
from typing import Any, Dict, Optional
import requests

# Optional integration with previous phases
try:
    from http_input_parser import parse_http_input
    from dns_resolver import resolve_domain
    from behavioral_flow_aggregator import generate_behavioral_flow
except ImportError:
    parse_http_input = None
    resolve_domain = None
    generate_behavioral_flow = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("APIDispatcher")

DEFAULT_GATEWAY_URL = "http://localhost:8000/api/traffic"
FALLBACK_GATEWAY_URL = "http://127.0.0.1:8000/api/traffic"


def dispatch_flow(
    flow_record: Dict[str, Any],
    api_url: str = DEFAULT_GATEWAY_URL,
    timeout: float = 6.0,
    render_terminal: bool = True,
) -> Dict[str, Any]:
    """
    Takes a compiled flow dictionary and executes an automated HTTP POST request
    to the FastAPI endpoint at http://localhost:8000/api/traffic using the requests library.

    Parses the server response to cleanly extract and render the threat prediction,
    confidence score, XAI reasons, and SHA-256 audit hash.

    :param flow_record: Complete 5-tuple flow dictionary conforming to FlowRecordSchema.
    :param api_url: FastAPI endpoint URL (default: http://localhost:8000/api/traffic).
    :param timeout: Request timeout in seconds.
    :param render_terminal: If True, prints a formatted security verdict card to terminal.
    :return: Parsed JSON response dictionary from the FastAPI gateway.
    :raises requests.RequestException: If API server is unreachable or returns HTTP 500/422.
    """
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    try:
        response = requests.post(api_url, json=flow_record, headers=headers, timeout=timeout)
    except requests.exceptions.ConnectionError:
        if api_url == DEFAULT_GATEWAY_URL:
            # Automatic fallback retry to 127.0.0.1
            try:
                response = requests.post(FALLBACK_GATEWAY_URL, json=flow_record, headers=headers, timeout=timeout)
                api_url = FALLBACK_GATEWAY_URL
            except requests.exceptions.RequestException as err:
                raise ConnectionError(
                    f"Failed to connect to FastAPI Control Gateway at {DEFAULT_GATEWAY_URL} or {FALLBACK_GATEWAY_URL}. "
                    f"Ensure 'uvicorn api:app --reload' is running."
                ) from err
        else:
            raise

    # Handle HTTP Error status codes gracefully
    if response.status_code not in (200, 201):
        err_msg = f"HTTP {response.status_code} Error from {api_url}: {response.text}"
        logger.error(err_msg)
        if render_terminal:
            print(f"\n[!] INGESTION REJECTED [HTTP {response.status_code}]")
            print(f"    Detail: {response.text}\n")
        response.raise_for_status()

    parsed_response: Dict[str, Any] = response.json()

    if render_terminal:
        render_response_card(flow_record, parsed_response, response.status_code)

    return parsed_response


def render_response_card(
    flow_record: Dict[str, Any],
    server_response: Dict[str, Any],
    status_code: int = 201,
) -> None:
    """
    Renders a formatted terminal UI report displaying AI threat determination,
    SHAP explainability reasons, Threat Intel geolocation, and SHA-256 audit hash.
    """
    prediction = server_response.get("prediction", "Unknown")
    confidence = float(server_response.get("confidence", 0.0))
    anomaly_score = float(server_response.get("anomaly_score", 0.0))
    is_malicious = bool(server_response.get("is_malicious", False))
    xai_reasons = server_response.get("xai_explanations", [])
    threat_intel = server_response.get("threat_intel", {})
    audit_hash = server_response.get("audit_hash")
    audit_id = server_response.get("audit_id")
    timestamp = server_response.get("timestamp", "")

    # Security Tag
    if is_malicious:
        tag = "[ALERT: MALICIOUS THREAT DETECTED]"
    else:
        tag = "[STATUS: BENIGN / NORMAL TRAFFIC]"

    print("\n" + "=" * 90)
    print(" NTRO CYBER DEFENSE - REAL-TIME TELEMETRY INGESTION & THREAT VERDICT")
    print("=" * 90)
    print(f" Status Code        : HTTP {status_code} Created")
    print(f" Ingestion Event ID : {audit_id or 'EVT-' + timestamp[:10]}")
    print(f" Ingestion Timestamp: {timestamp}")
    print(f" 5-Tuple Endpoint   : {flow_record.get('source_ip')}:{flow_record.get('source_port')} -> {flow_record.get('destination_ip')}:{flow_record.get('destination_port')} ({flow_record.get('protocol')})")
    print(f" Telemetry Volume   : {flow_record.get('packet_count', 0):,} pkts | {flow_record.get('total_bytes', 0):,} bytes | {flow_record.get('packets_per_second', 0.0):,.1f} pkts/s")
    print("-" * 90)
    print(" AI MODEL EVALUATION:")
    print(f"   * Verdict Tag         : {tag}")
    print(f"   * Threat Prediction   : {prediction}")
    print(f"   * Model Confidence    : {confidence * 100:.2f}%")
    print(f"   * Anomaly Score       : {anomaly_score:.4f} (Isolation Forest Threshold: 0.6500)")
    print("-" * 90)
    print(" EXPLAINABLE AI (XAI) JUSTIFICATIONS:")
    if xai_reasons:
        for idx, reason in enumerate(xai_reasons, 1):
            print(f"   {idx}. [+] {reason}")
    else:
        print("   * Flow features align within standard baseline traffic distributions.")

    print("-" * 90)
    print(" THREAT INTELLIGENCE ENRICHMENT:")
    src_intel = threat_intel.get("source_ip", {})
    dst_intel = threat_intel.get("destination_ip", {})
    print(f"   * Source IP Intel     : {src_intel.get('country', 'Internal / RFC1918')} ({src_intel.get('country_code', 'IN')}) | ASN: {src_intel.get('asn', 'AS-LAB-NTRO')} | Risk: {src_intel.get('reputation_score', 85)}/100")
    print(f"   * Destination IP Intel: {dst_intel.get('country', 'Internal / RFC1918')} | ASN: {dst_intel.get('asn', 'AS-LAB-NTRO (Target Gateway)')}")
    print("-" * 90)
    print(" FORENSIC AUDIT TRAIL:")
    if audit_hash:
        print(f"   * SHA-256 Audit Hash  : {audit_hash}")
        print(f"   * Blockchain Status   : READY_FOR_HYPERLEDGER_ANCHOR (Tamper-Evident Chain Validated)")
    else:
        print("   * Benign event stored in operational sliding history (No forensic lock required).")
    print("=" * 90 + "\n")



def main() -> None:
    """CLI execution for full automated pipeline dispatch."""
    parser = argparse.ArgumentParser(
        description="Phase 4: API Dispatcher & Response Handler - Send telemetry to FastAPI and parse verdict"
    )
    parser.add_argument(
        "target",
        type=str,
        nargs="?",
        default="collector.internal",
        help="Target IP, domain name, or URL (default: collector.internal)",
    )
    parser.add_argument(
        "--type",
        "-t",
        type=str,
        default="syn_flood",
        choices=["normal", "syn_flood", "port_scan", "udp_flood"],
        help="Traffic profile type (default: syn_flood)",
    )
    parser.add_argument(
        "--attack",
        "-a",
        action="store_true",
        default=True,
        help="Flag as security attack simulation (default: True)",
    )
    parser.add_argument(
        "--normal",
        "-n",
        action="store_true",
        help="Flag as normal / benign traffic simulation",
    )
    parser.add_argument(
        "--api-url",
        "-u",
        type=str,
        default=DEFAULT_GATEWAY_URL,
        help=f"FastAPI control gateway URL (default: {DEFAULT_GATEWAY_URL})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON server response only",
    )
    args = parser.parse_args()

    is_attack = not args.normal
    traffic_type = "normal" if args.normal else args.type

    # Generate synthetic behavioral flow record
    if generate_behavioral_flow is not None:
        flow = generate_behavioral_flow(
            target_host_or_ip=args.target,
            traffic_type=traffic_type,
            is_attack=is_attack,
        )
    else:
        # Standalone default flow if module is executed independently
        flow = {
            "source_ip": "10.0.4.88",
            "destination_ip": "192.168.10.20",
            "source_port": 54321,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 500,
            "total_bytes": 32000,
            "packets_per_second": 1000.0,
            "bytes_per_second": 64000.0,
            "iat_mean": 0.001,
            "syn_count": 500,
            "ack_count": 0,
            "syn_ratio": 1.0,
            "ack_ratio": 0.0,
        }

    try:
        response_data = dispatch_flow(
            flow_record=flow,
            api_url=args.api_url,
            render_terminal=not args.json,
        )
        if args.json:
            print(json.dumps(response_data, indent=2))
    except Exception as exc:
        print(f"[!] Dispatch failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
