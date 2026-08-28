#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 2: Traffic Gateway
Module: test_api_phase2.py
Description: Automated test client to trigger asynchronous traffic profiles and poll telemetry status.
"""

import argparse
import json
import sys
import time
import requests


def test_api_gateway(base_url: str = "http://127.0.0.1:8000") -> None:
    print("=" * 70)
    print(f" TESTING PHASE 2 FASTAPI TRAFFIC CONTROL GATEWAY ({base_url})")
    print("=" * 70)

    # 1. Verify /health
    health_url = f"{base_url}/health"
    print(f"\n[*] Step 1: Checking API Gateway Health at {health_url}...")
    try:
        resp = requests.get(health_url, timeout=5)
        resp.raise_for_status()
        print(f"[SUCCESS] Gateway is online: {resp.json()}")
    except Exception as exc:
        print(f"[ERROR] Failed to reach API Gateway: {exc}")
        print("Ensure the FastAPI server is running (e.g. 'python api.py' or uvicorn).")
        sys.exit(1)

    # 2. Trigger Profile Traffic Job (high_velocity_tcp)
    profile_url = f"{base_url}/api/v1/traffic/profile"
    payload = {
        "profile_name": "high_velocity_tcp",
        "source_ip": "192.168.10.10",
        "destination_ip": "192.168.10.20",
        "packet_count": 100,
        "iat": 0.005,
    }
    print(f"\n[*] Step 2: Triggering Profile 'high_velocity_tcp' via {profile_url}...")
    print(f"    Payload: {json.dumps(payload, indent=2)}")

    try:
        resp = requests.post(profile_url, json=payload, timeout=5)
        resp.raise_for_status()
        queued_data = resp.json()
        job_id = queued_data.get("job_id")
        print(f"[SUCCESS] Job queued successfully. Job ID: {job_id}")
    except Exception as exc:
        print(f"[ERROR] Failed to queue profile job: {exc}")
        sys.exit(1)

    # 3. Poll Job Status until Completion
    status_url = f"{base_url}/api/v1/traffic/status/{job_id}"
    print(f"\n[*] Step 3: Polling Job Status at {status_url}...")

    max_retries = 30
    poll_interval = 0.5
    final_data = None

    for attempt in range(1, max_retries + 1):
        try:
            status_resp = requests.get(status_url, timeout=5)
            status_resp.raise_for_status()
            job_status = status_resp.json()
            current_state = job_status.get("status")

            print(f"    [Poll #{attempt}] Current Status: '{current_state}'")

            if current_state in ("completed", "failed"):
                final_data = job_status
                break

            time.sleep(poll_interval)
        except Exception as exc:
            print(f"[WARNING] Polling error on attempt {attempt}: {exc}")
            time.sleep(poll_interval)

    # 4. Validate and Output Results
    print("\n" + "=" * 70)
    if final_data and final_data.get("status") == "completed":
        print(" [SUMMARY] PHASE 2 ASYNC TRAFFIC DISPATCH: TEST PASSED")
        print("=" * 70)
        print("\nFinal Telemetry Report:")
        print(json.dumps(final_data, indent=2))
        sys.exit(0)
    else:
        print(" [SUMMARY] PHASE 2 ASYNC TRAFFIC DISPATCH: TEST FAILED")
        print("=" * 70)
        if final_data:
            print(json.dumps(final_data, indent=2))
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Test FastAPI Phase 2 Traffic Gateway")
    parser.add_argument(
        "--host",
        type=str,
        default="http://127.0.0.1:8000",
        help="Base URL of the FastAPI gateway (default: http://127.0.0.1:8000)",
    )
    args = parser.parse_args()
    test_api_gateway(base_url=args.host.rstrip("/"))


if __name__ == "__main__":
    main()
