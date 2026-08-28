#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 6: System Orchestrator
Module: run_system.py
Description: Master orchestrator script that:
             1. Launches detection_daemon.py in a background daemon thread.
             2. Triggers realistic multi-class traffic bursts (Normal, SYN Flood, Port Scan, UDP Flood)
                to populate telemetry and trigger live XAI-attributed security incidents.
             3. Launches the interactive SOC Visual Dashboard (Streamlit / Native SOC Server).
"""

import argparse
import logging
import os
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List

from dataset_generator import DatasetGenerator
from detection_daemon import DetectionDaemon

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("SystemOrchestrator")


def launch_traffic_generator(daemon: DetectionDaemon) -> None:
    """Generate realistic initial traffic bursts to populate telemetry and security incidents."""
    logger.info("Initializing multi-class traffic stream generation...")
    generator = DatasetGenerator(random_seed=42, noise_level=0.15)
    time.sleep(1.0)

    # 1. Normal Web Session
    logger.info("Injecting Normal Web Application Session...")
    pkts_normal = generator._generate_normal_packets("192.168.10.15", "192.168.10.20", 52340, 443, time.time())
    daemon.inject_packets(pkts_normal)
    time.sleep(2.0)

    # 2. SYN Flood Burst
    logger.info("Injecting High-Velocity TCP SYN Flood Attack...")
    pkts_syn = generator._generate_syn_flood_packets("10.0.99.55", "192.168.10.20", 49152, 80, time.time())
    daemon.inject_packets(pkts_syn)
    time.sleep(2.0)

    # 3. Port Scan Reconnaissance Sweep
    logger.info("Injecting Port Sweep Reconnaissance Probes...")
    pkts_scan = generator._generate_port_scan_packets("172.16.4.12", "192.168.10.20", 59000, [21, 22, 23, 25, 80, 443, 8080], time.time())
    daemon.inject_packets(pkts_scan)
    time.sleep(2.0)

    # 4. Volumetric UDP Flood Burst
    logger.info("Injecting High-Volume UDP Flood Burst...")
    pkts_udp = generator._generate_udp_flood_packets("198.51.100.88", "192.168.10.20", 44550, 9999, time.time())
    daemon.inject_packets(pkts_udp)

    logger.info("Traffic generation bursts completed successfully.")


def launch_dashboard(port: int = 8501) -> None:
    """Launch the SOC Visual Dashboard (Streamlit if installed, otherwise standalone server)."""
    # Check if streamlit executable exists
    try:
        import streamlit
        has_streamlit = True
    except ImportError:
        has_streamlit = False

    if has_streamlit:
        logger.info("Launching Streamlit SOC Dashboard on port %d...", port)
        cmd = [sys.executable, "-m", "streamlit", "run", "dashboard.py", "--server.port", str(port), "--server.headless", "true"]
        subprocess.run(cmd)
    else:
        logger.info("Launching Standalone SOC Visual Dashboard Server on http://localhost:%d...", port)
        from dashboard import run_standalone_dashboard
        run_standalone_dashboard(port=port)


def main() -> None:
    parser = argparse.ArgumentParser(description="NTRO Phase 6: Full Cyber Threat Detection System Orchestrator")
    parser.add_argument("--interface", "-i", type=str, default="eth0", help="Sniffer interface (default: eth0)")
    parser.add_argument("--window", "-w", type=float, default=3.0, help="Sliding window seconds (default: 3.0)")
    parser.add_argument("--port", "-p", type=int, default=8501, help="Dashboard port (default: 8501)")
    parser.add_argument("--skip-traffic", action="store_true", help="Skip initial test traffic burst injection")

    args = parser.parse_args()

    print("=" * 90)
    print(" NTRO CYBER THREAT DETECTION SYSTEM - PHASE 6 SOC ORCHESTRATOR")
    print("=" * 90)

    # 1. Start Detection Daemon
    logger.info("Starting Detection Daemon with real-time XAI and Incident Aggregation...")
    daemon = DetectionDaemon(
        interface=args.interface,
        window_seconds=args.window,
        model_dir="models",
        alert_log_file="logs/alerts.json",
    )
    daemon.start()

    # 2. Inject initial traffic bursts in background thread
    if not args.skip_traffic:
        traffic_thread = threading.Thread(target=launch_traffic_generator, args=(daemon,), daemon=True)
        traffic_thread.start()

    # 3. Launch Dashboard (blocking)
    try:
        launch_dashboard(port=args.port)
    except KeyboardInterrupt:
        print("\n[!] Shutting down system orchestrator...")
    finally:
        daemon.stop()
        print("[*] NTRO Threat Detection System stopped cleanly.")


if __name__ == "__main__":
    main()
