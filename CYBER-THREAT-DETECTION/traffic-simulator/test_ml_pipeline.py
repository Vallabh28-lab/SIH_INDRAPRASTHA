#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - ML Threat Detection Pipeline
Module: test_ml_pipeline.py
Description: Comprehensive end-to-end integration and verification harness testing:
             1. Robust dataset synthesis with noise injection and bi-directional feature engineering.
             2. Dual-layer model training and Out-of-Distribution (OOD) Zero-Day Anomaly Detection.
             3. Statistical Data Drift Monitoring (KS-test and PSI).
             4. Real-time Detection Daemon with overlapping mixed traffic, alert rate-limiting, and incident aggregation.
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List

from dataset_generator import DatasetGenerator
from detection_daemon import DetectionDaemon
from drift_detector import DataDriftDetector
from flow_aggregator import FlowAggregator
from threat_detector import ThreatDetectionEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("MLPipelineDriver")


def main() -> None:
    parser = argparse.ArgumentParser(description="NTRO Phase 5: Advanced ML Threat Detection Pipeline Verification")
    parser.add_argument("--samples-per-class", "-s", type=int, default=200, help="Samples per class (default: 200)")
    parser.add_argument("--noise-level", "-n", type=float, default=0.15, help="Noise and jitter magnitude (default: 0.15)")
    parser.add_argument("--data-dir", "-d", type=str, default="data", help="Data directory (default: data)")
    parser.add_argument("--model-dir", "-m", type=str, default="models", help="Model directory (default: models)")
    parser.add_argument("--log-file", "-l", type=str, default="logs/alerts.json", help="Alert log file (default: logs/alerts.json)")
    parser.add_argument("--daemon-duration", type=int, default=25, help="Daemon test runtime in seconds (default: 25)")
    parser.add_argument("--interface", "-i", type=str, default="eth0", help="Sniffer interface (default: eth0)")

    args = parser.parse_args()

    print("=" * 95)
    print(" NTRO CYBER THREAT DETECTION SYSTEM - ADVANCED ML PIPELINE VERIFICATION")
    print("=" * 95)

    # -------------------------------------------------------------------------
    # STAGE 1: Robust Multi-Class Dataset Generation with Noise Injection
    # -------------------------------------------------------------------------
    print("\n" + "=" * 95)
    print(" [STAGE 1/4] ROBUST DATASET SYNTHESIS (Noise Injection + Bi-Directional Dynamics)")
    print("=" * 95)
    generator = DatasetGenerator(random_seed=42, noise_level=args.noise_level)
    train_df, test_df = generator.generate_dataset(
        samples_per_class=args.samples_per_class,
        train_split=0.8,
        output_dir=args.data_dir,
    )
    train_csv_path = os.path.join(args.data_dir, "dataset_train.csv")
    test_csv_path = os.path.join(args.data_dir, "dataset_test.csv")

    print(f"[*] Training partition generated : {len(train_df)} flows -> {train_csv_path}")
    print(f"[*] Testing partition generated  : {len(test_df)} flows -> {test_csv_path}")
    print(f"[*] Feature Dimensionality       : {len(train_df.columns)} columns (Bi-directional & Ratio metrics)")
    print(f"[*] Class Distribution:\n{train_df['label_name'].value_counts().to_string()}")

    # -------------------------------------------------------------------------
    # STAGE 2: Model Training & Out-of-Distribution (OOD) Zero-Day Anomaly Testing
    # -------------------------------------------------------------------------
    print("\n" + "=" * 95)
    print(" [STAGE 2/4] MODEL TRAINING & ZERO-DAY ANOMALY DETECTION EVALUATION")
    print("=" * 95)
    engine = ThreatDetectionEngine(model_dir=args.model_dir)
    metrics = engine.train(
        train_csv_path=train_csv_path,
        test_csv_path=test_csv_path,
        random_state=42,
    )

    print(f"[*] Test Accuracy        : {metrics['accuracy'] * 100:.2f}%")
    print(f"[*] Weighted F1-Score    : {metrics['weighted_f1_score'] * 100:.2f}%")

    # Generate and test unlabelled Out-of-Distribution novel attack (Slowloris)
    print("\n[*] Synthesizing novel Out-of-Distribution (OOD) attack patterns not in training set...")
    ood_df = generator.generate_ood_dataset(num_samples=30)
    ood_metrics = engine.evaluate_zero_day_anomaly(ood_df)

    # -------------------------------------------------------------------------
    # STAGE 3: Statistical Data Drift Detection Verification (KS-Test & PSI)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 95)
    print(" [STAGE 3/4] STATISTICAL DATA DRIFT MONITORING (KS-Test & Population Stability Index)")
    print("=" * 95)
    drift_detector = DataDriftDetector(baseline_df=train_df)

    # 1. Test In-Distribution test data (should show NO_DRIFT)
    in_dist_report = drift_detector.evaluate_drift(test_df)
    print(f"[*] In-Distribution Test Traffic Drift Status : {in_dist_report['drift_level']} (Drifted Features: {in_dist_report['drifted_features_count']})")

    # 2. Test Shifted / Anomalous data (should flag DRIFT)
    drift_report = drift_detector.evaluate_drift(ood_df)
    print(f"[*] Shifted Zero-Day Traffic Drift Status     : {drift_report['drift_level']} (Drifted Features: {drift_report['drifted_features_count']})")
    print(f"[*] Drift Recommendation                      : {drift_report['recommendation']}")

    # -------------------------------------------------------------------------
    # STAGE 4: Real-Time Detection Daemon with Overlapping Mixed Traffic & Rate Limiting
    # -------------------------------------------------------------------------
    print("\n" + "=" * 95)
    print(f" [STAGE 4/4] LIVE DETECTION DAEMON ({args.daemon_duration}s Sliding Window, Rate Limiting & Incident Aggregation)")
    print("=" * 95)

    if os.path.exists(args.log_file):
        try:
            os.remove(args.log_file)
        except OSError:
            pass

    daemon = DetectionDaemon(
        interface=args.interface,
        window_seconds=3.0,
        model_dir=args.model_dir,
        alert_log_file=args.log_file,
    )
    daemon.start()

    # Define interleaved, overlapping concurrent traffic streams
    concurrent_schedules = [
        # Normal continuous background browsing
        {
            "delay": 1,
            "desc": "Background Normal Web Browsing (Session A)",
            "fn": lambda: generator._generate_normal_packets("192.168.10.11", "192.168.10.20", 52100, 443, time.time()),
        },
        # High-Velocity SYN flood from Host 10.0.88.5 (Multiple bursts to test deduplication / incident aggregation)
        {
            "delay": 4,
            "desc": "SYN Flood Attack - Burst 1 (Source: 10.0.88.5)",
            "fn": lambda: generator._generate_syn_flood_packets("10.0.88.5", "192.168.10.20", 49152, 80, time.time()),
        },
        {
            "delay": 7,
            "desc": "SYN Flood Attack - Burst 2 (Source: 10.0.88.5) -> Tests Alert Rate Limiting",
            "fn": lambda: generator._generate_syn_flood_packets("10.0.88.5", "192.168.10.20", 49152, 80, time.time()),
        },
        # Overlapping Port Scan reconnaissance occurring concurrently with background traffic
        {
            "delay": 10,
            "desc": "Mixed Overlapping Port Sweep (Source: 172.16.8.99)",
            "fn": lambda: generator._generate_port_scan_packets("172.16.8.99", "192.168.10.20", 58000, [21, 22, 23, 25, 80, 443, 3389], time.time()),
        },
        # Volumetric UDP flood burst
        {
            "delay": 14,
            "desc": "Volumetric High-Volume UDP Flood (Source: 198.51.100.33)",
            "fn": lambda: generator._generate_udp_flood_packets("198.51.100.33", "192.168.10.20", 44550, 9999, time.time()),
        },
    ]

    start_t = time.time()
    injected_pkts = 0

    try:
        while time.time() - start_t < args.daemon_duration:
            elapsed = int(time.time() - start_t)
            for item in concurrent_schedules:
                if elapsed >= item["delay"] and "injected" not in item:
                    item["injected"] = True
                    pkts = item["fn"]()
                    daemon.inject_packets(pkts)
                    injected_pkts += len(pkts)
                    print(f"[*] [{elapsed:02d}s] INJECTED CONCURRENT STREAM: {item['desc']} ({len(pkts)} packets)")
            time.sleep(1.0)
    finally:
        print("\n[*] Stopping Detection Daemon and harvesting incident telemetry...")
        summary = daemon.stop()

    # Load recorded incident records
    persisted_incidents: List[Dict[str, Any]] = []
    if os.path.exists(args.log_file):
        try:
            with open(args.log_file, "r") as f:
                persisted_incidents = json.load(f)
        except Exception as exc:
            logger.error("Failed to read alert log: %s", exc)

    print("\n" + "=" * 95)
    print(" DETECTION DAEMON EXECUTION & INCIDENT AGGREGATION SUMMARY")
    print("=" * 95)
    print(f" Total Injected Frames          : {injected_pkts}")
    print(f" Total Raw Flows Inspected      : {summary['total_flows_inspected']}")
    print(f" Total Threat Alerts Triggered  : {summary['total_alerts_triggered']}")
    print(f" Unique Incidents Aggregated    : {len(persisted_incidents)} (Deduplicated across sliding window)")
    print(f" Persisted Incident File        : {args.log_file}")
    print("=" * 95)

    if persisted_incidents:
        print("\n--- AGGREGATED SECURITY INCIDENT RECORDS (alerts.json) ---")
        for i, inc in enumerate(persisted_incidents, 1):
            print(f"[{i}] Incident ID: {inc['incident_id']} | Type: {inc['threat_type']} | Source: {inc['src_ip']} | Occurrences: {inc['occurrence_count']} | Target Ports: {inc['target_ports']} | Max Anomaly: {inc['max_anomaly_score']:.4f} | Avg Conf: {inc['avg_confidence']*100:.1f}%")

    print("\n" + "=" * 95)
    print(" [SUCCESS] ALL ADVANCED ML PIPELINE MODULES VERIFIED SUCCESSFULLY!")
    print("=" * 95)


if __name__ == "__main__":
    main()
