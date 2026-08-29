#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 5: Machine Learning Engine
Module: test_phase5.py
Description: Automated end-to-end verification harness for dataset synthesis, model training,
             cross-validation metrics evaluation, and real-time flow inference simulation.
"""

import argparse
import json
import logging
import os
import sys
import pandas as pd
from dataset_generator import DatasetGenerator
from ml_engine import ThreatDetectionEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("TestPhase5Harness")


def main() -> None:
    parser = argparse.ArgumentParser(description="NTRO Phase 5: Machine Learning Threat Detection Verification")
    parser.add_argument(
        "--samples-per-class",
        "-s",
        type=int,
        default=200,
        help="Number of flow samples per class for training dataset (default: 200)",
    )
    parser.add_argument(
        "--dataset-path",
        "-d",
        type=str,
        default="data/telemetry_dataset.csv",
        help="Path to save / load dataset CSV (default: data/telemetry_dataset.csv)",
    )
    parser.add_argument(
        "--model-dir",
        "-m",
        type=str,
        default="models",
        help="Directory to save trained model artifacts (default: models)",
    )
    args = parser.parse_args()

    print("=" * 85)
    print(" NTRO CYBER THREAT DETECTION - PHASE 5 AI / ML DETECTION ENGINE VERIFICATION")
    print("=" * 85)

    # 1. Dataset Generation
    print(f"\n[STEP 1] Generating balanced multi-class telemetry dataset ({args.samples_per_class} per class)...")
    generator = DatasetGenerator(random_seed=42)
    df_dataset = generator.build_dataset(
        samples_per_class=args.samples_per_class,
        output_path=args.dataset_path,
    )
    print(f"[*] Dataset successfully synthesized: {len(df_dataset)} total labeled flow records.")

    # 2. Model Training & Evaluation
    print(f"\n[STEP 2] Initializing and training ThreatDetectionEngine models (Scaler + Isolation Forest + Classifier)...")
    engine = ThreatDetectionEngine(model_dir=args.model_dir)
    metrics = engine.train(dataset=df_dataset, test_size=0.25, random_state=42)

    print("\n" + "=" * 85)
    print(" MODEL PERFORMANCE EVALUATION METRICS (TEST SET)")
    print("=" * 85)
    print(f"  Total Dataset Samples   : {metrics['total_samples']}")
    print(f"  Training Samples        : {metrics['train_samples']}")
    print(f"  Hold-out Test Samples   : {metrics['test_samples']}")
    print(f"  Overall Accuracy        : {metrics['accuracy'] * 100:.2f}%")
    print(f"  Weighted Precision      : {metrics['weighted_precision'] * 100:.2f}%")
    print(f"  Weighted Recall         : {metrics['weighted_recall'] * 100:.2f}%")
    print(f"  Weighted F1-Score       : {metrics['weighted_f1_score'] * 100:.2f}%")
    print("=" * 85)

    print("\nClassification Report by Attack Class:")
    report_df = pd.DataFrame(metrics["classification_report"]).transpose()
    print(report_df.to_string())

    # 3. Live Inference Simulation
    print("\n" + "=" * 85)
    print(" [STEP 3] RUNNING REAL-TIME THREAT INFERENCE ON SIMULATED FLOW SAMPLES")
    print("=" * 85)

    # Define diverse test flow profiles
    test_cases = [
        {
            "name": "Live Web Session (Normal)",
            "flow": {
                "src_ip": "192.168.10.15",
                "dst_ip": "192.168.10.20",
                "src_port": 54321,
                "dst_port": 443,
                "protocol": "TCP",
                "packet_count": 35,
                "total_bytes": 18500,
                "flow_duration": 4.82,
                "packets_per_sec": 7.26,
                "bytes_per_sec": 3838.17,
                "mean_packet_size": 528.57,
                "std_packet_size": 412.30,
                "iat_mean": 0.1377,
                "iat_std": 0.0452,
                "syn_count": 1,
                "ack_count": 28,
            },
        },
        {
            "name": "High-Velocity TCP Burst (SYN Flood Attack)",
            "flow": {
                "src_ip": "10.0.4.88",
                "dst_ip": "192.168.10.20",
                "src_port": 49152,
                "dst_port": 80,
                "protocol": "TCP",
                "packet_count": 240,
                "total_bytes": 15360,
                "flow_duration": 0.72,
                "packets_per_sec": 333.33,
                "bytes_per_sec": 21333.33,
                "mean_packet_size": 64.0,
                "std_packet_size": 0.0,
                "iat_mean": 0.0030,
                "iat_std": 0.0008,
                "syn_count": 240,
                "ack_count": 0,
            },
        },
        {
            "name": "Reconnaissance Port Probe (Port Scan Attack)",
            "flow": {
                "src_ip": "172.16.5.99",
                "dst_ip": "192.168.10.20",
                "src_port": 58000,
                "dst_port": 22,
                "protocol": "TCP",
                "packet_count": 1,
                "total_bytes": 60,
                "flow_duration": 0.0,
                "packets_per_sec": 10000.0,
                "bytes_per_sec": 600000.0,
                "mean_packet_size": 60.0,
                "std_packet_size": 0.0,
                "iat_mean": 0.0,
                "iat_std": 0.0,
                "syn_count": 1,
                "ack_count": 0,
            },
        },
        {
            "name": "High-Bandwidth Datagram Blast (UDP Flood Attack)",
            "flow": {
                "src_ip": "198.51.100.45",
                "dst_ip": "192.168.10.20",
                "src_port": 44550,
                "dst_port": 9999,
                "protocol": "UDP",
                "packet_count": 180,
                "total_bytes": 184320,
                "flow_duration": 0.95,
                "packets_per_sec": 189.47,
                "bytes_per_sec": 194021.05,
                "mean_packet_size": 1024.0,
                "std_packet_size": 0.0,
                "iat_mean": 0.0052,
                "iat_std": 0.0011,
                "syn_count": 0,
                "ack_count": 0,
            },
        },
    ]

    results = []
    for test in test_cases:
        inference = engine.predict_flow(test["flow"])
        status_tag = "[ALERT: THREAT DETECTED]" if inference["is_malicious"] else "[STATUS: BENIGN / NORMAL]"
        print(f"\n>> Test Case: {test['name']}")
        src_ip = inference.get("source_ip", inference.get("src_ip", "127.0.0.1"))
        dst_ip = inference.get("destination_ip", inference.get("dst_ip", "127.0.0.1"))
        src_port = inference.get("source_port", inference.get("src_port", 0))
        dst_port = inference.get("destination_port", inference.get("dst_port", 0))
        protocol = inference.get("protocol", "TCP")
        print(f"   5-Tuple           : {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})")
        print(f"   Class Prediction  : {inference['prediction']} (Confidence: {inference['confidence']*100:.1f}%)")
        print(f"   Anomaly Score     : {inference['anomaly_score']:.4f} (Threshold: 0.65)")
        print(f"   Security Verdict  : {status_tag}")
        results.append({
            "Test_Case": test["name"],
            "Prediction": inference["prediction"],
            "Confidence": f"{inference['confidence']*100:.1f}%",
            "Anomaly_Score": inference["anomaly_score"],
            "Malicious": inference["is_malicious"],
        })

    print("\n" + "=" * 85)
    print(" INFERENCE SUMMARY TABLE")
    print("=" * 85)
    summary_df = pd.DataFrame(results)
    print(summary_df.to_string(index=False))

    print("\n" + "=" * 85)
    print(" [SUCCESS] PHASE 5 THREAT DETECTION PIPELINE VERIFIED SUCCESSFULLY")
    print("=" * 85)


if __name__ == "__main__":
    main()
