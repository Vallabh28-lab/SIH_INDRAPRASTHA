#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 8: E2E System Evaluation Harness
Module: evaluate_system.py
Description: Automated end-to-end integration and benchmarking suite.
             Tests diverse network traffic profiles (Normal, SYN Flood, Port Scan,
             UDP Flood, Spoofed/Anomalous) across the complete pipeline (ML Engine,
             SHAP XAI Explainer, Threat Intelligence, and SHA-256 Audit Trail).
             Measures Accuracy, Precision, Recall, F1-Score, False Positive Rate (FPR),
             Detection Latency (ms), and System Throughput (flows/sec).
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score

# Ensure local module imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from audit_logger import ForensicAuditManager
from threat_detector import ThreatDetectionEngine
from threat_intel import ThreatIntelService
from xai_explainer import ThreatExplainer

# Configure structured logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("SystemEvaluationHarness")


class SystemEvaluator:
    """
    End-to-End System Integration & Evaluation Suite:
    - Simulates multi-profile network flow workloads.
    - Evaluates detection accuracy & latency across ML, XAI, Intel, and Audit modules.
    - Generates comprehensive performance metrics report.
    """

    def __init__(self, model_dir: str = "models", audit_log_path: str = "logs/eval_audit_trail.json"):
        logger.info("Initializing NTRO System Evaluator & AI Components...")
        self.engine = ThreatDetectionEngine(model_dir=model_dir)
        self.explainer = ThreatExplainer(model_dir=model_dir)
        self.intel_service = ThreatIntelService()
        self.audit_manager = ForensicAuditManager(log_path=audit_log_path)

        # Train models if not pre-loaded
        if not self.engine.is_trained:
            logger.info("Pre-trained models missing. Generating training dataset & fitting engine...")
            from dataset_generator import DatasetGenerator
            gen = DatasetGenerator(random_seed=42)
            df_train = gen.build_dataset(samples_per_class=200, output_path="data/telemetry_dataset.csv")
            self.engine.train(dataset=df_train)

    def generate_benchmark_scenarios(self, samples_per_category: int = 100) -> List[Dict[str, Any]]:
        """
        Generate labeled flow records across 5 distinct network traffic profiles:
        1. Normal (Benign web & DNS sessions)
        2. SYN Flood (TCP SYN flood attack)
        3. Port Scan (Reconnaissance port sweep)
        4. UDP Flood (Datagram amplification blast)
        5. Spoofed / Anomalous (Spoofed IP header & anomalous statistical profile)
        """
        np.random.seed(42)
        scenarios: List[Dict[str, Any]] = []

        # 1. Normal Baseline Traffic
        for _ in range(samples_per_category):
            scenarios.append({
                "true_label": "Normal",
                "is_malicious_true": False,
                "flow": {
                    "source_ip": f"192.168.10.{np.random.randint(10, 250)}",
                    "destination_ip": "192.168.10.1",
                    "source_port": int(np.random.randint(1024, 65535)),
                    "destination_port": int(np.random.choice([80, 443, 53, 8080])),
                    "protocol": "TCP" if np.random.rand() > 0.2 else "UDP",
                    "packet_count": int(np.random.randint(10, 80)),
                    "total_bytes": int(np.random.randint(1000, 50000)),
                    "flow_duration": float(np.random.uniform(1.0, 10.0)),
                    "packets_per_sec": float(np.random.uniform(2.0, 20.0)),
                    "bytes_per_sec": float(np.random.uniform(500.0, 10000.0)),
                    "mean_packet_size": float(np.random.uniform(200.0, 800.0)),
                    "std_packet_size": float(np.random.uniform(50.0, 300.0)),
                    "iat_mean": float(np.random.uniform(0.05, 0.5)),
                    "iat_std": float(np.random.uniform(0.01, 0.1)),
                    "syn_count": 1,
                    "ack_count": int(np.random.randint(8, 75)),
                }
            })

        # 2. SYN Flood Attack
        for _ in range(samples_per_category):
            scenarios.append({
                "true_label": "SYN_Flood",
                "is_malicious_true": True,
                "flow": {
                    "source_ip": "10.0.4.88",
                    "destination_ip": "192.168.10.20",
                    "source_port": int(np.random.randint(49152, 65535)),
                    "destination_port": 80,
                    "protocol": "TCP",
                    "packet_count": int(np.random.randint(400, 1000)),
                    "total_bytes": int(np.random.randint(25000, 64000)),
                    "flow_duration": float(np.random.uniform(0.2, 1.0)),
                    "packets_per_sec": float(np.random.uniform(400.0, 1200.0)),
                    "bytes_per_sec": float(np.random.uniform(25000.0, 80000.0)),
                    "mean_packet_size": 64.0,
                    "std_packet_size": 0.0,
                    "iat_mean": float(np.random.uniform(0.0005, 0.002)),
                    "iat_std": float(np.random.uniform(0.0001, 0.0005)),
                    "syn_count": int(np.random.randint(400, 1000)),
                    "ack_count": 0,
                }
            })

        # 3. Port Scan Reconnaissance
        for _ in range(samples_per_category):
            scenarios.append({
                "true_label": "Port_Scan",
                "is_malicious_true": True,
                "flow": {
                    "source_ip": "172.16.5.99",
                    "destination_ip": "192.168.10.20",
                    "source_port": int(np.random.randint(50000, 60000)),
                    "destination_port": int(np.random.randint(1, 1024)),
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
                }
            })

        # 4. UDP Flood Attack
        for _ in range(samples_per_category):
            scenarios.append({
                "true_label": "UDP_Flood",
                "is_malicious_true": True,
                "flow": {
                    "source_ip": "198.51.100.45",
                    "destination_ip": "192.168.10.20",
                    "source_port": int(np.random.randint(40000, 50000)),
                    "destination_port": 9999,
                    "protocol": "UDP",
                    "packet_count": int(np.random.randint(800, 2000)),
                    "total_bytes": int(np.random.randint(1000000, 2500000)),
                    "flow_duration": float(np.random.uniform(0.5, 2.0)),
                    "packets_per_sec": float(np.random.uniform(800.0, 1500.0)),
                    "bytes_per_sec": float(np.random.uniform(1000000.0, 2000000.0)),
                    "mean_packet_size": 1420.0,
                    "std_packet_size": 10.0,
                    "iat_mean": float(np.random.uniform(0.0005, 0.0015)),
                    "iat_std": float(np.random.uniform(0.0001, 0.0004)),
                    "syn_count": 0,
                    "ack_count": 0,
                }
            })

        # 5. Spoofed / Anomalous Traffic
        for _ in range(samples_per_category):
            scenarios.append({
                "true_label": "SYN_Flood",  # Treated as threat classification
                "is_malicious_true": True,
                "flow": {
                    "source_ip": f"185.220.101.{np.random.randint(1, 250)}",  # Tor exit node range
                    "destination_ip": "192.168.10.20",
                    "source_port": int(np.random.randint(10000, 60000)),
                    "destination_port": 443,
                    "protocol": "TCP",
                    "packet_count": int(np.random.randint(300, 800)),
                    "total_bytes": int(np.random.randint(19000, 50000)),
                    "flow_duration": float(np.random.uniform(0.1, 0.8)),
                    "packets_per_sec": float(np.random.uniform(300.0, 1000.0)),
                    "bytes_per_sec": float(np.random.uniform(20000.0, 70000.0)),
                    "mean_packet_size": 64.0,
                    "std_packet_size": 0.0,
                    "iat_mean": float(np.random.uniform(0.001, 0.003)),
                    "iat_std": float(np.random.uniform(0.0002, 0.0008)),
                    "syn_count": int(np.random.randint(300, 800)),
                    "ack_count": 0,
                }
            })

        return scenarios

    def run_evaluation(self, samples_per_category: int = 100) -> Dict[str, Any]:
        """
        Executes end-to-end evaluation harness over all benchmark scenarios.
        Measures classification accuracy, latency per stage, throughput, and audit integrity.
        """
        logger.info("Starting End-to-End System Evaluation Harness (%d samples/category)...", samples_per_category)
        scenarios = self.generate_benchmark_scenarios(samples_per_category=samples_per_category)

        y_true_class: List[str] = []
        y_pred_class: List[str] = []
        y_true_binary: List[bool] = []
        y_pred_binary: List[bool] = []

        latencies_ms: List[float] = []
        audit_records_created = 0

        start_total_time = time.perf_counter()

        for item in scenarios:
            flow_data = item["flow"]
            true_label = item["true_label"]
            is_malicious_true = item["is_malicious_true"]

            t0 = time.perf_counter()

            # 1. AI ML Threat Engine Inference
            pred_res = self.engine.predict_flow(flow_data)
            pred_label = pred_res["prediction"]
            confidence = pred_res["confidence"]
            anomaly_score = pred_res["anomaly_score"]
            is_malicious_pred = pred_res["is_malicious"]

            # 2. XAI Justification Generation
            xai_reasons = self.explainer.explain_prediction(flow_data)

            # 3. Threat Intelligence Enrichment
            src_intel = self.intel_service.enrich_ip(flow_data["source_ip"])
            dst_intel = self.intel_service.enrich_ip(flow_data["destination_ip"])
            combined_intel = {"source_ip": src_intel, "destination_ip": dst_intel}

            # 4. Forensic SHA-256 Audit Trail Logging
            if is_malicious_pred:
                audit_record = self.audit_manager.log_malicious_event(
                    event_payload=flow_data,
                    prediction=pred_label,
                    confidence=confidence,
                    anomaly_score=anomaly_score,
                    source_ip=flow_data["source_ip"],
                    destination_ip=flow_data["destination_ip"],
                    xai_reasons=xai_reasons,
                    threat_intel=combined_intel,
                    auto_save=False,
                )
                audit_records_created += 1

            t1 = time.perf_counter()
            latency_ms = (t1 - t0) * 1000.0
            latencies_ms.append(latency_ms)

            y_true_class.append(true_label)
            y_pred_class.append(pred_label)
            y_true_binary.append(is_malicious_true)
            y_pred_binary.append(is_malicious_pred)

        self.audit_manager._save_audit_trail()
        total_elapsed = time.perf_counter() - start_total_time
        throughput_fps = len(scenarios) / max(total_elapsed, 0.001)

        # 5. Cryptographic Chain Integrity Verification
        integrity_res = self.audit_manager.verify_integrity()

        # Compute Core Metrics
        accuracy = float(np.mean(np.array(y_true_class) == np.array(y_pred_class)))
        precision = float(precision_score(y_true_class, y_pred_class, average="weighted", zero_division=0))
        recall = float(recall_score(y_true_class, y_pred_class, average="weighted", zero_division=0))
        f1 = float(f1_score(y_true_class, y_pred_class, average="weighted", zero_division=0))

        # Binary Confusion Matrix & False Positive Rate (FPR)
        # TN, FP, FN, TP
        cm_bin = confusion_matrix(y_true_binary, y_pred_binary, labels=[False, True])
        tn, fp, fn, tp = cm_bin.ravel() if cm_bin.shape == (2, 2) else (0, 0, 0, 0)
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        mean_latency = float(np.mean(latencies_ms))
        p95_latency = float(np.percentile(latencies_ms, 95))
        p99_latency = float(np.percentile(latencies_ms, 99))

        report_data = {
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_evaluated_flows": len(scenarios),
            "metrics": {
                "overall_accuracy": round(accuracy, 4),
                "weighted_precision": round(precision, 4),
                "weighted_recall": round(recall, 4),
                "weighted_f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
            },
            "confusion_matrix": {
                "true_negatives": int(tn),
                "false_positives": int(fp),
                "false_negatives": int(fn),
                "true_positives": int(tp),
            },
            "performance_latency": {
                "mean_latency_ms": round(mean_latency, 3),
                "p95_latency_ms": round(p95_latency, 3),
                "p99_latency_ms": round(p99_latency, 3),
                "throughput_flows_per_sec": round(throughput_fps, 1),
            },
            "forensic_audit": {
                "audit_records_logged": audit_records_created,
                "chain_status": integrity_res.get("status", "VALID"),
                "corrupted_count": integrity_res.get("corrupted_count", 0),
            },
            "classification_report": classification_report(
                y_true_class, y_pred_class, output_dict=True, zero_division=0
            ),
        }

        # Save summary report to JSON
        os.makedirs("logs", exist_ok=True)
        with open("logs/evaluation_report.json", "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        self._print_formatted_report(report_data)
        return report_data

    def _print_formatted_report(self, data: Dict[str, Any]) -> None:
        """Print styled terminal performance evaluation matrix."""
        m = data["metrics"]
        cm = data["confusion_matrix"]
        lat = data["performance_latency"]
        audit = data["forensic_audit"]

        print("\n" + "=" * 90)
        print(" NTRO CYBER THREAT DETECTION SYSTEM - PHASE 8 END-TO-END EVALUATION REPORT")
        print("=" * 90)
        print(f" Evaluation Timestamp      : {data['evaluation_timestamp']}")
        print(f" Total Evaluated Flow Records: {data['total_evaluated_flows']}")
        print("-" * 90)
        print(" CORE DETECTION ACCURACY & RELIABILITY METRICS:")
        print(f"   • Overall Accuracy        : {m['overall_accuracy'] * 100:.2f}%")
        print(f"   • Weighted Precision      : {m['weighted_precision'] * 100:.2f}%")
        print(f"   • Weighted Recall         : {m['weighted_recall'] * 100:.2f}%")
        print(f"   • Weighted F1-Score       : {m['weighted_f1_score'] * 100:.2f}%")
        print(f"   • False Positive Rate (FPR): {m['false_positive_rate'] * 100:.2f}%")
        print("-" * 90)
        print(" CONFUSION MATRIX BREAKDOWN:")
        print(f"   • True Negatives (Normal Correct) : {cm['true_negatives']}")
        print(f"   • False Positives (False Alarms)   : {cm['false_positives']}")
        print(f"   • False Negatives (Missed Threats) : {cm['false_negatives']}")
        print(f"   • True Positives (Threats Blocked) : {cm['true_positives']}")
        print("-" * 90)
        print(" REAL-TIME PIPELINE LATENCY & THROUGHPUT:")
        print(f"   • Mean Latency / Flow     : {lat['mean_latency_ms']:.3f} ms")
        print(f"   • 95th Percentile Latency : {lat['p95_latency_ms']:.3f} ms")
        print(f"   • 99th Percentile Latency : {lat['p99_latency_ms']:.3f} ms")
        print(f"   • Processing Throughput   : {lat['throughput_flows_per_sec']:.1f} flows / sec")
        print("-" * 90)
        print(" CRYPTOGRAPHIC FORENSIC AUDIT INTEGRITY:")
        print(f"   • Total Audit Logs Written: {audit['audit_records_logged']}")
        print(f"   • SHA-256 Chain Integrity : [STATUS: {audit['chain_status']}]")
        print(f"   • Corrupted Record Count  : {audit['corrupted_count']}")
        print("=" * 90)
        print(" [SUCCESS] PHASE 8 END-TO-END SYSTEM EVALUATION COMPLETE & PERSISTED")
        print(" Saved report artifact to: logs/evaluation_report.json\n")


def main() -> None:
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    evaluator = SystemEvaluator(model_dir="models")
    evaluator.run_evaluation(samples_per_category=100)


if __name__ == "__main__":
    main()
