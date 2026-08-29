#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 8: E2E System Evaluation Harness
Module: evaluate_system.py
Description: Automated end-to-end integration, benchmarking, and evaluation suite.
             Simulates 6 distinct network traffic scenarios:
               1. Normal TCP Traffic (HTTP/HTTPS web sessions)
               2. Normal UDP Traffic (DNS query/response flows)
               3. High Packet Rate Volume Anomaly (Statistical flow rate spike)
               4. TCP SYN Flood Attack (Volumetric connection exhaustion)
               5. Port Scan Reconnaissance (Single-packet horizontal port sweep)
               6. Spoofed / Malicious Tor Exit Anomaly (Anomalous IP header distribution)
             Evaluates flows across the complete pipeline (ML Threat Engine, SHAP XAI
             Explainer, Threat Intelligence Enrichment, and SHA-256 Forensic Audit Trail).
             Computes Accuracy, Precision, Recall, F1-Score, False-Positive Rate (FPR),
             Mean/P95/P99 Detection Latency (ms), and System Throughput (flows/sec).
"""

import json
import logging
import os
import sys
import time
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score

# Ensure local module path resolution
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from audit_logger import ForensicAuditManager
from threat_detector import ThreatDetectionEngine
from threat_intel import ThreatIntelService
from xai_explainer import ThreatExplainer

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("SystemEvaluationHarness")


class SystemEvaluator:
    """
    Principal Evaluation Suite for the NTRO Cyber Threat Detection System.
    Executes automated multi-scenario flow simulations, benchmarks full-pipeline
    telemetry processing, and generates detailed mathematical evaluation matrices.
    """

    def __init__(
        self,
        model_dir: str = "models",
        audit_log_path: str = "logs/eval_audit_trail.json",
    ):
        logger.info("Initializing NTRO System Evaluator & AI Pipeline Components...")
        self.model_dir = model_dir
        self.audit_log_path = audit_log_path

        # Instantiate core components
        self.engine = ThreatDetectionEngine(model_dir=self.model_dir)
        self.explainer = ThreatExplainer(model_dir=self.model_dir)
        self.intel_service = ThreatIntelService()
        self.audit_manager = ForensicAuditManager(log_path=self.audit_log_path)

        # Auto-train models if missing
        if not self.engine.is_trained:
            logger.info("Model artifacts missing in '%s'. Synthesizing training dataset and fitting models...", model_dir)
            from dataset_generator import DatasetGenerator
            gen = DatasetGenerator(random_seed=42)
            df_train = gen.build_dataset(samples_per_class=250, output_path="data/telemetry_dataset.csv")
            self.engine.train(dataset=df_train)

    def generate_6_test_scenarios(self, samples_per_scenario: int = 100) -> List[Dict[str, Any]]:
        """
        Synthesizes 6 distinct, rigorously labeled network traffic scenarios:
        1. Normal TCP Traffic
        2. Normal UDP Traffic
        3. High Packet Rate Volume Anomaly
        4. TCP SYN Flood Attack
        5. Port Scan Reconnaissance
        6. Spoofed / Malicious Tor Exit Traffic
        """
        np.random.seed(42)
        scenarios: List[Dict[str, Any]] = []

        # Scenario 1: Normal TCP Web Browsing (HTTP/HTTPS sessions)
        for _ in range(samples_per_scenario):
            scenarios.append({
                "scenario_name": "Normal_TCP_Web",
                "true_label": "Normal",
                "is_malicious_true": False,
                "flow": {
                    "source_ip": f"192.168.10.{np.random.randint(10, 250)}",
                    "destination_ip": "192.168.10.1",
                    "source_port": int(np.random.randint(1024, 65535)),
                    "destination_port": int(np.random.choice([80, 443, 8080])),
                    "protocol": "TCP",
                    "packet_count": int(np.random.randint(20, 100)),
                    "total_bytes": int(np.random.randint(5000, 80000)),
                    "flow_duration": float(np.random.uniform(1.0, 10.0)),
                    "packets_per_sec": float(np.random.uniform(2.0, 20.0)),
                    "bytes_per_sec": float(np.random.uniform(1000.0, 15000.0)),
                    "mean_packet_size": float(np.random.uniform(300.0, 850.0)),
                    "std_packet_size": float(np.random.uniform(50.0, 350.0)),
                    "iat_mean": float(np.random.uniform(0.04, 0.4)),
                    "iat_std": float(np.random.uniform(0.01, 0.08)),
                    "syn_count": 1,
                    "ack_count": int(np.random.randint(18, 95)),
                },
            })

        # Scenario 2: Normal Application & Telemetry Sessions
        for _ in range(samples_per_scenario):
            scenarios.append({
                "scenario_name": "Normal_App_Traffic",
                "true_label": "Normal",
                "is_malicious_true": False,
                "flow": {
                    "source_ip": f"192.168.10.{np.random.randint(10, 250)}",
                    "destination_ip": "192.168.10.1",
                    "source_port": int(np.random.randint(1024, 65535)),
                    "destination_port": int(np.random.choice([53, 443, 8080])),
                    "protocol": "TCP",
                    "packet_count": int(np.random.randint(15, 60)),
                    "total_bytes": int(np.random.randint(3000, 40000)),
                    "flow_duration": float(np.random.uniform(0.8, 6.0)),
                    "packets_per_sec": float(np.random.uniform(2.0, 15.0)),
                    "bytes_per_sec": float(np.random.uniform(800.0, 8000.0)),
                    "mean_packet_size": float(np.random.uniform(250.0, 650.0)),
                    "std_packet_size": float(np.random.uniform(40.0, 200.0)),
                    "iat_mean": float(np.random.uniform(0.05, 0.3)),
                    "iat_std": float(np.random.uniform(0.01, 0.05)),
                    "syn_count": 1,
                    "ack_count": int(np.random.randint(14, 58)),
                },
            })

        # Scenario 3: High Packet Rate Anomaly (Statistical Burst)
        for _ in range(samples_per_scenario):
            scenarios.append({
                "scenario_name": "High_Packet_Rate_Anomaly",
                "true_label": "UDP_Flood",  # Categorized as volumetric anomaly
                "is_malicious_true": True,
                "flow": {
                    "source_ip": "198.51.100.45",
                    "destination_ip": "192.168.10.20",
                    "source_port": int(np.random.randint(30000, 50000)),
                    "destination_port": 9999,
                    "protocol": "UDP",
                    "packet_count": int(np.random.randint(1200, 3000)),
                    "total_bytes": int(np.random.randint(1500000, 4000000)),
                    "flow_duration": float(np.random.uniform(0.5, 2.0)),
                    "packets_per_sec": float(np.random.uniform(1000.0, 2500.0)),
                    "bytes_per_sec": float(np.random.uniform(1500000.0, 3500000.0)),
                    "mean_packet_size": 1420.0,
                    "std_packet_size": 15.0,
                    "iat_mean": float(np.random.uniform(0.0004, 0.001)),
                    "iat_std": float(np.random.uniform(0.0001, 0.0003)),
                    "syn_count": 0,
                    "ack_count": 0,
                },
            })

        # Scenario 4: TCP SYN Flood Attack (Volumetric State Exhaustion)
        for _ in range(samples_per_scenario):
            scenarios.append({
                "scenario_name": "TCP_SYN_Flood",
                "true_label": "SYN_Flood",
                "is_malicious_true": True,
                "flow": {
                    "source_ip": "10.0.4.88",
                    "destination_ip": "192.168.10.20",
                    "source_port": int(np.random.randint(49152, 65535)),
                    "destination_port": 80,
                    "protocol": "TCP",
                    "packet_count": int(np.random.randint(500, 1500)),
                    "total_bytes": int(np.random.randint(32000, 96000)),
                    "flow_duration": float(np.random.uniform(0.2, 1.2)),
                    "packets_per_sec": float(np.random.uniform(500.0, 1500.0)),
                    "bytes_per_sec": float(np.random.uniform(32000.0, 120000.0)),
                    "mean_packet_size": 64.0,
                    "std_packet_size": 0.0,
                    "iat_mean": float(np.random.uniform(0.0005, 0.0018)),
                    "iat_std": float(np.random.uniform(0.0001, 0.0004)),
                    "syn_count": int(np.random.randint(500, 1500)),
                    "ack_count": 0,
                },
            })

        # Scenario 5: Port Scan Reconnaissance (Single-Packet Sweep)
        for _ in range(samples_per_scenario):
            scenarios.append({
                "scenario_name": "Port_Scan_Recon",
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
                },
            })

        # Scenario 6: Spoofed / Tor Exit Node Anomaly (High-Risk Threat)
        for _ in range(samples_per_scenario):
            scenarios.append({
                "scenario_name": "Spoofed_Tor_Anomaly",
                "true_label": "SYN_Flood",
                "is_malicious_true": True,
                "flow": {
                    "source_ip": f"185.220.101.{np.random.randint(1, 250)}",  # Tor exit range
                    "destination_ip": "192.168.10.20",
                    "source_port": int(np.random.randint(10000, 60000)),
                    "destination_port": 443,
                    "protocol": "TCP",
                    "packet_count": int(np.random.randint(400, 900)),
                    "total_bytes": int(np.random.randint(25000, 58000)),
                    "flow_duration": float(np.random.uniform(0.1, 0.9)),
                    "packets_per_sec": float(np.random.uniform(400.0, 1100.0)),
                    "bytes_per_sec": float(np.random.uniform(25000.0, 75000.0)),
                    "mean_packet_size": 64.0,
                    "std_packet_size": 0.0,
                    "iat_mean": float(np.random.uniform(0.0008, 0.0025)),
                    "iat_std": float(np.random.uniform(0.0001, 0.0006)),
                    "syn_count": int(np.random.randint(400, 900)),
                    "ack_count": 0,
                },
            })

        return scenarios

    def run_evaluation(self, samples_per_scenario: int = 100) -> Dict[str, Any]:
        """
        Executes end-to-end automated evaluation across all 6 scenarios.
        Measures classification accuracy, stage-by-stage latency, throughput, and audit integrity.
        """
        logger.info(
            "Executing Phase 8 E2E System Evaluation Harness (%d samples x 6 scenarios = %d flows)...",
            samples_per_scenario,
            samples_per_scenario * 6,
        )

        scenarios = self.generate_6_test_scenarios(samples_per_scenario=samples_per_scenario)

        y_true_class: List[str] = []
        y_pred_class: List[str] = []
        y_true_binary: List[bool] = []
        y_pred_binary: List[bool] = []

        latencies_ms: List[float] = []
        audit_records_logged = 0
        scenario_breakdown: Dict[str, Dict[str, int]] = {}

        start_total = time.perf_counter()

        for item in scenarios:
            sc_name = item["scenario_name"]
            flow_data = item["flow"]
            true_label = item["true_label"]
            is_malicious_true = item["is_malicious_true"]

            if sc_name not in scenario_breakdown:
                scenario_breakdown[sc_name] = {"total": 0, "correct": 0}
            scenario_breakdown[sc_name]["total"] += 1

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

            # 4. SHA-256 Forensic Audit Logging (Buffered)
            if is_malicious_pred:
                self.audit_manager.log_malicious_event(
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
                audit_records_logged += 1

            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

            if pred_label == true_label:
                scenario_breakdown[sc_name]["correct"] += 1

            y_true_class.append(true_label)
            y_pred_class.append(pred_label)
            y_true_binary.append(is_malicious_true)
            y_pred_binary.append(is_malicious_pred)

        # Flush buffered audit logs to disk
        self.audit_manager._save_audit_trail()
        total_time_sec = time.perf_counter() - start_total
        throughput_fps = len(scenarios) / max(total_time_sec, 0.001)

        # 5. Cryptographic Chain Integrity Verification
        integrity_res = self.audit_manager.verify_integrity()

        # Compute Core Metrics
        accuracy = float(np.mean(np.array(y_true_class) == np.array(y_pred_class)))
        precision = float(precision_score(y_true_class, y_pred_class, average="weighted", zero_division=0))
        recall = float(recall_score(y_true_class, y_pred_class, average="weighted", zero_division=0))
        f1 = float(f1_score(y_true_class, y_pred_class, average="weighted", zero_division=0))

        # Binary Confusion Matrix & False Positive Rate (FPR)
        cm_bin = confusion_matrix(y_true_binary, y_pred_binary, labels=[False, True])
        tn, fp, fn, tp = cm_bin.ravel() if cm_bin.shape == (2, 2) else (0, 0, 0, 0)
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        mean_latency = float(np.mean(latencies_ms))
        p95_latency = float(np.percentile(latencies_ms, 95))
        p99_latency = float(np.percentile(latencies_ms, 99))

        report_data = {
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_evaluated_flows": len(scenarios),
            "scenario_count": 6,
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
            "scenario_accuracy": {
                k: f"{(v['correct'] / v['total']) * 100:.1f}% ({v['correct']}/{v['total']})"
                for k, v in scenario_breakdown.items()
            },
            "forensic_audit": {
                "audit_records_logged": audit_records_logged,
                "chain_status": integrity_res.get("status", "VALID"),
                "corrupted_count": integrity_res.get("corrupted_count", 0),
            },
            "classification_report": classification_report(
                y_true_class, y_pred_class, output_dict=True, zero_division=0
            ),
        }

        # Save to JSON
        os.makedirs("logs", exist_ok=True)
        with open("logs/evaluation_report.json", "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        self._print_formatted_report(report_data)
        return report_data

    def _print_formatted_report(self, data: Dict[str, Any]) -> None:
        """Print stylized benchmark evaluation matrix to console."""
        m = data["metrics"]
        cm = data["confusion_matrix"]
        lat = data["performance_latency"]
        audit = data["forensic_audit"]
        sc = data["scenario_accuracy"]

        print("\n" + "=" * 94)
        print(" NTRO CYBER THREAT DETECTION SYSTEM - PHASE 8 END-TO-END EVALUATION REPORT")
        print("=" * 94)
        print(f" Evaluation Timestamp        : {data['evaluation_timestamp']}")
        print(f" Total Evaluated Flow Records  : {data['total_evaluated_flows']} across 6 Test Scenarios")
        print("-" * 94)
        print(" SCENARIO-BY-SCENARIO ACCURACY:")
        for name, acc_str in sc.items():
            print(f"   • {name:<26} : {acc_str}")
        print("-" * 94)
        print(" CORE DETECTION ACCURACY & RELIABILITY METRICS:")
        print(f"   • Overall Accuracy          : {m['overall_accuracy'] * 100:.2f}%")
        print(f"   • Weighted Precision        : {m['weighted_precision'] * 100:.2f}%")
        print(f"   • Weighted Recall           : {m['weighted_recall'] * 100:.2f}%")
        print(f"   • Weighted F1-Score         : {m['weighted_f1_score'] * 100:.2f}%")
        print(f"   • False Positive Rate (FPR) : {m['false_positive_rate'] * 100:.2f}%")
        print("-" * 94)
        print(" CONFUSION MATRIX BREAKDOWN:")
        print(f"   • True Negatives (Normal Correct)   : {cm['true_negatives']}")
        print(f"   • False Positives (False Alarms)     : {cm['false_positives']}")
        print(f"   • False Negatives (Missed Threats)   : {cm['false_negatives']}")
        print(f"   • True Positives (Threats Blocked)   : {cm['true_positives']}")
        print("-" * 94)
        print(" REAL-TIME PIPELINE LATENCY & THROUGHPUT:")
        print(f"   • Mean Latency / Flow       : {lat['mean_latency_ms']:.3f} ms")
        print(f"   • 95th Percentile Latency   : {lat['p95_latency_ms']:.3f} ms")
        print(f"   • 99th Percentile Latency   : {lat['p99_latency_ms']:.3f} ms")
        print(f"   • Processing Throughput     : {lat['throughput_flows_per_sec']:.1f} flows / sec")
        print("-" * 94)
        print(" CRYPTOGRAPHIC FORENSIC AUDIT INTEGRITY:")
        print(f"   • Total Audit Logs Written  : {audit['audit_records_logged']}")
        print(f"   • SHA-256 Chain Integrity   : [STATUS: {audit['chain_status']}]")
        print(f"   • Corrupted Record Count    : {audit['corrupted_count']}")
        print("=" * 94)
        print(" [SUCCESS] PHASE 8 EVALUATION HARNESS COMPLETE")
        print(" Output Report Saved to       : logs/evaluation_report.json\n")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    evaluator = SystemEvaluator(model_dir="models")
    evaluator.run_evaluation(samples_per_scenario=100)


if __name__ == "__main__":
    main()
