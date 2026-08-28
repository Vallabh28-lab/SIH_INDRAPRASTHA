#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 6: SOC Live Telemetry & Detection Daemon
Module: detection_daemon.py
Description: Real-time detection daemon featuring sliding-window bi-directional flow extraction,
             online ML threat scoring, SHAP/XAI feature attribution embedding,
             incident alert aggregation & rate-limiting, and live data drift monitoring.
"""

import argparse
import datetime
import json
import logging
import os
import signal
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from flow_aggregator import FlowAggregator
from packet_capture import PacketCaptureEngine
from threat_detector import ThreatDetectionEngine
from xai_explainer import ThreatExplainer

# Configure standard structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger("DetectionDaemon")


class AlertAggregator:
    """
    Stateful incident deduplication and rate-limiting manager with embedded XAI attribution.
    Aggregates repetitive flow alerts from the same source IP and attack type within an incident time window.
    """

    def __init__(self, incident_window_sec: float = 20.0):
        self.incident_window_sec = incident_window_sec
        # Key: (src_ip, threat_type) -> Incident Record
        self.active_incidents: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def process_alert(self, alert: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Ingest a flow alert and aggregate it into an active incident with XAI explanations.

        :param alert: Extracted raw flow alert dictionary with XAI metadata
        :return: (is_new_incident, incident_summary)
        """
        now = time.time()
        key = (alert["src_ip"], alert["threat_type"])

        with self._lock:
            if key in self.active_incidents:
                inc = self.active_incidents[key]
                # Check if within existing incident aggregation window
                if now - inc["_last_seen_t"] <= self.incident_window_sec:
                    inc["occurrence_count"] += 1
                    inc["last_seen_utc"] = alert["timestamp_utc"]
                    inc["_last_seen_t"] = now
                    inc["target_ports"].add(alert["dst_port"])
                    inc["total_packets"] += alert["flow_metrics"]["packet_count"]
                    inc["total_bytes"] += alert["flow_metrics"]["total_bytes"]
                    inc["max_anomaly_score"] = max(inc["max_anomaly_score"], alert["anomaly_score"])
                    inc["confidence_scores"].append(alert["confidence"])
                    inc["avg_confidence"] = round(sum(inc["confidence_scores"]) / len(inc["confidence_scores"]), 4)

                    # Update top XAI features if higher confidence
                    if alert.get("xai_top_features"):
                        inc["xai_top_features"] = alert["xai_top_features"]
                        inc["xai_feature_attributions"] = alert.get("xai_feature_attributions", {})

                    return False, self._format_incident(inc)

            # New Incident initialization
            inc_id = f"INC-{int(now * 1000)}-{len(self.active_incidents) + 1}"
            inc_data = {
                "incident_id": inc_id,
                "threat_type": alert["threat_type"],
                "src_ip": alert["src_ip"],
                "dst_ip": alert["dst_ip"],
                "first_seen_utc": alert["timestamp_utc"],
                "last_seen_utc": alert["timestamp_utc"],
                "_first_seen_t": now,
                "_last_seen_t": now,
                "occurrence_count": 1,
                "target_ports": {alert["dst_port"]},
                "total_packets": alert["flow_metrics"]["packet_count"],
                "total_bytes": alert["flow_metrics"]["total_bytes"],
                "max_anomaly_score": alert["anomaly_score"],
                "confidence_scores": [alert["confidence"]],
                "avg_confidence": alert["confidence"],
                "protocol": alert["protocol"],
                "sample_flow_metrics": {
                    "packets_per_sec": alert["flow_metrics"].get("packets_per_sec", 0.0),
                    "bytes_per_sec": alert["flow_metrics"].get("bytes_per_sec", 0.0),
                    "flow_duration": alert["flow_metrics"].get("flow_duration", 0.0),
                    "syn_ratio": alert["flow_metrics"].get("syn_ratio", 0.0),
                    "syn_ack_ratio": alert["flow_metrics"].get("syn_ack_ratio", 0.0),
                    "fwd_bwd_ratio": alert["flow_metrics"].get("fwd_bwd_ratio", 0.0),
                },
                "xai_top_features": alert.get("xai_top_features", []),
                "xai_feature_attributions": alert.get("xai_feature_attributions", {}),
            }
            self.active_incidents[key] = inc_data
            return True, self._format_incident(inc_data)

    def _format_incident(self, inc: Dict[str, Any]) -> Dict[str, Any]:
        """Produce JSON-serializable incident report with XAI explanations."""
        return {
            "incident_id": inc["incident_id"],
            "threat_type": inc["threat_type"],
            "src_ip": inc["src_ip"],
            "dst_ip": inc["dst_ip"],
            "first_seen_utc": inc["first_seen_utc"],
            "last_seen_utc": inc["last_seen_utc"],
            "occurrence_count": inc["occurrence_count"],
            "target_ports": sorted(list(inc["target_ports"])),
            "total_packets": inc["total_packets"],
            "total_bytes": inc["total_bytes"],
            "max_anomaly_score": inc["max_anomaly_score"],
            "avg_confidence": inc["avg_confidence"],
            "protocol": inc["protocol"],
            "sample_flow_metrics": inc.get("sample_flow_metrics", {}),
            "xai_top_features": inc.get("xai_top_features", []),
            "xai_feature_attributions": inc.get("xai_feature_attributions", {}),
        }

    def get_all_incidents(self) -> List[Dict[str, Any]]:
        """Retrieve formatted records of all tracked incidents."""
        with self._lock:
            return [self._format_incident(v) for v in self.active_incidents.values()]


class DetectionDaemon:
    """
    Continuous real-time threat detection daemon integrating PacketCaptureEngine,
    FlowAggregator, ThreatDetectionEngine, ThreatExplainer, AlertAggregator, and DataDriftDetector.
    """

    def __init__(
        self,
        interface: str = "eth0",
        window_seconds: float = 5.0,
        model_dir: str = "models",
        alert_log_file: str = "logs/alerts.json",
        bpf_filter: Optional[str] = None,
        drift_check_interval: int = 4,
    ):
        self.interface = interface
        self.window_seconds = max(1.0, window_seconds)
        self.model_dir = model_dir
        self.alert_log_file = alert_log_file
        self.bpf_filter = bpf_filter
        self.drift_check_interval = drift_check_interval

        # Ensure destination logs directory exists
        os.makedirs(os.path.dirname(os.path.abspath(self.alert_log_file)), exist_ok=True)

        # Initialize ML Threat Detection Engine
        self.engine = ThreatDetectionEngine(model_dir=self.model_dir)
        self.engine.load_models()

        # Initialize SHAP / XAI Explainer
        self.explainer = ThreatExplainer(model_dir=self.model_dir)

        # Initialize Alert Aggregator
        self.alert_aggregator = AlertAggregator(incident_window_sec=25.0)

        # Initialize Capture Engine
        self.capture_engine = PacketCaptureEngine(
            interface=self.interface,
            buffer_capacity=25000,
            bpf_filter=self.bpf_filter,
        )

        self._is_running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._total_flows_inspected = 0
        self._total_alerts_triggered = 0
        self._window_counter = 0
        self._buffered_flows_for_drift: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._is_running

    def _persist_incidents(self) -> None:
        """Atomically persist aggregated incident records to logs/alerts.json."""
        with self._lock:
            try:
                incidents = self.alert_aggregator.get_all_incidents()
                with open(self.alert_log_file, "w") as f:
                    json.dump(incidents, f, indent=2)
            except Exception as exc:
                LOG.error("Failed to persist incident log file '%s': %s", self.alert_log_file, exc)

    def _process_buffered_window(self) -> List[Dict[str, Any]]:
        """Extract buffered packets, compute bi-directional flows, and score through ML engine & XAI."""
        raw_packets = self.capture_engine.get_buffered_packets()
        self.capture_engine.clear_buffer()

        if not raw_packets:
            LOG.debug("Sliding window empty (0 packets buffered).")
            return []

        # 1. Aggregate into Bi-Directional 5-tuple statistical flows
        aggregator = FlowAggregator(raw_packets=raw_packets, bidirectional=True)
        flows = aggregator.aggregate()

        if not flows:
            return []

        self._window_counter += 1
        self._buffered_flows_for_drift.extend(flows)

        LOG.info(
            "Window [%03d]: %d packets aggregated into %d bi-directional flow(s).",
            self._window_counter,
            len(raw_packets),
            len(flows),
        )

        # 2. Score each flow through ML detection engine
        for flow in flows:
            self._total_flows_inspected += 1
            prediction = self.engine.predict_flow(flow)

            if prediction["is_malicious"]:
                self._total_alerts_triggered += 1

                # Generate XAI feature attribution
                xai_res = self.explainer.explain_flow(flow, top_k=3)

                alert_entry = {
                    "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "threat_type": prediction["prediction"],
                    "confidence": prediction["confidence"],
                    "anomaly_score": prediction["anomaly_score"],
                    "src_ip": prediction["src_ip"],
                    "dst_ip": prediction["dst_ip"],
                    "src_port": prediction["src_port"],
                    "dst_port": prediction["dst_port"],
                    "protocol": prediction["protocol"],
                    "flow_metrics": flow,
                    "xai_top_features": xai_res.get("top_features", []),
                    "xai_feature_attributions": xai_res.get("feature_attributions", {}),
                }

                # Ingest through Alert Rate Limiter & Aggregator
                is_new, inc_summary = self.alert_aggregator.process_alert(alert_entry)

                if is_new:
                    LOG.warning(
                        "[ALERT - NEW INCIDENT] Type: %s | Conf: %.2f | Src: %s:%d -> Dst: %s:%d | Anomaly: %.4f | XAI: %s",
                        inc_summary["threat_type"],
                        inc_summary["avg_confidence"],
                        inc_summary["src_ip"],
                        prediction["src_port"],
                        inc_summary["dst_ip"],
                        prediction["dst_port"],
                        inc_summary["max_anomaly_score"],
                        "; ".join(inc_summary.get("xai_top_features", [])[:2]),
                    )
                else:
                    LOG.warning(
                        "[ALERT - AGGREGATED INCIDENT] ID: %s | %s from %s | Occurrences: %d | Target Ports: %s | Max Anomaly: %.4f",
                        inc_summary["incident_id"],
                        inc_summary["threat_type"],
                        inc_summary["src_ip"],
                        inc_summary["occurrence_count"],
                        inc_summary["target_ports"][:5],
                        inc_summary["max_anomaly_score"],
                    )

                self._persist_incidents()
            else:
                LOG.info(
                    "[BENIGN] Flow %s:%d <-> %s:%d (%s) | Pkts: %d | Conf: %.2f%%",
                    prediction["src_ip"],
                    prediction["src_port"],
                    prediction["dst_ip"],
                    prediction["dst_port"],
                    prediction["protocol"],
                    flow.get("packet_count", 0),
                    prediction["confidence"] * 100,
                )

        # 3. Periodic Data Drift Evaluation
        if self._window_counter % self.drift_check_interval == 0 and self.engine.drift_detector:
            drift_report = self.engine.drift_detector.evaluate_drift(self._buffered_flows_for_drift)
            LOG.info(
                "[DRIFT MONITOR] Status: %s | Drifted Features: %d | Ratio: %.1f%%",
                drift_report["drift_level"],
                drift_report["drifted_features_count"],
                drift_report["drift_ratio"] * 100,
            )
            self._buffered_flows_for_drift.clear()

        return flows

    def inject_packets(self, packets: List[Dict[str, Any]]) -> None:
        """Inject packets directly into the capture buffer (for test simulation)."""
        with self.capture_engine._lock:
            for p in packets:
                from packet_capture import PacketMetadata
                record = PacketMetadata(
                    timestamp=float(p.get("timestamp", time.time())),
                    src_ip=str(p.get("src_ip", "0.0.0.0")),
                    dst_ip=str(p.get("dst_ip", "0.0.0.0")),
                    src_port=int(p.get("src_port", 0)),
                    dst_port=int(p.get("dst_port", 0)),
                    protocol=str(p.get("protocol", "OTHER")),
                    length=int(p.get("length", 0)),
                    tcp_flags=p.get("tcp_flags", []),
                    payload_size=int(p.get("payload_size", 0)),
                )
                self.capture_engine._buffer.append(record)
                self.capture_engine._total_packets_captured += 1

    def _daemon_loop(self) -> None:
        """Internal background monitoring loop."""
        LOG.info(
            "Threat Detection Daemon active (Interface: %s, Window: %.1fs, XAI Engine: Enabled).",
            self.interface,
            self.window_seconds,
        )
        while self._is_running:
            time.sleep(self.window_seconds)
            if not self._is_running:
                break
            try:
                self._process_buffered_window()
            except Exception as exc:
                LOG.error("Error during sliding window flow inspection: %s", exc, exc_info=True)

    def start(self) -> None:
        """Start packet sniffer and daemon background thread."""
        if self._is_running:
            LOG.warning("Detection daemon is already running.")
            return

        LOG.info("Starting Threat Detection Daemon on interface '%s'...", self.interface)
        self._is_running = True

        try:
            self.capture_engine.start_capture()
        except Exception as exc:
            LOG.warning("Live sniffer could not bind interface '%s' (%s). Telemetry ingestion mode active.", self.interface, exc)

        self._worker_thread = threading.Thread(target=self._daemon_loop, daemon=True)
        self._worker_thread.start()
        LOG.info("Threat Detection Daemon is actively monitoring network telemetry.")

    def stop(self) -> Dict[str, Any]:
        """Stop daemon, flush remaining packets, persist incidents, and return session stats."""
        if not self._is_running:
            return {"status": "STOPPED"}

        LOG.info("Stopping Threat Detection Daemon...")
        self._is_running = False

        if self._worker_thread:
            self._worker_thread.join(timeout=2.0)

        # Process any remaining buffered frames
        self._process_buffered_window()
        self._persist_incidents()
        capture_summary = self.capture_engine.stop_capture()

        incidents = self.alert_aggregator.get_all_incidents()
        summary = {
            "status": "STOPPED",
            "interface": self.interface,
            "total_flows_inspected": self._total_flows_inspected,
            "total_alerts_triggered": self._total_alerts_triggered,
            "unique_incidents_aggregated": len(incidents),
            "capture_stats": capture_summary,
            "alert_log_file": self.alert_log_file,
            "incidents": incidents,
        }
        LOG.info(
            "Daemon stopped. Total Flows: %d | Alerts Triggered: %d | Unique Incidents: %d",
            self._total_flows_inspected,
            self._total_alerts_triggered,
            len(incidents),
        )
        return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="NTRO Phase 6: Real-Time Threat Detection Daemon with XAI")
    parser.add_argument("--interface", "-i", type=str, default="eth0")
    parser.add_argument("--window", "-w", type=float, default=5.0)
    parser.add_argument("--model-dir", "-m", type=str, default="models")
    parser.add_argument("--log-file", "-l", type=str, default="logs/alerts.json")
    parser.add_argument("--duration", "-d", type=int, default=0)

    args = parser.parse_args()

    daemon = DetectionDaemon(
        interface=args.interface,
        window_seconds=args.window,
        model_dir=args.model_dir,
        alert_log_file=args.log_file,
    )

    def handle_sigint(signum, frame):
        print("\n[!] Terminating detection daemon gracefully...")
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    daemon.start()

    if args.duration > 0:
        LOG.info("Running daemon for %d seconds...", args.duration)
        time.sleep(args.duration)
        daemon.stop()
    else:
        LOG.info("Running interactively. Press Ctrl+C to terminate.")
        while True:
            time.sleep(1.0)


if __name__ == "__main__":
    main()
