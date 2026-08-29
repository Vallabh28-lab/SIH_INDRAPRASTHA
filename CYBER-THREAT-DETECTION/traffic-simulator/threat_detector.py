#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 5: Machine Learning Engine
Module: threat_detector.py
Description: Dual-layer Threat Detection Engine combining unsupervised Isolation Forest
             anomaly scoring (0.00 to 1.00) with supervised multi-class XGBoost / Random Forest
             classification ("Normal", "SYN_Flood", "Port_Scan", "UDP_Flood") conforming
             to standard CICIDS2017 / NetFlow telemetry schemas.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Attempt XGBoost import with graceful fallback to RandomForestClassifier
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except (ImportError, Exception):
    xgb = None  # type: ignore
    XGBOOST_AVAILABLE = False

logger = logging.getLogger("ThreatDetectionEngine")

# Canonical feature list matching CICIDS2017 & standard network telemetry profiles
FLOW_FEATURE_COLUMNS = [
    "packet_count",
    "total_bytes",
    "flow_duration",
    "packets_per_sec",
    "bytes_per_sec",
    "mean_packet_size",
    "std_packet_size",
    "iat_mean",
    "iat_std",
    "syn_count",
    "ack_count",
    "syn_ratio",
    "ack_ratio",
]

# Numerical class ID to human-readable label mapping
CLASS_LABELS = {
    0: "Normal",
    1: "SYN_Flood",
    2: "Port_Scan",
    3: "UDP_Flood",
}

LABEL_TO_CLASS = {v: k for k, v in CLASS_LABELS.items()}


class ThreatDetectionEngine:
    """
    AI-driven cybersecurity analytics engine performing dual-tier classification & anomaly scoring:
    1. Unsupervised Anomaly Scoring (Isolation Forest) -> Normalized Score in [0.00, 1.00]
    2. Supervised Multi-Class Threat Classification (XGBoost / Random Forest) -> ("Normal", "SYN_Flood", "Port_Scan", "UDP_Flood")
    """

    def __init__(self, model_dir: str = "models", use_xgboost: bool = True):
        self.model_dir = model_dir
        self.use_xgboost = use_xgboost and XGBOOST_AVAILABLE
        self.scaler: Optional[StandardScaler] = None
        self.anomaly_model: Optional[IsolationForest] = None
        self.classifier_model: Optional[Any] = None
        self.feature_columns = FLOW_FEATURE_COLUMNS
        self.is_trained = False

        # Attempt to auto-load pre-trained models if available on disk
        self._try_auto_load()

    def _try_auto_load(self) -> bool:
        """Attempt to load saved models from model_dir without raising exceptions."""
        try:
            scaler_path = os.path.join(self.model_dir, "scaler.joblib")
            anomaly_path = os.path.join(self.model_dir, "anomaly_model.joblib")
            classifier_path = os.path.join(self.model_dir, "classifier_model.joblib")

            if not os.path.exists(classifier_path):
                # Fallback to alternate naming convention if present
                classifier_path = os.path.join(self.model_dir, "classifier.joblib")

            if os.path.exists(scaler_path) and os.path.exists(anomaly_path) and os.path.exists(classifier_path):
                self.scaler = joblib.load(scaler_path)
                self.anomaly_model = joblib.load(anomaly_path)
                self.classifier_model = joblib.load(classifier_path)
                self.is_trained = True
                logger.info("ThreatDetectionEngine auto-loaded models from '%s'", self.model_dir)
                return True
        except Exception as exc:
            logger.debug("Auto-load models skipped: %s", exc)
        return False

    def _extract_feature_dict(self, flow: Union[Dict[str, Any], pd.Series, Any]) -> Dict[str, float]:
        """
        Normalize and extract standardized features from either Pydantic FlowRecordSchema,
        raw packet flow dictionaries, or DataFrame Series.
        """
        if hasattr(flow, "model_dump"):
            raw = flow.model_dump()
        elif hasattr(flow, "to_dict"):
            raw = flow.to_dict()
        elif isinstance(flow, dict):
            raw = dict(flow)
        else:
            raw = dict(flow)

        packet_count = float(raw.get("packet_count", raw.get("packets", 1)))
        total_bytes = float(raw.get("total_bytes", raw.get("bytes", 0)))
        duration = float(raw.get("flow_duration", raw.get("duration", 0.0)))

        # Packet and byte throughput calculations
        pps = float(raw.get("packets_per_second", raw.get("packets_per_sec", 0.0)))
        if pps == 0.0 and duration > 0:
            pps = packet_count / duration
        elif pps == 0.0 and packet_count > 0:
            pps = packet_count

        bps = float(raw.get("bytes_per_second", raw.get("bytes_per_sec", 0.0)))
        if bps == 0.0 and duration > 0:
            bps = total_bytes / duration
        elif bps == 0.0 and total_bytes > 0:
            bps = total_bytes

        # Packet size statistics
        mean_pkt_size = float(raw.get("mean_packet_size", 0.0))
        if mean_pkt_size == 0.0 and packet_count > 0:
            mean_pkt_size = total_bytes / packet_count

        std_pkt_size = float(raw.get("std_packet_size", 0.0))

        # Timing statistics
        iat_mean = float(raw.get("iat_mean", 0.0))
        iat_std = float(raw.get("iat_std", 0.0))

        # Flag metrics and ratios
        syn_count = float(raw.get("syn_count", 0))
        ack_count = float(raw.get("ack_count", 0))

        syn_ratio = float(raw.get("syn_ratio", syn_count / max(packet_count, 1.0)))
        ack_ratio = float(raw.get("ack_ratio", ack_count / max(packet_count, 1.0)))

        return {
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "flow_duration": duration,
            "packets_per_sec": pps,
            "bytes_per_sec": bps,
            "mean_packet_size": mean_pkt_size,
            "std_packet_size": std_pkt_size,
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "syn_count": syn_count,
            "ack_count": ack_count,
            "syn_ratio": syn_ratio,
            "ack_ratio": ack_ratio,
        }

    def _extract_feature_array(self, flow: Union[Dict[str, Any], pd.Series, Any]) -> np.ndarray:
        """Extract ordered numerical feature vector from flow dictionary or Series."""
        feat_map = self._extract_feature_dict(flow)
        vector = [feat_map.get(col, 0.0) for col in self.feature_columns]
        return np.array(vector, dtype=np.float64).reshape(1, -1)

    def train(
        self,
        train_csv_path: Optional[Union[str, pd.DataFrame]] = None,
        test_csv_path: Optional[Union[str, pd.DataFrame]] = None,
        dataset: Optional[Union[str, pd.DataFrame]] = None,
        test_size: float = 0.25,
        random_state: int = 42,
    ) -> Dict[str, Any]:
        """
        Train StandardScaler, Isolation Forest anomaly detector, and multi-class classifier.
        Supports single combined dataset DataFrame / CSV path or separate train / test partitions.
        """
        if dataset is not None:
            df = pd.read_csv(dataset) if isinstance(dataset, str) else dataset.copy()
            if "label" not in df.columns and "label_name" in df.columns:
                df["label"] = df["label_name"].map(LABEL_TO_CLASS)

            feat_rows = [self._extract_feature_dict(row) for _, row in df.iterrows()]
            X_df = pd.DataFrame(feat_rows)[self.feature_columns]
            X = X_df.values.astype(np.float64)
            y = df["label"].values.astype(int)

            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )
        elif train_csv_path is not None:
            train_df = pd.read_csv(train_csv_path) if isinstance(train_csv_path, str) else train_csv_path.copy()
            if "label" not in train_df.columns and "label_name" in train_df.columns:
                train_df["label"] = train_df["label_name"].map(LABEL_TO_CLASS)

            train_rows = [self._extract_feature_dict(row) for _, row in train_df.iterrows()]
            X_train = pd.DataFrame(train_rows)[self.feature_columns].values.astype(np.float64)
            y_train = train_df["label"].values.astype(int)

            if test_csv_path is not None:
                test_df = pd.read_csv(test_csv_path) if isinstance(test_csv_path, str) else test_csv_path.copy()
                if "label" not in test_df.columns and "label_name" in test_df.columns:
                    test_df["label"] = test_df["label_name"].map(LABEL_TO_CLASS)
                test_rows = [self._extract_feature_dict(row) for _, row in test_df.iterrows()]
                X_test = pd.DataFrame(test_rows)[self.feature_columns].values.astype(np.float64)
                y_test = test_df["label"].values.astype(int)
            else:
                X_train, X_test, y_train, y_test = train_test_split(
                    X_train, y_train, test_size=test_size, random_state=random_state, stratify=y_train
                )
            df = train_df
        else:
            # Generate fallback bootstrap training data
            df = self._generate_fallback_training_data()
            train_rows = [self._extract_feature_dict(row) for _, row in df.iterrows()]
            X = pd.DataFrame(train_rows)[self.feature_columns].values.astype(np.float64)
            y = df["label"].values.astype(int)
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )

        logger.info("Fitting StandardScaler on %d training samples...", len(X_train))
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # 1. Unsupervised Anomaly Scoring (Isolation Forest)
        logger.info("Training Isolation Forest Anomaly Detection Model...")
        self.anomaly_model = IsolationForest(
            n_estimators=100,
            contamination=0.20,
            random_state=random_state,
            n_jobs=-1,
        )
        self.anomaly_model.fit(X_train_scaled)

        # 2. Supervised Multi-Class Threat Classification (XGBoost or Random Forest)
        if self.use_xgboost and XGBOOST_AVAILABLE and xgb is not None:
            logger.info("Training Multi-Class XGBoost Threat Classifier...")
            self.classifier_model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                objective="multi:softprob",
                num_class=len(CLASS_LABELS),
                random_state=random_state,
                eval_metric="mlogloss",
            )
        else:
            logger.info("Training Multi-Class Random Forest Threat Classifier...")
            self.classifier_model = RandomForestClassifier(
                n_estimators=120,
                max_depth=12,
                random_state=random_state,
                n_jobs=-1,
            )

        self.classifier_model.fit(X_train_scaled, y_train)
        self.is_trained = True

        # Model Performance Evaluation
        y_pred = self.classifier_model.predict(X_test_scaled)
        report = classification_report(
            y_test,
            y_pred,
            target_names=[CLASS_LABELS[i] for i in sorted(CLASS_LABELS.keys()) if i in np.unique(y_test)],
            output_dict=True,
            zero_division=0,
        )
        conf_matrix = confusion_matrix(y_test, y_pred).tolist()

        metrics = {
            "total_samples": len(X_train) + len(X_test),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "accuracy": float(report.get("accuracy", 0.0)),
            "weighted_precision": float(report.get("weighted avg", {}).get("precision", 0.0)),
            "weighted_recall": float(report.get("weighted avg", {}).get("recall", 0.0)),
            "weighted_f1_score": float(report.get("weighted avg", {}).get("f1-score", 0.0)),
            "confusion_matrix": conf_matrix,
            "classification_report": report,
        }

        logger.info(
            "Model Training Complete! Accuracy: %.4f | Weighted F1: %.4f",
            metrics["accuracy"],
            metrics["weighted_f1_score"],
        )

        self.save_models()
        return metrics

    def _generate_fallback_training_data(self) -> pd.DataFrame:
        """Synthesize balanced telemetry dataset for bootstrap training."""
        records = []
        # Class 0: Normal
        for _ in range(150):
            records.append({
                "packet_count": np.random.randint(10, 80),
                "total_bytes": np.random.randint(2000, 50000),
                "flow_duration": np.random.uniform(1.0, 15.0),
                "packets_per_sec": np.random.uniform(2.0, 25.0),
                "bytes_per_sec": np.random.uniform(500.0, 15000.0),
                "mean_packet_size": np.random.uniform(200.0, 900.0),
                "std_packet_size": np.random.uniform(50.0, 300.0),
                "iat_mean": np.random.uniform(0.05, 0.5),
                "iat_std": np.random.uniform(0.01, 0.1),
                "syn_count": np.random.randint(1, 3),
                "ack_count": np.random.randint(8, 70),
                "syn_ratio": 0.05,
                "ack_ratio": 0.90,
                "label": 0,
                "label_name": "Normal",
            })
        # Class 1: SYN Flood
        for _ in range(150):
            pkts = np.random.randint(300, 2000)
            records.append({
                "packet_count": pkts,
                "total_bytes": pkts * 64,
                "flow_duration": np.random.uniform(0.1, 2.0),
                "packets_per_sec": np.random.uniform(250.0, 1500.0),
                "bytes_per_sec": np.random.uniform(15000.0, 120000.0),
                "mean_packet_size": 64.0,
                "std_packet_size": 0.0,
                "iat_mean": np.random.uniform(0.0005, 0.005),
                "iat_std": np.random.uniform(0.0001, 0.001),
                "syn_count": pkts,
                "ack_count": 0,
                "syn_ratio": 1.0,
                "ack_ratio": 0.0,
                "label": 1,
                "label_name": "SYN_Flood",
            })
        # Class 2: Port Scan
        for _ in range(150):
            records.append({
                "packet_count": np.random.randint(1, 4),
                "total_bytes": np.random.randint(60, 240),
                "flow_duration": np.random.uniform(0.001, 0.05),
                "packets_per_sec": np.random.uniform(500.0, 5000.0),
                "bytes_per_sec": np.random.uniform(25000.0, 250000.0),
                "mean_packet_size": 60.0,
                "std_packet_size": 0.0,
                "iat_mean": 0.001,
                "iat_std": 0.0,
                "syn_count": 1,
                "ack_count": 0,
                "syn_ratio": 1.0,
                "ack_ratio": 0.0,
                "label": 2,
                "label_name": "Port_Scan",
            })
        # Class 3: UDP Flood
        for _ in range(150):
            pkts = np.random.randint(200, 1500)
            records.append({
                "packet_count": pkts,
                "total_bytes": pkts * 1024,
                "flow_duration": np.random.uniform(0.2, 2.5),
                "packets_per_sec": np.random.uniform(200.0, 1000.0),
                "bytes_per_sec": np.random.uniform(200000.0, 1200000.0),
                "mean_packet_size": 1024.0,
                "std_packet_size": 0.0,
                "iat_mean": np.random.uniform(0.001, 0.008),
                "iat_std": np.random.uniform(0.0002, 0.002),
                "syn_count": 0,
                "ack_count": 0,
                "syn_ratio": 0.0,
                "ack_ratio": 0.0,
                "label": 3,
                "label_name": "UDP_Flood",
            })
        return pd.DataFrame(records)

    def save_models(self, output_dir: Optional[str] = None) -> None:
        """Persist trained scaler, anomaly model, and classifier to disk."""
        target_dir = output_dir or self.model_dir
        os.makedirs(target_dir, exist_ok=True)

        if not self.is_trained or not self.scaler or not self.classifier_model or not self.anomaly_model:
            raise RuntimeError("Models are not trained. Call train() before save_models().")

        joblib.dump(self.scaler, os.path.join(target_dir, "scaler.joblib"))
        joblib.dump(self.anomaly_model, os.path.join(target_dir, "anomaly_model.joblib"))
        joblib.dump(self.classifier_model, os.path.join(target_dir, "classifier_model.joblib"))
        joblib.dump(self.classifier_model, os.path.join(target_dir, "classifier.joblib"))

        metadata = {
            "feature_columns": self.feature_columns,
            "class_labels": CLASS_LABELS,
            "classifier_type": "XGBoost" if (self.use_xgboost and XGBOOST_AVAILABLE) else "RandomForest",
        }
        with open(os.path.join(target_dir, "model_metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info("All ML threat detection artifacts persisted to: %s", target_dir)

    def load_models(self, model_dir: Optional[str] = None) -> None:
        """Load persisted scaler, anomaly model, and classifier from disk."""
        target_dir = model_dir or self.model_dir
        if not self._try_auto_load():
            logger.info("Model artifacts not found in '%s'. Initializing bootstrap self-training...", target_dir)
            self.train()

    def predict_flow(self, flow: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        """
        Perform real-time threat inference on a single flow record.

        :param flow: Flow record dictionary or Pydantic FlowRecordSchema
        :return: Structured inference response dictionary containing prediction, confidence, and anomaly score.
        """
        if not self.is_trained:
            self.load_models()

        if self.scaler is None or self.anomaly_model is None or self.classifier_model is None:
            return self._heuristic_fallback(flow)

        raw: Dict[str, Any] = flow.model_dump() if hasattr(flow, "model_dump") else dict(flow)

        # Extract & scale feature vector
        feat_vector = self._extract_feature_array(raw)
        scaled_feat = self.scaler.transform(feat_vector)

        # 1. Unsupervised Anomaly Scoring (Sigmoid mapped decision function -> [0.0, 1.0])
        raw_score = float(self.anomaly_model.decision_function(scaled_feat)[0])
        # Higher score means higher anomaly (1.0 = extreme outlier, 0.0 = normal inlier)
        anomaly_score = float(1.0 / (1.0 + np.exp(raw_score * 3.5)))
        anomaly_score = max(0.0, min(1.0, round(anomaly_score, 4)))

        # 2. Supervised Multi-Class Threat Classification
        pred_class_id = int(self.classifier_model.predict(scaled_feat)[0])
        probabilities = self.classifier_model.predict_proba(scaled_feat)[0]
        confidence = float(probabilities[pred_class_id])
        prediction_label = CLASS_LABELS.get(pred_class_id, "Unknown")

        # Heuristic calibration for high-rate signatures
        syn_count = float(raw.get("syn_count", 0))
        ack_count = float(raw.get("ack_count", 0))
        protocol = str(raw.get("protocol", "TCP")).upper()

        if protocol == "TCP" and syn_count >= 100 and ack_count == 0:
            prediction_label = "SYN_Flood"
            confidence = max(confidence, 0.98)
            anomaly_score = max(anomaly_score, 0.85)
        elif protocol == "UDP" and (raw.get("bytes_per_second", 0) > 100000 or raw.get("bytes_per_sec", 0) > 100000):
            prediction_label = "UDP_Flood"
            confidence = max(confidence, 0.95)
            anomaly_score = max(anomaly_score, 0.80)

        is_malicious = (prediction_label != "Normal") or (anomaly_score >= 0.65)

        src_ip = raw.get("source_ip", raw.get("src_ip", "0.0.0.0"))
        dst_ip = raw.get("destination_ip", raw.get("dst_ip", "0.0.0.0"))
        src_port = raw.get("source_port", raw.get("src_port", 0))
        dst_port = raw.get("destination_port", raw.get("dst_port", 0))

        return {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "prediction": prediction_label,
            "confidence": round(confidence, 4),
            "anomaly_score": anomaly_score,
            "is_malicious": is_malicious,
            "class_probabilities": {
                CLASS_LABELS[i]: round(float(prob), 4) for i, prob in enumerate(probabilities)
            } if len(probabilities) == len(CLASS_LABELS) else {},
        }

    def _heuristic_fallback(self, flow: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        """Rule-based fallback when ML engine models are uninitialized."""
        raw: Dict[str, Any] = flow.model_dump() if hasattr(flow, "model_dump") else dict(flow)
        syn = float(raw.get("syn_count", 0))
        ack = float(raw.get("ack_count", 0))
        pps = float(raw.get("packets_per_second", raw.get("packets_per_sec", 0.0)))
        bps = float(raw.get("bytes_per_second", raw.get("bytes_per_sec", 0.0)))
        proto = str(raw.get("protocol", "TCP")).upper()

        prediction = "Normal"
        confidence = 0.85
        anomaly_score = 0.15

        if proto == "TCP" and syn > 100 and ack == 0:
            prediction = "SYN_Flood"
            confidence = 0.98
            anomaly_score = 0.92
        elif proto == "UDP" and (pps > 150 or bps > 100000):
            prediction = "UDP_Flood"
            confidence = 0.94
            anomaly_score = 0.88
        elif pps > 500 and float(raw.get("packet_count", 1)) <= 3:
            prediction = "Port_Scan"
            confidence = 0.92
            anomaly_score = 0.79

        return {
            "source_ip": raw.get("source_ip", raw.get("src_ip", "0.0.0.0")),
            "destination_ip": raw.get("destination_ip", raw.get("dst_ip", "0.0.0.0")),
            "src_ip": raw.get("source_ip", raw.get("src_ip", "0.0.0.0")),
            "dst_ip": raw.get("destination_ip", raw.get("dst_ip", "0.0.0.0")),
            "src_port": raw.get("source_port", raw.get("src_port", 0)),
            "dst_port": raw.get("destination_port", raw.get("dst_port", 0)),
            "protocol": proto,
            "prediction": prediction,
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "is_malicious": prediction != "Normal",
            "class_probabilities": {prediction: confidence},
        }

    def evaluate_zero_day_anomaly(self, ood_df: pd.DataFrame, threshold: float = 0.65) -> Dict[str, Any]:
        """
        Evaluate unsupervised Isolation Forest anomaly scoring on Out-of-Distribution (OOD) novel zero-day attack traces.
        """
        if not self.is_trained:
            self.load_models()

        if self.scaler is None or self.anomaly_model is None:
            raise RuntimeError("Anomaly model is uninitialized.")

        results = []
        for _, row in ood_df.iterrows():
            pred = self.predict_flow(row)
            results.append(pred)

        scores = [r["anomaly_score"] for r in results]
        anomalies_flagged = sum(1 for s in scores if s >= threshold or r["is_malicious"])
        total = len(scores)
        detection_rate = (anomalies_flagged / total) if total > 0 else 0.0

        metrics = {
            "total_ood_samples": total,
            "anomalies_detected": anomalies_flagged,
            "zero_day_detection_rate": round(detection_rate, 4),
            "mean_anomaly_score": round(float(np.mean(scores)), 4) if scores else 0.0,
            "min_anomaly_score": round(float(np.min(scores)), 4) if scores else 0.0,
            "max_anomaly_score": round(float(np.max(scores)), 4) if scores else 0.0,
        }

        print(f"[*] Zero-Day / OOD Novel Attack Detection Rate : {metrics['zero_day_detection_rate']*100:.1f}% ({anomalies_flagged}/{total} flows flagged)")
        print(f"[*] Mean Zero-Day Anomaly Rating Score         : {metrics['mean_anomaly_score']:.4f} (Threshold: {threshold})")

        return metrics

    def predict_batch(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Perform batch threat inference on a sequence of flow records."""
        return [self.predict_flow(f) for f in flows]


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    engine = ThreatDetectionEngine()
    engine.train()

    sample_flow = {
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
    }
    result = engine.predict_flow(sample_flow)
    print("\nInference Output:")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
