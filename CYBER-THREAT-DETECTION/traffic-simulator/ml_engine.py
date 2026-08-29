#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 5: Machine Learning Engine
Module: ml_engine.py
Description: Dual-layer machine learning threat detector combining unsupervised Isolation Forest
             anomaly scoring with supervised multi-class Random Forest / XGBoost classification.
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

logger = logging.getLogger("ThreatDetectionEngine")

# Canonical feature list used for inference (13 features)
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
    1. Unsupervised Anomaly Scoring (Isolation Forest)
    2. Supervised Multi-Class Threat Classification (Random Forest / XGBoost)
    """

    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.scaler: Optional[StandardScaler] = None
        self.anomaly_model: Optional[IsolationForest] = None
        self.classifier_model: Optional[Any] = None
        self.feature_columns = FLOW_FEATURE_COLUMNS
        self.is_trained = False

        self._try_auto_load()

    def _try_auto_load(self) -> bool:
        """Attempt to load saved models from model_dir."""
        try:
            scaler_path = os.path.join(self.model_dir, "scaler.joblib")
            anomaly_path = os.path.join(self.model_dir, "anomaly_model.joblib")
            classifier_path = os.path.join(self.model_dir, "classifier_model.joblib")

            if not os.path.exists(classifier_path):
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

    def _extract_feature_dict(self, raw: Dict[str, Any]) -> Dict[str, float]:
        """Normalize raw flow dictionary keys into standardized numerical features."""
        packet_count = float(raw.get("packet_count", raw.get("packets", 1)))
        total_bytes = float(raw.get("total_bytes", raw.get("bytes", 0)))
        duration = float(raw.get("flow_duration", raw.get("duration", 0.0)))

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

        mean_pkt_size = float(raw.get("mean_packet_size", 0.0))
        if mean_pkt_size == 0.0 and packet_count > 0:
            mean_pkt_size = total_bytes / packet_count

        std_pkt_size = float(raw.get("std_packet_size", 0.0))
        iat_mean = float(raw.get("iat_mean", 0.0))
        iat_std = float(raw.get("iat_std", 0.0))
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
        raw = flow.to_dict() if hasattr(flow, "to_dict") else dict(flow)
        feat_map = self._extract_feature_dict(raw)
        vector = [feat_map.get(col, 0.0) for col in self.feature_columns]
        return np.array(vector, dtype=np.float64).reshape(1, -1)

    def train(
        self,
        dataset: Optional[Union[str, pd.DataFrame]] = None,
        test_size: float = 0.25,
        random_state: int = 42,
    ) -> Dict[str, Any]:
        """Train StandardScaler, Isolation Forest, and Multi-Class Random Forest classifier."""
        if dataset is not None:
            df = pd.read_csv(dataset) if isinstance(dataset, str) else dataset.copy()
            if "label" not in df.columns and "label_name" in df.columns:
                df["label"] = df["label_name"].map(LABEL_TO_CLASS)

            feat_rows = [self._extract_feature_dict(row) for _, row in df.iterrows()]
            X = pd.DataFrame(feat_rows)[self.feature_columns].values.astype(np.float64)
            y = df["label"].values.astype(int)
        else:
            raise ValueError("Dataset is required for training.")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        logger.info("Fitting StandardScaler on %d training feature vectors...", len(X_train))
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        logger.info("Training Isolation Forest Anomaly Detection Model...")
        self.anomaly_model = IsolationForest(
            n_estimators=100,
            contamination=0.20,
            random_state=random_state,
            n_jobs=-1,
        )
        self.anomaly_model.fit(X_train_scaled)

        logger.info("Training Multi-Class Random Forest Threat Classifier...")
        self.classifier_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=random_state,
            n_jobs=-1,
        )
        self.classifier_model.fit(X_train_scaled, y_train)

        y_pred = self.classifier_model.predict(X_test_scaled)
        accuracy = float(np.mean(y_pred == y_test))
        w_f1 = float(f1_score(y_test, y_pred, average="weighted"))
        w_prec = float(precision_score(y_test, y_pred, average="weighted"))
        w_rec = float(recall_score(y_test, y_pred, average="weighted"))

        report = classification_report(
            y_test, y_pred, target_names=[CLASS_LABELS[i] for i in sorted(CLASS_LABELS.keys())], output_dict=True
        )

        self.is_trained = True
        self.save_models(self.model_dir)

        logger.info("Model Training Complete! Test Accuracy: %.4f | Weighted F1: %.4f", accuracy, w_f1)
        return {
            "total_samples": len(df),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "accuracy": round(accuracy, 4),
            "weighted_precision": round(w_prec, 4),
            "weighted_recall": round(w_rec, 4),
            "weighted_f1_score": round(w_f1, 4),
            "classification_report": report,
        }

    def save_models(self, target_dir: str = "models") -> None:
        """Persist model artifacts."""
        os.makedirs(target_dir, exist_ok=True)
        if self.scaler:
            joblib.dump(self.scaler, os.path.join(target_dir, "scaler.joblib"))
        if self.anomaly_model:
            joblib.dump(self.anomaly_model, os.path.join(target_dir, "anomaly_model.joblib"))
        if self.classifier_model:
            joblib.dump(self.classifier_model, os.path.join(target_dir, "classifier_model.joblib"))
            joblib.dump(self.classifier_model, os.path.join(target_dir, "classifier.joblib"))
        logger.info("All model artifacts successfully persisted to: %s", target_dir)

    def predict_flow(self, flow: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        """Perform real-time threat classification & anomaly scoring."""
        raw = flow.model_dump() if hasattr(flow, "model_dump") else dict(flow)
        raw_feat = self._extract_feature_array(raw)

        if not self.is_trained or self.scaler is None or self.classifier_model is None:
            self._try_auto_load()

        if self.scaler is None or self.classifier_model is None or self.anomaly_model is None:
            # Fallback heuristic prediction if models missing
            pps = float(raw.get("packets_per_second", raw.get("packets_per_sec", 0)))
            syn = float(raw.get("syn_count", 0))
            protocol = str(raw.get("protocol", "TCP")).upper()

            if syn > 50:
                pred = "SYN_Flood"
                conf = 0.95
                anom = 0.85
            elif pps > 200 and protocol == "UDP":
                pred = "UDP_Flood"
                conf = 0.90
                anom = 0.80
            elif pps > 100:
                pred = "Port_Scan"
                conf = 0.88
                anom = 0.75
            else:
                pred = "Normal"
                conf = 0.98
                anom = 0.10

            return {
                "prediction": pred,
                "confidence": conf,
                "anomaly_score": anom,
                "is_malicious": pred != "Normal",
            }

        scaled_feat = self.scaler.transform(raw_feat)
        pred_class_id = int(self.classifier_model.predict(scaled_feat)[0])
        probabilities = self.classifier_model.predict_proba(scaled_feat)[0]
        confidence = float(probabilities[pred_class_id])
        prediction_label = CLASS_LABELS.get(pred_class_id, "Normal")

        # Isolation Forest anomaly score normalization to [0.0, 1.0]
        raw_score = self.anomaly_model.score_samples(scaled_feat)[0]
        anomaly_score = float(np.clip(0.5 - raw_score, 0.0, 1.0))

        is_malicious = prediction_label != "Normal" or anomaly_score > 0.65

        return {
            "prediction": prediction_label,
            "confidence": round(confidence, 4),
            "anomaly_score": round(anomaly_score, 4),
            "is_malicious": is_malicious,
        }
