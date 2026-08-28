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

# Canonical feature list used for inference
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
        self.classifier: Optional[RandomForestClassifier] = None
        self.is_trained = False

    def _extract_feature_array(self, flow: Union[Dict[str, Any], pd.Series]) -> np.ndarray:
        """Extract ordered numerical feature vector from flow dictionary or Series."""
        vector = []
        for col in FLOW_FEATURE_COLUMNS:
            val = flow.get(col, 0.0) if isinstance(flow, dict) else flow[col]
            try:
                vector.append(float(val))
            except (ValueError, TypeError):
                vector.append(0.0)
        return np.array(vector, dtype=np.float64).reshape(1, -1)

    def train(
        self,
        dataset: Union[str, pd.DataFrame],
        test_size: float = 0.2,
        random_state: int = 42,
    ) -> Dict[str, Any]:
        """
        Train the feature scaler, Isolation Forest anomaly detector, and multi-class classifier.

        :param dataset: Path to CSV dataset or existing pandas DataFrame
        :param test_size: Fraction of samples reserved for test evaluation
        :param random_state: Seed for reproducible dataset splitting and training
        :return: Comprehensive performance evaluation dictionary
        """
        if isinstance(dataset, str):
            logger.info("Loading training dataset from: %s", dataset)
            df = pd.read_csv(dataset)
        else:
            df = dataset.copy()

        # Ensure required columns are present
        for col in FLOW_FEATURE_COLUMNS:
            if col not in df.columns:
                raise ValueError(f"Missing required feature column in dataset: '{col}'")

        if "label" not in df.columns and "label_name" in df.columns:
            df["label"] = df["label_name"].map(LABEL_TO_CLASS)

        X = df[FLOW_FEATURE_COLUMNS].values.astype(np.float64)
        y = df["label"].values.astype(int)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        logger.info("Fitting StandardScaler on %d training feature vectors...", len(X_train))
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # 1. Train Unsupervised Anomaly Detector (Isolation Forest)
        logger.info("Training Isolation Forest Anomaly Detection Model...")
        # Contamination estimated ~ 0.25 (as ~75% of dataset may be attacks in balanced lab benchmark)
        self.anomaly_model = IsolationForest(
            n_estimators=100,
            contamination=0.25,
            random_state=random_state,
            n_jobs=-1,
        )
        self.anomaly_model.fit(X_train_scaled)

        # 2. Train Multi-Class Threat Classifier (Random Forest)
        logger.info("Training Multi-Class Random Forest Threat Classifier...")
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            random_state=random_state,
            n_jobs=-1,
        )
        self.classifier.fit(X_train_scaled, y_train)

        self.is_trained = True

        # 3. Model Evaluation on Test Partition
        y_pred = self.classifier.predict(X_test_scaled)
        report = classification_report(
            y_test,
            y_pred,
            target_names=[CLASS_LABELS[i] for i in sorted(CLASS_LABELS.keys())],
            output_dict=True,
            zero_division=0,
        )
        conf_matrix = confusion_matrix(y_test, y_pred).tolist()

        metrics = {
            "total_samples": len(df),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "accuracy": float(report["accuracy"]),
            "weighted_precision": float(report["weighted avg"]["precision"]),
            "weighted_recall": float(report["weighted avg"]["recall"]),
            "weighted_f1_score": float(report["weighted avg"]["f1-score"]),
            "confusion_matrix": conf_matrix,
            "classification_report": report,
        }

        logger.info(
            "Model Training Complete! Test Accuracy: %.4f | Weighted F1: %.4f",
            metrics["accuracy"],
            metrics["weighted_f1_score"],
        )

        # Save artifacts
        self.save_models()
        return metrics

    def save_models(self, output_dir: Optional[str] = None) -> None:
        """Persist trained scaler, anomaly model, and classifier to disk."""
        target_dir = output_dir or self.model_dir
        os.makedirs(target_dir, exist_ok=True)

        if not self.is_trained or not self.scaler or not self.classifier or not self.anomaly_model:
            raise RuntimeError("Models are not trained. Call train() before save_models().")

        joblib.dump(self.scaler, os.path.join(target_dir, "scaler.joblib"))
        joblib.dump(self.anomaly_model, os.path.join(target_dir, "anomaly_model.joblib"))
        joblib.dump(self.classifier, os.path.join(target_dir, "classifier.joblib"))

        metadata = {
            "feature_columns": FLOW_FEATURE_COLUMNS,
            "class_labels": CLASS_LABELS,
        }
        with open(os.path.join(target_dir, "model_metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info("All model artifacts successfully persisted to: %s", target_dir)

    def load_models(self, model_dir: Optional[str] = None) -> None:
        """Load persisted scaler, anomaly model, and classifier from disk."""
        target_dir = model_dir or self.model_dir
        scaler_path = os.path.join(target_dir, "scaler.joblib")
        anomaly_path = os.path.join(target_dir, "anomaly_model.joblib")
        classifier_path = os.path.join(target_dir, "classifier.joblib")

        if not (os.path.exists(scaler_path) and os.path.exists(anomaly_path) and os.path.exists(classifier_path)):
            raise FileNotFoundError(f"Model artifacts not found in directory: '{target_dir}'")

        self.scaler = joblib.load(scaler_path)
        self.anomaly_model = joblib.load(anomaly_path)
        self.classifier = joblib.load(classifier_path)
        self.is_trained = True
        logger.info("Loaded models and scaler from: %s", target_dir)

    def predict_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform real-time threat inference on a single 5-tuple flow record.

        :param flow: Flow record dictionary containing statistical features
        :return: Structured inference result dict
        """
        if not self.is_trained:
            self.load_models()

        if self.scaler is None or self.anomaly_model is None or self.classifier is None:
            raise RuntimeError("Models are not initialized.")

        # Extract & scale feature vector
        feat_vector = self._extract_feature_array(flow)
        scaled_feat = self.scaler.transform(feat_vector)

        # 1. Unsupervised Anomaly Scoring (Sigmoid transformed decision function -> [0.0, 1.0])
        # Decision function: >0 is inlier (normal), <0 is outlier (anomalous)
        raw_score = float(self.anomaly_model.decision_function(scaled_feat)[0])
        # Map raw score so that higher value = higher anomaly (1.0 = highly anomalous, 0.0 = normal)
        anomaly_score = float(1.0 / (1.0 + np.exp(raw_score * 3.5)))
        anomaly_score = max(0.0, min(1.0, round(anomaly_score, 4)))

        # 2. Supervised Multi-Class Threat Classification
        pred_class_id = int(self.classifier.predict(scaled_feat)[0])
        probabilities = self.classifier.predict_proba(scaled_feat)[0]
        confidence = float(probabilities[pred_class_id])
        prediction_label = CLASS_LABELS.get(pred_class_id, "Unknown")

        # Determine malicious status
        is_malicious = (pred_class_id != 0) or (anomaly_score > 0.65)

        return {
            "src_ip": flow.get("src_ip", "0.0.0.0"),
            "dst_ip": flow.get("dst_ip", "0.0.0.0"),
            "src_port": flow.get("src_port", 0),
            "dst_port": flow.get("dst_port", 0),
            "protocol": flow.get("protocol", "OTHER"),
            "prediction": prediction_label,
            "confidence": round(confidence, 4),
            "anomaly_score": anomaly_score,
            "is_malicious": is_malicious,
            "class_probabilities": {
                CLASS_LABELS[i]: round(float(prob), 4) for i, prob in enumerate(probabilities)
            },
        }

    def predict_batch(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Perform batch threat inference on a sequence of flow records."""
        return [self.predict_flow(f) for f in flows]
