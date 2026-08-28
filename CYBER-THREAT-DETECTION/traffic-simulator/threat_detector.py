#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - ML Threat Detection Pipeline
Module: threat_detector.py
Description: Advanced Threat Detection Engine with bi-directional and ratio-based feature representations,
             unsupervised Isolation Forest outlier scoring, supervised Random Forest classification,
             and Out-of-Distribution (OOD) zero-day anomaly evaluation.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd

from drift_detector import DataDriftDetector

logger = logging.getLogger("ThreatDetector")

# Comprehensive bi-directional and normalized ratio feature columns
FLOW_FEATURE_COLUMNS = [
    "packet_count",
    "fwd_packet_count",
    "bwd_packet_count",
    "total_bytes",
    "fwd_bytes",
    "bwd_bytes",
    "flow_duration",
    "packets_per_sec",
    "bytes_per_sec",
    "bwd_packets_per_sec",
    "mean_packet_size",
    "std_packet_size",
    "iat_mean",
    "iat_std",
    "syn_count",
    "syn_ack_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "syn_ratio",
    "ack_ratio",
    "syn_ack_ratio",
    "fwd_bwd_ratio",
    "byte_rate",
]

# Categorical class mapping
CLASS_LABELS = {
    0: "Normal",
    1: "SYN_Flood",
    2: "Port_Scan",
    3: "UDP_Flood",
}

LABEL_TO_CLASS = {v: k for k, v in CLASS_LABELS.items()}


class ThreatDetectionEngine:
    """
    Dual-layer machine learning detection engine for real-time network flow analysis:
    - Unsupervised Anomaly Scoring via Isolation Forest (0.0 to 1.0)
    - Supervised Multi-Class Threat Classification via Random Forest
    - Baseline Data Drift Detection
    """

    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.scaler: Optional[StandardScaler] = None
        self.anomaly_model: Optional[IsolationForest] = None
        self.classifier_model: Optional[RandomForestClassifier] = None
        self.drift_detector: Optional[DataDriftDetector] = None
        self.is_trained = False

    def _extract_feature_array(self, flow: Union[Dict[str, Any], pd.Series]) -> np.ndarray:
        """Extract ordered numerical feature vector from flow dictionary or pandas Series."""
        vector = []
        for col in FLOW_FEATURE_COLUMNS:
            val = flow.get(col, 0.0) if isinstance(flow, dict) else (flow[col] if col in flow else 0.0)
            try:
                vector.append(float(val))
            except (ValueError, TypeError):
                vector.append(0.0)
        return np.array(vector, dtype=np.float64).reshape(1, -1)

    def train(
        self,
        train_csv_path: Union[str, pd.DataFrame] = "data/dataset_train.csv",
        test_csv_path: Optional[Union[str, pd.DataFrame]] = "data/dataset_test.csv",
        random_state: int = 42,
    ) -> Dict[str, Any]:
        """
        Train scaler, Isolation Forest, and Random Forest classifier on labeled flow datasets.

        :param train_csv_path: Path to train CSV or DataFrame
        :param test_csv_path: Path to test CSV or DataFrame
        :param random_state: Seed for deterministic training
        :return: Evaluation metrics dictionary
        """
        if isinstance(train_csv_path, str):
            logger.info("Loading training dataset from: %s", train_csv_path)
            train_df = pd.read_csv(train_csv_path)
        else:
            train_df = train_csv_path.copy()

        if isinstance(test_csv_path, str) and os.path.exists(test_csv_path):
            logger.info("Loading test dataset from: %s", test_csv_path)
            test_df = pd.read_csv(test_csv_path)
        elif isinstance(test_csv_path, pd.DataFrame):
            test_df = test_csv_path.copy()
        else:
            logger.warning("No test dataset file found; partitioning 20%% hold-out from train dataset.")
            from sklearn.model_selection import train_test_split
            train_df, test_df = train_test_split(train_df, test_size=0.2, random_state=random_state)

        # Initialize Drift Detector with baseline distributions
        self.drift_detector = DataDriftDetector(baseline_df=train_df)

        # Extract numerical features and labels
        X_train = train_df[FLOW_FEATURE_COLUMNS].values.astype(np.float64)
        y_train = train_df["label"].values.astype(int)

        X_test = test_df[FLOW_FEATURE_COLUMNS].values.astype(np.float64)
        y_test = test_df["label"].values.astype(int)

        # 1. Fit StandardScaler on numerical features
        logger.info("Fitting StandardScaler on %d training flow feature vectors (%d dimensions)...", len(X_train), len(FLOW_FEATURE_COLUMNS))
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # 2. Train Unsupervised Isolation Forest (Anomaly Score Model)
        logger.info("Training Isolation Forest Anomaly Detection Model...")
        self.anomaly_model = IsolationForest(
            n_estimators=150,
            contamination=0.20,
            max_samples=0.85,
            random_state=random_state,
            n_jobs=-1,
        )
        self.anomaly_model.fit(X_train_scaled)

        # 3. Train Supervised Multi-Class Threat Classifier (Random Forest)
        logger.info("Training Random Forest Multi-Class Threat Classifier...")
        self.classifier_model = RandomForestClassifier(
            n_estimators=150,
            max_depth=16,
            min_samples_split=4,
            random_state=random_state,
            n_jobs=-1,
        )
        self.classifier_model.fit(X_train_scaled, y_train)

        self.is_trained = True

        # 4. Model Evaluation on dataset_test.csv
        y_pred = self.classifier_model.predict(X_test_scaled)
        report = classification_report(
            y_test,
            y_pred,
            target_names=[CLASS_LABELS[i] for i in sorted(CLASS_LABELS.keys())],
            output_dict=True,
            zero_division=0,
        )
        conf_matrix = confusion_matrix(y_test, y_pred).tolist()

        metrics = {
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "feature_count": len(FLOW_FEATURE_COLUMNS),
            "accuracy": float(report["accuracy"]),
            "weighted_precision": float(report["weighted avg"]["precision"]),
            "weighted_recall": float(report["weighted avg"]["recall"]),
            "weighted_f1_score": float(report["weighted avg"]["f1-score"]),
            "confusion_matrix": conf_matrix,
            "classification_report": report,
        }

        print("\n" + "=" * 80)
        print(" THREAT DETECTION ENGINE - TEST EVALUATION REPORT")
        print("=" * 80)
        print(f" Train Samples: {metrics['train_samples']} | Test Samples: {metrics['test_samples']} | Features: {metrics['feature_count']}")
        print(f" Test Accuracy: {metrics['accuracy']*100:.2f}% | Weighted F1: {metrics['weighted_f1_score']*100:.2f}%")
        print("=" * 80)
        print(pd.DataFrame(report).transpose().to_string())
        print("=" * 80)

        # 5. Persist Serialized Artifacts
        self.save_models()
        return metrics

    def evaluate_zero_day_anomaly(self, ood_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Evaluate unsupervised Isolation Forest against novel Out-of-Distribution (OOD) attack patterns
        not present in the supervised training dataset (Zero-Day Anomaly Validation).
        """
        if not self.is_trained:
            self.load_models()

        if self.scaler is None or self.anomaly_model is None:
            raise RuntimeError("Models must be trained before OOD evaluation.")

        X_ood = ood_df[FLOW_FEATURE_COLUMNS].values.astype(np.float64)
        X_ood_scaled = self.scaler.transform(X_ood)

        raw_scores = self.anomaly_model.decision_function(X_ood_scaled)
        # Scaled anomaly score (0.0 to 1.0)
        anomaly_scores = [float(1.0 / (1.0 + np.exp(s * 3.5))) for s in raw_scores]

        # Anomaly threshold
        anomalies_detected = sum(1 for s in anomaly_scores if s >= 0.45)
        detection_rate = anomalies_detected / len(anomaly_scores) if anomaly_scores else 0.0

        results = {
            "total_ood_samples": len(ood_df),
            "anomalies_flagged_count": anomalies_detected,
            "zero_day_detection_rate": round(detection_rate * 100, 2),
            "mean_anomaly_score": round(float(np.mean(anomaly_scores)), 4),
            "max_anomaly_score": round(float(np.max(anomaly_scores)), 4),
            "min_anomaly_score": round(float(np.min(anomaly_scores)), 4),
        }

        print("\n" + "=" * 80)
        print(" OUT-OF-DISTRIBUTION (OOD) ZERO-DAY ANOMALY DETECTION REPORT")
        print("=" * 80)
        print(f" Novel Zero-Day Samples Tested : {results['total_ood_samples']}")
        print(f" Flagged Anomaly Count         : {results['anomalies_flagged_count']} / {results['total_ood_samples']}")
        print(f" Zero-Day Detection Rate       : {results['zero_day_detection_rate']}%")
        print(f" Mean Anomaly Score            : {results['mean_anomaly_score']} (Outlier rating 0.0 - 1.0)")
        print("=" * 80)

        return results

    def save_models(self, output_dir: Optional[str] = None) -> None:
        """Persist serialized models and scaler under models/ directory."""
        target_dir = output_dir or self.model_dir
        os.makedirs(target_dir, exist_ok=True)

        if not self.is_trained or not self.scaler or not self.classifier_model or not self.anomaly_model:
            raise RuntimeError("Models must be trained before saving.")

        joblib.dump(self.scaler, os.path.join(target_dir, "scaler.joblib"))
        joblib.dump(self.anomaly_model, os.path.join(target_dir, "anomaly_model.joblib"))
        joblib.dump(self.classifier_model, os.path.join(target_dir, "classifier_model.joblib"))

        if self.drift_detector:
            joblib.dump(self.drift_detector, os.path.join(target_dir, "drift_detector.joblib"))

        metadata = {
            "feature_columns": FLOW_FEATURE_COLUMNS,
            "class_labels": CLASS_LABELS,
        }
        with open(os.path.join(target_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info("Persisted upgraded ML artifacts to '%s'", target_dir)

    def load_models(self, model_dir: Optional[str] = None) -> None:
        """Load serialized models and scaler from disk."""
        target_dir = model_dir or self.model_dir
        scaler_path = os.path.join(target_dir, "scaler.joblib")
        anomaly_path = os.path.join(target_dir, "anomaly_model.joblib")
        classifier_path = os.path.join(target_dir, "classifier_model.joblib")
        drift_path = os.path.join(target_dir, "drift_detector.joblib")

        if not (os.path.exists(scaler_path) and os.path.exists(anomaly_path) and os.path.exists(classifier_path)):
            raise FileNotFoundError(f"Required model artifacts missing in directory: '{target_dir}'")

        self.scaler = joblib.load(scaler_path)
        self.anomaly_model = joblib.load(anomaly_path)
        self.classifier_model = joblib.load(classifier_path)

        if os.path.exists(drift_path):
            self.drift_detector = joblib.load(drift_path)

        self.is_trained = True
        logger.info("Successfully loaded threat detection models from '%s'", target_dir)

    def predict_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Accept a single flow dictionary, scale features, and perform dual-layer threat inference:
        - prediction: String class name ("Normal", "SYN_Flood", "Port_Scan", "UDP_Flood")
        - confidence: Classification probability float (0.00 - 1.00)
        - anomaly_score: Outlier rating float (0.00 - 1.00)
        - is_malicious: Boolean flag (True if not Normal)
        """
        if not self.is_trained:
            self.load_models()

        if self.scaler is None or self.anomaly_model is None or self.classifier_model is None:
            raise RuntimeError("Engine models are not initialized.")

        # Extract & scale feature vector
        feat_vector = self._extract_feature_array(flow)
        scaled_feat = self.scaler.transform(feat_vector)

        # 1. Unsupervised Anomaly Scoring (Sigmoid transformed score in [0.0, 1.0])
        raw_score = float(self.anomaly_model.decision_function(scaled_feat)[0])
        anomaly_score = float(1.0 / (1.0 + np.exp(raw_score * 3.5)))
        anomaly_score = max(0.0, min(1.0, round(anomaly_score, 4)))

        # 2. Supervised Multi-Class Threat Classification
        pred_class_id = int(self.classifier_model.predict(scaled_feat)[0])
        probabilities = self.classifier_model.predict_proba(scaled_feat)[0]
        confidence = float(probabilities[pred_class_id])
        prediction_label = CLASS_LABELS.get(pred_class_id, "Unknown")

        # Threat classification verdict
        is_malicious = (pred_class_id != 0)

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
        """Perform batch threat prediction across multiple flow dictionaries."""
        return [self.predict_flow(f) for f in flows]


def main() -> None:
    engine = ThreatDetectionEngine()
    engine.train("data/dataset_train.csv", "data/dataset_test.csv")


if __name__ == "__main__":
    main()
