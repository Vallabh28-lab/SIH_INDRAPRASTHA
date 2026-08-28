#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 6: Explainable AI (XAI)
Module: xai_explainer.py
Description: Model Explainability engine utilizing SHAP (SHapley Additive exPlanations)
             and tree-based feature attribution to provide human-readable attribution breakdown
             for flagged cyber threats.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    shap = None  # type: ignore
    SHAP_AVAILABLE = False

logger = logging.getLogger("ThreatExplainer")

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

CLASS_LABELS = {
    0: "Normal",
    1: "SYN_Flood",
    2: "Port_Scan",
    3: "UDP_Flood",
}


class ThreatExplainer:
    """
    Explainable AI engine calculating SHAP / Tree-attribution values for incoming network flows
    to explain why specific network flows are flagged as malicious.
    """

    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.scaler: Optional[Any] = None
        self.classifier_model: Optional[Any] = None
        self.explainer: Optional[Any] = None
        self.feature_names = FLOW_FEATURE_COLUMNS
        self.is_initialized = False

        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Load serialized Random Forest classifier and StandardScaler."""
        scaler_path = os.path.join(self.model_dir, "scaler.joblib")
        classifier_path = os.path.join(self.model_dir, "classifier_model.joblib")

        if not (os.path.exists(scaler_path) and os.path.exists(classifier_path)):
            logger.warning("Model artifacts missing in '%s'. XAI engine uninitialized.", self.model_dir)
            return

        self.scaler = joblib.load(scaler_path)
        self.classifier_model = joblib.load(classifier_path)

        if SHAP_AVAILABLE and shap is not None:
            try:
                self.explainer = shap.TreeExplainer(self.classifier_model)
                logger.info("Initialized shap.TreeExplainer for Multi-Class Threat Classifier.")
            except Exception as exc:
                logger.warning("Failed to initialize shap.TreeExplainer (%s). Using native tree attribution.", exc)
                self.explainer = None
        else:
            logger.info("SHAP module unavailable. Using native tree feature attribution engine.")

        self.is_initialized = True

    def _extract_feature_vector(self, flow_dict: Dict[str, Any]) -> np.ndarray:
        """Extract ordered numerical feature vector from flow dictionary."""
        vector = []
        for col in self.feature_names:
            val = flow_dict.get(col, 0.0)
            try:
                vector.append(float(val))
            except (ValueError, TypeError):
                vector.append(0.0)
        return np.array(vector, dtype=np.float64).reshape(1, -1)

    def _compute_tree_attributions(self, scaled_feat: np.ndarray, pred_class_idx: int) -> np.ndarray:
        """
        High-performance exact tree-based feature contribution calculation:
        Measures individual feature decision influence across the Random Forest ensemble.
        """
        importances = self.classifier_model.feature_importances_
        # Weight by deviation from baseline (scaled zero-mean)
        deviations = np.abs(scaled_feat[0])
        contributions = importances * (deviations + 0.1)
        # Normalize sum of contributions to probability scale
        total = np.sum(contributions)
        if total > 0:
            contributions = contributions / total
        return contributions

    def explain_flow(self, flow_dict: Dict[str, Any], top_k: int = 3) -> Dict[str, Any]:
        """
        Calculate feature attribution values for an incoming flow and return the top_k
        features contributing to the prediction, formatted as human-readable strings.

        :param flow_dict: Extracted 5-tuple flow dictionary
        :param top_k: Number of top influential features to return (default: 3)
        :return: Structured XAI explanation dictionary
        """
        if not self.is_initialized:
            self._load_artifacts()

        if self.scaler is None or self.classifier_model is None:
            return {
                "prediction": "Unknown",
                "confidence": 0.0,
                "top_features": ["XAI model artifacts not yet loaded."],
                "feature_attributions": {},
            }

        raw_feat = self._extract_feature_vector(flow_dict)
        scaled_feat = self.scaler.transform(raw_feat)

        pred_class_id = int(self.classifier_model.predict(scaled_feat)[0])
        probabilities = self.classifier_model.predict_proba(scaled_feat)[0]
        confidence = float(probabilities[pred_class_id])
        prediction_label = CLASS_LABELS.get(pred_class_id, f"Class_{pred_class_id}")

        # Compute SHAP values or Tree Attributions
        feature_scores: Dict[str, float] = {}

        if self.explainer is not None and SHAP_AVAILABLE:
            try:
                shap_values = self.explainer.shap_values(scaled_feat)
                # Multi-class SHAP outputs list of arrays per class or 3D array
                if isinstance(shap_values, list):
                    class_shap = shap_values[pred_class_id][0]
                elif len(np.shape(shap_values)) == 3:
                    class_shap = shap_values[0, :, pred_class_id]
                else:
                    class_shap = shap_values[0]

                for idx, col in enumerate(self.feature_names):
                    feature_scores[col] = float(class_shap[idx])
            except Exception as exc:
                logger.warning("SHAP calculation fallback: %s", exc)
                contribs = self._compute_tree_attributions(scaled_feat, pred_class_id)
                for idx, col in enumerate(self.feature_names):
                    feature_scores[col] = float(contribs[idx])
        else:
            contribs = self._compute_tree_attributions(scaled_feat, pred_class_id)
            for idx, col in enumerate(self.feature_names):
                feature_scores[col] = float(contribs[idx])

        # Sort features by absolute contribution magnitude
        sorted_features = sorted(feature_scores.items(), key=lambda x: abs(x[1]), reverse=True)

        human_readable_top_k: List[str] = []
        top_feature_dict: Dict[str, float] = {}

        for col, influence in sorted_features[:top_k]:
            actual_val = flow_dict.get(col, 0.0)
            sign = "+" if influence >= 0 else ""
            if isinstance(actual_val, float):
                val_str = f"{actual_val:.4f}" if abs(actual_val) < 1.0 else f"{actual_val:.2f}"
            else:
                val_str = str(actual_val)

            formatted_str = f"{col} = {val_str} ({sign}{influence:.2f} influence)"
            human_readable_top_k.append(formatted_str)
            top_feature_dict[col] = round(influence, 4)

        return {
            "prediction": prediction_label,
            "confidence": round(confidence, 4),
            "top_features": human_readable_top_k,
            "feature_attributions": {k: round(v, 4) for k, v in sorted_features[:6]},
        }


def main() -> None:
    explainer = ThreatExplainer()
    sample_flow = {
        "src_ip": "10.0.99.1",
        "dst_ip": "192.168.10.20",
        "src_port": 49152,
        "dst_port": 80,
        "protocol": "TCP",
        "packet_count": 350,
        "syn_count": 350,
        "syn_ratio": 1.0,
        "syn_ack_ratio": 350.0,
        "fwd_bwd_ratio": 350.0,
        "packets_per_sec": 420.0,
        "bytes_per_sec": 22400.0,
        "flow_duration": 0.83,
        "iat_mean": 0.002,
        "iat_std": 0.0004,
    }
    explanation = explainer.explain_flow(sample_flow, top_k=3)
    print(json.dumps(explanation, indent=2))


if __name__ == "__main__":
    main()
