#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - ML Threat Detection Pipeline
Module: drift_detector.py
Description: Statistical data drift monitoring engine utilizing two-sample Kolmogorov-Smirnov (KS)
             tests and Population Stability Index (PSI) to detect distribution shifts in streaming telemetry.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

logger = logging.getLogger("DataDriftDetector")

DRIFT_MONITORED_FEATURES = [
    "packet_count",
    "total_bytes",
    "flow_duration",
    "packets_per_sec",
    "bytes_per_sec",
    "mean_packet_size",
    "std_packet_size",
    "iat_mean",
    "iat_std",
    "syn_ratio",
    "ack_ratio",
    "syn_ack_ratio",
    "fwd_bwd_ratio",
    "byte_rate",
]


def ks_2samp_numpy(data1: np.ndarray, data2: np.ndarray) -> Tuple[float, float]:
    """
    High-performance two-sample Kolmogorov-Smirnov test computed via empirical CDFs.

    :param data1: Sample 1 array (baseline)
    :param data2: Sample 2 array (streaming)
    :return: (ks_statistic, p_value)
    """
    n1 = len(data1)
    n2 = len(data2)
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0

    data1_sorted = np.sort(data1)
    data2_sorted = np.sort(data2)
    all_data = np.concatenate([data1_sorted, data2_sorted])

    cdf1 = np.searchsorted(data1_sorted, all_data, side="right") / n1
    cdf2 = np.searchsorted(data2_sorted, all_data, side="right") / n2

    ks_stat = float(np.max(np.abs(cdf1 - cdf2)))

    # Asymptotic p-value approximation via Smirnov Kolmogorov expansion
    en = np.sqrt(n1 * n2 / (n1 + n2))
    lambda_val = (en + 0.12 + 0.11 / max(en, 0.01)) * ks_stat
    if lambda_val <= 0:
        p_val = 1.0
    else:
        terms = [2.0 * ((-1.0) ** (k - 1)) * np.exp(-2.0 * (k ** 2) * (lambda_val ** 2)) for k in range(1, 20)]
        p_val = float(np.clip(sum(terms), 0.0, 1.0))

    return ks_stat, p_val


class DataDriftDetector:
    """
    Continuous statistical drift detection engine comparing active inference telemetry
    against reference training baseline distributions using KS-test and PSI.
    """

    def __init__(
        self,
        baseline_df: Optional[pd.DataFrame] = None,
        ks_p_value_threshold: float = 0.05,
        psi_threshold: float = 0.20,
    ):
        self.ks_p_value_threshold = ks_p_value_threshold
        self.psi_threshold = psi_threshold
        self.baseline_stats: Dict[str, Dict[str, Any]] = {}
        self.baseline_distributions: Dict[str, np.ndarray] = {}

        if baseline_df is not None:
            self.fit_baseline(baseline_df)

    def fit_baseline(self, baseline_df: pd.DataFrame) -> "DataDriftDetector":
        """Fit and store baseline statistical distribution parameters from training dataset."""
        self.baseline_stats.clear()
        self.baseline_distributions.clear()

        for col in DRIFT_MONITORED_FEATURES:
            if col in baseline_df.columns:
                vals = baseline_df[col].dropna().values.astype(np.float64)
                if len(vals) > 0:
                    self.baseline_distributions[col] = vals
                    self.baseline_stats[col] = {
                        "mean": float(np.mean(vals)),
                        "std": float(np.std(vals)),
                        "min": float(np.min(vals)),
                        "max": float(np.max(vals)),
                        "median": float(np.median(vals)),
                        "count": len(vals),
                    }
        logger.info("Fitted drift baseline across %d continuous features.", len(self.baseline_stats))
        return self

    def _calculate_psi(
        self,
        expected: np.ndarray,
        actual: np.ndarray,
        num_buckets: int = 10,
    ) -> float:
        """Calculate Population Stability Index (PSI) between reference and streaming arrays."""
        if len(expected) == 0 or len(actual) == 0:
            return 0.0

        percentiles = np.linspace(0, 100, num_buckets + 1)
        try:
            bins = np.percentile(expected, percentiles)
            bins = np.unique(bins)
            if len(bins) < 2:
                bins = np.array([np.min(expected) - 1e-5, np.max(expected) + 1e-5])
        except Exception:
            bins = np.linspace(min(np.min(expected), np.min(actual)), max(np.max(expected), np.max(actual)), num_buckets + 1)

        exp_counts, _ = np.histogram(expected, bins=bins)
        act_counts, _ = np.histogram(actual, bins=bins)

        exp_pct = (exp_counts + 1e-4) / (len(expected) + 1e-4 * len(exp_counts))
        act_pct = (act_counts + 1e-4) / (len(actual) + 1e-4 * len(act_counts))

        psi_val = np.sum((act_pct - exp_pct) * np.log(act_pct / exp_pct))
        return float(max(0.0, psi_val))

    def evaluate_drift(
        self,
        current_data: Union[pd.DataFrame, List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Evaluate statistical drift between current window data and baseline distributions.

        :param current_data: Streaming window DataFrame or list of flow dictionaries
        :return: Structured drift report dictionary
        """
        if isinstance(current_data, list):
            current_df = pd.DataFrame(current_data)
        else:
            current_df = current_data.copy()

        if current_df.empty or not self.baseline_distributions:
            return {
                "drift_detected": False,
                "drift_level": "INSUFFICIENT_DATA",
                "drifted_features_count": 0,
                "feature_drift_metrics": {},
                "recommendation": "Collect more telemetry samples before computing drift.",
            }

        feature_metrics: Dict[str, Dict[str, Any]] = {}
        drifted_features: List[str] = []

        for col, base_vals in self.baseline_distributions.items():
            if col not in current_df.columns:
                continue

            curr_vals = current_df[col].dropna().values.astype(np.float64)
            if len(curr_vals) < 3:
                continue

            # 1. Kolmogorov-Smirnov Test via NumPy
            ks_stat, p_value = ks_2samp_numpy(base_vals, curr_vals)

            # 2. Population Stability Index (PSI)
            psi = self._calculate_psi(base_vals, curr_vals)

            is_drifted = (p_value < self.ks_p_value_threshold) or (psi > self.psi_threshold)
            if is_drifted:
                drifted_features.append(col)

            feature_metrics[col] = {
                "ks_statistic": round(ks_stat, 4),
                "p_value": round(p_value, 5),
                "psi": round(psi, 4),
                "is_drifted": is_drifted,
                "current_mean": round(float(np.mean(curr_vals)), 4),
                "baseline_mean": round(self.baseline_stats[col]["mean"], 4),
            }

        drift_ratio = len(drifted_features) / max(len(feature_metrics), 1)

        if drift_ratio >= 0.35:
            drift_level = "SIGNIFICANT_DRIFT"
            recommendation = "High data drift detected. Network topology or traffic baseline shifted. Trigger model retraining pipeline."
            drift_detected = True
        elif drift_ratio >= 0.15:
            drift_level = "MODERATE_DRIFT"
            recommendation = "Moderate drift observed. Monitor streaming window feature distributions closely."
            drift_detected = True
        else:
            drift_level = "NO_DRIFT"
            recommendation = "Traffic distributions align with baseline. Model inference remains reliable."
            drift_detected = False

        report = {
            "drift_detected": drift_detected,
            "drift_level": drift_level,
            "drift_ratio": round(drift_ratio, 4),
            "drifted_features_count": len(drifted_features),
            "drifted_features": drifted_features,
            "sample_count": len(current_df),
            "recommendation": recommendation,
            "feature_drift_metrics": feature_metrics,
        }

        if drift_detected:
            logger.warning(
                "[DATA DRIFT ALERT] Level: %s | Drifted: %d/%d features (%s)",
                drift_level,
                len(drifted_features),
                len(feature_metrics),
                ", ".join(drifted_features[:4]),
            )

        return report
