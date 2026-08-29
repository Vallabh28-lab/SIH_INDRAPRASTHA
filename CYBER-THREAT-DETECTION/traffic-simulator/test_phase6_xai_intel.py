#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 6 Unit Tests
Module: test_phase6_xai_intel.py
Description: Unit test suite for XAI Explainability and Threat Intelligence enrichment.
"""

import unittest
from xai_explainer import ThreatExplainer
from threat_intel import ThreatIntelService


class TestXAIAndThreatIntel(unittest.TestCase):
    """Test suite for XAI TreeExplainer attribution and Threat Intelligence enrichment."""

    def setUp(self):
        self.explainer = ThreatExplainer(model_dir="models")
        self.intel_service = ThreatIntelService()

    def test_xai_syn_flood_explanations(self):
        """Verify that SYN Flood flows produce distinct XAI justifications."""
        syn_flood_flow = {
            "source_ip": "10.0.4.88",
            "destination_ip": "192.168.10.20",
            "source_port": 49152,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 500,
            "total_bytes": 32000,
            "flow_duration": 0.5,
            "packets_per_sec": 1000.0,
            "bytes_per_sec": 64000.0,
            "mean_packet_size": 64.0,
            "std_packet_size": 0.0,
            "iat_mean": 0.001,
            "iat_std": 0.0001,
            "syn_count": 500,
            "ack_count": 0,
            "syn_ratio": 1.0,
            "ack_ratio": 0.0,
        }
        explanations = self.explainer.explain_prediction(syn_flood_flow)
        self.assertIsInstance(explanations, list)
        self.assertGreater(len(explanations), 0)
        # Check if explanation contains human readable text
        joined_exp = " ".join(explanations)
        self.assertTrue("SYN" in joined_exp or "packet" in joined_exp or "rate" in joined_exp)

    def test_threat_intel_ip_enrichment_known_ip(self):
        """Verify enrichment of known adversarial IP (e.g. Tor or Chinese backbone)."""
        intel = self.intel_service.enrich_ip("185.220.101.5")
        self.assertIn("country", intel)
        self.assertIn("asn", intel)
        self.assertIn("reputation_score", intel)
        self.assertEqual(intel["country_code"], "DE")
        self.assertGreater(intel["reputation_score"], 80)

    def test_threat_intel_ip_enrichment_rfc1918(self):
        """Verify enrichment of local RFC1918 private IP."""
        intel = self.intel_service.enrich_ip("192.168.10.10")
        self.assertEqual(intel["country"], "India")
        self.assertIn("asn", intel)

    def test_threat_intel_ip_enrichment_dynamic_fallback(self):
        """Verify dynamic deterministic enrichment for unknown external IPs."""
        intel = self.intel_service.enrich_ip("203.0.113.195")
        self.assertIn("asn", intel)
        self.assertIn("reputation_score", intel)
        self.assertIn("risk_level", intel)


if __name__ == "__main__":
    unittest.main()
