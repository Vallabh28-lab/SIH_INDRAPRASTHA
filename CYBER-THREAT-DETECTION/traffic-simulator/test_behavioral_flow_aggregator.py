#!/usr/bin/env python3
"""
Unit tests for Phase 3 Behavioral Flow Aggregator (behavioral_flow_aggregator.py).
"""

import unittest
from behavioral_flow_aggregator import generate_behavioral_flow
from flow_schema import FlowRecordSchema
from threat_detector import ThreatDetectionEngine


class TestBehavioralFlowAggregator(unittest.TestCase):
    """Test suite verifying behavioral profile generation, anomaly injection, and schema compliance."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatDetectionEngine(model_dir="models")

    def test_normal_traffic_profile(self):
        """Verify normal traffic produces balanced handshakes and passes Pydantic validation."""
        flow = generate_behavioral_flow(
            target_host_or_ip="192.168.10.20",
            traffic_type="normal",
            is_attack=False,
        )
        # Check Pydantic compliance
        validated = FlowRecordSchema(**flow)
        self.assertIsNotNone(validated)
        self.assertEqual(flow["destination_ip"], "192.168.10.20")
        self.assertGreater(flow["ack_count"], 0)
        self.assertGreater(flow["ack_ratio"], 0.80)
        self.assertGreater(flow["iat_mean"], 0.01)

    def test_syn_flood_attack_injection(self):
        """Verify malicious SYN flood injection generates massive SYNs, 0 ACKs, and low IAT."""
        flow = generate_behavioral_flow(
            target_host_or_ip="collector.internal",
            traffic_type="syn_flood",
            is_attack=True,
        )
        self.assertEqual(flow["destination_ip"], "192.168.10.20")
        self.assertEqual(flow["protocol"], "TCP")
        self.assertGreaterEqual(flow["syn_count"], 250)
        self.assertEqual(flow["ack_count"], 0)
        self.assertEqual(flow["syn_ratio"], 1.0)
        self.assertEqual(flow["ack_ratio"], 0.0)
        self.assertLess(flow["iat_mean"], 0.005)
        self.assertGreater(flow["packets_per_second"], 200.0)

        # Verify Threat Engine evaluates this as a malicious SYN_Flood
        prediction = self.engine.predict_flow(flow)
        self.assertEqual(prediction["prediction"], "SYN_Flood")
        self.assertTrue(prediction["is_malicious"])

    def test_port_scan_reconnaissance_injection(self):
        """Verify port scan produces single-packet probe with instantaneous burst rate."""
        flow = generate_behavioral_flow(
            target_host_or_ip="192.168.10.20",
            traffic_type="port_scan",
            is_attack=True,
        )
        self.assertEqual(flow["packet_count"], 1)
        self.assertEqual(flow["syn_count"], 1)
        self.assertEqual(flow["ack_count"], 0)
        self.assertEqual(flow["flow_duration"], 0.0)

        # Verify Threat Engine classification
        prediction = self.engine.predict_flow(flow)
        self.assertEqual(prediction["prediction"], "Port_Scan")
        self.assertTrue(prediction["is_malicious"])

    def test_udp_flood_attack_injection(self):
        """Verify UDP flood produces large volume UDP packets and 0 flags."""
        flow = generate_behavioral_flow(
            target_host_or_ip="192.168.10.20",
            traffic_type="udp_flood",
            is_attack=True,
        )
        self.assertEqual(flow["protocol"], "UDP")
        self.assertGreater(flow["total_bytes"], 100000)
        self.assertEqual(flow["syn_count"], 0)
        self.assertEqual(flow["ack_count"], 0)

        # Verify Threat Engine classification
        prediction = self.engine.predict_flow(flow)
        self.assertEqual(prediction["prediction"], "UDP_Flood")
        self.assertTrue(prediction["is_malicious"])


if __name__ == "__main__":
    unittest.main()
