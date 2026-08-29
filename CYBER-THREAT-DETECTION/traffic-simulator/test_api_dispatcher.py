#!/usr/bin/env python3
"""
Unit tests for Phase 4 API Dispatcher & Response Handler (api_dispatcher.py).
"""

import unittest
from unittest.mock import patch, MagicMock
from api_dispatcher import dispatch_flow, render_response_card


class TestAPIDispatcher(unittest.TestCase):
    """Test suite verifying client dispatch, response parsing, and terminal rendering."""

    def setUp(self):
        self.sample_syn_flow = {
            "source_ip": "10.0.4.88",
            "destination_ip": "192.168.10.20",
            "source_port": 54321,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 500,
            "total_bytes": 32000,
            "packets_per_second": 1000.0,
            "bytes_per_second": 64000.0,
            "iat_mean": 0.001,
            "syn_count": 500,
            "ack_count": 0,
            "syn_ratio": 1.0,
            "ack_ratio": 0.0,
        }

        self.mock_api_response_malicious = {
            "status": "success",
            "prediction": "SYN_Flood",
            "confidence": 0.998,
            "anomaly_score": 0.8500,
            "is_malicious": True,
            "xai_explanations": [
                "High SYN packet concentration without ACK handshakes (syn_ratio = 1.000)",
                "Extremely high packet transmission rate (1000.0 pkts/sec)",
            ],
            "threat_intel": {
                "source_ip": {"country": "India", "asn": "AS-LAB-NTRO", "reputation_score": 85},
                "destination_ip": {"country": "India", "asn": "AS-LAB-NTRO (Target Gateway)"},
            },
            "audit_hash": "4779c2c543accb1c4e7f90119283748291028374910283749102837491028374",
            "audit_id": "AUD-04F2F7DA8184",
            "timestamp": "2026-08-30T00:50:00.000Z",
        }

    @patch("requests.post")
    def test_dispatch_flow_success(self, mock_post):
        """Verify successful dispatch and response parsing."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = self.mock_api_response_malicious
        mock_post.return_value = mock_resp

        result = dispatch_flow(self.sample_syn_flow, render_terminal=False)

        self.assertEqual(result["prediction"], "SYN_Flood")
        self.assertEqual(result["confidence"], 0.998)
        self.assertTrue(result["is_malicious"])
        self.assertEqual(len(result["xai_explanations"]), 2)
        self.assertTrue(len(result["audit_hash"]) == 64)

    @patch("requests.post")
    def test_dispatch_flow_render_terminal(self, mock_post):
        """Verify terminal rendering executes cleanly without exceptions."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = self.mock_api_response_malicious
        mock_post.return_value = mock_resp

        # Should execute print formatting without throwing
        result = dispatch_flow(self.sample_syn_flow, render_terminal=True)
        self.assertIsNotNone(result)

    @patch("requests.post")
    def test_dispatch_flow_connection_failure(self, mock_post):
        """Verify proper exception handling when the server is unreachable."""
        import requests
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection Refused")

        with self.assertRaises(ConnectionError):
            dispatch_flow(self.sample_syn_flow, render_terminal=False)


if __name__ == "__main__":
    unittest.main()
