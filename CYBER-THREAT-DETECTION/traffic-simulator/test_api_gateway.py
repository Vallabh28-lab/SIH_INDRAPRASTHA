#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 4 Unit Tests
Module: test_api_gateway.py
Description: Comprehensive API Gateway endpoint and schema validation test suite using FastAPI TestClient.
"""

import json
import os
import unittest
from fastapi.testclient import TestClient
from api import app, FLOWS_LOG_FILE
from flow_schema import FlowRecordSchema


class TestFastAPIGateway(unittest.TestCase):
    """Test suite for FastAPI Control Gateway and Flow Ingestion Pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_check_endpoint(self):
        """Verify GET /health endpoint returns 200 OK and system status."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "traffic-simulator-gateway")

    def test_ingest_valid_flow_telemetry(self):
        """Verify POST /api/traffic successfully ingests and validates standard flow payload."""
        payload = {
            "source_ip": "192.168.10.10",
            "destination_ip": "192.168.10.20",
            "source_port": 54321,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 100,
            "total_bytes": 38400,
            "packets_per_second": 33.88,
            "bytes_per_second": 13012.5,
            "iat_mean": 0.0298,
            "syn_count": 1,
            "ack_count": 99,
            "flow_duration": 2.951,
        }
        response = self.client.post("/api/traffic", json=payload)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("prediction", data)
        self.assertIn("confidence", data)
        self.assertIn("anomaly_score", data)

        # Verify record was appended to logs/flows.jsonl
        self.assertTrue(os.path.exists(FLOWS_LOG_FILE))
        with open(FLOWS_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            self.assertGreater(len(lines), 0)
            last_record = json.loads(lines[-1])
            self.assertEqual(last_record["source_ip"], "192.168.10.10")

    def test_ingest_aliased_field_reconciliation(self):
        """Verify schema automatically reconciles src_ip/dst_ip into source_ip/destination_ip."""
        aliased_payload = {
            "src_ip": "172.16.8.99",
            "dst_ip": "192.168.10.20",
            "src_port": 58000,
            "dst_port": 22,
            "protocol": "tcp",
            "packet_count": 1,
            "total_bytes": 64,
            "packets_per_sec": 100.0,
            "bytes_per_sec": 6400.0,
            "iat_mean": 0.0,
            "syn_count": 1,
            "ack_count": 0,
        }
        response = self.client.post("/api/traffic", json=aliased_payload)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["received_flow"]["source_ip"], "172.16.8.99")
        self.assertEqual(data["received_flow"]["protocol"], "TCP")

    def test_validation_error_invalid_ip_format(self):
        """Verify POST /api/traffic returns 422 Unprocessable Entity on malformed IP address."""
        invalid_ip_payload = {
            "source_ip": "999.999.999.999",  # Invalid IPv4
            "destination_ip": "192.168.10.20",
            "protocol": "TCP",
            "packet_count": 10,
            "total_bytes": 640,
            "packets_per_second": 10.0,
            "bytes_per_second": 640.0,
            "iat_mean": 0.1,
            "syn_count": 1,
            "ack_count": 9,
        }
        response = self.client.post("/api/traffic", json=invalid_ip_payload)
        self.assertEqual(response.status_code, 422)

    def test_validation_error_negative_counts(self):
        """Verify POST /api/traffic returns 422 on negative packet counts."""
        negative_payload = {
            "source_ip": "192.168.10.10",
            "destination_ip": "192.168.10.20",
            "protocol": "TCP",
            "packet_count": -5,  # Invalid ge=1
            "total_bytes": 640,
            "packets_per_second": 10.0,
            "bytes_per_second": 640.0,
            "iat_mean": 0.1,
            "syn_count": 1,
            "ack_count": 9,
        }
        response = self.client.post("/api/traffic", json=negative_payload)
        self.assertEqual(response.status_code, 422)

    def test_get_traffic_polling_endpoint(self):
        """Verify GET /api/traffic returns SOC dashboard metrics and recent events."""
        response = self.client.get("/api/traffic?limit=50")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("metrics", data)
        self.assertIn("events", data)
        self.assertIn("total_flows", data["metrics"])



if __name__ == "__main__":
    unittest.main()
