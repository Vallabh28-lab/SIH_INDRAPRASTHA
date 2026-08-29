#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 7 Unit Tests
Module: test_audit_logger.py
Description: Unit tests for cryptographic SHA-256 tamper-evident forensic audit trail engine.
"""

import json
import os
import tempfile
import unittest
from audit_logger import ForensicAuditManager


class TestForensicAuditLogger(unittest.TestCase):
    """Test suite for SHA-256 hash chaining and tamper-evident integrity verification."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.temp_dir.name, "test_audit_trail.json")
        self.manager = ForensicAuditManager(log_path=self.log_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_log_malicious_event_creates_chained_record(self):
        """Verify logging malicious events computes block hashes and links prev_hash."""
        flow_payload_1 = {
            "source_ip": "10.0.4.88",
            "destination_ip": "192.168.10.20",
            "protocol": "TCP",
            "packet_count": 500,
            "total_bytes": 32000,
        }
        rec1 = self.manager.log_malicious_event(
            event_payload=flow_payload_1,
            prediction="SYN_Flood",
            confidence=0.99,
            anomaly_score=0.88,
            source_ip="10.0.4.88",
            destination_ip="192.168.10.20",
            xai_reasons=["High SYN ratio"],
        )

        self.assertEqual(rec1["prev_hash"], ForensicAuditManager.GENESIS_HASH)
        self.assertTrue(len(rec1["audit_hash"]) == 64)
        self.assertEqual(rec1["prediction"], "SYN_Flood")

        # Second record must chain from rec1
        flow_payload_2 = {
            "source_ip": "172.16.5.99",
            "destination_ip": "192.168.10.20",
            "protocol": "TCP",
            "packet_count": 1,
            "total_bytes": 60,
        }
        rec2 = self.manager.log_malicious_event(
            event_payload=flow_payload_2,
            prediction="Port_Scan",
            confidence=1.0,
            anomaly_score=0.75,
            source_ip="172.16.5.99",
            destination_ip="192.168.10.20",
            xai_reasons=["Single port probe"],
        )

        self.assertEqual(rec2["prev_hash"], rec1["audit_hash"])
        self.assertTrue(len(rec2["audit_hash"]) == 64)

    def test_cryptographic_integrity_verification(self):
        """Verify audit chain verification returns valid when untouched."""
        for i in range(3):
            self.manager.log_malicious_event(
                event_payload={"idx": i, "data": f"payload_{i}"},
                prediction="SYN_Flood",
                confidence=0.95,
                anomaly_score=0.80,
                source_ip=f"10.0.0.{i+1}",
                destination_ip="192.168.10.20",
            )

        verification = self.manager.verify_integrity()
        self.assertEqual(verification["status"], "VALID")
        self.assertEqual(verification["total_records"], 3)
        self.assertEqual(len(verification["corrupted_records"]), 0)

    def test_tamper_detection(self):
        """Verify that altering a field in audit log causes verification failure."""
        self.manager.log_malicious_event(
            event_payload={"data": "authentic"},
            prediction="SYN_Flood",
            confidence=0.95,
            anomaly_score=0.80,
            source_ip="10.0.0.1",
            destination_ip="192.168.10.20",
        )

        # Deliberately mutate data in memory / on disk
        self.manager.audit_records[0]["prediction"] = "Normal"  # Tampered!
        self.manager._save_audit_trail()

        verification = self.manager.verify_integrity()
        self.assertEqual(verification["status"], "CORRUPTED")
        self.assertEqual(len(verification["corrupted_records"]), 1)



if __name__ == "__main__":
    unittest.main()
