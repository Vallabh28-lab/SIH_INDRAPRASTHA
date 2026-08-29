#!/usr/bin/env python3
"""
End-to-end verification script testing Phases 1 through 4 in an integrated pipeline.
"""

import unittest
from http_input_parser import parse_http_input
from dns_resolver import resolve_domain
from behavioral_flow_aggregator import generate_behavioral_flow
from threat_detector import ThreatDetectionEngine
from xai_explainer import ThreatExplainer
from threat_intel import ThreatIntelService
from audit_logger import ForensicAuditManager


class TestE2EPipeline4Phases(unittest.TestCase):
    """Integrates Phase 1 (Input Parsing), Phase 2 (DNS), Phase 3 (Flow Aggregation), and Phase 4 (Evaluation & Audit)."""

    def setUp(self):
        self.engine = ThreatDetectionEngine(model_dir="models")
        self.explainer = ThreatExplainer(model_dir="models")
        self.intel_service = ThreatIntelService()
        self.audit_manager = ForensicAuditManager("logs/test_e2e_audit.json")

    def test_full_pipeline_attack_workflow(self):
        # 1. Phase 1: Parse raw input URL
        raw_url = "https://target.lab:443/v1/admin/login?debug=true"
        domain = parse_http_input(raw_url)
        self.assertEqual(domain, "target.lab")

        # 2. Phase 2: Resolve Domain with Lab / Fallback support
        ip = resolve_domain(domain)
        self.assertEqual(ip, "192.168.10.20")

        # 3. Phase 3: Synthesize Behavioral SYN Flood flow record
        flow_record = generate_behavioral_flow(
            target_host_or_ip=ip,
            traffic_type="syn_flood",
            is_attack=True,
            destination_port=443,
        )
        self.assertEqual(flow_record["destination_ip"], "192.168.10.20")
        self.assertEqual(flow_record["destination_port"], 443)
        self.assertEqual(flow_record["syn_ratio"], 1.0)
        self.assertEqual(flow_record["ack_count"], 0)

        # 4. Phase 4: Local Pipeline Evaluation & Forensics
        pred = self.engine.predict_flow(flow_record)
        self.assertEqual(pred["prediction"], "SYN_Flood")
        self.assertTrue(pred["is_malicious"])

        xai = self.explainer.explain_prediction(flow_record)
        self.assertGreater(len(xai), 0)

        intel = self.intel_service.enrich_ip(flow_record["source_ip"])
        self.assertIn("country", intel)

        audit = self.audit_manager.log_malicious_event(
            event_payload=flow_record,
            prediction=pred["prediction"],
            confidence=pred["confidence"],
            anomaly_score=pred["anomaly_score"],
            source_ip=flow_record["source_ip"],
            destination_ip=flow_record["destination_ip"],
            xai_reasons=xai,
            auto_save=False,
        )
        self.assertTrue(len(audit["audit_hash"]) == 64)


if __name__ == "__main__":
    unittest.main()
