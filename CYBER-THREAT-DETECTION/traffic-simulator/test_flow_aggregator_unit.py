#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 3 Unit Tests
Module: test_flow_aggregator_unit.py
Description: Unit and integration tests for flow_aggregator.py
"""

import time
import unittest
from flow_aggregator import (
    FlowAggregator,
    FlowRecord,
    RealTimeFlowSniffer,
    format_flows_table,
)


class TestFlowAggregator(unittest.TestCase):
    """Test suite for 5-tuple flow aggregation and statistical feature engineering."""

    def setUp(self):
        # Construct synthetic bi-directional TCP conversation
        self.t0 = 1000.0
        self.synthetic_packets = [
            # Packet 1: Client -> Server (SYN)
            {
                "timestamp": self.t0 + 0.00,
                "src_ip": "192.168.10.10",
                "dst_ip": "192.168.10.20",
                "src_port": 54321,
                "dst_port": 80,
                "protocol": "TCP",
                "length": 64,
                "tcp_flags": ["SYN"],
            },
            # Packet 2: Server -> Client (SYN-ACK)
            {
                "timestamp": self.t0 + 0.01,
                "src_ip": "192.168.10.20",
                "dst_ip": "192.168.10.10",
                "src_port": 80,
                "dst_port": 54321,
                "protocol": "TCP",
                "length": 64,
                "tcp_flags": ["SYN", "ACK"],
            },
            # Packet 3: Client -> Server (ACK)
            {
                "timestamp": self.t0 + 0.02,
                "src_ip": "192.168.10.10",
                "dst_ip": "192.168.10.20",
                "src_port": 54321,
                "dst_port": 80,
                "protocol": "TCP",
                "length": 54,
                "tcp_flags": ["ACK"],
            },
            # Packet 4: Client -> Server (PSH-ACK HTTP GET)
            {
                "timestamp": self.t0 + 0.05,
                "src_ip": "192.168.10.10",
                "dst_ip": "192.168.10.20",
                "src_port": 54321,
                "dst_port": 80,
                "protocol": "TCP",
                "length": 350,
                "tcp_flags": ["PSH", "ACK"],
            },
            # Packet 5: Server -> Client (ACK Data Stream)
            {
                "timestamp": self.t0 + 0.08,
                "src_ip": "192.168.10.20",
                "dst_ip": "192.168.10.10",
                "src_port": 80,
                "dst_port": 54321,
                "protocol": "TCP",
                "length": 1400,
                "tcp_flags": ["ACK"],
            },
        ]

    def test_bidirectional_aggregation_single_flow(self):
        """Verify that reverse packets are mapped into a single canonical bi-directional flow."""
        aggregator = FlowAggregator(raw_packets=self.synthetic_packets, bidirectional=True)
        flows = aggregator.aggregate()

        self.assertEqual(len(flows), 1)
        flow = flows[0]

        # Verify Canonical 5-Tuple
        self.assertEqual(flow["src_ip"], "192.168.10.10")
        self.assertEqual(flow["dst_ip"], "192.168.10.20")
        self.assertEqual(flow["src_port"], 54321)
        self.assertEqual(flow["dst_port"], 80)
        self.assertEqual(flow["protocol"], "TCP")

        # Verify Packet & Byte Counts
        self.assertEqual(flow["packet_count"], 5)
        self.assertEqual(flow["fwd_packet_count"], 3)  # Packets 1, 3, 4
        self.assertEqual(flow["bwd_packet_count"], 2)  # Packets 2, 5
        self.assertEqual(flow["total_bytes"], 64 + 64 + 54 + 350 + 1400)
        self.assertEqual(flow["fwd_bytes"], 64 + 54 + 350)
        self.assertEqual(flow["bwd_bytes"], 64 + 1400)

        # Verify Temporal & IAT
        self.assertAlmostEqual(flow["flow_duration"], 0.08, places=4)
        self.assertGreater(flow["iat_mean"], 0.0)
        self.assertEqual(flow["iat_min"], 0.01)
        self.assertEqual(flow["iat_max"], 0.03)

        # Verify TCP Flags
        self.assertEqual(flow["syn_count"], 1)  # Packet 1 is SYN
        self.assertEqual(flow["syn_ack_count"], 1)  # Packet 2 is SYN-ACK
        self.assertEqual(flow["ack_count"], 4)  # Packets 2, 3, 4, 5
        self.assertEqual(flow["psh_count"], 1)  # Packet 4

        # Verify Ratios
        self.assertEqual(flow["syn_ratio"], 0.2)  # 1 / 5
        self.assertEqual(flow["ack_ratio"], 0.8)  # 4 / 5

    def test_unidirectional_aggregation_mode(self):
        """Verify that disabling bidirectional aggregation creates distinct forward/backward flows."""
        aggregator = FlowAggregator(raw_packets=self.synthetic_packets, bidirectional=False)
        flows = aggregator.aggregate()

        self.assertEqual(len(flows), 2)  # One Client->Server, One Server->Client

    def test_api_record_serialization(self):
        """Verify that to_api_records outputs schema compatible with FlowRecordSchema."""
        aggregator = FlowAggregator(raw_packets=self.synthetic_packets)
        api_records = aggregator.to_api_records()

        self.assertEqual(len(api_records), 1)
        rec = api_records[0]
        self.assertIn("source_ip", rec)
        self.assertIn("destination_ip", rec)
        self.assertIn("packets_per_second", rec)
        self.assertIn("bytes_per_second", rec)
        self.assertEqual(rec["source_ip"], "192.168.10.10")

    def test_dataframe_export(self):
        """Verify Pandas DataFrame export format."""
        aggregator = FlowAggregator(raw_packets=self.synthetic_packets)
        df = aggregator.to_dataframe()
        self.assertEqual(len(df), 1)

    def test_summary_metrics(self):
        """Verify summary calculations."""
        aggregator = FlowAggregator(raw_packets=self.synthetic_packets)
        summary = aggregator.summary()
        self.assertEqual(summary["total_raw_packets"], 5)
        self.assertEqual(summary["unique_flows_count"], 1)
        self.assertEqual(summary["detected_protocols"], ["TCP"])

    def test_format_flows_table(self):
        """Verify terminal table formatting string."""
        aggregator = FlowAggregator(raw_packets=self.synthetic_packets)
        flows = aggregator.aggregate()
        table_str = format_flows_table(flows)
        self.assertIn("192.168.10.10:54321 -> 192.168.10.20:80", table_str)
        self.assertIn("TCP", table_str)


if __name__ == "__main__":
    unittest.main()
