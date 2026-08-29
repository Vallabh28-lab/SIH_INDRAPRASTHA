#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 2 Unit Tests
Module: test_traffic_generator.py
Description: Comprehensive unit and integration test suite for traffic_generator.py
"""

import unittest
from unittest.mock import MagicMock, patch
from traffic_generator import (
    BaseTrafficConfig,
    NormalTrafficConfig,
    SynFloodConfig,
    PortScanConfig,
    UdpFloodConfig,
    TrafficGenerator,
    generate_random_ip_from_subnet,
    resolve_tcp_flags,
    calculate_payload_padding,
    format_telemetry_table,
    TOP_SERVICES_PORTS,
)


class TestTrafficGeneratorUtilities(unittest.TestCase):
    """Test suite for helper functions and network utilities."""

    def test_random_ip_generation(self):
        """Test random IP generation from CIDR."""
        ip = generate_random_ip_from_subnet("10.0.0.0/16")
        self.assertTrue(ip.startswith("10.0."))
        
        ip_class_b = generate_random_ip_from_subnet("172.16.0.0/16")
        self.assertTrue(ip_class_b.startswith("172.16."))

    def test_resolve_tcp_flags(self):
        """Test TCP flag string resolution."""
        self.assertEqual(resolve_tcp_flags(["SYN"]), "S")
        self.assertEqual(resolve_tcp_flags(["SYN", "ACK"]), "SA")
        self.assertEqual(resolve_tcp_flags(["FIN", "PSH", "URG"]), "FPU")
        self.assertEqual(resolve_tcp_flags(["UNKNOWN"]), "S")  # Fallback

    def test_calculate_payload_padding(self):
        """Test payload padding calculation for target packet sizes."""
        payload = calculate_payload_padding(
            base_headers_size=40,
            target_packet_size=100,
            custom_payload="HELLO",
        )
        self.assertEqual(len(payload), 60)  # 100 - 40
        self.assertTrue(payload.startswith(b"HELLO"))


class TestTrafficGeneratorEngine(unittest.TestCase):
    """Test suite for packet synthesis and attack simulation modules."""

    def setUp(self):
        self.generator = TrafficGenerator()

    @patch("traffic_generator.send")
    def test_generate_normal_stream_tcp(self, mock_send):
        """Test Normal HTTP/TCP background traffic generation."""
        config = NormalTrafficConfig(
            source_ip="192.168.10.10",
            destination_ip="192.168.10.20",
            source_port=50000,
            destination_port=80,
            packet_count=10,
            iat_sec=0.001,
            protocol="TCP",
        )
        report = self.generator.generate_normal_stream(config)

        self.assertEqual(report.status, "COMPLETED")
        self.assertEqual(report.packets_transmitted, 10)
        self.assertEqual(report.protocol, "TCP")
        self.assertEqual(report.attack_vector, "Normal_Traffic")
        self.assertEqual(mock_send.call_count, 10)

    @patch("traffic_generator.send")
    def test_generate_normal_stream_udp(self, mock_send):
        """Test Normal DNS/UDP background traffic generation."""
        config = NormalTrafficConfig(
            source_ip="192.168.10.10",
            destination_ip="192.168.10.20",
            source_port=5353,
            destination_port=53,
            packet_count=5,
            iat_sec=0.001,
            protocol="UDP",
        )
        report = self.generator.generate_normal_stream(config)

        self.assertEqual(report.status, "COMPLETED")
        self.assertEqual(report.packets_transmitted, 5)
        self.assertEqual(report.protocol, "UDP")
        self.assertEqual(mock_send.call_count, 5)

    @patch("traffic_generator.send")
    def test_generate_syn_flood(self, mock_send):
        """Test High-Rate Spoofed SYN Flood generation."""
        config = SynFloodConfig(
            source_ip="192.168.10.10",
            destination_ip="192.168.10.20",
            destination_port=80,
            packet_count=20,
            iat_sec=0.001,
            spoof_source_ip=True,
            spoof_subnet="172.16.0.0/16",
            random_source_port=True,
        )
        report = self.generator.generate_syn_flood(config)

        self.assertEqual(report.status, "COMPLETED")
        self.assertEqual(report.packets_transmitted, 20)
        self.assertEqual(report.attack_vector, "SYN_Flood")
        self.assertEqual(mock_send.call_count, 20)

    @patch("traffic_generator.send")
    def test_generate_port_scan_sequential(self, mock_send):
        """Test Sequential Multi-Port Scan probe generation."""
        config = PortScanConfig(
            source_ip="192.168.10.10",
            destination_ip="192.168.10.20",
            start_port=20,
            end_port=25,
            scan_type="SYN",
            iat_sec=0.001,
        )
        report = self.generator.generate_port_scan(config)

        self.assertEqual(report.status, "COMPLETED")
        self.assertEqual(report.packets_transmitted, 6)  # Ports 20, 21, 22, 23, 24, 25
        self.assertEqual(report.attack_vector, "Port_Scan_SYN")
        self.assertEqual(mock_send.call_count, 6)

    @patch("traffic_generator.send")
    def test_generate_port_scan_common(self, mock_send):
        """Test Port Scan with top common service ports."""
        config = PortScanConfig(
            source_ip="192.168.10.10",
            destination_ip="192.168.10.20",
            custom_ports=TOP_SERVICES_PORTS[:5],
            scan_type="XMAS",
            iat_sec=0.001,
        )
        report = self.generator.generate_port_scan(config)

        self.assertEqual(report.status, "COMPLETED")
        self.assertEqual(report.packets_transmitted, 5)
        self.assertEqual(report.attack_vector, "Port_Scan_XMAS")
        self.assertEqual(mock_send.call_count, 5)

    @patch("traffic_generator.send")
    def test_generate_udp_flood(self, mock_send):
        """Test Dense Volumetric UDP Flood generation."""
        config = UdpFloodConfig(
            source_ip="192.168.10.10",
            destination_ip="192.168.10.20",
            destination_port=9999,
            packet_count=15,
            packet_size=512,
            iat_sec=0.001,
            spoof_source_ip=False,
        )
        report = self.generator.generate_udp_flood(config)

        self.assertEqual(report.status, "COMPLETED")
        self.assertEqual(report.packets_transmitted, 15)
        self.assertEqual(report.attack_vector, "UDP_Flood")
        self.assertEqual(mock_send.call_count, 15)
        self.assertGreater(report.total_bytes_sent, 15 * 500)

    def test_format_telemetry_table(self):
        """Test telemetry report formatter output string."""
        config = NormalTrafficConfig(packet_count=5)
        with patch("traffic_generator.send"):
            report = self.generator.generate_normal_stream(config)
        table_str = format_telemetry_table(report)
        self.assertIn("NTRO TELEMETRY GENERATION REPORT", table_str)
        self.assertIn("NORMAL_TRAFFIC", table_str)
        self.assertIn("Execution Status", table_str)



if __name__ == "__main__":
    unittest.main()
