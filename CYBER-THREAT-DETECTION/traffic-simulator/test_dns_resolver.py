#!/usr/bin/env python3
"""
Unit tests for Phase 2 DNS Resolution Service (dns_resolver.py).
"""

import unittest
from dns_resolver import resolve_domain, resolve_domain_details, DEFAULT_LAB_FALLBACK_IP, LAB_DNS_REGISTRY


class TestDNSResolver(unittest.TestCase):
    """Test suite verifying IPv4 bypass, lab registry lookup, live DNS, and socket.gaierror fallback."""

    def test_direct_ipv4_bypass(self):
        """Verify that passing an IP directly returns the same IP immediately."""
        self.assertEqual(resolve_domain("192.168.10.20"), "192.168.10.20")
        self.assertEqual(resolve_domain("10.0.4.88"), "10.0.4.88")
        self.assertEqual(resolve_domain("127.0.0.1"), "127.0.0.1")

    def test_lab_dns_registry_lookup(self):
        """Verify preconfigured simulation lab hosts resolve without contacting external DNS."""
        self.assertEqual(resolve_domain("collector.internal"), "192.168.10.20")
        self.assertEqual(resolve_domain("generator.internal"), "192.168.10.10")
        self.assertEqual(resolve_domain("target.lab"), "192.168.10.20")
        self.assertEqual(resolve_domain("mock-bank.lab"), "192.168.10.100")

    def test_localhost_resolution(self):
        """Verify localhost resolves to 127.0.0.1."""
        self.assertEqual(resolve_domain("localhost"), "127.0.0.1")

    def test_unresolvable_mock_domain_gaierror_fallback(self):
        """Verify unresolvable or mock domains safely fallback to 192.168.10.1 without crashing."""
        unresolvable_host = "nonexistent-mock-demo-presentation-target.test"
        result_ip = resolve_domain(unresolvable_host)
        self.assertEqual(result_ip, DEFAULT_LAB_FALLBACK_IP)

    def test_custom_fallback_ip(self):
        """Verify user-defined custom fallback IP is respected on resolution failure."""
        unresolvable_host = "invalid-presentation-domain.internal-fake"
        custom_ip = "10.99.99.1"
        result_ip = resolve_domain(unresolvable_host, default_ip=custom_ip)
        self.assertEqual(result_ip, custom_ip)

    def test_resolve_domain_details_metadata(self):
        """Verify structured resolution diagnostic dictionary."""
        details_lab = resolve_domain_details("collector.internal")
        self.assertEqual(details_lab["resolved_ip"], "192.168.10.20")
        self.assertEqual(details_lab["resolution_source"], "LAB_REGISTRY")
        self.assertFalse(details_lab["is_fallback"])

        details_mock = resolve_domain_details("demo-adversary-fake-endpoint.test")
        self.assertEqual(details_mock["resolved_ip"], DEFAULT_LAB_FALLBACK_IP)
        self.assertEqual(details_mock["resolution_source"], "FALLBACK_SAFE_SUBNET")
        self.assertTrue(details_mock["is_fallback"])
        self.assertIn("socket.gaierror", details_mock["error"])


if __name__ == "__main__":
    unittest.main()
