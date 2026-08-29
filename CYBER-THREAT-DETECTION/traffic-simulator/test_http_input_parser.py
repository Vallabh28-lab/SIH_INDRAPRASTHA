#!/usr/bin/env python3
"""
Unit tests for Phase 1 Input Parser Module (http_input_parser.py).
"""

import unittest
from http_input_parser import parse_http_input, parse_http_target_details


class TestHttpInputParser(unittest.TestCase):
    """Test suite covering standard URLs, bare domains, raw request lines, and edge cases."""

    def test_standard_http_and_https_urls(self):
        self.assertEqual(parse_http_input("http://example.com/path"), "example.com")
        self.assertEqual(parse_http_input("https://sub.domain.org/api/v1"), "sub.domain.org")
        self.assertEqual(parse_http_input("http://target.co.in/"), "target.co.in")

    def test_urls_with_ports_and_queries(self):
        self.assertEqual(parse_http_input("http://example.com:8080/path?query=test#hash"), "example.com")
        self.assertEqual(parse_http_input("http://example.com:8080/path", include_port=True), "example.com:8080")

    def test_bare_domains_and_ip_addresses(self):
        self.assertEqual(parse_http_input("example.com"), "example.com")
        self.assertEqual(parse_http_input("example.com/login"), "example.com")
        self.assertEqual(parse_http_input("192.168.10.20:8000/api/traffic"), "192.168.10.20")
        self.assertEqual(parse_http_input("192.168.10.20:8000", include_port=True), "192.168.10.20:8000")

    def test_userinfo_and_protocol_relative_urls(self):
        self.assertEqual(parse_http_input("http://user:pass@secure.bank.com/account"), "secure.bank.com")
        self.assertEqual(parse_http_input("//cdn.assets.org/js/app.js"), "cdn.assets.org")

    def test_raw_http_request_lines(self):
        # Proxy-style full URL in request line
        self.assertEqual(parse_http_input("GET http://example.com/login HTTP/1.1"), "example.com")
        self.assertEqual(parse_http_input("POST https://api.threat-intel.org/v2/scan HTTP/2"), "api.threat-intel.org")
        
        # CONNECT proxy request
        self.assertEqual(parse_http_input("CONNECT tunnel.proxy.net:443 HTTP/1.1"), "tunnel.proxy.net")
        
        # Multiline HTTP request with Host header
        raw_request = "GET /dashboard HTTP/1.1\r\nHost: internal.portal.gov\r\nUser-Agent: curl/7.68.0"
        self.assertEqual(parse_http_input(raw_request), "internal.portal.gov")

    def test_ipv6_addresses(self):
        self.assertEqual(parse_http_input("http://[2001:db8::1]:8080/index.html"), "2001:db8::1")
        self.assertEqual(parse_http_input("http://[::1]:8080/path", include_port=True), "[::1]:8080")

    def test_parse_http_target_details(self):
        details = parse_http_target_details("https://api.cyberdefense.org:8443/v1/telemetry?stream=true")
        self.assertTrue(details["is_valid"])
        self.assertEqual(details["domain"], "api.cyberdefense.org")
        self.assertEqual(details["port"], 8443)
        self.assertEqual(details["scheme"], "https")
        self.assertEqual(details["path"], "/v1/telemetry?stream=true")

    def test_empty_and_invalid_inputs(self):
        with self.assertRaises(ValueError):
            parse_http_input("")
        with self.assertRaises(ValueError):
            parse_http_input("   ")
        with self.assertRaises(ValueError):
            parse_http_input(None)  # type: ignore


if __name__ == "__main__":
    unittest.main()
