#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 6: Threat Intelligence
Module: threat_intel.py
Description: Threat Intelligence enrichment stub providing ASN lookup, Geolocation mapping,
             and IP reputation risk scoring for real-time telemetry analysis.
"""

import hashlib
import ipaddress
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ThreatIntelService")


class ThreatIntelService:
    """
    Threat Intelligence Enrichment Engine:
    Provides ASN details, geographical location, threat tags, and IP reputation risk scoring.
    """

    # Static threat registry for recognized lab and public test telemetry IP ranges
    KNOWN_IP_REGISTRY: Dict[str, Dict[str, Any]] = {
        "192.168.10.10": {
            "asn": "AS-LAB-NTRO (Internal Security Simulation Lab)",
            "asn_number": 64512,
            "organization": "NTRO Cyber Defense Testbed",
            "country": "India",
            "country_code": "IN",
            "city": "New Delhi",
            "latitude": 28.6139,
            "longitude": 77.2090,
            "reputation_score": 85,
            "risk_level": "HIGH",
            "threat_tags": ["SIMULATED_ATTACK_SOURCE", "HIGH_RATE_FLOODER"],
            "is_malicious": True,
        },
        "10.0.20.10": {
            "asn": "AS-LAB-NTRO (Internal Protected Asset)",
            "asn_number": 64513,
            "organization": "NTRO Cyber Range Target Gateway",
            "country": "India",
            "country_code": "IN",
            "city": "New Delhi",
            "latitude": 28.6139,
            "longitude": 77.2090,
            "reputation_score": 10,
            "risk_level": "LOW",
            "threat_tags": ["CRITICAL_INFRASTRUCTURE_TARGET", "PROTECTED_VIP"],
            "is_malicious": False,
        },
        "10.0.4.88": {
            "asn": "AS-LAB-NTRO (Botnet Agent Simulator)",
            "asn_number": 64514,
            "organization": "Adversary Simulation Cluster",
            "country": "India",
            "country_code": "IN",
            "city": "Bangalore",
            "latitude": 12.9716,
            "longitude": 77.5946,
            "reputation_score": 95,
            "risk_level": "CRITICAL",
            "threat_tags": ["SYN_FLOOD_BOTNET", "KNOWN_ADVERSARY"],
            "is_malicious": True,
        },
        "172.16.5.99": {
            "asn": "AS-LAB-NTRO (Reconnaissance Scanner)",
            "asn_number": 64515,
            "organization": "Penetration Testing Subnet",
            "country": "India",
            "country_code": "IN",
            "city": "Hyderabad",
            "latitude": 17.3850,
            "longitude": 78.4867,
            "reputation_score": 78,
            "risk_level": "HIGH",
            "threat_tags": ["PORT_SCANNER", "RECON_PROBE"],
            "is_malicious": True,
        },
        "198.51.100.45": {
            "asn": "AS4134 Chinanet Backbone",
            "asn_number": 4134,
            "organization": "Chinanet Autonomous System",
            "country": "China",
            "country_code": "CN",
            "city": "Beijing",
            "latitude": 39.9042,
            "longitude": 116.4074,
            "reputation_score": 92,
            "risk_level": "CRITICAL",
            "threat_tags": ["UDP_AMPLIFICATION_REFLECTOR", "DDOS_CLUSTER"],
            "is_malicious": True,
        },
        "185.220.101.5": {
            "asn": "AS60729 Zwiebelfreunde e.V.",
            "asn_number": 60729,
            "organization": "Tor Anonymity Network",
            "country": "Germany",
            "country_code": "DE",
            "city": "Frankfurt",
            "latitude": 50.1109,
            "longitude": 8.6821,
            "reputation_score": 88,
            "risk_level": "HIGH",
            "threat_tags": ["TOR_EXIT_NODE", "ANONYMIZER"],
            "is_malicious": True,
        },
        "8.8.8.8": {
            "asn": "AS15169 Google LLC",
            "asn_number": 15169,
            "organization": "Google Public DNS",
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "latitude": 37.4220,
            "longitude": -122.0841,
            "reputation_score": 0,
            "risk_level": "CLEAN",
            "threat_tags": ["PUBLIC_RESOLVER", "WHITELISTED"],
            "is_malicious": False,
        },
        "1.1.1.1": {
            "asn": "AS13335 Cloudflare, Inc.",
            "asn_number": 13335,
            "organization": "Cloudflare DNS Resolver",
            "country": "United States",
            "country_code": "US",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "reputation_score": 0,
            "risk_level": "CLEAN",
            "threat_tags": ["PUBLIC_RESOLVER", "WHITELISTED"],
            "is_malicious": False,
        },
    }

    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Enrich an IP address with Threat Intelligence metadata (ASN, Geo, Reputation).

        :param ip_address: IPv4 or IPv6 address string
        :return: Comprehensive Threat Intelligence dictionary
        """
        clean_ip = ip_address.strip()

        # Check static registry first
        if clean_ip in self.KNOWN_IP_REGISTRY:
            intel = dict(self.KNOWN_IP_REGISTRY[clean_ip])
            intel["ip_address"] = clean_ip
            return intel

        # Parse IP to determine scope
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except ValueError:
            is_private = False

        if is_private:
            return {
                "ip_address": clean_ip,
                "asn": "AS-PRIVATE (RFC1918 Private Network)",
                "asn_number": 0,
                "organization": "Internal Lab Infrastructure",
                "country": "Internal / Local Network",
                "country_code": "LOC",
                "city": "Local Subnet",
                "latitude": 0.0,
                "longitude": 0.0,
                "reputation_score": 25,
                "risk_level": "LOW",
                "threat_tags": ["INTERNAL_RFC1918"],
                "is_malicious": False,
            }

        # Deterministic simulation for arbitrary public IPs based on hash
        ip_hash = int(hashlib.md5(clean_ip.encode("utf-8")).hexdigest(), 16)
        reputation = ip_hash % 100
        
        if reputation >= 80:
            risk = "CRITICAL"
            tags = ["SUSPICIOUS_ACTIVITY", "EXTERNAL_SCANNER"]
            is_mal = True
        elif reputation >= 50:
            risk = "HIGH"
            tags = ["HIGH_VOLUME_SOURCE"]
            is_mal = True
        elif reputation >= 25:
            risk = "MEDIUM"
            tags = ["UNVERIFIED_HOST"]
            is_mal = False
        else:
            risk = "CLEAN"
            tags = ["BENIGN_HOST"]
            is_mal = False

        asn_id = 10000 + (ip_hash % 50000)

        return {
            "ip_address": clean_ip,
            "asn": f"AS{asn_id} Telecommunications Backbone",
            "asn_number": asn_id,
            "organization": f"Global Internet Service Provider AS{asn_id}",
            "country": "International",
            "country_code": "INT",
            "city": "Unknown / Public Route",
            "latitude": round((ip_hash % 180) - 90, 4),
            "longitude": round((ip_hash % 360) - 180, 4),
            "reputation_score": reputation,
            "risk_level": risk,
            "threat_tags": tags,
            "is_malicious": is_mal,
        }


def main() -> None:
    service = ThreatIntelService()
    test_ips = ["192.168.10.10", "10.0.20.10", "8.8.8.8", "185.220.101.5", "10.0.4.88", "192.0.2.1"]
    for ip in test_ips:
        res = service.enrich_ip(ip)
        print(f"\n--- IP: {ip} ---")
        for k, v in res.items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
