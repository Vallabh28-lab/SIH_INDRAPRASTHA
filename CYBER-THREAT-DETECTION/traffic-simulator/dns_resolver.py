#!/usr/bin/env python3
"""
====================================================================================================
Cyber Threat Detection & Telemetry Simulation System - Phase 2: DNS Resolution Service
Module: dns_resolver.py
Description: Robust DNS resolution engine converting domain names into IPv4 addresses using
             socket.gethostbyname with graceful socket.gaierror fallback protection for live
             presentations, sandbox environments, and mock targets.
====================================================================================================
"""

import argparse
import ipaddress
import json
import logging
import socket
import sys
from typing import Any, Dict, Optional

# Optional import of input parser for unified CLI handling
try:
    from http_input_parser import parse_http_input
except ImportError:
    parse_http_input = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("DNSResolutionService")

# Default safe fallback IP within the isolated sandbox subnet
DEFAULT_LAB_FALLBACK_IP = "192.168.10.1"

# Static lab resolution map for preconfigured simulation assets
LAB_DNS_REGISTRY: Dict[str, str] = {
    "collector.internal": "192.168.10.20",
    "collector-node": "192.168.10.20",
    "generator.internal": "192.168.10.10",
    "generator-node": "192.168.10.10",
    "generator-node-2": "192.168.10.11",
    "target.lab": "192.168.10.20",
    "mock-bank.lab": "192.168.10.100",
    "adversary.lab": "10.0.4.88",
    "recon.lab": "172.16.5.99",
    "localhost": "127.0.0.1",
}


def is_valid_ipv4(ip_str: str) -> bool:
    """Check if the provided string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True
    except (ValueError, AttributeError):
        return False


def resolve_domain(
    domain: str,
    default_ip: str = DEFAULT_LAB_FALLBACK_IP,
    timeout: float = 3.0,
) -> str:
    """
    Translates an extracted domain name into a live IPv4 network address using socket.gethostbyname.
    Implements a robust fallback exception block (socket.gaierror, socket.timeout, OSError)
    to gracefully route unresolvable or mock lab domains to a safe local subnet address.

    :param domain: Extracted host or domain name (e.g. 'example.com', 'mock-bank.lab', '192.168.10.20').
    :param default_ip: Safe fallback IP to return if DNS resolution fails (default: 192.168.10.1).
    :param timeout: DNS socket timeout in seconds.
    :return: Resolved IPv4 address as a string.
    """
    if not domain or not isinstance(domain, str):
        logger.warning("Empty or invalid domain provided. Defaulting to fallback IP: %s", default_ip)
        return default_ip

    cleaned_host = domain.strip().lower()

    # 1. Direct IPv4 Bypass: If the host is already an IPv4 address, return immediately
    if is_valid_ipv4(cleaned_host):
        return cleaned_host

    # 2. Local Sandbox / Lab DNS Registry Lookup
    if cleaned_host in LAB_DNS_REGISTRY:
        resolved = LAB_DNS_REGISTRY[cleaned_host]
        logger.info("[DNS CACHE] Resolved lab host '%s' -> %s", cleaned_host, resolved)
        return resolved

    # 3. Live DNS Resolution via socket.gethostbyname with socket.gaierror Handler
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        resolved_ip = socket.gethostbyname(cleaned_host)
        logger.info("[DNS RESOLVED] '%s' -> %s", cleaned_host, resolved_ip)
        return resolved_ip
    except socket.gaierror as gai_err:
        logger.warning(
            "[DNS WARNING] Hostname '%s' unresolvable (socket.gaierror: %s). Defaulting to safe lab IP: %s",
            cleaned_host,
            gai_err,
            default_ip,
        )
        return default_ip
    except (socket.herror, socket.timeout, OSError, Exception) as exc:
        logger.warning(
            "[DNS ERROR] Failed to resolve '%s' (%s). Defaulting to safe lab IP: %s",
            cleaned_host,
            exc,
            default_ip,
        )
        return default_ip
    finally:
        socket.setdefaulttimeout(original_timeout)


def resolve_domain_details(
    raw_target: str,
    default_ip: str = DEFAULT_LAB_FALLBACK_IP,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """
    Parses arbitrary input and performs DNS resolution, returning a structured diagnostic record.

    :param raw_target: Domain, URL, or raw HTTP request line.
    :param default_ip: Fallback IP if resolution fails.
    :param timeout: Socket resolution timeout.
    :return: Dictionary containing domain, resolved IP, resolution source, and error details.
    """
    if parse_http_input is not None:
        try:
            target_host = parse_http_input(raw_target)
        except Exception:
            target_host = raw_target.strip()
    else:
        target_host = raw_target.strip()

    cleaned_host = target_host.lower()

    if is_valid_ipv4(cleaned_host):
        return {
            "input": raw_target,
            "host": cleaned_host,
            "resolved_ip": cleaned_host,
            "is_fallback": False,
            "resolution_source": "DIRECT_IPV4",
            "error": None,
        }

    if cleaned_host in LAB_DNS_REGISTRY:
        return {
            "input": raw_target,
            "host": cleaned_host,
            "resolved_ip": LAB_DNS_REGISTRY[cleaned_host],
            "is_fallback": False,
            "resolution_source": "LAB_REGISTRY",
            "error": None,
        }

    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        resolved_ip = socket.gethostbyname(cleaned_host)
        return {
            "input": raw_target,
            "host": cleaned_host,
            "resolved_ip": resolved_ip,
            "is_fallback": False,
            "resolution_source": "LIVE_DNS",
            "error": None,
        }
    except socket.gaierror as gai_err:
        return {
            "input": raw_target,
            "host": cleaned_host,
            "resolved_ip": default_ip,
            "is_fallback": True,
            "resolution_source": "FALLBACK_SAFE_SUBNET",
            "error": f"socket.gaierror: {gai_err}",
        }
    except Exception as exc:
        return {
            "input": raw_target,
            "host": cleaned_host,
            "resolved_ip": default_ip,
            "is_fallback": True,
            "resolution_source": "FALLBACK_SAFE_SUBNET",
            "error": str(exc),
        }
    finally:
        socket.setdefaulttimeout(original_timeout)


def main() -> None:
    """CLI interface for DNS resolution."""
    parser = argparse.ArgumentParser(
        description="Phase 2: DNS Resolution Service - Translate domain names to IPv4 with gaierror fallback"
    )
    parser.add_argument(
        "target",
        type=str,
        nargs="?",
        default="collector.internal",
        help="Domain name, URL, or IP address to resolve (default: collector.internal)",
    )
    parser.add_argument(
        "--default-ip",
        type=str,
        default=DEFAULT_LAB_FALLBACK_IP,
        help=f"Safe fallback IPv4 address for unresolvable domains (default: {DEFAULT_LAB_FALLBACK_IP})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="DNS resolution timeout in seconds (default: 3.0)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured JSON resolution metadata",
    )
    args = parser.parse_args()

    if args.json:
        result = resolve_domain_details(args.target, default_ip=args.default_ip, timeout=args.timeout)
        print(json.dumps(result, indent=2))
    else:
        ip = resolve_domain(args.target, default_ip=args.default_ip, timeout=args.timeout)
        print(f"[*] Input Target  : {args.target}")
        print(f"[*] Resolved IPv4 : {ip}")


if __name__ == "__main__":
    main()
