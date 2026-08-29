#!/usr/bin/env python3
"""
====================================================================================================
Cyber Threat Detection & Telemetry Simulation System - Phase 1: Input Parser Module
Module: http_input_parser.py
Description: Robust input parsing engine for extracting target domain/hostname from arbitrary
             HTTP inputs, including full URLs, bare domains, protocol-relative URIs, and raw
             HTTP request lines.
====================================================================================================
"""

import argparse
import re
import sys
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, unquote


def parse_http_input(raw_input: str, include_port: bool = False) -> str:
    """
    Accepts either a full URL (e.g. 'http://example.com/path'), a domain string
    (e.g. 'sub.example.com/test'), or a raw HTTP request line (e.g. 'GET /login HTTP/1.1'
    or 'GET http://example.com/login HTTP/1.1').

    Uses urllib.parse and regex string manipulation to cleanly extract the target
    domain or hostname while stripping protocol prefixes (http://, https://, etc.).

    :param raw_input: Target URL, domain, or raw HTTP request line.
    :param include_port: If True, retains ':port' if present in the host. If False, returns host only.
    :return: Extracted domain or hostname string (e.g., 'example.com').
    :raises ValueError: If the input is empty or cannot be parsed to a valid host.
    """
    if not raw_input or not isinstance(raw_input, str):
        raise ValueError("Input string must be a non-empty string.")

    cleaned = raw_input.strip()
    if not cleaned:
        raise ValueError("Input string cannot be empty or whitespace only.")

    # Remove enclosing quotes or angle brackets if present
    cleaned = cleaned.strip("\"'<>")

    # -------------------------------------------------------------------------
    # 1. Handle Raw HTTP Request Lines (e.g. "GET /login HTTP/1.1", "POST https://api.io/v1 HTTP/2")
    # -------------------------------------------------------------------------
    http_methods = (
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"
    )
    first_token = cleaned.split()[0].upper() if cleaned.split() else ""

    if first_token in http_methods:
        parts = cleaned.split()
        if len(parts) >= 2:
            request_target = parts[1]
            # If request target is a full URL (e.g., in proxy requests: GET http://target.com/path HTTP/1.1)
            if "://" in request_target or request_target.startswith("//"):
                cleaned = request_target
            elif first_token == "CONNECT":
                # CONNECT authority-form: e.g. "CONNECT server.example.com:443 HTTP/1.1"
                cleaned = request_target
            else:
                # Relative path (e.g., "GET /login HTTP/1.1")
                # Look for subsequent headers in multiline input (e.g., Host: example.com)
                host_header_match = re.search(r"(?im)^\s*Host:\s*([^\r\n]+)", cleaned)
                if host_header_match:
                    cleaned = host_header_match.group(1).strip()
                else:
                    # If only a request line without Host header is provided,
                    # parse the path or return the authority/path token
                    cleaned = request_target.lstrip("/")

    # -------------------------------------------------------------------------
    # 2. Protocol and Authority Extraction via urllib.parse
    # -------------------------------------------------------------------------
    # If string doesn't start with a scheme, prepend a dummy scheme so urlparse can parse authority
    if "://" not in cleaned:
        if cleaned.startswith("//"):
            parse_target = "http:" + cleaned
        else:
            parse_target = "http://" + cleaned
    else:
        parse_target = cleaned

    parsed = urlparse(parse_target)

    # Netloc (authority) contains 'hostname:port' or 'hostname'
    netloc = parsed.netloc or parsed.path

    # If netloc contains path components (can happen if bare domain with path), split on '/'
    if "/" in netloc:
        netloc = netloc.split("/")[0]

    # Remove userinfo (e.g., user:pass@host)
    if "@" in netloc:
        netloc = netloc.split("@")[-1]

    # Handle IPv6 bracketed hosts e.g. [::1]:8080 or [::1]
    if netloc.startswith("[") and "]" in netloc:
        ipv6_host = netloc[1:netloc.index("]")]
        port_part = netloc[netloc.index("]") + 1:]
        if include_port and port_part.startswith(":"):
            host = f"[{ipv6_host}]{port_part}"
        else:
            host = ipv6_host
    else:
        # Strip port if not requested
        if ":" in netloc and not include_port:
            host = netloc.split(":")[0]
        else:
            host = netloc

    # Final cleanup: lowercase hostname and strip trailing dots/slashes
    host = host.strip("/: ").lower()

    if not host:
        raise ValueError(f"Could not extract a valid host or domain from: '{raw_input}'")

    return host


def parse_http_target_details(raw_input: str) -> Dict[str, Any]:
    """
    Extracts comprehensive metadata and structured components from the input.

    :param raw_input: Target URL, domain, or raw HTTP request line.
    :return: Dictionary containing domain, host, port, scheme, path, method, and validity.
    """
    try:
        cleaned = raw_input.strip().strip("\"'<>")
        method: Optional[str] = None
        http_methods = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE")
        first_token = cleaned.split()[0].upper() if cleaned.split() else ""

        if first_token in http_methods:
            method = first_token
            parts = cleaned.split()
            request_target = parts[1] if len(parts) > 1 else "/"
        else:
            request_target = cleaned

        # Normalized URL parsing
        if "://" not in request_target:
            if request_target.startswith("//"):
                parse_target = "http:" + request_target
            else:
                parse_target = "http://" + request_target
        else:
            parse_target = request_target

        parsed = urlparse(parse_target)
        host = parse_http_input(raw_input, include_port=False)
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        scheme = parsed.scheme if "://" in request_target else "http"
        path = parsed.path if parsed.path else "/"
        if parsed.query:
            path += f"?{parsed.query}"

        return {
            "raw_input": raw_input,
            "domain": host,
            "host": host,
            "port": port,
            "scheme": scheme,
            "path": path,
            "method": method,
            "is_valid": True,
            "error": None,
        }
    except Exception as exc:
        return {
            "raw_input": raw_input,
            "domain": None,
            "host": None,
            "port": None,
            "scheme": None,
            "path": None,
            "method": None,
            "is_valid": False,
            "error": str(exc),
        }


def main() -> None:
    """CLI entry point for testing and executing parse_http_input."""
    parser = argparse.ArgumentParser(
        description="Phase 1: HTTP Input Parser Module - Extract domain/host from URLs or request lines"
    )
    parser.add_argument(
        "target",
        type=str,
        nargs="?",
        default="http://example.com/path",
        help="Input target URL, domain string, or raw HTTP request line (e.g. 'GET /login HTTP/1.1')",
    )
    parser.add_argument(
        "--include-port",
        action="store_true",
        help="Retain destination port in extracted output if present (e.g. example.com:8080)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output full parsed target details as formatted JSON",
    )
    args = parser.parse_args()

    try:
        if args.json:
            import json
            details = parse_http_target_details(args.target)
            print(json.dumps(details, indent=2))
        else:
            domain = parse_http_input(args.target, include_port=args.include_port)
            print(f"[*] Input  : {args.target}")
            print(f"[*] Target : {domain}")
    except Exception as err:
        print(f"[!] Error parsing input: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
