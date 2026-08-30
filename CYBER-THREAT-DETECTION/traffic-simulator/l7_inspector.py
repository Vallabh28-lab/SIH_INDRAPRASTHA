#!/usr/bin/env python3
"""
NTRO Cyber Threat Detection - Layer 7 HTTP Payload Inspector
Module: l7_inspector.py
Description: Signature-based detection of SQLi, XSS, and Path Traversal / LFI
             attacks using compiled regular expressions against URI, body, and headers.
"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Compiled signature sets — (pattern, human-readable label)
# ---------------------------------------------------------------------------
_SQL_INJECTION: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\bOR\s+1\s*=\s*1\b"),          "SQL Injection: OR 1=1 tautology"),
    (re.compile(r"(?i)\bUNION\s+SELECT\b"),            "SQL Injection: UNION SELECT statement"),
    (re.compile(r"(?i)\bDROP\s+TABLE\b"),              "SQL Injection: DROP TABLE statement"),
    (re.compile(r"--\s*$", re.MULTILINE),              "SQL Injection: inline comment (--) terminator"),
    (re.compile(r"(?i)\bSELECT\b.+\bFROM\b"),         "SQL Injection: SELECT...FROM clause"),
    (re.compile(r"(?i)\bINSERT\s+INTO\b"),             "SQL Injection: INSERT INTO statement"),
    (re.compile(r"(?i)\bEXEC\s*\("),                   "SQL Injection: EXEC() call"),
    (re.compile(r"(?i)'\s*OR\s*'"),                    "SQL Injection: string OR bypass"),
]

_XSS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)<\s*script[\s>]"),               "XSS: <script> tag injection"),
    (re.compile(r"(?i)onerror\s*="),                   "XSS: onerror event handler"),
    (re.compile(r"(?i)onload\s*="),                    "XSS: onload event handler"),
    (re.compile(r"(?i)javascript\s*:"),                "XSS: javascript: URI scheme"),
    (re.compile(r"(?i)<\s*img[^>]+src\s*="),           "XSS: <img src> injection"),
    (re.compile(r"(?i)alert\s*\("),                    "XSS: alert() call"),
    (re.compile(r"(?i)document\s*\.\s*cookie"),        "XSS: document.cookie access"),
]

_PATH_TRAVERSAL: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\.\./"),                             "Path Traversal: ../ sequence"),
    (re.compile(r"\.\.\\"),                            "Path Traversal: ..\\ sequence"),
    (re.compile(r"(?i)/etc/passwd"),                   "LFI: /etc/passwd access attempt"),
    (re.compile(r"(?i)/etc/shadow"),                   "LFI: /etc/shadow access attempt"),
    (re.compile(r"(?i)/proc/self"),                    "LFI: /proc/self access attempt"),
    (re.compile(r"(?i)%2e%2e[%2f%5c]", re.IGNORECASE), "Path Traversal: URL-encoded ../ or ..\\"),
]

_SIGNATURE_GROUPS: list[tuple[str, list[tuple[re.Pattern, str]]]] = [
    ("SQL_Injection",    _SQL_INJECTION),
    ("XSS",              _XSS),
    ("Path_Traversal",   _PATH_TRAVERSAL),
]


def inspect_http_payload(
    uri_path: str,
    body_payload: str,
    headers: dict,
) -> dict:
    """
    Scan URI path, request body, and HTTP headers for L7 web attack signatures.

    Returns:
        {
            "is_l7_malicious": bool,
            "l7_threat_type": str | None,   # first matched category
            "matched_signatures": list[str] # all triggered signature labels
        }
    """
    combined = " ".join([
        uri_path or "",
        body_payload or "",
        " ".join(str(v) for v in (headers or {}).values()),
    ])

    matched: list[str] = []
    first_threat: Optional[str] = None

    for threat_type, patterns in _SIGNATURE_GROUPS:
        for pattern, label in patterns:
            if pattern.search(combined):
                matched.append(label)
                if first_threat is None:
                    first_threat = threat_type

    return {
        "is_l7_malicious": bool(matched),
        "l7_threat_type":  first_threat,
        "matched_signatures": matched,
    }
