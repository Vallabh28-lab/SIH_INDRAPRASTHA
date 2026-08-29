"""
L7 HTTP payload inspector

Provides a simple signature-based Layer-7 HTTP inspector for common web attacks
(SQL Injection, XSS, Path Traversal/LFI). This is intentionally lightweight and
uses compiled regular expressions to find common suspicious patterns in the
request URI, body payload or headers.

Function:
    inspect_http_payload(uri_path: str, body_payload: str, headers: dict) -> dict

Return structure:
{
  "is_l7_malicious": bool,
  "l7_threat_type": str or None,
  "matched_signatures": list[str]
}

Note: This is a heuristic signature scanner — for production use combine with
contextual analysis, rate-limiting, and more robust parsers.
"""

from typing import Dict, List, Optional
import re


# Pre-compile common attack signature regexes (case-insensitive)
_SIGNATURES = [
    # SQL Injection signatures
    ("SQLi", "OR 1=1", re.compile(r"\bOR\b\s+1\s*=\s*1", re.IGNORECASE)),
    ("SQLi", "UNION SELECT", re.compile(r"UNION\s+SELECT", re.IGNORECASE)),
    ("SQLi", "DROP TABLE", re.compile(r"DROP\s+TABLE", re.IGNORECASE)),
    ("SQLi", "SQL comment --", re.compile(r"--", re.IGNORECASE)),

    # Cross-Site Scripting (XSS)
    ("XSS", "<script>", re.compile(r"<script\b", re.IGNORECASE)),
    ("XSS", "onerror=", re.compile(r"onerror\s*=", re.IGNORECASE)),
    ("XSS", "javascript:", re.compile(r"javascript:\s*", re.IGNORECASE)),

    # Path Traversal / LFI
    ("PathTraversal", "../ (double dot)", re.compile(r"(\.\./)+", re.IGNORECASE)),
    ("PathTraversal", "/etc/passwd", re.compile(r"/etc/passwd", re.IGNORECASE)),
]


def inspect_http_payload(uri_path: Optional[str], body_payload: Optional[str], headers: Optional[Dict]) -> Dict:
    """
    Inspect provided HTTP-like inputs for simple Layer-7 attack signatures.

    Args:
        uri_path: request URI/path string (may include query string)
        body_payload: raw request body as text (may be JSON encoded as string)
        headers: dictionary of request headers (keys and values will be scanned)

    Returns:
        dict with keys "is_l7_malicious" (bool), "l7_threat_type" (str|None),
        and "matched_signatures" (list of human-readable match descriptions).
    """
    matched: List[str] = []
    detected_types: List[str] = []

    # Normalize None inputs to empty strings
    uri_text = uri_path or ""
    body_text = body_payload or ""

    # Flatten headers into a single string (include header names and values)
    headers_text = ""
    if headers:
        try:
            # Join keys and values; ensure values are converted to str
            headers_text = "\n".join(f"{k}:{v}" for k, v in headers.items())
        except Exception:
            # Fallback to repr if something unexpected is provided
            headers_text = repr(headers)

    # Fields to scan with readable names
    fields = [
        ("uri_path", uri_text),
        ("body_payload", body_text),
        ("request_headers", headers_text),
    ]

    for threat_type, signature_name, pattern in _SIGNATURES:
        for field_name, text in fields:
            if not text:
                continue
            m = pattern.search(text)
            if m:
                snippet = m.group(0)
                # Keep snippet short for readability
                snippet_display = snippet if len(snippet) <= 120 else snippet[:117] + "..."
                matched.append(f"{threat_type}: '{signature_name}' matched in {field_name} -> '{snippet_display}'")
                if threat_type not in detected_types:
                    detected_types.append(threat_type)

    is_malicious = len(matched) > 0
    l7_threat_type = None
    if detected_types:
        # Return comma-separated threat types when multiple are found
        l7_threat_type = ",".join(detected_types)

    return {
        "is_l7_malicious": is_malicious,
        "l7_threat_type": l7_threat_type,
        "matched_signatures": matched,
    }


# Simple self-test when module executed directly
if __name__ == "__main__":
    samples = [
        {
            "uri_path": "/search?q=1 OR 1=1",
            "body_payload": "{\"user\": \"admin\' --\"}",
            "headers": {"User-Agent": "curl/7.68.0"},
        },
        {
            "uri_path": "/images?src=<script>alert(1)</script>",
            "body_payload": "",
            "headers": {"Referer": "http://example.com"},
        },
        {
            "uri_path": "/../../etc/passwd",
            "body_payload": "",
            "headers": {},
        },
    ]

    for s in samples:
        print("Input:", s)
        print("Result:", inspect_http_payload(s["uri_path"], s["body_payload"], s["headers"]))
        print("-", 80)
