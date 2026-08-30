#!/usr/bin/env python3
"""
NTRO Cyber Threat Detection - L7 Integration Test Harness
Module: test_l7_integration.py

Sends live HTTP requests to POST /api/traffic and validates:
  TC-01  SQL Injection in uri_path       -> is_malicious: true, SQL_Injection
  TC-02  XSS in body_payload             -> is_malicious: true, XSS
  TC-03  Path Traversal in http_headers  -> is_malicious: true, Path_Traversal
  TC-04  Multi-vector SQLi + XSS         -> is_malicious: true, both signatures
  TC-05  Clean normal flow               -> l7_analysis: null
"""

import sys
import requests

BASE_URL = "http://localhost:8000/api/traffic"

_BASE_FLOW = {
    "source_ip":          "192.168.10.55",
    "destination_ip":     "192.168.10.20",
    "source_port":        54321,
    "destination_port":   80,
    "protocol":           "TCP",
    "packet_count":       30,
    "total_bytes":        9600,
    "flow_duration":      3.0,
    "packets_per_second": 10.0,
    "bytes_per_second":   3200.0,
    "iat_mean":           0.1,
    "syn_count":          1,
    "ack_count":          29,
}

TEST_CASES = [
    {
        "name":        "TC-01 | SQL Injection via uri_path",
        "desc":        "OR 1=1 tautology in URI query string",
        "payload":     {**_BASE_FLOW, "uri_path": "/login?user=admin' OR 1=1 --"},
        "l7_malicious":   True,
        "l7_type":        "SQL_Injection",
        "sigs":           ["SQL Injection: OR 1=1 tautology",
                           "SQL Injection: inline comment (--) terminator"],
        "null_l7":        False,
    },
    {
        "name":        "TC-02 | XSS via body_payload",
        "desc":        "<script> tag + alert() in POST body",
        "payload":     {**_BASE_FLOW,
                        "body_payload": "comment=<script>alert(document.cookie)</script>"},
        "l7_malicious":   True,
        "l7_type":        "XSS",
        "sigs":           ["XSS: <script> tag injection",
                           "XSS: alert() call",
                           "XSS: document.cookie access"],
        "null_l7":        False,
    },
    {
        "name":        "TC-03 | Path Traversal via http_headers",
        "desc":        "LFI attempt smuggled in custom header value",
        "payload":     {**_BASE_FLOW,
                        "http_headers": {"X-File-Path": "../../../../etc/passwd"}},
        "l7_malicious":   True,
        "l7_type":        "Path_Traversal",
        "sigs":           ["Path Traversal: ../ sequence",
                           "LFI: /etc/passwd access attempt"],
        "null_l7":        False,
    },
    {
        "name":        "TC-04 | Multi-vector SQLi + XSS",
        "desc":        "UNION SELECT in URI + onerror= XSS in body",
        "payload":     {**_BASE_FLOW,
                        "uri_path":     "/search?q=1 UNION SELECT user,pass FROM users",
                        "body_payload": "<img src=x onerror=alert(1)>"},
        "l7_malicious":   True,
        "l7_type":        "SQL_Injection",
        "sigs":           ["SQL Injection: UNION SELECT statement",
                           "XSS: onerror event handler"],
        "null_l7":        False,
    },
    {
        "name":        "TC-05 | Clean normal flow (no L7 fields)",
        "desc":        "Baseline benign flow — l7_analysis must be null",
        "payload":     _BASE_FLOW,
        "l7_malicious":   None,
        "l7_type":        None,
        "sigs":           [],
        "null_l7":        True,
    },
]


def check(condition, label):
    """Return (passed: bool, line: str)."""
    tag = "[PASS]" if condition else "[FAIL]"
    return condition, f"    {tag}  {label}"


def run_test(tc):
    lines = []
    all_ok = True

    try:
        resp = requests.post(BASE_URL, json=tc["payload"], timeout=15)
    except requests.ConnectionError:
        return False, ["    [FAIL]  CONNECTION REFUSED - is api.py running on port 8000?"]

    ok, msg = check(resp.status_code == 201, f"HTTP 201 received (got {resp.status_code})")
    lines.append(msg)
    if not ok:
        all_ok = False
        lines.append(f"           Body: {resp.text[:300]}")
        return all_ok, lines

    body = resp.json()
    l7 = body.get("l7_analysis")

    # TC-05: expect null l7_analysis
    if tc["null_l7"]:
        ok, msg = check(l7 is None, "l7_analysis is null for clean flow")
        lines.append(msg)
        if not ok:
            all_ok = False
        return all_ok, lines

    # l7_analysis must be present
    ok, msg = check(l7 is not None, "l7_analysis key present in response")
    lines.append(msg)
    if not ok:
        return False, lines

    # is_l7_malicious
    ok, msg = check(
        l7["is_l7_malicious"] == tc["l7_malicious"],
        f"is_l7_malicious == {tc['l7_malicious']}  (got {l7['is_l7_malicious']})",
    )
    lines.append(msg)
    if not ok:
        all_ok = False

    # top-level is_malicious escalation
    ok, msg = check(body["is_malicious"] is True,
                    f"top-level is_malicious escalated to true  (got {body['is_malicious']})")
    lines.append(msg)
    if not ok:
        all_ok = False

    # l7_threat_type
    ok, msg = check(
        l7["l7_threat_type"] == tc["l7_type"],
        f"l7_threat_type == '{tc['l7_type']}'  (got '{l7['l7_threat_type']}')",
    )
    lines.append(msg)
    if not ok:
        all_ok = False

    # individual signature labels
    for sig in tc["sigs"]:
        ok, msg = check(sig in l7["matched_signatures"],
                        f"matched_signatures contains: '{sig}'")
        lines.append(msg)
        if not ok:
            all_ok = False

    # SHA-256 audit record written
    ok, msg = check(body.get("audit_id") is not None,
                    f"audit_id written to SHA-256 chain  (got '{body.get('audit_id')}')")
    lines.append(msg)
    if not ok:
        all_ok = False

    return all_ok, lines


def main():
    SEP  = "=" * 72
    DASH = "-" * 72

    print(f"\n{SEP}")
    print("  NTRO L7 INSPECTOR - UNIFIED ENDPOINT INTEGRATION TEST SUITE")
    print("  Target: POST http://localhost:8000/api/traffic")
    print(SEP)

    results = []

    for tc in TEST_CASES:
        print(f"\n{DASH}")
        print(f"  {tc['name']}")
        print(f"  {tc['desc']}")
        print(DASH)

        passed, lines = run_test(tc)
        for line in lines:
            print(line)

        verdict = "PASS" if passed else "FAIL"
        print(f"\n  Result: [{verdict}]")
        results.append((tc["name"], passed))

    # Summary
    total  = len(results)
    passed = sum(1 for _, p in results if p)
    print(f"\n{SEP}")
    print("  SUMMARY")
    print(SEP)
    for name, ok in results:
        label = "PASS" if ok else "FAIL"
        print(f"  [{label}]  {name}")
    print(f"\n  {passed}/{total} tests passed")
    print(SEP)

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
