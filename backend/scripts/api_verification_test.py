#!/usr/bin/env python3
"""Automated API verification for the dual-engine ATT&CK mapping changes.

Logs in, fires four payloads at /api/analyze/text, and asserts the Intake
Router / Token-Overlap Gate / Bi-Encoder behaviour. Prints a Pass/Fail report
and dumps the full JSON for any test with a failed assertion.
"""
import json
import sys
import urllib.parse
import requests

BASE = "http://localhost:8001"
USER, PW = "verify_bot", "Verify!2026"


def login() -> str:
    # Ensure the account exists (idempotent), then fetch a token.
    requests.post(f"{BASE}/api/auth/register", json={
        "username": USER, "email": "verify_bot@example.com", "password": PW})
    r = requests.post(
        f"{BASE}/api/auth/token",
        data=urllib.parse.urlencode({"username": USER, "password": PW}),
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    r.raise_for_status()
    return r.json()["access_token"]


def analyze(token: str, text: str) -> dict:
    r = requests.post(
        f"{BASE}/api/analyze/text",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"text": text, "pipeline_mode": "auto"},
        timeout=180)
    r.raise_for_status()
    return r.json()


def engine_of(resp: dict) -> str:
    rd = resp.get("routing_decision") or {}
    return rd.get("engine_used") or rd.get("engine") or "?"


def tech_ids(resp: dict) -> list:
    tr = resp.get("threat_result") or {}
    return [t.get("id") for t in (tr.get("attack_techniques") or [])]


TESTS = [
    {
        "name": "TEST 1 — Hallucination Defense (opaque telemetry)",
        "payload": (
            "EventID: 4688 Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
            "powershell.exe CommandLine: powershell.exe -nop -w hidden -enc "
            "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUA"
            "YQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIA"
            "aQBuAGcAKAAiAEgA..."
        ),
        "asserts": [
            ("routing_decision == 'rag'", lambda r: engine_of(r) == "rag"),
            ("techniques CONTAIN T1059.001", lambda r: "T1059.001" in tech_ids(r)),
            ("techniques DO NOT contain T1003.001", lambda r: "T1003.001" not in tech_ids(r)),
        ],
    },
    {
        "name": "TEST 2 — DL Bi-Encoder Gate (CTI prose)",
        "payload": (
            "Upon gaining initial access via a vulnerable public-facing web server, "
            "the APT group deployed a PHP web shell to maintain persistence. Several "
            "hours later, the threat actors were observed utilizing procdump.exe to "
            "extract credentials from the LSASS process memory, which were "
            "subsequently exfiltrated using Rclone to a remote cloud storage bucket."
        ),
        "asserts": [
            ("routing_decision == 'deep_learning'", lambda r: engine_of(r) == "deep_learning"),
            ("techniques CONTAIN T1003.001", lambda r: "T1003.001" in tech_ids(r)),
            ("techniques CONTAIN T1505.003", lambda r: "T1505.003" in tech_ids(r)),
        ],
    },
    {
        "name": "TEST 3 — Paraphrase Threshold (semantic extraction)",
        "payload": (
            "Alert: Suspicious activity detected. The adversary successfully "
            "harvested logon secrets from the local security authority subsystem "
            "service."
        ),
        "asserts": [
            ("techniques CONTAIN T1003.001", lambda r: "T1003.001" in tech_ids(r)),
        ],
    },
    {
        "name": "TEST 4 — Raw Clear-Text SIEM Log",
        "payload": (
            '{"EventTime": "2026-06-08 10:15:22", "EventID": 1, "Provider": '
            '"Microsoft-Windows-Sysmon", "Image": "C:\\\\Windows\\\\System32\\\\'
            'vssadmin.exe", "CommandLine": "vssadmin.exe Delete Shadows /All '
            '/Quiet", "User": "NT AUTHORITY\\\\SYSTEM"}'
        ),
        "asserts": [
            ("routing_decision == 'rag'", lambda r: engine_of(r) == "rag"),
            ("techniques CONTAIN T1490", lambda r: "T1490" in tech_ids(r)),
        ],
    },
]


def main():
    token = login()
    print("=" * 72)
    print("  autoMITRE — API VERIFICATION REPORT")
    print("=" * 72)
    total_pass = total = 0
    failed_dumps = []
    for t in TESTS:
        resp = analyze(token, t["payload"])
        eng, ids = engine_of(resp), tech_ids(resp)
        print(f"\n{t['name']}")
        print(f"  engine={eng}  techniques={ids}")
        test_failed = False
        for label, fn in t["asserts"]:
            total += 1
            try:
                ok = bool(fn(resp))
            except Exception as e:  # noqa: BLE001
                ok = False
                label += f"  (assertion error: {e})"
            total_pass += ok
            test_failed = test_failed or not ok
            print(f"    [{'PASS' if ok else 'FAIL'}] {label}")
        if test_failed:
            failed_dumps.append((t["name"], resp))

    print("\n" + "=" * 72)
    print(f"  RESULT: {total_pass}/{total} assertions passed across {len(TESTS)} tests")
    print("=" * 72)

    for name, resp in failed_dumps:
        print(f"\n----- FULL JSON for failed test: {name} -----")
        print(json.dumps(resp, indent=2, default=str))

    sys.exit(0 if total_pass == total else 1)


if __name__ == "__main__":
    main()
