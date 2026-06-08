"""
threat_pipeline.main  —  standalone demo
========================================
Runs sample security telemetry through the full three-layer pipeline and prints
the structured result, so you can exercise the engine without the FastAPI app.

Run from the backend root, inside the venv:

    python -m core.threat_pipeline.main
    python -m core.threat_pipeline.main --sample 1
    echo "powershell downloaded mimikatz and dumped lsass" | python -m core.threat_pipeline.main -

First run builds the ChromaDB index (downloads the embedding model if not
cached); subsequent runs are fast.
"""
import argparse
import json
import logging
import sys

from .pipeline import pipeline


# Sample logs chosen to exercise each Layer 3 constraint.
SAMPLE_LOGS = [
    # 0 — Credential dumping + DNS exfil (Windows). Exercises lexical + protocol boosts.
    (
        "Windows Security: process powershell.exe spawned rundll32 which loaded "
        "mimikatz to dump credentials from the LSASS process. Shortly after, the "
        "host began making repeated DNS TXT queries to an external resolver on "
        "port 53, exfiltrating data over the DNS protocol."
    ),
    # 1 — Lateral movement via RDP with VALID credentials. Should ELIMINATE
    #     'Exploitation of Remote Services' and BOOST 'Valid Accounts'/'Remote Services'.
    (
        "SIEM alert: successful logon (valid credentials) for account svc_admin "
        "over RDP (Remote Desktop) on port 3389 to the domain controller. An "
        "interactive remote desktop session was then established and used to run "
        "commands on the target server."
    ),
    # 2 — C2 beacon over HTTPS/443. Should ELIMINATE 'Non-Application Layer
    #     Protocol' (traffic is application-layer HTTPS).
    (
        "Firewall + proxy logs: the endpoint established a persistent encrypted "
        "channel to a command-and-control server over HTTPS on port 443, beaconing "
        "every 60 seconds with TLS-encrypted payloads."
    ),
    # 3 — Linux web-server exploitation. Platform rule should drop Windows-only hits.
    (
        "Linux auth.log + nginx: attacker exploited a vulnerable web application on "
        "the Apache/nginx server, dropped a bash reverse shell to /tmp/.x, added a "
        "cron job for persistence, and ran chmod +x on the payload."
    ),
]


def _print_result(result) -> None:
    out = result.to_json()
    print("=" * 78)
    print("INPUT TELEMETRY")
    print("=" * 78)
    print(result.input_text)
    print()
    print("=" * 78)
    print(f"LAYER 1 — extracted context & relations  (backend: {out['extractor_backend']})")
    print("=" * 78)
    print(json.dumps(out["context"], indent=2))
    for r in out["extracted_relations"]:
        tool = f" | tool={r['tool']}" if r.get("tool") else ""
        tgt = f" | target={r['target']}" if r.get("target") else ""
        mod = f" | modifier={r['modifier']}" if r.get("modifier") else ""
        print(f"  • {r['action']}{tool}{tgt}{mod}")
    print()
    print("=" * 78)
    print("LAYER 2+3 — final mapped techniques (constraint-adjusted)")
    print("=" * 78)
    if not out["mapped_techniques"]:
        print("  (none passed the constraint engine)")
    for t in out["mapped_techniques"]:
        print(f"  ✓ {t['id']:10} {t['name']:42} conf={t['confidence']:.2f}  tactic={t['tactic']}")
        for reason in t["reasons"]:
            print(f"       └─ {reason}")
    if out["suppressed"]:
        print()
        print("  Suppressed / eliminated by constraints:")
        for s in out["suppressed"]:
            print(f"  ✗ {s['id']:10} {s['name']}")
            for reason in s["reasons"]:
                print(f"       └─ {reason}")
    print()
    print("=" * 78)
    print("FINAL JSON OBJECT")
    print("=" * 78)
    print(json.dumps(out, indent=2))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="Run a log through the 3-layer MITRE pipeline.")
    parser.add_argument("log", nargs="?", default=None,
                        help="Raw log text, or '-' to read from stdin. Omit to use a sample.")
    parser.add_argument("--sample", type=int, default=0,
                        help=f"Sample index 0..{len(SAMPLE_LOGS) - 1} (default 0).")
    parser.add_argument("--all", action="store_true", help="Run every built-in sample.")
    args = parser.parse_args()

    if args.all:
        for log_text in SAMPLE_LOGS:
            _print_result(pipeline.run(log_text))
            print("\n\n")
        return

    if args.log == "-":
        raw = sys.stdin.read()
    elif args.log:
        raw = args.log
    else:
        raw = SAMPLE_LOGS[max(0, min(args.sample, len(SAMPLE_LOGS) - 1))]

    _print_result(pipeline.run(raw))


if __name__ == "__main__":
    main()
