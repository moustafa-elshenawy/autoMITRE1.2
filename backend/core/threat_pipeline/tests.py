"""
threat_pipeline.tests  —  deterministic constraint-engine checks
================================================================
These do NOT require the LLM, the embedding model, or the vector DB. They feed
hand-built candidates straight into Layer 3 to prove the gatekeeper logic from
the spec fires correctly.

Run from the backend root, inside the venv:

    python -m core.threat_pipeline.tests
"""
from .schema import Extraction, LogContext, RetrievedTechnique
from .logic_engine import constraint_engine


def _status(mapped, tid):
    for m in mapped:
        if m.id == tid:
            return m.status, m.adjusted_confidence
    return None, None


def test_port443_eliminates_non_application_layer():
    candidates = [
        RetrievedTechnique("T1095", "Non-Application Layer Protocol", "Command And Control",
                           ["Windows", "Linux", "macOS"], "...", 0.71),
        RetrievedTechnique("T1071", "Application Layer Protocol", "Command And Control",
                           ["Windows", "Linux", "macOS"], "...", 0.66),
    ]
    ctx = LogContext(platform="windows", ports=[443], protocols=["https", "tls"])
    mapped = constraint_engine.evaluate(candidates, Extraction(relations=[], context=ctx))
    assert _status(mapped, "T1095")[0] == "eliminated"
    assert _status(mapped, "T1071")[0] == "accepted"
    assert _status(mapped, "T1071")[1] > 0.66  # boosted above baseline


def test_valid_creds_eliminate_exploitation_of_remote_services():
    candidates = [
        RetrievedTechnique("T1210", "Exploitation of Remote Services", "Lateral Movement",
                           ["Windows", "Linux", "macOS"], "...", 0.68),
        RetrievedTechnique("T1078", "Valid Accounts", "Defense Evasion",
                           ["Windows", "Linux", "macOS"], "...", 0.55),
        RetrievedTechnique("T1021", "Remote Services", "Lateral Movement",
                           ["Windows", "Linux", "macOS"], "...", 0.50),
    ]
    ctx = LogContext(platform="windows", ports=[3389], protocols=["rdp"],
                     uses_valid_credentials=True, uses_native_remote_service=True)
    mapped = constraint_engine.evaluate(candidates, Extraction(relations=[], context=ctx))
    assert _status(mapped, "T1210")[0] == "eliminated"
    assert _status(mapped, "T1078")[0] == "accepted"
    assert _status(mapped, "T1021")[0] == "accepted"


def test_platform_drops_windows_technique_on_linux():
    candidates = [
        RetrievedTechnique("T1547.001", "Registry Run Keys", "Persistence",
                           ["Windows"], "...", 0.60),
        RetrievedTechnique("T1053.003", "Cron", "Execution",
                           ["Linux"], "...", 0.55),
    ]
    ctx = LogContext(platform="linux")
    mapped = constraint_engine.evaluate(candidates, Extraction(relations=[], context=ctx))
    assert _status(mapped, "T1547.001")[0] == "eliminated"
    assert _status(mapped, "T1053.003")[0] == "accepted"


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        t()
        print(f"  PASS  {t.__name__}")
        passed += 1
    print(f"\n{passed}/{len(tests)} constraint tests passed.")


if __name__ == "__main__":
    main()
