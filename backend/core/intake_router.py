"""
core.intake_router  —  Unstructured-Traffic Intelligent Router
==============================================================
Decides which technique-mapping engine should process a given piece of threat
telemetry when the caller asks for ``pipeline_mode="auto"``:

  * **Structured telemetry** (JSON/XML payloads, SIEM/Sysmon/Windows-Event
    fields, syslog headers, raw command-line invocations) → the **RAG +
    Constraint Engine** (`core.threat_pipeline`). That engine's extractor +
    deterministic constraints are built for log-shaped, field-rich input.

  * **Unstructured prose** (CTI report paragraphs, advisory write-ups, narrative
    incident summaries) → the **SecureBERT + Bi-Encoder** deep-learning
    classifier (`ml.attack_hierarchical`), which was fine-tuned on sentence-level
    CTI text (the CTID TRAM corpus).

The routing is purely structural and explainable: every decision returns the
individual signals it fired on, so the choice is auditable and surfaced back to
the user as ``routing_decision`` in the API response.

This module has **no heavy imports** (regex + stdlib only) so it is cheap to call
on every request and trivial to unit-test in isolation.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

# --- engine identifiers (kept as plain strings to avoid import cycles) -------
ENGINE_RAG = "rag"
ENGINE_DEEP_LEARNING = "deep_learning"
# Sequential ensemble: run the DL track, free MPS, then run the RAG track and
# merge both result sets by MITRE ID. Selected only via explicit pipeline_mode
# ("hybrid"); the structural auto-router never picks it on its own.
ENGINE_HYBRID = "hybrid"

# --- structured-telemetry signal patterns -----------------------------------
# Common SIEM / Windows-Event / Sysmon / EDR field names. Matched as whole
# tokens (case-insensitive) so prose mentioning "the process name" doesn't fire.
_SIEM_FIELD_NAMES = [
    "EventID", "EventCode", "process_name", "ParentImage", "Image",
    "CommandLine", "ParentCommandLine", "TargetFilename", "SourceImage",
    "process_id", "ProcessId", "ProcessGuid", "LogonId", "SubjectUserName",
    "AccountName", "src_ip", "dst_ip", "source_ip", "dest_ip", "src_port",
    "dst_port", "sourcetype", "host", "user", "signature_id", "dvc",
    "DeviceName", "RuleName", "Hashes", "IntegrityLevel",
]
# key=value or key: value tokens (Splunk / logfmt / KV-pair logs).
_KV_PAIR_RE = re.compile(r'\b[A-Za-z_][\w.\-]{1,40}\s*[=:]\s*("[^"]*"|\'[^\']*\'|[^\s,;]+)')
# An XML / HTML-ish tag.
_XML_TAG_RE = re.compile(r"<\s*/?\s*[A-Za-z][\w:.\-]*(\s+[^<>]*)?>")
# Syslog priority header "<34>" and the classic "Mon DD HH:MM:SS host" prefix.
_SYSLOG_PRI_RE = re.compile(r"^\s*<\d{1,3}>")
_SYSLOG_TS_RE = re.compile(
    r"^\s*(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+", re.MULTILINE
)
# Raw terminal / PowerShell flags, e.g. -ExecutionPolicy, -enc, -nop, /c, --headless.
_CLI_FLAG_RE = re.compile(
    r"(?:^|\s)(-{1,2}[A-Za-z][\w-]+|/[a-zA-Z]{1,12})\b"
)
# Well-known high-signal invocation flags that strongly imply raw command input.
_KNOWN_CLI_FLAGS = {
    "-executionpolicy", "-encodedcommand", "-enc", "-nop", "-noprofile",
    "-windowstyle", "-noninteractive", "-command", "-w", "/c", "/k", "/q",
    "-accepteula", "-ssh", "-i",
}
_SIEM_FIELD_RE = re.compile(
    r"\b(" + "|".join(re.escape(f) for f in _SIEM_FIELD_NAMES) + r")\b", re.IGNORECASE
)
# Sentence-ish prose detector: words ending a clause with terminal punctuation.
_SENTENCE_RE = re.compile(r"[A-Za-z][^.!?]{15,}?[.!?](?:\s|$)")

# --- raw command-line execution signals -------------------------------------
# Known shells, LOLBins, and offensive binaries. When one of these is invoked as
# a *raw command* — at the start of the input/line, followed by CLI args, or with
# mimikatz/DCOM "module::command" syntax — the payload is unambiguous structured
# telemetry even without JSON wrapping or SIEM field headers, so we force RAG.
# Deliberately excludes ambiguous English words (net/sc/reg) and tools that
# commonly appear inside CTI prose (procdump) so narrative reports still route to
# the deep-learning classifier; the context guards below keep firing precise.
_CMD_BINARIES = (
    "cmd", "powershell", "pwsh", "psexec", "paexec", "mimi", "mimikatz",
    "wmic", "rundll32", "regsvr32", "certutil", "bitsadmin", "mshta",
    "cscript", "wscript", "schtasks", "vssadmin", "nltest", "ntdsutil",
    "wevtutil", "sekurlsa", "lazagne", "cobaltstrike", "beacon",
)
_BIN_ALT = "|".join(_CMD_BINARIES)
# 1) a binary that starts the input or a line (optionally with a .exe suffix).
_CMD_AT_START_RE = re.compile(rf"(?im)(?:^|[\n\r;|&`])\s*(?:{_BIN_ALT})(?:\.exe)?\b")
# 2) a binary immediately followed by a CLI flag, path, UNC, or module syntax
#    (a plain English word after it does NOT count, so prose stays prose).
_CMD_WITH_ARGS_RE = re.compile(
    rf"\b(?:{_BIN_ALT})(?:\.exe)?\s*(?=[/\-\"']|\\|\w+::)", re.IGNORECASE)
# 3) mimikatz / DCOM-style "module::command" syntax (e.g. sekurlsa::logonpasswords).
_CMD_MODULE_RE = re.compile(r"\b[A-Za-z][\w]+::[A-Za-z][\w]+")
# 4) UNC path / admin share, e.g. \\192.168.10.25 or \\HOST\ADMIN$.
_UNC_PATH_RE = re.compile(r"\\\\[\w.\-]+(?:\\[\w.$\-]+)*")


def _detect_command_exec(text: str) -> Dict[str, Any]:
    """Detect raw command-line execution; returns fired signal descriptions."""
    fired: List[str] = []
    if _CMD_MODULE_RE.search(text):
        fired.append("module::command syntax")
    if _UNC_PATH_RE.search(text):
        fired.append("UNC/admin-share path")
    if _CMD_AT_START_RE.search(text):
        fired.append("command binary at line start")
    if _CMD_WITH_ARGS_RE.search(text):
        fired.append("command binary with CLI args")
    return {"command_exec": bool(fired), "command_signals": fired}


def _looks_like_json(text: str) -> bool:
    """True if the payload is (or begins as) a JSON object/array."""
    s = text.strip()
    if not s or s[0] not in "{[":
        return False
    # Try a real parse first; fall back to a structural heuristic for truncated
    # or concatenated log lines that are JSON-shaped but not a single document.
    try:
        json.loads(s)
        return True
    except (ValueError, TypeError):
        return bool(re.search(r'"\s*\w+\s*"\s*:', s)) and s.count("{") >= 1


def analyze_structure(text: str) -> Dict[str, Any]:
    """Compute the raw structural signals used by the router (no decision yet)."""
    text = text or ""
    sample = text[:20000]  # cap work on huge payloads; structure shows early

    siem_hits = sorted({m.group(1) for m in _SIEM_FIELD_RE.finditer(sample)})
    kv_pairs = len(_KV_PAIR_RE.findall(sample))
    xml_tags = len(_XML_TAG_RE.findall(sample))
    cli_flags_all = [f.strip() for f in _CLI_FLAG_RE.findall(sample)]
    known_cli = sorted({f for f in (c.lower() for c in cli_flags_all) if f in _KNOWN_CLI_FLAGS})
    sentences = len(_SENTENCE_RE.findall(sample))
    words = len(re.findall(r"[A-Za-z']+", sample))
    cmd = _detect_command_exec(sample)

    return {
        "is_json": _looks_like_json(sample),
        "xml_tags": xml_tags,
        "siem_fields": siem_hits,
        "kv_pairs": kv_pairs,
        "cli_flags": known_cli,
        "syslog_header": bool(_SYSLOG_PRI_RE.search(sample) or _SYSLOG_TS_RE.search(sample)),
        "command_exec": cmd["command_exec"],
        "command_signals": cmd["command_signals"],
        "sentences": sentences,
        "words": words,
        "chars": len(text),
    }


def _structured_score(sig: Dict[str, Any]) -> float:
    """Weighted evidence that the input is machine/structured telemetry."""
    score = 0.0
    # Raw command-line execution is decisive on its own (forced in route()); the
    # score is bumped here too so the signal is visible in transparency output.
    if sig.get("command_exec"):
        score += 5.0
    if sig["is_json"]:
        score += 3.0
    if sig["syslog_header"]:
        score += 3.0
    if sig["xml_tags"] >= 2:
        score += 2.5
    elif sig["xml_tags"] == 1:
        score += 1.0
    # SIEM field names are a strong, specific signal.
    score += min(len(sig["siem_fields"]), 4) * 1.5
    # Known raw CLI flags (e.g. -ExecutionPolicy) strongly imply command input.
    score += min(len(sig["cli_flags"]), 4) * 1.5
    # Dense key=value structure (relative to length) implies log-shaped data.
    if sig["words"]:
        kv_density = sig["kv_pairs"] / max(sig["words"] / 5.0, 1.0)
        if kv_density >= 1.0 and sig["kv_pairs"] >= 3:
            score += 2.5
        elif sig["kv_pairs"] >= 3:
            score += 1.0
    return round(score, 2)


def _prose_score(sig: Dict[str, Any]) -> float:
    """Weighted evidence that the input is unstructured natural-language prose."""
    score = 0.0
    # Multiple real sentences is the hallmark of a CTI write-up.
    score += min(sig["sentences"], 6) * 1.0
    # A healthy word count with few structured artefacts reads as prose.
    if sig["words"] >= 40 and sig["kv_pairs"] <= 2 and not sig["is_json"]:
        score += 2.0
    if sig["words"] >= 120:
        score += 1.0
    return round(score, 2)


# Structured score must clear this AND beat prose for telemetry routing.
STRUCTURED_THRESHOLD = 3.0


def route(text: str, pipeline_mode: str = "auto") -> Dict[str, Any]:
    """Resolve the engine for a request.

    Returns a ``routing_decision`` dict with the chosen ``engine``, a
    human-readable ``reason``, the requested ``mode``, and the structural
    ``signals`` that drove the choice. For explicit modes the structure is still
    analysed (for transparency) but does not change the outcome.
    """
    mode = (pipeline_mode or "auto").lower()
    signals = analyze_structure(text)
    struct = _structured_score(signals)
    prose = _prose_score(signals)
    signals["structured_score"] = struct
    signals["prose_score"] = prose

    if mode == ENGINE_RAG:
        return {
            "mode": mode, "engine": ENGINE_RAG, "auto": False,
            "reason": "Explicit pipeline_mode=rag override.",
            "signals": signals,
        }
    if mode == ENGINE_DEEP_LEARNING:
        return {
            "mode": mode, "engine": ENGINE_DEEP_LEARNING, "auto": False,
            "reason": "Explicit pipeline_mode=deep_learning override.",
            "signals": signals,
        }
    if mode == ENGINE_HYBRID:
        return {
            "mode": mode, "engine": ENGINE_HYBRID, "auto": False,
            "reason": ("Explicit pipeline_mode=hybrid override; running the "
                       "SecureBERT and RAG tracks sequentially and merging by "
                       "MITRE ID."),
            "signals": signals,
        }

    # --- auto ---------------------------------------------------------------
    # Hard override: a raw command-line invocation is structured telemetry by
    # definition (a shell/LOLBin with args, module syntax, or a UNC path), so it
    # goes to the RAG + constraint engine regardless of any prose-like wrapping.
    if signals.get("command_exec"):
        fired = ", ".join(signals.get("command_signals") or []) or "raw command invocation"
        return {
            "mode": "auto", "engine": ENGINE_RAG, "auto": True,
            "reason": (f"Raw command-line execution detected ({fired}); forced to "
                       f"the RAG + constraint engine."),
            "signals": signals,
        }
    if struct >= STRUCTURED_THRESHOLD and struct >= prose:
        fired = _describe_structured(signals)
        engine = ENGINE_RAG
        reason = (f"Structured telemetry detected ({fired}); routed to the "
                  f"RAG + constraint engine.")
    else:
        engine = ENGINE_DEEP_LEARNING
        reason = (f"Unstructured prose detected ({signals['sentences']} sentence(s), "
                  f"{signals['words']} words, low structured signal); routed to the "
                  f"SecureBERT + bi-encoder classifier.")
    return {
        "mode": "auto", "engine": engine, "auto": True,
        "reason": reason, "signals": signals,
    }


def _describe_structured(sig: Dict[str, Any]) -> str:
    parts: List[str] = []
    if sig.get("command_exec"):
        parts.append("raw command (" + ", ".join(sig.get("command_signals") or []) + ")")
    if sig["is_json"]:
        parts.append("JSON payload")
    if sig["syslog_header"]:
        parts.append("syslog header")
    if sig["xml_tags"]:
        parts.append(f"{sig['xml_tags']} XML tag(s)")
    if sig["siem_fields"]:
        parts.append("SIEM fields: " + ", ".join(sig["siem_fields"][:4]))
    if sig["cli_flags"]:
        parts.append("CLI flags: " + ", ".join(sig["cli_flags"][:4]))
    if sig["kv_pairs"] >= 3:
        parts.append(f"{sig['kv_pairs']} key=value pairs")
    return "; ".join(parts) or "structured artefacts"
