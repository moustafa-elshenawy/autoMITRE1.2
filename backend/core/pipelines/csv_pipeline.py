"""
csv_pipeline.py  —  autoMITRE SOC-Grade CSV Threat-Hunting Engine
==================================================================
Phase 1 – High-fidelity dual-context attack extraction:
  • Endpoint rules  : Sysmon / Windows Event / EDR telemetry
  • Network rules   : Suricata / Zeek / Firewall / IDS alerts
  Streams the CSV row-by-row via csv.DictReader — never loads the full
  file into RAM.  Safe on Apple Silicon M-series unified memory.

Phase 2 – Isolated MITRE ATT&CK handoff:
  Passes a synthesised raw_snippet into analyze_text_pipeline with
  hard-coded legacy bypass parameters so the NLP/RAG models are
  completely skipped.

ISOLATION CONTRACT:
  This module MUST NOT import from json_pipeline, pcap_pipeline, or
  any pipeline other than text_pipeline for the Phase-2 handoff.
"""
from __future__ import annotations

import csv
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from models.schemas import ExtractedAttack, InputType, ThreatResult
from core.input_processor import process_input
from core.pipelines.text_pipeline import analyze_text_pipeline

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 1 — RULE ENGINE DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CsvRule:
    """
    A single, self-contained detection rule.

    Attributes
    ----------
    name        Human-readable alert title shown in the UI.
    regex       Compiled pattern applied to the serialised row string.
    context     'endpoint' | 'network' — for snippet formatting.
    tactic      MITRE ATT&CK tactic label.
    technique   MITRE ATT&CK technique ID (best guess at detection time).
    severity    Critical / High / Medium / Low.
    confidence  Default pre-analysis confidence score (0-1).
    """
    name:       str
    regex:      re.Pattern
    context:    str          # 'endpoint' or 'network'
    tactic:     str
    technique:  str
    severity:   str
    confidence: float = 0.88


def _r(pattern: str) -> re.Pattern:
    """Compile a regex with IGNORECASE | DOTALL."""
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# ───────────────────────────────────────────────────────────────────────
# ENDPOINT RULES  (Sysmon / Windows Event / EDR / auditd)
# ───────────────────────────────────────────────────────────────────────
ENDPOINT_RULES: List[CsvRule] = [

    # ── Credential Access ─────────────────────────────────────────────
    CsvRule(
        name="Credential Dumping — Mimikatz / LSASS",
        regex=_r(r"(mimikatz|sekurlsa|lsadump|hashdump|lsass\.exe|procdump\s+-ma|"
                 r"gsecdump|wce\.exe|invoke-mimikatz|dcsync)"),
        context="endpoint", tactic="Credential Access", technique="T1003",
        severity="Critical", confidence=0.97,
    ),

    # ── Execution: PowerShell obfuscation ─────────────────────────────
    CsvRule(
        name="Obfuscated PowerShell Execution",
        regex=_r(r"powershell[^\n|]{0,60}(-[eE][nN][cC]|-[eE]xecution[pP]olicy\s+[bB]ypass|"
                 r"-[wW]indow[sS][tT]yle\s+[hH]idden|-[nN]o[pP]rofile|-[nN]onI[nN]teractive|"
                 r"FromBase64String|IEX\s*\()"),
        context="endpoint", tactic="Execution", technique="T1059.001",
        severity="Critical", confidence=0.95,
    ),

    # ── Execution: CMD shell / LOLBin abuse ───────────────────────────
    CsvRule(
        name="Suspicious CMD / LOLBin Execution",
        regex=_r(r"(cmd\.exe.{0,30}/[ck]\s+|wmic\s+\w|rundll32\.exe|regsvr32\.exe\s+/s|"
                 r"mshta\.exe|cscript\.exe|wscript\.exe|certutil\.exe.{0,30}-decode|"
                 r"bitsadmin\.exe|forfiles\s+/p)"),
        context="endpoint", tactic="Execution", technique="T1059",
        severity="High", confidence=0.88,
    ),

    # ── Defence Evasion: process-hollow / injection ───────────────────
    CsvRule(
        name="Process Injection / Hollowing",
        regex=_r(r"(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|"
                 r"RtlCreateUserThread|SetWindowsHookEx|CreateThread.{0,20}0x0|"
                 r"inject|hollow|shellcode)"),
        context="endpoint", tactic="Defence Evasion", technique="T1055",
        severity="Critical", confidence=0.90,
    ),

    # ── Persistence: scheduled tasks / registry run keys ─────────────
    CsvRule(
        name="Persistence — Scheduled Task / Registry Run Key",
        regex=_r(r"(schtasks\.exe.{0,40}/create|at\.exe\s+\d|"
                 r"reg\s+add.{0,60}(\\Run|\\RunOnce)|"
                 r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|"
                 r"crontab\s+-[el]|/etc/cron)"),
        context="endpoint", tactic="Persistence", technique="T1053",
        severity="High", confidence=0.88,
    ),

    # ── Lateral Movement: PSExec / DCOM / WMI ─────────────────────────
    CsvRule(
        name="Lateral Movement — PSExec / WMI / DCOM",
        regex=_r(r"(psexec|paexec|psexesvc|WMIC\s+/node|wmiexec|smbexec|"
                 r"\\\\.*\\admin\$|\\\\.*\\c\$|invoke-wmimethod|"
                 r"DCOM.*CreateInstanceEx)"),
        context="endpoint", tactic="Lateral Movement", technique="T1021",
        severity="Critical", confidence=0.90,
    ),

    # ── Discovery: AD / domain recon ──────────────────────────────────
    CsvRule(
        name="Active Directory / Domain Enumeration",
        regex=_r(r"(nltest\s+/domain_dusts|net\s+group.{0,30}domain|"
                 r"net\s+user\s+/domain|ldap_search|dsquery|bloodhound|"
                 r"sharphound|adrecon|get-aduser|get-addomain)"),
        context="endpoint", tactic="Discovery", technique="T1087",
        severity="High", confidence=0.88,
    ),

    # ── Exfiltration: shadow copy deletion (ransomware prep) ──────────
    CsvRule(
        name="Shadow Copy Deletion — Ransomware Precursor",
        regex=_r(r"(vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|"
                 r"bcdedit.{0,30}recovery|bcdedit.{0,30}no)"),
        context="endpoint", tactic="Impact", technique="T1490",
        severity="Critical", confidence=0.95,
    ),

    # ── Defence Evasion: AMSI / ETW bypass ───────────────────────────
    CsvRule(
        name="AMSI / ETW / Defender Bypass",
        regex=_r(r"(AmsiScanBuffer|amsiInitFailed|Set-MpPreference.{0,30}Disable|"
                 r"EtwEventWrite\s*0|COMPlus_ETWEnabled|disable.*antivirus|"
                 r"add-mppreference.*exclusionpath)"),
        context="endpoint", tactic="Defence Evasion", technique="T1562",
        severity="High", confidence=0.90,
    ),

    # ── Credential Access: token manipulation ─────────────────────────
    CsvRule(
        name="Token Impersonation / Privilege Escalation",
        regex=_r(r"(ImpersonateLoggedOnUser|SeDebugPrivilege|AdjustTokenPrivileges|"
                 r"CreateProcessWithTokenW|getsystem|impersonate|runas\s+/user)"),
        context="endpoint", tactic="Privilege Escalation", technique="T1134",
        severity="High", confidence=0.88,
    ),

    # ── Event ID 4688: suspicious new process ─────────────────────────
    CsvRule(
        name="Suspicious Process Creation (EventID 4688)",
        regex=_r(r"(EventID.*4688|event_id.*4688|event.*4688).{0,200}"
                 r"(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)"),
        context="endpoint", tactic="Execution", technique="T1059",
        severity="High", confidence=0.85,
    ),

    # ── Event ID 4625: brute force / failed logon ─────────────────────
    CsvRule(
        name="Brute Force / Failed Logon (EventID 4625)",
        regex=_r(r"(EventID.*4625|event_id.*4625|FailureReason|LogonFailure|"
                 r"4625.*0xC000006D|repeated.*failed.*logon|brute.?force)"),
        context="endpoint", tactic="Credential Access", technique="T1110",
        severity="Medium", confidence=0.80,
    ),
]


# ───────────────────────────────────────────────────────────────────────
# NETWORK RULES  (Suricata / Zeek / Firewall / IDS alert exports)
# ───────────────────────────────────────────────────────────────────────
NETWORK_RULES: List[CsvRule] = [

    # ── C2 by suspicious destination port ────────────────────────────
    CsvRule(
        name="Suspicious C2 Port Contact",
        regex=_r(r"(dest_port|dst_port|dport|destination.port)[^\n|]{0,10}"
                 r"(4444|4445|1337|31337|6667|6666|9001|9050|8443|1234)"),
        context="network", tactic="Command and Control", technique="T1071",
        severity="Critical", confidence=0.90,
    ),

    # ── Web exploit: SQL injection ────────────────────────────────────
    CsvRule(
        name="SQL Injection Detected",
        regex=_r(r"(UNION[\s+]+SELECT|1\s*=\s*1|'\s*OR\s+'|--\s*$|"
                 r";\s*DROP\s+TABLE|sleep\(\d+\)|benchmark\(\d+|"
                 r"WAITFOR\s+DELAY|pg_sleep)"),
        context="network", tactic="Initial Access", technique="T1190",
        severity="Critical", confidence=0.93,
    ),

    # ── Web exploit: directory traversal / LFI ───────────────────────
    CsvRule(
        name="Directory Traversal / LFI",
        regex=_r(r"(\.\./\.\./|%2e%2e%2f|%252e|/etc/passwd|/etc/shadow|"
                 r"c:\\windows\\|\\\\.*\\.*|path.traversal)"),
        context="network", tactic="Initial Access", technique="T1190",
        severity="High", confidence=0.90,
    ),

    # ── Web exploit: XSS ──────────────────────────────────────────────
    CsvRule(
        name="Cross-Site Scripting (XSS)",
        regex=_r(r"(<script[\s>]|javascript\s*:|onerror\s*=|onload\s*=|"
                 r"<img[^>]+onerror|alert\s*\(|document\.cookie)"),
        context="network", tactic="Initial Access", technique="T1059.007",
        severity="High", confidence=0.88,
    ),

    # ── Reverse shell payload indicators ──────────────────────────────
    CsvRule(
        name="Reverse Shell / Bind Shell Payload",
        regex=_r(r"(nc\s+-[lvp]+\s+\d+|ncat.{0,30}-[eE]|/bin/sh\s+-i|"
                 r"bash\s+-i\s+>&|/dev/tcp/[\d.]+/\d+|"
                 r"python\s+-c\s+'import\s+socket|"
                 r"rm\s+/tmp/[fhpqrs];\s*(nc|mkfifo))"),
        context="network", tactic="Command and Control", technique="T1059.004",
        severity="Critical", confidence=0.95,
    ),

    # ── Known Suricata / Snort ET alert signatures ────────────────────
    CsvRule(
        name="Known IDS Signature Match (ET / Snort)",
        regex=_r(r"(ET\s+(TROJAN|MALWARE|EXPLOIT|SCAN|POLICY|DOS)|"
                 r"SURICATA\s+\w+|GPL\s+(ATTACK|EXPLOIT|SCAN)|"
                 r"alert\s+tcp|alert\s+udp|alert\s+icmp)"),
        context="network", tactic="Command and Control", technique="T1071",
        severity="High", confidence=0.87,
    ),

    # ── Data exfiltration over HTTP ───────────────────────────────────
    CsvRule(
        name="Suspicious Data Exfiltration over HTTP",
        regex=_r(r"(Content-Disposition:\s*attachment|multipart/form-data.*filename=|"
                 r"large.{0,20}(upload|POST)|bytes_out[^\n|]{0,10}[0-9]{7,}|"
                 r"exfil|data.loss|DLP)"),
        context="network", tactic="Exfiltration", technique="T1048",
        severity="High", confidence=0.85,
    ),

    # ── Tor / proxy / dark-web routing ───────────────────────────────
    CsvRule(
        name="Tor / Dark-Web C2 Communication",
        regex=_r(r"(\.onion|tor2web|torify|torsocks|"
                 r"(dest_port|dport)[^\n|]{0,10}(9001|9050)|"
                 r"socks5.*127\.0\.0\.1:9050)"),
        context="network", tactic="Command and Control", technique="T1090.003",
        severity="High", confidence=0.90,
    ),

    # ── Cleartext authentication ───────────────────────────────────────
    CsvRule(
        name="Cleartext Credential Transmission (FTP / Telnet / HTTP-Basic)",
        regex=_r(r"(Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}|"
                 r"USER\s+\w+\r?\n|PASS\s+\w+\r?\n|"
                 r"(dest_port|dport)[^\n|]{0,8}(21|23)\b)"),
        context="network", tactic="Credential Access", technique="T1552.001",
        severity="Medium", confidence=0.80,
    ),

    # ── Network / port scanning ────────────────────────────────────────
    CsvRule(
        name="Network Reconnaissance / Port Scan",
        regex=_r(r"(Nmap|masscan|zmap|unicornscan|shodan|censys|"
                 r"gobuster|dirbuster|nikto|scan_type|portscan|"
                 r"connection.refused.*repeated|SYN.*flood)"),
        context="network", tactic="Reconnaissance", technique="T1046",
        severity="High", confidence=0.88,
    ),

    # ── Lateral movement over SMB ──────────────────────────────────────
    CsvRule(
        name="Lateral Movement over SMB / WinRM",
        regex=_r(r"(PSEXEC|psexesvc\.exe|"
                 r"(dest_port|dport)[^\n|]{0,8}(445|5985|5986)\b|"
                 r"NTLM_RELAY|responder|ntlmrelayx|Pass.the.Hash|PTH)"),
        context="network", tactic="Lateral Movement", technique="T1021.002",
        severity="Critical", confidence=0.90,
    ),
]

ALL_RULES: List[CsvRule] = ENDPOINT_RULES + NETWORK_RULES

# ───────────────────────────────────────────────────────────────────────
# Column-name vocabularies used to auto-detect log schema
# ───────────────────────────────────────────────────────────────────────

# Endpoint / Sysmon / Windows telemetry headers
_ENDPOINT_HEADERS = {
    "eventid", "event_id", "eventcode", "event_code",
    "cmdline", "commandline", "command_line", "parentcommandline",
    "process_name", "processname", "parentimage", "image",
    "hostname", "computer", "computername", "host",
    "user", "username", "accountname", "subjectusername",
    "processguid", "processid", "parentprocessguid",
    "targetfilename", "sourceimage",
}

# Network / Suricata / Zeek / firewall headers
_NETWORK_HEADERS = {
    "src_ip", "source_ip", "srcip", "sourceip",
    "dst_ip", "dest_ip", "dstip", "destip",
    "src_port", "source_port", "srcport",
    "dst_port", "dest_port", "dstport", "dport",
    "proto", "protocol", "transport",
    "alert", "signature", "sig_name", "category", "action",
    "bytes_in", "bytes_out", "flow_id",
    "http_method", "http_uri", "http_user_agent",
}

# Hard caps — tuned for M-series unified memory safety
MAX_UNIQUE_ATTACKS  = 100   # distinct ExtractedAttack objects returned
MAX_ROWS_PER_ATTACK = 50    # matching rows compressed into one snippet
ROW_FIELD_CAP       = 400   # max chars from any single CSV field value


# ═══════════════════════════════════════════════════════════════════════
# SECTION 2 — HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _detect_log_schema(headers: List[str]) -> str:
    """
    Inspect the CSV header row and return 'endpoint', 'network', or 'generic'.
    """
    normalised = {h.strip().lower() for h in headers if h}
    endpoint_score = len(normalised & _ENDPOINT_HEADERS)
    network_score  = len(normalised & _NETWORK_HEADERS)
    if endpoint_score >= 2:
        return "endpoint"
    if network_score >= 2:
        return "network"
    return "generic"


def _serialise_row(row: Dict[str, str]) -> str:
    """
    Turn a csv.DictReader row into a compact 'key: value | key: value' string.
    Values longer than ROW_FIELD_CAP are truncated to avoid bloating snippets.
    """
    parts = []
    for k, v in row.items():
        k_str = str(k).strip() if k else ""
        v_str = str(v).strip() if v else ""
        if k_str and v_str:
            if len(v_str) > ROW_FIELD_CAP:
                v_str = v_str[:ROW_FIELD_CAP] + "…"
            parts.append(f"{k_str}: {v_str}")
    return " | ".join(parts)


def _build_endpoint_snippet(row: Dict[str, str], rule: CsvRule, context: Optional[str]) -> str:
    """
    Format a Sysmon/Windows log row into a rich analyst-friendly snippet.
    Priority fields are pulled out and displayed first.
    """
    def _get(*keys: str) -> str:
        for k in keys:
            for col, val in row.items():
                if col and col.strip().lower() == k.lower() and val and val.strip():
                    return val.strip()[:ROW_FIELD_CAP]
        return ""

    host     = _get("hostname", "computer", "computername", "host", "dvc") or "Unknown"
    cmdline  = _get("cmdline", "commandline", "command_line", "parentcommandline")
    process  = _get("image", "processname", "process_name", "parentimage")
    user     = _get("user", "username", "accountname", "subjectusername")
    event_id = _get("eventid", "event_id", "eventcode", "event_code")
    ts       = _get("timestamp", "date", "time", "utctime", "systime", "eventtime", "@timestamp")

    parts: List[str] = [f"[Endpoint Alert] {rule.name}"]
    if ts:        parts.append(f"Time    : {ts}")
    parts.append(f"Host    : {host}")
    if event_id:  parts.append(f"EventID : {event_id}")
    if process:   parts.append(f"Process : {process}")
    if user:      parts.append(f"User    : {user}")
    if cmdline:   parts.append(f"Cmdline : {cmdline}")
    parts.append(f"Tactic  : {rule.tactic}  |  Technique: {rule.technique}")
    if context:   parts.insert(0, f"Analyst Context: {context}")
    return "\n".join(parts)


def _build_network_snippet(row: Dict[str, str], rule: CsvRule, context: Optional[str]) -> str:
    """
    Format a Suricata/Zeek/firewall alert row into a rich analyst snippet.
    """
    def _get(*keys: str) -> str:
        for k in keys:
            for col, val in row.items():
                if col and col.strip().lower() == k.lower() and val and val.strip():
                    return val.strip()[:ROW_FIELD_CAP]
        return ""

    src_ip   = _get("src_ip", "source_ip", "srcip", "sourceip") or "?"
    dst_ip   = _get("dst_ip", "dest_ip", "dstip", "destip")     or "?"
    dst_port = _get("dst_port", "dest_port", "dstport", "dport")
    proto    = _get("proto", "protocol", "transport")
    sig_name = _get("signature", "sig_name", "alert", "msg", "message", "rule", "rule_name")
    category = _get("category", "event_type", "class", "severity")
    ts       = _get("timestamp", "ts", "date", "time", "flow_start", "@timestamp")

    flow = f"{src_ip} → {dst_ip}"
    if dst_port: flow += f":{dst_port}"
    if proto:    flow += f" ({proto.upper()})"

    parts: List[str] = [f"[Network Alert] {rule.name}"]
    if ts:        parts.append(f"Time    : {ts}")
    parts.append(f"Flow    : {flow}")
    if sig_name:  parts.append(f"Sig     : {sig_name}")
    if category:  parts.append(f"Category: {category}")
    parts.append(f"Tactic  : {rule.tactic}  |  Technique: {rule.technique}")
    if context:   parts.insert(0, f"Analyst Context: {context}")
    return "\n".join(parts)


def _build_generic_snippet(row: Dict[str, str], rule: CsvRule, context: Optional[str]) -> str:
    """Fallback for CSV files whose schema could not be fingerprinted."""
    row_kv = _serialise_row(row)
    parts = [
        f"[CSV Alert] {rule.name}",
        f"Row Data : {row_kv}",
        f"Tactic   : {rule.tactic}  |  Technique: {rule.technique}",
    ]
    if context:
        parts.insert(0, f"Analyst Context: {context}")
    return "\n".join(parts)


def _estimate_severity_from_rows(matched_rules: List[CsvRule]) -> str:
    """Return the highest severity from the rules that fired on this group."""
    rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    best = "Low"
    for rule in matched_rules:
        if rank.get(rule.severity, 0) > rank.get(best, 0):
            best = rule.severity
    return best


# ═══════════════════════════════════════════════════════════════════════
# SECTION 3 — PHASE 1: EXTRACTION
# ═══════════════════════════════════════════════════════════════════════

def extract_csv_attacks_pipeline(
    file_path: str,
    context: Optional[str] = None,
) -> List[ExtractedAttack]:
    """
    Dual-context, memory-safe streaming CSV threat hunter.

    For each row the engine:
      1. Serialises the row to a compact 'key: value' string.
      2. Runs every rule's regex against that string.
      3. On a hit, builds a context-aware snippet (endpoint or network).
      4. Accumulates up to MAX_ROWS_PER_ATTACK example rows per rule,
         capped at MAX_UNIQUE_ATTACKS distinct ExtractedAttack objects.

    The file is never fully loaded into RAM; it is streamed via
    csv.DictReader which yields one dict at a time.
    """
    # ── per-rule accumulators: rule_name → list of (row, rule) ────────
    hits: Dict[str, List[Tuple[Dict[str, str], CsvRule]]] = {}
    schema: str = "generic"
    headers_detected: bool = False

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            reader = csv.DictReader(fh)

            for row_num, row in enumerate(reader):
                # Auto-detect schema from the first row's keys
                if not headers_detected and row:
                    schema = _detect_log_schema(list(row.keys()))
                    headers_detected = True

                serialised = _serialise_row(row)
                if not serialised:
                    continue

                # Choose ruleset based on schema (or try all on 'generic')
                if schema == "endpoint":
                    ruleset = ENDPOINT_RULES
                elif schema == "network":
                    ruleset = NETWORK_RULES
                else:
                    ruleset = ALL_RULES

                for rule in ruleset:
                    if rule.regex.search(serialised):
                        bucket = hits.setdefault(rule.name, [])
                        if len(bucket) < MAX_ROWS_PER_ATTACK:
                            bucket.append((row, rule))

                        # Hard cap on distinct threat groups
                        if len(hits) >= MAX_UNIQUE_ATTACKS:
                            break   # stop processing new rules this row

    except OSError as exc:
        logger.error("CSV stream error on %s: %s", file_path, exc)
        raise ValueError(f"Cannot open CSV file: {exc}") from exc
    except csv.Error as exc:
        logger.error("CSV parse error on %s: %s", file_path, exc)
        raise ValueError(f"Malformed CSV: {exc}") from exc

    # ── Build ExtractedAttack objects from the accumulators ────────────
    extracted: List[ExtractedAttack] = []

    for rule_name, row_list in hits.items():
        if not row_list:
            continue

        rule = row_list[0][1]   # all rows in this bucket share the same rule

        # Build individual snippets for each matching row, then join
        individual_snippets: List[str] = []
        for idx, (row, _rule) in enumerate(row_list):
            if schema == "endpoint":
                snip = _build_endpoint_snippet(row, rule, context if idx == 0 else None)
            elif schema == "network":
                snip = _build_network_snippet(row, rule, context if idx == 0 else None)
            else:
                snip = _build_generic_snippet(row, rule, context if idx == 0 else None)
            individual_snippets.append(snip)

        combined_snippet = ("\n" + "─" * 60 + "\n").join(individual_snippets)

        extracted.append(ExtractedAttack(
            id=f"csv-{uuid.uuid4().hex[:10]}",
            title=rule.name,
            description=(
                f"{rule.severity} severity — {rule.tactic} ({rule.technique}). "
                f"{len(row_list)} matching row(s) detected in {schema} log."
            ),
            raw_snippet=combined_snippet,
            severity_estimate=rule.severity,
            input_type="csv",
            mitre_technique_id=rule.technique,
            mitre_tactic=rule.tactic,
            confidence=rule.confidence,
        ))

    # ── Fallback: no rules fired → surface first 50 rows as a single block
    if not extracted:
        extracted = _fallback_extraction(file_path, context)

    return extracted


def _fallback_extraction(
    file_path: str,
    context: Optional[str],
) -> List[ExtractedAttack]:
    """
    When no signature fires, produce a single generic ExtractedAttack
    containing the first 50 rows so the analyst can still inspect the data.
    """
    rows_text: List[str] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            reader = csv.DictReader(fh)
            for idx, row in enumerate(reader):
                if idx >= 50:
                    break
                serialised = _serialise_row(row)
                if serialised:
                    rows_text.append(f"[CSV Row {idx + 1}] {serialised}")
    except Exception:
        pass

    if not rows_text:
        return []

    snippet = "\n".join(rows_text)
    if context:
        snippet = f"Analyst Context: {context}\n\n{snippet}"

    return [ExtractedAttack(
        id=f"csv-{uuid.uuid4().hex[:10]}",
        title="CSV Log Data (No Signatures Matched)",
        description="No known attack signatures fired. First 50 rows included for manual review.",
        raw_snippet=snippet,
        severity_estimate="Low",
        input_type="csv",
        confidence=0.50,
    )]


# ═══════════════════════════════════════════════════════════════════════
# SECTION 4 — PHASE 2: ISOLATED ANALYSIS HANDOFF
# ═══════════════════════════════════════════════════════════════════════

def analyze_csv_pipeline(
    csv_source: str,
    context: Optional[str] = None,
    suggested_techniques: Optional[List[str]] = None,
    suggested_severity: Optional[str] = None
) -> ThreatResult:
    """
    Isolated MITRE ATT&CK mapping for a synthesised CSV attack snippet.

    ``csv_source`` may be:
      • A file-system path  → runs extraction + takes the first attack's snippet.
      • A raw text string   → treated directly as the analysis payload.

    The call to analyze_text_pipeline is locked to the four legacy bypass
    parameters that guarantee the NLP/RAG models are completely skipped and
    only the deterministic heuristic engine runs.
    """
    import os

    if os.path.isfile(csv_source):
        # File path: extract, grab first block's snippet
        attacks = extract_csv_attacks_pipeline(csv_source, context=context)
        text_payload = attacks[0].raw_snippet if attacks else csv_source
    else:
        # Raw snippet received from the UI (user clicked an extracted block)
        text_payload = csv_source

    if context and not text_payload.startswith("Analyst Context:"):
        text_payload = f"Analyst Context: {context}\n\n{text_payload}"

    processed = process_input(text_payload, InputType.TEXT.value)

    if suggested_techniques:
        processed['suggested_techniques'] = processed.get('suggested_techniques', []) + suggested_techniques

    # ── CRITICAL: enforce four hard isolation parameters ───────────────
    res = analyze_text_pipeline(
        processed,
        pipeline_mode="legacy",    # short-circuit before intake router
        apply_semantic_penalty=True,
        chunk_text=False,          # never split — snippet is already scoped
        bypass_semantic=True,      # skip SecureBERT bi-encoder
        pruning_threshold=0.70,    # deterministic heuristic gate
    )
    
    if suggested_severity and res.risk_score:
        from models.schemas import SeverityLevel
        try:
            res.risk_score.severity = SeverityLevel(suggested_severity.capitalize())
        except ValueError:
            pass
            
    return res
