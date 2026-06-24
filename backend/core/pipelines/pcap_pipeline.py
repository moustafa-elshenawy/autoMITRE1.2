"""
pcap_pipeline.py  —  autoMITRE SOC-Grade PCAP Ingestion Engine
==============================================================
Phase 1: Signature-based threat hunting via memory-safe streaming (PcapReader).
Phase 2: Isolated MITRE ATT&CK handoff via legacy text pipeline.

DO NOT import from json_pipeline.py or alter text_pipeline.py.
This module is physically isolated.
"""
import re
import uuid
import logging
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple

from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Raw

from models.schemas import ThreatResult, ExtractedAttack, InputType
from core.input_processor import process_input
from core.pipelines.text_pipeline import analyze_text_pipeline

logger = logging.getLogger(__name__)


# =============================================================================
# SIGNATURE MATCHING ENGINE
# =============================================================================

class SignatureRule:
    """
    A single IDS rule definition.
    - pattern:  compiled regex (bytes or str)
    - title:    human-readable attack label shown in the UI
    - tactic:   MITRE ATT&CK tactic
    - technique_id: MITRE ATT&CK technique ID (best guess at detection time)
    - severity: Critical / High / Medium / Low
    """
    __slots__ = ("pattern", "title", "tactic", "technique_id", "severity")

    def __init__(self, pattern: str, title: str, tactic: str,
                 technique_id: str, severity: str):
        self.pattern     = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        self.title       = title
        self.tactic      = tactic
        self.technique_id = technique_id
        self.severity    = severity

    def match(self, payload: str) -> Optional[re.Match]:
        return self.pattern.search(payload)


SIGNATURE_RULES: List[SignatureRule] = [
    # ─── Web Exploits ────────────────────────────────────────────────────────
    SignatureRule(
        r"(\bUNION\b.{0,40}\bSELECT\b|\bSELECT\b.{0,60}\bFROM\b|1\s*=\s*1|'\s*OR\s+'|--\s*$|;\s*DROP\s+TABLE)",
        "SQL Injection Detected",
        "Initial Access", "T1190", "Critical"
    ),
    SignatureRule(
        r"(\/etc\/passwd|\/etc\/shadow|\.\.\/\.\.\/|%2e%2e%2f|%252e|path\s*traversal)",
        "Path Traversal / LFI Detected",
        "Initial Access", "T1190", "High"
    ),
    SignatureRule(
        r"(<script[\s>]|javascript\s*:|onerror\s*=|onload\s*=|<img[^>]+onerror|alert\s*\(|document\.cookie)",
        "Cross-Site Scripting (XSS) Detected",
        "Initial Access", "T1059.007", "High"
    ),
    SignatureRule(
        r"(cmd\.exe|/c\s+\w|powershell\s+-|wget\s+http|curl\s+-o|bash\s+-i|\.sh\s*&)",
        "Command Injection Detected",
        "Execution", "T1059", "Critical"
    ),
    SignatureRule(
        r"(sleep\(\d+\)|benchmark\(\d+|waitfor\s+delay|pg_sleep\(|time-based\s+blind)",
        "Blind SQL Injection (Time-Based) Detected",
        "Initial Access", "T1190", "Critical"
    ),
    SignatureRule(
        r"(XXE|<!ENTITY\s+\w+\s+SYSTEM|<!DOCTYPE[^>]+SYSTEM|file:///etc)",
        "XXE Injection Detected",
        "Initial Access", "T1190", "High"
    ),

    # ─── Malware & C2 ────────────────────────────────────────────────────────
    SignatureRule(
        r"(powershell.{0,20}-[eE][nN][cC]|FromBase64String\(|-[wW]indow[sS][tT]yle\s+[hH]idden|-[eE]xecution[pP]olicy\s+[bB]ypass)",
        "Obfuscated PowerShell Execution",
        "Execution", "T1059.001", "Critical"
    ),
    SignatureRule(
        r"(meterpreter|mimikatz|sekurlsa|lsadump|hashdump|wce\.exe|gsecdump|procdump\s+-ma\s+lsass)",
        "Credential Dumping / Post-Exploitation Tool",
        "Credential Access", "T1003", "Critical"
    ),
    SignatureRule(
        r"(nc\s+-[lvp]+\s+\d+|ncat\s+.{0,30}-[eE]|/bin/sh\s+-i|bash\s+-i\s+>&|/dev/tcp/[\d.]+/\d+)",
        "Reverse Shell / Bind Shell Detected",
        "Command and Control", "T1059.004", "Critical"
    ),
    SignatureRule(
        r"(python\s+-c\s+'import\s+socket|import\s+subprocess.*shell=True|exec\(base64|eval\(__import__)",
        "Python Reverse Shell / Code Injection",
        "Execution", "T1059.006", "Critical"
    ),
    SignatureRule(
        r"(Havoc|CobaltStrike|Sliver|BeaconEye|wce32|empire\s+powershell|invoke-mimikatz)",
        "Known C2 Framework Artifact",
        "Command and Control", "T1071", "Critical"
    ),
    SignatureRule(
        r"(GET\s+\/\s+HTTP|User-Agent:\s*curl|User-Agent:\s*python-requests|User-Agent:\s*Wget|User-Agent:\s*libwww-perl)",
        "Suspicious / Scripted HTTP User-Agent",
        "Command and Control", "T1071.001", "Medium"
    ),
    SignatureRule(
        r"(\.onion|tor2web|torify|torsocks)",
        "Tor / Dark Web C2 Communication",
        "Command and Control", "T1090.003", "High"
    ),

    # ─── Recon & Scanning ────────────────────────────────────────────────────
    SignatureRule(
        r"(Nmap|nmap\s+-[sSA]|masscan|zmap|shodan|censys|gobuster|dirbuster|nikto)",
        "Network / Web Reconnaissance Scanner",
        "Reconnaissance", "T1046", "High"
    ),
    SignatureRule(
        r"(USER\s+\w+\r\n|PASS\s+\w+\r\n|AUTH\s+LOGIN|530\s+Login|230\s+Login\s+successful)",
        "Cleartext FTP Authentication Detected",
        "Credential Access", "T1110", "Medium"
    ),
    SignatureRule(
        r"(telnet\b.*login:|login:\s*\w+\r\npassword:|^\w{1,20}\r\n[\w!@#$%^&*]{1,20}\r\n)",
        "Cleartext Telnet Authentication Detected",
        "Credential Access", "T1110", "Medium"
    ),
    SignatureRule(
        r"(Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,})",
        "HTTP Basic Auth Credentials in Cleartext",
        "Credential Access", "T1552.001", "High"
    ),

    # ─── Lateral Movement & Persistence ─────────────────────────────────────
    SignatureRule(
        r"(PSEXEC|psexesvc\.exe|admin\$\\|\\\\.*\\c\$\\|IPC\$|wmiexec|smbexec)",
        "Lateral Movement via SMB / PSExec",
        "Lateral Movement", "T1021.002", "Critical"
    ),
    SignatureRule(
        r"(PASS_HASH|NTLM_RELAY|responder|ntlmrelayx|hashcat\s+--hash-type|john\s+--wordlist)",
        "Pass-the-Hash / NTLM Relay Attack",
        "Lateral Movement", "T1550.002", "Critical"
    ),
    SignatureRule(
        r"(schtasks\s+/create|reg\s+add.*\\run|HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|crontab\s+-[le]|/etc/cron)",
        "Persistence Mechanism Detected",
        "Persistence", "T1053", "High"
    ),

    # ─── Exfiltration ────────────────────────────────────────────────────────
    SignatureRule(
        r"(Content-Disposition:\s*attachment|multipart/form-data.*filename=.*\.zip|\.rar|\.7z|\.tar\.gz)",
        "Suspicious File Upload / Data Exfiltration",
        "Exfiltration", "T1048", "High"
    ),
    SignatureRule(
        r"(base64_encode\(|base64_decode\(|btoa\(|atob\(|[A-Za-z0-9+/]{40,}={0,2})",
        "Base64-Encoded Payload Detected (Possible Staging)",
        "Defense Evasion", "T1027", "Medium"
    ),
]

# Suspicious destination ports mapped to context labels
SUSPICIOUS_PORTS: Dict[int, Tuple[str, str, str]] = {
    4444:  ("Metasploit Default C2 Port",     "Command and Control", "T1071"),
    4445:  ("Metasploit Stager Port",          "Command and Control", "T1071"),
    1337:  ("Elite / L33t C2 Port",            "Command and Control", "T1071"),
    31337: ("BackOrifice / Elite Port",        "Command and Control", "T1071"),
    6667:  ("IRC C2 Channel",                  "Command and Control", "T1071.004"),
    6666:  ("IRC / Botnet C2",                 "Command and Control", "T1071.004"),
    9001:  ("Tor OR Port",                     "Command and Control", "T1090.003"),
    9050:  ("Tor SOCKS Proxy Port",            "Command and Control", "T1090.003"),
    23:    ("Cleartext Telnet",                "Credential Access",   "T1110"),
    21:    ("Cleartext FTP",                   "Credential Access",   "T1110"),
    69:    ("TFTP (often abused for drops)",   "Lateral Movement",    "T1105"),
    445:   ("SMB - Lateral Movement Vector",   "Lateral Movement",    "T1021.002"),
    3389:  ("RDP - Remote Desktop",            "Lateral Movement",    "T1021.001"),
}

# Minimum payload size to inspect (skip tiny ACK/handshake packets)
MIN_PAYLOAD_BYTES = 20
# Maximum payload bytes aggregated per flow (prevents OOM on giant flows)
FLOW_PAYLOAD_CAP  = 8_000
# Maximum unique flows tracked in memory (large PCAPs)
MAX_FLOWS         = 50_000


# =============================================================================
# PHASE 1: EXTRACTION
# =============================================================================

def extract_pcap_attacks_pipeline(
    file_path: str,
    context: Optional[str] = None
) -> List[ExtractedAttack]:
    """
    Memory-safe IDS-grade threat extraction from a PCAP file.

    Uses PcapReader to stream packets one-at-a-time, assembles them into
    5-tuple sessions, and runs every reassembled payload through the
    SIGNATURE_RULES engine. Port-based heuristics fire independently.
    """
    # ── Flow table ──────────────────────────────────────────────────────────
    # key  → (src_ip:sport, dst_ip:dport, proto) tuple (sorted for bidir)
    # value → flow metadata dict
    flows: Dict[tuple, dict] = {}
    
    # ── Stream the PCAP one packet at a time ────────────────────────────────
    try:
        with PcapReader(file_path) as reader:
            for pkt in reader:
                if IP not in pkt:
                    continue
                if TCP not in pkt and UDP not in pkt:
                    continue
                if len(flows) >= MAX_FLOWS:
                    break  # Safety cap on massive enterprise captures

                src_ip  = pkt[IP].src
                dst_ip  = pkt[IP].dst
                sport   = int(pkt.sport)
                dport   = int(pkt.dport)
                proto   = "TCP" if TCP in pkt else "UDP"

                # Canonical bi-directional key
                endpoint_a = f"{src_ip}:{sport}"
                endpoint_b = f"{dst_ip}:{dport}"
                if endpoint_a > endpoint_b:
                    endpoint_a, endpoint_b = endpoint_b, endpoint_a
                flow_key = (endpoint_a, endpoint_b, proto)

                if flow_key not in flows:
                    flows[flow_key] = {
                        "src_ip":   src_ip,
                        "dst_ip":   dst_ip,
                        "sport":    sport,
                        "dport":    dport,
                        "proto":    proto,
                        "packets":  0,
                        "bytes":    0,
                        "payload":  "",   # decoded ASCII accumulator
                        "hits":     [],   # list of (rule_title, matched_text)
                        "port_hit": None, # populated if suspicious port matched
                    }

                flow = flows[flow_key]
                flow["packets"] += 1
                flow["bytes"]   += len(pkt)

                # ── Payload reassembly ───────────────────────────────────────
                if Raw in pkt and len(flow["payload"]) < FLOW_PAYLOAD_CAP:
                    raw_bytes = bytes(pkt[Raw].load)
                    decoded   = raw_bytes.decode("utf-8", errors="replace").strip()
                    if len(decoded) >= MIN_PAYLOAD_BYTES:
                        flow["payload"] += decoded + "\n"

                # ── Port heuristic (immediate, no payload needed) ────────────
                if dport in SUSPICIOUS_PORTS and flow["port_hit"] is None:
                    label, _, _ = SUSPICIOUS_PORTS[dport]
                    flow["port_hit"] = (dport, label)

    except Exception as exc:
        logger.error("PcapReader error on %s: %s", file_path, exc)
        raise ValueError(f"Failed to stream PCAP file: {exc}") from exc

    # ── Run signature engine over each assembled flow ───────────────────────
    validated_attacks: List[ExtractedAttack] = []
    attack_idx = 1

    for flow_key, flow in flows.items():
        payload_text = flow["payload"]

        # Signature rule sweep
        for rule in SIGNATURE_RULES:
            m = rule.match(payload_text)
            if m:
                hit_excerpt = payload_text[
                    max(0, m.start() - 80) : m.end() + 200
                ].replace("\n", " | ")[:400]
                flow["hits"].append((rule, hit_excerpt))

        # Build ExtractedAttack objects for each distinct hit
        for rule, excerpt in flow["hits"]:
            snippet = _build_snippet(flow, context,
                                     attack_label=rule.title,
                                     trigger_excerpt=excerpt,
                                     tactic=rule.tactic)
            validated_attacks.append(ExtractedAttack(
                id=f"pcap-sig-{attack_idx}-{uuid.uuid4().hex[:6]}",
                title=rule.title,
                description=(
                    f"Signature match in {flow['proto']} flow "
                    f"{flow['src_ip']}:{flow['sport']} → "
                    f"{flow['dst_ip']}:{flow['dport']}. "
                    f"MITRE: {rule.technique_id} ({rule.tactic})"
                ),
                raw_snippet=snippet,
                severity_estimate=rule.severity,
                mitre_technique_id=rule.technique_id,
                mitre_tactic=rule.tactic,
                confidence=0.88,
                input_type="pcap",
                payload_snippets=[excerpt],
            ))
            attack_idx += 1

        # Port-based hit (only if no deeper signature already fired)
        if flow["port_hit"] and not flow["hits"]:
            dport_num, port_label = flow["port_hit"]
            _, tactic, technique_id = SUSPICIOUS_PORTS[dport_num]
            snippet = _build_snippet(flow, context,
                                     attack_label=port_label,
                                     trigger_excerpt=f"Destination port {dport_num} contacted",
                                     tactic=tactic)
            validated_attacks.append(ExtractedAttack(
                id=f"pcap-port-{attack_idx}-{uuid.uuid4().hex[:6]}",
                title=f"Suspicious Port Contact: {dport_num} ({port_label})",
                description=(
                    f"{flow['proto']} session to port {dport_num} "
                    f"({flow['src_ip']} → {flow['dst_ip']}). "
                    f"MITRE: {technique_id} ({tactic})"
                ),
                raw_snippet=snippet,
                severity_estimate="High",
                mitre_technique_id=technique_id,
                mitre_tactic=tactic,
                confidence=0.75,
                input_type="pcap",
                payload_snippets=[flow["payload"][:300]] if flow["payload"] else [],
            ))
            attack_idx += 1

    return validated_attacks


def _build_snippet(flow: dict, context: Optional[str],
                   attack_label: str, trigger_excerpt: str,
                   tactic: str) -> str:
    """
    Construct the raw_snippet string that will be fed to analyze_text_pipeline.
    Written to maximise ATT&CK heuristic signal density.
    """
    lines = [
        f"[PCAP IDS ALERT] {attack_label}",
        f"Flow    : {flow['src_ip']}:{flow['sport']} → {flow['dst_ip']}:{flow['dport']} ({flow['proto']})",
        f"Tactic  : {tactic}",
        f"Volume  : {flow['packets']} packets / {flow['bytes']} bytes",
        f"Trigger : {trigger_excerpt}",
    ]
    if flow["payload"]:
        lines.append(f"Payload Sample:\n{flow['payload'][:600]}")
    if context:
        lines.insert(0, f"Analyst Context: {context}")
    return "\n".join(lines)


# =============================================================================
# PHASE 2: ISOLATED ANALYSIS HANDOFF
# =============================================================================

def analyze_pcap_pipeline(
    file_path: str,
    context: Optional[str] = None
) -> ThreatResult:
    """
    Runs the full IDS extraction, merges all snippets into one enriched block,
    then hands off to the isolated text pipeline.
    """
    attacks = extract_pcap_attacks_pipeline(file_path, context=context)

    if attacks:
        combined_text = "\n\n" + ("=" * 60) + "\n\n".join(a.raw_snippet for a in attacks)
        combined_text = f"[PCAP ANALYSIS — {len(attacks)} threat(s) detected]\n" + combined_text
    else:
        combined_text = "[PCAP ANALYSIS] No signature matches or suspicious ports detected. Traffic appears benign."

    if context and not attacks:
        combined_text = f"Analyst Context: {context}\n\n{combined_text}"

    processed = process_input(combined_text, InputType.TEXT.value)

    # Enforce strict isolation parameters — identical to JSON pipeline handoff
    return analyze_text_pipeline(
        processed,
        pipeline_mode="legacy",
        apply_semantic_penalty=True,
        chunk_text=False,
        bypass_semantic=True,
        pruning_threshold=0.70,
    )
