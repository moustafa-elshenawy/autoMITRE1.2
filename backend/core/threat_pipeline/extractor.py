"""
threat_pipeline.extractor  —  LAYER 1: Semantic Extraction
==========================================================
The LLM is used **strictly as an NLP engine**. It is forbidden from naming or
guessing MITRE techniques. Its only job is to turn raw, messy telemetry into a
clean list of structured relationships:

        [Action]  ->  [Tool]  ->  [Target / Modifier]

Two distinct extraction concerns live here:

  1. RELATIONS  — the behavioural facts ("dumped credentials from LSASS using
     mimikatz"). These come from the LLM (mlx-lm on Apple Silicon) because they
     require language understanding. A deterministic regex fallback is provided
     so the pipeline runs with zero model downloads.

  2. CONTEXT    — environmental facts (OS, ports, protocols, credential use).
     These are parsed deterministically with regex/keywords, NEVER the LLM,
     because Layer 3 (the constraint engine) must be able to trust them
     absolutely. A hallucinated port would poison every downstream rule.
"""
from __future__ import annotations

import json
import logging
import re
from typing import List, Optional, Tuple

from . import config
from .schema import ExtractedRelation, LogContext, Extraction

log = logging.getLogger("threat_pipeline.extractor")


# ===========================================================================
# EXACT LLM SYSTEM INSTRUCTIONS  (Layer 1 contract)
# ===========================================================================
SYSTEM_PROMPT = (
    "You are a cybersecurity log parser. You are NOT an analyst and you do NOT "
    "know the MITRE ATT&CK framework. Your ONLY task is natural-language "
    "relation extraction.\n"
    "\n"
    "From the raw security telemetry given, extract every distinct adversary "
    "behaviour as a structured relationship of the form:\n"
    "    action  ->  tool  ->  target  (with an optional modifier)\n"
    "\n"
    "STRICT RULES:\n"
    "1. NEVER output a MITRE technique ID (e.g. T1059) or technique name. If you "
    "are tempted to, output the plain-English behaviour instead.\n"
    "2. GROUNDING IS MANDATORY. Every value you output must be built from words "
    "that LITERALLY APPEAR in the telemetry below. Copy the log's own wording. "
    "Do NOT translate, normalise, paraphrase into canonical attack phrasing, or "
    "introduce any word that is not present in the log.\n"
    "3. 'action' is the verb/behaviour, taken from the log's own words. Use null "
    "is not allowed for action — if no behaviour is literally present, emit no "
    "relation for it.\n"
    "4. 'tool' is the concrete instrument actually named in the log text (a "
    "process/binary/utility that appears verbatim). Use null if none is named.\n"
    "5. 'target' is the object acted upon, taken from the log text. Use null if "
    "none is present.\n"
    "6. 'modifier' is any qualifier present in the log text. Use null if none.\n"
    "7. Do NOT invent, assume, or embellish. If the payload is encoded, opaque, "
    "or its intent is unclear, do NOT guess a plausible attack story — extract "
    "only the literal tokens present and leave everything else null. Returning "
    "FEWER, fully-grounded relations is always better than guessing.\n"
    "8. If nothing behavioural is literally present, return {\"relations\": []}.\n"
    "9. Output ONLY a JSON object, no prose, no markdown fences.\n"
)

# ===========================================================================
# EXACT PROMPT TEMPLATE
# ===========================================================================
PROMPT_TEMPLATE = (
    "Extract the adversary behaviour relationships from this telemetry.\n"
    "Use ONLY words that appear verbatim in the TELEMETRY block below; do not add "
    "words that are not present in it.\n"
    "\n"
    "Return JSON exactly in this shape:\n"
    "{{\n"
    '  "relations": [\n'
    '    {{"action": "<verb phrase>", "tool": "<tool or null>", '
    '"target": "<target or null>", "modifier": "<modifier or null>"}}\n'
    "  ]\n"
    "}}\n"
    "\n"
    "TELEMETRY:\n"
    '"""\n{log_text}\n"""\n'
)


# ---------------------------------------------------------------------------
# Deterministic context lexicons
# ---------------------------------------------------------------------------
_WINDOWS_MARKERS = (
    r"\bwindows\b", r"\bpowershell\b", r"\blsass\b", r"\bhk(?:lm|cu)\b",
    r"\bregistry\b", r"\bcmd\.exe\b", r"\b\w+\.exe\b", r"c:\\\\?", r"\.dll\b",
    r"\bwinrm\b", r"\bwmi\b", r"\bsysmon\b", r"\bevent id\b", r"\bntlm\b",
)
_LINUX_MARKERS = (
    r"\blinux\b", r"\bsshd?\b", r"/etc/", r"/var/log", r"/tmp/", r"\bbash\b",
    r"\bsystemd\b", r"\bcron(?:tab)?\b", r"\bchmod\b", r"\bsyslog\b", r"\.sh\b",
    r"/usr/bin", r"\bsudo\b",
)
_MACOS_MARKERS = (
    r"\bmacos\b", r"\bmac os\b", r"\bdarwin\b", r"\blaunchd\b", r"\bosascript\b",
    r"\.plist\b", r"/library/", r"\bplistbuddy\b", r"\bjamf\b",
)

# port -> (protocol label, is_application_layer)
_PORT_PROTOCOL = {
    20: "ftp", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 88: "kerberos", 110: "pop3", 135: "rpc", 137: "netbios",
    139: "smb", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtp", 587: "smtp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5985: "winrm",
    5986: "winrm", 8080: "http", 8443: "https",
}

_PROTOCOL_KEYWORDS = (
    "https", "http", "dns", "tls", "ssl", "ssh", "rdp", "smb", "ftp", "ldap",
    "icmp", "smtp", "kerberos", "winrm", "ntlm", "telnet", "snmp",
)

_NATIVE_REMOTE_KEYWORDS = (
    "rdp", "remote desktop", "ssh session", "winrm", "smb session",
    "psremoting", "wmi", "remote service", "interactive logon",
)

_VALID_CRED_KEYWORDS = (
    "valid account", "valid credential", "valid user", "legitimate credential",
    "stolen credential", "compromised credential", "successful logon",
    "successful authentication", "authenticated successfully", "logon succeeded",
    "login succeeded", "valid login",
)

# Tools we recognise without the LLM, for the fallback extractor.
_KNOWN_TOOLS = (
    "mimikatz", "powershell", "psexec", "cobalt strike", "metasploit",
    "rundll32", "regsvr32", "certutil", "bitsadmin", "wmic", "schtasks",
    "net.exe", "net", "nltest", "ssh", "scp", "curl", "wget", "nc", "ncat",
    "nmap", "bloodhound", "sharphound", "procdump", "lsass", "ntdsutil",
    "vssadmin", "wevtutil", "msbuild", "mshta", "cscript", "wscript",
)

_PORT_RE = re.compile(r"\b(?:port|dst\s*port|dport|:)\s*[:=]?\s*(\d{1,5})\b", re.I)
_PORT_COLON_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:(\d{1,5})\b")  # ip:port
_ACTION_VERBS = (
    "dump", "dumped", "execut", "ran", "launch", "encrypt", "exfiltrat",
    "download", "upload", "scan", "connect", "established", "created",
    "modified", "deleted", "injected", "escalat", "moved", "spray",
    "brute", "phish", "disabled", "cleared", "harvest", "enumerat",
    "persist", "tunnel", "spawned", "accessed", "transferred", "compress",
)


class SemanticExtractor:
    """Layer 1 entry point. Lazy-loads mlx-lm; degrades to regex on any failure."""

    def __init__(self) -> None:
        self._model = None
        self._tokenizer = None
        self._mlx_ok = not config.EXTRACTOR_FORCE_FALLBACK
        self._loaded = False

    # -- public API ---------------------------------------------------------
    def extract(self, raw_log: str) -> Extraction:
        """Turn one raw log/alert into structured relations + context."""
        raw_log = (raw_log or "").strip()
        context = self._detect_context(raw_log)

        relations, backend = [], "fallback"
        if self._mlx_ok:
            relations = self._extract_relations_llm(raw_log)
            backend = "mlx" if relations else "fallback"

        if not relations:
            relations = self._extract_relations_fallback(raw_log)

        return Extraction(relations=relations, context=context, backend=backend)

    # -- Layer 1a: LLM relation extraction ---------------------------------
    def _ensure_model(self) -> bool:
        if self._loaded:
            return self._model is not None
        self._loaded = True
        try:
            from mlx_lm import load  # imported lazily; heavy + Apple-Silicon only
            log.info("Loading mlx-lm model '%s' ...", config.MLX_MODEL)
            self._model, self._tokenizer = load(config.MLX_MODEL)
            log.info("mlx-lm model ready.")
            return True
        except Exception as e:  # noqa: BLE001 — any failure -> deterministic fallback
            log.warning("mlx-lm unavailable (%s). Using regex extractor.", e)
            self._mlx_ok = False
            return False

    def _build_prompt(self, raw_log: str) -> str:
        user_msg = PROMPT_TEMPLATE.format(log_text=raw_log[:6000])
        # Prefer the model's chat template so instruct formatting is correct.
        try:
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ]
            return self._tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
        except Exception:  # tokenizer without chat template
            return f"{SYSTEM_PROMPT}\n\n{user_msg}\n\nJSON:"

    def _extract_relations_llm(self, raw_log: str) -> List[ExtractedRelation]:
        if not raw_log or not self._ensure_model():
            return []
        try:
            from mlx_lm import generate
            prompt = self._build_prompt(raw_log)
            gen_kwargs = dict(max_tokens=config.EXTRACTOR_MAX_TOKENS, verbose=False)
            # temperature lives behind a sampler in recent mlx-lm; tolerate both.
            try:
                from mlx_lm.sample_utils import make_sampler
                gen_kwargs["sampler"] = make_sampler(temp=config.EXTRACTOR_TEMPERATURE)
            except Exception:
                pass
            text = generate(self._model, self._tokenizer, prompt=prompt, **gen_kwargs)
            return self._parse_llm_json(text, raw_log)
        except Exception as e:  # noqa: BLE001
            log.warning("mlx-lm generation failed (%s); falling back.", e)
            self._mlx_ok = False
            return []

    @staticmethod
    def _parse_llm_json(text: str, raw_log: str) -> List[ExtractedRelation]:
        if not text:
            return []
        # Strip markdown fences if the model wrapped its JSON in them.
        if "```" in text:
            parts = text.split("```")
            if len(parts) >= 3:
                text = parts[1]
                if text.lstrip().lower().startswith("json"):
                    text = text.split("\n", 1)[1] if "\n" in text else ""
        # Small instruct models sometimes drop a trailing brace/bracket; repair
        # before giving up so a perfectly good extraction isn't discarded.
        data = _loads_lenient(text)
        if not isinstance(data, dict):
            return []
        # Pre-compute the source token set once for the grounding gate.
        gate_on = config.EXTRACTOR_GROUND_RELATIONS
        source_tokens = _ground_tokens(raw_log) if gate_on else set()
        min_overlap = config.EXTRACTOR_MIN_TOKEN_OVERLAP
        out: List[ExtractedRelation] = []
        dropped = 0
        for r in data.get("relations", []):
            if not isinstance(r, dict):
                continue
            action = (r.get("action") or "").strip()
            if not action:
                continue
            relation = ExtractedRelation(
                action=action,
                tool=_clean(r.get("tool")),
                target=_clean(r.get("target")),
                modifier=_clean(r.get("modifier")),
                raw_phrase=raw_log[:200],
            )
            if gate_on:
                grounded = _ground_relation(relation, source_tokens, min_overlap)
                if grounded is None:
                    dropped += 1
                    continue
                relation = grounded
            out.append(relation)
        if dropped:
            log.info("grounding gate dropped %d ungrounded LLM relation(s) "
                     "(action shared <%d token(s) with source).", dropped, min_overlap)
        return out

    # -- Layer 1b: deterministic fallback ----------------------------------
    def _extract_relations_fallback(self, raw_log: str) -> List[ExtractedRelation]:
        """Regex/keyword extractor used when the LLM is unavailable.

        Splits the log into clauses and, for each clause containing an action
        verb, pulls out the (action, tool, target/modifier) triple heuristically.
        """
        relations: List[ExtractedRelation] = []
        # Split on sentence boundaries / clause separators, but NOT on periods
        # inside tokens like "powershell.exe" or "/tmp/.x" (period must be
        # followed by whitespace or end-of-string to count).
        clauses = re.split(r"[\n;]|\.(?=\s|$)|\b(?:and then|then|->|=>)\b", raw_log)
        for clause in clauses:
            c = clause.strip()
            if len(c) < 6:
                continue
            low = c.lower()
            if not any(v in low for v in _ACTION_VERBS):
                continue
            tool = next((t for t in _KNOWN_TOOLS if re.search(rf"\b{re.escape(t)}\b", low)), None)
            relations.append(
                ExtractedRelation(
                    action=c if len(c) <= 120 else c[:120],
                    tool=tool,
                    target=None,
                    modifier=None,
                    raw_phrase=c[:200],
                )
            )
        # If nothing matched, fall back to a single relation = the whole log.
        if not relations and raw_log:
            relations.append(ExtractedRelation(action=raw_log[:160], raw_phrase=raw_log[:200]))
        return relations

    # -- Deterministic context detection -----------------------------------
    def _detect_context(self, raw_log: str) -> LogContext:
        low = raw_log.lower()

        platform = self._detect_platform(low)
        ports = self._detect_ports(raw_log)
        protocols = self._detect_protocols(low, ports)
        uses_creds = any(k in low for k in _VALID_CRED_KEYWORDS)
        uses_native_remote = any(k in low for k in _NATIVE_REMOTE_KEYWORDS) or bool(
            {"rdp", "ssh", "smb", "winrm"} & set(protocols)
        )

        return LogContext(
            platform=platform,
            ports=ports,
            protocols=protocols,
            uses_valid_credentials=uses_creds,
            uses_native_remote_service=uses_native_remote,
            raw_text=raw_log,
        )

    @staticmethod
    def _detect_platform(low: str) -> str:
        scores = {
            "windows": sum(bool(re.search(p, low)) for p in _WINDOWS_MARKERS),
            "linux": sum(bool(re.search(p, low)) for p in _LINUX_MARKERS),
            "macos": sum(bool(re.search(p, low)) for p in _MACOS_MARKERS),
        }
        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else "unknown"

    @staticmethod
    def _detect_ports(raw_log: str) -> List[int]:
        found = set()
        for m in _PORT_RE.finditer(raw_log):
            found.add(int(m.group(1)))
        for m in _PORT_COLON_RE.finditer(raw_log):
            found.add(int(m.group(1)))
        return sorted(p for p in found if 0 < p <= 65535)

    @staticmethod
    def _detect_protocols(low: str, ports: List[int]) -> List[str]:
        protos = {kw for kw in _PROTOCOL_KEYWORDS if re.search(rf"\b{kw}\b", low)}
        for p in ports:
            if p in _PORT_PROTOCOL:
                protos.add(_PORT_PROTOCOL[p])
        return sorted(protos)


def _loads_lenient(text: str) -> Optional[dict]:
    """Parse the first JSON object in ``text``, repairing truncated output."""
    start = text.find("{")
    if start == -1:
        return None
    snippet = text[start:]
    try:
        return json.loads(snippet)
    except Exception:
        pass
    try:
        return json.loads(_balance_json(snippet))
    except Exception:
        return None


def _balance_json(s: str) -> str:
    """Close any unterminated string and unbalanced braces/brackets.

    Walks the text tracking string state (so braces inside string literals are
    ignored), then appends the mirror closers for whatever is still open — in
    correct innermost-first order.
    """
    stack: List[str] = []
    in_str = False
    esc = False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]" and stack:
            stack.pop()
    out = s
    if in_str:
        out += '"'
    out = out.rstrip()
    if out.endswith(","):
        out = out[:-1]
    closers = {"{": "}", "[": "]"}
    out += "".join(closers[c] for c in reversed(stack))
    return out


# ---------------------------------------------------------------------------
# Token-overlap grounding gate
# ---------------------------------------------------------------------------
_GROUND_TOKEN_RE = re.compile(r"[a-z0-9]+")
# A small, generic stop-list so connective words don't count as "grounding".
# Deliberately NOT security-specific so it can't mask a hallucinated behaviour.
_GROUND_STOPWORDS = frozenset({
    "the", "a", "an", "of", "to", "from", "with", "and", "or", "for", "on",
    "in", "at", "by", "as", "via", "using", "into", "onto", "over", "off",
    "out", "up", "down", "is", "was", "were", "be", "been", "being", "it",
    "its", "this", "that", "these", "those", "then", "than", "but", "not",
})


def _ground_tokens(text: Optional[str]) -> set:
    """Lower-cased content tokens (len>=2, stop-words removed) of ``text``."""
    return {
        t for t in _GROUND_TOKEN_RE.findall((text or "").lower())
        if len(t) >= 2 and t not in _GROUND_STOPWORDS
    }


def _overlap_count(field: Optional[str], source_tokens: set) -> Tuple[int, int]:
    """Return (#field tokens also in source, #field content tokens)."""
    ft = _ground_tokens(field)
    if not ft:
        return 0, 0
    return len(ft & source_tokens), len(ft)


def _ground_relation(relation: ExtractedRelation, source_tokens: set,
                     min_overlap: int) -> Optional[ExtractedRelation]:
    """Apply the token-overlap gate to one LLM relation.

    Returns the (possibly field-scrubbed) relation, or ``None`` if the relation
    is ungrounded and must be dropped. The ``action`` is the behavioural claim
    and the retrieval query, so an ungrounded action drops the whole relation;
    an ungrounded ``tool``/``target``/``modifier`` is merely nulled so it cannot
    pollute the retrieval query or evidence string.
    """
    if not source_tokens:
        return relation  # nothing to check against; don't gate
    a_hit, a_total = _overlap_count(relation.action, source_tokens)
    # a_total == 0 -> action carried no scorable tokens; can't judge, keep it.
    if a_total and a_hit < min_overlap:
        return None
    for attr in ("tool", "target", "modifier"):
        val = getattr(relation, attr)
        if val:
            hit, total = _overlap_count(val, source_tokens)
            if total and hit < min_overlap:
                setattr(relation, attr, None)
    return relation


def _clean(val: Optional[str]) -> Optional[str]:
    if val is None:
        return None
    s = str(val).strip()
    if not s or s.lower() in ("null", "none", "n/a", "unknown", ""):
        return None
    return s


# Singleton — model loading is expensive, share one instance app-wide.
extractor = SemanticExtractor()
