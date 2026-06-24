"""
htm_pipeline.py  —  autoMITRE Microsoft TMT Report Parser
==========================================================
Parses the HTML (.htm) report exported by Microsoft Threat Modeling Tool (TMT).

Phase 1 – extract_htm_attacks_pipeline
  Streams the HTM file, locates the threat table rows, and emits one
  ExtractedAttack per threat entry.  Each entry includes the STRIDE
  category, threat title, description, priority, and mitigation.

Phase 2 – analyze_htm_pipeline
  Passes a selected attack's raw_snippet to analyze_text_pipeline
  with the four mandatory legacy bypass parameters.

ISOLATION CONTRACT:
  This module MUST NOT import from any other pipeline (csv, json, pcap).
"""
from __future__ import annotations

import logging
import re
import uuid
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

from models.schemas import ExtractedAttack, InputType, ThreatResult
from core.input_processor import process_input
from core.pipelines.text_pipeline import analyze_text_pipeline

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 1 — STRIDE / PRIORITY MAPPINGS
# ═══════════════════════════════════════════════════════════════════════

# STRIDE → (MITRE tactic, MITRE technique, severity)
STRIDE_MAP: Dict[str, Tuple[str, str, str]] = {
    "Spoofing":              ("Initial Access",    "T1078",  "High"),
    "Tampering":             ("Impact",            "T1565",  "High"),
    "Repudiation":           ("Defence Evasion",   "T1070",  "Medium"),
    "Information Disclosure":("Collection",        "T1530",  "High"),
    "Denial of Service":     ("Impact",            "T1499",  "High"),
    "Elevation of Privilege":("Privilege Escalation", "T1068", "Critical"),
}

# TMT priority strings → our severity labels
PRIORITY_SEVERITY: Dict[str, str] = {
    "high":     "High",
    "critical": "Critical",
    "medium":   "Medium",
    "low":      "Low",
    "undefined":"Low",
    "not applicable": "Low",
}


# ═══════════════════════════════════════════════════════════════════════
# SECTION 2 — HTM PARSER
# ═══════════════════════════════════════════════════════════════════════

class _TMTHTMParser(HTMLParser):
    """
    State-machine HTML parser for the Microsoft TMT .htm report.

    The TMT report is a flat HTML page with a single large <table>.
    Each threat occupies a contiguous group of <tr> rows that share a
    common 'Threat #' identifier in the first cell.  We walk row-by-row,
    accumulating cell text, then flush a ThreatEntry when we detect a
    new threat or reach end-of-table.

    The parser is intentionally lenient: it ignores unknown tags and
    skips rows that don't contain recognisable threat content, making
    it robust to different TMT versions.
    """

    def __init__(self) -> None:
        super().__init__()
        self.threats: List[Dict[str, str]] = []

        # --- state -------------------------------------------------------
        self._in_table   : bool = False
        self._in_tr      : bool = False
        self._in_td      : bool = False
        self._cell_buf   : str  = ""
        self._row_cells  : List[str] = []
        self._current    : Dict[str, str] = {}
        self._capture    : bool = False  # True once we've seen a threat header row

    # ── HTMLParser callbacks ─────────────────────────────────────────────

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag == "table":
            self._in_table = True
        elif tag == "tr" and self._in_table:
            self._in_tr    = True
            self._row_cells = []
        elif tag in ("td", "th") and self._in_tr:
            self._in_td   = True
            self._cell_buf = ""

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and self._in_td:
            self._row_cells.append(self._cell_buf.strip())
            self._in_td   = False
            self._cell_buf = ""
        elif tag == "tr" and self._in_tr:
            self._process_row(self._row_cells)
            self._in_tr    = False
            self._row_cells = []
        elif tag == "table" and self._in_table:
            self._flush()
            self._in_table = False

    def handle_data(self, data: str) -> None:
        if self._in_td:
            self._cell_buf += data

    def handle_entityref(self, name: str) -> None:
        _ENTITY = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "nbsp": " ", "apos": "'"}
        if self._in_td:
            self._cell_buf += _ENTITY.get(name, "")

    def handle_charref(self, name: str) -> None:
        try:
            ch = chr(int(name[1:], 16) if name.startswith("x") else int(name))
        except (ValueError, OverflowError):
            ch = ""
        if self._in_td:
            self._cell_buf += ch

    # ── Row classification ───────────────────────────────────────────────

    def _process_row(self, cells: List[str]) -> None:
        if not cells:
            return

        # Detect a "Threat #N" header row
        if cells[0].strip().lower().startswith("threat #") or (
            len(cells) == 1 and re.match(r"threat\s*#?\d+", cells[0].strip(), re.I)
        ):
            self._flush()
            self._current = {"_header": cells[0].strip()}
            self._capture = True
            return

        if not self._capture:
            return

        # Key-value rows: first cell is a label (e.g. "Category:"), rest is value
        if len(cells) >= 2:
            label = cells[0].strip().rstrip(":").lower()
            value = " ".join(c.strip() for c in cells[1:] if c.strip())
            if label and value:
                self._current[label] = value

    def _flush(self) -> None:
        """Persist self._current as a finished threat if it has enough content."""
        c = self._current
        if not c or not any(
            k in c for k in ("threat name", "description", "category", "title", "name")
        ):
            self._current = {}
            return
        self.threats.append(dict(c))
        self._current = {}


# ═══════════════════════════════════════════════════════════════════════
# SECTION 3 — SNIPPET BUILDER
# ═══════════════════════════════════════════════════════════════════════

def _clean(text: str) -> str:
    """Collapse whitespace and strip NBSP."""
    return re.sub(r"\s+", " ", text.replace("\xa0", " ")).strip()


def _build_snippet(threat: Dict[str, str], context: Optional[str]) -> str:
    """
    Synthesise a high-signal analyst snippet from a parsed TMT threat dict.
    Prioritises the fields most useful for ATT&CK heuristic matching.
    """
    # Flexible key aliases produced by different TMT versions
    def _get(*keys: str) -> str:
        for k in keys:
            v = threat.get(k.lower(), "")
            if v and v.strip():
                return _clean(v)
        return ""

    title       = _get("threat name", "name", "title", "_header")
    category    = _get("category", "stride")
    description = _get("description", "details", "threat description")
    priority    = _get("priority", "risk")
    mitigation  = _get("possible mitigations", "mitigations", "countermeasure", "mitigation")
    component   = _get("component name", "component", "asset", "target")
    state       = _get("state", "status", "threat state")
    justification = _get("justification", "justification note")

    stride_info  = STRIDE_MAP.get(category, ("", "", ""))
    tactic       = stride_info[0] or "Multiple Tactics"
    technique    = stride_info[1] or ""

    lines = [f"[Microsoft TMT Threat] {title}"]
    if category:    lines.append(f"STRIDE Category : {category}")
    if tactic:      lines.append(f"Tactic          : {tactic}" + (f"  |  Technique: {technique}" if technique else ""))
    if priority:    lines.append(f"Priority        : {priority}")
    if component:   lines.append(f"Component       : {component}")
    if state:       lines.append(f"State           : {state}")
    if description: lines.append(f"Description     : {description}")
    if mitigation:  lines.append(f"Mitigation      : {mitigation}")
    if justification: lines.append(f"Justification   : {justification}")
    if context:     lines.insert(0, f"Analyst Context : {context}")

    return "\n".join(lines)


def _severity_for(threat: Dict[str, str]) -> str:
    """Determine severity from priority field, falling back to STRIDE category."""
    def _get(*keys: str) -> str:
        for k in keys:
            v = threat.get(k, "")
            if v:
                return v.strip().lower()
        return ""

    priority_raw = _get("priority", "risk")
    if priority_raw:
        for key, sev in PRIORITY_SEVERITY.items():
            if key in priority_raw:
                return sev

    category = _get("category", "stride")
    _, _, sev = STRIDE_MAP.get(category, ("", "", "Medium"))
    return sev or "Medium"


# ═══════════════════════════════════════════════════════════════════════
# SECTION 4 — PHASE 1: EXTRACTION
# ═══════════════════════════════════════════════════════════════════════

# Hard caps — memory safety on large model reports
MAX_THREATS = 200   # absolute cap on extracted ExtractedAttack objects


def extract_htm_attacks_pipeline(
    file_path: str,
    context: Optional[str] = None,
) -> List[ExtractedAttack]:
    """
    Parse a Microsoft TMT .htm report and return one ExtractedAttack per threat.

    The file is read in a single streaming pass via html.parser (stdlib only,
    no BeautifulSoup / lxml dependency required).  The parser is tolerant of
    varying TMT export formats (TMT 2016 through TMT 7).
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            raw_html = fh.read()
    except OSError as exc:
        raise ValueError(f"Cannot open HTM file: {exc}") from exc

    if not raw_html.strip():
        raise ValueError("HTM file is empty.")

    # Try structured table parse first
    parser = _TMTHTMParser()
    try:
        parser.feed(raw_html)
    except Exception as exc:
        logger.warning("TMT HTML parser encountered an error: %s — attempting fallback", exc)

    threats = parser.threats

    # ── Fallback: regex extraction when table parse yields nothing ──────
    if not threats:
        threats = _regex_fallback(raw_html)

    if not threats:
        # Last resort: Use the NLP heuristic engine to extract distinct threats from the raw text
        text_content = re.sub(r"<[^>]+>", " ", raw_html)
        text_content = _clean(text_content)[:15000] # Give the LLM enough context
        
        try:
            from core.nano_llm_engine import nano_llm
            llm_attacks = nano_llm.identify_attacks(text_content)
            if llm_attacks:
                extracted = []
                for idx, a in enumerate(llm_attacks):
                    extracted.append(ExtractedAttack(
                        id=f"htm-{uuid.uuid4().hex[:10]}",
                        title=a.get("title", f"Extracted TMT Threat {idx+1}"),
                        description=a.get("description", "Extracted from TMT report text."),
                        raw_snippet=a.get("raw_snippet", text_content[:500]),
                        severity_estimate=a.get("severity_estimate", "Medium"),
                        input_type="htm",
                        confidence=0.75,
                    ))
                return extracted
        except Exception as e:
            logger.warning(f"Nano LLM fallback for HTM failed: {e}")
            
        # Absolute worst case fallback if Nano LLM also fails
        snippet = f"[Microsoft TMT Report]\n{text_content[:8000]}"
        if context:
            snippet = f"Analyst Context: {context}\n\n{snippet}"
        return [ExtractedAttack(
            id=f"htm-{uuid.uuid4().hex[:10]}",
            title="Microsoft TMT Report (Full Document)",
            description="No structured threat table detected. Full report text extracted.",
            raw_snippet=snippet,
            severity_estimate="Medium",
            input_type="htm",
            confidence=0.60,
        )]

    extracted: List[ExtractedAttack] = []
    for threat in threats[:MAX_THREATS]:
        def _get(*keys: str) -> str:
            for k in keys:
                v = threat.get(k.lower(), "")
                if v:
                    return _clean(v)
            return ""

        title    = _get("threat name", "name", "title", "_header") or "Unnamed Threat"
        category = _get("category", "stride") or "Unknown"
        severity = _severity_for(threat)
        snippet  = _build_snippet(threat, context)

        stride_info = STRIDE_MAP.get(category, ("", "", ""))
        technique   = stride_info[1] or None
        tactic      = stride_info[0] or None

        extracted.append(ExtractedAttack(
            id=f"htm-{uuid.uuid4().hex[:10]}",
            title=title,
            description=(
                f"STRIDE: {category} | Priority: {_get('priority', 'risk') or 'Undefined'} | "
                f"Component: {_get('component name', 'component', 'asset') or 'N/A'}"
            ),
            raw_snippet=snippet,
            severity_estimate=severity,
            input_type="htm",
            mitre_technique_id=technique,
            mitre_tactic=tactic,
            confidence=0.88,
        ))

    return extracted


# ── Regex fallback for simpler / non-table TMT outputs ─────────────────

def _regex_fallback(html: str) -> List[Dict[str, str]]:
    """
    Secondary parser: pulls threat blocks using regex when the table
    parser yields nothing (e.g., non-standard HTML structure).
    """
    # Strip all tags to get readable text
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text)

    threats: List[Dict[str, str]] = []

    # Look for "Threat #N" ... "Threat #N+1" spans
    blocks = re.split(r"Threat\s*#\s*\d+", text, flags=re.IGNORECASE)
    for block in blocks[1:]:  # skip preamble
        t: Dict[str, str] = {}

        def _extract(pattern: str, label: str) -> None:
            m = re.search(pattern, block, re.IGNORECASE)
            if m:
                t[label] = m.group(1).strip()[:600]

        _extract(r"Threat Name\s*[:\-]?\s*(.+?)(?:\n|Category|Priority|$)", "threat name")
        _extract(r"Category\s*[:\-]?\s*(Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege)", "category")
        _extract(r"Description\s*[:\-]?\s*(.+?)(?:\n|Priority|Mitigation|$)", "description")
        _extract(r"Priority\s*[:\-]?\s*(High|Critical|Medium|Low|Undefined|Not Applicable)", "priority")
        _extract(r"Possible Mitigations\s*[:\-]?\s*(.+?)(?:\n|$)", "possible mitigations")

        if t:
            threats.append(t)

    return threats


# ═══════════════════════════════════════════════════════════════════════
# SECTION 5 — PHASE 2: ISOLATED ANALYSIS HANDOFF
# ═══════════════════════════════════════════════════════════════════════

def analyze_htm_pipeline(
    snippet: str,
    context: Optional[str] = None,
    suggested_techniques: Optional[List[str]] = None,
    suggested_severity: Optional[str] = None
) -> ThreatResult:
    """
    Map a Microsoft TMT threat snippet to MITRE ATT&CK techniques.

    ``snippet`` is the raw_snippet string from an ExtractedAttack block
    (already synthesised by _build_snippet).  It is passed directly to
    analyze_text_pipeline under the four mandatory legacy bypass parameters.
    """
    text_payload = snippet
    if context and not text_payload.startswith("Analyst Context"):
        text_payload = f"Analyst Context: {context}\n\n{text_payload}"

    processed = process_input(text_payload, InputType.TEXT.value)
    
    if suggested_techniques:
        processed['suggested_techniques'] = processed.get('suggested_techniques', []) + suggested_techniques

    # ── CRITICAL: four hard isolation parameters ───────────────────────
    res = analyze_text_pipeline(
        processed,
        pipeline_mode="legacy",
        apply_semantic_penalty=True,
        chunk_text=False,
        bypass_semantic=True,
        pruning_threshold=0.70,
    )
    
    if suggested_severity and res.risk_score:
        from models.schemas import SeverityLevel
        try:
            res.risk_score.severity = SeverityLevel(suggested_severity.capitalize())
        except ValueError:
            pass
            
    return res
