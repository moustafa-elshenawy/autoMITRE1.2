import uuid
import logging
from bs4 import BeautifulSoup
from typing import List, Optional
import os

from models.schemas import ExtractedAttack, ThreatResult, InputType
from core.input_processor import process_input
from core.pipelines.text_pipeline import analyze_text_pipeline

logger = logging.getLogger(__name__)

# STRIDE Category to MITRE mapping for fallback/hints
STRIDE_MAP = {
    "Spoofing": ("Initial Access", "T1078", "High"),
    "Tampering": ("Impact", "T1565", "High"),
    "Repudiation": ("Defense Evasion", "T1070", "Medium"),
    "Information Disclosure": ("Collection", "T1530", "High"),
    "Denial of Service": ("Impact", "T1499", "High"),
    "Elevation of Privilege": ("Privilege Escalation", "T1068", "Critical"),
}

def extract_tmt_attacks_pipeline(
    file_path: str,
    context: Optional[str] = None
) -> List[ExtractedAttack]:
    """
    Phase 1: High-Fidelity TMT HTML Extraction
    Parses a Microsoft Threat Modeling Tool .html report using BeautifulSoup.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            soup = BeautifulSoup(f.read(), "html.parser")
    except OSError as exc:
        logger.error(f"Failed to open TMT file {file_path}: {exc}")
        return []

    attacks: List[ExtractedAttack] = []
    
    # In TMT reports, threats are usually in tables where rows represent a threat.
    # Often, they are defined in a table where the first column is a property and the second is a value.
    # We will look for sequences that indicate a threat, or standard TMT table structures.
    # Typically, a TMT HTML report has multiple tables. A threat usually starts with "Threat Name" or "Title".
    
    # We will find all tables and extract rows. 
    # Because TMT reports can be structured as one large table with "Threat N" header rows, 
    # OR multiple small tables, we'll implement a robust block extractor.
    
    current_threat = {}
    threat_divs = soup.find_all("div", class_="threat")
    if not threat_divs:
        logger.warning("No structured TMT threats found via bs4 div parsing. TMT template may differ.")
    
    import re
    state_pattern = re.compile(r"\[State:\s*([^\]]+)\]", re.IGNORECASE)
    priority_pattern = re.compile(r"\[Priority:\s*([^\]]+)\]", re.IGNORECASE)

    for div in threat_divs:
        current_threat = {}
        # Title and inline tags
        h4 = div.find("h4")
        if h4:
            raw_title = h4.get_text(strip=True)
            # Extract state/priority if present in title
            s_match = state_pattern.search(raw_title)
            if s_match:
                current_threat["state"] = s_match.group(1).strip()
            p_match = priority_pattern.search(raw_title)
            if p_match:
                current_threat["priority"] = p_match.group(1).strip()
            
            # Clean title
            clean_title = state_pattern.sub("", raw_title)
            clean_title = priority_pattern.sub("", clean_title)
            # Remove leading numbers like "1. "
            clean_title = re.sub(r"^\d+\.\s*", "", clean_title).strip()
            current_threat["title"] = clean_title

        # Properties table
        table = div.find("table")
        if table:
            for row in table.find_all("tr"):
                cells = row.find_all(["th", "td"])
                if len(cells) >= 2:
                    key = cells[0].get_text(strip=True).lower().rstrip(":")
                    val = cells[1].get_text(strip=True)
                    if key in ["category", "stride"]:
                        current_threat["category"] = val
                    elif key in ["description", "details", "threat description"]:
                        current_threat["description"] = val
                    elif key in ["interaction", "flow"]:
                        current_threat["interaction"] = val
                    elif key in ["state", "status"]:
                        current_threat["state"] = val
                    elif key in ["priority", "risk"]:
                        current_threat["priority"] = val
                    elif key in ["mitigation", "possible mitigations"]:
                        current_threat["mitigation"] = val

        if current_threat.get("title") or current_threat.get("description"):
            _process_threat(current_threat, attacks, context)

    return attacks

def _process_threat(threat: dict, attacks: list, context: Optional[str]):
    """Filter and build ExtractedAttack."""
    state = threat.get("state", "").lower()
    
    # Filter out mitigated/not applicable
    if state in ["mitigated", "not applicable", "resolved"]:
        return
        
    title = threat.get("title", "Unnamed TMT Threat")
    category = threat.get("category", "Unknown")
    desc = threat.get("description", "No description provided.")
    interaction = threat.get("interaction", "Unknown Flow")
    
    stride_info = STRIDE_MAP.get(category, ("", "", "Medium"))
    tactic = stride_info[0]
    technique = stride_info[1]
    
    # Priority handling
    priority_raw = threat.get("priority", "").lower()
    if "critical" in priority_raw: severity = "Critical"
    elif "high" in priority_raw: severity = "High"
    elif "low" in priority_raw: severity = "Low"
    else: severity = stride_info[2]

    # Synthesize the raw_snippet
    snippet_lines = [f"[STRIDE: {category}] Title: {title} | Flow: {interaction}"]
    snippet_lines.append(f"Description: {desc}")
    if threat.get("mitigation"):
        snippet_lines.append(f"Mitigation: {threat.get('mitigation')}")
    if context:
        snippet_lines.insert(0, f"Analyst Context: {context}")
        
    raw_snippet = " | ".join(snippet_lines)

    attacks.append(ExtractedAttack(
        id=f"tmt-{uuid.uuid4().hex[:10]}",
        title=title,
        description=f"STRIDE: {category} | State: {threat.get('state', 'Unknown').capitalize()}",
        raw_snippet=raw_snippet,
        severity_estimate=severity,
        input_type="html",
        mitre_technique_id=technique,
        mitre_tactic=tactic,
        confidence=0.85
    ))

def analyze_tmt_pipeline(
    snippet: str,
    context: Optional[str] = None,
    suggested_techniques: Optional[List[str]] = None,
    suggested_severity: Optional[str] = None
) -> ThreatResult:
    """
    Phase 2: The Isolated Handoff
    Passes the synthesized raw_snippet into analyze_text_pipeline using strict isolation parameters.
    """
    if os.path.isfile(snippet):
        attacks = extract_tmt_attacks_pipeline(snippet, context=context)
        text_payload = attacks[0].raw_snippet if attacks else snippet
    else:
        text_payload = snippet

    if context and not text_payload.startswith("Analyst Context:"):
        text_payload = f"Analyst Context: {context}\n\n{text_payload}"
        
    processed = process_input(text_payload, InputType.TEXT.value)
    
    if suggested_techniques:
        processed['suggested_techniques'] = processed.get('suggested_techniques', []) + suggested_techniques

    # CRITICAL ISOLATION: Bypass NLP models, enforce deterministic heuristics
    res = analyze_text_pipeline(
        processed,
        pipeline_mode="legacy",
        apply_semantic_penalty=True,
        chunk_text=False,
        bypass_semantic=False,  # Set to False so it uses NLP for STRIDE descriptions!
        pruning_threshold=0.70
    )
    
    # Inject suggested techniques if text_pipeline missed them
    if suggested_techniques:
        if not res.raw_indicators:
            res.raw_indicators = {}
        if 'technique_ids' not in res.raw_indicators:
            res.raw_indicators['technique_ids'] = []
        for tech in suggested_techniques:
            if tech not in res.raw_indicators['technique_ids']:
                res.raw_indicators['technique_ids'].append(tech)

    # Forcefully apply suggested severity if provided
    if suggested_severity and res.risk_score:
        from models.schemas import SeverityLevel
        try:
            # First, update the SeverityLevel enum
            res.risk_score.severity = SeverityLevel(suggested_severity.capitalize())
        except ValueError:
            pass
            
    return res
