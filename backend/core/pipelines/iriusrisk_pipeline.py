import uuid
import logging
import os
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from typing import List, Optional

from models.schemas import ExtractedAttack, ThreatResult, InputType
from core.input_processor import process_input
from core.pipelines.text_pipeline import analyze_text_pipeline

logger = logging.getLogger(__name__)

def extract_iriusrisk_attacks_pipeline(
    file_path: str,
    context: Optional[str] = None
) -> List[ExtractedAttack]:
    """
    Phase 1: High-Fidelity IriusRisk Extraction
    Dual-parser: bs4 for HTML and iterparse for XML.
    Extracts Component Name, Threat Title, Description, and CWE/CAPEC.
    """
    attacks: List[ExtractedAttack] = []
    
    is_html = file_path.endswith((".htm", ".html"))
    is_xml = file_path.endswith(".xml")
    is_csv = file_path.endswith(".csv")
    is_excel = file_path.endswith((".xls", ".xlsx"))
    is_pdf = file_path.endswith(".pdf")

    if is_html:
        attacks = _parse_html_report(file_path, context)
    elif is_xml:
        attacks = _parse_xml_data_model(file_path, context)
    elif is_csv:
        attacks = _parse_tabular_data(file_path, context, is_excel=False)
    elif is_excel:
        attacks = _parse_tabular_data(file_path, context, is_excel=True)
    elif is_pdf:
        attacks = _parse_pdf_report(file_path, context)
    else:
        logger.error(f"Unsupported file type for IriusRisk pipeline: {file_path}")

    return attacks

def _parse_html_report(file_path: str, context: Optional[str]) -> List[ExtractedAttack]:
    """
    Schema router: detects the IriusRisk HTML report type and dispatches to the
    appropriate sub-parser.

    Supported schemas:
      1. Technical Threat Report  — classic tabular layout (original parser)
      2. Current Risk Summary     — CSS flexbox layout (new parser)
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            html_content = f.read()
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception as exc:
        logger.error(f"Failed to read/parse HTML file '{file_path}': {exc}")
        return []

    # ── Schema Detection ──────────────────────────────────────────────────────
    # The Current Risk Summary wraps everything in a distinctive root element.
    is_summary_report = bool(
        soup.find(class_="current-risk-summary-report")
        or soup.find(class_="current-risk-threats-list")
        or soup.find(id="current-risk-summary-report")
        # Broader title-based fallback
        or any(
            "current risk summary" in tag.get_text(" ", strip=True).lower()
            for tag in soup.find_all(["h1", "h2", "title"])
        )
    )

    if is_summary_report:
        logger.info("IriusRisk HTML: detected 'Current Risk Summary Report' schema.")
        return _parse_html_current_risk_summary(soup, context)
    else:
        logger.info("IriusRisk HTML: detected 'Technical Threat Report' schema.")
        return _parse_html_technical_report(soup, context)


def _parse_html_technical_report(soup: "BeautifulSoup", context: Optional[str]) -> List[ExtractedAttack]:
    """
    Original tabular parser for the IriusRisk Technical Threat Report.
    Preserved exactly as before — do NOT modify Phase 2 handoff parameters.
    """
    attacks = []
    try:
        tables = soup.find_all("table")
        for table in tables:
            headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]

            if not any(k in headers for k in ["threat", "weakness", "countermeasure", "risk"]):
                continue

            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) != len(headers) or not cells:
                    continue

                row_data = {headers[i]: cells[i].get_text(strip=True) for i in range(len(cells))}

                state = row_data.get("state", "").lower()
                if state in ["passed", "implemented", "mitigated"]:
                    continue

                component = row_data.get("component", row_data.get("trust zone", "Unknown Component"))
                title = row_data.get("threat", row_data.get("name", "Unnamed Threat"))
                desc = row_data.get("description", "No description provided.")
                weakness = row_data.get("weakness", row_data.get("cwe", ""))

                attacks.append(_build_attack(component, title, desc, weakness, context))
    except Exception as exc:
        logger.error(f"HTML (Technical Threat Report) parsing failed: {exc}")

    return attacks


def _parse_html_current_risk_summary(soup: "BeautifulSoup", context: Optional[str]) -> List[ExtractedAttack]:
    """
    Parser for the IriusRisk 'Current Risk Summary Report' (CSS flexbox layout).

    DOM traversal strategy
    ──────────────────────
    The report is structured as a list of *component blocks*, each containing
    one or more *threat items*.  The relevant CSS class hierarchy is:

        .current-risk-threats-list
          └── .current-risk-threats-list__component-item   (component name)
                └── .current-risk-threats-list__list-block-item  (one threat)
                      ├── .threat-name .text-name                (threat title)
                      └── .current-risk-threats-list__countermeasure__status  (per-CM status)

    Filter rule: drop a threat only when *all* of its associated countermeasures
    have a status of "Implemented" or "Passed" (case-insensitive).
    """
    attacks: List[ExtractedAttack] = []
    MITIGATED_STATUSES = {"implemented", "passed"}

    try:
        # ── Locate threat-list root(s) ────────────────────────────────────────
        threat_lists = soup.find_all(class_="current-risk-threats-list")
        if not threat_lists:
            # Broader fallback: look for any container whose class contains the keyword
            threat_lists = soup.find_all(
                lambda tag: tag.name and
                any("current-risk-threats-list" in c for c in tag.get("class", []))
            )

        if not threat_lists:
            logger.warning(
                "Current Risk Summary parser: could not locate "
                "'.current-risk-threats-list' — falling back to full-document scan."
            )
            threat_lists = [soup]  # Scan the whole document as a last resort

        for threat_list in threat_lists:
            # ── Iterate component blocks ──────────────────────────────────────
            component_blocks = threat_list.find_all(
                class_="current-risk-threats-list__component-item"
            )

            if not component_blocks:
                # Some report variants don't use a dedicated component wrapper;
                # treat the whole list as a single implicit component.
                component_blocks = [threat_list]

            for comp_block in component_blocks:
                # Extract component name from the block heading / label
                component = _extract_component_name(comp_block)

                # ── Iterate threat items inside this component ────────────────
                threat_items = comp_block.find_all(
                    class_="current-risk-threats-list__list-block-item"
                )
                if not threat_items:
                    # Fallback: any child div that contains a .threat-name
                    threat_items = [
                        el for el in comp_block.find_all(True)
                        if el.find(class_="threat-name")
                    ]

                for item in threat_items:
                    # ── Threat title ─────────────────────────────────────────
                    title = _extract_threat_title(item)
                    if not title:
                        continue  # Skip malformed blocks

                    # ── Description (optional — not always present in summary) ─
                    desc_el = item.find(class_="threat-description") or item.find(class_="text-description")
                    desc = desc_el.get_text(" ", strip=True) if desc_el else "See IriusRisk for full description."

                    # ── Countermeasure statuses ───────────────────────────────
                    cm_status_els = item.find_all(
                        class_="current-risk-threats-list__countermeasure__status"
                    )
                    # Also accept generic status badges if the specific class is absent
                    if not cm_status_els:
                        cm_status_els = item.find_all(class_=lambda c: c and "status" in c)

                    cm_statuses = [
                        el.get_text(" ", strip=True).lower()
                        for el in cm_status_els
                    ]

                    # ── Mitigation filter ─────────────────────────────────────
                    # Drop the threat only if ALL countermeasures are mitigated.
                    if cm_statuses and all(s in MITIGATED_STATUSES for s in cm_statuses):
                        logger.debug(
                            f"Skipping fully-mitigated threat: '{title}' "
                            f"(statuses: {cm_statuses})"
                        )
                        continue

                    # ── CWE / weakness (optional) ─────────────────────────────
                    weakness_el = item.find(class_="cwe") or item.find(class_="weakness")
                    weakness = weakness_el.get_text(" ", strip=True) if weakness_el else ""

                    attacks.append(_build_attack(component, title, desc, weakness, context))

    except Exception as exc:
        logger.error(f"HTML (Current Risk Summary) parsing failed: {exc}", exc_info=True)

    logger.info(
        f"Current Risk Summary parser extracted {len(attacks)} unmitigated threat(s)."
    )
    return attacks


def _extract_component_name(block) -> str:
    """
    Heuristically extract the component/component-group name from a block element.
    Tries several well-known IriusRisk CSS classes before falling back to text.
    """
    for cls in [
        "current-risk-threats-list__component-name",
        "component-name",
        "component-title",
        "component-header",
        "block-title",
    ]:
        el = block.find(class_=cls)
        if el:
            return el.get_text(" ", strip=True) or "Unknown Component"

    # Try heading tags inside the block
    for heading in block.find_all(["h1", "h2", "h3", "h4", "h5", "strong"], limit=1):
        text = heading.get_text(" ", strip=True)
        if text:
            return text

    return "Unknown Component"


def _extract_threat_title(item) -> str:
    """
    Heuristically extract the threat title from a threat-item element.
    Priority: .threat-name .text-name  →  .threat-name  →  [data-name]  →  first heading.
    """
    # Primary: nested class path .threat-name > .text-name
    threat_name_el = item.find(class_="threat-name")
    if threat_name_el:
        text_name_el = threat_name_el.find(class_="text-name")
        if text_name_el:
            return text_name_el.get_text(" ", strip=True)
        return threat_name_el.get_text(" ", strip=True)

    # Fallback: data attribute
    if item.get("data-name"):
        return item["data-name"].strip()

    # Fallback: first heading inside the item
    for heading in item.find_all(["h3", "h4", "h5", "strong", "b"], limit=1):
        text = heading.get_text(" ", strip=True)
        if text:
            return text

    return ""

def _parse_xml_data_model(file_path: str, context: Optional[str]) -> List[ExtractedAttack]:
    attacks = []
    try:
        # Use iterparse for memory safety on ARM64 / large models
        context_iter = ET.iterparse(file_path, events=("end",))
        
        current_component = "Unknown Component"
        
        for event, elem in context_iter:
            tag = elem.tag.split('}')[-1].lower() if '}' in elem.tag else elem.tag.lower()
            
            # Keep track of component/trust zone context
            if tag in ["component", "trustzone"]:
                current_component = elem.attrib.get("name", "Unknown Component")
                
            elif tag == "threat":
                title = elem.attrib.get("name", "Unnamed Threat")
                desc = elem.attrib.get("desc", "No description provided.")
                
                # Check child countermeasures to determine state
                is_mitigated = False
                weaknesses = []
                
                for child in elem:
                    ctag = child.tag.split('}')[-1].lower() if '}' in child.tag else child.tag.lower()
                    if ctag == "countermeasure":
                        state = child.attrib.get("state", "").lower()
                        if state in ["passed", "implemented"]:
                            is_mitigated = True
                    elif ctag == "weakness":
                        w_name = child.attrib.get("name", "")
                        if w_name:
                            weaknesses.append(w_name)
                            
                if not is_mitigated:
                    w_str = ", ".join(weaknesses)
                    attacks.append(_build_attack(current_component, title, desc, w_str, context))
                
                elem.clear() # Memory safe cleanup
    except Exception as exc:
        logger.error(f"XML Parsing failed for IriusRisk: {exc}")
        
    return attacks

def _build_attack(component: str, title: str, desc: str, weakness: str, context: Optional[str]) -> ExtractedAttack:
    # Synthesize a clean raw_snippet
    snippet_lines = [
        f"[IriusRisk Threat: Unmitigated] Component: {component} | Threat: {title}"
    ]
    snippet_lines.append(f"Description: {desc}")
    if weakness:
        snippet_lines.append(f"Weakness: {weakness}")
    if context:
        snippet_lines.insert(0, f"Analyst Context: {context}")
        
    raw_snippet = " | ".join(snippet_lines)
    
    return ExtractedAttack(
        id=f"irius-{uuid.uuid4().hex[:10]}",
        title=title,
        description=f"Component: {component} | Weakness: {weakness or 'None'}",
        raw_snippet=raw_snippet,
        severity_estimate="High", # Can be extracted later if mapped
        input_type="xml",
        mitre_technique_id="",
        mitre_tactic="",
        confidence=0.85
    )

def analyze_iriusrisk_pipeline(
    snippet: str,
    context: Optional[str] = None,
    suggested_techniques: Optional[List[str]] = None,
    suggested_severity: Optional[str] = None
) -> ThreatResult:
    """
    Phase 2: The Isolated Handoff
    CRITICAL ISOLATION: Enforces structured-data bypass parameters to map directly to static heuristics.
    """
    if os.path.isfile(snippet):
        attacks = extract_iriusrisk_attacks_pipeline(snippet, context=context)
        text_payload = attacks[0].raw_snippet if attacks else snippet
    else:
        text_payload = snippet

    if context and not text_payload.startswith("Analyst Context:"):
        text_payload = f"Analyst Context: {context}\n\n{text_payload}"
        
    processed = process_input(text_payload, InputType.TEXT.value)
    
    # CRITICAL ISOLATION: Bypass NLP models, enforce deterministic heuristics
    res = analyze_text_pipeline(
        processed,
        pipeline_mode="legacy",
        apply_semantic_penalty=True,
        chunk_text=False,
        bypass_semantic=True, # Mathematically guarantees bypass of fuzzy NLP
        pruning_threshold=0.70
    )
    
    if suggested_techniques:
        if not res.raw_indicators:
            res.raw_indicators = {}
        if 'technique_ids' not in res.raw_indicators:
            res.raw_indicators['technique_ids'] = []
        for tech in suggested_techniques:
            if tech not in res.raw_indicators['technique_ids']:
                res.raw_indicators['technique_ids'].append(tech)

    if suggested_severity and res.risk_score:
        from models.schemas import SeverityLevel
        try:
            res.risk_score.severity = SeverityLevel(suggested_severity.capitalize())
        except ValueError:
            pass
            
    return res

def _parse_tabular_data(file_path: str, context: Optional[str], is_excel: bool) -> List[ExtractedAttack]:
    attacks = []
    try:
        import pandas as pd
        if is_excel:
            df = pd.read_excel(file_path)
        else:
            df = pd.read_csv(file_path)
            
        # Standardize column headers to lowercase
        df.columns = [str(c).strip().lower() for c in df.columns]
        
        for idx, row in df.iterrows():
            state = str(row.get("state", row.get("status", ""))).lower()
            if state in ["passed", "implemented", "mitigated"]:
                continue
                
            component = str(row.get("component", row.get("trust zone", "Unknown Component")))
            title = str(row.get("threat", row.get("name", row.get("title", "Unnamed Threat"))))
            desc = str(row.get("description", row.get("desc", "No description provided.")))
            weakness = str(row.get("weakness", row.get("cwe", "")))
            
            if title != "Unnamed Threat" and title != "nan":
                attacks.append(_build_attack(component, title, desc, weakness, context))
                
    except Exception as exc:
        logger.error(f"Tabular parsing failed for IriusRisk: {exc}")
    return attacks

def _parse_pdf_report(file_path: str, context: Optional[str]) -> List[ExtractedAttack]:
    attacks = []
    try:
        import pdfplumber
        with pdfplumber.open(file_path) as pdf:
            for page in pdf.pages:
                tables = page.extract_tables()
                for table in tables:
                    if not table or len(table) < 2:
                        continue
                        
                    headers = [str(h).strip().lower() if h else "" for h in table[0]]
                    
                    if not any(k in headers for k in ["threat", "weakness", "countermeasure", "risk", "name"]):
                        continue
                        
                    for row in table[1:]:
                        if len(row) != len(headers):
                            continue
                            
                        row_data = {headers[i]: str(row[i]).strip() if row[i] else "" for i in range(len(headers))}
                        
                        state = row_data.get("state", row_data.get("status", "")).lower()
                        if state in ["passed", "implemented", "mitigated"]:
                            continue
                            
                        component = row_data.get("component", row_data.get("trust zone", "Unknown Component"))
                        title = row_data.get("threat", row_data.get("name", "Unnamed Threat"))
                        desc = row_data.get("description", row_data.get("desc", "No description provided."))
                        weakness = row_data.get("weakness", row_data.get("cwe", ""))
                        
                        if title and title != "Unnamed Threat":
                            attacks.append(_build_attack(component, title, desc, weakness, context))
                            
    except Exception as exc:
        logger.error(f"PDF parsing failed for IriusRisk: {exc}")
    return attacks
