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
    attacks = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            soup = BeautifulSoup(f.read(), "html.parser")
            
        # IriusRisk HTML reports typically contain tables for threats.
        # This is a heuristic parser tailored to standard IriusRisk Technical Threat Reports.
        tables = soup.find_all("table")
        for table in tables:
            headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]
            
            # Identify if it's a threat table
            if not any(k in headers for k in ["threat", "weakness", "countermeasure", "risk"]):
                continue
                
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) != len(headers) or not cells:
                    continue
                    
                row_data = {headers[i]: cells[i].get_text(strip=True) for i in range(len(cells))}
                
                # Check for mitigated state in countermeasures
                state = row_data.get("state", "").lower()
                if state in ["passed", "implemented", "mitigated"]:
                    continue
                    
                component = row_data.get("component", row_data.get("trust zone", "Unknown Component"))
                title = row_data.get("threat", row_data.get("name", "Unnamed Threat"))
                desc = row_data.get("description", "No description provided.")
                weakness = row_data.get("weakness", row_data.get("cwe", ""))
                
                attacks.append(_build_attack(component, title, desc, weakness, context))
    except Exception as exc:
        logger.error(f"HTML Parsing failed for IriusRisk: {exc}")
        
    return attacks

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
