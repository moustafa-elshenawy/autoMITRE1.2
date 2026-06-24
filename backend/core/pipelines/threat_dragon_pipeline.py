import uuid
import logging
import os
import json
from typing import List, Optional

from models.schemas import ExtractedAttack, ThreatResult, InputType
from core.input_processor import process_input
from core.pipelines.text_pipeline import analyze_text_pipeline

logger = logging.getLogger(__name__)

def extract_threat_dragon_attacks_pipeline(
    file_path: str,
    context: Optional[str] = None
) -> List[ExtractedAttack]:
    """
    Phase 1: High-Fidelity OWASP Threat Dragon Extraction
    Parses the Threat Dragon JSON export to extract threats programmatically.
    """
    attacks: List[ExtractedAttack] = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        threats_found = []
        def extract_threats(node, component_context="Unknown Component"):
            if isinstance(node, dict):
                # Threat Dragon V2 typically has title/name on elements
                current_component = node.get("name", node.get("title", component_context))
                
                if "threats" in node and isinstance(node["threats"], list):
                    for t in node["threats"]:
                        t["_component"] = current_component
                        threats_found.append(t)
                        
                for v in node.values():
                    extract_threats(v, current_component)
            elif isinstance(node, list):
                for item in node:
                    extract_threats(item, component_context)
        
        extract_threats(data)
        
        for t in threats_found:
            status = t.get("status", "").lower()
            if status in ["mitigated", "resolved", "not applicable"]:
                continue
                
            title = t.get("title", "Unnamed Threat")
            desc = t.get("description", "No description provided.")
            sev = t.get("severity", "Medium")
            component = t.get("_component", "Unknown Component")
            
            # Synthesize snippet
            snippet_lines = [
                f"[Threat Dragon Threat: Unmitigated] Component: {component} | Threat: {title}"
            ]
            snippet_lines.append(f"Description: {desc}")
            if context:
                snippet_lines.insert(0, f"Analyst Context: {context}")
                
            raw_snippet = " | ".join(snippet_lines)
            
            attacks.append(ExtractedAttack(
                id=f"tdragon-{uuid.uuid4().hex[:10]}",
                title=title,
                description=f"Component: {component} | Status: {status or 'Open'}",
                raw_snippet=raw_snippet,
                severity_estimate=sev.capitalize() if sev else "Medium",
                input_type="threat_dragon",
                mitre_technique_id="",
                mitre_tactic="",
                confidence=0.85
            ))
            
    except Exception as exc:
        logger.error(f"Failed to parse Threat Dragon JSON: {exc}")
        
    return attacks

def analyze_threat_dragon_pipeline(
    snippet: str,
    context: Optional[str] = None,
    suggested_techniques: Optional[List[str]] = None,
    suggested_severity: Optional[str] = None
) -> ThreatResult:
    """
    Phase 2: Semantic Analysis of Threat Dragon Threats
    Passes the textual prose of the Threat Dragon threat into the semantic deep learning pipeline.
    """
    if os.path.isfile(snippet):
        attacks = extract_threat_dragon_attacks_pipeline(snippet, context=context)
        text_payload = attacks[0].raw_snippet if attacks else snippet
    else:
        text_payload = snippet

    if context and not text_payload.startswith("Analyst Context:"):
        text_payload = f"Analyst Context: {context}\n\n{text_payload}"
        
    processed = process_input(text_payload, InputType.TEXT.value)
    
    # We enforce NLP bypass for Threat Dragon since we synthesized the snippet block
    res = analyze_text_pipeline(
        processed,
        pipeline_mode="legacy",
        apply_semantic_penalty=True,
        chunk_text=False,
        bypass_semantic=True, # Maps against the deterministic heuristics
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
