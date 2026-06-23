import uuid
import os
from typing import Dict, Any, List, Optional
from models.schemas import ThreatResult, ExtractedAttack, InputType
from core.pcap_parser import parse_pcap_bytes
from core.pcap_extractor import analyze_pcap
from core.input_processor import process_input
from core.pipelines.text_pipeline import analyze_text_pipeline

def analyze_pcap_pipeline(file_path: str, context: Optional[str] = None) -> ThreatResult:
    """
    Parses PCAP into text logs (via Hybrid NIDS ML/Heuristic triage) and runs 
    the core threat analysis engine.
    """
    # 1. Parse PCAP bytes to text representation
    text_content = parse_pcap_bytes(file_path)
    
    # 2. Add contextual metadata if provided
    if context:
        text_content = context + "\n" + text_content
        
    # 3. Process the normalized text representation
    processed = process_input(text_content, InputType.TEXT.value)
    
    # 4. Delegate to text pipeline to perform the ATT&CK/framework mapping
    # Since they share the AI Model Singletons, this is OOM-safe and fast.
    return analyze_text_pipeline(processed, apply_semantic_penalty=True, chunk_text=False, bypass_semantic=True, pruning_threshold=0.70)

def extract_pcap_attacks_pipeline(file_path: str, context: Optional[str] = None) -> List[ExtractedAttack]:
    """
    Directly extracts distinct attacks and alerts from the raw PCAP file.
    """
    pcap_report = analyze_pcap(file_path)
    if 'error' in pcap_report:
        raise ValueError(pcap_report['error'])
        
    validated_attacks = []
    for idx, att in enumerate(pcap_report.get('attacks', []), 1):
        snippet = f"Attack Type: {att['type']}\nMetrics: {att['metrics']}\nDetails: {att['verdict']}"
        if context:
            snippet = f"Context: {context}\n\n{snippet}"

        validated_attacks.append(
            ExtractedAttack(
                id=f"pcap-{idx}",
                title=att['type'],
                description=att['verdict'],
                raw_snippet=snippet,
                severity_estimate=att['severity'],
                mitre_technique_id=att.get('mitre_technique_id'),
                mitre_tactic=att.get('mitre_tactic'),
                confidence=att.get('confidence'),
                payload_snippets=att.get('payload_snippets', [])
            )
        )
        
    return validated_attacks
