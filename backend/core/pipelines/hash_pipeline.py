from typing import Dict, Any
from models.schemas import ThreatResult, InputType
from core.virustotal_client import lookup_hash
from core.input_processor import process_input
from core.pipelines.text_pipeline import analyze_text_pipeline

def analyze_hash_pipeline(hash_value: str) -> ThreatResult:
    """
    Performs malware hash reputation check via VirusTotal and structures the results.
    """
    # 1. Lookup hash on VirusTotal
    vt_result = lookup_hash(hash_value)
    if not vt_result.get("found"):
        raise ValueError(vt_result.get("message", "Hash not found in VirusTotal."))

    # 2. Build descriptive text from detection results
    verdict = vt_result.get('verdict', 'unknown')
    ratio = vt_result.get('detection_ratio', '0/0')
    description = f"Malware hash analysis: {hash_value}. Detection ratio: {ratio}. Verdict: {verdict}."

    if vt_result.get('names'):
        description += f" Known names: {', '.join(vt_result['names'][:3])}."

    # 3. Create normalized input representation
    processed = process_input(hash_value, InputType.HASH.value)
    processed['normalized_text'] = description
    
    # Pre-populate techniques suggested by VT signatures
    if vt_result.get('suggested_techniques'):
        processed['suggested_techniques'] = list(
            set(processed.get('suggested_techniques', []) + vt_result['suggested_techniques'])
        )

    # 4. Analyze threat using text pipeline (for framework enrichment)
    threat = analyze_text_pipeline(processed, apply_semantic_penalty=True, chunk_text=False, bypass_semantic=True, pruning_threshold=0.70)
    
    # 5. Hydrate final raw indicators with VirusTotal payload
    threat.raw_indicators['virustotal'] = vt_result
    
    return threat
