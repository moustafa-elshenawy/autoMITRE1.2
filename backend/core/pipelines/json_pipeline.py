import json
import uuid
from typing import List, Optional, Any
from models.schemas import ExtractedAttack, ThreatResult, InputType
from core.input_processor import process_input
from core.pipelines.text_pipeline import analyze_text_pipeline
from core.nano_llm_engine import nano_llm

def flatten_json_values(data: Any) -> list:
    """
    Recursively traverse a JSON object (dict/list) and extract only the string/number values.
    Discards keys, arrays, objects, and brackets to clean out structural noise.
    """
    values = []
    if isinstance(data, dict):
        for v in data.values():
            values.extend(flatten_json_values(v))
    elif isinstance(data, list):
        for item in data:
            values.extend(flatten_json_values(item))
    elif isinstance(data, str):
        val = data.strip()
        if val:
            values.append(val)
    elif isinstance(data, (int, float, bool)) and data is not None:
        values.append(str(data))
    
    return values

def extract_json_attacks_pipeline(file_path: str, context: Optional[str] = None) -> List[ExtractedAttack]:
    """
    Parse a JSON file, flatten its structure, and extract discrete attacks.
    """
    print("!!! JSON PIPELINE HIT - EXTRACT: ", file_path, " !!!")
    with open(file_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON file format: {e}")
            
    # Flatten JSON to clean string of values
    flat_values = flatten_json_values(data)
    flattened_text = " ".join(flat_values)
    
    # Truncate if massive (prevent token overflow)
    if len(flattened_text) > 100000:
        flattened_text = flattened_text[:100000]
    
    # Prepend context if given
    if context:
        flattened_text = f"Context: {context}\n\n{flattened_text}"
        
    # Bypass the LLM UI splitter entirely for JSON files to stop mutation/truncation
    # Send the entire flattened file directly as a single comprehensive block
    attack = ExtractedAttack(
        id=f"json-{uuid.uuid4()}",
        title="Structured JSON Payload",
        description="Comprehensive Flattened JSON Block",
        raw_snippet=flattened_text,
        severity_estimate="Unknown",
        input_type="json"
    )
    
    return [attack]

def analyze_json_pipeline(text_content: str, context: Optional[str] = None) -> ThreatResult:
    """
    Run full threat analysis on flattened JSON text snippet with strict NLP isolation.
    """
    print("!!! JSON PIPELINE HIT - ANALYZE !!!")
    # 1. Parse and flatten the JSON payload if it is valid JSON
    try:
        data = json.loads(text_content)
        flat_values = flatten_json_values(data)
        text_content = " ".join(flat_values)
    except json.JSONDecodeError:
        # If it's already a flattened string or invalid JSON, proceed with the raw text
        pass

    if context:
        text_content = context + "\n" + text_content
        
    # It's treated as TEXT type structurally, but we bypass the NLP parser.
    processed = process_input(text_content, InputType.TEXT.value)
    
    # Use explicit isolation parameters for structured data
    return analyze_text_pipeline(
        processed, 
        pipeline_mode="legacy",
        apply_semantic_penalty=True, 
        chunk_text=False, 
        bypass_semantic=True, 
        pruning_threshold=0.70
    )
