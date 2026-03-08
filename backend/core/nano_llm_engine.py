import os
import json
import logging
from typing import List, Dict, Any, Optional
from llama_cpp import Llama

log = logging.getLogger("nano_llm")

# Paths for the GGUF model
MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "Phi-3.5-mini-instruct-Q4_K_M.gguf")

class NanoLLMEngine:
    """
    Stage 2 Industrial-Grade Reasoning Engine.
    Uses quantized Phi-3.5-mini (3.8B) via llama-cpp-python for high-performance 
    Metal-accelerated inference on 8GB M1 hardware.
    """
    def __init__(self):
        self.llm = None
        self.is_loaded = False
        log.info("NanoLLMEngine (Phi-3.5) initialized. Metal acceleration (MPS) enabled via llama-cpp.")

    def load(self):
        if self.is_loaded:
            return True

        if not os.path.exists(MODEL_PATH):
            log.warning(f"Phi-3.5-mini GGUF not found at {MODEL_PATH}. Download required.")
            return False

        try:
            log.info(f"Loading Phi-3.5-mini from {MODEL_PATH} (n_gpu_layers=-1 for Metal)...")
            # Load with n_gpu_layers=-1 to use Apple Silicon GPU (Metal)
            self.llm = Llama(
                model_path=MODEL_PATH,
                n_gpu_layers=-1, # Force Metal
                n_ctx=4096,      # Sufficient for CTI analysis
                verbose=False
            )
            self.is_loaded = True
            log.info("Phi-3.5-mini successfully loaded into M1 GPU memory.")
            return True
        except Exception as e:
            log.error(f"Failed to load Phi-3.5-mini: {e}")
            self.is_loaded = False
            return False

    def extract_and_analyze(self, raw_text: str, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Industrial-grade reasoning:
        1. Analyzes raw text for hidden cybersecurity terms.
        2. Correlates findings with SecBERT's TTP detections.
        3. Generates a deep technical narrative and executive summary.
        """
        if not self.is_loaded and not self.load():
            return self._fallback_narrative(techniques)

        # Build context from SecBERT techniques
        tech_context = ", ".join([f"{t.get('id', '')} ({t.get('name', '')})" for t in techniques])
        
        prompt = (
            f"<|system|>\nYou are an industrial-grade Cyber Threat Intelligence (CTI) Assistant. "
            f"You MUST output ONLY valid JSON. No conversational text. No markdown blocks.\n"
            f"<|user|>\nAnalyze this threat data and output a JSON object with PRECISELY these 4 keys:\n"
            f"1. 'title': Short professional title.\n"
            f"2. 'summary': 2-sentence executive summary.\n"
            f"3. 'analysis': Deep technical dive (300+ words) into the methods, potential impact, and attribution.\n"
            f"4. 'extracted_terms': List of all technical terms, IPs, hostnames, or specific tools mentioned.\n\n"
            f"REPORT:\n{raw_text}\n\n"
            f"CONTEXT (Techniques): {tech_context}\n\n"
            f"JSON OUTPUT:\n"
            f"<|assistant|>\n"
            f"{{"
        )

        try:
            # Generate response
            output = self.llm(
                prompt,
                max_tokens=512,
                stop=["<|end|>", "--- REPORT START ---"],
                temperature=0.1, # Lower for higher precision
                repeat_penalty=1.1
            )
            
            response_text = output['choices'][0]['text'].strip()
            
            # 1. Aggressive JSON Extraction
            # Look for JSON between code blocks if they exist
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()

            # 2. Find outermost curly braces
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_part = response_text[start_idx:end_idx]
                try:
                    parsed = json.loads(json_part)
                    # Standardize keys to match frontend expectations
                    return {
                        "title": parsed.get("title", "AI Analysis Report"),
                        "summary": parsed.get("summary", "Technical threat detected."),
                        "analysis": parsed.get("analysis", "Deep reasoning continues."),
                        "terms": parsed.get("extracted_terms", parsed.get("terms", [])),
                        "ttps": parsed.get("ttps", techniques) # Pass-through techniques
                    }
                except json.JSONDecodeError as jde:
                    log.warning(f"Partial JSON detected but failed to parse: {jde}")
            
            # Catch-all for non-JSON or broken JSON
            return {
                "title": "Industrial Threat Insight",
                "summary": response_text[:200].replace('\n', ' '),
                "analysis": response_text,
                "terms": [],
                "ttps": techniques
            }

        except Exception as e:
            log.error(f"Error during Phi-3.5 inference: {e}")
            return self._fallback_narrative(techniques)

    def _fallback_narrative(self, techniques: json) -> dict:
        tech_names = [t.get('name', '') for t in techniques]
        nar = f"Identified activity: {' and '.join(tech_names[:3])}."
        return {
            "title": "Threat Detection Summary",
            "summary": nar,
            "analysis": "LLM secondary analysis currently unavailable.",
            "extracted_terms": []
        }

# Singleton instance
nano_llm = NanoLLMEngine()
