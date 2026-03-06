import os
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class LocalHuggingFaceEngine:
    def __init__(self):
        try:
            from transformers import pipeline
            import torch
            # Using a very small, fast instruction-tuned model for local narrative generation
            self.model_name = "HuggingFaceTB/SmolLM2-135M-Instruct"
            # Try MPS (Mac Silicon), else CPU
            device = "mps" if torch.backends.mps.is_available() else "cpu"
            self.generator = pipeline(
                "text-generation", 
                model=self.model_name, 
                device=device,
                torch_dtype=torch.float16 if device == "mps" else torch.float32
            )
            self._is_healthy = True
            logger.info(f"Loaded local LLM: {self.model_name} on {device}")
        except Exception as e:
            logger.error(f"Failed to initialize local HuggingFace pipeline: {e}")
            self.generator = None
            self._is_healthy = False

    def is_healthy(self) -> bool:
        """Check if pipeline was initialized successfully."""
        return self._is_healthy

    def generate_threat_analysis(self, raw_text: str, context_techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Uses a local LLM to generate a dynamic prediction narrative.
        Since small models struggle with strict JSON schemas, we just ask for the narrative
        and manually wrap it in the expected JSON payload so the analyzer doesn't crash.
        """
        if not self.is_healthy():
            return {}

        tech_names = ", ".join([t['name'] for t in context_techniques[:3]])
        
        # System prompt tailored for small instruction models
        prompt = f"""<|im_start|>system
You are a cybersecurity expert. Write a strict 2-sentence prediction of what the attacker will do next based on the threat report. Do not suggest mitigations. Be concise.<|im_end|>
<|im_start|>user
Threat Report: {raw_text}
Detected Techniques: {tech_names}<|im_end|>
<|im_start|>assistant
"""
        try:
            response = self.generator(
                prompt,
                max_new_tokens=100,
                temperature=0.3,
                do_sample=True,
                return_full_text=False
            )
            
            narrative = response[0]['generated_text'].strip()
            
            # If the model rambles, cut it at the first double newline
            if "\n\n" in narrative:
                narrative = narrative.split("\n\n")[0]
                
            # If it's too long, truncate it
            if len(narrative) > 300:
                narrative = narrative[:297] + "..."
                
            # Format the output to match what ai_threat_analyzer expects
            return {
                "prediction_narrative": narrative,
                # The small model isn't good at picking techniques/mitigations reliably,
                # so we let the highly accurate TRAM ML classifier handle techniques
                # and let the curated heuristics handle mitigations.
                "detected_techniques": None,
                "mitigations": None
            }
            
        except Exception as e:
            logger.error(f"LLM Generation Failed (Local HF): {e}")
            return {}
