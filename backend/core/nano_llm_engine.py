import os
import json
import logging
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

log = logging.getLogger("nano_llm")

# Set up MPS for M1
DEVICE = "mps" if torch.backends.mps.is_available() else "cpu"
MODEL_ID = "HuggingFaceTB/SmolLM2-135M-Instruct"

class NanoLLMEngine:
    def __init__(self):
        self.tokenizer = None
        self.model = None
        self.is_loaded = False
        log.info(f"NanoLLMEngine initialized on {DEVICE}. Waiting for load...")
        
    def load(self):
        if self.is_loaded:
            return
            
        try:
            log.info(f"Loading {MODEL_ID} into {DEVICE} memory...")
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
            self.model = AutoModelForCausalLM.from_pretrained(MODEL_ID).to(DEVICE)
            self.is_loaded = True
            log.info("Nano LLM Stage 2 successfully loaded!")
        except Exception as e:
            log.error(f"Failed to load Nano LLM: {e}")
            self.is_loaded = False

    def generate_narrative(self, raw_text: str, techniques: list) -> dict:
        """
        Takes the raw text and the techniques found by SecBERT (Stage 1)
        and writes a cohesive threat narrative and title using SmolLM2.
        """
        if not self.is_loaded:
            self.load()
            if not self.is_loaded:
                return self._fallback_narrative(techniques)

        # Build context from techniques
        tech_context = ", ".join([f"{t.get('id', '')} ({t.get('name', '')})" for t in techniques])
        
        system_prompt = "You are an expert Cyber Threat Intelligence Analyst. Your summaries must be strictly factual and based ONLY on the provided text. Do not invent details or assume the attacker's intent."
        
        user_prompt = (
            f"Analyze this threat report:\n'{raw_text}'\n\n"
            f"The following ATT&CK techniques have been applied to this text: {tech_context}\n\n"
            "Write a clear, 3-sentence executive summary explaining what happened in the text based on these techniques. Do not provide a general definition of the techniques."
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            # Add generation prompt so it knows to start answering
            input_text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            inputs = self.tokenizer(input_text, return_tensors="pt").to(DEVICE)
            
            # Generate output
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=150,
                do_sample=True,
                temperature=0.4,
                pad_token_id=self.tokenizer.eos_token_id,
                eos_token_id=self.tokenizer.eos_token_id
            )
            
            # Decode only the newly generated tokens
            input_length = inputs["input_ids"].shape[1]
            generated_tokens = outputs[0][input_length:]
            response_text = self.tokenizer.decode(generated_tokens, skip_special_tokens=True).strip()
            
            # Clean up potential chat artifacts
            if response_text.startswith("assistant\n"):
                response_text = response_text[10:].strip()

            return {
                "title": "Threat Activity Detected",
                "narrative": response_text
            }

        except Exception as e:
            log.error(f"Error generating narrative with Nano LLM: {e}")
            return self._fallback_narrative(techniques)

    def _fallback_narrative(self, techniques: list) -> dict:
        tech_names = [t.get('name', '') for t in techniques]
        if tech_names:
            nar = f"The automated analysis identified activity indicative of {' and '.join(tech_names[:3])}."
        else:
            nar = "The automated analysis identified anomalous activity requiring further investigation."
            
        return {
            "title": "Threat Activity Detected",
            "narrative": nar
        }

nano_llm = NanoLLMEngine()
