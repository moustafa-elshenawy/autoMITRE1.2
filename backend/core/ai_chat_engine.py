import os
import logging
import httpx
from typing import List, Dict, Any, Optional
from models.schemas import ChatMessage

log = logging.getLogger("ai_chat")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = "llama-3.3-70b-versatile" # Use the larger 70B model for chat as it's smarter

def generate_chat_response(message: str, history: List[ChatMessage], threat_context: str = None) -> Dict[str, Any]:
    """
    Generate a dynamic, context-aware AI chat response using Llama 3 70B (Cloud).
    Falls back to a helpful message if the cloud is unavailable.
    """
    if not GROQ_API_KEY:
        return {
            "response": "Cloud AI is currently disabled (missing GROQ_API_KEY). Please configure your environment to enable Llama 3 chat capabilities.",
            "suggestions": ["How to set up Groq?", "Analyze a threat", "View help"]
        }

    # Prepare conversation history
    messages = [
        {
            "role": "system",
            "content": (
                "You are AutoMITRE AI, a professional Cybersecurity Threat Analyst. "
                "You help users analyze threats, map to MITRE ATT&CK, NIST, and D3FEND, and generate mitigations. "
                "Keep responses professional, detailed, and formatted in Markdown with clear headers and bullet points."
            )
        }
    ]

    # Add threat context if available
    if threat_context:
        messages.append({
            "role": "system", 
            "content": f"CURRENT THREAT CONTEXT: The user is currently analyzing this threat: {threat_context}"
        })

    # Add history (limit to last 10 messages for context window management)
    for h in history[-10:]:
         role = "user" if h.role == "user" else "assistant"
         messages.append({"role": role, "content": h.content})

    # Add current message
    messages.append({"role": "user", "content": message})

    try:
        with httpx.Client(timeout=45.0) as client:
            response = client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
                json={
                    "model": GROQ_MODEL,
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 1024
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                ai_text = data['choices'][0]['message']['content']
                
                # Dynamic suggestion generation
                suggestions = _generate_dynamic_suggestions(ai_text)
                
                return {
                    "response": ai_text,
                    "suggestions": suggestions
                }
            else:
                log.error(f"Chat API Error: {response.status_code} - {response.text}")
                return {
                    "response": "I encountered an issue connecting to the Llama 3 Cloud. Please try again in a moment.",
                    "suggestions": ["Retry", "Analyze a threat"]
                }

    except Exception as e:
        log.error(f"Chat request failed: {e}")
        return {
            "response": "My reasoning engine is currently experiencing connectivity issues. I'm standing by to assist once connection is restored.",
            "suggestions": ["Check status", "View local documentation"]
        }

def _generate_dynamic_suggestions(ai_text: str) -> List[str]:
    """Basic extraction of potential follow-up questions from AI response."""
    suggestions = ["Analyze another threat", "Export to STIX", "View MITRE Matrix"]
    
    # Try to find common cybersecurity keywords to tailor suggestions
    text = ai_text.lower()
    if "ransomware" in text:
        suggestions.insert(0, "Create Ransomware IR Plan")
    if "nist" in text or "control" in text:
        suggestions.insert(0, "Show NIST 800-53 Mapping")
    if "detection" in text or "sigma" in text:
        suggestions.insert(0, "Generate Sigma Rules")
        
    return suggestions[:4]
