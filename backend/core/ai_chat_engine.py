"""
AI Chat Engine
Provides conversational AI for risk assessment and threat queries.
"""
from typing import List, Dict, Any
from models.schemas import ChatMessage

SYSTEM_KNOWLEDGE = {
    "ransomware": {
        "keywords": ["ransomware", "encrypt", "ransom"],
        "response": """**Ransomware Threat Assessment**

Ransomware represents one of the most severe threats to organizational continuity. Based on my analysis:

🔴 **Risk Level: CRITICAL**

**MITRE ATT&CK Mapping:**
- T1486 — Data Encrypted for Impact (Tactic: Impact)
- T1489 — Service Stop
- T1021 — Remote Services (Lateral Movement)
- T1566 — Phishing (Initial Access vector)

**Immediate Actions Required:**
1. **Isolate** affected systems from network immediately
2. **Preserve** forensic evidence before remediation
3. **Activate** incident response plan (IRP)
4. **Notify** legal, executive team, and cyber insurance

**Countermeasures (MITRE D3FEND):**
- D3-BA: Immutable offline backups (3-2-1 strategy)
- D3-EM: EDR with behavioral detection
- D3-NM: Network segmentation to limit propagation

**NIST SP 800-53 Controls:**
- IR-4: Incident Handling
- SC-28: Protection of Information at Rest
- CP-9: System Backup"""
    },
    "sql injection": {
        "keywords": ["sql", "injection", "sqli", "database"],
        "response": """**SQL Injection Threat Assessment**

SQL Injection remains one of the most exploited vulnerabilities (OWASP A03:2021).

🟠 **Risk Level: HIGH**

**MITRE ATT&CK Mapping:**
- T1190 — Exploit Public-Facing Application (Initial Access)
- T1190.001 — SQL Injection sub-technique

**Remediation Priority:** Immediate

**Countermeasures:**
- Implement parameterized queries / prepared statements
- Deploy WAF with SQLi rule sets (e.g., ModSecurity)
- Apply principle of least privilege to DB accounts
- Enable database activity monitoring (DAM)

**NIST Controls:** AC-3 (Access Enforcement), RA-5 (Vulnerability Scanning)
**OWASP ASVS:** V5 (Input Validation Requirements)"""
    },
    "phishing": {
        "keywords": ["phishing", "spear phishing", "email attack"],
        "response": """**Phishing Threat Assessment**

Phishing remains the #1 initial access vector in 80%+ of breaches.

🟠 **Risk Level: HIGH**

**MITRE ATT&CK Mapping:**
- T1566 — Phishing (Initial Access)
- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link

**Defensive Measures:**
- Deploy anti-phishing SEG with DMARC/DKIM/SPF enforcement
- Implement URL rewriting and real-time link analysis
- Enable MFA to mitigate credential theft impact
- Conduct quarterly phishing simulation training

**NIST Controls:** AT-2 (Security Awareness Training), SC-20 (Secure Name/Address Resolution)"""
    },
    "ddos": {
        "keywords": ["ddos", "dos", "denial of service", "flood"],
        "response": """**DDoS/DoS Threat Assessment**

Denial of Service attacks can cause significant service disruption.

🟡 **Risk Level: MEDIUM-HIGH**

**MITRE ATT&CK Mapping:**
- T1498 — Network Denial of Service (Impact)
- T1499 — Endpoint Denial of Service

**Defense Strategy:**
- Deploy CDN with DDoS protection (e.g., Cloudflare, AWS Shield)
- Implement rate limiting and traffic scrubbing
- Configure BGP blackholing for volumetric attacks
- Establish upstream ISP mitigation agreement

**NIST Controls:** SC-5 (Denial-of-Service Protection), IR-4 (Incident Handling)"""
    },
    "default": {
        "response": """**AutoMITRE AI Risk Assessment**

I'm your AI-powered cybersecurity threat analyst. I can help you with:

🔍 **Threat Analysis** — Describe a threat or paste an IoC and I'll analyze it
🗺️ **Framework Mapping** — Map threats to MITRE ATT&CK, D3FEND, NIST, OWASP
📊 **Risk Scoring** — Generate risk severity and business impact analysis
🛡️ **Mitigation Guidance** — Get prioritized remediation recommendations
📤 **SIEM Export** — Generate STIX 2.1 or Splunk-ready threat intelligence

**Try asking me:**
- "Analyze a ransomware threat"
- "What controls apply to brute force attacks?"
- "How do I defend against SQL injection?"
- "What is the risk score for a phishing attack?"

I'm continuously learning from MITRE ATT&CK v14, NIST SP 800-53 Rev 5, and OWASP Top 10 2023."""
    }
}

SUGGESTIONS_MAP = {
    "ransomware": ["Generate STIX export", "Show D3FEND countermeasures", "Create incident response plan"],
    "phishing": ["Analyze email headers", "Show NIST AT-2 controls", "Simulate phishing campaign"],
    "sql injection": ["Run OWASP ASVS checklist", "Export to Splunk", "View WAF rules"],
    "ddos": ["Show SC-5 NIST controls", "Configure rate limiting", "Generate alert rule"],
    "default": ["Analyze a threat", "Export to STIX", "View risk heatmap", "Generate report"]
}


def generate_chat_response(message: str, history: List[ChatMessage], threat_context: str = None) -> Dict[str, Any]:
    """Generate contextual AI chat response."""
    msg_lower = message.lower()
    
    # Match against knowledge base
    best_match = None
    for key, knowledge in SYSTEM_KNOWLEDGE.items():
        if key == "default":
            continue
        if any(kw in msg_lower for kw in knowledge.get("keywords", [])):
            best_match = key
            break
    
    # Check history for context
    if not best_match and history:
        for prev_msg in reversed(history[-4:]):
            prev_lower = prev_msg.content.lower()
            for key, knowledge in SYSTEM_KNOWLEDGE.items():
                if key == "default":
                    continue
                if any(kw in prev_lower for kw in knowledge.get("keywords", [])):
                    best_match = key
                    break
            if best_match:
                break
    
    # Handle specific queries
    if any(word in msg_lower for word in ['hello', 'hi', 'hey', 'help']):
        response = SYSTEM_KNOWLEDGE['default']['response']
        suggestions = SUGGESTIONS_MAP['default']
    elif best_match:
        response = SYSTEM_KNOWLEDGE[best_match]['response']
        suggestions = SUGGESTIONS_MAP.get(best_match, SUGGESTIONS_MAP['default'])
    elif any(word in msg_lower for word in ['mitre', 'attack', 'technique', 'tactic']):
        response = """**MITRE ATT&CK Framework Overview**

The MITRE ATT&CK framework contains 14 Tactics and 600+ Techniques:

| Tactic | ID | Purpose |
|---|---|---|
| Initial Access | TA0001 | Entry points into your network |
| Execution | TA0002 | Running malicious code |
| Persistence | TA0003 | Maintaining access |
| Privilege Escalation | TA0004 | Gaining higher permissions |
| Defense Evasion | TA0005 | Avoiding detection |
| Credential Access | TA0006 | Stealing credentials |
| Discovery | TA0007 | Exploring the environment |
| Lateral Movement | TA0008 | Moving through the network |
| Collection | TA0009 | Gathering target data |
| Command & Control | TA0011 | Communicating with compromised systems |
| Exfiltration | TA0010 | Stealing data |
| Impact | TA0040 | Disrupting/destroying systems |

Use the **Framework Coverage** page to visualize your coverage across all tactics."""
        suggestions = ["View ATT&CK matrix", "Analyze a specific tactic", "Map to D3FEND"]
    elif any(word in msg_lower for word in ['nist', 'control', '800-53']):
        response = """**NIST SP 800-53 Rev 5 Controls**

NIST SP 800-53 provides a comprehensive catalog of security controls organized into 20 control families:

🔐 **Key Control Families:**
- **AC** — Access Control (23 controls)
- **AU** — Audit and Accountability (16 controls)
- **CM** — Configuration Management (14 controls)
- **IA** — Identification and Authentication (13 controls)
- **IR** — Incident Response (10 controls)
- **RA** — Risk Assessment (10 controls)
- **SC** — System and Communications Protection (51 controls)
- **SI** — System and Information Integrity (23 controls)

autoMITRE automatically maps detected threats to the relevant NIST controls. View the Framework Coverage page for your organization's control coverage."""
        suggestions = ["Show high priority controls", "Export NIST mapping", "View coverage gaps"]
    elif threat_context:
        response = f"""**Analysis of Your Threat Context**

Based on the threat intelligence you've provided, I've identified the following:

The threat appears to involve **{threat_context[:100]}**

**Recommended Immediate Actions:**
1. Verify the threat is active in your environment
2. Check your SIEM for related indicators
3. Review framework mappings in the Analysis tab
4. Generate a STIX export for your threat sharing platform

Would you like me to dive deeper into any specific aspect of this threat?"""
        suggestions = ["Generate STIX export", "Show mitigations", "Calculate risk score"]
    else:
        response = f"""**Threat Query Analysis**

I analyzed your query: *"{message[:100]}"*

Based on available threat intelligence, this appears to relate to **cybersecurity threat activity**.

**To provide a more specific analysis:**
- Use the **Threat Analysis** page to analyze specific files, text, or hashes
- Describe the threat in more detail (what systems are affected, what indicators you observed)
- Specify if this is for detection, response, or compliance mapping

**General Security Recommendations:**
- Ensure comprehensive logging is enabled on all critical systems
- Review your SIEM alerts for related indicators
- Check MITRE ATT&CK for technique-specific guidance

I'm here to help! Ask me about specific threats, frameworks, or controls."""
        suggestions = ["Analyze a threat", "View MITRE ATT&CK", "Show NIST controls"]
    
    return {
        "response": response,
        "suggestions": suggestions
    }
