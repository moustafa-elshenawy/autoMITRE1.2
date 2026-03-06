import json
import urllib.request
import ssl
import sys
import logging

logging.basicConfig(level=logging.INFO)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def fetch_json(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, context=ctx) as response:
        return json.loads(response.read().decode())

def process_attack():
    logging.info("Fetching MITRE ATT&CK Enterprise...")
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    data = fetch_json(url)
    
    techniques = []
    
    tactic_map = {
        "initial-access": "TA0001", "execution": "TA0002", "persistence": "TA0003",
        "privilege-escalation": "TA0004", "defense-evasion": "TA0005", "credential-access": "TA0006",
        "discovery": "TA0007", "lateral-movement": "TA0008", "collection": "TA0009",
        "exfiltration": "TA0010", "command-and-control": "TA0011", "impact": "TA0040"
    }

    for obj in data.get('objects', []):
        if obj.get('type') == 'attack-pattern':
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue
                
            ext_refs = obj.get('external_references', [])
            attack_id = next((ref['external_id'] for ref in ext_refs if ref.get('source_name') == 'mitre-attack'), None)
            
            if not attack_id:
                continue
                
            tactics = []
            for kp in obj.get('kill_chain_phases', []):
                if kp.get('kill_chain_name') == 'mitre-attack':
                    tactics.append(kp.get('phase_name'))
            
            tactic_raw = tactics[0] if tactics else "unknown"
            tactic_name = tactic_raw.replace('-', ' ').title()
            
            techniques.append({
                "id": attack_id,
                "name": obj.get('name', 'Unknown'),
                "tactic": tactic_name,
                "tactic_id": tactic_map.get(tactic_raw, "Unknown"),
                "description": obj.get('description', '').split('\n')[0][:300] + '...',
                "platforms": obj.get('x_mitre_platforms', [])
            })
    
    logging.info(f"Processed {len(techniques)} ATT&CK techniques")
    with open('data/mitre_attack.json', 'w') as f:
        json.dump(techniques, f, indent=2)

if __name__ == '__main__':
    process_attack()

def process_owasp():
    logging.info("Generating comprehensive OWASP Top 10 + ASVS mapping...")
    
    # OWASP Top 10 (2021)
    top10 = [
        {"id": "A01:2021", "name": "Broken Access Control", "description": "Failures typically lead to unauthorized information disclosure, modification, or destruction of all data.", "techniques": ["T1078", "T1134", "T1548", "T1068", "T1210"]},
        {"id": "A02:2021", "name": "Cryptographic Failures", "description": "Failures related to cryptography (or lack thereof), which often leads to sensitive data exposure or system compromise.", "techniques": ["T1552", "T1040", "T1003", "T1555"]},
        {"id": "A03:2021", "name": "Injection", "description": "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query.", "techniques": ["T1190", "T1059", "T1210"]},
        {"id": "A04:2021", "name": "Insecure Design", "description": "Focuses on risks related to design flaws. A secure design requires secure architecture/patterns and threat modeling.", "techniques": ["T1068", "T1190", "T1133"]},
        {"id": "A05:2021", "name": "Security Misconfiguration", "description": "Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default settings, incomplete or ad hoc configurations.", "techniques": ["T1562", "T1003", "T1078", "T1548"]},
        {"id": "A06:2021", "name": "Vulnerable and Outdated Components", "description": "Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application.", "techniques": ["T1190", "T1203", "T1210"]},
        {"id": "A07:2021", "name": "Identification and Authentication Failures", "description": "Authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens.", "techniques": ["T1110", "T1078", "T1558", "T1555", "T1556"]},
        {"id": "A08:2021", "name": "Software and Data Integrity Failures", "description": "Relates to code and infrastructure that does not protect against integrity violations. An example is an application that relies upon plugins from untrusted sources.", "techniques": ["T1195", "T1547", "T1554", "T1565"]},
        {"id": "A09:2021", "name": "Security Logging and Monitoring Failures", "description": "Without logging and monitoring, breaches cannot be detected. Attackers rely on this to maintain persistence and extract data.", "techniques": ["T1562", "T1070", "T1146"]},
        {"id": "A10:2021", "name": "Server-Side Request Forgery (SSRF)", "description": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.", "techniques": ["T1190", "T1134", "T1046", "T1018"]}
    ]
    
    # Selected OWASP ASVS Items that correspond well to ATT&CK
    asvs = [
        {"id": "V1", "name": "Architecture, Design and Threat Modeling", "techniques": ["T1190"]},
        {"id": "V2", "name": "Authentication", "techniques": ["T1110", "T1078", "T1555"]},
        {"id": "V3", "name": "Session Management", "techniques": ["T1556", "T1539"]},
        {"id": "V4", "name": "Access Control", "techniques": ["T1078", "T1548", "T1134"]},
        {"id": "V5", "name": "Validation, Sanitization and Encoding", "techniques": ["T1190", "T1059", "T1210"]},
        {"id": "V6", "name": "Stored Cryptography", "techniques": ["T1552", "T1003", "T1528"]},
        {"id": "V7", "name": "Error Handling and Logging", "techniques": ["T1562", "T1070"]},
        {"id": "V8", "name": "Data Protection", "techniques": ["T1048", "T1041", "T1560"]},
        {"id": "V9", "name": "Communication", "techniques": ["T1040", "T1119", "T1048"]},
        {"id": "V10", "name": "Malicious Code", "techniques": ["T1055", "T1027", "T1543"]},
        {"id": "V11", "name": "Business Logic", "techniques": ["T1565", "T1560"]},
        {"id": "V12", "name": "File and Resources", "techniques": ["T1048", "T1083", "T1005"]},
        {"id": "V13", "name": "API and Web Service", "techniques": ["T1190"]},
        {"id": "V14", "name": "Configuration", "techniques": ["T1562", "T1078", "T1548"]}
    ]

    owasp_data = {
        "top10": top10,
        "asvs": asvs
    }
    
    with open('data/owasp_data.json', 'w') as f:
        json.dump(owasp_data, f, indent=2)
        
    logging.info(f"Processed 10 OWASP Top 10 items and {len(asvs)} ASVS categories")

if __name__ == '__main__':
    # process_attack() already ran
    process_owasp()

def process_nist():
    logging.info("Generating comprehensive NIST SP 800-53 mappings...")
    
    # Selected key NIST controls across families with attack mapping
    nist = [
        {"id": "AC-2", "family": "Access Control", "name": "Account Management", "description": "Manage system accounts, establishing conditions for group membership.", "severity": "High", "threats": ["T1078", "T1098", "T1136", "T1087", "T1071"]},
        {"id": "AC-3", "family": "Access Control", "name": "Access Enforcement", "description": "Enforce approved authorizations for logical access to information and system resources.", "severity": "High", "threats": ["T1210", "T1134", "T1548", "T1068", "T1558", "T1068", "T1021", "T1531", "T1222"]},
        {"id": "AC-4", "family": "Access Control", "name": "Information Flow Enforcement", "description": "Enforce approved authorizations for controlling information flow within the system and between connected systems.", "severity": "Medium", "threats": ["T1562", "T1048", "T1041", "T1560"]},
        {"id": "AU-2", "family": "Audit and Accountability", "name": "Event Logging", "description": "Identify types of events that the system is capable of logging.", "severity": "High", "threats": ["T1562", "T1070", "T1059", "T1003", "T1146"]},
        {"id": "AU-6", "family": "Audit and Accountability", "name": "Audit Record Review, Analysis, and Reporting", "description": "Review and analyze system audit records for indications of inappropriate or unusual activity.", "severity": "High", "threats": ["T1562", "T1070", "T1046", "T1083"]},
        {"id": "CM-2", "family": "Configuration Management", "name": "Baseline Configuration", "description": "Develop, document, and maintain under configuration control, a current baseline configuration of the system.", "severity": "Medium", "threats": ["T1562", "T1003", "T1078", "T1546", "T1547"]},
        {"id": "CM-6", "family": "Configuration Management", "name": "Configuration Settings", "description": "Establish and document configuration settings for information technology products.", "severity": "High", "threats": ["T1562", "T1548", "T1574"]},
        {"id": "CP-9", "family": "Contingency Planning", "name": "System Backup", "description": "Conduct backups of user-level and system-level information and system documentation.", "severity": "Critical", "threats": ["T1486", "T1485", "T1490"]},
        {"id": "IA-2", "family": "Identification and Authentication", "name": "Identification and Authentication (Organizational Users)", "description": "Uniquely identify and authenticate organizational users (or processes acting on behalf of users).", "severity": "High", "threats": ["T1110", "T1078", "T1556", "T1558", "T1555", "T1003"]},
        {"id": "IR-4", "family": "Incident Response", "name": "Incident Handling", "description": "Handle incidents, including preparation, detection, analysis, containment, recovery, and user response.", "severity": "High", "threats": ["T1486", "T1070", "T1562"]},
        {"id": "PL-4", "family": "Planning", "name": "Rules of Behavior", "description": "Establish and make readily available to individuals requiring access to the system, rules of behavior.", "severity": "Low", "threats": ["T1078"]},
        {"id": "SA-11", "family": "System and Services Acquisition", "name": "Developer Testing and Evaluation", "description": "Require developers of the system to implement testing and evaluation.", "severity": "Medium", "threats": ["T1190", "T1133"]},
        {"id": "SC-7", "family": "System and Communications Protection", "name": "Boundary Protection", "description": "Monitor and control communications at external boundary and key internal boundaries.", "severity": "High", "threats": ["T1190", "T1133", "T1048", "T1041", "T1040", "T1071", "T1095"]},
        {"id": "SC-8", "family": "System and Communications Protection", "name": "Transmission Confidentiality and Integrity", "description": "Protect the confidentiality and integrity of transmitted information.", "severity": "High", "threats": ["T1040", "T1027"]},
        {"id": "SC-28", "family": "System and Communications Protection", "name": "Protection of Information at Rest", "description": "Protect the confidentiality and integrity of information at rest.", "severity": "High", "threats": ["T1486", "T1027", "T1119"]},
        {"id": "SI-2", "family": "System and Information Integrity", "name": "Flaw Remediation", "description": "Identify, report, and correct system flaws.", "severity": "Critical", "threats": ["T1190", "T1203", "T1210"]},
        {"id": "SI-3", "family": "System and Information Integrity", "name": "Malicious Code Protection", "description": "Employ malicious code protection mechanisms at system entry and exit points.", "severity": "High", "threats": ["T1059", "T1055", "T1486", "T1485", "T1204"]},
        {"id": "SI-4", "family": "System and Information Integrity", "name": "System Monitoring", "description": "Monitor the system to detect attacks and indicators of potential attacks.", "severity": "High", "threats": ["T1040", "T1046", "T1048", "T1071", "T1095"]}
    ]
    
    with open('data/nist_controls.json', 'w') as f:
        json.dump(nist, f, indent=2)
        
    logging.info(f"Processed {len(nist)} NIST SP 800-53 framework controls")

if __name__ == '__main__':
    # process_attack()
    # process_owasp()
    process_nist()

def process_defend():
    logging.info("Generating comprehensive D3FEND mappings...")
    
    # Selected key D3FEND countermeasures mapped to ATT&CK
    defend = [
        {"id": "D3-AL", "name": "Application Logging", "category": "Detect", "description": "Configure applications to generate log records.", "counters": ["T1190", "T1059", "T1078", "T1562", "T1210"]},
        {"id": "D3-BA", "name": "Backup and Recovery", "category": "Restore", "description": "Maintain copies of data and systems to enable restoration.", "counters": ["T1486", "T1485", "T1490"]},
        {"id": "D3-EM", "name": "Endpoint Monitoring", "category": "Detect", "description": "Monitor endpoint systems for suspicious activity.", "counters": ["T1059", "T1053", "T1543", "T1547", "T1055"]},
        {"id": "D3-FA", "name": "File Analysis", "category": "Detect", "description": "Analyze files to identify malicious characteristics.", "counters": ["T1204", "T1027", "T1059"]},
        {"id": "D3-IAM", "name": "Identity and Access Management", "category": "Protect", "description": "Manage user identities, authentication, and authorization.", "counters": ["T1078", "T1110", "T1555", "T1558"]},
        {"id": "D3-IP", "name": "Intrusion Prevention", "category": "Protect", "description": "Prevent unauthorized network access and malicious activity.", "counters": ["T1190", "T1133", "T1046"]},
        {"id": "D3-MR", "name": "Malware Remediation", "category": "Evict", "description": "Remove malware and restore affected systems.", "counters": ["T1059", "T1055", "T1486", "T1027"]},
        {"id": "D3-MFA", "name": "Multi-Factor Authentication", "category": "Protect", "description": "Require multiple layers of authentication.", "counters": ["T1078", "T1110", "T1133", "T1021"]},
        {"id": "D3-NM", "name": "Network Monitoring", "category": "Detect", "description": "Monitor network traffic for suspicious activity.", "counters": ["T1040", "T1046", "T1048", "T1071", "T1095"]},
        {"id": "D3-NS", "name": "Network Segmentation", "category": "Protect", "description": "Divide networks to isolate critical assets.", "counters": ["T1021", "T1048", "T1560"]},
        {"id": "D3-PP", "name": "Process Protection", "category": "Protect", "description": "Protect processes from unauthorized modification.", "counters": ["T1055", "T1543", "T1548", "T1134"]},
        {"id": "D3-SNC", "name": "Software Node Configuration", "category": "Protect", "description": "Harden software and system configurations.", "counters": ["T1562", "T1574"]},
        {"id": "D3-TVM", "name": "Threat and Vulnerability Management", "category": "Anticipate", "description": "Identify, assess, and remediate vulnerabilities.", "counters": ["T1190", "T1203", "T1210"]}
    ]
    
    with open('data/mitre_defend.json', 'w') as f:
        json.dump(defend, f, indent=2)
        
    logging.info(f"Processed {len(defend)} D3FEND countermeasures")

if __name__ == '__main__':
    # process_attack()
    # process_owasp()
    # process_nist()
    process_defend()
