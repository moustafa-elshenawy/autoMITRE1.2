"""
Input Processor Module
Handles normalization of diverse threat input formats:
PCAP metadata, JSON/STIX feeds, plain text, malware hashes.
"""
import json
import re
from typing import Dict, Any, List, Tuple, Optional
from models.schemas import InputType, ThreatEntity


# Regex patterns for entity extraction
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|org|net|edu|gov|mil|int|io|co|uk|de|fr|ru|cn)\b'
)
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
PORT_PATTERN = re.compile(r'\bport[:\s]+(\d{1,5})\b', re.IGNORECASE)
URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)

MALWARE_KEYWORDS = [
    'ransomware', 'trojan', 'rootkit', 'keylogger', 'spyware', 'adware',
    'worm', 'virus', 'botnet', 'backdoor', 'rat', 'payload', 'dropper',
    'exploit', 'shellcode', 'webshell', 'cryptominer', 'stealer', 'loader',
    'ryuk', 'emotet', 'wannacry', 'petya', 'mirai', 'cobalt strike',
    'metasploit', 'mimikatz', 'lazarus', 'apt28', 'apt29', 'darkside'
]

ATTACK_KEYWORDS = {
    'sql injection': ['T1190', 'T1190.001'],
    'xss': ['T1190', 'T1190.002'],
    'cross-site scripting': ['T1190', 'T1190.002'],
    'brute force': ['T1110'],
    'password spray': ['T1110'],
    'phishing': ['T1566'],
    'spear phishing': ['T1566'],
    'command execution': ['T1059'],
    'powershell': ['T1059.001'],
    'credential dump': ['T1003'],
    'lateral movement': ['T1021'],
    'privilege escalation': ['T1548', 'T1134'],
    'exfiltration': ['T1048', 'T1041'],
    'ransomware': ['T1486', 'T1485'],
    'data destruction': ['T1485'],
    'port scan': ['T1046'],
    'network scan': ['T1046'],
    'c2': ['T1071', 'T1095'],
    'command and control': ['T1071'],
    'persistence': ['T1053', 'T1547'],
    'process injection': ['T1055'],
    'obfuscation': ['T1027'],
    'log tampering': ['T1070'],
    'remote access': ['T1021', 'T1133'],
    'vpn': ['T1133'],
    'rdp': ['T1021'],
    'ssh': ['T1021'],
}


def detect_input_type(content: str) -> InputType:
    """Detect the type of input from its content."""
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            if data.get('type') == 'bundle' or 'objects' in data:
                return InputType.STIX
            return InputType.JSON
    except (json.JSONDecodeError, ValueError):
        pass

    # Check for hash
    if SHA256_PATTERN.match(content.strip()):
        return InputType.HASH
    if SHA1_PATTERN.match(content.strip()):
        return InputType.HASH
    if MD5_PATTERN.match(content.strip()):
        return InputType.HASH

    return InputType.TEXT


def extract_entities(text: str) -> List[ThreatEntity]:
    """Extract threat entities from text."""
    entities = []

    for ip in set(IP_PATTERN.findall(text)):
        # Skip private/loopback IPs
        if not (ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.')):
            entities.append(ThreatEntity(type='ip', value=ip, context='Network indicator'))

    for domain in set(DOMAIN_PATTERN.findall(text)):
        entities.append(ThreatEntity(type='domain', value=domain, context='Network indicator'))

    for cve in set(CVE_PATTERN.findall(text)):
        entities.append(ThreatEntity(type='cve', value=cve.upper(), context='Vulnerability reference'))

    for url in set(URL_PATTERN.findall(text)):
        entities.append(ThreatEntity(type='url', value=url, context='URL indicator'))

    for hash_val in set(SHA256_PATTERN.findall(text)):
        entities.append(ThreatEntity(type='hash_sha256', value=hash_val, context='File hash'))

    for hash_val in set(MD5_PATTERN.findall(text)):
        entities.append(ThreatEntity(type='hash_md5', value=hash_val, context='File hash'))

    text_lower = text.lower()
    for malware in MALWARE_KEYWORDS:
        if malware in text_lower:
            entities.append(ThreatEntity(type='malware', value=malware.title(), context='Malware reference'))

    return entities[:20]  # Cap at 20 entities


def normalize_text_input(text: str) -> Dict[str, Any]:
    """Normalize plain text threat description."""
    entities = extract_entities(text)
    
    # Find attack keywords
    matched_techniques = []
    text_lower = text.lower()
    for keyword, techniques in ATTACK_KEYWORDS.items():
        if keyword in text_lower:
            matched_techniques.extend(techniques)
    
    return {
        'normalized_text': text,
        'entities': entities,
        'suggested_techniques': list(set(matched_techniques)),
        'input_type': InputType.TEXT,
        'word_count': len(text.split()),
        'has_iocs': len(entities) > 0
    }


def normalize_json_input(content: str) -> Dict[str, Any]:
    """Normalize JSON/STIX threat intelligence."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return {'error': 'Invalid JSON', 'input_type': InputType.TEXT}
    
    # Flatten JSON to text for entity extraction
    flat_text = json.dumps(data)
    entities = extract_entities(flat_text)
    
    matched_techniques = []
    for keyword, techniques in ATTACK_KEYWORDS.items():
        if keyword in flat_text.lower():
            matched_techniques.extend(techniques)
    
    return {
        'normalized_text': flat_text,
        'entities': entities,
        'suggested_techniques': list(set(matched_techniques)),
        'input_type': InputType.JSON,
        'structured_data': data,
        'has_iocs': len(entities) > 0
    }


def normalize_hash_input(hash_value: str) -> Dict[str, Any]:
    """Normalize malware hash for VirusTotal lookup."""
    hash_val = hash_value.strip()
    hash_type = 'md5'
    if len(hash_val) == 64:
        hash_type = 'sha256'
    elif len(hash_val) == 40:
        hash_type = 'sha1'
    
    return {
        'normalized_text': f"Malware hash lookup: {hash_val}",
        'entities': [ThreatEntity(type=f'hash_{hash_type}', value=hash_val, context='File hash for analysis')],
        'suggested_techniques': [],
        'input_type': InputType.HASH,
        'hash_value': hash_val,
        'hash_type': hash_type,
        'has_iocs': True
    }


def process_input(content: str, input_type: Optional[str] = None) -> Dict[str, Any]:
    """Main dispatcher for input processing."""
    if input_type:
        detected_type = InputType(input_type)
    else:
        detected_type = detect_input_type(content)

    if detected_type == InputType.TEXT:
        return normalize_text_input(content)
    elif detected_type in (InputType.JSON, InputType.STIX):
        return normalize_json_input(content)
    elif detected_type == InputType.HASH:
        return normalize_hash_input(content)
    else:
        return normalize_text_input(content)
