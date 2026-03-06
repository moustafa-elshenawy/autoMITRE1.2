"""
VirusTotal Client Module
Integrates with the VirusTotal API for malware hash analysis.
"""
import os
import requests
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from core.osint_client import RUNTIME_CONFIG

load_dotenv()  # Ensure .env is loaded before reading the API key
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def lookup_hash(hash_value: str) -> Dict[str, Any]:
    """
    Look up a file hash on VirusTotal.
    Returns real data or proper error messages. No mock data.
    """
    api_key = RUNTIME_CONFIG.get("virustotal_api_key") or VT_API_KEY
    if not api_key:
        return {"found": False, "hash": hash_value, "message": "VIRUSTOTAL_API_KEY is not configured in the backend .env file or Settings. Real lookups require an API key."}
    
    try:
        headers = {"x-apikey": api_key}
        response = requests.get(
            f"{VT_BASE_URL}/files/{hash_value}",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            parsed = _parse_vt_response(response.json())
            # Fetch real behavioral technique mapped by sandboxes
            real_techniques = _fetch_mitre_techniques(hash_value)
            if real_techniques:
                parsed["suggested_techniques"].extend(real_techniques)
                parsed["suggested_techniques"] = list(set(parsed["suggested_techniques"]))
            return parsed
        elif response.status_code == 404:
            return {"found": False, "hash": hash_value, "message": "Hash not found in VirusTotal database."}
        elif response.status_code == 401:
            return {"found": False, "hash": hash_value, "message": "Invalid VirusTotal API key configured."}
        elif response.status_code == 429:
            return {"found": False, "hash": hash_value, "message": "VirusTotal API quota exceeded. Please wait."}
        else:
            return {"found": False, "hash": hash_value, "message": f"VirusTotal API returned error {response.status_code}."}
    except Exception as e:
        return {"found": False, "hash": hash_value, "message": f"Failed to connect to VirusTotal API: {e}"}


def _parse_vt_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse VirusTotal API response."""
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    names = attributes.get("names", [])
    
    # Extract hashes
    hashes = {
        "md5": attributes.get("md5", ""),
        "sha1": attributes.get("sha1", ""),
        "sha256": attributes.get("sha256", "")
    }
    
    # Try to grab signature info if it's a PE
    signature_info = attributes.get("signature_info", {})
    signer = signature_info.get("product", "") or signature_info.get("original name", "")
    
    # Meaningful name
    meaningful_name = attributes.get("meaningful_name") or (names[0] if names else "Unknown File")
    
    # Tags & Sandbox Verdicts
    tags = attributes.get("tags", [])
    sandbox_verdicts = attributes.get("sandbox_verdicts", {})
    sandbox_labels = [k for k, v in sandbox_verdicts.items() if v.get("category") == "malicious"]
    
    # New Extra Fields
    trid_array = attributes.get("trid", [])
    trid = trid_array[0].get("file_type") if trid_array else None
    yara_hits = [y.get("rule_name") for y in attributes.get("crowdsourced_yara_results", [])]
    magic = attributes.get("magic", "Unknown")
    times_submitted = attributes.get("times_submitted", 0)
    
    # Advanced Static Details
    ssdeep = attributes.get("ssdeep")
    tlsh = attributes.get("tlsh")
    magika = attributes.get("magika")
    unique_sources = attributes.get("unique_sources")
    first_seen_itw = attributes.get("first_seen_itw_date")
    type_extension = attributes.get("type_extension")
    
    return {
        "found": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "total_engines": total,
        "detection_ratio": f"{malicious}/{total}",
        "verdict": "malicious" if malicious > 3 else ("suspicious" if suspicious > 0 else "clean"),
        "file_type": attributes.get("type_description", "Unknown"),
        "file_size": attributes.get("size", 0),
        "first_seen": attributes.get("first_submission_date", ""),
        "last_seen": attributes.get("last_analysis_date", ""),
        "creation_date": attributes.get("creation_date", ""),
        "names": names[:5],
        "meaningful_name": meaningful_name,
        "hashes": hashes,
        "signer": signer,
        "tags": tags[:10],
        "sandbox_hits": sandbox_labels,
        "reputation": attributes.get("reputation", 0),
        "suggested_techniques": _infer_techniques(attributes),
        "magic": magic,
        "trid": trid,
        "yara_hits": yara_hits[:5],
        "times_submitted": times_submitted,
        "ssdeep": ssdeep,
        "tlsh": tlsh,
        "magika": magika,
        "unique_sources": unique_sources,
        "first_seen_itw": first_seen_itw,
        "type_extension": type_extension
    }

def _infer_techniques(attributes: Dict[str, Any]) -> list:
    """Infer ATT&CK techniques from VirusTotal attributes."""
    techniques = []
    type_desc = attributes.get("type_description", "").lower()
    
    if "executable" in type_desc or "pe32" in type_desc:
        techniques.extend(["T1059", "T1204"])
    if "script" in type_desc:
        techniques.extend(["T1059.001", "T1059.003"])
    if "pdf" in type_desc:
        techniques.extend(["T1566"])
    if "office" in type_desc or "macro" in type_desc:
        techniques.extend(["T1566", "T1059"])
    
    # Check tags for behavior hints
    for tag in attributes.get("tags", []):
        if "ransomware" in tag:
            techniques.extend(["T1486", "T1485"])
        if "trojan" in tag or "rat" in tag:
            techniques.extend(["T1071", "T1055"])
        if "keylogger" in tag:
            techniques.extend(["T1056"])
    
    return list(set(techniques))[:6]


def _fetch_mitre_techniques(hash_value: str) -> list:
    """Fetch exact MITRE ATT&CK techniques from VirusTotal behaviour_mitre_trees."""
    api_key = RUNTIME_CONFIG.get("virustotal_api_key") or VT_API_KEY
    if not api_key:
        return []
        
    try:
        headers = {"x-apikey": api_key}
        response = requests.get(
            f"{VT_BASE_URL}/files/{hash_value}/behaviour_mitre_trees",
            headers=headers,
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            techniques = set()
            for sandbox, info in data.get("data", {}).items():
                for tactic in info.get("tactics", []):
                    for tech in tactic.get("techniques", []):
                        if "id" in tech:
                            techniques.add(tech["id"])
            return list(techniques)
    except Exception:
        pass
    return []
