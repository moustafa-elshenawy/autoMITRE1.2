import re
import logging
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)

# Deterministic Evidence Map (Atomic & Behavioral Indicators)
# Sources: Atomic Red Team, Sigma Rules, MITRE ATT&CK Data Sources
EVIDENCE_MAP: Dict[str, Dict[str, Any]] = {
    "T1059.001": { # PowerShell
        "patterns": [r"powershell", r"pwsh", r"iex", r"encodedcommand", r"downloadstring", r"invoke-webrequest"],
        "weight": 1.0
    },
    "T1003": { # OS Credential Dumping
        "patterns": [r"mimikatz", r"lsass", r"procdump", r"sekurlsa", r"logonpasswords", r"samdump", r"pwdump"],
        "weight": 1.2
    },
    "T1053.005": { # Scheduled Task
        "patterns": [r"schtasks", r"at.exe", r"task scheduler", r"create /tn", r"registry\w+schedule\w+task"],
        "weight": 1.0
    },
    "T1048": { # Exfiltration Over Alternative Protocol
        "patterns": [r"ftp", r"scp", r"rclone", r"megaupload", r"rsync", r"dropbox", r"googledrive"],
        "weight": 1.1
    },
    "T1021.001": { # RDP
        "patterns": [r"rdp", r"remote desktop", r"mstsc", r"port 3389", r"termdd.sys"],
        "weight": 1.0
    },
    "T1071.001": { # Web Protocols
        "patterns": [r"http", r"https", r"c2 server", r"callback", r"user-agent", r"get /", r"post /"],
        "weight": 0.8
    },
    "T1562.001": { # Disable or Modify Tools
        "patterns": [r"sc stop", r"net stop", r"disable-antivirus", r"set-mppreference", r"clear-eventlog"],
        "weight": 1.2
    },
    "T1486": { # Data Encrypted for Impact (Ransomware)
        "patterns": [r"encrypt", r"ext:.\w{4,8}", r"vssadmin delete shadows", r"wbadmin delete", r"cipher /w"],
        "weight": 1.5
    },
    "T1027": { # Obfuscated Files or Information
        "patterns": [r"base64", r"xor", r"rot13", r"packing", r"upx", r"obfuscated"],
        "weight": 0.9
    },
    "T1105": { # Ingress Tool Transfer
        "patterns": [r"wget", r"curl", r"certutil -urlcache", r"bitsadmin /transfer"],
        "weight": 1.0
    }
}

class EvidenceAligner:
    """
    Stage 3: Technical Evidence Alignment Engine.
    Validates AI predictions (probabilistic) against deterministic evidence (strings, commands).
    """

    def align_techniques(self, techniques: List[Dict[str, Any]], extracted_terms: List[str], raw_text: str) -> List[Dict[str, Any]]:
        """
        Re-scores and validates techniques based on hard evidence.
        """
        combined_evidence = " ".join(extracted_terms).lower() + " " + raw_text.lower()
        aligned_results = []

        for tech in techniques:
            tech_id = tech.get("id")
            confidence = tech.get("confidence", 0.5)
            evidence_found = []
            
            # Check for matches in our deterministic map
            if tech_id and str(tech_id) in EVIDENCE_MAP:
                rules = EVIDENCE_MAP[str(tech_id)]
                patterns = rules.get("patterns", [])
                if isinstance(patterns, list):
                    for pattern in patterns:
                        if re.search(str(pattern), combined_evidence):
                            evidence_found.append(str(pattern))
            
            # Cross-reference: If Stage 2 extracted a term that exactly matches a TTP name/keyword
            # (Simplified logic for now)

            # Re-scoring Logic:
            # - If evidence is found, boost confidence.
            # - Mark as "verified" if evidence is strong.
            
            is_verified = len(evidence_found) > 0
            if is_verified:
                # Boost confidence but cap at 0.99
                boost = 0.1 * len(evidence_found) * float(EVIDENCE_MAP.get(str(tech_id), {}).get("weight", 1.0))
                confidence = min(0.99, float(confidence) + boost)
            
            # Add metadata for UI
            aligned_tech = {
                "id": str(tech_id) if tech_id else "unknown",
                "name": str(tech.get("name", "Classified Technique")),
                "confidence": float(round(float(confidence), 2)),
                "verified": bool(is_verified),
                "evidence": list(set(evidence_found))
            }
            aligned_results.append(aligned_tech)

        # Optional: Pruning
        # If confidence is very low and NO evidence found, we could prune.
        # But for industrial safety, we keep them unless confidence < 0.2
        return [t for t in aligned_results if float(t.get("confidence", 0)) > 0.15]

# Singleton
evidence_aligner = EvidenceAligner()
