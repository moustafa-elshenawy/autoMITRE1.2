"""
SIEM Exporter Module
Exports threat intelligence to STIX 2.1, JSON, CSV formats.
"""
import json
import csv
import io
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any


def _generate_stix_indicator(threat: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a STIX 2.1 Indicator object."""
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{str(uuid.uuid4())}",
        "created": datetime.now(timezone.utc).isoformat(),
        "modified": datetime.now(timezone.utc).isoformat(),
        "name": threat.get('title', 'Unknown Threat'),
        "description": threat.get('description', '')[:500],
        "pattern": "[file:hashes.MD5 = 'unknown'] OR [ipv4-addr:value = '0.0.0.0']",
        "pattern_type": "stix",
        "valid_from": datetime.now(timezone.utc).isoformat(),
        "labels": ["malicious-activity"],
        "confidence": int(threat.get('confidence', 70)),
    }


def _generate_stix_attack_pattern(technique: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a STIX 2.1 Attack Pattern object."""
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": f"attack-pattern--{str(uuid.uuid4())}",
        "created": datetime.now(timezone.utc).isoformat(),
        "modified": datetime.now(timezone.utc).isoformat(),
        "name": technique.get('name', 'Unknown Technique'),
        "description": technique.get('description', ''),
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique.get('id', ''),
                "url": f"https://attack.mitre.org/techniques/{technique.get('id', '').replace('.', '/')}"
            }
        ],
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": technique.get('tactic', '').lower().replace(' ', '-')
            }
        ]
    }


def _generate_stix_course_of_action(mitigation: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a STIX 2.1 Course of Action object."""
    return {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": f"course-of-action--{str(uuid.uuid4())}",
        "created": datetime.now(timezone.utc).isoformat(),
        "modified": datetime.now(timezone.utc).isoformat(),
        "name": mitigation.get('title', 'Unknown Mitigation'),
        "description": mitigation.get('description', '')
    }


def export_to_stix(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Export threats to STIX 2.1 bundle."""
    objects = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{str(uuid.uuid4())}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": "autoMITRE Threat Intelligence Platform",
            "identity_class": "system"
        }
    ]
    
    for threat in threats:
        # Add indicator
        indicator = _generate_stix_indicator(threat)
        objects.append(indicator)
        
        # Add attack patterns for each technique
        for technique in threat.get('attack_techniques', []):
            if isinstance(technique, dict):
                ap = _generate_stix_attack_pattern(technique)
                objects.append(ap)
        
        # Add courses of action for mitigations
        for mitigation in threat.get('mitigations', [])[:3]:
            if isinstance(mitigation, dict):
                coa = _generate_stix_course_of_action(mitigation)
                objects.append(coa)
    
    return {
        "type": "bundle",
        "id": f"bundle--{str(uuid.uuid4())}",
        "spec_version": "2.1",
        "objects": objects
    }


def export_to_json(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Export threats to a structured JSON format."""
    return {
        "export_metadata": {
            "tool": "autoMITRE",
            "version": "1.2",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "count": len(threats)
        },
        "threats": threats
    }


def export_to_csv(threats: List[Dict[str, Any]]) -> str:
    """Export threats to CSV format."""
    output = io.StringIO()
    fieldnames = ['id', 'title', 'severity', 'risk_score', 'techniques', 
                  'nist_controls', 'owasp_items', 'timestamp', 'description']
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for threat in threats:
        risk = threat.get('risk_score', {})
        techniques = ','.join([
            t.get('id', '') if isinstance(t, dict) else str(t)
            for t in threat.get('attack_techniques', [])[:5]
        ])
        nist = ','.join([
            n.get('id', '') if isinstance(n, dict) else str(n)
            for n in threat.get('nist_controls', [])[:3]
        ])
        owasp = ','.join([
            o.get('id', '') if isinstance(o, dict) else str(o)
            for o in threat.get('owasp_items', [])[:3]
        ])
        
        writer.writerow({
            'id': threat.get('id', ''),
            'title': threat.get('title', ''),
            'severity': risk.get('severity', '') if isinstance(risk, dict) else '',
            'risk_score': risk.get('score', '') if isinstance(risk, dict) else '',
            'techniques': techniques,
            'nist_controls': nist,
            'owasp_items': owasp,
            'timestamp': threat.get('timestamp', ''),
            'description': threat.get('description', '')[:200]
        })
    
    return output.getvalue()


def format_for_splunk(threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Format threats for Splunk ingestion."""
    return [
        {
            "time": threat.get('timestamp', ''),
            "sourcetype": "autoMITRE:threat",
            "source": "autoMITRE",
            "host": "autoMITRE-platform",
            "event": {
                "threat_id": threat.get('id', ''),
                "severity": threat.get('risk_score', {}).get('severity', '') if isinstance(threat.get('risk_score'), dict) else '',
                "risk_score": threat.get('risk_score', {}).get('score', 0) if isinstance(threat.get('risk_score'), dict) else 0,
                "attack_techniques": [
                    t.get('id', '') for t in threat.get('attack_techniques', []) if isinstance(t, dict)
                ],
                "title": threat.get('title', ''),
                "mitre_tactics": list(set([
                    t.get('tactic', '') for t in threat.get('attack_techniques', []) if isinstance(t, dict)
                ]))
            }
        }
        for threat in threats
    ]
