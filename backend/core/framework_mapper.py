"""
Framework Mapper Module
Maps detected threats to MITRE D3FEND, NIST SP 800-53, and OWASP frameworks.
"""
import json
import os
from typing import List, Dict, Any
from models.schemas import (
    D3FENDCountermeasure, NISTControl, OWASPItem, ATTACKTechnique
)

_DEFEND_DB = None
_NIST_DB = None
_OWASP_DB = None


def _load_databases():
    global _DEFEND_DB, _NIST_DB, _OWASP_DB
    base = os.path.join(os.path.dirname(__file__), '..', 'data')
    with open(os.path.join(base, 'mitre_defend.json')) as f:
        _DEFEND_DB = json.load(f)
    with open(os.path.join(base, 'nist_controls.json')) as f:
        _NIST_DB = json.load(f)
    with open(os.path.join(base, 'owasp_data.json')) as f:
        _OWASP_DB = json.load(f)


_load_databases()


def map_to_defend(technique_ids: List[str]) -> List[D3FENDCountermeasure]:
    """Map ATT&CK techniques to D3FEND countermeasures."""
    countermeasures = []
    seen = set()
    
    for technique_id in technique_ids:
        for counter in _DEFEND_DB:
            if technique_id in counter.get('counters', []) and counter['id'] not in seen:
                seen.add(counter['id'])
                countermeasures.append(D3FENDCountermeasure(
                    id=counter['id'],
                    name=counter['name'],
                    category=counter['category'],
                    description=counter['description']
                ))
    
    return countermeasures[:8]


def map_to_nist(technique_ids: List[str]) -> List[NISTControl]:
    """Map ATT&CK techniques to NIST SP 800-53 controls."""
    controls = []
    seen = set()
    
    for technique_id in technique_ids:
        for control in _NIST_DB:
            if technique_id in control.get('threats', []) and control['id'] not in seen:
                seen.add(control['id'])
                controls.append(NISTControl(
                    id=control['id'],
                    family=control['family'],
                    name=control['name'],
                    description=control['description'],
                    severity=control['severity']
                ))
    
    return controls[:8]


def map_to_owasp(technique_ids: List[str]) -> List[OWASPItem]:
    """Map ATT&CK techniques to OWASP Top 10 and ASVS items."""
    items = []
    seen = set()
    
    for item in _OWASP_DB.get('top10', []):
        for technique_id in technique_ids:
            if technique_id in item.get('techniques', []) and item['id'] not in seen:
                seen.add(item['id'])
                items.append(OWASPItem(
                    id=f"OWASP-{item['id']}",
                    name=item.get('name', item['id']),
                    description=item.get('description', 'See OWASP documentation for details.'),
                    type='top10'
                ))
                break
    
    for item in _OWASP_DB.get('asvs', []):
        for technique_id in technique_ids:
            if technique_id in item.get('techniques', []) and item['id'] not in seen:
                seen.add(item['id'])
                items.append(OWASPItem(
                    id=f"ASVS-{item['id']}",
                    name=item.get('name', item['id']),
                    description=item.get('description', 'See OWASP ASVS documentation for details.'),
                    type='asvs'
                ))
                break
    
    return items[:6]


def map_all_frameworks(technique_ids: List[str]) -> Dict[str, Any]:
    """Map techniques across all frameworks in one call."""
    return {
        'defend': map_to_defend(technique_ids),
        'nist': map_to_nist(technique_ids),
        'owasp': map_to_owasp(technique_ids)
    }


def get_framework_coverage_stats(technique_ids: List[str]) -> Dict[str, Any]:
    """Get coverage statistics across all frameworks."""
    defend = map_to_defend(technique_ids)
    nist = map_to_nist(technique_ids)
    owasp = map_to_owasp(technique_ids)
    
    return {
        'attack_techniques': len(technique_ids),
        'defend_countermeasures': len(defend),
        'nist_controls': len(nist),
        'owasp_items': len(owasp),
        'total_coverage': len(technique_ids) + len(defend) + len(nist) + len(owasp)
    }
