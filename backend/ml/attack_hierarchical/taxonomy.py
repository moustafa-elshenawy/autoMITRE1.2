"""
attack_hierarchical.taxonomy
============================
Builds the hierarchical label space — Tactic -> Technique -> Sub-technique —
from the real MITRE corpus shipped at ``data/mitre_attack.json``.

The synthetic training corpus (dataset.py) invents *text*, but the *labels* and
their parent/child relationships are genuine ATT&CK structure. This object is
the single source of truth shared by the dataset, the loss function (parent
matrices), the re-ranker (technique definitions) and inference (id -> name).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np

from . import config

log = logging.getLogger("attack_hierarchical.taxonomy")


@dataclass
class Taxonomy:
    # ordered label vocabularies
    tactics: List[str]                 # tactic names, e.g. "Credential Access"
    techniques: List[str]              # technique ids, e.g. "T1003.001"
    # lookups
    tactic2idx: Dict[str, int]
    technique2idx: Dict[str, int]
    technique_names: Dict[str, str]    # id -> human name
    technique_text: Dict[str, str]     # id -> "name. description" (for re-ranker)
    technique_tactics: Dict[str, List[str]]  # id -> parent tactic names
    # parent matrices (numpy float32)
    tactic_parent_matrix: np.ndarray   # [num_techniques, num_tactics] 1 if tactic is a parent
    base_parent_matrix: np.ndarray     # [num_techniques, num_techniques] 1 if col is the base technique of sub-technique row

    # -- sizes --------------------------------------------------------------
    @property
    def num_tactics(self) -> int:
        return len(self.tactics)

    @property
    def num_techniques(self) -> int:
        return len(self.techniques)

    # -- convenience --------------------------------------------------------
    def technique_tactic_indices(self, tech_id: str) -> List[int]:
        return [self.tactic2idx[t] for t in self.technique_tactics.get(tech_id, [])]

    def to_meta(self) -> dict:
        """Serialisable description persisted alongside a checkpoint."""
        return {
            "tactics": self.tactics,
            "techniques": self.techniques,
            "technique_names": self.technique_names,
            "technique_text": self.technique_text,
            "technique_tactics": self.technique_tactics,
        }

    @classmethod
    def from_meta(cls, meta: dict) -> "Taxonomy":
        return _assemble(
            raw_entries=[
                {
                    "id": tid,
                    "name": meta["technique_names"].get(tid, tid),
                    "tactic": (meta["technique_tactics"].get(tid) or ["Unknown"])[0],
                    "tactics": meta["technique_tactics"].get(tid, []),
                    "text": meta["technique_text"].get(tid, ""),
                }
                for tid in meta["techniques"]
            ],
            ordered_tactics=meta["tactics"],
            ordered_techniques=meta["techniques"],
        )


def _base_id(tech_id: str) -> str:
    """'T1059.001' -> 'T1059'  (a base technique returns itself)."""
    return tech_id.split(".")[0]


def load_taxonomy(path: Optional[str] = None) -> Taxonomy:
    """Construct the taxonomy from the MITRE JSON, honouring config's subset."""
    path = path or config.MITRE_ATTACK_JSON
    with open(path, "r", encoding="utf-8") as fh:
        techniques_json = json.load(fh)

    # Aggregate by id (a technique can appear under multiple tactics).
    by_id: Dict[str, dict] = {}
    for t in techniques_json:
        tid = t.get("id")
        if not tid:
            continue
        entry = by_id.setdefault(
            tid,
            {
                "id": tid,
                "name": t.get("name", tid),
                "description": t.get("description", ""),
                "tactics": [],
            },
        )
        tac = t.get("tactic")
        if tac and tac not in entry["tactics"]:
            entry["tactics"].append(tac)

    # Restrict to the curated subset unless the full matrix is requested.
    if config.USE_FULL_TAXONOMY:
        keep_ids = list(by_id.keys())
    else:
        keep_ids = [tid for tid in config.SUBSET_TECHNIQUE_IDS if tid in by_id]
        # Ensure every kept sub-technique's base technique is also a label, so
        # the sub -> base hierarchy is representable.
        for tid in list(keep_ids):
            base = _base_id(tid)
            if base != tid and base in by_id and base not in keep_ids:
                keep_ids.append(base)
        missing = [t for t in config.SUBSET_TECHNIQUE_IDS if t not in by_id]
        if missing:
            log.warning("Subset ids not found in corpus and skipped: %s", missing)

    raw_entries = []
    for tid in keep_ids:
        e = by_id[tid]
        raw_entries.append(
            {
                "id": tid,
                "name": e["name"],
                "tactic": (e["tactics"] or ["Unknown"])[0],
                "tactics": e["tactics"] or ["Unknown"],
                "text": f"{e['name']}. {e['description']}".strip(),
            }
        )

    ordered_techniques = sorted({e["id"] for e in raw_entries})
    ordered_tactics = sorted({tac for e in raw_entries for tac in e["tactics"]})
    tax = _assemble(raw_entries, ordered_tactics, ordered_techniques)
    log.info(
        "Taxonomy: %d tactics, %d techniques (%d sub-techniques).",
        tax.num_tactics,
        tax.num_techniques,
        sum(1 for t in tax.techniques if "." in t),
    )
    return tax


def _assemble(raw_entries: List[dict], ordered_tactics: List[str],
              ordered_techniques: List[str]) -> Taxonomy:
    tactic2idx = {t: i for i, t in enumerate(ordered_tactics)}
    technique2idx = {t: i for i, t in enumerate(ordered_techniques)}

    technique_names: Dict[str, str] = {}
    technique_text: Dict[str, str] = {}
    technique_tactics: Dict[str, List[str]] = {}
    for e in raw_entries:
        technique_names[e["id"]] = e["name"]
        technique_text[e["id"]] = e.get("text") or e["name"]
        technique_tactics[e["id"]] = [t for t in e.get("tactics", []) if t in tactic2idx] or \
            ([e["tactic"]] if e.get("tactic") in tactic2idx else [])

    num_t, num_a = len(ordered_techniques), len(ordered_tactics)
    tactic_parent = np.zeros((num_t, num_a), dtype=np.float32)
    base_parent = np.zeros((num_t, num_t), dtype=np.float32)

    for tid in ordered_techniques:
        ti = technique2idx[tid]
        for tac in technique_tactics.get(tid, []):
            tactic_parent[ti, tactic2idx[tac]] = 1.0
        base = _base_id(tid)
        if base != tid and base in technique2idx:
            base_parent[ti, technique2idx[base]] = 1.0

    return Taxonomy(
        tactics=ordered_tactics,
        techniques=ordered_techniques,
        tactic2idx=tactic2idx,
        technique2idx=technique2idx,
        technique_names=technique_names,
        technique_text=technique_text,
        technique_tactics=technique_tactics,
        tactic_parent_matrix=tactic_parent,
        base_parent_matrix=base_parent,
    )


# ===========================================================================
# TRAM support — build a taxonomy whose technique space is driven by a real
# corpus (the CSV), with the fixed 14 enterprise Tactics for Head A.
# ===========================================================================
# Canonical enterprise tactics in kill-chain order — a STABLE 14-dim label
# space for Head A regardless of which tactics appear in the data.
CANONICAL_TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]
_CANON_NAME_BY_ID = {tid: name for tid, name in CANONICAL_TACTICS}
CANONICAL_TACTIC_NAMES = [name for _, name in CANONICAL_TACTICS]


def load_json_index(path: Optional[str] = None) -> Dict[str, dict]:
    """Index the shipped MITRE corpus by technique id -> {name, description, tactic_ids}.

    A technique appearing under several tactics aggregates all of them. This is
    the static mapping used to resolve TRAM technique ids to their parent
    tactics offline (no STIX download needed). If you prefer the live STIX
    source, install ``mitreattack-python`` and replace ``load_json_index`` with
    a MitreAttackData lookup — the rest of the pipeline is agnostic.
    """
    path = path or config.MITRE_ATTACK_JSON
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    idx: Dict[str, dict] = {}
    for t in data:
        tid = t.get("id")
        if not tid:
            continue
        entry = idx.setdefault(
            tid, {"id": tid, "name": t.get("name", tid),
                  "description": t.get("description", ""), "tactic_ids": []}
        )
        tac_id = t.get("tactic_id")
        if tac_id and tac_id not in entry["tactic_ids"]:
            entry["tactic_ids"].append(tac_id)
    return idx


def resolve_parent_tactics(technique_id: str, json_index: Optional[Dict[str, dict]] = None
                           ) -> List[str]:
    """Return the parent **Tactic IDs** (e.g. ['TA0006']) for a technique id.

    Sub-techniques inherit their base technique's tactics when not listed
    directly. Unknown ids return an empty list.
    """
    idx = json_index if json_index is not None else load_json_index()
    entry = idx.get(technique_id) or idx.get(technique_id.split(".")[0])
    if entry is None:
        return []
    return [tid for tid in entry["tactic_ids"] if tid in _CANON_NAME_BY_ID]


def build_taxonomy_from_techniques(technique_ids: List[str],
                                   path: Optional[str] = None) -> Taxonomy:
    """Build a Taxonomy over an arbitrary technique set (e.g. the labels present
    in a TRAM CSV), using the fixed 14-tactic Head-A space.
    """
    idx = load_json_index(path)

    # Keep resolvable ids; pull in each sub-technique's base so sub->base
    # consistency is representable.
    keep: List[str] = []
    seen = set()
    for tid in technique_ids:
        if tid in seen:
            continue
        base = tid.split(".")[0]
        if tid in idx or base in idx:
            keep.append(tid)
            seen.add(tid)
            if base != tid and base in idx and base not in seen:
                keep.append(base)
                seen.add(base)
    ordered_techniques = sorted(set(keep))

    raw_entries: List[dict] = []
    for tid in ordered_techniques:
        entry = idx.get(tid) or idx.get(tid.split(".")[0]) or {
            "name": tid, "description": "", "tactic_ids": []}
        tac_names = [_CANON_NAME_BY_ID[t] for t in entry.get("tactic_ids", [])
                     if t in _CANON_NAME_BY_ID]
        raw_entries.append({
            "id": tid,
            "name": entry.get("name", tid),
            "tactic": (tac_names or ["Unknown"])[0],
            "tactics": tac_names,
            "text": f"{entry.get('name', tid)}. {entry.get('description', '')}".strip(),
        })

    tax = _assemble(raw_entries, CANONICAL_TACTIC_NAMES, ordered_techniques)
    log.info("TRAM taxonomy: %d tactics (fixed), %d techniques (%d sub-techniques).",
             tax.num_tactics, tax.num_techniques,
             sum(1 for t in tax.techniques if "." in t))
    return tax
