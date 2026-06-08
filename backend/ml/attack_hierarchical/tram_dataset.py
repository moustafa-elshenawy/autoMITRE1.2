"""
attack_hierarchical.tram_dataset
================================
Real-world data pipeline for the CTID **TRAM** dataset (CTI report text ->
MITRE Technique IDs). Produces everything ``train.py`` needs to fine-tune the
``MultiLabelHierarchicalClassifier`` natively on Apple Silicon.

Pipeline:

  CSV ─▶ load_tram_csv          parse text + technique ids (column auto-detect)
      ─▶ build_taxonomy...      resolve parent Tactic IDs, fix 14-tactic space
      ─▶ TRAMDataset            tokenize (max_length=512) + hierarchical multi-hot
      ─▶ compute_class_weights  per-label pos_weight to fight imbalance

The TRAM CSV only carries Technique IDs; parent Tactics are resolved offline via
``taxonomy.resolve_parent_tactics`` (static MITRE mapping shipped with the app —
no STIX download). Swap in ``mitreattack-python`` there if you want the live
bundle; nothing else changes.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset

from . import config
from .dataset import AttackDataset, Collator, Sample, load_tokenizer  # noqa: F401 (re-export)
from .taxonomy import (
    Taxonomy,
    build_taxonomy_from_techniques,
    load_json_index,
    resolve_parent_tactics,
)

log = logging.getLogger("attack_hierarchical.tram_dataset")

# Matches T1059 and T1059.001 (technique + sub-technique).
TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Common TRAM / CTI column names, tried in order.
_TEXT_COLUMNS = ["text", "sentence", "Sentence", "Text", "document", "report",
                 "report_text", "body", "content", "Document"]
_LABEL_COLUMNS = ["label", "labels", "Label", "technique", "technique_id",
                  "technique_ids", "techniques", "mappings", "attack_id",
                  "attack_ids", "tid", "tids", "y", "Technique ID"]


# ---------------------------------------------------------------------------
# Parent-tactic resolver (the explicit "look up the parent Tactic ID" helper)
# ---------------------------------------------------------------------------
class TechniqueTacticResolver:
    """Resolves a Technique ID to its parent Tactic ID(s), offline.

    >>> r = TechniqueTacticResolver()
    >>> r.parent_tactic_ids("T1003.001")
    ['TA0006']
    >>> r.parent_tactic_names("T1003.001")
    ['Credential Access']
    """

    def __init__(self, path: Optional[str] = None):
        self._index = load_json_index(path)

    def parent_tactic_ids(self, technique_id: str) -> List[str]:
        return resolve_parent_tactics(technique_id, self._index)

    def parent_tactic_names(self, technique_id: str) -> List[str]:
        from .taxonomy import _CANON_NAME_BY_ID
        return [_CANON_NAME_BY_ID[t] for t in self.parent_tactic_ids(technique_id)]

    def is_known(self, technique_id: str) -> bool:
        return bool(self.parent_tactic_ids(technique_id))


# ---------------------------------------------------------------------------
# CSV loading
# ---------------------------------------------------------------------------
def _detect_column(df: pd.DataFrame, candidates: List[str], kind: str) -> str:
    for c in candidates:
        if c in df.columns:
            return c
    # case-insensitive retry
    lower = {col.lower(): col for col in df.columns}
    for c in candidates:
        if c.lower() in lower:
            return lower[c.lower()]
    raise ValueError(
        f"Could not auto-detect the {kind} column. Columns present: "
        f"{list(df.columns)}. Pass it explicitly (--text-col / --label-col)."
    )


def load_tram_csv(path: str, text_col: Optional[str] = None,
                  label_col: Optional[str] = None) -> List[Sample]:
    """Read a TRAM CSV into multi-label ``Sample`` objects.

    Robust to format variance: technique ids are extracted by regex from the
    label cell (handles comma/space/semicolon-separated or messy strings), and
    rows sharing identical text are merged into one multi-label example.
    """
    df = pd.read_csv(path, dtype=str, keep_default_na=False, engine="python")
    if df.empty:
        raise ValueError(f"TRAM CSV is empty: {path}")

    text_col = text_col or _detect_column(df, _TEXT_COLUMNS, "text")
    label_col = label_col or _detect_column(df, _LABEL_COLUMNS, "label")
    log.info("TRAM columns -> text='%s', label='%s'", text_col, label_col)

    merged: Dict[str, set] = {}
    for _, row in df.iterrows():
        text = (row[text_col] or "").strip()
        if not text:
            continue
        ids = set(TECHNIQUE_ID_RE.findall(row[label_col] or ""))
        if not ids:
            continue
        key = " ".join(text.split())  # normalise whitespace for de-dup
        merged.setdefault(key, set()).update(ids)

    samples = [Sample(text=t, technique_ids=sorted(ids)) for t, ids in merged.items()]
    log.info("Loaded %d unique TRAM samples from %d rows.", len(samples), len(df))
    if not samples:
        raise ValueError("No (text, technique-id) pairs found — check the columns.")
    return samples


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------
class TRAMDataset(AttackDataset):
    """Tokenised TRAM examples with hierarchical multi-hot targets.

    Reuses ``AttackDataset``'s tokenisation + multi-hot machinery; only the
    default ``max_length`` differs (512 for full CTI paragraphs).
    """

    def __init__(self, samples: List[Sample], tokenizer, taxonomy: Taxonomy,
                 max_length: int = 512):
        super().__init__(samples, tokenizer, taxonomy, max_len=max_length)


# ---------------------------------------------------------------------------
# Imbalance handling
# ---------------------------------------------------------------------------
def compute_class_weights(samples: List[Sample], tax: Taxonomy,
                          tactic_cap: float = 20.0, technique_cap: float = 50.0
                          ) -> Dict[str, object]:
    """Per-label ``pos_weight = negatives / positives``.

    Rare techniques get a large weight, so BCEWithLogitsLoss penalises the model
    far more for missing them — the standard remedy for TRAM's long-tail
    imbalance. Capped to avoid runaway gradients on near-zero-support labels.
    """
    n = len(samples)
    tech_pos = np.zeros(tax.num_techniques, dtype=np.float64)
    tac_pos = np.zeros(tax.num_tactics, dtype=np.float64)
    for s in samples:
        for tid in s.technique_ids:
            j = tax.technique2idx.get(tid)
            if j is None:
                continue
            tech_pos[j] += 1
            for ai in tax.technique_tactic_indices(tid):
                tac_pos[ai] += 1

    tech_w = np.clip((n - tech_pos) / np.clip(tech_pos, 1.0, None), 0.1, technique_cap)
    tac_w = np.clip((n - tac_pos) / np.clip(tac_pos, 1.0, None), 0.1, tactic_cap)

    # Report the rarest few techniques so the imbalance is visible in logs.
    order = np.argsort(tech_pos)
    rare = [(tax.techniques[i], int(tech_pos[i]), round(float(tech_w[i]), 2))
            for i in order[:5]]
    log.info("Class imbalance — rarest techniques (id, count, pos_weight): %s", rare)

    return {
        "technique_pos_weight": torch.tensor(tech_w, dtype=torch.float32),
        "tactic_pos_weight": torch.tensor(tac_w, dtype=torch.float32),
        "technique_freq": tech_pos,
        "tactic_freq": tac_pos,
        "n_samples": n,
    }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def build_tram_datasets(csv_path: str, tokenizer, max_length: int = 512,
                        val_split: float = config.VAL_SPLIT, seed: int = config.SEED,
                        text_col: Optional[str] = None, label_col: Optional[str] = None
                        ) -> Tuple[TRAMDataset, TRAMDataset, Taxonomy, Dict[str, object], Dict[str, int]]:
    """End-to-end: CSV -> (train_ds, val_ds, taxonomy, class_weights, stats)."""
    from .dataset import train_val_split

    samples = load_tram_csv(csv_path, text_col, label_col)

    # Technique label space = ids actually present (resolvable to a tactic).
    universe = sorted({tid for s in samples for tid in s.technique_ids})
    tax = build_taxonomy_from_techniques(universe)
    known = set(tax.technique2idx)

    # Drop unresolved ids from each sample; drop now-empty samples.
    cleaned: List[Sample] = []
    dropped_ids = set()
    for s in samples:
        ids = [t for t in s.technique_ids if t in known]
        dropped_ids.update(set(s.technique_ids) - known)
        if ids:
            cleaned.append(Sample(text=s.text, technique_ids=ids))
    if dropped_ids:
        log.warning("Dropped %d technique ids not resolvable in the MITRE corpus "
                    "(e.g. deprecated/revoked): %s ...",
                    len(dropped_ids), sorted(dropped_ids)[:8])

    train_s, val_s = train_val_split(cleaned, val_split, seed)
    class_weights = compute_class_weights(train_s, tax)

    train_ds = TRAMDataset(train_s, tokenizer, tax, max_length)
    val_ds = TRAMDataset(val_s, tokenizer, tax, max_length)
    stats = {
        "samples": len(cleaned),
        "train": len(train_s),
        "val": len(val_s),
        "techniques": tax.num_techniques,
        "tactics": tax.num_tactics,
        "sub_techniques": sum(1 for t in tax.techniques if "." in t),
    }
    log.info("TRAM datasets ready: %s", stats)
    return train_ds, val_ds, tax, class_weights, stats


# ---------------------------------------------------------------------------
# CLI: inspect a CSV without training
# ---------------------------------------------------------------------------
def main() -> None:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(description="Inspect a TRAM CSV through the data pipeline.")
    p.add_argument("csv", help="Path to the TRAM CSV.")
    p.add_argument("--text-col", default=None)
    p.add_argument("--label-col", default=None)
    p.add_argument("--max-len", type=int, default=512)
    args = p.parse_args()

    tokenizer, name = load_tokenizer()
    train_ds, val_ds, tax, weights, stats = build_tram_datasets(
        args.csv, tokenizer, args.max_len, text_col=args.text_col, label_col=args.label_col)

    print("\n=== TRAM pipeline summary ===")
    print(f"tokenizer            : {name}")
    print(f"samples (train/val)  : {stats['train']} / {stats['val']}")
    print(f"tactics / techniques : {stats['tactics']} / {stats['techniques']} "
          f"({stats['sub_techniques']} sub-techniques)")
    # Show one tensorised example.
    ex = train_ds[0]
    print(f"example input_ids len: {len(ex['input_ids'])}")
    print(f"tactic_targets sum   : {float(np.sum(ex['tactic_labels']))}")
    print(f"technique_targets sum: {float(np.sum(ex['technique_labels']))}")
    print(f"technique pos_weight : min={float(weights['technique_pos_weight'].min()):.2f} "
          f"max={float(weights['technique_pos_weight'].max()):.2f}")


if __name__ == "__main__":
    main()
