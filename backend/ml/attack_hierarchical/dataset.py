"""
attack_hierarchical.dataset
===========================
Data pipeline + feature engineering.

  * ``load_tokenizer`` — a cybersecurity-aware tokenizer (SecureBERT, falling
    back to bert-base-uncased) that keeps file paths, CVE IDs and registry keys
    reasonably intact.
  * ``build_mock_corpus`` — synthesises a TRAM/BRON-style multi-label corpus:
    each sample is a short report/log snippet labelled with one or more
    techniques. Sample *text* is generated; the *labels* and their hierarchy
    come from the real taxonomy.
  * ``AttackDataset`` — a ``torch.utils.data.Dataset`` yielding token tensors
    plus hierarchical multi-hot targets for both heads.
  * ``Collator`` — dynamic-padding collate for efficient batching.
"""
from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
from torch.utils.data import Dataset
from transformers import AutoTokenizer

from . import config
from .taxonomy import Taxonomy

log = logging.getLogger("attack_hierarchical.dataset")


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------
def load_tokenizer(name: Optional[str] = None):
    """Load the primary cyber tokenizer, transparently falling back."""
    name = name or config.TRANSFORMER_MODEL
    try:
        tok = AutoTokenizer.from_pretrained(name, use_fast=True)
        log.info("Tokenizer loaded: %s", name)
        return tok, name
    except Exception as e:  # noqa: BLE001
        log.warning("Tokenizer '%s' unavailable (%s); falling back to '%s'.",
                    name, e, config.TRANSFORMER_FALLBACK)
        tok = AutoTokenizer.from_pretrained(config.TRANSFORMER_FALLBACK, use_fast=True)
        return tok, config.TRANSFORMER_FALLBACK


# ---------------------------------------------------------------------------
# Synthetic corpus (TRAM/BRON-inspired)
# ---------------------------------------------------------------------------
@dataclass
class Sample:
    text: str
    technique_ids: List[str]


# Specialised artefacts injected so the tokenizer sees real cyber tokens.
_FILE_PATHS = [
    r"C:\Windows\System32\rundll32.exe",
    r"C:\Users\admin\AppData\Local\Temp\payload.dll",
    r"C:\ProgramData\update.vbs",
    "/etc/passwd", "/tmp/.x9", "/var/spool/cron/root", "/usr/bin/python3",
    r"C:\Windows\System32\lsass.exe",
]
_REGISTRY_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Classes\ms-settings\shell\open\command",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
]
_CVES = ["CVE-2021-44228", "CVE-2017-0144", "CVE-2020-1472", "CVE-2019-0708", "CVE-2021-34527"]
_IPS = ["10.0.0.5", "192.168.1.42", "45.77.13.201", "172.16.4.9"]
_PORTS = [443, 53, 3389, 445, 8080, 22, 4444]
_HASHES = ["e99a18c428cb38d5f260853678922e03", "5d41402abc4b2a76b9719d911017c592"]
_TOOLS = ["mimikatz", "PsExec", "Cobalt Strike", "rundll32", "certutil", "BloodHound"]

# Sentence frames; {name}/{tid}/{art} are filled per technique so the model has
# a learnable signal in this tiny synthetic regime.
_FRAMES = [
    "SOC report: the adversary performed {name} ({tid}); analysts observed {art} on the affected host.",
    "Syslog excerpt indicates {name}. Indicator {art} was recorded shortly before the alert ({tid}).",
    "Threat intel: actor leveraged {tid} — {name} — using {art} to achieve their objective.",
    "Incident timeline shows {name} behaviour ({tid}); forensic artefact: {art}.",
    "PCAP description: traffic consistent with {name} was captured involving {art} ({tid}).",
    "EDR telemetry flagged {name} ({tid}). Supporting evidence includes {art}.",
    "The campaign used {name} as a key step ({tid}); responders found {art}.",
]


def _artifact(rng: random.Random) -> str:
    pool = rng.choice([_FILE_PATHS, _REGISTRY_KEYS, _CVES, _TOOLS])
    art = rng.choice(pool)
    # Sometimes append a network artefact to densify cyber tokens.
    if rng.random() < 0.4:
        art += f" via {rng.choice(_IPS)}:{rng.choice(_PORTS)}"
    if rng.random() < 0.2:
        art += f" (sha256-like {rng.choice(_HASHES)})"
    return art


def build_mock_corpus(
    tax: Taxonomy,
    samples_per_technique: int = config.SAMPLES_PER_TECHNIQUE,
    combo_samples: int = config.COMBO_SAMPLES,
    seed: int = config.SEED,
) -> List[Sample]:
    """Generate a deterministic multi-label corpus over the taxonomy."""
    rng = random.Random(seed)
    samples: List[Sample] = []

    # Single-technique samples.
    for tid in tax.techniques:
        name = tax.technique_names[tid]
        for _ in range(samples_per_technique):
            frame = rng.choice(_FRAMES)
            text = frame.format(name=name, tid=tid, art=_artifact(rng))
            samples.append(Sample(text=text, technique_ids=[tid]))

    # Multi-technique (chained) samples to create genuine multi-label targets.
    for _ in range(combo_samples):
        k = rng.choice([2, 2, 3])
        chosen = rng.sample(tax.techniques, k)
        clauses = []
        for tid in chosen:
            name = tax.technique_names[tid]
            clauses.append(
                rng.choice([
                    f"{name} ({tid}) using {_artifact(rng)}",
                    f"{name} was observed ({tid}); see {_artifact(rng)}",
                ])
            )
        text = "Multi-stage intrusion: " + ", then ".join(clauses) + "."
        samples.append(Sample(text=text, technique_ids=chosen))

    rng.shuffle(samples)
    log.info("Mock corpus: %d samples (%d single + %d combo).",
             len(samples), len(tax.techniques) * samples_per_technique, combo_samples)
    return samples


def train_val_split(samples: List[Sample], val_split: float, seed: int) -> Tuple[List[Sample], List[Sample]]:
    rng = random.Random(seed)
    idx = list(range(len(samples)))
    rng.shuffle(idx)
    n_val = max(1, int(len(samples) * val_split))
    val_idx = set(idx[:n_val])
    train = [s for i, s in enumerate(samples) if i not in val_idx]
    val = [s for i, s in enumerate(samples) if i in val_idx]
    return train, val


# ---------------------------------------------------------------------------
# Dataset + collator
# ---------------------------------------------------------------------------
class AttackDataset(Dataset):
    """Yields tokenised text plus hierarchical multi-hot targets."""

    def __init__(self, samples: List[Sample], tokenizer, tax: Taxonomy,
                 max_len: int = config.MAX_SEQ_LEN):
        self.samples = samples
        self.tokenizer = tokenizer
        self.tax = tax
        self.max_len = max_len

    def __len__(self) -> int:
        return len(self.samples)

    def _multi_hot(self, sample: Sample) -> Tuple[np.ndarray, np.ndarray]:
        tac = np.zeros(self.tax.num_tactics, dtype=np.float32)
        tech = np.zeros(self.tax.num_techniques, dtype=np.float32)
        for tid in sample.technique_ids:
            if tid in self.tax.technique2idx:
                tech[self.tax.technique2idx[tid]] = 1.0
                for ai in self.tax.technique_tactic_indices(tid):
                    tac[ai] = 1.0
        return tac, tech

    def __getitem__(self, i: int) -> Dict:
        s = self.samples[i]
        enc = self.tokenizer(
            s.text, truncation=True, max_length=self.max_len, return_attention_mask=True,
        )
        tac, tech = self._multi_hot(s)
        return {
            "input_ids": enc["input_ids"],
            "attention_mask": enc["attention_mask"],
            "tactic_labels": tac,
            "technique_labels": tech,
        }


class Collator:
    """Dynamic-padding collate: pads to the longest item in the batch."""

    def __init__(self, tokenizer):
        self.tokenizer = tokenizer

    def __call__(self, batch: List[Dict]) -> Dict[str, torch.Tensor]:
        enc = self.tokenizer.pad(
            {
                "input_ids": [b["input_ids"] for b in batch],
                "attention_mask": [b["attention_mask"] for b in batch],
            },
            padding=True,
            return_tensors="pt",
        )
        enc["tactic_labels"] = torch.tensor(np.stack([b["tactic_labels"] for b in batch]))
        enc["technique_labels"] = torch.tensor(np.stack([b["technique_labels"] for b in batch]))
        return enc
