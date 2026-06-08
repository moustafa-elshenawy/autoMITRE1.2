"""
attack_hierarchical.config
==========================
Central configuration for the hierarchical deep-learning ATT&CK mapper:
device selection (Apple-Silicon MPS first), model identifiers, hyper-parameters,
decision thresholds, paths, and the curated label sub-space used by the mock
training corpus.

Everything is overridable via environment variables so the same code trains a
full run on a workstation and a fast smoke run in CI.
"""
from __future__ import annotations

import os
import logging

import torch

log = logging.getLogger("attack_hierarchical.config")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# backend/ml/attack_hierarchical/config.py -> backend/
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))

DATA_DIR = os.path.join(BACKEND_ROOT, "data")
# Real MITRE corpus shipped with the app — used to build the *label taxonomy*
# (the hierarchy is real even though the training *samples* are synthetic).
MITRE_ATTACK_JSON = os.path.join(DATA_DIR, "mitre_attack.json")

OUTPUT_DIR = os.getenv(
    "ATTACK_OUTPUT_DIR", os.path.join(BACKEND_ROOT, "models", "attack_hierarchical")
)
CHECKPOINT_NAME = "hierarchical_classifier.pt"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
# Primary transformer core: a cybersecurity-pretrained encoder. SecureBERT is
# RoBERTa-based and tokenizes file paths / CVE IDs / registry keys far better
# than vanilla BERT. We fall back to bert-base-uncased if it can't be fetched.
TRANSFORMER_MODEL = os.getenv("ATTACK_HF_MODEL", "ehsanaghaei/SecureBERT")
TRANSFORMER_FALLBACK = os.getenv("ATTACK_HF_FALLBACK", "google-bert/bert-base-uncased")

# Semantic verification model. A bi-encoder embeds the input and every ATT&CK
# definition into a local vector index; cosine support gates acceptance. (The
# old ms-marco cross-encoder was dropped: it under-scored CTI-vs-definition
# pairs to ~0.0 even for correct techniques, and loading it cost extra memory.)
BIENCODER_MODEL = os.getenv("ATTACK_BIENCODER", "sentence-transformers/all-mpnet-base-v2")


# ---------------------------------------------------------------------------
# Hyper-parameters
# ---------------------------------------------------------------------------
MAX_SEQ_LEN = int(os.getenv("ATTACK_MAX_LEN", "256"))
BATCH_SIZE = int(os.getenv("ATTACK_BATCH_SIZE", "16"))
EPOCHS = int(os.getenv("ATTACK_EPOCHS", "8"))
LEARNING_RATE = float(os.getenv("ATTACK_LR", "2e-5"))
WEIGHT_DECAY = float(os.getenv("ATTACK_WEIGHT_DECAY", "0.01"))
WARMUP_RATIO = float(os.getenv("ATTACK_WARMUP_RATIO", "0.1"))
DROPOUT = float(os.getenv("ATTACK_DROPOUT", "0.2"))
SEED = int(os.getenv("ATTACK_SEED", "42"))

# Hierarchical-consistency loss weights.
LAMBDA_TACTIC_CONSISTENCY = float(os.getenv("ATTACK_LAMBDA_TACTIC", "0.5"))
LAMBDA_SUBTECH_CONSISTENCY = float(os.getenv("ATTACK_LAMBDA_SUBTECH", "0.3"))

# Mixed precision (autocast). Disabled automatically on unsupported devices.
USE_AMP = os.getenv("ATTACK_AMP", "1") == "1"

# Mock-corpus controls.
SAMPLES_PER_TECHNIQUE = int(os.getenv("ATTACK_SAMPLES_PER_TECH", "24"))
COMBO_SAMPLES = int(os.getenv("ATTACK_COMBO_SAMPLES", "200"))
VAL_SPLIT = float(os.getenv("ATTACK_VAL_SPLIT", "0.15"))


# ---------------------------------------------------------------------------
# Inference thresholds
# ---------------------------------------------------------------------------
# Per-label sigmoid probability floor (multi-label) for a technique to be kept.
PROB_THRESHOLD = float(os.getenv("ATTACK_PROB_THRESHOLD", "0.5"))
# Bi-encoder cosine-support floor (0-1) the kept technique must also clear.
# Empirically, correct techniques score ~0.45-0.53 while noise scores ~0.0, so
# 0.40 cleanly separates the two.
BIENCODER_THRESHOLD = float(os.getenv("ATTACK_BIENCODER_THRESHOLD", "0.40"))
# How many top-probability techniques to score against the bi-encoder index.
RERANK_TOP_K = int(os.getenv("ATTACK_RERANK_TOP_K", "10"))


# ---------------------------------------------------------------------------
# Curated label sub-space
# ---------------------------------------------------------------------------
# The full ATT&CK matrix (600+ techniques) is intractable to demonstrate on a
# synthetic corpus, so we train over a representative, multi-tactic subset that
# deliberately includes sub-techniques to exercise the 3-level hierarchy. Set
# ATTACK_USE_FULL=1 to build the taxonomy over every technique in the JSON.
USE_FULL_TAXONOMY = os.getenv("ATTACK_USE_FULL", "0") == "1"

SUBSET_TECHNIQUE_IDS = [
    # Initial Access
    "T1190", "T1566", "T1566.001", "T1133", "T1078",
    # Execution
    "T1059", "T1059.001", "T1059.003", "T1059.004", "T1053", "T1053.005", "T1204",
    # Persistence
    "T1547", "T1547.001", "T1543", "T1543.003", "T1505", "T1505.003", "T1136",
    # Privilege Escalation / Defense Evasion
    "T1548", "T1055", "T1027", "T1070", "T1070.004", "T1112", "T1140",
    # Credential Access
    "T1003", "T1003.001", "T1110", "T1555", "T1558",
    # Discovery
    "T1046", "T1018", "T1057", "T1082", "T1083", "T1016",
    # Lateral Movement
    "T1021", "T1021.001", "T1021.004", "T1210", "T1570",
    # Collection / C2
    "T1071", "T1071.001", "T1071.004", "T1572", "T1090", "T1095", "T1105", "T1568",
    # Exfiltration / Impact
    "T1041", "T1048", "T1048.003", "T1486", "T1490", "T1567",
]


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------
def get_device(prefer: str | None = None) -> torch.device:
    """Return the best available torch device.

    Order on Apple Silicon: MPS -> CUDA -> CPU. ``prefer`` forces a specific
    backend (e.g. "cpu" for a deterministic smoke run).
    """
    if prefer:
        return torch.device(prefer)
    if torch.backends.mps.is_available():
        return torch.device("mps")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def amp_settings(device: torch.device) -> tuple[bool, "torch.dtype | None"]:
    """Resolve mixed-precision usability + dtype for a device.

    MPS and CUDA autocast to float16; CPU autocasts to bfloat16. GradScaler is
    only needed (and only works) on CUDA — train.py handles that separately.
    """
    if not USE_AMP:
        return False, None
    if device.type == "cuda":
        return True, torch.float16
    if device.type == "mps":
        return True, torch.float16
    if device.type == "cpu":
        return True, torch.bfloat16
    return False, None
