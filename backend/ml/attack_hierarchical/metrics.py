"""
attack_hierarchical.metrics
===========================
Evaluation metrics tuned for highly imbalanced multi-label problems:

  * Macro-F1 (every technique counts equally, regardless of support)
  * Micro-F1 (instance-weighted)
  * Macro Average-Precision (area under the per-label Precision-Recall curve —
    the right summary for rare positives, far more informative than ROC-AUC)
  * Optional PR-curve dump (per label) for offline plotting.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
)

log = logging.getLogger("attack_hierarchical.metrics")


def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5,
                    prefix: str = "") -> Dict[str, float]:
    """Compute multi-label metrics from probabilities + binary targets.

    y_true, y_prob : [N, num_labels]
    """
    y_pred = (y_prob >= threshold).astype(int)
    p = f"{prefix}_" if prefix else ""

    out: Dict[str, float] = {
        f"{p}macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        f"{p}micro_f1": float(f1_score(y_true, y_pred, average="micro", zero_division=0)),
        f"{p}macro_precision": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        f"{p}macro_recall": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
    }

    # Macro Average-Precision over labels that have at least one positive.
    aps: List[float] = []
    for j in range(y_true.shape[1]):
        if y_true[:, j].sum() > 0:
            aps.append(float(average_precision_score(y_true[:, j], y_prob[:, j])))
    out[f"{p}macro_ap"] = float(np.mean(aps)) if aps else 0.0
    return out


def pr_curves(y_true: np.ndarray, y_prob: np.ndarray, label_names: List[str],
              max_labels: Optional[int] = None) -> Dict[str, Dict[str, list]]:
    """Per-label Precision-Recall curves (for plotting / inspection)."""
    curves: Dict[str, Dict[str, list]] = {}
    cols = range(y_true.shape[1])
    count = 0
    for j in cols:
        if y_true[:, j].sum() == 0:
            continue
        precision, recall, thresholds = precision_recall_curve(y_true[:, j], y_prob[:, j])
        curves[label_names[j]] = {
            "precision": precision.tolist(),
            "recall": recall.tolist(),
            "thresholds": thresholds.tolist(),
            "average_precision": float(average_precision_score(y_true[:, j], y_prob[:, j])),
        }
        count += 1
        if max_labels and count >= max_labels:
            break
    return curves


def save_pr_plot(curves: Dict[str, Dict[str, list]], path: str, max_labels: int = 12) -> bool:
    """Save a multi-label PR-curve figure if matplotlib is available."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # noqa: BLE001
        log.warning("matplotlib unavailable (%s); skipping PR plot.", e)
        return False

    plt.figure(figsize=(8, 6))
    for i, (name, c) in enumerate(curves.items()):
        if i >= max_labels:
            break
        plt.plot(c["recall"], c["precision"], lw=1.2,
                 label=f"{name} (AP={c['average_precision']:.2f})")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Per-technique Precision-Recall curves")
    plt.legend(fontsize=7, loc="lower left")
    plt.grid(alpha=0.2)
    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close()
    log.info("Saved PR plot to %s", path)
    return True
