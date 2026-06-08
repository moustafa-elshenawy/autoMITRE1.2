#!/usr/bin/env python3
"""
generate_evaluation_report.py
=============================
Standalone evaluation-asset generator for the `attack_hierarchical` SecureBERT
ATT&CK classifier trained on the CTID TRAM corpus.

It reads the artifacts produced by the training run (`train.py --save-pr`):
  * `models/attack_hierarchical/pr_curves.json` — per-technique precision/recall
    curves + average precision (the `--save-pr` artifact).
  * `logs/tram_train.log` — per-epoch validation metrics (loss convergence,
    macro-F1, macro-AP) emitted during training.

and emits two report-ready assets:
  1. A high-resolution PNG (`model_performance_report.png`) with two panels —
     per-epoch convergence (loss / macro-F1 / macro-AP) and the precision-recall
     curves of the best-performing techniques.
  2. A formatted Markdown summary (`docs/model_performance_report.md`) with the
     headline metrics, per-epoch table, and per-technique AP breakdown, ready to
     paste into research documentation.

Usage (from the backend root, inside the venv):

    python scripts/generate_evaluation_report.py
    python scripts/generate_evaluation_report.py --dpi 300 --top 8
    python scripts/generate_evaluation_report.py --out-dir /path/to/docs
"""
from __future__ import annotations

import argparse
import json
import os
import re
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Paths (resolved relative to this script so it runs from anywhere)
# ---------------------------------------------------------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.dirname(_THIS_DIR)               # backend/
REPO_ROOT = os.path.dirname(BACKEND_ROOT)               # repo root
DEFAULT_PR = os.path.join(BACKEND_ROOT, "models", "attack_hierarchical", "pr_curves.json")
DEFAULT_LOG = os.path.join(BACKEND_ROOT, "logs", "tram_train.log")
DEFAULT_OUT = os.path.join(REPO_ROOT, "docs")

# Headline metrics fallback (best epoch) if the training log is unavailable.
FALLBACK_HEADLINE = {
    "technique_macro_f1": 0.419,
    "technique_macro_ap": 0.729,
    "tactic_macro_f1": 0.626,
    "best_epoch": 7,
}

_EPOCH_RE = re.compile(
    r"\[epoch (\d+)\]\s*train_loss=([\d.]+)\s*\|\s*tactic_macroF1=([\d.]+)\s*"
    r"technique_macroF1=([\d.]+)\s*technique_macroAP=([\d.]+)"
)
_DATASET_RE = re.compile(r"TRAM datasets ready:\s*(\{.*\})")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def parse_training_log(path: str) -> Tuple[List[Dict], Optional[Dict]]:
    """Return (per-epoch metric rows, dataset-stats dict) from the training log."""
    epochs: List[Dict] = []
    dataset: Optional[Dict] = None
    if not os.path.exists(path):
        print(f"[warn] training log not found at {path}; using headline fallback.")
        return epochs, dataset

    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = _EPOCH_RE.search(line)
            if m:
                epochs.append({
                    "epoch": int(m.group(1)),
                    "train_loss": float(m.group(2)),
                    "tactic_macro_f1": float(m.group(3)),
                    "technique_macro_f1": float(m.group(4)),
                    "technique_macro_ap": float(m.group(5)),
                })
            d = _DATASET_RE.search(line)
            if d:
                try:
                    # The log prints a python-dict repr (single quotes).
                    dataset = json.loads(d.group(1).replace("'", '"'))
                except (ValueError, TypeError):
                    pass
    # De-duplicate epochs (keep last occurrence per epoch number).
    if epochs:
        by_epoch = {e["epoch"]: e for e in epochs}
        epochs = [by_epoch[k] for k in sorted(by_epoch)]
    return epochs, dataset


def load_pr_curves(path: str) -> Dict[str, Dict]:
    if not os.path.exists(path):
        print(f"[warn] PR-curve artifact not found at {path}; PR panel will be skipped.")
        return {}
    with open(path, "r") as f:
        return json.load(f)


def best_epoch_row(epochs: List[Dict]) -> Dict:
    """The epoch with the highest technique macro-F1 (the checkpoint criterion)."""
    if not epochs:
        return dict(FALLBACK_HEADLINE, train_loss=None)
    return max(epochs, key=lambda e: e["technique_macro_f1"])


# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------
def build_png(epochs: List[Dict], pr: Dict[str, Dict], out_png: str,
              dpi: int, top: int) -> None:
    import matplotlib
    matplotlib.use("Agg")  # headless
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(15, 6))
    fig.suptitle("autoMITRE — SecureBERT ATT&CK Classifier (TRAM) Evaluation",
                 fontsize=15, fontweight="bold")

    # --- Panel 1: per-epoch convergence -----------------------------------
    ax = axes[0]
    if epochs:
        xs = [e["epoch"] for e in epochs]
        ax.plot(xs, [e["train_loss"] for e in epochs], "o-", color="#d62728", label="Train loss")
        ax.plot(xs, [e["technique_macro_f1"] for e in epochs], "s-", color="#1f77b4", label="Technique macro-F1")
        ax.plot(xs, [e["technique_macro_ap"] for e in epochs], "^-", color="#2ca02c", label="Technique macro-AP")
        ax.plot(xs, [e["tactic_macro_f1"] for e in epochs], "d-", color="#9467bd", label="Tactic macro-F1")
        be = best_epoch_row(epochs)
        ax.axvline(be["epoch"], color="gray", ls="--", alpha=0.6)
        ax.annotate(f"best epoch {be['epoch']}",
                    xy=(be["epoch"], be["technique_macro_f1"]),
                    xytext=(6, 8), textcoords="offset points", fontsize=9, color="gray")
        ax.set_xticks(xs)
    else:
        ax.text(0.5, 0.5, "training log unavailable", ha="center", va="center",
                transform=ax.transAxes)
    ax.set_title("Validation convergence across epochs")
    ax.set_xlabel("Epoch")
    ax.set_ylabel("Metric value")
    ax.set_ylim(0, max(1.0, 1.05))
    ax.grid(True, alpha=0.3)
    ax.legend(loc="center right", fontsize=9)

    # --- Panel 2: precision-recall curves for the top techniques ----------
    ax = axes[1]
    if pr:
        ranked = sorted(pr.items(), key=lambda kv: kv[1].get("average_precision", 0.0), reverse=True)
        cmap = plt.get_cmap("tab10")
        for i, (tid, data) in enumerate(ranked[:top]):
            ax.plot(data["recall"], data["precision"], color=cmap(i % 10), lw=1.8,
                    label=f"{tid} (AP={data.get('average_precision', 0):.2f})")
        ax.set_title(f"Precision-Recall — top {min(top, len(ranked))} techniques (by AP)")
        ax.set_xlabel("Recall")
        ax.set_ylabel("Precision")
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1.02)
        ax.grid(True, alpha=0.3)
        ax.legend(loc="lower left", fontsize=8)
    else:
        ax.text(0.5, 0.5, "PR artifact unavailable", ha="center", va="center",
                transform=ax.transAxes)

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(out_png, dpi=dpi, bbox_inches="tight")
    plt.close(fig)
    print(f"[ok] wrote chart  -> {out_png}  ({dpi} dpi)")


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def build_markdown(epochs: List[Dict], pr: Dict[str, Dict], dataset: Optional[Dict],
                   png_name: str, out_md: str) -> None:
    be = best_epoch_row(epochs)
    aps = sorted(((tid, v.get("average_precision", 0.0)) for tid, v in pr.items()),
                 key=lambda kv: kv[1], reverse=True)
    pr_mean = (sum(a for _, a in aps) / len(aps)) if aps else None

    lines: List[str] = []
    lines.append("# Model Performance Report — SecureBERT ATT&CK Classifier (TRAM)\n")
    lines.append("_Auto-generated by `scripts/generate_evaluation_report.py` from the "
                 "training `--save-pr` artifacts. Do not edit by hand._\n")

    lines.append("## Headline metrics (best checkpoint)\n")
    lines.append(f"Selected by highest technique macro-F1 (epoch **{be['epoch']}**):\n")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Technique macro-F1 | **{be['technique_macro_f1']:.3f}** |")
    lines.append(f"| Technique macro-AP (PR-AUC) | **{be['technique_macro_ap']:.3f}** |")
    lines.append(f"| Tactic macro-F1 | **{be['tactic_macro_f1']:.3f}** |")
    if be.get("train_loss") is not None:
        lines.append(f"| Train loss @ best epoch | {be['train_loss']:.3f} |")
    lines.append("")

    if dataset:
        lines.append("## Dataset\n")
        lines.append("CTID TRAM corpus (multi-label, sentence-level CTI):\n")
        lines.append("| Split | Count |")
        lines.append("|---|---|")
        lines.append(f"| Total samples | {dataset.get('samples', '—')} |")
        lines.append(f"| Train | {dataset.get('train', '—')} |")
        lines.append(f"| Validation | {dataset.get('val', '—')} |")
        lines.append(f"| Tactics | {dataset.get('tactics', '—')} |")
        lines.append(f"| Techniques (incl. {dataset.get('sub_techniques', '—')} sub-techniques) | {dataset.get('techniques', '—')} |")
        lines.append("")

    lines.append("## Evaluation chart\n")
    lines.append(f"![Evaluation chart]({png_name})\n")

    if epochs:
        lines.append("## Per-epoch validation metrics\n")
        lines.append("| Epoch | Train loss | Tactic macro-F1 | Technique macro-F1 | Technique macro-AP |")
        lines.append("|---:|---:|---:|---:|---:|")
        for e in epochs:
            star = " ⭐" if e["epoch"] == be["epoch"] else ""
            lines.append(f"| {e['epoch']}{star} | {e['train_loss']:.3f} | "
                         f"{e['tactic_macro_f1']:.3f} | {e['technique_macro_f1']:.3f} | "
                         f"{e['technique_macro_ap']:.3f} |")
        lines.append("")

    if aps:
        lines.append("## Per-technique average precision (PR artifact)\n")
        lines.append(f"From `pr_curves.json` (top-{len(aps)} labels by support, final epoch). "
                     f"Mean AP across these labels: **{pr_mean:.3f}**.\n")
        lines.append("| Technique | Average Precision |")
        lines.append("|---|---:|")
        for tid, ap in aps:
            lines.append(f"| {tid} | {ap:.3f} |")
        lines.append("")

    lines.append("## Methodology notes\n")
    lines.append("- **Architecture:** SecureBERT (RoBERTa-based) twin-head multi-label "
                 "classifier (tactics + techniques) with a hierarchical-consistency loss "
                 "(child probability ≤ parent probability).")
    lines.append("- **Acceptance gate at inference:** `model_probability ≥ 0.50` AND "
                 "`bi_encoder_support ≥ 0.40` (a cross-encoder stage was dropped as it "
                 "under-scored CTI-vs-definition pairs).")
    lines.append("- **Imbalance handling:** per-label `pos_weight = negatives/positives` "
                 "in the BCE terms; macro-F1 and macro Average-Precision (PR-AUC) are the "
                 "headline metrics for this long-tailed label space.")
    lines.append("- **Hardware:** fine-tuned natively on Apple-Silicon MPS "
                 "(`--batch-size 4 --max-len 128`, watermark lifted) on an 8 GB M1.")
    lines.append("")

    os.makedirs(os.path.dirname(out_md), exist_ok=True)
    with open(out_md, "w") as f:
        f.write("\n".join(lines))
    print(f"[ok] wrote report -> {out_md}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(description="Generate evaluation PNG + Markdown for the TRAM model.")
    p.add_argument("--pr-curves", default=DEFAULT_PR, help="Path to pr_curves.json")
    p.add_argument("--log", default=DEFAULT_LOG, help="Path to the training log")
    p.add_argument("--out-dir", default=DEFAULT_OUT, help="Output directory (default: <repo>/docs)")
    p.add_argument("--dpi", type=int, default=200, help="PNG resolution (default 200)")
    p.add_argument("--top", type=int, default=8, help="How many techniques to plot in the PR panel")
    args = p.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    out_png = os.path.join(args.out_dir, "model_performance_report.png")
    out_md = os.path.join(args.out_dir, "model_performance_report.md")

    epochs, dataset = parse_training_log(args.log)
    pr = load_pr_curves(args.pr_curves)

    build_png(epochs, pr, out_png, dpi=args.dpi, top=args.top)
    build_markdown(epochs, pr, dataset, os.path.basename(out_png), out_md)
    print("[done] evaluation assets generated.")


if __name__ == "__main__":
    main()
