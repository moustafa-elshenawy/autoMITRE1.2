"""
attack_hierarchical.train
=========================
Training loop, optimised for Apple-Silicon (PyTorch MPS) with optional mixed
precision, evaluating Macro-F1 and macro Average-Precision each epoch and
checkpointing the best model.

Run from the backend root, inside the venv:

    python -m ml.attack_hierarchical.train                 # full run (SecureBERT)
    python -m ml.attack_hierarchical.train --smoke         # fast CPU sanity run
    python -m ml.attack_hierarchical.train --epochs 6 --batch-size 32
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import random
from typing import Tuple

import numpy as np
import torch
from torch.optim import AdamW
from torch.utils.data import DataLoader
from transformers import get_linear_schedule_with_warmup

from . import config
from .dataset import (
    AttackDataset,
    Collator,
    build_mock_corpus,
    load_tokenizer,
    train_val_split,
)
from .metrics import compute_metrics, pr_curves, save_pr_plot
from .model import HierarchicalConsistencyLoss, MultiLabelHierarchicalClassifier
from .taxonomy import load_taxonomy

log = logging.getLogger("attack_hierarchical.train")


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def compute_pos_weight(loader: DataLoader, num_tactics: int, num_techniques: int
                       ) -> Tuple[torch.Tensor, torch.Tensor]:
    """Per-label pos_weight = neg/pos, to counter multi-label imbalance."""
    tac_pos = torch.zeros(num_tactics)
    tech_pos = torch.zeros(num_techniques)
    n = 0
    for batch in loader:
        tac_pos += batch["tactic_labels"].sum(dim=0)
        tech_pos += batch["technique_labels"].sum(dim=0)
        n += batch["tactic_labels"].shape[0]
    tac_neg = n - tac_pos
    tech_neg = n - tech_pos
    # clamp to avoid div-by-zero and runaway weights
    tac_w = (tac_neg / tac_pos.clamp(min=1.0)).clamp(min=0.1, max=20.0)
    tech_w = (tech_neg / tech_pos.clamp(min=1.0)).clamp(min=0.1, max=20.0)
    return tac_w, tech_w


@torch.no_grad()
def evaluate(model, loader, device, tax) -> Tuple[dict, np.ndarray, np.ndarray]:
    model.eval()
    all_tac_prob, all_tac_true = [], []
    all_tech_prob, all_tech_true = [], []
    for batch in loader:
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        out = model(input_ids, attention_mask)
        all_tac_prob.append(torch.sigmoid(out["tactic_logits"]).float().cpu().numpy())
        all_tech_prob.append(torch.sigmoid(out["technique_logits"]).float().cpu().numpy())
        all_tac_true.append(batch["tactic_labels"].numpy())
        all_tech_true.append(batch["technique_labels"].numpy())

    tac_prob = np.concatenate(all_tac_prob)
    tac_true = np.concatenate(all_tac_true)
    tech_prob = np.concatenate(all_tech_prob)
    tech_true = np.concatenate(all_tech_true)

    metrics = {}
    metrics.update(compute_metrics(tac_true, tac_prob, config.PROB_THRESHOLD, prefix="tactic"))
    metrics.update(compute_metrics(tech_true, tech_prob, config.PROB_THRESHOLD, prefix="technique"))
    return metrics, tech_true, tech_prob


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train the hierarchical ATT&CK classifier.")
    p.add_argument("--epochs", type=int, default=config.EPOCHS)
    p.add_argument("--batch-size", type=int, default=config.BATCH_SIZE)
    p.add_argument("--lr", type=float, default=config.LEARNING_RATE)
    p.add_argument("--max-len", type=int, default=None,
                   help="Token max length (default 512 for TRAM, else config.MAX_SEQ_LEN).")
    p.add_argument("--tram-csv", type=str, default=None,
                   help="Train on a real TRAM CSV instead of the synthetic corpus.")
    p.add_argument("--text-col", type=str, default=None, help="TRAM text column override.")
    p.add_argument("--label-col", type=str, default=None, help="TRAM label column override.")
    p.add_argument("--model", type=str, default=None, help="Override transformer backbone.")
    p.add_argument("--device", type=str, default=None, help="cpu | mps | cuda")
    p.add_argument("--out-dir", type=str, default=config.OUTPUT_DIR)
    p.add_argument("--no-amp", action="store_true", help="Disable mixed precision.")
    p.add_argument("--save-pr", action="store_true", help="Dump PR curves + plot.")
    p.add_argument("--smoke", action="store_true",
                   help="Tiny fast run (bert-tiny, 1 epoch, small corpus) to validate the pipeline.")
    return p.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = build_args()

    # Smoke mode: shrink everything and use a tiny public backbone.
    if args.smoke:
        args.model = args.model or "google/bert_uncased_L-2_H-128_A-2"
        args.epochs = 1
        args.batch_size = 16
        args.max_len = 64
        config.SAMPLES_PER_TECHNIQUE = 6
        config.COMBO_SAMPLES = 40
        log.info("SMOKE MODE: backbone=%s, 1 epoch, tiny corpus.", args.model)

    set_seed(config.SEED)
    device = config.get_device(args.device)
    use_amp, amp_dtype = (False, None) if args.no_amp else config.amp_settings(device)
    log.info("Device: %s | AMP: %s (%s)", device, use_amp, amp_dtype)

    # --- data ---
    tokenizer, tok_name = load_tokenizer(args.model)
    max_len = args.max_len or (512 if args.tram_csv else config.MAX_SEQ_LEN)
    dataset_weights = None

    if args.tram_csv:
        # Real-world TRAM corpus: taxonomy + class weights come from the data.
        from .tram_dataset import build_tram_datasets
        train_ds, val_ds, tax, dataset_weights, stats = build_tram_datasets(
            args.tram_csv, tokenizer, max_length=max_len,
            val_split=config.VAL_SPLIT, seed=config.SEED,
            text_col=args.text_col, label_col=args.label_col)
        log.info("TRAM training: %s", stats)
    else:
        # Synthetic corpus over the curated taxonomy.
        tax = load_taxonomy()
        samples = build_mock_corpus(tax)
        train_s, val_s = train_val_split(samples, config.VAL_SPLIT, config.SEED)
        train_ds = AttackDataset(train_s, tokenizer, tax, max_len)
        val_ds = AttackDataset(val_s, tokenizer, tax, max_len)

    collate = Collator(tokenizer)
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True, collate_fn=collate)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False, collate_fn=collate)
    log.info("Train %d / Val %d samples | max_len=%d", len(train_ds), len(val_ds), max_len)

    # --- model + loss ---
    model = MultiLabelHierarchicalClassifier(tax.num_tactics, tax.num_techniques,
                                             backbone_name=args.model).to(device)
    # Prefer the TRAM-computed class weights; otherwise derive from the loader.
    if dataset_weights is not None:
        tac_w = dataset_weights["tactic_pos_weight"]
        tech_w = dataset_weights["technique_pos_weight"]
    else:
        tac_w, tech_w = compute_pos_weight(train_loader, tax.num_tactics, tax.num_techniques)
    criterion = HierarchicalConsistencyLoss(
        torch.from_numpy(tax.tactic_parent_matrix),
        torch.from_numpy(tax.base_parent_matrix),
        pos_weight_tactic=tac_w.to(device),
        pos_weight_technique=tech_w.to(device),
    ).to(device)

    optimizer = AdamW(model.parameters(), lr=args.lr, weight_decay=config.WEIGHT_DECAY)
    total_steps = max(1, len(train_loader) * args.epochs)
    scheduler = get_linear_schedule_with_warmup(
        optimizer, int(total_steps * config.WARMUP_RATIO), total_steps)
    # GradScaler is CUDA-only; MPS/CPU autocast runs without it.
    scaler = torch.amp.GradScaler("cuda", enabled=(use_amp and device.type == "cuda"))

    best_f1 = -1.0
    os.makedirs(args.out_dir, exist_ok=True)
    ckpt_path = os.path.join(args.out_dir, config.CHECKPOINT_NAME)

    for epoch in range(1, args.epochs + 1):
        model.train()
        running = 0.0
        for step, batch in enumerate(train_loader, 1):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            y_tac = batch["tactic_labels"].to(device)
            y_tech = batch["technique_labels"].to(device)

            optimizer.zero_grad(set_to_none=True)
            try:
                if use_amp:
                    with torch.autocast(device_type=device.type, dtype=amp_dtype):
                        out = model(input_ids, attention_mask)
                        loss, comps = criterion(out["tactic_logits"], out["technique_logits"],
                                                y_tac, y_tech)
                else:
                    out = model(input_ids, attention_mask)
                    loss, comps = criterion(out["tactic_logits"], out["technique_logits"],
                                            y_tac, y_tech)
            except RuntimeError as e:
                if use_amp:
                    log.warning("autocast failed (%s); disabling AMP and retrying fp32.", e)
                    use_amp = False
                    out = model(input_ids, attention_mask)
                    loss, comps = criterion(out["tactic_logits"], out["technique_logits"],
                                            y_tac, y_tech)
                else:
                    raise

            if scaler.is_enabled():
                scaler.scale(loss).backward()
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(optimizer)
                scaler.update()
            else:
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
            scheduler.step()

            running += comps["loss"]
            if step % 20 == 0:
                log.info("epoch %d step %d/%d loss=%.4f (bce_a=%.3f bce_b=%.3f cons_tac=%.3f cons_sub=%.3f)",
                         epoch, step, len(train_loader), comps["loss"], comps["bce_tactic"],
                         comps["bce_technique"], comps["consistency_tactic"], comps["consistency_subtech"])

        metrics, tech_true, tech_prob = evaluate(model, val_loader, device, tax)
        log.info("[epoch %d] train_loss=%.4f | tactic_macroF1=%.3f technique_macroF1=%.3f "
                 "technique_macroAP=%.3f", epoch, running / max(1, len(train_loader)),
                 metrics["tactic_macro_f1"], metrics["technique_macro_f1"], metrics["technique_macro_ap"])

        if metrics["technique_macro_f1"] >= best_f1:
            best_f1 = metrics["technique_macro_f1"]
            torch.save(
                {
                    "model_state": model.state_dict(),
                    "backbone_name": model.backbone_name,
                    "tokenizer_name": tok_name,
                    "num_tactics": tax.num_tactics,
                    "num_techniques": tax.num_techniques,
                    "taxonomy_meta": tax.to_meta(),
                    "metrics": metrics,
                    "thresholds": {
                        "prob": config.PROB_THRESHOLD,
                        "bi_encoder": config.BIENCODER_THRESHOLD,
                    },
                },
                ckpt_path,
            )
            log.info("  ✓ saved best checkpoint (technique macro-F1=%.3f) -> %s", best_f1, ckpt_path)

    # Optional PR-curve artefacts from the final epoch's validation predictions.
    if args.save_pr:
        curves = pr_curves(tech_true, tech_prob, tax.techniques, max_labels=20)
        with open(os.path.join(args.out_dir, "pr_curves.json"), "w") as fh:
            json.dump(curves, fh, indent=2)
        save_pr_plot(curves, os.path.join(args.out_dir, "pr_curves.png"))

    log.info("Done. Best technique macro-F1: %.3f", best_f1)


if __name__ == "__main__":
    main()
