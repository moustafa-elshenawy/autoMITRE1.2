# attack_hierarchical — hierarchical deep-learning ATT&CK mapper

A supervised, deep-learning pipeline that maps arbitrary cybersecurity text
(threat reports, syslogs, PCAP descriptions) to MITRE ATT&CK — **no regex, no
keyword matching, no if-else technique logic**. Built with PyTorch + Hugging
Face transformers + scikit-learn, optimised for Apple Silicon (PyTorch MPS).

> This is a **distinct architecture** from `core/threat_pipeline/` (the live
> RAG + constraint engine). This package is the *trainable classifier* track:
> a transformer learns ATT&CK semantics, then a bi-encoder support gate filters
> out false positives. It is standalone (training + inference scripts); it is
> not wired into FastAPI.

## Architecture

```
                      ┌─────────────────────────────────────────────┐
 raw text ──tokenize─▶│  MultiLabelHierarchicalClassifier (model.py) │
                      │   transformer core (SecureBERT)              │
                      │   ├─ Head A: Tactics      (multi-label BCE)  │
                      │   └─ Head B: Techniques   (multi-label BCE)  │
                      └─────────────────────────────────────────────┘
                                       │ logits
                                       ▼
            HierarchicalConsistencyLoss: child prob ≤ parent prob
              (Technique→Tactic  and  Sub-technique→Technique)
                                       │ top-k by probability
                                       ▼
                      ┌─────────────────────────────────────────────┐
                      │  SemanticVerifier (reranker.py)              │
                      │   Bi-Encoder → embeds text + every ATT&CK    │
                      │   definition; cosine "support" per candidate │
                      └─────────────────────────────────────────────┘
                                       │ prob ≥ τ AND bi-support ≥ τ′
                                       ▼
                              clean JSON payload
```

## Files

| File          | Role |
|---------------|------|
| `config.py`   | Device (MPS→CUDA→CPU), model ids, hyper-params, thresholds, curated label subset |
| `taxonomy.py` | Builds the real Tactic→Technique→Sub-technique hierarchy + parent matrices from `data/mitre_attack.json` |
| `dataset.py`  | Cyber tokenizer (SecureBERT/fallback), TRAM/BRON-style **mock corpus**, `AttackDataset`, dynamic-padding collate |
| `tram_dataset.py` | **Real** CTID TRAM CSV loader: column auto-detect, technique-id parse, parent-tactic resolution, `TRAMDataset`, `compute_class_weights` (imbalance) |
| `model.py`    | `MultiLabelHierarchicalClassifier` (twin heads) + `HierarchicalConsistencyLoss` |
| `reranker.py` | `SemanticVerifier` — bi-encoder vector index over ATT&CK definitions; cosine-support acceptance gate (no cross-encoder) |
| `metrics.py`  | Macro-F1, micro-F1, macro Average-Precision, PR curves (+ optional plot) |
| `train.py`    | MPS training loop, mixed precision, per-epoch eval, best-checkpoint saving |
| `predict.py`  | Raw text → classify → bi-encoder verify → threshold → JSON |

## Setup & usage

All dependencies are already in `requirements.txt` (torch, transformers,
sentence-transformers, scikit-learn, numpy). `matplotlib` is optional, only for
`--save-pr` plots.

From the backend root, inside the venv:

```bash
# Fast end-to-end sanity check (tiny backbone, 1 epoch, CPU/MPS)
python -m ml.attack_hierarchical.train --smoke
python -m ml.attack_hierarchical.predict --smoke

# Real training on the cybersecurity backbone (downloads SecureBERT ~440MB)
python -m ml.attack_hierarchical.train --epochs 8 --batch-size 32 --save-pr

# Inference on your own text
python -m ml.attack_hierarchical.predict "powershell.exe ran mimikatz against lsass, then exfil over https"
```

## Training on the real CTID TRAM dataset

The TRAM CSV only carries Technique IDs; parent Tactics are resolved offline
from the shipped MITRE corpus (`taxonomy.resolve_parent_tactics`). Head A uses
the fixed 14 enterprise tactics; the technique label space is built from the IDs
present in your CSV.

```bash
# Inspect the pipeline without training (columns, sizes, class weights)
python -m ml.attack_hierarchical.tram_dataset path/to/tram.csv

# Fine-tune SecureBERT on TRAM, natively on the M1 (MPS)
python -m ml.attack_hierarchical.train --tram-csv path/to/tram.csv \
    --epochs 8 --batch-size 16 --max-len 256 --save-pr

# Predict with the TRAM-trained checkpoint (unchanged interface)
python -m ml.attack_hierarchical.predict "the actor dumped lsass and moved laterally over smb"
```

> **Memory note (8 GB Apple Silicon).** A full fine-tune of SecureBERT (RoBERTa-
> base, ~125M params) + AdamW fp32 optimiser state (~2 GB) is tight on an 8 GB
> M1: `--batch-size 16 --max-len 512` overruns the MPS watermark and OOMs. TRAM
> is sentence-level (mean ~40 tokens, p95 ~92), so `--max-len 128` keeps 97.6%
> of rows un-truncated. The settings that train cleanly on 8 GB:
>
> ```bash
> PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0 \
> python -m ml.attack_hierarchical.train --tram-csv path/to/tram.csv \
>     --epochs 8 --batch-size 4 --max-len 128 --save-pr
> ```
>
> `PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0` lifts the artificial allocation cap so
> the optimiser step doesn't hard-fail at the edge. ~11 min/epoch on an M1.

Column names are auto-detected (`text`/`sentence`/… and `label`/`labels`/
`mappings`/…); override with `--text-col` / `--label-col`. Technique IDs are
regex-extracted from the label cell, so comma/space/semicolon-separated or messy
formats all work, and rows sharing identical text are merged into one
multi-label example. Revoked/unknown IDs are dropped with a warning. Imbalance
is handled by per-label `pos_weight = negatives/positives`, fed straight into the
BCE terms of `HierarchicalConsistencyLoss`.

A runnable `sample_tram.csv` is included for smoke-testing:
`python -m ml.attack_hierarchical.train --smoke --tram-csv ml/attack_hierarchical/sample_tram.csv`.

## Output schema

`predict.py` emits, per accepted technique:

```json
{
  "tactic": "Credential Access",
  "predicted_technique_id": "T1003.001",
  "technique_name": "LSASS Memory",
  "model_probability_score": 0.87,
  "softmax_confidence": 0.07,
  "bi_encoder_support": 0.48,
  "accepted": true
}
```

A technique is **accepted** only if `model_probability_score ≥ PROB_THRESHOLD`
(default 0.5) **and** `bi_encoder_support ≥ BIENCODER_THRESHOLD` (default 0.40).
With `--no-reranker` the support gate is skipped and acceptance falls back to
probability alone.

## Notes on rigour

- **Hierarchy is real, text is synthetic.** The label taxonomy and parent maps
  come from the shipped MITRE corpus; only the training *sentences* are mocked
  (TRAM/BRON-style). Swap `build_mock_corpus` for a real annotated loader to
  train for production. Set `ATTACK_USE_FULL=1` to use all 600+ techniques.
- **Imbalance handling.** Per-label `pos_weight` in the BCE terms, Macro-F1 +
  macro Average-Precision (PR-AUC) as the headline metrics.
- **Apple Silicon.** Auto-targets `mps`; fp16 autocast on MPS/CUDA, bf16 on CPU.
  GradScaler is used only on CUDA (autocast on MPS needs none).
- **Graceful fallback.** If SecureBERT can't be fetched, the tokenizer and
  backbone fall back to `bert-base-uncased` automatically.
- **Why a bi-encoder gate, not a cross-encoder.** The verifier originally ran a
  `ms-marco-MiniLM` cross-encoder on each (text, definition) pair, but that model
  scored CTI-vs-ATT&CK-definition pairs at ~0.0 even for unambiguously correct
  techniques, so it rejected everything at any usable threshold. The bi-encoder's
  cosine support is the discriminative signal here — correct techniques land at
  ~0.45–0.53 while off-topic candidates sit at ~0.0, so a 0.40 floor separates
  them. Dropping the cross-encoder also removes one transformer from memory at
  inference time (helpful on the 8 GB M1). Note the candidate set is proposed by
  the **classifier**; the bi-encoder *filters* those candidates — it is a
  verification gate, not a retrieval stage.
