"""
attack_hierarchical.predict
===========================
Robust inference. Takes a raw, unstructured paragraph, runs it through the
hierarchical transformer classifier, verifies the top predictions with the
bi-encoder support gate, applies probability + support thresholds, and emits a
clean JSON payload.

Each emitted technique contains:
    tactic, predicted_technique_id, model_probability_score, bi_encoder_support
(plus technique_name, softmax_confidence and accepted flag).

Run from the backend root, inside the venv:

    python -m ml.attack_hierarchical.predict "powershell.exe dropped mimikatz and dumped LSASS"
    python -m ml.attack_hierarchical.predict --smoke
    echo "report text..." | python -m ml.attack_hierarchical.predict -
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, Dict, List, Optional

import numpy as np
import torch

from . import config
from .dataset import load_tokenizer
from .model import MultiLabelHierarchicalClassifier
from .reranker import SemanticVerifier
from .taxonomy import Taxonomy

log = logging.getLogger("attack_hierarchical.predict")


class HierarchicalPredictor:
    """Loads a trained checkpoint and runs the full classify -> verify pipeline."""

    def __init__(self, checkpoint_path: Optional[str] = None, device: Optional[str] = None,
                 enable_reranker: bool = True):
        import os
        self.checkpoint_path = checkpoint_path or os.path.join(
            config.OUTPUT_DIR, config.CHECKPOINT_NAME)
        self.device = config.get_device(device)
        self.enable_reranker = enable_reranker

        log.info("Loading checkpoint: %s", self.checkpoint_path)
        ckpt = torch.load(self.checkpoint_path, map_location=self.device, weights_only=False)

        self.tax = Taxonomy.from_meta(ckpt["taxonomy_meta"])
        self.prob_threshold = ckpt.get("thresholds", {}).get("prob", config.PROB_THRESHOLD)
        self.bi_threshold = ckpt.get("thresholds", {}).get("bi_encoder", config.BIENCODER_THRESHOLD)

        self.tokenizer, _ = load_tokenizer(ckpt["tokenizer_name"])
        self.model = MultiLabelHierarchicalClassifier(
            ckpt["num_tactics"], ckpt["num_techniques"], backbone_name=ckpt["backbone_name"])
        self.model.load_state_dict(ckpt["model_state"])
        self.model.to(self.device).eval()

        self.verifier = SemanticVerifier(self.tax) if enable_reranker else None

    # -- core inference -----------------------------------------------------
    @torch.no_grad()
    def _classify(self, text: str) -> Dict[str, np.ndarray]:
        enc = self.tokenizer(text, truncation=True, max_length=config.MAX_SEQ_LEN,
                             return_tensors="pt")
        enc = {k: v.to(self.device) for k, v in enc.items()
               if k in ("input_ids", "attention_mask")}
        out = self.model(**enc)
        tech_logits = out["technique_logits"][0]
        tac_logits = out["tactic_logits"][0]
        return {
            "tech_prob": torch.sigmoid(tech_logits).float().cpu().numpy(),
            # softmax over techniques -> normalised confidence across the label set
            "tech_softmax": torch.softmax(tech_logits, dim=-1).float().cpu().numpy(),
            "tac_prob": torch.sigmoid(tac_logits).float().cpu().numpy(),
        }

    def predict(self, text: str, top_k: int = config.RERANK_TOP_K, chunk_text: bool = False) -> Dict[str, Any]:
        text = (text or "").strip()
        
        if chunk_text:
            words = text.split()
            if len(words) <= 50:
                scores = self._classify(text)
            else:
                chunks = [" ".join(words[i:i + 50]) for i in range(0, len(words), 50)]
                scores = None
                for chunk in chunks:
                    chunk_scores = self._classify(chunk)
                    if scores is None:
                        scores = chunk_scores
                    else:
                        scores["tech_prob"] = np.maximum(scores["tech_prob"], chunk_scores["tech_prob"])
                        scores["tech_softmax"] = np.maximum(scores["tech_softmax"], chunk_scores["tech_softmax"])
                        scores["tac_prob"] = np.maximum(scores["tac_prob"], chunk_scores["tac_prob"])
        else:
            scores = self._classify(text)
            
        tech_prob = scores["tech_prob"]
        tech_softmax = scores["tech_softmax"]

        # Candidate set: union of (above prob threshold) and (top-k by prob), so
        # the verifier always sees a sensible shortlist even if nothing clears
        # the raw threshold.
        above = set(np.where(tech_prob >= self.prob_threshold)[0].tolist())
        topk = set(np.argsort(-tech_prob)[:top_k].tolist())
        cand_idx = sorted(above | topk, key=lambda i: -tech_prob[i])
        cand_ids = [self.tax.techniques[i] for i in cand_idx]

        support = {}
        if self.verifier is not None and cand_ids:
            support = self.verifier.verify(text, cand_ids, chunk_text=chunk_text)

        print(f"DEBUG CANDIDATES: {cand_ids}")
        results: List[Dict[str, Any]] = []
        for i in cand_idx:
            tid = self.tax.techniques[i]
            prob = float(tech_prob[i])
            bi_support = float(support.get(tid, 0.0)) if self.verifier else None
            print(f"DEBUG CANDIDATE {tid}: prob={prob}, bi_support={bi_support}")
            # Acceptance gate: high model probability AND bi-encoder agreement
            # that the text is in the technique's semantic neighbourhood. When
            # the verifier is disabled, fall back to probability alone.
            accepted = prob >= self.prob_threshold and (
                self.verifier is None or bi_support >= self.bi_threshold
            )
            tactics = self.tax.technique_tactics.get(tid, [])
            results.append({
                "tactic": tactics[0] if tactics else "Unknown",
                "all_tactics": tactics,
                "predicted_technique_id": tid,
                "technique_name": self.tax.technique_names.get(tid, tid),
                "model_probability_score": round(prob, 4),
                "softmax_confidence": round(float(tech_softmax[i]), 4),
                "bi_encoder_support": round(bi_support, 4) if bi_support is not None else None,
                "accepted": bool(accepted),
            })

        accepted = [r for r in results if r["accepted"]]
        accepted.sort(key=lambda r: (r["bi_encoder_support"] or 0,
                                     r["model_probability_score"]), reverse=True)
        return {
            "input": text,
            "device": str(self.device),
            "reranker": self.enable_reranker,
            "mapped_techniques": accepted,
            "candidates_considered": results,
        }


def _read_text(arg: Optional[str]) -> str:
    if arg == "-":
        return sys.stdin.read()
    if arg:
        return arg
    return ("Threat report: the actor sent a spearphishing attachment, then used "
            "powershell.exe to run a malicious script that loaded mimikatz "
            "(C:\\Windows\\System32\\lsass.exe) to dump credentials, and finally "
            "exfiltrated data over HTTPS to 45.77.13.201:443.")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(description="Run inference with the hierarchical ATT&CK classifier.")
    p.add_argument("text", nargs="?", default=None, help="Raw text, '-' for stdin, omit for a sample.")
    p.add_argument("--checkpoint", type=str, default=None)
    p.add_argument("--device", type=str, default=None)
    p.add_argument("--no-reranker", action="store_true", help="Skip the bi-encoder support gate.")
    p.add_argument("--smoke", action="store_true", help="Use the built-in sample text.")
    args = p.parse_args()

    text = _read_text(None if args.smoke else args.text)
    predictor = HierarchicalPredictor(
        checkpoint_path=args.checkpoint, device=args.device,
        enable_reranker=not args.no_reranker)
    payload = predictor.predict(text)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
