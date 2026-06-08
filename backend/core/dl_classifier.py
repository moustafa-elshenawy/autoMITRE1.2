"""
core.dl_classifier  —  Deep-learning ATT&CK classifier lifecycle
================================================================
Thin application-facing wrapper around the standalone
``ml.attack_hierarchical`` package. It owns the *process-wide singleton* of the
fine-tuned SecureBERT + bi-encoder predictor so the heavy 499 MB checkpoint is
loaded **once** (ideally at FastAPI startup) instead of per request.

Design goals:
  * **Safe startup.** ``load()`` never raises — if the checkpoint/transformers
    can't be loaded (e.g. memory pressure on an 8 GB M1, missing file), it logs
    a warning and leaves the service unavailable. The app still boots and the
    RAG engine keeps working; "deep_learning"/"auto"→DL requests fall back.
  * **Device aware.** Maps tensors to Apple-Silicon MPS when available, else CPU
    (CUDA in between), honouring ``AUTOMITRE_DL_DEVICE`` if set.
  * **Stable output.** ``predict_techniques()`` returns the same
    ATTACKTechnique-shaped dicts the RAG adapter emits, so the analyzer can
    consume either engine interchangeably.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

log = logging.getLogger("dl_classifier")

# Module-level singleton + a lock so a concurrent first-request can't double-load.
_predictor = None          # type: Optional[object]
_load_attempted = False
_load_error: Optional[str] = None
_lock = threading.Lock()


def _resolve_device() -> Optional[str]:
    """Explicit device override, else let the package auto-detect (MPS→CUDA→CPU)."""
    dev = os.getenv("AUTOMITRE_DL_DEVICE")
    return dev.strip() if dev else None


def load(force: bool = False) -> bool:
    """Load the predictor singleton. Returns True on success, False otherwise.

    Idempotent and exception-safe: intended to be called from the FastAPI
    lifespan handler at startup, but also self-heals if called lazily later.
    """
    global _predictor, _load_attempted, _load_error

    if os.getenv("AUTOMITRE_DL_ENABLED", "1") != "1":
        _load_error = "disabled via AUTOMITRE_DL_ENABLED=0"
        log.info("Deep-learning classifier disabled (AUTOMITRE_DL_ENABLED=0).")
        return False

    with _lock:
        if _predictor is not None and not force:
            return True
        _load_attempted = True
        try:
            # Imported lazily so a torch/transformers import error can't break
            # module import (and thus app boot).
            from ml.attack_hierarchical.predict import HierarchicalPredictor

            device = _resolve_device()
            checkpoint = os.getenv("AUTOMITRE_DL_CHECKPOINT")  # optional override
            log.info("Loading deep-learning ATT&CK classifier (device=%s)...",
                     device or "auto")
            predictor = HierarchicalPredictor(
                checkpoint_path=checkpoint,
                device=device,
                enable_reranker=True,  # bi-encoder support gate
            )
            _predictor = predictor
            _load_error = None
            log.info("Deep-learning classifier ready on device=%s.",
                     getattr(predictor, "device", "?"))

            if os.getenv("AUTOMITRE_DL_WARMUP", "0") == "1":
                try:
                    predictor.predict("powershell downloaded and ran mimikatz against lsass")
                    log.info("Deep-learning classifier warmup complete.")
                except Exception as warm_err:  # noqa: BLE001
                    log.warning("DL warmup failed (non-fatal): %s", warm_err)
            return True
        except Exception as e:  # noqa: BLE001 — never break app boot
            _predictor = None
            _load_error = str(e)
            log.warning("Deep-learning classifier unavailable, RAG remains the "
                        "fallback engine: %s", e)
            return False


def is_available() -> bool:
    return _predictor is not None


def status() -> Dict[str, Any]:
    """Lightweight health/introspection payload for diagnostics."""
    return {
        "available": _predictor is not None,
        "load_attempted": _load_attempted,
        "device": str(getattr(_predictor, "device", None)) if _predictor else None,
        "error": _load_error,
    }


def predict_techniques(text: str) -> List[Dict[str, Any]]:
    """Map raw text to accepted ATT&CK techniques via the deep-learning engine.

    Returns ATTACKTechnique-shaped dicts (id, name, tactic, confidence, verified,
    evidence). Lazily loads the model if startup preload was skipped/failed.
    Raises RuntimeError if the model genuinely cannot be loaded, so callers can
    fall back to RAG deterministically.
    """
    if _predictor is None:
        # One self-heal attempt (e.g. preload disabled); raise if still down.
        if not load():
            raise RuntimeError(f"deep-learning classifier unavailable: {_load_error}")

    payload = _predictor.predict(text)  # type: ignore[union-attr]
    out: List[Dict[str, Any]] = []
    for t in payload.get("mapped_techniques", []):
        prob = float(t.get("model_probability_score", 0.0))
        bi = t.get("bi_encoder_support")
        evidence = [f"SecureBERT probability {prob:.2f}"]
        if bi is not None:
            evidence.append(f"bi-encoder support {float(bi):.2f}")
        out.append({
            "id": t.get("predicted_technique_id"),
            "name": t.get("technique_name") or "Classified Technique",
            "tactic": t.get("tactic") or "Multiple Tactics",
            "confidence": round(prob, 3),
            "verified": True,  # cleared prob + bi-encoder support gates
            "evidence": evidence,
        })
    return out
