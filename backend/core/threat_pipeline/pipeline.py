"""
threat_pipeline.pipeline  —  orchestrator
=========================================
Ties the three layers together:

    raw log
       │
       ▼  Layer 1  (extractor)   relations + deterministic context
       ▼  Layer 2  (retriever)   top-K MITRE candidates by cosine similarity
       ▼  Layer 3  (logic)       constraint-adjusted final mapping
       │
       ▼  PipelineResult (-> final JSON)

``run_pipeline()`` returns the spec's JSON object. ``map_log_to_attack_techniques()``
adapts the result to the app's ATTACKTechnique-shaped dicts for FastAPI wiring.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from . import config
from .extractor import extractor
from .retriever import retriever
from .logic_engine import constraint_engine
from .schema import PipelineResult

log = logging.getLogger("threat_pipeline.pipeline")


class ThreatMappingPipeline:
    def __init__(self) -> None:
        self.extractor = extractor
        self.retriever = retriever
        self.engine = constraint_engine

    def run(self, raw_log: str, top_k: int = config.TOP_K) -> PipelineResult:
        # Layer 1 — semantic extraction (LLM as NLP) + deterministic context.
        extraction = self.extractor.extract(raw_log)
        log.debug("Layer 1: %d relations (backend=%s)", len(extraction.relations), extraction.backend)

        # Layer 2 — vector retrieval of MITRE candidates.
        self.retriever.ensure_index()
        candidates = self.retriever.retrieve_for_extraction(extraction, top_k=top_k)
        log.debug("Layer 2: %d candidate techniques", len(candidates))

        # Layer 3 — deterministic constraint engine.
        mapped = self.engine.evaluate(candidates, extraction)
        log.debug("Layer 3: %d accepted", sum(1 for m in mapped if m.status == "accepted"))

        return PipelineResult(
            input_text=raw_log,
            extraction=extraction,
            candidates=candidates,
            mapped=mapped,
        )


# App-wide singleton.
pipeline = ThreatMappingPipeline()


def run_pipeline(raw_log: str, top_k: int = config.TOP_K) -> Dict[str, Any]:
    """Run a log through all three layers and return the final JSON object."""
    return pipeline.run(raw_log, top_k=top_k).to_json()


def map_log_to_attack_techniques(raw_log: str, top_k: int = config.TOP_K) -> List[Dict[str, Any]]:
    """Adapter for the FastAPI analyzer.

    Returns accepted techniques as dicts compatible with
    ``models.schemas.ATTACKTechnique`` (id, name, tactic, confidence, verified,
    evidence). ``verified`` is True because every returned technique survived the
    deterministic constraint engine.
    """
    result = pipeline.run(raw_log, top_k=top_k)
    out: List[Dict[str, Any]] = []
    for m in result.accepted():
        out.append(
            {
                "id": m.id,
                "name": m.name,
                "tactic": m.tactic,
                "confidence": float(round(m.adjusted_confidence, 3)),
                "verified": True,
                "evidence": m.evidence,
            }
        )
    return out
