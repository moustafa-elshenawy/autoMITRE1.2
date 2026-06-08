"""
threat_pipeline
===============
Three-layer MITRE ATT&CK mapping engine, optimised for local execution on
Apple Silicon (M1):

    Layer 1  extractor.py     LLM-as-NLP relation extraction (mlx-lm)
    Layer 2  retriever.py     ChromaDB + sentence-transformers RAG retrieval
    Layer 3  logic_engine.py  deterministic constraint / gatekeeper engine

Public surface:

    from core.threat_pipeline import run_pipeline, map_log_to_attack_techniques
"""
from .pipeline import (
    ThreatMappingPipeline,
    pipeline,
    run_pipeline,
    map_log_to_attack_techniques,
)
from .schema import (
    Extraction,
    ExtractedRelation,
    LogContext,
    RetrievedTechnique,
    MappedTechnique,
    PipelineResult,
)

__all__ = [
    "ThreatMappingPipeline",
    "pipeline",
    "run_pipeline",
    "map_log_to_attack_techniques",
    "Extraction",
    "ExtractedRelation",
    "LogContext",
    "RetrievedTechnique",
    "MappedTechnique",
    "PipelineResult",
]
