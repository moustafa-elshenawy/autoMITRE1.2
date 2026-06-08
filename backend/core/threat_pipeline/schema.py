"""
threat_pipeline.schema
======================
Plain dataclasses that flow between the three layers. Keeping these decoupled
from the FastAPI/Pydantic response models means the pipeline can be unit-tested
and run standalone without importing the web app.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


# ---------------------------------------------------------------------------
# Layer 1 output
# ---------------------------------------------------------------------------
@dataclass
class ExtractedRelation:
    """A single [Action] -> [Tool] -> [Target/Modifier] relationship.

    These are *linguistic* facts about the log, NOT MITRE guesses. The LLM is
    only allowed to populate these fields; it never names a technique.
    """
    action: str                      # the verb / behaviour, e.g. "dumped credentials"
    tool: Optional[str] = None       # the instrument, e.g. "mimikatz", "powershell"
    target: Optional[str] = None     # the object acted upon, e.g. "LSASS process"
    modifier: Optional[str] = None   # qualifier, e.g. "over port 443", "remotely"
    raw_phrase: Optional[str] = None # source span the relation came from

    def query_text(self) -> str:
        """Natural-language query used to embed/retrieve against MITRE."""
        parts = [p for p in (self.action, self.tool, self.target, self.modifier) if p]
        return " ".join(parts).strip()


@dataclass
class LogContext:
    """Deterministically extracted environmental facts about the telemetry.

    Unlike relations, context is parsed with regex/keyword rules (not the LLM)
    because Layer 3 must be able to trust it absolutely — a hallucinated port or
    OS would corrupt every constraint downstream.
    """
    platform: str = "unknown"               # windows | linux | macos | unknown
    ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)  # e.g. ["https", "dns"]
    uses_valid_credentials: bool = False    # log shows authenticated/valid account use
    uses_native_remote_service: bool = False  # native RDP/SSH/SMB session (not exploit)
    raw_text: str = ""


@dataclass
class Extraction:
    """Full Layer 1 output: structured relations + environmental context."""
    relations: List[ExtractedRelation] = field(default_factory=list)
    context: LogContext = field(default_factory=LogContext)
    backend: str = "fallback"  # "mlx" | "fallback" — which extractor produced this


# ---------------------------------------------------------------------------
# Layer 2 output
# ---------------------------------------------------------------------------
@dataclass
class RetrievedTechnique:
    """A MITRE technique candidate returned by the vector DB for one query."""
    id: str
    name: str
    tactic: str
    platforms: List[str]
    description: str
    similarity: float                       # cosine similarity in [0, 1]
    source_query: str = ""                  # the relation query that surfaced it


# ---------------------------------------------------------------------------
# Layer 3 output
# ---------------------------------------------------------------------------
@dataclass
class MappedTechnique:
    """Final, constraint-adjudicated technique."""
    id: str
    name: str
    tactic: str
    base_confidence: float                  # similarity-derived score before rules
    adjusted_confidence: float              # after constraint engine
    status: str                             # "accepted" | "suppressed" | "eliminated"
    reasons: List[str] = field(default_factory=list)   # human-readable rule trace
    evidence: List[str] = field(default_factory=list)  # phrases supporting the map

    def to_public_dict(self) -> Dict[str, Any]:
        """Compact dict for API consumers (accepted techniques)."""
        return {
            "id": self.id,
            "name": self.name,
            "tactic": self.tactic,
            "confidence": round(self.adjusted_confidence, 3),
            "evidence": self.evidence,
            "reasons": self.reasons,
        }


@dataclass
class PipelineResult:
    """End-to-end result of running one log through all three layers."""
    input_text: str
    extraction: Extraction
    candidates: List[RetrievedTechnique]
    mapped: List[MappedTechnique]

    def accepted(self) -> List[MappedTechnique]:
        return [m for m in self.mapped if m.status == "accepted"]

    def to_json(self) -> Dict[str, Any]:
        """The final JSON object the spec asks for."""
        return {
            "input": self.input_text,
            "context": asdict(self.extraction.context),
            "extracted_relations": [asdict(r) for r in self.extraction.relations],
            "extractor_backend": self.extraction.backend,
            "mapped_techniques": [m.to_public_dict() for m in self.accepted()],
            "suppressed": [
                {"id": m.id, "name": m.name, "reasons": m.reasons}
                for m in self.mapped
                if m.status != "accepted"
            ],
        }
