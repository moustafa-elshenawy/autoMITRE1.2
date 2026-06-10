from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class InputType(str, Enum):
    TEXT = "text"
    JSON = "json"
    HASH = "hash"
    STIX = "stix"
    PCAP = "pcap"
    LOG = "log"


class PipelineMode(str, Enum):
    AUTO = "auto"               # intelligent intake router picks the engine
    RAG = "rag"                 # 3-layer RAG + constraint engine
    DEEP_LEARNING = "deep_learning"  # SecureBERT + bi-encoder classifier
    HYBRID = "hybrid"           # sequential ensemble: DL + RAG, merged by MITRE ID


class TextAnalysisRequest(BaseModel):
    text: str
    context: Optional[str] = None
    deep_analysis: bool = False
    # Which technique-mapping engine to use. "auto" (default) routes structured
    # telemetry to the RAG/constraint engine and prose CTI reports to the
    # SecureBERT deep-learning classifier. See core.intake_router.
    pipeline_mode: PipelineMode = PipelineMode.AUTO


class ExtractedAttack(BaseModel):
    id: str
    title: str
    description: str
    raw_snippet: str
    severity_estimate: str
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    confidence: Optional[float] = None
    payload_snippets: Optional[List[str]] = []


class ExtractedAttacksResponse(BaseModel):
    success: bool
    attacks: List[ExtractedAttack] = []
    error: Optional[str] = None


class HashLookupRequest(BaseModel):
    hash: str
    hash_type: Optional[str] = "sha256"


class ATTACKTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    tactic_id: Optional[str] = "Unknown"
    description: Optional[str] = ""
    confidence: float = Field(ge=0.0, le=1.0)
    verified: bool = False
    evidence: List[str] = []


class D3FENDCountermeasure(BaseModel):
    id: str
    name: str
    category: str
    description: str


class NISTControl(BaseModel):
    id: str
    family: str
    name: str
    description: str
    severity: str


class OWASPItem(BaseModel):
    id: str
    name: str
    description: str
    type: str  # "top10" or "asvs"


class MitigationStep(BaseModel):
    title: str
    description: str
    priority: str
    effort: str
    iac_snippet: Optional[str] = None
    iac_type: Optional[str] = None
    
    
class PredictedStep(BaseModel):
    id: int
    title: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)


class RiskScore(BaseModel):
    score: float = Field(ge=0.0, le=10.0)
    severity: SeverityLevel
    likelihood: float = Field(ge=0.0, le=5.0)
    impact: float = Field(ge=0.0, le=5.0)
    business_impact: str


class ThreatEntity(BaseModel):
    type: str  # ip, domain, hash, cve, malware
    value: str
    context: Optional[str] = None


class ThreatResult(BaseModel):
    id: str
    title: str
    description: str
    input_type: str
    risk_score: RiskScore
    entities: List[ThreatEntity] = []
    attack_techniques: List[ATTACKTechnique] = []
    defend_countermeasures: List[D3FENDCountermeasure] = []
    nist_controls: List[NISTControl] = []
    owasp_items: List[OWASPItem] = []
    mitigations: List[MitigationStep] = []
    predicted_steps: List[PredictedStep] = []
    raw_indicators: Dict[str, Any] = {}
    timestamp: str

    model_config = {
        "from_attributes": True
    }


class ThreatHistoryResponse(BaseModel):
    items: List[ThreatResult]


class AnalysisResponse(BaseModel):
    success: bool
    threat_result: Optional[ThreatResult] = None
    error: Optional[str] = None
    # Which engine processed the request and why (populated by the intake
    # router). Also mirrored into threat_result.raw_indicators["routing_decision"].
    routing_decision: Optional[Dict[str, Any]] = None


class ChatMessage(BaseModel):
    role: str  # "user" or "assistant"
    content: str


class ChatRequest(BaseModel):
    message: str
    history: List[ChatMessage] = []
    threat_context: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    suggestions: List[str] = []


class ExportRequest(BaseModel):
    threat_ids: List[str]
    format: str  # "stix", "json", "csv"
    platform: Optional[str] = None  # "splunk", "qradar", "sentinel"


class DashboardStats(BaseModel):
    total_threats: int
    critical_threats: int
    high_threats: int
    medium_threats: int
    low_threats: int
    techniques_covered: int
    frameworks_mapped: int
    risk_score_avg: float
