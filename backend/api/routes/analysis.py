"""
Analysis API Routes
Handles all threat analysis endpoints.
"""
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, BackgroundTasks
from typing import Optional
import json

from models.schemas import (
    TextAnalysisRequest, HashLookupRequest, AnalysisResponse,
    ThreatResult, ChatRequest, ChatResponse
)
from core.input_processor import process_input, InputType
from core.framework_mapper import map_all_frameworks
from core.ai_chat_engine import generate_chat_response
from core.pipelines import (
    analyze_text_pipeline,
    analyze_pcap_pipeline,
    extract_pcap_attacks_pipeline,
    analyze_hash_pipeline,
    analyze_csv_pipeline,
    extract_csv_attacks_pipeline,
    analyze_htm_pipeline,
    extract_htm_attacks_pipeline
)
from core.pipelines.json_pipeline import analyze_json_pipeline, extract_json_attacks_pipeline
from sqlalchemy.ext.asyncio import AsyncSession
import os
import uuid
from fastapi import Depends
from database.config import get_db
from database.crud import create_threat_record
from api.dependencies import get_current_user, get_workspace, WorkspaceState
from database.models import User
from core.audit import log_event

router = APIRouter(prefix="/api/analyze", tags=["analysis"])


def map_record_to_result(r) -> ThreatResult:
    """Map a database ThreatRecord to a ThreatResult schema."""
    return ThreatResult(
        id=r.id,
        title=r.title,
        description=r.description or "",
        input_type=r.input_type or "text",
        risk_score={
            "score": r.risk_score,
            "severity": r.severity,
            "likelihood": r.likelihood,
            "impact": r.impact_score,
            "business_impact": r.business_impact or ""
        },
        entities=[{"type": e.type, "value": e.value, "context": e.context} for e in r.entities],
        attack_techniques=[{"id": t.technique_id, "name": t.name, "tactic": t.tactic, "tactic_id": t.tactic_id, "description": t.description, "confidence": t.confidence, "verified": getattr(t, 'verified', False), "evidence": getattr(t, 'evidence', [])} for t in r.techniques],
        defend_countermeasures=r.defend_json or [],
        nist_controls=r.nist_json or [],
        owasp_items=r.owasp_json or [],
        mitigations=[{"title": m.title, "description": m.description, "priority": m.priority, "effort": m.effort, "iac_snippet": m.iac_snippet, "iac_type": m.iac_type} for m in r.mitigations],
        predicted_steps=[{"id": s.step_id, "title": s.title, "description": s.description, "confidence": s.confidence} for s in r.predicted_steps],
        raw_indicators=r.raw_indicators or {},
        timestamp=r.timestamp.isoformat() if hasattr(r.timestamp, "isoformat") else str(r.timestamp)
    )


def enrich_threat_result(threat: ThreatResult, technique_ids: list) -> ThreatResult:
    """Enrich a threat result with framework mappings."""
    from core.osint_client import RUNTIME_CONFIG
    
    # Check framework toggles from settings
    attack_enabled = str(RUNTIME_CONFIG.get("framework_attack", "True")).lower() == "true"
    defend_enabled = str(RUNTIME_CONFIG.get("framework_defend", "True")).lower() == "true"
    nist_enabled   = str(RUNTIME_CONFIG.get("framework_nist", "True")).lower() == "true"
    owasp_enabled  = str(RUNTIME_CONFIG.get("framework_owasp", "True")).lower() == "true"

    if attack_enabled:
        mappings = map_all_frameworks(technique_ids)
        threat.defend_countermeasures = mappings['defend'] if defend_enabled else []
        threat.nist_controls = mappings['nist'] if nist_enabled else []
        threat.owasp_items = mappings['owasp'] if owasp_enabled else []
    else:
        # If ATT&CK is disabled, usually everything else also fails as they map FROM attack IDs
        threat.attack_techniques = []
        threat.defend_countermeasures = []
        threat.nist_controls = []
        threat.owasp_items = []
        
    return threat


@router.post("/text", response_model=AnalysisResponse)
async def analyze_text(request: TextAnalysisRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user), workspace: WorkspaceState = Depends(get_workspace)):
    """Analyze a text description of a threat."""
    try:
        processed = process_input(request.text, InputType.TEXT)
        pipeline_mode = request.pipeline_mode.value if hasattr(request.pipeline_mode, "value") else str(request.pipeline_mode)
        threat = analyze_text_pipeline(processed, deep_analysis=request.deep_analysis, pipeline_mode=pipeline_mode)
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        threat = enrich_threat_result(threat, technique_ids)

        routing_decision = threat.raw_indicators.get('routing_decision')
        await create_threat_record(db, threat, current_user.id, group_id=workspace.group_id)
        background_tasks.add_task(log_event,
            category="ANALYSIS", action="analyze_text",
            user_id=current_user.id, username=current_user.username,
            details={"threat_id": threat.id, "severity": threat.risk_score.get("severity") if isinstance(threat.risk_score, dict) else None, "techniques": len(threat.attack_techniques), "engine": (routing_decision or {}).get("engine_used") or (routing_decision or {}).get("engine")}
        )
        return AnalysisResponse(success=True, threat_result=threat, routing_decision=routing_decision)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/hash", response_model=AnalysisResponse)
async def analyze_hash(request: HashLookupRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user), workspace: WorkspaceState = Depends(get_workspace)):
    """Look up a malware hash on VirusTotal and analyze it."""
    try:
        threat = analyze_hash_pipeline(request.hash)
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        threat = enrich_threat_result(threat, technique_ids)

        await create_threat_record(db, threat, current_user.id, group_id=workspace.group_id)
        background_tasks.add_task(log_event,
            category="ANALYSIS", action="analyze_hash",
            user_id=current_user.id, username=current_user.username,
            details={"hash": request.hash, "verdict": threat.raw_indicators.get("virustotal", {}).get("verdict", "unknown"), "detection_ratio": threat.raw_indicators.get("virustotal", {}).get("detection_ratio", "0/0")}
        )
        return AnalysisResponse(success=True, threat_result=threat)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/json")
async def analyze_json(request: TextAnalysisRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user), workspace: WorkspaceState = Depends(get_workspace)):
    """Analyze a JSON snippet deeply using the isolated pipeline."""
    try:
        from core.pipelines.json_pipeline import analyze_json_pipeline
        threat = analyze_json_pipeline(request.text, request.context, request.suggested_techniques, request.suggested_severity)
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        
        await create_threat_record(db, threat, current_user.id, group_id=workspace.group_id)
        background_tasks.add_task(log_event,
            category="ANALYSIS", action="analyze_json",
            user_id=current_user.id, username=current_user.username,
            details={"description": "Analyzed structured JSON"}
        )
        return AnalysisResponse(success=True, threat_result=threat)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pcap")
async def analyze_pcap(request: TextAnalysisRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user), workspace: WorkspaceState = Depends(get_workspace)):
    """Analyze a PCAP snippet deeply using the isolated pipeline."""
    try:
        from core.pipelines.pcap_pipeline import analyze_pcap_pipeline
        threat = analyze_pcap_pipeline(request.text, request.context, request.suggested_techniques, request.suggested_severity)
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        
        await create_threat_record(db, threat, current_user.id, group_id=workspace.group_id)
        background_tasks.add_task(log_event,
            category="ANALYSIS", action="analyze_pcap",
            user_id=current_user.id, username=current_user.username,
            details={"description": "Analyzed PCAP packet stream"}
        )
        return AnalysisResponse(success=True, threat_result=threat)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/csv")
async def analyze_csv(request: TextAnalysisRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user), workspace: WorkspaceState = Depends(get_workspace)):
    """Analyze a CSV snippet deeply using the isolated pipeline."""
    try:
        from core.pipelines.csv_pipeline import analyze_csv_pipeline
        threat = analyze_csv_pipeline(request.text, request.context, request.suggested_techniques, request.suggested_severity)
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        threat = enrich_threat_result(threat, technique_ids)
        
        await create_threat_record(db, threat, current_user.id, group_id=workspace.group_id)
        background_tasks.add_task(log_event,
            category="ANALYSIS", action="analyze_csv",
            user_id=current_user.id, username=current_user.username,
            details={"description": "Analyzed structured CSV"}
        )
        return AnalysisResponse(success=True, threat_result=threat)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tmt")
async def analyze_tmt(request: TextAnalysisRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user), workspace: WorkspaceState = Depends(get_workspace)):
    """Analyze a Microsoft TMT threat snippet using the isolated TMT pipeline."""
    try:
        from core.pipelines.tmt_pipeline import analyze_tmt_pipeline
        threat = analyze_tmt_pipeline(request.text, request.context, request.suggested_techniques, request.suggested_severity)
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        threat = enrich_threat_result(threat, technique_ids)

        await create_threat_record(db, threat, current_user.id, group_id=workspace.group_id)
        background_tasks.add_task(log_event,
            category="ANALYSIS", action="analyze_tmt",
            user_id=current_user.id, username=current_user.username,
            details={"description": "Analyzed Microsoft TMT threat block"}
        )
        return AnalysisResponse(success=True, threat_result=threat)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@router.post("/extract-attacks", response_model=None) # Returning ExtractedAttacksResponse
async def extract_attacks(file: UploadFile = File(...), context: Optional[str] = Form(None), db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Analyze an uploaded file and extract a list of discrete attacks."""
    try:
        filename = file.filename.lower() if file.filename else ""
        content = await file.read()
        
        from models.schemas import ExtractedAttacksResponse, ExtractedAttack
        
        # Binary PCAP routing (support common extensions or magic bytes)
        pcap_exts = (".pcap", ".pcapng", ".cap", ".dmp")
        is_pcap = filename.endswith(pcap_exts)
        
        valid_magics = [
            b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',  # Standard PCAP (microsecond)
            b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d',  # Nanosecond PCAP
            b'\x0a\x0d\x0d\x0a'                        # PCAPNG
        ]
        if len(content) >= 4 and content[:4] in valid_magics:
            is_pcap = True
            
        if is_pcap:
            temp_path = f"/tmp/{uuid.uuid4()}_{filename if filename else 'upload.pcap'}"
            with open(temp_path, "wb") as f:
                f.write(content)
            
            try:
                validated_attacks = extract_pcap_attacks_pipeline(temp_path, context)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                
            return ExtractedAttacksResponse(success=True, attacks=validated_attacks)

        # TMT Routing (Microsoft TMT reports)
        is_tmt = filename.endswith(".htm") or filename.endswith(".html")
        if is_tmt:
            print("!!! ROUTER HIT - TMT ROUTE (EXTRACT): ", filename, " !!!")
            temp_path = f"/tmp/{uuid.uuid4()}_{filename if filename else 'upload.htm'}"
            with open(temp_path, "wb") as f:
                f.write(content)
            try:
                from core.pipelines.tmt_pipeline import extract_tmt_attacks_pipeline
                validated_attacks = extract_tmt_attacks_pipeline(temp_path, context)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            return ExtractedAttacksResponse(success=True, attacks=validated_attacks)

        # CSV Routing
        is_csv = filename.endswith(".csv") or getattr(file, 'content_type', '') == "text/csv"
        if is_csv:
            print("!!! ROUTER HIT - CSV ROUTE (EXTRACT): ", filename, " !!!")
            temp_path = f"/tmp/{uuid.uuid4()}_{filename if filename else 'upload.csv'}"
            with open(temp_path, "wb") as f:
                f.write(content)
            
            try:
                validated_attacks = extract_csv_attacks_pipeline(temp_path, context)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                
            return ExtractedAttacksResponse(success=True, attacks=validated_attacks)

        # JSON Routing
        is_json = filename.endswith(".json") or file.content_type == "application/json"
        if is_json:
            print("!!! ROUTER HIT - JSON FALLTHROUGH: ", filename, " !!!")
            temp_path = f"/tmp/{uuid.uuid4()}_{filename if filename else 'upload.json'}"
            with open(temp_path, "wb") as f:
                f.write(content)
            
            try:
                validated_attacks = extract_json_attacks_pipeline(temp_path, context)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                
            return ExtractedAttacksResponse(success=True, attacks=validated_attacks)

        # Handle Standard Text Logs
        print("!!! ROUTER HIT - GENERIC TEXT FALLBACK: ", filename, " !!!")
        trimmed_content = content[:2000000] # 2MB absolute cap
        text_content = trimmed_content.decode('utf-8', errors='ignore')
        
        if context:
            text_content = f"Context: {context}\n\n{text_content}"
            
        from core.nano_llm_engine import nano_llm
        attacks = nano_llm.identify_attacks(text_content)
        
        validated_attacks = [ExtractedAttack(**a) for a in attacks]
        
        return ExtractedAttacksResponse(success=True, attacks=validated_attacks)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

from pydantic import BaseModel

class ToolImportRequest(BaseModel):
    tool_type: str # "iriusrisk" or "threat_dragon"
    url: str
    api_token: Optional[str] = None
    project_id: Optional[str] = None
    context: Optional[str] = None

@router.post("/import-tool-api", response_model=None)
async def import_tool_api(request: ToolImportRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Fetch external Threat Models directly from an API and extract attacks via LLM."""
    try:
        from core.threat_model_api import fetch_iriusrisk_threats, fetch_threat_dragon_url
        from core.nano_llm_engine import nano_llm
        from models.schemas import ExtractedAttacksResponse, ExtractedAttack
        
        raw_text = ""
        if request.tool_type == "iriusrisk":
            if not request.api_token or not request.project_id:
                raise ValueError("IriusRisk requires both API Token and Project ID.")
            raw_text = await fetch_iriusrisk_threats(request.url, request.api_token, request.project_id)
        elif request.tool_type == "threat_dragon":
            raw_text = await fetch_threat_dragon_url(request.url)
        else:
            raise ValueError(f"Unknown tool type: {request.tool_type}")

        if request.context:
            raw_text = f"Context: {request.context}\n\n{raw_text}"
            
        attacks = nano_llm.identify_attacks(raw_text)
        validated_attacks = [ExtractedAttack(**a) for a in attacks]
            
        if not validated_attacks:
            raise ValueError("No viable threats could be parsed from the remote source.")
            
        return ExtractedAttacksResponse(success=True, attacks=validated_attacks)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/file")
async def analyze_file(file: UploadFile = File(...), context: Optional[str] = Form(None), db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user), workspace: WorkspaceState = Depends(get_workspace)):
    """Analyze an uploaded file (JSON, STIX, text log, or PCAP)."""
    try:
        filename = file.filename.lower() if file.filename else ""
        content = await file.read()
        
        if filename.endswith(".pcap") or filename.endswith(".pcapng"):
            temp_path = f"/tmp/{uuid.uuid4()}_{filename}"
            with open(temp_path, "wb") as f:
                f.write(content)
            try:
                threat = analyze_pcap_pipeline(temp_path, context)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        elif filename.endswith(".csv") or getattr(file, 'content_type', '') == "text/csv":
            temp_path = f"/tmp/{uuid.uuid4()}_{filename}"
            with open(temp_path, "wb") as f:
                f.write(content)
            try:
                threat = analyze_csv_pipeline(temp_path, context)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        elif filename.endswith(".htm") or filename.endswith(".html"):
            temp_path = f"/tmp/{uuid.uuid4()}_{filename}"
            with open(temp_path, "wb") as f:
                f.write(content)
            try:
                from core.pipelines.tmt_pipeline import analyze_tmt_pipeline
                threat = analyze_tmt_pipeline(temp_path, context)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        else:
            text_content = content.decode('utf-8', errors='ignore')
            input_type = InputType.TEXT
            try:
                data = json.loads(text_content)
                if isinstance(data, dict) and ('objects' in data or data.get('type') == 'bundle'):
                    input_type = InputType.STIX
                else:
                    input_type = InputType.JSON
            except (json.JSONDecodeError, ValueError):
                pass
                
            processed = process_input(text_content, input_type)
            if context:
                processed['normalized_text'] = context + "\n" + processed['normalized_text']
            threat = analyze_text_pipeline(processed)
            
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        threat = enrich_threat_result(threat, technique_ids)
        
        await create_threat_record(db, threat, current_user.id, group_id=workspace.group_id)
        
        return AnalysisResponse(success=True, threat_result=threat)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/json-stix")
async def analyze_json_stix(request: TextAnalysisRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user), workspace: WorkspaceState = Depends(get_workspace)):
    """Analyze JSON or STIX threat intelligence."""
    try:
        processed = process_input(request.text, InputType.JSON)
        threat = analyze_threat(processed)
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        threat = enrich_threat_result(threat, technique_ids)
        
        await create_threat_record(db, threat, current_user.id, group_id=workspace.group_id)
        
        return AnalysisResponse(success=True, threat_result=threat)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@router.get("/threats/{threat_id}", response_model=ThreatResult)
async def get_threat_record(threat_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Fetch a historical threat record by ID."""
    from database.crud import get_threat_by_id
    record = await get_threat_by_id(db, threat_id)
    if not record:
        raise HTTPException(status_code=404, detail="Threat record not found.")
    
    # Optional: Check if record belongs to user
    if record.user_id and record.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied.")
        
    return map_record_to_result(record)


@router.delete("/threats/{threat_id}")
async def delete_threat_record_endpoint(threat_id: str, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Delete a threat record by ID."""
    from database.crud import get_threat_by_id, delete_threat_record
    record = await get_threat_by_id(db, threat_id)
    if not record:
        raise HTTPException(status_code=404, detail="Threat record not found.")

    if record.user_id and record.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied.")

    success = await delete_threat_record(db, threat_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete threat record.")

    background_tasks.add_task(log_event,
        category="THREAT", action="delete_threat",
        user_id=current_user.id, username=current_user.username,
        details={"threat_id": threat_id}
    )
    return {"success": True, "message": "Threat record deleted successfully."}
