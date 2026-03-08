"""
Analysis API Routes
Handles all threat analysis endpoints.
"""
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from typing import Optional
import json

from models.schemas import (
    TextAnalysisRequest, HashLookupRequest, AnalysisResponse,
    ThreatResult, ChatRequest, ChatResponse
)
from core.input_processor import process_input, InputType
from core.ai_threat_analyzer import analyze_threat
from core.framework_mapper import map_all_frameworks
from core.virustotal_client import lookup_hash
from core.ai_chat_engine import generate_chat_response
from core.pcap_parser import parse_pcap_bytes
from sqlalchemy.ext.asyncio import AsyncSession
import os
import uuid
from fastapi import Depends
from database.config import get_db
from database.crud import create_threat_record
from api.dependencies import get_current_user
from database.models import User

router = APIRouter(prefix="/api/analyze", tags=["analysis"])


def enrich_threat_result(threat: ThreatResult, technique_ids: list) -> ThreatResult:
    """Enrich a threat result with framework mappings."""
    mappings = map_all_frameworks(technique_ids)
    threat.defend_countermeasures = mappings['defend']
    threat.nist_controls = mappings['nist']
    threat.owasp_items = mappings['owasp']
    return threat


@router.post("/text", response_model=AnalysisResponse)
async def analyze_text(request: TextAnalysisRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Analyze a text description of a threat."""
    try:
        processed = process_input(request.text, InputType.TEXT)
        threat = analyze_threat(processed, deep_analysis=request.deep_analysis)
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        threat = enrich_threat_result(threat, technique_ids)
        
        # Save to database
        await create_threat_record(db, threat, current_user.id)
        
        return AnalysisResponse(success=True, threat_result=threat)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/hash", response_model=AnalysisResponse)
async def analyze_hash(request: HashLookupRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Look up a malware hash on VirusTotal and analyze it."""
    try:
        # Get VirusTotal result
        vt_result = lookup_hash(request.hash)
        if not vt_result.get("found"):
            raise HTTPException(status_code=400, detail=vt_result.get("message", "Hash not found in VirusTotal."))
        
        # Build description from VT result
        verdict = vt_result.get('verdict', 'unknown')
        ratio = vt_result.get('detection_ratio', '0/0')
        description = f"Malware hash analysis: {request.hash}. Detection ratio: {ratio}. Verdict: {verdict}."
        
        if vt_result.get('names'):
            description += f" Known names: {', '.join(vt_result['names'][:3])}."
        
        processed = process_input(request.hash, InputType.HASH)
        processed['normalized_text'] = description
        # Add VT-suggested techniques
        if vt_result.get('suggested_techniques'):
            processed['suggested_techniques'].extend(vt_result['suggested_techniques'])
        
        threat = analyze_threat(processed)
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        threat = enrich_threat_result(threat, technique_ids)
        threat.raw_indicators['virustotal'] = vt_result
        
        # Save to database
        await create_threat_record(db, threat, current_user.id)
        
        return AnalysisResponse(success=True, threat_result=threat)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/file")
async def analyze_file(file: UploadFile = File(...), context: Optional[str] = Form(None), db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Analyze an uploaded file (JSON, STIX, text log)."""
    try:
        filename = file.filename.lower() if file.filename else ""
        content = await file.read()
        
        input_type = InputType.TEXT
        text_content = ""
        
        # Binary PCAP routing
        if filename.endswith(".pcap") or filename.endswith(".pcapng"):
            temp_path = f"/tmp/{uuid.uuid4()}_{filename}"
            with open(temp_path, "wb") as f:
                f.write(content)
            
            # Scapy binary decode to textual representation
            text_content = parse_pcap_bytes(temp_path)
            
            # Safely cleanup binary temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
        else:
            # Handle Standard Text/JSON Logs
            text_content = content.decode('utf-8', errors='ignore')
            
            # Detect JSON/STIX natively inside string
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
        
        threat = analyze_threat(processed)
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        threat = enrich_threat_result(threat, technique_ids)
        
        # Save to database
        await create_threat_record(db, threat, current_user.id)
        
        return AnalysisResponse(success=True, threat_result=threat)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/json-stix")
async def analyze_json_stix(request: TextAnalysisRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Analyze JSON or STIX threat intelligence."""
    try:
        processed = process_input(request.text, InputType.JSON)
        threat = analyze_threat(processed)
        technique_ids = threat.raw_indicators.get('technique_ids', [])
        threat = enrich_threat_result(threat, technique_ids)
        
        # Save to database
        await create_threat_record(db, threat, current_user.id)
        
        return AnalysisResponse(success=True, threat_result=threat)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
