"""
Export API Routes
Handles threat intelligence export to STIX, JSON, CSV, and SIEM platforms.
"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
import json
import io
from sqlalchemy.ext.asyncio import AsyncSession

from models.schemas import ExportRequest
from core.siem_exporter import export_to_stix, export_to_json, export_to_csv, format_for_splunk
from core.pdf_generator import generate_pdf_report
from api.dependencies import get_current_user
from database.models import User
from database.config import get_db
from database.crud import get_threat_by_id

router = APIRouter(prefix="/api/export", tags=["export"])


@router.post("/stix")
async def export_stix(request: ExportRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Export threat intelligence as STIX 2.1 bundle."""
    try:
        real_threats = await _get_real_threats(request.threat_ids, db)
        bundle = export_to_stix(real_threats)
        return bundle
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/json")
async def export_json(request: ExportRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Export threat intelligence as structured JSON."""
    try:
        real_threats = await _get_real_threats(request.threat_ids, db)
        result = export_to_json(real_threats)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/csv")
async def export_csv(request: ExportRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Export threat intelligence as CSV."""
    try:
        real_threats = await _get_real_threats(request.threat_ids, db)
        csv_content = export_to_csv(real_threats)
        return StreamingResponse(
            io.StringIO(csv_content),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=autoMITRE_export.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/splunk")
async def export_splunk(request: ExportRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Format threats for Splunk HEC ingestion."""
    try:
        real_threats = await _get_real_threats(request.threat_ids, db)
        result = format_for_splunk(real_threats)
        return {"events": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pdf")
async def export_pdf(request: ExportRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Export threat intelligence as a formatted PDF report."""
    try:
        real_threats = await _get_real_threats(request.threat_ids, db)
        # request format field can double as the report_type: 'executive', 'technical', 'managerial'
        report_type = request.format if request.format else "executive"
        
        pdf_bytes = generate_pdf_report(real_threats, report_type)
        
        return StreamingResponse(
            pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=autoMITRE_{report_type}_report.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def _get_real_threats(threat_ids: list, db: AsyncSession) -> list:
    """Fetches real threat records from the database and maps them to export format."""
    threats = []
    for tid in threat_ids:
        record = await get_threat_by_id(db, tid)
        if record:
            threats.append({
                "id": record.id,
                "title": record.title,
                "description": record.description,
                "timestamp": record.timestamp,
                "confidence": 100,
                "risk_score": {"score": record.risk_score, "severity": record.severity},
                "attack_techniques": [
                    {"id": t.technique_id, "name": t.name, "tactic": t.tactic, "description": t.description}
                    for t in record.techniques
                ],
                "mitigations": [
                    {"title": m.title, "description": m.description}
                    for m in record.mitigations
                ]
            })
    return threats
