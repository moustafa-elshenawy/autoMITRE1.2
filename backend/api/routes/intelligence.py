"""
Intelligence API Routes
Handles chat, dashboard stats, and threat feed.
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
import asyncio
import random

from models.schemas import ChatRequest, ChatResponse, DashboardStats
from core.ai_chat_engine import generate_chat_response
from database.config import get_db
from database.crud import get_dashboard_stats as get_db_stats, get_recent_threats, get_threat_activity, get_attack_tactic_coverage
from api.dependencies import get_current_user
from database.models import User

router = APIRouter(prefix="/api", tags=["intelligence"])


@router.post("/chat", response_model=ChatResponse)
async def chat_with_ai(request: ChatRequest, current_user: User = Depends(get_current_user)):
    """General cyber threat intelligence chat."""
    try:
        result = generate_chat_response(
            request.message,
            request.history,
            request.threat_context
        )
        return ChatResponse(
            response=result['response'],
            suggestions=result.get('suggestions', [])
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get dashboard statistics."""
    stats = await get_db_stats(db, current_user.id)
    stats["last_updated"] = datetime.utcnow().isoformat()
    return stats


@router.get("/dashboard/activity")
async def get_activity(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get threat counts grouped by day and severity for the last 7 days."""
    return await get_threat_activity(db, current_user.id)


@router.get("/intelligence/feed")
async def get_threat_feed(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get live threat intelligence feed blending OSINT sources + user's own analyzed threats."""
    from core.osint_client import fetch_all_osint, RUNTIME_CONFIG
    from database.models import OSINTFeedItem
    from sqlalchemy.future import select

    # Run OSINT fetch + DB query concurrently
    osint_task = asyncio.create_task(fetch_all_osint())
    db_threats = await get_recent_threats(db, limit=20, user_id=current_user.id)
    osint_result = await osint_task

    feed_items = []

    # 1. User's own analyzed threats from DB (shown first, most relevant)
    for t in db_threats:
        primary_tech_id = ""
        primary_tactic  = ""
        if t.techniques:
            primary_tech_id = t.techniques[0].technique_id
            primary_tactic  = t.techniques[0].tactic
        elif isinstance(t.raw_indicators, dict) and t.raw_indicators.get("technique_ids"):
            primary_tech_id = t.raw_indicators["technique_ids"][0]

        frameworks = ["ATT&CK"]
        if t.framework_coverage_defend > 0: frameworks.append("D3FEND")
        if t.framework_coverage_nist   > 0: frameworks.append("NIST")
        if t.framework_coverage_owasp  > 0: frameworks.append("OWASP")

        iocs = [e.value for e in t.entities[:3]]

        feed_items.append({
            "id":          t.id,
            "title":       t.title,
            "severity":    t.severity,
            "technique":   primary_tech_id,
            "tactic":      primary_tactic or "Unknown",
            "timestamp":   t.timestamp,
            "source":      f"autoMITRE ({t.input_type})",
            "source_key":  "db",
            "iocs":        iocs,
            "frameworks":  frameworks,
            "description": t.description[:200] if t.description else "",
            "external_url": "",
            "tags":        [],
        })

    # 2. Add local historical OSINT if enabled
    store_locally = str(RUNTIME_CONFIG.get("osint_store_locally", "false")).lower() == "true"
    db_osint = []
    if store_locally:
        try:
            stmt = select(OSINTFeedItem).order_by(OSINTFeedItem.timestamp.desc()).limit(1500)
            result = await db.execute(stmt)
            db_osint = result.scalars().all()
        except Exception as e:
            pass
            
    # Serialize historical OSINT
    historic_entries = []
    for d in db_osint:
        historic_entries.append({
            "id": d.id,
            "title": d.title,
            "severity": d.severity,
            "technique": d.technique,
            "tactic": d.tactic,
            "timestamp": d.timestamp,
            "source": f"{d.source} (Local DB)",
            "source_key": d.source_key,
            "iocs": d.iocs or [],
            "frameworks": d.frameworks or [],
            "description": d.description or "",
            "external_url": d.external_url or "",
            "tags": d.tags or [],
            "is_historic": True
        })

    # 3. Live OSINT items from external sources + Historic
    all_osint = osint_result.get("items", []) + historic_entries
    
    # Deduplicate by ID
    seen_ids = set()
    deduped_osint = []
    for item in all_osint:
        if item["id"] not in seen_ids:
            seen_ids.add(item["id"])
            deduped_osint.append(item)
            
    feed_items.extend(deduped_osint)

    # Sort everything by timestamp descending
    feed_items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "threats":      feed_items,
        "total":        len(feed_items),
        "sources":      osint_result.get("sources", {}),
        "last_updated": datetime.utcnow().isoformat(),
    }


@router.get("/intelligence/osint-history")
async def get_osint_history(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get strictly historical OSINT feed items from the local database."""
    from database.models import OSINTFeedItem
    from sqlalchemy.future import select
    
    try:
        stmt = select(OSINTFeedItem).order_by(OSINTFeedItem.timestamp.desc()).limit(1500)
        result = await db.execute(stmt)
        db_osint = result.scalars().all()
    except Exception as e:
        db_osint = []
        
    historic_entries = []
    for d in db_osint:
        historic_entries.append({
            "id": d.id,
            "title": d.title,
            "severity": d.severity,
            "technique": d.technique,
            "tactic": d.tactic,
            "timestamp": d.timestamp,
            "source": f"{d.source} (Local DB)",
            "source_key": d.source_key,
            "iocs": d.iocs or [],
            "frameworks": d.frameworks or [],
            "description": d.description or "",
            "external_url": d.external_url or "",
            "tags": d.tags or [],
            "is_historic": True
        })
        
    return {
        "items": historic_entries,
        "total": len(historic_entries)
    }


@router.get("/intelligence/feed/sources")
async def get_feed_sources(current_user: User = Depends(get_current_user)):
    """Return configuration status of all OSINT sources (no live fetch)."""
    from core.osint_client import get_source_status
    return {"sources": get_source_status()}



@router.get("/framework/coverage")
async def get_framework_coverage(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get framework coverage statistics."""
    tactic_stats = await get_attack_tactic_coverage(db, current_user.id)
    
    # Mapping to handle backend names vs frontend expectation if needed, 
    # but primarily ensuring values are dynamic.
    by_tactic_template = {
        "Initial Access": 10,
        "Execution": 14,
        "Persistence": 20,
        "Privilege Escalation": 14,
        "Defense Evasion": 44,
        "Credential Access": 17,
        "Discovery": 32,
        "Lateral Movement": 9,
        "Collection": 17,
        "Command and Control": 18,
        "Exfiltration": 9,
        "Impact": 14
    }
    
    dynamic_by_tactic = {}
    normalized_tactic_stats = {k.lower(): v for k, v in tactic_stats.items()}
    
    total_covered = 0
    for name, total in by_tactic_template.items():
        covered = normalized_tactic_stats.get(name.lower(), 0)
        dynamic_by_tactic[name] = {"total": total, "covered": covered}
        total_covered += covered

    # Get total unique techniques covered for the top level percentage
    from database.crud import get_dashboard_stats
    stats = await get_dashboard_stats(db, current_user.id)
    unique_techs = stats.get("techniques_covered", 0)

    return {
        "attack": {
            "total_techniques": 635,
            "covered": unique_techs,
            "percentage": round((unique_techs / 635) * 100, 1) if 635 > 0 else 0,
            "by_tactic": dynamic_by_tactic
        },
        "defend": {
            "total_countermeasures": 58,
            "covered": 15,
            "percentage": 25.9
        },
        "nist": {
            "total_controls": 1000,
            "covered": 16,
            "percentage": 1.6
        },
        "owasp": {
            "total_items": 20,
            "covered": 10,
            "percentage": 50.0
        }
    }
