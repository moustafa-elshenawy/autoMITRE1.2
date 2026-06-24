from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
from database.config import get_db
from database.models import User, ThreatRecord, ThreatEntity, ThreatTechnique
from api.dependencies import get_current_user
from core.audit import log_event
import datetime
import os

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

def get_view_filter(query, view: str, user: User):
    if view == "personal":
        return query.filter(ThreatRecord.user_id == user.id, ThreatRecord.group_id == None)
    elif view == "team":
        if user.memberships:
            group_id = user.memberships[0].group_id
            return query.filter(ThreatRecord.group_id == group_id)
        else:
            return query.filter(ThreatRecord.id == "NONE")
    elif view == "both":
        if user.memberships:
            group_id = user.memberships[0].group_id
            return query.filter(
                (ThreatRecord.user_id == user.id) | (ThreatRecord.group_id == group_id)
            )
        else:
            return query.filter(ThreatRecord.user_id == user.id)
    else:
        return query.filter(ThreatRecord.user_id == user.id)

@router.get("/stats")
async def get_dashboard_stats(
    view: str = "personal",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Base query for ThreatRecord
    threats_query = select(ThreatRecord)
    threats_query = get_view_filter(threats_query, view, current_user)
    
    result = await db.execute(threats_query)
    threats = result.scalars().all()

    total_threats = len(threats)
    critical_threats = sum(1 for t in threats if t.severity == "Critical")
    high_threats = sum(1 for t in threats if t.severity == "High")
    medium_threats = sum(1 for t in threats if t.severity == "Medium")
    low_threats = sum(1 for t in threats if t.severity == "Low")
    
    avg_risk = sum(t.risk_score for t in threats) / total_threats if total_threats > 0 else 0.0
    
    # Calculate mapped techniques
    # We will get all techniques associated with the filtered threats
    technique_query = select(ThreatTechnique).join(ThreatRecord, ThreatRecord.id == ThreatTechnique.threat_id)
    technique_query = get_view_filter(technique_query, view, current_user)
    tech_res = await db.execute(technique_query)
    techniques = tech_res.scalars().all()
    techniques_covered = len(set(t.technique_id for t in techniques))

    active_frameworks = []
    if os.getenv("FRAMEWORK_ATTACK", "true").lower() == "true": active_frameworks.append("ATT&CK")
    if os.getenv("FRAMEWORK_DEFEND", "true").lower() == "true": active_frameworks.append("D3FEND")
    if os.getenv("FRAMEWORK_NIST", "true").lower() == "true": active_frameworks.append("NIST")
    if os.getenv("FRAMEWORK_OWASP", "true").lower() == "true": active_frameworks.append("OWASP")

    # Calculate trend percentage (last 7 days vs previous 7 days)
    # Use datetime.now() — timestamps are stored as local naive datetimes
    now = datetime.datetime.now()
    seven_days_ago = now - datetime.timedelta(days=7)
    fourteen_days_ago = now - datetime.timedelta(days=14)
    
    this_week_count = 0
    last_week_count = 0
    
    for t in threats:
        if t.timestamp:
            try:
                # Handle 'Z' suffix and make timezone naive for comparison with utcnow
                ts_clean = t.timestamp.replace('Z', '+00:00') if t.timestamp.endswith('Z') else t.timestamp
                t_date = datetime.datetime.fromisoformat(ts_clean).replace(tzinfo=None)
                if t_date >= seven_days_ago:
                    this_week_count += 1
                elif t_date >= fourteen_days_ago:
                    last_week_count += 1
            except Exception:
                pass

    if last_week_count > 0:
        trend = ((this_week_count - last_week_count) / last_week_count) * 100
    elif this_week_count > 0:
        trend = 100
    else:
        trend = 0
        
    print(f"DEBUG STATS -> Total: {total_threats}, this_week: {this_week_count}, last_week: {last_week_count}, trend: {trend}", flush=True)

    return {
        "total_threats": total_threats,
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "medium_threats": medium_threats,
        "low_threats": low_threats,
        "techniques_covered": techniques_covered,
        "active_framework_names": active_frameworks,
        "risk_score_avg": round(avg_risk, 1),
        "trend_percentage": round(trend),
        "this_week_count": this_week_count,
        "prev_week_count": last_week_count
    }

@router.get("/debug_stats")
async def get_debug_stats(db: AsyncSession = Depends(get_db)):
    from database.models import User
    result = await db.execute(select(User).filter(User.username.ilike('%shno%')))
    user = result.scalars().first()
    if not user:
        return {"error": "no user"}
    return await get_dashboard_stats(view="personal", current_user=user, db=db)

@router.get("/activity")
async def get_dashboard_activity(
    view: str = "personal",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Last 7 days — use datetime.now() because timestamps are stored as local naive datetimes
    today = datetime.datetime.now().date()
    dates = [(today - datetime.timedelta(days=i)) for i in range(6, -1, -1)]
    labels = [d.strftime("%a") for d in dates] # 'Mon', 'Tue', etc.
    
    # Initialize counts
    datasets = {
        "Critical": [0] * 7,
        "High": [0] * 7,
        "Medium": [0] * 7,
        "Low": [0] * 7
    }
    
    threats_query = select(ThreatRecord)
    threats_query = get_view_filter(threats_query, view, current_user)
    result = await db.execute(threats_query)
    threats = result.scalars().all()
    
    for threat in threats:
        if threat.timestamp:
            try:
                # Handle 'Z' suffix and make timezone naive for comparison
                ts_clean = threat.timestamp.replace('Z', '+00:00') if threat.timestamp.endswith('Z') else threat.timestamp
                t_date = datetime.datetime.fromisoformat(ts_clean).replace(tzinfo=None).date()
                if t_date in dates:
                    idx = dates.index(t_date)
                    sev = threat.severity
                    if sev in datasets:
                        datasets[sev][idx] += 1
            except Exception:
                pass

    return {
        "labels": labels,
        "datasets": [
            {"label": k, "data": v} for k, v in datasets.items()
        ]
    }

@router.get("/trends")
async def get_dashboard_trends(
    view: str = "personal",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Top targets (entities)
    entity_query = select(ThreatEntity.type, ThreatEntity.value, func.count(ThreatEntity.id).label('count')).join(ThreatRecord, ThreatRecord.id == ThreatEntity.threat_id)
    entity_query = get_view_filter(entity_query, view, current_user)
    entity_query = entity_query.group_by(ThreatEntity.type, ThreatEntity.value).order_by(func.count(ThreatEntity.id).desc()).limit(10)
    
    ent_res = await db.execute(entity_query)
    top_targets = [{"type": row.type, "value": row.value, "count": row.count} for row in ent_res.all()]
    
    # Top techniques
    tech_query = select(ThreatTechnique.name, func.count(ThreatTechnique.id).label('count')).join(ThreatRecord, ThreatRecord.id == ThreatTechnique.threat_id)
    tech_query = get_view_filter(tech_query, view, current_user)
    tech_query = tech_query.group_by(ThreatTechnique.name).order_by(func.count(ThreatTechnique.id).desc()).limit(10)
    
    tech_res = await db.execute(tech_query)
    top_techniques = [{"name": row.name, "count": row.count} for row in tech_res.all()]

    return {
        "top_targets": top_targets,
        "top_techniques": top_techniques
    }
