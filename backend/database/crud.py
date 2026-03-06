from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, desc
from typing import List, Dict, Any

from database import models
from models.schemas import ThreatResult, SeverityLevel


async def create_threat_record(db: AsyncSession, threat: ThreatResult, user_id: str = None) -> models.ThreatRecord:
    """Save a new threat analysis result to the database."""
    
    # Create main record
    db_threat = models.ThreatRecord(
        id=threat.id,
        user_id=user_id,
        title=threat.title,
        description=threat.description,
        input_type=threat.input_type,
        risk_score=threat.risk_score.score,
        severity=threat.risk_score.severity.value,
        likelihood=threat.risk_score.likelihood,
        impact_score=threat.risk_score.impact,
        business_impact=threat.risk_score.business_impact,
        raw_indicators=threat.raw_indicators,
        framework_coverage_attack=len(threat.attack_techniques),
        framework_coverage_defend=len(threat.defend_countermeasures),
        framework_coverage_nist=len(threat.nist_controls),
        framework_coverage_owasp=len(threat.owasp_items),
        timestamp=threat.timestamp
    )
    db.add(db_threat)
    
    # Add entities
    for entity in threat.entities:
        db_entity = models.ThreatEntity(
            threat_id=threat.id,
            type=entity.type,
            value=entity.value,
            context=entity.context
        )
        db.add(db_entity)
        
    # Add techniques
    for tech in threat.attack_techniques:
        db_tech = models.ThreatTechnique(
            threat_id=threat.id,
            technique_id=tech.id,
            name=tech.name,
            tactic=tech.tactic,
            tactic_id=tech.tactic_id,
            description=tech.description,
            confidence=tech.confidence
        )
        db.add(db_tech)
        
    # Add mitigations
    for mit in threat.mitigations:
        db_mit = models.ThreatMitigation(
            threat_id=threat.id,
            title=mit.title,
            description=mit.description,
            priority=mit.priority,
            effort=mit.effort,
            iac_snippet=mit.iac_snippet,
            iac_type=mit.iac_type
        )
        db.add(db_mit)
        
    await db.commit()
    await db.refresh(db_threat)
    return db_threat


from sqlalchemy.orm import selectinload

async def get_recent_threats(db: AsyncSession, limit: int = 20, user_id: str = None) -> List[models.ThreatRecord]:
    """Get the most recent threat records for the feed."""
    query = (
        select(models.ThreatRecord)
        .options(selectinload(models.ThreatRecord.techniques))
        .options(selectinload(models.ThreatRecord.entities))
        .options(selectinload(models.ThreatRecord.mitigations))
    )
    if user_id:
        query = query.where(models.ThreatRecord.user_id == user_id)
        
    query = query.order_by(desc(models.ThreatRecord.timestamp)).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


async def get_dashboard_stats(db: AsyncSession, user_id: str = None) -> Dict[str, Any]:
    """Calculate dashboard statistics from the database."""
    
    base_where = [models.ThreatRecord.user_id == user_id] if user_id else []
    
    # Total threats
    query = select(func.count(models.ThreatRecord.id))
    if base_where: query = query.where(*base_where)
    result = await db.execute(query)
    total_threats = result.scalar() or 0
    
    if total_threats == 0:
        return {
            "total_threats": 0,
            "critical_threats": 0,
            "high_threats": 0,
            "medium_threats": 0,
            "low_threats": 0,
            "techniques_covered": 0,
            "frameworks_mapped": 4,
            "risk_score_avg": 0.0,
        }
        
    # Severity counts
    async def get_count(severity_level):
        q = select(func.count(models.ThreatRecord.id)).where(models.ThreatRecord.severity == severity_level)
        if base_where: q = q.where(*base_where)
        res = await db.execute(q)
        return res.scalar() or 0

    critical = await get_count(SeverityLevel.CRITICAL.value)
    high = await get_count(SeverityLevel.HIGH.value)
    medium = await get_count(SeverityLevel.MEDIUM.value)
    low = await get_count(SeverityLevel.LOW.value)
    
    # Average Risk Score
    q_avg = select(func.avg(models.ThreatRecord.risk_score))
    if base_where: q_avg = q_avg.where(*base_where)
    avg_score = (await db.execute(q_avg)).scalar() or 0.0
    
    # Unique Techniques Covered
    q_tech = select(func.count(func.distinct(models.ThreatTechnique.technique_id))).join(models.ThreatRecord)
    if base_where: q_tech = q_tech.where(*base_where)
    unique_techs = (await db.execute(q_tech)).scalar() or 0
    
    return {
        "total_threats": total_threats,
        "critical_threats": critical,
        "high_threats": high,
        "medium_threats": medium,
        "low_threats": low,
        "techniques_covered": unique_techs,
        "frameworks_mapped": 4,
        "risk_score_avg": round(avg_score, 1)
    }


async def get_threat_by_id(db: AsyncSession, threat_id: str) -> models.ThreatRecord:
    """Get a specific threat by ID."""
    query = (
        select(models.ThreatRecord)
        .where(models.ThreatRecord.id == threat_id)
        .options(selectinload(models.ThreatRecord.techniques))
        .options(selectinload(models.ThreatRecord.entities))
        .options(selectinload(models.ThreatRecord.mitigations))
    )
    result = await db.execute(query)
    return result.scalar_one_or_none()
