"""
User profile management endpoints.
Each authenticated user can retrieve and update their own profile,
change their password, and view per-account statistics.
"""
import datetime
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, desc

from database.config import get_db
from database.models import User, ThreatRecord
from models.auth import UserProfile, UserProfileUpdate, ChangePasswordRequest
from models.schemas import ThreatHistoryResponse
from core.security import verify_password, get_password_hash
from api.dependencies import get_current_user, get_workspace, WorkspaceState
import database.crud as crud
import database.crud as crud
from api.routes.analysis import map_record_to_result
from core.audit import log_event

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("/profile", response_model=UserProfile)
async def get_profile(current_user: User = Depends(get_current_user)):
    """Return the full profile of the authenticated user."""
    return current_user


@router.patch("/profile", response_model=UserProfile)
async def update_profile(
    profile_update: UserProfileUpdate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update allowed profile fields for the authenticated user."""
    update_data = profile_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(current_user, field, value)

    db.add(current_user)
    await db.commit()
    await db.refresh(current_user)
    
    background_tasks.add_task(
        log_event,
        category="USER", action="update_profile",
        username=current_user.username, status="success"
    )
    
    return current_user


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Allow a user to change their own password after verifying the current one."""
    if not verify_password(payload.current_password, current_user.hashed_password):
        await log_event(
            category="USER", action="change_password",
            username=current_user.username, status="failure",
            details={"reason": "incorrect_current_password"}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    current_user.hashed_password = get_password_hash(payload.new_password)
    db.add(current_user)
    await db.commit()
    
    background_tasks.add_task(
        log_event,
        category="USER", action="change_password",
        username=current_user.username, status="success"
    )
    
    return {"message": "Password updated successfully"}


@router.get("/history", response_model=ThreatHistoryResponse)
async def get_threat_history(
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    workspace: WorkspaceState = Depends(get_workspace),
    db: AsyncSession = Depends(get_db),
):
    """Return historical threat analyses for the current user."""
    records = await crud.get_recent_threats(db, limit=limit, user_id=current_user.id, group_id=workspace.group_id, view_mode=workspace.view_mode)
    
    # We must manually map the nested ORM components into the Pydantic schemas 
    # since SQLite uses relationships that need processing for the `ThreatResult` output format.
    items = [map_record_to_result(r) for r in records]

    return {"items": items}


@router.get("/stats")
async def get_user_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return threat analysis statistics for the authenticated user."""
    uid = current_user.id

    # Total threats
    total_q = await db.execute(
        select(func.count(ThreatRecord.id)).where(ThreatRecord.user_id == uid)
    )
    total = total_q.scalar() or 0

    if total == 0:
        return {
            "total_analyses": 0,
            "avg_risk_score": 0.0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "member_since": current_user.created_at,
            "last_login": current_user.last_login_at,
        }

    async def count_severity(sev: str) -> int:
        q = await db.execute(
            select(func.count(ThreatRecord.id))
            .where(ThreatRecord.user_id == uid)
            .where(ThreatRecord.severity == sev)
        )
        return q.scalar() or 0

    critical = await count_severity("Critical")
    high = await count_severity("High")
    medium = await count_severity("Medium")
    low = await count_severity("Low")

    avg_q = await db.execute(
        select(func.avg(ThreatRecord.risk_score)).where(ThreatRecord.user_id == uid)
    )
    avg_score = round(avg_q.scalar() or 0.0, 1)

    return {
        "total_analyses": total,
        "avg_risk_score": avg_score,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "member_since": current_user.created_at,
        "last_login": current_user.last_login_at,
    }


@router.delete("/profile")
async def delete_user_account(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete the authenticated user's account and personal data."""
    from database.models import GroupMembership, GroupInvitation
    uid = current_user.id
    username = current_user.username

    # Delete personal threats
    personal_threats_q = await db.execute(
        select(ThreatRecord).where(ThreatRecord.user_id == uid, ThreatRecord.group_id == None)
    )
    for pt in personal_threats_q.scalars().all():
        await db.delete(pt)

    # Anonymize group threats
    group_threats_q = await db.execute(
        select(ThreatRecord).where(ThreatRecord.user_id == uid, ThreatRecord.group_id != None)
    )
    for gt in group_threats_q.scalars().all():
        gt.user_id = None

    # Delete memberships
    memberships_q = await db.execute(select(GroupMembership).where(GroupMembership.user_id == uid))
    for m in memberships_q.scalars().all():
        await db.delete(m)

    # Delete invitations
    invitations_q = await db.execute(
        select(GroupInvitation).where(
            (GroupInvitation.inviter_id == uid) | (GroupInvitation.invitee_id == uid)
        )
    )
    for inv in invitations_q.scalars().all():
        await db.delete(inv)

    # Finally delete the user
    await db.delete(current_user)
    await db.commit()

    background_tasks.add_task(
        log_event,
        category="USER", action="delete_account",
        username=username, status="success"
    )

    return {"success": True, "message": "Account deleted successfully"}
