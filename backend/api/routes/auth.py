from datetime import timedelta
import datetime
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update as sql_update, func

from database.config import get_db, SessionLocal
from database.models import User, AuditLog
from core.security import (
    verify_password, get_password_hash, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES,
    create_password_reset_token, verify_password_reset_token
)
from core.email import send_reset_password_email
from api.dependencies import get_current_user
from models.auth import UserCreate, UserResponse, Token, ForgotPasswordRequest, ResetPasswordRequest
from core.audit import log_event

router = APIRouter(prefix="/api/auth", tags=["auth"])


async def _update_last_login(user_id: str):
    """Background task: update last_login_at without blocking the token response."""
    try:
        async with SessionLocal() as session:
            await session.execute(
                sql_update(User)
                .where(User.id == user_id)
                .values(last_login_at=datetime.datetime.utcnow().isoformat())
            )
            await session.commit()
    except Exception:
        pass  # Don't fail login if this update fails


@router.post("/register", response_model=UserResponse)
async def register_user(user_in: UserCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    # Check if user exists
    result = await db.execute(select(User).filter(User.username == user_in.username))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Username already registered")
        
    result = await db.execute(select(User).filter(User.email == user_in.email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Email already registered")
        
    # Every self-registered user is system-level admin.
    # The analyst distinction is managed at the GROUP level (GroupMembership.role),
    # not at the system level. An admin can demote via /api/admin/users if needed.
    assigned_role = "admin"

    hashed_password = get_password_hash(user_in.password)
    new_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hashed_password,
        full_name=getattr(user_in, 'full_name', None),
        role=assigned_role,
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    background_tasks.add_task(log_event,
        category="AUTH", action="register",
        user_id=new_user.id, username=new_user.username,
        details={"email": new_user.email, "role": assigned_role}
    )
    return new_user


@router.post("/token", response_model=Token)
async def login_for_access_token(
    background_tasks: BackgroundTasks,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    # Accept login by username OR email
    result = await db.execute(select(User).filter(User.username == form_data.username))
    user = result.scalars().first()

    if not user:
        # Try by email
        result = await db.execute(select(User).filter(User.email == form_data.username))
        user = result.scalars().first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        # Log failed login synchronously because raising HTTPException skips BackgroundTasks
        await log_event(
            category="AUTH", action="login_failure",
            username=form_data.username, status="failure",
            details={"reason": "Invalid credentials"}
        )

        # Check for multiple failed attempts
        two_mins_ago = (datetime.datetime.utcnow() - datetime.timedelta(minutes=2)).isoformat()
        count_result = await db.execute(
            select(func.count(AuditLog.id))
            .filter(
                AuditLog.action == "login_failure",
                AuditLog.username == form_data.username,
                AuditLog.timestamp >= two_mins_ago
            )
        )
        failure_count = count_result.scalar() or 0
        
        # We just added one asynchronously, but it's not in DB yet, so failure_count is past failures.
        # If past failures >= 2, total failures now >= 3.
        if failure_count >= 2:
            await log_event(
                category="AUTH", action="brute_force_warning",
                username=form_data.username, status="warning",
                details={"reason": f"Multiple failed login attempts ({failure_count + 1} attempts in 2 minutes)"}
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update last_login_at in the background (non-blocking)
    background_tasks.add_task(_update_last_login, user.id)
    background_tasks.add_task(log_event,
        category="AUTH", action="login_success",
        user_id=user.id, username=user.username,
        details={"role": user.role}
    )
        
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role or "analyst"}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/forgot-password")
async def forgot_password(
    request: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Generate a password reset token and send an email."""
    result = await db.execute(select(User).filter(User.email == request.email))
    user = result.scalars().first()

    # Even if the user doesn't exist, return a generic success message
    # to prevent email enumeration attacks.
    if user:
        reset_token = create_password_reset_token(user.email)
        
        # In a real setup, frontend_url would be read from ENV.
        frontend_url = "http://localhost:5174"
        reset_url = f"{frontend_url}/reset-password?token={reset_token}"
        
        background_tasks.add_task(send_reset_password_email, user.email, reset_url)
        
        background_tasks.add_task(log_event,
            category="AUTH", action="forgot_password",
            username=user.username, status="success"
        )
        
    return {"message": "If an account with that email exists, a password reset link has been sent."}

@router.post("/reset-password")
async def reset_password(
    request: ResetPasswordRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Reset the user's password using the token sent to their email."""
    email = verify_password_reset_token(request.token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token."
        )

    result = await db.execute(select(User).filter(User.email == email))
    user = result.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User no longer exists."
        )

    user.hashed_password = get_password_hash(request.new_password)
    db.add(user)
    await db.commit()

    background_tasks.add_task(log_event,
        category="AUTH", action="reset_password",
        username=user.username, status="success"
    )

    return {"message": "Password successfully reset."}
