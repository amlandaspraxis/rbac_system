from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import secrets

from passlib.context import CryptContext
from app.database import get_db
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.schemas import UserRegister, UserLogin, Token, TokenResponse, UserOut
from app.utils.jwt_handler import create_access_token, create_refresh_token, get_current_user
from app.utils.email_sender import send_verification_email
from app.utils.audit_logger import log_action
from app.routes.auth_limiter import limiter
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── Register ────────────────────────────────────────────────────
@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserRegister,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Register a new user with email verification."""
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    verification_token = secrets.token_urlsafe(32)

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        is_verified=False,
        verification_token=verification_token,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, user.id, "REGISTER", f"users/{user.id}")

    # Send verification email in background (non-blocking)
    background_tasks.add_task(send_verification_email, user.email, verification_token)

    return user


# ── Verify Email ────────────────────────────────────────────────
@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    """Verify a user's email address via the emailed token."""
    user = db.query(User).filter(User.verification_token == token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    user.is_verified = True
    user.verification_token = None
    db.commit()
    return {"message": "Email verified successfully. You can now log in."}


# ── Login (form — Swagger compatible) ───────────────────────────
@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """Authenticate via form-data (used by Swagger UI Authorize button). Includes brute-force protection."""
    user = db.query(User).filter(User.username == form_data.username).first()

    # Check account lockout
    if user and user.locked_until and datetime.now(timezone.utc) < user.locked_until:
        remaining = int((user.locked_until - datetime.now(timezone.utc)).total_seconds() / 60)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account locked. Try again in {remaining} minutes.",
        )

    # Validate credentials
    if not user or not verify_password(form_data.password, user.hashed_password):
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
                user.failed_login_attempts = 0
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.",
                )
            db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Please verify your email before logging in")

    # Reset failed attempts on success
    user.failed_login_attempts = 0
    user.locked_until = None

    # Create tokens
    access_token = create_access_token(data={"sub": str(user.id), "username": user.username})
    refresh_token_value = create_refresh_token()

    db_refresh = RefreshToken(
        token=refresh_token_value,
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(db_refresh)
    db.commit()

    log_action(db, user.id, "LOGIN", f"users/{user.id}")
    return {"access_token": access_token, "refresh_token": refresh_token_value, "token_type": "bearer"}


# ── Login JSON (for API clients) ───────────────────────────────
@router.post("/login/json", response_model=TokenResponse)
def login_json(payload: UserLogin, db: Session = Depends(get_db)):
    """Authenticate via JSON body (for API clients)."""
    user = db.query(User).filter(User.username == payload.username).first()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Please verify your email before logging in")

    access_token = create_access_token(data={"sub": str(user.id), "username": user.username})
    refresh_token_value = create_refresh_token()

    db_refresh = RefreshToken(
        token=refresh_token_value,
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(db_refresh)
    db.commit()

    log_action(db, user.id, "LOGIN", f"users/{user.id}")
    return {"access_token": access_token, "refresh_token": refresh_token_value, "token_type": "bearer"}


# ── Refresh Token ───────────────────────────────────────────────
@router.post("/refresh", response_model=TokenResponse)
def refresh(refresh_token: str, db: Session = Depends(get_db)):
    """Exchange a valid refresh token for a new access + refresh token pair (token rotation)."""
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token == refresh_token,
        RefreshToken.revoked == False,
    ).first()

    if not db_token or db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    # Rotate: revoke old, issue new
    db_token.revoked = True

    new_refresh = create_refresh_token()
    new_access = create_access_token(data={"sub": str(db_token.user_id)})

    db.add(RefreshToken(
        token=new_refresh,
        user_id=db_token.user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    ))
    db.commit()

    return {"access_token": new_access, "refresh_token": new_refresh, "token_type": "bearer"}


# ── Logout (revoke refresh token) ──────────────────────────────
@router.post("/logout")
def logout(refresh_token: str, db: Session = Depends(get_db)):
    """Revoke a refresh token (logout)."""
    db_token = db.query(RefreshToken).filter(RefreshToken.token == refresh_token).first()
    if db_token:
        db_token.revoked = True
        db.commit()
    return {"message": "Logged out successfully"}


# ── Me ──────────────────────────────────────────────────────────
@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    """Get the currently authenticated user's profile."""
    return current_user