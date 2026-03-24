from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.user import User
from app.models.role import Role
from app.schemas import UserOut, UserUpdate
from app.utils.jwt_handler import get_current_user
from app.utils.audit_logger import log_action
from app.middleware.rbac_guard import PermissionChecker

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/", response_model=List[UserOut], dependencies=[Depends(PermissionChecker(["users:read"]))])
def list_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """List all users (requires users:read)."""
    return db.query(User).offset(skip).limit(limit).all()


@router.get("/{user_id}", response_model=UserOut, dependencies=[Depends(PermissionChecker(["users:read"]))])
def get_user(user_id: int, db: Session = Depends(get_db)):
    """Get a specific user by ID (requires users:read)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.put("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["users:update"])),
):
    """Update a user (requires users:update)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user, key, value)

    db.commit()
    db.refresh(user)
    log_action(db, current_user.id, "UPDATE_USER", f"users/{user_id}", str(update_data))
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["users:delete"])),
):
    """Delete a user (requires users:delete)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    log_action(db, current_user.id, "DELETE_USER", f"users/{user_id}")


# ── Role Assignment Endpoints ──────────────────────────────────

@router.post("/{user_id}/roles/{role_id}", response_model=UserOut)
def assign_role(
    user_id: int,
    role_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["users:update"])),
):
    """Assign a role to a user (requires users:update)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if role in user.roles:
        raise HTTPException(status_code=400, detail="User already has this role")

    user.roles.append(role)
    db.commit()
    db.refresh(user)
    log_action(db, current_user.id, "ASSIGN_ROLE", f"users/{user_id}/roles/{role_id}")
    return user


@router.delete("/{user_id}/roles/{role_id}", response_model=UserOut)
def revoke_role(
    user_id: int,
    role_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["users:update"])),
):
    """Revoke a role from a user (requires users:update)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if role not in user.roles:
        raise HTTPException(status_code=400, detail="User does not have this role")

    user.roles.remove(role)
    db.commit()
    db.refresh(user)
    log_action(db, current_user.id, "REVOKE_ROLE", f"users/{user_id}/roles/{role_id}")
    return user
