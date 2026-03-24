from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.role import Role
from app.models.permission import Permission
from app.models.user import User
from app.schemas import RoleCreate, RoleUpdate, RoleOut
from app.utils.jwt_handler import get_current_user
from app.utils.audit_logger import log_action
from app.middleware.rbac_guard import PermissionChecker

router = APIRouter(prefix="/roles", tags=["Roles"])


@router.get("/", response_model=List[RoleOut], dependencies=[Depends(PermissionChecker(["roles:read"]))])
def list_roles(db: Session = Depends(get_db)):
    """List all roles (requires roles:read)."""
    return db.query(Role).all()


@router.get("/{role_id}", response_model=RoleOut, dependencies=[Depends(PermissionChecker(["roles:read"]))])
def get_role(role_id: int, db: Session = Depends(get_db)):
    """Get a specific role (requires roles:read)."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return role


@router.post("/", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
def create_role(
    payload: RoleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["roles:create"])),
):
    """Create a new role (requires roles:create)."""
    if db.query(Role).filter(Role.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Role name already exists")

    role = Role(name=payload.name, description=payload.description)
    db.add(role)
    db.commit()
    db.refresh(role)
    log_action(db, current_user.id, "CREATE_ROLE", f"roles/{role.id}")
    return role


@router.put("/{role_id}", response_model=RoleOut)
def update_role(
    role_id: int,
    payload: RoleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["roles:update"])),
):
    """Update a role (requires roles:update)."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(role, key, value)

    db.commit()
    db.refresh(role)
    log_action(db, current_user.id, "UPDATE_ROLE", f"roles/{role_id}", str(update_data))
    return role


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(
    role_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["roles:delete"])),
):
    """Delete a role (requires roles:delete)."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    db.delete(role)
    db.commit()
    log_action(db, current_user.id, "DELETE_ROLE", f"roles/{role_id}")


# ── Permission Assignment Endpoints ────────────────────────────

@router.post("/{role_id}/permissions/{permission_id}", response_model=RoleOut)
def assign_permission(
    role_id: int,
    permission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["roles:update"])),
):
    """Assign a permission to a role (requires roles:update)."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    perm = db.query(Permission).filter(Permission.id == permission_id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")

    if perm in role.permissions:
        raise HTTPException(status_code=400, detail="Role already has this permission")

    role.permissions.append(perm)
    db.commit()
    db.refresh(role)
    log_action(db, current_user.id, "ASSIGN_PERMISSION", f"roles/{role_id}/permissions/{permission_id}")
    return role


@router.delete("/{role_id}/permissions/{permission_id}", response_model=RoleOut)
def revoke_permission(
    role_id: int,
    permission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["roles:update"])),
):
    """Revoke a permission from a role (requires roles:update)."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    perm = db.query(Permission).filter(Permission.id == permission_id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")

    if perm not in role.permissions:
        raise HTTPException(status_code=400, detail="Role does not have this permission")

    role.permissions.remove(perm)
    db.commit()
    db.refresh(role)
    log_action(db, current_user.id, "REVOKE_PERMISSION", f"roles/{role_id}/permissions/{permission_id}")
    return role
