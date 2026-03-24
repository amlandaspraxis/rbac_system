from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.permission import Permission
from app.models.user import User
from app.schemas import PermissionCreate, PermissionUpdate, PermissionOut
from app.utils.audit_logger import log_action
from app.middleware.rbac_guard import PermissionChecker

router = APIRouter(prefix="/permissions", tags=["Permissions"])


@router.get("/", response_model=List[PermissionOut], dependencies=[Depends(PermissionChecker(["permissions:read"]))])
def list_permissions(db: Session = Depends(get_db)):
    """List all permissions (requires permissions:read)."""
    return db.query(Permission).all()


@router.get("/{perm_id}", response_model=PermissionOut, dependencies=[Depends(PermissionChecker(["permissions:read"]))])
def get_permission(perm_id: int, db: Session = Depends(get_db)):
    """Get a specific permission (requires permissions:read)."""
    perm = db.query(Permission).filter(Permission.id == perm_id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    return perm


@router.post("/", response_model=PermissionOut, status_code=status.HTTP_201_CREATED)
def create_permission(
    payload: PermissionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["permissions:create"])),
):
    """Create a new permission (requires permissions:create)."""
    if db.query(Permission).filter(Permission.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Permission name already exists")

    perm = Permission(name=payload.name, description=payload.description)
    db.add(perm)
    db.commit()
    db.refresh(perm)
    log_action(db, current_user.id, "CREATE_PERMISSION", f"permissions/{perm.id}")
    return perm


@router.put("/{perm_id}", response_model=PermissionOut)
def update_permission(
    perm_id: int,
    payload: PermissionUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["permissions:update"])),
):
    """Update a permission (requires permissions:update)."""
    perm = db.query(Permission).filter(Permission.id == perm_id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(perm, key, value)

    db.commit()
    db.refresh(perm)
    log_action(db, current_user.id, "UPDATE_PERMISSION", f"permissions/{perm_id}", str(update_data))
    return perm


@router.delete("/{perm_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_permission(
    perm_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(PermissionChecker(["permissions:delete"])),
):
    """Delete a permission (requires permissions:delete)."""
    perm = db.query(Permission).filter(Permission.id == perm_id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")

    db.delete(perm)
    db.commit()
    log_action(db, current_user.id, "DELETE_PERMISSION", f"permissions/{perm_id}")
