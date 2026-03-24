from typing import List
from fastapi import Depends, HTTPException, status
from app.utils.jwt_handler import get_current_user
from app.models.user import User


class PermissionChecker:
    """
    FastAPI dependency that checks if the current user has ALL of the required permissions.

    Usage:
        @router.get("/users", dependencies=[Depends(PermissionChecker(["users:read"]))])
        def list_users():
            ...
    """

    def __init__(self, required_permissions: List[str]):
        self.required_permissions = required_permissions

    def __call__(self, current_user: User = Depends(get_current_user)):
        # Superadmin bypasses all permission checks
        if current_user.has_role("superadmin"):
            return current_user

        for permission in self.required_permissions:
            if not current_user.has_permission(permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied. Required: {permission}",
                )
        return current_user
