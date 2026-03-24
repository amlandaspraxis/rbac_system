from app.routes.auth import router as auth_router
from app.routes.users import router as users_router
from app.routes.roles import router as roles_router
from app.routes.permissions import router as permissions_router

__all__ = ["auth_router", "users_router", "roles_router", "permissions_router"]
