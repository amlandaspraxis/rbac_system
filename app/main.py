from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.database import engine, Base, SessionLocal
from app.models import User, Role, Permission, RefreshToken, user_roles, role_permissions
from app.utils.audit_logger import AuditLog
from app.routes import auth_router, users_router, roles_router, permissions_router
from app.routes.auth_limiter import limiter

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Default permissions to seed ─────────────────────────────────
DEFAULT_PERMISSIONS = [
    ("users:read", "Read users"),
    ("users:create", "Create users"),
    ("users:update", "Update users"),
    ("users:delete", "Delete users"),
    ("roles:read", "Read roles"),
    ("roles:create", "Create roles"),
    ("roles:update", "Update roles"),
    ("roles:delete", "Delete roles"),
    ("permissions:read", "Read permissions"),
    ("permissions:create", "Create permissions"),
    ("permissions:update", "Update permissions"),
    ("permissions:delete", "Delete permissions"),
]


def seed_superadmin(db: Session):
    """Seed a superadmin user with all permissions if none exists."""
    # Check if superadmin role exists
    superadmin_role = db.query(Role).filter(Role.name == "superadmin").first()
    if superadmin_role:
        return  # Already seeded

    # Create all default permissions
    perm_objects = []
    for perm_name, perm_desc in DEFAULT_PERMISSIONS:
        perm = db.query(Permission).filter(Permission.name == perm_name).first()
        if not perm:
            perm = Permission(name=perm_name, description=perm_desc)
            db.add(perm)
        perm_objects.append(perm)

    db.flush()

    # Create superadmin role with all permissions
    superadmin_role = Role(name="superadmin", description="Super Administrator with all permissions")
    superadmin_role.permissions = perm_objects
    db.add(superadmin_role)
    db.flush()

    # Create superadmin user (pre-verified, active)
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        admin_user = User(
            username="admin",
            email="admin@rbac.local",
            hashed_password=pwd_context.hash("admin123"),
            is_active=True,
            is_verified=True,
            is_superadmin=True,
        )
        db.add(admin_user)
        db.flush()

    admin_user.roles.append(superadmin_role)
    db.commit()
    print("✅ Superadmin seeded: username=admin, password=admin123")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create tables & seed superadmin. Shutdown: cleanup."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_superadmin(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="RBAC System",
    description="Role-Based Access Control API with JWT authentication, role & permission management, and audit logging.",
    version="1.0.0",
    lifespan=lifespan,
)

# ── Rate Limiter ────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ─────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(roles_router)
app.include_router(permissions_router)


@app.get("/", response_class=HTMLResponse, tags=["Health"])
async def root():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>RBAC Security Suite</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
                color: #e0e0e0;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
            }
            .card {
                background: rgba(255,255,255,0.06);
                backdrop-filter: blur(12px);
                border: 1px solid rgba(255,255,255,0.1);
                border-radius: 16px;
                padding: 48px;
                max-width: 520px;
                text-align: center;
                box-shadow: 0 8px 32px rgba(0,0,0,0.4);
            }
            h1 { color: #a78bfa; margin-bottom: 8px; font-size: 2rem; }
            p { color: #94a3b8; line-height: 1.6; }
            a {
                display: inline-block;
                margin-top: 24px;
                padding: 12px 32px;
                background: linear-gradient(135deg, #7c3aed, #a78bfa);
                color: #fff;
                text-decoration: none;
                border-radius: 8px;
                font-weight: 600;
                transition: transform 0.2s, box-shadow 0.2s;
            }
            a:hover { transform: translateY(-2px); box-shadow: 0 4px 20px rgba(167,139,250,0.4); }
            .features { text-align: left; margin: 24px 0; font-size: 0.9rem; }
            .features li { margin: 6px 0; color: #cbd5e1; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🛡️ RBAC Security Suite</h1>
            <p>Role-Based Access Control API with enterprise-grade security.</p>
            <ul class="features">
                <li>✅ JWT Authentication &amp; Refresh Token Rotation</li>
                <li>✅ Email Verification</li>
                <li>✅ Brute-Force Protection &amp; Rate Limiting</li>
                <li>✅ Granular Roles &amp; Permissions</li>
                <li>✅ Audit Logging</li>
            </ul>
            <a href="/docs">Open API Documentation →</a>
        </div>
    </body>
    </html>
    """