"""
Email sender utility.
Gracefully degrades if fastapi-mail is not installed or misconfigured.
"""
from app.config import settings

# Try to import fastapi-mail; if it fails, email sending is disabled
_mail_available = False
try:
    from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType

    if settings.MAIL_USERNAME:
        conf = ConnectionConfig(
            MAIL_USERNAME=settings.MAIL_USERNAME,
            MAIL_PASSWORD=settings.MAIL_PASSWORD,
            MAIL_FROM=settings.MAIL_FROM,
            MAIL_PORT=settings.MAIL_PORT,
            MAIL_SERVER=settings.MAIL_SERVER,
            MAIL_STARTTLS=settings.MAIL_STARTTLS,
            MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
            USE_CREDENTIALS=True,
        )
        _mail_available = True
except Exception:
    pass


async def send_verification_email(email: str, token: str):
    """Send email verification link. Prints to console if mail is not configured."""
    if not _mail_available or not settings.MAIL_USERNAME:
        print(f"⚠️  Mail not configured. Verification token for {email}: {token}")
        return

    verify_url = f"http://localhost:8000/auth/verify-email?token={token}"
    message = MessageSchema(
        subject="Verify your email — RBAC System",
        recipients=[email],
        body=f"""
        <h3>Welcome to the RBAC System!</h3>
        <p>Click the link below to verify your email address:</p>
        <a href="{verify_url}">{verify_url}</a>
        <p>This link expires in 24 hours.</p>
        """,
        subtype=MessageType.html,
    )
    fm = FastMail(conf)
    await fm.send_message(message)