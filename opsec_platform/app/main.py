from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles

from opsec_platform.app.config import get_settings
from opsec_platform.app.dependencies import configure_db
from opsec_platform.app.database import init_db
from opsec_platform.app import auth_routes, oauth_routes, activity_routes
from opsec_platform.app.oauth_providers import configured_providers


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="OPSEC Scanner Platform", version="0.1.0")

    static_dir = Path(__file__).resolve().parents[1] / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Authlib's Starlette integration stores OAuth state/nonce in the
    # request session during the redirect round-trip — needs signed
    # session cookies, distinct from our own JWT session cookie.
    if settings.jwt_secret:
        app.add_middleware(
            SessionMiddleware,
            secret_key=settings.jwt_secret,
            session_cookie="opsec_oauth",
            max_age=600,
            same_site="lax",
            https_only=settings.cookie_secure,
        )

    configure_db()
    from opsec_platform.app.dependencies import _engine
    init_db(_engine)

    # Optional one-time/bootstrap administrator. Credentials come only from
    # deployment secrets; no production password is stored in source control.
    import os
    bootstrap_email = os.environ.get("PLATFORM_BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
    bootstrap_password = os.environ.get("PLATFORM_BOOTSTRAP_ADMIN_PASSWORD", "")
    if bootstrap_email and bootstrap_password:
        from opsec_platform.app.dependencies import _SessionLocal
        from opsec_platform.app.models import Org, User
        from opsec_platform.app.security import hash_password
        db = _SessionLocal()
        try:
            admin = db.query(User).filter(User.email == bootstrap_email).first()
            if admin is None:
                org = db.query(Org).filter(Org.name == "OPSEC Scanner").first()
                if org is None:
                    org = Org(name="OPSEC Scanner")
                    db.add(org)
                    db.flush()
                db.add(User(
                    org_id=org.id,
                    email=bootstrap_email,
                    display_name="Administrator",
                    hashed_password=hash_password(bootstrap_password),
                    auth_provider="local",
                    is_org_admin=True,
                    is_active=True,
                ))
                db.commit()
        finally:
            db.close()


    app.include_router(auth_routes.router)
    app.include_router(oauth_routes.router)
    app.include_router(activity_routes.router)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.get("/")
    def root_redirect():
        return FileResponse(static_dir / "login.html")

    @app.get("/login")
    def login_page():
        return FileResponse(static_dir / "login.html")

    @app.get("/dashboard")
    def dashboard_page():
        return FileResponse(static_dir / "login.html")

    @app.get("/health")
    def health():
        from sqlalchemy import text
        from opsec_platform.app.dependencies import _SessionLocal
        db = _SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            database = "ok"
        except Exception:
            database = "unavailable"
        finally:
            db.close()
        status_code = 200 if database == "ok" else 503
        return JSONResponse(status_code=status_code, content={"status": "ok" if database == "ok" else "degraded", "database": database, "sso_providers_configured": configured_providers(settings)})

    return app


app = create_app()
