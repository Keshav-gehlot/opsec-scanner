from __future__ import annotations

import logging
import os
import secrets
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles

from opsec_platform.app import activity_routes, auth_routes, oauth_routes
from opsec_platform.app.config import get_settings
from opsec_platform.app.database import init_db
from opsec_platform.app.dependencies import configure_db
from opsec_platform.app.oauth_providers import configured_providers


APP_VERSION = "0.2.2"
logger = logging.getLogger(__name__)


def deployed_commit() -> str | None:
    """Short git SHA of the running build, from the host platform.

    APP_VERSION is a hand-maintained string, so it cannot prove which
    build is live; the platform-provided commit can.
    """
    for name in ("RENDER_GIT_COMMIT", "VERCEL_GIT_COMMIT_SHA", "PLATFORM_GIT_COMMIT"):
        value = os.environ.get(name, "").strip()
        if value:
            return value[:12]
    return None


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="OPSEC Scanner Platform", version=APP_VERSION)

    if settings.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        )

    static_dir = Path(__file__).resolve().parents[1] / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Authlib stores OAuth state in the Starlette session cookie. It is
    # signed with its own dedicated secret: never PLATFORM_JWT_SECRET and
    # never an OAuth provider's client secret. HTTPS deployments must
    # supply PLATFORM_OAUTH_SESSION_SECRET (see Settings.oauth_config_problems;
    # the OAuth routes refuse to run without it). Plain-http local
    # development gets an ephemeral per-process key so it needs no setup.
    oauth_enabled = any(cfg.is_configured for cfg in settings.oauth_providers().values())
    oauth_session_secret = settings.oauth_session_secret
    if not oauth_session_secret and oauth_enabled and not settings.cookie_secure:
        oauth_session_secret = secrets.token_urlsafe(32)
    for problem in settings.oauth_config_problems() if oauth_enabled else []:
        logger.error("SSO disabled until fixed: %s", problem)
    if oauth_enabled and oauth_session_secret:
        app.add_middleware(
            SessionMiddleware,
            secret_key=oauth_session_secret,
            session_cookie="opsec_oauth",
            max_age=600,
            same_site="lax",
            https_only=settings.cookie_secure,
        )

    configure_db()
    from opsec_platform.app.dependencies import _SessionLocal, _engine
    init_db(_engine)

    bootstrap_email = os.environ.get("PLATFORM_BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
    bootstrap_password = os.environ.get("PLATFORM_BOOTSTRAP_ADMIN_PASSWORD", "")
    if bootstrap_email and bootstrap_password:
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
            elif not admin.is_org_admin:
                admin.is_org_admin = True
                db.commit()
        finally:
            db.close()

    app.include_router(auth_routes.router)
    app.include_router(oauth_routes.router)
    app.include_router(activity_routes.router)

    @app.middleware("http")
    async def platform_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        response = await call_next(request)

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "style-src 'self'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )

        if request.url.path.startswith(("/auth/", "/activity/", "/dashboard", "/health")):
            response.headers["Cache-Control"] = "no-store"

        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.get("/", include_in_schema=False)
    def root():
        return FileResponse(static_dir / "login.html")

    @app.get("/login", include_in_schema=False)
    def login_page():
        return FileResponse(static_dir / "login.html")

    @app.get("/dashboard", include_in_schema=False)
    def dashboard_page():
        return FileResponse(static_dir / "login.html")

    def database_check() -> str:
        from sqlalchemy import text
        from opsec_platform.app.dependencies import _SessionLocal

        db = _SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            return "ok"
        except Exception:
            return "unavailable"
        finally:
            db.close()

    @app.get("/health")
    def health():
        database = database_check()
        status_code = 200 if database == "ok" else 503
        return JSONResponse(
            status_code=status_code,
            content={
                "status": "ok" if database == "ok" else "degraded",
                "version": APP_VERSION,
                "commit": deployed_commit(),
                "database": database,
                "sso_providers_configured": configured_providers(settings),
            },
        )

    @app.get("/health/live", include_in_schema=False)
    def liveness():
        return {"status": "ok", "version": APP_VERSION, "commit": deployed_commit()}

    @app.get("/health/ready", include_in_schema=False)
    def readiness():
        database = database_check()
        status_code = 200 if database == "ok" else 503
        return JSONResponse(
            status_code=status_code,
            content={"status": "ready" if database == "ok" else "not_ready", "database": database},
        )

    return app


app = create_app()
