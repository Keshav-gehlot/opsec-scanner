from __future__ import annotations

import logging
import os
import secrets
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles

from opsec_platform.app import activity_routes, auth_routes, monitor_routes, oauth_routes, scan_routes
from opsec_platform.app.config import get_settings
from opsec_platform.app.database import init_db
from opsec_platform.app.dependencies import configure_db
from opsec_platform.app.oauth_providers import configured_providers


APP_VERSION = "0.4.0"
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


def scanner_status() -> dict:
    from opsec_platform.app.scan_service import rules_status

    status = rules_status()
    return {"rules_loaded": status["rules"], "ok": status["ok"], "web_scans_enabled": get_settings().web_scans_enabled}


def create_app() -> FastAPI:
    from opsec_platform.app.logging_setup import configure as configure_logging

    configure_logging()
    settings = get_settings()
    app = FastAPI(title="OPSEC Scanner Platform", version=APP_VERSION)

    if settings.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
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

    from opsec_platform.app.bootstrap import run_bootstrap_admin

    run_bootstrap_admin(
        _SessionLocal,
        os.environ.get("PLATFORM_BOOTSTRAP_ADMIN_EMAIL", ""),
        os.environ.get("PLATFORM_BOOTSTRAP_ADMIN_PASSWORD", ""),
        secure=settings.cookie_secure,
    )

    # Scan jobs run in-process; anything left queued/running by a previous
    # process can never finish, so mark it failed instead of spinning forever.
    db = _SessionLocal()
    try:
        from opsec_platform.app.scan_service import recover_stale_scans
        recover_stale_scans(db)
    except Exception:
        logger.exception("Could not recover stale scans at startup")
    finally:
        db.close()

    app.include_router(auth_routes.router)
    app.include_router(oauth_routes.router)
    app.include_router(activity_routes.router)
    app.include_router(scan_routes.router)
    app.include_router(scan_routes.profile_router)
    app.include_router(monitor_routes.targets_router)
    app.include_router(monitor_routes.findings_router)
    app.include_router(monitor_routes.reports_router)
    app.include_router(monitor_routes.intel_router)
    app.include_router(monitor_routes.integrations_router)

    from opsec_platform.app.osint import scheduler
    scheduler.start()

    trusted_origins = {o.lower() for o in settings.allowed_origins}
    if settings.base_url_explicit:
        trusted_origins.add(settings.base_url.rstrip("/").lower())

    def origin_allowed(request: Request, origin: str) -> bool:
        origin = origin.rstrip("/").lower()
        if origin in trusted_origins:
            return True
        # Same-origin: the browser's Origin host equals the Host it sent the
        # request to (scheme may differ behind the TLS-terminating proxy).
        host = request.headers.get("host", "").lower()
        return bool(host) and origin.split("://", 1)[-1] == host

    @app.middleware("http")
    async def csrf_origin_guard(request: Request, call_next):
        # Defense in depth on top of SameSite=Lax cookies: refuse state-changing
        # browser requests that a foreign site initiated. Requests without an
        # Origin header (CLI/bearer-token clients) are unaffected. Provider
        # form_post callbacks (Apple) legitimately arrive cross-site.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            is_oauth_callback = request.url.path.startswith("/auth/oauth/") and request.url.path.endswith("/callback")
            if origin and not is_oauth_callback and (origin == "null" or not origin_allowed(request, origin)):
                return JSONResponse(status_code=403, content={"detail": "Cross-site request refused."})
        return await call_next(request)

    @app.middleware("http")
    async def platform_middleware(request: Request, call_next):
        supplied_id = request.headers.get("X-Request-ID", "")
        request_id = supplied_id if 0 < len(supplied_id) <= 128 and supplied_id.isprintable() else str(uuid.uuid4())
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

        if request.url.path.startswith(("/auth/", "/activity/", "/dashboard", "/health", "/scans", "/profile", "/login", "/targets", "/findings", "/reports", "/identity", "/intel", "/integrations", "/rules")) or request.url.path == "/":
            response.headers["Cache-Control"] = "no-store"

        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    def page(name: str) -> FileResponse:
        return FileResponse(static_dir / name, media_type="text/html")

    def has_valid_session(request: Request) -> bool:
        from opsec_platform.app.dependencies import SESSION_COOKIE_NAME, get_current_user
        from fastapi import HTTPException

        if not request.cookies.get(SESSION_COOKIE_NAME):
            return False
        db = _SessionLocal()
        try:
            get_current_user(request, db)
            return True
        except HTTPException:
            return False
        finally:
            db.close()

    # The sign-in page and the workspace are separate documents, and the
    # server decides which one to send. Previously /dashboard served the
    # login markup and JavaScript swapped views after load, which flashed
    # the sign-in form on every visit.
    @app.get("/", include_in_schema=False)
    def root(request: Request):
        if has_valid_session(request):
            return RedirectResponse("/dashboard", status_code=302)
        return page("login.html")

    @app.get("/login", include_in_schema=False)
    def login_page(request: Request):
        if has_valid_session(request):
            return RedirectResponse("/dashboard", status_code=302)
        return page("login.html")

    @app.get("/dashboard", include_in_schema=False)
    def dashboard_page(request: Request):
        if not has_valid_session(request):
            return RedirectResponse("/login", status_code=302)
        return page("app.html")

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
                "scanner": scanner_status(),
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
