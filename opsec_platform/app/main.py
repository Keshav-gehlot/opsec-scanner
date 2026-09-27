from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
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
        app.add_middleware(SessionMiddleware, secret_key=settings.jwt_secret)

    configure_db()
    from opsec_platform.app.dependencies import _engine
    init_db(_engine)

    # Bootstrap the requested fixed local administrator account. This is
    # idempotent, so a fresh Render filesystem/redeploy still has a usable admin.
    from opsec_platform.app.dependencies import _SessionLocal
    from opsec_platform.app.models import Org, User
    from opsec_platform.app.security import hash_password
    db = _SessionLocal()
    try:
        admin = db.query(User).filter(User.email == "admin@opsecscanner.com").first()
        if admin is None:
            org = db.query(Org).filter(Org.name == "OPSEC Scanner").first()
            if org is None:
                org = Org(name="OPSEC Scanner")
                db.add(org)
                db.flush()
            db.add(User(
                org_id=org.id,
                email="admin@opsecscanner.com",
                display_name="Administrator",
                hashed_password=hash_password("admin12345"),
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
        return {"status": "ok", "sso_providers_configured": configured_providers(settings)}

    return app


app = create_app()
