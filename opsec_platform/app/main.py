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
        app.add_middleware(SessionMiddleware, secret_key=settings.jwt_secret)

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

