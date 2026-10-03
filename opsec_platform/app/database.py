from __future__ import annotations

import logging
import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from opsec_platform.app.config import get_settings
from opsec_platform.app.models import Base

logger = logging.getLogger(__name__)

_ALLOWED_DRIVERS = {"sqlite", "postgresql", "postgresql+psycopg"}


def normalize_database_url(raw: str | None) -> str:
    url = (raw or "").strip().strip("\"'").strip()
    if not url:
        raise RuntimeError("Database URL is empty (check PLATFORM_DATABASE_URL or DATABASE_URL).")
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    try:
        parsed = make_url(url)
    except ArgumentError:
        raise RuntimeError(
            "Database URL is not a valid SQLAlchemy URL. Check for stray quotes/"
            "whitespace, leftover placeholders, and URL-encode special characters "
            "in the password (@ -> %40, # -> %23, / -> %2F)."
        ) from None
    if parsed.drivername not in _ALLOWED_DRIVERS:
        raise RuntimeError(
            f"Unsupported database URL scheme '{parsed.drivername}'. "
            "Use postgresql://, postgresql+psycopg://, or sqlite://."
        )
    return url


def make_engine(database_url: str | None = None):
    if database_url is not None:
        url = normalize_database_url(database_url)
    else:
        settings = get_settings()
        explicit = os.environ.get("PLATFORM_DATABASE_URL", "").strip()
        managed = os.environ.get("DATABASE_URL", "").strip()

        if explicit:
            try:
                url = normalize_database_url(explicit)
            except RuntimeError:
                # Render can inject its managed DATABASE_URL separately. If a
                # stale PLATFORM_DATABASE_URL is malformed, prefer the managed
                # database rather than bringing the whole service down.
                if not managed:
                    raise
                logger.warning("PLATFORM_DATABASE_URL is invalid; using managed DATABASE_URL instead.")
                url = normalize_database_url(managed)
        elif managed:
            url = normalize_database_url(managed)
        else:
            url = normalize_database_url(settings.database_url)

    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        if ":memory:" in url:
            return create_engine(url, connect_args=connect_args, poolclass=StaticPool)
        return create_engine(url, connect_args=connect_args)
    return create_engine(url, pool_pre_ping=True)


def make_session_factory(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _user_columns(engine) -> set[str]:
    return {column["name"] for column in inspect(engine).get_columns("users")}


def ensure_schema_compat(engine) -> None:
    """Bridge the legacy is_org_admin column until Alembic owns schema changes."""
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return
    if "is_org_admin" in _user_columns(engine):
        return

    false_literal = "FALSE" if engine.dialect.name == "postgresql" else "0"
    try:
        with engine.begin() as connection:
            connection.execute(text(
                f"ALTER TABLE users ADD COLUMN is_org_admin BOOLEAN NOT NULL DEFAULT {false_literal}"
            ))
    except Exception:
        # Multiple workers can initialize simultaneously. If another worker
        # already added the column, this worker can safely continue.
        if "is_org_admin" not in _user_columns(engine):
            raise


def init_db(engine) -> None:
    Base.metadata.create_all(bind=engine)
    ensure_schema_compat(engine)
