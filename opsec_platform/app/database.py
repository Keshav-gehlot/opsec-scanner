from __future__ import annotations

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from opsec_platform.app.config import get_settings
from opsec_platform.app.models import Base


def normalize_database_url(url: str) -> str:
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


def make_engine(database_url: str | None = None):
    url = normalize_database_url(database_url or get_settings().database_url)
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        # SQLite's :memory: database is connection-scoped by default —
        # each new connection from a pool gets its own empty database,
        # so init_db()'s CREATE TABLE calls would be invisible to any
        # later request that grabs a different connection (confirmed by
        # actually hitting "no such table: users" when testing this).
        # StaticPool forces every checkout to reuse the same single
        # connection, which is exactly what an in-memory DB needs to
        # behave like one database instead of a new one per connection.
        if ":memory:" in url:
            return create_engine(url, connect_args=connect_args, poolclass=StaticPool)
        return create_engine(url, connect_args=connect_args)
    return create_engine(url)


def make_session_factory(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db(engine) -> None:
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    if "users" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("users")}
        if "is_org_admin" not in columns:
            with engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN is_org_admin BOOLEAN NOT NULL DEFAULT FALSE")
                )
