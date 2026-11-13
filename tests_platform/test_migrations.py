"""Alembic adoption: fresh databases, pre-Alembic databases with data, and
models/migrations drift."""

from __future__ import annotations

import sqlite3

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text

from opsec_platform.app.database import BASELINE_REVISION, init_db, make_engine, run_migrations
from opsec_platform.app.models import Base


def _revision(engine):
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def _drift(engine):
    with engine.connect() as conn:
        return compare_metadata(MigrationContext.configure(conn), Base.metadata)


def test_fresh_database_gets_full_schema_from_migrations(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    assert run_migrations(engine) == "fresh"
    assert _revision(engine) is not None
    # Every model change must ship with a migration (alembic revision --autogenerate).
    assert _drift(engine) == []


def test_pre_alembic_database_is_adopted_without_losing_data(tmp_path):
    path = tmp_path / "legacy.db"
    # The oldest shape seen in production: users without is_org_admin,
    # findings without status, no alembic_version.
    engine = make_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    engine.dispose()
    con = sqlite3.connect(path)
    con.execute("ALTER TABLE users DROP COLUMN is_org_admin")
    con.execute("ALTER TABLE findings DROP COLUMN status")
    con.execute("INSERT INTO orgs (id, name, created_at) VALUES ('o1', 'Acme', '2026-01-01')")
    con.execute("INSERT INTO users (id, org_id, email, auth_provider, is_active, created_at) "
                "VALUES ('u1', 'o1', 'a@example.com', 'local', 1, '2026-01-01')")
    con.commit()
    con.close()

    engine = make_engine(f"sqlite:///{path}")
    assert run_migrations(engine) == "stamped"
    assert _revision(engine) == BASELINE_REVISION or _revision(engine) is not None
    with engine.connect() as conn:
        assert conn.execute(text("SELECT email, is_org_admin FROM users")).all() == [("a@example.com", 0)]
    assert "status" in {c["name"] for c in inspect(engine).get_columns("findings")}
    assert _drift(engine) == []

    # Second start: nothing to do.
    assert run_migrations(engine) == "upgraded"


def test_init_db_is_idempotent(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'twice.db'}")
    init_db(engine)
    init_db(engine)
    assert _drift(engine) == []


# --- Postgres (CI runs this with a service container; skipped locally if unset) ---

import os
import threading

import pytest

PG_URL = os.environ.get("OPSEC_TEST_POSTGRES_URL", "")


@pytest.mark.skipif(not PG_URL, reason="OPSEC_TEST_POSTGRES_URL not set")
def test_postgres_legacy_adoption_with_concurrent_workers():
    engine = make_engine(PG_URL)
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(text(f'DROP TABLE IF EXISTS "{table.name}" CASCADE'))
        conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users DROP COLUMN is_org_admin"))
        conn.execute(text("INSERT INTO users (id, email, auth_provider, is_active, created_at) "
                          "VALUES ('u1', 'a@example.com', 'google', true, now())"))

    outcomes = []
    workers = [threading.Thread(target=lambda: outcomes.append(run_migrations(make_engine(PG_URL)))) for _ in range(3)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    assert sorted(outcomes) == ["stamped", "upgraded", "upgraded"]
    assert _drift(engine) == []
    with engine.connect() as conn:
        assert conn.execute(text("SELECT email, is_org_admin FROM users")).all() == [("a@example.com", False)]
