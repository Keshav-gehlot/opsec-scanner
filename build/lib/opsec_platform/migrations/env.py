"""Alembic environment for the platform database.

Used both by the `alembic` CLI (alembic.ini at the repo root) and by
opsec_platform.app.database.run_migrations at startup, which passes its
own connection in config.attributes["connection"].
"""

from __future__ import annotations

from alembic import context

from opsec_platform.app.models import Base

config = context.config
target_metadata = Base.metadata


def _configure(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",  # SQLite cannot ALTER most things
        compare_type=True,
    )


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        with context.begin_transaction():
            context.run_migrations()
        return

    from opsec_platform.app.database import make_engine

    url = config.get_main_option("sqlalchemy.url") or None
    engine = make_engine(url)
    try:
        with engine.connect() as conn:
            _configure(conn)
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise SystemExit("Offline (--sql) mode is not supported; run against a database.")
run_migrations_online()
