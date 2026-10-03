"""Startup database selection must fail loudly, never fall back silently."""

import pytest


def _env(monkeypatch, *, secure, explicit=None, managed=None):
    monkeypatch.setenv("PLATFORM_COOKIE_SECURE", "true" if secure else "false")
    for name, value in (("PLATFORM_DATABASE_URL", explicit), ("DATABASE_URL", managed)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def test_production_without_database_refuses_sqlite_fallback(monkeypatch):
    from opsec_platform.app.database import make_engine

    _env(monkeypatch, secure=True)
    with pytest.raises(RuntimeError, match="No database configured"):
        make_engine()


def test_local_dev_without_database_uses_sqlite(monkeypatch, tmp_path):
    from opsec_platform.app.database import make_engine

    _env(monkeypatch, secure=False)
    monkeypatch.chdir(tmp_path)
    assert make_engine().dialect.name == "sqlite"


def test_invalid_platform_url_names_variable_not_value(monkeypatch):
    from opsec_platform.app.database import make_engine

    _env(monkeypatch, secure=True, explicit="* `postgresql://u:SECRETPW@h/db`")
    with pytest.raises(RuntimeError) as info:
        make_engine()
    assert "PLATFORM_DATABASE_URL is invalid" in str(info.value)
    assert "SECRETPW" not in str(info.value)


def test_invalid_platform_url_falls_back_to_managed(monkeypatch):
    from opsec_platform.app.database import make_engine

    _env(monkeypatch, secure=True, explicit="not a url", managed="sqlite:///:memory:")
    assert make_engine().dialect.name == "sqlite"
