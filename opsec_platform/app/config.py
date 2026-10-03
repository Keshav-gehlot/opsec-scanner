"""
Platform configuration.

Everything here is read from environment variables so real secrets
(OAuth client secrets, the JWT signing key) never live in source
control. See platform/.env.example for every variable this reads and
platform/README.md for how to obtain real values for each OAuth
provider — those have to come from your own developer-console app
registrations; nothing here can generate them for you.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


MIN_SECRET_BYTES = 32


def _get(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _int(name: str, default: int) -> int:
    """Positive integer setting; a malformed or non-positive value falls
    back to the default rather than crashing startup."""
    try:
        value = int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass
class OAuthProviderConfig:
    name: str
    client_id: str
    client_secret: str

    @property
    def is_configured(self) -> bool:
        return bool(self.client_id) and bool(self.client_secret)


@dataclass
class Settings:
    jwt_secret: str = field(default_factory=lambda: _get("PLATFORM_JWT_SECRET"))
    jwt_algorithm: str = "HS256"
    session_ttl_minutes: int = field(default_factory=lambda: int(_get("PLATFORM_SESSION_TTL_MINUTES", "480")))

    login_rate_limit_attempts: int = field(default_factory=lambda: int(_get("PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS", "5")))
    login_rate_limit_window_minutes: int = field(default_factory=lambda: int(_get("PLATFORM_LOGIN_RATE_LIMIT_WINDOW_MINUTES", "15")))
    login_ip_rate_limit_attempts: int = field(default_factory=lambda: int(_get("PLATFORM_LOGIN_IP_RATE_LIMIT_ATTEMPTS", "20")))
    login_ip_rate_limit_window_minutes: int = field(default_factory=lambda: int(_get("PLATFORM_LOGIN_IP_RATE_LIMIT_WINDOW_MINUTES", "15")))
    register_rate_limit_attempts: int = field(default_factory=lambda: int(_get("PLATFORM_REGISTER_RATE_LIMIT_ATTEMPTS", "10")))
    register_rate_limit_window_minutes: int = field(default_factory=lambda: int(_get("PLATFORM_REGISTER_RATE_LIMIT_WINDOW_MINUTES", "60")))

    # Explicit app configuration wins so local/test fixtures can force SQLite.
    # Render/Vercel's conventional DATABASE_URL remains the production fallback.
    database_url: str = field(default_factory=lambda: (
        _get("PLATFORM_DATABASE_URL")
        or _get("DATABASE_URL")
        or "sqlite:///./platform.db"
    ))

    # Dedicated key for the short-lived Authlib OAuth state cookie
    # ("opsec_oauth"). Deliberately separate from PLATFORM_JWT_SECRET and
    # never derived from an OAuth provider's client secret.
    oauth_session_secret: str = field(default_factory=lambda: _get("PLATFORM_OAUTH_SESSION_SECRET"))

    base_url: str = field(default_factory=lambda: _get("PLATFORM_BASE_URL", "http://localhost:8000"))
    # True only when PLATFORM_BASE_URL was actually supplied, as opposed to
    # the localhost default above.
    base_url_explicit: bool = field(default_factory=lambda: bool(_get("PLATFORM_BASE_URL").strip()))
    cookie_secure: bool = field(default_factory=lambda: _get("PLATFORM_COOKIE_SECURE", "true").lower() != "false")
    allowed_origins: tuple[str, ...] = field(default_factory=lambda: tuple(o.strip().rstrip("/") for o in _get("PLATFORM_ALLOWED_ORIGINS").split(",") if o.strip()))

    # Web workspace scanning. Server-side scans (uploaded media, public git
    # URLs) can be switched off entirely; JSON/CLI result imports keep working.
    web_scans_enabled: bool = field(default_factory=lambda: _get("PLATFORM_WEB_SCANS_ENABLED", "true").lower() != "false")
    scan_max_concurrent: int = field(default_factory=lambda: _int("PLATFORM_SCAN_MAX_CONCURRENT", 2))
    scan_daily_limit: int = field(default_factory=lambda: _int("PLATFORM_SCAN_DAILY_LIMIT", 30))
    scan_media_max_files: int = field(default_factory=lambda: _int("PLATFORM_SCAN_MEDIA_MAX_FILES", 20))
    scan_media_max_file_mb: int = field(default_factory=lambda: _int("PLATFORM_SCAN_MEDIA_MAX_FILE_MB", 10))
    scan_media_max_total_mb: int = field(default_factory=lambda: _int("PLATFORM_SCAN_MEDIA_MAX_TOTAL_MB", 25))
    scan_import_max_mb: int = field(default_factory=lambda: _int("PLATFORM_SCAN_IMPORT_MAX_MB", 10))
    scan_import_max_findings: int = field(default_factory=lambda: _int("PLATFORM_SCAN_IMPORT_MAX_FINDINGS", 10000))
    scan_git_default_depth: int = field(default_factory=lambda: _int("PLATFORM_SCAN_GIT_DEFAULT_DEPTH", 200))
    scan_git_max_depth: int = field(default_factory=lambda: _int("PLATFORM_SCAN_GIT_MAX_DEPTH", 1000))
    scan_git_max_mb: int = field(default_factory=lambda: _int("PLATFORM_SCAN_GIT_MAX_MB", 200))
    scan_git_timeout_seconds: int = field(default_factory=lambda: _int("PLATFORM_SCAN_GIT_TIMEOUT_SECONDS", 120))
    scan_git_hosts: tuple[str, ...] = field(default_factory=lambda: tuple(
        h.strip().lower() for h in _get("PLATFORM_SCAN_GIT_HOSTS", "github.com,gitlab.com,bitbucket.org,codeberg.org").split(",") if h.strip()
    ))
    api_token_max_days: int = field(default_factory=lambda: _int("PLATFORM_API_TOKEN_MAX_DAYS", 365))

    google: OAuthProviderConfig = field(default_factory=lambda: OAuthProviderConfig(
        "google", _get("GOOGLE_CLIENT_ID"), _get("GOOGLE_CLIENT_SECRET")))
    github: OAuthProviderConfig = field(default_factory=lambda: OAuthProviderConfig(
        "github", _get("GITHUB_CLIENT_ID"), _get("GITHUB_CLIENT_SECRET")))
    microsoft: OAuthProviderConfig = field(default_factory=lambda: OAuthProviderConfig(
        "microsoft", _get("MICROSOFT_CLIENT_ID"), _get("MICROSOFT_CLIENT_SECRET")))
    apple: OAuthProviderConfig = field(default_factory=lambda: OAuthProviderConfig(
        "apple", _get("APPLE_CLIENT_ID"), _get("APPLE_CLIENT_SECRET")))

    def oauth_providers(self) -> dict:
        return {"google": self.google, "github": self.github, "microsoft": self.microsoft, "apple": self.apple}

    def oauth_config_problems(self) -> list[str]:
        """Deployment misconfigurations that make SSO unsafe to run.

        Only enforced for HTTPS deployments (cookie_secure=True); local
        plain-http development keeps working with no extra variables.
        Messages name variables only and never include their values.
        """
        if not self.cookie_secure:
            return []
        problems: list[str] = []
        secret = self.oauth_session_secret
        if len(secret.encode("utf-8")) < MIN_SECRET_BYTES:
            problems.append(
                f"PLATFORM_OAUTH_SESSION_SECRET must be set to at least {MIN_SECRET_BYTES} random bytes."
            )
        elif secret == self.jwt_secret or any(
            secret == cfg.client_secret for cfg in self.oauth_providers().values() if cfg.client_secret
        ):
            problems.append(
                "PLATFORM_OAUTH_SESSION_SECRET must not reuse PLATFORM_JWT_SECRET or an OAuth client secret."
            )
        if not self.base_url_explicit:
            problems.append(
                "PLATFORM_BASE_URL must be set to the public origin users sign in through."
            )
        elif not self.base_url.startswith("https://"):
            problems.append("PLATFORM_BASE_URL must use https:// in HTTPS deployments.")
        return problems


def get_settings() -> Settings:
    return Settings()
