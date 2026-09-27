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


def _get(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@dataclass
class OAuthProviderConfig:
    name: str
    client_id: str
    client_secret: str
    # Populated per-provider in Settings — kept here so "is this provider
    # configured" is one check (non-empty id+secret) regardless of provider.
    @property
    def is_configured(self) -> bool:
        return bool(self.client_id) and bool(self.client_secret)


@dataclass
class Settings:
    # Session / JWT signing. HS256 (symmetric) for simplicity — swap to
    # RS256 with a real keypair if this ever needs to verify tokens in a
    # separate service that shouldn't hold the signing secret.
    jwt_secret: str = field(default_factory=lambda: _get("PLATFORM_JWT_SECRET"))
    jwt_algorithm: str = "HS256"
    session_ttl_minutes: int = field(default_factory=lambda: int(_get("PLATFORM_SESSION_TTL_MINUTES", "480")))  # 8 hours

    # Login rate limiting — counts recent failed attempts for the target
    # email from the activity log itself rather than a separate
    # in-memory store, so it's persisted, auditable, and correct across
    # multiple app processes sharing one database.
    login_rate_limit_attempts: int = field(default_factory=lambda: int(_get("PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS", "5")))
    login_rate_limit_window_minutes: int = field(default_factory=lambda: int(_get("PLATFORM_LOGIN_RATE_LIMIT_WINDOW_MINUTES", "15")))

    # Second layer of protection: block a client IP once it has produced
    # too many failed login attempts across one or more target accounts,
    # regardless of whether the rate-limited email would otherwise pass
    # the per-account threshold. This complements the email-based limiter
    # and is especially important in environments that expose one public
    # IP to many users.
    login_ip_rate_limit_attempts: int = field(default_factory=lambda: int(_get("PLATFORM_LOGIN_IP_RATE_LIMIT_ATTEMPTS", "20")))
    login_ip_rate_limit_window_minutes: int = field(default_factory=lambda: int(_get("PLATFORM_LOGIN_IP_RATE_LIMIT_WINDOW_MINUTES", "15")))

    database_url: str = field(default_factory=lambda: _get("PLATFORM_DATABASE_URL", "sqlite:///./platform.db"))

    base_url: str = field(default_factory=lambda: _get("PLATFORM_BASE_URL", "http://localhost:8000"))

    # Session cookies must be Secure (HTTPS-only) in any real deployment
    # — never send a session token over plain HTTP. But that same
    # correctness breaks local http://localhost development and testing
    # outright, since a Secure cookie is silently dropped by the client
    # over an insecure connection (confirmed directly: TestClient's
    # plain-http requests never sent the cookie back, causing every
    # "login then make an authenticated request" test to 401). Default
    # to secure and require an explicit opt-out, so this can't
    # accidentally ship insecure — but make the opt-out available.
    cookie_secure: bool = field(default_factory=lambda: _get("PLATFORM_COOKIE_SECURE", "true").lower() != "false")

    google: OAuthProviderConfig = field(default_factory=lambda: OAuthProviderConfig(
        "google", _get("GOOGLE_CLIENT_ID"), _get("GOOGLE_CLIENT_SECRET")))
    github: OAuthProviderConfig = field(default_factory=lambda: OAuthProviderConfig(
        "github", _get("GITHUB_CLIENT_ID"), _get("GITHUB_CLIENT_SECRET")))
    microsoft: OAuthProviderConfig = field(default_factory=lambda: OAuthProviderConfig(
        "microsoft", _get("MICROSOFT_CLIENT_ID"), _get("MICROSOFT_CLIENT_SECRET")))
    # Apple's OAuth ("Sign in with Apple") uses a JWT as the client secret,
    # signed with a private key from your Apple Developer account, instead
    # of a static string — see README for how APPLE_CLIENT_SECRET is
    # actually a pre-generated signed JWT, not a plain secret.
    apple: OAuthProviderConfig = field(default_factory=lambda: OAuthProviderConfig(
        "apple", _get("APPLE_CLIENT_ID"), _get("APPLE_CLIENT_SECRET")))

    def oauth_providers(self) -> dict:
        return {"google": self.google, "github": self.github, "microsoft": self.microsoft, "apple": self.apple}


def get_settings() -> Settings:
    # Re-read on every call rather than caching a module-level singleton —
    # makes it trivial to test different configurations by setting env
    # vars per-test without import-order/caching headaches.
    return Settings()
