"""
OAuth/OIDC client registration.

Uses Authlib rather than hand-rolling OAuth2/OIDC flows — hand-rolling
this is a well-known way to introduce real security bugs (state/nonce
validation, PKCE, token verification), and Authlib is a maintained,
widely-used library that gets these details right.

Every provider here needs real credentials from your own developer-
console app registration before it will actually work — see
opsec_platform/README.md for exact steps per provider. Until then,
is_configured is False and the route layer returns a clear "not
configured" error instead of a broken redirect.
"""

from __future__ import annotations

from authlib.integrations.starlette_client import OAuth

from opsec_platform.app.config import Settings

# Redirect URIs to register with each provider (exact string, including
# scheme/host — most providers require an exact match):
#   Google:     {base_url}/auth/oauth/google/callback
#   GitHub:     {base_url}/auth/oauth/github/callback
#   Microsoft:  {base_url}/auth/oauth/microsoft/callback
#   Apple:      {base_url}/auth/oauth/apple/callback


def build_oauth_registry(settings: Settings) -> OAuth:
    oauth = OAuth()

    if settings.google.is_configured:
        oauth.register(
            name="google",
            client_id=settings.google.client_id,
            client_secret=settings.google.client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    if settings.github.is_configured:
        # GitHub isn't an OIDC provider (no discovery doc, no id_token) —
        # registered as a plain OAuth2 client; user identity comes from
        # a REST call to /user after the token exchange, not a userinfo
        # endpoint or id_token claims.
        oauth.register(
            name="github",
            client_id=settings.github.client_id,
            client_secret=settings.github.client_secret,
            access_token_url="https://github.com/login/oauth/access_token",
            authorize_url="https://github.com/login/oauth/authorize",
            api_base_url="https://api.github.com/",
            client_kwargs={"scope": "read:user user:email"},
        )

    if settings.microsoft.is_configured:
        # "common" tenant accepts both personal Microsoft accounts and
        # any organizational (Entra ID) account — the usual choice
        # unless this platform should be restricted to one specific org.
        oauth.register(
            name="microsoft",
            client_id=settings.microsoft.client_id,
            client_secret=settings.microsoft.client_secret,
            server_metadata_url="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    if settings.apple.is_configured:
        # "Sign in with Apple" is OIDC-compliant but unusual: the client
        # secret is a JWT you pre-generate and sign with a private key
        # from your Apple Developer account (not a static string), it
        # expires after at most 6 months and must be regenerated, and
        # it requires response_mode=form_post when requesting name/email
        # scopes. See README for the exact generation steps.
        oauth.register(
            name="apple",
            client_id=settings.apple.client_id,
            client_secret=settings.apple.client_secret,
            server_metadata_url="https://appleid.apple.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email name", "response_mode": "form_post"},
        )

    return oauth


def configured_providers(settings: Settings) -> list[str]:
    # A provider with credentials is still unusable while the deployment
    # is missing its OAuth session secret or public base URL.
    if settings.oauth_config_problems():
        return []
    return [name for name, cfg in settings.oauth_providers().items() if cfg.is_configured]
