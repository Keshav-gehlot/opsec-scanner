"""
Opt-in live verification of found credentials (`--verify-secrets`).

For credential types whose issuer offers a harmless "who am I" call, ask the
issuer whether the value still works. A live credential is escalated to
CRITICAL (it grants access right now); a rejected one stays in the report,
marked revoked, because it still shows that secrets were committed.

Safety rules:
- Only ever sent to the credential's own issuer, over HTTPS, to a read-only
  identity endpoint. No other host ever sees a value.
- Never logged or printed; only the outcome is recorded.
- Off by default. Each unique value is checked once, up to MAX_CHECKS per run.
- Types that cannot be checked from the value alone are skipped (an AWS
  access key ID needs its secret key; a Google API key has no neutral call).

Outcome per finding, in metadata["verification"]:
  "active"   the issuer accepted it
  "inactive" the issuer rejected it (revoked / expired / fake)
  "unknown"  network error, rate limit or an unexpected answer
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from opsec_scanner.scoring.risk_engine import ScoredFinding

MAX_CHECKS = 50
TIMEOUT_SECONDS = 8.0


@dataclass(frozen=True)
class Check:
    method: str
    url: str
    headers: Callable[[str], dict]
    active: Callable[[int, dict | None], bool | None]  # True / False / None (unknown)
    auth: Callable[[str], tuple[str, str]] | None = None


def _status_only(ok: int = 200, bad: tuple[int, ...] = (401,)):
    # 403 is ambiguous (rate limit, missing scope on a valid token): unknown.
    def judge(status: int, _body: dict | None) -> bool | None:
        if status == ok:
            return True
        if status in bad:
            return False
        return None
    return judge


def _json_ok_flag(status: int, body: dict | None) -> bool | None:
    if status != 200 or body is None:
        return None if status >= 500 or status == 429 else False
    return bool(body.get("ok"))


CHECKS: dict[str, Check] = {
    "github_pat": Check("GET", "https://api.github.com/user",
                        lambda v: {"Authorization": f"Bearer {v}", "Accept": "application/vnd.github+json"},
                        _status_only()),
    "slack_token": Check("POST", "https://slack.com/api/auth.test",
                         lambda v: {"Authorization": f"Bearer {v}"}, _json_ok_flag),
    # A restricted key without balance access answers 403: still a live key.
    "stripe_key": Check("GET", "https://api.stripe.com/v1/balance", lambda v: {},
                        lambda status, _b: True if status in (200, 403) else (False if status == 401 else None),
                        auth=lambda v: (v, "")),
    "openai_api_key": Check("GET", "https://api.openai.com/v1/models",
                            lambda v: {"Authorization": f"Bearer {v}"}, _status_only()),
    "anthropic_api_key": Check("GET", "https://api.anthropic.com/v1/models",
                               lambda v: {"x-api-key": v, "anthropic-version": "2023-06-01"}, _status_only()),
    "sendgrid_api_key": Check("GET", "https://api.sendgrid.com/v3/scopes",
                              lambda v: {"Authorization": f"Bearer {v}"}, _status_only()),
    "npm_token": Check("GET", "https://registry.npmjs.org/-/whoami",
                       lambda v: {"Authorization": f"Bearer {v}"}, _status_only()),
    "telegram_bot_token": Check("GET", "https://api.telegram.org/bot{value}/getMe", lambda v: {}, _json_ok_flag),
}

# Stripe publishable keys (pk_) are meant to be public; checking them proves nothing.
_SKIP = {"stripe_key": re.compile(r"^pk_")}


def verifiable(rule_id: str, value: str) -> bool:
    skip = _SKIP.get(rule_id)
    return rule_id in CHECKS and not (skip and skip.match(value))


def check_one(rule_id: str, value: str, client) -> str:
    spec = CHECKS[rule_id]
    url = spec.url.replace("{value}", value)
    try:
        response = client.request(spec.method, url, headers=spec.headers(value),
                                  auth=spec.auth(value) if spec.auth else None, timeout=TIMEOUT_SECONDS)
    except Exception:
        return "unknown"
    try:
        body = response.json()
    except Exception:
        body = None
    verdict = spec.active(response.status_code, body if isinstance(body, dict) else None)
    return "unknown" if verdict is None else ("active" if verdict else "inactive")


def verify_findings(scored: list[ScoredFinding], client=None, max_checks: int = MAX_CHECKS) -> dict[str, int]:
    """Annotates findings in place (metadata["verification"]) and escalates
    live credentials to CRITICAL. Returns counts per outcome."""
    from opsec_scanner.scoring.risk_engine import RISK_BANDS

    critical_floor = next(t for t, label in RISK_BANDS if label == "CRITICAL")
    owns = client is None
    if owns:
        import httpx

        # No redirects: a value must never be forwarded to another host.
        client = httpx.Client(follow_redirects=False, headers={"User-Agent": "opsec-scanner-verify"})
    counts = {"active": 0, "inactive": 0, "unknown": 0, "skipped": 0}
    cache: dict[tuple[str, str], str] = {}
    try:
        for s in scored:
            rule, value = s.match.rule_id, s.match.matched_text
            if not verifiable(rule, value):
                continue
            key = (rule, value)
            if key not in cache:
                if len(cache) >= max_checks:
                    counts["skipped"] += 1
                    continue
                cache[key] = check_one(rule, value, client)
            outcome = cache[key]
            s.match.finding.metadata["verification"] = outcome
            counts[outcome] += 1
            if outcome == "active" and s.risk_score < critical_floor:
                s.risk_score = critical_floor
                s.risk_label = "CRITICAL"
                s.identity_reason = f"{s.identity_reason}; credential verified ACTIVE with its issuer"
            elif outcome == "inactive":
                s.identity_reason = f"{s.identity_reason}; issuer rejected it (revoked or invalid)"
    finally:
        if owns:
            client.close()
    scored.sort(key=lambda s: s.risk_score, reverse=True)
    return counts
