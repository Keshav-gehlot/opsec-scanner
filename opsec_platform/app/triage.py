"""
Optional LLM triage of stored findings.

Enabled with PLATFORM_LLM_TRIAGE=true plus PLATFORM_LLM_API_KEY and
PLATFORM_LLM_MODEL (Anthropic Messages API, the same settings the report
narrative uses). After a scan is stored, its findings are classified in one
background request as:

  likely_real  looks like a genuine exposure worth acting on
  likely_test  placeholder, example, fixture or documentation value
  unclear      not enough context to tell

What leaves the server per finding: rule id, category, source type, the
already-redacted preview (never the matched value) and the first 300
characters of the stored context (a file path or commit reference). The
verdict is advisory: it is shown next to the finding and never changes the
score, status or alerts.
"""

from __future__ import annotations

import json
import logging
import os
import re

logger = logging.getLogger("opsec_platform.triage")

VERDICTS = ("likely_real", "likely_test", "unclear")
MAX_FINDINGS = 40
CONTEXT_CHARS = 300
API_URL = "https://api.anthropic.com/v1/messages"

PROMPT = (
    "You triage findings from an OPSEC leak scanner. For each finding decide whether it is a genuine "
    "exposure (likely_real), a placeholder/example/test/documentation value (likely_test), or cannot be "
    "told from what is shown (unclear). Values are redacted; judge from the rule, the preview shape and "
    "the file/commit context (paths like tests/, fixtures/, examples/, docs/ or values like EXAMPLE, "
    "dummy, xxxx suggest test data). Reply with JSON only: "
    '[{"id": <id>, "verdict": "likely_real|likely_test|unclear", "reason": "<= 20 words"}].\n'
)


def enabled() -> bool:
    return (os.environ.get("PLATFORM_LLM_TRIAGE", "").strip().lower() == "true"
            and bool(os.environ.get("PLATFORM_LLM_API_KEY", "").strip())
            and bool(os.environ.get("PLATFORM_LLM_MODEL", "").strip()))


def _payload(rows) -> list[dict]:
    return [{
        "id": r.id, "rule": r.rule_id, "category": r.category, "source": r.source_type,
        "preview": r.preview, "context": (r.context or "")[:CONTEXT_CHARS],
    } for r in rows]


def _parse(text: str, ids: set[int]) -> dict[int, tuple[str, str]]:
    match = re.search(r"\[.*\]", text, re.S)
    if not match:
        return {}
    try:
        items = json.loads(match.group(0))
    except ValueError:
        return {}
    out: dict[int, tuple[str, str]] = {}
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        fid, verdict = item.get("id"), item.get("verdict")
        if isinstance(fid, int) and fid in ids and verdict in VERDICTS:
            out[fid] = (verdict, str(item.get("reason") or "")[:300])
    return out


def classify(rows, post=None) -> dict[int, tuple[str, str]]:
    """Return {finding_id: (verdict, reason)}; empty on any failure."""
    if not rows:
        return {}
    if post is None:
        import httpx

        post = httpx.post
    key = os.environ.get("PLATFORM_LLM_API_KEY", "").strip()
    model = os.environ.get("PLATFORM_LLM_MODEL", "").strip()
    try:
        response = post(
            API_URL,
            headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": model, "max_tokens": 3000, "messages": [{"role": "user", "content":
                  PROMPT + json.dumps(_payload(rows))}]},
            timeout=45,
        )
        if response.status_code != 200:
            logger.warning("LLM triage request failed with HTTP %s", response.status_code)
            return {}
        text = "".join(b.get("text", "") for b in response.json().get("content", []) if isinstance(b, dict))
    except Exception:
        logger.warning("LLM triage request failed", exc_info=True)
        return {}
    return _parse(text, {r.id for r in rows})


def triage_scan(scan_id: str, post=None) -> int:
    """Classify the highest-risk open findings of one scan. Returns how many were updated."""
    from opsec_platform.app import scan_service as svc
    from opsec_platform.app.models import Finding

    db = svc._session()
    try:
        rows = (db.query(Finding).filter(Finding.scan_id == scan_id, Finding.status == "open",
                                         Finding.ai_verdict.is_(None))
                .order_by(Finding.risk_score.desc()).limit(MAX_FINDINGS).all())
        verdicts = classify(rows, post=post)
        for row in rows:
            if row.id in verdicts:
                row.ai_verdict, row.ai_reason = verdicts[row.id]
        db.commit()
        return len(verdicts)
    finally:
        db.close()
