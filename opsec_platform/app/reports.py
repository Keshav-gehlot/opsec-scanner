"""
Executive summary, exposure index, identity graph and PDF/TXT rendering.

Everything here is computed from stored scans — no hardcoded numbers.
The optional AI narrative only receives aggregate, already-redacted data
(counts, rule ids, categories, target labels) and is off unless
PLATFORM_LLM_API_KEY and PLATFORM_LLM_MODEL are set.
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict

from opsec_platform.app import scan_service as svc
from opsec_platform.app.models import Finding, MonitoredTarget, Scan

RECOMMENDATIONS = {
    "credentials": "Rotate every exposed credential first, then remove it from history (git filter-repo / BFG) and add a pre-push scan.",
    "misconfiguration": "Block public access to repository metadata, environment files and backups at the web server, then redeploy.",
    "email_security": "Publish SPF ending in -all and a DMARC policy of quarantine or reject to stop domain spoofing.",
    "infrastructure": "Avoid leaking internal hostnames/IPs: use public DNS names in code and keep dev/staging hosts off public certificates or behind auth.",
    "personal": "Strip personal emails, phone numbers and WHOIS contact data; enable registrar privacy.",
    "personal_id": "Remove national ID numbers from public artifacts and treat affected files as a data-protection incident.",
    "financial": "Remove payment or bank data immediately and check whether it must be reported under PCI-DSS or local law.",
    "system": "Strip local usernames and paths from build artifacts and documents (they reveal real names and machines).",
    "code_exposure": "Review the public repositories mentioning your identifiers for copied secrets or internal details.",
}
LABEL_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.5, "MEDIUM": 0.15, "LOW": 0.03}


def latest_scans(db, user_id: str, org_id: str | None = None, scope: str = "mine") -> list[Scan]:
    query = db.query(Scan).filter(Scan.status == "completed")
    query = query.filter(Scan.org_id == org_id) if scope == "org" else query.filter(Scan.user_id == user_id)
    latest: dict[tuple, Scan] = {}
    for scan in query.order_by(Scan.created_at.asc()).all():
        latest[(scan.user_id, scan.target_label)] = scan
    return list(latest.values())


def open_findings(db, scans: list[Scan]) -> list[Finding]:
    ids = [s.id for s in scans]
    if not ids:
        return []
    return db.query(Finding).filter(Finding.scan_id.in_(ids), Finding.status.notin_(svc.CLOSED_STATUSES)).all()


def exposure_index(findings: list[Finding]) -> float:
    """0–10. Dominated by the worst open finding, raised by volume:
    max_score * 0.7 + min(3, Σ label weights). Documented in the UI."""
    if not findings:
        return 0.0
    worst = max(f.risk_score for f in findings)
    volume = min(3.0, sum(LABEL_WEIGHT.get(f.risk_label, 0) for f in findings))
    return round(min(10.0, worst * 0.7 + volume), 1)


def summary(db, user, scope: str = "mine") -> dict:
    scans = latest_scans(db, user.id, user.org_id, scope)
    findings = open_findings(db, scans)
    counts = Counter(f.risk_label for f in findings)
    by_category = Counter(f.category for f in findings)
    meta = svc.rule_meta()
    top = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:10]
    target_rows = []
    for scan in sorted(scans, key=lambda s: s.max_risk_score, reverse=True):
        rows = [f for f in findings if f.scan_id == scan.id]
        target_rows.append({"target": scan.target_label, "scan_id": scan.id, "source": scan.source,
                            "scanned_at": scan.completed_at, "open": len(rows), "index": exposure_index(rows)})
    mitre = Counter(meta.get(f.rule_id, {}).get("mitre") for f in findings if meta.get(f.rule_id, {}).get("mitre"))
    triage = Counter(row[0] for row in db.query(Finding.status).filter(Finding.scan_id.in_([s.id for s in scans] or [""])).all())
    data = {
        "scope": scope,
        "exposure_index": exposure_index(findings),
        "targets": len(scans),
        "open_findings": len(findings),
        "counts": {label: counts.get(label, 0) for label in svc.RISK_LABELS},
        "categories": [{"category": c, "count": n} for c, n in by_category.most_common()],
        "mitre": [{"technique": t, "count": n} for t, n in mitre.most_common(10)],
        "triage": dict(triage),
        "top_findings": [
            {"id": f.id, "scan_id": f.scan_id, "rule_id": f.rule_id, "risk_label": f.risk_label, "risk_score": f.risk_score,
             "category": f.category, "preview": f.preview, "origin": f.origin,
             "description": meta.get(f.rule_id, {}).get("description"), "mitre": meta.get(f.rule_id, {}).get("mitre")}
            for f in top
        ],
        "by_target": target_rows,
        "recommendations": [
            {"category": c, "text": RECOMMENDATIONS[c]} for c, _ in by_category.most_common() if c in RECOMMENDATIONS
        ][:6],
    }
    data["narrative"] = ai_narrative(data)
    return data


def ai_narrative(data: dict) -> str | None:
    key = os.environ.get("PLATFORM_LLM_API_KEY", "").strip()
    model = os.environ.get("PLATFORM_LLM_MODEL", "").strip()
    if not key or not model or not data["open_findings"]:
        return None
    facts = {
        "exposure_index": data["exposure_index"], "open_findings": data["open_findings"], "counts": data["counts"],
        "categories": data["categories"], "mitre": data["mitre"],
        "top": [{"rule": f["rule_id"], "severity": f["risk_label"], "category": f["category"]} for f in data["top_findings"]],
    }
    try:
        import httpx

        response = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": model, "max_tokens": 400, "messages": [{"role": "user", "content":
                  "Write a 4-sentence executive summary of this OPSEC exposure report for a non-technical "
                  "manager. Be factual, no invented numbers, end with the single most important action.\n"
                  + json.dumps(facts)}]},
            timeout=20,
        )
        if response.status_code == 200:
            return "".join(block.get("text", "") for block in response.json().get("content", []))[:2000] or None
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# Identity graph
# ---------------------------------------------------------------------------

def identity_graph(db, user) -> dict:
    profile = svc.load_profile_data(db, user)
    nodes, edges = [], []
    seen = set()

    def node(nid, kind, label, **extra):
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "kind": kind, "label": label, **extra})
        return nid

    root = node("person", "person", profile.get("name") or user.email)
    for kind, key in (("email", "emails"), ("domain", "domains"), ("handle", "github_handles"), ("alias", "aliases")):
        for value in profile.get(key) or []:
            edges.append({"from": root, "to": node(f"{kind}:{value.lower()}", kind, value), "label": "identity"})
    for target in db.query(MonitoredTarget).filter(MonitoredTarget.user_id == user.id).all():
        tid = node(f"target:{target.id}", "target", f"{target.kind}: {target.value}", verified=bool(target.verified_at))
        anchor = {"domain": f"domain:{target.value}", "email": f"email:{target.value}", "github_handle": f"handle:{target.value.lower()}"}.get(target.kind)
        edges.append({"from": anchor if anchor in seen else root, "to": tid, "label": "monitored"})

    scans = latest_scans(db, user.id)
    findings = open_findings(db, scans)
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.scan_id, f.rule_id)].append(f)
    for scan in scans:
        sid = node(f"scan:{scan.id}", "scan", scan.target_label, scan_id=scan.id)
        linked = False
        for t in db.query(MonitoredTarget).filter(MonitoredTarget.last_scan_id == scan.id).all():
            edges.append({"from": f"target:{t.id}", "to": sid, "label": "scanned"})
            linked = True
        if not linked:
            edges.append({"from": root, "to": sid, "label": "scanned"})
    for (scan_id, rule_id), rows in sorted(groups.items(), key=lambda kv: -max(f.risk_score for f in kv[1]))[:40]:
        worst = max(rows, key=lambda f: f.risk_score)
        fid = node(f"rule:{scan_id}:{rule_id}", "finding", rule_id, risk_label=worst.risk_label, count=len(rows),
                   scan_id=scan_id, correlated=any((f.identity_confidence or 0) > 1 for f in rows))
        edges.append({"from": f"scan:{scan_id}", "to": fid, "label": f"{len(rows)}×"})
        for f in rows:
            reason = (f.identity_reason or "")
            if "'" in reason and (f.identity_confidence or 0) > 1:
                matched = reason.split("'")[1].lower()
                for prefix in ("email", "domain", "handle", "alias"):
                    if f"{prefix}:{matched}" in seen:
                        edges.append({"from": f"{prefix}:{matched}", "to": fid, "label": "correlates"})
                        break
    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def summary_text(data: dict, title: str) -> str:
    out = [title, "=" * len(title), "",
           f"Exposure index: {data['exposure_index']} / 10",
           f"Open findings: {data['open_findings']} across {data['targets']} target(s)",
           "Severity: " + ", ".join(f"{k} {v}" for k, v in data["counts"].items()), ""]
    if data.get("narrative"):
        out += ["Summary", "-------", data["narrative"], ""]
    out += ["Top findings", "------------"]
    for f in data["top_findings"]:
        out.append(f"[{f['risk_label']}] {f['risk_score']:.1f} {f['rule_id']} {f['preview']}  {f.get('mitre') or ''}")
        out.append(f"    {f['origin'] or ''}")
    out += ["", "Recommended actions", "-------------------"]
    out += [f"- {r['text']}" for r in data["recommendations"]] or ["- No open findings."]
    out += ["", "By target", "---------"]
    out += [f"- {t['target']}: {t['open']} open, index {t['index']}" for t in data["by_target"]]
    return "\n".join(out) + "\n"


def text_to_pdf(text: str) -> bytes:
    """Plain, dependency-light PDF (PyMuPDF is already a scanner dependency;
    WeasyPrint needs system libraries hosts often lack)."""
    import fitz

    doc = fitz.open()
    # Base-14 Courier covers Windows-1252; replace anything outside it.
    lines = text.encode("cp1252", "replace").decode("cp1252").splitlines()
    per_page = 60
    for start in range(0, max(1, len(lines)), per_page):
        page = doc.new_page(width=595, height=842)
        y = 48
        for line in lines[start:start + per_page]:
            for chunk in [line[i:i + 100] for i in range(0, max(1, len(line)), 100)]:
                page.insert_text((40, y), chunk, fontsize=9, fontname="cour")
                y += 12.5
    data = doc.tobytes()
    doc.close()
    return data
