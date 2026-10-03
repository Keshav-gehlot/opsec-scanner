"""
Collection modules for monitored (ownership-verified) targets.

Each collector returns a CollectorResult:
  raw     text fragments (RawFinding) that go through the regular detection
          rules — same engine and rules as the CLI;
  direct  findings that are facts rather than pattern matches (an exposed
          .git directory, a missing DMARC record, a breach listing...);
  intel   structured context for the Domain & Infra view (records,
          subdomains, IP owners);
  notes   human-readable remarks (a source skipped for lack of an API key).

Network access: user-influenced URLs only go through net.safe_request.
Fixed public APIs (crt.sh, rdap.org, api.github.com, haveibeenpwned.com,
api.shodan.io) use net.api_get.
"""

from __future__ import annotations

import os
import re
from collections import deque
from dataclasses import dataclass, field
from html import unescape
from urllib.parse import quote, urldefrag, urljoin, urlparse
from urllib.robotparser import RobotFileParser

from opsec_scanner.models import RawFinding, SourceType

from opsec_platform.app.osint import net
from opsec_platform.app.osint.verification import domain_covers


@dataclass
class DirectFinding:
    rule_id: str
    matched_text: str
    origin: str
    context: str = ""


@dataclass
class CollectorResult:
    raw: list[RawFinding] = field(default_factory=list)
    direct: list[DirectFinding] = field(default_factory=list)
    intel: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def extend(self, other: "CollectorResult") -> None:
        self.raw.extend(other.raw)
        self.direct.extend(other.direct)
        for key, value in other.intel.items():
            self.intel.setdefault(key, value)
        self.notes.extend(other.notes)


# id -> (category, base_severity, mitre, description)
DIRECT_RULES: dict[str, tuple[str, float, str, str]] = {
    "exposed_git_directory": ("misconfiguration", 9.0, "T1213", "Public /.git directory: full source history downloadable"),
    "exposed_env_file": ("credentials", 9.5, "T1552.001", "Public .env file"),
    "exposed_backup_file": ("misconfiguration", 7.5, "T1213", "Downloadable backup or database dump"),
    "exposed_ds_store": ("misconfiguration", 3.5, "T1083", ".DS_Store file lists directory contents"),
    "exposed_server_status": ("misconfiguration", 5.5, "T1592", "Server status / phpinfo page exposed"),
    "directory_listing": ("misconfiguration", 4.5, "T1083", "Web server directory listing enabled"),
    "missing_security_headers": ("misconfiguration", 2.5, "T1592", "Homepage lacks HSTS / CSP headers"),
    "missing_spf": ("email_security", 5.0, "T1566", "No SPF record: anyone can spoof mail from this domain"),
    "permissive_spf": ("email_security", 6.0, "T1566", "SPF ends in +all/?all and authorises any sender"),
    "missing_dmarc": ("email_security", 5.0, "T1566", "No DMARC record"),
    "weak_dmarc_policy": ("email_security", 3.5, "T1566", "DMARC policy is p=none (monitoring only)"),
    "whois_registrant_exposed": ("personal", 4.0, "T1589", "Registrant contact details are public in WHOIS/RDAP"),
    "sensitive_subdomain": ("infrastructure", 4.5, "T1590.002", "Certificate logs reveal an internal/dev subdomain"),
    "open_sensitive_port": ("infrastructure", 7.0, "T1590.005", "Database/admin service port open to the internet"),
    "public_code_mention": ("code_exposure", 3.0, "T1593.003", "Identifier appears in public code on GitHub"),
    "breach_exposure": ("credentials", 7.5, "T1589.001", "Address appears in a known data breach"),
    "paste_exposure": ("credentials", 6.5, "T1589.001", "Address appears in a public paste"),
}

SENSITIVE_SUBDOMAIN_RE = re.compile(
    r"(?:^|[.-])(dev|devel|staging|stage|stg|test|qa|uat|sandbox|internal|intranet|corp|admin|jenkins|gitlab|"
    r"vpn|grafana|kibana|jira|confluence|backup|db|mysql|postgres|redis|elastic)(?:[.-]|\d|$)"
)
SENSITIVE_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 2375: "Docker API", 3306: "MySQL",
                   3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
                   11211: "Memcached", 27017: "MongoDB"}
TEXT_TYPES = ("text/html", "text/plain", "application/javascript", "text/javascript", "application/json",
              "application/xml", "text/xml", "text/css")
_LINK_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"'#][^"']*)["']""", re.I)
_TAG_RE = re.compile(r"<script\b[^>]*>|</script>|<style\b[^>]*>.*?</style>|<[^>]+>", re.I | re.S)


def _lines_to_raw(text: str, origin: str, source: SourceType, max_lines: int = 5000) -> list[RawFinding]:
    out = []
    for number, line in enumerate(text.splitlines()[:max_lines], start=1):
        line = line.strip()
        if 6 <= len(line) <= 2000:
            out.append(RawFinding(source_type=source, raw_text=line, origin=origin, context=f"line {number}"))
    return out


def _html_text(html: str) -> str:
    # Keep script bodies (inline config/keys live there); drop markup.
    return unescape(_TAG_RE.sub("\n", html))


# ---------------------------------------------------------------------------
# Website crawler + exposure checks (verified domains only)
# ---------------------------------------------------------------------------

def crawl_site(start_urls: list[str], verified_domains: list[str], max_pages: int = 30, max_depth: int = 2,
               fetch=net.safe_request) -> CollectorResult:
    result = CollectorResult()
    robots: dict[str, RobotFileParser | None] = {}
    seen: set[str] = set()
    queue = deque((url, 0) for url in start_urls)
    pages = 0

    def allowed(url: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in ("http", "https") or not any(domain_covers(d, host) for d in verified_domains):
            return False
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in robots:
            try:
                response = fetch("GET", base + "/robots.txt", max_bytes=100_000, timeout=6)
                parser = RobotFileParser()
                parser.parse(response.text.splitlines() if response.status_code == 200 else [])
                robots[base] = parser
            except Exception:
                robots[base] = None
        parser = robots[base]
        return parser is None or parser.can_fetch(net.USER_AGENT, url)

    while queue and pages < max_pages:
        url, depth = queue.popleft()
        url = urldefrag(url)[0]
        if url in seen or not allowed(url):
            continue
        seen.add(url)
        try:
            response = fetch("GET", url, max_bytes=1_500_000, timeout=10)
        except Exception as exc:
            result.notes.append(f"Could not fetch {url}: {type(exc).__name__}")
            continue
        pages += 1
        ctype = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if response.status_code >= 400 or (ctype and ctype not in TEXT_TYPES):
            continue
        body = response.text
        if ctype == "text/html" or "<html" in body[:500].lower():
            result.raw.extend(_lines_to_raw(_html_text(body), response.url, SourceType.WEB_CONTENT))
            if "<title>index of /" in body[:2000].lower():
                result.direct.append(DirectFinding("directory_listing", response.url, response.url, "Index of / page"))
            if depth < max_depth:
                for link in _LINK_RE.findall(body)[:300]:
                    absolute = urldefrag(urljoin(response.url, link.strip()))[0]
                    if absolute not in seen:
                        queue.append((absolute, depth + 1))
        else:
            result.raw.extend(_lines_to_raw(body, response.url, SourceType.WEB_CONTENT))
    result.intel["pages_crawled"] = pages
    return result


EXPOSURE_PATHS = [
    ("/.git/HEAD", "exposed_git_directory", lambda r: r.text.lstrip().startswith("ref:")),
    ("/.env", "exposed_env_file", lambda r: "=" in r.text[:2000] and "<html" not in r.text[:500].lower()),
    ("/.DS_Store", "exposed_ds_store", lambda r: r.content[:8] == b"\x00\x00\x00\x01Bud1"),
    ("/backup.zip", "exposed_backup_file", lambda r: r.content[:2] == b"PK"),
    ("/backup.sql", "exposed_backup_file", lambda r: re.search(rb"(CREATE TABLE|INSERT INTO)", r.content[:4096]) is not None),
    ("/db.sql", "exposed_backup_file", lambda r: re.search(rb"(CREATE TABLE|INSERT INTO)", r.content[:4096]) is not None),
    ("/server-status", "exposed_server_status", lambda r: b"Server Status" in r.content[:4096]),
    ("/phpinfo.php", "exposed_server_status", lambda r: b"phpinfo()" in r.content[:20000] or b"PHP Version" in r.content[:20000]),
]


def exposure_checks(domain: str, fetch=net.safe_request) -> CollectorResult:
    result = CollectorResult()
    base = f"https://{domain}"
    try:
        home = fetch("GET", base + "/", max_bytes=200_000, timeout=10)
        missing = [h for h in ("strict-transport-security", "content-security-policy") if h not in home.headers]
        if missing and home.status_code < 400:
            result.direct.append(DirectFinding("missing_security_headers", f"{domain}: {', '.join(missing)}", base + "/",
                                               "Missing: " + ", ".join(missing)))
    except Exception as exc:
        result.notes.append(f"Homepage not reachable over HTTPS ({type(exc).__name__}).")
        return result
    for path, rule_id, looks_real in EXPOSURE_PATHS:
        try:
            response = fetch("GET", base + path, max_bytes=65_536, timeout=8, max_redirects=0)
        except Exception:
            continue
        if response.status_code == 200 and response.content and looks_real(response):
            result.direct.append(DirectFinding(rule_id, base + path, base + path, f"HTTP 200 for {path}"))
            if rule_id == "exposed_env_file":
                result.raw.extend(_lines_to_raw(response.text, base + path, SourceType.EXPOSURE_CHECK))
    return result


# ---------------------------------------------------------------------------
# Public records: DNS, certificate transparency, RDAP/WHOIS, Shodan
# ---------------------------------------------------------------------------

def _dns(name: str, rtype: str, resolver=None) -> list[str]:
    import dns.resolver

    resolver = resolver or dns.resolver.Resolver()
    resolver.lifetime = 6.0
    try:
        answers = resolver.resolve(name, rtype)
    except Exception:
        return []
    out = []
    for record in answers:
        if rtype == "TXT":
            out.append(b"".join(record.strings).decode("utf-8", "replace"))
        else:
            out.append(record.to_text().rstrip("."))
    return out


def public_records(domain: str, dns_lookup=_dns, api_get=net.api_get) -> CollectorResult:
    result = CollectorResult()
    records = {rtype: dns_lookup(domain, rtype) for rtype in ("A", "AAAA", "MX", "NS", "TXT")}
    dmarc = [t for t in dns_lookup(f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
    result.intel["dns"] = records
    result.intel["dmarc"] = dmarc[0] if dmarc else None

    spf = [t for t in records["TXT"] if t.lower().startswith("v=spf1")]
    result.intel["spf"] = spf[0] if spf else None
    if records["MX"] or spf:
        if not spf:
            result.direct.append(DirectFinding("missing_spf", f"{domain} SPF", f"dns:{domain}", "No v=spf1 TXT record"))
        elif re.search(r"[+?]all\b", spf[0]):
            result.direct.append(DirectFinding("permissive_spf", spf[0], f"dns:{domain}", spf[0][:200]))
        if not dmarc:
            result.direct.append(DirectFinding("missing_dmarc", f"{domain} DMARC", f"dns:_dmarc.{domain}", "No _dmarc TXT record"))
        elif re.search(r"\bp\s*=\s*none\b", dmarc[0], re.I):
            result.direct.append(DirectFinding("weak_dmarc_policy", dmarc[0], f"dns:_dmarc.{domain}", dmarc[0][:200]))
    for txt in records["TXT"]:
        result.raw.append(RawFinding(source_type=SourceType.DNS_RECORD, raw_text=txt, origin=f"dns:{domain}", context="TXT record"))

    # Certificate transparency: every name a public CA has issued a cert for.
    names: list[str] = []
    try:
        response = api_get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=25)
        if response.status_code == 200:
            for entry in response.json()[:5000]:
                for name in str(entry.get("name_value", "")).lower().split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(domain) and name not in names:
                        names.append(name)
    except Exception as exc:
        result.notes.append(f"Certificate transparency lookup failed ({type(exc).__name__}).")
    names = sorted(names)[:500]
    result.intel["subdomains"] = names
    for name in names:
        label = name[: -len(domain)].rstrip(".")
        if label and SENSITIVE_SUBDOMAIN_RE.search(label):
            result.direct.append(DirectFinding("sensitive_subdomain", name, f"crt.sh:{domain}", "Listed in certificate transparency logs"))
        result.raw.append(RawFinding(source_type=SourceType.CERT_TRANSPARENCY, raw_text=name, origin=f"crt.sh:{domain}", context="certificate name"))

    # RDAP (structured WHOIS).
    try:
        response = api_get(f"https://rdap.org/domain/{quote(domain)}", timeout=15)
        if response.status_code == 200:
            data = response.json()
            registrar, registrant = None, {}
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                vcard = {item[0]: item[3] for item in (entity.get("vcardArray") or [None, []])[1] if len(item) > 3}
                if "registrar" in roles:
                    registrar = vcard.get("fn")
                if "registrant" in roles:
                    registrant = {k: vcard.get(k) for k in ("fn", "email", "tel", "org") if vcard.get(k)}
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
            result.intel["rdap"] = {"registrar": registrar, "expires": events.get("expiration"), "registered": events.get("registration")}
            exposed = {k: v for k, v in registrant.items()
                       if v and not re.search(r"redacted|privacy|withheld|proxy|protect|not disclosed", str(v), re.I)}
            if exposed.get("email") or exposed.get("tel") or exposed.get("fn"):
                shown = ", ".join(sorted(exposed))
                result.direct.append(DirectFinding("whois_registrant_exposed", f"{domain} registrant {shown}", f"rdap:{domain}",
                                                   f"Public registrant fields: {shown}"))
                for value in exposed.values():
                    result.raw.append(RawFinding(source_type=SourceType.DNS_RECORD, raw_text=str(value), origin=f"rdap:{domain}", context="RDAP registrant"))
    except Exception as exc:
        result.notes.append(f"RDAP lookup failed ({type(exc).__name__}).")

    # IP ownership enrichment.
    ips = []
    for ip in (records["A"] + records["AAAA"])[:6]:
        info = {"ip": ip}
        try:
            response = api_get(f"https://rdap.org/ip/{quote(ip)}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                info.update({"network": data.get("name"), "country": data.get("country"),
                             "range": f"{data.get('startAddress')} - {data.get('endAddress')}"})
        except Exception:
            pass
        ips.append(info)
    result.intel["ips"] = ips

    key = os.environ.get("PLATFORM_SHODAN_API_KEY", "").strip()
    if key:
        result.extend(shodan_hosts([i["ip"] for i in ips if ":" not in i["ip"]], key, api_get=api_get))
    else:
        result.notes.append("Shodan port data skipped (set PLATFORM_SHODAN_API_KEY to enable).")
    return result


def shodan_hosts(ips: list[str], key: str, api_get=net.api_get) -> CollectorResult:
    result = CollectorResult()
    services = []
    for ip in ips[:4]:
        try:
            response = api_get(f"https://api.shodan.io/shodan/host/{quote(ip)}", params={"key": key}, timeout=15)
        except Exception:
            continue
        if response.status_code != 200:
            continue
        for port in response.json().get("ports", []):
            services.append({"ip": ip, "port": port})
            if port in SENSITIVE_PORTS:
                result.direct.append(DirectFinding("open_sensitive_port", f"{ip}:{port}", f"shodan:{ip}",
                                                   f"{SENSITIVE_PORTS[port]} reachable on {ip}:{port}"))
    result.intel["services"] = services
    return result


# ---------------------------------------------------------------------------
# GitHub: code search (paste-site equivalent) and a handle's own gists/repos
# ---------------------------------------------------------------------------

def _github_headers(extra: dict | None = None) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("PLATFORM_GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return {**headers, **(extra or {})}


def github_code_search(term: str, api_get=net.api_get) -> CollectorResult:
    result = CollectorResult()
    if not os.environ.get("PLATFORM_GITHUB_TOKEN", "").strip():
        result.notes.append("GitHub code search skipped (set PLATFORM_GITHUB_TOKEN to enable).")
        return result
    try:
        response = api_get("https://api.github.com/search/code", params={"q": f'"{term}"', "per_page": 30},
                           headers=_github_headers({"Accept": "application/vnd.github.text-match+json"}), timeout=20)
    except Exception as exc:
        result.notes.append(f"GitHub code search failed ({type(exc).__name__}).")
        return result
    if response.status_code != 200:
        result.notes.append(f"GitHub code search returned HTTP {response.status_code}.")
        return result
    repos = {}
    for item in response.json().get("items", []):
        repo = (item.get("repository") or {}).get("full_name", "?")
        origin = f"github:{repo}/{item.get('path', '')}"
        repos.setdefault(repo, origin)
        for match in item.get("text_matches", []):
            result.raw.extend(_lines_to_raw(match.get("fragment", ""), origin, SourceType.CODE_SEARCH, max_lines=50))
    for repo, origin in repos.items():
        result.direct.append(DirectFinding("public_code_mention", f"{term} in {repo}", origin, f"'{term}' appears in {repo}"))
    result.intel["code_mentions"] = sorted(repos)
    return result


def github_handle(handle: str, api_get=net.api_get) -> CollectorResult:
    """Public gists' contents and the list of public repositories."""
    result = CollectorResult()
    try:
        gists = api_get(f"https://api.github.com/users/{handle}/gists", params={"per_page": 30}, headers=_github_headers(), timeout=15)
        gist_list = gists.json() if gists.status_code == 200 else []
    except Exception:
        gist_list = []
    files = 0
    for gist in gist_list:
        for name, meta in (gist.get("files") or {}).items():
            raw_url = meta.get("raw_url", "")
            if files >= 25 or not raw_url.startswith("https://gist.githubusercontent.com/") or (meta.get("size") or 0) > 1_000_000:
                continue
            try:
                content = api_get(raw_url, timeout=15)
            except Exception:
                continue
            if content.status_code == 200:
                files += 1
                result.raw.extend(_lines_to_raw(content.text, f"gist:{handle}/{name}", SourceType.CODE_SEARCH))
    try:
        repos = api_get(f"https://api.github.com/users/{handle}/repos", params={"per_page": 100, "sort": "pushed"},
                        headers=_github_headers(), timeout=15)
        repo_list = repos.json() if repos.status_code == 200 else []
    except Exception:
        repo_list = []
    result.intel["github"] = {
        "gist_files_scanned": files,
        "repos": [{"name": r.get("full_name"), "url": r.get("html_url"), "pushed_at": r.get("pushed_at"),
                   "fork": r.get("fork")} for r in repo_list[:100]],
    }
    return result


# ---------------------------------------------------------------------------
# Breach and paste exposure (HaveIBeenPwned)
# ---------------------------------------------------------------------------

def breach_check(email: str, api_get=net.api_get) -> CollectorResult:
    result = CollectorResult()
    key = os.environ.get("PLATFORM_HIBP_API_KEY", "").strip()
    if not key:
        result.notes.append("Breach and paste check skipped (set PLATFORM_HIBP_API_KEY to enable).")
        return result
    headers = {"hibp-api-key": key}
    breaches = []
    try:
        response = api_get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                           params={"truncateResponse": "false"}, headers=headers, timeout=15)
        if response.status_code == 200:
            for breach in response.json():
                name = breach.get("Name", "?")
                classes = ", ".join(breach.get("DataClasses", [])[:8])
                breaches.append({"name": name, "date": breach.get("BreachDate"), "data": classes})
                result.direct.append(DirectFinding("breach_exposure", f"{email} in {name}", f"hibp:{name}",
                                                   f"{breach.get('BreachDate')}: {classes}"))
        elif response.status_code != 404:
            result.notes.append(f"Breach lookup returned HTTP {response.status_code}.")
        pastes = api_get(f"https://haveibeenpwned.com/api/v3/pasteaccount/{quote(email)}", headers=headers, timeout=15)
        if pastes.status_code == 200:
            for paste in pastes.json()[:50]:
                source = f"{paste.get('Source')}/{paste.get('Id')}"
                result.direct.append(DirectFinding("paste_exposure", f"{email} in {source}", f"hibp-paste:{source}",
                                                   f"{paste.get('Date') or 'undated'} paste on {paste.get('Source')}"))
    except Exception as exc:
        result.notes.append(f"Breach lookup failed ({type(exc).__name__}).")
    result.intel["breaches"] = breaches
    return result
