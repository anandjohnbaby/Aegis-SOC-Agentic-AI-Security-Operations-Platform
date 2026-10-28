"""Built-in lightweight scanners (pure Python, no external binaries).

Used in LIVE mode when Nmap / Nikto / ZAP are not installed, so results are
produced from the real target instead of fixed demo data.

Safety: by default these only touch loopback / private-network hosts. Set
ALLOW_EXTERNAL_SCANS=true only for systems you own or are authorised to test.
They send benign probes only (a marker string and a single quote).
"""
from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from uuid import uuid4

import requests

from shared.config import get_settings
from shared.schemas import Finding, Severity

TIMEOUT = 4

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}
RISKY = {"telnet", "ftp", "rdp", "vnc", "smb", "netbios", "msrpc",
         "redis", "mongodb", "mysql", "mssql", "postgresql"}

PROBE_PATHS = ["/", "/login", "/search", "/api", "/query", "/user", "/users", "/item"]
PROBE_PARAMS = ["q", "search", "query", "s", "user", "username", "id", "name"]
SQL_ERRORS = re.compile(
    r"sql syntax|sqlite3?\.|sqlite error|unrecognized token|mysql|psql|"
    r"ora-\d{5}|unterminated quoted string|odbc|syntax error at or near", re.I)


def _parse(target: str):
    t = target if "://" in target else f"http://{target}"
    u = urlparse(t)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    return t.rstrip("/"), u.scheme, host, port


def _guard(host: str) -> None:
    if get_settings().allow_external_scans:
        return
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except Exception:
        raise RuntimeError(f"cannot resolve host '{host}'")
    if not (ip.is_loopback or ip.is_private):
        raise RuntimeError(
            "built-in scanners are limited to loopback/private targets "
            "(set ALLOW_EXTERNAL_SCANS=true only for systems you own)")


def _get(url: str, **kw):
    return requests.get(url, timeout=TIMEOUT, allow_redirects=False, **kw)


# --------------------------------------------------------------------------
# Nmap replacement: TCP connect scan of common ports + the target's own port
# --------------------------------------------------------------------------
def port_scan(target: str, scanner: str) -> list[Finding]:
    base, scheme, host, port = _parse(target)
    _guard(host)
    ports = sorted(set(COMMON_PORTS) | {port})

    def check(p: int):
        try:
            with socket.create_connection((host, p), timeout=0.8):
                return p
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=32) as ex:
        open_ports = [p for p in ex.map(check, ports) if p]

    findings = []
    for p in open_ports:
        svc = COMMON_PORTS.get(p, "unknown")
        risky = svc in RISKY
        desc = ("Potentially sensitive service exposed." if risky
                else "Service reachable on this port.")
        if p == port:
            desc += " This is the scan target's own port."
        findings.append(Finding(
            scanner=scanner, target=target,
            severity=Severity.MEDIUM if risky else Severity.LOW,
            title=f"Open port {p}/tcp ({svc})", description=desc))
    return findings


# --------------------------------------------------------------------------
# Nikto replacement: headers, banners, sensitive files
# --------------------------------------------------------------------------
SENSITIVE = {
    "/.git/HEAD": (Severity.HIGH, "Exposed .git repository", "CWE-538",
                   lambda r: r.text.startswith("ref:")),
    "/.env": (Severity.HIGH, "Exposed .env file", "CWE-538",
              lambda r: "=" in r.text),
    "/server-status": (Severity.MEDIUM, "Apache server-status exposed", "CWE-200",
                       lambda r: "Apache Server Status" in r.text),
    "/phpinfo.php": (Severity.MEDIUM, "phpinfo() page exposed", "CWE-200",
                     lambda r: "phpinfo" in r.text.lower()),
    "/admin": (Severity.LOW, "Admin interface reachable", "CWE-284",
               lambda r: True),
}


def web_checks(target: str, scanner: str) -> list[Finding]:
    base, scheme, host, port = _parse(target)
    _guard(host)
    try:
        r = _get(base + "/")
    except requests.RequestException as exc:
        raise RuntimeError(f"target not reachable: {exc}")

    findings: list[Finding] = []

    def add(sev, title, desc="", cwe=None):
        findings.append(Finding(scanner=scanner, target=target, severity=sev,
                                title=title, description=desc, cwe_id=cwe))

    h = {k.lower(): v for k, v in r.headers.items()}
    wanted = ["x-frame-options", "content-security-policy", "x-content-type-options"]
    if scheme == "https":
        wanted.append("strict-transport-security")
    missing = [n for n in wanted if n not in h]
    if missing:
        add(Severity.MEDIUM, "Missing security headers (" + ", ".join(missing) + ")",
            "Response lacks recommended hardening headers.", "CWE-693")

    server = h.get("server", "")
    if re.search(r"\d", server):
        add(Severity.LOW, f"Server banner leaks version info ({server})",
            "Version details help attackers pick known exploits.", "CWE-200")
    if h.get("x-powered-by"):
        add(Severity.LOW, f"X-Powered-By header leaks technology ({h['x-powered-by']})",
            cwe="CWE-200")
    if scheme == "http" and port not in (80,) and "localhost" not in host and host != "127.0.0.1":
        add(Severity.LOW, "Service served over plain HTTP (no TLS)", cwe="CWE-319")

    # soft-404 baseline so single-page apps don't produce false positives
    try:
        junk = _get(base + "/zz-nonexistent-" + uuid4().hex[:6])
    except requests.RequestException:
        junk = None
    for path, (sev, title, cwe, check) in SENSITIVE.items():
        try:
            pr = _get(base + path)
        except requests.RequestException:
            continue
        if pr.status_code != 200:
            continue
        if junk is not None and junk.status_code == 200 and pr.text == junk.text:
            continue
        if check(pr):
            add(sev, f"{title} ({path})", cwe=cwe)
    return findings


# --------------------------------------------------------------------------
# ZAP replacement: benign reflected-XSS and error-based SQLi probes
# --------------------------------------------------------------------------
def web_probe(target: str, scanner: str) -> list[Finding]:
    base, scheme, host, port = _parse(target)
    _guard(host)
    try:
        junk = _get(base + "/zz-nonexistent-" + uuid4().hex[:6])
    except requests.RequestException as exc:
        raise RuntimeError(f"target not reachable: {exc}")

    findings: list[Finding] = []
    seen: set[tuple] = set()

    def add(sev, title, desc, cwe):
        findings.append(Finding(scanner=scanner, target=target, severity=sev,
                                title=title, description=desc, cwe_id=cwe))

    for path in PROBE_PATHS:
        url = base + path
        try:
            b = _get(url)
        except requests.RequestException:
            continue
        if b.status_code in (404, 405):
            continue
        if junk.status_code == 200 and b.text == junk.text:
            continue                       # soft-404 / catch-all page
        for param in PROBE_PARAMS:
            marker = "zx" + uuid4().hex[:6]
            payload = f"<{marker}>"
            try:
                r1 = _get(url, params={param: payload})
                r2 = _get(url, params={param: "'"})
            except requests.RequestException:
                continue
            if payload in r1.text and ("xss", path, param) not in seen:
                seen.add(("xss", path, param))
                add(Severity.MEDIUM,
                    f"Reflected XSS in {path} parameter '{param}'",
                    "Input is echoed into the page without encoding.", "CWE-79")
            sql_hit = (SQL_ERRORS.search(r2.text) and not SQL_ERRORS.search(b.text)) \
                or (b.status_code < 500 <= r2.status_code)
            if sql_hit and ("sqli", path, param) not in seen:
                seen.add(("sqli", path, param))
                add(Severity.HIGH,
                    f"Possible SQL injection in {path} parameter '{param}'",
                    "A single quote caused a server error or SQL error message.",
                    "CWE-89")
    return findings
