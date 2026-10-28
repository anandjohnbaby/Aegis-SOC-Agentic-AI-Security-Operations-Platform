"""OWASP ZAP integration (dynamic web application scanning)."""
from __future__ import annotations

from scanners.base import BaseScanner
from shared.schemas import Finding, Severity


class ZapScanner(BaseScanner):
    name = "owasp_zap"
    binary = "zap-baseline.py"

    def native_scan(self, target: str):
        from scanners import native
        return native.web_probe(target, self.name)

    def command(self, target: str) -> list[str]:
        return ["zap-baseline.py", "-t", target, "-J", "-"]

    def parse(self, raw: str, target: str) -> list[Finding]:
        import json
        try:
            data = json.loads(raw)
        except Exception:
            return []
        findings = []
        for site in data.get("site", []):
            for a in site.get("alerts", []):
                sev = {"3": Severity.HIGH, "2": Severity.MEDIUM,
                       "1": Severity.LOW}.get(str(a.get("riskcode")), Severity.INFO)
                findings.append(Finding(
                    scanner=self.name, target=target, severity=sev,
                    title=a.get("name", "ZAP alert"),
                    cwe_id=f"CWE-{a.get('cweid')}" if a.get("cweid") else None,
                    description=a.get("desc", "")[:400]))
        return findings

    def mock_findings(self, target: str) -> list[Finding]:
        return [
            Finding(scanner=self.name, target=target, severity=Severity.HIGH,
                    cwe_id="CWE-89", title="SQL Injection in /login parameter 'user'",
                    description="Boolean-based SQLi confirmed on login form."),
            Finding(scanner=self.name, target=target, severity=Severity.MEDIUM,
                    cwe_id="CWE-79", title="Reflected XSS in /search parameter 'q'"),
        ]
