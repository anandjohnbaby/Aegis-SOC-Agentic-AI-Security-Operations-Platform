"""Nikto integration (web server misconfiguration scanning)."""
from __future__ import annotations

from scanners.base import BaseScanner
from shared.schemas import Finding, Severity


class NiktoScanner(BaseScanner):
    name = "nikto"
    binary = "nikto"

    def native_scan(self, target: str):
        from scanners import native
        return native.web_checks(target, self.name)

    def command(self, target: str) -> list[str]:
        return ["nikto", "-host", target, "-nointeractive"]

    def parse(self, raw: str, target: str) -> list[Finding]:
        findings = []
        for line in raw.splitlines():
            if line.strip().startswith("+") and "OSVDB" not in line:
                findings.append(Finding(
                    scanner=self.name, target=target, severity=Severity.LOW,
                    title=line.strip("+ ").strip()[:120]))
        return findings

    def mock_findings(self, target: str) -> list[Finding]:
        return [
            Finding(scanner=self.name, target=target, severity=Severity.MEDIUM,
                    cwe_id="CWE-693",
                    title="Missing security headers (X-Frame-Options, CSP)"),
            Finding(scanner=self.name, target=target, severity=Severity.LOW,
                    title="Server banner leaks version info (Werkzeug/2.0.1)"),
        ]
