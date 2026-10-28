"""Nmap integration (network / port scanning)."""
from __future__ import annotations

import re

from scanners.base import BaseScanner
from shared.schemas import Finding, Severity


class NmapScanner(BaseScanner):
    name = "nmap"
    binary = "nmap"

    def native_scan(self, target: str):
        from scanners import native
        return native.port_scan(target, self.name)

    def command(self, target: str) -> list[str]:
        host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        return ["nmap", "-sV", "-T4", "--open", host]

    def parse(self, raw: str, target: str) -> list[Finding]:
        findings = []
        for line in raw.splitlines():
            m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line.strip())
            if m:
                port, svc, ver = m.groups()
                sev = Severity.MEDIUM if svc in ("ftp", "telnet", "rdp") else Severity.LOW
                findings.append(Finding(
                    scanner=self.name, target=target, severity=sev,
                    title=f"Open port {port}/tcp ({svc})",
                    description=f"Service: {svc} {ver}".strip()))
        return findings

    def mock_findings(self, target: str) -> list[Finding]:
        return [
            Finding(scanner=self.name, target=target, severity=Severity.MEDIUM,
                    title="Open port 23/tcp (telnet)",
                    description="Cleartext administrative protocol exposed."),
            Finding(scanner=self.name, target=target, severity=Severity.LOW,
                    title="Open port 5000/tcp (http)",
                    description="Werkzeug/2.0.1 Python/3.9 dev server exposed."),
        ]
