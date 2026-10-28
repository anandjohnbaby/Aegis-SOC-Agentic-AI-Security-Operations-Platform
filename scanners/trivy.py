"""Trivy integration (container / filesystem vulnerability scanning)."""
from __future__ import annotations

import json

from scanners.base import BaseScanner
from shared.schemas import Finding, Severity


class TrivyScanner(BaseScanner):
    name = "trivy"
    binary = "trivy"

    def command(self, target: str) -> list[str]:
        # `target` may be an image name or filesystem path
        return ["trivy", "--quiet", "image", "--format", "json", target]

    def parse(self, raw: str, target: str) -> list[Finding]:
        data = json.loads(raw or "{}")
        findings: list[Finding] = []
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []) or []:
                findings.append(Finding(
                    scanner=self.name, target=target,
                    title=v.get("Title") or v.get("VulnerabilityID", "vuln"),
                    description=v.get("Description", "")[:400],
                    severity=Severity(v.get("Severity", "LOW").upper()),
                    cve_id=v.get("VulnerabilityID"),
                    cvss_score=_cvss(v),
                    package=v.get("PkgName"),
                    installed_version=v.get("InstalledVersion"),
                    fixed_version=v.get("FixedVersion"),
                    references=v.get("References", [])[:3],
                ))
        return findings

    def mock_findings(self, target: str) -> list[Finding]:
        return [
            Finding(scanner=self.name, target=target,
                    title="CVE-2023-4911 glibc buffer overflow (Looney Tunables)",
                    severity=Severity.CRITICAL, cve_id="CVE-2023-4911",
                    cvss_score=7.8, package="glibc",
                    installed_version="2.31-13", fixed_version="2.31-13+deb11u7",
                    description="Local privilege escalation via GLIBC_TUNABLES."),
            Finding(scanner=self.name, target=target,
                    title="CVE-2022-37434 zlib heap over-read",
                    severity=Severity.HIGH, cve_id="CVE-2022-37434",
                    cvss_score=9.8, package="zlib1g",
                    installed_version="1.2.11", fixed_version="1.2.11.dfsg-2+deb11u2"),
            Finding(scanner=self.name, target=target,
                    title="Outdated Flask with known XSS",
                    severity=Severity.MEDIUM, cwe_id="CWE-79", cvss_score=6.1,
                    package="flask", installed_version="2.0.1",
                    fixed_version="2.3.3"),
        ]


def _cvss(v: dict) -> float | None:
    cvss = v.get("CVSS", {})
    for vendor in cvss.values():
        for key in ("V3Score", "V2Score"):
            if key in vendor:
                return vendor[key]
    return None
