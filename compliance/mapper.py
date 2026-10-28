"""GRC mapping: maps findings (by CWE / category) to NIST CSF, CIS v8, ISO 27001.

Covers the 'GRC frameworks' + 'vulnerability management lifecycle' JD items.
"""
from __future__ import annotations

from shared.schemas import Finding

# category -> (NIST CSF, CIS Control, ISO 27001 Annex A)
_MAP: dict[str, list[str]] = {
    "CWE-89": ["NIST PR.DS-5", "CIS 16.11", "ISO A.14.2.5"],   # SQLi
    "CWE-79": ["NIST PR.DS-5", "CIS 16.11", "ISO A.14.2.1"],   # XSS
    "CWE-693": ["NIST PR.IP-1", "CIS 4.1", "ISO A.14.1.2"],    # missing hardening
    "vuln_patch": ["NIST ID.RA-1", "CIS 7.1", "ISO A.12.6.1"], # known CVE unpatched
    "network_exposure": ["NIST PR.AC-5", "CIS 4.4", "ISO A.13.1.1"],
    "default": ["NIST ID.RA-1", "CIS 7.1", "ISO A.12.6.1"],
}


class ComplianceMapper:
    def controls_for(self, finding: Finding) -> list[str]:
        if finding.cwe_id and finding.cwe_id in _MAP:
            return _MAP[finding.cwe_id]
        if finding.cve_id:
            return _MAP["vuln_patch"]
        if finding.scanner == "nmap":
            return _MAP["network_exposure"]
        return _MAP["default"]

    def enrich(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            f.compliance = self.controls_for(f)
        return findings

    def gap_summary(self, findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            for ctrl in f.compliance:
                counts[ctrl] = counts.get(ctrl, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))
