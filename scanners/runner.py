"""Security Scanner Agent — sits between Supervisor and Vulnerability Agent.

    Supervisor -> SecurityScannerAgent -> [Trivy, Nmap, Nikto, ZAP] -> Vuln Agent

Runs the tool fan-out, normalizes + merges findings, and enforces guardrails
on the scan target before any tool executes (prevents tool misuse / SSRF).
"""
from __future__ import annotations

from scanners.trivy import TrivyScanner
from scanners.nmap import NmapScanner
from scanners.nikto import NiktoScanner
from scanners.zap import ZapScanner
from shared.schemas import Finding, ScanResult
from guardrails import GuardrailEngine
from observability.logging import get_logger, traced

logger = get_logger(__name__)


class SecurityScannerAgent:
    def __init__(self, guardrails: GuardrailEngine | None = None):
        self.scanners = [TrivyScanner(), NmapScanner(), NiktoScanner(), ZapScanner()]
        self.guardrails = guardrails or GuardrailEngine(
            allowed_tools={s.name for s in
                           [TrivyScanner(), NmapScanner(), NiktoScanner(), ZapScanner()]})

    @traced("security_scanner_agent")
    def run(self, target: str) -> tuple[list[ScanResult], list[Finding]]:
        results: list[ScanResult] = []
        for scanner in self.scanners:
            # tool-misuse guardrail: validate target before executing the tool
            self.guardrails.authorize_tool(scanner.name, {"target": target})
            res = scanner.scan(target)
            logger.info("scan.done", extra={"scanner": scanner.name,
                                            "n": len(res.findings),
                                            "mock": res.mock,
                                            "err": res.error})
            results.append(res)
        merged = self._dedupe([f for r in results for f in r.findings])
        return results, merged

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for f in findings:
            key = f.cve_id or f"{f.scanner}:{f.title}"
            if key not in seen:
                seen[key] = f
        return list(seen.values())
