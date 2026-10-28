"""Agent tools — the capabilities the orchestrators invoke.

These plain functions are reused by LangGraph, CrewAI, and AutoGen so all three
frameworks share identical behavior. Each tool is guardrail-aware.
"""
from __future__ import annotations

from scanners import SecurityScannerAgent
from compliance import ComplianceMapper
from mock_apis.client import ServiceNowClient
from shared.config import get_settings
from shared.rag import SecurityRAG
from shared.llm import chat
from shared.prompts import VULNERABILITY, COMPLIANCE, REMEDIATION, REPORTING
from shared.schemas import (Finding, ScanResult, Ticket, Report, Severity,
                            SEVERITY_ORDER)
from guardrails import GuardrailEngine, guarded_llm

_rag = SecurityRAG()
_mapper = ComplianceMapper()
_snow = ServiceNowClient()
_scanner_agent = SecurityScannerAgent()
_guard = GuardrailEngine(allowed_tools={"trivy", "nmap", "nikto", "owasp_zap",
                                        "servicenow"})


def tool_run_scanners(target: str) -> tuple[list[ScanResult], list[Finding]]:
    """Security Scanner Agent fan-out across Trivy/Nmap/Nikto/ZAP."""
    return _scanner_agent.run(target)


def tool_triage_findings(findings: list[Finding]) -> list[Finding]:
    """Vulnerability agent: enrich each finding with RAG remediation + sort."""
    for f in findings:
        ctx = _rag.context_for(f.cve_id or f.title, k=2)
        user = (f"Finding: {f.title} (severity={f.severity}, cve={f.cve_id}).\n"
                f"Knowledge base context:\n{ctx}\n"
                "Give a one-paragraph remediation recommendation.")
        f.remediation = guarded_llm(_guard, chat, VULNERABILITY, user, max_tokens=800)
    findings.sort(key=lambda x: SEVERITY_ORDER[x.severity], reverse=True)
    return findings


def tool_map_compliance(findings: list[Finding]) -> list[Finding]:
    """Compliance agent: attach GRC control mappings."""
    return _mapper.enrich(findings)


def tool_create_tickets(findings: list[Finding]) -> list[Ticket]:
    """Remediation agent: open ServiceNow incidents for HIGH/CRITICAL."""
    tickets: list[Ticket] = []
    cfg = get_settings()
    if not cfg.mock_mode and not cfg.servicenow_url.strip():
        return tickets          # ticketing disabled (SERVICENOW_URL is empty)
    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            _guard.authorize_tool("servicenow", {"target": f.target})
            t = Ticket(short_description=f"[{f.severity}] {f.title}",
                       description=f"{f.description}\n\nRemediation: {f.remediation}\n"
                                   f"Compliance: {', '.join(f.compliance)}",
                       priority=1 if f.severity == Severity.CRITICAL else 2)
            tickets.append(_snow.create_incident(t))
    return tickets


def tool_build_report(findings: list[Finding], tickets: list[Ticket]) -> Report:
    """Reporting agent: executive summary + risk rating."""
    counts = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}
    worst = max((f.severity for f in findings), default=Severity.INFO,
                key=lambda s: SEVERITY_ORDER[s])
    comp = _mapper.gap_summary(findings)
    user = (f"Severity counts: {counts}. Tickets opened: {len(tickets)}. "
            f"Top compliance gaps: {list(comp.items())[:5]}. "
            "Write a 4-6 sentence executive investigation summary.")
    narrative = guarded_llm(_guard, chat, REPORTING, user, max_tokens=800)
    return Report(summary=f"{len(findings)} findings, {len(tickets)} tickets opened",
                  risk_rating=worst, finding_count=len(findings), narrative=narrative)


def seed_rag_once() -> None:
    from shared.rag import seed_knowledge_base
    seed_knowledge_base(_rag)
