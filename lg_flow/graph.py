"""LangGraph orchestration (primary).

Flow:
  supervisor -> security_scanner -> vulnerability -> compliance
             -> remediation -> reporting
"""
from __future__ import annotations

from langgraph.graph import StateGraph, END

from lg_flow.state import InvestigationState
from shared import tools
from shared.llm import chat
from shared.prompts import SUPERVISOR
from guardrails import GuardrailEngine, guarded_llm
from observability.logging import get_logger, traced

logger = get_logger(__name__)
_guard = GuardrailEngine()


def _log(state: InvestigationState, msg: str) -> list[str]:
    trace = state.get("trace", []) + [msg]
    logger.info("node", extra={"step": msg})
    return trace


@traced("supervisor")
def supervisor_node(state: InvestigationState) -> dict:
    alert = state["alert"]
    plan = guarded_llm(_guard, chat, SUPERVISOR,
                       f"Alert: {alert.title}\n{alert.description}\n"
                       f"Target: {alert.target}", max_tokens=600)
    return {"plan": plan, "trace": _log(state, "Supervisor built investigation plan")}


@traced("security_scanner_node")
def scanner_node(state: InvestigationState) -> dict:
    target = state["alert"].target
    results, findings = tools.tool_run_scanners(target)
    trace = _log(state, f"Security Scanner Agent produced {len(findings)} findings")
    for r in results:
        if r.error:
            trace = trace + [f"WARNING scanner '{r.scanner}': {r.error}"]
    return {"scan_results": results, "findings": findings, "trace": trace}


@traced("vulnerability_node")
def vulnerability_node(state: InvestigationState) -> dict:
    findings = tools.tool_triage_findings(state["findings"])
    return {"findings": findings,
            "trace": _log(state, "Vulnerability agent triaged + enriched via RAG")}


@traced("compliance_node")
def compliance_node(state: InvestigationState) -> dict:
    findings = tools.tool_map_compliance(state["findings"])
    return {"findings": findings,
            "trace": _log(state, "Compliance agent mapped findings to GRC controls")}


@traced("remediation_node")
def remediation_node(state: InvestigationState) -> dict:
    tickets = tools.tool_create_tickets(state["findings"])
    return {"tickets": tickets,
            "trace": _log(state, f"Remediation agent opened {len(tickets)} tickets")}


@traced("reporting_node")
def reporting_node(state: InvestigationState) -> dict:
    report = tools.tool_build_report(state["findings"], state.get("tickets", []))
    return {"report": report,
            "trace": _log(state, "Reporting agent produced executive summary")}


def build_graph():
    g = StateGraph(InvestigationState)
    g.add_node("supervisor", supervisor_node)
    g.add_node("security_scanner", scanner_node)
    g.add_node("vulnerability", vulnerability_node)
    g.add_node("compliance", compliance_node)
    g.add_node("remediation", remediation_node)
    g.add_node("reporting", reporting_node)

    g.set_entry_point("supervisor")
    g.add_edge("supervisor", "security_scanner")
    g.add_edge("security_scanner", "vulnerability")
    g.add_edge("vulnerability", "compliance")
    g.add_edge("compliance", "remediation")
    g.add_edge("remediation", "reporting")
    g.add_edge("reporting", END)
    return g.compile()
