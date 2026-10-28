"""Typed state shared across LangGraph nodes."""
from __future__ import annotations

from typing import TypedDict

from shared.schemas import Alert, Finding, Ticket, Report, ScanResult


class InvestigationState(TypedDict, total=False):
    alert: Alert
    plan: str
    scan_results: list[ScanResult]
    findings: list[Finding]
    tickets: list[Ticket]
    report: Report
    trace: list[str]
