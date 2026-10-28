"""Pydantic data contracts shared across agents, scanners, and the API."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
    Severity.LOW: 2, Severity.INFO: 1,
}


class Alert(BaseModel):
    """An inbound alert (e.g. from a SIEM)."""
    id: str = Field(default_factory=lambda: f"ALERT-{uuid4().hex[:8]}")
    source: str = "manual"
    title: str
    description: str = ""
    target: str = ""
    raw: dict = Field(default_factory=dict)
    received_at: datetime = Field(default_factory=_now)


class Finding(BaseModel):
    """A normalized vulnerability finding from any scanner."""
    id: str = Field(default_factory=lambda: f"FND-{uuid4().hex[:8]}")
    scanner: str
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    target: str = ""
    references: list[str] = Field(default_factory=list)
    # enrichment added by RAG / agents:
    remediation: Optional[str] = None
    compliance: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    scanner: str
    target: str
    findings: list[Finding] = Field(default_factory=list)
    mock: bool = False
    error: Optional[str] = None


class Ticket(BaseModel):
    sys_id: Optional[str] = None
    number: Optional[str] = None
    short_description: str
    description: str = ""
    priority: int = 3
    state: str = "new"


class Report(BaseModel):
    summary: str = ""
    risk_rating: Severity = Severity.INFO
    finding_count: int = 0
    narrative: str = ""


class Investigation(BaseModel):
    id: str = Field(default_factory=lambda: f"INV-{uuid4().hex[:8]}")
    alert: Alert
    findings: list[Finding] = Field(default_factory=list)
    tickets: list[Ticket] = Field(default_factory=list)
    report: Optional[Report] = None
    status: str = "pending"
    created_at: datetime = Field(default_factory=_now)
    trace: list[str] = Field(default_factory=list)   # human-readable agent steps
