"""Thin persistence layer bridging pydantic Investigation -> SQL rows."""
from __future__ import annotations

from database.models import init_db, InvestigationRow, FindingRow
from shared.schemas import Investigation


class Repository:
    def __init__(self):
        self.Session = init_db()

    def save_investigation(self, inv: Investigation) -> None:
        with self.Session() as s:
            row = InvestigationRow(
                id=inv.id, title=inv.alert.title, status=inv.status,
                risk_rating=inv.report.risk_rating.value if inv.report else "INFO")
            for f in inv.findings:
                row.findings.append(FindingRow(
                    id=f.id, investigation_id=inv.id, scanner=f.scanner,
                    title=f.title, severity=f.severity.value,
                    cve_id=f.cve_id, cvss_score=f.cvss_score))
            s.merge(row)
            s.commit()
