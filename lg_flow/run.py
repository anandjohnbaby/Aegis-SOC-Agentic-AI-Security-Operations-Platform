"""Run an investigation through the LangGraph pipeline."""
from __future__ import annotations

from lg_flow.graph import build_graph
from shared import tools
from shared.schemas import Alert, Investigation


def run_investigation(alert: Alert) -> Investigation:
    tools.seed_rag_once()
    app = build_graph()
    final = app.invoke({"alert": alert, "trace": []})
    return Investigation(
        alert=alert,
        findings=final.get("findings", []),
        tickets=final.get("tickets", []),
        report=final.get("report"),
        status="completed",
        trace=final.get("trace", []),
    )


if __name__ == "__main__":
    inv = run_investigation(Alert(
        source="siem", title="Suspicious outbound traffic from web host",
        description="EDR flagged anomalous egress on the public web server.",
        target="http://localhost:5000"))
    print(inv.model_dump_json(indent=2))
