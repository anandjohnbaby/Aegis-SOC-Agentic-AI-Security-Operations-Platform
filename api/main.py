"""FastAPI gateway — the production entrypoint.

Endpoints:
  GET  /health
  POST /investigate        run full agentic investigation (LangGraph)
  POST /ingest/alert       accept a SIEM-style alert and investigate
  GET  /investigations     list past investigations
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shared.config import get_settings
from shared.schemas import Alert
from shared.llm import LLMError
from mock_apis.client import TicketingError
from lg_flow.run import run_investigation
from memory import InvestigationMemory
from database.repository import Repository
from observability.logging import get_logger

logger = get_logger(__name__)
app = FastAPI(title="Aegis-SOC Agentic Security Platform", version="1.0.0")
_mem = InvestigationMemory()
_repo = Repository()


class AlertIn(BaseModel):
    title: str
    description: str = ""
    target: str = ""
    source: str = "api"


@app.get("/health")
def health():
    s = get_settings()
    return {"status": "ok", "mock_mode": s.mock_mode, "llm_live": s.llm_is_live}


@app.post("/investigate")
@app.post("/ingest/alert")
def investigate(body: AlertIn):
    s = get_settings()
    alert = Alert(title=body.title, description=body.description,
                  target=body.target or s.default_scan_target, source=body.source)
    try:
        inv = run_investigation(alert)
    except (LLMError, TicketingError) as exc:
        logger.error("investigation.failed", extra={"err": str(exc)})
        raise HTTPException(status_code=502, detail=str(exc))
    _mem.save(inv)
    _repo.save_investigation(inv)
    return inv.model_dump()


@app.get("/investigations")
def investigations():
    return {"count": len(_mem.all()), "items": _mem.all()}
