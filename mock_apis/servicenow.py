"""Mock ServiceNow (SOAR / ITSM ticketing) REST API.

Mimics the Table API: POST/GET /api/now/table/incident. Lets the Remediation
agent demonstrate real REST integration with a third-party security platform.
Run:  uvicorn mock_apis.servicenow:app --port 8001
"""
from __future__ import annotations

from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Mock ServiceNow")
_DB: dict[str, dict] = {}
_counter = {"n": 1000}


class IncidentIn(BaseModel):
    short_description: str
    description: str = ""
    priority: int = 3
    urgency: int = 3


@app.post("/api/now/table/incident")
def create_incident(body: IncidentIn):
    sys_id = uuid4().hex
    _counter["n"] += 1
    rec = {"sys_id": sys_id, "number": f"INC{_counter['n']:07d}",
           "state": "new", **body.model_dump()}
    _DB[sys_id] = rec
    return {"result": rec}


@app.get("/api/now/table/incident")
def list_incidents():
    return {"result": list(_DB.values())}


@app.get("/api/now/table/incident/{sys_id}")
def get_incident(sys_id: str):
    if sys_id not in _DB:
        raise HTTPException(404, "not found")
    return {"result": _DB[sys_id]}


@app.get("/health")
def health():
    return {"status": "ok", "incidents": len(_DB)}
