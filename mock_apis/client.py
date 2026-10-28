"""ServiceNow REST client used by the Remediation agent.

Talks HTTP to the ServiceNow service. In mock mode an unreachable service falls
back to an in-memory stub; in live mode it raises TicketingError.
"""
from __future__ import annotations

import requests

from shared.config import get_settings
from shared.schemas import Ticket
from observability.logging import get_logger

logger = get_logger(__name__)


class TicketingError(RuntimeError):
    """Raised in live mode when the ticketing system cannot be reached."""


class ServiceNowClient:
    def __init__(self):
        s = get_settings()
        self.base = s.servicenow_url.rstrip("/")
        self.auth = (s.servicenow_user, s.servicenow_password)
        self._mem_counter = 9000

    def create_incident(self, ticket: Ticket) -> Ticket:
        payload = {"short_description": ticket.short_description,
                   "description": ticket.description,
                   "priority": ticket.priority}
        try:
            r = requests.post(f"{self.base}/api/now/table/incident",
                              json=payload, auth=self.auth, timeout=5)
            r.raise_for_status()
            res = r.json()["result"]
            logger.info("servicenow.created", extra={"number": res["number"]})
            return ticket.model_copy(update={"sys_id": res["sys_id"],
                                             "number": res["number"],
                                             "state": res["state"]})
        except Exception as exc:
            if not get_settings().mock_mode:
                raise TicketingError(
                    f"ServiceNow request to {self.base} failed: {exc}. Start the ticketing "
                    "API (make servicenow) or set SERVICENOW_URL= (empty) to disable tickets."
                ) from exc
            self._mem_counter += 1
            logger.warning("servicenow.offline_stub", extra={"err": str(exc)})
            return ticket.model_copy(update={"sys_id": f"stub-{self._mem_counter}",
                                             "number": f"INC{self._mem_counter}",
                                             "state": "new"})
