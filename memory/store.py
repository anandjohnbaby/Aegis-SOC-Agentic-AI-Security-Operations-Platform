"""Short-term conversation memory + persistent investigation store."""
from __future__ import annotations

import json
import pathlib
from collections import deque

from shared.schemas import Investigation


class ConversationMemory:
    """Rolling window of agent messages for multi-turn context."""
    def __init__(self, max_turns: int = 20):
        self._buf: deque[dict] = deque(maxlen=max_turns)

    def add(self, role: str, content: str) -> None:
        self._buf.append({"role": role, "content": content})

    def as_messages(self) -> list[dict]:
        return list(self._buf)


class InvestigationMemory:
    """Persists completed investigations to JSONL (read by analytics/API)."""
    def __init__(self, path: str = "data/investigations.jsonl"):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, inv: Investigation) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(inv.model_dump_json() + "\n")

    def all(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
