"""Structured JSON logging + a tiny tracing decorator."""
from __future__ import annotations

import functools
import json
import logging
import sys
import time
from typing import Any, Callable


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, val in record.__dict__.items():
            if key not in logging.LogRecord("", 0, "", 0, "", (), None).__dict__ \
                    and key not in ("message", "asctime"):
                payload[key] = val
        return json.dumps(payload, default=str)


_configured = False


def _configure() -> None:
    global _configured
    if _configured:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    _configure()
    return logging.getLogger(name)


def traced(label: str | None = None) -> Callable:
    """Decorator that logs entry/exit and duration of a function (a trace span)."""
    def deco(fn: Callable) -> Callable:
        name = label or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            log = get_logger("trace")
            start = time.perf_counter()
            log.info("span.start", extra={"span": name})
            try:
                return fn(*args, **kwargs)
            finally:
                dur = round((time.perf_counter() - start) * 1000, 1)
                log.info("span.end", extra={"span": name, "ms": dur})
        return wrapper
    return deco
