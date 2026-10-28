"""AI security guardrails: prompt-injection detection, PII/secret redaction,
tool-misuse checks, and safe output handling.

Addresses the three agentic AI risks called out in the JD:
  * prompt injection  -> input scanning
  * data leakage      -> PII/secret redaction on input AND output
  * tool misuse       -> allow-list + argument validation before any tool runs
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from observability.logging import get_logger

logger = get_logger(__name__)

# --- prompt-injection heuristics -------------------------------------------
INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) (instructions|prompts)",
    r"disregard (the )?(system|previous) (prompt|message)",
    r"you are now (a|an|in) .{0,40}(mode|jailbreak)",
    r"reveal (your )?(system prompt|instructions)",
    r"\bDAN\b|do anything now",
    r"print (your )?(api key|secret|password|credentials)",
    r"</?(system|assistant)>",   # fake role tags
]

# --- secret / PII patterns (redacted, never stored or displayed) ------------
SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "openai_key": r"sk-[A-Za-z0-9]{20,}",
    "groq_key": r"gsk_[A-Za-z0-9]{20,}",
    "bearer": r"Bearer\s+[A-Za-z0-9\-_\.]{20,}",
    "email": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "ipv4_private": r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+\b",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
}


class GuardrailViolation(Exception):
    """Raised when an input is blocked outright."""


@dataclass
class GuardrailReport:
    ok: bool = True
    blocked: bool = False
    reasons: list[str] = field(default_factory=list)
    redactions: list[str] = field(default_factory=list)
    text: str = ""


class GuardrailEngine:
    def __init__(self, allowed_tools: set[str] | None = None,
                 block_on_injection: bool = True):
        self.allowed_tools = allowed_tools or set()
        self.block_on_injection = block_on_injection
        self._inj = [re.compile(p, re.I) for p in INJECTION_PATTERNS]
        self._secret = {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}

    # ---- input side -------------------------------------------------------
    def scan_input(self, text: str) -> GuardrailReport:
        rep = GuardrailReport(text=text)
        for pat in self._inj:
            if pat.search(text):
                rep.reasons.append(f"prompt_injection:{pat.pattern[:30]}")
        if rep.reasons and self.block_on_injection:
            rep.ok, rep.blocked = False, True
            logger.warning("guardrail.input_blocked", extra={"reasons": rep.reasons})
            return rep
        rep.text, rep.redactions = self._redact(text)
        if rep.redactions:
            logger.info("guardrail.input_redacted", extra={"kinds": rep.redactions})
        return rep

    # ---- output side ------------------------------------------------------
    def sanitize_output(self, text: str) -> GuardrailReport:
        clean, kinds = self._redact(text)
        if kinds:
            logger.info("guardrail.output_redacted", extra={"kinds": kinds})
        return GuardrailReport(ok=True, text=clean, redactions=kinds)

    # ---- tool-misuse check ------------------------------------------------
    def authorize_tool(self, tool_name: str, args: dict) -> None:
        if self.allowed_tools and tool_name not in self.allowed_tools:
            raise GuardrailViolation(f"tool '{tool_name}' not in allow-list")
        # block obvious destructive / SSRF-style misuse of scan targets
        target = str(args.get("target", ""))
        if re.search(r"169\.254\.169\.254|file://|/etc/passwd", target):
            raise GuardrailViolation(f"blocked unsafe tool target: {target}")

    # ---- helpers ----------------------------------------------------------
    def _redact(self, text: str) -> tuple[str, list[str]]:
        kinds: list[str] = []
        for kind, pat in self._secret.items():
            if pat.search(text):
                kinds.append(kind)
                text = pat.sub(f"[REDACTED:{kind}]", text)
        return text, kinds


def guarded_llm(engine: GuardrailEngine, chat_fn, system: str, user: str, **kw) -> str:
    """Wrap any chat function with input + output guardrails."""
    report = engine.scan_input(user)
    if report.blocked:
        return "[BLOCKED by guardrails: potential prompt injection detected]"
    raw = chat_fn(system, report.text, **kw)
    return engine.sanitize_output(raw).text
