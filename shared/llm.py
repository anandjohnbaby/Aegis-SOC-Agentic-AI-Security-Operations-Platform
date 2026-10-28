"""LLM integration layer.

Wraps Groq and OpenRouter behind one `chat()` call using the OpenAI-compatible
client. Mock text is used ONLY when MOCK_MODE=true; live mode raises LLMError.
"""
from __future__ import annotations

from typing import Optional

from shared.config import get_settings
from observability.logging import get_logger

logger = get_logger(__name__)

_PROVIDER_BASE_URLS = {
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
}


def _client_and_model():
    s = get_settings()
    from openai import OpenAI  # imported lazily so mock mode has no hard dep
    if s.llm_provider == "groq":
        return OpenAI(api_key=s.groq_api_key,
                      base_url=_PROVIDER_BASE_URLS["groq"]), s.groq_model
    return OpenAI(api_key=s.openrouter_api_key,
                  base_url=_PROVIDER_BASE_URLS["openrouter"]), s.openrouter_model


def _mock_chat(system: str, user: str) -> str:
    """Deterministic, useful-looking response for offline runs."""
    head = user.strip().splitlines()[0][:120] if user.strip() else "(empty)"
    return (
        "[MOCK-LLM] Analysis complete.\n"
        f"Context handled: {head}\n"
        "Assessment: findings triaged by severity; critical/high items prioritised "
        "for remediation and ticketing; low/info items logged. "
        "Recommend patching to fixed versions and mapping to NIST CSF controls."
    )


class LLMError(RuntimeError):
    """Raised in live mode (MOCK_MODE=false) when the LLM cannot be used.

    There is deliberately NO fallback to mock text in live mode: a broken key,
    quota error, or empty answer must be visible, not hidden.
    """


def chat(system: str, user: str, temperature: float = 0.2,
         max_tokens: int = 800) -> str:
    """Single-shot chat completion. Mock text only when MOCK_MODE=true."""
    s = get_settings()
    if s.mock_mode:
        logger.debug("llm.mock", extra={"provider": s.llm_provider})
        return _mock_chat(system, user)

    # ---- live mode: fail loudly -------------------------------------------
    if s.llm_provider not in ("groq", "openrouter"):
        raise LLMError(f"LLM_PROVIDER='{s.llm_provider}' is not valid in live mode "
                       "(use 'groq' or 'openrouter').")
    key_name = "GROQ_API_KEY" if s.llm_provider == "groq" else "OPENROUTER_API_KEY"
    if not s.llm_is_live:
        raise LLMError(f"MOCK_MODE=false but {key_name} is empty. "
                       f"Set {key_name} in .env (or set MOCK_MODE=true).")
    def _call(tokens: int):
        client, model = _client_and_model()
        return client.chat.completions.create(
            model=model, temperature=temperature, max_tokens=tokens,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}])

    try:
        resp = _call(max_tokens)
        # Reasoning models may spend the whole budget thinking and return no
        # text (finish_reason == "length"). Retry ONCE with a bigger budget.
        if not (resp.choices[0].message.content or "").strip() \
                and getattr(resp.choices[0], "finish_reason", None) == "length":
            logger.warning("llm.empty_retry", extra={"model": getattr(resp, "model", "?")})
            resp = _call(min(max_tokens * 4, 4000))
    except Exception as exc:
        logger.error("llm.error", extra={"provider": s.llm_provider, "err": str(exc)})
        raise LLMError(f"{s.llm_provider} LLM call failed: {exc}") from exc

    choice = resp.choices[0]
    text = (choice.message.content or "").strip()
    if not text:
        used = getattr(resp, "model", None) or "unknown model"
        reason = getattr(choice, "finish_reason", None)
        raise LLMError(
            f"{s.llm_provider} model '{used}' returned an empty answer "
            f"(finish_reason={reason}). It is probably a reasoning model; choose a "
            "non-reasoning model (e.g. Groq llama-3.3-70b-versatile) in .env.")
    return text
