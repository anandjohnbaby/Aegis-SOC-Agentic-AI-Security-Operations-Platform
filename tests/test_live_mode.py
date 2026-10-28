"""With MOCK_MODE=false nothing may fall back to fake data - errors must surface."""
import pytest

from shared.config import get_settings


@pytest.fixture
def live(monkeypatch):
    monkeypatch.setenv("MOCK_MODE", "false")
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "")
    get_settings.cache_clear()
    yield monkeypatch
    monkeypatch.undo()
    get_settings.cache_clear()


def test_missing_key_raises_instead_of_mock(live):
    from shared.llm import chat, LLMError
    with pytest.raises(LLMError, match="GROQ_API_KEY"):
        chat("sys", "hello")


def test_api_error_is_surfaced(live):
    from shared import llm
    live.setenv("GROQ_API_KEY", "bad-key")
    get_settings.cache_clear()

    class Boom:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    raise Exception("401 Invalid API Key")
    live.setattr(llm, "_client_and_model", lambda: (Boom, "m"))
    with pytest.raises(llm.LLMError, match="401 Invalid API Key"):
        llm.chat("sys", "hello")


def test_empty_answer_is_an_error(live):
    from shared import llm
    live.setenv("GROQ_API_KEY", "k")
    get_settings.cache_clear()

    class Msg: content = ""
    class Choice:
        message = Msg()
        finish_reason = "stop"
    class Resp:
        choices = [Choice()]
        model = "some/reasoning-model:free"

    class Fake:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    return Resp()
    live.setattr(llm, "_client_and_model", lambda: (Fake, "m"))
    with pytest.raises(llm.LLMError, match="some/reasoning-model:free"):
        llm.chat("sys", "hello")


def test_ticketing_down_raises_not_fake_numbers(live):
    from mock_apis.client import ServiceNowClient, TicketingError
    from shared.schemas import Ticket
    live.setenv("SERVICENOW_URL", "http://127.0.0.1:9")
    get_settings.cache_clear()
    with pytest.raises(TicketingError):
        ServiceNowClient().create_incident(Ticket(short_description="x"))


def test_scanners_return_no_fake_findings(live):
    from scanners import SecurityScannerAgent
    results, merged = SecurityScannerAgent().run("http://127.0.0.1:9")
    assert merged == []
    assert all(not r.mock for r in results)
    by = {r.scanner: r for r in results}
    assert by['trivy'].error and by['nikto'].error and by['owasp_zap'].error


def test_empty_then_retry_with_bigger_budget_succeeds(live):
    from shared import llm
    live.setenv("GROQ_API_KEY", "k")
    get_settings.cache_clear()
    calls = []

    def make(content, reason):
        class Msg: pass
        m = Msg(); m.content = content
        class Choice: pass
        c = Choice(); c.message = m; c.finish_reason = reason
        class Resp: pass
        r = Resp(); r.choices = [c]; r.model = "x"
        return r

    class Fake:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    calls.append(kw["max_tokens"])
                    return make("" if len(calls) == 1 else "real answer",
                                "length" if len(calls) == 1 else "stop")
    live.setattr(llm, "_client_and_model", lambda: (Fake, "m"))
    assert llm.chat("s", "u", max_tokens=300) == "real answer"
    assert calls == [300, 1200]
