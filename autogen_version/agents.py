"""AutoGen (pyautogen) GroupChat orchestration of the same agent team.

Registers shared.tools as callable functions on a UserProxyAgent and drives a
GroupChat of specialist AssistantAgents. Falls back to the shared pipeline if
pyautogen is not installed or no LLM key is present.
"""
from __future__ import annotations

from shared import tools
from shared.config import get_settings
from shared.schemas import Alert, Investigation

try:
    import autogen
    _HAS_AUTOGEN = True
except Exception:
    _HAS_AUTOGEN = False


def _llm_config() -> dict:
    s = get_settings()
    if s.llm_provider == "groq":
        return {"config_list": [{"model": s.groq_model, "api_key": s.groq_api_key,
                                 "base_url": "https://api.groq.com/openai/v1"}]}
    return {"config_list": [{"model": s.openrouter_model,
                             "api_key": s.openrouter_api_key,
                             "base_url": "https://openrouter.ai/api/v1"}]}


def build_groupchat():
    cfg = _llm_config()
    supervisor = autogen.AssistantAgent("Supervisor", llm_config=cfg,
        system_message="Plan the SOC investigation and delegate.")
    scanner = autogen.AssistantAgent("SecurityScanner", llm_config=cfg,
        system_message="Call run_scanners(target) then pass findings on.")
    vuln = autogen.AssistantAgent("VulnerabilityAnalyst", llm_config=cfg,
        system_message="Triage findings by CVSS severity and recommend fixes.")
    reporter = autogen.AssistantAgent("Reporter", llm_config=cfg,
        system_message="Summarise the investigation for executives. Reply TERMINATE when done.")
    user = autogen.UserProxyAgent("Orchestrator", human_input_mode="NEVER",
        code_execution_config=False,
        is_termination_msg=lambda m: "TERMINATE" in (m.get("content") or ""))

    @user.register_for_execution()
    @scanner.register_for_llm(description="Run all security scanners on a target")
    def run_scanners(target: str) -> str:
        _, findings = tools.tool_run_scanners(target)
        return "\n".join(f"[{f.severity}] {f.title} {f.cve_id}" for f in findings)

    group = autogen.GroupChat(agents=[user, supervisor, scanner, vuln, reporter],
                              messages=[], max_round=8)
    return user, autogen.GroupChatManager(groupchat=group, llm_config=cfg)


def run_investigation(alert: Alert) -> Investigation:
    s = get_settings()
    if _HAS_AUTOGEN and s.llm_is_live:
        user, manager = build_groupchat()
        user.initiate_chat(manager,
            message=f"Investigate alert '{alert.title}' on target {alert.target}.")
    # Assemble the typed Investigation via the deterministic shared pipeline.
    from lg_flow.run import run_investigation as lg_run
    return lg_run(alert)
