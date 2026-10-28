"""CrewAI orchestration of the same agent team.

Uses CrewAI Agents/Tasks/Crew with @tool-wrapped versions of shared.tools.
LLM runs through Groq/OpenRouter (litellm model strings). Degrades to a direct
pipeline call if crewai is not installed.
"""
from __future__ import annotations

from shared import tools
from shared.config import get_settings
from shared.schemas import Alert, Investigation

try:
    from crewai import Agent, Task, Crew, Process
    from crewai.tools import tool
    _HAS_CREWAI = True
except Exception:
    _HAS_CREWAI = False


if _HAS_CREWAI:
    @tool("run_security_scanners")
    def run_scanners_tool(target: str) -> str:
        """Run Trivy/Nmap/Nikto/ZAP against a target and return findings."""
        _, findings = tools.tool_run_scanners(target)
        return "\n".join(f"- [{f.severity}] {f.title} ({f.cve_id})" for f in findings)

    def _llm_model() -> str:
        s = get_settings()
        return (f"groq/{s.groq_model}" if s.llm_provider == "groq"
                else f"openrouter/{s.openrouter_model}")


def build_crew():
    s = get_settings()
    model = _llm_model()
    supervisor = Agent(role="SOC Supervisor", goal="Plan the investigation",
                       backstory="Lead SOC analyst.", llm=model, verbose=False)
    scanner = Agent(role="Security Scanner", goal="Run all scanners on the target",
                    backstory="Owns Trivy/Nmap/Nikto/ZAP.", tools=[run_scanners_tool],
                    llm=model, verbose=False)
    vuln = Agent(role="Vulnerability Analyst", goal="Triage and enrich findings",
                 backstory="CVSS + remediation expert.", llm=model, verbose=False)
    reporter = Agent(role="Reporter", goal="Write the executive summary",
                     backstory="Communicates risk to leadership.", llm=model)

    plan = Task(description="Plan the investigation for: {alert}",
                agent=supervisor, expected_output="A short plan.")
    scan = Task(description="Run all scanners on target {target}.",
                agent=scanner, expected_output="List of findings.")
    triage = Task(description="Triage the findings by severity with remediation.",
                  agent=vuln, expected_output="Prioritised findings.")
    report = Task(description="Produce the executive investigation report.",
                  agent=reporter, expected_output="Executive summary.")
    return Crew(agents=[supervisor, scanner, vuln, reporter],
                tasks=[plan, scan, triage, report], process=Process.sequential)


def run_investigation(alert: Alert) -> Investigation:
    """CrewAI path; falls back to shared pipeline if crewai unavailable/offline."""
    if not _HAS_CREWAI:
        from lg_flow.run import run_investigation as lg_run
        return lg_run(alert)
    crew = build_crew()
    crew.kickoff(inputs={"alert": alert.title, "target": alert.target})
    # we still run the deterministic tool pipeline to assemble the typed object
    from lg_flow.run import run_investigation as lg_run
    return lg_run(alert)
