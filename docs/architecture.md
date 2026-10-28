# Architecture

Aegis-SOC is a multi-agent security operations platform. A shared `core` of
tools (scanners, RAG, guardrails, compliance, ticketing) is orchestrated by three
interchangeable agent frameworks (LangGraph, CrewAI, AutoGen). The FastAPI
gateway exposes the pipeline; a Streamlit dashboard visualises results.

Agent roles: Supervisor → Security Scanner → Vulnerability → Compliance →
Remediation → Reporting. The Security Scanner Agent fans out to Trivy, Nmap,
Nikto, and OWASP ZAP, normalises their output into a single `Finding` schema,
then hands off to the Vulnerability Agent.

Every LLM call passes through the guardrail engine (input injection scan +
output secret/PII redaction), and every tool call is authorised against an
allow-list to prevent tool misuse / SSRF.
