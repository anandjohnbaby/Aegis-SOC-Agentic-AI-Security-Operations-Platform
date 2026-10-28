# 🛡️ Aegis-SOC — Agentic AI Security Operations Platform

A production-style, multi-agent AI system that automates the vulnerability
management lifecycle: it ingests a SIEM-style alert, runs a **Security Scanner
Agent** (Trivy / Nmap / Nikto / OWASP ZAP), triages findings with a
RAG-enriched **Vulnerability Agent**, maps them to GRC frameworks, opens
**ServiceNow** tickets over REST, and produces an executive report — all behind
**AI security guardrails**.

Implemented three ways over one shared core: **LangGraph**, **CrewAI**, and
**AutoGen**. Runs fully offline in `MOCK_MODE`; switch to Groq/OpenRouter + real
scanners with env vars only.

## Architecture Diagram
```
                 ┌───────────────┐
 SIEM / API ───▶ │ FastAPI (8000)│
                 └──────┬────────┘
                        ▼
                 ┌───────────────┐
                 │  Supervisor   │  (LangGraph / CrewAI / AutoGen)
                 └──────┬────────┘
                        ▼
                 ┌──────────────────────┐
                 │ Security Scanner Agent│
                 └──┬────┬────┬────┬─────┘
                  Trivy Nmap Nikto ZAP
                        ▼
                 ┌───────────────┐   ┌──────────────┐
                 │ Vulnerability │◀──│ RAG: ChromaDB │
                 └──────┬────────┘   └──────────────┘
                        ▼
                 ┌───────────────┐
                 │  Compliance   │ (NIST / CIS / ISO)
                 └──────┬────────┘
                        ▼
                 ┌───────────────┐   ┌──────────────────┐
                 │  Remediation  │──▶│ Mock ServiceNow  │ (REST, 8001)
                 └──────┬────────┘   └──────────────────┘
                        ▼
                 ┌───────────────┐   ┌──────────────────┐
                 │   Reporting   │──▶│ Streamlit (8501) │
                 └───────────────┘   └──────────────────┘
  Guardrails wrap every LLM call; allow-list wraps every tool call.
```

## Agent Architecture
Six specialist agents share one tool core: Supervisor (planner), Security
Scanner (tool fan-out), Vulnerability (CVSS triage + RAG remediation),
Compliance (GRC mapping), Remediation (ticketing), Reporting (exec summary).

## LangGraph Flow
`supervisor → security_scanner → vulnerability → compliance → remediation →
reporting → END`, with a typed `InvestigationState`. (`langgraph/graph.py`)

## CrewAI Workflow
Sequential `Crew` of Agents/Tasks with `@tool`-wrapped scanners, LLM via
litellm Groq/OpenRouter model strings. (`crewai_version/crew.py`)

## AutoGen Workflow
`GroupChat` + `GroupChatManager` with specialist `AssistantAgent`s and a
`UserProxyAgent` executing registered tool functions. (`autogen_version/agents.py`)

## RAG Architecture
ChromaDB persistent vector store seeded from `data/knowledge_base.json`
(CVE notes, OWASP/CIS remediation playbooks). Paragraph-aware chunking with
overlap; retrieval injects context into the Vulnerability agent's prompt.
Falls back to an in-memory lexical store if ChromaDB is unavailable.

## Guardrail Architecture
`guardrails/engine.py`: (1) prompt-injection detection on input, (2) PII/secret
redaction on input **and** output, (3) tool allow-list + target validation to
block tool misuse / SSRF (e.g. cloud-metadata IPs, `file://`).

## Trivy Integration
`scanners/trivy.py` calls `trivy image --format json` and parses CVE id, CVSS,
package, installed/fixed versions. Mock fallback returns realistic CVEs offline.

## Docker Setup
`docker compose up --build` starts api (8000), mock ServiceNow (8001),
Streamlit (8501), and the vulnerable Flask target (5000). Trivy + Nmap are
baked into the image for real-mode scanning.

## Running Instructions
```bash
pip install -r requirements.txt
cp .env.example .env            # MOCK_MODE=true works with no keys
make servicenow &               # terminal 1
make api                        # terminal 2
curl -X POST localhost:8000/investigate \
  -H 'content-type: application/json' \
  -d '{"title":"Web host alert","target":"http://localhost:5000"}'
make dashboard                  # analytics UI
make demo                       # run the LangGraph pipeline directly
make test                       # unit + integration tests
```

## Sample Investigations
`make demo` produces an `Investigation` with findings from all four scanners,
RAG-enriched remediation, GRC mappings, auto-created tickets, and a report.

## Sample Reports
The Reporting agent emits a risk rating (worst-severity rollup), severity
counts, top compliance gaps, and a narrative summary (see `shared/tools.py`).

## Screenshots
Run `make dashboard` → Streamlit shows severity/scanner charts and a findings
table. (Add your own screenshots to `docs/`.)

## API Documentation
See `docs/api.md`, or open `http://localhost:8000/docs` (FastAPI Swagger UI).

## Free models only
Groq (`console.groq.com`) and OpenRouter free tier — configured in `.env`.
