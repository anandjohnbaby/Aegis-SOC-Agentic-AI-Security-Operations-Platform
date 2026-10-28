# API

| Method | Path | Description |
|--------|------|-------------|
| GET  | /health | Service + mode status |
| POST | /investigate | Run full agentic investigation. Body: {title, description, target} |
| POST | /ingest/alert | Alias for /investigate (SIEM-style ingestion) |
| GET  | /investigations | List past investigations |

Mock ServiceNow (port 8001):
| POST | /api/now/table/incident | Create incident |
| GET  | /api/now/table/incident | List incidents |
