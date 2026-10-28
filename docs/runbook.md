# Runbook

1. `pip install -r requirements.txt`
2. `cp .env.example .env`  (keep MOCK_MODE=true for first run)
3. Terminal A: `make servicenow`
4. Terminal B: `make api`
5. `curl -X POST localhost:8000/investigate -H 'content-type: application/json' \
      -d '{"title":"Web host alert","target":"http://localhost:5000"}'`
6. `make dashboard` to view analytics.

Going live: set MOCK_MODE=false, add GROQ_API_KEY (free at console.groq.com),
install Trivy/Nmap, and the same code uses real tools + a real LLM.
