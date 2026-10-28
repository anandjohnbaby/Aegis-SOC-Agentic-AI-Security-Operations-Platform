import os

# tests rely on deterministic mock data regardless of the developer's .env
os.environ["MOCK_MODE"] = "true"
