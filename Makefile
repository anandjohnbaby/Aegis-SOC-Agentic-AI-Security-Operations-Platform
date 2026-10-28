.PHONY: install run api servicenow dashboard demo test docker

install:   ; pip install -r requirements.txt
servicenow:; uvicorn mock_apis.servicenow:app --port 8001 --reload
api:       ; uvicorn api.main:app --port 8000 --reload
dashboard: ; streamlit run analytics/dashboard.py
demo:      ; python -m lg_flow.run
test:      ; pytest -q
docker:    ; docker compose up --build
