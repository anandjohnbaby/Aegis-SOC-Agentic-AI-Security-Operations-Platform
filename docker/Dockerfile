FROM python:3.11-slim
WORKDIR /app
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

# Install Trivy (optional, for real-mode scanning)
RUN apt-get update && apt-get install -y curl nmap && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin || true && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
