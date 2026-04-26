FROM python:3.11-slim

WORKDIR /app

RUN apt-get update -q && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir -e .

COPY app ./app

EXPOSE 8010 1389 1099 9999

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
  CMD curl -fsS http://localhost:8010/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8010"]
