# Passbolt Bulk Tool — local Docker image (see README → "Option B · Docker").
# Keys, passphrases and credentials are never copied into the image: upload the key
# in the page, or mount it at runtime (docker-compose.yml).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PASSBOLT_TOOL_HOST=0.0.0.0 \
    PASSBOLT_TOOL_PORT=8765 \
    PASSBOLT_TOOL_OPEN_BROWSER=0

RUN useradd --create-home --uid 10001 app
WORKDIR /app

COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt

COPY passbolt_client.py webapp.py webapp_auto.py ./
# The app writes an uploaded CA certificate next to itself (custom-ca.pem).
RUN chown -R app:app /app
USER app

EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/status', timeout=4)"

CMD ["python", "webapp.py"]
