FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UPLOAD_FOLDER=/data/recordings

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    ffmpeg \
    gnupg \
    tini \
 && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg \
 && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | tee /etc/apt/sources.list.d/caddy-stable.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends caddy \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md uv.lock ./
COPY server server
COPY webapp webapp
COPY docker docker

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r server/requirements.txt \
 && pip install --no-cache-dir gunicorn flask-cors requests

RUN mkdir -p /data/recordings && chmod 755 /app/docker/*.sh

EXPOSE 80 443 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker/entrypoint.sh"]
