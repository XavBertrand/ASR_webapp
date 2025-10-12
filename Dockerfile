# ================================
# ASR_webapp — Dockerfile (Flask)
# ================================
# Hypothèses retenues :
# - Backend Flask dans: server/app.py et objet Flask nommé `app`
# - Frontend statique dans: webapp/  (servi par Flask ou en statique)
# - Dépendances Python minimales: flask, flask-cors, werkzeug, requests, gunicorn
# - La webapp appelle l'ASR via l'URL fournie par JETSON_URL (ex: http://asr:8001)
#
# Placement : à la racine du repo ASR_webapp/  (ASR_webapp/Dockerfile)
# Build:  docker build -t xavier/asr-webapp:latest .
# Run :   docker run --rm -p 8000:8000 -e JETSON_URL=http://asr:8001 xavier/asr-webapp:latest
# =================================

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# OS deps minimalistes (certifs, build tools réduits)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copie fine (d’abord requirements si tu en as, sinon on installe en dur)
# Si tu ajoutes un pyproject.toml plus tard, adapte ici pour faire un layer de cache.
COPY server/ server/
COPY webapp/ webapp/
# (éventuellement) COPY .env ./
# (éventuellement) COPY config/ config/

# Dépendances Python — on reste simple et robuste (prod)
# Tu utilises uv en dev : pas obligé dans l'image prod.
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir \
    flask \
    flask-cors \
    werkzeug \
    requests \
    gunicorn

# Variables d'env par défaut (surchargées au run/compose)
ENV JETSON_URL="http://asr:8001" \
    FLASK_ENV=production

# Exposer le port du backend Flask
EXPOSE 8000

# Santé (optionnel) — ping /api/status si tu l’implémentes
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/status || exit 1

# Démarrage
# - gunicorn: 2 workers threads → bon compromis uploads + I/O
# - timeout augmenté si gros fichiers audio (120s ici, adapte à ton besoin)
# - si ton entrypoint Flask n'est pas server.app:app, modifie la cible gunicorn
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["gunicorn", "server.app:app", \
     "-w", "2", "-k", "gthread", \
     "--threads", "4", \
     "-b", "0.0.0.0:8000", \
     "--timeout", "120"]
