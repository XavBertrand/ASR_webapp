#!/usr/bin/env bash
set -euo pipefail
umask 0002

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

APP_DIR="/app"
DATA_DIR="/data"
RECORDINGS_DIR="${UPLOAD_FOLDER:-${DATA_DIR}/recordings}"
mkdir -p "${RECORDINGS_DIR}" "${DATA_DIR}"
ln -sfn "${RECORDINGS_DIR}" "${APP_DIR}/recordings"
ln -sfn "${RECORDINGS_DIR}" "${DATA_DIR}/recordings"

TARGET_UID="${UPLOAD_UID:-${LOCAL_UID:-}}"
TARGET_GID="${UPLOAD_GID:-${LOCAL_GID:-}}"
if [[ -z "${TARGET_UID}" ]]; then
    TARGET_UID="$(stat -c '%u' "${RECORDINGS_DIR}" 2>/dev/null || echo 0)"
fi
if [[ -z "${TARGET_GID}" ]]; then
    TARGET_GID="$(stat -c '%g' "${RECORDINGS_DIR}" 2>/dev/null || echo 0)"
fi
export UPLOAD_UID="${TARGET_UID}"
export UPLOAD_GID="${TARGET_GID}"

if [[ "${TARGET_UID}" != "0" || "${TARGET_GID}" != "0" ]]; then
    if ! chown -R "${TARGET_UID}:${TARGET_GID}" "${RECORDINGS_DIR}"; then
        log "WARNING: impossible de chown ${RECORDINGS_DIR} vers ${TARGET_UID}:${TARGET_GID}"
    fi
fi
if ! chmod -R g+rwX "${RECORDINGS_DIR}"; then
    log "WARNING: chmod -R g+rwX a échoué sur ${RECORDINGS_DIR}"
fi
if ! find "${RECORDINGS_DIR}" -type d -exec chmod g+s {} +; then
    log "WARNING: impossible d'activer le bit setgid sur ${RECORDINGS_DIR}"
fi
log "Uploads seront créés avec UID:GID ${UPLOAD_UID}:${UPLOAD_GID}"

CADDY_DOMAIN="${CADDY_DOMAIN:-localhost}"
CADDY_EMAIL="${CADDY_EMAIL:-}"
WEBAPP_ENV="${WEBAPP_ENV:-}"
DEFAULT_BIND_LOCAL_ONLY="false"
if [[ "${WEBAPP_ENV}" == "production" || "${WEBAPP_ENV}" == "prod" ]]; then
    DEFAULT_BIND_LOCAL_ONLY="true"
fi
GUNICORN_BIND_LOCAL_ONLY="${GUNICORN_BIND_LOCAL_ONLY:-${DEFAULT_BIND_LOCAL_ONLY}}"
GUNICORN_HOST="${GUNICORN_HOST:-127.0.0.1}"
GUNICORN_PORT="${GUNICORN_PORT:-8000}"
GUNICORN_WORKERS="${GUNICORN_WORKERS:-4}"
GUNICORN_THREADS="${GUNICORN_THREADS:-4}"
GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-300}"
if [[ "${GUNICORN_BIND_LOCAL_ONLY}" == "true" ]]; then
    GUNICORN_HOST="127.0.0.1"
fi
if [[ "${GUNICORN_HOST}" == "0.0.0.0" ]]; then
    log "WARNING: GUNICORN_HOST=0.0.0.0 — Gunicorn exposé directement (bypass Caddy)."
    if [[ "${WEBAPP_ENV}" == "production" || "${WEBAPP_ENV}" == "prod" ]]; then
        log "WARNING: environnement production détecté avec bind 0.0.0.0 (non recommandé)."
    fi
fi

GATEWAY_BASICAUTH_USER="${GATEWAY_BASICAUTH_USER:-}"
GATEWAY_BASICAUTH_HASHED_PASSWORD="${GATEWAY_BASICAUTH_HASHED_PASSWORD:-}"
if [[ -n "${GATEWAY_BASICAUTH_USER}" && -z "${GATEWAY_BASICAUTH_HASHED_PASSWORD}" && -n "${GATEWAY_BASICAUTH_PASSWORD:-}" ]]; then
    GATEWAY_BASICAUTH_HASHED_PASSWORD="$(caddy hash-password --plaintext "${GATEWAY_BASICAUTH_PASSWORD}")"
fi
if [[ -n "${GATEWAY_BASICAUTH_USER}" && -z "${GATEWAY_BASICAUTH_HASHED_PASSWORD}" ]]; then
    log "INFO: GATEWAY_BASICAUTH_USER fourni sans mot de passe hashé — BasicAuth désactivé."
    GATEWAY_BASICAUTH_USER=""
fi

log "Using Caddy domain ${CADDY_DOMAIN}"
{
    printf '{\n    admin off\n'
    if [[ -n "${CADDY_EMAIL}" ]]; then
        printf '    email %s\n' "${CADDY_EMAIL}"
    fi
    printf '}\n\n'
    printf '%s {\n' "${CADDY_DOMAIN}"
    printf '    encode zstd gzip\n\n'
    printf '    header {\n'
    printf '        Content-Security-Policy "default-src '\''self'\''; script-src '\''self'\'' '\''unsafe-inline'\''; style-src '\''self'\'' '\''unsafe-inline'\'' https://fonts.googleapis.com; font-src '\''self'\'' https://fonts.gstatic.com data:; img-src '\''self'\'' data:; frame-ancestors '\''none'\''"\n'
    printf '        X-Content-Type-Options "nosniff"\n'
    printf '        X-Frame-Options "DENY"\n'
    printf '        Referrer-Policy "strict-origin-when-cross-origin"\n'
    printf '        Permissions-Policy "geolocation=(), microphone=(), camera=()"\n'
    printf '    }\n\n'
    if [[ -n "${GATEWAY_BASICAUTH_USER}" && -n "${GATEWAY_BASICAUTH_HASHED_PASSWORD}" ]]; then
        printf '    basic_auth {\n'
        printf '        %s %s\n' "${GATEWAY_BASICAUTH_USER}" "${GATEWAY_BASICAUTH_HASHED_PASSWORD}"
        printf '    }\n\n'
    fi
    printf '    @health {\n        path /health\n    }\n'
    printf '    handle @health {\n        reverse_proxy 127.0.0.1:%s\n    }\n\n' "${GUNICORN_PORT}"
    printf '    handle {\n'
    printf '        reverse_proxy 127.0.0.1:%s {\n' "${GUNICORN_PORT}"
    printf '            transport http {\n'
    printf '                read_timeout  300s\n'
    printf '                write_timeout 300s\n'
    printf '                dial_timeout  10s\n'
    printf '            }\n'
    printf '        }\n'
    printf '    }\n'
    printf '}\n'
} >/etc/caddy/Caddyfile

declare -a CHILD_PIDS=()
declare -a CHILD_NAMES=()

register_child() {
    CHILD_NAMES+=("$1")
    CHILD_PIDS+=("$2")
    log "$1 started with PID $2"
}

start_duckdns() {
    if [[ -z "${DUCKDNS_DOMAIN:-}" || -z "${DUCKDNS_TOKEN:-}" ]]; then
        log "DuckDNS credentials not provided — skipping auto-update."
        return
    fi
    local interval="${DUCKDNS_INTERVAL:-300}"
    log "Enabling DuckDNS auto-update for ${DUCKDNS_DOMAIN} (every ${interval}s)"
    /app/docker/duckdns-updater.sh "${DUCKDNS_DOMAIN}" "${DUCKDNS_TOKEN}" "${interval}" &
    register_child "DuckDNS" $!
}

start_caddy() {
    log "Starting Caddy"
    caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
    register_child "Caddy" $!
}

start_gunicorn() {
    log "Starting Gunicorn on ${GUNICORN_HOST}:${GUNICORN_PORT}"
    (
        cd "${APP_DIR}"
        exec gunicorn server.app:app \
            -w "${GUNICORN_WORKERS}" \
            -k gthread \
            --threads "${GUNICORN_THREADS}" \
            --bind "${GUNICORN_HOST}:${GUNICORN_PORT}" \
            --timeout "${GUNICORN_TIMEOUT}"
    ) &
    register_child "Gunicorn" $!
}

terminate_children() {
    for pid in "${CHILD_PIDS[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
            log "Stopping PID ${pid}"
            kill "${pid}" 2>/dev/null || true
        fi
    done
}

trap 'terminate_children' INT TERM

start_duckdns
start_caddy
start_gunicorn

set +e
if ! wait -n; then
    EXIT_CODE=$?
else
    EXIT_CODE=0
fi
log "A child process exited (code ${EXIT_CODE}), shutting down the rest..."
terminate_children
wait || true
exit "${EXIT_CODE}"
