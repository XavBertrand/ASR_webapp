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
GUNICORN_HOST="${GUNICORN_HOST:-0.0.0.0}"
GUNICORN_PORT="${GUNICORN_PORT:-8000}"
GUNICORN_WORKERS="${GUNICORN_WORKERS:-4}"
GUNICORN_THREADS="${GUNICORN_THREADS:-4}"
GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-300}"

BASIC_AUTH_USER="${BASIC_AUTH_USER:-xavier}"
BASIC_AUTH_PASSWORD_HASH="${BASIC_AUTH_PASSWORD_HASH:-}"
if [[ -z "${BASIC_AUTH_PASSWORD_HASH}" ]]; then
    BASIC_AUTH_PASSWORD="${BASIC_AUTH_PASSWORD:-MyPassword}"
    if [[ "${BASIC_AUTH_PASSWORD}" == "MyPassword" ]]; then
        log "WARNING: BASIC_AUTH_PASSWORD not provided, using default 'MyPassword'."
    fi
    BASIC_AUTH_PASSWORD_HASH="$(caddy hash-password --plaintext "${BASIC_AUTH_PASSWORD}")"
fi

auth_lines=$'        '"${BASIC_AUTH_USER} ${BASIC_AUTH_PASSWORD_HASH}"
if [[ -n "${BASIC_AUTH_EXTRA_USERS:-}" ]]; then
    IFS=';' read -ra extra_users <<< "${BASIC_AUTH_EXTRA_USERS}"
    for pair in "${extra_users[@]}"; do
        pair="$(echo "${pair}" | xargs || true)"
        [[ -z "${pair}" ]] && continue
        auth_lines+=$'\n        '"${pair}"
    done
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
    printf '    basic_auth {\n%b\n    }\n\n' "${auth_lines}"
    printf '    @health {\n        path /health\n    }\n'
    printf '    reverse_proxy @health 127.0.0.1:%s\n\n' "${GUNICORN_PORT}"
    printf '    @uploads {\n        path /upload*\n    }\n'
    printf '    reverse_proxy @uploads 127.0.0.1:%s {\n' "${GUNICORN_PORT}"
    printf '        transport http {\n'
    printf '            read_timeout  300s\n'
    printf '            write_timeout 300s\n'
    printf '            dial_timeout  10s\n'
    printf '        }\n'
    printf '    }\n\n'
    printf '    root * %s/webapp\n' "${APP_DIR}"
    printf '    file_server\n'
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
