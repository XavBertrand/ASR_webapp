#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "[duckdns] usage: duckdns-updater.sh <domain> <token> [interval_seconds]" >&2
    exit 1
fi

DOMAIN="$1"
TOKEN="$2"
INTERVAL="${3:-300}"

log() {
    printf '[%s] [duckdns] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

log "Starting update loop for ${DOMAIN} (every ${INTERVAL}s)"

while true; do
    if RESPONSE="$(curl -fsS "https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&ip=")"; then
        log "Update response: ${RESPONSE}"
    else
        log "Failed to reach DuckDNS"
    fi
    sleep "${INTERVAL}"
done
