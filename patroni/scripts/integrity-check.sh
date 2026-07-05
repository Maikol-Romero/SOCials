#!/bin/bash
# Daily Postgres integrity check.
# - Captures table row counts + extension count snapshot
# - Compares with yesterday's snapshot
# - Alerts if any monitored table dropped >50% rows or went empty
# - Alerts if extension count regressed
#
# Used as a pre-flight check for backup.sh — if integrity fails, we DO NOT
# overwrite our last good backup with a potentially poisoned one.
#
# Required env (or .env): S3_BUCKET, DISCORD_WEBHOOK
set -e

[ -f "$(dirname "$0")/../.env" ] && set -a && . "$(dirname "$0")/../.env" && set +a
: "${S3_BUCKET:?S3_BUCKET not set}"
: "${DISCORD_WEBHOOK:?DISCORD_WEBHOOK not set}"

CONTAINER="${PATRONI_CONTAINER:-patroni-node}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/var/lib/postgres-integrity/snapshots}"
TODAY=$(date +%Y-%m-%d)
YESTERDAY_FILE="${SNAPSHOT_DIR}/snapshot-latest.json"
TODAY_FILE="${SNAPSHOT_DIR}/snapshot-${TODAY}.json"

# Customize the list of databases you want monitored
DATABASES="${DATABASES:-postgres}"
# Customize the schemas you want compared
WATCHED_SCHEMAS="${WATCHED_SCHEMAS:-public,auth,storage}"

log() { echo "[$(date)] $1"; }

notify_discord() {
    local color=$1
    local title=$2
    local msg=$3
    curl -s -H "Content-Type: application/json" -X POST ${DISCORD_WEBHOOK} -d "{
        \"embeds\": [{
            \"title\": \"${title}\",
            \"description\": \"${msg}\",
            \"color\": ${color},
            \"footer\": {\"text\": \"postgres integrity · $(date +%Y-%m-%d\ %H:%M\ UTC)\"}
        }]
    }" > /dev/null 2>&1
}

mkdir -p ${SNAPSHOT_DIR}
> ${TODAY_FILE}

log "Tomando snapshot de integridad..."

SCHEMAS_LIST=$(echo "$WATCHED_SCHEMAS" | sed "s/,/','/g")
SCHEMAS_LIST="'${SCHEMAS_LIST}'"

for DB in ${DATABASES//,/ }; do
    docker exec ${CONTAINER} psql -U postgres -d ${DB} -c "ANALYZE;" > /dev/null 2>&1
    docker exec ${CONTAINER} psql -U postgres -d ${DB} -t -A -c "
        SELECT '${DB}.' || schemaname || '.' || relname || '|' || n_live_tup
        FROM pg_stat_user_tables
        WHERE schemaname IN (${SCHEMAS_LIST})
        ORDER BY schemaname, relname;
    " 2>/dev/null >> ${TODAY_FILE}
done

EXT_COUNT=$(docker exec ${CONTAINER} psql -U postgres -tA -c "SELECT count(*) FROM pg_extension;" 2>/dev/null)
echo "EXTENSIONS|${EXT_COUNT}" >> ${TODAY_FILE}

TABLES=$(grep -cE "^[^|]+\." ${TODAY_FILE} 2>/dev/null || echo 0)
log "Snapshot: ${TABLES} tablas, extensiones=${EXT_COUNT}"

ALL_OK=true
ALERT_BODY=""

if [ -f "${YESTERDAY_FILE}" ]; then
    log "Comparando con snapshot anterior..."

    while IFS='|' read -r tabla filas_hoy; do
        if [ -z "$tabla" ] || [ "$tabla" = "EXTENSIONS" ]; then continue; fi
        [ -z "$filas_hoy" ] && filas_hoy=0

        filas_ayer=$(grep "^${tabla}|" ${YESTERDAY_FILE} | head -1 | cut -d'|' -f2)
        [ -z "$filas_ayer" ] && continue

        if [ "$filas_ayer" -gt 10 ] 2>/dev/null; then
            diff=$((filas_hoy - filas_ayer))
            pct_change=$(( (diff * 100) / filas_ayer ))

            PROBLEM=""
            if [ "$filas_hoy" -eq 0 ] && [ "$filas_ayer" -gt 10 ]; then
                PROBLEM="VACIA (tenia ${filas_ayer})"
            elif [ "$pct_change" -lt -50 ]; then
                PROBLEM="${filas_ayer} -> ${filas_hoy} (${pct_change}%)"
            fi

            if [ -n "$PROBLEM" ]; then
                ALL_OK=false
                ALERT_BODY="${ALERT_BODY}${tabla}: ${PROBLEM}\n"
            fi
        fi
    done < ${TODAY_FILE}

    ext_ayer=$(grep "^EXTENSIONS" ${YESTERDAY_FILE} | cut -d'|' -f2)
    if [ -n "$ext_ayer" ] && [ "${EXT_COUNT}" -lt "$ext_ayer" ]; then
        ALL_OK=false
        ALERT_BODY="${ALERT_BODY}Extensiones: ${ext_ayer} -> ${EXT_COUNT}\n"
    fi
else
    log "Primera ejecucion — guardando snapshot base"
fi

cp ${TODAY_FILE} ${YESTERDAY_FILE}
aws s3 cp ${TODAY_FILE} ${S3_BUCKET}/integrity/snapshot-${TODAY}.json --quiet 2>/dev/null

if [ "$ALL_OK" = false ]; then
    log "ALERTA DE INTEGRIDAD DETECTADA"
    log "${ALERT_BODY}"
    notify_discord 16711680 "ALERTA INTEGRIDAD POSTGRES" "${ALERT_BODY}Accion: verificar delayed replica INMEDIATAMENTE"
    exit 1
else
    log "Integridad OK — sin anomalias"
    notify_discord 3066993 "Integridad postgres OK" "${TABLES} tablas OK\nExtensiones: ${EXT_COUNT}"
fi
