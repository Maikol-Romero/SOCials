#!/bin/bash
# Daily Postgres backup → S3.
# - Runs integrity-check.sh first; cancels backup if integrity fails.
# - Streams pg_dumpall through gzip and uploads to S3.
# - Notifies Discord on success / failure.
#
# Required env (or .env in this dir): S3_BUCKET, DISCORD_WEBHOOK
# Required tooling on host: docker, aws-cli, curl, gzip
set -e

# Load .env if present
[ -f "$(dirname "$0")/../.env" ] && set -a && . "$(dirname "$0")/../.env" && set +a
: "${S3_BUCKET:?S3_BUCKET not set}"
: "${DISCORD_WEBHOOK:?DISCORD_WEBHOOK not set}"

CONTAINER="${PATRONI_CONTAINER:-patroni-node}"
TIMESTAMP=$(date +%Y-%m-%d_%H%M)
BACKUP_DIR="/tmp/db-backups"
BACKUP_FILE="postgres-backup-${TIMESTAMP}.sql.gz"
LOG_FILE="/var/log/postgres-backup.log"
INTEGRITY_SCRIPT="$(dirname "$0")/integrity-check.sh"

log() { echo "[$(date)] $1" | tee -a ${LOG_FILE}; }

notify_discord() {
    local color=$1
    local title=$2
    local msg=$3
    curl -s -H "Content-Type: application/json" -X POST ${DISCORD_WEBHOOK} -d "{
        \"embeds\": [{
            \"title\": \"${title}\",
            \"description\": \"${msg}\",
            \"color\": ${color},
            \"footer\": {\"text\": \"postgres backup · $(date +%Y-%m-%d\ %H:%M\ UTC)\"}
        }]
    }" > /dev/null 2>&1
}

log "Iniciando backup..."
mkdir -p ${BACKUP_DIR}

# Integrity check first — abort if anomalies detected.
if ! bash "$INTEGRITY_SCRIPT" >> ${LOG_FILE} 2>&1; then
    log "INTEGRIDAD FALLIDA — backup cancelado"
    notify_discord 16711680 "BACKUP CANCELADO — Integridad fallida" "El check de integridad detectó anomalías. El backup NO se ejecutó para proteger los backups limpios.\n\nAcción: verificar delayed replica INMEDIATAMENTE"
    exit 1
fi

# pg_dumpall through gzip → local file
docker exec ${CONTAINER} pg_dumpall -U postgres | gzip > ${BACKUP_DIR}/${BACKUP_FILE}
FILESIZE=$(du -h ${BACKUP_DIR}/${BACKUP_FILE} | cut -f1)
log "Dump completado: ${BACKUP_FILE} (${FILESIZE})"

# Upload to S3
aws s3 cp ${BACKUP_DIR}/${BACKUP_FILE} ${S3_BUCKET}/daily/${BACKUP_FILE} --quiet
log "Subido a S3: ${S3_BUCKET}/daily/${BACKUP_FILE}"

rm -f ${BACKUP_DIR}/${BACKUP_FILE}

BACKUP_COUNT=$(aws s3 ls ${S3_BUCKET}/daily/ | wc -l)

log "Backup completado exitosamente"
notify_discord 3066993 "Backup diario OK" "Archivo: ${BACKUP_FILE}\nTamaño: ${FILESIZE}\nDestino: S3 (Object Lock recomendado)\nBackups totales: ${BACKUP_COUNT}\nIntegridad: OK"
