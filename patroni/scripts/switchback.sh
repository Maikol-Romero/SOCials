#!/bin/bash
# Patroni Switchback + Auto-Reinitialize.
# Designed to run on the "preferred leader" node every minute via cron:
#
#   * * * * * /opt/patroni/scripts/switchback.sh
#
# Logic:
#   1. If this node is NOT the leader and has been streaming with 0 lag for
#      ${STABLE_MINUTES}, hand leadership back to it (switchover).
#   2. If this node IS the leader and any replica is "running" with lag > 1MB,
#      kick it with /reinitialize (rate-limited to once per 10 minutes).
#
# Required env (or .env): DISCORD_WEBHOOK, PATRONI_NODE_NAME

[ -f "$(dirname "$0")/../.env" ] && set -a && . "$(dirname "$0")/../.env" && set +a
: "${DISCORD_WEBHOOK:?DISCORD_WEBHOOK not set}"
: "${PATRONI_NODE_NAME:?PATRONI_NODE_NAME not set}"

PATRONI_API="${PATRONI_API:-http://localhost:8008}"
MY_NAME="${PATRONI_NODE_NAME}"
STABLE_FILE="/tmp/patroni-stable-since"
STABLE_MINUTES="${STABLE_MINUTES:-5}"
LOG="/var/log/patroni-switchback.log"

log() { echo "[$(date)] $1" >> ${LOG}; }

CLUSTER=$(curl -s --max-time 5 ${PATRONI_API}/cluster 2>/dev/null)
if [ -z "$CLUSTER" ]; then
    rm -f ${STABLE_FILE}
    exit 0
fi

# === PART 1: SWITCHBACK ===

MY_ROLE=$(echo "$CLUSTER" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for m in data.get('members', []):
    if m['name'] == '${MY_NAME}':
        print(m['role'])
        break
" 2>/dev/null)

if [ "$MY_ROLE" = "leader" ]; then
    rm -f ${STABLE_FILE}
else
    # I'm a replica — check if I'm a switchback candidate
    MY_STATE=$(echo "$CLUSTER" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for m in data.get('members', []):
    if m['name'] == '${MY_NAME}':
        print(m.get('state', ''))
        break
" 2>/dev/null)

    MY_LAG=$(echo "$CLUSTER" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for m in data.get('members', []):
    if m['name'] == '${MY_NAME}':
        print(m.get('lag', -1))
        break
" 2>/dev/null)

    if [ "$MY_STATE" = "streaming" ] && [ "$MY_LAG" = "0" ]; then
        if [ ! -f ${STABLE_FILE} ]; then
            date +%s > ${STABLE_FILE}
            log "Replica estable detectada. Esperando ${STABLE_MINUTES} minutos."
        else
            STABLE_SINCE=$(cat ${STABLE_FILE})
            NOW=$(date +%s)
            ELAPSED=$(( (NOW - STABLE_SINCE) / 60 ))
            if [ $ELAPSED -ge $STABLE_MINUTES ]; then
                CURRENT_LEADER=$(echo "$CLUSTER" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for m in data.get('members', []):
    if m['role'] == 'leader':
        print(m['name'])
        break
" 2>/dev/null)
                if [ -n "$CURRENT_LEADER" ]; then
                    log "Iniciando switchback: ${CURRENT_LEADER} -> ${MY_NAME} (estable ${ELAPSED} min)"
                    RESULT=$(curl -s -X POST ${PATRONI_API}/switchover \
                        -d "{\"leader\": \"${CURRENT_LEADER}\", \"candidate\": \"${MY_NAME}\"}" \
                        -H "Content-Type: application/json" 2>&1)
                    log "Resultado: ${RESULT}"
                    rm -f ${STABLE_FILE}
                    if echo "$RESULT" | grep -q "Successfully"; then
                        log "Switchback exitoso"
                        curl -s -H "Content-Type: application/json" -X POST ${DISCORD_WEBHOOK} -d "{
                            \"embeds\": [{
                                \"title\": \"Switchback automatico OK\",
                                \"description\": \"Liderazgo devuelto a ${MY_NAME}\nAnterior lider: ${CURRENT_LEADER}\nEstable: ${ELAPSED} min\",
                                \"color\": 3066993,
                                \"footer\": {\"text\": \"Patroni switchback\"}
                            }]
                        }" > /dev/null 2>&1
                    else
                        log "Switchback fallido: ${RESULT}"
                        curl -s -H "Content-Type: application/json" -X POST ${DISCORD_WEBHOOK} -d "{
                            \"embeds\": [{
                                \"title\": \"Switchback fallido\",
                                \"description\": \"Error: ${RESULT}\",
                                \"color\": 16711680,
                                \"footer\": {\"text\": \"Patroni switchback\"}
                            }]
                        }" > /dev/null 2>&1
                    fi
                fi
            fi
        fi
    else
        rm -f ${STABLE_FILE}
    fi
fi

# === PART 2: AUTO-REINITIALIZE STUCK REPLICAS ===
# Only the leader sees the cluster's true state, so this only runs there.

if [ "$MY_ROLE" = "leader" ]; then
    STUCK=$(echo "$CLUSTER" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for m in data.get('members', []):
    if m['role'] == 'replica' and m.get('state') == 'running':
        lag = m.get('lag', 0)
        if isinstance(lag, str) and lag == 'unknown':
            lag = 999999
        if isinstance(lag, (int, float)) and lag > 1000:
            print(m['name'] + '|' + m.get('api_url', '').replace('/patroni', ''))
" 2>/dev/null)

    if [ -n "$STUCK" ]; then
        echo "$STUCK" | while IFS='|' read -r RNAME RAPI; do
            [ -z "$RNAME" ] || [ -z "$RAPI" ] && continue
            LOCKFILE="/tmp/reinit-${RNAME}"

            # Don't reinit the same node more than once per 10 minutes.
            if [ -f "$LOCKFILE" ]; then
                LOCK_AGE=$(( $(date +%s) - $(cat "$LOCKFILE") ))
                [ $LOCK_AGE -lt 600 ] && continue
            fi

            log "Auto-reinitialize: ${RNAME} (stuck en running con lag alto)"
            RESULT=$(curl -s -X POST "${RAPI}/reinitialize" 2>&1)
            log "Reinitialize ${RNAME}: ${RESULT}"
            date +%s > "$LOCKFILE"

            curl -s -H "Content-Type: application/json" -X POST ${DISCORD_WEBHOOK} -d "{
                \"embeds\": [{
                    \"title\": \"Auto-reinitialize replica\",
                    \"description\": \"Replica ${RNAME} estaba stuck (running con lag alto)\nReinitialize enviado\nResultado: ${RESULT}\",
                    \"color\": 16776960,
                    \"footer\": {\"text\": \"Patroni auto-heal\"}
                }]
            }" > /dev/null 2>&1
        done
    fi
fi
