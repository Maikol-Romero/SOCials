#!/bin/bash
# ============================================
# SOCials — Setup Maestro v2
# ============================================
# Un solo comando para desplegar todo el SOC.
# Detecta máquinas, instala monitoring remoto, configura alertas.
#
# Uso: ./setup.sh

set -e
# Parsear argumentos
CHECK_ONLY=false
for arg in "$@"; do
    case $arg in
        --check) CHECK_ONLY=true ;;
        --help|-h)
            echo "Uso: ./setup.sh [--check]"
            echo "  --check  Solo verificar estado, no desplegar"
            exit 0
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Backup de configs antes de desplegar
BACKUP_DIR="$SCRIPT_DIR/backups/$(date '+%Y%m%d_%H%M%S')"
if [ -f "$SCRIPT_DIR/monitor/observability/.env" ] || [ -f "$SCRIPT_DIR/inventory.json" ]; then
    mkdir -p "$BACKUP_DIR"
    cp "$SCRIPT_DIR/monitor/observability/.env" "$BACKUP_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/monitor/wazuh/.env" "$BACKUP_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/monitor/homepage/.env" "$BACKUP_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/inventory.json" "$BACKUP_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/monitor/observability/prometheus/prometheus.yml" "$BACKUP_DIR/" 2>/dev/null || true
    echo "Backup guardado en backups/"
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }
log_section() { echo -e "\n${CYAN}${BOLD}═══════════════════════════════════════${NC}"; echo -e "${CYAN}${BOLD}  $1${NC}"; echo -e "${CYAN}${BOLD}═══════════════════════════════════════${NC}\n"; }
log_ask()     { echo -en "${YELLOW}[?]${NC} $1"; }

# Arrays para máquinas de producción
declare -a PROD_NAMES PROD_IPS PROD_SSH_PORTS PROD_SSH_USERS PROD_SSH_CMDS
declare -a PROD_HAS_PG PROD_DB_USERS PROD_DB_PASSES PROD_DB_NAMES PROD_DB_HOSTS PROD_DB_PORTS

# ============================================
# 1. VERIFICAR DEPENDENCIAS
# ============================================
log_section "1/8 — Verificando dependencias"

for CMD in docker python3 tailscale; do
    if command -v $CMD &>/dev/null; then
        log_info "$CMD instalado"
    else
        log_error "$CMD no está instalado"
        exit 1
    fi
done

if docker compose version &>/dev/null; then
    log_info "docker compose disponible"
else
    log_error "docker compose no disponible"
    exit 1
fi

MONITOR_IP=$(tailscale ip -4 2>/dev/null || echo "")
MONITOR_NAME=$(hostname)
if [ -z "$MONITOR_IP" ]; then
    log_error "Tailscale no está conectado"
    exit 1
fi
log_info "Esta máquina: ${BOLD}$MONITOR_NAME${NC} ($MONITOR_IP)"

# Mostrar info del sistema
MONITOR_OS=$(. /etc/os-release && echo $PRETTY_NAME)
MONITOR_CPU="$(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs) ($(nproc) cores)"
MONITOR_RAM=$(free -h | awk '/^Mem:/{print $2}')
MONITOR_DISK=$(df -h / | awk 'NR==2{print $2}')
MONITOR_GPU=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 || echo "No detectada")
MONITOR_DOCKER=$(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',')

echo ""
echo -e "  ${BOLD}Software:${NC}"
echo -e "    OS:      $MONITOR_OS"
echo -e "    Docker:  v$MONITOR_DOCKER"
echo ""
echo -e "  ${BOLD}Hardware:${NC}"
echo -e "    CPU:     $MONITOR_CPU"
echo -e "    RAM:     $MONITOR_RAM"
echo -e "    Disco:   $MONITOR_DISK"
echo -e "    GPU:     ${MONITOR_GPU:-No detectada}"

# ============================================
# 2. CONFIGURAR CREDENCIALES
# ============================================
log_section "2/8 — Configurando credenciales"

OBS_ENV="$SCRIPT_DIR/monitor/observability/.env"
WAZ_ENV="$SCRIPT_DIR/monitor/wazuh/.env"
HOME_ENV="$SCRIPT_DIR/monitor/homepage/.env"

# Si no existe .env de observabilidad, pedir credenciales
if [ ! -f "$OBS_ENV" ] || grep -q "CAMBIAR" "$OBS_ENV" 2>/dev/null; then
    log_ask "Contraseña para Grafana admin: "
    read -r GF_PASS
    log_ask "Webhook URL de Discord (vacío para después): "
    read -r DISCORD_URL
    [ -z "$DISCORD_URL" ] && DISCORD_URL="PENDIENTE"

    cat > "$OBS_ENV" << ENVEOF
MONITOR_IP=$MONITOR_IP

GF_ADMIN_USER=admin
GF_ADMIN_PASSWORD=$GF_PASS
GF_HTTP_PORT=3001
PROMETHEUS_PORT=9090
PROMETHEUS_RETENTION=15d
LOKI_PORT=3100
LOKI_RETENTION=168h
TEMPO_HTTP_PORT=3200
TEMPO_GRPC_PORT=4317
DISCORD_WEBHOOK_URL=$DISCORD_URL
ENVEOF
    log_info "observability/.env creado"
else
    GF_PASS=$(grep GF_ADMIN_PASSWORD "$OBS_ENV" | cut -d= -f2- | tr -d '\r')
    DISCORD_URL=$(grep DISCORD_WEBHOOK_URL "$OBS_ENV" | cut -d= -f2- | tr -d '\r')
    log_info "observability/.env ya existe"
    # Verificar parámetros faltantes
    REQUIRED_KEYS="MONITOR_IP GF_ADMIN_USER GF_ADMIN_PASSWORD GF_HTTP_PORT PROMETHEUS_PORT LOKI_PORT TEMPO_HTTP_PORT TEMPO_GRPC_PORT DISCORD_WEBHOOK_URL PROMETHEUS_RETENTION LOKI_RETENTION"
    MISSING_KEYS=""
    for KEY in $REQUIRED_KEYS; do
        if ! grep -q "^${KEY}=" "$OBS_ENV" 2>/dev/null; then
            MISSING_KEYS="$MISSING_KEYS $KEY"
        fi
    done
    if [ -n "$MISSING_KEYS" ]; then
        log_warn "Faltan parámetros en observability/.env:$MISSING_KEYS"
        log_info "Añadiendo con valores por defecto..."
        for KEY in $MISSING_KEYS; do
            case $KEY in
                MONITOR_IP) echo "MONITOR_IP=$MONITOR_IP" >> "$OBS_ENV" ;;
                GF_ADMIN_USER) echo "GF_ADMIN_USER=admin" >> "$OBS_ENV" ;;
                GF_ADMIN_PASSWORD) echo "GF_ADMIN_PASSWORD=admin" >> "$OBS_ENV" ;;
                GF_HTTP_PORT) echo "GF_HTTP_PORT=3001" >> "$OBS_ENV" ;;
                PROMETHEUS_PORT) echo "PROMETHEUS_PORT=9090" >> "$OBS_ENV" ;;
                PROMETHEUS_RETENTION) echo "PROMETHEUS_RETENTION=15d" >> "$OBS_ENV" ;;
                LOKI_PORT) echo "LOKI_PORT=3100" >> "$OBS_ENV" ;;
                LOKI_RETENTION) echo "LOKI_RETENTION=168h" >> "$OBS_ENV" ;;
                TEMPO_HTTP_PORT) echo "TEMPO_HTTP_PORT=3200" >> "$OBS_ENV" ;;
                TEMPO_GRPC_PORT) echo "TEMPO_GRPC_PORT=4317" >> "$OBS_ENV" ;;
                DISCORD_WEBHOOK_URL) echo "DISCORD_WEBHOOK_URL=PENDIENTE" >> "$OBS_ENV" ;;
            esac
            log_info "Añadido: $KEY"
        done
    fi
fi

# Siempre cargar MONITOR_IP del .env existente
MONITOR_IP=$(grep "^MONITOR_IP=" "$OBS_ENV" | cut -d= -f2- | tr -d '\r')
if [ -z "$MONITOR_IP" ]; then
    MONITOR_IP=$(tailscale ip -4 2>/dev/null)
    echo "MONITOR_IP=$MONITOR_IP" >> "$OBS_ENV"
    log_info "MONITOR_IP añadido: $MONITOR_IP"
fi
export MONITOR_IP

# Asegurar que DNS tiene .env
cat > "$SCRIPT_DIR/monitor/dns/.env" << ENVEOF
MONITOR_IP=$MONITOR_IP
DNS_PORT=${DNS_PORT:-53}
DNS_WEB_PORT=${DNS_WEB_PORT:-2999}
DNS_PORT=${DNS_PORT:-53}
DNS_WEB_PORT=${DNS_WEB_PORT:-2999}
ENVEOF

# Asegurar que todos los .env tienen MONITOR_IP
for ENV_F in "$WAZ_ENV" "$HOME_ENV"; do
    if ! grep -q "^MONITOR_IP=" "$ENV_F" 2>/dev/null; then
        echo "MONITOR_IP=$MONITOR_IP" >> "$ENV_F"
    fi
done

# Wazuh .env
if [ ! -f "$WAZ_ENV" ]; then
    cat > "$WAZ_ENV" << ENVEOF
MONITOR_IP=$MONITOR_IP
INDEXER_PASSWORD=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 24)
INDEXER_JAVA_OPTS="-Xms512m -Xmx512m"
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 24)
DISCORD_WEBHOOK_URL=${DISCORD_URL:-PENDIENTE}
ENVEOF
    log_info "wazuh/.env creado"
else
    log_info "wazuh/.env ya existe"
fi

# Homepage .env
if [ ! -f "$HOME_ENV" ]; then
    cat > "$HOME_ENV" << ENVEOF
MONITOR_IP=$MONITOR_IP
HOMEPAGE_PORT=${HOMEPAGE_PORT:-8082}
GF_ADMIN_PASSWORD=$GF_PASS
GF_HTTP_PORT=${GF_HTTP_PORT:-3001}
PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}
DNS_WEB_PORT=${DNS_WEB_PORT:-2999}
WAZUH_DASHBOARD_PORT=${WAZUH_DASHBOARD_PORT:-5601}
GF_ADMIN_PASSWORD=$GF_PASS
DNS_WEB_PORT=${DNS_WEB_PORT:-2999}
GF_ADMIN_PASSWORD=$GF_PASS
ENVEOF
    log_info "homepage/.env creado"
else
    log_info "homepage/.env ya existe"
fi

# Crear .env para DNS
cat > "$SCRIPT_DIR/monitor/dns/.env" << ENVEOF
MONITOR_IP=$MONITOR_IP
DNS_PORT=${DNS_PORT:-53}
DNS_WEB_PORT=${DNS_WEB_PORT:-2999}
DNS_PORT=${DNS_PORT:-53}
DNS_WEB_PORT=${DNS_WEB_PORT:-2999}
ENVEOF
log_info "dns/.env creado"

# Exportar MONITOR_IP para todos los docker compose
export MONITOR_IP=$MONITOR_IP

# ============================================
# 3. DETECTAR MÁQUINAS DE PRODUCCIÓN
# ============================================

# Check mode — solo verificar estado
if [ "$CHECK_ONLY" = true ]; then
    log_section "MODO CHECK — Solo verificación"
    python3 "$SCRIPT_DIR/status.py"
    exit 0
fi

log_section "3/8 — Detectando máquinas de producción"

# Verificar/generar clave SSH
if [ ! -f "$HOME/.ssh/id_rsa" ] && [ ! -f "$HOME/.ssh/id_ed25519" ]; then
    log_info "Generando clave SSH..."
    ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N "" -q
    log_info "Clave SSH generada: $HOME/.ssh/id_ed25519"
else
    log_info "Clave SSH ya existe"
fi

log_ask "¿Cuántas máquinas de producción quieres monitorizar?: "
read -r PROD_COUNT

for i in $(seq 1 $PROD_COUNT); do
    echo ""
    log_ask "Máquina $i — Nombre (ej: servidor-web): "
    read -r NAME
    NAME=$(echo "$NAME" | tr '[:upper:]' '[:lower:]')
    log_ask "Máquina $i — IP de Tailscale: "
    read -r IP
    log_ask "Máquina $i — Puerto SSH [22]: "
    read -r PORT
    PORT=${PORT:-22}
    log_ask "Máquina $i — Usuario SSH [root]: "
    read -r USER
    USER=${USER:-root}

log_ask "Máquina $i — ¿Tiene PostgreSQL local para monitorizar? (s/n) [s]: "
    read -r HAS_PG
    HAS_PG=${HAS_PG:-s}
    if [ "$HAS_PG" = "s" ]; then
        log_ask "Máquina $i — Usuario PostgreSQL [postgres]: "
        read -r DB_USER_INPUT
        DB_USER_INPUT=${DB_USER_INPUT:-postgres}
        log_ask "Máquina $i — Contraseña PostgreSQL: "
        read -rs DB_PASS_INPUT
        echo ""
        log_ask "Máquina $i — Nombre de la base de datos [postgres]: "
        read -r DB_NAME_INPUT
        DB_NAME_INPUT=${DB_NAME_INPUT:-postgres}
        log_ask "Máquina $i — Host PostgreSQL (nombre del contenedor) [postgres]: "
        read -r DB_HOST_INPUT
        DB_HOST_INPUT=${DB_HOST_INPUT:-postgres}
        log_ask "Máquina $i — Puerto PostgreSQL [5432]: "
        read -r DB_PORT_INPUT
        DB_PORT_INPUT=${DB_PORT_INPUT:-5432}
    else
        DB_USER_INPUT=""
        DB_PASS_INPUT=""
        DB_NAME_INPUT=""
        DB_HOST_INPUT=""
        DB_PORT_INPUT=""
    fi

    PROD_HAS_PG+=("$HAS_PG")
    PROD_DB_USERS+=("$DB_USER_INPUT")
    PROD_DB_PASSES+=("$DB_PASS_INPUT")
    PROD_DB_NAMES+=("$DB_NAME_INPUT")
    PROD_DB_HOSTS+=("$DB_HOST_INPUT")
    PROD_DB_PORTS+=("$DB_PORT_INPUT")

    PROD_NAMES+=("$NAME")
    PROD_IPS+=("$IP")
    PROD_SSH_PORTS+=("$PORT")
    PROD_SSH_USERS+=("$USER")

    # Copiar clave SSH si es necesario
    if ! ssh -o ConnectTimeout=10 -o BatchMode=yes -p $PORT ${USER}@${IP} "echo ok" &>/dev/null; then
        log_warn "Se necesita configurar acceso SSH sin contraseña"
        log_info "Copiando clave SSH a $NAME (se pedirá contraseña una sola vez)..."
        SSH_KEY=$(ls "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub" 2>/dev/null | head -1)
        if [ -n "$SSH_KEY" ]; then
            ssh-copy-id -o StrictHostKeyChecking=accept-new -i "$SSH_KEY" -p $PORT ${USER}@${IP} 2>/dev/null
        fi
    fi

    # Test SSH con multiplexing
    SOCK_DIR=$(mktemp -d)
    SSH_CMD="ssh -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new -o ControlMaster=auto -o ControlPath=$SOCK_DIR/%r@%h:%p -o ControlPersist=300 -p $PORT ${USER}@${IP}"

    if $SSH_CMD -o BatchMode=yes "echo ok" &>/dev/null; then
        log_info "$NAME ($IP) → ${GREEN}SSH conectado${NC}"
        PROD_SSH_CMDS+=("$SSH_CMD")
    else
        log_warn "$NAME ($IP) → ${RED}SSH falló${NC} — se intentará después"
        PROD_SSH_CMDS+=("FAILED")
    fi
done

# ============================================
# 3b. VERIFICAR PUERTOS
# ============================================
log_section "3b/8 — Verificando puertos"

# Monitor (local)
python3 "$SCRIPT_DIR/scripts/check-ports.py" "monitor" "$MONITOR_NAME" "LOCAL"

# Producción (remoto)
for i in $(seq 0 $((PROD_COUNT - 1))); do
    NAME="${PROD_NAMES[$i]}"
    SSH="${PROD_SSH_CMDS[$i]}"
    [ "$SSH" = "FAILED" ] && continue
    python3 "$SCRIPT_DIR/scripts/check-ports.py" "agent" "$NAME" "$SSH"
done

# Leer puertos resueltos y guardar para cada máquina
for i in $(seq 0 $((PROD_COUNT - 1))); do
    NAME="${PROD_NAMES[$i]}"
    PORTS_FILE="/tmp/ports_${NAME}.json"
    if [ -f "$PORTS_FILE" ]; then
        PROD_NODE_PORT=$(python3 -c "import json; d=json.load(open('$PORTS_FILE')); print(d.get('Node Exporter', 9100))")
        PROD_CADV_PORT=$(python3 -c "import json; d=json.load(open('$PORTS_FILE')); print(d.get('Cadvisor', 8080))")
        PROD_PG_PORT=$(python3 -c "import json; d=json.load(open('$PORTS_FILE')); print(d.get('Postgres Exporter', 9187))")
        PROD_REDIS_PORT=$(python3 -c "import json; d=json.load(open('$PORTS_FILE')); print(d.get('Redis Exporter', 9121))")
        PROD_OTEL_PORT=$(python3 -c "import json; d=json.load(open('$PORTS_FILE')); print(d.get('OTEL Metrics', 8889))")
        # Guardar en arrays para usar en paso 5 y 6
        eval "PORTS_NODE_${i}=$PROD_NODE_PORT"
        eval "PORTS_CADV_${i}=$PROD_CADV_PORT"
        eval "PORTS_PG_${i}=$PROD_PG_PORT"
        eval "PORTS_REDIS_${i}=$PROD_REDIS_PORT"
        eval "PORTS_OTEL_${i}=$PROD_OTEL_PORT"
        log_info "$NAME puertos: node=$PROD_NODE_PORT cadvisor=$PROD_CADV_PORT pg=$PROD_PG_PORT redis=$PROD_REDIS_PORT otel=$PROD_OTEL_PORT"
    fi
done

# Aplicar puertos resueltos del monitor al .env
MONITOR_PORTS_FILE="/tmp/ports_${MONITOR_NAME}.json"
if [ -f "$MONITOR_PORTS_FILE" ]; then
    DNS_PORT=$(python3 -c "import json; d=json.load(open('$MONITOR_PORTS_FILE')); print(d.get('AdGuard DNS', 53))")
    DNS_WEB_PORT=$(python3 -c "import json; d=json.load(open('$MONITOR_PORTS_FILE')); print(d.get('AdGuard Web', 3000))")
    PROM_PORT=$(python3 -c "import json; d=json.load(open('$MONITOR_PORTS_FILE')); print(d.get('Prometheus', 9090))")
    LOKI_PORT=$(python3 -c "import json; d=json.load(open('$MONITOR_PORTS_FILE')); print(d.get('Loki', 3100))")
    TEMPO_HTTP_PORT=$(python3 -c "import json; d=json.load(open('$MONITOR_PORTS_FILE')); print(d.get('Tempo HTTP', 3200))")
    TEMPO_GRPC_PORT=$(python3 -c "import json; d=json.load(open('$MONITOR_PORTS_FILE')); print(d.get('Tempo gRPC', 4317))")
    GF_HTTP_PORT=$(python3 -c "import json; d=json.load(open('$MONITOR_PORTS_FILE')); print(d.get('Grafana', 3001))")
    HOMEPAGE_PORT=$(python3 -c "import json; d=json.load(open('$MONITOR_PORTS_FILE')); print(d.get('Homepage', 8082))")
    NODE_EXP_PORT=$(python3 -c "import json; d=json.load(open('$MONITOR_PORTS_FILE')); print(d.get('Node Exporter', 9100))")
    CADV_PORT=$(python3 -c "import json; d=json.load(open('$MONITOR_PORTS_FILE')); print(d.get('Cadvisor', 8080))")

    # Actualizar DNS .env
    cat > "$SCRIPT_DIR/monitor/dns/.env" << DNSEOF
MONITOR_IP=$MONITOR_IP
DNS_PORT=$DNS_PORT
DNS_WEB_PORT=$DNS_WEB_PORT
DNSEOF

    # Actualizar observability .env con puertos resueltos
    for KEY_VAL in "PROMETHEUS_PORT=$PROM_PORT" "LOKI_PORT=$LOKI_PORT" "TEMPO_HTTP_PORT=$TEMPO_HTTP_PORT" "TEMPO_GRPC_PORT=$TEMPO_GRPC_PORT" "GF_HTTP_PORT=$GF_HTTP_PORT"; do
        KEY=$(echo "$KEY_VAL" | cut -d= -f1)
        sed -i "/^${KEY}=/d" "$OBS_ENV"
        echo "$KEY_VAL" >> "$OBS_ENV"
    done

    # Actualizar homepage .env
    sed -i "/^HOMEPAGE_PORT=/d" "$HOME_ENV"
    echo "HOMEPAGE_PORT=$HOMEPAGE_PORT" >> "$HOME_ENV"

    # Exportar para docker compose
    export DNS_PORT DNS_WEB_PORT HOMEPAGE_PORT GF_HTTP_PORT

    log_info "Puertos del monitor aplicados a los .env"
fi

# Generar resolved.env — única fuente de verdad para IPs y puertos
RESOLVED_ENV="$SCRIPT_DIR/resolved.env"
MONITOR_PORTS="/tmp/ports_${MONITOR_NAME}.json"
{
    echo "# resolved.env — generado por setup.sh ($(date))"
    echo "MONITOR_IP=$MONITOR_IP"
    echo "MONITOR_NAME=${MONITOR_FRIENDLY:-$MONITOR_NAME}"
    if [ -f "$MONITOR_PORTS" ]; then
        echo "PROMETHEUS_PORT=$(python3 -c "import json; print(json.load(open('$MONITOR_PORTS')).get('Prometheus', 9090))")"
        echo "GF_HTTP_PORT=$(python3 -c "import json; print(json.load(open('$MONITOR_PORTS')).get('Grafana', 3001))")"
        echo "LOKI_PORT=$(python3 -c "import json; print(json.load(open('$MONITOR_PORTS')).get('Loki', 3100))")"
        echo "TEMPO_HTTP_PORT=$(python3 -c "import json; print(json.load(open('$MONITOR_PORTS')).get('Tempo HTTP', 3200))")"
        echo "HOMEPAGE_PORT=$(python3 -c "import json; print(json.load(open('$MONITOR_PORTS')).get('Homepage', 8082))")"
        echo "DNS_PORT=$(python3 -c "import json; print(json.load(open('$MONITOR_PORTS')).get('AdGuard DNS', 53))")"
        echo "DNS_WEB_PORT=$(python3 -c "import json; print(json.load(open('$MONITOR_PORTS')).get('AdGuard Web', 2999))")"
    fi
    echo "WAZUH_DASHBOARD_PORT=5601"
    echo "PROD_COUNT=$PROD_COUNT"
    for i in $(seq 0 $((PROD_COUNT - 1))); do
        eval "P_NODE=\$PORTS_NODE_${i}"; eval "P_CADV=\$PORTS_CADV_${i}"
        eval "P_PG=\$PORTS_PG_${i}"; eval "P_REDIS=\$PORTS_REDIS_${i}"
        echo "PROD_${i}_NAME=${PROD_NAMES[$i]}"
        echo "PROD_${i}_IP=${PROD_IPS[$i]}"
        echo "PROD_${i}_NODE_PORT=${P_NODE:-9100}"
        echo "PROD_${i}_CADV_PORT=${P_CADV:-8080}"
        echo "PROD_${i}_PG_PORT=${P_PG:-9187}"
        echo "PROD_${i}_REDIS_PORT=${P_REDIS:-9121}"
        echo "PROD_${i}_HAS_PG=${PROD_HAS_PG[$i]:-n}"
    done
} > "$RESOLVED_ENV"
source "$RESOLVED_ENV"
export DNS_PORT DNS_WEB_PORT GF_HTTP_PORT PROMETHEUS_PORT HOMEPAGE_PORT WAZUH_DASHBOARD_PORT
log_info "resolved.env generado"

# ============================================
# 4. LEVANTAR MONITOR (DNS + Observabilidad + Wazuh + Homepage)
# ============================================
log_section "4/8 — Levantando servicios del monitor"

# 4a. DNS
if [ -f "$SCRIPT_DIR/monitor/dns/docker-compose.yml" ]; then
    cd "$SCRIPT_DIR/monitor/dns"
    docker compose up -d
    sleep 5
    log_info "DNS levantado"
fi

# 4b. Observabilidad
cd "$SCRIPT_DIR/monitor/observability"
docker compose up -d
log_info "Esperando healthchecks (40s)..."
sleep 40

ALL_HEALTHY=true
for SVC in soc-prometheus soc-loki soc-tempo soc-grafana; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' $SVC 2>/dev/null || echo "sin-health")
    if [ "$STATUS" = "healthy" ]; then
        log_info "$SVC → healthy"
    else
        log_warn "$SVC → $STATUS"
        ALL_HEALTHY=false
    fi
done

# Resetear contraseña de Grafana
GF_PASS=$(grep GF_ADMIN_PASSWORD "$OBS_ENV" | cut -d= -f2- | tr -d '\r')
docker exec soc-grafana grafana-cli admin reset-admin-password "$GF_PASS" > /dev/null 2>&1 || true
log_info "Contraseña de Grafana actualizada"

# 4c. Wazuh
cd "$SCRIPT_DIR/monitor/wazuh"

# Certificados
CERTS_DIR="$SCRIPT_DIR/monitor/wazuh/certs"
if [ -f "$CERTS_DIR/root-ca.pem" ] && [ -f "$CERTS_DIR/wazuh.indexer.pem" ]; then
    log_info "Certificados Wazuh ya existen"
else
    log_info "Generando certificados Wazuh..."
    mkdir -p "$CERTS_DIR"
    [ ! -f "$CERTS_DIR/config.yml" ] && cat > "$CERTS_DIR/config.yml" << 'CERTEOF'
nodes:
  indexer:
    - name: wazuh.indexer
      ip: "127.0.0.1"
  server:
    - name: wazuh.manager
      ip: "127.0.0.1"
  dashboard:
    - name: wazuh.dashboard
      ip: "127.0.0.1"
CERTEOF
    cd "$CERTS_DIR"
    curl -sO https://packages.wazuh.com/4.14/wazuh-certs-tool.sh
    bash wazuh-certs-tool.sh -A
    mv wazuh-certificates/* . 2>/dev/null || true
    rmdir wazuh-certificates 2>/dev/null || true
    rm -f wazuh-certs-tool.sh
    chmod 644 *.pem
    cd "$SCRIPT_DIR/monitor/wazuh"
    log_info "Certificados generados"
fi

# Levantar Indexer
log_info "Levantando Wazuh Indexer..."
docker compose up -d wazuh.indexer
log_info "Esperando al Indexer (90s)..."
sleep 90

# Inicializar seguridad
INDEXER_PASSWORD=$(grep INDEXER_PASSWORD "$WAZ_ENV" | cut -d= -f2- | tr -d '\r')
SECURITY_CHECK=$(curl -sku admin:${INDEXER_PASSWORD} https://localhost:9200/.opendistro_security 2>/dev/null | grep -c "opendistro_security" || true)

if [ "$SECURITY_CHECK" -gt 0 ]; then
    log_info "Seguridad ya inicializada"
else
    log_info "Inicializando seguridad..."
    docker exec -u 0 soc-wazuh-indexer bash -c "
        chmod +x /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh && \
        export JAVA_HOME=/usr/share/wazuh-indexer/jdk && \
        /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
          -cd /usr/share/wazuh-indexer/config/opensearch-security/ -nhnv \
          -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
          -cert /usr/share/wazuh-indexer/config/certs/admin.pem \
          -key /usr/share/wazuh-indexer/config/certs/admin-key.pem \
          -icl -h localhost
    " 2>&1 | tail -3
    log_info "Seguridad inicializada"
    # Fix filebeat password para enviar alertas al indexer
    docker exec -u 0 soc-wazuh-manager bash -c "sed -i 's|#password:.*|password: \"admin\"|' /etc/filebeat/filebeat.yml" 2>/dev/null || true
    docker exec -u 0 soc-wazuh-manager bash -c "kill \$(pgrep filebeat) 2>/dev/null; sleep 2; nohup /usr/share/filebeat/bin/filebeat -c /etc/filebeat/filebeat.yml >/dev/null 2>&1 &" 2>/dev/null || true
    log_info "Filebeat configurado"
fi

# Levantar Manager y Dashboard
log_info "Levantando Manager y Dashboard..."
docker compose up -d
log_info "Esperando healthchecks (120s)..."
sleep 120

for SVC in soc-wazuh-indexer soc-wazuh-manager soc-wazuh-dashboard; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' $SVC 2>/dev/null || echo "sin-health")
    if [ "$STATUS" = "healthy" ]; then
        log_info "$SVC → healthy"
    else
        log_warn "$SVC → $STATUS"
    fi
done

# 4d. Homepage
cd "$SCRIPT_DIR/monitor/homepage"
docker compose up -d
sleep 10
log_info "Homepage levantado"

# 4e. Trivy
if [ -f "$SCRIPT_DIR/monitor/trivy/docker-compose.yml" ]; then
    cd "$SCRIPT_DIR/monitor/trivy"
    docker compose up -d
    sleep 5
    log_info "Trivy scanner levantado"
    CRON_LINE="0 3 * * 0 $SCRIPT_DIR/scripts/trivy-scan.sh >> /var/log/trivy-scan.log 2>&1"
    if ! crontab -l 2>/dev/null | grep -q "trivy-scan"; then
        (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
        log_info "Cron semanal de Trivy configurado (domingos 3:00)"
    else
        log_info "Cron de Trivy ya configurado"
    fi
fi

# ============================================
# 5. INSTALAR AGENTS REMOTAMENTE
# ============================================
log_section "5/8 — Instalando agents en servidores de producción"

PROM_TARGETS=""

for i in $(seq 0 $((PROD_COUNT - 1))); do
    NAME="${PROD_NAMES[$i]}"
    IP="${PROD_IPS[$i]}"
    SSH="${PROD_SSH_CMDS[$i]}"

    echo ""
    log_info "Desplegando en ${BOLD}$NAME${NC} ($IP)..."

   # Mostrar info del sistema remoto
    REMOTE_INFO=$($SSH "echo OS=\$(. /etc/os-release && echo \$PRETTY_NAME) && echo CPU=\$(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs) \(\$(nproc) cores\) && echo RAM=\$(free -h | awk '/^Mem:/{print \$2}') && echo DISK=\$(df -h / | awk 'NR==2{print \$2}') && echo GPU=\$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || echo No detectada) && echo DOCKER=\$(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',')" 2>/dev/null)

    if [ -n "$REMOTE_INFO" ]; then
        R_OS=$(echo "$REMOTE_INFO" | grep "^OS=" | cut -d= -f2-)
        R_CPU=$(echo "$REMOTE_INFO" | grep "^CPU=" | cut -d= -f2-)
        R_RAM=$(echo "$REMOTE_INFO" | grep "^RAM=" | cut -d= -f2-)
        R_DISK=$(echo "$REMOTE_INFO" | grep "^DISK=" | cut -d= -f2-)
        R_GPU=$(echo "$REMOTE_INFO" | grep "^GPU=" | cut -d= -f2-)
        R_DOCKER=$(echo "$REMOTE_INFO" | grep "^DOCKER=" | cut -d= -f2-)

        echo -e "  ${BOLD}Software:${NC}"
        echo -e "    OS:      $R_OS"
        echo -e "    Docker:  v$R_DOCKER"
        echo -e "  ${BOLD}Hardware:${NC}"
        echo -e "    CPU:     $R_CPU"
        echo -e "    RAM:     $R_RAM"
        echo -e "    Disco:   $R_DISK"
        echo -e "    GPU:     $R_GPU"
        echo ""
    fi

    if [ "$SSH" = "FAILED" ]; then
        log_warn "SSH no disponible para $NAME — saltando"
        continue
    fi

    # Crear directorio remoto
    $SSH "mkdir -p ~/socials-monitoring" 2>/dev/null

    # Copiar archivos
    SCP_OPTS="-o ControlPath=$(echo $SSH | grep -oP 'ControlPath=\K[^ ]+')" 2>/dev/null || SCP_OPTS=""
    SCP_PORT="${PROD_SSH_PORTS[$i]}"
    SCP_USER="${PROD_SSH_USERS[$i]}"
    scp -P $SCP_PORT -o ConnectTimeout=30 \
        "$SCRIPT_DIR/agent/docker-compose.yml" \
        "$SCRIPT_DIR/agent/otel-collector-config.yaml" \
        "$SCRIPT_DIR/agent/install.sh" \
        ${SCP_USER}@${IP}:~/socials-monitoring/ 2>/dev/null

    if [ $? -eq 0 ]; then
        log_info "Archivos copiados"
    else
        log_warn "Error copiando archivos — intentando método alternativo..."
        # Copiar via SSH cat
        for FILE in docker-compose.yml otel-collector-config.yaml install.sh; do
            $SSH "cat > ~/socials-monitoring/$FILE" < "$SCRIPT_DIR/agent/$FILE" 2>/dev/null
        done
        $SSH "chmod +x ~/socials-monitoring/install.sh"
        log_info "Archivos copiados (método alternativo)"
    fi

# Actualizar .env remoto con puertos resueltos
    eval "P_NODE=\$PORTS_NODE_${i}"
    eval "P_CADV=\$PORTS_CADV_${i}"
    eval "P_PG=\$PORTS_PG_${i}"
    eval "P_REDIS=\$PORTS_REDIS_${i}"
    eval "P_OTEL=\$PORTS_OTEL_${i}"

    $SSH "cat > ~/socials-monitoring/.env.ports << PORTSEOF
NODE_EXPORTER_PORT=${P_NODE:-9100}
CADVISOR_PORT=${P_CADV:-8080}
PG_EXPORTER_PORT=${P_PG:-9187}
REDIS_EXPORTER_PORT=${P_REDIS:-9121}
OTEL_METRICS_PORT=${P_OTEL:-8889}
PORTSEOF
" 2>/dev/null

# Añadir configuración de DB si tiene PostgreSQL
    if [ "${PROD_HAS_PG[$i]}" = "s" ]; then
        $SSH "cat >> ~/socials-monitoring/.env.ports << DBEOF
DB_USER=${PROD_DB_USERS[$i]}
DB_PASSWORD=${PROD_DB_PASSES[$i]}
DB_NAME=${PROD_DB_NAMES[$i]}
DB_HOST=${PROD_DB_HOSTS[$i]}
DB_PORT=${PROD_DB_PORTS[$i]}
DBEOF
" 2>/dev/null
    fi

    # Merge puertos resueltos en .env
    $SSH "if [ -f ~/socials-monitoring/.env.ports ]; then
        if [ -f ~/socials-monitoring/.env ]; then
            while IFS= read -r line; do
                KEY=\$(echo \"\$line\" | cut -d= -f1)
                sed -i \"/^\$KEY=/d\" ~/socials-monitoring/.env
                echo \"\$line\" >> ~/socials-monitoring/.env
            done < ~/socials-monitoring/.env.ports
        else
            cp ~/socials-monitoring/.env.ports ~/socials-monitoring/.env
        fi
        rm -f ~/socials-monitoring/.env.ports
    fi" 2>/dev/null

    log_info "Ejecutando instalación..."
    $SSH "cd ~/socials-monitoring && chmod +x install.sh && ./install.sh $MONITOR_IP" 2>&1 | while read -r line; do
        echo "  [$NAME] $line"
    done

# Construir targets de Prometheus con puertos resueltos
    eval "P_NODE=\$PORTS_NODE_${i}"
    eval "P_CADV=\$PORTS_CADV_${i}"
    eval "P_PG=\$PORTS_PG_${i}"
    eval "P_REDIS=\$PORTS_REDIS_${i}"

    PROM_TARGETS+="
  - job_name: \"${NAME}_node\"
    static_configs:
      - targets: [\"${IP}:${P_NODE:-9100}\"]
        labels:
          instance: \"${NAME}\"
          layer: \"infrastructure\"

  - job_name: \"${NAME}_containers\"
    static_configs:
      - targets: [\"${IP}:${P_CADV:-8080}\"]
        labels:
          instance: \"${NAME}\"
          layer: \"containers\"

  - job_name: \"${NAME}_postgres\"
    static_configs:
      - targets: [\"${IP}:${P_PG:-9187}\"]
        labels:
          instance: \"${NAME}\"
          layer: \"database\"

  - job_name: \"${NAME}_redis\"
    static_configs:
      - targets: [\"${IP}:${P_REDIS:-9121}\"]
        labels:
          instance: \"${NAME}\"
          layer: \"cache\"
"
done

# Guardar inventario de máquinas para otros scripts
INVENTORY_FILE="$SCRIPT_DIR/inventory.json"
python3 -c "
import json
machines = []
machines.append({'name': '$MONITOR_NAME', 'ip': '$MONITOR_IP', 'role': 'monitor', 'ssh': 'LOCAL'})
$(for i in $(seq 0 $((PROD_COUNT - 1))); do
    echo "machines.append({'name': '${PROD_NAMES[$i]}', 'ip': '${PROD_IPS[$i]}', 'role': 'production', 'ssh': 'ssh -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new -p ${PROD_SSH_PORTS[$i]} ${PROD_SSH_USERS[$i]}@${PROD_IPS[$i]}'})"
done)
with open('$INVENTORY_FILE', 'w') as f:
    json.dump(machines, f, indent=2)
"
log_info "Inventario guardado en inventory.json"

# ============================================
# 6. ACTUALIZAR PROMETHEUS CON TARGETS
# ============================================
log_section "6/8 — Actualizando Prometheus"

cat > "$SCRIPT_DIR/monitor/observability/prometheus/prometheus.yml" << PROMEOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: "prometheus_self"
    static_configs:
      - targets: ["localhost:9090"]
        labels:
          instance: "$MONITOR_NAME"

  - job_name: "monitor_node"
    static_configs:
      - targets: ["soc-node-exporter:9100"]
        labels:
          instance: "$MONITOR_NAME"
          layer: "infrastructure"

  - job_name: "monitor_containers"
    static_configs:
      - targets: ["soc-cadvisor:8080"]
        labels:
          instance: "$MONITOR_NAME"
          layer: "containers"

  - job_name: "tempo_metrics"
    static_configs:
      - targets: ["tempo:3200"]
        labels:
          instance: "$MONITOR_NAME"
          layer: "traces"
$PROM_TARGETS
PROMEOF

# Reiniciar Prometheus para cargar nuevos targets
docker restart soc-prometheus > /dev/null 2>&1
sleep 10
log_info "Prometheus actualizado con $(echo "$PROM_TARGETS" | grep -c 'job_name') targets de producción"

# ============================================
# 7. CREAR DASHBOARD Y ALERTAS
# ============================================
log_section "7/8 — Configurando Grafana (dashboard + alertas)"

cd "$SCRIPT_DIR"
TAILSCALE_IP_ULT=$(grep MONITOR_IP "$OBS_ENV" | cut -d= -f2- | tr -d '\r')
GF_HTTP_PORT=$(grep GF_HTTP_PORT "$OBS_ENV" | cut -d= -f2- | tr -d '\r')
export GF_URL="http://${TAILSCALE_IP_ULT}:${GF_HTTP_PORT}"
export GF_USER=$(grep GF_ADMIN_USER "$OBS_ENV" | cut -d= -f2- | tr -d '\r')
export GF_PASS=$(grep GF_ADMIN_PASSWORD "$OBS_ENV" | cut -d= -f2- | tr -d '\r')
export DISCORD_URL=$(grep DISCORD_WEBHOOK_URL "$OBS_ENV" | cut -d= -f2- | tr -d '\r')

# Esperar a Grafana
for i in $(seq 1 10); do
    if curl -s "$GF_URL/api/health" -u "$GF_USER:$GF_PASS" 2>/dev/null | grep -q "ok"; then
        break
    fi
    sleep 3
done

# Dashboard + Alertas via Python
python3 "$SCRIPT_DIR/scripts/create-dashboard.py"

python3 << 'PYEOF'
import os, json, urllib.request, urllib.error, base64

gf_url = os.environ["GF_URL"]
gf_user = os.environ["GF_USER"]
gf_pass = os.environ["GF_PASS"]
discord_url = os.environ.get("DISCORD_URL", "")

auth = base64.b64encode(f"{gf_user}:{gf_pass}".encode()).decode()
headers = {"Content-Type": "application/json", "Authorization": f"Basic {auth}"}

def api(url, payload=None, method="POST"):
    data = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        res = urllib.request.urlopen(req)
        return res.getcode(), json.loads(res.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except:
        return 500, {}

def api_get(url):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        res = urllib.request.urlopen(req)
        return res.getcode(), json.loads(res.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except:
        return 500, {}

# Carpeta de alertas (idempotente)
code, _ = api_get(f"{gf_url}/api/folders/soc-alerts")
if code != 200:
    api(f"{gf_url}/api/folders", {"uid": "soc-alerts", "title": "SOC Alerts"})
    print("[✓] Carpeta SOC Alerts creada")
else:
    print("[✓] Carpeta SOC Alerts ya existe")

# Discord (idempotente — verificar si ya existe)
if discord_url and discord_url != "PENDIENTE":
    code, points = api_get(f"{gf_url}/api/v1/provisioning/contact-points")
    discord_exists = False
    if code == 200 and isinstance(points, list):
        discord_exists = any(p.get("name") == "Discord SOC" for p in points)

    if discord_exists:
        print("[✓] Discord SOC ya configurado")
    else:
        api(f"{gf_url}/api/v1/provisioning/contact-points",
            {"name": "Discord SOC", "type": "discord", "settings": {"url": discord_url}})
        print("[✓] Discord SOC creado")

    # Policy siempre se actualiza (es PUT, idempotente por naturaleza)
    api(f"{gf_url}/api/v1/provisioning/policies",
        {"receiver": "Discord SOC", "group_by": ["alertname","severity"],
         "group_wait": "30s", "group_interval": "5m", "repeat_interval": "4h"}, method="PUT")
else:
    print("[!] Discord webhook no configurado")

# Alertas (idempotente — verificar existentes por título)
code, existing_alerts = api_get(f"{gf_url}/api/v1/provisioning/alert-rules")
existing_titles = set()
if code == 200 and isinstance(existing_alerts, list):
    existing_titles = {a.get("title", "") for a in existing_alerts}

alerts = [
    {"title":"CRITICAL - Contenedor reiniciandose","group":"containers","severity":"critical","for":"2m",
     "expr":"rate(container_restart_count{name=~\"socials-.*\"}[5m]) > 0","condition":"gt","threshold":0},
    {"title":"CRITICAL - API SOCials CAIDA","group":"containers","severity":"critical","for":"30s",
     "expr":"probe_success{job=~\".*_api\"}","condition":"lt","threshold":1,"noData":"Alerting"},
    {"title":"HIGH - GPU Temperatura > 85C","group":"gpu","severity":"high","for":"2m",
     "expr":"DCGM_FI_DEV_GPU_TEMP","condition":"gt","threshold":85},
    {"title":"HIGH - GPU Utilization > 95%","group":"gpu","severity":"high","for":"5m",
     "expr":"DCGM_FI_DEV_GPU_UTIL","condition":"gt","threshold":95},
    {"title":"HIGH - GPU Memoria > 90%","group":"gpu","severity":"high","for":"5m",
     "expr":"DCGM_FI_DEV_FB_USED / (DCGM_FI_DEV_FB_USED + DCGM_FI_DEV_FB_FREE) * 100","condition":"gt","threshold":90},
    {"title":"HIGH - CPU > 90%","group":"infrastructure","severity":"high","for":"5m",
     "expr":"100 - (avg by(instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)","condition":"gt","threshold":90},
    {"title":"HIGH - RAM > 90%","group":"infrastructure","severity":"high","for":"5m",
     "expr":"(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100","condition":"gt","threshold":90},
    {"title":"HIGH - Disco > 85%","group":"infrastructure","severity":"high","for":"5m",
     "expr":"(1 - (node_filesystem_avail_bytes{mountpoint=\"/\",fstype!=\"tmpfs\"} / node_filesystem_size_bytes{mountpoint=\"/\",fstype!=\"tmpfs\"})) * 100","condition":"gt","threshold":85},
    {"title":"HIGH - Redis > 512MB","group":"services","severity":"high","for":"5m",
     "expr":"redis_memory_used_bytes","condition":"gt","threshold":536870912},
    {"title":"HIGH - PostgreSQL conexiones > 80%","group":"services","severity":"high","for":"5m",
     "expr":"sum(pg_stat_activity_count) / pg_settings_max_connections * 100","condition":"gt","threshold":80}
]

created = 0
skipped = 0
for a in alerts:
    if a["title"] in existing_titles:
        skipped += 1
        continue
    payload = {
        "title": a["title"], "ruleGroup": a["group"], "folderUID": "soc-alerts",
        "condition": "C", "noDataState": a.get("noData", "OK"), "execErrState": "Alerting", "for": a["for"],
        "data": [
            {"refId": "A", "datasourceUid": "prometheus", "model": {"expr": a["expr"], "refId": "A"}, "relativeTimeRange": {"from": 600, "to": 0}},
            {"refId": "B", "datasourceUid": "__expr__", "model": {"type": "reduce", "expression": "A", "reducer": "last", "refId": "B"}, "relativeTimeRange": {"from": 600, "to": 0}},
            {"refId": "C", "datasourceUid": "__expr__", "model": {"type": "threshold", "expression": "B", "conditions": [{"evaluator": {"type": a["condition"], "params": [a["threshold"]]}}], "refId": "C"}, "relativeTimeRange": {"from": 600, "to": 0}}
        ],
        "labels": {"severity": a["severity"]}
    }
    code, _ = api(f"{gf_url}/api/v1/provisioning/alert-rules", payload)
    if code in [200, 201]:
        created += 1

print(f"[✓] Alertas: {created} creadas, {skipped} ya existían")
PYEOF

log_info "Grafana configurado"

# ============================================
# 8. RESUMEN FINAL
# ============================================
log_section "8/8 — DESPLIEGUE COMPLETADO"

echo ""
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E "soc-|socials-dns" || true
echo ""

echo -e "  ${BOLD}═══════════════════════════════════════${NC}"
echo -e "  ${BOLD}  ACCESOS (solo VPN)${NC}"
echo -e "  ${BOLD}═══════════════════════════════════════${NC}"
echo -e "  Homepage:        http://$MONITOR_IP:8082"
echo -e "  Grafana:         http://$MONITOR_IP:${GRAFANA_PORT:-3001}"
echo -e "  Wazuh Dashboard: https://$MONITOR_IP:5601"
echo -e "  Prometheus:      http://$MONITOR_IP:9090"
echo -e "  AdGuard DNS:     http://$MONITOR_IP:${DNS_WEB_PORT:-2999}"
echo ""
echo -e "  ${BOLD}═══════════════════════════════════════${NC}"
echo -e "  ${BOLD}  CREDENCIALES${NC}"
echo -e "  ${BOLD}═══════════════════════════════════════${NC}"
echo -e "  Grafana:     ${GF_USER:-admin} / $GF_PASS"
echo -e "  Wazuh:       admin / admin"
echo -e "  AdGuard:     (configurar en primer acceso)"
echo ""
echo -e "  ${RED}${BOLD}⚠  SEGURIDAD: Cambia TODAS las contraseñas por defecto${NC}"
echo -e "  ${RED}  antes de exponer estos servicios. Las credenciales${NC}"
echo -e "  ${RED}  por defecto son un riesgo de seguridad conocido.${NC}"
echo -e "  ${RED}  Especialmente: Wazuh (admin/admin) y AdGuard.${NC}"
echo ""
echo -e "  ${BOLD}═══════════════════════════════════════${NC}"
echo -e "  ${BOLD}  MÁQUINAS MONITORIZADAS${NC}"
echo -e "  ${BOLD}═══════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}${BOLD}Monitor: $MONITOR_NAME ($MONITOR_IP)${NC}"
echo -e "    OS:      $MONITOR_OS"
echo -e "    Docker:  v$MONITOR_DOCKER"
echo -e "    CPU:     $MONITOR_CPU"
echo -e "    RAM:     $MONITOR_RAM"
echo -e "    Disco:   $MONITOR_DISK"
echo -e "    GPU:     ${MONITOR_GPU:-No detectada}"
echo ""
for i in $(seq 0 $((PROD_COUNT - 1))); do
    echo -e "  ${GREEN}${BOLD}Producción: ${PROD_NAMES[$i]} (${PROD_IPS[$i]})${NC}"
    SSH="${PROD_SSH_CMDS[$i]}"
    if [ "$SSH" != "FAILED" ]; then
        R_OS=$($SSH ". /etc/os-release && echo \$PRETTY_NAME" 2>/dev/null)
        R_CPU=$($SSH "grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs" 2>/dev/null)
        R_CORES=$($SSH "nproc" 2>/dev/null)
        R_RAM=$($SSH "free -h | awk '/^Mem:/{print \$2}'" 2>/dev/null)
        R_DISK=$($SSH "df -h / | awk 'NR==2{print \$2}'" 2>/dev/null)
        R_GPU=$($SSH "nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || echo No detectada" 2>/dev/null)
        R_DOCKER=$($SSH "docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ','" 2>/dev/null)
        echo -e "    OS:      ${R_OS:-Desconocido}"
        echo -e "    Docker:  v${R_DOCKER:-?}"
        echo -e "    CPU:     ${R_CPU:-?} (${R_CORES:-?} cores)"
        echo -e "    RAM:     ${R_RAM:-?}"
        echo -e "    Disco:   ${R_DISK:-?}"
        echo -e "    GPU:     ${R_GPU:-No detectada}"
    else
        echo -e "    ${YELLOW}(SSH no disponible)${NC}"
    fi
    echo ""
done
echo ""
echo -e "  ${BOLD}HERRAMIENTAS:${NC}"
echo -e "  python3 alerts.py list       — Ver alertas"
echo -e "  python3 alerts.py create     — Crear alerta"
echo -e "  python3 alerts.py delete     — Eliminar alerta"
echo -e "  python3 alerts.py test       — Test Discord"
echo -e ""
echo -e "  python3 machines.py list     — Ver máquinas registradas"
echo -e "  python3 machines.py add      — Añadir nueva máquina"
echo -e "  python3 machines.py remove   — Eliminar máquina"
echo -e "  python3 machines.py deploy X — Desplegar agents en máquina X"
echo -e ""
echo -e "  bash scripts/trivy-scan.sh   — Escaneo de vulnerabilidades"
echo ""
echo -e "  python3 deploy.py generate   — Regenerar configs desde inventario"
echo -e "  python3 deploy.py diff       — Ver diferencias con configs actuales"
echo ""
