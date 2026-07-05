#!/bin/bash
# ============================================
# Agent Install — Runs on each production server
# ============================================
# Called remotely by the monitor host.
# Installs node-exporter, cadvisor, postgres-exporter (if PG present),
# redis-exporter (if Redis present), an OTEL collector, the NVIDIA DCGM
# exporter (if a GPU is detected) and optionally the Wazuh agent.
#
# Usage: ./install.sh <MONITOR_VPN_IP>

set -e
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

INSTALL_DIR="$HOME/socials-monitoring"
MONITOR_IP="${1:-}"
HOSTNAME=$(hostname)

if [ -z "$MONITOR_IP" ]; then
    log_error "Usage: ./install.sh <MONITOR_VPN_IP>"
    exit 1
fi

# Tailscale is the assumed VPN mesh. Replace with your own VPN bootstrap if needed.
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
if [ -z "$TAILSCALE_IP" ]; then
    log_error "Tailscale is not installed or not connected"
    exit 1
fi

log_info "Installing agent on $HOSTNAME ($TAILSCALE_IP)"
log_info "Monitor: $MONITOR_IP"

# ============================================
# 1. CONFIGURE .ENV
# ============================================
log_info "Writing .env..."

if [ -f "$INSTALL_DIR/.env" ]; then
    if grep -q "^TAILSCALE_IP=" "$INSTALL_DIR/.env"; then
        sed -i "s|^TAILSCALE_IP=.*|TAILSCALE_IP=$TAILSCALE_IP|" "$INSTALL_DIR/.env"
    else
        echo "TAILSCALE_IP=$TAILSCALE_IP" >> "$INSTALL_DIR/.env"
    fi
    if grep -q "^MONITOR_IP=" "$INSTALL_DIR/.env"; then
        sed -i "s|^MONITOR_IP=.*|MONITOR_IP=$MONITOR_IP|" "$INSTALL_DIR/.env"
    else
        echo "MONITOR_IP=$MONITOR_IP" >> "$INSTALL_DIR/.env"
    fi
    log_info ".env updated with TAILSCALE_IP=$TAILSCALE_IP"
else
    cat > "$INSTALL_DIR/.env" << ENVEOF
TAILSCALE_IP=$TAILSCALE_IP
MONITOR_IP=$MONITOR_IP
NODE_EXPORTER_PORT=9100
CADVISOR_PORT=8080
PG_EXPORTER_PORT=9187
REDIS_EXPORTER_PORT=9121
OTEL_METRICS_PORT=8889
REDIS_HOST=redis
REDIS_PORT=6379
ENVEOF
    log_info ".env created"
fi

source "$INSTALL_DIR/.env" 2>/dev/null || true

# ============================================
# 2. CONFIGURE OTEL COLLECTOR
# ============================================
log_info "Configuring OTEL Collector..."
sed -i "s/PLACEHOLDER_MONITOR_IP/$MONITOR_IP/g" "$INSTALL_DIR/otel-collector-config.yaml" 2>/dev/null || true
sed -i "s/PLACEHOLDER_HOSTNAME/$HOSTNAME/g" "$INSTALL_DIR/otel-collector-config.yaml" 2>/dev/null || true

# ============================================
# 3. ENSURE DOCKER NETWORK
# ============================================
if $SUDO docker network inspect socials-network >/dev/null 2>&1; then
    log_info "Network socials-network already exists"
else
    log_warn "Network socials-network missing — creating..."
    $SUDO docker network create socials-network
fi

# ============================================
# 4. DETECT EXISTING SERVICES
# ============================================

OTEL_EXISTS=false
if $SUDO docker ps --format '{{.Names}}' | grep -q "socials-otel-collector"; then
    log_info "OTEL Collector already running — skipping duplicate"
    OTEL_EXISTS=true
fi

HAS_PG=false
if grep -q "^DB_USER=" "$INSTALL_DIR/.env" 2>/dev/null && grep -q "^DB_PASSWORD=" "$INSTALL_DIR/.env" 2>/dev/null; then
    DB_PASS_VAL=$(grep "^DB_PASSWORD=" "$INSTALL_DIR/.env" | cut -d= -f2-)
    if [ -n "$DB_PASS_VAL" ] && [ "$DB_PASS_VAL" != "CHANGE_ME_DB_PASSWORD" ]; then
        HAS_PG=true
    fi
fi

HAS_REDIS=false
if $SUDO docker ps --format '{{.Names}}' | grep -qi "redis"; then
    HAS_REDIS=true
fi

# ============================================
# 5. BRING UP EXPORTERS (selectively)
# ============================================
log_info "Starting exporters..."
cd "$INSTALL_DIR"

SERVICES="node-exporter cadvisor"

if [ "$HAS_PG" = true ]; then
    SERVICES="$SERVICES postgres-exporter"
    log_info "PostgreSQL detected — including postgres-exporter"
else
    log_info "No PostgreSQL — postgres-exporter skipped"
fi

if [ "$HAS_REDIS" = true ]; then
    SERVICES="$SERVICES redis-exporter"
    log_info "Redis detected — including redis-exporter"
else
    log_info "No Redis — redis-exporter skipped"
fi

if [ "$OTEL_EXISTS" = false ]; then
    SERVICES="$SERVICES otel-collector"
    log_info "OTEL Collector will be deployed"
else
    log_info "OTEL Collector already running — skipping"
fi

$SUDO docker compose up -d $SERVICES 2>&1 || true
sleep 15

for SVC_NAME in node-exporter cadvisor; do
    CONTAINER="socials-${SVC_NAME}"
    if $SUDO docker ps --format '{{.Names}}' | grep -q "$CONTAINER"; then
        log_info "$CONTAINER -> running"
    else
        log_warn "$CONTAINER -> failed to start"
    fi
done

if [ "$HAS_PG" = true ]; then
    if $SUDO docker ps --format '{{.Names}}' | grep -q "socials-postgres-exporter"; then
        log_info "socials-postgres-exporter -> running"
        # Optional: attach to a co-located DB network if you run Supabase
        if $SUDO docker network inspect supabase_default >/dev/null 2>&1; then
            $SUDO docker network connect supabase_default socials-postgres-exporter 2>/dev/null || true
            $SUDO docker restart socials-postgres-exporter 2>/dev/null || true
            log_info "postgres-exporter attached to supabase_default"
        fi
    else
        log_warn "socials-postgres-exporter -> failed to start"
    fi
fi

if [ "$HAS_REDIS" = true ]; then
    if $SUDO docker ps --format '{{.Names}}' | grep -q "socials-redis-exporter"; then
        log_info "socials-redis-exporter -> running"
    else
        log_warn "socials-redis-exporter -> failed to start"
    fi
fi

# ============================================
# 6. GPU EXPORTER (if NVIDIA GPU present)
# ============================================
if command -v nvidia-smi &>/dev/null; then
    log_info "NVIDIA GPU detected — installing DCGM exporter"
    GPU_PORT=${GPU_EXPORTER_PORT:-9400}

    $SUDO docker stop socials-nvidia-exporter 2>/dev/null || true
    $SUDO docker rm socials-nvidia-exporter 2>/dev/null || true

    $SUDO docker run -d \
        --name socials-nvidia-exporter \
        --restart unless-stopped \
        --gpus all \
        --network socials-monitoring-net \
        -p "${TAILSCALE_IP}:${GPU_PORT}:9400" \
        nvidia/dcgm-exporter:3.3.5-3.4.0-ubuntu22.04 2>&1 || true

    sleep 10
    if $SUDO docker ps --format '{{.Names}}' | grep -q "socials-nvidia-exporter"; then
        log_info "GPU Exporter -> running on :$GPU_PORT"
    else
        log_warn "GPU Exporter failed — check NVIDIA drivers / docker runtime"
    fi

    if ! grep -q "GPU_EXPORTER_PORT" "$INSTALL_DIR/.env"; then
        echo "GPU_EXPORTER_PORT=$GPU_PORT" >> "$INSTALL_DIR/.env"
    fi
else
    log_info "No NVIDIA GPU — DCGM exporter skipped"
fi

# ============================================
# 7. WAZUH AGENT (optional)
# ============================================
if command -v /var/ossec/bin/wazuh-control &>/dev/null; then
    log_info "Wazuh agent already installed"
else
    log_info "Installing Wazuh agent..."
    if [ -f /etc/debian_version ]; then
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | $SUDO gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null
        $SUDO chmod 644 /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | $SUDO tee /etc/apt/sources.list.d/wazuh.list
        $SUDO apt-get update -qq
        $SUDO WAZUH_MANAGER="$MONITOR_IP" apt-get install -y wazuh-agent 2>&1 | tail -5
    else
        log_error "Only Debian / Ubuntu are currently supported for the Wazuh step"
    fi
fi

OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
    CURRENT=$($SUDO grep -oP '<address>\K[^<]+' "$OSSEC_CONF" 2>/dev/null || echo "")
    if [ "$CURRENT" != "$MONITOR_IP" ]; then
        $SUDO sed -i "s|<address>.*</address>|<address>$MONITOR_IP</address>|" "$OSSEC_CONF"
        log_info "Wazuh agent pointed at $MONITOR_IP"
    fi
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable wazuh-agent
    $SUDO systemctl restart wazuh-agent
    sleep 10
    if $SUDO systemctl is-active --quiet wazuh-agent; then
        log_info "Wazuh agent active"
    else
        log_warn "Wazuh agent failed to start"
    fi
fi

# ============================================
# SUMMARY
# ============================================
echo ""
NODE_PORT=${NODE_EXPORTER_PORT:-9100}
CADV_PORT=${CADVISOR_PORT:-8080}
PG_PORT=${PG_EXPORTER_PORT:-9187}
REDIS_PORT_VAL=${REDIS_EXPORTER_PORT:-9121}
OTEL_PORT=${OTEL_METRICS_PORT:-8889}

echo -e "${GREEN}Install complete on $HOSTNAME${NC}"
echo -e "  Node Exporter:     $TAILSCALE_IP:$NODE_PORT"
echo -e "  cAdvisor:          $TAILSCALE_IP:$CADV_PORT"
[ "$HAS_PG" = true ] && echo -e "  Postgres Exporter: $TAILSCALE_IP:$PG_PORT"
[ "$HAS_REDIS" = true ] && echo -e "  Redis Exporter:    $TAILSCALE_IP:$REDIS_PORT_VAL"
[ "$OTEL_EXISTS" = false ] && echo -e "  OTEL Collector:    $TAILSCALE_IP:$OTEL_PORT"
command -v nvidia-smi &>/dev/null && echo -e "  GPU Exporter:      $TAILSCALE_IP:${GPU_EXPORTER_PORT:-9400}"
echo -e "  Wazuh Agent:       $($SUDO systemctl is-active wazuh-agent 2>/dev/null || echo 'not installed')"
echo ""
