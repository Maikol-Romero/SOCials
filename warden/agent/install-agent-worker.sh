#!/bin/bash
# install-agent-worker.sh — companion installer for machines that run a
# your-app docker-compose alongside socialwarden-agent.
# ─────────────────────────────────────────────────────────────────────────
# Sets up the boot ordering: socialwarden-agent renders age-encrypted secrets
# bundles into /run/secrets/<bundle>.env, then docker compose up reads them
# via env_file. A systemd oneshot (agent-app.service by default) wires
# the two together with proper After/Wants/Requires.
#
# What it does (idempotent):
#   1. Pre-flight: socialwarden-agent installed + bundle present
#   2. Docker Engine + docker compose plugin (apt or convenience script)
#   3. Adds <user> to the docker group
#   4. App dir + compose.yaml install (preserves existing if --keep-compose)
#   5. systemd unit (agent-app.service) with correct ordering
#   6. systemctl daemon-reload + enable + (optional) start
#
# Usage:
#   sudo bash install-agent-worker.sh \
#       --bundle <name>           Required: bundle name (renders to /run/secrets/<name>.env)
#       --compose <path>          Required (first run): compose.yaml to install
#       [--user <name>]           User who'll own /home/<user>/agent/ (default: ubuntu)
#       [--app-dir <path>]        Override (default: /home/<user>/agent)
#       [--service-name <name>]   Systemd unit name (default: agent-app)
#       [--keep-compose]          Don't overwrite /<app-dir>/compose.yaml
#       [--no-start]              Install + enable but don't start
#       [--no-restart]            If service exists and active, don't restart
#       [--dry-run]               Report what would happen, change nothing
#       [--force]                 Reinstall even if same compose hash present

set -euo pipefail

# --- Colors -----------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*" >&2; }
step()  { echo -e "\n${BLUE}=== $* ===${NC}"; }

# --- Args -------------------------------------------------------------------
BUNDLE=""
COMPOSE_SRC=""
APP_USER="ubuntu"
APP_DIR=""
SERVICE_NAME="agent-app"
KEEP_COMPOSE=0
NO_START=0
NO_RESTART=0
DRY_RUN=0
FORCE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --bundle)        BUNDLE="$2"; shift 2 ;;
        --compose)       COMPOSE_SRC="$2"; shift 2 ;;
        --user)          APP_USER="$2"; shift 2 ;;
        --app-dir)       APP_DIR="$2"; shift 2 ;;
        --service-name)  SERVICE_NAME="$2"; shift 2 ;;
        --keep-compose)  KEEP_COMPOSE=1; shift ;;
        --no-start)      NO_START=1; shift ;;
        --no-restart)    NO_RESTART=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        --force)         FORCE=1; shift ;;
        -h|--help)
            sed -n '3,30p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) err "Unknown arg: $1"; exit 2 ;;
    esac
done

# --- Validation -------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    err "Must run as root. Try: sudo bash install-agent-worker.sh ..."
    exit 1
fi

if [ -z "$BUNDLE" ]; then
    err "Missing --bundle <name>"
    exit 2
fi
# Bundle name regex (filename-safe)
case "$BUNDLE" in
    *[!a-zA-Z0-9._-]* | "" )
        err "Invalid bundle name: '$BUNDLE'. Allowed: [a-zA-Z0-9._-]"
        exit 2
        ;;
esac
case "$APP_USER" in
    *[!a-zA-Z0-9._-]* | "" )
        err "Invalid user: '$APP_USER'"
        exit 2
        ;;
esac
case "$SERVICE_NAME" in
    *[!a-zA-Z0-9._-]* | "" )
        err "Invalid service name: '$SERVICE_NAME'"
        exit 2
        ;;
esac

# Resolve user home
if ! id "$APP_USER" >/dev/null 2>&1; then
    err "User '$APP_USER' does not exist on this machine"
    exit 2
fi
USER_HOME=$(getent passwd "$APP_USER" | cut -d: -f6)
if [ -z "$USER_HOME" ] || [ ! -d "$USER_HOME" ]; then
    err "Could not resolve home dir for '$APP_USER'"
    exit 2
fi

# Default app-dir
if [ -z "$APP_DIR" ]; then
    APP_DIR="$USER_HOME/agent"
fi

BUNDLE_PATH="/run/secrets/${BUNDLE}.env"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
STAMP=$(date -u +%Y%m%dT%H%M%S)

# --- Pre-flight: socialwarden-agent installed + bundle resolvable -------------
step "Pre-flight checks"

if ! command -v socialwarden-agent >/dev/null 2>&1; then
    err "socialwarden-agent not installed. Run socialwarden-agent installer first."
    exit 3
fi
info "socialwarden-agent CLI present"

DGW_VERSION=$(grep -m1 '^VERSION\s*=' /opt/socialwarden-agent/socialwarden-agent.py 2>/dev/null \
    | sed -E 's/^VERSION\s*=\s*["'\''"]([^"'\''"]+).*/\1/' || echo "?")
info "socialwarden-agent version: ${DGW_VERSION}"

if ! systemctl is-active --quiet socialwarden-agent 2>/dev/null; then
    warn "socialwarden-agent service is NOT active. Starting it before continuing."
    systemctl start socialwarden-agent
    sleep 2
    if ! systemctl is-active --quiet socialwarden-agent; then
        err "Could not start socialwarden-agent. Fix that first, then re-run."
        exit 3
    fi
fi
info "socialwarden-agent service active"

# Try to render the bundle now so /run/secrets/<bundle>.env exists. If the
# bundle isn't on disk yet, this is non-fatal — operator may push the bundle
# after this script via `socialwarden-manager bundle-push`. The systemd unit's
# ExecStartPre will wait for it on first boot.
if /usr/local/bin/socialwarden-agent render "$BUNDLE" >/dev/null 2>&1; then
    info "Bundle '$BUNDLE' rendered → $BUNDLE_PATH"
else
    warn "Bundle '$BUNDLE' did not render now. /var/lib/socialwarden/bundles/${BUNDLE}.age may be missing."
    warn "Push it with: socialwarden-manager bundle-push <machine> $BUNDLE --env-file <path>"
    warn "Continuing — the systemd unit will retry render on first boot."
fi

# --- Dry-run summary --------------------------------------------------------
if [ $DRY_RUN -eq 1 ]; then
    step "DRY RUN — would do"
    echo "  - Ensure docker engine + compose plugin"
    echo "  - Add user '$APP_USER' to docker group"
    echo "  - mkdir -p $APP_DIR (owner $APP_USER)"
    if [ -n "$COMPOSE_SRC" ] && [ $KEEP_COMPOSE -eq 0 ]; then
        echo "  - Install compose: $COMPOSE_SRC → $APP_DIR/compose.yaml"
    fi
    echo "  - Write systemd unit: $SERVICE_PATH"
    echo "  - systemctl daemon-reload && systemctl enable $SERVICE_NAME"
    [ $NO_START -eq 0 ] && echo "  - systemctl start $SERVICE_NAME"
    exit 0
fi

# --- Docker Engine + compose plugin ----------------------------------------
step "Docker Engine + compose plugin"

if ! command -v docker >/dev/null 2>&1; then
    info "docker not present. Installing via official convenience script."
    if ! curl -fsSL https://get.docker.com | sh; then
        err "docker install failed. Install manually then re-run."
        exit 4
    fi
fi
info "docker: $(docker --version 2>&1 | head -1)"

if ! docker compose version >/dev/null 2>&1; then
    info "docker-compose-plugin not present. Installing."
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-plugin; then
        err "docker-compose-plugin install failed."
        exit 4
    fi
fi
info "docker compose: $(docker compose version 2>&1 | head -1)"

systemctl enable --now docker.service >/dev/null 2>&1 || true
info "docker.service enabled"

# --- User in docker group --------------------------------------------------
step "Add $APP_USER to docker group"
if id -nG "$APP_USER" | tr ' ' '\n' | grep -qx docker; then
    info "$APP_USER already in docker group"
else
    usermod -aG docker "$APP_USER"
    info "Added $APP_USER to docker group (requires re-login to take effect for interactive shells)"
fi

# --- App dir ----------------------------------------------------------------
step "App directory: $APP_DIR"
if [ ! -d "$APP_DIR" ]; then
    install -d -m 755 -o "$APP_USER" -g "$APP_USER" "$APP_DIR"
    info "Created $APP_DIR (owner $APP_USER)"
else
    info "$APP_DIR already exists"
fi

# --- compose.yaml install (or preserve) -------------------------------------
COMPOSE_DEST="$APP_DIR/compose.yaml"
if [ -n "$COMPOSE_SRC" ]; then
    if [ ! -f "$COMPOSE_SRC" ]; then
        err "Compose source not found: $COMPOSE_SRC"
        exit 5
    fi
    if [ -f "$COMPOSE_DEST" ] && [ $KEEP_COMPOSE -eq 1 ]; then
        info "--keep-compose set; leaving existing $COMPOSE_DEST untouched"
    elif [ -f "$COMPOSE_DEST" ] && [ $FORCE -eq 0 ]; then
        SRC_HASH=$(sha256sum "$COMPOSE_SRC"  | cut -d' ' -f1)
        DST_HASH=$(sha256sum "$COMPOSE_DEST" | cut -d' ' -f1)
        if [ "$SRC_HASH" = "$DST_HASH" ]; then
            info "compose.yaml unchanged (sha256 match)"
        else
            cp -p "$COMPOSE_DEST" "$COMPOSE_DEST.bak-$STAMP"
            install -m 644 -o "$APP_USER" -g "$APP_USER" "$COMPOSE_SRC" "$COMPOSE_DEST"
            info "Updated compose.yaml (backup: $COMPOSE_DEST.bak-$STAMP)"
        fi
    else
        install -m 644 -o "$APP_USER" -g "$APP_USER" "$COMPOSE_SRC" "$COMPOSE_DEST"
        info "Installed compose.yaml from $COMPOSE_SRC"
    fi
elif [ ! -f "$COMPOSE_DEST" ]; then
    err "No compose.yaml at $COMPOSE_DEST and --compose not provided."
    err "Either run with --compose <path>, or manually drop a compose.yaml at $COMPOSE_DEST."
    exit 5
fi

# Validate compose can parse (catches obvious errors before service starts)
if [ -f "$COMPOSE_DEST" ]; then
    if (cd "$APP_DIR" && docker compose config --quiet) 2>/dev/null; then
        info "compose.yaml validates"
    else
        warn "compose.yaml fails docker compose config — service will fail at start. Inspect:"
        warn "  cd $APP_DIR && docker compose config"
    fi
fi

# --- systemd unit -----------------------------------------------------------
step "systemd unit: $SERVICE_NAME.service"

NEW_UNIT=$(cat <<EOF
[Unit]
Description=tu fleet agent worker (docker compose up) — installed by install-agent-worker.sh
Documentation=https://github.com/your-org/your-infra-ops
After=socialwarden-agent.service docker.service network-online.target
Requires=docker.service
Wants=socialwarden-agent.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$APP_DIR

# Render any pending bundles → /run/secrets/<name>.env (idempotent, no-op if no bundles)
ExecStartPre=/bin/sh -c '/usr/local/bin/socialwarden-agent render-all || true'

# Wait briefly for /run/secrets/$BUNDLE.env to appear after render-all
ExecStartPre=/bin/sh -c 'for i in 1 2 3 4 5 6 7 8 9 10; do [ -f $BUNDLE_PATH ] && exit 0; sleep 1; done; echo "missing $BUNDLE_PATH after 10s" >&2; exit 1'

ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down

TimeoutStartSec=180
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF
)

if [ -f "$SERVICE_PATH" ]; then
    EXISTING_HASH=$(sha256sum "$SERVICE_PATH" | cut -d' ' -f1)
    # Match the trailing newline that `printf '%s\n' "$NEW_UNIT"` writes,
    # otherwise the hashes never match and we re-write on every run.
    NEW_HASH=$(printf '%s\n' "$NEW_UNIT" | sha256sum | cut -d' ' -f1)
    if [ "$EXISTING_HASH" = "$NEW_HASH" ] && [ $FORCE -eq 0 ]; then
        info "Unit file unchanged (sha256 match)"
    else
        cp -p "$SERVICE_PATH" "$SERVICE_PATH.bak-$STAMP"
        printf '%s\n' "$NEW_UNIT" > "$SERVICE_PATH"
        chmod 644 "$SERVICE_PATH"
        info "Updated unit (backup: $SERVICE_PATH.bak-$STAMP)"
    fi
else
    printf '%s\n' "$NEW_UNIT" > "$SERVICE_PATH"
    chmod 644 "$SERVICE_PATH"
    info "Installed new unit at $SERVICE_PATH"
fi

# --- daemon-reload + enable + start -----------------------------------------
step "systemctl reload + enable"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME.service" >/dev/null 2>&1 || true
info "$SERVICE_NAME enabled"

if [ $NO_START -eq 1 ]; then
    warn "--no-start: not starting now. Manual: sudo systemctl start $SERVICE_NAME"
elif systemctl is-active --quiet "$SERVICE_NAME"; then
    if [ $NO_RESTART -eq 1 ]; then
        info "$SERVICE_NAME already active (--no-restart)"
    else
        step "Restart $SERVICE_NAME"
        systemctl restart "$SERVICE_NAME"
        info "$SERVICE_NAME restarted"
    fi
else
    step "Start $SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    info "$SERVICE_NAME started"
fi

# Wait briefly for compose to settle
if [ $NO_START -eq 0 ]; then
    sleep 3
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        info "Service active"
        # Container summary
        if cd "$APP_DIR" && docker compose ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null; then
            true
        fi
    else
        err "$SERVICE_NAME failed to activate. Diagnose with:"
        err "  sudo systemctl status $SERVICE_NAME"
        err "  sudo journalctl -u $SERVICE_NAME -n 50 --no-pager"
        exit 6
    fi
fi

# --- Summary ---------------------------------------------------------------
step "Done"
echo -e "  ${BOLD}Service:${NC}      $SERVICE_NAME ($SERVICE_PATH)"
echo -e "  ${BOLD}App dir:${NC}      $APP_DIR (owner $APP_USER)"
echo -e "  ${BOLD}Compose:${NC}      $COMPOSE_DEST"
echo -e "  ${BOLD}Bundle:${NC}       $BUNDLE → $BUNDLE_PATH"
echo -e "  ${BOLD}Boot order:${NC}   socialwarden-agent.service → $SERVICE_NAME.service → docker compose up"
echo ""
info "Worker installation complete"
