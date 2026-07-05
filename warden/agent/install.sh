#!/bin/bash
# socialwarden-agent installer — client-side
#
# Installs just the files a CLIENT machine needs:
#   /opt/socialwarden-agent/socialwarden-agent.py   — daemon
#   /opt/socialwarden-agent/hot_env.py            — Python library
#   /opt/socialwarden-agent/VERSION               — version stamp
#   /usr/local/bin/socialwarden-agent             — operator CLI
#   /etc/systemd/system/socialwarden-agent.service
#   /etc/socialwarden/config.yaml                 — (preserves existing, or warns)
#
# Idempotent. Timestamped backups of anything it overwrites.
# Migrates from old /opt/socialwarden/ layout if present.
#
# Usage:
#   Local:  sudo bash install.sh [--config <path>]
#   Remote: run socialwarden-enroll from the manager host.
#
# Options:
#   --config <path>   Path to a config.yaml to install (default: keep existing)
#   --dry-run         Print what would happen, don't change anything
#   --no-restart      Install files but don't restart systemd (for chained enroll)
#   --force           Overwrite even if agent is healthy with same version

set -euo pipefail

# --- Colors -----------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*" >&2; }
step()  { echo -e "\n${BLUE}=== $* ===${NC}"; }

# --- Args -------------------------------------------------------------------
CONFIG_SRC=""
DRY_RUN=0
NO_RESTART=0
FORCE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --config)     CONFIG_SRC="$2"; shift 2 ;;
        --dry-run)    DRY_RUN=1; shift ;;
        --no-restart) NO_RESTART=1; shift ;;
        --force)      FORCE=1; shift ;;
        -h|--help)
            sed -n '3,25p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) err "Unknown arg: $1"; exit 2 ;;
    esac
done

# --- Safety checks ----------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    err "Must run as root. Try: sudo bash install.sh"
    exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
for f in socialwarden-agent.py socialwarden-agent hot_env.py socialwarden-agent.service VERSION shamir.py; do
    if [ ! -f "$SRC_DIR/$f" ]; then
        err "Missing source file: $SRC_DIR/$f"
        exit 1
    fi
done

NEW_VERSION=$(cat "$SRC_DIR/VERSION" | tr -d '[:space:]')
STAMP=$(date -u +%Y%m%dT%H%M%S)

# --- Detect existing install ------------------------------------------------
step "Detect existing install"

OLD_LAYOUT_PRESENT=0
NEW_LAYOUT_PRESENT=0
[ -f /opt/socialwarden/socialwarden-agent.py ] && OLD_LAYOUT_PRESENT=1
[ -f /opt/socialwarden-agent/socialwarden-agent.py ] && NEW_LAYOUT_PRESENT=1

CURRENT_VERSION=""
if [ $NEW_LAYOUT_PRESENT -eq 1 ]; then
    CURRENT_VERSION=$(grep -m1 '^VERSION\s*=' /opt/socialwarden-agent/socialwarden-agent.py | sed -E 's/^VERSION\s*=\s*["'\''"]([^"'\''"]+).*/\1/' || echo "?")
    info "New layout present at /opt/socialwarden-agent/ (v${CURRENT_VERSION})"
elif [ $OLD_LAYOUT_PRESENT -eq 1 ]; then
    CURRENT_VERSION=$(grep -m1 '^VERSION\s*=' /opt/socialwarden/socialwarden-agent.py | sed -E 's/^VERSION\s*=\s*["'\''"]([^"'\''"]+).*/\1/' || echo "?")
    warn "Old layout at /opt/socialwarden/ (v${CURRENT_VERSION}) — will migrate to new /opt/socialwarden-agent/"
else
    info "No previous install detected"
fi

if [ -n "$CURRENT_VERSION" ] && [ "$CURRENT_VERSION" = "$NEW_VERSION" ] && [ $FORCE -eq 0 ]; then
    info "Agent already at v${NEW_VERSION}. Nothing to do. Use --force to reinstall."
    exit 0
fi

# --- Dry run ----------------------------------------------------------------
if [ $DRY_RUN -eq 1 ]; then
    warn "DRY RUN — would perform:"
    echo "  - Create /opt/socialwarden-agent/, /etc/socialwarden/, /run/socialwarden/, /var/lib/socialwarden/"
    echo "  - Backup existing files to /opt/socialwarden-agent/backups-${STAMP}/"
    echo "  - Install: agent.py, hot_env.py, CLI, systemd unit, VERSION"
    [ -n "$CONFIG_SRC" ] && echo "  - Install config from $CONFIG_SRC"
    echo "  - systemctl daemon-reload"
    [ $NO_RESTART -eq 0 ] && echo "  - systemctl restart socialwarden-agent"
    exit 0
fi

# --- Create directories -----------------------------------------------------
step "Create directories"
install -d -m 755 /opt/socialwarden-agent
install -d -m 755 /etc/socialwarden
# tmpfs /run is volatile; the service unit recreates it. These dirs are
# not sensitive themselves; the files inside are.
install -d -m 755 /run/socialwarden
# /run/secrets is where per-collection merged env files are written. Mode
# 0700 keeps them unreadable by non-root; Docker bind-mounts specific files
# into containers, so this dir itself doesn't need wider perms.
# Service unit has ExecStartPre that re-creates this after reboot too.
install -d -m 700 /run/secrets
install -d -m 700 /var/lib/socialwarden
install -d -m 700 /var/lib/socialwarden/versions
# Bundle drop-zone for `socialwarden-manager bundle-push` (encrypted age files)
install -d -m 700 /var/lib/socialwarden/bundles
info "Dirs ready"

# --- Install age + ensure age keypair (for bundle-push / render) ------------
step "Ensure age binary + age keypair"
if ! command -v age >/dev/null 2>&1; then
    info "age not present, installing via apt"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq age >/dev/null 2>&1 || {
        warn "apt-get install age failed — bundle-push/render will be unavailable until installed manually"
    }
fi
if command -v age-keygen >/dev/null 2>&1; then
    if [ ! -s /var/lib/socialwarden/age.key ]; then
        # No private key yet — generate one. age-keygen prints pubkey to stderr;
        # we re-derive it from the file with -y for the .pub artifact.
        age-keygen -o /var/lib/socialwarden/age.key >/dev/null 2>&1
        chmod 600 /var/lib/socialwarden/age.key
        chown root:root /var/lib/socialwarden/age.key
        info "Generated /var/lib/socialwarden/age.key (X25519, mode 600 root)"
    fi
    if [ -s /var/lib/socialwarden/age.key ]; then
        age-keygen -y /var/lib/socialwarden/age.key > /var/lib/socialwarden/age.pub
        chmod 644 /var/lib/socialwarden/age.pub
        info "age pubkey: $(cat /var/lib/socialwarden/age.pub)"
    fi
else
    warn "age-keygen unavailable — skipping keypair generation"
fi

# --- Install bw CLI as native binary (NOT snap — snap version conflicts with
#     systemd hardening: NoNewPrivileges + apparmor → "Operation not permitted"
#     when bw tries to switch profiles. Native binary works clean.) ------------
step "Ensure bw CLI (native binary)"
BW_INSTALLED=0
if [ -x /usr/local/bin/bw ]; then
    # Check it's not the snap shim
    if readlink /usr/local/bin/bw 2>/dev/null | grep -q "/snap/"; then
        warn "Existing /usr/local/bin/bw points to snap — replacing with native"
        rm -f /usr/local/bin/bw
    else
        BW_VER=$(/usr/local/bin/bw --version 2>/dev/null | head -1)
        info "Existing native bw: ${BW_VER:-unknown}"
        BW_INSTALLED=1
    fi
fi
if [ $BW_INSTALLED -eq 0 ]; then
    # Need unzip to extract the bw release. Fail loudly if we can't get it —
    # silent failure here used to leave the agent with no bw and no diagnostic.
    if ! command -v unzip >/dev/null 2>&1; then
        info "Installing unzip (required for bw extraction)..."
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip; then
            err "apt-get install unzip failed — cannot install bw automatically."
            err "Install unzip manually (apt install unzip) and re-run the installer."
            exit 6
        fi
        if ! command -v unzip >/dev/null 2>&1; then
            err "unzip still not on PATH after apt install — aborting bw install."
            exit 6
        fi
    fi
    BW_VER_TARGET="2026.3.0"
    BW_TMP="/tmp/bw-install-$$"
    mkdir -p "$BW_TMP"
    BW_URL="https://github.com/bitwarden/clients/releases/download/cli-v${BW_VER_TARGET}/bw-oss-linux-${BW_VER_TARGET}.zip"
    if curl -fsSL --retry 3 -o "$BW_TMP/bw.zip" "$BW_URL" 2>/dev/null && \
       unzip -q -o "$BW_TMP/bw.zip" -d "$BW_TMP" 2>/dev/null && \
       [ -f "$BW_TMP/bw" ]; then
        # Atomic swap: stage in /usr/local/bin (same fs, mv is rename(2)) then
        # mv. Avoids ETXTBSY if the running agent has /usr/local/bin/bw exec'd
        # mid-call (install -m, by contrast, opens the dest file for writing
        # and would race).
        STAGE="/usr/local/bin/bw.new-${STAMP}"
        chown root:root "$BW_TMP/bw"
        chmod 755 "$BW_TMP/bw"
        cp -p "$BW_TMP/bw" "$STAGE"
        mv -f "$STAGE" /usr/local/bin/bw
        info "Installed bw v${BW_VER_TARGET} → /usr/local/bin/bw (atomic rename)"
    else
        warn "Failed to download/extract bw v${BW_VER_TARGET} — vault sync will be unavailable"
        warn "Install manually: https://bitwarden.com/help/cli/"
    fi
    rm -rf "$BW_TMP"
fi

# --- Default /etc/socialwarden/config.yaml (idempotent) -----------------------
# Without a config the daemon refuses to start. We seed a minimal one whose
# `machine.name` is taken from the hostname so it matches the inventory entry.
# Operators can edit later (e.g. add Vault collections), but the agent will
# at least come up healthy on a fresh install.
step "Ensure /etc/socialwarden/config.yaml (default seed)"
if [ ! -f /etc/socialwarden/config.yaml ]; then
    MACHINE_NAME="${SOCIALWARDEN_MACHINE_NAME:-$(hostname)}"
    cat > /etc/socialwarden/config.yaml <<YAML
# SocialWarden Agent Configuration — ${MACHINE_NAME}
# Auto-generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Edit \`sync.collections\` to subscribe this machine to Vaultwarden collections.
# For machines that only use the bundle-push flow, leave collections empty.

server:
  url: "https://vault.example.com"
  poll_interval: 60
  max_retries: 5

machine:
  name: "${MACHINE_NAME}"

auth:
  email: "contact@example.com"
  master_key_path: "/var/lib/socialwarden/master.key"

organization:
  id: "<YOUR_VAULTWARDEN_ORG_UUID>"

sync:
  collections: []

alerts:
  secret_age_threshold_days: 90
  drift_auto_correct: false
YAML
    chmod 600 /etc/socialwarden/config.yaml
    chown root:root /etc/socialwarden/config.yaml
    info "Seeded default config (machine.name=${MACHINE_NAME})"
else
    info "Config already present — leaving alone"
fi

# --- Backup anything we'll overwrite ----------------------------------------
step "Backup existing files"
BACKUP_DIR="/opt/socialwarden-agent/backups-${STAMP}"
install -d -m 700 "$BACKUP_DIR"

backup_if_exists() {
    local f="$1"
    if [ -e "$f" ]; then
        cp -a "$f" "$BACKUP_DIR/$(basename "$f")"
    fi
}

# From new layout (if upgrading in place)
backup_if_exists /opt/socialwarden-agent/socialwarden-agent.py
backup_if_exists /opt/socialwarden-agent/hot_env.py
backup_if_exists /opt/socialwarden-agent/VERSION
# From old layout (if migrating)
backup_if_exists /opt/socialwarden/socialwarden-agent.py
backup_if_exists /opt/socialwarden/hot_env.py
# Shared locations
backup_if_exists /usr/local/bin/socialwarden-agent
backup_if_exists /etc/systemd/system/socialwarden-agent.service
backup_if_exists /etc/socialwarden/config.yaml

chmod -R go= "$BACKUP_DIR"
info "Backup: $BACKUP_DIR"

# --- Install files ----------------------------------------------------------
step "Install files (v${NEW_VERSION})"

install -m 644 -o root -g root "$SRC_DIR/socialwarden-agent.py" /opt/socialwarden-agent/socialwarden-agent.py
install -m 644 -o root -g root "$SRC_DIR/hot_env.py"           /opt/socialwarden-agent/hot_env.py
install -m 644 -o root -g root "$SRC_DIR/shamir.py"            /opt/socialwarden-agent/shamir.py
install -m 644 -o root -g root "$SRC_DIR/VERSION"              /opt/socialwarden-agent/VERSION
install -m 755 -o root -g root "$SRC_DIR/socialwarden-agent"     /usr/local/bin/socialwarden-agent
install -m 644 -o root -g root "$SRC_DIR/socialwarden-agent.service" /etc/systemd/system/socialwarden-agent.service

# Config handling: if --config given, install it. Otherwise preserve existing
# or warn if absent.
if [ -n "$CONFIG_SRC" ]; then
    if [ ! -f "$CONFIG_SRC" ]; then
        err "Config source not found: $CONFIG_SRC"
        exit 1
    fi
    install -m 600 -o root -g root "$CONFIG_SRC" /etc/socialwarden/config.yaml
    info "Installed config from $CONFIG_SRC"
elif [ -f /etc/socialwarden/config.yaml ]; then
    chmod 600 /etc/socialwarden/config.yaml
    info "Preserved existing /etc/socialwarden/config.yaml"

    # Resilience upgrade: if the config points master_key_path at tmpfs
    # (/run/socialwarden/master.key), migrate it to persistent storage
    # (/var/lib/socialwarden/master.key). This survives reboots without
    # human intervention, and does NOT weaken security because the key is
    # encrypted with a machine-id-derived key (machine-id is on disk too).
    if grep -qE '^\s*master_key_path:\s*"?/run/socialwarden/master\.key"?' /etc/socialwarden/config.yaml; then
        info "Migrating master_key_path: /run/socialwarden/ → /var/lib/socialwarden/ (reboot-resilient)"
        # Pre-validate BACKUP_DIR exists and is writable before sed-i runs.
        # Without this, a transient backup-dir failure would leave .bak alongside
        # the live config and the next install would error on existing .bak.
        if [ ! -d "$BACKUP_DIR" ] || [ ! -w "$BACKUP_DIR" ]; then
            err "BACKUP_DIR ($BACKUP_DIR) missing or not writable — refusing migration"
            exit 7
        fi
        sed -i.bak-master-migration \
            -E 's|(^\s*master_key_path:\s*"?)/run/socialwarden/master\.key("?.*)|\1/var/lib/socialwarden/master.key\2|' \
            /etc/socialwarden/config.yaml
        if ! mv /etc/socialwarden/config.yaml.bak-master-migration "$BACKUP_DIR/config.yaml.pre-master-migration"; then
            warn "Backup mv failed — leaving .bak-master-migration in place for operator review"
        fi
        # If the master key currently lives in tmpfs, copy to persistent.
        # The agent will also do this on first read (belt + suspenders).
        if [ -f /run/socialwarden/master.key ] && [ ! -f /var/lib/socialwarden/master.key ]; then
            install -m 600 -o root -g root /run/socialwarden/master.key /var/lib/socialwarden/master.key
            info "Copied master.key to /var/lib/socialwarden/ (kept /run/ copy for safety)"
        fi
    fi
else
    warn "No /etc/socialwarden/config.yaml present. Agent will fail to start until you create one."
fi

info "Files installed"

# --- Sanity: python syntax --------------------------------------------------
step "Python syntax validation"
if python3 -c "import ast; ast.parse(open('/opt/socialwarden-agent/socialwarden-agent.py').read())" 2>/dev/null; then
    info "agent.py syntax OK"
else
    err "agent.py syntax check FAILED — not restarting service"
    err "Rollback: cp $BACKUP_DIR/* /opt/socialwarden-agent/ && systemctl restart socialwarden-agent"
    exit 4
fi

# --- Migrate from old /opt/socialwarden/ if present ---------------------------
if [ $OLD_LAYOUT_PRESENT -eq 1 ] && [ ! -L /opt/socialwarden ]; then
    step "Migrate from old /opt/socialwarden/ layout"
    # Do NOT delete the old dir — leave as fallback for 24h or until operator confirms.
    # Mark it so operator knows it's deprecated.
    if [ ! -f /opt/socialwarden/.DEPRECATED ]; then
        echo "Deprecated as of $STAMP — migrated to /opt/socialwarden-agent/" > /opt/socialwarden/.DEPRECATED
        info "Old /opt/socialwarden/ kept as fallback (mark: .DEPRECATED). Remove manually after validation."
    fi
fi

# --- Reload systemd ---------------------------------------------------------
step "systemd reload"
systemctl daemon-reload
info "daemon-reload done"

if [ $NO_RESTART -eq 1 ]; then
    warn "Skipping restart (--no-restart). Run manually: sudo systemctl restart socialwarden-agent"
else
    if systemctl is-enabled socialwarden-agent >/dev/null 2>&1; then
        step "Restart socialwarden-agent"
        systemctl restart socialwarden-agent
        # Wait up to 15s for fresh heartbeat (indicator of successful sync)
        info "Waiting up to 15s for post-restart heartbeat..."
        for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
            if [ -f /run/socialwarden/heartbeat ]; then
                hb=$(cat /run/socialwarden/heartbeat 2>/dev/null || echo "")
                if [ -n "$hb" ]; then
                    # Check mtime freshness
                    if [ $(stat -c "%Y" /run/socialwarden/heartbeat 2>/dev/null || echo 0) -gt $(date -d "10 seconds ago" +%s) ]; then
                        info "Heartbeat fresh: $hb"
                        break
                    fi
                fi
            fi
            sleep 1
        done
        if ! systemctl is-active --quiet socialwarden-agent; then
            err "Service failed to activate. See: journalctl -u socialwarden-agent -n 50"
            exit 5
        fi
        info "Service active"
    else
        step "Enable + start socialwarden-agent"
        systemctl enable --now socialwarden-agent
        info "Service enabled and started"
    fi
fi

# --- Post-install summary ---------------------------------------------------
step "Done"
echo -e "  ${BOLD}Version:${NC}  $NEW_VERSION"
echo -e "  ${BOLD}Agent dir:${NC}   /opt/socialwarden-agent/"
echo -e "  ${BOLD}Config:${NC}     /etc/socialwarden/config.yaml"
echo -e "  ${BOLD}Backup:${NC}     $BACKUP_DIR"
echo -e "  ${BOLD}CLI:${NC}        socialwarden-agent status | doctor | discover"
echo ""
info "Installation complete"
