#!/bin/bash
# install-watcher.sh — local installer for socialwarden-watcher
# ─────────────────────────────────────────────────────────────────────────────
# Run ON the target machine (typically host-utils only — Sprint 2 scope):
#   sudo bash install-watcher.sh             # install + enable, do NOT start
#   sudo bash install-watcher.sh --enable-now
#   sudo bash install-watcher.sh --dry-run
#
# What it does (idempotent — safe to rerun):
#   1. Pre-flight checks (root, agent installed, bw + python3 on PATH, config)
#   2. Install /opt/socialwarden-watcher/socialwarden-watcher.py (mode 0750)
#   3. Install /etc/systemd/system/socialwarden-watcher.service (mode 0644)
#   4. Parse watch.paths from --config and write a drop-in at
#      /etc/systemd/system/socialwarden-watcher.service.d/scan-paths.conf
#      with the additional ReadWritePaths= entries the watcher needs to
#      replace .env files with symlinks (parent dirs of every scan root).
#   5. systemctl daemon-reload + enable
#   6. Stop here UNLESS --enable-now is set:
#        sudo touch /etc/socialwarden/watcher-enabled    # opt-in marker
#        sudo systemctl start socialwarden-watcher
#
# Re-running on an already-installed host is a no-op for unchanged files.
# Hashes are compared before overwriting so the service is not restarted
# unnecessarily.

set -euo pipefail

# --- Defaults --------------------------------------------------------------
CONFIG_PATH="/etc/socialwarden/config.yaml"
WATCHER_BIN_DST="/opt/socialwarden-watcher/socialwarden-watcher.py"
WATCHER_UNIT_DST="/etc/systemd/system/socialwarden-watcher.service"
DROPIN_DIR="/etc/systemd/system/socialwarden-watcher.service.d"
DROPIN_PATH="$DROPIN_DIR/scan-paths.conf"

ENABLE_NOW=0
DRY_RUN=0

# --- Args ------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --config)      CONFIG_PATH="$2"; shift 2 ;;
        --enable-now)  ENABLE_NOW=1; shift ;;
        --dry-run)     DRY_RUN=1; shift ;;
        -h|--help)
            sed -n '3,28p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

# --- Colors ----------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*" >&2; }
step()  { echo -e "\n${BLUE}=== $* ===${NC}"; }
note()  { [ "$DRY_RUN" -eq 1 ] && echo -e "  ${YELLOW}(dry-run)${NC} $*" || true; }

# --- Pre-flight ------------------------------------------------------------
step "Pre-flight"

if [ "$EUID" -ne 0 ]; then
    err "Must run as root. Try: sudo bash $0"
    exit 1
fi

# Locate sibling files. install-watcher.sh ships alongside watcher/ and
# service/ in the repo; we accept either layout for flexibility.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

WATCHER_SRC=""
for candidate in \
    "$SCRIPT_DIR/../watcher/socialwarden-watcher.py" \
    "$SCRIPT_DIR/socialwarden-watcher.py" \
    "$SCRIPT_DIR/../socialwarden-watcher.py"; do
    if [ -f "$candidate" ]; then WATCHER_SRC="$candidate"; break; fi
done
if [ -z "$WATCHER_SRC" ]; then
    err "Cannot find socialwarden-watcher.py (looked in ../watcher/, ., ..)"
    exit 1
fi

UNIT_SRC=""
for candidate in \
    "$SCRIPT_DIR/../service/socialwarden-watcher.service" \
    "$SCRIPT_DIR/socialwarden-watcher.service" \
    "$SCRIPT_DIR/../socialwarden-watcher.service"; do
    if [ -f "$candidate" ]; then UNIT_SRC="$candidate"; break; fi
done
if [ -z "$UNIT_SRC" ]; then
    err "Cannot find socialwarden-watcher.service (looked in ../service/, ., ..)"
    exit 1
fi

info "Watcher source: $WATCHER_SRC"
info "Service source: $UNIT_SRC"

# Agent must be installed (the watcher coexists with it; sharing the bw flock
# is the whole point).
if ! systemctl cat socialwarden-agent.service >/dev/null 2>&1; then
    err "socialwarden-agent.service not found. Install the agent first."
    exit 1
fi
info "socialwarden-agent.service present"

for tool in python3 bw systemctl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        err "Missing required tool on PATH: $tool"
        exit 1
    fi
done
info "Required tools on PATH: python3 bw systemctl"

if [ ! -f "$CONFIG_PATH" ]; then
    err "Config not found: $CONFIG_PATH"
    err "The watcher reuses the agent's config; install the agent first."
    exit 1
fi
info "Config: $CONFIG_PATH"

# Syntax-check the watcher binary so we never deploy broken Python.
if ! python3 -m py_compile "$WATCHER_SRC" 2>/dev/null; then
    err "py_compile failed on $WATCHER_SRC — refusing to deploy."
    python3 -m py_compile "$WATCHER_SRC"  # rerun verbosely
    exit 1
fi
info "Watcher binary parses cleanly"

# --- Helpers ---------------------------------------------------------------
# install_file <src> <dst> <mode> — copy only if content differs. Returns 0
# always; sets CHANGED=1 in caller if anything was written.
install_file() {
    local src="$1" dst="$2" mode="$3"
    local dst_dir
    dst_dir="$(dirname "$dst")"

    if [ -f "$dst" ] && cmp -s "$src" "$dst" && \
       [ "$(stat -c '%a' "$dst")" = "$mode" ]; then
        info "$(basename "$dst"): unchanged"
        return 0
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        note "would install $src → $dst (mode $mode)"
        return 0
    fi

    install -d -m 755 "$dst_dir"
    install -m "$mode" "$src" "$dst"
    info "$(basename "$dst"): installed → $dst"
    CHANGED=1
}

# parse_scan_paths — emit space-separated parent dirs of watch.paths from
# the YAML config. Empty output is fine (watcher idles without paths).
parse_scan_paths() {
    python3 - "$CONFIG_PATH" <<'PYEOF'
import os, sys
try:
    import yaml
except ImportError:
    print("PyYAML not installed", file=sys.stderr)
    sys.exit(3)
try:
    with open(sys.argv[1]) as f:
        cfg = yaml.safe_load(f) or {}
except OSError as e:
    print(f"cannot read {sys.argv[1]}: {e}", file=sys.stderr)
    sys.exit(3)
paths = (cfg.get("watch") or {}).get("paths") or []
out = set()
for p in paths:
    if not isinstance(p, str) or not p.startswith("/"):
        print(f"WARN: skipping non-absolute scan path: {p!r}", file=sys.stderr)
        continue
    # Watcher writes inside the scan root (replaces .env with symlink), so
    # the root itself must be writable. We include both the root and its
    # parent to allow renames across the boundary.
    out.add(os.path.normpath(p))
print(" ".join(sorted(out)))
PYEOF
}

# --- 1. Install watcher binary --------------------------------------------
step "Install watcher binary"
CHANGED=0
install_file "$WATCHER_SRC" "$WATCHER_BIN_DST" 0750

# --- 2. Install systemd unit ----------------------------------------------
step "Install systemd unit"
install_file "$UNIT_SRC" "$WATCHER_UNIT_DST" 0644

# --- 3. Generate drop-in for scan paths -----------------------------------
step "Generate scan-paths drop-in"

SCAN_PATHS="$(parse_scan_paths)" || {
    err "Failed to parse watch.paths from $CONFIG_PATH"
    exit 1
}

if [ -z "$SCAN_PATHS" ]; then
    warn "watch.paths is empty in $CONFIG_PATH"
    warn "Watcher will idle until you add paths and rerun this installer."
    DROPIN_CONTENT=$'# Auto-generated by install-watcher.sh — DO NOT EDIT BY HAND.\n# watch.paths is empty in config.yaml; no extra ReadWritePaths needed yet.\n[Service]\n'
else
    info "Scan paths: $SCAN_PATHS"
    DROPIN_CONTENT=$'# Auto-generated by install-watcher.sh — DO NOT EDIT BY HAND.\n# Sourced from watch.paths in '"$CONFIG_PATH"$'\n[Service]\nReadWritePaths='"$SCAN_PATHS"$'\n'
fi

DROPIN_TMP="$(mktemp)"
trap 'rm -f "$DROPIN_TMP"' EXIT
printf '%s' "$DROPIN_CONTENT" > "$DROPIN_TMP"

if [ -f "$DROPIN_PATH" ] && cmp -s "$DROPIN_TMP" "$DROPIN_PATH"; then
    info "$(basename "$DROPIN_PATH"): unchanged"
else
    if [ "$DRY_RUN" -eq 1 ]; then
        note "would write drop-in:"
        sed 's/^/    /' "$DROPIN_TMP"
    else
        install -d -m 755 "$DROPIN_DIR"
        install -m 0644 "$DROPIN_TMP" "$DROPIN_PATH"
        info "drop-in installed → $DROPIN_PATH"
        CHANGED=1
    fi
fi

# --- 4. systemd reload + enable -------------------------------------------
step "systemd reload + enable"

if [ "$DRY_RUN" -eq 1 ]; then
    note "would: systemctl daemon-reload"
    note "would: systemctl enable socialwarden-watcher.service"
elif [ "$CHANGED" -eq 1 ] || ! systemctl is-enabled socialwarden-watcher.service >/dev/null 2>&1; then
    systemctl daemon-reload
    info "daemon-reload"
    systemctl enable socialwarden-watcher.service >/dev/null
    info "enabled socialwarden-watcher.service"
else
    info "no changes — skipping daemon-reload"
fi

# --- 5. doctor (sanity check) ---------------------------------------------
step "doctor"
if [ "$DRY_RUN" -eq 1 ]; then
    note "would run: $WATCHER_BIN_DST --config $CONFIG_PATH doctor"
else
    if python3 "$WATCHER_BIN_DST" --config "$CONFIG_PATH" doctor; then
        info "doctor exit OK"
    else
        warn "doctor reported problems (above). Review before enabling."
    fi
fi

# --- 6. Final guidance / optional start -----------------------------------
step "Next steps"
echo
if [ "$ENABLE_NOW" -eq 1 ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
        note "would: touch /etc/socialwarden/watcher-enabled"
        note "would: systemctl restart socialwarden-watcher.service"
    else
        if [ ! -f /etc/socialwarden/watcher-enabled ]; then
            install -d -m 700 /etc/socialwarden
            touch /etc/socialwarden/watcher-enabled
            chmod 600 /etc/socialwarden/watcher-enabled
            info "created opt-in marker: /etc/socialwarden/watcher-enabled"
        fi
        systemctl restart socialwarden-watcher.service
        info "service restarted"
        echo
        echo "Tail logs with:"
        echo "  journalctl -u socialwarden-watcher.service -f"
    fi
else
    echo "Watcher is installed + enabled but NOT started (defense in depth)."
    echo "To turn it on:"
    echo "  sudo touch /etc/socialwarden/watcher-enabled"
    echo "  sudo systemctl start socialwarden-watcher.service"
    echo "  journalctl -u socialwarden-watcher.service -f"
fi
echo
