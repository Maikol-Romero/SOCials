#!/bin/bash
# socialwarden-manager installer — runs ONLY on the manager host.
# Installs the manager CLI + its library module to /opt/socialwarden-manager/.
#
# Idempotent. Timestamped backup of whatever it overwrites.
#
# Usage:
#   sudo bash install.sh [--force]

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*" >&2; }
step()  { echo -e "\n${BLUE}=== $* ===${NC}"; }

FORCE=0
for a in "$@"; do
    case "$a" in
        --force) FORCE=1 ;;
        -h|--help)
            sed -n '3,10p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) err "Unknown arg: $a"; exit 2 ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    err "Must run as root. Try: sudo bash install.sh"
    exit 1
fi

# This installer is manager-only. Refuse to run on a non-monitor machine.
# We detect by checking inventory.json for the local hostname's role.
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
INVENTORY="$(realpath "$SRC_DIR/../inventory.json" 2>/dev/null || echo "$SRC_DIR/../inventory.json")"

if [ -f "$INVENTORY" ]; then
    HOSTNAME_LOCAL=$(hostname)
    LOCAL_ROLE=$(python3 -c "
import json, sys, socket
inv = json.load(open('$INVENTORY'))
hn = socket.gethostname()
for m in inv:
    if m.get('role') == 'monitor':
        print(m.get('name','monitor'))
        sys.exit(0)
" 2>/dev/null || echo "")
fi

# Check we're on the manager machine via presence of /opt/your-infra-ops
# (the inventory + ops repo lives on the manager host, not the clients).
if [ ! -d "/opt/your-infra-ops" ] && [ $FORCE -eq 0 ]; then
    err "This looks like a CLIENT machine (no /opt/your-infra-ops/)."
    err "socialwarden-manager belongs on the MANAGER host only."
    err "If you really want to override, use --force."
    exit 3
fi

for f in VERSION socialwarden-manager shamir.py; do
    if [ ! -f "$SRC_DIR/$f" ]; then
        err "Missing source file: $SRC_DIR/$f"
        exit 1
    fi
done

NEW_VERSION=$(tr -d '[:space:]' < "$SRC_DIR/VERSION")
STAMP=$(date -u +%Y%m%dT%H%M%S)

step "Install socialwarden-manager v${NEW_VERSION}"

# Create dirs
install -d -m 755 /opt/socialwarden-manager
install -d -m 700 /var/lib/socialwarden-manager
install -d -m 700 /var/lib/socialwarden-manager/shares
install -d -m 700 /var/lib/socialwarden-manager/identities
info "Dirs ready"

# Backup
BACKUP_DIR="/opt/socialwarden-manager/backups-${STAMP}"
install -d -m 700 "$BACKUP_DIR"
for f in /opt/socialwarden-manager/socialwarden-manager /opt/socialwarden-manager/shamir.py /opt/socialwarden-manager/VERSION /usr/local/bin/socialwarden-manager; do
    if [ -e "$f" ]; then cp -a "$f" "$BACKUP_DIR/$(basename "$f")"; fi
done
info "Backup: $BACKUP_DIR"

# Install files
install -m 755 -o root -g root "$SRC_DIR/socialwarden-manager" /opt/socialwarden-manager/socialwarden-manager
install -m 644 -o root -g root "$SRC_DIR/shamir.py"            /opt/socialwarden-manager/shamir.py
install -m 644 -o root -g root "$SRC_DIR/VERSION"              /opt/socialwarden-manager/VERSION

# Symlink for operator convenience
if [ -L /usr/local/bin/socialwarden-manager ] || [ ! -e /usr/local/bin/socialwarden-manager ]; then
    ln -snf /opt/socialwarden-manager/socialwarden-manager /usr/local/bin/socialwarden-manager
else
    # Already a regular file; overwrite via install
    install -m 755 /opt/socialwarden-manager/socialwarden-manager /usr/local/bin/socialwarden-manager
fi
info "CLI symlinked at /usr/local/bin/socialwarden-manager"

# Sanity
step "Python syntax check"
if python3 -c "import ast; ast.parse(open('/opt/socialwarden-manager/socialwarden-manager').read())" 2>/dev/null; then
    info "Syntax OK"
else
    err "Syntax check failed"
    exit 4
fi

step "Done"
echo -e "  ${BOLD}Version:${NC}  $NEW_VERSION"
echo -e "  ${BOLD}Code:${NC}     /opt/socialwarden-manager/"
echo -e "  ${BOLD}State:${NC}    /var/lib/socialwarden-manager/"
echo -e "  ${BOLD}CLI:${NC}      socialwarden-manager status | list | shamir-split | shamir-combine"
echo ""
info "Installation complete"
