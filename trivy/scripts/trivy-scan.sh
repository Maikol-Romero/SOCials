#!/bin/bash
# ============================================
# Trivy — Escaneo completo de vulnerabilidades
# ============================================
# Escanea imágenes Docker + paquetes del sistema en TODAS las máquinas.
# Muestra detalles de cada vulnerabilidad.
# Envía resumen a Discord.
#
# Uso manual: ./trivy-scan.sh
# Cron:       0 3 * * 0 /path/to/trivy-scan.sh

set +e  # No exit on error — remote machines may fail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="$SCRIPT_DIR/../reports"
TIMESTAMP=$(date '+%Y-%m-%d_%H%M')
REPORT_FILE="$REPORT_DIR/scan_${TIMESTAMP}.txt"
ENV_FILE="$SCRIPT_DIR/../.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }
log_section() { echo -e "\n${CYAN}${BOLD}═══════════════════════════════════════${NC}"; echo -e "${CYAN}${BOLD}  $1${NC}"; echo -e "${CYAN}${BOLD}═══════════════════════════════════════${NC}\n"; }

DISCORD_URL=""
if [ -f "$ENV_FILE" ]; then
    DISCORD_URL=$(grep DISCORD_WEBHOOK_URL "$ENV_FILE" | cut -d= -f2- | tr -d '\r')
fi

mkdir -p "$REPORT_DIR"

# Verificar que trivy está corriendo
if ! docker ps --format '{{.Names}}' | grep -q "soc-trivy"; then
    log_error "Contenedor soc-trivy no está corriendo"
    log_info "Levantando Trivy..."
    cd "$SCRIPT_DIR/.." && docker compose up -d
    sleep 5
fi

TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
DISCORD_DETAILS=""

# ============================================
# Función: Escanear imágenes Docker de una máquina
# ============================================
scan_docker_images() {
    local MACHINE_NAME=$1
    local SSH_CMD=$2  # vacío = local

    log_section "Docker Images — $MACHINE_NAME"

    # Collect image metadata: image|compose_dir|service
    if [ -z "$SSH_CMD" ]; then
        IMAGE_META=$(docker ps --format '{{.Image}}|{{.Label "com.docker.compose.project.working_dir"}}|{{.Label "com.docker.compose.service"}}' 2>/dev/null)
        IMAGES=$(echo "$IMAGE_META" | cut -d'|' -f1 | sort -u)
    else
        IMAGE_META=$($SSH_CMD 'docker ps --format '"'"'{{.Image}}|{{.Label "com.docker.compose.project.working_dir"}}|{{.Label "com.docker.compose.service"}}'"'"'' 2>/dev/null)
        IMAGES=$(echo "$IMAGE_META" | cut -d'|' -f1 | sort -u)
    fi

    # Build lookup: IMAGE -> compose_dir|service (first match wins)
    declare -A IMG_SERVICE IMG_PATH
    while IFS='|' read -r img cdir svc; do
        [ -z "$img" ] && continue
        if [ -z "${IMG_SERVICE[$img]+x}" ]; then
            IMG_SERVICE[$img]="$svc"
            IMG_PATH[$img]="$cdir"
        fi
    done <<< "$IMAGE_META"

    if [ -z "$IMAGES" ]; then
        log_warn "No hay contenedores corriendo en $MACHINE_NAME"
        return
    fi

    IMAGE_COUNT=$(echo "$IMAGES" | wc -l)
    log_info "Escaneando $IMAGE_COUNT imágenes en $MACHINE_NAME..."
    echo ""

    echo "=== Docker Images — $MACHINE_NAME ===" >> "$REPORT_FILE"

    # Write image metadata to a separate file for JSON export
    for IMG_KEY in "${!IMG_SERVICE[@]}"; do
        CLEAN_IMG=$(echo "$IMG_KEY" | rev | cut -d/ -f1 | rev | cut -d: -f1)
        echo "${MACHINE_NAME}|${CLEAN_IMG}|${IMG_SERVICE[$IMG_KEY]}|${IMG_PATH[$IMG_KEY]}" >> "$REPORT_DIR/.image_meta.tmp"
    done

    for IMAGE in $IMAGES; do
        SCAN_JSON=$(docker exec soc-trivy trivy image \
            --severity HIGH,CRITICAL \
            --format json \
            --quiet \
            "$IMAGE" 2>/dev/null || echo "{}")

        parse_and_display "$IMAGE" "$SCAN_JSON" "$MACHINE_NAME" "image" "${IMG_SERVICE[$IMAGE]:-}" "${IMG_PATH[$IMAGE]:-}"
    done
}

# ============================================
# Función: Escanear paquetes del sistema
# ============================================
scan_os_packages() {
    local MACHINE_NAME=$1
    local SSH_CMD=$2

    log_section "Sistema Operativo — $MACHINE_NAME"

    # Generar SBOM del sistema remoto o local
    if [ -z "$SSH_CMD" ]; then
        OS_NAME=$(. /etc/os-release && echo "$PRETTY_NAME")
        # Exportar lista de paquetes instalados
        PKGS_FILE="/tmp/trivy_pkgs_${MACHINE_NAME}.txt"
        dpkg-query -W -f='${Package} ${Version}\n' > "$PKGS_FILE" 2>/dev/null || true
    else
        OS_NAME=$($SSH_CMD ". /etc/os-release && echo \$PRETTY_NAME" 2>/dev/null)
        PKGS_FILE="/tmp/trivy_pkgs_${MACHINE_NAME}.txt"
        $SSH_CMD "dpkg-query -W -f='\${Package} \${Version}\n'" > "$PKGS_FILE" 2>/dev/null || true
    fi

    log_info "OS: $OS_NAME"
    PKG_COUNT=$(wc -l < "$PKGS_FILE" 2>/dev/null || echo 0)
    log_info "Paquetes instalados: $PKG_COUNT"

    echo "=== OS Packages — $MACHINE_NAME ($OS_NAME) ===" >> "$REPORT_FILE"

    # Escanear con trivy fs mode usando la lista de paquetes
    # Copiamos la lista al contenedor de trivy
    docker cp "$PKGS_FILE" soc-trivy:/tmp/pkgs.txt 2>/dev/null

    # Para OS scanning usamos trivy rootfs si es local
    if [ -z "$SSH_CMD" ]; then
        SCAN_JSON=$(docker exec soc-trivy trivy rootfs \
            --severity MEDIUM,HIGH,CRITICAL \
            --format json \
            --quiet \
            / 2>/dev/null || echo "{}")
    else
        # Para remoto generamos un tarball mínimo del dpkg status
	mkdir -p "/tmp/trivy_rootfs_${MACHINE_NAME}/var/lib/dpkg"
        mkdir -p "/tmp/trivy_rootfs_${MACHINE_NAME}/etc"
        $SSH_CMD "cat /var/lib/dpkg/status" > "/tmp/trivy_rootfs_${MACHINE_NAME}/var/lib/dpkg/status" 2>/dev/null
        $SSH_CMD "cat /etc/os-release" > "/tmp/trivy_rootfs_${MACHINE_NAME}/etc/os-release" 2>/dev/null

        # Montar en trivy y escanear
        docker cp "/tmp/trivy_rootfs_${MACHINE_NAME}" soc-trivy:/tmp/rootfs_scan 2>/dev/null
        SCAN_JSON=$(docker exec soc-trivy trivy rootfs \
            --severity MEDIUM,HIGH,CRITICAL \
            --format json \
            --quiet \
            /tmp/rootfs_scan 2>/dev/null || echo "{}")
    fi

    parse_and_display "OS ($OS_NAME)" "$SCAN_JSON" "$MACHINE_NAME" "os"

    rm -f "$PKGS_FILE" 2>/dev/null
    rm -rf "/tmp/trivy_rootfs_${MACHINE_NAME}" "/tmp/dpkg_status_${MACHINE_NAME}" 2>/dev/null
}

# ============================================
# Función: Parsear resultados y mostrar detalle
# ============================================
parse_and_display() {
    local TARGET=$1
    local JSON=$2
    local MACHINE=$3
    local SCAN_TYPE=$4
    local SERVICE=${5:-}
    local COMPOSE_DIR=${6:-}

    PARSED=$(echo "$JSON" | TARGET="$TARGET" SVC="$SERVICE" CDIR="$COMPOSE_DIR" python3 -c "
import json, sys, os
try:
    target = os.environ.get('TARGET', '?')
    data = json.load(sys.stdin)
    results = data.get('Results', [])
    vulns = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': []}
    for r in results:
        for v in r.get('Vulnerabilities', []):
            sev = v.get('Severity', 'UNKNOWN')
            if sev in vulns:
                vulns[sev].append({
                    'id': v.get('VulnerabilityID', '?'),
                    'pkg': v.get('PkgName', '?'),
                    'installed': v.get('InstalledVersion', '?'),
                    'fixed': v.get('FixedVersion', 'sin fix'),
                    'title': v.get('Title', '')[:80]
                })
    # Output format: severity|id|pkg|installed|fixed|title
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM']:
        for v in vulns[sev]:
            print(f\"{sev}|{v['id']}|{v['pkg']}|{v['installed']}|{v['fixed']}|{target}|{v['title']}\")
    # Summary line
    print(f\"SUMMARY|{len(vulns['CRITICAL'])}|{len(vulns['HIGH'])}|{len(vulns['MEDIUM'])}\")
except:
    print('SUMMARY|0|0|0')
" 2>/dev/null)

    CRIT=$(echo "$PARSED" | grep "^SUMMARY" | cut -d'|' -f2)
    HIGH=$(echo "$PARSED" | grep "^SUMMARY" | cut -d'|' -f3)
    MED=$(echo "$PARSED" | grep "^SUMMARY" | cut -d'|' -f4)
    CRIT=${CRIT:-0}; HIGH=${HIGH:-0}; MED=${MED:-0}

    TOTAL_CRITICAL=$((TOTAL_CRITICAL + CRIT))
    TOTAL_HIGH=$((TOTAL_HIGH + HIGH))
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + MED))

    # Header por target
    if [ "$CRIT" -gt 0 ]; then
        echo -e "  ${RED}●${NC} ${BOLD}$TARGET${NC} — ${RED}$CRIT CRITICAL${NC}, ${YELLOW}$HIGH HIGH${NC}, $MED MEDIUM"
    elif [ "$HIGH" -gt 0 ]; then
        echo -e "  ${YELLOW}●${NC} ${BOLD}$TARGET${NC} — ${YELLOW}$HIGH HIGH${NC}, $MED MEDIUM"
    elif [ "$MED" -gt 0 ]; then
        echo -e "  ${CYAN}●${NC} ${BOLD}$TARGET${NC} — $MED MEDIUM"
    else
        echo -e "  ${GREEN}●${NC} ${BOLD}$TARGET${NC} — Limpia"
        return
    fi

    # Detalle de vulnerabilidades CRITICAL
    CRIT_LINES=$(echo "$PARSED" | grep "^CRITICAL|" || true)
    if [ -n "$CRIT_LINES" ]; then
        echo -e "    ${RED}${BOLD}CRITICAL:${NC}"
        echo "$CRIT_LINES" | while IFS='|' read -r SEV ID PKG INSTALLED FIXED IMAGE TITLE; do
            if [ "$FIXED" = "sin fix" ]; then
                FIX_COLOR="${RED}sin fix${NC}"
            else
                FIX_COLOR="${GREEN}→ $FIXED${NC}"
            fi
            echo -e "      ${RED}■${NC} $ID — $PKG ($INSTALLED) $FIX_COLOR"
            [ -n "$TITLE" ] && echo -e "        $TITLE"
        done
        echo "$CRIT_LINES" >> "$REPORT_FILE"
        DISCORD_DETAILS="${DISCORD_DETAILS}\n[$MACHINE] $TARGET: $CRIT CRITICAL"
    fi

    # Detalle de vulnerabilidades HIGH
    HIGH_LINES=$(echo "$PARSED" | grep "^HIGH|" || true)
    if [ -n "$HIGH_LINES" ]; then
        HIGH_SHOW=$(echo "$HIGH_LINES" | head -10)
        HIGH_TOTAL=$(echo "$HIGH_LINES" | wc -l)
        echo -e "    ${YELLOW}${BOLD}HIGH ($HIGH_TOTAL):${NC}"
        echo "$HIGH_SHOW" | while IFS='|' read -r SEV ID PKG INSTALLED FIXED IMAGE TITLE; do
            if [ "$FIXED" = "sin fix" ]; then
                FIX_COLOR="${YELLOW}sin fix${NC}"
            else
                FIX_COLOR="${GREEN}→ $FIXED${NC}"
            fi
            echo -e "      ${YELLOW}■${NC} $ID — $PKG ($INSTALLED) $FIX_COLOR"
        done
        [ "$HIGH_TOTAL" -gt 10 ] && echo -e "      ... y $((HIGH_TOTAL - 10)) más (ver reporte completo)"
        echo "$HIGH_LINES" >> "$REPORT_FILE"
    fi

    # MEDIUM solo contamos
    MED_LINES=$(echo "$PARSED" | grep "^MEDIUM|" || true)
    if [ -n "$MED_LINES" ]; then
        MED_TOTAL=$(echo "$MED_LINES" | wc -l)
        echo -e "    ${CYAN}MEDIUM: $MED_TOTAL vulnerabilidades${NC} (ver reporte)"
        echo "$MED_LINES" >> "$REPORT_FILE"
    fi

    echo ""
}

# ============================================
# MAIN
# ============================================
echo ""
echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║   Trivy — Escaneo de Vulnerabilidades     ║${NC}"
echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════╝${NC}"

echo "Scan: $(date '+%Y-%m-%d %H:%M:%S')" > "$REPORT_FILE"
> "$REPORT_DIR/.image_meta.tmp"
echo "" >> "$REPORT_FILE"

# Escanear monitor (local)
MONITOR_NAME=$(hostname)
scan_docker_images "$MONITOR_NAME" ""
scan_os_packages "$MONITOR_NAME" ""

# Escanear máquinas remotas (leer del inventario)
INVENTORY="$SCRIPT_DIR/../inventory.json"
if [ -f "$INVENTORY" ]; then
    REMOTE_MACHINES=$(python3 -c "
import json
with open('$INVENTORY') as f:
    inv = json.load(f)
machines = inv if isinstance(inv, list) else inv.get('machines', [])
for m in machines:
    name = m.get('name','')
    ssh = m.get('ssh','')
    if not ssh and m.get('private_ip') and m.get('ssh_user'):
        ssh = f\"ssh -o ConnectTimeout=10 -o BatchMode=yes {m['ssh_user']}@{m['private_ip']}\"
    if name and ssh:
        print(f\"{name}|{ssh}\")
" 2>/dev/null)

    while IFS='|' read -r RNAME RSSH <&3; do
        [ -z "$RNAME" ] && continue
        log_info "Escaneando máquina remota: $RNAME"
        scan_docker_images "$RNAME" "$RSSH"
        scan_os_packages "$RNAME" "$RSSH"
    done 3<<< "$REMOTE_MACHINES"
else
    log_warn "No se encontró inventory.json — solo se escanea la máquina local"
    log_warn "Ejecuta setup.sh primero para generar el inventario"
fi

# ============================================
# RESUMEN FINAL
# ============================================
log_section "RESUMEN"

echo -e "  ${RED}${BOLD}CRITICAL:${NC}  $TOTAL_CRITICAL"
echo -e "  ${YELLOW}${BOLD}HIGH:${NC}      $TOTAL_HIGH"
echo -e "  ${CYAN}${BOLD}MEDIUM:${NC}    $TOTAL_MEDIUM"
echo ""
echo -e "  Reporte completo: $REPORT_FILE"
echo ""

echo "" >> "$REPORT_FILE"
echo "TOTAL: $TOTAL_CRITICAL CRITICAL, $TOTAL_HIGH HIGH, $TOTAL_MEDIUM MEDIUM" >> "$REPORT_FILE"

# ============================================
# EXPORTAR JSON PARA DASHBOARD
# ============================================
TIMESTAMP_JSON=$(date '+%Y-%m-%d_%H%M')
JSON_REPORT="$REPORT_DIR/scan_${TIMESTAMP_JSON}.json"
JSON_LATEST="$REPORT_DIR/latest.json"
python3 - "$REPORT_FILE" "$JSON_REPORT" << 'JSONEOF'
import sys, json, os
from datetime import datetime, timezone

report_file = sys.argv[1]
json_file = sys.argv[2]

vulns = {}
current_machine = "unknown"
current_section = "docker"

# Map AWS internal hostnames (e.g. "ip-10-0-0-10") to logical fleet names.
# Add entries for your machines; raw hostnames not in the map pass through.
name_map = {
    # Example mappings — replace with your fleet:
    # "ip-10-0-0-10": "web-prod",
    # "ip-10-0-0-20": "db-primary",
}

with open(report_file) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("Scan:") or line.startswith("TOTAL:") or line.startswith("SUMMARY|"):
            continue
        if line.startswith("=== Docker Images"):
            raw = line.replace("=== Docker Images — ", "").replace(" ===", "")
            current_machine = name_map.get(raw, raw)
            current_section = "docker"
            continue
        if line.startswith("=== OS Packages"):
            raw = line.split("—")[1].strip().split("(")[0].strip() if "—" in line else "unknown"
            current_machine = name_map.get(raw, raw)
            current_section = "os"
            continue
        if line.startswith("==="):
            continue
        parts = line.split("|")
        if len(parts) >= 7:
            severity, cve_id, pkg = parts[0], parts[1], parts[2]
            installed, fixed = parts[3], parts[4]
            image = parts[5]
            title = "|".join(parts[6:]).strip()
        elif len(parts) >= 6:
            severity, cve_id, pkg = parts[0], parts[1], parts[2]
            installed, fixed = parts[3], parts[4]
            image = None
            title = "|".join(parts[5:]).strip()
        else:
            continue
        key = f"{cve_id}:{pkg}"
        if key not in vulns:
            vulns[key] = {
                "id": cve_id, "severity": severity, "pkg": pkg,
                "installed": installed,
                "fixed": fixed if fixed != "sin fix" else None,
                "title": title, "machines": [], "machine_images": {},
                "source": current_section,
            }
        if current_machine not in vulns[key]["machines"]:
            vulns[key]["machines"].append(current_machine)
        if image and image != "?":
            # Clean image name: registry.example.com/your-api:latest → soc-api
            clean_img = image.rsplit("/", 1)[-1].split(":")[0] if "/" in image else image.split(":")[0]
            if current_machine not in vulns[key]["machine_images"]:
                vulns[key]["machine_images"][current_machine] = []
            # Store as object with service/path if available
            existing_imgs = [x["image"] if isinstance(x, dict) else x for x in vulns[key]["machine_images"][current_machine]]
            if clean_img not in existing_imgs:
                vulns[key]["machine_images"][current_machine].append(clean_img)

# --- Detección de conflictos ---
import re

def parse_major(ver):
    """Extrae versión mayor de un string de versión"""
    if not ver: return None
    # Limpiar prefijos: v1.2.3, 1:1.2.3, epoch:ver
    clean = ver.split(":")[-1].lstrip("v")
    m = re.match(r"(\\d+)", clean.split("-")[0])
    return int(m.group(1)) if m else None

# Paquetes core del sistema — actualizar estos afecta a muchos otros
SYSTEM_CORE = {
    "openssl", "libssl3", "libcrypto3", "libssl1.1", "libssl-dev",
    "glibc", "libc6", "libc-bin", "linux-libc-dev",
    "zlib", "zlib1g", "libz1",
    "libcurl", "curl",
    "libxml2", "libpython3", "python3",
    "stdlib",  # Go stdlib
}

for key, v in vulns.items():
    if not v.get("fixed"):
        continue

    old_maj = parse_major(v["installed"])
    new_maj = parse_major(v["fixed"])
    is_major_bump = (old_maj is not None and new_maj is not None and new_maj > old_maj)
    is_core = any(v["pkg"].startswith(c) or v["pkg"] == c for c in SYSTEM_CORE)

    if is_major_bump:
        v["hasConflict"] = True
        v["conflictDetail"] = {
            "problem": f"La versión corregida ({v['fixed']}) es un salto de versión mayor ({old_maj}.x → {new_maj}.x)",
            "current": f"Versión instalada: {v['installed']}. Otros paquetes pueden depender de la API de {v['pkg']} {old_maj}.x",
            "consequence": f"Los paquetes que dependen de {v['pkg']} pueden dejar de funcionar porque la versión {new_maj}.x puede tener cambios incompatibles",
            "recommendation": f"Probar primero en staging. Verificar dependencias con 'pip show {v['pkg']}' o 'npm ls {v['pkg']}' antes de actualizar"
        }
    elif is_core:
        v["hasConflict"] = True
        v["conflictDetail"] = {
            "problem": f"{v['pkg']} es un paquete del sistema del que dependen muchos otros programas",
            "current": f"Versión instalada: {v['installed']}. Es una dependencia fundamental del sistema operativo o runtime",
            "consequence": f"Actualizar {v['pkg']} puede afectar a todos los programas que lo usan internamente (cifrado, red, compilación, etc.)",
            "recommendation": f"Actualizar la imagen base completa (Alpine/Debian) en vez de solo este paquete. Así todas las dependencias se actualizan juntas"
        }

vlist = sorted(vulns.values(), key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2}.get(x["severity"],3))
machines_found = sorted(set(m for v in vlist for m in v["machines"]))

# Load image metadata (machine|image|service|compose_dir)
image_info = {}
meta_file = os.path.join(os.path.dirname(report_file), ".image_meta.tmp")
if os.path.exists(meta_file):
    with open(meta_file) as mf:
        for line in mf:
            parts = line.strip().split("|")
            if len(parts) >= 4:
                machine, img, svc, cdir = parts[0], parts[1], parts[2], parts[3]
                machine = name_map.get(machine, machine)
                # Shorten path: /home/ubuntu/your-app → ~/your-app
                cdir = cdir.replace("/home/ubuntu/", "~/").replace("/root/", "~/")
                key = f"{machine}:{img}"
                if key not in image_info:
                    image_info[key] = {"machine": machine, "image": img, "service": svc, "path": cdir}

output = {
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
    "total": len(vlist),
    "critical": len([v for v in vlist if v["severity"] == "CRITICAL"]),
    "high": len([v for v in vlist if v["severity"] == "HIGH"]),
    "medium": len([v for v in vlist if v["severity"] == "MEDIUM"]),
    "machines_scanned": machines_found,
    "image_info": image_info,
    "vulnerabilities": vlist
}

with open(json_file, "w") as f:
    json.dump(output, f, indent=2)

print(f"[✓] JSON exportado: {json_file} ({len(vlist)} vulnerabilidades únicas, máquinas: {machines_found})")
JSONEOF

# Carry over AI enrichment from previous scan
python3 - "$JSON_REPORT" "$JSON_LATEST" << 'CARRYEOF'
import sys, json, os
new_file = sys.argv[1]
old_file = sys.argv[2]

if not os.path.exists(old_file):
    sys.exit(0)

with open(new_file) as f:
    new_data = json.load(f)
with open(old_file) as f:
    old_data = json.load(f)

# Build lookup from old scan: CVE ID -> AI fields
ai_lookup = {}
for v in old_data.get("vulnerabilities", []):
    if v.get("what"):
        ai_lookup[v["id"]] = {"what": v["what"], "why": v["why"], "howToFix": v["howToFix"]}

carried = 0
for v in new_data.get("vulnerabilities", []):
    if not v.get("what") and v["id"] in ai_lookup:
        v.update(ai_lookup[v["id"]])
        carried += 1

if carried > 0:
    with open(new_file, "w") as f:
        json.dump(new_data, f, indent=2, ensure_ascii=False)

print(f"[✓] IA heredada del scan anterior: {carried}/{len(new_data.get('vulnerabilities',[]))} vulnerabilidades")
CARRYEOF

cp "$JSON_REPORT" "$JSON_LATEST"
log_info "JSON: $JSON_REPORT + latest.json"

# Guardar resumen en historial
HISTORY_FILE="$REPORT_DIR/history.json"
python3 - "$JSON_REPORT" "$HISTORY_FILE" << 'HISTEOF'
import sys, json, os

json_file = sys.argv[1]
history_file = sys.argv[2]

with open(json_file) as f:
    scan = json.load(f)

entry = {
    "date": scan["timestamp"],
    "total": scan["total"],
    "critical": scan["critical"],
    "high": scan["high"],
    "medium": scan["medium"],
    "top_packages": {}
}

pkg_count = {}
for v in scan["vulnerabilities"]:
    pkg_count[v["pkg"]] = pkg_count.get(v["pkg"], 0) + 1
entry["top_packages"] = dict(sorted(pkg_count.items(), key=lambda x: -x[1])[:10])

history = []
if os.path.exists(history_file):
    try:
        with open(history_file) as f:
            history = json.load(f)
    except:
        history = []

history.append(entry)

# Dedup: keep only the last scan per day
by_day = {}
for h in history:
    day = h["date"][:10]
    by_day[day] = h
history = sorted(by_day.values(), key=lambda x: x["date"])
history = history[-52:]

with open(history_file, "w") as f:
    json.dump(history, f, indent=2)

print(f"[✓] Historial actualizado: {len(history)} entradas")
HISTEOF

# Generar resolved.json (comparar último scan con el anterior)
RESOLVED_FILE="$REPORT_DIR/resolved.json"
python3 - "$REPORT_DIR" "$RESOLVED_FILE" << 'RESOLVEDEOF'
import sys, json, os, glob
reports_dir = sys.argv[1]
resolved_file = sys.argv[2]
scan_files = sorted(glob.glob(os.path.join(reports_dir, "scan_*.json")))
resolved = []
if os.path.exists(resolved_file):
    try:
        with open(resolved_file) as f:
            resolved = json.load(f)
    except:
        resolved = []
if len(scan_files) >= 2:
    with open(scan_files[-2]) as f:
        old_scan = json.load(f)
    with open(scan_files[-1]) as f:
        new_scan = json.load(f)
    old_map = {f"{v['id']}:{v['pkg']}": v for v in old_scan.get("vulnerabilities", [])}
    new_keys = set(f"{v['id']}:{v['pkg']}" for v in new_scan.get("vulnerabilities", []))
    existing_keys = set(f"{r['id']}:{r['pkg']}" for r in resolved)
    for key, v in old_map.items():
        if key not in new_keys and key not in existing_keys:
            resolved.append({
                "id": v["id"], "pkg": v["pkg"], "severity": v["severity"],
                "title": v.get("title",""), "installed": v.get("installed",""),
                "fixed": v.get("fixed"), "machines": v.get("machines",[]),
                "machine_images": v.get("machine_images",{}),
                "resolved_date": new_scan.get("timestamp",""),
                "what": v.get("what",""), "why": v.get("why",""),
                "howToFix": v.get("howToFix",""),
            })
    resolved = resolved[-200:]
    with open(resolved_file, "w") as f:
        json.dump(resolved, f, indent=2, ensure_ascii=False)
    print(f"[✓] Resueltas: {len(resolved)} (nuevas este scan: {len(resolved) - len(existing_keys)})")
RESOLVEDEOF

# Auto-enrich con Claude CLI (si disponible)
ENRICH_SCRIPT="$SCRIPT_DIR/trivy-enrich.py"
if [ -f "$ENRICH_SCRIPT" ] && command -v claude &>/dev/null; then
    log_info "Iniciando enriquecimiento AI..."
    python3 "$ENRICH_SCRIPT" 2>&1 | tail -5
    log_info "Enriquecimiento completado"
else
    log_warn "trivy-enrich.py o claude CLI no disponible — skipping AI enrichment"
fi

# Recolectar dependencias reales de contenedores
DEPS_SCRIPT="$SCRIPT_DIR/trivy-deps.py"
if [ -f "$DEPS_SCRIPT" ]; then
    log_info "Recolectando dependencias reales..."
    python3 "$DEPS_SCRIPT" 2>&1 | tail -3
    log_info "Dependencias completadas"
else
    log_warn "trivy-deps.py no encontrado — skipping"
fi

# Generar resumen ejecutivo semanal
SUMMARY_SCRIPT="$SCRIPT_DIR/trivy-summary.py"
if [ -f "$SUMMARY_SCRIPT" ]; then
    log_info "Generando resumen semanal..."
    python3 "$SUMMARY_SCRIPT" 2>&1 | tail -3
    log_info "Resumen completado"
else
    log_warn "trivy-summary.py no encontrado — skipping"
fi

# Limpiar reportes antiguos (90 días)
find "$REPORT_DIR" -name "scan_*.txt" -mtime +90 -delete 2>/dev/null || true
find "$REPORT_DIR" -name "scan_*.json" -mtime +90 -delete 2>/dev/null || true

# Enviar a Discord si hay CRITICAL o HIGH
if [ "$TOTAL_CRITICAL" -gt 0 ] || [ "$TOTAL_HIGH" -gt 0 ]; then
    if [ -n "$DISCORD_URL" ] && [ "$DISCORD_URL" != "PENDIENTE" ]; then
        DISCORD_MSG="🔴 **Trivy Vulnerability Scan**\n\n"
        DISCORD_MSG+="**CRITICAL:** $TOTAL_CRITICAL\n"
        DISCORD_MSG+="**HIGH:** $TOTAL_HIGH\n"
        DISCORD_MSG+="**MEDIUM:** $TOTAL_MEDIUM\n"

        if [ -n "$DISCORD_DETAILS" ]; then
            DISCORD_MSG+="\n**Detalles:**\n\`\`\`"
            DISCORD_MSG+="$DISCORD_DETAILS"
            DISCORD_MSG+="\n\`\`\`\n"
        fi

        DISCORD_MSG+="Fecha: $(date '+%Y-%m-%d %H:%M')"

        curl -s -H "Content-Type: application/json" \
            -d "{\"content\": \"$(echo -e "$DISCORD_MSG")\"}" \
            "$DISCORD_URL" > /dev/null 2>&1

        log_info "Notificación enviada a Discord"
    fi
else
    log_info "Sin vulnerabilidades HIGH/CRITICAL"
fi

# Limpieza movida arriba (90 días)
