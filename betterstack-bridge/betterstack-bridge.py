#!/usr/bin/env python3
"""
Better Stack Status Bridge — Grafana / BetterStack alerts → public status page.

Usage:
  python3 betterstack-bridge.py          # interactive menu
  python3 betterstack-bridge.py serve    # webhook server

Config: services.json next to this script (copy from services.example.json
and edit). Defines service categories, routing maps, message templates, and
language. The script ships with no service-specific defaults — everything
domain-specific lives in the JSON config.
"""

import json
import logging
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============================================
# CONFIG LOADER
# ============================================

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_services_config():
    """Load services.json (or services.example.json as fallback). The script
    has no service-specific defaults — all routing/messaging is config-driven.
    """
    for fname in ("services.json", "services.example.json"):
        path = os.path.join(_SCRIPT_DIR, fname)
        if os.path.isfile(path):
            with open(path) as f:
                return json.load(f), fname
    sys.stderr.write(
        "FATAL: neither services.json nor services.example.json found next "
        "to betterstack-bridge.py. Copy services.example.json from the repo "
        "and edit before running.\n"
    )
    sys.exit(2)


_CONFIG, _CONFIG_SRC = _load_services_config()

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8085
BETTERSTACK_TOKEN = os.environ.get("BETTERSTACK_TOKEN")  # required, no default
STATUS_PAGE_ID = os.environ.get("BETTERSTACK_STATUS_PAGE_ID")  # required, your numeric status-page id
# Shared secret expected on inbound BS webhook (set in BS panel as `?token=...`
# query param or `X-Bridge-Token` header). Reject without it so a random POST
# can't create incidents on the public status page.
BS_INBOUND_TOKEN = os.environ.get("BS_INBOUND_TOKEN", "")
CLAUDE_MODEL = _CONFIG["claude"]["model"]
CLAUDE_TIMEOUT = _CONFIG["claude"]["timeout_s"]
CLAUDE_PROMPT_TEMPLATE = _CONFIG["claude"]["prompt_template"]
LANGUAGE = _CONFIG.get("language", "english")
LOCAL_TZ = timezone(timedelta(hours=_CONFIG.get("timezone_offset_hours", 0)))
HISTORY_FILE = os.path.expanduser("~/.betterstack-bridge/history.log")

# ============================================
# RESOURCES (built from services config + env)
# ============================================

# Map of "service key" → BS status-page resource ID. Each service key in
# services.json reads its ID from env var BS_RESOURCE_<KEY_UPPER>.
RESOURCES = {
    key: os.environ.get(f"BS_RESOURCE_{key.upper()}", "REPLACE_WITH_RESOURCE_ID")
    for key in _CONFIG["services"].keys()
}
# Display name (used in incident messages) keyed by RESOURCES values
RESOURCE_NAMES = {
    RESOURCES[k]: v for k, v in _CONFIG["resource_names_in_message"].items()
}
RESOURCE_DISPLAY = [(k, v) for k, v in _CONFIG["services"].items()]

# Map: prometheus container/instance label  →  status-page resource key.
# Edit grafana_map in services.json to fit your fleet's naming convention.
GRAFANA_MAP = dict(_CONFIG["grafana_map"])

# BetterStack monitor/heartbeat name → status page resource key.
# Substring match (case-insensitive) on the `name` field. Edit
# betterstack_monitor_map in services.json.
BS_MONITOR_MAP = [tuple(pair) for pair in _CONFIG["betterstack_monitor_map"]]

# Names containing any of these substrings are dropped — protects status page
# from accidental triggers (own smoke tests, scanners, etc).
PROBE_GUARD_SUBSTRINGS = tuple(_CONFIG.get(
    "probe_guard_substrings",
    ["test", "smoke", "probe", "synthetic", "dummy", "ignore"],
))

# ============================================
# INCIDENT TYPES + LIFECYCLE
# ============================================

INCIDENT_TYPES = [tuple(pair) for pair in _CONFIG["incident_types"]]
TYPE_TO_STATUS = dict(_CONFIG["type_to_status"])
LIFECYCLE_UPDATES = [tuple(pair) for pair in _CONFIG["lifecycle_updates"]]

# ============================================
# TITLES + FALLBACK TEMPLATES
# ============================================

TITLES = dict(_CONFIG["titles"])
FALLBACK = dict(_CONFIG["fallback_messages"])

# ============================================
# ESTADO
# ============================================

active_reports = {}
STATE_FILE = os.path.expanduser("~/.betterstack-bridge/state.json")
_interactive_mode = False


def load_state():
    global active_reports
    try:
        with open(STATE_FILE) as f:
            active_reports = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        active_reports = {}


def save_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(active_reports, f, indent=2)
    except Exception as e:
        logging.error(f"Error guardando estado: {e}")


def sname(rid):
    return RESOURCE_NAMES.get(rid, _CONFIG.get("default_service_display_message", "our services"))


_LIST_SEP = _CONFIG.get("list_separator", " y ")  # " and " in English, " y " in Spanish, etc.


def join_names(rids):
    """Join service display-message names: 'A and B' or 'A, B and C'."""
    names = [sname(r) for r in rids]
    if len(names) == 1:
        return names[0]
    elif len(names) == 2:
        return f"{names[0]}{_LIST_SEP}{names[1]}"
    else:
        return ", ".join(names[:-1]) + f"{_LIST_SEP}{names[-1]}"


def join_display_names(service_keys):
    """Join service display labels with the configured list separator."""
    names = []
    display_map = dict(RESOURCE_DISPLAY)
    for k in service_keys:
        names.append(display_map.get(k, k))
    if len(names) == 1:
        return names[0]
    elif len(names) == 2:
        return f"{names[0]}{_LIST_SEP}{names[1]}"
    else:
        return ", ".join(names[:-1]) + f"{_LIST_SEP}{names[-1]}"


def log_history(msg):
    """Escribe en el historial"""
    try:
        ts = datetime.now(LOCAL_TZ).strftime("%d/%m/%Y %H:%M")
        with open(HISTORY_FILE, "a") as f:
            f.write(f"{ts} — {msg}\n")
    except Exception:
        pass


def format_duration(minutes):
    """Formatea minutos a texto legible: '30 minutos', '1 hora', '1 hora y 30 minutos'"""
    if minutes < 60:
        return f"{minutes} minuto{'s' if minutes != 1 else ''}"
    hours = minutes // 60
    mins = minutes % 60
    h_str = f"{hours} hora{'s' if hours != 1 else ''}"
    if mins == 0:
        return h_str
    m_str = f"{mins} minuto{'s' if mins != 1 else ''}"
    return f"{h_str} y {m_str}"


def parse_duration(text):
    """Parsea duración: '30m', '1h', '2h30m', '1h 30m', '90m' → minutos"""
    text = text.strip().lower().replace(" ", "")
    total = 0
    h_match = re.search(r'(\d+)h', text)
    m_match = re.search(r'(\d+)m', text)
    if h_match:
        total += int(h_match.group(1)) * 60
    if m_match:
        total += int(m_match.group(1))
    if not h_match and not m_match:
        # Solo número: asumir minutos
        try:
            total = int(text)
        except ValueError:
            return None
    return total if total > 0 else None


def local_now():
    return datetime.now(LOCAL_TZ)


# ============================================
# CLAUDE CODE
# ============================================

CLAUDE_CONTEXTS = dict(_CONFIG["claude_contexts"])


def generate_message(service_name, status, context="", duration_str=""):
    """Generate a status-page message via Claude. Falls back to a deterministic
    template if Claude is unavailable."""
    base_ctx = CLAUDE_CONTEXTS.get(status, "")
    extra = ""
    if context:
        extra = f" Additional context: {context}."
    if duration_str:
        extra += f" Estimated duration: {duration_str}."

    prompt = CLAUDE_PROMPT_TEMPLATE.format(
        service_name=service_name,
        base_ctx=base_ctx,
        extra=extra,
        language=LANGUAGE,
    )

    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--model", CLAUDE_MODEL],
            capture_output=True, text=True, timeout=CLAUDE_TIMEOUT,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except subprocess.TimeoutExpired:
        if not _interactive_mode:
            logging.warning("Claude timeout, using fallback")
    except Exception as e:
        if not _interactive_mode:
            logging.warning(f"Claude error: {e}")

    fb = FALLBACK.get(status, FALLBACK["downtime"])
    return fb.format(s=service_name)


# ============================================
# BETTER STACK API
# ============================================

def bs_api(method, path, data=None):
    url = f"https://uptime.betterstack.com/api/v2/status-pages/{STATUS_PAGE_ID}/{path}"
    headers = {"Authorization": f"Bearer {BETTERSTACK_TOKEN}", "Content-Type": "application/json"}
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        if resp.status == 204:
            return {"ok": True}
        return json.loads(resp.read()) if resp.status in (200, 201) else None
    except urllib.error.HTTPError as e:
        err = e.read().decode(errors="replace")[:300]
        if not _interactive_mode:
            logging.error(f"BS API {e.code}: {err}")
        else:
            logging.debug(f"BS API {e.code}: {err}")
        return None
    except Exception as e:
        if not _interactive_mode:
            logging.error(f"BS API error: {e}")
        return None


def bs_delete(path):
    url = f"https://uptime.betterstack.com/api/v2/status-pages/{STATUS_PAGE_ID}/{path}"
    headers = {"Authorization": f"Bearer {BETTERSTACK_TOKEN}"}
    req = urllib.request.Request(url, headers=headers, method="DELETE")
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return resp.status == 204
    except Exception:
        return False


# ============================================
# INCIDENCIAS
# ============================================

def create_incident(resource_ids, incident_type="downtime", context="", message_override=None):
    """Crea una incidencia que afecta a uno o más recursos"""
    # Verificar si ya hay reporte para alguno de estos recursos
    for rid in resource_ids:
        if rid in active_reports:
            return active_reports[rid].get("report_id")

    names = join_names(resource_ids)

    if len(resource_ids) == len(RESOURCES):
        title = TITLES.get("incident_all", "Interrupciones en la plataforma")
    else:
        title = TITLES.get(incident_type, TITLES["downtime"]).format(s=names)

    if message_override:
        message = message_override
    else:
        message = generate_message(names, incident_type, context)

    bs_status = TYPE_TO_STATUS.get(incident_type, "degraded")
    data = {
        "title": title, "message": message, "report_type": "manual",
        "affected_resources": [{"status_page_resource_id": r, "status": bs_status} for r in resource_ids],
    }
    result = bs_api("POST", "status-reports", data)
    if result:
        rid = result["data"]["id"]
        created_at = local_now().isoformat()
        for r in resource_ids:
            active_reports[r] = {"report_id": rid, "type": incident_type, "title": title, "created_at": created_at, "resources": resource_ids}
        save_state()
        log_history(f"Incidencia creada #{rid}: {title}")
        return rid
    return None


def update_incident(resource_id, lifecycle_status, context="", message_override=None):
    rd = active_reports.get(resource_id)
    if not rd:
        return False

    rids = rd.get("resources", [resource_id])
    names = join_names(rids)

    if message_override:
        message = message_override
    else:
        message = generate_message(names, lifecycle_status, context)

    bs_status = "degraded" if lifecycle_status == "monitoring" else TYPE_TO_STATUS.get(rd["type"], "degraded")
    data = {
        "message": message,
        "affected_resources": [{"status_page_resource_id": r, "status": bs_status} for r in rids],
    }
    result = bs_api("POST", f"status-reports/{rd['report_id']}/status-updates", data)
    if result:
        label = dict(LIFECYCLE_UPDATES).get(lifecycle_status, lifecycle_status)
        log_history(f"Incidencia actualizada #{rd['report_id']}: {label} — {names}")
        return True
    return False


def resolve_incident(resource_id, context="", message_override=None):
    rd = active_reports.get(resource_id)
    if not rd:
        return False

    rids = rd.get("resources", [resource_id])
    names = join_names(rids)

    if message_override:
        message = message_override
    else:
        message = generate_message(names, "resolved", context)

    data = {
        "message": message,
        "affected_resources": [{"status_page_resource_id": r, "status": "resolved"} for r in rids],
    }
    result = bs_api("POST", f"status-reports/{rd['report_id']}/status-updates", data)
    if result:
        report_id = rd["report_id"]
        for r in rids:
            active_reports.pop(r, None)
        save_state()
        log_history(f"Incidencia resuelta #{report_id}: {names}")
        return True
    return False


# ============================================
# MANTENIMIENTO
# ============================================

def create_maintenance(service_keys, starts_at_iso, ends_at_iso, duration_str="", context="", message_override=None):
    """Crea mantenimiento. starts_at y ends_at en ISO 8601."""
    if "all" in service_keys:
        rids = list(RESOURCES.values())
        title = TITLES["maint_all"]
        names = "toda la plataforma"
    else:
        rids = [RESOURCES[k] for k in service_keys if k in RESOURCES]
        if not rids:
            return None
        names = join_names(rids)
        title = TITLES["maintenance"].format(s=names) if len(rids) == 1 else f"Mantenimiento programado en {names}"

    if message_override:
        message = message_override
    else:
        message = generate_message(names, "maintenance", context, duration_str)

    data = {
        "title": title, "message": message, "report_type": "maintenance",
        "starts_at": starts_at_iso,
        "ends_at": ends_at_iso,
        "affected_resources": [{"status_page_resource_id": r, "status": "maintenance"} for r in rids],
    }

    result = bs_api("POST", "status-reports", data)
    if result:
        rid = result["data"]["id"]
        active_reports["maintenance"] = {
            "report_id": rid, "type": "maintenance", "resources": rids,
            "starts_at": starts_at_iso, "ends_at": ends_at_iso, "title": title,
        }
        save_state()
        log_history(f"Mantenimiento creado #{rid}: {title}")
        return rid
    return None


def update_maintenance(maint_status="maint_update", context="", message_override=None):
    m = active_reports.get("maintenance")
    if not m:
        return False

    names = join_names(m["resources"])

    if message_override:
        message = message_override
    else:
        message = generate_message(names, maint_status, context)

    data = {
        "message": message,
        "affected_resources": [{"status_page_resource_id": r, "status": "maintenance"} for r in m["resources"]],
    }
    result = bs_api("POST", f"status-reports/{m['report_id']}/status-updates", data)
    if result:
        log_history(f"Mantenimiento actualizado #{m['report_id']}: {maint_status}")
        return True
    return False


def end_maintenance(context="", message_override=None):
    m = active_reports.get("maintenance")
    if not m:
        return False

    names = join_names(m["resources"])

    if message_override:
        message = message_override
    else:
        message = generate_message(names, "maint_end", context)

    data = {
        "message": message,
        "affected_resources": [{"status_page_resource_id": r, "status": "resolved"} for r in m["resources"]],
    }
    result = bs_api("POST", f"status-reports/{m['report_id']}/status-updates", data)
    if result:
        report_id = m["report_id"]
        del active_reports["maintenance"]
        save_state()
        log_history(f"Mantenimiento finalizado #{report_id}")
        return True
    return False


def cancel_maintenance():
    m = active_reports.get("maintenance")
    if not m:
        return False
    ok = bs_delete(f"status-reports/{m['report_id']}")
    if ok:
        report_id = m["report_id"]
        del active_reports["maintenance"]
        save_state()
        log_history(f"Mantenimiento cancelado #{report_id}")
        return True
    return False


def is_maintenance_started():
    """Comprueba si el mantenimiento programado ya ha empezado"""
    m = active_reports.get("maintenance")
    if not m:
        return False
    starts = m.get("starts_at", "")
    if not starts:
        return True  # Si no tiene starts_at, asumimos que empezó
    try:
        start_dt = datetime.fromisoformat(starts)
        return datetime.now(LOCAL_TZ) >= start_dt
    except Exception:
        return True


# ============================================
# MENÚ INTERACTIVO
# ============================================

def clear():
    os.system("clear" if os.name != "nt" else "cls")


def ask_multi(prompt, options, allow_all=True):
    """Selector con opción de elegir varios separados por coma o espacio"""
    print()
    for i, (_, label) in enumerate(options, 1):
        print(f"  {i}. {label}")
    if allow_all:
        print(f"  {len(options) + 1}. Todos los servicios")
    print(f"  0. Volver")
    print()

    while True:
        try:
            raw = input(f"{prompt} → ").strip()
            if raw == "0":
                return None

            if allow_all and raw == str(len(options) + 1):
                return ["all"]

            # Aceptar comas, espacios o ambos
            parts = re.split(r'[,\s]+', raw)
            indices = [int(p) - 1 for p in parts if p.isdigit()]

            if all(0 <= i < len(options) for i in indices) and indices:
                return [options[i][0] for i in indices]
        except (ValueError, EOFError):
            pass
        print("  Opción no válida. Usa números separados por coma: 1,3")


def ask_single(prompt, options, allow_back=True):
    """Selector de una opción"""
    print()
    for i, (_, label) in enumerate(options, 1):
        print(f"  {i}. {label}")
    if allow_back:
        print(f"  0. Volver")
    print()

    while True:
        try:
            raw = input(f"{prompt} → ").strip()
            if raw == "0" and allow_back:
                return None
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return options[idx][0]
        except (ValueError, EOFError):
            pass
        print("  Opción no válida")


def ask_context():
    """Pide contexto adicional o mensaje manual"""
    print()
    print("¿Contexto adicional? (Enter para automático, ! para mensaje manual)")
    raw = input("→ ").strip()
    if not raw:
        return "", False
    if raw.startswith("!"):
        return raw[1:].strip(), True
    return raw, False


def ask_confirm(summary):
    """Muestra resumen y pide confirmación"""
    print()
    for line in summary:
        print(f"  {line}")
    print()
    while True:
        raw = input("¿Publicar? (s/n) → ").strip().lower()
        if raw in ("s", "si", "sí", "y", "yes"):
            return True
        if raw in ("n", "no"):
            return False


def parse_time_input(raw):
    """Parsea hora: 5pm, 5:38pm, 17, 17:42, 10am, 10:49am, etc."""
    raw = raw.strip().lower().replace(" ", "")
    is_pm = "pm" in raw
    is_am = "am" in raw
    raw = raw.replace("pm", "").replace("am", "")

    if ":" in raw:
        parts = raw.split(":")
        h, m = int(parts[0]), int(parts[1])
    else:
        h, m = int(raw), 0

    if is_pm and h != 12:
        h += 12
    if is_am and h == 12:
        h = 0

    # Si no especificó am/pm y la hora es 1-12, preguntar
    if not is_am and not is_pm and 1 <= h <= 12:
        while True:
            ampm = input(f"  ¿{h}:{m:02d} AM o PM? → ").strip().lower()
            if ampm in ("am", "a"):
                if h == 12:
                    h = 0
                break
            elif ampm in ("pm", "p"):
                if h != 12:
                    h += 12
                break
            print("  Escribe AM o PM")

    if 0 <= h <= 23 and 0 <= m <= 59:
        return h, m
    return None, None


def ask_time_full():
    """Pide día y hora completos, devuelve datetime"""
    now = local_now()
    print(f"\n  Fecha actual: {now.strftime('%d/%m/%Y %H:%M')} (hora España)")
    print()

    while True:
        try:
            day = int(input("  Día → ").strip())
            if 1 <= day <= 31:
                break
        except (ValueError, EOFError):
            pass
        print("  Día no válido (1-31)")

    while True:
        raw = input("  Hora (ej: 5pm, 10am, 14:00, 17:42) → ").strip()
        h, m = parse_time_input(raw)
        if h is not None:
            break
        print("  Formato no válido. Ejemplos: 5pm, 10am, 14:00, 17:42")

    year, month = now.year, now.month
    if day < now.day:
        month += 1
        if month > 12:
            month = 1
            year += 1

    return datetime(year, month, day, h, m, 0, tzinfo=LOCAL_TZ)


def ask_duration():
    """Pide duración estimada"""
    while True:
        raw = input("Duración estimada (ej: 30m, 1h, 2h30m) → ").strip()
        mins = parse_duration(raw)
        if mins:
            return mins
        print("  Formato no válido. Ejemplos: 30m, 1h, 2h30m, 90m")


def time_ago(iso_str):
    """Calcula 'hace X min' desde un ISO string"""
    try:
        created = datetime.fromisoformat(iso_str)
        diff = local_now() - created
        mins = int(diff.total_seconds() / 60)
        if mins < 1:
            return "hace menos de 1 min"
        elif mins < 60:
            return f"hace {mins} min"
        else:
            hours = mins // 60
            remaining = mins % 60
            if remaining == 0:
                return f"hace {hours}h"
            return f"hace {hours}h {remaining}min"
    except Exception:
        return ""


# ============================================
# MENÚ: INCIDENCIAS
# ============================================

def menu_create_incident():
    services = ask_multi("Servicio (separados por coma: 1,3)", RESOURCE_DISPLAY)
    if not services:
        return

    inc_type = ask_single("Tipo de incidencia", INCIDENT_TYPES)
    if not inc_type:
        return

    context, is_manual = ask_context()

    if "all" in services:
        rids = list(RESOURCES.values())
    else:
        rids = [RESOURCES[s] for s in services if s in RESOURCES]

    names = join_names(rids) if "all" not in services else "toda la plataforma"
    display_names = "Todos" if "all" in services else join_display_names(services)
    type_label = dict(INCIDENT_TYPES).get(inc_type, inc_type)

    if len(rids) == len(RESOURCES) or "all" in services:
        title = TITLES.get("incident_all", "Interrupciones en la plataforma")
    else:
        title = TITLES.get(inc_type, TITLES["downtime"]).format(s=names)

    print("\n  Generando mensaje...")
    if is_manual:
        message = context
    else:
        message = generate_message(names, inc_type, context)

    summary = [
        f"Servicios: {display_names}",
        f"Tipo:      {type_label}",
        f"Título:    {title}",
        f"Mensaje:   {message}",
    ]
    if not ask_confirm(summary):
        print("  Cancelado")
        return

    result = create_incident(rids, inc_type, context if not is_manual else "", message if is_manual else None)
    if result:
        print(f"  ✅ Incidencia #{result} creada")
    else:
        print(f"  ❌ Error creando incidencia")


def menu_update_incident():
    # Encontrar incidencias únicas (por report_id)
    seen = {}
    for k, d in active_reports.items():
        if k == "maintenance":
            continue
        rid = d.get("report_id")
        if rid not in seen:
            rids = d.get("resources", [k])
            names = join_names(rids)
            type_label = dict(INCIDENT_TYPES).get(d.get("type", ""), d.get("type", "?"))
            ago = time_ago(d.get("created_at", ""))
            seen[rid] = {"rids": rids, "label": f"{names} — {type_label} ({ago})", "first_rid": k}

    if not seen:
        print("\n  No hay incidencias activas")
        return

    opts = [(data["first_rid"], data["label"]) for data in seen.values()]
    rid = ask_single("Incidencia a actualizar", opts)
    if not rid:
        return

    lifecycle = ask_single("Estado del ciclo de vida", LIFECYCLE_UPDATES)
    if not lifecycle:
        return

    context, is_manual = ask_context()

    print("\n  Generando mensaje...")
    rd = active_reports[rid]
    rids = rd.get("resources", [rid])
    names = join_names(rids)

    if is_manual:
        message = context
    else:
        message = generate_message(names, lifecycle, context)

    lifecycle_label = dict(LIFECYCLE_UPDATES).get(lifecycle, lifecycle)
    summary = [
        f"Incidencia: {rd.get('title', '?')}",
        f"Estado:     {lifecycle_label}",
        f"Mensaje:    {message}",
    ]
    if not ask_confirm(summary):
        print("  Cancelado")
        return

    if update_incident(rid, lifecycle, context if not is_manual else "", message if is_manual else None):
        print(f"  ✅ Actualizada — {names} ({lifecycle_label})")
    else:
        print(f"  ❌ Error actualizando")


def menu_resolve_incident():
    seen = {}
    for k, d in active_reports.items():
        if k == "maintenance":
            continue
        rid = d.get("report_id")
        if rid not in seen:
            rids = d.get("resources", [k])
            names = join_names(rids)
            type_label = dict(INCIDENT_TYPES).get(d.get("type", ""), d.get("type", "?"))
            ago = time_ago(d.get("created_at", ""))
            seen[rid] = {"rids": rids, "label": f"{names} — {type_label} ({ago})", "first_rid": k, "title": d.get("title", "?"), "ago": ago}

    if not seen:
        print("\n  No hay incidencias activas")
        return

    opts = [(data["first_rid"], data["label"]) for data in seen.values()]
    if len(opts) > 1:
        opts.append(("__all__", "Todas las incidencias"))

    rid = ask_single("Incidencia a resolver", opts)
    if not rid:
        return

    context, is_manual = ask_context()

    if rid == "__all__":
        # Resolver todas
        items = list(seen.values())
        print("\n  Generando mensajes de resolución...")

        resolve_list = []
        for item in items:
            rids = item["rids"]
            names = join_names(rids)
            if is_manual:
                msg = context
            else:
                msg = generate_message(names, "resolved", context)
            resolve_list.append({"first_rid": item["first_rid"], "names": names, "title": item["title"], "ago": item["ago"], "message": msg})

        summary = [f"Vas a resolver {len(resolve_list)} incidencia(s):"]
        for r in resolve_list:
            summary.append(f"  - {r['title']} ({r['ago']})")
            summary.append(f"    Mensaje: {r['message']}")

        if not ask_confirm(summary):
            print("  Cancelado")
            return

        for r in resolve_list:
            if resolve_incident(r["first_rid"], context if not is_manual else "", r["message"] if is_manual else None):
                print(f"  ✅ Resuelta — {r['names']}")
            else:
                print(f"  ❌ Error resolviendo — {r['names']}")
    else:
        rd = active_reports[rid]
        rids = rd.get("resources", [rid])
        names = join_names(rids)

        print("\n  Generando mensaje de resolución...")
        if is_manual:
            message = context
        else:
            message = generate_message(names, "resolved", context)

        summary = [
            f"Vas a resolver: {rd.get('title', '?')} ({time_ago(rd.get('created_at', ''))})",
            f"Mensaje:        {message}",
        ]
        if not ask_confirm(summary):
            print("  Cancelado")
            return

        if resolve_incident(rid, context if not is_manual else "", message if is_manual else None):
            print(f"  ✅ Resuelta — {names}")
        else:
            print(f"  ❌ Error resolviendo")


# ============================================
# MENÚ: MANTENIMIENTO
# ============================================

def menu_create_maintenance():
    if "maintenance" in active_reports:
        print(f"\n  ⚠️  Ya hay un mantenimiento activo: {active_reports['maintenance'].get('title', '?')}")
        print("  Finalízalo o cancélalo antes de crear otro.")
        return

    services = ask_multi("Servicio (separados por coma: 1,3)", RESOURCE_DISPLAY)
    if not services:
        return

    when = ask_single("¿Cuándo?", [("now", "Ahora mismo"), ("scheduled", "Programar fecha/hora")])
    if not when:
        return

    if when == "now":
        start_dt = local_now()
    else:
        start_dt = ask_time_full()

    duration_mins = ask_duration()
    end_dt = start_dt + timedelta(minutes=duration_mins)
    duration_str = format_duration(duration_mins)

    context, is_manual = ask_context()

    if "all" in services:
        rids = list(RESOURCES.values())
        display = "Todos"
        names = "toda la plataforma"
    else:
        rids = [RESOURCES[s] for s in services if s in RESOURCES]
        display = join_display_names(services)
        names = join_names(rids)

    if len(rids) == len(RESOURCES) or "all" in services:
        title = TITLES["maint_all"]
    else:
        title = TITLES["maintenance"].format(s=names) if len(rids) == 1 else f"Mantenimiento programado en {names}"

    starts_iso = start_dt.isoformat()
    ends_iso = end_dt.isoformat()

    print("\n  Generando mensaje...")
    if is_manual:
        message = context
    else:
        message = generate_message(names, "maintenance", context, duration_str)

    if when == "now":
        time_display = "Ahora"
    else:
        time_display = start_dt.strftime("%d/%m/%Y a las %H:%M") + " (hora España)"

    summary = [
        f"Servicios: {display}",
        f"Inicio:    {time_display}",
        f"Fin:       {end_dt.strftime('%d/%m/%Y a las %H:%M')} (hora España)",
        f"Duración:  {duration_str}",
        f"Título:    {title}",
        f"Mensaje:   {message}",
    ]
    if not ask_confirm(summary):
        print("  Cancelado")
        return

    svcs = list(RESOURCES.keys()) if "all" in services else services
    result = create_maintenance(svcs, starts_iso, ends_iso, duration_str, context if not is_manual else "", message if is_manual else None)
    if result:
        if when == "scheduled":
            print(f"  ✅ Mantenimiento #{result} programado para {start_dt.strftime('%d/%m/%Y %H:%M')}")
        else:
            print(f"  ✅ Mantenimiento #{result} creado")
    else:
        print(f"  ❌ Error creando mantenimiento")


def menu_update_maintenance():
    if "maintenance" not in active_reports:
        print("\n  No hay mantenimiento activo")
        return

    m = active_reports["maintenance"]

    # Comprobar si ya expiró
    ends = m.get("ends_at", "")
    if ends:
        try:
            end_dt = datetime.fromisoformat(ends)
            if local_now() > end_dt:
                del active_reports["maintenance"]
                save_state()
                print("\n  ℹ️  El mantenimiento ya finalizó automáticamente (hora de fin alcanzada).")
                return
        except Exception:
            pass

    if not is_maintenance_started():
        starts = m.get("starts_at", "?")
        try:
            start_dt = datetime.fromisoformat(starts)
            start_str = start_dt.strftime("%d/%m/%Y %H:%M")
        except Exception:
            start_str = starts
        print(f"\n  ⚠️  El mantenimiento aún no ha iniciado (programado para {start_str}).")
        print("  No es posible actualizarlo hasta que comience.")
        return

    mtype = ask_single("Tipo de actualización", [
        ("maint_update",   "En curso (update normal)"),
        ("maint_extended", "Se está extendiendo"),
    ])
    if not mtype:
        return

    context, is_manual = ask_context()

    print("\n  Generando mensaje...")
    names = join_names(m["resources"])
    if is_manual:
        message = context
    else:
        message = generate_message(names, mtype, context)

    summary = [
        f"Mantenimiento: {m.get('title', '?')}",
        f"Mensaje:       {message}",
    ]
    if not ask_confirm(summary):
        print("  Cancelado")
        return

    if update_maintenance(mtype, context if not is_manual else "", message if is_manual else None):
        print("  ✅ Mantenimiento actualizado")
    else:
        print("  ❌ Error actualizando")


def menu_end_maintenance():
    if "maintenance" not in active_reports:
        print("\n  No hay mantenimiento activo")
        return

    m = active_reports["maintenance"]

    # Comprobar si ya expiró
    ends = m.get("ends_at", "")
    if ends:
        try:
            end_dt = datetime.fromisoformat(ends)
            if local_now() > end_dt:
                del active_reports["maintenance"]
                save_state()
                print("\n  ℹ️  El mantenimiento ya finalizó automáticamente (hora de fin alcanzada).")
                return
        except Exception:
            pass

    if not is_maintenance_started():
        starts = m.get("starts_at", "?")
        try:
            start_dt = datetime.fromisoformat(starts)
            start_str = start_dt.strftime("%d/%m/%Y %H:%M")
        except Exception:
            start_str = starts
        print(f"\n  ⚠️  El mantenimiento aún no ha iniciado (programado para {start_str}).")
        while True:
            raw = input("  ¿Deseas cancelarlo? (s/n) → ").strip().lower()
            if raw in ("s", "si", "sí", "y"):
                if cancel_maintenance():
                    print("  ✅ Mantenimiento cancelado")
                else:
                    print("  ❌ Error cancelando")
                return
            if raw in ("n", "no"):
                return

    context, is_manual = ask_context()

    print("\n  Generando mensaje de finalización...")
    names = join_names(m["resources"])
    if is_manual:
        message = context
    else:
        message = generate_message(names, "maint_end", context)

    summary = [
        f"Mantenimiento: {m.get('title', '?')}",
        f"Mensaje:       {message}",
    ]
    if not ask_confirm(summary):
        print("  Cancelado")
        return

    if end_maintenance(context if not is_manual else "", message if is_manual else None):
        print("  ✅ Mantenimiento finalizado")
    else:
        print("  ❌ Error finalizando")


def menu_status():
    print()
    if not active_reports:
        print("  ✅ No hay incidencias ni mantenimientos activos")
    else:
        seen_reports = set()
        for k, d in active_reports.items():
            if k == "maintenance":
                svcs = join_names(d["resources"])
                started = "en curso" if is_maintenance_started() else "programado"
                print(f"  🔧 Mantenimiento #{d['report_id']} ({started}): {svcs}")
            else:
                rid = d.get("report_id")
                if rid in seen_reports:
                    continue
                seen_reports.add(rid)
                rids = d.get("resources", [k])
                names = join_names(rids)
                tipo = dict(INCIDENT_TYPES).get(d.get("type", ""), d.get("type", "?"))
                ago = time_ago(d.get("created_at", ""))
                print(f"  🔴 Incidencia #{rid}: {names} — {tipo} ({ago})")
    print()


def menu_history():
    print()
    try:
        with open(HISTORY_FILE) as f:
            lines = f.readlines()
        if not lines:
            print("  No hay historial")
        else:
            for line in lines[-20:]:  # Últimas 20 entradas
                print(f"  {line.rstrip()}")
    except FileNotFoundError:
        print("  No hay historial")
    print()


def interactive():
    global _interactive_mode
    _interactive_mode = True
    load_state()

    MAIN_MENU = [
        ("incident",     "Reportar incidencia"),
        ("update",       "Actualizar incidencia activa"),
        ("resolve",      "Resolver incidencia"),
        ("maintenance",  "Iniciar mantenimiento"),
        ("maint_update", "Actualizar mantenimiento"),
        ("maint_end",    "Finalizar mantenimiento"),
        ("status",       "Ver estado actual"),
        ("history",      "Ver historial"),
        ("exit",         "Salir"),
    ]

    while True:
        # Auto-limpiar mantenimientos expirados
        if "maintenance" in active_reports:
            m = active_reports["maintenance"]
            ends = m.get("ends_at", "")
            if ends:
                try:
                    end_dt = datetime.fromisoformat(ends)
                    if local_now() > end_dt:
                        del active_reports["maintenance"]
                        save_state()
                        log_history(f"Mantenimiento #{m.get('report_id', '?')} auto-finalizado (hora de fin alcanzada)")
                except Exception:
                    pass

        clear()
        print("╔═══════════════════════════════════════════╗")
        print("║  Better Stack Status Bridge               ║")
        print("╚═══════════════════════════════════════════╝")

        # Mostrar estado si hay algo activo
        active_incidents = set()
        for k, d in active_reports.items():
            if k != "maintenance":
                active_incidents.add(d.get("report_id"))
        maint_active = "maintenance" in active_reports

        if active_incidents or maint_active:
            print()
            if active_incidents:
                print(f"  ⚠️  {len(active_incidents)} incidencia(s) activa(s)")
            if maint_active:
                started = "en curso" if is_maintenance_started() else "programado"
                print(f"  🔧 Mantenimiento {started}")

        choice = ask_single("¿Qué deseas hacer?", MAIN_MENU, allow_back=False)

        if choice is None or choice == "exit":
            print("\n  👋 Hasta luego")
            break
        elif choice == "incident":
            menu_create_incident()
        elif choice == "update":
            menu_update_incident()
        elif choice == "resolve":
            menu_resolve_incident()
        elif choice == "maintenance":
            menu_create_maintenance()
        elif choice == "maint_update":
            menu_update_maintenance()
        elif choice == "maint_end":
            menu_end_maintenance()
        elif choice == "status":
            menu_status()
        elif choice == "history":
            menu_history()

        input("\n  Pulsa Enter para continuar...")


# ============================================
# GRAFANA WEBHOOK (modo servidor)
# ============================================

_INSTANCE_IGNORE_SUBSTRINGS = tuple(_CONFIG.get("instance_ignore_substrings", ["staging"]))
_DEFAULT_SERVICE_KEY = _CONFIG.get("default_service_key", next(iter(_CONFIG["services"].keys())))


def extract_service(alert):
    labels = alert.get("labels", {})
    instance = labels.get("instance", "")
    # Drop alerts from instances that match the ignore list (e.g. staging,
    # canary). Configurable via instance_ignore_substrings in services.json.
    if any(skip in instance for skip in _INSTANCE_IGNORE_SUBSTRINGS):
        return None

    for field in ("container", "instance"):
        val = labels.get(field, "")
        if val in GRAFANA_MAP:
            return GRAFANA_MAP[val]
    job = labels.get("job", "")
    for key, svc in GRAFANA_MAP.items():
        if key in job:
            return svc
    return _DEFAULT_SERVICE_KEY


def grafana_severity(alert):
    labels = alert.get("labels", {})
    sev = labels.get("severity", "").lower()
    name = labels.get("alertname", "").lower()
    if sev == "critical" or "down" in name:
        return "downtime"
    if any(kw in name for kw in ("cpu", "ram", "disk", "gpu", "redis", "postgres", "memory")):
        return "capacity"
    return "degraded"


def map_bs_name_to_resource(name):
    if not name:
        return None
    low = name.lower()
    # Refuse any name that looks like a probe/test — protects the public status
    # page from accidental triggers (own smoke tests, scanners, etc.)
    for guard in PROBE_GUARD_SUBSTRINGS:
        if guard in low:
            return None
    for needle, key in BS_MONITOR_MAP:
        if needle in low:
            return key
    return None


def handle_betterstack_payload(payload):
    """BetterStack outbound webhook → genera mensaje Claude → crea/resuelve incidencia status page.

    Soporta dos formatos comunes de BS:
      - JSON:API: {"data": {"attributes": {"name", "cause", "started_at", "resolved_at"}}}
      - Plano:    {"name", "cause", "started_at", "resolved_at"}
    """
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, dict) and isinstance(data.get("attributes"), dict):
        attrs = data["attributes"]
    else:
        attrs = payload if isinstance(payload, dict) else {}

    name = attrs.get("name") or attrs.get("monitor_name") or ""
    cause = attrs.get("cause") or ""
    resolved_at = attrs.get("resolved_at")
    acknowledged_at = attrs.get("acknowledged_at")

    svc = map_bs_name_to_resource(name)
    if not svc:
        logging.warning(f"BS webhook: no resource match for name={name!r}")
        return False
    rid = RESOURCES[svc]

    # Resolved → cerrar si tenemos incidencia activa
    if resolved_at:
        if rid in active_reports:
            resolve_incident(rid, context=f"BetterStack: {name} recuperado")
            log_history(f"BS webhook resolved: {name} → {svc}")
            return True
        logging.info(f"BS webhook resolved pero no había incidencia activa para {svc}")
        return False

    # Firing/acknowledged → crear si no hay activa
    if rid in active_reports:
        logging.info(f"BS webhook firing pero {svc} ya tiene incidencia activa, ignorado")
        return False

    ctx = f"Detectado por BetterStack ({name})."
    if cause:
        ctx += f" Causa: {cause}."
    create_incident([rid], "downtime", context=ctx)
    log_history(f"BS webhook firing: {name} → {svc}")
    return True


class WebhookHandler(BaseHTTPRequestHandler):
    def _check_bs_token(self):
        """Return True if the inbound request carries the expected secret."""
        if not BS_INBOUND_TOKEN:
            # No token configured → reject all /betterstack POSTs by default.
            return False
        # Header form: X-Bridge-Token: <secret>
        header_token = self.headers.get("X-Bridge-Token", "")
        if header_token == BS_INBOUND_TOKEN:
            return True
        # Query-string form: /betterstack?token=<secret>
        if "?" in self.path:
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            if qs.get("token", [""])[0] == BS_INBOUND_TOKEN:
                return True
        return False

    def do_POST(self):
        try:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            payload = json.loads(body)

            if self.path.startswith("/betterstack"):
                if not self._check_bs_token():
                    logging.warning(
                        f"/betterstack rejected: missing or invalid token (path={self.path})"
                    )
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'{"error":"unauthorized"}')
                    return
                handle_betterstack_payload(payload)
            else:
                for alert in payload.get("alerts", []):
                    status = alert.get("status", "")
                    svc = extract_service(alert)
                    if not svc:
                        continue  # alert from an ignored instance
                    rid = RESOURCES.get(svc, RESOURCES.get(_DEFAULT_SERVICE_KEY))

                    if status == "firing" and rid not in active_reports:
                        create_incident([rid], grafana_severity(alert))
                    elif status == "resolved" and rid in active_reports:
                        resolve_incident(rid)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        except Exception as e:
            logging.error(f"Webhook error: {e}", exc_info=True)
            self.send_response(500)
            self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "active_reports": active_reports}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    log_level = logging.DEBUG if "--verbose" in sys.argv else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    if len(sys.argv) > 1 and sys.argv[1] in ("serve", "server"):
        load_state()
        httpd = HTTPServer((LISTEN_HOST, LISTEN_PORT), WebhookHandler)
        logging.info(f"Bridge en {LISTEN_HOST}:{LISTEN_PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()
    else:
        interactive() 
