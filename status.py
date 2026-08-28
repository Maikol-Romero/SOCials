#!/usr/bin/env python3
"""
SOCials — Estado del Sistema
Muestra el estado de todas las máquinas, servicios y alertas de un vistazo.

Uso: python3 status.sh  o  ./status.sh
"""

import json, os, subprocess, sys, urllib.request, urllib.error, base64

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INVENTORY = os.path.join(SCRIPT_DIR, "inventory.json")
ENV_FILE = os.path.join(SCRIPT_DIR, "monitor", "observability", ".env")

class C:
    RED = '\033[0;31m'; GREEN = '\033[0;32m'; YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'; BOLD = '\033[1m'; NC = '\033[0m'
    DIM = '\033[2m'

def read_env(key, default=""):
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip().replace('\r', '')
                if line.startswith(f"{key}="):
                    return line.split("=", 1)[1]
    return default

def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        return ""

def check_url(url, timeout=5):
    try:
        req = urllib.request.Request(url)
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except (urllib.error.URLError, OSError):
        return False

def main():
    print(f"\n{C.CYAN}{C.BOLD}╔═══════════════════════════════════════════╗{C.NC}")
    print(f"{C.CYAN}{C.BOLD}║   SOCials — Estado del Sistema           ║{C.NC}")
    print(f"{C.CYAN}{C.BOLD}╚═══════════════════════════════════════════╝{C.NC}")

    # ========== SERVICIOS DEL MONITOR ==========
    print(f"\n  {C.CYAN}{C.BOLD}SERVICIOS DEL MONITOR{C.NC}\n")

    monitor_services = [
        ("Prometheus", "soc-prometheus"),
        ("Loki", "soc-loki"),
        ("Tempo", "soc-tempo"),
        ("Grafana", "soc-grafana"),
        ("Wazuh Indexer", "soc-wazuh-indexer"),
        ("Wazuh Manager", "soc-wazuh-manager"),
        ("Wazuh Dashboard", "soc-wazuh-dashboard"),
        ("Homepage", "soc-homepage"),
        ("Node Exporter", "soc-node-exporter"),
        ("Cadvisor", "soc-cadvisor"),
        ("Trivy", "soc-trivy"),
        ("AdGuard DNS", "soc-dns"),
    ]

    for name, container in monitor_services:
        status = run(f"docker inspect --format='{{{{.State.Health.Status}}}}' {container} 2>/dev/null")
        if not status:
            running = run(f"docker inspect --format='{{{{.State.Running}}}}' {container} 2>/dev/null")
            if running == "true":
                status = "running"
            else:
                status = "stopped"

        if status == "healthy":
            icon = f"{C.GREEN}●{C.NC}"
        elif status in ["running", "true"]:
            icon = f"{C.GREEN}●{C.NC}"
            status = "running (no healthcheck)"
        elif status == "starting":
            icon = f"{C.YELLOW}●{C.NC}"
        else:
            icon = f"{C.RED}●{C.NC}"
            if not status:
                status = "not found"

        print(f"    {icon} {name:20s} {status}")

    # ========== PROMETHEUS TARGETS ==========
    print(f"\n  {C.CYAN}{C.BOLD}PROMETHEUS TARGETS{C.NC}\n")

    gf_ip = read_env('MONITOR_IP', '127.0.0.1')
    try:
        req = urllib.request.Request(f"http://{gf_ip}:9090/api/v1/targets")
        res = urllib.request.urlopen(req, timeout=5)
        data = json.loads(res.read())
        targets = data.get('data', {}).get('activeTargets', [])

        up_count = 0
        down_count = 0
        for t in sorted(targets, key=lambda x: x['labels'].get('job', '')):
            job = t['labels'].get('job', '?')
            instance = t['labels'].get('instance', '?')
            health = t.get('health', '?')

            if health == "up":
                icon = f"{C.GREEN}●{C.NC}"
                up_count += 1
            else:
                icon = f"{C.RED}●{C.NC}"
                down_count += 1

            print(f"    {icon} {job:25s} {instance:15s} {health}")

        print(f"\n    Total: {C.GREEN}{up_count} UP{C.NC}, {C.RED}{down_count} DOWN{C.NC}")
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        print(f"    {C.RED}No se puede conectar a Prometheus{C.NC}")

    # ========== MÁQUINAS ==========
    print(f"\n  {C.CYAN}{C.BOLD}MÁQUINAS{C.NC}\n")

    if os.path.exists(INVENTORY):
        with open(INVENTORY) as f:
            machines = json.load(f)

        for m in machines:
            name = m.get('name', '?')
            ip = m.get('ip', '?')
            role = m.get('role', '?')
            ssh = m.get('ssh', '')

            role_label = f"{C.CYAN}Monitor{C.NC}" if role == 'monitor' else f"{C.GREEN}Producción{C.NC}"

            if ssh == "LOCAL":
                # Local machine
                cpu = run("awk '{printf \"%.1f\", (1-$5/($2+$4+$5))*100}' /proc/stat 2>/dev/null | head -c 5")
                ram = run("free | awk '/^Mem:/{printf \"%.1f\", $3/$2*100}'")
                disk = run("df / | awk 'NR==2{print $5}' | tr -d '%'")
                containers = run("docker ps -q | wc -l")

                print(f"    {C.BOLD}{name}{C.NC} ({ip}) — {role_label}")
                print(f"      CPU: {cpu}%  RAM: {ram}%  Disco: {disk}%  Contenedores: {containers}")
            else:
                # Remote machine
                ssh_test = run(f"{ssh} echo ok 2>/dev/null", timeout=15)
                if ssh_test == "ok":
                    cpu = run(f"{ssh} \"awk '{{printf \\\"%.1f\\\", (1-\\$5/(\\$2+\\$4+\\$5))*100}}' /proc/stat 2>/dev/null | head -c 5\"", timeout=15)
                    ram = run(f"{ssh} \"free | awk '/^Mem:/{{printf \\\"%.1f\\\", \\$3/\\$2*100}}'\"", timeout=15)
                    disk = run(f"{ssh} \"df / | awk 'NR==2{{print \\$5}}' | tr -d '%'\"", timeout=15)
                    containers = run(f"{ssh} \"docker ps -q | wc -l\"", timeout=15)

                    print(f"    {C.BOLD}{name}{C.NC} ({ip}) — {role_label}")
                    print(f"      CPU: {cpu}%  RAM: {ram}%  Disco: {disk}%  Contenedores: {containers}")
                else:
                    print(f"    {C.BOLD}{name}{C.NC} ({ip}) — {role_label}")
                    print(f"      {C.RED}SSH no disponible{C.NC}")
    else:
        print(f"    {C.YELLOW}No se encontró inventory.json{C.NC}")

    # ========== ALERTAS DE GRAFANA ==========
    print(f"\n  {C.CYAN}{C.BOLD}ALERTAS{C.NC}\n")

    gf_user = read_env('GF_ADMIN_USER', 'admin')
    gf_pass = read_env('GF_ADMIN_PASSWORD', 'admin')
    gf_port = read_env('GF_HTTP_PORT', '3001')
    auth = base64.b64encode(f"{gf_user}:{gf_pass}".encode()).decode()

    try:
        req = urllib.request.Request(
            f"http://{gf_ip}:{gf_port}/api/v1/provisioning/alert-rules",
            headers={"Authorization": f"Basic {auth}"})
        res = urllib.request.urlopen(req, timeout=5)
        alerts = json.loads(res.read())

        firing = 0
        for a in alerts:
            title = a.get('title', '?')
            severity = a.get('labels', {}).get('severity', '?')

            if severity == 'critical':
                icon = f"{C.RED}●{C.NC}"
            else:
                icon = f"{C.YELLOW}●{C.NC}"

            print(f"    {icon} [{severity:8s}] {title}")

        # Check firing alerts
        try:
            req2 = urllib.request.Request(
                f"http://{gf_ip}:{gf_port}/api/alertmanager/grafana/api/v2/alerts",
                headers={"Authorization": f"Basic {auth}"})
            res2 = urllib.request.urlopen(req2, timeout=5)
            active = json.loads(res2.read())
            firing = len([a for a in active if a.get('status', {}).get('state') == 'active'])
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            firing = 0

        print(f"\n    Total: {len(alerts)} alertas configuradas, {C.RED}{firing} disparadas{C.NC}")
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        print(f"    {C.RED}No se puede conectar a Grafana{C.NC}")

    # ========== WAZUH ==========
    print(f"\n  {C.CYAN}{C.BOLD}WAZUH{C.NC}\n")

    wazuh_healthy = run("docker inspect --format='{{.State.Health.Status}}' soc-wazuh-manager 2>/dev/null")
    if wazuh_healthy == "healthy":
        print(f"    {C.GREEN}●{C.NC} Manager: healthy")

        # Contar agentes
        try:
            agents_output = run("docker exec soc-wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c 'ID:'")
            print(f"    Agentes registrados: {agents_output}")
        except (ValueError, OSError):
            print(f"    Agentes: {C.DIM}no disponible{C.NC}")
    else:
        print(f"    {C.RED}●{C.NC} Manager: {wazuh_healthy or 'no encontrado'}")

    # ========== TRIVY ==========
    print(f"\n  {C.CYAN}{C.BOLD}TRIVY{C.NC}\n")

    trivy_running = run("docker inspect --format='{{.State.Running}}' soc-trivy 2>/dev/null")
    if trivy_running == "true":
        print(f"    {C.GREEN}●{C.NC} Scanner: corriendo")
    else:
        print(f"    {C.RED}●{C.NC} Scanner: parado")

    # Último escaneo
    report_dir = os.path.join(SCRIPT_DIR, "monitor", "trivy", "reports")
    if os.path.exists(report_dir):
        reports = sorted([f for f in os.listdir(report_dir) if f.startswith("scan_")])
        if reports:
            last = reports[-1].replace("scan_", "").replace(".txt", "").replace("_", " ")
            print(f"    Último escaneo: {last}")
        else:
            print(f"    Último escaneo: ninguno")

    # Cron
    cron_check = run("crontab -l 2>/dev/null | grep -c trivy-scan")
    if cron_check == "1":
        print(f"    Cron semanal: {C.GREEN}configurado{C.NC}")
    else:
        print(f"    Cron semanal: {C.RED}no configurado{C.NC}")

    # ========== RESUMEN ==========
    print(f"\n  {C.CYAN}{C.BOLD}ACCESOS RÁPIDOS{C.NC}\n")
    print(f"    Homepage:   http://{gf_ip}:8082")
    print(f"    Grafana:    http://{gf_ip}:{gf_port}")
    print(f"    Wazuh:      https://{gf_ip}:5601")
    print(f"    Prometheus: http://{gf_ip}:9090")
    print()

if __name__ == "__main__":
    main()
