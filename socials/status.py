"""System status: machines, services, alerts, and Prometheus targets."""

from __future__ import annotations

import json
import urllib.request
import urllib.error

from .utils import C, bold, run, project_root
from . import config, inventory


def show_status() -> None:
    print(f"\n{C.CYAN}{C.BOLD}  SOCials — System Status{C.NC}")

    _show_monitor_services()
    _show_prometheus_targets()
    _show_machines()
    _show_alerts()
    _show_wazuh()
    _show_trivy()
    _show_access_urls()


def _show_monitor_services() -> None:
    print(f"\n  {C.CYAN}{C.BOLD}MONITOR SERVICES{C.NC}\n")

    services = [
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

    for name, container in services:
        status, _ = run(
            f"docker inspect --format='{{{{.State.Health.Status}}}}' {container} 2>/dev/null"
        )
        if not status:
            running, _ = run(
                f"docker inspect --format='{{{{.State.Running}}}}' {container} 2>/dev/null"
            )
            status = "running (no healthcheck)" if running == "true" else "stopped"

        if status == "healthy":
            icon = f"{C.GREEN}●{C.NC}"
        elif "running" in status:
            icon = f"{C.GREEN}●{C.NC}"
        elif status == "starting":
            icon = f"{C.YELLOW}●{C.NC}"
        else:
            icon = f"{C.RED}●{C.NC}"
            if not status:
                status = "not found"

        print(f"    {icon} {name:20s} {status}")


def _show_prometheus_targets() -> None:
    print(f"\n  {C.CYAN}{C.BOLD}PROMETHEUS TARGETS{C.NC}\n")

    gf_ip = config.get("monitor.ip", "127.0.0.1")
    try:
        req = urllib.request.Request(f"http://{gf_ip}:9090/api/v1/targets")
        res = urllib.request.urlopen(req, timeout=5)
        data = json.loads(res.read())
        targets = data.get("data", {}).get("activeTargets", [])

        up = down = 0
        for t in sorted(targets, key=lambda x: x["labels"].get("job", "")):
            job = t["labels"].get("job", "?")
            instance = t["labels"].get("instance", "?")
            health = t.get("health", "?")
            icon = f"{C.GREEN}●{C.NC}" if health == "up" else f"{C.RED}●{C.NC}"
            up += health == "up"
            down += health != "up"
            print(f"    {icon} {job:25s} {instance:15s} {health}")

        print(f"\n    Total: {C.GREEN}{up} UP{C.NC}, {C.RED}{down} DOWN{C.NC}")
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        print(f"    {C.RED}Cannot connect to Prometheus{C.NC}")


def _show_machines() -> None:
    print(f"\n  {C.CYAN}{C.BOLD}MACHINES{C.NC}\n")

    machines = inventory.load()
    if not machines:
        print(f"    {C.YELLOW}No inventory.json found{C.NC}")
        return

    for m in machines:
        name = m.get("name", "?")
        ip = m.get("ip", "?")
        role = m.get("role", "?")
        ssh = m.get("ssh", "")
        role_label = f"{C.CYAN}Monitor{C.NC}" if role == "monitor" else f"{C.GREEN}Production{C.NC}"

        if ssh == "LOCAL":
            cpu, _ = run("awk '{printf \"%.1f\", (1-$5/($2+$4+$5))*100}' /proc/stat 2>/dev/null | head -c 5")
            ram, _ = run("free | awk '/^Mem:/{printf \"%.1f\", $3/$2*100}'")
            disk, _ = run("df / | awk 'NR==2{print $5}' | tr -d '%'")
            containers, _ = run("docker ps -q | wc -l")
            print(f"    {bold(name)} ({ip}) — {role_label}")
            print(f"      CPU: {cpu}%  RAM: {ram}%  Disk: {disk}%  Containers: {containers}")
        else:
            ssh_test, _ = run(f"{ssh} echo ok 2>/dev/null", timeout=15)
            if ssh_test == "ok":
                cpu, _ = run(f'{ssh} "awk \'{{printf \\"%.1f\\", (1-$5/($2+$4+$5))*100}}\' /proc/stat 2>/dev/null | head -c 5"', timeout=15)
                ram, _ = run(f'{ssh} "free | awk \'/^Mem:/{{printf \\"%.1f\\", $3/$2*100}}\'"', timeout=15)
                disk, _ = run(f"{ssh} \"df / | awk 'NR==2{{print $5}}' | tr -d '%'\"", timeout=15)
                containers, _ = run(f'{ssh} "docker ps -q | wc -l"', timeout=15)
                print(f"    {bold(name)} ({ip}) — {role_label}")
                print(f"      CPU: {cpu}%  RAM: {ram}%  Disk: {disk}%  Containers: {containers}")
            else:
                print(f"    {bold(name)} ({ip}) — {role_label}")
                print(f"      {C.RED}SSH unavailable{C.NC}")


def _show_alerts() -> None:
    print(f"\n  {C.CYAN}{C.BOLD}ALERTS{C.NC}\n")

    gf_ip = config.get("monitor.ip", "127.0.0.1")
    gf_user = config.get("grafana.user", "admin")
    gf_pass = config.get("grafana.password", "admin")
    gf_port = config.get("grafana.port", "3001")

    import base64
    auth = base64.b64encode(f"{gf_user}:{gf_pass}".encode()).decode()

    try:
        req = urllib.request.Request(
            f"http://{gf_ip}:{gf_port}/api/v1/provisioning/alert-rules",
            headers={"Authorization": f"Basic {auth}"},
        )
        res = urllib.request.urlopen(req, timeout=5)
        alerts = json.loads(res.read())

        for a in alerts:
            title = a.get("title", "?")
            severity = a.get("labels", {}).get("severity", "?")
            icon = f"{C.RED}●{C.NC}" if severity == "critical" else f"{C.YELLOW}●{C.NC}"
            print(f"    {icon} [{severity:8s}] {title}")

        firing = 0
        try:
            req2 = urllib.request.Request(
                f"http://{gf_ip}:{gf_port}/api/alertmanager/grafana/api/v2/alerts",
                headers={"Authorization": f"Basic {auth}"},
            )
            res2 = urllib.request.urlopen(req2, timeout=5)
            active = json.loads(res2.read())
            firing = len([a for a in active if a.get("status", {}).get("state") == "active"])
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            pass

        print(f"\n    Total: {len(alerts)} configured, {C.RED}{firing} firing{C.NC}")
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        print(f"    {C.RED}Cannot connect to Grafana{C.NC}")


def _show_wazuh() -> None:
    print(f"\n  {C.CYAN}{C.BOLD}WAZUH{C.NC}\n")

    health, _ = run("docker inspect --format='{{.State.Health.Status}}' soc-wazuh-manager 2>/dev/null")
    if health == "healthy":
        print(f"    {C.GREEN}●{C.NC} Manager: healthy")
        agents, _ = run("docker exec soc-wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c 'ID:'")
        print(f"    Registered agents: {agents or 'unavailable'}")
    else:
        print(f"    {C.RED}●{C.NC} Manager: {health or 'not found'}")


def _show_trivy() -> None:
    import os

    print(f"\n  {C.CYAN}{C.BOLD}TRIVY{C.NC}\n")

    running, _ = run("docker inspect --format='{{.State.Running}}' soc-trivy 2>/dev/null")
    icon = f"{C.GREEN}●{C.NC}" if running == "true" else f"{C.RED}●{C.NC}"
    print(f"    {icon} Scanner: {'running' if running == 'true' else 'stopped'}")

    report_dir = os.path.join(project_root(), "monitor", "trivy", "reports")
    if os.path.exists(report_dir):
        reports = sorted(f for f in os.listdir(report_dir) if f.startswith("scan_"))
        if reports:
            last = reports[-1].replace("scan_", "").replace(".txt", "").replace("_", " ")
            print(f"    Last scan: {last}")

    cron_check, _ = run("crontab -l 2>/dev/null | grep -c trivy-scan")
    cron_status = f"{C.GREEN}configured{C.NC}" if cron_check == "1" else f"{C.RED}not configured{C.NC}"
    print(f"    Weekly cron: {cron_status}")


def _show_access_urls() -> None:
    gf_ip = config.get("monitor.ip", "127.0.0.1")
    gf_port = config.get("grafana.port", "3001")

    print(f"\n  {C.CYAN}{C.BOLD}ACCESS URLS{C.NC}\n")
    print(f"    Homepage:   http://{gf_ip}:8082")
    print(f"    Grafana:    http://{gf_ip}:{gf_port}")
    print(f"    Wazuh:      https://{gf_ip}:5601")
    print(f"    Prometheus: http://{gf_ip}:9090")
    print()
