"""Config generation from inventory: prometheus.yml, homepage services, OTEL configs."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile

from . import inventory
from .otel import generate_collector_config
from .utils import C, bold, info, warn, error, run, project_root


_PROM_DIR = os.path.join(project_root(), "monitor", "observability", "prometheus")
_HOMEPAGE_DIR = os.path.join(project_root(), "monitor", "homepage", "config")


def run_generate() -> None:
    machines = inventory.load()
    if not machines:
        error("No inventory.json found — run setup.sh or socials machines add first")
        return

    print(f"\n  {C.CYAN}{C.BOLD}Generating configs from inventory{C.NC}\n")

    mon = inventory.monitor(machines)
    prod = inventory.production_machines(machines)

    _generate_prometheus(mon, prod)
    _generate_homepage(mon, prod)
    _generate_watchdog(machines)

    print(f"\n  {C.GREEN}Configs generated. Restart services:{C.NC}")
    print("  docker restart soc-prometheus soc-homepage\n")


def run_diff() -> None:
    machines = inventory.load()
    if not machines:
        error("No inventory — nothing to diff")
        return

    mon = inventory.monitor(machines)
    prod = inventory.production_machines(machines)

    print(f"\n  {C.CYAN}{C.BOLD}Config diff vs inventory{C.NC}\n")
    _diff_prometheus(mon, prod)
    _diff_otel(prod)


def _generate_prometheus(mon: dict | None, prod: list[dict]) -> None:
    info("Generating prometheus.yml...")

    monitor_name = mon.get("name", "monitor") if mon else "monitor"
    monitor_ip = mon.get("ip", "127.0.0.1") if mon else "127.0.0.1"

    lines: list[str] = [
        "global:",
        "  scrape_interval: 15s",
        "  evaluation_interval: 15s",
        "",
        "scrape_configs:",
        "  # === Monitor ===",
        '  - job_name: "prometheus_self"',
        "    static_configs:",
        '      - targets: ["localhost:9090"]',
        "        labels:",
        f'          instance: "{monitor_name}"',
        "",
        '  - job_name: "monitor_node"',
        "    static_configs:",
        '      - targets: ["soc-node-exporter:9100"]',
        "        labels:",
        f'          instance: "{monitor_name}"',
        '          layer: "infrastructure"',
        "",
        '  - job_name: "monitor_containers"',
        "    static_configs:",
        '      - targets: ["soc-cadvisor:8080"]',
        "        labels:",
        f'          instance: "{monitor_name}"',
        '          layer: "containers"',
        "",
        '  - job_name: "tempo_metrics"',
        "    static_configs:",
        '      - targets: ["tempo:3200"]',
        "        labels:",
        f'          instance: "{monitor_name}"',
        '          layer: "traces"',
        "",
    ]

    for m in prod:
        name = m["name"]
        ip = m.get("ip", m.get("tailscale_ip", ""))
        exporters = m.get("exporters", {})
        ports = m.get("ports", {})

        lines.append(f"  # === {name} ===")

        if ports:
            _add_port_targets(lines, name, ip, ports, m.get("gpu"))
        elif exporters:
            _add_exporter_targets(lines, name, ip, exporters)

        for hc in m.get("healthchecks", []):
            lines.append(f'  - job_name: "{name}_{hc["name"]}"')
            lines.append("    metrics_path: /probe")
            lines.append("    params:")
            lines.append("      module: [http_2xx]")
            lines.append(f"    scrape_interval: {hc['interval']}")
            lines.append("    static_configs:")
            lines.append(f'      - targets: ["{hc["url"]}"]')
            lines.append("        labels:")
            lines.append(f'          instance: "{name}"')
            lines.append(f'          container: "{hc["container"]}"')
            lines.append(f'          layer: "{hc["layer"]}"')
            lines.append("    relabel_configs:")
            lines.append("      - source_labels: [__address__]")
            lines.append("        target_label: __param_target")
            lines.append("      - source_labels: [__param_target]")
            lines.append("        target_label: instance_url")
            lines.append("      - target_label: __address__")
            lines.append("        replacement: soc-blackbox:9115")
            lines.append("")

    config = "\n".join(lines) + "\n"
    path = os.path.join(_PROM_DIR, "prometheus.yml")

    if os.path.exists(path):
        import stat
        mode = os.stat(path).st_mode
        if not (mode & stat.S_IWUSR):
            os.chmod(path, 0o644)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(config)

    try:
        os.chmod(path, 0o444)
    except OSError:
        pass

    total_jobs = config.count("job_name:")
    info(f"prometheus.yml: {total_jobs} jobs ({len(prod)} machines)")


def _add_port_targets(lines: list[str], name: str, ip: str, ports: dict, gpu: bool | None) -> None:
    layer_map = {
        "node_exporter": ("node", "infrastructure"),
        "cadvisor": ("containers", "containers"),
        "pg_exporter": ("postgres", "database"),
        "redis_exporter": ("redis", "cache"),
        "gpu_exporter": ("gpu", "gpu"),
    }
    for port_key, (suffix, layer) in layer_map.items():
        if port_key == "gpu_exporter" and not gpu:
            continue
        port = ports.get(port_key)
        if port is None:
            continue
        lines.append(f'  - job_name: "{name}_{suffix}"')
        lines.append("    static_configs:")
        lines.append(f'      - targets: ["{ip}:{port}"]')
        lines.append("        labels:")
        lines.append(f'          instance: "{name}"')
        lines.append(f'          layer: "{layer}"')
        lines.append("")


def _add_exporter_targets(lines: list[str], name: str, ip: str, exporters: dict) -> None:
    layer_map = {
        "node": "infrastructure",
        "containers": "containers",
        "postgres": "database",
        "redis": "cache",
        "gpu": "gpu",
    }
    for exporter, port in exporters.items():
        layer = layer_map.get(exporter, "infrastructure")
        lines.append(f'  - job_name: "{name}_{exporter}"')
        lines.append("    static_configs:")
        lines.append(f'      - targets: ["{ip}:{port}"]')
        lines.append("        labels:")
        lines.append(f'          instance: "{name}"')
        lines.append(f'          layer: "{layer}"')
        lines.append("")


def _generate_homepage(mon: dict | None, prod: list[dict]) -> None:
    info("Generating homepage services.yaml...")

    monitor_ip = mon.get("ip", "127.0.0.1") if mon else "127.0.0.1"
    domains = mon.get("domains", {}) if mon else {}

    services = f"""- Monitor (Observabilidad):
    - Grafana:
        icon: grafana.png
        href: "https://{domains.get('grafana', 'grafana.socials.local')}"
        description: Dashboards, metricas y alertas
        widget:
          type: grafana
          url: http://soc-grafana:3000
          username: admin
          password: "{{{{HOMEPAGE_VAR_GRAFANA_PASS}}}}"
    - Prometheus:
        icon: prometheus.png
        href: "https://{domains.get('prometheus', 'prometheus.socials.local')}"
        description: Base de datos de metricas
        widget:
          type: prometheus
          url: http://soc-prometheus:9090
    - Wazuh:
        icon: wazuh.png
        href: "https://{domains.get('wazuh', monitor_ip + ':5601')}"
        description: Seguridad, intrusiones, FIM
    - AdGuard:
        icon: adguard-home.png
        href: "https://{domains.get('adguard', 'adguard.socials.local')}"
        description: DNS interno
    - Trivy:
        icon: /images/trivy.png
        href: "https://{domains.get('homepage', 'homepage.socials.local')}"
        description: Scanner de vulnerabilidades
    - Loki:
        icon: https://grafana.com/media/docs/loki/logo-grafana-loki.png
        href: "https://{domains.get('grafana', 'grafana.socials.local')}/explore?orgId=1&left=%7B%22datasource%22:%22loki%22%7D"
        description: Logs centralizados
    - Tempo:
        icon: /images/tempo.png
        href: "https://{domains.get('grafana', 'grafana.socials.local')}/explore?orgId=1&left=%7B%22datasource%22:%22tempo%22%7D"
        description: Trazas distribuidas
"""

    for m in prod:
        name = m.get("name", "?")
        ip = m.get("ip", m.get("tailscale_ip", ""))
        services += f"""- {name}:
    - Node Exporter:
        icon: si-prometheus
        href: "http://{ip}:9100/metrics"
        description: Metricas de infraestructura
    - cAdvisor:
        icon: si-docker
        href: "http://{ip}:8080"
        description: Metricas de contenedores
"""

    path = os.path.join(_HOMEPAGE_DIR, "services.yaml")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(services)

    info("services.yaml generated with SSL domains")


def _generate_watchdog(machines: list[dict]) -> None:
    all_containers: set[str] = set()
    for m in machines:
        for c in m.get("watchdog_containers", []):
            all_containers.add(c)

    if not all_containers:
        return

    info(f"Watchdog: {len(all_containers)} monitored containers")

    watchdog_path = os.path.join(project_root(), "scripts", "api-watchdog.sh")
    if os.path.exists(watchdog_path):
        with open(watchdog_path) as f:
            content = f.read()
        missing = [c for c in all_containers if c not in content]
        if missing:
            warn(f"Containers NOT in watchdog: {', '.join(missing)}")
        else:
            info("All containers present in watchdog script")


def _diff_prometheus(mon: dict | None, prod: list[dict]) -> None:
    prom_path = os.path.join(_PROM_DIR, "prometheus.yml")
    if not os.path.exists(prom_path):
        error("prometheus.yml not found")
        return

    with open(prom_path) as f:
        content = f.read()

    current_jobs = content.count("job_name:")

    expected = 4
    for m in prod:
        exporters = m.get("exporters", {})
        ports = m.get("ports", {})
        if ports:
            expected += len([k for k in ports if k != "gpu_exporter" or m.get("gpu")])
        elif exporters:
            expected += len(exporters)
        else:
            expected += 4
        expected += len(m.get("healthchecks", []))

    if current_jobs == expected:
        info(f"prometheus.yml: OK ({current_jobs} jobs)")
    else:
        warn(f"prometheus.yml: {current_jobs} current vs {expected} expected jobs")

    for m in prod:
        ip = m.get("ip", m.get("tailscale_ip", ""))
        name = m["name"]
        if ip and ip in content:
            info(f"  {name} ({ip}): present")
        else:
            warn(f"  {name} ({ip}): MISSING")


def _diff_otel(prod: list[dict]) -> None:
    print()
    for m in prod:
        ssh = m.get("ssh", "")
        name = m["name"]
        if not ssh or ssh == "LOCAL":
            continue
        otel_check, _ = run(
            f"{ssh} 'grep -c filelog ~/socials-monitoring/otel-collector-config.yaml 2>/dev/null'",
            timeout=10,
        )
        if otel_check and otel_check.strip().isdigit() and int(otel_check.strip()) > 0:
            info(f"OTEL {name}: filelog configured")
        else:
            warn(f"OTEL {name}: filelog NOT configured")


def run_deploy_otel(target_name: str | None = None) -> None:
    """Deploy updated OTEL configs to fleet machines (or a single target)."""
    machines = inventory.load()
    if not machines:
        error("No inventory — nothing to deploy")
        return

    mon = inventory.monitor(machines)
    prod = inventory.production_machines(machines)

    if not prod:
        error("No production machines in inventory")
        return

    monitor_ip = mon.get("ip", mon.get("tailscale_ip", "")) if mon else ""
    if not monitor_ip:
        error("Monitor IP not found in inventory")
        return

    if target_name:
        target = inventory.find(target_name, prod)
        if not target:
            error(f"Machine '{target_name}' not found among production machines")
            return
        targets = [target]
    else:
        targets = prod

    print(f"\n  {C.CYAN}{C.BOLD}Deploying OTEL configs{C.NC}\n")

    for m in targets:
        name = m["name"]
        ssh_cmd = m.get("ssh", "")
        ip = m.get("ip", m.get("tailscale_ip", ""))
        user = m.get("user", m.get("ssh_user", "root"))

        if not ssh_cmd:
            if not ip:
                warn(f"Skipping {name}: no SSH or IP configured")
                continue
            ssh_cmd = f"ssh -o ConnectTimeout=10 -o BatchMode=yes {user}@{ip}"

        info(f"Deploying OTEL to {name}...")

        config = generate_collector_config(m, monitor_ip)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", prefix=f"otel-{name}-", delete=False
        ) as tmp:
            tmp.write(config)
            tmp_path = tmp.name

        try:
            home = "/root" if user == "root" else f"/home/{user}"
            remote_path = f"{home}/socials-monitoring/otel-collector-config.yaml"

            port = str(m.get("port", "22"))
            scp_cmd = [
                "scp", "-P", port, "-o", "ConnectTimeout=10",
                "-o", "BatchMode=yes", tmp_path,
                f"{user}@{ip}:{remote_path}",
            ]
            r = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                error(f"  scp failed for {name}: {r.stderr.strip()}")
                continue
        finally:
            os.unlink(tmp_path)

        restart_cmd = (
            f"cd {home}/socials-monitoring && "
            f"docker compose stop otel-collector && "
            f"docker rm -f socials-otel-collector 2>/dev/null; "
            f"docker compose up -d otel-collector 2>&1 | tail -2"
        )
        r = subprocess.run(
            f"{ssh_cmd} {shlex.quote(restart_cmd)}",
            shell=True, text=True, capture_output=True, timeout=120,
        )
        output = r.stdout.strip()
        if "Started" in output or "started" in output.lower() or r.returncode == 0:
            info(f"  {name}: OTEL restarted")
        else:
            warn(f"  {name}: {output or r.stderr.strip()}")

    print()
