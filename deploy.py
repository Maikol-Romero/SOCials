#!/usr/bin/env python3
"""
SOCials — Deploy Generator
Lee inventory.json y genera todos los configs con IPs/nombres reales.
Genera: prometheus.yml, homepage services.yaml, OTEL configs, watchdog config.

Uso:
  python3 deploy.py generate    Genera configs desde inventory.json
  python3 deploy.py diff        Muestra diferencias con configs actuales
  python3 deploy.py status      Muestra estado actual del inventario
"""

import json, os, sys, shutil, copy

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INVENTORY = os.path.join(SCRIPT_DIR, "inventory.json")

class C:
    RED = '\033[0;31m'; GREEN = '\033[0;32m'; YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'; BOLD = '\033[1m'; NC = '\033[0m'

def info(msg):  print(f"{C.GREEN}[✓]{C.NC} {msg}")
def warn(msg):  print(f"{C.YELLOW}[!]{C.NC} {msg}")
def error(msg): print(f"{C.RED}[✗]{C.NC} {msg}")

def load_inventory():
    if not os.path.exists(INVENTORY):
        error(f"No se encontró {INVENTORY}")
        error("Crea el inventory.json con los datos de tus máquinas")
        sys.exit(1)
    with open(INVENTORY) as f:
        return json.load(f)

# ============================================
# GENERAR PROMETHEUS.YML
# ============================================
def generate_prometheus(inv):
    info("Generando prometheus.yml...")

    monitor = inv['monitor']
    machines = inv['machines']
    monitor_ip = monitor['tailscale_ip']

    lines = []
    lines.append("global:")
    lines.append("  scrape_interval: 15s")
    lines.append("  evaluation_interval: 15s")
    lines.append("")
    lines.append("scrape_configs:")

    # Monitor targets
    lines.append("  # === Monitor (socials-utils) ===")
    lines.append("  - job_name: \"prometheus_self\"")
    lines.append("    static_configs:")
    lines.append(f"      - targets: [\"localhost:9090\"]")
    lines.append(f"        labels:")
    lines.append(f"          instance: \"{monitor['name']}\"")
    lines.append("")

    lines.append("  - job_name: \"monitor_node\"")
    lines.append("    static_configs:")
    lines.append(f"      - targets: [\"soc-node-exporter:9100\"]")
    lines.append(f"        labels:")
    lines.append(f"          instance: \"{monitor['name']}\"")
    lines.append(f"          layer: \"infrastructure\"")
    lines.append("")

    lines.append("  - job_name: \"monitor_containers\"")
    lines.append("    static_configs:")
    lines.append(f"      - targets: [\"soc-cadvisor:8080\"]")
    lines.append(f"        labels:")
    lines.append(f"          instance: \"{monitor['name']}\"")
    lines.append(f"          layer: \"containers\"")
    lines.append("")

    lines.append("  - job_name: \"tempo_metrics\"")
    lines.append("    static_configs:")
    lines.append(f"      - targets: [\"tempo:3200\"]")
    lines.append(f"        labels:")
    lines.append(f"          instance: \"{monitor['name']}\"")
    lines.append(f"          layer: \"traces\"")
    lines.append("")

    # Production machine targets
    for m in machines:
        name = m['name']
        ip = m['tailscale_ip']
        ports = m['ports']

        lines.append(f"  # === {name} ===")

        # Node exporter
        lines.append(f"  - job_name: \"{name}_node\"")
        lines.append(f"    static_configs:")
        lines.append(f"      - targets: [\"{ip}:{ports['node_exporter']}\"]")
        lines.append(f"        labels:")
        lines.append(f"          instance: \"{name}\"")
        lines.append(f"          layer: \"infrastructure\"")
        lines.append("")

        # Container metrics (textfile collector via node-exporter)
        lines.append(f"  - job_name: \"{name}_containers\"")
        lines.append(f"    static_configs:")
        lines.append(f"      - targets: [\"{ip}:{ports['node_exporter']}\"]")
        lines.append(f"        labels:")
        lines.append(f"          instance: \"{name}\"")
        lines.append(f"          layer: \"containers\"")
        lines.append("")

        # PostgreSQL exporter
        lines.append(f"  - job_name: \"{name}_postgres\"")
        lines.append(f"    static_configs:")
        lines.append(f"      - targets: [\"{ip}:{ports['pg_exporter']}\"]")
        lines.append(f"        labels:")
        lines.append(f"          instance: \"{name}\"")
        lines.append(f"          layer: \"database\"")
        lines.append("")

        # Redis exporter
        lines.append(f"  - job_name: \"{name}_redis\"")
        lines.append(f"    static_configs:")
        lines.append(f"      - targets: [\"{ip}:{ports['redis_exporter']}\"]")
        lines.append(f"        labels:")
        lines.append(f"          instance: \"{name}\"")
        lines.append(f"          layer: \"cache\"")
        lines.append("")

        # GPU exporter (if available)
        if m.get('gpu') and 'gpu_exporter' in ports:
            lines.append(f"  - job_name: \"{name}_gpu\"")
            lines.append(f"    static_configs:")
            lines.append(f"      - targets: [\"{ip}:{ports['gpu_exporter']}\"]")
            lines.append(f"        labels:")
            lines.append(f"          instance: \"{name}\"")
            lines.append(f"          layer: \"gpu\"")
            lines.append("")

    # Blackbox healthchecks
    all_healthchecks = []
    for m in machines:
        for hc in m.get('healthchecks', []):
            all_healthchecks.append((m['name'], hc))

    if all_healthchecks:
        lines.append("  # === Blackbox Healthchecks ===")
        for mname, hc in all_healthchecks:
            job_name = f"{mname}_{hc['name']}"
            lines.append(f"  - job_name: \"{job_name}\"")
            lines.append(f"    metrics_path: /probe")
            lines.append(f"    params:")
            lines.append(f"      module: [http_2xx]")
            lines.append(f"    scrape_interval: {hc['interval']}")
            lines.append(f"    static_configs:")
            lines.append(f"      - targets: [\"{hc['url']}\"]")
            lines.append(f"        labels:")
            lines.append(f"          instance: \"{mname}\"")
            lines.append(f"          container: \"{hc['container']}\"")
            lines.append(f"          layer: \"{hc['layer']}\"")
            lines.append(f"    relabel_configs:")
            lines.append(f"      - source_labels: [__address__]")
            lines.append(f"        target_label: __param_target")
            lines.append(f"      - source_labels: [__param_target]")
            lines.append(f"        target_label: instance_url")
            lines.append(f"      - target_label: __address__")
            lines.append(f"        replacement: soc-blackbox:9115")
            lines.append("")

    config = "\n".join(lines) + "\n"

    path = os.path.join(SCRIPT_DIR, "monitor", "observability", "prometheus", "prometheus.yml")

    # Check if protected
    if os.path.exists(path):
        import stat
        mode = os.stat(path).st_mode
        if not (mode & stat.S_IWUSR):
            warn(f"prometheus.yml está protegido (chmod 444). Desprotegiendo...")
            os.chmod(path, 0o644)

    with open(path, 'w') as f:
        f.write(config)

    # Re-protect
    os.chmod(path, 0o444)

    total_jobs = config.count("job_name:")
    info(f"prometheus.yml generado con {total_jobs} jobs ({len(machines)} máquinas + {len(all_healthchecks)} healthchecks)")


# ============================================
# GENERAR HOMEPAGE SERVICES
# ============================================
def generate_homepage(inv):
    info("Generando homepage services.yaml...")

    monitor = inv['monitor']
    domains = monitor.get('domains', {})

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
        href: "https://{domains.get('wazuh', monitor['tailscale_ip'] + ':5601')}"
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
- Webs Internas de SOCials:
    - Panel Admin:
        icon: si-react
        href: "https://{domains.get('panel', 'panel.socials.local')}"
        description: Dashboard interno (empresas, usuarios, telefonía)
    - Internal:
        icon: /images/affine.png
        href: https://internal.socials.local
        description: Affine
    - Storybook:
        icon: si-storybook
        href: https://storybook.socials.local
        description: Storybook
"""

    path = os.path.join(SCRIPT_DIR, "monitor", "homepage", "config", "services.yaml")
    with open(path, 'w') as f:
        f.write(services)

    info(f"services.yaml generado con dominios SSL")


# ============================================
# GENERAR OTEL CONFIG PARA UNA MÁQUINA
# ============================================
def generate_otel_config(machine, monitor_ip):
    """Genera el contenido de otel-collector-config.yaml para una máquina."""

    return f"""receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
  filelog/docker:
    include: ["/var/lib/docker/containers/*/*.log"]
    start_at: end
    operators:
      - type: json_parser
        timestamp:
          parse_from: attributes.time
          layout: "%Y-%m-%dT%H:%M:%S.%LZ"
      - type: move
        from: attributes.log
        to: body
      - type: move
        from: attributes.stream
        to: attributes["log.iostream"]

processors:
  batch:
    timeout: 5s
    send_batch_size: 100
    send_batch_max_size: 500
  memory_limiter:
    check_interval: 1s
    limit_mib: 256
    spike_limit_mib: 64
  resource:
    attributes:
      - key: deployment.environment
        value: "{machine['environment']}"
        action: upsert
      - key: host.name
        value: "{machine['name']}"
        action: upsert

exporters:
  otlp/tempo:
    endpoint: "{monitor_ip}:4317"
    tls:
      insecure: true
  otlphttp/loki:
    endpoint: "http://{monitor_ip}:3100/otlp"

# Turn Detector GPU targets (si el puerto está configurado en inventory)
for m in inv.get("machines", []):
    if m.get("ports", {}).get("turn_detector"):
        ip = m["tailscale_ip"]
        port = m["ports"]["turn_detector"]
        name = m["name"]
        targets.append(f"""
  - job_name: "{name}_turn-detector"
    static_configs:
      - targets: ["{ip}:{port}"]
        labels:
          instance: "{name}"
          layer: "ai"
    metrics_path: /metrics""")
    tls:
      insecure: true
  prometheus:
    endpoint: "0.0.0.0:8889"
    namespace: socials

extensions:
  health_check:
    endpoint: 0.0.0.0:13133

service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [otlp/tempo]
    logs:
      receivers: [otlp, filelog/docker]
      processors: [memory_limiter, resource, batch]
      exporters: [otlphttp/loki]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [prometheus]
  telemetry:
    logs:
      level: warn
"""


# ============================================
# GENERAR WATCHDOG CONFIG
# ============================================
def generate_watchdog(inv):
    """Muestra los contenedores que el watchdog debería monitorizar."""
    info("Verificando watchdog config...")

    all_containers = set()
    for m in inv['machines']:
        for c in m.get('watchdog_containers', []):
            all_containers.add(c)

    if not all_containers:
        warn("No hay contenedores configurados para el watchdog")
        return

    info(f"Contenedores monitorizados por el watchdog: {len(all_containers)}")
    for c in sorted(all_containers):
        print(f"    {c}")

    # Check if watchdog script matches
    watchdog_path = os.path.join(SCRIPT_DIR, "scripts", "api-watchdog.sh")
    if os.path.exists(watchdog_path):
        with open(watchdog_path) as f:
            content = f.read()
        missing = []
        for c in all_containers:
            if c not in content:
                missing.append(c)
        if missing:
            warn(f"Contenedores NO en el watchdog: {', '.join(missing)}")
        else:
            info("Todos los contenedores están en el watchdog")


# ============================================
# DIFF
# ============================================
def show_diff(inv):
    print(f"\n  {C.CYAN}{C.BOLD}Diferencias con configs actuales{C.NC}\n")

    monitor = inv['monitor']
    machines = inv['machines']

    # Check prometheus.yml
    prom_path = os.path.join(SCRIPT_DIR, "monitor", "observability", "prometheus", "prometheus.yml")
    if os.path.exists(prom_path):
        with open(prom_path) as f:
            content = f.read()
        current_jobs = content.count("job_name:")

        # Calculate expected: 4 monitor + per machine (node, containers, postgres, redis, [gpu]) + healthchecks
        expected = 4
        for m in machines:
            expected += 4  # node, containers, postgres, redis
            if m.get('gpu'):
                expected += 1
        for m in machines:
            expected += len(m.get('healthchecks', []))

        if current_jobs == expected:
            info(f"prometheus.yml: OK ({current_jobs} jobs)")
        else:
            warn(f"prometheus.yml: {current_jobs} jobs actuales, {expected} esperados")

        # Check each machine is present
        for m in machines:
            if m['tailscale_ip'] in content:
                info(f"  {m['name']} ({m['tailscale_ip']}): presente")
            else:
                warn(f"  {m['name']} ({m['tailscale_ip']}): FALTA")
    else:
        error("prometheus.yml no existe")

    # Check OTEL configs
    print()
    for m in machines:
        ssh_cmd = f"ssh -o ConnectTimeout=5 -o BatchMode=yes {m['ssh_user']}@{m['private_ip']}"
        otel_check = os.popen(f"{ssh_cmd} 'grep -c filelog ~/socials-monitoring/otel-collector-config.yaml 2>/dev/null'").read().strip()
        if otel_check and int(otel_check) > 0:
            info(f"OTEL {m['name']}: filelog configurado")
        else:
            warn(f"OTEL {m['name']}: filelog NO configurado")

    # Check textfile collector
    print()
    for m in machines:
        ssh_cmd = f"ssh -o ConnectTimeout=5 -o BatchMode=yes {m['ssh_user']}@{m['private_ip']}"
        textfile_check = os.popen(f"{ssh_cmd} 'ls /tmp/node-exporter-textfile/container_metrics.prom 2>/dev/null && echo OK'").read().strip()
        if "OK" in textfile_check:
            info(f"Textfile {m['name']}: OK")
        else:
            warn(f"Textfile {m['name']}: NO configurado")


# ============================================
# STATUS
# ============================================
def show_status(inv):
    print(f"\n  {C.CYAN}{C.BOLD}SOCials — Inventario{C.NC}\n")

    monitor = inv['monitor']
    machines = inv['machines']

    print(f"  {C.BOLD}Monitor:{C.NC} {monitor['name']} ({monitor['tailscale_ip']})")
    print(f"  {C.BOLD}Dominios:{C.NC}")
    for k, v in monitor.get('domains', {}).items():
        print(f"    {k}: {v}")

    print(f"\n  {C.BOLD}Máquinas ({len(machines)}):{C.NC}")
    for m in machines:
        gpu_tag = " 🎮GPU" if m.get('gpu') else ""
        hc_count = len(m.get('healthchecks', []))
        wc_count = len(m.get('watchdog_containers', []))
        print(f"    {m['name']:15s} {m['tailscale_ip']:18s} {m['environment']:12s}{gpu_tag}")
        print(f"      Puertos: node={m['ports']['node_exporter']} cadvisor={m['ports'].get('cadvisor','—')} pg={m['ports']['pg_exporter']} redis={m['ports']['redis_exporter']}")
        if hc_count:
            print(f"      Healthchecks: {hc_count} | Watchdog containers: {wc_count}")

    total_targets = 4  # monitor base
    total_hc = 0
    for m in machines:
        total_targets += 4
        if m.get('gpu'):
            total_targets += 1
        total_hc += len(m.get('healthchecks', []))
    total_targets += total_hc

    print(f"\n  {C.BOLD}Total:{C.NC} {total_targets} Prometheus targets, {total_hc} healthchecks")
    print()


# ============================================
# DEPLOY OTEL TO MACHINES
# ============================================
def deploy_otel(inv):
    """Despliega la config OTEL actualizada a todas las máquinas."""
    monitor = inv['monitor']
    machines = inv['machines']
    monitor_ip = monitor['tailscale_ip']

    for m in machines:
        name = m['name']
        ssh_base = f"ssh -o ConnectTimeout=10 -o BatchMode=yes {m['ssh_user']}@{m['private_ip']}"

        info(f"Desplegando OTEL en {name}...")

        config = generate_otel_config(m, monitor_ip)
        # Write to temp file and scp
        tmp_path = f"/tmp/otel-config-{name}.yaml"
        with open(tmp_path, 'w') as f:
            f.write(config)

        remote_path = f"{'/root' if m['ssh_user'] == 'root' else '/home/' + m['ssh_user']}/socials-monitoring/otel-collector-config.yaml"
        os.system(f"scp -o ConnectTimeout=10 -o BatchMode=yes {tmp_path} {m['ssh_user']}@{m['private_ip']}:{remote_path}")
        os.remove(tmp_path)

        # Recreate OTEL collector
        home = "/root" if m["ssh_user"] == "root" else f"/home/{m['ssh_user']}"
        result = os.popen(f"{ssh_base} 'cd {home}/socials-monitoring && docker compose stop otel-collector && docker rm -f socials-otel-collector 2>/dev/null; docker compose up -d otel-collector 2>&1 | tail -2'").read().strip()
        if "Started" in result:
            info(f"  {name}: OTEL reiniciado")
        else:
            warn(f"  {name}: {result}")


# ============================================
# MAIN
# ============================================
def main():
    if len(sys.argv) < 2:
        print(f"""
{C.CYAN}{C.BOLD}  SOCials — Deploy Generator{C.NC}

  Uso:
    python3 deploy.py {C.BOLD}generate{C.NC}      Genera prometheus.yml y homepage services.yaml
    python3 deploy.py {C.BOLD}diff{C.NC}           Muestra diferencias con configs actuales
    python3 deploy.py {C.BOLD}status{C.NC}         Muestra inventario y estado
    python3 deploy.py {C.BOLD}deploy-otel{C.NC}    Despliega OTEL config a todas las máquinas
""")
        return

    cmd = sys.argv[1].lower()
    inv = load_inventory()

    if cmd == "generate":
        print(f"\n  {C.CYAN}{C.BOLD}Generando configuraciones desde inventario{C.NC}\n")
        generate_prometheus(inv)
        generate_homepage(inv)
        generate_watchdog(inv)
        print(f"\n  {C.GREEN}Configuraciones generadas. Reinicia servicios con:{C.NC}")
        print(f"  docker restart soc-prometheus soc-homepage\n")

    elif cmd == "diff":
        show_diff(inv)

    elif cmd == "status":
        show_status(inv)

    elif cmd == "deploy-otel":
        print(f"\n  {C.CYAN}{C.BOLD}Desplegando OTEL configs{C.NC}\n")
        deploy_otel(inv)
        print()

    else:
        error(f"Comando desconocido: {cmd}")

if __name__ == "__main__":
    main()
