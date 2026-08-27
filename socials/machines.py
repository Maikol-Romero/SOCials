"""Machine fleet management: add, remove, deploy agents, deploy databases."""

from __future__ import annotations

import os
import random
import shlex
import string
import subprocess
import sys

from . import inventory
from .utils import C, bold, error, info, warn, ask, run, read_env, env_path, project_root


AGENT_DIR = os.path.join(project_root(), "agent")


def list_machines() -> None:
    machines = inventory.load()
    if not machines:
        warn("No machines registered. Run setup.sh or socials machines add")
        return

    print(f"\n  {C.CYAN}{C.BOLD}Registered Machines{C.NC}\n")

    for m in machines:
        role = m.get("role", "?")
        icon = f"{C.CYAN}●{C.NC}" if role == "monitor" else f"{C.GREEN}●{C.NC}"
        label = "Monitor" if role == "monitor" else "Production"
        name = m.get("name", "?")
        ip = m.get("ip", "?")
        ssh = m.get("ssh", "?")

        print(f"  {icon} {bold(name)} ({ip}) — {label}")

        if ssh != "LOCAL":
            test, _ = run(f"{ssh} echo ok", timeout=15)
            ssh_status = f"{C.GREEN}connected{C.NC}" if test == "ok" else f"{C.RED}unavailable{C.NC}"
            print(f"    SSH: {ssh_status}")

            exporters, _ = run(
                f"{ssh} docker ps --format '{{{{.Names}}}}' 2>/dev/null | grep -c socials-node-exporter",
                timeout=15,
            )
            exp_status = f"{C.GREEN}running{C.NC}" if exporters.strip() == "1" else f"{C.RED}not detected{C.NC}"
            print(f"    Exporters: {exp_status}")
        else:
            print(f"    SSH: LOCAL")

    print(f"\n  Total: {bold(str(len(machines)))} machines\n")


def add_machine() -> None:
    machines = inventory.load()
    print(f"\n  {C.CYAN}{C.BOLD}Add Production Machine{C.NC}\n")

    name = ask("Name (e.g. web-server): ").strip().lower()
    ip = ask("Tailscale IP: ").strip()
    port = ask("SSH port [22]: ").strip() or "22"
    user = ask("SSH user [root]: ").strip() or "root"

    for m in machines:
        if m["name"] == name:
            error(f"Machine '{name}' already exists")
            return
        if m["ip"] == ip:
            error(f"Machine with IP '{ip}' already exists")
            return

    ssh_cmd = f"ssh -o ConnectTimeout=30 -p {port} {user}@{ip}"
    info("Testing SSH connection...")

    test, _ = run(f"{ssh_cmd} -o BatchMode=yes echo ok", timeout=35)
    if test != "ok":
        warn("SSH key auth failed. Copying SSH key...")
        ssh_key = ""
        for key_file in ["id_ed25519.pub", "id_rsa.pub"]:
            path = os.path.expanduser(f"~/.ssh/{key_file}")
            if os.path.exists(path):
                ssh_key = path
                break

        if ssh_key:
            info(f"Copying {ssh_key} (password will be asked once)...")
            subprocess.run(
                ["ssh-copy-id", "-i", ssh_key, "-p", port, f"{user}@{ip}"],
                check=False,
            )
        else:
            error("No SSH key found. Generate one: ssh-keygen -t ed25519")
            return

        test, _ = run(f"{ssh_cmd} -o BatchMode=yes echo ok", timeout=35)
        if test != "ok":
            error("SSH still failing after key copy")
            return

    info(f"SSH connected to {name}")

    info("Detecting system...")
    os_name, _ = run(f'{ssh_cmd} ". /etc/os-release && echo $PRETTY_NAME"', timeout=15)
    cpu, _ = run(f"{ssh_cmd} \"grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs\"", timeout=15)
    cores, _ = run(f"{ssh_cmd} nproc", timeout=15)
    ram, _ = run(f"{ssh_cmd} \"free -h | awk '/^Mem:/{{print $2}}'\"", timeout=15)
    gpu, _ = run(f'{ssh_cmd} "nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || echo None"', timeout=15)

    print(f"\n  {bold('Detected system:')}")
    print(f"    OS:  {os_name}")
    print(f"    CPU: {cpu} ({cores} cores)")
    print(f"    RAM: {ram}")
    print(f"    GPU: {gpu}")

    print(f"\n  {bold('Configure exporters:')}")
    exporters: dict[str, int] = {}

    node_port = ask("node-exporter port [9100]: ").strip() or "9100"
    if node_port:
        exporters["node"] = int(node_port)

    cadvisor_port = ask("cadvisor port [8080]: ").strip() or "8080"
    if cadvisor_port:
        exporters["containers"] = int(cadvisor_port)

    pg_port = ask("postgres-exporter port (empty to skip): ").strip()
    if pg_port:
        exporters["postgres"] = int(pg_port)

    redis_port = ask("redis-exporter port (empty to skip): ").strip()
    if redis_port:
        exporters["redis"] = int(redis_port)

    if gpu and gpu != "None":
        gpu_port = ask("GPU exporter port [9400]: ").strip() or "9400"
        if gpu_port:
            exporters["gpu"] = int(gpu_port)

    confirm = ask("\nAdd this machine? (y/n): ")
    if confirm.lower() not in ("y", "s"):
        warn("Cancelled")
        return

    machines.append({
        "name": name,
        "ip": ip,
        "role": "production",
        "ssh": ssh_cmd,
        "port": port,
        "user": user,
        "os": os_name,
        "cpu": f"{cpu} ({cores} cores)",
        "ram": ram,
        "gpu": gpu,
        "exporters": exporters,
    })
    inventory.save(machines)
    info(f"Machine '{name}' added to inventory")

    deploy = ask("Deploy exporters and Wazuh agent now? (y/n): ")
    if deploy.lower() in ("y", "s"):
        deploy_to_machine(name)

    _update_prometheus(machines)


def remove_machine() -> None:
    machines = inventory.load()
    prod = inventory.production_machines(machines)
    if not prod:
        warn("No production machines to remove")
        return

    print(f"\n  {C.CYAN}{C.BOLD}Remove Machine{C.NC}\n")

    for i, m in enumerate(prod, 1):
        print(f"    {C.BOLD}{i}){C.NC} {m['name']} ({m['ip']})")

    choice = ask("\nMachine number to remove (0 to cancel): ")
    try:
        idx = int(choice)
        if idx == 0:
            warn("Cancelled")
            return
        target = prod[idx - 1]
    except (ValueError, IndexError):
        error("Invalid option")
        return

    confirm = ask(f"Remove '{target['name']}'? Exporters will keep running. (y/n): ")
    if confirm.lower() not in ("y", "s"):
        warn("Cancelled")
        return

    machines = [m for m in machines if not (m["name"] == target["name"] and m["role"] == "production")]
    inventory.save(machines)
    info(f"Machine '{target['name']}' removed from inventory")
    _update_prometheus(machines)


def deploy_to_machine(name: str) -> None:
    if not inventory.validate_machine_name(name):
        return
    machines = inventory.load()
    target = inventory.find(name, machines)

    if not target:
        error(f"Machine '{name}' not found in inventory")
        return

    ssh_cmd = target["ssh"]
    ip = target.get("ip", "")
    ef = env_path()
    monitor_ip = read_env(ef, "MONITOR_IP", "")

    if not monitor_ip:
        mon = inventory.monitor(machines)
        if mon:
            monitor_ip = mon.get("ip", "")

    if not inventory.IP_RE.match(monitor_ip or ""):
        error(f"Invalid MONITOR_IP: {monitor_ip!r}. Must be dotted-quad IPv4.")
        return

    info(f"Deploying to {bold(name)} ({ip})...")

    run(f'{ssh_cmd} "mkdir -p ~/socials-monitoring"', timeout=15)

    port = str(target.get("port", "22"))
    user = target.get("user", "root")
    if not inventory.MACHINE_NAME_RE.match(user):
        error(f"Invalid user in inventory for {name}: {user!r}")
        return
    if not inventory.validate_ip(ip):
        error(f"Invalid IP in inventory for {name}: {ip!r}")
        return
    if not port.isdigit():
        error(f"Invalid port in inventory for {name}: {port!r}")
        return

    for f in ["docker-compose.yml", "otel-collector-config.yaml", "install.sh"]:
        filepath = os.path.join(AGENT_DIR, f)
        if not os.path.exists(filepath):
            error(f"Agent file not found: {filepath}")
            return
        cmd = ["scp", "-P", port, "-o", "ConnectTimeout=30", filepath,
               f"{user}@{ip}:~/socials-monitoring/"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            error(f"scp {f} failed (exit {r.returncode}): {r.stderr.strip()}")
            return

    info("Files copied")

    info("Running installation...")
    install_remote = (
        f"cd ~/socials-monitoring && chmod +x install.sh && "
        f"./install.sh {shlex.quote(monitor_ip)}"
    )
    r = subprocess.run(
        f"{ssh_cmd} {shlex.quote(install_remote)}",
        shell=True, text=True, capture_output=True, timeout=300,
    )
    if r.stdout:
        sys.stdout.write(r.stdout)
    if r.returncode != 0:
        if r.stderr:
            sys.stderr.write(r.stderr)
        error(f"install.sh failed (exit {r.returncode})")
        return

    info(f"Deploy completed on {name}")


def deploy_db(name: str) -> None:
    if not inventory.validate_machine_name(name):
        return
    machines = inventory.load()
    target = inventory.find(name, machines)
    if not target:
        error(f"Machine '{name}' not found in inventory")
        return

    ssh_cmd = target["ssh"]
    ip = target.get("ip", "?")
    port = str(target.get("port", "22"))
    user = target.get("user", "root")

    print(f"\n  {C.CYAN}{C.BOLD}Deploy Database to {name} ({ip}){C.NC}\n")

    info("Checking for existing databases...")
    output, _ = run(f"{ssh_cmd} \"netstat -tlnp 2>/dev/null | grep -E ':(5432|3306) '\"", timeout=15)
    if output:
        warn(f"Service detected on port 5432 or 3306 on {name}.")
        proceed = ask("Continue anyway? (y/n): ")
        if proceed.lower() not in ("y", "s"):
            return

    print(f"\n  {bold('Select database engine:')}")
    print("    1) PostgreSQL (recommended, works with Patroni)")
    print("    2) MySQL 8.0")
    print("    3) MariaDB 11")

    choice = ask("Option (1-3) [1]: ").strip() or "1"
    db_type = {"1": "postgres", "2": "mysql", "3": "mariadb"}.get(choice, "postgres")

    password = "".join(random.choices(string.ascii_letters + string.digits, k=20))

    compose = _db_compose(db_type, password)

    local_tmp = f"/tmp/socials_db_{name}"
    run(f"rm -rf {local_tmp} && mkdir -p {local_tmp}")

    with open(f"{local_tmp}/docker-compose.yml", "w") as f:
        f.write(compose)

    info(f"Copying docker-compose.yml to {name}...")
    run(f'{ssh_cmd} "mkdir -p ~/socials-db"')
    run(f"scp -P {port} -o ConnectTimeout=30 {local_tmp}/docker-compose.yml {user}@{ip}:~/socials-db/")

    info(f"Starting containers on {name}...")
    subprocess.run(
        f'{ssh_cmd} "cd ~/socials-db && docker compose up -d"',
        shell=True, text=True, capture_output=True, timeout=300,
    )

    print(f"\n{C.GREEN}{C.BOLD}  Database deployed on {name}!{C.NC}")
    print(f"    Engine:   {db_type}")
    print(f"    Host:     {ip}")
    print(f"    User:     admin")
    print(f"    Password: {password}")
    print(f"    Adminer:  http://{ip}:8080\n")

    run(f"rm -rf {local_tmp}")


def _db_compose(db_type: str, password: str) -> str:
    if db_type == "postgres":
        return f"""services:
  postgres:
    image: postgres:16-alpine
    container_name: socials-postgres
    environment:
      POSTGRES_PASSWORD: {password}
      POSTGRES_USER: admin
      POSTGRES_DB: socials
    ports:
      - "5432:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped
  adminer:
    image: adminer:latest
    container_name: socials-adminer
    ports:
      - "8080:8080"
    environment:
      ADMINER_DEFAULT_SERVER: postgres
    restart: unless-stopped
volumes:
  postgres-data:
"""
    elif db_type == "mysql":
        return f"""services:
  mysql:
    image: mysql:8.0
    container_name: socials-mysql
    environment:
      MYSQL_ROOT_PASSWORD: {password}
      MYSQL_DATABASE: socials
      MYSQL_USER: admin
      MYSQL_PASSWORD: {password}
    ports:
      - "3306:3306"
    volumes:
      - mysql-data:/var/lib/mysql
    restart: unless-stopped
  adminer:
    image: adminer:latest
    container_name: socials-adminer
    ports:
      - "8080:8080"
    environment:
      ADMINER_DEFAULT_SERVER: mysql
    restart: unless-stopped
volumes:
  mysql-data:
"""
    else:
        return f"""services:
  mariadb:
    image: mariadb:11
    container_name: socials-mariadb
    environment:
      MARIADB_ROOT_PASSWORD: {password}
      MARIADB_DATABASE: socials
      MARIADB_USER: admin
      MARIADB_PASSWORD: {password}
    ports:
      - "3306:3306"
    volumes:
      - mariadb-data:/var/lib/mysql
    restart: unless-stopped
  adminer:
    image: adminer:latest
    container_name: socials-adminer
    ports:
      - "8080:8080"
    environment:
      ADMINER_DEFAULT_SERVER: mariadb
    restart: unless-stopped
volumes:
  mariadb-data:
"""


def _update_prometheus(machines: list[dict]) -> None:
    import stat as stat_mod

    prom_path = os.path.join(project_root(), "monitor", "observability", "prometheus", "prometheus.yml")
    if not os.path.exists(prom_path):
        warn("prometheus.yml not found — skipping target update")
        return

    target = machines[-1]
    name = target["name"]
    ip = target.get("ip", "")
    exporters = target.get("exporters", {"node": 9100, "containers": 8080})

    with open(prom_path) as f:
        content = f.read()

    if f'"{name}_node"' in content or f'"{name}_containers"' in content:
        info(f"{name} already in prometheus.yml — skipping")
        return

    layer_map = {
        "node": "infrastructure",
        "containers": "containers",
        "postgres": "database",
        "redis": "cache",
        "gpu": "gpu",
    }

    new_blocks = ""
    for exporter, port in exporters.items():
        layer = layer_map.get(exporter, "infrastructure")
        new_blocks += f"""
  - job_name: "{name}_{exporter}"
    static_configs:
      - targets: ["{ip}:{port}"]
        labels:
          instance: "{name}"
          layer: "{layer}"
"""

    with open(prom_path, "a") as f:
        f.write(new_blocks)

    try:
        os.chmod(prom_path, 0o644)
    except OSError:
        pass

    run("docker restart soc-prometheus", timeout=15)
    info(f"Prometheus updated — {name} added ({len(exporters)} exporters)")
