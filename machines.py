#!/usr/bin/env python3
"""
SOCials — Gestor de Máquinas
Añadir, listar y eliminar máquinas del inventario.

Uso:
  python3 machines.py list              Ver máquinas registradas
  python3 machines.py add               Añadir máquina (interactivo)
  python3 machines.py remove            Eliminar máquina (interactivo)
  python3 machines.py deploy <nombre>   Desplegar agents en una máquina
"""

import json, os, sys, subprocess, time, shlex, fcntl
from contextlib import contextmanager

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INVENTORY = os.path.join(SCRIPT_DIR, "inventory.json")
AGENT_DIR = os.path.join(SCRIPT_DIR, "agent")
ENV_FILE = os.path.join(SCRIPT_DIR, "monitor", "observability", ".env")

class C:
    RED = '\033[0;31m'; GREEN = '\033[0;32m'; YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'; BOLD = '\033[1m'; NC = '\033[0m'

def info(msg):  print(f"{C.GREEN}[✓]{C.NC} {msg}")
def warn(msg):  print(f"{C.YELLOW}[!]{C.NC} {msg}")
def error(msg): print(f"{C.RED}[✗]{C.NC} {msg}")
def ask(msg):   return input(f"{C.YELLOW}[?]{C.NC} {msg}")
def bold(t):    return f"{C.BOLD}{t}{C.NC}"

def load_inventory():
    if os.path.exists(INVENTORY):
        with open(INVENTORY) as f:
            return json.load(f)
    return []

_INVENTORY_LOCK = INVENTORY + ".lock"
_inventory_lock_depth = 0


@contextmanager
def inventory_lock():
    """Reentrant advisory file lock shared with socialwarden-manager."""
    global _inventory_lock_depth
    if _inventory_lock_depth > 0:
        _inventory_lock_depth += 1
        try:
            yield
        finally:
            _inventory_lock_depth -= 1
        return
    if not os.path.exists(_INVENTORY_LOCK):
        try:
            os.close(os.open(_INVENTORY_LOCK, os.O_WRONLY | os.O_CREAT, 0o644))
        except PermissionError:
            pass
    fd = os.open(_INVENTORY_LOCK, os.O_RDONLY)
    try:
        deadline = time.time() + 30
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() > deadline:
                    raise TimeoutError("inventory lock held by another process for >30s")
                time.sleep(0.2)
        _inventory_lock_depth = 1
        yield
    finally:
        _inventory_lock_depth = 0
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def update_inventory(mutator):
    """Atomic read-modify-write under inventory_lock.

    `mutator(machines: list[dict]) -> list[dict] | None`. If the mutator
    returns None, the (in-place mutated) `machines` argument is saved.
    The lock is held across load → mutate → save so concurrent invocations
    do NOT lose each other's changes.
    """
    with inventory_lock():
        machines = load_inventory()
        result = mutator(machines)
        if result is not None:
            machines = result
        # Re-implement save without re-acquiring the lock (we hold it).
        tmp = INVENTORY + ".tmp"
        pre_uid = pre_gid = None
        if os.path.exists(INVENTORY):
            st = os.stat(INVENTORY)
            pre_uid, pre_gid = st.st_uid, st.st_gid
        with open(tmp, 'w') as f:
            json.dump(machines, f, indent=2)
        os.replace(tmp, INVENTORY)
        if pre_uid is not None:
            try:
                os.chown(INVENTORY, pre_uid, pre_gid)
            except PermissionError:
                pass
        try:
            os.chmod(INVENTORY, 0o640)
        except PermissionError:
            pass


def save_inventory(machines):
    # Write atomically + tighten perms + advisory lock.
    # Mode 0640 (root/ubuntu group readable; world unreadable) prevents
    # leakage of fleet topology, tailscale IPs, and identity fingerprints.
    with inventory_lock():
        tmp = INVENTORY + ".tmp"
        pre_uid = pre_gid = None
        if os.path.exists(INVENTORY):
            st = os.stat(INVENTORY)
            pre_uid, pre_gid = st.st_uid, st.st_gid
        with open(tmp, 'w') as f:
            json.dump(machines, f, indent=2)
        os.replace(tmp, INVENTORY)
        if pre_uid is not None:
            try:
                os.chown(INVENTORY, pre_uid, pre_gid)
            except PermissionError:
                pass
        try:
            os.chmod(INVENTORY, 0o640)
        except PermissionError:
            pass

def read_env(key, default=""):
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip().replace('\r', '')
                if line.startswith(f"{key}="):
                    return line.split("=", 1)[1]
    return default

def run(cmd, timeout=30):
    # Catch only OSError (cmd not found) + TimeoutExpired. Bare except: would
    # swallow KeyboardInterrupt/SystemExit and make the script un-killable.
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", 124
    except OSError:
        return "", 1

# ============================================
# LISTAR
# ============================================
def list_machines():
    machines = load_inventory()
    if not machines:
        warn("No hay máquinas registradas. Ejecuta setup.sh o machines.py add")
        return

    print(f"\n  {C.CYAN}{C.BOLD}Máquinas registradas{C.NC}\n")

    for m in machines:
        role = m.get('role', '?')
        if role == 'monitor':
            icon = f"{C.CYAN}●{C.NC}"
            label = "Monitor"
        else:
            icon = f"{C.GREEN}●{C.NC}"
            label = "Producción"

        name = m.get('name', '?')
        ip = m.get('ip', '?')
        ssh = m.get('ssh', '?')

        print(f"  {icon} {bold(name)} ({ip}) — {label}")

        if ssh != "LOCAL":
            # Test SSH
            test, code = run(f"{ssh} echo ok", timeout=15)
            if test == "ok":
                print(f"    SSH: {C.GREEN}conectado{C.NC}")
            else:
                print(f"    SSH: {C.RED}no disponible{C.NC}")

            # Test exporters
            exporters, _ = run(f"{ssh} docker ps --format '{{{{.Names}}}}' 2>/dev/null | grep -c socials-node-exporter", timeout=15)
            if exporters.strip() == "1":
                print(f"    Exporters: {C.GREEN}corriendo{C.NC}")
            else:
                print(f"    Exporters: {C.RED}no detectados{C.NC}")
        else:
            print(f"    SSH: LOCAL")

    print(f"\n  Total: {bold(str(len(machines)))} máquinas\n")

# ============================================
# AÑADIR
# ============================================
def add_machine():
    machines = load_inventory()
    print(f"\n  {C.CYAN}{C.BOLD}Añadir máquina de producción{C.NC}\n")

    name = ask("Nombre (ej: servidor-ia): ").strip().lower()
    ip = ask("IP de Tailscale: ").strip()
    port = ask("Puerto SSH [22]: ").strip() or "22"
    user = ask("Usuario SSH [root]: ").strip() or "root"

    # Verificar que no existe
    for m in machines:
        if m['name'] == name:
            error(f"Ya existe una máquina con nombre '{name}'")
            return
        if m['ip'] == ip:
            error(f"Ya existe una máquina con IP '{ip}'")
            return

    # Test SSH
    ssh_cmd = f"ssh -o ConnectTimeout=30 -p {port} {user}@{ip}"
    info("Probando conexión SSH...")

    # Intentar con BatchMode primero
    test, code = run(f"{ssh_cmd} -o BatchMode=yes echo ok", timeout=35)
    if test != "ok":
        warn("SSH sin clave no funciona. Copiando clave SSH...")
        ssh_key = ""
        for key_file in ["id_ed25519.pub", "id_rsa.pub"]:
            path = os.path.expanduser(f"~/.ssh/{key_file}")
            if os.path.exists(path):
                ssh_key = path
                break

        if ssh_key:
            info(f"Copiando {ssh_key} (se pedirá contraseña una sola vez)...")
            os.system(f"ssh-copy-id -i {ssh_key} -p {port} {user}@{ip}")
        else:
            error("No se encontró clave SSH. Genera una con: ssh-keygen -t ed25519")
            return

        # Re-test
        test, code = run(f"{ssh_cmd} -o BatchMode=yes echo ok", timeout=35)
        if test != "ok":
            error("SSH sigue sin funcionar después de copiar la clave")
            return

    info(f"SSH conectado a {name}")

    # Recoger info del sistema
    info("Detectando sistema...")
    os_name, _ = run(f"{ssh_cmd} \". /etc/os-release && echo \\$PRETTY_NAME\"", timeout=15)
    cpu, _ = run(f"{ssh_cmd} \"grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs\"", timeout=15)
    cores, _ = run(f"{ssh_cmd} nproc", timeout=15)
    ram, _ = run(f"{ssh_cmd} \"free -h | awk '/^Mem:/{{print \\$2}}'\"", timeout=15)
    gpu, _ = run(f"{ssh_cmd} \"nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || echo No detectada\"", timeout=15)

    print(f"\n  {bold('Sistema detectado:')}")
    print(f"    OS:  {os_name}")
    print(f"    CPU: {cpu} ({cores} cores)")
    print(f"    RAM: {ram}")
    print(f"    GPU: {gpu}")

    # Preguntar puertos de exporters
    print(f"\n  {bold('Configurar exporters:')}")
    print(f"    Deja vacío para omitir un exporter")
    exporters = {}
    
    node_port = ask("Puerto node-exporter [9100]: ").strip() or "9100"
    if node_port: exporters['node'] = int(node_port)
    
    cadvisor_port = ask("Puerto cadvisor [8080]: ").strip() or "8080"
    if cadvisor_port: exporters['containers'] = int(cadvisor_port)
    
    pg_port = ask("Puerto postgres-exporter (vacío si no tiene): ").strip()
    if pg_port: exporters['postgres'] = int(pg_port)
    
    redis_port = ask("Puerto redis-exporter (vacío si no tiene): ").strip()
    if redis_port: exporters['redis'] = int(redis_port)
    
    if gpu and gpu != 'No detectada':
        gpu_port = ask("Puerto GPU exporter [9400]: ").strip() or "9400"
        if gpu_port: exporters['gpu'] = int(gpu_port)

    confirm = ask("\n¿Añadir esta máquina? (s/n): ")
    if confirm.lower() != 's':
        warn("Cancelado")
        return

    # Añadir al inventario
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
        "exporters": exporters
    })
    save_inventory(machines)
    info(f"Máquina '{name}' añadida al inventario")

    # Preguntar si desplegar agents
    deploy = ask("¿Desplegar exporters y Wazuh agent ahora? (s/n): ")
    if deploy.lower() == 's':
        deploy_to_machine(name)

    # Preguntar si desplegar Base de Datos
    deploy_database = ask("¿Deseas desplegar una Base de Datos en esta máquina ahora? (s/n): ")
    if deploy_database.lower() == 's':
        deploy_db(name)

    # Actualizar Prometheus
    update_prometheus(machines)

# ============================================
# ELIMINAR
# ============================================
def remove_machine():
    machines = load_inventory()
    if not machines:
        warn("No hay máquinas registradas")
        return

    print(f"\n  {C.CYAN}{C.BOLD}Eliminar máquina{C.NC}\n")

    prod_machines = [m for m in machines if m['role'] == 'production']
    if not prod_machines:
        warn("No hay máquinas de producción para eliminar")
        return

    for i, m in enumerate(prod_machines, 1):
        print(f"    {C.BOLD}{i}){C.NC} {m['name']} ({m['ip']})")

    choice = ask("\nNúmero de máquina a eliminar (0 para cancelar): ")
    try:
        idx = int(choice)
        if idx == 0:
            warn("Cancelado")
            return
        target = prod_machines[idx - 1]
    except (ValueError, IndexError):
        error("Opción no válida")
        return

    confirm = ask(f"¿Eliminar '{target['name']}'? Los exporters seguirán corriendo. (s/n): ")
    if confirm.lower() != 's':
        warn("Cancelado")
        return

    machines = [m for m in machines if not (m['name'] == target['name'] and m['role'] == 'production')]
    save_inventory(machines)
    info(f"Máquina '{target['name']}' eliminada del inventario")

    # Actualizar Prometheus
    update_prometheus(machines)

# ============================================
# DESPLEGAR EN UNA MÁQUINA
# ============================================
_IP_RE = __import__("re").compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$")


def deploy_to_machine(name):
    if not _validate_machine_name(name):
        return
    machines = load_inventory()
    target = None
    for m in machines:
        if m['name'] == name:
            target = m
            break

    if not target:
        error(f"Máquina '{name}' no encontrada en el inventario")
        return

    ssh_cmd = target['ssh']
    ip = target.get('ip', '')
    monitor_ip = read_env('MONITOR_IP', '')

    if not monitor_ip:
        for m in machines:
            if m['role'] == 'monitor':
                monitor_ip = m.get('ip', '')
                break

    if not _IP_RE.match(monitor_ip or ''):
        error(f"MONITOR_IP inválido: {monitor_ip!r}. Debe ser un IPv4 dotted-quad.")
        return

    info(f"Desplegando en {bold(name)} ({ip})...")

    # Crear directorio remoto
    run(f'{ssh_cmd} "mkdir -p ~/socials-monitoring"', timeout=15)

    # Copiar archivos — subprocess.run con returncode check, abortar al primer fallo.
    port = str(target.get('port', '22'))
    user = target.get('user', 'root')
    if not _MACHINE_NAME_RE.match(user):
        error(f"User inválido en inventory para {name}: {user!r}")
        return
    if not _IP_RE.match(ip):
        error(f"IP inválida en inventory para {name}: {ip!r}")
        return
    if not port.isdigit():
        error(f"Port inválido en inventory para {name}: {port!r}")
        return
    for f in ['docker-compose.yml', 'otel-collector-config.yaml', 'install.sh']:
        filepath = os.path.join(AGENT_DIR, f)
        cmd = ["scp", "-P", port, "-o", "ConnectTimeout=30", filepath,
               f"{user}@{ip}:~/socials-monitoring/"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            error(f"scp {f} falló (exit {r.returncode}): {r.stderr.strip()}")
            return

    info("Archivos copiados")

    # Ejecutar install.sh — monitor_ip ya validado como IPv4.
    info("Ejecutando instalación...")
    install_remote = (
        f"cd ~/socials-monitoring && chmod +x install.sh && "
        f"./install.sh {shlex.quote(monitor_ip)}"
    )
    r = subprocess.run(f"{ssh_cmd} {shlex.quote(install_remote)}",
                       shell=True, text=True, capture_output=True, timeout=300)
    if r.stdout: sys.stdout.write(r.stdout)
    if r.returncode != 0:
        if r.stderr: sys.stderr.write(r.stderr)
        error(f"install.sh remoto falló (exit {r.returncode})")
        return

    info(f"Deploy completado en {name}")

# ============================================
# DESPLEGAR BASE DE DATOS
# ============================================
def deploy_db(name):
    if not _validate_machine_name(name):
        return
    machines = load_inventory()
    target = next((m for m in machines if m["name"] == name), None)
    if not target:
        error(f"Máquina '{name}' no encontrada en el inventario")
        return
        
    ssh_cmd = target["ssh"]
    ip = target.get("ip", "?")
    port = str(target.get("port", "22"))
    user = target.get("user", "root")
    
    print(f"\n  {C.CYAN}{C.BOLD}Desplegar Base de Datos en {name} ({ip}){C.NC}\n")
    
    # 1. Comprobar si ya hay una BD corriendo (puertos 5432 o 3306)
    info("Comprobando si existen bases de datos previas...")
    check_cmd = f"{ssh_cmd} \"netstat -tlnp 2>/dev/null | grep -E ':(5432|3306) '\""
    output, _ = run(check_cmd, timeout=15)
    if output:
        warn(f"Se ha detectado un servicio escuchando en el puerto 5432 o 3306 en {name}.")
        print("    " + output.replace("\n", "\n    "))
        warn("No se recomienda desplegar una BD automática sobre un puerto ya ocupado.")
        proceed = ask("¿Continuar de todos modos? (s/n): ")
        if proceed.lower() != 's':
            return
    
    print(f"\n  {bold('Selecciona el motor de base de datos:')}")
    print("    1) PostgreSQL (Recomendado, funciona con Patroni)")
    print("    2) MySQL 8.0")
    print("    3) MariaDB 11")
    
    choice = ask("Opción (1-3) [1]: ").strip() or "1"
    
    db_type = "postgres"
    if choice == "2": db_type = "mysql"
    elif choice == "3": db_type = "mariadb"
    
    import random, string
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    
    info("Generando configuraciones...")
    
    local_tmp = f"/tmp/socials_db_{name}"
    run(f"rm -rf {local_tmp} && mkdir -p {local_tmp}")
    
    if db_type == "postgres":
        compose = f"""services:
  postgres:
    image: postgres:15-alpine
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
      ADMINER_DESIGN: pepa-linha
    restart: unless-stopped
volumes:
  postgres-data:
"""
    elif db_type == "mysql":
        compose = f"""services:
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
      ADMINER_DESIGN: pepa-linha
    restart: unless-stopped
volumes:
  mysql-data:
"""
    else:
        compose = f"""services:
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
      ADMINER_DESIGN: pepa-linha
    restart: unless-stopped
volumes:
  mariadb-data:
"""

    with open(f"{local_tmp}/docker-compose.yml", "w") as f:
        f.write(compose)
        
    info(f"Copiando docker-compose.yml a {name}...")
    run(f"{ssh_cmd} \"mkdir -p ~/socials-db\"")
    scp_cmd = f"scp -P {port} -o ConnectTimeout=30 {local_tmp}/docker-compose.yml {user}@{ip}:~/socials-db/"
    run(scp_cmd)
    
    info(f"Levantando contenedores en {name}...")
    subprocess.run(f"{ssh_cmd} \"cd ~/socials-db && docker compose up -d\"", shell=True, text=True, capture_output=True, timeout=300)
    
    print(f"\n{C.GREEN}{C.BOLD}  ¡Base de Datos desplegada con éxito en {name}!{C.NC}")
    print(f"    - Motor: {db_type}")
    print(f"    - IP de conexión: {ip}")
    print(f"    - Usuario: admin")
    print(f"    - Contraseña: {password}")
    print(f"    - Adminer Web UI: http://{ip}:8080")
    print(f"    - (Inicia sesión en Adminer con usuario 'admin' y la contraseña generada)\n")
    
    run(f"rm -rf {local_tmp}")

# ============================================
# ACTUALIZAR PROMETHEUS
# ============================================
def update_prometheus(machines):
    """Añade la última máquina del inventario a prometheus.yml sin tocar lo existente."""
    import stat as stat_mod
    
    prom_path = os.path.join(SCRIPT_DIR, "monitor", "observability", "prometheus", "prometheus.yml")
    
    # La última máquina añadida
    target = machines[-1]
    name = target['name']
    ip = target.get('ip', '')
    exporters = target.get('exporters', {'node': 9100, 'containers': 8080})
    
    # Verificar que no existe ya
    with open(prom_path) as f:
        content = f.read()
    
    if f'\"{name}_node\"' in content or f'\"{name}_containers\"' in content:
        info(f"{name} ya existe en prometheus.yml — saltando")
        return
    
    # Construir bloques
    new_blocks = ""
    for exporter, port in exporters.items():
        layer_map = {'node': 'infrastructure', 'containers': 'containers', 
                     'postgres': 'database', 'redis': 'cache', 'gpu': 'gpu'}
        layer = layer_map.get(exporter, 'infrastructure')
        new_blocks += f"""
  - job_name: "{name}_{exporter}"
    static_configs:
      - targets: ["{ip}:{port}"]
        labels:
          instance: "{name}"
          layer: "{layer}"
"""
    
    # Append + keep file writable so the next add_machine doesn't need to
    # chmod-toggle. 0o644 is fine here: prometheus.yml has no secrets, just
    # scrape targets. Read-only (0o444) prevented edits without un-protecting
    # and was a foot-gun.
    with open(prom_path, 'a') as f:
        f.write(new_blocks)
    os.chmod(prom_path, 0o644)
    
    # Reiniciar Prometheus
    run("docker restart soc-prometheus", timeout=15)
    info(f"Prometheus actualizado — {name} añadido ({len(exporters)} exporters)")


# ============================================
# socialwarden — enrollment (v1.4.0 client)
# ============================================
# Instala el agent socialwarden ligero (solo client-side) en una máquina del
# inventario, siguiendo el patrón Wazuh-agent: scp del paquete → ejecuta
# install.sh vía SSH → marca la máquina como "socialwarden": "enrolled" en
# inventory.json.
#
# Separación de responsabilidades:
#   - Manager (utils, esta máquina):  vaultwarden + aggregator + rotate + scan orchestrator
#   - Client (todas las demás):        socialwarden-agent (poll + sync + merge + optional api/scan)
socialwarden_AGENT_SRC = os.path.join(SCRIPT_DIR, "socialwarden-agent")


import re as _re_machine_name
_MACHINE_NAME_RE = _re_machine_name.compile(r"^[a-zA-Z0-9._-]+$")


def _validate_machine_name(name):
    """Reject names that would break shell quoting or path construction."""
    if not _MACHINE_NAME_RE.match(name or ""):
        error(f"Machine name '{name}' contains invalid chars. Allowed: [a-zA-Z0-9._-]")
        return False
    return True


def socialwarden_enroll(name, no_restart=False, force=False):
    """Enrol a machine as a socialwarden client: scp package + run install.sh.

    Args:
      no_restart: pass --no-restart to the remote installer (useful when
                  master.key is missing on the target; operator will provide
                  it manually and then start the service).
      force: pass --force to reinstall even if same version already present.
    """
    if not _validate_machine_name(name):
        return
    machines = load_inventory()
    target = next((m for m in machines if m["name"] == name), None)
    if not target:
        error(f"Máquina '{name}' no encontrada en el inventario")
        return
    if target.get("role") == "monitor":
        error(f"{name} es el manager (monitor) — socialwarden ya está instalado aquí directamente, no se enrola")
        return

    if not os.path.isdir(socialwarden_AGENT_SRC):
        error(f"Paquete socialwarden-agent no encontrado en {socialwarden_AGENT_SRC}")
        return

    required_files = [
        "VERSION", "install.sh",
        "socialwarden-agent.py", "socialwarden-agent", "hot_env.py",
        "socialwarden-agent.service", "shamir.py",
    ]
    for f in required_files:
        p = os.path.join(socialwarden_AGENT_SRC, f)
        if not os.path.isfile(p):
            error(f"Falta fichero del paquete: {p}")
            return

    ssh_cmd = target["ssh"]
    ip = target.get("ip", "?")
    print(f"\n{C.CYAN}{C.BOLD}  Enrolando socialwarden-agent en {name} ({ip}){C.NC}\n")

    # ---- Step 1: test SSH ---------------------------------------------------
    print(f"{C.BOLD}[1/5]{C.NC} Probando SSH...")
    test = subprocess.run(f"{ssh_cmd} 'echo OK'", shell=True, capture_output=True, text=True, timeout=20)
    if test.returncode != 0 or "OK" not in test.stdout:
        error(f"SSH falló: {test.stderr.strip() or test.stdout.strip()}")
        return
    info("SSH conecta")

    # ---- Step 2: create remote temp dir ------------------------------------
    print(f"\n{C.BOLD}[2/5]{C.NC} Preparando transferencia...")
    # Sub-second uniqueness: int(time.time()) collides if two enrolls fire
    # within 1s on the same host. PID + ms gives ~unique paths even under cron.
    remote_tmp = f"/tmp/socialwarden-agent-install-{int(time.time()*1000)}-{os.getpid()}"
    mk = subprocess.run(f"{ssh_cmd} 'mkdir -p {remote_tmp} && chmod 700 {remote_tmp}'",
                        shell=True, capture_output=True, text=True, timeout=20)
    if mk.returncode != 0:
        error(f"No pude crear {remote_tmp}: {mk.stderr.strip()}")
        return
    info(f"Remote tmp: {remote_tmp}")

    # ---- Step 3: scp files --------------------------------------------------
    print(f"\n{C.BOLD}[3/5]{C.NC} Copiando ficheros del paquete...")
    # Translate ssh command → scp-compatible opts. Example input:
    #   "ssh -o ConnectTimeout=10 -o BatchMode=yes -p 22 user@host"
    # We need to preserve -o KEY=VAL pairs and convert -p (port) → -P (scp).
    ssh_tokens = ssh_cmd.split()
    ssh_host = ssh_tokens[-1]  # user@host (or host)
    scp_tokens = []
    i = 1  # skip "ssh"
    while i < len(ssh_tokens) - 1:
        tok = ssh_tokens[i]
        if tok in ("-o", "-i"):
            # flag that takes an argument
            if i + 1 < len(ssh_tokens) - 1:
                scp_tokens.extend([tok, ssh_tokens[i + 1]])
                i += 2
                continue
        elif tok == "-p":
            # ssh uses -p, scp uses -P for port
            if i + 1 < len(ssh_tokens) - 1:
                scp_tokens.extend(["-P", ssh_tokens[i + 1]])
                i += 2
                continue
        i += 1
    scp_opts = " ".join(scp_tokens)

    for f in required_files:
        src = os.path.join(socialwarden_AGENT_SRC, f)
        cmd = f"scp -q {scp_opts} {src} {ssh_host}:{remote_tmp}/{f}"
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            error(f"scp {f} falló: {r.stderr.strip()}")
            subprocess.run(f"{ssh_cmd} 'rm -rf {remote_tmp}'", shell=True, timeout=10)
            return
    info(f"{len(required_files)} ficheros transferidos")

    # ---- Step 4: run install.sh on the remote ------------------------------
    print(f"\n{C.BOLD}[4/5]{C.NC} Ejecutando installer remoto...")
    # Always use sudo — install.sh requires root. If the ssh user is root
    # already, sudo is a no-op; otherwise it prompts once.
    flags = []
    if no_restart:
        flags.append("--no-restart")
    if force:
        flags.append("--force")
    flag_str = (" " + " ".join(flags)) if flags else ""
    # Pass machine name from inventory so install.sh seeds /etc/socialwarden/config.yaml
    # with the correct `machine.name` field. Without this, install.sh defaults
    # to `hostname` which often diverges from the inventory name (e.g. inventory
    # "socials-agent-prod" vs hostname "prod-2").
    # Defense in depth: name was already regex-validated, but shlex.quote keeps
    # the call safe even if the validator regresses or remote_tmp ever becomes
    # operator-supplied. capture_output preserves remote stderr for diagnosis
    # of installer failures.
    install_cmd = (
        f"cd {shlex.quote(remote_tmp)} && "
        f"sudo socialwarden_MACHINE_NAME={shlex.quote(name)} bash install.sh{flag_str}"
    )
    r = subprocess.run(f"{ssh_cmd} {shlex.quote(install_cmd)}",
                       shell=True, text=True, capture_output=True, timeout=180)
    # Surface installer output even on success (operator wants to see it).
    if r.stdout:
        sys.stdout.write(r.stdout)
    if r.returncode != 0:
        if r.stderr:
            sys.stderr.write(r.stderr)
        error(f"Installer salió con código {r.returncode}")
        subprocess.run(f"{ssh_cmd} 'rm -rf {shlex.quote(remote_tmp)}'", shell=True, timeout=10)
        return
    info("Installer completado")

    # ---- Step 5: cleanup + mark inventory ----------------------------------
    print(f"\n{C.BOLD}[5/5]{C.NC} Cleanup + inventario...")
    subprocess.run(f"{ssh_cmd} 'rm -rf {remote_tmp}'", shell=True, timeout=10)
    info("Remote tmp limpiado")

    # Read VERSION file to stamp the inventory
    with open(os.path.join(socialwarden_AGENT_SRC, "VERSION")) as f:
        v = f.read().strip()

    # MERGE (do not replace) — preserve shamir metadata, identity_fingerprint,
    # identity_registered_at, etc. that other commands populated.
    for m in machines:
        if m["name"] == name:
            dw = m.setdefault("socialwarden", {})
            dw["enrolled"] = True
            dw["version"] = v
            dw["enrolled_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            break
    save_inventory(machines)
    info(f"Inventario actualizado: {name} → socialwarden v{v}")

    print(f"\n{C.GREEN}{C.BOLD}  Enrolado {name} en socialwarden{C.NC}\n")
    print(f"  Siguiente paso: asegurar que hay una config.yaml en el host con las colecciones correctas,")
    print(f"  y que hay una master.key en /run/socialwarden/ (o un bw login válido).")
    print(f"  Verifica con: {C.BOLD}ssh {ssh_host} 'sudo socialwarden-agent status'{C.NC}\n")


# ============================================
# MAIN
# ============================================
def main():
    if len(sys.argv) < 2:
        print(f"""
{C.CYAN}{C.BOLD}  SOCials — Gestor de Máquinas{C.NC}

  Uso:
    python3 machines.py {C.BOLD}list{C.NC}                         Ver máquinas registradas
    python3 machines.py {C.BOLD}add{C.NC}                          Añadir máquina (interactivo)
    python3 machines.py {C.BOLD}remove{C.NC}                       Eliminar máquina
    python3 machines.py {C.BOLD}deploy{C.NC} <nombre>              Desplegar SOC agents (node-exporter, cadvisor, …)
    python3 machines.py {C.BOLD}deploy-db{C.NC} <nombre>           Desplegar Base de Datos interactiva (PG/MySQL/MariaDB + Adminer)
    python3 machines.py {C.BOLD}socialwarden-enroll{C.NC} <nombre>   Instalar socialwarden-agent (client) en la máquina
""")
        return

    cmd = sys.argv[1].lower()

    def _dispatch():
        if cmd == "list":
            list_machines()
        elif cmd == "add":
            add_machine()
        elif cmd == "remove":
            remove_machine()
        elif cmd == "deploy":
            if len(sys.argv) < 3:
                name = ask("Nombre de la máquina: ")
            else:
                name = sys.argv[2]
            deploy_to_machine(name)
        elif cmd == "deploy-db":
            if len(sys.argv) < 3:
                name = ask("Nombre de la máquina: ")
            else:
                name = sys.argv[2]
            deploy_db(name)
        elif cmd in ("socialwarden-enroll", "enroll"):
            args = sys.argv[2:]
            no_restart = "--no-restart" in args
            force = "--force" in args
            name_args = [a for a in args if not a.startswith("--")]
            if not name_args:
                name = ask("Nombre de la máquina: ")
            else:
                name = name_args[0]
            socialwarden_enroll(name, no_restart=no_restart, force=force)
        else:
            error(f"Comando desconocido: {cmd}")

    # Hold the reentrant inventory lock for the whole transaction on mutating
    # commands. `list` is pure read, no lock needed.
    if cmd == "list":
        _dispatch()
    else:
        with inventory_lock():
            _dispatch()

if __name__ == "__main__":
    main()
