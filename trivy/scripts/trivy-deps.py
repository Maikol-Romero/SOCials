#!/usr/bin/env python3
"""
Trivy Dependencies — Recolecta dependencias reales de paquetes vulnerables

Para cada contenedor en cada máquina:
1. Detecta el package manager (apk/dpkg)
2. Dump TODAS las dependencias en un solo comando
3. Construye mapa inverso: "qué depende de este paquete"
4. Cruza con latest.json y añade campo dependsOn

Uso:
  python3 trivy-deps.py           # Recolecta y guarda en latest.json
  python3 trivy-deps.py --dry-run # Solo muestra lo que haría

Requires: SSH access from this host to fleet machines (defined in inventory.json)
"""
import json, subprocess, os, sys, re
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(SCRIPT_DIR, "..", "reports", "latest.json")
INVENTORY = os.path.join(SCRIPT_DIR, "..", "inventory.json")
DRY_RUN = "--dry-run" in sys.argv


def run(cmd, timeout=30):
    """Run a command and return stdout, or empty string on failure."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else ""
    except:
        return ""


def docker_cmd(ssh_cmd, cmd):
    """Run docker command locally or via SSH with proper quoting."""
    if ssh_cmd:
        # Use bash -c with base64 to avoid all quoting issues
        import base64
        encoded = base64.b64encode(cmd.encode()).decode()
        return run(f'{ssh_cmd} "echo {encoded} | base64 -d | bash"')
    return run(cmd)

def get_containers(ssh_cmd=""):
    """Get list of (container_name, image) from a machine."""
    out = docker_cmd(ssh_cmd, 'docker ps --format "{{.Names}}|{{.Image}}"')
    if not out:
        return []
    containers = []
    for line in out.strip().split("\n"):
        parts = line.split("|")
        if len(parts) == 2:
            containers.append((parts[0].strip(), parts[1].strip()))
    return containers


def detect_pkg_manager(container, ssh_cmd=""):
    """Detect package manager in a container: apk, dpkg, or None."""
    out = docker_cmd(ssh_cmd, f"docker exec {container} which apk 2>/dev/null")
    if out and "apk" in out:
        return "apk"
    out = docker_cmd(ssh_cmd, f"docker exec {container} which dpkg 2>/dev/null")
    if out and "dpkg" in out:
        return "dpkg"
    return None


def get_deps_dpkg(container, ssh_cmd=""):
    """Get all package dependencies via dpkg-query. Returns {pkg: [dep1, dep2, ...]}"""
    fmt = chr(92) + 'n'  # literal backslash-n
    out = docker_cmd(ssh_cmd, 'docker exec ' + container + ' dpkg-query -W -f ' + chr(39) + '${Package}|${Depends}' + fmt + chr(39) + ' 2>/dev/null')
    if not out:
        return {}
    deps = {}
    for line in out.strip().split("\n"):
        parts = line.split("|", 1)
        if len(parts) == 2:
            pkg = parts[0].strip()
            raw_deps = parts[1].strip()
            if raw_deps:
                # Parse: "pkg1 (>= 1.0), pkg2 | pkg3" → ["pkg1", "pkg2", "pkg3"]
                dep_list = []
                for d in re.split(r'[,|]', raw_deps):
                    d = d.strip().split("(")[0].strip().split(":")[0].strip()
                    if d and d not in dep_list:
                        dep_list.append(d)
                deps[pkg] = dep_list
            else:
                deps[pkg] = []
    return deps


def get_deps_apk(container, ssh_cmd=""):
    """Get all reverse dependencies via apk --rdepends in a single docker exec."""
    apk_script = 'for p in $(apk list -I 2>/dev/null | cut -d" " -f1 | sed "s/-[0-9].*//"); do rdeps=$(apk info --rdepends $p 2>/dev/null | grep -v "required by" | grep -v "^$" | sed "s/-[0-9].*//" | tr "\n" ","); [ -n "$rdeps" ] && echo "$p|$rdeps"; done'
    out = docker_cmd(ssh_cmd, "docker exec " + container + " sh -c '" + apk_script + "'")
    if not out:
        return {}
    deps = {}
    for line in out.strip().split(chr(10)):
        parts = line.split("|", 1)
        if len(parts) == 2:
            pkg = parts[0].strip()
            raw = parts[1].strip().rstrip(",")
            if raw:
                dep_list = [d.strip() for d in raw.split(",") if d.strip() and d.strip() != pkg]
                deps[pkg] = dep_list
            else:
                deps[pkg] = []
    return deps


def build_reverse_deps(deps_map):
    """From {pkg: [dep1, dep2]} build reverse: {dep1: [pkg], dep2: [pkg]}"""
    reverse = defaultdict(set)
    for pkg, deps in deps_map.items():
        for dep in deps:
            reverse[dep].add(pkg)
    return {k: sorted(v) for k, v in reverse.items()}


def clean_image_name(image):
    """e.g. registry.example.com/your-api:v1.1.7 → your-api"""
    name = image.rsplit("/", 1)[-1] if "/" in image else image
    return name.split(":")[0]


def main():
    print("🔍 Trivy Dependencies Collector")
    print(f"  Report: {REPORT}")
    if DRY_RUN:
        print("  Mode: DRY RUN (no changes)")

    # Load latest.json
    with open(REPORT) as f:
        data = json.load(f)

    vulns = data["vulnerabilities"]
    vuln_pkgs = set(v["pkg"] for v in vulns)
    print(f"  Paquetes vulnerables únicos: {len(vuln_pkgs)}")

    # Load inventory for SSH commands
    machines = [{"name": os.uname().nodename, "ssh": ""}]  # local first
    if os.path.exists(INVENTORY):
        with open(INVENTORY) as f:
            inv = json.load(f)
        mlist = inv.get("machines", inv) if isinstance(inv, dict) else inv
        for m in mlist:
            ssh = m.get("ssh", "")
            if not ssh and m.get("private_ip") and m.get("ssh_user"):
                ssh = f"ssh -o ConnectTimeout=10 -o BatchMode=yes {m['ssh_user']}@{m['private_ip']}"
            if ssh:
                machines.append({"name": m["name"], "ssh": ssh})

    # Map raw hostnames (e.g. AWS internal "ip-10-0-0-10") to logical fleet names.
    # Hostnames not in the map pass through unchanged.
    name_map = {
        # Example mappings — customise for your fleet:
        # "ip-10-0-0-10": "web-prod",
        # "ip-10-0-0-20": "db-primary",
    }

    # Collect deps per image per machine
    # Structure: {machine: {image_clean: {pkg: [rdeps]}}}
    all_rdeps = {}  # "machine:image_clean:pkg" → [rdeps]
    total_containers = 0
    total_with_deps = 0

    for machine in machines:
        mname = name_map.get(machine["name"], machine["name"])
        ssh = machine["ssh"]
        print(f"\n  ── {mname} ──")

        containers = get_containers(ssh)
        if not containers:
            print(f"    No containers found")
            continue

        # Group by image (multiple containers can share same image)
        seen_images = set()
        for cname, image in containers:
            img_clean = clean_image_name(image)
            if img_clean in seen_images:
                continue
            seen_images.add(img_clean)
            total_containers += 1

            # Detect package manager
            pkg_mgr = detect_pkg_manager(cname, ssh)
            if not pkg_mgr:
                print(f"    {img_clean} ({cname}): no package manager")
                continue

            # Get dependencies
            if pkg_mgr == "dpkg":
                deps_map = get_deps_dpkg(cname, ssh)
            else:
                deps_map = get_deps_apk(cname, ssh)

            if not deps_map:
                print(f"    {img_clean} ({cname}): empty deps")
                continue

            # For dpkg: deps_map is forward deps, need to invert
            # For apk: deps_map is already rdeps (--rdepends), use directly
            if pkg_mgr == "dpkg":
                rdeps = build_reverse_deps(deps_map)
            else:
                rdeps = deps_map  # already reverse

            # Only keep entries for vulnerable packages
            relevant = {pkg: rdeps[pkg] for pkg in vuln_pkgs if pkg in rdeps and rdeps[pkg]}

            if relevant:
                total_with_deps += 1
                for pkg, dependants in relevant.items():
                    key = f"{mname}:{img_clean}:{pkg}"
                    all_rdeps[key] = dependants
                print(f"    ✓ {img_clean}: {len(deps_map)} pkgs, {len(relevant)} vulnerable con rdeps")
            else:
                print(f"    {img_clean}: {len(deps_map)} pkgs, 0 vulnerable con rdeps")

    print(f"\n  Contenedores analizados: {total_containers}")
    print(f"  Con dependencias relevantes: {total_with_deps}")
    print(f"  Entradas de rdeps: {len(all_rdeps)}")

    if DRY_RUN:
        # Show sample
        for key, rdeps in list(all_rdeps.items())[:5]:
            print(f"    {key} → {rdeps[:5]}")
        print("  DRY RUN: no changes saved")
        return

    # Apply to vulns
    updated = 0
    for v in vulns:
        pkg = v["pkg"]
        machines_list = v.get("machines", [])
        images = v.get("machine_images", {})

        # Collect all rdeps for this pkg across its machines/images
        all_dependants = set()
        for machine in machines_list:
            machine_images = images.get(machine, [])
            if machine_images:
                for img in machine_images:
                    key = f"{machine}:{img}:{pkg}"
                    if key in all_rdeps:
                        all_dependants.update(all_rdeps[key])
            else:
                # Try any image on this machine
                for key, rdeps in all_rdeps.items():
                    if key.startswith(f"{machine}:") and key.endswith(f":{pkg}"):
                        all_dependants.update(rdeps)

        # Remove self-reference
        all_dependants.discard(pkg)

        if all_dependants:
            v["dependsOn"] = sorted(all_dependants)[:20]  # Cap at 20
            updated += 1

    # Save
    with open(REPORT, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Dependencias aplicadas:")
    print(f"  Vulnerabilidades con dependsOn: {updated}/{len(vulns)}")

    # Classify conflict types
    SYSTEM_CORE = {'libc-bin', 'libc6', 'libc6-compat', 'linux-libc-dev', 'libc-dev-bin', 'libc6-dev'}
    RUNTIME = {'stdlib', 'libpython3.9', 'libpython3.9-minimal', 'libpython3.9-stdlib',
               'libpython3.11', 'libpython3.11-minimal', 'libpython3.11-stdlib'}
    APP_DEPS = {'python3-pyasn1', 'python3-urllib3', 'python3-cryptography', 'jspdf',
                'xgrammar', 'node-fetch', 'express', 'axios'}

    def classify_conflict(pkg, source=""):
        pkg_lower = pkg.lower()
        if pkg in SYSTEM_CORE or pkg_lower.startswith('linux-libc'):
            return {"type": "system-core", "label": "Sistema base", "risk": "alto", "action": "Solo actualizar con rebuild completo de imagen base. Afecta a todo el sistema."}
        if pkg in RUNTIME or 'python3.' in pkg_lower:
            return {"type": "runtime", "label": "Runtime", "risk": "medio", "action": "Requiere recompilar binarios o actualizar el runtime. Puede cambiar comportamiento."}
        if pkg in APP_DEPS or source in ('npm', 'pip'):
            return {"type": "app-dep", "label": "Dependencia de app", "risk": "medio", "action": "Puede afectar al código de la aplicación. Probar en staging antes de prod."}
        if any(x in pkg_lower for x in ['ssl', 'crypto', 'tls', 'openssl']):
            return {"type": "tls", "label": "TLS/Cifrado", "risk": "bajo", "action": "Rebuild de imagen Docker. No afecta código, solo cifrado."}
        if any(x in pkg_lower for x in ['curl', 'xml', 'zlib', 'expat', 'nghttp']):
            return {"type": "image-lib", "label": "Librería de imagen", "risk": "bajo", "action": "Rebuild de imagen Docker o apk/apt upgrade. No afecta código."}
        return {"type": "image-base", "label": "Imagen base", "risk": "bajo", "action": "Rebuild de imagen Docker. No afecta código de la aplicación."}

    classified = 0
    for v in vulns:
        if v.get("hasConflict"):
            ct = classify_conflict(v["pkg"], v.get("source", ""))
            v["conflictType"] = ct
            if v.get("conflictDetail"):
                v["conflictDetail"]["type"] = ct["label"]
                v["conflictDetail"]["riskLevel"] = ct["risk"]
                v["conflictDetail"]["recommendation"] = ct["action"]
            classified += 1
    print(f"  Conflictos clasificados: {classified}")

    # Mark exposed vulnerabilities
    exposed_file = os.path.join(os.path.dirname(REPORT), "exposed.json")
    if os.path.exists(exposed_file):
        with open(exposed_file) as f:
            exposed = json.load(f)
        exp_containers = {}
        for machine, services in exposed.get("services", {}).items():
            exp_containers[machine] = services
        image_info = data.get("image_info", {})
        exp_count = 0
        for v in vulns:
            exposed_domains = []
            for machine in v.get("machines", []):
                for img in v.get("machine_images", {}).get(machine, []):
                    meta = image_info.get(f"{machine}:{img}", {})
                    service = meta.get("service", "")
                    if machine in exp_containers:
                        for exp_name, exp_info in exp_containers[machine].items():
                            img_lower = img.lower()
                            if (img_lower in exp_name.lower() or
                                exp_name.lower() in img_lower or
                                (service and service.lower() in exp_name.lower()) or
                                (service and exp_name.lower() in service.lower())):
                                domain = exp_info.get("domain", "")
                                if domain and domain not in exposed_domains:
                                    exposed_domains.append(domain)
            v["exposed"] = bool(exposed_domains)
            if exposed_domains:
                v["exposedDomains"] = exposed_domains
                exp_count += 1
        print(f"  Vulnerabilidades expuestas a internet: {exp_count}/{len(vulns)}")
    
    with open(REPORT, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  Guardado en: {REPORT}")


if __name__ == "__main__":
    main()
