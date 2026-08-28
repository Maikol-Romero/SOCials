"""SocialWarden agent enrollment: deploy the secrets agent to fleet machines."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time

from . import inventory
from .utils import C, bold, error, info, warn, project_root


AGENT_SRC = os.path.join(project_root(), "socialwarden-agent")

REQUIRED_FILES = [
    "VERSION", "install.sh",
    "socialwarden-agent.py", "socialwarden-agent", "hot_env.py",
    "socialwarden-agent.service", "shamir.py",
]


def enroll(name: str, no_restart: bool = False, force: bool = False) -> None:
    """Enroll a machine as a socialwarden client: scp package + run install.sh."""
    if not inventory.validate_machine_name(name):
        return

    machines = inventory.load()
    target = inventory.find(name, machines)
    if not target:
        error(f"Machine '{name}' not found in inventory")
        return

    if target.get("role") == "monitor":
        error(f"{name} is the monitor — socialwarden is installed locally, not enrolled")
        return

    if not os.path.isdir(AGENT_SRC):
        error(f"socialwarden-agent package not found at {AGENT_SRC}")
        return

    for f in REQUIRED_FILES:
        p = os.path.join(AGENT_SRC, f)
        if not os.path.isfile(p):
            error(f"Missing package file: {p}")
            return

    ssh_cmd = target["ssh"]
    ip = target.get("ip", "?")
    print(f"\n{C.CYAN}{C.BOLD}  Enrolling socialwarden-agent on {name} ({ip}){C.NC}\n")

    # Step 1: test SSH
    print(f"{C.BOLD}[1/5]{C.NC} Testing SSH...")
    test = subprocess.run(
        f"{ssh_cmd} 'echo OK'",
        shell=True, capture_output=True, text=True, timeout=20,
    )
    if test.returncode != 0 or "OK" not in test.stdout:
        error(f"SSH failed: {test.stderr.strip() or test.stdout.strip()}")
        return
    info("SSH connected")

    # Step 2: create remote temp dir
    print(f"\n{C.BOLD}[2/5]{C.NC} Preparing transfer...")
    remote_tmp = f"/tmp/socialwarden-agent-install-{int(time.time() * 1000)}-{os.getpid()}"
    mk = subprocess.run(
        f"{ssh_cmd} 'mkdir -p {remote_tmp} && chmod 700 {remote_tmp}'",
        shell=True, capture_output=True, text=True, timeout=20,
    )
    if mk.returncode != 0:
        error(f"Cannot create {remote_tmp}: {mk.stderr.strip()}")
        return
    info(f"Remote tmp: {remote_tmp}")

    # Step 3: scp files
    print(f"\n{C.BOLD}[3/5]{C.NC} Copying package files...")
    scp_opts, ssh_host = _parse_ssh_to_scp(ssh_cmd)

    for f in REQUIRED_FILES:
        src = os.path.join(AGENT_SRC, f)
        cmd = f"scp -q {scp_opts} {src} {ssh_host}:{remote_tmp}/{f}"
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            error(f"scp {f} failed: {r.stderr.strip()}")
            subprocess.run(
                f"{ssh_cmd} 'rm -rf {remote_tmp}'", shell=True, timeout=10,
            )
            return
    info(f"{len(REQUIRED_FILES)} files transferred")

    # Step 4: run install.sh
    print(f"\n{C.BOLD}[4/5]{C.NC} Running remote installer...")
    flags = []
    if no_restart:
        flags.append("--no-restart")
    if force:
        flags.append("--force")
    flag_str = (" " + " ".join(flags)) if flags else ""

    install_cmd = (
        f"cd {shlex.quote(remote_tmp)} && "
        f"sudo socialwarden_MACHINE_NAME={shlex.quote(name)} bash install.sh{flag_str}"
    )
    r = subprocess.run(
        f"{ssh_cmd} {shlex.quote(install_cmd)}",
        shell=True, text=True, capture_output=True, timeout=180,
    )
    if r.stdout:
        sys.stdout.write(r.stdout)
    if r.returncode != 0:
        if r.stderr:
            sys.stderr.write(r.stderr)
        error(f"Installer exited with code {r.returncode}")
        subprocess.run(
            f"{ssh_cmd} 'rm -rf {shlex.quote(remote_tmp)}'", shell=True, timeout=10,
        )
        return
    info("Installer completed")

    # Step 5: cleanup + update inventory
    print(f"\n{C.BOLD}[5/5]{C.NC} Cleanup + inventory update...")
    subprocess.run(f"{ssh_cmd} 'rm -rf {remote_tmp}'", shell=True, timeout=10)
    info("Remote tmp cleaned")

    with open(os.path.join(AGENT_SRC, "VERSION")) as vf:
        version = vf.read().strip()

    def _mark_enrolled(machines: list[dict]) -> None:
        for m in machines:
            if m["name"] == name:
                dw = m.setdefault("socialwarden", {})
                dw["enrolled"] = True
                dw["version"] = version
                dw["enrolled_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                break

    inventory.update(_mark_enrolled)
    info(f"Inventory updated: {name} -> socialwarden v{version}")

    print(f"\n{C.GREEN}{C.BOLD}  Enrolled {name} in socialwarden{C.NC}\n")
    print(f"  Next: ensure config.yaml has the right collections on the host,")
    print(f"  and that master.key exists in /run/socialwarden/ (or bw login is valid).")
    print(f"  Verify: {C.BOLD}ssh {ssh_host} 'sudo socialwarden-agent status'{C.NC}\n")


def _parse_ssh_to_scp(ssh_cmd: str) -> tuple[str, str]:
    """Convert ssh command opts to scp-compatible opts. Returns (scp_opts, host)."""
    tokens = ssh_cmd.split()
    host = tokens[-1]
    scp_parts: list[str] = []
    i = 1
    while i < len(tokens) - 1:
        tok = tokens[i]
        if tok in ("-o", "-i"):
            if i + 1 < len(tokens) - 1:
                scp_parts.extend([tok, tokens[i + 1]])
                i += 2
                continue
        elif tok == "-p":
            if i + 1 < len(tokens) - 1:
                scp_parts.extend(["-P", tokens[i + 1]])
                i += 2
                continue
        i += 1
    return " ".join(scp_parts), host
