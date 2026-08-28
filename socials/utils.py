"""Shared utilities: terminal colors, logging, env reading, subprocess runner."""

from __future__ import annotations

import os
import subprocess
import sys


class Colors:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    CYAN = "\033[0;36m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    NC = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        for attr in ("RED", "GREEN", "YELLOW", "CYAN", "DIM", "BOLD", "NC"):
            setattr(cls, attr, "")


if not sys.stdout.isatty():
    Colors.disable()

C = Colors


def info(msg: str) -> None:
    print(f"{C.GREEN}[+]{C.NC} {msg}")


def warn(msg: str) -> None:
    print(f"{C.YELLOW}[!]{C.NC} {msg}")


def error(msg: str) -> None:
    print(f"{C.RED}[-]{C.NC} {msg}")


def ask(msg: str) -> str:
    return input(f"{C.YELLOW}[?]{C.NC} {msg}")


def bold(text: str) -> str:
    return f"{C.BOLD}{text}{C.NC}"


def section(title: str) -> None:
    line = "=" * 39
    print(f"\n{C.CYAN}{C.BOLD}{line}{C.NC}")
    print(f"{C.CYAN}{C.BOLD}  {title}{C.NC}")
    print(f"{C.CYAN}{C.BOLD}{line}{C.NC}\n")


def read_env(filepath: str, key: str, default: str = "") -> str:
    if not os.path.exists(filepath):
        return default
    with open(filepath) as f:
        for line in f:
            line = line.strip().replace("\r", "")
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1]
    return default


def run(cmd: str, timeout: int = 30) -> tuple[str, int]:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", 124
    except OSError:
        return "", 1


def project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def env_path() -> str:
    return os.path.join(project_root(), "monitor", "observability", ".env")


def inventory_path() -> str:
    return os.path.join(project_root(), "inventory.json")
