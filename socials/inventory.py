"""Inventory management: load, save, and query the machine fleet."""

from __future__ import annotations

import json
import os
import re
import time
from contextlib import contextmanager
from typing import Any

from .utils import error, inventory_path

MACHINE_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")
IP_RE = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$")


def validate_machine_name(name: str) -> bool:
    if not MACHINE_NAME_RE.match(name or ""):
        error(f"Machine name '{name}' contains invalid chars. Allowed: [a-zA-Z0-9._-]")
        return False
    return True


def validate_ip(ip: str) -> bool:
    return bool(IP_RE.match(ip or ""))


def load() -> list[dict[str, Any]]:
    path = inventory_path()
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []


def save(machines: list[dict[str, Any]]) -> None:
    path = inventory_path()
    tmp = path + ".tmp"
    pre_uid = pre_gid = None
    if os.path.exists(path):
        st = os.stat(path)
        pre_uid, pre_gid = st.st_uid, st.st_gid
    with open(tmp, "w") as f:
        json.dump(machines, f, indent=2)
    os.replace(tmp, path)
    if pre_uid is not None:
        try:
            os.chown(path, pre_uid, pre_gid)
        except (PermissionError, OSError, AttributeError):
            pass
    try:
        os.chmod(path, 0o640)
    except (PermissionError, OSError):
        pass


def find(name: str, machines: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    if machines is None:
        machines = load()
    return next((m for m in machines if m["name"] == name), None)


def monitor(machines: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    if machines is None:
        machines = load()
    return next((m for m in machines if m.get("role") == "monitor"), None)


def production_machines(machines: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    if machines is None:
        machines = load()
    return [m for m in machines if m.get("role") == "production"]
