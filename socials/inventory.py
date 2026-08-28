"""Inventory management: load, save, lock, and query the machine fleet."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from contextlib import contextmanager
from typing import Any, Callable

from .utils import error, inventory_path

MACHINE_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")
IP_RE = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$")

_lock_depth = 0


def _lock_path() -> str:
    return inventory_path() + ".lock"


@contextmanager
def lock():
    """Reentrant advisory file lock, cross-platform (fcntl on Linux, msvcrt on Windows)."""
    global _lock_depth
    if _lock_depth > 0:
        _lock_depth += 1
        try:
            yield
        finally:
            _lock_depth -= 1
        return

    lp = _lock_path()
    os.makedirs(os.path.dirname(lp) or ".", exist_ok=True)
    if not os.path.exists(lp):
        try:
            with open(lp, "w"):
                pass
        except PermissionError:
            pass

    fd = os.open(lp, os.O_RDONLY)
    try:
        deadline = time.time() + 30
        while True:
            try:
                _flock_acquire(fd)
                break
            except (BlockingIOError, OSError):
                if time.time() > deadline:
                    raise TimeoutError("inventory lock held by another process for >30s")
                time.sleep(0.2)
        _lock_depth = 1
        yield
    finally:
        _lock_depth = 0
        try:
            _flock_release(fd)
        except OSError:
            pass
        os.close(fd)


def _flock_acquire(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _flock_release(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)


def update(mutator: Callable[[list[dict[str, Any]]], list[dict[str, Any]] | None]) -> None:
    """Atomic read-modify-write under inventory lock.

    mutator receives machines list — return a new list to replace, or None to save in-place.
    """
    with lock():
        machines = load()
        result = mutator(machines)
        save(result if result is not None else machines)


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
