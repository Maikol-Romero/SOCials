"""hot_env: re-read env from /run/secrets on every request, mtime-cached.

Use from any service that needs to pick up rotated secrets without
a container restart. Cost per call: one stat() (microseconds). File read
happens only on mtime change.

    from hot_env import hot_env
    API_KEY = hot_env()["OPENAI_API_KEY"]

For docker services, mount /run/secrets as ro volume:

    services:
      myservice:
        volumes:
          - /run/secrets:/run/secrets:ro
"""
import os
from pathlib import Path
from threading import RLock

_cache = {}            # {path: (mtime_ns, {k: v})}
_lock = RLock()

DEFAULT_PATH = os.environ.get("SOCIALWARDEN_ENV", "/run/secrets/your-app.env")


def hot_env(path=DEFAULT_PATH):
    """Return the parsed env dict for `path`. Reloads on mtime change."""
    st = os.stat(path)
    with _lock:
        cached = _cache.get(path)
        if cached and cached[0] == st.st_mtime_ns:
            return cached[1]
        parsed = _parse_env(Path(path).read_text())
        _cache[path] = (st.st_mtime_ns, parsed)
        return parsed


def _parse_env(content):
    out = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        # Strip surrounding quotes for shell compatibility
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        out[k.strip()] = v
    return out


def get(key, default=None, path=DEFAULT_PATH):
    """Shortcut: hot_env(path).get(key, default)."""
    try:
        return hot_env(path).get(key, default)
    except FileNotFoundError:
        return default
