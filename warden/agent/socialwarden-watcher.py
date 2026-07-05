#!/usr/bin/env python3
"""
SocialWarden Watcher — opt-in daemon that absorbs stray .env files into the vault.

Architecture:
  Filesystem .env (plaintext on disk) → discover → classify → bw create →
  edit /etc/socialwarden/config.yaml → SIGHUP agent → atomic symlink to
  /run/secrets/<name>.env → audit log.

Runs as a separate systemd service alongside socialwarden-agent v1.4.7+.
Opt-in via marker file /etc/socialwarden/watcher-enabled (otherwise no-op).

Security model:
  - Never logs secret values, only key names + sha256 of the original file.
  - Backs up every .env to .env.pre-socialwarden-<TS> before symlinking.
  - Atomic write+rename for symlink swap (no torn state).
  - Coordinates with the agent via global flock on /var/lib/socialwarden/bw.lock
    so the two daemons never call `bw` in parallel.
  - Per-host single-instance via flock on /var/lib/socialwarden/watcher.lock.

Robustness rules (per project policy 2026-05-13):
  - Never crash on a single bad .env — log + skip + continue the tick.
  - Validate every parse boundary: UTF-8, YAML, JSON, env syntax, bw output.
  - Atomic writes for any file we own. Backups before destructive edits.
  - Bounded retries with exponential backoff for transient bw errors.
  - Timeouts on every subprocess and HTTP call.

# Author: Maikol Romero
Version: 1.0.0
"""

from __future__ import annotations

import base64
import contextlib
import errno
import fcntl
import hashlib
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
WATCHER_NAME = "socialwarden-watcher"
# v1.2.1 (in v1.5.0) — eight bug fixes shipped together. Severity in (parens):
#  1 (CRITICAL) NEVER mutate an existing collection's `output:` in
#    _add_collection_to_agent_config. Pre-existing entries keep their original
#    output path; we ONLY add the merge: block. Otherwise consumers that read
#    /run/secrets/<old>.env stop receiving updates after the watcher edit.
#  2 (CRITICAL) decode_env_text uses splitlines() so CRLF (\r\n) does not
#    leak \r into rendered values (round-trip would silently break).
#  3 (HIGH) drift-marker dedup: compare local value against ALL existing
#    `KEY [drift *]` markers in the collection too, not only the canonical
#    KEY item — prevents cascade of one-marker-per-tick when local stays
#    different from the canonical and a marker already captures it.
#  4 (HIGH) auto_naming format-string injection: escape `{`/`}` in regex
#    group values before template.format() so an exotic path like
#    `/foo/{bar}/.env` cannot raise ValueError or hijack format.
#  5 (MEDIUM) fallback alert: surface WARNING + record metric when Discord
#    delivery fails, so silent webhook outages no longer hide unmapped paths.
#  6 (MEDIUM) materialize=copy race: write tmp in a sibling directory
#    (operator-visible parent) only when the consumer dir is writable; fall
#    back to atomic rename within the same directory otherwise — both paths
#    use fsync+rename, but a sibling tmp narrows the inotify-OPEN window.
#  7 (LOW) _compute_static_content: log WARNING when a key classified as
#    secret has an empty value (so the operator can't miss it post-absorb).
#  8 (LOW) _wait_for_file: parse the merged file once after appearance and
#    return False if parse_env_file returns None (catches partial writes).
# All prior 1.4.18/1.4.19 behaviour (drift markers, auto-discover, rules,
# ignores, fallback_behavior, machine.short_name) preserved.
#
# v1.2.2 (in v1.5.1) — drift-loop hotfix uncovered in live S-FINAL migration:
#  9 (CRITICAL) is_already_managed: accept ANY known managed header, not just
#    SOCIALWARDEN_MERGED_SENTINEL. Sprint 1B/1C/1D `render:` templates carry a
#    different "Generated from .env + vault" banner that pre-dates the
#    sentinel; without recognising it the watcher emits DRIFT [reverted]
#    every tick after the agent re-renders such a consumer. Headers tuple is
#    extensible — add new known shapes there as the fleet evolves.
# 10 (MEDIUM) stats accounting: paths matched by ignore_paths /
#    ignore_patterns no longer inflate stats.no_mapping. `_collection_for`
#    returns a sentinel dict {source: "ignored"} so the caller books them as
#    stats.skipped (the semantics they always should have had). Pre-fix tick
#    summaries claimed `no_mapping: N` for paths we deliberately chose to
#    ignore, which made tick output hard to read.
VERSION = "1.2.2"

DEFAULT_CONFIG = "/etc/socialwarden/config.yaml"
WATCHER_MARKER = "/etc/socialwarden/watcher-enabled"  # opt-in: must exist
WATCHER_LOCK = "/var/lib/socialwarden/watcher.lock"  # single instance
WATCHER_STATE_DIR = "/var/lib/socialwarden/watcher-state"  # M3 absorb journals
# An absorb journal older than this with a non-terminal phase = a partial
# absorb that died mid-flight → surfaced by tick() so it never rots silently.
STUCK_ABSORB_AGE_S = 900
BW_LOCK = "/var/lib/socialwarden/bw.lock"  # serialize bw vs agent
AGENT_PID_FILE = "/run/socialwarden/agent.pid"  # for SIGHUP
SECRETS_DIR = "/run/secrets"  # agent's output dir
AUDIT_LOG = "/var/log/socialwarden/watcher.audit.jsonl"  # append-only
# S5: rolling-head anchor for the audit hash-chain lives at
# "<audit_log>.head" (0600 root). Kept as a separate file so tail-
# truncation / full chain-strip — the one thing in-log chaining alone
# cannot catch — becomes detectable. Off-host shipping (node_exporter
# textfile → Loki/SOC) remains the authoritative defense against a root
# attacker who also deletes this anchor.

# The exact header line the agent writes between the static config block and
# the vault secrets block in every merged file. Used to recognise a
# `materialize: copy` consumer (a REAL managed file, not a symlink). MUST stay
# byte-identical to socialwarden-agent._merge_and_link.
SOCIALWARDEN_MERGED_SENTINEL = "# === Secrets managed by SocialWarden (do not edit) ==="

# v1.2.2 — additional managed-file markers for `render:` templates.
# Sprint 1B/1C/1D templates pre-date the merge sentinel and use their own
# "Generated from .env + vault" header. Recognising both shapes prevents
# spurious DRIFT [reverted] alerts every time the agent re-renders a
# template-managed consumer. Add new known template headers here as the
# fleet evolves; the check is substring match on the first 4 KiB.
SOCIALWARDEN_MANAGED_HEADERS: tuple[str, ...] = (
    SOCIALWARDEN_MERGED_SENTINEL,
    "# Generated from .env + vault. DO NOT EDIT MANUALLY.",
)

# Backups live in tmpfs (intentional — lost on reboot, that's fine).
# Janitor purges anything older than BACKUP_RETENTION_DAYS by absorbed_at
# (NOT by mtime — operator edits to the backup don't extend its life).
BACKUP_DIR = "/run/socialwarden-backups"
BACKUP_RETENTION_DAYS = 30
BACKUP_NAME_FMT = "%Y%m%dT%H%M%SZ"  # appended after sanitized origin path

DEFAULT_POLL_INTERVAL_S = 30
SUBPROCESS_TIMEOUT_S = 30
HTTP_TIMEOUT_S = 10
SYMLINK_WAIT_TIMEOUT_S = 60

# v1.2.0 — auto-naming defaults. These are applied when the operator does
# not override `watch.auto_naming.rules` (and `enabled: true`). Rules are
# tried in order; first match wins. Templates use Python str.format with
# the named groups from the regex plus `{machine_short}` (resolved from
# `machine.short_name` or, if absent, `machine.name`).
DEFAULT_AUTO_NAMING_RULES_RAW: list[dict] = [
    # 1. Stacks under .../fleet-ops-main/monitor/<stack>/.env
    #    Shared monitoring stacks — name is host-agnostic on purpose
    #    (Wazuh/Grafana/Prom config is the same across the fleet manager host).
    {
        "match": r"^/home/ubuntu/fleet-ops-main/monitor/(?P<stack>[^/]+)/\.env$",
        "collection_name": "monitor-{stack}",
    },
    # 2. Other service stacks under .../fleet-ops-main/<svc>/.env
    #    (socialwarden Vaultwarden bootstrap, betterstack-bridge dir, etc.)
    {
        "match": r"^/home/ubuntu/fleet-ops-main/(?P<svc>[^/]+)/\.env$",
        "collection_name": "{svc}-{machine_short}",
    },
    # 3. Apps living under /home/ubuntu/<dirname>/.env — the most common shape
    #    (app-b, example-b, example-app, example-db-project, example-c, ...)
    {
        "match": r"^/home/ubuntu/(?P<dirname>[^/]+)/\.env$",
        "collection_name": "{dirname}-{machine_short}",
    },
    # 4. Same pattern under /root/ for hosts where ops works as root.
    {
        "match": r"^/root/(?P<dirname>[^/]+)/\.env$",
        "collection_name": "{dirname}-{machine_short}",
    },
    # 5. Loose service files in /etc/<svc>.env (e.g. /etc/betterstack-bridge.env
    #    consumed by a systemd EnvironmentFile= unit).
    {
        "match": r"^/etc/(?P<svc>[^/]+)\.env$",
        "collection_name": "{svc}",
    },
    # 6. Catch-all for /home/ubuntu/.env (a generic catch-bin some operators
    #    use). Distinct collection name keeps it from polluting other namespaces.
    {
        "match": r"^/home/ubuntu/\.env$",
        "collection_name": "home-misc-{machine_short}",
    },
]

# Path prefixes the watcher will NEVER touch even if a rule somehow matches.
# These are the system / framework / our-own-state directories where a .env
# is either fake (kernel virtual fs) or a stash of metadata we must not move.
DEFAULT_IGNORE_PATHS: list[str] = [
    "/etc/nvidia-container-toolkit/",
    "/home/ubuntu/tests/",
    "/home/ubuntu/server-setup/",
    "/home/ubuntu/fleet-ops-main/.git/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/tmp/",
    "/var/",  # service state files (Patroni, postgres, our own etc.) — fail-closed
    "/usr/",  # OS packages
    "/opt/socialwarden-agent/",  # our backups
    "/var/lib/socialwarden/",  # our state
    "/run/secrets/",  # our own rendered files (already-managed check covers this too)
]

# basename-level patterns to skip (regex applied to os.path.basename).
DEFAULT_IGNORE_PATTERNS_RAW: list[str] = [
    # Static portions of merge: pipelines, backups, examples, our own rolls.
    r"\.env\.(static|backup|copy|example|template|sample|merged|pre-socialwarden.*|am-\d+T\d+Z)$",
    r"^\.env\.app-b\.copy$",
    r"^\.env-backup$",
]

# Behaviors when no rule matches and the candidate is not ignored:
#   alert_and_wait — fire a Discord alert with a suggested name; do NOT
#                    absorb. Operator confirms via collection_for_dir
#                    override or by adding a rule.
#   silent_skip    — log info; do nothing.
#   absorb_with_default — fall back to `<dirname>-{machine_short}` and
#                    absorb anyway. Aggressive; use with care.
DEFAULT_FALLBACK_BEHAVIOR = "alert_and_wait"

# Discord colors (mirror agent palette for visual continuity)
COLOR_GREEN = 0x2ECC71
COLOR_RED = 0xE74C3C
COLOR_YELLOW = 0xF39C12
COLOR_BLUE = 0x3498DB


# ---------------------------------------------------------------------------
# Logging — JSON line format for Promtail/Loki, mirrors agent
# ---------------------------------------------------------------------------
# Logical machine name (e.g. "host-utils", "host-staging") is read from
# config.yaml -> machine.name at startup; falls back to socket.gethostname()
# if the config can't be loaded. Module-level so all log records pick it up.
_MACHINE_NAME = socket.gethostname()


def set_machine_name(name: str) -> None:
    """Override the logical machine name used in logs / Discord / bw notes."""
    global _MACHINE_NAME
    if name:
        _MACHINE_NAME = name


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "component": WATCHER_NAME,
            "machine": _MACHINE_NAME,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def _setup_logging(level: str = "INFO") -> logging.Logger:
    log = logging.getLogger(WATCHER_NAME)
    if log.handlers:
        return log
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    log.addHandler(handler)
    log.setLevel(getattr(logging, level.upper(), logging.INFO))
    log.propagate = False
    return log


logger = _setup_logging()


# ---------------------------------------------------------------------------
# Discord alerts — never blocks, never crashes
# ---------------------------------------------------------------------------
def send_discord_alert(
    webhook_url: Optional[str],
    title: str,
    description: str,
    color: int,
    machine_name: str,
    fields: Optional[list[dict]] = None,
) -> None:
    """Fire-and-forget Discord embed. Returns silently on any failure."""
    if not webhook_url:
        return

    embed = {
        "title": f"🔎 SocialWarden Watcher — {title}",
        "description": description,
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"SocialWarden Watcher v{VERSION} • {machine_name}"},
    }
    if fields:
        embed["fields"] = fields

    payload = json.dumps({"embeds": [embed]}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"{WATCHER_NAME}/{VERSION}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            if resp.status not in (200, 204):
                logger.warning(f"Discord webhook returned HTTP {resp.status}")
    except urllib.error.URLError as e:
        logger.warning(f"Discord alert failed (URLError): {e.reason}")
    except Exception as e:
        logger.warning(f"Discord alert failed: {e}")


def _safe_blob(s: str) -> str:
    """M21: a non-reversible descriptor of opaque output for logs.

    `bw` stdout for list/create item is JSON containing login.password —
    logging raw prefixes of malformed output could leak a secret. Log the
    length + a sha256 prefix instead (enough to correlate, impossible to
    reverse). Never put bw stdout/stderr verbatim in a log line."""
    if s is None:
        return "<none>"
    h = hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:8]
    return f"<{len(s)}b sha256={h}>"


# ---------------------------------------------------------------------------
# .env parsing — tolerant, never raises
# ---------------------------------------------------------------------------
# Matches KEY=VALUE with optional `export `, optional surrounding whitespace.
# Captures key in group 1 and the raw value (after `=`) in group 2.
_ENV_LINE_RE = re.compile(
    r"""^\s*(?:export\s+)?     # optional 'export '
        ([A-Za-z_][A-Za-z0-9_]*)  # key (POSIX-ish identifier)
        \s*=\s*                  # '=' with optional spaces
        (.*)$                    # raw value, may be quoted, may contain '#'
    """,
    re.VERBOSE,
)


# --- .env value codec (must-fix #1 + #2) ---------------------------------
# This decoder MUST stay byte-for-byte consistent with the agent's
# encode_env_value()/decode_env_value() (socialwarden-agent.py "value codec"
# block). The agent emits values that are not "simple-safe" as a
# self-describing base64 sentinel  __SWB64__<b64>__  (no char special to
# bash/dotenv/compose), so a value with spaces / '#' / '$' / quotes / a
# NEWLINE (PEM, GCP JSON) survives the env file losslessly. We reverse it
# here so absorb-time re-parsing yields the EXACT original bytes.
_DWB64_PREFIX = "__SWB64__"
_DWB64_SUFFIX = "__"


def _decode_dwb64(token: str) -> Optional[str]:
    """If `token` is a SocialWarden base64 sentinel, return the decoded
    original string; otherwise None. Never raises (malformed -> None, so
    the caller falls back to treating it as a literal value and a later
    round-trip check can flag the anomaly rather than silently corrupt)."""
    if (
        token.startswith(_DWB64_PREFIX)
        and token.endswith(_DWB64_SUFFIX)
        and len(token) >= len(_DWB64_PREFIX) + len(_DWB64_SUFFIX)
    ):
        inner = token[len(_DWB64_PREFIX) : len(token) - len(_DWB64_SUFFIX)]
        try:
            return base64.b64decode(inner, validate=True).decode("utf-8")
        except Exception:
            return None
    return None


def _strip_value(raw: str) -> str:
    """Strip surrounding quotes and trailing unescaped comments from a raw .env value.

    Rules (best-effort, matches dotenv conventions):
      - __SWB64__<b64>__ → exact original bytes  (SocialWarden sentinel: #1/#2)
      - "foo bar"   → foo bar       (double-quoted: keep contents verbatim)
      - 'foo bar'   → foo bar       (single-quoted: keep contents verbatim, no escapes)
      - foo bar #c  → foo bar       (unquoted: strip trailing ' #...')
      - foo\\#bar   → foo#bar       (unquoted: '\\#' becomes '#')
    Never raises.
    """
    v = raw.rstrip("\r\n").strip()
    # SocialWarden sentinel is emitted RAW (never quoted, no '#'/space), so the
    # logical token is exactly `v` here. Decode FIRST — it is unambiguous.
    decoded = _decode_dwb64(v)
    if decoded is not None:
        return decoded
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        return v[1:-1]
    # Unquoted: strip inline comment ' #...' but respect '\#'
    out = []
    i = 0
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v) and v[i + 1] == "#":
            out.append("#")
            i += 2
            continue
        if c == "#" and (i == 0 or v[i - 1].isspace()):
            break
        out.append(c)
        i += 1
    return "".join(out).rstrip()


def _raw_dwb64_sentinel_keys(text: str) -> list[str]:
    """ABSORB-side fail-closed guard for the #1/#2 codec sentinel collision.

    Scans the RAW text of a candidate .env for any line whose raw value —
    after the SAME leading normalization `_strip_value` applies first
    (`rstrip("\\r\\n").strip()`) and BEFORE any quote/comment handling —
    is itself a well-formed SocialWarden `__SWB64__<valid-b64>__` sentinel
    (i.e. `_decode_dwb64` would decode it).

    Returns the list of offending keys (empty == clean).

    Why this exists: `parse_env_file` → `_strip_value` → `_decode_dwb64`
    base64-DECODES any value matching that sentinel shape. That is CORRECT
    when re-reading SocialWarden's OWN rendered output (the sentinel is
    expected). But when ABSORBING a RAW, human-written .env for the FIRST
    time, a raw value that literally equals a valid `__SWB64__...__` token
    is anomalous: decoding-and-storing it would put the WRONG bytes in the
    vault, and the must-fix #6 round-trip guard cannot catch it (its
    baseline is derived from the same already-decoded parse). The caller
    (migrate(), only reached when the file is NOT already-managed) uses
    this to refuse the absorb fail-closed and alert, instead of silently
    corrupting. The shared `_decode_dwb64`/`_strip_value` decode semantics
    are intentionally left untouched so managed re-reads do not regress.

    Never raises (best-effort scan; on any error returns []).
    """
    offenders: list[str] = []
    try:
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = _ENV_LINE_RE.match(line)
            if not m:
                continue
            key = m.group(1)
            # Mirror _strip_value's pre-decode normalization EXACTLY so we
            # flag precisely the values it would silently decode.
            v = m.group(2).rstrip("\r\n").strip()
            if _decode_dwb64(v) is not None:
                offenders.append(key)
    except Exception:
        return offenders
    return offenders


def parse_env_file(path: str | os.PathLike) -> Optional[list[tuple[str, str]]]:
    """Parse a .env file into a list of (key, value) pairs preserving order.

    Returns None if the file is unreadable / not UTF-8 / fundamentally broken.
    Returns [] for an empty (but readable) file.
    Skips malformed lines (logs and continues) — never raises.
    Duplicates are preserved (last-write-wins is the caller's job).
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        logger.warning(f"parse_env: cannot read {path}: {e}")
        return None

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        logger.warning(f"parse_env: {path} is not UTF-8 ({e}); skipping")
        return None

    out: list[tuple[str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _ENV_LINE_RE.match(line)
        if not m:
            logger.debug(f"parse_env: {path}:{lineno} malformed, skipping")
            continue
        key = m.group(1)
        value = _strip_value(m.group(2))
        out.append((key, value))
    return out


# ---------------------------------------------------------------------------
# Classification — is a (key, value) pair a secret, config, or skip?
# ---------------------------------------------------------------------------
# Strong signals: substring of key is a known secret marker.
_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(KEY|SECRET|PASSWORD|PASSWD|PWD|TOKEN|BEARER|HMAC|SIGNING|PRIVATE|CREDENTIAL|CREDENTIALS|API_KEY|ACCESS_KEY|DSN|JWT|SESSION_KEY)(?:$|_)",
    re.IGNORECASE,
)

# Strong signals: substring of key is a known config marker.
_CONFIG_KEY_RE = re.compile(
    r"^(PORT|HOST|HOSTNAME|URL|URI|PATH|DIR|FILE|DOMAIN|LOG_LEVEL|DEBUG|VERBOSE|"
    r"ENV|NODE_ENV|PYTHON_ENV|TIMEOUT|MAX_.*|MIN_.*|RETRY_.*|POLL_.*|"
    r"DB_NAME|DB_USER|DB_HOST|DB_PORT|REDIS_HOST|REDIS_PORT|"
    r"REGION|ZONE|BUCKET|TOPIC|QUEUE_NAME)$",
    re.IGNORECASE,
)

# Keys we never touch (managed by other systems, or noise).
_SKIP_KEY_RE = re.compile(
    r"^(IMAGE_TAG|GIT_COMMIT|GIT_BRANCH|BUILD_NUMBER|CI|GITHUB_.*|RUNNER_.*)$",
    re.IGNORECASE,
)

# Empty / placeholder values we never absorb.
_PLACEHOLDER_VALUES = {"", "changeme", "TODO", "FIXME", "xxx", "<your-secret-here>"}


def _looks_high_entropy(value: str) -> bool:
    """Crude entropy heuristic — only used as tie-breaker for ambiguous keys.

    Returns True if `value` looks like a random token (≥16 chars, mixed case
    or digits, no spaces). Conservative — false negatives are fine.
    """
    if len(value) < 16 or " " in value:
        return False
    has_lower = any(c.islower() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_digit = any(c.isdigit() for c in value)
    classes = sum((has_lower, has_upper, has_digit))
    return classes >= 2


def classify(key: str, value: str, overrides: Optional[dict] = None) -> str:
    """Return one of: 'secret', 'config', 'skip'.

    Decision order:
      1. Skip placeholders / CI variables / empty values.
      2. M11 per-target overrides: explicit force_secret / force_config win
         over the name/entropy heuristic (the operator knows their app
         better than a regex does).
      3. Strong key signal → secret.
      4. Strong key signal → config.
      5. Tie-breaker: high-entropy value → secret, else config.
    Defaults to 'config' on ambiguity (don't move into the vault unsolicited).

    `overrides` (M11): {"force_secret": set[str], "force_config": set[str]}
    — typically resolved per consumer dir from
    config.watch.classify_overrides. None = pure heuristic (back-compat).
    """
    if not key:
        return "skip"
    if value in _PLACEHOLDER_VALUES:
        return "skip"
    if _SKIP_KEY_RE.match(key):
        return "skip"
    if overrides:
        if key in (overrides.get("force_secret") or ()):
            return "secret"
        if key in (overrides.get("force_config") or ()):
            return "config"
    if _SECRET_KEY_RE.search(key):
        return "secret"
    if _CONFIG_KEY_RE.match(key):
        return "config"
    # Ambiguous — fall back on value entropy.
    if _looks_high_entropy(value):
        return "secret"
    # Conservative default: when we can't tell, prefer config (don't move into
    # vault unsolicited). The watcher will leave these where they are; the
    # operator can decide to migrate them manually.
    return "config"


# ---------------------------------------------------------------------------
# Discovery — find candidate .env files under a path
# ---------------------------------------------------------------------------
_FILENAME_SKIP_RE = re.compile(
    r"""(
        ^\.env\.example$ | ^\.env\.template$ | ^\.env\.sample$ |
        \.pre-socialwarden-.* | \.bak(-.*)?$ | \.backup$ |
        ^\.env\.test$ | ^\.env\.local$
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# Directory names we never descend into (vendor / build / git internals).
_DIR_SKIP_NAMES = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    "target",
    ".terraform",
}

# M17 — self-protection deny-list. The watcher must NEVER absorb SocialWarden's
# own infrastructure: the machine master.key (decrypts to the agent's
# bootstrap credential — absorbing it = circular dependency + lockout), the
# agent/watcher state + config, and the rendered-secrets tmpfs. A misconfig
# putting one of these under a watch path must fail safe, not eat the bus.
_INFRA_PROTECTED_PREFIXES = (
    "/var/lib/socialwarden",  # master.key, versions, watcher-state, bw.lock
    "/run/socialwarden",  # runtime (pid, heartbeat, backups)
    "/run/socialwarden-backups",
    "/run/secrets",  # the agent's own rendered output
    "/etc/socialwarden",  # config.yaml + opt-in marker
)
# Decommission marker (M18): sibling file that pins a target as deliberately
# rolled back so the next tick does NOT silently re-absorb it.
DECOMMISSION_SUFFIX = ".socialwarden-decommissioned"


def _is_infra_protected(path: str) -> bool:
    """True if `path` is (or lives under) SocialWarden's own infra — never
    absorb. Also matches a file literally named master.key anywhere."""
    try:
        rp = os.path.realpath(path)
    except OSError:
        rp = os.path.abspath(path)
    if os.path.basename(rp) == "master.key":
        return True
    for pref in _INFRA_PROTECTED_PREFIXES:
        pn = os.path.normpath(pref)
        if rp == pn or rp.startswith(pn + os.sep):
            return True
    return False


def discover_candidates(
    root: str | os.PathLike,
    recursive: bool = True,
    max_depth: int = 3,
) -> list[Path]:
    """Find .env-like candidate files under `root`.

    A "candidate" is any regular file whose name matches `.env` or `*.env`
    (excluding the skip patterns above), located under `root` no deeper than
    `max_depth` directory levels.

    Returns absolute Path objects, sorted. Empty list if `root` doesn't exist
    or is unreadable. Never raises.
    """
    root_path = Path(root)
    try:
        if not root_path.is_dir():
            return []
    except OSError as e:
        logger.warning(f"discover: cannot stat {root_path}: {e}")
        return []

    found: list[Path] = []
    root_depth = len(root_path.parts)

    try:
        walker = os.walk(root_path, followlinks=False, onerror=_walk_error)
    except OSError as e:
        logger.warning(f"discover: os.walk failed on {root_path}: {e}")
        return []

    for dirpath, dirnames, filenames in walker:
        # Depth guard
        depth = len(Path(dirpath).parts) - root_depth
        if depth >= max_depth:
            dirnames.clear()  # don't descend further
        # Skip vendor / build dirs (in-place mutation prunes the walk)
        dirnames[:] = [d for d in dirnames if d not in _DIR_SKIP_NAMES]

        for name in filenames:
            if not (name == ".env" or name.endswith(".env")):
                continue
            if _FILENAME_SKIP_RE.search(name):
                continue
            found.append(Path(dirpath) / name)

        if not recursive:
            break

    found.sort()
    return found


def _walk_error(err: OSError) -> None:
    logger.debug(f"discover: walk error {err}")


# ---------------------------------------------------------------------------
# Managed check — has this .env already been absorbed?
# ---------------------------------------------------------------------------
def is_already_managed(
    env_path: str | os.PathLike,
    secrets_dir: str = SECRETS_DIR,
) -> bool:
    """Return True if `env_path` is a symlink whose ultimate target lives
    under `secrets_dir` (default `/run/secrets`).

    Follows the FULL symlink chain (not just one level) so an operator who
    interposed a redirect symlink (e.g. /home/foo/.env → /etc/links/foo.env →
    /run/secrets/foo.env.merged) still gets recognised as managed.

    `secrets_dir` is parametrizable so tests / non-standard deployments can
    override it without monkey-patching the module constant.

    Robust: returns False on any error (no panic). Handles dangling links
    (strict=False) and infinite symlink loops (caught as RuntimeError).
    """
    p = Path(env_path)
    try:
        if p.is_symlink():
            # Resolve walks the whole chain. strict=False lets us match
            # symlinks whose final target doesn't exist yet (common during a
            # race: the watcher swaps the link before the agent renders the
            # merged file).
            resolved = str(p.resolve(strict=False))
            prefix = os.path.normpath(secrets_dir).rstrip("/")
            return resolved == prefix or resolved.startswith(prefix + os.sep)
        # M2: a `materialize: copy` consumer is NOT a symlink — it's a real
        # file the agent rewrote in place, carrying the SocialWarden sentinel
        # header. Without recognising this the watcher would re-absorb it on
        # every tick (the .env is no longer a symlink into secrets_dir).
        # v1.2.2: accept ANY known managed header (merge sentinel OR template
        # "Generated from .env + vault" Sprint 1B/1C/1D shape). Recognising
        # both shapes stops the DRIFT [reverted] loop that fires whenever the
        # agent re-renders a template-managed consumer.
        if p.is_file():
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(4096)
            return any(marker in head for marker in SOCIALWARDEN_MANAGED_HEADERS)
    except (OSError, RuntimeError):
        return False
    return False


# ---------------------------------------------------------------------------
# Crypto — duplicated from socialwarden-agent v1.4.7 lines 118-176 (per S2 scope
# decision 2A: watcher autocontenido). DO NOT diverge from agent's algorithm;
# both must produce identical ciphertext for the same master.key file.
# ---------------------------------------------------------------------------
def _machine_key() -> bytes:
    """sha256('socialwarden-' + /etc/machine-id). Machine-bound — credentials
    encrypted with this can only be decrypted on the same host."""
    try:
        machine_id = open("/etc/machine-id").read().strip()
    except OSError:
        try:
            machine_id = (
                "fallback-" + open("/sys/class/dmi/id/product_uuid").read().strip()
            )
        except OSError as e:
            raise RuntimeError(f"cannot derive machine key: {e}") from e
    return hashlib.sha256(f"socialwarden-{machine_id}".encode()).digest()


def _decrypt_credential(ciphertext_b64: str) -> str:
    """Inverse of agent.encrypt_credential. Raises ValueError on tampering."""
    import base64

    key = _machine_key()
    raw = base64.b64decode(ciphertext_b64)
    if len(raw) < 32:
        raise ValueError("ciphertext too short")
    nonce, mac, encrypted = raw[:16], raw[16:32], raw[32:]
    expected = hashlib.sha256(key + nonce + encrypted).digest()[:16]
    if mac != expected:
        raise ValueError("integrity check failed — wrong machine or tampered file")
    stream = hashlib.sha256(key + nonce).digest()
    decrypted = bytes(
        a ^ b for a, b in zip(encrypted, stream * ((len(encrypted) // 32) + 1))
    )
    return decrypted.decode()


def read_encrypted_file(path: str | os.PathLike) -> Optional[str]:
    """Read /var/lib/socialwarden/master.key (ENC:... format) → plaintext.
    Returns None on any error (no panic). Never logs the plaintext."""
    try:
        content = open(path).read().strip()
    except OSError as e:
        logger.error(f"read_encrypted: cannot read {path}: {e}")
        return None
    if not content.startswith("ENC:"):
        # The agent auto-upgrades plaintext on first read; we won't, since the
        # watcher should never modify the agent's master.key.
        logger.error(
            f"read_encrypted: {path} is not in ENC: format — refusing to touch"
        )
        return None
    try:
        return _decrypt_credential(content[4:])
    except Exception as e:
        logger.error(f"read_encrypted: decrypt failed for {path}: {e}")
        return None


# ---------------------------------------------------------------------------
# flock helper — coordinate bw calls with the agent (shared lock file).
# ---------------------------------------------------------------------------
class FlockTimeout(Exception):
    """Raised when we couldn't acquire the lock within the timeout window."""


class _LockedFile:
    """Context manager: open `path`, take LOCK_EX with timeout, release on exit.

    Uses a busy-wait poll with exponential-ish backoff because fcntl.flock
    has no built-in timeout. Timeout is a hard ceiling (raises FlockTimeout).
    """

    def __init__(self, path: str, timeout_s: float = 30.0):
        self.path = path
        self.timeout_s = timeout_s
        self._fh = None

    def __enter__(self):
        # Ensure the parent dir exists (the lock file itself is touched on open).
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
        except OSError as e:
            raise FlockTimeout(
                f"cannot create lock dir {os.path.dirname(self.path)}: {e}"
            ) from e
        self._fh = open(self.path, "a+")
        deadline = time.monotonic() + self.timeout_s
        delay = 0.05
        while True:
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    self._fh.close()
                    self._fh = None
                    raise FlockTimeout(
                        f"could not acquire {self.path} within {self.timeout_s}s"
                    )
                time.sleep(delay)
                delay = min(delay * 1.5, 1.0)

    def __exit__(self, *exc):
        if self._fh is not None:
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            self._fh.close()
            self._fh = None
        return False


# ---------------------------------------------------------------------------
# BWClient — robust wrapper around the `bw` CLI
# ---------------------------------------------------------------------------
# Stderr substrings that mean "your session is gone, unlock and retry".
_SESSION_INVALID_SIGNALS = (
    "Vault is locked",
    "mac failed",
    "Invalid Master Password",
    "Failed to decrypt",
    "You are not logged in",
    "Session timeout",
    "Invalid api key",  # bw quirk on stale sessions
)

# Stderr substrings worth retrying with backoff (transient network/server).
_TRANSIENT_SIGNALS = (
    "ECONNRESET",
    "ETIMEDOUT",
    "ENOTFOUND",
    "ECONNREFUSED",
    "self-signed certificate",  # vault.example.com is real but bw sometimes flakes
    "fetch failed",
    "Unable to connect",
    "503",
    "502",
    "504",
)


class BWError(Exception):
    """All recoverable bw failures funnel through here so callers can be uniform."""


class BWClient:
    """Wraps the `bw` CLI with session caching, flock, retry, and safe logging.

    Design:
      - Single global lock (BW_LOCK = /var/lib/socialwarden/bw.lock) serializes
        bw calls with the agent. The agent (v1.4.8+) acquires this SAME lock
        path with LOCK_EX around every one of its own `bw` invocations
        (_bw_flock in socialwarden-agent.py), so watcher and agent now
        cooperate: neither clobbers the other's bw session mid-call. The
        retry+re-unlock path below is still kept as defence-in-depth for the
        residual race where the agent times out waiting for the lock and
        proceeds unlocked under heavy contention.
      - lock_scope(): a reentrant context manager that holds the flock across
        a MULTI-call logical operation (e.g. ensure_collection → list_items →
        create item → read-back) so the agent cannot interleave a session
        change between the sub-steps. _run_raw detects an outer-held lock and
        does not re-acquire (flock from two fds in one process self-blocks).
      - Session is cached in memory only (never persisted to disk).
      - Retry policy: up to `max_retries` attempts with exponential backoff
        on transient errors; on session-invalid we re-unlock + retry once.
      - All values are kept out of logs — only key names and short hashes.
    """

    def __init__(
        self,
        email: str,
        server_url: str,
        master_password: str,
        bw_binary: str = "bw",
        lock_path: str = BW_LOCK,
        lock_timeout_s: float = 30.0,
        max_retries: int = 3,
    ):
        if not email or not master_password:
            raise ValueError("BWClient requires email + master_password")
        self.email = email
        self.server_url = server_url
        self._master = master_password  # held in memory only
        self.bw = bw_binary
        self.lock_path = lock_path
        self.lock_timeout_s = lock_timeout_s
        self.max_retries = max_retries
        self._session: Optional[str] = None
        # When non-None, a logical-op flock is already held by an outer
        # lock_scope() and _run_raw must NOT re-acquire (flock from a second
        # fd in the same process would self-block until timeout).
        self._held_lock: Optional["_LockedFile"] = None

    # ------------------------------- public ---------------------------------

    @contextlib.contextmanager
    def lock_scope(self):
        """Hold the bw flock across a multi-call logical operation.

        Use around sequences that must be atomic w.r.t. the agent's bw usage
        — e.g. ensure_collection → list_items → create item → read-back. The
        agent (v1.4.8+) takes the same lock per call, so without this scope
        it could grab the lock *between* our sub-steps and (re)unlock,
        invalidating our session mid-operation. Reentrant: nested scopes
        reuse the outermost lock. Falls back to per-call locking if the
        scope lock can't be acquired (logged, never raises here)."""
        if self._held_lock is not None:
            # Already inside an outer scope — reuse it (no re-acquire).
            yield
            return
        try:
            lf = _LockedFile(self.lock_path, timeout_s=self.lock_timeout_s)
            lf.__enter__()
        except FlockTimeout as e:
            # Could not get the scope lock; degrade to per-call locking so we
            # still make progress (each _run_raw will try on its own).
            logger.warning(
                f"lock_scope: could not acquire {self.lock_path} "
                f"({e}); proceeding with per-call locking"
            )
            yield
            return
        self._held_lock = lf
        try:
            yield
        finally:
            self._held_lock = None
            try:
                lf.__exit__(None, None, None)
            except Exception:
                pass

    def health_check(self) -> dict:
        """Return parsed `bw status` JSON. {'status': 'unlocked'|'locked'|...}.
        Returns {'status': 'error', 'error': '<msg>'} on failure (never raises).
        """
        rc, out, err = self._run_raw(["status"], use_session=False)
        if rc != 0:
            return {"status": "error", "error": err.strip()[:200]}
        try:
            return json.loads(out)
        except json.JSONDecodeError as e:
            return {"status": "error", "error": f"unparseable status: {e}"}

    def list_items_in_collection(self, collection_id: str) -> Optional[list[dict]]:
        """Return all items in the collection (parsed JSON). None on failure.

        Stale-session handler: when bw returns malformed/empty stdout on the
        first attempt (a classic symptom of a peer's `bw unlock` having
        invalidated our cached session), drop the session and retry once
        with a fresh re-unlock. Matches the agent v1.4.8 diagnose_empty
        pattern; without it the watcher silently defers tick after tick
        when the agent is doing concurrent bw work.
        """
        if not collection_id:
            logger.error("list_items: empty collection_id")
            return None

        for attempt in (1, 2):
            rc, out, err = self._run(["list", "items", "--collectionid", collection_id])
            if rc != 0:
                logger.warning(
                    f"list_items({collection_id[:8]}…) attempt {attempt}: "
                    f"bw exit {rc}: {err.strip()[:200]}"
                )
                if attempt == 1:
                    self._session = None  # force re-unlock on retry
                    continue
                return None
            try:
                data = json.loads(out)
            except json.JSONDecodeError as e:
                if attempt == 1:
                    logger.info(
                        f"list_items: malformed stdout on attempt 1 ({e}); "
                        f"dropping session + retrying. stdout={_safe_blob(out)}"
                    )
                    self._session = None
                    continue
                logger.warning(
                    f"list_items: still malformed after re-unlock ({e}); "
                    f"stdout={_safe_blob(out)}"
                )
                return None
            if not isinstance(data, list):
                logger.warning(f"list_items: expected list, got {type(data).__name__}")
                return None
            return data
        return None  # unreachable, defensive

    def list_org_collections(self, org_id: str) -> Optional[list[dict]]:
        """Return all collections in the org (parsed JSON). None on failure.

        Same stale-session retry discipline as list_items_in_collection: a
        peer `bw unlock` (the agent) can invalidate our cached session and
        make the first call return malformed/empty stdout — we drop the
        session and retry once.
        """
        if not org_id:
            logger.error("list_org_collections: empty org_id")
            return None
        for attempt in (1, 2):
            rc, out, err = self._run(
                ["list", "org-collections", "--organizationid", org_id]
            )
            if rc != 0:
                logger.warning(
                    f"list_org_collections attempt {attempt}: bw exit {rc}: "
                    f"{err.strip()[:200]}"
                )
                if attempt == 1:
                    self._session = None
                    continue
                return None
            try:
                data = json.loads(out)
            except json.JSONDecodeError as e:
                if attempt == 1:
                    logger.info(
                        f"list_org_collections: malformed stdout on attempt 1 "
                        f"({e}); dropping session + retrying"
                    )
                    self._session = None
                    continue
                logger.warning(
                    f"list_org_collections: still malformed after re-unlock ({e})"
                )
                return None
            if not isinstance(data, list):
                logger.warning(
                    f"list_org_collections: expected list, got {type(data).__name__}"
                )
                return None
            return data
        return None  # unreachable, defensive

    def ensure_collection(
        self,
        name: str,
        org_id: str,
        preferred_id: Optional[str] = None,
    ) -> tuple[Optional[str], str]:
        """Idempotent get-or-create of an org-collection by name.

        Resolution order:
          1. If `preferred_id` exists in the org → return it (normal path,
             the config-mapped id is valid; no vault mutation).
          2. Else if a collection with `name` exists → return that id
             (the config id drifted / operator supplied only a name).
          3. Else create a new collection named `name` → return its id.

        Returns (collection_id, status) where status is one of:
          - "exists"  : found by id or name, nothing created
          - "created" : a new collection was created
          - "unreachable": bw list failed (transient — caller should defer,
            NOT mutate disk)
          - "denied"  : creation attempted but bw refused (perms) — caller
            must FAIL CLOSED and not touch the .env

        Never raises. Never logs secret material (collection names are not
        secret; ids are truncated).
        """
        if not name or not org_id:
            logger.error("ensure_collection: name and org_id required")
            return None, "denied"

        # The list→create sequence must be one critical section vs the agent
        # (so a peer bw unlock can't split it and so we never double-create).
        with self.lock_scope():
            return self._ensure_collection_locked(name, org_id, preferred_id)

    def _ensure_collection_locked(
        self,
        name: str,
        org_id: str,
        preferred_id: Optional[str],
    ) -> tuple[Optional[str], str]:
        existing = self.list_org_collections(org_id)
        if existing is None:
            # Can't even list — treat as transient. Caller defers; we do NOT
            # create blindly (avoids duplicate collections on a flaky list).
            return None, "unreachable"

        by_id = {c.get("id"): c for c in existing if isinstance(c, dict)}
        by_name = {c.get("name"): c for c in existing if isinstance(c, dict)}

        if preferred_id and preferred_id in by_id:
            return preferred_id, "exists"
        if name in by_name:
            found_id = by_name[name].get("id")
            if found_id:
                if preferred_id and preferred_id != found_id:
                    logger.warning(
                        f"ensure_collection: config id {preferred_id[:8]}… not "
                        f"found, but a collection named {name!r} exists as "
                        f"{found_id[:8]}… — using the existing one (id drift)"
                    )
                return found_id, "exists"

        # Not found by id or name → create it.
        payload = json.dumps(
            {
                "organizationId": org_id,
                "name": name,
                "externalId": None,
                "groups": [],
            }
        )
        logger.info(
            f"ensure_collection: collection {name!r} absent — creating in "
            f"org {org_id[:8]}…"
        )
        rc, out, err = self._run(["encode"], input_data=payload)
        if rc != 0:
            logger.error(f"ensure_collection: bw encode failed: {err.strip()[:200]}")
            return None, "denied"
        encoded = out.strip()
        rc, out, err = self._run(
            ["create", "org-collection", encoded, "--organizationid", org_id]
        )
        if rc != 0:
            # The classic failure here is a least-privilege service account:
            # "You do not have permission" / "User is not part of organization".
            logger.error(
                f"ensure_collection: create org-collection {name!r} refused: "
                f"{err.strip()[:200]}"
            )
            return None, "denied"
        try:
            created = json.loads(out)
            new_id = created.get("id")
        except json.JSONDecodeError as e:
            logger.error(
                f"ensure_collection: create response not JSON ({e}); "
                f"stdout={_safe_blob(out)}"
            )
            return None, "denied"
        if not new_id:
            logger.error("ensure_collection: created collection has no id")
            return None, "denied"
        logger.info(f"ensure_collection: created collection {name!r} = {new_id[:8]}…")
        return new_id, "created"

    def create_login_item(
        self,
        collection_id: str,
        org_id: str,
        name: str,
        value: str,
        username_label: str = "",
        notes: str = "",
    ) -> Optional[str]:
        """Create a login item in `collection_id`.

        Item shape (matches the agent's render_env expectations and the
        existing example-staging convention):
          - item.name           = `name`            (env var key — what the agent uses to render)
          - item.login.username = `username_label`  (descriptive service label, optional)
          - item.login.password = `value`           (the secret)

        Returns the created item's id, or None on failure. Logs only the
        item name + sha256 short prefix of the value — never the value itself.
        """
        if not all([collection_id, org_id, name]):
            logger.error("create_login_item: missing required arg")
            return None

        item = {
            "organizationId": org_id,
            "collectionIds": [collection_id],
            "type": 1,  # 1 = login
            "name": name,
            "notes": notes,
            "login": {
                "username": username_label,
                "password": value,
                "uris": [],
            },
        }
        payload = json.dumps(item)
        value_fp = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[
            :8
        ]
        logger.info(
            f"bw create item name={name!r} label={username_label!r} "
            f"value_sha256={value_fp}… collection={collection_id[:8]}…"
        )

        # encode→create must be one critical section vs the agent so a peer
        # bw unlock cannot invalidate the session between the two sub-calls.
        with self.lock_scope():
            rc, out, err = self._run(["encode"], input_data=payload)
            if rc != 0:
                logger.warning(
                    f"create_login_item: bw encode failed: {err.strip()[:200]}"
                )
                return None
            encoded = out.strip()

            rc, out, err = self._run(["create", "item", encoded])
        if rc != 0:
            logger.warning(f"create_login_item({name!r}) failed: {err.strip()[:200]}")
            return None
        try:
            created = json.loads(out)
            return created.get("id")
        except json.JSONDecodeError as e:
            logger.warning(
                f"create_login_item: response not JSON: {e}; stdout={_safe_blob(out)}"
            )
            return None

    # ------------------------------- internals ------------------------------

    def _run(
        self,
        args: list[str],
        input_data: Optional[str] = None,
    ) -> tuple[int, str, str]:
        """Run `bw <args>` with the cached session, retrying on transient/session errors.

        Returns (rc, stdout, stderr). All under a single flock acquisition for
        the lifetime of the call (single bw process per attempt).
        """
        backoff = 0.5
        last_rc, last_out, last_err = 1, "", "no attempt made"
        for attempt in range(1, self.max_retries + 1):
            try:
                self._ensure_session()
            except BWError as e:
                logger.warning(f"bw unlock failed (attempt {attempt}): {e}")
                last_err = str(e)
                if attempt < self.max_retries:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10.0)
                    continue
                return 1, "", last_err

            rc, out, err = self._run_raw(args, input_data=input_data, use_session=True)
            last_rc, last_out, last_err = rc, out, err
            if rc == 0:
                return rc, out, err

            # Session-invalid → drop cached session, re-unlock, retry once.
            if any(sig in err for sig in _SESSION_INVALID_SIGNALS):
                logger.info(f"bw session invalidated (attempt {attempt}); re-unlocking")
                self._session = None
                continue

            # Transient → backoff + retry.
            if any(sig in err for sig in _TRANSIENT_SIGNALS):
                logger.info(
                    f"bw transient error (attempt {attempt}/{self.max_retries}): "
                    f"{err.strip()[:120]} — backing off {backoff:.1f}s"
                )
                if attempt < self.max_retries:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10.0)
                    continue

            # Non-retryable error.
            break
        return last_rc, last_out, last_err

    def _run_raw(
        self,
        args: list[str],
        input_data: Optional[str] = None,
        use_session: bool = True,
        timeout: float = SUBPROCESS_TIMEOUT_S,
        extra_env: Optional[dict] = None,
    ) -> tuple[int, str, str]:
        """Single bw invocation, under flock, no retry. Robust to all error modes."""
        env = os.environ.copy()
        env["BW_NOINTERACTION"] = "1"
        if use_session and self._session:
            env["BW_SESSION"] = self._session
        if extra_env:
            env.update(extra_env)

        cmd = [self.bw] + args

        def _spawn() -> tuple[int, str, str]:
            try:
                proc = subprocess.run(
                    cmd,
                    input=input_data,
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                logger.warning(
                    f"bw {args[0] if args else '?'} timed out after {timeout}s"
                )
                return 124, "", f"bw {args[0]} timed out"
            except FileNotFoundError:
                logger.error(f"bw binary not found at {self.bw!r}")
                return 127, "", "bw binary not found"
            except OSError as e:
                logger.warning(f"bw spawn failed: {e}")
                return 1, "", str(e)
            return proc.returncode, proc.stdout or "", proc.stderr or ""

        # If an outer lock_scope() already holds the flock, run directly —
        # re-acquiring from a second fd in this process would self-block.
        if self._held_lock is not None:
            return _spawn()
        try:
            with _LockedFile(self.lock_path, timeout_s=self.lock_timeout_s):
                return _spawn()
        except FlockTimeout as e:
            logger.warning(f"bw flock timeout: {e}")
            return 1, "", str(e)

    def _ensure_session(self) -> None:
        """Acquire a BW_SESSION (cached). Raises BWError if unlock fails.

        Master password is passed via env (`BW_PASSWORD_INTERNAL`) so it never
        appears in argv (visible via /proc/<pid>/cmdline) or shell history.
        """
        if self._session:
            return
        # Sanity: are we logged in? If not, fail loud (the agent installer
        # should have run `bw login --apikey` already; we don't reproduce that).
        status = self.health_check()
        if status.get("status") == "unauthenticated":
            raise BWError(
                "bw is not logged in. The agent installer should have run "
                "`bw login --apikey` already; refusing to overwrite that state."
            )
        # Pin the server URL defensively (idempotent if already set).
        if self.server_url:
            self._run_raw(
                ["config", "server", self.server_url],
                use_session=False,
                timeout=10,
            )
        # Unlock — master password injected via env, NEVER argv.
        rc, out, err = self._run_raw(
            ["unlock", "--passwordenv", "BW_PASSWORD_INTERNAL", "--raw"],
            use_session=False,
            extra_env={"BW_PASSWORD_INTERNAL": self._master},
        )
        if rc != 0 or not out.strip():
            raise BWError(f"bw unlock failed: {err.strip()[:200]}")
        self._session = out.strip()


# ---------------------------------------------------------------------------
# Migration result — explicit dataclass so the caller never guesses status
# ---------------------------------------------------------------------------
@dataclass
class MigrationResult:
    """Outcome of a single migrate() invocation.

    status:
      - "absorbed": .env replaced by symlink, bw items created/updated, audit
        written, alert fired.
      - "skipped": nothing to do (already managed, empty file, all-config keys,
        etc.). Idempotent — safe to call repeatedly.
      - "deferred": transient issue (collection unreachable, agent unhealthy).
        Caller should retry on the next tick.
      - "failed": real error. Caller should NOT retry blindly — operator
        attention warranted (reason carries the why).
    """

    status: str
    env_path: str
    collection_id: Optional[str] = None
    collection_name: Optional[str] = None
    keys_absorbed: list = field(default_factory=list)
    keys_skipped: list = field(default_factory=list)
    backup_path: Optional[str] = None
    static_path: Optional[str] = None  # sibling .env.static written for merge
    items_created: list = field(default_factory=list)
    # v1.1.1: value-aware dedup. When a key already exists in the collection
    # with a DIFFERENT value, we create a parallel "drift marker" item (name
    # is intentionally non-POSIX so the agent does not render it into the
    # consumer's .env) and record the event here. Operator decides afterwards
    # which value is canonical. We NEVER overwrite silently.
    drift_items: list = field(default_factory=list)
    reason: str = ""


# ---------------------------------------------------------------------------
# Backup + audit + notes helpers
# ---------------------------------------------------------------------------
def _flatten_path_for_backup(env_path: str) -> str:
    """Encode an absolute path as a single safe filename component.

    /home/ubuntu/svc-a/.env -> home-ubuntu-svc-a-.env
    Non-alphanumeric chars other than '.', '_', '-' are replaced with '_'.
    """
    s = env_path.lstrip("/")
    s = s.replace("/", "-")
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def _ensure_dir(path: str, mode: int = 0o700) -> bool:
    """mkdir -p with target mode. Returns True on success. Never raises."""
    try:
        os.makedirs(path, mode=mode, exist_ok=True)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
        return True
    except OSError as e:
        logger.error(f"_ensure_dir({path}): {e}")
        return False


def _sha256_file(path: str) -> Optional[str]:
    """sha256 hex digest of file contents, or None on read error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        logger.warning(f"sha256: cannot read {path}: {e}")
        return None


def _atomic_copy(src: str, dst: str, mode: int = 0o600) -> bool:
    """Copy src -> dst atomically. Mode applied. Never raises."""
    try:
        with open(src, "rb") as f:
            data = f.read()
    except OSError as e:
        logger.error(f"atomic_copy: read {src} failed: {e}")
        return False
    tmp = f"{dst}.tmp.{os.getpid()}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.chmod(tmp, mode)
        os.rename(tmp, dst)
        return True
    except OSError as e:
        logger.error(f"atomic_copy: write {dst} failed: {e}")
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


# Matches the start of a shell-style env assignment line:
#   FOO=bar         export FOO=bar         FOO="bar"
# Captures the variable name. Lines that don't match (comments, blanks,
# malformed input) are preserved verbatim by _compute_static_content().
_ENV_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def _compute_static_content(env_text: str, secret_keys: set[str]) -> str:
    """Return env_text with every line that defines a secret-classified key
    removed. Preserves comments, blank lines, non-secret assignments, and
    skipped/CI keys verbatim — anything the operator put there for the
    benefit of the app (PORT, LOG_LEVEL, ALLOWED_HOSTS, ...) remains intact.

    Why: the watcher absorbs only the *secret* portion of an .env into the
    vault; the remaining configuration must keep flowing through to the app
    via the agent's `merge:` pipeline. This helper produces what becomes
    `<file>.env.static`.
    """
    if not secret_keys:
        return env_text
    out: list[str] = []
    for line in env_text.splitlines(keepends=True):
        m = _ENV_ASSIGN_RE.match(line)
        if m and m.group(1) in secret_keys:
            continue
        out.append(line)
    return "".join(out)


def _static_path_for(env_path: str) -> str:
    """Return the sibling `.static` path for an absorbed env file.

    Examples:
      /home/foo/.env            -> /home/foo/.env.static
      /home/foo/production.env  -> /home/foo/production.env.static
    """
    return env_path + ".static"


def _merged_target_for(secrets_dir: str, collection_name: str) -> str:
    """Where the agent will render the merged (vault + static) file."""
    return os.path.join(secrets_dir, f"{collection_name}.env.merged")


def _vault_only_target_for(secrets_dir: str, collection_name: str) -> str:
    """Where the agent renders the vault-only file (input to the merge)."""
    return os.path.join(secrets_dir, f"{collection_name}.env")


def _write_text_atomic(path: str, content: str, mode: int = 0o600) -> bool:
    """Write `content` to `path` atomically (write tmp, rename). Returns
    True on success. Never raises. The temp file path is unique per pid so
    concurrent writers don't collide on a shared tmpfs."""
    tmp = f"{path}.tmp.{os.getpid()}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(tmp, mode)
        os.rename(tmp, path)
        return True
    except OSError as e:
        # M22: tmp+rename means `path` (the last-good content) is NEVER
        # truncated on failure — we just don't advance it. Call out ENOSPC
        # explicitly so the operator sees the real cause, not a vague IO err.
        if e.errno == errno.ENOSPC:
            logger.error(
                f"_write_text_atomic({path}): DISK FULL (ENOSPC) — keeping "
                f"last-good {path} untouched; free space and the next "
                f"tick/sync will converge"
            )
        else:
            logger.error(f"_write_text_atomic({path}): {e}")
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


def _format_bw_notes(
    machine_name: str,
    origin: str,
    backup_path: str,
    absorbed_at: datetime,
    retention_days: int,
    key: str,
) -> str:
    """Build the `notes` block we write into every absorbed bw item."""
    expires = absorbed_at + timedelta(days=retention_days)
    return (
        f"[socialwarden-watcher v{VERSION}]\n"
        f"absorbed_at: {absorbed_at.isoformat()}\n"
        f"host: {machine_name}\n"
        f"origin: {origin}\n"
        f"backup_path: {backup_path}\n"
        f"backup_retention_days: {retention_days}\n"
        f"backup_expires_at: {expires.isoformat()}\n"
        f"key: {key}\n"
        # S3: this value lived in plaintext on disk (and possibly git/CI/"
        # backups) BEFORE absorption → treat as already exposed.\n"
        f"rotation_recommended: yes (was plaintext-on-disk pre-absorb; "
        f"rotate at the provider, then update this vault item)\n"
    )


def _format_bw_notes_drift(
    machine_name: str,
    origin: str,
    backup_path: str,
    absorbed_at: datetime,
    retention_days: int,
    key: str,
    drift_name: str,
    existing_item_id: str,
    existing_value_sha_prefix: str,
    local_value_sha_prefix: str,
) -> str:
    """Notes for a v1.1.1 DRIFT marker item.

    A drift marker is created when migrate() finds a key already in the
    target collection with a DIFFERENT value. The marker's NAME is the
    non-POSIX `<KEY> [drift <DATE>]` so agent.render_env skips it (it never
    leaks into the consumer's .env). The notes carry just enough metadata
    (sha256 *prefixes* — never values) for the operator to decide which
    value is canonical and delete the loser afterwards.
    """
    expires = absorbed_at + timedelta(days=retention_days)
    return (
        f"[socialwarden-watcher v{VERSION}]\n"
        f"⚠️ DRIFT — value mismatch on absorb (NOT overwriting)\n"
        f"key_original: {key}\n"
        f"drift_marker_name: {drift_name}\n"
        f"existing_item_id: {existing_item_id}\n"
        f"existing_value_sha256_prefix: {existing_value_sha_prefix}\n"
        f"local_value_sha256_prefix:    {local_value_sha_prefix}\n"
        f"host: {machine_name}\n"
        f"origin: {origin}\n"
        f"backup_path: {backup_path}\n"
        f"absorbed_at: {absorbed_at.isoformat()}\n"
        f"backup_retention_days: {retention_days}\n"
        f"backup_expires_at: {expires.isoformat()}\n"
        f"action_required: verify whether '{key}' (existing) is still the "
        f"canonical value or whether '{drift_name}' (this item) should be. "
        f"After deciding, DELETE the losing item to reduce noise in the "
        f"collection. NOTE: the consumer does NOT read THIS item — its "
        f"non-POSIX name is filtered by agent.render_env (v1.4.18+).\n"
        f"rotation_recommended: yes (value lived in plaintext on disk; "
        f"rotate at provider before promoting either value)\n"
    )


_AUDIT_GENESIS = "GENESIS"


def _audit_last_line(audit_path: str) -> Optional[str]:
    """Return the last non-empty raw line (no trailing \\n) or None."""
    try:
        with open(audit_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if not data:
        return None
    for raw in reversed(data.split(b"\n")):
        if raw.strip():
            return raw.decode("utf-8", "replace")
    return None


def _audit_head_path(audit_path: str) -> str:
    return audit_path + ".head"


def _audit_head_read(audit_path: str) -> Optional[dict]:
    """Return the rolling-head anchor dict, or None if absent/unreadable."""
    try:
        with open(_audit_head_path(audit_path)) as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _audit_head_write(audit_path: str, last_line: str, chained_n: int) -> None:
    """Persist the rolling head (sha256 of the last raw chained line +
    count) atomically at 0600. Best-effort — never raises."""
    hp = _audit_head_path(audit_path)
    payload = json.dumps(
        {
            "sha256": hashlib.sha256(last_line.encode("utf-8")).hexdigest(),
            "n": chained_n,
            "updated": datetime.now(timezone.utc).isoformat(),
        },
        sort_keys=True,
    )
    try:
        tmp = f"{hp}.tmp.{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, hp)
    except OSError as e:
        logger.warning(f"audit head write failed: {e}")


def _append_audit_line(audit_path: str, entry: dict) -> bool:
    """Append a tamper-evident JSON line to the audit log (S5).

    Each entry carries `prev_sha` = sha256 of the previous line's exact
    bytes (no newline). In-place edits / deletions inside the chained
    segment break the chain; tail-truncation and full chain-strip are
    caught by the out-of-log rolling-head anchor (<log>.head). Both are
    surfaced by `verify-audit`. Never raises."""
    parent = os.path.dirname(audit_path)
    if parent:
        _ensure_dir(parent, mode=0o750)
    prev = _audit_last_line(audit_path)
    entry = dict(entry)
    entry["prev_sha"] = (
        hashlib.sha256(prev.encode("utf-8")).hexdigest()
        if prev is not None
        else _AUDIT_GENESIS
    )
    line = json.dumps(entry, ensure_ascii=False, default=str, sort_keys=True)
    try:
        fd = os.open(audit_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except OSError as e:
        logger.warning(f"audit append failed: {e}")
        return False
    # Roll the head anchor forward. n = prior chained count + 1 (best-effort;
    # the sha-of-last-line check is the strong signal, n is a secondary
    # "lines removed" tripwire).
    head = _audit_head_read(audit_path)
    prior_n = head.get("n") if isinstance(head, dict) else None
    chained_n = (prior_n + 1) if isinstance(prior_n, int) else 1
    _audit_head_write(audit_path, line, chained_n)
    return True


def _verify_audit(audit_path: str) -> int:
    """Verify the audit hash-chain. 0=intact, 1=broken/tampered,
    2=unreadable.

    A log that predates S5 has a leading run of UNCHAINED legacy lines
    (no `prev_sha`). Those cannot be cryptographically verified — they are
    reported, not flagged as tampering. The chain anchors onto the LAST
    legacy line (the first chained entry's prev_sha covers it), so editing
    the legacy/chain boundary IS detected. Inside the chained segment every
    line must chain; a non-chained line appearing after the chain started =
    splice/downgrade → broken. The out-of-log rolling-head anchor closes
    tail-truncation and full chain-strip."""
    try:
        with open(audit_path, "rb") as f:
            raw_lines = [ln for ln in f.read().split(b"\n") if ln.strip()]
    except OSError as e:
        print(f"verify-audit: cannot read {audit_path}: {e}")
        return 2
    head = _audit_head_read(audit_path)
    if not raw_lines:
        if head:
            print(
                "verify-audit: log empty but head-anchor present — "
                "the entire chain was stripped (TAMPERED)"
            )
            return 1
        print(f"verify-audit: {audit_path} empty — nothing to verify")
        return 0

    prev_raw: Optional[bytes] = None
    legacy = 0
    chained = 0
    chain_started = False
    for i, rb in enumerate(raw_lines):
        try:
            obj = json.loads(rb)
        except json.JSONDecodeError as e:
            if chain_started:
                print(
                    f"verify-audit: line {i + 1} not JSON ({e}) after chain "
                    "started — chain BROKEN"
                )
                return 1
            legacy += 1
            prev_raw = rb
            continue
        has_prev = "prev_sha" in obj
        if not chain_started and not has_prev:
            legacy += 1
            prev_raw = rb
            continue
        expect = (
            _AUDIT_GENESIS if prev_raw is None else hashlib.sha256(prev_raw).hexdigest()
        )
        if not chain_started:
            if obj.get("prev_sha") != expect:
                print(
                    f"verify-audit: line {i + 1} chain-anchor mismatch — "
                    "the legacy/chain boundary was edited or the chain was "
                    "spliced (TAMPERED)"
                )
                return 1
            chain_started = True
            chained += 1
            prev_raw = rb
            continue
        if not has_prev:
            print(
                f"verify-audit: line {i + 1} has no prev_sha after the chain "
                "started — splice/downgrade attempt (TAMPERED)"
            )
            return 1
        if obj.get("prev_sha") != expect:
            print(
                f"verify-audit: line {i + 1} prev_sha mismatch — a line was "
                f"edited/removed at or before {i + 1} (TAMPERED)"
            )
            return 1
        chained += 1
        prev_raw = rb

    # Out-of-log rolling-head anchor: catches tail-truncation, trailing
    # edits, and full chain-strip that pure in-log chaining cannot see.
    if head:
        if not chain_started:
            print(
                "verify-audit: head-anchor present but the log has no "
                "chained entries — chain stripped (TAMPERED)"
            )
            return 1
        if head.get("sha256") != hashlib.sha256(raw_lines[-1]).hexdigest():
            print(
                "verify-audit: last line does not match the head-anchor — "
                "tail truncated/edited or appended outside the chain "
                "(TAMPERED)"
            )
            return 1
        hn = head.get("n")
        if isinstance(hn, int) and hn > chained:
            print(
                f"verify-audit: head-anchor expects {hn} chained entries "
                f"but only {chained} present — lines removed (TAMPERED)"
            )
            return 1
        anchor_note = "head-anchor OK"
    else:
        anchor_note = "no head-anchor (tail-truncation undetectable)"

    print(
        f"verify-audit: chain intact ✓ ({legacy} legacy + {chained} "
        f"chained of {len(raw_lines)} lines, {anchor_note}, {audit_path})"
    )
    return 0


# ---------------------------------------------------------------------------
# M3 — absorb journal: a durable per-target record of how far an absorb got.
# The migrate() ordering is already crash-safe (symlink/copy is the LAST,
# atomic step), so the journal's job is NOT to make it safe — it's to make a
# partial absorb VISIBLE (so it can't rot silently) and to give `rollback`
# (M4) and drift reconciliation (M14) something authoritative to act on.
# Phases: started → backed_up → static_written → vault_created →
#         config_edited → validated → materialized → done | failed | deferred
# ---------------------------------------------------------------------------
_JOURNAL_TERMINAL = {"done", "failed", "deferred", "skipped"}


def _journal_path(env_path: str, state_dir: str = WATCHER_STATE_DIR) -> str:
    return os.path.join(state_dir, _flatten_path_for_backup(env_path) + ".json")


def _journal_write(
    env_path: str, entry: dict, state_dir: str = WATCHER_STATE_DIR
) -> bool:
    """Atomically persist the absorb journal for `env_path`. Never raises."""
    if not _ensure_dir(state_dir, mode=0o700):
        return False
    path = _journal_path(env_path, state_dir)
    entry = dict(entry)
    entry["env_path"] = env_path
    entry["updated_at"] = datetime.now(timezone.utc).isoformat()
    try:
        return _write_text_atomic(
            path, json.dumps(entry, default=str, indent=2) + "\n", mode=0o600
        )
    except Exception as e:  # noqa: BLE001 — journal must never break migrate
        logger.warning(f"journal write failed for {env_path}: {e}")
        return False


def _journal_read(env_path: str, state_dir: str = WATCHER_STATE_DIR) -> Optional[dict]:
    """Return the journal dict for `env_path`, or None if absent/unreadable."""
    try:
        with open(_journal_path(env_path, state_dir)) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _journal_clear(env_path: str, state_dir: str = WATCHER_STATE_DIR) -> None:
    """Remove the journal once an absorb reached a clean terminal state."""
    try:
        os.unlink(_journal_path(env_path, state_dir))
    except OSError:
        pass


def _shred_unlink(path: str) -> bool:
    """S1: securely destroy a plaintext-secret file. Best-effort multi-pass
    overwrite (random → zeros) then unlink. On any error, still attempt a
    plain unlink so the plaintext doesn't linger. Returns True if the file
    is gone afterwards. Never raises.

    Note: overwrite-in-place is not a guarantee on CoW/journaled/SSD-TRIM
    filesystems, but it raises the bar and, combined with unlink, removes
    the file from normal access + future snapshots. The authoritative win
    is that the plaintext original no longer exists on persistent disk."""
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            try:
                os.unlink(path)
            except OSError:
                pass
            return not os.path.exists(path)
        size = os.path.getsize(path)
        fd = os.open(path, os.O_WRONLY)
        try:
            for filler in (lambda n: os.urandom(n), lambda n: b"\x00" * n):
                os.lseek(fd, 0, os.SEEK_SET)
                remaining = size
                while remaining > 0:
                    chunk = min(remaining, 65536)
                    os.write(fd, filler(chunk))
                    remaining -= chunk
                os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as e:
        logger.warning(
            f"_shred_unlink({path}): overwrite failed ({e}); unlinking anyway"
        )
    try:
        os.unlink(path)
    except OSError as e:
        logger.error(f"_shred_unlink({path}): unlink failed: {e}")
    return not os.path.exists(path)


# Filename format used both by writer and janitor: <flat>-<YYYYMMDDTHHMMSSZ>
_BACKUP_TS_RE = re.compile(r"-(\d{8}T\d{6}Z)$")


def purge_old_backups(
    backup_dir: str = BACKUP_DIR,
    retention_days: int = BACKUP_RETENTION_DAYS,
    now: Optional[datetime] = None,
) -> int:
    """Delete backup files whose embedded TS is older than retention_days.

    Retention is from `absorbed_at` (the TS encoded in the filename), NOT from
    mtime — so an operator editing the backup doesn't extend its life. Returns
    the count of deleted entries. Never raises.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=retention_days)
    try:
        names = os.listdir(backup_dir)
    except FileNotFoundError:
        return 0
    except OSError as e:
        logger.warning(f"purge: cannot list {backup_dir}: {e}")
        return 0

    deleted = 0
    for name in names:
        m = _BACKUP_TS_RE.search(name)
        if not m:
            continue  # foreign filename — leave alone
        try:
            ts = datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue
        if ts >= cutoff:
            continue
        path = os.path.join(backup_dir, name)
        try:
            os.unlink(path)
            deleted += 1
            logger.info(f"purge: deleted {name} (absorbed {(now - ts).days}d ago)")
        except OSError as e:
            logger.warning(f"purge: cannot delete {path}: {e}")
    return deleted


# ---------------------------------------------------------------------------
# M4 — rollback: atomically revert an absorb (the reverse of migrate()).
# ---------------------------------------------------------------------------
def _find_latest_backup(env_path: str, backup_dir: str = BACKUP_DIR) -> Optional[str]:
    """Newest BACKUP_DIR/<flat>-<TS> for env_path, by embedded timestamp."""
    flat = _flatten_path_for_backup(env_path)
    try:
        names = os.listdir(backup_dir)
    except OSError:
        return None
    best, best_ts = None, None
    for n in names:
        if not n.startswith(flat + "-"):
            continue
        m = _BACKUP_TS_RE.search(n)
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ")
        except ValueError:
            continue
        if best_ts is None or ts > best_ts:
            best, best_ts = os.path.join(backup_dir, n), ts
    return best


def _remove_collection_from_agent_config(
    config_path: str, env_path: str
) -> tuple[bool, Optional[dict]]:
    """Remove the sync.collections entry whose merge.link == env_path.

    Atomic (tmp+rename), backs up the config first. Returns (removed, entry).
    `entry` is the removed dict (so the caller can purge its vault items).
    """
    try:
        import yaml
    except ImportError:
        logger.error("rollback: PyYAML not installed")
        return False, None
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f) or {}
    except OSError as e:
        logger.error(f"rollback: cannot read {config_path}: {e}")
        return False, None
    collections = (cfg.get("sync") or {}).get("collections") or []
    removed_entry = None
    kept = []
    for c in collections:
        if (c.get("merge") or {}).get("link") == env_path:
            removed_entry = c
        else:
            kept.append(c)
    if removed_entry is None:
        return False, None
    cfg["sync"]["collections"] = kept

    ts = datetime.now(timezone.utc).strftime(BACKUP_NAME_FMT)
    try:
        with (
            open(config_path, "rb") as fsrc,
            open(f"{config_path}.bak-{ts}", "wb") as fdst,
        ):
            fdst.write(fsrc.read())
        try:
            os.chmod(f"{config_path}.bak-{ts}", 0o600)
        except OSError:
            pass
    except OSError as e:
        logger.warning(f"rollback: config backup failed: {e} (continuing)")

    tmp = f"{config_path}.tmp.{os.getpid()}"
    try:
        with open(tmp, "w") as f:
            yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
        os.chmod(tmp, 0o600)
        os.rename(tmp, config_path)
        return True, removed_entry
    except OSError as e:
        logger.error(f"rollback: config write failed: {e}")
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False, None


def _rollback(
    env_path: str,
    config_path: str = DEFAULT_CONFIG,
    apply: bool = False,
    purge_vault: bool = False,
    backup_dir: str = BACKUP_DIR,
    state_dir: str = WATCHER_STATE_DIR,
    audit_log: str = AUDIT_LOG,
) -> int:
    """Revert an absorb: restore the original .env from backup, drop the
    agent-config collection entry, SIGHUP, remove .env.static. Optionally
    (--purge-vault) delete the vault items too. Dry-run by default.

    Returns 0 on success / clean dry-run, non-zero on error.
    """
    env_path = os.path.abspath(env_path)
    journal = _journal_read(env_path, state_dir=state_dir) or {}
    backup = journal.get("backup_path")
    if not backup or not os.path.exists(backup):
        backup = _find_latest_backup(env_path, backup_dir=backup_dir)
    static_path = _static_path_for(env_path)

    # Resolve the config entry (for the plan + vault purge target).
    entry = None
    try:
        import yaml

        with open(config_path) as f:
            _cfg = yaml.safe_load(f) or {}
        for c in (_cfg.get("sync") or {}).get("collections") or []:
            if (c.get("merge") or {}).get("link") == env_path:
                entry = c
                break
    except (OSError, ImportError, Exception):  # noqa: BLE001
        pass

    print(f"{'APPLY' if apply else 'DRY-RUN'} rollback of {env_path}")
    print(f"  backup to restore : {backup or 'NONE FOUND — cannot restore'}")
    print(
        f"  .env.static remove: {static_path}"
        f"{' (exists)' if os.path.exists(static_path) else ' (absent)'}"
    )
    print(
        f"  agent-config entry: {entry.get('name') if entry else 'NONE (already gone)'}"
    )
    print(f"  journal phase     : {journal.get('phase', 'none')}")
    print(f"  purge vault items : {'YES' if purge_vault else 'no (vault left intact)'}")
    if purge_vault:
        items = journal.get("items_created") or []
        print(f"    items_created   : {items or 'unknown (journal absent)'}")

    if not backup:
        print(
            "ABORT: no backup found — refusing to remove managed state "
            "with nothing to restore."
        )
        return 1
    if not apply:
        print("\n(dry-run — re-run with --apply to execute)")
        return 0

    # 1. Restore the original .env (replace symlink/copy-managed file).
    try:
        with open(backup, "rb") as f:
            original = f.read()
        if os.path.islink(env_path) or os.path.exists(env_path):
            os.unlink(env_path)
        fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, original)
        finally:
            os.close(fd)
        print(f"  restored {env_path} from {os.path.basename(backup)}")
    except OSError as e:
        print(f"ABORT: restore failed: {e}")
        return 1

    # 2. Drop the agent-config collection entry.
    removed, removed_entry = _remove_collection_from_agent_config(config_path, env_path)
    entry = removed_entry or entry
    print(f"  agent-config entry removed: {removed}")

    # 3. SIGHUP the agent so it stops managing/rendering it.
    try:
        subprocess.run(
            ["systemctl", "kill", "--signal=HUP", "socialwarden-agent.service"],
            capture_output=True,
            timeout=5,
        )
        print("  SIGHUP sent to socialwarden-agent")
    except (OSError, subprocess.SubprocessError) as e:
        print(f"  SIGHUP best-effort failed: {e}")

    # 4. Remove .env.static (no longer needed; secrets are back in .env).
    try:
        os.unlink(static_path)
        print(f"  removed {static_path}")
    except FileNotFoundError:
        pass
    except OSError as e:
        print(f"  could not remove {static_path}: {e}")

    # 5. Optional vault purge (OFF by default — deletion is irreversible).
    if purge_vault and entry:
        try:
            cfg = _load_config(config_path)
            daemon = _build_daemon(cfg) if cfg else None
        except Exception:  # noqa: BLE001
            daemon = None
        if daemon is None:
            print("  purge-vault: SKIPPED (could not build bw client)")
        else:
            cid = entry.get("id")
            items = daemon.bw.list_items_in_collection(cid) or []
            for it in items:
                iid = it.get("id")
                if not iid:
                    continue
                rc, _, err = daemon.bw._run(["delete", "item", iid])
                print(
                    f"    deleted vault item {iid[:8]}…: "
                    f"{'ok' if rc == 0 else err.strip()[:80]}"
                )

    # 6. M18: drop a decommission marker so the next tick does NOT silently
    # re-absorb what we just reverted (the .env is plaintext again and would
    # otherwise look like a fresh candidate). Operator removes the marker
    # (`rm <env>.socialwarden-decommissioned`) to re-enable absorption.
    marker = env_path + DECOMMISSION_SUFFIX
    try:
        with open(marker, "w") as f:
            f.write(
                f"rolled back {datetime.now(timezone.utc).isoformat()}\n"
                f"remove this file to let socialwarden-watcher absorb "
                f"{env_path} again\n"
            )
        print(f"  decommission marker written: {marker}")
    except OSError as e:
        print(
            f"  WARNING: could not write decommission marker ({e}); "
            f"the watcher may re-absorb {env_path} on its next tick"
        )

    # 7. Clear the journal + audit.
    _journal_clear(env_path, state_dir=state_dir)
    _append_audit_line(
        audit_log,
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "rolled_back",
            "origin": env_path,
            "restored_from": backup,
            "config_entry_removed": removed,
            "vault_purged": bool(purge_vault and entry),
            "decommission_marker": marker,
        },
    )
    print("rollback complete.")
    return 0


# ---------------------------------------------------------------------------
# v1.2.0 — auto-discover helpers (pure functions, easy to unit-test)
# ---------------------------------------------------------------------------
def _machine_short_name(config: dict) -> str:
    """Resolve the per-host short alias for collection naming.

    Convention used in this fleet (matches the existing collection names in
    the vault, e.g. `example-staging`, `example-app-staging`, `host-prod`):
      machine.name           machine.short_name
      host-utils             utils
      host-staging           staging
      host-db                db
      host-2            host-2
      host-dev            dev
      voice-host             prod
      host-prod              prod

    If `machine.short_name` is set in config.yaml, use that verbatim.
    Otherwise fall back to `machine.name` literally (safe default — no
    surprising rewrites; the operator can set short_name later).
    """
    machine = config.get("machine") or {}
    short = machine.get("short_name")
    if short:
        return str(short)
    return str(machine.get("name") or "unknown")


def _compile_auto_naming_rules(config: dict) -> list[tuple]:
    """Compile (regex, template) tuples from config.watch.auto_naming.rules.

    Returns [] if auto_naming is disabled or absent. Uses
    DEFAULT_AUTO_NAMING_RULES_RAW if `enabled: true` but no `rules:` key
    is provided.

    Each compiled tuple is (re.Pattern, str). The template string is
    expanded later via str.format with the regex named groups + the
    `machine_short` injection.

    Fail-closed: a malformed regex raises re.error at config load.
    """
    watch = config.get("watch") or {}
    auto = watch.get("auto_naming") or {}
    if not auto.get("enabled", False):
        return []
    rules_raw = auto.get("rules")
    if rules_raw is None:
        rules_raw = DEFAULT_AUTO_NAMING_RULES_RAW
    compiled: list[tuple] = []
    for rule in rules_raw or []:
        pat = None
        tmpl = None
        if isinstance(rule, dict):
            pat = rule.get("match")
            tmpl = rule.get("collection_name")
        elif isinstance(rule, (list, tuple)) and len(rule) == 2:
            pat, tmpl = rule[0], rule[1]
        if not pat or not tmpl:
            logger.warning(
                f"auto_naming: rule missing match/collection_name, skipping: {rule!r}"
            )
            continue
        try:
            compiled.append((re.compile(pat), str(tmpl)))
        except re.error as e:
            # Fail loud: an operator who writes a bad regex deserves to know
            # at startup, not three weeks later when a new .env appears.
            raise ValueError(f"auto_naming: bad regex {pat!r} in rule: {e}") from e
    return compiled


def _load_ignore_paths(config: dict) -> list[str]:
    """Return the path-prefix ignore list (defaults if absent)."""
    watch = config.get("watch") or {}
    raw = watch.get("ignore_paths")
    if raw is None:
        return list(DEFAULT_IGNORE_PATHS)
    return [str(p) for p in raw if p]


def _compile_ignore_patterns(config: dict) -> list:
    """Return compiled basename regex ignore patterns (defaults if absent)."""
    watch = config.get("watch") or {}
    raw = watch.get("ignore_patterns")
    if raw is None:
        raw = DEFAULT_IGNORE_PATTERNS_RAW
    compiled = []
    for p in raw or []:
        if not p:
            continue
        try:
            compiled.append(re.compile(p))
        except re.error as e:
            raise ValueError(f"ignore_patterns: bad regex {p!r}: {e}") from e
    return compiled


def _is_path_ignored(env_path: str, ignore_paths: list[str]) -> bool:
    """True if env_path starts with ANY of the ignore_paths prefixes."""
    norm = env_path
    for prefix in ignore_paths:
        if not prefix:
            continue
        # Match directory prefix exactly OR as a path component boundary.
        if norm.startswith(prefix):
            return True
    return False


def _is_basename_ignored(env_path: str, ignore_patterns: list) -> bool:
    """True if os.path.basename(env_path) matches any ignore_patterns regex."""
    base = os.path.basename(env_path)
    for pat in ignore_patterns:
        if pat.search(base):
            return True
    return False


def _apply_auto_naming(
    env_path: str,
    rules: list[tuple],
    machine_short: str,
) -> Optional[tuple]:
    """Apply compiled auto-naming rules to env_path.

    Returns (collection_name, rule_index) on first match, or None if no
    rule matches. The template is expanded with the regex named groups
    plus a `machine_short` injection.
    """
    for idx, (regex, template) in enumerate(rules):
        m = regex.match(env_path)
        if not m:
            continue
        params = dict(m.groupdict())
        # Always available — even if the template doesn't use it, no harm.
        params["machine_short"] = machine_short
        # v1.5.0 (bug #4, HIGH): escape '{' and '}' inside captured groups
        # before format() so a path containing literal braces (e.g. a folder
        # called `{foo}`) can't blow up template.format with ValueError nor
        # be misinterpreted as a nested format placeholder. machine_short
        # is operator-supplied config, escape it too defensively.
        params = {
            k: (str(v).replace("{", "{{").replace("}", "}}") if v is not None else "")
            for k, v in params.items()
        }
        try:
            name = template.format(**params)
        except (KeyError, IndexError, ValueError) as e:
            logger.warning(
                f"auto_naming: rule {idx} template {template!r} expansion "
                f"failed for {env_path!r}: {e}"
            )
            continue
        if not name:
            continue
        return (name, idx)
    return None


def _suggest_name_for_unmapped(env_path: str, machine_short: str) -> str:
    """Best-effort suggestion when no rule fires (used by fallback alert)."""
    parent = os.path.dirname(env_path)
    dirname = os.path.basename(parent) or "misc"
    base = os.path.basename(env_path)
    # If it's `<dir>/.env`, suggest `<dirname>-<machine_short>`.
    # If it's `/etc/<name>.env`, suggest `<name>-<machine_short>`.
    if base == ".env":
        return f"{dirname}-{machine_short}"
    stem = base[:-4] if base.endswith(".env") else base
    return f"{stem}-{machine_short}"


# ---------------------------------------------------------------------------
# WatcherDaemon — owns the migrate() flow. tick() + main loop live in Phase D.
# ---------------------------------------------------------------------------
class WatcherDaemon:
    """Holds config + bw_client + per-host state. Stateless across ticks."""

    def __init__(
        self,
        config: dict,
        bw_client: BWClient,
        machine_name: str = "",
        agent_config_path: str = DEFAULT_CONFIG,
        agent_pid_file: str = AGENT_PID_FILE,
        secrets_dir: str = SECRETS_DIR,
        backup_dir: str = BACKUP_DIR,
        audit_log: str = AUDIT_LOG,
        backup_retention_days: int = BACKUP_RETENTION_DAYS,
        symlink_wait_timeout: float = SYMLINK_WAIT_TIMEOUT_S,
        max_per_tick: int = 5,
        discord_webhook: Optional[str] = None,
    ):
        if bw_client is None:
            raise ValueError("WatcherDaemon requires a bw_client")
        self.config = config or {}
        self.bw = bw_client
        self.machine_name = machine_name or _MACHINE_NAME
        self.agent_config_path = agent_config_path
        self.agent_pid_file = agent_pid_file
        self.secrets_dir = secrets_dir
        self.backup_dir = backup_dir
        self.audit_log = audit_log
        self.state_dir = WATCHER_STATE_DIR
        self.backup_retention_days = backup_retention_days
        self.symlink_wait_timeout = symlink_wait_timeout
        self.max_per_tick = max(1, int(max_per_tick))
        self.discord_webhook = discord_webhook
        # M14: flap-suppression for drift alerts — (link, kind) seen this run.
        self._drift_alerted: set = set()
        self.org_id = (self.config.get("organization") or {}).get("id", "")
        if not self.org_id:
            logger.warning(
                "WatcherDaemon: organization.id not set in config — bw create will fail"
            )
        # v1.2.0 auto-discover state. Compiled at construction so a bad
        # regex in config.yaml surfaces at startup (fail-loud), and so the
        # hot tick path doesn't re-compile on every candidate.
        self.machine_short = _machine_short_name(self.config)
        try:
            self.auto_naming_rules = _compile_auto_naming_rules(self.config)
            self.ignore_paths = _load_ignore_paths(self.config)
            self.ignore_patterns = _compile_ignore_patterns(self.config)
        except ValueError:
            # Bad regex in config → refuse to start (no silent skip).
            raise
        # Per-tick alert dedup so a single tick doesn't spam Discord for
        # the same unmapped path more than once. Lifetime: cleared each tick.
        self._alerted_unmapped: set = set()
        self.fallback_behavior = (
            (self.config.get("watch") or {})
            .get("auto_naming", {})
            .get("fallback_behavior", DEFAULT_FALLBACK_BEHAVIOR)
        )

    # ---------------------- public: migration -------------------------------

    def migrate(
        self,
        env_path: str,
        collection_id: str,
        collection_name: str,
    ) -> MigrationResult:
        """Absorb a single .env into the vault. Idempotent + atomic.

        Mixed-content safe: secrets go to the vault, **non-secret config
        (PORT, LOG_LEVEL, comments, blanks) is preserved verbatim in a
        sibling `.env.static` file**, and the agent's `merge:` pipeline
        rebuilds a `.env.merged` file containing BOTH halves. The original
        path becomes a symlink to that merged file, so the app sees the
        same content it always did.

        Order matters: we BACK UP the original, write the static file,
        create vault items, edit the agent config (with merge: block),
        SIGHUP + wait for /run/secrets/<name>.env.merged, validate, then
        symlink-swap, then audit + post_sync + alert. Any failure pre-
        symlink leaves the .env intact (the static file may be present
        but is benign — it's just a copy minus the secrets).
        """
        res = MigrationResult(
            status="failed",
            env_path=env_path,
            collection_id=collection_id,
            collection_name=collection_name,
        )

        started_at = datetime.now(timezone.utc).isoformat()

        def _j(phase: str) -> None:
            # M3: durable phase journal. Best-effort — never breaks migrate.
            _journal_write(
                env_path,
                {
                    "phase": phase,
                    "collection_id": res.collection_id,
                    "collection_name": collection_name,
                    "started_at": started_at,
                    "backup_path": res.backup_path,
                    "static_path": res.static_path,
                    "items_created": res.items_created,
                    "machine": self.machine_name,
                },
                state_dir=self.state_dir,
            )

        # --- Idempotence guard ---
        if is_already_managed(env_path, secrets_dir=self.secrets_dir):
            res.status = "skipped"
            res.reason = "already a symlink under secrets_dir"
            # A previously-partial journal is now moot (target is managed).
            _journal_clear(env_path, state_dir=self.state_dir)
            return res

        # --- 1. parse + read original text (for static computation) ---
        pairs = parse_env_file(env_path)
        if pairs is None:
            res.reason = "parse_env_file failed (unreadable or non-UTF-8)"
            return res
        if not pairs:
            res.status = "skipped"
            res.reason = "empty env file"
            return res
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                original_text = f.read()
        except OSError as e:
            res.reason = f"cannot re-read {env_path} for static: {e}"
            return res

        # --- 1.5 ABSORB sentinel-collision guard (fail-closed) -------------
        # We only reach here when the file is NOT already-managed (the
        # idempotence guard above returned early for managed files). So this
        # is a RAW, first-time absorb. If any raw value literally equals a
        # well-formed SocialWarden `__SWB64__<valid-b64>__` sentinel,
        # `_strip_value` would have base64-DECODED it during the parse above,
        # storing the WRONG bytes in the vault — and the must-fix #6 round-
        # trip guard cannot catch it (its baseline derives from this same
        # already-decoded parse). No organic secret has SocialWarden's exact
        # internal shape, so refuse the WHOLE file fail-closed rather than
        # risk silent corruption: nothing has been written to disk or the
        # vault yet (backup/static/bw all happen below), so the original
        # .env is left exactly as-is and is NEVER shredded. Operator must
        # handle it manually.
        sentinel_keys = _raw_dwb64_sentinel_keys(original_text)
        if sentinel_keys:
            res.status = "failed"
            res.reason = (
                f"ABSORB REFUSED: raw value(s) for {sentinel_keys} in "
                f"{env_path} match the SocialWarden internal sentinel form "
                f"__SWB64__<base64>__. Absorbing would silently base64-"
                f"decode and store the WRONG bytes in the vault (the value "
                f"round-trip guard cannot detect this on a raw absorb). "
                f"File left untouched (NOT absorbed, NOT shredded). Operator "
                f"must resolve the collision manually before re-running."
            )
            logger.warning(res.reason, extra={"machine": self.machine_name})
            send_discord_alert(
                self.discord_webhook,
                title="ABSORB REFUSED — value matches internal sentinel form",
                description=(
                    f"`{env_path}`: raw value(s) for {sentinel_keys} are "
                    f"shaped exactly like SocialWarden's internal "
                    f"`__SWB64__<base64>__` codec sentinel. The watcher "
                    f"REFUSED to absorb this file to avoid silently base64-"
                    f"decoding and storing corrupted secret bytes. The "
                    f"original file is untouched and was not shredded. "
                    f"Operator action required (rename/escape the value or "
                    f"absorb the affected key manually)."
                ),
                color=COLOR_RED,
                machine_name=self.machine_name,
            )
            return res

        # --- 2. classify (with M11 per-target overrides) ---
        overrides = self._classify_overrides_for(env_path)
        to_absorb: list[tuple[str, str]] = []
        for key, value in pairs:
            kind = classify(key, value, overrides=overrides)
            if kind == "secret":
                to_absorb.append((key, value))
                res.keys_absorbed.append(key)
            else:
                res.keys_skipped.append(f"{key}({kind})")
        if not to_absorb:
            res.status = "skipped"
            res.reason = "no keys classified as secret"
            return res

        # --- 3. compute paths up front (single source of truth) ---
        static_path = _static_path_for(env_path)
        vault_only_target = _vault_only_target_for(self.secrets_dir, collection_name)
        merged_target = _merged_target_for(self.secrets_dir, collection_name)

        # --- 3.5 ensure the vault collection exists (M1) ---------------------
        # FIRST bw op, BEFORE any disk mutation (backup/static/symlink). If the
        # mapped collection doesn't exist we create it idempotently rather than
        # blocking the whole absorb on a missing collection. Fail CLOSED on a
        # permission error (nothing on disk has been touched yet, so the .env
        # is left exactly as-is).
        resolved_id, ensure_status = self.bw.ensure_collection(
            name=collection_name,
            org_id=self.org_id,
            preferred_id=collection_id,
        )
        if ensure_status == "unreachable":
            res.status = "deferred"
            res.reason = "bw could not list org-collections; will retry next tick"
            return res
        if ensure_status == "denied" or not resolved_id:
            res.status = "failed"
            res.reason = (
                f"collection {collection_name!r} absent and could not be "
                f"created (insufficient bw permission?). .env left untouched. "
                f"Fix: create the collection in the vault or grant the "
                f"service account collection-create rights."
            )
            return res
        if resolved_id != collection_id:
            logger.info(
                f"migrate: resolved collection {collection_name!r} to id "
                f"{resolved_id[:8]}… ({ensure_status}); config had "
                f"{collection_id[:8] if collection_id else '<none>'}…"
            )
            collection_id = resolved_id
            res.collection_id = resolved_id

        # --- 4. pre-flight: collection reachable? ---
        existing_items = self.bw.list_items_in_collection(collection_id)
        if existing_items is None:
            res.status = "deferred"
            res.reason = "bw list_items failed; will retry next tick"
            return res

        # Dedup against existing items by item.name (= env var key in our
        # convention). The agent uses item.name to derive the rendered env
        # key, so this is the field that defines uniqueness within a
        # collection from the consumer's perspective.
        # v1.1.1: keep the FULL item (not just the name) so we can compare
        # values too. Same-name + same-value → silent skip (current behavior).
        # Same-name + different-value → DRIFT (create parallel marker, never
        # overwrite). See migrate() bucle and _format_bw_notes_drift below.
        existing_items_by_name: dict[str, dict] = {}
        for it in existing_items:
            if not isinstance(it, dict):
                continue
            nm = it.get("name", "")
            if not nm:
                continue
            # Fail-closed on ambiguity: two items in the same collection with
            # the same name leaves us with no canonical existing value to
            # compare against. Refuse rather than guess (caller can retry
            # after the operator dedupes the vault manually).
            if nm in existing_items_by_name:
                res.status = "failed"
                res.reason = (
                    f"vault collection {collection_name!r} has >1 item named "
                    f"{nm!r}; refusing to migrate ambiguously. Resolve in "
                    f"vault first, then retry."
                )
                logger.warning(res.reason, extra={"machine": self.machine_name})
                return res
            existing_items_by_name[nm] = it

        # --- 5. backup full original BEFORE any bw mutation ---
        if not _ensure_dir(self.backup_dir, mode=0o700):
            res.reason = "cannot create backup dir"
            return res
        absorbed_at = datetime.now(timezone.utc)
        ts = absorbed_at.strftime(BACKUP_NAME_FMT)
        flat = _flatten_path_for_backup(env_path)
        backup_path = os.path.join(self.backup_dir, f"{flat}-{ts}")
        if not _atomic_copy(env_path, backup_path, mode=0o600):
            res.reason = "backup copy failed"
            return res
        res.backup_path = backup_path
        origin_sha = _sha256_file(env_path) or "unavailable"
        _j("backed_up")  # first disk mutation — journal starts here

        # --- 6. write .env.static (config + comments + blanks, minus secrets)
        # We do this BEFORE the agent config edit so that when the agent picks
        # up the new merge: block, the static file it expects already exists.
        secret_keys_set = {k for k, _ in to_absorb}
        # v1.5.0 (bug #7, LOW): warn loudly when an absorb-bound secret has
        # an empty value. The codec round-trip will succeed (empty string is
        # well-defined), but the consumer often interprets `KEY=` as
        # "unset / use default", which may not be what the operator wants
        # for a value that was deliberately classified as a secret.
        empty_secrets = sorted(k for k, v in to_absorb if v == "")
        if empty_secrets:
            logger.warning(
                f"migrate: {len(empty_secrets)} secret(s) in {env_path!r} have "
                f"EMPTY value and will be stored as empty bw items: "
                f"{empty_secrets}. Consumers reading these keys will see "
                f"KEY= (empty). If that is not intended, set a real value "
                f"in the vault before deploying.",
                extra={"machine": self.machine_name},
            )
        static_content = _compute_static_content(original_text, secret_keys_set)
        if not _write_text_atomic(static_path, static_content, mode=0o600):
            res.reason = f"failed to write static file {static_path}"
            return res
        res.static_path = static_path
        _j("static_written")

        # --- 7. create bw items (value-aware dedup) ---
        # v1.1.1: three buckets per `(key, value)` from the local .env vs the
        # vault collection:
        #   - key NOT in vault             → create as before (NEW)
        #   - key in vault, SAME value     → silent skip (idempotent re-runs)
        #   - key in vault, DIFFERENT val  → DRIFT: create parallel marker
        #     item "<KEY> [drift YYYY-MM-DD]" with a notes block listing
        #     sha256 prefixes of both values. NEVER overwrite the existing
        #     vault value (overwrites would lose forensics on real drift).
        # The drift marker's NAME is intentionally non-POSIX so that
        # agent.render_env (v1.4.18+) filters it out of consumer .env files.
        notes_args = dict(
            machine_name=self.machine_name,
            origin=env_path,
            backup_path=backup_path,
            absorbed_at=absorbed_at,
            retention_days=self.backup_retention_days,
        )

        def _sha_prefix(s: str) -> str:
            return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]

        # v1.5.0 (bug #3, HIGH): build a per-key lookup of EXISTING drift
        # markers so we can compare the local value against ALL of them and
        # NOT against just the canonical `KEY` item. Otherwise — if the
        # local value stays different from the canonical AND a drift marker
        # already captures that exact value — every tick keeps creating a
        # new `KEY [drift YYYY-MM-DDTHH:MM]` marker forever (cascade).
        drift_markers_by_key: dict[str, list] = {}
        for nm, it in existing_items_by_name.items():
            # A drift marker name follows shape "<KEY> [drift <DATE>...]".
            # Use a simple prefix split: everything before " [drift " is
            # the canonical key. Names without that suffix are not markers.
            sep = " [drift "
            if sep in nm and nm.endswith("]"):
                canon_key = nm.split(sep, 1)[0]
                drift_markers_by_key.setdefault(canon_key, []).append(it)

        for key, value in to_absorb:
            existing = existing_items_by_name.get(key)
            if existing is not None:
                # SAME-NAME branch: compare values.
                existing_pw = (existing.get("login") or {}).get("password") or ""
                if existing_pw == value:
                    logger.info(
                        f"migrate: key {key!r} present in vault with matching "
                        f"value — silent skip"
                    )
                    continue
                # v1.5.0 (bug #3): before creating a NEW marker, check if
                # an existing drift marker already captures this exact value.
                # Same value already-captured → silent skip (idempotent).
                already_captured = False
                for marker in drift_markers_by_key.get(key, []):
                    marker_pw = (marker.get("login") or {}).get("password") or ""
                    if marker_pw == value:
                        already_captured = True
                        marker_name_for_log = marker.get("name", "?")
                        logger.info(
                            f"migrate: drift for key {key!r} ALREADY captured "
                            f"by marker {marker_name_for_log!r} "
                            f"(value sha={_sha_prefix(value)}) — silent skip "
                            f"to avoid cascade"
                        )
                        break
                if already_captured:
                    continue
                # DRIFT detected (and not already captured): build a non-POSIX
                # marker name (corchetes + spaces ⇒ agent.render_env skips it).
                # Use a stable date-only suffix; if a marker for the same key +
                # date already exists (different value), add HH:MM; if THAT also
                # exists, skip to avoid noisy minute-level cascade.
                day_tag = absorbed_at.strftime("%Y-%m-%d")
                drift_name = f"{key} [drift {day_tag}]"
                if drift_name in existing_items_by_name:
                    minute_tag = absorbed_at.strftime("%Y-%m-%dT%H:%M")
                    drift_name = f"{key} [drift {minute_tag}]"
                    if drift_name in existing_items_by_name:
                        logger.info(
                            f"migrate: drift marker for {key!r} already exists "
                            f"for this minute ({drift_name!r}) — silent skip"
                        )
                        continue
                existing_id = existing.get("id", "?")
                existing_sha_p = _sha_prefix(existing_pw)
                local_sha_p = _sha_prefix(value)
                drift_notes = _format_bw_notes_drift(
                    key=key,
                    drift_name=drift_name,
                    existing_item_id=existing_id,
                    existing_value_sha_prefix=existing_sha_p,
                    local_value_sha_prefix=local_sha_p,
                    **notes_args,
                )
                logger.warning(
                    f"migrate: DRIFT key={key!r} vault_sha={existing_sha_p} "
                    f"local_sha={local_sha_p} → creating marker "
                    f"{drift_name!r} (NOT overwriting existing item "
                    f"{existing_id[:8] if existing_id != '?' else '?'}…)",
                    extra={"machine": self.machine_name},
                )
                drift_id = self.bw.create_login_item(
                    collection_id=collection_id,
                    org_id=self.org_id,
                    name=drift_name,
                    value=value,
                    username_label=collection_name,
                    notes=drift_notes,
                )
                if not drift_id:
                    res.reason = (
                        f"create_login_item failed for drift marker {drift_name!r}"
                    )
                    return res
                res.items_created.append(drift_id)
                res.drift_items.append(
                    {
                        "key": key,
                        "drift_name": drift_name,
                        "drift_item_id": drift_id,
                        "existing_item_id": existing_id,
                        "existing_value_sha_prefix": existing_sha_p,
                        "local_value_sha_prefix": local_sha_p,
                    }
                )
                continue

            # NEW-KEY branch (original behavior).
            notes = _format_bw_notes(key=key, **notes_args)
            # bw item shape: name=key (= env var key, matches agent render),
            # login.username=collection_name (descriptive label only).
            item_id = self.bw.create_login_item(
                collection_id=collection_id,
                org_id=self.org_id,
                name=key,
                value=value,
                username_label=collection_name,
                notes=notes,
            )
            if not item_id:
                res.reason = f"create_login_item failed for key={key}"
                # NOTE: items already created stay in vault (harmless; will be
                # deduplicated on the next attempt). We do NOT delete them
                # because deletion adds risk; vault items without consumers are
                # benign and the next tick will reconcile.
                return res
            res.items_created.append(item_id)
        _j("vault_created")

        # --- 8. edit /etc/socialwarden/config.yaml with merge: block ---
        # M2: decide how the agent should materialize the merged file for
        # this consumer (symlink into /run/secrets, or a real file copied to
        # the .env path for non-root operators).
        mat = self._materialize_for(env_path)
        if not self._add_collection_to_agent_config(
            collection_id=collection_id,
            collection_name=collection_name,
            merge_link=env_path,
            merge_static=static_path,
            merge_target=merged_target,
            vault_only_output=vault_only_target,
            materialize_cfg=mat,
        ):
            res.reason = "agent config.yaml edit failed"
            return res
        _j("config_edited")

        # --- 9. SIGHUP agent (non-fatal if it fails) ---
        self._signal_agent_reload()

        # --- 10. wait for /run/secrets/<name>.env.merged ---
        if not self._wait_for_file(merged_target, self.symlink_wait_timeout):
            res.reason = (
                f"agent did not produce {merged_target} within "
                f"{self.symlink_wait_timeout}s; leaving original .env untouched"
            )
            return res

        # --- 11. validate ALL expected keys (secret + non-secret) in merged ---
        rendered = parse_env_file(merged_target)
        if rendered is None:
            res.reason = f"cannot parse merged {merged_target}"
            return res
        rendered_keys = {k for k, _ in rendered}
        missing_secret = [k for k, _ in to_absorb if k not in rendered_keys]
        if missing_secret:
            res.reason = (
                f"merged file missing absorbed keys: {missing_secret}; not symlinking"
            )
            return res
        # Also verify non-secret keys propagated through the merge. This
        # catches an agent that read .static but failed to copy a value.
        static_pairs = parse_env_file(static_path) or []
        missing_static = [k for k, _ in static_pairs if k not in rendered_keys]
        if missing_static:
            res.reason = (
                f"merged file missing non-secret keys from static: "
                f"{missing_static}; not symlinking"
            )
            return res

        # --- 11.5 VALUE-level round-trip check (must-fix #6) ---------------
        # Key PRESENCE is not enough: if the value codec (#1/#2) mangled a
        # value with spaces / '#' / '$' / quotes / a NEWLINE, the key is
        # still "present" but the bytes are WRONG. We must prove the merged
        # file parses back (SAME parser the consumer-side uses) to the EXACT
        # original bytes BEFORE we let step 12.5 shred the only persistent
        # plaintext copy. Fail CLOSED on any mismatch: keep the original,
        # surface a hard error, alert — an unrecoverable wrong secret in the
        # vault after a reboot (tmpfs backup gone) is the worst outcome.
        merged_map: dict[str, str] = {}
        for k, v in rendered:
            merged_map[k] = v  # last-write-wins, mirrors bash/dotenv/compose
        value_mismatches = []
        for k, original_value in to_absorb:
            got = merged_map.get(k, None)
            if got != original_value:
                value_mismatches.append(k)
        if value_mismatches:
            res.status = "failed"
            res.reason = (
                f"VALUE round-trip FAILED for {value_mismatches} — merged "
                f"file does not decode back to the original bytes; keeping "
                f"{env_path} and the .pre-socialwarden backup intact "
                f"(NOT shredding, NOT symlinking). Likely an .env value "
                f"codec defect; do not deploy."
            )
            logger.error(res.reason, extra={"machine": self.machine_name})
            send_discord_alert(
                self.discord_webhook,
                title="ABSORB ABORTED — value round-trip mismatch",
                description=(
                    f"`{env_path}` → **{collection_name}**: keys "
                    f"{value_mismatches} do not survive the .env codec "
                    f"round-trip. Original file and backup kept; secret was "
                    f"NOT corrupted on disk. Operator action required."
                ),
                color=COLOR_RED,
                machine_name=self.machine_name,
            )
            return res
        _j("validated")

        # --- 12. materialize check + idempotent safety net ---
        # The agent sees merge.{link,materialize} in config and materializes
        # the consumer's .env itself when rendering. The block below is a
        # SAFETY NET that fires only when the agent didn't (older agent,
        # missing feature, race).
        if mat["materialize"] == "copy":
            # Expect a REAL managed file at env_path (sentinel header). If the
            # agent already did it, is_already_managed() is True → done. Else
            # the watcher copies the validated merged bytes into place itself.
            if is_already_managed(env_path, secrets_dir=self.secrets_dir):
                logger.debug("migrate: copy-managed file already in place (agent)")
            else:
                if not self._materialize_copy_safety_net(env_path, merged_target, mat):
                    res.reason = (
                        "materialize=copy: agent did not write the managed "
                        "file and the watcher safety-net copy failed"
                    )
                    return res
                logger.info("migrate: copy-materialized by watcher (agent didn't)")
        else:
            # os.rename() is POSIX-atomic and replaces any prior file/symlink,
            # so re-running when the agent already created the symlink is a
            # benign no-op.
            already_swapped = os.path.islink(env_path) and os.path.realpath(
                env_path
            ) == os.path.realpath(merged_target)
            if not already_swapped:
                if not self._atomic_symlink_swap(env_path, merged_target):
                    res.reason = "symlink swap failed (agent didn't swap either)"
                    return res
                logger.info("migrate: symlink swap performed by watcher (agent didn't)")
            else:
                logger.debug("migrate: symlink already in place (likely by agent)")
        _j("materialized")

        # --- 12.5 S1: destroy the persistent plaintext .pre-socialwarden ---
        # The agent stashes the ORIGINAL .env (with secrets, in cleartext)
        # at <env>.pre-socialwarden on persistent disk. We have an independent
        # tmpfs recovery copy (res.backup_path, made in step 5) AND the
        # secrets are now in the vault — so the persistent plaintext is pure
        # liability (world/group readable, lands in every disk snapshot,
        # defeats SocialWarden's whole reason to exist). Shred it now that the
        # absorb is verified.
        #
        # must-fix #6: the step-5 backup (res.backup_path) is on TMPFS
        # (/run/socialwarden-backups) — a reboot wipes it. .pre-socialwarden is
        # the ONLY persistent copy of the original secrets. We may shred it
        # ONLY if a FINAL value-level round-trip against the file the
        # consumer ACTUALLY sees (env_path: real file for copy, symlink ->
        # merged for symlink) decodes byte-identically to every original
        # secret value. If that fails, KEEP the persistent plaintext (and
        # alert) — a wrong, unrecoverable secret post-reboot is far worse
        # than a lingering plaintext we can re-absorb.
        pre = env_path + ".pre-socialwarden"
        if os.path.isfile(pre) and not os.path.islink(pre):
            final_ok = False
            final_pairs = parse_env_file(env_path)
            if final_pairs is None:
                logger.error(
                    f"S1: cannot re-parse materialized {env_path} for the "
                    f"pre-shred round-trip check — KEEPING {pre}"
                )
            else:
                final_map: dict[str, str] = {}
                for _k, _v in final_pairs:
                    final_map[_k] = _v  # last-write-wins
                final_bad = [k for k, ov in to_absorb if final_map.get(k, None) != ov]
                if final_bad:
                    logger.error(
                        f"S1: FINAL round-trip mismatch on {final_bad} when "
                        f"reading the live {env_path}; KEEPING persistent "
                        f"plaintext {pre} (do not deploy this codec)",
                        extra={"machine": self.machine_name},
                    )
                    send_discord_alert(
                        self.discord_webhook,
                        title="Plaintext KEPT — final round-trip mismatch",
                        description=(
                            f"`{env_path}`: live materialized file does not "
                            f"decode back to original secret(s) {final_bad}. "
                            f"`{pre}` deliberately NOT shredded so the "
                            f"original is still recoverable. Operator action "
                            f"required."
                        ),
                        color=COLOR_RED,
                        machine_name=self.machine_name,
                    )
                else:
                    final_ok = True
            # Belt-and-suspenders: also require the step-5 recovery copy to
            # exist (unchanged precondition) before destroying anything.
            if final_ok and res.backup_path and os.path.exists(res.backup_path):
                if _shred_unlink(pre):
                    logger.info(
                        f"S1: shredded persistent plaintext backup {pre} "
                        f"(value round-trip verified against live {env_path}; "
                        f"tmpfs recovery copy kept at {res.backup_path})"
                    )
                else:
                    logger.warning(f"S1: could not remove {pre}")
            elif final_ok:
                logger.warning(
                    f"S1: round-trip OK but step-5 recovery copy missing "
                    f"({res.backup_path}); KEEPING {pre} until a backup exists"
                )

        # --- 13. audit ---
        _append_audit_line(
            self.audit_log,
            {
                "timestamp": absorbed_at.isoformat(),
                "event": "absorbed",
                "host": self.machine_name,
                "origin": env_path,
                "origin_sha256": origin_sha,
                "backup_path": backup_path,
                "static_path": static_path,
                "collection_id": collection_id,
                "collection_name": collection_name,
                "keys_absorbed": [k for k, _ in to_absorb],
                "keys_skipped": res.keys_skipped,
                "items_created": res.items_created,
                "watcher_version": VERSION,
                # S3: absorbed secrets were plaintext-on-disk before absorption.
                "rotation_recommended": [k for k, _ in to_absorb],
            },
        )
        if to_absorb:
            logger.warning(
                f"S3: {len(to_absorb)} secret(s) from {env_path} were "
                f"plaintext on disk pre-absorb — flagged rotation_recommended "
                f"in vault notes + audit (rotate at provider when feasible)",
                extra={"machine": self.machine_name},
            )

        # --- 14. post_sync hook (optional, fire-and-forget, capped 300s) ---
        ps_cmd = self._post_sync_for(env_path)
        if ps_cmd:
            self._run_post_sync_async(ps_cmd, env_path)

        # --- 15. Discord alert — only when something actually new was added ---
        # If items_created is empty, every secret was already in the vault
        # (a re-validation pass after a previous partial success). Sending
        # an alert in that case is misleading noise.
        if res.items_created:
            send_discord_alert(
                self.discord_webhook,
                title="Absorbed .env",
                description=(
                    f"`{env_path}` → collection **{collection_name}** — "
                    f"{len(res.items_created)} new secret(s) "
                    f"(of {len(to_absorb)} total in vault)"
                ),
                color=COLOR_GREEN,
                machine_name=self.machine_name,
                fields=[
                    {"name": "Host", "value": self.machine_name, "inline": True},
                    {"name": "Backup", "value": backup_path, "inline": False},
                ],
            )
        else:
            logger.info(
                f"migrate: {env_path} re-validated against vault (no new items); "
                "skipping Discord alert"
            )

        res.status = "absorbed"
        res.reason = "ok"
        # Clean terminal state — drop the journal so it doesn't look stuck.
        _journal_clear(env_path, state_dir=self.state_dir)
        return res

    # ---------------------- internals --------------------------------------

    def _post_sync_for(self, env_path: str) -> Optional[str]:
        watch = self.config.get("watch") or {}
        return ((watch.get("post_sync_per_path") or {}).get(env_path)) or None

    def _classify_overrides_for(self, env_path: str) -> Optional[dict]:
        """M11: resolve per-consumer-dir classify overrides.

        config.watch.classify_overrides:
          { "<dir>": {force_secret: [K,...], force_config: [K,...]} }
        Returns {"force_secret": set, "force_config": set} or None. The
        operator's explicit call beats the name/entropy heuristic — fixes
        both misclass directions (a secret named oddly that the regex
        misses; a config like API_BASE_URL the regex would over-absorb)."""
        watch = self.config.get("watch") or {}
        entry = (watch.get("classify_overrides") or {}).get(os.path.dirname(env_path))
        if not isinstance(entry, dict):
            return None
        fs = set(entry.get("force_secret") or [])
        fc = set(entry.get("force_config") or [])
        if not fs and not fc:
            return None
        overlap = fs & fc
        if overlap:
            logger.warning(
                f"classify_overrides for {os.path.dirname(env_path)}: keys "
                f"{sorted(overlap)} in BOTH force_secret and force_config — "
                f"force_secret wins (safer to absorb than to leak)"
            )
        return {"force_secret": fs, "force_config": fc}

    def _materialize_for(self, env_path: str) -> dict:
        """Decide how the agent should materialize the merged file for this
        consumer (M2). Returns {materialize, mode, owner, group}.

        Resolution order:
          1. Explicit `watch.materialize_for_dir[<dir>]` config wins.
          2. Auto-detect: if the consumer's project dir is owned by a
             NON-root user, that consumer is operated by that user (e.g.
             `docker compose` run as `ubuntu` resolving ${VAR} from ./.env).
             A symlink into the 0700 /run/secrets dir would make the .env
             unreadable for them → choose `copy` + group=that user so the
             real file is group-readable. The original .env was already a
             plaintext file owned by that user, so root:<grp> 0640 is
             strictly tighter than the pre-absorb state.
          3. Default: `symlink` (historical) + mode 0o640 (M8 tighten,
             zero-regression: /run/secrets is 0700 so the old world bit was
             already unreachable).

        Never raises — any stat/lookup error falls back to the safe default.
        """
        import grp
        import pwd

        watch = self.config.get("watch") or {}
        parent = os.path.dirname(env_path)
        explicit = (watch.get("materialize_for_dir") or {}).get(parent)
        if isinstance(explicit, dict) and explicit.get("strategy") in (
            "copy",
            "symlink",
        ):
            return {
                "materialize": explicit["strategy"],
                "mode": explicit.get("mode", "0640"),
                "owner": explicit.get("owner", "root"),
                "group": explicit.get("group", "root"),
            }

        default = {
            "materialize": "symlink",
            "mode": "0640",
            "owner": "root",
            "group": "root",
        }
        try:
            st = os.stat(parent)
        except OSError:
            return default
        if st.st_uid == 0:
            return default
        # Non-root-owned project dir → copy mode, group = the owning user's
        # primary group (fallback to the dir's gid group, then the username).
        try:
            pw = pwd.getpwuid(st.st_uid)
            owner_name = pw.pw_name
            try:
                group_name = grp.getgrgid(pw.pw_gid).gr_name
            except KeyError:
                group_name = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            return default
        logger.info(
            f"materialize: {parent} owned by non-root {owner_name!r} — "
            f"using copy mode (group={group_name}) so the operator can read "
            f"the managed .env"
        )
        return {
            "materialize": "copy",
            "mode": "0640",
            "owner": "root",
            "group": group_name,
        }

    def _add_collection_to_agent_config(
        self,
        collection_id: str,
        collection_name: str,
        merge_link: str,
        merge_static: str,
        merge_target: str,
        vault_only_output: str,
        materialize_cfg: Optional[dict] = None,
    ) -> bool:
        """Atomically add a sync.collections entry with a `merge:` block.

        The entry mirrors the agent's existing example-staging pattern:
            id, name, output (vault-only render), merge:{link,static,target}
        Idempotent. Backs up the file before writing. Atomic via tmp+rename.
        """
        try:
            import yaml
        except ImportError:
            logger.error("config edit: PyYAML not installed; cannot proceed")
            return False
        try:
            with open(self.agent_config_path) as f:
                cfg = yaml.safe_load(f) or {}
        except OSError as e:
            logger.error(f"config edit: cannot read {self.agent_config_path}: {e}")
            return False
        sync = cfg.setdefault("sync", {})
        collections = sync.setdefault("collections", [])

        # Build the canonical entry shape (single source of truth).
        mat = materialize_cfg or {
            "materialize": "symlink",
            "mode": "0640",
            "owner": "root",
            "group": "root",
        }
        merge_block = {
            "link": merge_link,
            "static": merge_static,
            "target": merge_target,
            "materialize": mat["materialize"],
            "mode": mat["mode"],
            "owner": mat["owner"],
            "group": mat["group"],
        }
        new_entry = {
            "id": collection_id,
            "name": collection_name,
            "output": vault_only_output,
            "merge": merge_block,
        }

        # Idempotent edit: if a collection with this id already exists, only
        # rewrite the file when the entry has drifted (different output or
        # merge values). If it matches exactly, this is a no-op and we
        # skip the file write entirely.
        found_idx = None
        for i, c in enumerate(collections):
            if c.get("id") == collection_id:
                found_idx = i
                break
        if found_idx is not None:
            current = collections[found_idx]
            # Compare the load-bearing fields, not the entire dict — the
            # operator may have added post_sync hooks or other extras that
            # we should preserve.
            current_merge = current.get("merge") or {}
            # v1.5.0 (bug #1, CRITICAL): the original `output:` path is the
            # path consumers read from BEFORE the migration. NEVER change it
            # when adding a merge: block to an existing entry — otherwise
            # the agent stops rendering the original path and the consumer
            # (next restart) gets either stale bytes or a missing file. The
            # merged file at `merge.target` is the post-migration consumer
            # path; `output` stays put for backward compatibility. We only
            # rewrite `output` if there was NO existing output (extremely
            # rare — corrupted/partial config). Same for `name`: a watcher
            # auto-derivation must not overwrite an operator's deliberate
            # naming choice.
            preserved_output = current.get("output") or vault_only_output
            preserved_name = current.get("name") or collection_name
            same = (
                current.get("output") == preserved_output
                and current.get("name") == preserved_name
                and current_merge.get("link") == merge_link
                and current_merge.get("static") == merge_static
                and current_merge.get("target") == merge_target
                and current_merge.get("materialize", "symlink") == mat["materialize"]
                and str(current_merge.get("mode", "0640")) == str(mat["mode"])
                and current_merge.get("owner", "root") == mat["owner"]
                and current_merge.get("group", "root") == mat["group"]
            )
            if same:
                logger.info(
                    f"config edit: collection {collection_id[:8]}… already in expected shape"
                )
                return True
            # Drifted — update ONLY merge: block + ensure name/output stay
            # at their PRESERVED value (no silent rewrite of operator setup).
            current["name"] = preserved_name
            current["output"] = preserved_output
            current["merge"] = new_entry["merge"]
            if preserved_output != vault_only_output:
                logger.info(
                    f"config edit: collection {collection_id[:8]}… present; "
                    f"preserved original output={preserved_output!r} "
                    f"(NOT changing to derived {vault_only_output!r}); "
                    f"added/updated merge: block"
                )
            else:
                logger.info(
                    f"config edit: collection {collection_id[:8]}… present but drifted; updating in place"
                )
        else:
            collections.append(new_entry)

        # Backup before write
        ts = datetime.now(timezone.utc).strftime(BACKUP_NAME_FMT)
        backup_cfg = f"{self.agent_config_path}.bak-{ts}"
        try:
            with open(self.agent_config_path, "rb") as fsrc:
                data = fsrc.read()
            with open(backup_cfg, "wb") as fdst:
                fdst.write(data)
            try:
                os.chmod(backup_cfg, 0o600)
            except OSError:
                pass
        except OSError as e:
            logger.warning(f"config edit: backup attempt failed: {e} (continuing)")

        tmp = f"{self.agent_config_path}.tmp.{os.getpid()}"
        try:
            with open(tmp, "w") as f:
                yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.rename(tmp, self.agent_config_path)
            logger.info(
                f"config edit: added collection {collection_name} "
                f"({collection_id[:8]}…)"
            )
            return True
        except OSError as e:
            logger.error(f"config edit: write {self.agent_config_path} failed: {e}")
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False

    def _signal_agent_reload(self) -> bool:
        """Best-effort SIGHUP to the agent. Tries two paths in order:

          1. PID file at self.agent_pid_file (legacy / customisable)
          2. `systemctl kill --signal=HUP socialwarden-agent.service`
             (no PID file required — systemd already knows the PID)

        Returns True if either path succeeded. Production agents run under
        systemd as socialwarden-agent.service and do not write a PID file, so
        path #2 is the load-bearing one; path #1 is kept for the test
        harness and for hosts that opt in via watch.agent_pid_file.
        """
        # --- path 1: PID file ------------------------------------------------
        try:
            with open(self.agent_pid_file) as f:
                pid = int(f.read().strip())
        except (OSError, ValueError) as e:
            # Fall through to systemctl — log at DEBUG so we don't spam.
            logger.debug(
                f"signal_agent_reload: PID file {self.agent_pid_file} unusable ({e}); "
                "trying systemctl"
            )
            pid = None

        if pid is not None:
            try:
                os.kill(pid, signal.SIGHUP)
                logger.info(f"signal_agent_reload: SIGHUP -> agent pid={pid}")
                return True
            except ProcessLookupError:
                logger.warning(
                    f"signal_agent_reload: pid {pid} not found; falling back to systemctl"
                )
            except PermissionError:
                logger.error(
                    f"signal_agent_reload: permission denied for pid {pid}; "
                    "falling back to systemctl"
                )
            except OSError as e:
                logger.warning(
                    f"signal_agent_reload: kill({pid}) failed: {e}; falling back to systemctl"
                )

        # --- path 2: systemctl ----------------------------------------------
        try:
            r = subprocess.run(
                ["systemctl", "kill", "--signal=HUP", "socialwarden-agent.service"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode == 0:
                logger.info("signal_agent_reload: SIGHUP via systemctl OK")
                return True
            logger.warning(
                f"signal_agent_reload: systemctl kill failed (rc={r.returncode}): "
                f"{(r.stderr or r.stdout).strip()}"
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            logger.warning(f"signal_agent_reload: systemctl invocation failed: {e}")
        return False

    def _wait_for_file(self, path: str, timeout_s: float) -> bool:
        """Poll for `path` to exist + be non-empty AND parse cleanly.

        v1.5.0 (bug #8, LOW): the prior implementation returned True the
        moment the file appeared with size > 0. If the agent was still in
        the middle of writing it (highly improbable with atomic write+
        rename, but possible with non-atomic file syncs), the caller would
        immediately parse a truncated/half-written .env and could see
        spurious "KEY missing" errors. We now do ONE best-effort parse
        after appearance: if parse_env_file returns None (malformed), we
        keep waiting; on the last second of the timeout we accept anyway
        (a tiny size+stable file but unparsable is somebody else's bug,
        not ours to swallow forever).
        """
        deadline = time.monotonic() + timeout_s
        delay = 0.5
        while time.monotonic() < deadline:
            try:
                st = os.stat(path)
                if st.st_size > 0:
                    # New: validate parse before returning True.
                    pairs = parse_env_file(path)
                    if pairs is not None:
                        return True
                    remaining = deadline - time.monotonic()
                    if remaining < 1.0:
                        logger.warning(
                            f"wait_for_file: {path} exists but parse_env_file "
                            f"returned None and timeout is imminent; "
                            f"accepting as ready and letting the caller's "
                            f"validation surface the issue."
                        )
                        return True
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.warning(f"wait_for_file: stat error on {path}: {e}")
                return False
            time.sleep(delay)
            delay = min(delay * 1.3, 3.0)
        return False

    def _atomic_symlink_swap(self, env_path: str, target: str) -> bool:
        """Replace env_path with symlink->target. POSIX-atomic via rename.

        Removes the destination via rename (which is atomic even when target
        exists). On failure we don't leave a dangling tmp link.
        """
        tmp = f"{env_path}.tmp.{os.getpid()}.symlink"
        try:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            os.symlink(target, tmp)
        except OSError as e:
            logger.error(f"symlink swap: cannot create tmp link at {tmp}: {e}")
            return False
        try:
            os.rename(tmp, env_path)
            return True
        except OSError as e:
            logger.error(f"symlink swap: rename({tmp} -> {env_path}) failed: {e}")
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False

    @staticmethod
    def _parse_mode(raw, default=0o640) -> int:
        """Octal mode from '0640' / 0o640 / 640. Falls back to default."""
        try:
            if isinstance(raw, str):
                return int(raw, 8)
            if isinstance(raw, int) and 600 <= raw <= 777:
                return int(str(raw), 8)
            return int(raw)
        except (TypeError, ValueError):
            return default

    def _materialize_copy_safety_net(
        self, env_path: str, merged_target: str, mat: dict
    ) -> bool:
        """Safety net for materialize=copy: the watcher copies the validated
        merged bytes from `merged_target` into `env_path` as a REAL file with
        the resolved mode/owner/group, when the agent didn't do it itself.

        Atomic (tmp in same dir + rename). chown is best-effort (delivering
        the file beats failing on a chown). Never raises."""
        import grp
        import pwd

        try:
            data = Path(merged_target).read_bytes()
        except OSError as e:
            logger.error(f"copy safety-net: cannot read {merged_target}: {e}")
            return False
        mode = self._parse_mode(mat.get("mode"), 0o640)

        def _id(val, resolver):
            if not val:
                return -1
            try:
                return int(val)
            except (TypeError, ValueError):
                pass
            try:
                return resolver(str(val))
            except KeyError:
                return -1

        uid = _id(mat.get("owner"), lambda n: pwd.getpwnam(n).pw_uid)
        gid = _id(mat.get("group"), lambda n: grp.getgrnam(n).gr_gid)
        tmp = f"{env_path}.tmp.{os.getpid()}.copy"
        try:
            if os.path.islink(env_path):
                os.unlink(env_path)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, data)
                os.fchmod(fd, mode)
                if uid != -1 or gid != -1:
                    try:
                        os.fchown(fd, uid, gid)
                    except OSError as e:
                        logger.warning(
                            f"copy safety-net: chown({uid},{gid}) failed ({e})"
                        )
            finally:
                os.close(fd)
            os.rename(tmp, env_path)
            return True
        except OSError as e:
            logger.error(f"copy safety-net: write {env_path} failed: {e}")
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False

    def _run_post_sync_async(self, cmd: str, env_path: str) -> None:
        """Fire-and-forget post_sync; same safety as agent v1.4.5+.

        - Runs in a daemon thread (doesn't block the migrate caller).
        - 300s timeout; on timeout we killpg the entire session.
        - stdout+stderr appended to /var/log/socialwarden/watcher.post_sync.log.
        - Discord alert ONLY on rc>0 or timeout (NOT on signal-kill = shutdown).
        """
        if not cmd:
            return
        log_path = os.path.join(
            os.path.dirname(self.audit_log), "watcher.post_sync.log"
        )
        _ensure_dir(os.path.dirname(log_path), mode=0o750)

        def _runner():
            try:
                fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            except OSError as e:
                logger.warning(f"post_sync: cannot open log {log_path}: {e}")
                return
            try:
                with os.fdopen(fd, "ab") as lf:
                    header = (
                        f"\n=== {datetime.now(timezone.utc).isoformat()} {env_path} ===\n"
                        f"cmd: {cmd}\n"
                    ).encode()
                    lf.write(header)
                    lf.flush()
                    try:
                        proc = subprocess.Popen(
                            ["bash", "-c", cmd],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            start_new_session=True,
                        )
                    except OSError as e:
                        lf.write(f"spawn failed: {e}\n".encode())
                        return
                    try:
                        out, _ = proc.communicate(timeout=300)
                        if out:
                            lf.write(out)
                        rc = proc.returncode
                        lf.write(f"\nrc={rc}\n".encode())
                        if rc > 0:
                            send_discord_alert(
                                self.discord_webhook,
                                title="post_sync failed",
                                description=f"`{env_path}` post_sync rc={rc}",
                                color=COLOR_RED,
                                machine_name=self.machine_name,
                            )
                        elif rc < 0:
                            # Signal-killed (e.g. systemd shutdown) — no alert.
                            lf.write(b"[post_sync] interrupted by signal\n")
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except OSError:
                            pass
                        lf.write(b"\n[post_sync] TIMEOUT after 300s, killed pgroup\n")
                        send_discord_alert(
                            self.discord_webhook,
                            title="post_sync timeout",
                            description=f"`{env_path}` post_sync exceeded 300s",
                            color=COLOR_RED,
                            machine_name=self.machine_name,
                        )
            except Exception as e:
                # Thread crashes are silent by default (daemon=True); without
                # this alert the operator may never learn the post_sync hook
                # is broken. Discord alert is best-effort — if it also
                # fails (network down), we still log.
                logger.warning(f"post_sync runner crashed: {e}", exc_info=True)
                try:
                    send_discord_alert(
                        self.discord_webhook,
                        title="post_sync thread crashed",
                        description=(
                            f"`{env_path}` post_sync runner raised before "
                            f"completion:\n```\n{e}\n```"
                        ),
                        color=COLOR_RED,
                        machine_name=self.machine_name,
                    )
                except Exception as alert_err:
                    logger.error(f"post_sync runner: also failed to alert: {alert_err}")

        t = threading.Thread(target=_runner, daemon=True)
        t.start()


# ===========================================================================
# Phase D — tick(), main loop, signal handling, opt-in marker, main()
# ===========================================================================


# Tick stats returned by WatcherDaemon.tick() for caller introspection.
@dataclass
class TickStats:
    discovered: int = 0
    skipped_managed: int = 0  # already symlinked under secrets_dir
    absorbed: int = 0
    skipped: int = 0  # no secrets to migrate, or all classified config
    deferred: int = 0  # transient errors, will retry
    failed: int = 0  # hard failures (operator attention)
    no_mapping: int = 0  # found a candidate but no collection_for_dir entry
    rate_limited: int = 0  # remaining candidates not processed this tick

    def as_dict(self) -> dict:
        return {
            "discovered": self.discovered,
            "skipped_managed": self.skipped_managed,
            "absorbed": self.absorbed,
            "skipped": self.skipped,
            "deferred": self.deferred,
            "failed": self.failed,
            "no_mapping": self.no_mapping,
            "rate_limited": self.rate_limited,
        }


# ---------------------------------------------------------------------------
# WatcherDaemon — extend with tick() and run_forever().
# We monkey-patch new methods rather than editing the class declaration so
# the Phase C body stays git-diff-clean. (Final cleanup happens in PR review.)
# ---------------------------------------------------------------------------


def _watcher_collection_for(self, env_path: str) -> Optional[dict]:
    """v1.2.0 resolution flow (priority order):

      1. manual collection_for_dir       → return entry (highest active
                                            priority — operator's explicit
                                            mapping always wins, including
                                            over ignore_paths since they're
                                            soft/configurable; the hard
                                            infra-protected check that
                                            blocks master.key et al. lives
                                            in _watcher_tick BEFORE this).
      2. ignore_paths / ignore_patterns  → return None (silent skip)
      3. auto_naming.rules               → derive {id:"", name:"<derived>",
                                            source:"rule_N"}; migrate() will
                                            call ensure_collection(name=...,
                                            preferred_id="") to resolve or
                                            create idempotently (M1)
      4. fallback_behavior:
          - alert_and_wait  → fire Discord alert, return None (no absorb)
          - silent_skip     → return None
          - absorb_with_default → derive {id:"", name:"<suggested>",
                                  source:"fallback_default", auto_named:True}

    Returns: collection dict {id, name, ...} or None.
    """
    # 1. Manual override (highest priority for active absorbs). If the
    # operator put an entry here, they're saying "I want this", so we
    # honor it even if ignore_paths would otherwise skip the path.
    # (The hard infra-protected check in _watcher_tick still blocks
    # paths like master.key — that's separate and inviolable.)
    watch = self.config.get("watch") or {}
    mapping = watch.get("collection_for_dir") or {}
    parent = os.path.dirname(env_path)
    entry = mapping.get(parent)
    if entry:
        if isinstance(entry, str):
            # Shorthand: { "/path": "collection-uuid" } → name = uuid suffix
            return {"id": entry, "name": entry[-12:], "source": "manual"}
        if isinstance(entry, dict):
            cid = entry.get("id") or ""
            cname = entry.get("name") or (cid[-12:] if cid else None)
            if cname:
                return {"id": cid, "name": cname, "source": "manual"}
            return None  # malformed override

    # 2. Soft ignores — paths/patterns the operator (or defaults) marked
    # as known-uninteresting noise. Never absorb (no rule, no fallback,
    # no alert). If the operator wanted one of these, step 1 already
    # caught it via manual override.
    # v1.2.2: return a sentinel dict so the caller can distinguish ignored
    # paths from genuine no-mapping (different stat bucket, different log
    # level). Pre-v1.2.2 both went to stats.no_mapping which inflated the
    # counter and made tick summaries confusing.
    if _is_path_ignored(env_path, self.ignore_paths):
        logger.debug(
            f"tick: {env_path} ignored by ignore_paths",
            extra={"machine": self.machine_name},
        )
        return {"source": "ignored", "id": "", "name": ""}
    if _is_basename_ignored(env_path, self.ignore_patterns):
        logger.debug(
            f"tick: {env_path} ignored by ignore_patterns",
            extra={"machine": self.machine_name},
        )
        return {"source": "ignored", "id": "", "name": ""}

    # 3. Auto-naming rules.
    if self.auto_naming_rules:
        result = _apply_auto_naming(
            env_path, self.auto_naming_rules, self.machine_short
        )
        if result is not None:
            name, idx = result
            return {
                "id": "",  # migrate() → ensure_collection resolves by name (M1)
                "name": name,
                "source": f"rule_{idx}",
                "auto_named": True,
            }

    # 4. Fallback for unmatched paths.
    behavior = self.fallback_behavior
    if behavior == "alert_and_wait":
        self._alert_unmapped_env(env_path)
        return None
    if behavior == "absorb_with_default":
        suggested = _suggest_name_for_unmapped(env_path, self.machine_short)
        logger.warning(
            f"tick: no rule matched {env_path!r}; absorbing with default "
            f"name {suggested!r} (fallback_behavior=absorb_with_default)",
            extra={"machine": self.machine_name},
        )
        return {
            "id": "",
            "name": suggested,
            "source": "fallback_default",
            "auto_named": True,
        }
    # silent_skip or any unknown value → just skip.
    return None


def _alert_unmapped_env(self, env_path: str) -> None:
    """v1.2.0: Discord alert for an unmapped candidate (no rule covered,
    not in manual override, not in ignores). Per-tick dedup so the same
    path is not alerted twice within a single tick."""
    if env_path in self._alerted_unmapped:
        return
    self._alerted_unmapped.add(env_path)

    suggested = _suggest_name_for_unmapped(env_path, self.machine_short)
    parent = os.path.dirname(env_path)

    description = (
        f"Watcher v{VERSION} found a `.env` candidate that no auto-naming "
        f"rule matches and that is not in `watch.collection_for_dir`. "
        f"The watcher has NOT absorbed it.\n\n"
        f"**path**: `{env_path}`\n"
        f"**suggested collection name**: `{suggested}`\n\n"
        f"To accept, append to `/etc/socialwarden/config.yaml` "
        f"(agent reloads on SIGHUP, no restart needed):\n"
        f"```yaml\n"
        f"watch:\n"
        f"  collection_for_dir:\n"
        f"    {parent}:\n"
        f"      name: {suggested}\n"
        f"```\n"
        f"Or, if this is a common shape, add a rule under "
        f"`watch.auto_naming.rules` so future hosts auto-absorb without "
        f"manual entries.\n\n"
        f"(Reason: `fallback_behavior=alert_and_wait`.)"
    )
    send_discord_alert(
        self.discord_webhook,
        title=f"SocialWarden: unmapped .env candidate on {self.machine_name}",
        description=description,
        color=COLOR_YELLOW,
        machine_name=self.machine_name,
    )
    # v1.5.0 (bug #5, MEDIUM): if send_discord_alert returns False/falsy
    # the alert silently vanished. We log WARNING (not INFO) so the gap is
    # visible at standard log levels, AND we bump a process-wide counter
    # the operator can scrape via doctor / metrics. (send_discord_alert
    # currently has no explicit bool return; rely on its internal ERROR
    # logging plus our own WARNING here for visibility.)
    if not getattr(self, "_unmapped_alerts_undelivered", None):
        self._unmapped_alerts_undelivered = 0
    if not self.discord_webhook:
        # Webhook never configured: alert path is by design unreachable.
        self._unmapped_alerts_undelivered += 1
        logger.warning(
            f"tick: unmapped candidate {env_path!r} (suggested name: "
            f"{suggested!r}) — Discord alert NOT sent (no webhook "
            f"configured); operator visibility for this path depends on log "
            f"scraping. Set alerts.discord_webhook_file or add a "
            f"collection_for_dir override.",
            extra={"machine": self.machine_name},
        )
    else:
        logger.warning(
            f"tick: unmapped candidate {env_path!r} → Discord alert dispatched "
            f"(suggested name: {suggested!r}); if not seen in Discord the "
            f"webhook may be invalid/throttled — check send_discord_alert "
            f"ERROR lines above this one in the journal.",
            extra={"machine": self.machine_name},
        )


def _watcher_tick(self) -> TickStats:
    """One full poll iteration. Robust to all errors: per-candidate failures
    are logged and tracked but never abort the tick. Never raises."""
    stats = TickStats()
    watch = self.config.get("watch") or {}
    paths = watch.get("paths") or []
    ignore = set(watch.get("ignore") or [])
    max_depth = int(watch.get("max_depth", 3))
    # v1.2.0: clear per-tick alert dedup so the same path can be re-alerted
    # on a future tick if it persists (e.g. once a day on the natural
    # poll cadence) — useful as a heartbeat reminder.
    self._alerted_unmapped.clear()

    candidates: list[Path] = []
    for root in paths:
        try:
            found = discover_candidates(root, recursive=True, max_depth=max_depth)
        except Exception as e:
            logger.warning(f"tick: discover failed for {root}: {e}")
            continue
        for p in found:
            sp = str(p)
            if sp in ignore:
                continue
            # M17: never absorb SocialWarden's own infrastructure.
            if _is_infra_protected(sp):
                logger.warning(
                    f"tick: REFUSING infra-protected path {sp} "
                    "(master.key / agent state / rendered secrets) — "
                    "check watch.paths config",
                    extra={"machine": self.machine_name},
                )
                continue
            # M18: a deliberately rolled-back target stays decommissioned
            # until the operator removes the marker (otherwise the next
            # tick silently re-absorbs what rollback just reverted).
            if os.path.exists(sp + DECOMMISSION_SUFFIX):
                logger.debug(
                    f"tick: {sp} decommissioned (marker present) — skipping",
                    extra={"machine": self.machine_name},
                )
                continue
            candidates.append(p)

    stats.discovered = len(candidates)
    if not candidates:
        return stats

    for cand in candidates:
        # Idempotence: skip already-managed without consuming the rate-limit budget.
        if is_already_managed(cand, secrets_dir=self.secrets_dir):
            stats.skipped_managed += 1
            continue

        # Resolve collection (v1.2.0 priority: ignores → manual → rules
        # → fallback). _collection_for either returns a coll dict (absorb)
        # or None. When None, the helper has ALREADY chosen the outcome:
        # Discord alert for alert_and_wait fallback, log info for silent_skip
        # fallback. v1.2.2: ignored paths get back a sentinel dict with
        # source="ignored" so we book them as stats.skipped (semantically
        # correct — they were a deliberate skip, not a missing mapping).
        coll = self._collection_for(str(cand))
        if not coll:
            stats.no_mapping += 1
            continue
        if coll.get("source") == "ignored":
            stats.skipped += 1
            continue

        # Rate limit: bound bw calls per tick.
        if stats.absorbed + stats.failed + stats.deferred >= self.max_per_tick:
            stats.rate_limited += 1
            continue

        try:
            result = self.migrate(
                env_path=str(cand),
                collection_id=coll["id"],
                collection_name=coll["name"],
            )
        except Exception as e:
            logger.error(
                f"tick: migrate({cand}) raised — should never happen: {e}",
                exc_info=True,
                extra={"machine": self.machine_name},
            )
            stats.failed += 1
            continue

        if result.status == "absorbed":
            stats.absorbed += 1
        elif result.status == "skipped":
            stats.skipped += 1
        elif result.status == "deferred":
            stats.deferred += 1
            logger.info(
                f"tick: deferred {cand}: {result.reason}",
                extra={"machine": self.machine_name},
            )
        elif result.status == "failed":
            stats.failed += 1
            logger.error(
                f"tick: failed {cand}: {result.reason}",
                extra={"machine": self.machine_name},
            )
            # Discord alert per failure (no flap suppression at this level
            # since failures should be rare; aggregate suppression can be
            # added later if noisy in practice).
            send_discord_alert(
                self.discord_webhook,
                title="Watcher migration failed",
                description=f"`{cand}` → {coll['name']}\nReason: {result.reason}",
                color=COLOR_RED,
                machine_name=self.machine_name,
            )

    # M3: surface partial absorbs that died mid-flight. A journal whose
    # phase is non-terminal and that hasn't advanced in STUCK_ABSORB_AGE_S
    # — while its target is NOT yet managed — is a stuck absorb the
    # operator must see (it would otherwise rot silently, the exact
    # failure class this hardening sprint targets).
    try:
        _scan_stuck_absorbs(self)
    except Exception as e:
        logger.debug(f"tick: stuck-absorb scan failed: {e}")

    # M14: drift reconciliation — detect managed targets that silently
    # degraded (symlink reverted to plaintext, copy-file clobbered, agent
    # stopped rendering the merged file, vault collection went empty).
    try:
        _reconcile_drift(self)
    except Exception as e:
        logger.debug(f"tick: drift reconcile failed: {e}")

    return stats


def _reconcile_drift(self) -> None:
    """Walk the agent config's merge collections and flag any managed
    consumer that drifted. Re-absorb of a reverted plaintext .env is
    already handled by the normal candidate→migrate path; this makes the
    degradation LOUD (audit + Discord, flap-suppressed) so it can't rot
    silently — the exact failure class this hardening sprint targets.

    Drift kinds:
      - reverted   : managed .env is now a plain file (app rewrote it) →
                     secrets are back on disk in cleartext.
      - missing    : the consumer .env vanished entirely.
      - no_merged  : agent isn't producing the merged/target file.
      - vault_empty: the collection that should hold secrets is empty
                     (lineage of the old false "Collection Emptied" — here
                     as an authoritative cross-check, only alerted when the
                     consumer is still expected to be managed).
    """
    try:
        import yaml

        with open(self.agent_config_path) as f:
            cfg = yaml.safe_load(f) or {}
    except (OSError, ImportError, Exception):  # noqa: BLE001
        return
    colls = (cfg.get("sync") or {}).get("collections") or []
    seen_keys = set()

    def _alert(link, kind, msg):
        key = (link, kind)
        seen_keys.add(key)
        if key in self._drift_alerted:
            return  # already alerted this run — flap suppression
        self._drift_alerted.add(key)
        logger.error(
            f"DRIFT [{kind}] {link}: {msg}", extra={"machine": self.machine_name}
        )
        _append_audit_line(
            self.audit_log,
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "drift_detected",
                "host": self.machine_name,
                "link": link,
                "kind": kind,
                "detail": msg,
            },
        )
        send_discord_alert(
            self.discord_webhook,
            title=f"Watcher drift: {kind}",
            description=f"`{link}` — {msg}",
            color=COLOR_RED,
            machine_name=self.machine_name,
        )

    for c in colls:
        merge = c.get("merge") or {}
        link = merge.get("link")
        target = merge.get("target")
        if not link:
            continue
        materialize = merge.get("materialize", "symlink")
        try:
            link_exists = os.path.lexists(link)
        except OSError:
            continue
        if not link_exists:
            _alert(
                link,
                "missing",
                "managed consumer .env vanished — agent will recreate on "
                "next sync; investigate what deleted it",
            )
            continue
        # Reverted? (symlink turned into a plain file, or copy-file lost the
        # SocialWarden sentinel = an app/operator overwrote it with cleartext)
        if not is_already_managed(link, secrets_dir=self.secrets_dir):
            _alert(
                link,
                "reverted",
                f"no longer a managed {materialize} target — cleartext "
                "secrets likely back on disk; will be re-absorbed",
            )
        # Agent still producing the merged/target file?
        if target:
            try:
                ok = os.path.exists(target) and os.path.getsize(target) > 0
            except OSError:
                ok = False
            if not ok:
                _alert(
                    link,
                    "no_merged",
                    f"agent is not producing {target} — consumer may be "
                    "running on stale/empty env",
                )
        # Vault collection unexpectedly empty?
        cid = c.get("id")
        if cid and is_already_managed(link, secrets_dir=self.secrets_dir):
            items = self.bw.list_items_in_collection(cid)
            if items is not None and len(items) == 0:
                _alert(
                    link,
                    "vault_empty",
                    f"collection {c.get('name')!r} has 0 items but the "
                    "consumer is still managed — secrets may be lost",
                )

    # Forget suppressed alerts whose drift is gone (so a recurrence re-alerts).
    self._drift_alerted &= seen_keys


def _scan_stuck_absorbs(self) -> None:
    state_dir = getattr(self, "state_dir", WATCHER_STATE_DIR)
    try:
        names = os.listdir(state_dir)
    except OSError:
        return
    now = datetime.now(timezone.utc)
    for fn in names:
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(state_dir, fn)) as f:
                j = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        phase = j.get("phase", "")
        env_path = j.get("env_path", "")
        if phase in _JOURNAL_TERMINAL or not env_path:
            continue
        if is_already_managed(env_path, secrets_dir=self.secrets_dir):
            # It actually completed; the clean-up just didn't run. Tidy up.
            _journal_clear(env_path, state_dir=state_dir)
            continue
        try:
            updated = datetime.fromisoformat(j.get("updated_at", ""))
        except ValueError:
            continue
        age = (now - updated).total_seconds()
        if age < STUCK_ABSORB_AGE_S:
            continue
        if j.get("stuck_alerted"):
            continue
        logger.error(
            f"STUCK ABSORB: {env_path} stalled at phase {phase!r} for "
            f"{int(age)}s (collection={j.get('collection_name')}). "
            f"Inspect/journal: {os.path.join(state_dir, fn)}; "
            f"`rollback` can revert it.",
            extra={"machine": self.machine_name},
        )
        send_discord_alert(
            self.discord_webhook,
            title="Watcher: stuck absorb",
            description=(
                f"`{env_path}` stalled at **{phase}** for {int(age)}s "
                f"(collection {j.get('collection_name')}). A partial absorb "
                f"that didn't complete — review or `rollback`."
            ),
            color=COLOR_RED,
            machine_name=self.machine_name,
        )
        j["stuck_alerted"] = True
        _journal_write(env_path, j, state_dir=state_dir)


def _watcher_run_forever(self, poll_interval: float, janitor_every_n: int = 120) -> int:
    """Main daemon loop. Returns exit code (0 on graceful shutdown).

    janitor_every_n: run purge_old_backups every N ticks. Default 120 means
    every hour when poll_interval=30s. Cheap operation either way.

    Robust: any per-tick error logs + continues; only fatal config/secret
    errors break the loop.
    """
    self._running = True
    tick_count = 0
    last_marker_warn = 0.0
    # M15: cumulative counters for the Prometheus textfile metrics.
    cum = {"absorbed": 0, "deferred": 0, "failed": 0, "discovered": 0, "ticks": 0}

    def _signal_handler(signum, _frame):
        sig_name = signal.Signals(signum).name
        logger.info(f"received {sig_name}, shutting down gracefully")
        self._running = False

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _signal_handler)

    logger.info(
        f"{WATCHER_NAME} v{VERSION} entering main loop "
        f"(poll_interval={poll_interval}s, janitor_every={janitor_every_n} ticks)",
        extra={"machine": self.machine_name},
    )

    while self._running:
        tick_start = time.monotonic()

        # Opt-in marker check on every tick: operator can disable in-place
        # without stopping the service by removing the marker file.
        if not os.path.exists(WATCHER_MARKER):
            now = time.monotonic()
            if now - last_marker_warn > 300:  # every 5 min
                logger.info(
                    f"opt-in marker {WATCHER_MARKER} absent — idle "
                    "(touch the file to activate)",
                    extra={"machine": self.machine_name},
                )
                last_marker_warn = now
        else:
            tick_count += 1
            try:
                stats = self.tick()
                cum["ticks"] += 1
                cum["absorbed"] += stats.absorbed
                cum["deferred"] += stats.deferred
                cum["failed"] += stats.failed
                cum["discovered"] = stats.discovered
                if stats.absorbed or stats.deferred or stats.failed or stats.no_mapping:
                    logger.info(
                        f"tick {tick_count}: {stats.as_dict()}",
                        extra={"machine": self.machine_name},
                    )
                else:
                    # Quiet tick — debug only (don't spam INFO every 30s).
                    logger.debug(
                        f"tick {tick_count}: {stats.as_dict()}",
                        extra={"machine": self.machine_name},
                    )
            except Exception as e:
                logger.error(
                    f"tick {tick_count} raised: {e}",
                    exc_info=True,
                    extra={"machine": self.machine_name},
                )

            # Periodic janitor
            if tick_count % janitor_every_n == 0:
                try:
                    deleted = purge_old_backups(
                        backup_dir=self.backup_dir,
                        retention_days=self.backup_retention_days,
                    )
                    if deleted > 0:
                        logger.info(
                            f"janitor: purged {deleted} expired backup(s)",
                            extra={"machine": self.machine_name},
                        )
                except Exception as e:
                    logger.warning(f"janitor failed: {e}")

            # Heartbeat + Prometheus textfile metrics (M15). Both are
            # best-effort — a dead-man's-switch the agent/SOC can watch so
            # a silently-stopped watcher gets noticed (dependency-scan lesson).
            try:
                _write_heartbeat()
                _write_watcher_metrics(
                    self.machine_name,
                    cum,
                    drift_count=len(getattr(self, "_drift_alerted", ())),
                )
            except Exception:
                pass  # never let metrics failure stop the loop

        # Interruptible sleep: wake up immediately on signal.
        elapsed = time.monotonic() - tick_start
        remaining = max(0.5, poll_interval - elapsed)
        end = time.monotonic() + remaining
        while self._running and time.monotonic() < end:
            time.sleep(min(0.5, end - time.monotonic()))

    logger.info(f"{WATCHER_NAME} stopped", extra={"machine": self.machine_name})
    return 0


# Bind helpers as methods.
WatcherDaemon._collection_for = _watcher_collection_for
WatcherDaemon._alert_unmapped_env = _alert_unmapped_env  # v1.2.0
WatcherDaemon.tick = _watcher_tick
WatcherDaemon.run_forever = _watcher_run_forever


# ---------------------------------------------------------------------------
# Process-level helpers
# ---------------------------------------------------------------------------
HEARTBEAT_PATH = "/run/socialwarden/watcher-heartbeat"
# Same node-exporter textfile dir the agent uses → the SOC/Grafana already
# scrapes it, so the watcher gets observability for free.
WATCHER_METRICS_PATH = "/tmp/node-exporter-textfile/socialwarden-watcher.prom"
# A heartbeat older than this means the watcher daemon stalled/died — the
# `healthcheck` subcommand (run by the agent/SOC/timer) alerts on it. This
# is the dead-man's-switch for the exact silent-death class observed in long-running dependency scanners.
HEARTBEAT_STALE_S = 600


def _write_heartbeat() -> None:
    """Write current UTC timestamp to heartbeat file. Best-effort, never raises."""
    try:
        _ensure_dir(os.path.dirname(HEARTBEAT_PATH), mode=0o755)
        fd = os.open(HEARTBEAT_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            os.write(fd, (datetime.now(timezone.utc).isoformat() + "\n").encode())
        finally:
            os.close(fd)
    except OSError:
        pass


def _write_watcher_metrics(
    machine_name: str, cum: dict, drift_count: int = 0, path: str = WATCHER_METRICS_PATH
) -> None:
    """Prometheus textfile metrics for node-exporter. Best-effort, atomic.

    Mirrors the agent's write_metrics format/labels so the same dashboards
    and Prometheus staleness alert work for the watcher too."""
    try:
        _ensure_dir(os.path.dirname(path), mode=0o755)
        now = time.time()
        m = machine_name
        lines = [
            "# HELP socialwarden_watcher_ticks_total Watcher tick cycles",
            "# TYPE socialwarden_watcher_ticks_total counter",
            f'socialwarden_watcher_ticks_total{{machine="{m}"}} {cum.get("ticks", 0)}',
            "# HELP socialwarden_watcher_absorbed_total Secrets absorbed",
            "# TYPE socialwarden_watcher_absorbed_total counter",
            f'socialwarden_watcher_absorbed_total{{machine="{m}"}} {cum.get("absorbed", 0)}',
            "# HELP socialwarden_watcher_failed_total Absorb failures",
            "# TYPE socialwarden_watcher_failed_total counter",
            f'socialwarden_watcher_failed_total{{machine="{m}"}} {cum.get("failed", 0)}',
            "# HELP socialwarden_watcher_deferred_total Absorbs deferred",
            "# TYPE socialwarden_watcher_deferred_total counter",
            f'socialwarden_watcher_deferred_total{{machine="{m}"}} {cum.get("deferred", 0)}',
            "# HELP socialwarden_watcher_drift_active Drift conditions currently flagged",
            "# TYPE socialwarden_watcher_drift_active gauge",
            f'socialwarden_watcher_drift_active{{machine="{m}"}} {drift_count}',
            "# HELP socialwarden_watcher_last_tick_timestamp Unix ts of last tick",
            "# TYPE socialwarden_watcher_last_tick_timestamp gauge",
            f'socialwarden_watcher_last_tick_timestamp{{machine="{m}"}} {now}',
            "# HELP socialwarden_watcher_up Watcher heartbeat (1=alive this cycle)",
            "# TYPE socialwarden_watcher_up gauge",
            f'socialwarden_watcher_up{{machine="{m}",version="{VERSION}"}} 1',
            "",
        ]
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write("\n".join(lines))
        os.replace(tmp, path)
    except OSError:
        pass


def _healthcheck(
    config_path: str = DEFAULT_CONFIG,
    max_age_s: int = HEARTBEAT_STALE_S,
    alert: bool = False,
) -> int:
    """Dead-man's-switch: 0 if the heartbeat is fresh, 1 if stale/missing.

    Designed to be run by an EXTERNAL watchdog (the agent, a systemd timer,
    or the SOC) — a watcher that silently dies can't alert on itself, which
    is exactly how a dependency scanner rotted for 4 weeks. With --alert it also
    fires a Discord notification (webhook resolved from the config)."""
    try:
        with open(HEARTBEAT_PATH) as f:
            ts = datetime.fromisoformat(f.read().strip())
        age = (datetime.now(timezone.utc) - ts).total_seconds()
    except (OSError, ValueError) as e:
        age = None
        reason = f"heartbeat unreadable ({e})"
    else:
        if age <= max_age_s:
            print(
                f"OK: watcher heartbeat fresh ({int(age)}s old, threshold {max_age_s}s)"
            )
            return 0
        reason = f"heartbeat STALE: {int(age)}s old (threshold {max_age_s}s)"

    print(f"STALE: {reason} — the watcher daemon may be dead/stuck")
    if alert:
        webhook = None
        cfg = _load_config(config_path)
        if cfg:
            webhook = (cfg.get("alerts") or {}).get("discord_webhook")
        machine = ((cfg or {}).get("machine") or {}).get(
            "name", ""
        ) or socket.gethostname()
        send_discord_alert(
            webhook,
            title="Watcher dead-man's-switch",
            description=(
                f"`{HEARTBEAT_PATH}` {reason}. The socialwarden-watcher "
                f"daemon on **{machine}** is not ticking — no .env "
                f"absorption / drift detection is happening."
            ),
            color=COLOR_RED,
            machine_name=machine,
        )
    return 1


def _load_config(path: str) -> Optional[dict]:
    """Parse /etc/socialwarden/config.yaml. Returns None on any failure.

    Resolves `alerts.discord_webhook_file` to `alerts.discord_webhook`
    (same shape as the agent does it) so the watcher can talk to Discord
    without holding the URL in plain config.
    """
    try:
        import yaml
    except ImportError:
        logger.error("PyYAML required to load config")
        return None
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
    except OSError as e:
        logger.error(f"cannot read config {path}: {e}")
        return None
    except yaml.YAMLError as e:
        logger.error(f"config {path} parse error: {e}")
        return None

    # Resolve discord_webhook_file → discord_webhook (mirror agent behavior).
    alerts = cfg.get("alerts") or {}
    wh_file = alerts.get("discord_webhook_file")
    if wh_file and not alerts.get("discord_webhook"):
        try:
            with open(wh_file) as f:
                alerts["discord_webhook"] = f.read().strip()
        except OSError as e:
            logger.warning(f"discord_webhook_file {wh_file} unreadable: {e}")
    return cfg


def _resolve_master_password(cfg: dict) -> Optional[str]:
    """Decrypt master.key (machine-bound). Returns plaintext password or None."""
    auth = cfg.get("auth") or {}
    path = auth.get("master_key_path") or "/var/lib/socialwarden/master.key"
    return read_encrypted_file(path)


def _acquire_single_instance_lock(path: str = WATCHER_LOCK):
    """Take a non-blocking flock on `path` to enforce single-instance.

    Returns the open file handle (caller holds it for the daemon's lifetime),
    or None if another instance is already running.
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError as e:
        logger.error(f"single-instance: cannot mkdir {os.path.dirname(path)}: {e}")
        return None
    try:
        fh = open(path, "a+")
    except OSError as e:
        logger.error(f"single-instance: cannot open lock {path}: {e}")
        return None
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logger.error(
            f"another {WATCHER_NAME} instance is already running (lock {path})"
        )
        fh.close()
        return None
    return fh


def _build_daemon(cfg: dict) -> Optional[WatcherDaemon]:
    """Construct a WatcherDaemon from a loaded config. None on any failure."""
    machine_name = ((cfg.get("machine") or {}).get("name") or "").strip()
    if machine_name:
        set_machine_name(machine_name)

    auth = cfg.get("auth") or {}
    server = cfg.get("server") or {}
    alerts = cfg.get("alerts") or {}

    email = auth.get("email")
    if not email:
        logger.error("config: auth.email is required")
        return None

    master_pw = _resolve_master_password(cfg)
    if not master_pw:
        logger.error("config: cannot resolve master password (master.key unreadable?)")
        return None

    try:
        bw = BWClient(
            email=email,
            server_url=server.get("url") or "",
            master_password=master_pw,
            lock_path=BW_LOCK,
        )
    except ValueError as e:
        logger.error(f"BWClient init failed: {e}")
        return None

    watch = cfg.get("watch") or {}
    return WatcherDaemon(
        config=cfg,
        bw_client=bw,
        machine_name=machine_name or _MACHINE_NAME,
        secrets_dir=SECRETS_DIR,
        backup_dir=BACKUP_DIR,
        audit_log=AUDIT_LOG,
        backup_retention_days=int(
            watch.get("backup_retention_days", BACKUP_RETENTION_DAYS)
        ),
        symlink_wait_timeout=float(
            watch.get("symlink_wait_timeout", SYMLINK_WAIT_TIMEOUT_S)
        ),
        max_per_tick=int(watch.get("max_per_tick", 5)),
        discord_webhook=alerts.get("discord_webhook"),
    )


def _doctor(config_path: str) -> int:
    """Run sanity checks. Prints findings + returns 0 if OK, 1 if any problem."""
    problems = []

    def check(label, ok, detail=""):
        mark = "✓" if ok else "✗"
        print(f"  [{mark}] {label}{(' — ' + detail) if detail else ''}")
        if not ok:
            problems.append(label)

    print(f"{WATCHER_NAME} doctor v{VERSION}")
    print(f"Machine hostname: {socket.gethostname()}")

    cfg = _load_config(config_path)
    check(f"config readable {config_path}", cfg is not None)
    if cfg is None:
        return 1

    check("auth.email set", bool((cfg.get("auth") or {}).get("email")))
    check("organization.id set", bool((cfg.get("organization") or {}).get("id")))
    check("server.url set", bool((cfg.get("server") or {}).get("url")))
    check(
        "machine.name set",
        bool((cfg.get("machine") or {}).get("name")),
        (cfg.get("machine") or {}).get("name", ""),
    )

    master_pw = _resolve_master_password(cfg)
    check("master.key decryptable", bool(master_pw))

    watch = cfg.get("watch") or {}
    paths = watch.get("paths") or []
    check(
        "watch.paths configured",
        len(paths) > 0,
        f"{len(paths)} path(s)" if paths else "EMPTY (daemon will idle)",
    )
    mapping = watch.get("collection_for_dir") or {}
    check(
        "watch.collection_for_dir entries",
        len(mapping) > 0,
        f"{len(mapping)} mapping(s)",
    )

    # Cross-check: every scan path must be (or live under) at least one
    # collection_for_dir prefix. Without this, the watcher will see .env
    # candidates and log "no collection mapping" forever — a silent
    # failure mode that's painful to debug from logs alone.
    if paths and mapping:
        unmapped = []
        for p in paths:
            covered = any(
                p == prefix or p.startswith(os.path.normpath(prefix) + os.sep)
                for prefix in mapping.keys()
            )
            if not covered:
                unmapped.append(p)
        check(
            "watch.paths all have collection mappings",
            len(unmapped) == 0,
            "all covered" if not unmapped else f"UNMAPPED: {unmapped}",
        )

    marker = os.path.exists(WATCHER_MARKER)
    check(
        f"opt-in marker {WATCHER_MARKER}",
        marker,
        "PRESENT (active)" if marker else "absent (will idle until touched)",
    )

    bw_path = subprocess.run(["which", "bw"], capture_output=True, text=True)
    check("bw CLI installed", bw_path.returncode == 0, bw_path.stdout.strip())

    check("BACKUP_DIR writable", _ensure_dir(BACKUP_DIR, mode=0o700), BACKUP_DIR)

    # ---- M5: per-target pre-flight (fail-closed) -----------------------
    # Catches the failure modes that otherwise only surface mid-absorb:
    # missing/looser disk, unwritable agent config, a materialize group
    # that doesn't exist, an unparseable .env, and (when bw is reachable)
    # a mapped collection that doesn't exist in the vault.
    def _free_mb(path: str):
        try:
            st = os.statvfs(path)
            return (st.f_bavail * st.f_frsize) // (1024 * 1024)
        except OSError:
            return None

    cfg_writable = os.access(config_path, os.W_OK)
    check("agent config.yaml writable by watcher", cfg_writable, config_path)

    for label, d in (("/run (merged tmpfs)", "/run"), ("backup dir", BACKUP_DIR)):
        mb = _free_mb(d)
        check(
            f"free space on {label}",
            mb is None or mb >= 10,
            f"{mb} MiB free" if mb is not None else "unknown",
        )

    # Build a daemon so we can reuse _collection_for / _materialize_for and
    # (best-effort) probe the vault. Never let doctor crash on bw issues.
    daemon = None
    try:
        daemon = _build_daemon(cfg)
    except Exception as e:
        logger.debug(f"doctor: _build_daemon failed: {e}")

    if daemon is not None and paths:
        import grp as _grp

        try:
            candidates = []
            for root in paths:
                candidates.extend(
                    discover_candidates(
                        root, recursive=True, max_depth=int(watch.get("max_depth", 3))
                    )
                )
        except Exception as e:
            candidates = []
            logger.debug(f"doctor: discover failed: {e}")

        # Probe the vault once (read-only — doctor NEVER creates).
        org_id = (cfg.get("organization") or {}).get("id", "")
        vault_colls = None
        if org_id:
            try:
                vault_colls = daemon.bw.list_org_collections(org_id)
            except Exception as e:
                logger.debug(f"doctor: list_org_collections failed: {e}")
        if vault_colls is None:
            check(
                "vault reachable for collection probe",
                False,
                "bw list_org_collections failed — per-target collection "
                "checks SKIPPED (run on the agent host while logged in)",
            )
        ids = {c.get("id") for c in (vault_colls or []) if isinstance(c, dict)}
        names = {c.get("name") for c in (vault_colls or []) if isinstance(c, dict)}

        for cand in candidates:
            cp = str(cand)
            if is_already_managed(cp, secrets_dir=SECRETS_DIR):
                continue
            coll = daemon._collection_for(cp)
            if not coll:
                continue  # already covered by the mapping cross-check above
            # .env parseable?
            check(f"{cp} parseable", parse_env_file(cp) is not None, "")
            # materialize group exists?
            mat = daemon._materialize_for(cp)
            if mat["materialize"] == "copy":
                grp_name = mat["group"]
                grp_ok = True
                try:
                    int(grp_name)
                except ValueError:
                    try:
                        _grp.getgrnam(str(grp_name))
                    except KeyError:
                        grp_ok = False
                check(
                    f"{cp} materialize=copy group {mat['group']!r} exists", grp_ok, ""
                )
            # collection present in vault? Informational ONLY — a missing
            # collection is NOT a failure: M1 makes the watcher create it
            # idempotently on absorb (and fail closed if it can't). So we
            # never flip doctor's exit code on this; we just surface it.
            if vault_colls is not None:
                present = coll["id"] in ids or coll["name"] in names
                check(
                    f"{cp} → collection {coll['name']!r} in vault",
                    True,
                    "present"
                    if present
                    else "absent — will be auto-created on absorb (M1); "
                    "fails closed if the service account lacks create rights",
                )

    return 0 if not problems else 1


def _classify_preview(env_path: str, config_path: str = DEFAULT_CONFIG) -> int:
    """M11: print how each key in `env_path` WOULD be classified (applying
    the per-dir overrides) WITHOUT mutating anything. Lets the operator
    confirm the secret/config split before enabling the watcher.

    Returns 0 always (informational); 2 if the file can't be parsed.
    """
    env_path = os.path.abspath(env_path)
    pairs = parse_env_file(env_path)
    if pairs is None:
        print(f"cannot parse {env_path} (unreadable / not UTF-8)")
        return 2

    overrides = None
    cfg = _load_config(config_path)
    if cfg:
        entry = ((cfg.get("watch") or {}).get("classify_overrides") or {}).get(
            os.path.dirname(env_path)
        )
        if isinstance(entry, dict):
            fs = set(entry.get("force_secret") or [])
            fc = set(entry.get("force_config") or [])
            if fs or fc:
                overrides = {"force_secret": fs, "force_config": fc}

    print(f"classify-preview: {env_path}")
    print(
        f"  overrides for dir: "
        f"{ {'force_secret': sorted(overrides['force_secret']), 'force_config': sorted(overrides['force_config'])} if overrides else 'none' }"
    )
    counts = {"secret": 0, "config": 0, "skip": 0}
    for key, value in pairs:
        kind = classify(key, value, overrides=overrides)
        counts[kind] += 1
        forced = ""
        if overrides and key in overrides["force_secret"]:
            forced = "  (forced secret)"
        elif overrides and key in overrides["force_config"]:
            forced = "  (forced config)"
        mark = {"secret": "🔒", "config": "  ", "skip": "··"}[kind]
        print(f"  [{mark}] {kind:<6} {key}{forced}")
    print(
        f"\nsummary: {counts['secret']} secret(s) would be absorbed, "
        f"{counts['config']} config kept in .env.static, "
        f"{counts['skip']} skipped"
    )
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog=WATCHER_NAME,
        description=f"SocialWarden Watcher v{VERSION} — absorbs stray .env files into the vault",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="start",
        choices=[
            "start",
            "doctor",
            "tick",
            "version",
            "purge",
            "rollback",
            "classify-preview",
            "healthcheck",
            "verify-audit",
        ],
        help="start = daemon loop (default); doctor = sanity checks; "
        "tick = single iteration for testing; purge = run janitor once; "
        "rollback = revert an absorb (needs <target> .env path); "
        "classify-preview = show secret/config split for a .env "
        "without mutating; healthcheck = dead-man's-switch (0 if the "
        "heartbeat is fresh, 1 if stale); verify-audit = walk the "
        "tamper-evident audit hash-chain (0 intact, 1 broken, 2 unreadable)",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="for `rollback` / `classify-preview`: the .env path; "
        "for `verify-audit`: optional audit-log path "
        f"(default {AUDIT_LOG})",
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="rollback: actually execute (default is dry-run)",
    )
    parser.add_argument(
        "--purge-vault",
        action="store_true",
        help="rollback: also delete the collection's vault items "
        "(irreversible; OFF by default)",
    )
    parser.add_argument(
        "--alert",
        action="store_true",
        help="healthcheck: also fire a Discord alert if the heartbeat is stale",
    )
    parser.add_argument(
        "--max-age",
        type=int,
        default=HEARTBEAT_STALE_S,
        help=f"healthcheck: stale threshold in seconds (default {HEARTBEAT_STALE_S})",
    )
    args = parser.parse_args(argv)

    if args.command == "healthcheck":
        return _healthcheck(
            config_path=args.config, max_age_s=args.max_age, alert=args.alert
        )

    if args.command == "rollback":
        if not args.target:
            print(
                "usage: socialwarden-watcher rollback <env-path> "
                "[--apply] [--purge-vault]"
            )
            return 2
        return _rollback(
            args.target,
            config_path=args.config,
            apply=args.apply,
            purge_vault=args.purge_vault,
        )

    if args.command == "classify-preview":
        if not args.target:
            print("usage: socialwarden-watcher classify-preview <env-path>")
            return 2
        return _classify_preview(args.target, config_path=args.config)

    if args.command == "verify-audit":
        return _verify_audit(args.target or AUDIT_LOG)

    if args.command == "version":
        print(f"{WATCHER_NAME} v{VERSION}")
        return 0

    if args.command == "doctor":
        return _doctor(args.config)

    if args.command == "purge":
        deleted = purge_old_backups()
        print(f"purged {deleted} expired backup(s) from {BACKUP_DIR}")
        return 0

    # Both `start` and `tick` need a working daemon.
    cfg = _load_config(args.config)
    if cfg is None:
        return 2

    if args.command == "tick":
        daemon = _build_daemon(cfg)
        if daemon is None:
            return 2
        stats = daemon.tick()
        print(json.dumps(stats.as_dict()))
        return 0

    # args.command == "start"
    lock_fh = _acquire_single_instance_lock()
    if lock_fh is None:
        return 3

    try:
        daemon = _build_daemon(cfg)
        if daemon is None:
            return 2

        # Friendly Discord ping on startup so operators see the watcher came up.
        send_discord_alert(
            daemon.discord_webhook,
            title="Watcher started",
            description=f"`{WATCHER_NAME} v{VERSION}` is now running.",
            color=COLOR_BLUE,
            machine_name=daemon.machine_name,
        )

        poll_interval = float(
            (cfg.get("watch") or {}).get("poll_interval", DEFAULT_POLL_INTERVAL_S)
        )
        return daemon.run_forever(poll_interval=poll_interval)
    finally:
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock_fh.close()


if __name__ == "__main__":
    sys.exit(main())
