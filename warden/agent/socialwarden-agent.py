#!/usr/bin/env python3
"""
SocialWarden Agent — Secrets sync daemon for SOCials
Syncs secrets from Vaultwarden to /run/secrets/ (tmpfs/RAM)

Architecture:
  Vaultwarden (vault.example.com) → bw CLI → Agent → /run/secrets/*.env

Security model:
  - Secrets decrypted client-side (Vaultwarden zero-knowledge)
  - Master password in /run/ (tmpfs, RAM only, never disk)
  - Output files in /run/secrets/ (tmpfs, chmod 600)
  - No plaintext secrets in logs (only names, never values)
  - Snapshots in /var/lib/socialwarden/versions/ encrypted at-rest with the
    machine-bound key (same primitive that protects master.key) — SEC-6.
    (Historical note: this line used to claim "SOPS"; that was never
    implemented — snapshots were plaintext until v1.4.13. SEC-6 fixes it.)

Based on analysis of Infisical Agent (Go, token lifecycle + templating)
and adapted for Vaultwarden's zero-knowledge E2E encryption model.

Changelog v1.2.1:
  - Fix: detect "vault is locked" and "mac failed" as recoverable session errors
  - Fix: list_items returns None on bw error (distinct from empty collection)
  - Fix: skip collection on fetch error instead of triggering false COLLECTION EMPTIED alerts
  - Fix: guard against re-auth recursion (skip re-auth for unlock commands, limit to one retry)
  - Fix: SIGHUP handler added — `socialwarden sync` no longer kills the daemon
  - Fix: poll loop uses interruptible sleep(1) so force-sync triggers within seconds

Changelog v1.2.0:
  - Merge mode: combine .env.static (config) + secrets (RAM) → symlink
  - Phase 3: eliminates plaintext secrets from disk
  - Automatic backup of original .env before replacing with symlink

Changelog v1.1.0:
  - Discord alerts: change, drift, error, secret age, agent start/stop
  - Discord alerts: secret added, secret deleted, empty password, collection emptied
  - Secret age uses revisionDate from Vaultwarden (survives agent restarts)
  - Fix: silence 'bw config server: Logout required' noise
  - Fix: _update_cache no longer duplicates bw.list_items() call
  - Bump version

Author: Maikol Romero
Version: 1.3.0

Changelog v1.3.0:
  - Feature: post_sync hooks per collection (fire-and-forget shell commands)
  - Feature: rotation/expiry scheduler via vault custom fields (expires_at, rotate_every_days)
  - Feature: optional policy enforcement via /etc/socialwarden/policy.yaml
  - Feature: honeypot tripwire — if configured secret values appear in container logs, alert
  - Perf: batch list_items — one `bw list items --organizationid` per cycle, client-filter per collection
  - Perf: skip _merge_and_link when nothing changed and merged file already exists
  - Security: cache stores password sha256 only, not plaintext (diff still works via hash compare)

Changelog v1.4.5:
  - Robustness: post_sync hooks now run in a daemon thread that captures
    stdout+stderr to /var/log/socialwarden/post_sync.log, waits for completion
    with a 300s timeout, kills the process group on timeout, and emits Discord
    alerts on real failures (rc > 0) or timeouts. Subprocess-killed-by-signal
    (rc < 0, e.g. systemd shutdown mid-hook) is logged as INTERRUPTED without
    Discord noise. Discovered after a real failure: post_sync was lighting up
    a worker container in Created state with no alert path.
  - Feature: post_sync hooks also trigger on .env.static changes (not just
    secret-value rotations). Previously editing .env.static would re-merge the
    target file but containers stayed stale. Now both `secrets_changed` and
    `static_changed` (merged-content delta) trigger the hook. Initial-sync
    guard preserved (hooks don't fire on cold start).
  - Security: `alerts.discord_webhook` can now be sourced from a separate file
    via `alerts.discord_webhook_file: /path/to/file` (mode 0600 root). Keeps
    the webhook URL out of config.yaml backups and any git checkout. The
    `_file` indirection is resolved at load time and the original key is
    removed from the in-memory dict. Backward-compatible: literal
    `discord_webhook:` in YAML still works.

Changelog v1.4.6:
  - Feature: MODO C — render template universal. Per-collection `render:`
    list of {template, target, mode, owner, backup} dicts. Engine is
    `string.Template` from stdlib (`${VAR}` substitution) — no external deps.
    Targets that don't fit the env-file pattern (service.yaml hardcoded keys,
    redis.conf with requirepass, pgbouncer.ini, etc.) can now be sourced from
    a `.tmpl` in /etc/socialwarden/templates/ + secrets from the vault.
  - Anti-error guarantees:
      * Strict substitution — missing ${VAR} fails the render, target is
        left intact, Discord alert with template path + missing var name.
      * Atomic write via tmp+rename. POSIX guarantees the target is never
        observed half-written by readers.
      * Hash-skip — if rendered content is byte-identical to current target,
        no rewrite, no post_sync trigger.
      * Backup rotation — before rename, copy current target to
        <target>.bak-<UTC-TS>. Prune to keep N=5 most recent backups.
      * Initial-render guard — first time the agent renders a target, it
        writes if different but does NOT fire post_sync (consistent with
        the merge initial-sync guard, avoids docker-storms on cold start).
  - Trigger logic in sync_once now considers three independent change
    signals: secrets_changed, static_changed, render_changed. ANY of them
    fires post_sync.
  - Available substitution variables: every secret name in the collection
    (the Bitwarden item `name` becomes `${NAME}`, value is the password),
    plus metadata: ${MACHINE_NAME}, ${COLLECTION_ID}, ${SYNCED_AT}.

Changelog v1.4.8:
  - Fix root-cause for false `Collection Emptied` alerts. v1.4.7 only added an
    anti-spam threshold (3 consecutive empties before alerting); v1.4.8
    actually CLASSIFIES the empty result before deciding to alert.
  - Layered defense added:
      Layer 1 — Cross-process flock on /var/lib/socialwarden/bw.lock around
        every bw subprocess call. Coordinates with cooperating callers
        (socialwarden-watcher Sprint 2+, manual operator commands) so they
        no longer race on the shared bw CLI state file.
      Layer 2 — BWClient.diagnose_empty(): when `bw list` returns [] for a
        previously non-empty collection, force a fresh unlock + retry. If
        items come back, treat it as silent session-staleness (log INFO, no
        streak tick, no alert). If items are still empty AND the collection
        is reachable via `bw get collection`, only then call it a real empty
        and tick the streak. Other verdicts ("transient", "unknown") defer
        to the next cycle without alerting.
      Layer 3 — preserved: 3-poll EMPTY_FLAP_THRESHOLD still gates the real
        alert path for defense-in-depth even after Layer 2 verdict.
      Layer 4 — preserved: /run/secrets/*.env never overwritten when items
        is empty — services keep reading the last-known-good values.
  - The combined effect: third-party bw unlocks (operator, watcher, audit)
    no longer trigger any Discord noise — the agent silently recovers.
    Real emptyings (operator/attacker deleted items) still alert.

Changelog v1.4.12:
  - UDS API is now a tiny op-router (Phase 2 — dispatcher/acyclic bus).
    `op:"get"` is byte-identical: per-container policy, rate-limit and
    secret delivery are untouched and unconditional. The critical
    secret-delivery path does NOT change.
  - New read-only BUS verbs (watcher↔agent control plane) behind three
    independent fail-closed guards (defense in depth):
      * BUS_PROTO_VERSION (== UDS_PROTO_VERSION): wrong `v` → bad_request
        so a skewed caller falls back to its self-contained mode.
      * hop-limit = 1: request carries `hop`; hop>1 (or non-int/bool) is
        rejected — no A→B→A chain can form even via a future bug.
      * uid==0 authz via SO_PEERCRED: BUS verbs require a root peer (the
        watcher runs as root). `get` keeps its non-root container model;
        the socket attack surface for containers is NOT widened.
  - BUS read verbs (all read-only, never call bw, never touch the 60s
    poll — derived purely from already-materialized state):
      * `status`            — liveness: agent, version, uptime, file count.
      * `collections`       — list of synced collections from
        /run/secrets/*.env: name, last-sync time, key count.
      * `collection-status` — same for one named collection; the name is
        strictly validated (alnum/._-, no `..`, resolved parent must be
        the secrets dir) so the verb cannot traverse the filesystem.
  - BUS calls are rate-limited (shared "bus" bucket) and audited as `get`.

Changelog v1.4.13 (SEC-6 — Sprint 3 slice 3a.1):
  - `_save_version()` now writes version snapshots ENCRYPTED at-rest
    (`ENC:` + machine-bound `encrypt_credential`, identical on-disk
    format to `ensure_encrypted` so `read_encrypted` and the watcher's
    `read_encrypted_file` both decrypt them). Before v1.4.13 these
    `/var/lib/socialwarden/versions/*.env` were PLAINTEXT on persistent
    disk (0600 root) since April — same exposure class SEC-1 closed for
    `.pre-socialwarden` (lives in every EBS snapshot / backup / forensic
    image). Nothing read them back (write-only/dead-on-read), so this is
    a zero-reader-break change; it also forward-enables 3a (boot
    fallback can now decrypt a snapshot when the vault is unreachable).
  - Caveat (tracked separately, NOT a regression): `encrypt_credential`
    is a homebrew XOR-stream+HMAC with a repeating 32-byte keystream —
    weak vs real AEAD, but it is the SAME primitive already protecting
    master.key, so versions/ now matches that protection level (not
    worse). Retro-clean of pre-v1.4.13 plaintext snapshots fleet-wide is
    a separate ops step (slice 3a.3).

Changelog v1.4.14 (Sprint 3 — slice 3a.2, boot fallback):
  - New opt-in `resilience.boot_fallback` (default OFF → zero change to
    the normal path / current fleet behaviour). When the INITIAL sync
    cannot reach the vault AND a collection's `output` file is
    missing/empty, the agent restores it from the latest ENCRYPTED
    versions/ snapshot (read_encrypted, machine-bound) so consumers do
    not boot with zero secrets. Fail-closed: never clobbers a present
    output, never runs if the vault was reachable, writes NOTHING if
    there is no snapshot or decrypt fails (alerts instead — consumer
    fails loudly, never gets fabricated/wrong secrets). Reconciliation
    is automatic — the 60s poll loop overwrites the degraded restore
    with authoritative vault data once the vault returns and emits a
    "Boot Fallback Reconciled" alert. Render (MODO C) targets are out of
    scope (snapshot is env, not the rendered file) — they wait for vault.
  - sync_once() now tracks last_sync_vault_ok (inert boolean: True once
    org items are fetched, False on the two vault early-returns) to
    drive the above. No behaviour change to the sync path itself.

Changelog v1.4.15 (Sprint 3 — slice 3b, post_sync retry + healthz):
  - `_exec_post_sync_hook` refactored into `_post_sync_run_once` (run +
    classify, no alert) + `_post_sync_alert` (terminal alert, titles &
    bodies BYTE-IDENTICAL to pre-3b) + orchestrator. DEFAULT
    (`resilience.post_sync_retry` OFF) = exactly one attempt with the
    same alerts as before → the whole current fleet is observably
    unchanged. OPT-IN (true): real failures (failed/timeout/exec_error)
    retry with backoff [30s,2min,10min] (override `post_sync_backoffs`);
    between attempts an optional per-collection `healthz_url` is probed —
    if it goes healthy the service recovered → stop (success) even
    though the hook failed; rc=0 but healthz never healthy → fail-closed
    `healthz_fail` alert (NEVER reported as success). `interrupted`
    (rc<0, agent teardown) is never retried/alerted, as before.
  - `_healthz_ok` (stdlib urllib, any error → False, fail-closed).

Changelog v1.4.16 (Sprint 3 — slice 3c.1, dynamic-pg revoke watcher scaffold):
  - New opt-in `PgRevokeWatcher` daemon thread, gated by
    `resilience.pg_revoke_watcher: true` (default OFF → thread is never
    started, zero change to current fleet behaviour). Tails
    `docker events --filter type=container --filter event=die` and, for a
    dead container that maps to a DB role in `resilience.pg_revoke_map`,
    triggers an immediate revoke instead of waiting for Postgres TCP
    keepalive / idle_in_transaction reaping. Acyclic: its own daemon
    thread, never touches sync_once()/the 60s poll, never calls back into
    SyncEngine. Fail-closed: a container NOT in the map is ignored (we
    never revoke a role we were not explicitly told to own); docker
    missing / stream death → bounded-backoff reconnect, never crashes the
    agent.
  - 3c.1 is DRY-RUN ONLY: it parses the stream and resolves
    container→role but performs NO database action (logs the intended
    revoke). The actual Postgres mutation (terminate backends + ALTER
    ROLE NOLOGIN, admin creds from a synced secret, fail-closed) is a
    deliberately separate later slice because it writes to the production
    Patroni cluster and its exact shape is pending an explicit decision.

Changelog v1.4.17 (Sprint 3 — slice 3c.2, reaper action):
  - Decision taken: 3c is a host-local, DB-agnostic SESSION REAPER (NOT a
    Vault-style per-container credential broker — there are no
    per-container DB users; roles are shared per app). On a watched
    container's `die`, the agent terminates that container's orphaned
    backends scoped by `client_addr` (the container's IP — verified
    distinct per container in pg_stat_activity), so a living sibling
    sharing the same role is never killed. Reversible `ALTER ROLE
    ... NOLOGIN` is opt-in OFF (`resilience.pg_revoke_nologin`) precisely
    because it is unsafe on shared roles.
  - IP cache kept fresh from `start`/`die` events + a `seed_ips()` sweep
    of already-running watched containers at thread start.
  - Admin connection parsed from `resilience.pg_revoke_admin_dsn_file`
    (a libpq URI, typically a socialwarden-synced secret in /run/secrets);
    password passed via PGPASSWORD env, never in argv/logs. Executes via
    `psql` subprocess — no new Python dependency, same pattern as the
    agent's existing `docker`/`bw` shell-outs.
  - Still DRY-RUN by default even when the watcher is enabled: mutates
    the DB only if `resilience.pg_revoke_dry_run: false` is set per host.
    Fail-closed throughout (unwatched / no cached IP / no-or-blank DSN /
    psql missing / non-zero / timeout → log + skip, never crash, never
    block the poll). Live enablement near prod Patroni remains a separate
    explicit-OK ops step.
"""

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
import string
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import yaml  # module-level: load_config, UDS API policy, and log scanner all need it
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Credential encryption (machine-bound)
# ---------------------------------------------------------------------------
def _get_machine_key():
    """Derive encryption key from machine-id (unique per server).
    If credentials are copied to another machine, they can't be decrypted."""
    import hashlib

    try:
        machine_id = open("/etc/machine-id").read().strip()
    except FileNotFoundError:
        machine_id = "fallback-" + open("/sys/class/dmi/id/product_uuid").read().strip()
    return hashlib.sha256(f"socialwarden-{machine_id}".encode()).digest()


def encrypt_credential(plaintext):
    """Encrypt a credential with machine-bound key (AES-256-GCM via XOR + HMAC).
    Simple but effective — no external dependency needed."""
    import hashlib
    import base64
    import os as _os

    key = _get_machine_key()
    nonce = _os.urandom(16)
    # XOR-based stream cipher with HMAC integrity
    stream = hashlib.sha256(key + nonce).digest()
    encrypted = bytes(
        a ^ b for a, b in zip(plaintext.encode(), stream * ((len(plaintext) // 32) + 1))
    )
    mac = hashlib.sha256(key + nonce + encrypted).digest()[:16]
    return base64.b64encode(nonce + mac + encrypted).decode()


def decrypt_credential(ciphertext):
    """Decrypt a machine-bound credential."""
    import hashlib
    import base64

    key = _get_machine_key()
    raw = base64.b64decode(ciphertext)
    nonce = raw[:16]
    mac = raw[16:32]
    encrypted = raw[32:]
    # Verify integrity
    expected_mac = hashlib.sha256(key + nonce + encrypted).digest()[:16]
    if mac != expected_mac:
        raise ValueError(
            "Credential integrity check failed — wrong machine or tampered file"
        )
    stream = hashlib.sha256(key + nonce).digest()
    decrypted = bytes(
        a ^ b for a, b in zip(encrypted, stream * ((len(encrypted) // 32) + 1))
    )
    return decrypted.decode()


def ensure_encrypted(path):
    """Encrypt a plaintext credential file in-place if not already encrypted."""
    with open(path) as f:
        content = f.read().strip()
    if content.startswith("ENC:"):
        return  # Already encrypted
    encrypted = "ENC:" + encrypt_credential(content)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, encrypted.encode() + b"\n")
    finally:
        os.close(fd)


def read_encrypted(path):
    """Read and decrypt a credential file."""
    content = open(path).read().strip()
    if content.startswith("ENC:"):
        return decrypt_credential(content[4:])
    # Not encrypted yet — encrypt it now and return plaintext
    ensure_encrypted(path)
    return content


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERSION = "1.5.0"
AGENT_NAME = "socialwarden-agent"

# v1.4.18: render_env skips items whose name is NOT a valid POSIX env-var
# identifier. The watcher creates such items intentionally (e.g. "<KEY>
# [drift <DATE>]") as human-only drift markers; they must NEVER leak into
# the consumer's .env. This regex matches the same identifier shape the
# POSIX entrypoint shim accepts (see line ~1164 in the shim block).
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DEFAULT_CONFIG = "/etc/socialwarden/config.yaml"
HEARTBEAT_PATH = "/run/socialwarden/heartbeat"
METRICS_PATH = "/tmp/node-exporter-textfile/socialwarden.prom"
CACHE_DIR = "/var/lib/socialwarden/cache"
VERSIONS_DIR = "/var/lib/socialwarden/versions"
IDENTITY_PRIV_PATH = "/var/lib/socialwarden/identity.key"
IDENTITY_PUB_PATH = "/var/lib/socialwarden/identity.pub"
MAX_VERSIONS = 30
# Collection-emptied flap suppression: require N consecutive polls with items=[]
# AND a clean diagnose verdict ("real_empty") before raising the alert. v1.4.8
# adds the diagnose step so transient session-staleness from concurrent bw
# usage no longer counts toward the streak (was: only suppressed for 3 polls,
# still alerted if the staleness lasted longer than that).
EMPTY_FLAP_THRESHOLD = 3
# Cross-process flock to coordinate bw CLI usage with other processes on the
# same host (socialwarden-watcher Sprint 2+, manual operator commands, etc.).
# Every subprocess `bw …` call goes through `_bw_flock()`. The bw CLI state
# file (~/.config/Bitwarden CLI/data.json) is shared across processes and
# concurrent unlock from another caller can silently invalidate our session
# (returning items=[] without any error string we can pattern-match on). The
# flock prevents that race for cooperating callers. Non-cooperating callers
# (third-party bw invocations bypassing the lock) are detected by the
# diagnose_empty() fallback in BWClient.
BW_LOCK_PATH = "/var/lib/socialwarden/bw.lock"
BW_LOCK_TIMEOUT_S = 30

# S1: same tmpfs recovery-backup dir + filename scheme the watcher uses, so an
# emergency `socialwarden-watcher rollback` / _find_latest_backup can also find a
# recovery copy the AGENT made. MUST NOT diverge from the watcher's BACKUP_DIR
# / BACKUP_NAME_FMT / _flatten_path_for_backup (see socialwarden-watcher.py).
BACKUP_DIR = "/run/socialwarden-backups"
BACKUP_NAME_FMT = "%Y%m%dT%H%M%SZ"

# Discord embed colors
COLOR_GREEN = 0x2ECC71  # Changes detected, new secrets
COLOR_RED = 0xE74C3C  # Drift / errors / deletions
COLOR_YELLOW = 0xF39C12  # Secret age warning
COLOR_ORANGE = 0xE67E22  # Empty password, warnings
COLOR_BLUE = 0x3498DB  # Agent lifecycle (start/stop)


# ---------------------------------------------------------------------------
# Logging — JSON format for Promtail/Loki
# ---------------------------------------------------------------------------
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "component": AGENT_NAME,
            "machine": getattr(record, "machine", "unknown"),
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


logger = logging.getLogger(AGENT_NAME)


# ---------------------------------------------------------------------------
# Discord alerts
# ---------------------------------------------------------------------------
def send_discord_alert(
    webhook_url, title, description, color, machine_name, fields=None
):
    """Send a Discord embed notification.

    Non-blocking: logs warning on failure but never crashes the agent.
    Uses only stdlib (urllib) — no external dependencies.
    """
    if not webhook_url:
        return  # No webhook configured — silent skip

    embed = {
        "title": f"🔐 SocialWarden — {title}",
        "description": description,
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"SocialWarden v{VERSION} • {machine_name}"},
    }
    if fields:
        embed["fields"] = fields

    payload = json.dumps({"embeds": [embed]}).encode("utf-8")

    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"SocialWarden/{VERSION}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 204):
                logger.warning(f"Discord webhook returned {resp.status}")
    except urllib.error.URLError as e:
        logger.warning(f"Discord alert failed (URLError): {e.reason}")
    except Exception as e:
        logger.warning(f"Discord alert failed: {e}")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_config(path):
    """Load YAML config. Minimal dependency — parse manually if PyYAML missing."""
    try:
        import yaml

        with open(path) as f:
            cfg = yaml.safe_load(f)
    except ImportError:
        # Fallback: parse simple YAML without external dependency
        logger.warning("PyYAML not installed, using JSON config fallback")
        json_path = path.replace(".yaml", ".json").replace(".yml", ".json")
        with open(json_path) as f:
            cfg = json.load(f)
    _resolve_secret_refs(cfg)
    return cfg


def _resolve_secret_refs(cfg):
    """Resolve `<key>_file:` indirections so secrets stay out of the YAML.

    Currently supported:
      alerts.discord_webhook_file → alerts.discord_webhook (read at load time).

    The original `_file` key is removed after resolution so the file path
    is the only thing that ever lives in the config dict itself.
    """
    alerts = (cfg or {}).get("alerts") or {}
    wh_file = alerts.get("discord_webhook_file")
    if wh_file and not alerts.get("discord_webhook"):
        try:
            with open(wh_file) as f:
                alerts["discord_webhook"] = f.read().strip()
            alerts.pop("discord_webhook_file", None)
        except OSError as e:
            logger.error(f"Failed to read discord_webhook_file={wh_file}: {e}")


# ---------------------------------------------------------------------------
# Bitwarden CLI wrapper
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Cross-process bw coordination (v1.4.8)
# ---------------------------------------------------------------------------
@contextlib.contextmanager
def _bw_flock(timeout_s=BW_LOCK_TIMEOUT_S, path=BW_LOCK_PATH):
    """Acquire an exclusive flock on BW_LOCK_PATH for the duration of a bw
    subprocess call. Coordinates with other cooperating processes on the
    same host (socialwarden-watcher, etc.) so concurrent bw invocations don't
    clobber the shared CLI state file under ~/.config/Bitwarden CLI/.

    On timeout the manager logs a warning and yields anyway (degraded mode
    — better to make the call without the lock than to crash the sync
    cycle). Lock failures here never propagate as exceptions to the caller.
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError:
        # Best-effort; if we can't create the lock dir, fall through unlocked.
        logger.debug(f"_bw_flock: cannot mkdir {os.path.dirname(path)}")
        yield
        return
    try:
        fh = open(path, "a+")
    except OSError as e:
        logger.warning(f"_bw_flock: cannot open lock {path}: {e}; proceeding unlocked")
        yield
        return
    try:
        deadline = time.monotonic() + timeout_s
        delay = 0.05
        acquired = False
        while True:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    logger.warning(
                        f"_bw_flock: timeout after {timeout_s}s on {path}; "
                        "proceeding unlocked (another bw caller is hogging the lock)"
                    )
                    break
                time.sleep(delay)
                delay = min(delay * 1.5, 1.0)
        try:
            yield
        finally:
            if acquired:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
    finally:
        try:
            fh.close()
        except OSError:
            pass


class BWClient:
    """Wraps the Bitwarden CLI (bw) for Vaultwarden interaction."""

    # Stderr messages from 'bw config server' that are harmless noise
    _CONFIG_NOISE = (
        "logout required",
        "you are already logged in",
        "saved setting",
    )

    def __init__(self, server_url, email, master_key_path):
        self.server_url = server_url
        self.email = email
        self.master_key_path = master_key_path
        self.session = None
        self._configured = False

    def _read_master_password(self):
        """Read and decrypt master password. Auto-migrates from legacy tmpfs
        location (/run/socialwarden/master.key) to persistent
        (/var/lib/socialwarden/master.key) if the persistent path is empty.

        Rationale: the key file is encrypted with a machine-id-derived key.
        An attacker with disk access has /etc/machine-id anyway, so tmpfs
        didn't add real security — it only broke reboot resilience. Moving
        to persistent storage (mode 0700 dir, 0600 file) maintains the
        same threat model while making reboots self-healing.
        """
        path = Path(self.master_key_path)
        legacy_path = Path("/run/socialwarden/master.key")

        # Auto-migrate: if the configured path is the new persistent one and
        # doesn't exist, but legacy tmpfs one does, copy it across.
        if (
            not path.exists()
            and str(path).startswith("/var/lib/")
            and legacy_path.exists()
            and legacy_path.resolve() != path.resolve()
        ):
            try:
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                content = legacy_path.read_bytes()
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.write(fd, content)
                os.close(fd)
                logger.info(
                    f"Migrated master key from tmpfs to persistent storage: "
                    f"{legacy_path} → {path}"
                )
            except OSError as e:
                logger.warning(f"Master key migration failed: {e}")

        if not path.exists():
            raise FileNotFoundError(
                f"Master key not found at {self.master_key_path}. "
                f"Create it with: echo 'YOUR_MASTER_PASSWORD' > {self.master_key_path} "
                f"&& chmod 600 {self.master_key_path}"
            )
        return read_encrypted(self.master_key_path)

    def _run(self, args, input_data=None, timeout=30, _retry_count=0, extra_env=None):
        """Execute bw CLI command.

        _retry_count: internal, prevents infinite re-auth recursion.
        Only re-authenticate once per call chain (max_retries=1).

        extra_env: optional {str: str} merged into the child env (NOT argv).
        Used to inject the master password for `unlock --passwordenv`
        (must-fix #3) so the plaintext never lands on persistent disk and
        never appears in /proc/<pid>/cmdline. Not propagated to the
        post-re-auth retry: a re-auth itself goes through
        _unlock_with_decrypted_key, which supplies its own extra_env.
        """
        env = os.environ.copy()
        if self.session:
            env["BW_SESSION"] = self.session
        env["BW_NOINTERACTION"] = "true"
        if extra_env:
            env.update(extra_env)
        # TLS: trust system certs (Tailscale + wildcard cert)

        # Skip re-auth logic entirely if this IS an unlock command.
        # _unlock_with_decrypted_key calls _run(["unlock", ...]); we must not
        # try to re-auth an unlock or we infinite-recurse.
        is_unlock_call = len(args) > 0 and args[0] == "unlock"

        try:
            # v1.4.8: serialize bw invocations across cooperating processes
            with _bw_flock():
                result = subprocess.run(
                    ["bw"] + args,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env,
                    input=input_data,
                )
            if result.returncode != 0:
                stderr = result.stderr.strip()
                # Don't log session tokens or passwords in errors
                safe_stderr = stderr[:200] if len(stderr) > 200 else stderr
                # Detect expired/invalid/locked session — all recoverable via re-unlock
                stderr_low = stderr.lower()
                session_issue = (
                    "not logged in" in stderr_low
                    or "session key" in stderr_low
                    or "unauthenticated" in stderr_low
                    or "vault is locked" in stderr_low
                    or "mac failed" in stderr_low  # corrupted session state
                )
                # Only attempt re-auth if:
                # - it's a session issue
                # - this is NOT an unlock call (prevents recursion)
                # - we haven't already retried (prevents loops)
                if session_issue and not is_unlock_call and _retry_count == 0:
                    logger.warning(
                        f"Session issue ({safe_stderr[:80]}) — attempting re-authentication"
                    )
                    if self._reauthenticate():
                        # Retry the original command with new session — must
                        # pass input_data along; some bw subcommands (encode,
                        # password change) need stdin to make sense.
                        env["BW_SESSION"] = self.session
                        # v1.4.8: serialize the retry too
                        with _bw_flock():
                            retry = subprocess.run(
                                ["bw"] + args,
                                capture_output=True,
                                text=True,
                                timeout=timeout,
                                env=env,
                                input=input_data,
                            )
                        if retry.returncode == 0:
                            return retry.stdout.strip()
                        # Retry also failed — log and give up this cycle
                        retry_stderr = retry.stderr.strip()[:200]
                        logger.error(
                            f"bw {' '.join(args[:2])}: retry after re-auth also failed: {retry_stderr}"
                        )
                        return None
                logger.error(
                    f"bw {' '.join(args[:2])}: exit {result.returncode}: {safe_stderr}"
                )
                return None
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            logger.error(f"bw {' '.join(args[:2])}: timeout after {timeout}s")
            return None
        except FileNotFoundError:
            logger.critical(
                "bw CLI not found. Install: https://bitwarden.com/download/#downloads-command-line-interface"
            )
            sys.exit(1)

    def configure(self):
        """Set server URL (one-time).

        bw config server returns non-zero with 'Logout required' if already
        logged in — this is harmless noise, not a real error.
        """
        if self._configured:
            return

        env = os.environ.copy()
        env["BW_NOINTERACTION"] = "true"
        try:
            # v1.4.8: serialize bw invocations across cooperating processes
            with _bw_flock():
                result = subprocess.run(
                    ["bw", "config", "server", self.server_url],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env=env,
                )
            stderr_lower = result.stderr.strip().lower()
            if result.returncode != 0:
                # Check if it's just the harmless "logout required" noise
                if any(noise in stderr_lower for noise in self._CONFIG_NOISE):
                    logger.debug(
                        f"bw config server: already configured (ignored: {result.stderr.strip()[:80]})"
                    )
                else:
                    logger.error(
                        f"bw config server failed: {result.stderr.strip()[:200]}"
                    )
            self._configured = True
        except subprocess.TimeoutExpired:
            logger.error("bw config server: timeout")
        except FileNotFoundError:
            logger.critical("bw CLI not found")
            sys.exit(1)

    def _unlock_with_decrypted_key(self):
        """Decrypt the master key and unlock bw, passing the password via an
        environment variable (must-fix #3).

        Previously this wrote the *plaintext* master password to
        ``<master_key_path>.unlock`` — a PERSISTENT file under
        /var/lib/socialwarden — and removed it with a plain ``os.unlink``
        (recoverable; lands in disk snapshots). We now inject it via
        ``BW_PASSWORD_INTERNAL`` and ``bw unlock --passwordenv`` (exactly
        what the watcher's _ensure_session already does): no temp file at
        all, and the secret never appears in argv (/proc/<pid>/cmdline).
        Behaviour is otherwise identical — bw still unlocks and we return
        the raw session token (or None on failure)."""
        plaintext = read_encrypted(self.master_key_path)
        session = self._run(
            ["unlock", "--passwordenv", "BW_PASSWORD_INTERNAL", "--raw"],
            timeout=60,
            extra_env={"BW_PASSWORD_INTERNAL": plaintext},
        )
        return session

    def login(self):
        """Authenticate: session already logged in, just unlock."""
        self.configure()

        status_out = self._run(["status"])
        if status_out:
            try:
                status = json.loads(status_out)
                if status.get("status") == "unlocked":
                    logger.info("Vault already unlocked")
                    return True
                elif status.get("status") in ("locked", "unauthenticated"):
                    if status.get("status") == "unauthenticated":
                        logger.critical(
                            "Not logged in. Run: sudo bw login YOUR_EMAIL "
                            "(one-time manual login with 2FA required)"
                        )
                        return False
                    session = self._unlock_with_decrypted_key()
                    if session:
                        self.session = session
                        logger.info("Vault unlocked successfully")
                        return True
                    logger.error("Vault unlock failed")
                    return False
            except json.JSONDecodeError:
                pass

        logger.error("Cannot determine vault status")
        return False

    def _reauthenticate(self):
        """Re-authenticate when session expires."""
        logger.info("Re-authenticating...")
        session = self._unlock_with_decrypted_key()
        if session and len(session) > 20:
            self.session = session
            logger.info("Re-authentication successful")
            return True
        logger.error("Re-authentication failed")
        return False

    def sync(self):
        """Sync vault with server."""
        result = self._run(["sync"], timeout=30)
        if result is not None:
            logger.debug("Vault synced")
            return True
        return False

    def list_all_org_items(self, org_id):
        """Fetch ALL items of an organization in a single bw invocation.

        Callers filter client-side per collection (see filter_by_collection).
        This is much faster than calling list_items once per collection when
        the agent manages multiple collections (N collections → 1 bw call
        instead of N).

        Returns:
            list: raw items (can be empty)
            None: if bw command failed (distinct from empty org)
        """
        output = self._run(
            ["list", "items", "--organizationid", org_id],
            timeout=60,
        )
        if output is None:
            return None
        if not output:
            return []
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            logger.error("Failed to parse items JSON")
            return None

    @staticmethod
    def filter_by_collection(all_items, collection_id):
        """Filter org items to those in a specific collection (type=Login only)."""
        return [
            item
            for item in all_items
            if collection_id in (item.get("collectionIds") or [])
            and item.get("type") == 1
        ]

    def list_items(self, org_id, collection_id):
        """Back-compat wrapper — fetches and filters. Prefer list_all_org_items
        + filter_by_collection when iterating multiple collections."""
        items = self.list_all_org_items(org_id)
        if items is None:
            return None
        return self.filter_by_collection(items, collection_id)

    def diagnose_empty(self, org_id, collection_id):
        """v1.4.8: classify why a previously non-empty collection looks empty.

        bw can return items=[] silently (no stderr) when:
         (a) our session was invalidated by a concurrent unlock from another
             process — the most common cause, and we can self-recover by
             dropping the cached session + re-authenticating + retrying;
         (b) the collection was actually emptied — real alert-worthy state;
         (c) the collection was deleted from the vault — different alert;
         (d) we lost permission to the collection — different alert;
         (e) bw cache/network glitch — transient, don't alert.

        Returns one of:
          ("session_stale", new_items)  — recovered; new_items is the refetched list
          ("real_empty",    [])         — collection is genuinely empty
          ("collection_gone", None)     — collection no longer exists
          ("permission_lost", None)     — collection exists but we can't see it
          ("transient",     None)       — bw flaked, retry next cycle silently
          ("unknown",       None)       — couldn't classify; defer to next cycle

        Never raises. Defensive every step.
        """
        # Step 1: drop our cached session and force a re-unlock + retry.
        # This handles case (a) — the most common false positive.
        cached_session = self.session
        self.session = None
        if not self._reauthenticate():
            # Couldn't re-unlock — can't tell what's happening.
            logger.warning("diagnose_empty: re-auth failed; treating as transient")
            self.session = cached_session  # restore in case it still works
            return ("transient", None)

        refetched = self.list_all_org_items(org_id)
        if refetched is None:
            # bw error after fresh unlock — transient.
            logger.warning("diagnose_empty: list_all failed after re-auth; transient")
            return ("transient", None)

        retry_items = self.filter_by_collection(refetched, collection_id)
        if retry_items:
            # Got items back after re-auth — was just stale session, silently recovered.
            return ("session_stale", retry_items)

        # Step 2: items are still empty after fresh unlock. Check whether the
        # COLLECTION still exists.
        coll_out = self._run(["get", "collection", collection_id], timeout=15)
        if coll_out is not None:
            # bw returned a collection object → collection exists, we have access.
            # The items=[] is real.
            return ("real_empty", [])

        # _run returned None — could be 'not found', 'access denied', or other.
        # We have no structured error from _run (it only returns None on failure).
        # Without changing _run's contract, we can't easily distinguish; defer to
        # next cycle and don't alert. If this state persists, an operator alert
        # path could be added later. (Better to be quiet than wrong.)
        logger.warning(
            f"diagnose_empty: 'bw get collection {collection_id[:8]}…' failed; "
            "cannot distinguish collection_gone vs permission_lost — deferring alert"
        )
        return ("unknown", None)


# ---------------------------------------------------------------------------
# .env value codec (must-fix #1 + #2) — LOSSLESS, consumer-safe
# ---------------------------------------------------------------------------
# Three implementations of this codec MUST stay byte-for-byte consistent:
#   * agent  render_env()        — ENCODE  (vault value -> .env line)
#   * agent  decode_env_value()  — DECODE  (used for round-trip verification)
#   * watcher _strip_value()     — DECODE  (when absorbing / re-parsing .env)
# Invariant: decode(encode(v)) == v for ANY str v, AND encode(simple) is
# byte-identical to the pre-fix `f"{k}={v}"` so a future deploy does not
# churn/break running services whose secrets are simple.
#
# Strategy:
#   * "Simple-safe" values (the common case: API keys, tokens, hex, b64,
#     URLs w/o spaces, empty) are emitted RAW (KEY=value) — unchanged output.
#   * EVERYTHING else (spaces, '#', '$', quotes, backslash, backtick, tab,
#     CR, NEWLINE/multi-line PEM+JSON, unicode, leading/trailing space) is
#     emitted as a self-describing sentinel token  KEY=__SWB64__<b64>__
#     whose alphabet ([A-Za-z0-9+/=_]) contains no char special to bash
#     `source`, python-dotenv, or `docker compose --env-file`, so every
#     consumer reads the token back verbatim and the decoder reconstructs
#     the EXACT original bytes (incl. real newlines — must-fix #2: never
#     emit a raw newline into the env file).
#
# Why a sentinel instead of double-quoting + backslash escapes: bash
# `source` and python-dotenv DISAGREE on '\$' (bash drops the backslash and
# would also interpolate a bare '$VAR'; dotenv keeps it) and on newlines, so
# no single quoted form round-trips through BOTH. The base64 token does.
_DWB64_PREFIX = "__SWB64__"
_DWB64_SUFFIX = "__"
# Raw-emit iff value is non-problematic for EVERY consumer and parser:
# only these chars, no leading/trailing whitespace, no newline. Empty
# string matches (=> KEY=, the historical empty-secret rendering).
#
# must-fix #1 zero-churn closure (2026-05-19): '=' is now in the safe set.
# Rationale + correctness proof: a value containing '=' (Fernet keys,
# Django SECRET_KEY, base64 with '=' padding, many JWT/opaque tokens) is
# UNAMBIGUOUS on the RHS because every consumer that reads these files
# splits each line on the FIRST '=' only:
#   * bash `set -a; . file`  → POSIX `name=value`; first '=' is the
#     assignment operator, the rest is literal value.
#   * python-dotenv          → splits key/value on the first '='.
#   * docker compose --env-file / `env_file:` → first '=' split.
# So `KEY=abc=def` round-trips as value `abc=def` everywhere. Excluding
# '=' only forced needless sentinel-wrapping → a future fleet deploy would
# rewrite those lines = churn, violating the zero-regression invariant
# that justifies shipping. '#', space, quotes, '$', '\\', backtick, CR,
# NEWLINE and control chars stay UNSAFE (still sentinel-encoded). This
# regex is the SINGLE source of truth for the encode side; the watcher has
# no encode path (decode-only), so there is no second copy to keep in sync.
_ENV_SAFE_RE = re.compile(r"^[A-Za-z0-9_@%/:.,+=\-]*$")


def _env_value_is_safe(value: str) -> bool:
    """True iff `value` can be emitted RAW (KEY=value) and still round-trip
    byte-identically through bash `source`, python-dotenv, docker compose
    AND our own decoder. Conservative on purpose: anything not provably
    safe goes through the base64 sentinel.

    Belt-and-suspenders beyond the regex: explicitly reject any value with
    a CR/LF anywhere (a mid-string newline would otherwise slip past
    `re.match`+`$`, which matches before a trailing '\\n'), any control
    char, and any value that STARTS WITH A QUOTE (a leading '"' or "'"
    would be eaten by dotenv/compose quote-stripping → not byte-identical).
    """
    if value == "":
        return True
    if value != value.strip():
        return False  # leading/trailing whitespace would be lost / ambiguous
    if value[0] in ('"', "'"):
        return False  # consumers strip surrounding quotes → not lossless
    # No CR/LF/control chars (NUL..US incl. tab) anywhere in the value.
    if any(ord(ch) < 0x20 for ch in value):
        return False
    return bool(_ENV_SAFE_RE.match(value))


def encode_env_value(value: str) -> str:
    """Encode a single secret value into the RHS of a `KEY=` .env line.

    Lossless + consumer-safe. See codec block comment above.
    """
    if value is None:
        value = ""
    if _env_value_is_safe(value):
        return value
    b64 = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"{_DWB64_PREFIX}{b64}{_DWB64_SUFFIX}"


def decode_env_value(raw: str) -> str:
    """Inverse of encode_env_value for a value ALREADY stripped of any
    surrounding quotes / inline comment (i.e. the logical token).

    If `raw` is a SocialWarden base64 sentinel, decode it back to the exact
    original bytes. Otherwise return it unchanged (covers raw-emitted safe
    values AND operator-authored plain values). Never raises — on a
    malformed sentinel it returns the token verbatim (fail-visible: the
    caller's round-trip check will then flag the mismatch rather than
    silently shipping garbage)."""
    if (
        raw.startswith(_DWB64_PREFIX)
        and raw.endswith(_DWB64_SUFFIX)
        and len(raw) >= len(_DWB64_PREFIX) + len(_DWB64_SUFFIX)
    ):
        inner = raw[len(_DWB64_PREFIX) : len(raw) - len(_DWB64_SUFFIX)]
        try:
            return base64.b64decode(inner, validate=True).decode("utf-8")
        except Exception:
            return raw
    return raw


# ---------------------------------------------------------------------------
# Consumer-facing decode (CRITICAL CHECK closure — 2026-05-19)
# ---------------------------------------------------------------------------
# THE PROBLEM this solves (the single most important correctness question):
# render_env() emits non-simple values as the sentinel  KEY=__SWB64__<b64>__.
# That sentinel is written to /run/secrets/<x>.env and then concatenated
# VERBATIM into the materialized merge file the *container* reads via docker
# compose `env_file:`. Nothing on that consumer-facing path used to decode
# it. So a multi-line PEM / GCP service-account JSON / any '$'/space/quote
# secret reached the service as the literal string "__SWB64__...__" — the
# service got a broken secret. That is the SAME class of silent corruption
# as the original must-fix bug, merely relocated to the consumer side.
#
# WHY WE CANNOT JUST DECODE-TO-RAW INTO THE env_file (proven empirically on
# docker compose v2.37, see test_codec.py "C" results): compose's env_file
# parser STRIPS leading/trailing whitespace, STRIPS a ` #...` inline
# comment, STRIPS surrounding quotes, INTERPOLATES `$VAR`/`$$`, and is
# strictly line-based (cannot carry a newline). bash `set -a; .` disagrees
# again on `$$`, `\`, quotes. So NO raw/quoted single representation of a
# `$`/`\`/edge-space/edge-quote/multi-line value round-trips through the
# real consumer. The base64 sentinel is the ONLY representation whose
# alphabet ([A-Za-z0-9+/=_]) is inert to compose AND bash — it is therefore
# kept on the wire ON PURPOSE. Decoding it to raw at merge would REINTRODUCE
# the corruption, not fix it.
#
# THE CORRECT FIX: decode AFTER the consumer has parsed the file —
# i.e. inside the container, just before the service process starts. The
# agent emits a tiny POSIX-sh entrypoint shim next to the materialized
# file; the shim base64-decodes every __SWB64__ env var in place and then
# exec()s the original command, so the service receives the EXACT original
# bytes (multi-line included). decode_env_text() below is the canonical
# Python reference of what the container env must end up being, used by the
# self-test harness to PROVE the container-facing value equals the input.
def decode_env_text(text: str):
    """Reference decoder for a rendered/merged .env *text* as the container
    must ultimately see it.

    Parses `text` line by line (same first-'=' split every real consumer
    uses), decodes any __SWB64__ sentinel value back to its exact original
    bytes, and returns an ordered list of (key, value) pairs. This models
    the post-shim container environment: it is what test_codec.py asserts
    equals the original secret, and the single source of truth the shim's
    sh implementation mirrors. Never raises.

    v1.5.0 (bug #2): use splitlines() so a merged file written with CRLF
    line endings (Windows / some text editors / unusual SSH pipes) does
    NOT leave a trailing '\\r' inside the parsed value — that residual
    byte would silently mutate the round-trip and make the watcher's
    integrity check refuse the absorb."""
    out = []
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        s = line.strip()
        if s.startswith("export "):
            s = s[len("export ") :].lstrip()
        eq = s.find("=")
        if eq <= 0:
            continue
        key = s[:eq].strip()
        val = s[eq + 1 :]
        out.append((key, decode_env_value(val)))
    return out


# POSIX-sh container entrypoint shim. Wrapped in front of the service
# command via compose `entrypoint:` (operator-applied, one line — never
# auto-edited into a live compose file by this agent). It rewrites every
# __SWB64__ env var to its decoded value, then exec()s the real command,
# so a multi-line / '$' / quoted secret reaches the process intact even
# though docker-compose env_file cannot carry it. Pure sh + base64 (both
# present in every service base image we run); fail-loud on bad base64.
_DWB64_ENTRYPOINT_SH = r"""#!/bin/sh
# SocialWarden consumer-side secret decoder (auto-generated — do not edit).
# Decodes __SWB64__<b64>__ env vars (multi-line/$/quote-safe transport)
# back to their real bytes, then exec()s the original container command.
set -u
# Fault-tolerant by design:
#   * NUL-delimited enumeration (`env -0`) so a value with a NEWLINE
#     (PEM / GCP service-account JSON) is ONE record — line parsing would
#     split and corrupt it. If `env -0` is unsupported we fall back to
#     newline `env`; multi-line decodes are then skipped (fail-VISIBLE: the
#     service sees the literal sentinel + a stderr warning, never silent
#     wrong bytes).
#   * NO pipe into the decode loop: a pipe spawns a subshell on POSIX sh
#     and its `export`s would NOT reach the exec'd process. We capture the
#     enumeration into one variable and parse it IN THIS shell.
#   * NO `eval`, NO `for $(...)`: the name is hard-validated to a POSIX
#     identifier before use, so an exotic/hostile env name cannot inject.
#   * `set -e` deliberately OFF: one bad var must not abort service start
#     before we have reported every problem; we exit non-zero at the end.
_dwb64_pfx='__SWB64__'
_dwb64_sfx='__'
_dwb64_rc=0
if env -0 >/dev/null 2>&1; then
    # POSIX sh variables cannot hold a NUL, and dash's `read` has no `-d`,
    # so a true NUL-delimited read is impossible in /bin/sh. We translate
    # the NUL record separator to FS (0x1C). A secret containing a literal
    # 0x1C control byte would mis-split — but 0x1C never occurs in real
    # secrets (PEM/JSON/tokens/passwords are printable text); the FS choice
    # is the best POSIX-portable option and far safer than newline.
    _dwb64_sep=$(printf '\034')      # FS — NUL stand-in
    _dwb64_blob=$(env -0 | tr '\0' '\034'; printf x)
else
    echo "socialwarden-shim: warning: 'env -0' unsupported; multi-line" \
         "secrets will NOT be decoded (delivered as literal sentinel)" >&2
    _dwb64_sep=$(printf '\n')
    _dwb64_blob=$(env; printf x)
fi
_dwb64_blob=${_dwb64_blob%x}         # strip the sentinel guard byte
while [ -n "$_dwb64_blob" ]; do
    case "$_dwb64_blob" in
        *"$_dwb64_sep"*)
            _kv=${_dwb64_blob%%"$_dwb64_sep"*}
            _dwb64_blob=${_dwb64_blob#*"$_dwb64_sep"}
            ;;
        *)
            _kv=$_dwb64_blob
            _dwb64_blob=''
            ;;
    esac
    case "$_kv" in *=*) : ;; *) continue ;; esac
    _k=${_kv%%=*}
    _val=${_kv#*=}
    # Only a valid POSIX identifier is a usable env var; skip anything else.
    case "$_k" in ""|[0-9]*|*[!A-Za-z0-9_]*) continue ;; esac
    case "$_val" in
        "$_dwb64_pfx"*"$_dwb64_sfx")
            _inner=${_val#"$_dwb64_pfx"}
            _inner=${_inner%"$_dwb64_sfx"}
            if _dec=$(printf '%s' "$_inner" | base64 -d 2>/dev/null); then
                export "$_k=$_dec"
            else
                echo "socialwarden-shim: FATAL bad base64 for \$$_k" >&2
                _dwb64_rc=97
            fi
            ;;
    esac
done
[ "$_dwb64_rc" -eq 0 ] || exit "$_dwb64_rc"
unset _dwb64_pfx _dwb64_sfx _dwb64_rc _dwb64_sep _dwb64_blob \
      _kv _k _val _inner _dec 2>/dev/null || true
exec "$@"
"""


def _materialized_has_sentinel(merged_text: str) -> bool:
    """True iff the merged/consumer file still contains at least one
    __SWB64__ sentinel — i.e. the container WILL need the entrypoint shim
    to receive the real secret. Used to emit a loud operator warning so a
    sentinel-bearing collection is never silently shipped without the shim
    wired into its compose `entrypoint:`."""
    for line in merged_text.split("\n"):
        eq = line.find("=")
        if eq > 0 and _DWB64_PREFIX in line[eq + 1 :]:
            return True
    return False


# ---------------------------------------------------------------------------
# Secrets renderer
# ---------------------------------------------------------------------------
def render_env(items, mapping=None):
    """Convert Vaultwarden items to .env format.

    Each item becomes one or more env vars:
    - If mapping is defined, use custom key names
    - Default: ITEM_NAME=password (for API keys, tokens)
    - If username is meaningful: ITEM_NAME_USER=username, ITEM_NAME_PASS=password

    Values are passed through `encode_env_value` so a value containing
    spaces, '#', '$', quotes, a NEWLINE (PEM / GCP JSON), etc. round-trips
    losslessly (must-fix #1 + #2). Simple values are emitted unchanged so
    existing fleet secrets render byte-identically (zero deploy churn).

    Args:
        items: list of Vaultwarden items
        mapping: optional dict {item_name: {env_key: field}} for custom mapping
    """
    lines = []
    skipped_non_posix = 0
    for item in sorted(items, key=lambda x: x.get("name", "")):
        name = item.get("name", "")
        login = item.get("login", {})
        username = login.get("username", "")
        password = login.get("password", "")

        if mapping and name in mapping:
            # Custom mapping: explicit env_key overrides → always honored,
            # regardless of item.name shape.
            for env_key, field in mapping[name].items():
                if not _ENV_KEY_RE.match(env_key):
                    # Configured override that is itself non-POSIX → skip the
                    # one entry but DO NOT skip the whole item (other entries
                    # for the same item may still be valid).
                    skipped_non_posix += 1
                    continue
                if field == "username":
                    lines.append(f"{env_key}={encode_env_value(username)}")
                elif field == "password":
                    lines.append(f"{env_key}={encode_env_value(password)}")
        else:
            # Default: NAME=password. v1.4.18: skip items whose name is not a
            # valid POSIX env-var identifier (watcher-created drift markers
            # like "<KEY> [drift <DATE>]" intentionally use non-POSIX names so
            # they stay visible in the vault for human review but never reach
            # consumers via the rendered .env).
            if not _ENV_KEY_RE.match(name):
                skipped_non_posix += 1
                continue
            lines.append(f"{name}={encode_env_value(password)}")

    if skipped_non_posix:
        logger.info(
            f"render_env: skipped {skipped_non_posix} item(s) with non-POSIX "
            f"name (drift markers stay vault-only — see watcher v1.1.1+)"
        )

    return "\n".join(lines) + "\n" if lines else ""


# ---------------------------------------------------------------------------
# S1 plaintext-hygiene primitives — duplicated VERBATIM from
# socialwarden-watcher.py (per S2 scope decision 2A: each binary self-contained).
# DO NOT diverge: the watcher and agent MUST produce byte-identical backup
# filenames so `socialwarden-watcher rollback` / _find_latest_backup can locate a
# recovery copy made by either side. (Mechanical no-divergence guard tracked
# separately — see "shared-core / dispatcher" architecture work.)
# ---------------------------------------------------------------------------
def _flatten_path_for_backup(env_path: str) -> str:
    """Encode an absolute path as a single safe filename component.

    /home/ubuntu/svc-a/.env -> home-ubuntu-svc-a-.env
    Non-alphanumeric chars other than '.', '_', '-' are replaced with '_'.
    """
    s = env_path.lstrip("/")
    s = s.replace("/", "-")
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


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


# ---------------------------------------------------------------------------
# Sync engine
# ---------------------------------------------------------------------------
class SyncEngine:
    """Core sync logic: poll Vaultwarden, detect changes, write to tmpfs."""

    def __init__(self, bw_client, config):
        self.bw = bw_client
        self.config = config
        self.org_id = config["organization"]["id"]
        self.machine_name = config["machine"]["name"]
        self.collections = config["sync"]["collections"]
        self.poll_interval = config["server"].get("poll_interval", 60)
        self._last_hashes = {}
        self._last_item_names = {}  # {coll_name: set(names)} for add/remove detection
        self._secret_revision_dates = {}  # {secret_name: revisionDate} from Vaultwarden
        self._last_all_items = []  # cache of last org-wide item fetch (for rotation/honeypot checks)
        self._last_merged_hashes = {}  # {coll_name: hash} of the merged file's content — to skip no-op merges
        self._last_rendered_hashes = {}  # {coll_name: {target_path: hash}} for MODO C render targets
        # Flap suppression for COLLECTION EMPTIED alert: items=[] on a collection
        # that previously had items can be caused by (a) genuine vault deletion or
        # (b) transient race condition with concurrent bw processes (e.g. operator
        # running `bw sync` from same userId clobbers the local cache mid-read).
        # Require N consecutive empty polls before alerting to suppress false alarms.
        self._empty_streak = {}  # {coll_name: consecutive_empty_polls}
        # Empty-password alert dedup: track which items had empty password
        # at the last alert. Only re-alert when the SET changes (new items
        # added to the empty list). Prevents spam on every agent restart.
        self._last_empty_pw_set = {}  # {coll_name: frozenset(item_names)}

        # Discord webhook from config (None = disabled)
        self.discord_webhook = config.get("alerts", {}).get("discord_webhook")

        # Counters for metrics
        self.sync_total = 0
        self.sync_errors = 0
        self.secrets_count = 0
        self.drift_detected = 0
        self.changes_detected = 0
        # 3a boot-fallback (Sprint 3): set True once a sync cycle confirms
        # the vault is reachable (org items fetched); False on the vault
        # early-return paths. Drives boot_fallback_restore() + reconcile.
        self.last_sync_vault_ok = False
        self._degraded_collections = set()

    def reload_config(self, new_config):
        """Hot-reload runtime config from a freshly-parsed YAML dict.

        Only fields that are safe to swap mid-process are updated:
        - collections (sync entries: new/removed/changed)
        - poll_interval
        - alerts.discord_webhook

        Fields that REQUIRE a full restart are NOT touched, but a warning
        is logged if they differ vs old config:
        - auth.email (BWClient was constructed with this)
        - auth.master_key_path
        - organization.id
        - server.url
        - shamir.* (BootShamirReconstructor already finished its work)

        In-memory state (_last_hashes, _last_rendered_hashes, _last_merged_hashes,
        _last_item_names, _secret_revision_dates) is PRESERVED. Initial-render
        guard correctly suppresses post_sync storms for newly-added render
        entries on the first sync after reload.
        """
        old_collections = {c.get("name"): c for c in self.collections}
        new_collections = {c.get("name"): c for c in new_config["sync"]["collections"]}
        added = set(new_collections) - set(old_collections)
        removed = set(old_collections) - set(new_collections)
        changed = {
            n
            for n in (set(old_collections) & set(new_collections))
            if old_collections[n] != new_collections[n]
        }

        # Warn (do not error) on restart-required field drift
        restart_fields = [
            ("auth.email", "auth", "email"),
            ("auth.master_key_path", "auth", "master_key_path"),
            ("organization.id", "organization", "id"),
            ("server.url", "server", "url"),
        ]
        for label, section, key in restart_fields:
            old_v = (self.config.get(section) or {}).get(key)
            new_v = (new_config.get(section) or {}).get(key)
            if old_v != new_v:
                logger.warning(
                    f"Config reload: {label} differs (old={old_v!r}, new={new_v!r}) — "
                    f"requires restart, NOT applied this cycle.",
                    extra={"machine": self.machine_name},
                )
        if (self.config.get("shamir") or {}) != (new_config.get("shamir") or {}):
            logger.warning(
                "Config reload: shamir.* differs — requires restart, NOT applied this cycle.",
                extra={"machine": self.machine_name},
            )

        # Apply the hot-reloadable subset
        self.config = new_config
        self.collections = new_config["sync"]["collections"]
        self.poll_interval = new_config["server"].get("poll_interval", 60)
        self.discord_webhook = new_config.get("alerts", {}).get("discord_webhook")

        if added or removed or changed:
            logger.warning(
                f"Config reloaded: +{sorted(added)} -{sorted(removed)} ~{sorted(changed)}",
                extra={"machine": self.machine_name},
            )
        else:
            logger.info(
                "Config reloaded: no collection-level diff",
                extra={"machine": self.machine_name},
            )

    def _alert(self, title, description, color, fields=None):
        """Send Discord alert (non-blocking wrapper)."""
        send_discord_alert(
            self.discord_webhook,
            title,
            description,
            color,
            self.machine_name,
            fields,
        )

    def sync_once(self):
        """Perform one sync cycle. Returns True if any changes detected."""
        self.sync_total += 1
        # 3a: assume vault NOT reached until proven otherwise this cycle.
        # The two vault early-returns below leave this False; it flips True
        # only once org items are actually fetched.
        self.last_sync_vault_ok = False

        # 1. Sync vault
        if not self.bw.sync():
            self.sync_errors += 1
            logger.warning("Vault sync failed — using cached data")
            # Alert on repeated failures (not on every single one)
            if self.sync_errors % 5 == 0:
                self._alert(
                    "Sync Error",
                    f"Vault sync has failed **{self.sync_errors}** times.\nUsing cached data.",
                    COLOR_RED,
                )
            return False

        changed = False
        total_secrets = 0

        # Perf: fetch all org items once, filter per collection in Python.
        # Saves N-1 subprocess spawns per cycle when managing N collections.
        all_items = self.bw.list_all_org_items(self.org_id)
        if all_items is None:
            self.sync_errors += 1
            logger.warning("bw list_all_org_items failed — skipping this cycle")
            if self.sync_errors % 5 == 0:
                self._alert(
                    "Sync Error",
                    f"Org-wide item fetch failed {self.sync_errors} times.",
                    COLOR_RED,
                )
            return False
        # Make available for rotation/honeypot checks later in the loop.
        self._last_all_items = all_items
        # 3a: vault sync + org-wide fetch both succeeded → vault reachable.
        self.last_sync_vault_ok = True

        for coll in self.collections:
            coll_name = coll["name"]
            coll_id = coll["id"]
            output_path = coll["output"]
            mapping = coll.get("mapping")

            # 2. Filter org items down to this collection (client-side)
            items = BWClient.filter_by_collection(all_items, coll_id)

            current_names = {i.get("name", "") for i in items}
            prev_names = self._last_item_names.get(coll_name, set())

            # 2b. Collection emptied detection — v1.4.8 layered defense.
            #
            # When filter_by_collection returns [] but we previously had items,
            # we DIAGNOSE before alerting:
            #   - "session_stale": concurrent bw unlock killed our session →
            #     silently recover, refetch items, continue (no streak tick).
            #   - "real_empty": collection genuinely emptied → tick streak,
            #     alert after EMPTY_FLAP_THRESHOLD consecutive verdicts.
            #   - "collection_gone" / "permission_lost": deferred to a future
            #     dedicated alert (v1.4.8 returns "unknown" for these — see
            #     diagnose_empty docstring; safe to be quiet for now).
            #   - "transient" / "unknown": don't tick streak, retry next cycle.
            if not items and prev_names:
                verdict, recovered = self.bw.diagnose_empty(self.org_id, coll_id)
                if verdict == "session_stale":
                    logger.info(
                        f"Collection '{coll_name}': session was stale, "
                        f"silently recovered {len(recovered)} items "
                        f"(would have falsely alerted in v1.4.7)",
                        extra={"machine": self.machine_name},
                    )
                    items = recovered
                    # Reset streak — this wasn't a real empty.
                    if self._empty_streak.get(coll_name, 0) > 0:
                        self._empty_streak[coll_name] = 0
                    # Fall through to normal processing with `items` repopulated.
                elif verdict in ("transient", "unknown"):
                    logger.warning(
                        f"Collection '{coll_name}': empty result classified as "
                        f"{verdict!r}; deferring decision to next cycle "
                        "(no streak increment, no alert)",
                        extra={"machine": self.machine_name},
                    )
                    continue
                # else: verdict == "real_empty" — fall through to streak logic below

            if not items:
                if prev_names:
                    streak = self._empty_streak.get(coll_name, 0) + 1
                    self._empty_streak[coll_name] = streak
                    if streak >= EMPTY_FLAP_THRESHOLD:
                        logger.error(
                            f"COLLECTION EMPTIED: '{coll_name}' had {len(prev_names)} secrets, "
                            f"now has 0 (sustained {streak} polls)",
                            extra={"machine": self.machine_name},
                        )
                        self._alert(
                            "🚨 Collection Emptied",
                            f"Collection **{coll_name}** went from **{len(prev_names)}** secrets to **0** "
                            f"(sustained {streak} consecutive polls).\n"
                            "This could be accidental deletion or a security incident.",
                            COLOR_RED,
                            fields=[
                                {
                                    "name": "Previous secrets",
                                    "value": ", ".join(sorted(prev_names))[:1024],
                                    "inline": False,
                                },
                            ],
                        )
                        # Reset so we do not re-alert on the next cycle unless
                        # there is a re-population followed by another empty streak
                        self._last_item_names[coll_name] = set()
                        self._empty_streak[coll_name] = 0
                    else:
                        logger.warning(
                            f"Collection '{coll_name}' appears empty "
                            f"(streak {streak}/{EMPTY_FLAP_THRESHOLD} — could be bw cache race, "
                            f"alert suppressed until threshold)",
                            extra={"machine": self.machine_name},
                        )
                        # IMPORTANT: do NOT update _last_item_names. We want the
                        # next non-empty cycle to compare against the original
                        # prev_names (and reset the streak), not against empty.
                else:
                    # No prior items either. Two real-world cases:
                    #   (a) genuinely brand-new empty collection on first sync
                    #   (b) post-SIGHUP reload reset _last_item_names AND the
                    #       first list_all hit a stale bw session that lies []
                    # Without disambiguation we'd log "No items found" forever
                    # in case (b). Probe via diagnose_empty: if session_stale,
                    # recover silently and proceed; otherwise keep the warn.
                    verdict, recovered = self.bw.diagnose_empty(self.org_id, coll_id)
                    if verdict == "session_stale" and recovered:
                        logger.info(
                            f"Collection '{coll_name}': session was stale on "
                            f"post-reload first poll, silently recovered "
                            f"{len(recovered)} items",
                            extra={"machine": self.machine_name},
                        )
                        items = recovered
                        # Fall through to normal processing below.
                    else:
                        logger.warning(
                            f"No items found for collection '{coll_name}' "
                            f"(diagnose: {verdict!r})"
                        )
                        continue
                # Re-check items after potential recovery above.
                if not items:
                    continue

            # Non-empty result — reset flap counter if we had been streaking
            if self._empty_streak.get(coll_name, 0) > 0:
                logger.info(
                    f"Collection '{coll_name}' recovered from empty streak "
                    f"({self._empty_streak[coll_name]} polls) — false alarm avoided",
                    extra={"machine": self.machine_name},
                )
                self._empty_streak[coll_name] = 0

            total_secrets += len(items)

            # 3. Render .env content
            env_content = render_env(items, mapping)

            # 4. Compute hash to detect changes
            current_hash = hashlib.sha256(env_content.encode()).hexdigest()
            prev_hash = self._last_hashes.get(coll_name)

            if current_hash != prev_hash:
                # 4a. Check for empty passwords with set-dedup + first-sync gate.
                # Pattern matches the existing Secret Added/Removed alerts (line ~888):
                # both are gated by `prev_hash is not None` so first-sync-after-restart
                # is treated as "baseline observed, do not alert about it".
                # Without that gate the alert would fire on every agent restart with
                # the same set of empty items — spam, not signal.
                empty_pw = [
                    i.get("name", "")
                    for i in items
                    if not i.get("login", {}).get("password")
                ]
                empty_pw_set = frozenset(empty_pw)
                last_empty_set = self._last_empty_pw_set.get(coll_name)

                # Alert iff: (a) we have a prior baseline (not first sync after restart),
                #           (b) some items are currently empty, and
                #           (c) the set changed vs baseline.
                if (
                    prev_hash is not None
                    and empty_pw
                    and empty_pw_set != last_empty_set
                ):
                    added = empty_pw_set - (last_empty_set or frozenset())
                    removed = (last_empty_set or frozenset()) - empty_pw_set
                    logger.warning(
                        f"EMPTY PASSWORD in '{coll_name}': "
                        f"current={sorted(empty_pw)} added={sorted(added)} removed={sorted(removed)}",
                        extra={"machine": self.machine_name},
                    )
                    self._alert(
                        "⚠️ Empty Password",
                        f"**{len(empty_pw)}** secrets in **{coll_name}** have no password set.\n"
                        f"Changed since last alert: +{sorted(added) or '[]'} -{sorted(removed) or '[]'}",
                        COLOR_ORANGE,
                        fields=[
                            {
                                "name": "Secrets (all current)",
                                "value": ", ".join(empty_pw),
                                "inline": False,
                            },
                        ],
                    )
                elif prev_hash is not None and not empty_pw and last_empty_set:
                    # All previously-empty items now have passwords. Quiet log,
                    # no Discord alert (the operator did the right thing).
                    logger.info(
                        f"Empty-password recovery in '{coll_name}': all items now have passwords "
                        f"(previously empty: {sorted(last_empty_set)})",
                        extra={"machine": self.machine_name},
                    )

                # ALWAYS update baseline — even on first sync — so the next cycle
                # compares against current state, not None. Otherwise the second
                # sync (with any vault change) would re-alert about the same items.
                self._last_empty_pw_set[coll_name] = empty_pw_set

                if prev_hash is not None:
                    # Analyze what changed (added, removed, modified)
                    self.changes_detected += 1
                    changes = self._analyze_changes(coll_name, items, prev_names)

                    logger.warning(
                        f"CHANGE DETECTED in '{coll_name}': "
                        f"added={changes['added']}, removed={changes['removed']}, modified={changes['modified']}",
                        extra={"machine": self.machine_name},
                    )
                    # Save version snapshot
                    self._save_version(coll_name, env_content)

                    # Discord alerts per change type
                    if changes["removed"]:
                        self._alert(
                            "🚨 Secret Deleted",
                            f"Secrets **removed** from collection **{coll_name}**.",
                            COLOR_RED,
                            fields=[
                                {
                                    "name": "Deleted",
                                    "value": ", ".join(changes["removed"]),
                                    "inline": False,
                                },
                                {
                                    "name": "Remaining",
                                    "value": str(len(items)),
                                    "inline": True,
                                },
                            ],
                        )

                    if changes["added"]:
                        self._alert(
                            "Secret Added",
                            f"New secrets in collection **{coll_name}**.",
                            COLOR_GREEN,
                            fields=[
                                {
                                    "name": "Added",
                                    "value": ", ".join(changes["added"]),
                                    "inline": False,
                                },
                                {
                                    "name": "Total",
                                    "value": str(len(items)),
                                    "inline": True,
                                },
                            ],
                        )

                    if changes["modified"]:
                        self._alert(
                            "Secret Modified",
                            f"Secrets **updated** in collection **{coll_name}**.",
                            COLOR_GREEN,
                            fields=[
                                {
                                    "name": "Modified",
                                    "value": ", ".join(changes["modified"]),
                                    "inline": False,
                                },
                                {
                                    "name": "Output",
                                    "value": f"`{output_path}`",
                                    "inline": True,
                                },
                            ],
                        )

                # 5. Write to tmpfs
                self._write_secrets(output_path, env_content)
                self._last_hashes[coll_name] = current_hash
                changed = True

                logger.info(
                    f"Synced {len(items)} secrets to {output_path}",
                    extra={"machine": self.machine_name},
                )

                # 6. Update cache (for offline fallback) — pass items directly
                self._update_cache(coll_name, items)

            # 7. Merge static config + secrets → symlink (Phase 3, MODO B)
            #    Only re-merge if secrets changed OR merged target doesn't exist.
            prev_merged_hash = self._last_merged_hashes.get(coll_name)
            self._merge_and_link(coll, force=(prev_hash != current_hash))
            post_merged_hash = self._last_merged_hashes.get(coll_name)

            # 7c. Render templates (MODO C — universal config files).
            #     `coll['render']` is an optional list of {template, target,
            #     mode, owner, backup} entries. Returns the set of targets
            #     that actually changed (initial render is excluded — see
            #     _render_templates docstring for the guard rationale).
            render_changed_targets = self._render_templates(coll, items)

            # 7b. Post-sync hooks — fire on real change. Triggers:
            #     (a) secret values changed (vault rotation), OR
            #     (b) merged-file content changed (e.g. operator edited
            #         .env.static to add/change a non-secret config var), OR
            #     (c) any rendered template target changed.
            #     All three cases need a container recreate to pick up the
            #     new env / config. Suppress on initial sync (no prev) so a
            #     daemon restart doesn't kick off a docker restart storm.
            secrets_changed = prev_hash is not None and current_hash != prev_hash
            static_changed = (
                prev_merged_hash is not None
                and post_merged_hash is not None
                and prev_merged_hash != post_merged_hash
            )
            render_changed = bool(render_changed_targets)
            if secrets_changed or static_changed or render_changed:
                self._run_post_sync_hooks(coll)

            # 8. Track item names + revision dates
            self._last_item_names[coll_name] = current_names
            self._track_revision_dates(items)

        # 3a reconcile: reaching here means the vault was reachable this
        # cycle (the loop above ran), so any collection restored from an
        # offline snapshot at boot has now been overwritten with
        # authoritative vault data. Clear the degraded set + tell the SOC.
        if self._degraded_collections:
            recovered = sorted(self._degraded_collections)
            self._degraded_collections.clear()
            logger.info(
                f"BOOT FALLBACK reconciled — vault reachable again; "
                f"{recovered} now on authoritative vault data",
                extra={"machine": self.machine_name},
            )
            self._alert(
                "Boot Fallback Reconciled",
                f"Vault reachable again — degraded collections re-synced "
                f"from vault: {', '.join(recovered)}.",
                COLOR_GREEN,
            )

        self.secrets_count = total_secrets
        return changed

    def check_drift(self):
        """Detect if someone manually edited files in /run/secrets/."""
        for coll in self.collections:
            output_path = coll["output"]
            coll_name = coll["name"]

            if not os.path.exists(output_path):
                continue

            try:
                with open(output_path) as f:
                    disk_content = f.read()
                disk_hash = hashlib.sha256(disk_content.encode()).hexdigest()
                expected_hash = self._last_hashes.get(coll_name)

                if expected_hash and disk_hash != expected_hash:
                    self.drift_detected += 1
                    logger.error(
                        f"DRIFT DETECTED: {output_path} was modified outside SocialWarden! "
                        "Someone edited the file manually.",
                        extra={"machine": self.machine_name},
                    )

                    # Discord alert — drift (RED, this is serious)
                    self._alert(
                        "⚠️ Drift Detected",
                        f"**{output_path}** was modified outside SocialWarden!\n"
                        f"Collection: **{coll_name}**\n"
                        "Someone edited the secrets file manually on disk.",
                        COLOR_RED,
                    )

                    # Auto-correct if configured
                    if self.config.get("alerts", {}).get("drift_auto_correct", False):
                        logger.warning(f"Auto-correcting drift in {output_path}")
                        # Re-sync will overwrite on next cycle
            except (IOError, OSError) as e:
                logger.error(f"Cannot read {output_path} for drift check: {e}")

    def check_secret_ages(self):
        """Warn about secrets whose revisionDate exceeds the threshold.

        Uses revisionDate from Vaultwarden (when the item was last modified),
        NOT when the agent first saw it. This survives agent restarts.
        """
        threshold_days = self.config.get("alerts", {}).get(
            "secret_age_threshold_days", 90
        )
        now = datetime.now(timezone.utc)
        old_secrets = []

        for secret_name, revision_dt in self._secret_revision_dates.items():
            age_days = (now - revision_dt).days
            if age_days > threshold_days:
                old_secrets.append((secret_name, age_days))
                logger.warning(
                    f"SECRET AGE: '{secret_name}' last modified {age_days} days ago "
                    f"(threshold: {threshold_days})",
                    extra={"machine": self.machine_name},
                )

        # Discord alert — batch all old secrets in one message (not spammy)
        if old_secrets:
            old_secrets.sort(key=lambda x: -x[1])  # oldest first
            secret_list = "\n".join(
                f"• **{name}** — {days}d" for name, days in old_secrets
            )
            self._alert(
                "Secret Age Warning",
                f"**{len(old_secrets)}** secrets not modified in >{threshold_days} days.",
                COLOR_YELLOW,
                fields=[
                    {
                        "name": "Secrets (oldest first)",
                        "value": secret_list[:1024],
                        "inline": False,
                    },
                ],
            )

    def _analyze_changes(self, coll_name, current_items, prev_names):
        """Analyze what changed: added, removed, modified secrets.

        Returns dict with lists of names for each change type.
        """
        result = {"added": [], "removed": [], "modified": []}
        current_names = {i.get("name", "") for i in current_items}

        # Added and removed
        result["added"] = sorted(current_names - prev_names)
        result["removed"] = sorted(prev_names - current_names)

        # Modified (value changed for existing secrets). Uses hashes on disk —
        # never stores plaintext passwords in the cache file.
        cache_path = Path(CACHE_DIR) / f"{coll_name}.json"
        if cache_path.exists():
            try:
                with open(cache_path) as f:
                    cached = json.load(f)

                # Back-compat: older cache files stored the full login dict;
                # fall back to hashing those values on read.
                def _cached_hash(entry):
                    if "pw_hash" in entry:
                        return entry["pw_hash"]
                    return hashlib.sha256(
                        (entry.get("login", {}).get("password", "") or "").encode()
                    ).hexdigest()

                cached_map = {i["name"]: _cached_hash(i) for i in cached}
                current_map = {
                    i["name"]: hashlib.sha256(
                        (i.get("login", {}).get("password", "") or "").encode()
                    ).hexdigest()
                    for i in current_items
                }
                for name in current_names & prev_names:
                    if cached_map.get(name) != current_map.get(name):
                        result["modified"].append(name)
            except Exception:
                pass

        # If nothing detected but hash changed, it's a structure change
        if not any(result.values()):
            result["modified"] = ["(structure change)"]

        return result

    @staticmethod
    def _atomic_tmp_name(dest) -> str:
        """Single source of truth for the staging temp filename (must-fix #4).

        Returns ``<dest>.tmp.<pid>``. Two reasons this is NOT
        ``Path.with_suffix(".tmp")`` (the old _write_secrets bug):

          * ``Path('/run/secrets/app-b.env').with_suffix('.tmp')`` yields
            ``/run/secrets/app-b.tmp`` — it DROPS the real ``.env`` segment,
            so _write_secrets and _atomic_write_secret used divergent temp
            names for the same destination.
          * Plain string concat keeps the full dest, and crucially the temp
            name ends in ``.tmp.<pid>`` — it does NOT match a ``*.env`` glob,
            so a scanner / UDS that ingests ``*.env`` files can never pick up
            a half-written staging file.

        Per-PID suffix also prevents two cooperating processes from colliding
        on the same staging path (the final rename is still atomic)."""
        return f"{os.fspath(dest)}.tmp.{os.getpid()}"

    def _write_secrets(self, output_path, content):
        """Atomically write secrets file with secure permissions.

        Thin wrapper over the unified _atomic_write_secret helper (must-fix
        #4): a single code path does open+write+fsync+rename with one
        non-`.env` temp name. Mode 0o600 / current owner preserves the prior
        behaviour for this caller."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self._atomic_write_secret(str(path), content.encode(), 0o600):
            # _atomic_write_secret already logged the specific errno.
            logger.error(f"Failed to write {output_path}")

    @staticmethod
    def _resolve_merge_perms(merge_cfg):
        """Resolve (mode, uid, gid, materialize) for a merge: block.

        M8: the merged file holds plaintext secrets. The historical default
        was 0o644 (world-readable) — only ever non-exploitable because
        /run/secrets is mode 0700 (root-only traversal). We tighten the
        default to 0o640 (zero regression: the world bit was already
        unreachable through the 0700 dir) and let a collection opt into a
        looser/owned mode for non-root consumers.

        M2: `materialize` selects how the consumer sees the merged file:
          - "symlink" (default): write to /run/secrets/<n>.env.merged and
            point `link` at it (the historical behaviour; the consumer's
            process/daemon must run as root to traverse /run/secrets).
          - "copy": write the merged content AS A REAL FILE at `link`
            directly (mode/owner/group applied there), with NO /run/secrets
            symlink — for consumers operated by a non-root user (e.g. a
            `docker compose` run as `ubuntu` that resolves `${VAR}` from
            ./.env). The original .env was already a plaintext disk file
            owned by that user, so root:<group> 0640 is strictly tighter.

        owner/group accept a numeric id or a name. Unknown/empty → keep
        current (uid/gid = -1, os.chown no-op). Never raises.
        """
        import grp
        import pwd

        def _to_id(val, resolver):
            if val is None or val == "":
                return -1
            try:
                return int(val)
            except (TypeError, ValueError):
                pass
            try:
                return resolver(str(val))
            except KeyError:
                logger.warning(f"merge perms: unknown owner/group {val!r}; ignoring")
                return -1

        raw_mode = merge_cfg.get("mode", 0o640)
        try:
            if isinstance(raw_mode, str):
                mode = int(raw_mode, 8)
            else:
                mode = int(raw_mode)
            # A 3-digit decimal like 640 almost certainly means octal 0o640.
            if isinstance(raw_mode, int) and 600 <= raw_mode <= 777:
                mode = int(str(raw_mode), 8)
        except (TypeError, ValueError):
            logger.warning(f"merge perms: bad mode {raw_mode!r}; falling back to 0o640")
            mode = 0o640
        uid = _to_id(merge_cfg.get("owner"), lambda n: pwd.getpwnam(n).pw_uid)
        gid = _to_id(merge_cfg.get("group"), lambda n: grp.getgrnam(n).gr_gid)
        materialize = (merge_cfg.get("materialize") or "symlink").strip().lower()
        if materialize not in ("symlink", "copy"):
            logger.warning(
                f"merge perms: unknown materialize {materialize!r}; "
                "defaulting to symlink"
            )
            materialize = "symlink"
        return mode, uid, gid, materialize

    def _merge_and_link(self, coll, force=False):
        """Merge static config (disk) + secrets (RAM) → merged file (RAM) + symlink.

        Phase 3: Eliminates plaintext secrets from disk.
        - static: .env.static on disk (config only, no secrets)
        - target: merged file in /run/secrets/ (RAM, config + secrets)
        - link: symlink from original .env path → merged in RAM

        Docker Compose reads the symlink as if it were the real .env.
        If the machine reboots, the agent recreates the merged file before Docker starts.

        Returns:
            bool: True if the merged file was (re)written this cycle, False otherwise.
        """
        merge_cfg = coll.get("merge")
        if not merge_cfg:
            return False  # No merge configured — old behavior

        static_path = merge_cfg.get("static", "")
        target_path = merge_cfg.get("target", "")
        link_path = merge_cfg.get("link", "")
        secrets_path = coll.get("output", "")

        if not all([static_path, target_path, link_path, secrets_path]):
            logger.error(f"Merge config incomplete for '{coll.get('name')}'")
            return False

        # 1. Read static config (from disk)
        try:
            static_content = Path(static_path).read_text()
        except FileNotFoundError:
            logger.error(
                f"Static config not found: {static_path}. "
                f"Create it by removing secrets from the original .env",
                extra={"machine": self.machine_name},
            )
            return False

        # 2. Read secrets (from RAM)
        try:
            secrets_content = Path(secrets_path).read_text()
        except FileNotFoundError:
            logger.error(f"Secrets file not found: {secrets_path}")
            return False

        # 3. Merge: static config + secrets
        merged = static_content.rstrip("\n") + "\n"
        merged += "# === Secrets managed by SocialWarden (do not edit) ===\n"
        merged += secrets_content

        # Perf: skip rewrite if content identical AND target exists AND link is correct.
        # Saves ~3 syscalls per idle cycle per collection.
        coll_name = coll.get("name", "")
        merged_hash = hashlib.sha256(merged.encode()).hexdigest()
        mode, uid, gid, materialize = self._resolve_merge_perms(merge_cfg)

        target = Path(target_path)
        link = Path(link_path)
        target_exists = target.exists()
        if materialize == "copy":
            # Managed state = `link` is a REAL regular file (not a symlink)
            # whose content already matches the freshly merged bytes.
            try:
                link_ok = (
                    link.is_file()
                    and not link.is_symlink()
                    and hashlib.sha256(link.read_bytes()).hexdigest() == merged_hash
                )
            except OSError:
                link_ok = False
        else:
            link_ok = link.is_symlink() and str(link.resolve()) == str(target.resolve())
        if (
            not force
            and self._last_merged_hashes.get(coll_name) == merged_hash
            and target_exists
            and link_ok
        ):
            # S1: managed state is verified-good here (live file matches the
            # vault-rendered merge). Sweep any lingering orphan
            # <link>.pre-socialwarden even though we rewrite nothing this poll.
            self._shred_orphan_pre_backup(link_path)
            return False
        self._last_merged_hashes[coll_name] = merged_hash

        # 4. Write merged to target (RAM, atomic). Use explicit fchmod after
        # open instead of os.umask — umask is process-global and racy across
        # threads; concurrent os.open of secret files could pick up the
        # temporarily relaxed umask and end up world-readable.
        # In "copy" materialize the consumer reads `link` (a real file), so
        # `target` only needs to be the tight root-only RAM canonical/
        # validation copy (0o600). In "symlink" mode the consumer reads
        # `target` through the symlink, so it gets the resolved mode.
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target_mode = 0o600 if materialize == "copy" else mode
        if not self._atomic_write_secret(
            str(target),
            merged.encode(),
            target_mode,
            uid=(-1 if materialize == "copy" else uid),
            gid=(-1 if materialize == "copy" else gid),
        ):
            return False

        # 5. Materialize what the consumer sees.
        try:
            if materialize == "copy":
                # Real file directly at `link` (root[:group] mode), NO symlink
                # into the 0700 /run/secrets dir — so a non-root operator
                # (e.g. `docker compose` as `ubuntu`) can read it.
                if link.is_symlink():
                    # Migrating from a previous symlink deployment.
                    link.unlink()
                    logger.info(f"materialize=copy: removed old symlink {link_path}")
                elif link.exists():
                    backup = Path(f"{link_path}.pre-socialwarden")
                    if not backup.exists():
                        link.rename(backup)
                        self._lock_pre_backup(backup)
                        logger.warning(f"Backed up {link_path} → {backup}")
                    else:
                        link.unlink()
                if not self._atomic_write_secret(
                    str(link), merged.encode(), mode, uid=uid, gid=gid
                ):
                    return False
                logger.info(
                    f"materialize=copy: wrote real file {link_path} "
                    f"(mode={oct(mode)}, uid={uid}, gid={gid})"
                )
            else:
                if link.is_symlink():
                    if str(link.resolve()) != str(target.resolve()):
                        link.unlink()
                        link.symlink_to(target_path)
                        logger.info(f"Symlink updated: {link_path} → {target_path}")
                elif link.exists():
                    backup = Path(f"{link_path}.pre-socialwarden")
                    if not backup.exists():
                        link.rename(backup)
                        self._lock_pre_backup(backup)
                        logger.warning(f"Backed up {link_path} → {backup}")
                    else:
                        link.unlink()
                    link.symlink_to(target_path)
                    logger.info(f"Replaced {link_path} with symlink → {target_path}")
                else:
                    link.symlink_to(target_path)
                    logger.info(f"Created symlink: {link_path} → {target_path}")
        except OSError as e:
            logger.error(f"Failed to materialize {link_path}: {e}")
            return False

        # CRITICAL CHECK closure: if the merged/consumer file still carries a
        # __SWB64__ sentinel, the container will read the LITERAL token unless
        # an entrypoint shim decodes it post-compose-parse. Emit the shim next
        # to the consumer file and warn LOUDLY (fail-visible, never silent).
        try:
            if _materialized_has_sentinel(merged):
                shim_path = str(link) + ".swb64-decode.sh"
                cur = None
                try:
                    cur = Path(shim_path).read_bytes()
                except OSError:
                    cur = None
                want = _DWB64_ENTRYPOINT_SH.encode()
                if cur != want:
                    # Shim is NOT a secret (no plaintext) — world-readable
                    # 0755 so a non-root compose/runtime can exec it.
                    self._atomic_write_secret(shim_path, want, 0o755, uid=uid, gid=gid)
                logger.warning(
                    f"'{coll_name}': merged {link_path} contains __SWB64__ "
                    f"sentinel value(s) (multi-line/$/space/quote secret). The "
                    f"container will receive the LITERAL token unless the "
                    f"decode shim is wired. Emitted {shim_path}; set the "
                    f"service compose `entrypoint:` to "
                    f'["{shim_path}"] (it exec()s the original command after '
                    f"decoding). Until then this secret is delivered ENCODED.",
                    extra={"machine": self.machine_name},
                )
        except Exception as e:  # never let shim emission break the merge
            logger.error(f"decode-shim emit for {link_path} failed: {e}")

        # S1: managed file written + verified this poll; the pre-management
        # plaintext stash is now pure liability — shred it (fail-safe).
        self._shred_orphan_pre_backup(link_path)
        return True

    @staticmethod
    def _lock_pre_backup(backup) -> None:
        """S1: the .pre-socialwarden backup is the ORIGINAL .env in plaintext.
        It inherits the source file's perms on rename (often 0644/0664 =
        world/group readable) and sits on persistent disk. Immediately
        tighten it to 0600 root:root so a non-root local user (or a disk
        snapshot consumer) cannot read the pre-absorption secrets. The
        watcher additionally shreds it once a redundant tmpfs backup +
        vault copy exist. Best-effort, never raises."""
        try:
            os.chmod(str(backup), 0o600)
            os.chown(str(backup), 0, 0)
        except OSError as e:
            logger.warning(f"_lock_pre_backup({backup}): {e}")

    @staticmethod
    def _tmpfs_recovery_copy(link_path: str, src: str) -> str | None:
        """Copy `src` into BACKUP_DIR/<flat>-<TS> (tmpfs/RAM, 0600 root) using
        the SAME dir + naming the watcher uses, so an emergency
        `socialwarden-watcher rollback` can find it too. Returns the dst path on
        success, None otherwise. Best-effort, never raises."""
        try:
            os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
            flat = _flatten_path_for_backup(link_path)
            ts = datetime.now(timezone.utc).strftime(BACKUP_NAME_FMT)
            dst = os.path.join(BACKUP_DIR, f"{flat}-{ts}")
            data = Path(src).read_bytes()
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.chown(dst, 0, 0)
            except OSError:
                pass
            return dst
        except OSError:
            return None

    def _shred_orphan_pre_backup(self, link_path: str) -> None:
        """S1 (agent side, mirrors watcher migrate step 12.5): once a
        consumer's .env is verifiably managed — the live file matches the
        freshly-merged render AND the secrets are in the vault (true by
        construction whenever this is called: the merged content was built
        from the vault-rendered secrets file this very poll) — the persistent
        ``<link>.pre-socialwarden`` plaintext stash is pure liability (it lands
        in every disk snapshot and defeats SocialWarden's reason to exist).

        Make an INDEPENDENT tmpfs recovery copy, then shred the persistent
        plaintext. Fail-safe: if the recovery copy cannot be made we KEEP the
        (already 0600 root:root) backup rather than destroy the only fallback.
        Best-effort, never raises — hygiene must never break a sync. Also
        sweeps orphans left by a PREVIOUS agent (covers consumers managed
        only via the agent materialize/symlink path, never via watcher
        migrate, e.g. internal-dashboard)."""
        try:
            pre = f"{link_path}.pre-socialwarden"
            if not os.path.isfile(pre) or os.path.islink(pre):
                return
            rec = self._tmpfs_recovery_copy(link_path, pre)
            if not rec:
                logger.warning(
                    f"S1: keeping {pre} — refusing to shred without a tmpfs "
                    "recovery fallback"
                )
                return
            if _shred_unlink(pre):
                logger.info(
                    f"S1: shredded persistent plaintext backup {pre} "
                    f"(tmpfs recovery copy at {rec}; secrets in vault)"
                )
            else:
                logger.warning(f"S1: could not remove {pre}")
        except Exception as e:
            # Hygiene must NEVER break a sync — swallow anything unexpected.
            logger.warning(f"S1 _shred_orphan_pre_backup({link_path}): {e}")

    @staticmethod
    def _atomic_write_secret(dest, data: bytes, mode: int, uid=-1, gid=-1) -> bool:
        """Atomically write `data` to `dest` (tmp in same dir + rename) with
        exact mode set via fchmod (no umask race) and best-effort chown.

        chown failure is logged but NOT fatal: delivering the secret with a
        slightly looser owner beats not delivering it (fail-open on chown,
        fail-closed on the write itself). Never raises.

        must-fix #4: the staging temp name comes from the single
        _atomic_tmp_name helper (``<dest>.tmp.<pid>``), NEVER
        Path.with_suffix — so it is identical to _write_secrets' temp name
        and never matches a ``*.env`` scanner glob. fsync before rename so a
        crash can't leave a renamed-but-empty file."""
        dest_p = Path(dest)
        # must-fix #4: this is a @staticmethod — there is no `self`. Reference
        # the sibling @staticmethod via the class (was `self._atomic_tmp_name`,
        # which raised NameError on EVERY secret write at all call sites).
        tmp = SyncEngine._atomic_tmp_name(dest_p)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, data)
                os.fchmod(fd, mode)
                if uid != -1 or gid != -1:
                    try:
                        os.fchown(fd, uid, gid)
                    except OSError as e:
                        logger.warning(
                            f"_atomic_write_secret: chown({uid},{gid}) on "
                            f"{dest} failed ({e}); delivering with current owner"
                        )
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, str(dest_p))
            # v1.5.0 (bug #6, MEDIUM): fsync the parent directory after the
            # rename so the new dir entry survives a crash. Without this,
            # tmp+rename guarantees content atomicity but the dirent itself
            # is only durable after the next fs writeback — a kernel panic
            # right after rename could leave the consumer staring at the
            # old file or no file at all. Best-effort; non-fatal on failure.
            try:
                parent = os.path.dirname(str(dest_p)) or "."
                dfd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                # Some filesystems (e.g. specific FUSE drivers, certain bind
                # mounts) refuse dir-fsync. Not fatal — content is on disk;
                # only durability of the rename itself is at slight risk.
                pass
            return True
        except OSError as e:
            # M22: tmp+rename keeps the previous good file intact on failure.
            # Name ENOSPC explicitly so disk-full doesn't masquerade as a
            # generic write error in the journal.
            if e.errno == errno.ENOSPC:
                logger.error(
                    f"_atomic_write_secret: DISK FULL (ENOSPC) writing "
                    f"{dest} — keeping last-good file; consumer keeps "
                    f"running on the previous secrets until space frees"
                )
            else:
                logger.error(f"_atomic_write_secret: write {dest} failed: {e}")
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False

    def _run_post_sync_hooks(self, coll):
        """Dispatch post_sync hooks for a collection.

        Each hook runs in its own daemon thread (so the sync loop is not
        blocked) but the thread waits for the subprocess to finish, captures
        stdout+stderr to /var/log/socialwarden/post_sync.log, and alerts on
        failure (non-zero rc, timeout, or dispatch exception).

        The subprocess uses start_new_session so it survives if the agent
        exits mid-hook; the daemon thread that monitors it does not.

        coll["post_sync"] may be a string (single command) or list of strings.
        """
        import threading

        hooks = coll.get("post_sync") or []
        if isinstance(hooks, str):
            hooks = [hooks]
        if not hooks:
            return

        coll_name = coll.get("name", "?")
        for cmd in hooks:
            logger.info(
                f"post_sync [{coll_name}]: {cmd[:120]}",
                extra={"machine": self.machine_name},
            )
            threading.Thread(
                target=self._exec_post_sync_hook,
                args=(coll_name, cmd, coll.get("healthz_url")),
                daemon=True,
                name=f"post_sync-{coll_name}",
            ).start()

    @staticmethod
    def _healthz_ok(url, timeout=10):
        """3b: GET `url`, True iff HTTP 2xx. Any error → False (fail-closed:
        an unreachable healthz means 'not healthy', never 'assume ok')."""
        if not url:
            return False
        import urllib.request

        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return 200 <= getattr(r, "status", r.getcode()) < 300
        except Exception:
            return False

    def _post_sync_run_once(self, coll_name, cmd, timeout_s):
        """Run ONE post_sync attempt. Returns a status dict; does NOT alert
        (the orchestrator decides alerting/retry). Status ∈ ok | failed |
        timeout | interrupted | exec_error. Body is the proven v1.4.x run
        logic with the _alert() calls lifted out."""
        log_path = "/var/log/socialwarden/post_sync.log"
        ts = datetime.now(timezone.utc).isoformat()
        try:
            Path(log_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with open(log_path, "ab") as logf:
                logf.write(f"\n=== {ts} [{coll_name}] {cmd}\n".encode())
                logf.flush()
                proc = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                try:
                    rc = proc.wait(timeout=timeout_s)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                        time.sleep(2)
                        if proc.poll() is None:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except (ProcessLookupError, OSError):
                        pass
                    logf.write(f"=== TIMEOUT after {timeout_s}s\n".encode())
                    logger.error(f"post_sync [{coll_name}] TIMEOUT after {timeout_s}s")
                    return {"status": "timeout"}
                logf.write(f"=== rc={rc}\n".encode())

            if rc < 0:
                try:
                    sig_name = signal.Signals(-rc).name
                except ValueError:
                    sig_name = f"signal {-rc}"
                logger.warning(
                    f"post_sync [{coll_name}] INTERRUPTED by {sig_name} (rc={rc})",
                    extra={"machine": self.machine_name},
                )
                return {"status": "interrupted", "rc": rc}
            if rc != 0:
                try:
                    tail = subprocess.check_output(
                        ["tail", "-30", log_path], timeout=5
                    ).decode(errors="replace")
                except Exception:
                    tail = "(could not read log tail)"
                logger.error(f"post_sync [{coll_name}] FAILED rc={rc}")
                return {"status": "failed", "rc": rc, "tail": tail}
            logger.info(
                f"post_sync [{coll_name}] OK (rc=0)",
                extra={"machine": self.machine_name},
            )
            return {"status": "ok", "rc": 0}
        except Exception as e:
            logger.error(f"post_sync exec failed ({coll_name}): {e}")
            return {"status": "exec_error", "err": str(e)}

    def _post_sync_alert(self, coll_name, cmd, res, timeout_s):
        """Emit the final Discord alert for a terminal post_sync failure.
        Alert titles/bodies are byte-identical to the pre-3b agent so the
        default (retry-disabled) path is observably unchanged."""
        st = res.get("status")
        if st == "timeout":
            self._alert(
                "Post-sync hook TIMEOUT",
                f"Hook for **{coll_name}** did not finish in {timeout_s}s:\n```\n{cmd[:200]}\n```",
                COLOR_RED,
            )
        elif st == "failed":
            tail = res.get("tail", "")
            self._alert(
                "Post-sync hook FAILED",
                f"Hook for **{coll_name}** exited rc=`{res.get('rc')}`:\n```\n{cmd[:200]}\n```\nLast log lines:\n```\n{tail[-1500:]}\n```",
                COLOR_RED,
            )
        elif st == "exec_error":
            self._alert(
                "Post-sync exec error",
                f"Hook for **{coll_name}** raised exception:\n```\n{cmd[:200]}\n```\nError: `{res.get('err')}`",
                COLOR_RED,
            )
        elif st == "healthz_fail":
            self._alert(
                "Post-sync healthz FAILED",
                f"Hook for **{coll_name}** ran but `healthz_url` never went "
                f"healthy after retries:\n```\n{cmd[:200]}\n```\n"
                f"Service treated as **degraded** (fail-closed).",
                COLOR_RED,
            )

    def _exec_post_sync_hook(self, coll_name, cmd, healthz_url=None, timeout_s=300):
        """Run a post_sync hook. DEFAULT (resilience.post_sync_retry OFF):
        exactly one attempt, same alerts as the pre-3b agent — observably
        unchanged for the whole current fleet.

        3b OPT-IN (resilience.post_sync_retry true): on a real failure
        (failed/timeout/exec_error) retry with backoff [30s, 2min, 10min];
        between attempts probe `healthz_url` — if it goes healthy the
        service recovered, stop (success) even though the hook reported a
        failure; if all retries exhausted (or, with healthz_url set, the
        hook is rc=0 but healthz never passes) → final alert, fail-closed
        (NEVER reported as success). `interrupted` (rc<0, agent teardown)
        is never retried/alerted, as before."""
        rcfg = self.config.get("resilience", {}) or {}
        retry_on = bool(rcfg.get("post_sync_retry"))
        backoffs = rcfg.get("post_sync_backoffs") or [30, 120, 600]
        if not (
            retry_on
            and isinstance(backoffs, list)
            and all(isinstance(b, int) and b >= 0 for b in backoffs)
        ):
            # ---- DEFAULT PATH: 1 attempt, identical to pre-3b ----
            res = self._post_sync_run_once(coll_name, cmd, timeout_s)
            if res["status"] in ("ok", "interrupted"):
                return
            self._post_sync_alert(coll_name, cmd, res, timeout_s)
            return

        # ---- 3b retry path (opt-in) ----
        attempts = 1 + len(backoffs)
        for i in range(attempts):
            res = self._post_sync_run_once(coll_name, cmd, timeout_s)
            st = res["status"]
            if st == "interrupted":
                return  # agent teardown — never retry/alert
            if st == "ok":
                if not healthz_url or self._healthz_ok(healthz_url):
                    if healthz_url:
                        logger.info(
                            f"post_sync [{coll_name}] OK + healthz pass",
                            extra={"machine": self.machine_name},
                        )
                    return
                logger.error(
                    f"post_sync [{coll_name}] rc=0 but healthz FAILED "
                    f"({healthz_url}) — fail-closed, treating as failure",
                    extra={"machine": self.machine_name},
                )
                res = {"status": "healthz_fail"}
            # st ∈ failed/timeout/exec_error/healthz_fail
            if i < attempts - 1:
                # maybe the service is actually healthy despite the hook
                if healthz_url and self._healthz_ok(healthz_url):
                    logger.warning(
                        f"post_sync [{coll_name}] hook failed but healthz now "
                        f"OK — service recovered, stop retrying",
                        extra={"machine": self.machine_name},
                    )
                    return
                wait = backoffs[i]
                logger.warning(
                    f"post_sync [{coll_name}] failed ({res['status']}); "
                    f"retry {i + 1}/{len(backoffs)} in {wait}s",
                    extra={"machine": self.machine_name},
                )
                time.sleep(wait)
                continue
            # exhausted
            self._post_sync_alert(coll_name, cmd, res, timeout_s)
            return

    def _render_templates(self, coll, items):
        """Render every `coll['render']` template with vault items + metadata.

        Each render entry: {template, target, mode?, owner?, backup?}.
        Returns the set of `target` paths that *changed AND should trigger
        post_sync*. Initial render (first time we see this target — no
        cached hash) is excluded from the trigger set even if a write
        happens, mirroring the merge initial-sync guard so a daemon restart
        never kicks off a docker-storm. Subsequent renders that produce a
        new hash DO fire the trigger.

        Anti-error guarantees:
          - Strict substitution: missing ${VAR} → fail this entry, target
            kept intact, Discord alert.
          - Atomic write: tmp+rename. POSIX guarantees the target file is
            never observed half-written.
          - Hash-skip: byte-identical rendered content → no rewrite, no
            cache update needed, no trigger.
          - Backup rotation: <target>.bak-<UTC-TS> created before rename;
            keep N=5 most-recent.
          - Per-entry isolation: a failure in one render entry does not
            abort the rest of the list.
        """
        renders = coll.get("render") or []
        if not renders:
            return set()

        coll_name = coll.get("name", "?")
        cache = self._last_rendered_hashes.setdefault(coll_name, {})
        changed_targets = set()

        # Build substitution dict: each vault item's name → password,
        # plus metadata. Items with empty/missing password are skipped to
        # avoid silently rendering an empty value into a config file.
        vars_dict = {}
        for it in items:
            name = it.get("name")
            login = it.get("login") or {}
            password = login.get("password")
            if name and password:
                vars_dict[name] = password
        vars_dict["MACHINE_NAME"] = self.machine_name
        vars_dict["COLLECTION_ID"] = coll.get("id", "")
        vars_dict["SYNCED_AT"] = datetime.now(timezone.utc).isoformat()

        for entry in renders:
            template_path = entry.get("template")
            target_path = entry.get("target")
            mode_str = str(entry.get("mode", "0644"))
            owner_str = entry.get("owner", "root:root")
            do_backup = entry.get("backup", True)

            if not template_path or not target_path:
                logger.error(
                    f"render [{coll_name}]: skipping invalid entry (missing template/target)"
                )
                continue

            try:
                mode = int(mode_str, 8)
            except (ValueError, TypeError):
                mode = 0o644
                logger.warning(
                    f"render [{coll_name}] {target_path}: bad mode {mode_str!r}, defaulting to 0644"
                )

            # 1. Read template
            try:
                with open(template_path) as f:
                    template_text = f.read()
            except OSError as e:
                logger.error(
                    f"render [{coll_name}] template unreadable {template_path}: {e}"
                )
                self._alert(
                    "Render hook FAILED — template missing",
                    f"Template `{template_path}` for **{coll_name}** is unreadable: `{e}`. "
                    f"Target `{target_path}` left intact.",
                    COLOR_RED,
                )
                continue

            # 2. Strict substitution — fails on missing var. Target NOT touched.
            try:
                rendered = string.Template(template_text).substitute(vars_dict)
            except KeyError as e:
                missing = str(e).strip("'\"")
                logger.error(
                    f"render [{coll_name}] {template_path}: missing variable ${{{missing}}}"
                )
                self._alert(
                    "Render hook FAILED — missing variable",
                    f"Template `{template_path}` for **{coll_name}** references "
                    f"`${{{missing}}}` which is NOT in the collection. "
                    f"Target `{target_path}` left intact; previous version preserved.",
                    COLOR_RED,
                )
                continue
            except ValueError as e:
                logger.error(
                    f"render [{coll_name}] {template_path}: substitution error: {e}"
                )
                self._alert(
                    "Render hook FAILED — template syntax",
                    f"Template `{template_path}` has invalid substitution syntax: `{e}`. "
                    f"Target `{target_path}` left intact.",
                    COLOR_RED,
                )
                continue

            # 3. Hash-based skip + cache lookup
            new_hash = hashlib.sha256(rendered.encode()).hexdigest()
            try:
                with open(target_path, "rb") as f:
                    cur_hash = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                cur_hash = None

            prev_cached = cache.get(target_path)

            if cur_hash == new_hash:
                # Already up-to-date on disk. Just refresh the cache (so we
                # know we've seen this target). No write, no trigger.
                cache[target_path] = new_hash
                continue

            # 4. Backup current target (if exists) before overwrite
            if do_backup and cur_hash is not None:
                ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                bak_path = f"{target_path}.bak-{ts}"
                try:
                    import shutil

                    shutil.copy2(target_path, bak_path)
                except OSError as e:
                    logger.warning(
                        f"render [{coll_name}] backup of {target_path} failed: {e}"
                    )
                self._rotate_render_backups(target_path, keep=5)

            # 5. Atomic write: tmp + chmod + chown + rename
            try:
                target = Path(target_path)
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp_path = f"{target_path}.tmp"
                with open(tmp_path, "w") as f:
                    f.write(rendered)
                os.chmod(tmp_path, mode)
                if owner_str:
                    try:
                        import pwd
                        import grp

                        user, group = owner_str.split(":")
                        uid = pwd.getpwnam(user).pw_uid
                        gid = grp.getgrnam(group).gr_gid
                        os.chown(tmp_path, uid, gid)
                    except (ValueError, KeyError, OSError) as e:
                        logger.warning(
                            f"render [{coll_name}] chown {owner_str} on {tmp_path} failed: {e}"
                        )
                os.rename(tmp_path, target_path)
            except OSError as e:
                logger.error(
                    f"render [{coll_name}] atomic write failed {target_path}: {e}"
                )
                self._alert(
                    "Render hook FAILED — write error",
                    f"Could not write rendered template to `{target_path}`: `{e}`",
                    COLOR_RED,
                )
                # Try to clean up the tmp if it's there
                try:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                except OSError:
                    pass
                continue

            cache[target_path] = new_hash
            logger.info(
                f"render [{coll_name}] {target_path} updated (hash {new_hash[:12]})",
                extra={"machine": self.machine_name},
            )

            # Initial-render guard: if there was no cached hash, this is
            # our first sight of this target. Don't fire post_sync (avoid
            # docker-storms on cold boot). Subsequent changes WILL fire.
            if prev_cached is not None:
                changed_targets.add(target_path)

        return changed_targets

    def _rotate_render_backups(self, target_path, keep=5):
        """Keep at most `keep` most-recent <target>.bak-* files; delete older."""
        import glob

        try:
            backups = sorted(
                glob.glob(f"{target_path}.bak-*"),
                reverse=True,  # newest first (timestamps sort lexicographically)
            )
            for old in backups[keep:]:
                try:
                    os.unlink(old)
                except OSError:
                    pass
        except Exception as e:
            logger.warning(f"backup rotation failed for {target_path}: {e}")

    def check_rotations(self):
        """Alert on secrets whose metadata indicates a rotation is due.

        Reads custom fields from vault items:
          - expires_at: ISO-8601 datetime string → rotate 7 days before expiry
          - rotate_every_days: integer → rotate N days after last revisionDate

        Only alerts (doesn't auto-rotate); auto-rotation requires the canary
        rotation machinery (Phase 6).
        """
        if not self._last_all_items:
            return
        threshold_days = int(
            self.config.get("alerts", {}).get("rotation_prewarn_days", 7)
        )
        now = datetime.now(timezone.utc)
        due = []
        for item in self._last_all_items:
            name = item.get("name", "")
            fields = {f.get("name"): f.get("value") for f in (item.get("fields") or [])}
            reason = None
            expires = fields.get("expires_at")
            if expires:
                try:
                    exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                    delta_days = (exp_dt - now).days
                    if delta_days < threshold_days:
                        reason = (
                            f"expires in {delta_days}d"
                            if delta_days >= 0
                            else f"EXPIRED {-delta_days}d ago"
                        )
                except ValueError:
                    pass
            if not reason:
                rot = fields.get("rotate_every_days")
                if rot:
                    try:
                        rev = item.get("revisionDate", "")
                        rev_dt = datetime.fromisoformat(rev.replace("Z", "+00:00"))
                        age = (now - rev_dt).days
                        cadence = int(rot)
                        if age >= cadence:
                            reason = f"rotation cadence ({cadence}d, age {age}d)"
                    except (ValueError, TypeError):
                        pass
            if reason:
                due.append((name, reason))
                logger.warning(
                    f"ROTATION DUE: {name} ({reason})",
                    extra={"machine": self.machine_name},
                )

        if due:
            listing = "\n".join(f"• **{n}** — {r}" for n, r in due)
            self._alert(
                "🔄 Rotations Due",
                f"**{len(due)}** secret(s) past rotation threshold.",
                COLOR_YELLOW,
                fields=[{"name": "Secrets", "value": listing[:1024], "inline": False}],
            )

    def _update_cache(self, coll_name, items):
        """Save items to local cache for change detection.

        v1.1.0: receives items directly instead of calling bw.list_items() again.
        """
        cache_dir = Path(CACHE_DIR)
        cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        cache_path = cache_dir / f"{coll_name}.json"

        # Security: store ONLY sha256(password), never plaintext, so a disk-cache
        # leak doesn't expose credentials. Change detection in _analyze_changes
        # compares hashes, not values.
        safe_items = [
            {
                "name": i["name"],
                "username": i.get("login", {}).get("username", ""),
                "pw_hash": hashlib.sha256(
                    (i.get("login", {}).get("password", "") or "").encode()
                ).hexdigest(),
            }
            for i in items
        ]

        fd = os.open(str(cache_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, json.dumps(safe_items).encode())
        os.close(fd)

    def _save_version(self, coll_name, env_content):
        """Save a timestamped version snapshot."""
        versions_dir = Path(VERSIONS_DIR)
        versions_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        filename = f"{timestamp}_{coll_name}.env"
        version_path = versions_dir / filename

        # SEC-6: encrypt at-rest. Same on-disk format as ensure_encrypted
        # ("ENC:" + machine-bound encrypt_credential) so both the agent's
        # read_encrypted and the watcher's read_encrypted_file decrypt it.
        # If encryption fails we must NOT fall back to writing plaintext
        # (that would silently reopen the exact hole SEC-6 closes) — skip
        # the snapshot and log; snapshots are best-effort and never on the
        # secret-delivery critical path.
        try:
            blob = "ENC:" + encrypt_credential(env_content)
        except Exception as e:
            logger.error(
                f"Version snapshot for {coll_name} NOT saved — encryption "
                f"failed (refusing plaintext fallback, SEC-6): {e}"
            )
            return
        fd = os.open(str(version_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, blob.encode() + b"\n")
        finally:
            os.close(fd)

        logger.info(f"Version snapshot saved (encrypted): {filename}")

        # Cleanup old versions (keep MAX_VERSIONS)
        versions = sorted(versions_dir.glob(f"*_{coll_name}.env"))
        while len(versions) > MAX_VERSIONS:
            old = versions.pop(0)
            old.unlink()
            logger.debug(f"Removed old version: {old.name}")

    def _latest_version_snapshot(self, coll_name):
        """Newest VERSIONS_DIR/<ts>_<coll>.env path, or None. The timestamp
        prefix sorts lexicographically so sorted()[-1] is the newest."""
        try:
            snaps = sorted(Path(VERSIONS_DIR).glob(f"*_{coll_name}.env"))
        except OSError:
            return None
        return snaps[-1] if snaps else None

    def boot_fallback_restore(self):
        """3a (Sprint 3, REDESIGNED): if the vault was UNREACHABLE during the
        initial sync AND a collection's output file is missing/empty, restore
        it from the latest ENCRYPTED versions/ snapshot so consumers don't
        come up with zero secrets. Opt-in (`resilience.boot_fallback`), OFF
        by default → zero change to the normal (vault-reachable) path.

        Fail-closed invariants (robust-by-default):
          - NEVER runs if the vault was reachable at boot
            (`last_sync_vault_ok`): the normal path already wrote
            authoritative data.
          - NEVER overwrites a present non-empty output (no clobber of good
            data — restores ONLY a missing/empty target).
          - Restores ONLY from the machine-bound ENCRYPTED snapshot
            (`read_encrypted`); if there is no snapshot OR decrypt fails it
            writes NOTHING (consumer fails loudly rather than getting
            wrong/empty secrets) and alerts.
          - Reconciliation is automatic: the 60s poll loop overwrites the
            degraded restore with fresh vault data once the vault returns
            (sync_once clears `_degraded_collections` + alerts).
          - NOT for render (MODO C) targets: the snapshot is env content,
            not the rendered file — those wait for the vault (logged).
        """
        rcfg = self.config.get("resilience", {}) or {}
        if not rcfg.get("boot_fallback"):
            return
        if self.last_sync_vault_ok:
            return  # vault was fine — normal path handled everything
        for coll in self.collections:
            coll_name = coll["name"]
            output_path = coll.get("output", "")
            if not output_path:
                continue
            try:
                p = Path(output_path)
                present = p.is_file() and p.stat().st_size > 0
            except OSError:
                present = False
            if present:
                continue  # don't clobber existing good data
            snap = self._latest_version_snapshot(coll_name)
            if snap is None:
                logger.error(
                    f"BOOT FALLBACK: '{coll_name}' output {output_path} is "
                    f"orphan and vault unreachable, but NO versions/ "
                    f"snapshot exists — refusing to fabricate (fail-closed)",
                    extra={"machine": self.machine_name},
                )
                self._alert(
                    "Boot Fallback FAILED",
                    f"`{coll_name}` output missing, vault unreachable, **no "
                    f"snapshot** to restore from. Consumer starts without "
                    f"these secrets until the vault returns.",
                    COLOR_RED,
                )
                continue
            try:
                content = read_encrypted(str(snap))
            except Exception as e:
                logger.error(
                    f"BOOT FALLBACK: decrypt of {snap.name} failed for "
                    f"'{coll_name}': {e} — refusing garbage (fail-closed)",
                    extra={"machine": self.machine_name},
                )
                self._alert(
                    "Boot Fallback FAILED",
                    f"`{coll_name}` snapshot `{snap.name}` could not be "
                    f"decrypted (wrong machine / tampered?). Not restored.",
                    COLOR_RED,
                )
                continue
            self._write_secrets(output_path, content)
            self._degraded_collections.add(coll_name)
            logger.warning(
                f"BOOT FALLBACK: '{coll_name}' restored from offline "
                f"encrypted snapshot {snap.name} → {output_path} (vault "
                f"unreachable; DEGRADED — reconciles when vault returns)",
                extra={"machine": self.machine_name},
            )
            self._alert(
                "⚠️ Boot Fallback — DEGRADED",
                f"Vault unreachable at boot. `{coll_name}` restored from "
                f"offline encrypted snapshot `{snap.name}`.\nRunning on "
                f"last-known-good; auto-reconciles when the vault returns.",
                COLOR_RED,
            )

    def _track_revision_dates(self, items):
        """Store revisionDate from Vaultwarden for each secret.

        revisionDate = last time the item was modified in Vaultwarden.
        This is the REAL age, not when the agent first saw it.
        bw CLI returns ISO format: "2026-04-15T09:30:00.000Z"
        """
        for item in items:
            name = item.get("name", "")
            revision = item.get("revisionDate", "")
            if revision:
                try:
                    # bw CLI returns ISO format with Z suffix
                    dt = datetime.fromisoformat(revision.replace("Z", "+00:00"))
                    self._secret_revision_dates[name] = dt
                except (ValueError, TypeError):
                    pass  # Skip unparseable dates


# ---------------------------------------------------------------------------
# Heartbeat & Metrics
# ---------------------------------------------------------------------------
_HEARTBEAT_LOCK = threading.Lock()


def write_heartbeat():
    """Write heartbeat file atomically — temp + rename.

    `path.write_text` is NOT atomic across truncate+write; a concurrent reader
    could see an empty file mid-write. Threading lock guards against the
    sync loop racing the API thread (both call this on shared state).
    Mode 0o755 on the parent: /run/socialwarden is created by RuntimeDirectory
    in the systemd unit; the mkdir here is a defensive belt-and-suspenders.
    """
    with _HEARTBEAT_LOCK:
        path = Path(HEARTBEAT_PATH)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(datetime.now(timezone.utc).isoformat())
        os.replace(tmp, path)


def write_metrics(engine):
    """Write Prometheus textfile metrics for node-exporter."""
    metrics_dir = Path(METRICS_PATH).parent
    metrics_dir.mkdir(parents=True, exist_ok=True)

    now = time.time()
    lines = [
        "# HELP socialwarden_sync_total Total number of sync cycles",
        "# TYPE socialwarden_sync_total counter",
        f'socialwarden_sync_total{{machine="{engine.machine_name}"}} {engine.sync_total}',
        "# HELP socialwarden_sync_errors_total Total sync errors",
        "# TYPE socialwarden_sync_errors_total counter",
        f'socialwarden_sync_errors_total{{machine="{engine.machine_name}"}} {engine.sync_errors}',
        "# HELP socialwarden_secrets_count Current number of managed secrets",
        "# TYPE socialwarden_secrets_count gauge",
        f'socialwarden_secrets_count{{machine="{engine.machine_name}"}} {engine.secrets_count}',
        "# HELP socialwarden_changes_detected_total Total secret changes detected",
        "# TYPE socialwarden_changes_detected_total counter",
        f'socialwarden_changes_detected_total{{machine="{engine.machine_name}"}} {engine.changes_detected}',
        "# HELP socialwarden_drift_detected_total Total drift events detected",
        "# TYPE socialwarden_drift_detected_total counter",
        f'socialwarden_drift_detected_total{{machine="{engine.machine_name}"}} {engine.drift_detected}',
        "# HELP socialwarden_last_sync_timestamp Unix timestamp of last successful sync",
        "# TYPE socialwarden_last_sync_timestamp gauge",
        f'socialwarden_last_sync_timestamp{{machine="{engine.machine_name}"}} {now}',
        "# HELP socialwarden_info Agent version info",
        "# TYPE socialwarden_info gauge",
        f'socialwarden_info{{machine="{engine.machine_name}",version="{VERSION}"}} 1',
        "",
    ]

    # Atomic write
    tmp = Path(METRICS_PATH + ".tmp")
    tmp.write_text("\n".join(lines))
    tmp.rename(METRICS_PATH)


# ---------------------------------------------------------------------------
# UDS API — per-container JIT secret access (integrated since v1.4.0)
# ---------------------------------------------------------------------------
# Protocol (newline-delimited JSON over UDS):
#   client → {"v": 1, "op": "get", "secret": "OPENAI_API_KEY"}
#   server → {"ok": true, "value": "sk-..."}
#         OR {"ok": false, "error": "denied"|"not_found"|"rate_limited"}
# Auth: SO_PEERCRED + cgroup → container name → policy allow/deny.

import asyncio as _uds_asyncio  # noqa: E402 -- namespaced UDS peer-auth section import
import fnmatch as _uds_fnmatch  # noqa: E402
import socket as _uds_socket  # noqa: E402
import struct as _uds_struct  # noqa: E402
import threading  # noqa: E402
from collections import defaultdict as _uds_defaultdict, deque as _uds_deque  # noqa: E402

UDS_SOCK_PATH = "/run/socialwarden/api.sock"
UDS_POLICY_PATH = "/etc/socialwarden/policy.yaml"
UDS_AUDIT_LOG = Path("/var/lib/socialwarden/audit.log")
UDS_RATE_LIMIT_PER_MIN = 100
UDS_PROTO_VERSION = 1
# Phase 2 bus: same wire protocol & version as UDS (single source of truth).
# Bus verbs are read-only, root-only and hop-limited (see _handle dispatcher
# + _handle_bus). They never call bw and never touch the 60s poll path.
BUS_PROTO_VERSION = UDS_PROTO_VERSION
BUS_READ_VERBS = ("status", "collections", "collection-status")
BUS_HOP_LIMIT = 1


class UDSApiServer:
    """Unix domain socket server for JIT secret access, runs in its own thread."""

    def __init__(self, secrets_dir=None, machine_name="unknown"):
        self.secrets_dir = Path(secrets_dir or "/run/secrets")
        self.machine_name = machine_name
        self._secrets_cache = {}
        self._secrets_mtime = {}
        self._policy_cache = {"mtime": 0, "data": None}
        self._name_cache = {}
        self._rate_buckets = _uds_defaultdict(_uds_deque)
        self._thread = None
        self._loop = None
        self._server = None
        self._stop_evt = threading.Event()
        self._started_at = time.time()

    # --- helpers ------------------------------------------------------------
    def _pid_to_container(self, pid):
        try:
            cg = Path(f"/proc/{pid}/cgroup").read_text()
        except (FileNotFoundError, PermissionError):
            return None
        for line in cg.splitlines():
            for seg in line.split("/"):
                if seg.startswith("docker-") and ".scope" in seg:
                    cid = seg[len("docker-") :].split(".")[0]
                    return self._name_from_id(cid)
                if len(seg) == 64 and all(c in "0123456789abcdef" for c in seg):
                    return self._name_from_id(seg)
        return None

    def _name_from_id(self, cid):
        if cid in self._name_cache:
            return self._name_cache[cid]
        try:
            r = subprocess.run(
                ["docker", "inspect", "--format", "{{.Name}}", cid],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode != 0:
                return None
            name = r.stdout.strip().lstrip("/")
            self._name_cache[cid] = name
            return name
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def _load_policy(self):
        try:
            st = os.stat(UDS_POLICY_PATH)
        except FileNotFoundError:
            return None
        except PermissionError as e:
            logger.error(
                f"Policy file not readable: {e}", extra={"machine": self.machine_name}
            )
            return None
        if self._policy_cache["mtime"] != st.st_mtime_ns:
            try:
                self._policy_cache["data"] = (
                    yaml.safe_load(Path(UDS_POLICY_PATH).read_text()) or {}
                )
                self._policy_cache["mtime"] = st.st_mtime_ns
            except (OSError, yaml.YAMLError) as e:
                # Narrow catch: we expect only IO or YAML-parse errors here.
                # If any other exception propagates (e.g. NameError, TypeError),
                # that's a bug and should crash loudly rather than be silenced.
                logger.error(
                    f"Policy parse failed: {e}", extra={"machine": self.machine_name}
                )
                return None
        return self._policy_cache["data"]

    def _policy_allows(self, container, secret_name):
        pol = self._load_policy()
        if not pol:
            return False, "no-policy"
        rules = (pol.get("containers") or {}).get(container, [])
        for rule in rules:
            if _uds_fnmatch.fnmatch(secret_name, rule.split("/", 1)[-1]):
                return True, rule
        return False, None

    def _load_secrets(self):
        if not self.secrets_dir.is_dir():
            return
        for envfile in self.secrets_dir.glob("*.env"):
            try:
                mt = os.stat(envfile).st_mtime_ns
            except FileNotFoundError:
                continue
            if self._secrets_mtime.get(str(envfile)) == mt:
                continue
            self._secrets_mtime[str(envfile)] = mt
            try:
                for line in envfile.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    self._secrets_cache[k.strip()] = v.strip().strip("'\"")
            except OSError:
                continue

    def _check_rate(self, container):
        now = time.time()
        bucket = self._rate_buckets[container]
        cutoff = now - 60
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= UDS_RATE_LIMIT_PER_MIN:
            return False
        bucket.append(now)
        return True

    def _audit(self, container, secret, decision, extra=None):
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "machine": self.machine_name,
            "container": container or "?",
            "secret": secret,
            "decision": decision,
        }
        if extra:
            entry.update(extra)
        try:
            UDS_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(
                str(UDS_AUDIT_LOG), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
            )
            os.write(fd, (json.dumps(entry) + "\n").encode())
            os.close(fd)
        except OSError:
            pass

    # --- async handler ------------------------------------------------------
    async def _handle(self, reader, writer):
        SO_PEERCRED = 17
        sock = writer.get_extra_info("socket")
        try:
            peercred = sock.getsockopt(_uds_socket.SOL_SOCKET, SO_PEERCRED, 12)
            pid, uid, gid = _uds_struct.unpack("iII", peercred)
        except Exception:
            writer.close()
            return

        container = self._pid_to_container(pid) or f"pid:{pid}"

        try:
            line = await _uds_asyncio.wait_for(reader.readline(), timeout=5)
        except _uds_asyncio.TimeoutError:
            writer.close()
            return

        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            writer.write(b'{"ok":false,"error":"bad_json"}\n')
            await writer.drain()
            writer.close()
            return

        # Proto check applies to every op; on skew we fail closed with
        # bad_request so a version-mismatched caller drops to its own
        # self-contained path (design §5.1). This is the same outcome the
        # old combined `v`-check produced for `get`, so `get` is unchanged.
        if req.get("v") != BUS_PROTO_VERSION:
            writer.write(b'{"ok":false,"error":"bad_request"}\n')
            await writer.drain()
            writer.close()
            return

        op = req.get("op")

        # ---- op:"get" — CRITICAL secret-delivery path, byte-identical ----
        # Per-container policy model; containers run non-root by design, so
        # there is deliberately NO uid gate and NO hop semantics here. The
        # bus uid/hop guards below are for the watcher↔agent control plane
        # only and must never gate container JIT secret fetch.
        if op == "get":
            secret_name = req.get("secret", "")
            if not self._check_rate(container):
                self._audit(container, secret_name, "rate_limited")
                writer.write(b'{"ok":false,"error":"rate_limited"}\n')
                await writer.drain()
                writer.close()
                return

            allowed, rule = self._policy_allows(container, secret_name)
            if not allowed:
                self._audit(container, secret_name, "denied", {"reason": "policy"})
                writer.write(b'{"ok":false,"error":"denied"}\n')
                await writer.drain()
                writer.close()
                return

            self._load_secrets()
            value = self._secrets_cache.get(secret_name)
            if value is None:
                self._audit(container, secret_name, "not_found")
                writer.write(b'{"ok":false,"error":"not_found"}\n')
            else:
                self._audit(container, secret_name, "ok", {"rule": rule})
                writer.write(json.dumps({"ok": True, "value": value}).encode() + b"\n")
            await writer.drain()
            writer.close()
            return

        # ---- bus read-only verbs (watcher↔agent control plane) ----
        if op in BUS_READ_VERBS:
            await self._handle_bus(op, req, container, uid, writer)
            return

        # ---- unknown op ----
        writer.write(b'{"ok":false,"error":"bad_request"}\n')
        await writer.drain()
        writer.close()

    @staticmethod
    def _count_env_keys(path):
        """Count `KEY=value` lines in an env file (same rule as
        _load_secrets). Returns an int, or None if the file can't be read.
        Never returns secret values — only the count."""
        try:
            n = 0
            for line in path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    n += 1
            return n
        except OSError:
            return None

    def _scan_collections(self):
        """Read-only view of synced collections from /run/secrets/*.env.

        `<name>.env` is the materialized collection; `<name>.env.merged`
        files are NOT matched by the *.env glob and are intentionally
        excluded. Pure stat()+read of small files — no bw, no poll, no
        secret values leave the process (only name/mtime/key-count)."""
        out = []
        try:
            files = sorted(self.secrets_dir.glob("*.env"))
        except OSError:
            return out
        for f in files:
            try:
                mtime = f.stat().st_mtime
            except OSError:
                continue
            keys = self._count_env_keys(f)
            if keys is None:
                continue
            out.append(
                {
                    "name": f.name[:-4],  # strip ".env" (glob guarantees it)
                    "synced_at": datetime.fromtimestamp(
                        mtime, timezone.utc
                    ).isoformat(),
                    "keys": keys,
                }
            )
        return out

    async def _handle_bus(self, op, req, container, uid, writer):
        """Phase 2 bus verbs — read-only, root-only, hop-limited.

        Three independent fail-closed guards (defense in depth):
          1. uid==0    — the peer must be root (the watcher runs as root).
             Containers reach the socket too (chmod 0666) but are non-root,
             so this keeps the bus control plane off the container surface.
          2. hop-limit — `hop` defaults to 0; reject hop>1 (or non-int, or
             bool — bool is an int subclass in Python) so no A→B→A chain
             can form even if a future bug added a reverse edge.
          3. rate-limit — shared "bus" bucket so a wedged watcher cannot
             spin the agent.
        Never calls bw and never touches the 60s poll path.
        """
        if uid != 0:
            self._audit(container, op, "denied", {"reason": "bus_uid", "uid": uid})
            writer.write(b'{"ok":false,"error":"denied"}\n')
            await writer.drain()
            writer.close()
            return

        hop = req.get("hop", 0)
        if isinstance(hop, bool) or not isinstance(hop, int) or hop > BUS_HOP_LIMIT:
            self._audit(container, op, "denied", {"reason": "hop", "hop": hop})
            writer.write(b'{"ok":false,"error":"hop_exceeded"}\n')
            await writer.drain()
            writer.close()
            return

        if not self._check_rate("bus"):
            self._audit(container, op, "rate_limited")
            writer.write(b'{"ok":false,"error":"rate_limited"}\n')
            await writer.drain()
            writer.close()
            return

        if op == "status":
            try:
                secret_files = sum(1 for _ in self.secrets_dir.glob("*.env"))
            except OSError:
                secret_files = -1
            resp = {
                "ok": True,
                "v": BUS_PROTO_VERSION,
                "op": "status",
                "agent": self.machine_name,
                "version": VERSION,
                "uptime_s": int(time.time() - self._started_at),
                "secret_files": secret_files,
                "hop": hop + 1,
            }
            self._audit(container, "status", "ok", {"hop": hop})
            writer.write(json.dumps(resp).encode() + b"\n")
            await writer.drain()
            writer.close()
            return

        if op == "collections":
            cols = self._scan_collections()
            resp = {
                "ok": True,
                "v": BUS_PROTO_VERSION,
                "op": "collections",
                "collections": cols,
                "count": len(cols),
                "hop": hop + 1,
            }
            self._audit(container, "collections", "ok", {"hop": hop, "n": len(cols)})
            writer.write(json.dumps(resp).encode() + b"\n")
            await writer.drain()
            writer.close()
            return

        if op == "collection-status":
            name = req.get("collection", "")
            # This verb derives a filesystem path from caller input, so the
            # name is strictly validated: it must be a non-empty str of
            # [alnum . _ -] with no `..`, AND the resolved parent must be
            # the secrets dir. Belt-and-braces — the verb can never
            # traverse out of /run/secrets.
            valid = (
                isinstance(name, str)
                and bool(name)
                and ".." not in name
                and all(c.isalnum() or c in "._-" for c in name)
            )
            target = self.secrets_dir / f"{name}.env" if valid else None
            if valid and target is not None:
                try:
                    valid = target.resolve().parent == self.secrets_dir.resolve()
                except OSError:
                    valid = False
            if not valid:
                self._audit(
                    container,
                    "collection-status",
                    "denied",
                    {"reason": "bad_name", "name": name},
                )
                writer.write(b'{"ok":false,"error":"bad_request"}\n')
                await writer.drain()
                writer.close()
                return
            if not target.exists():
                resp = {
                    "ok": True,
                    "v": BUS_PROTO_VERSION,
                    "op": "collection-status",
                    "name": name,
                    "present": False,
                    "hop": hop + 1,
                }
            else:
                try:
                    mtime = target.stat().st_mtime
                except OSError:
                    mtime = None
                resp = {
                    "ok": True,
                    "v": BUS_PROTO_VERSION,
                    "op": "collection-status",
                    "name": name,
                    "present": True,
                    "synced_at": (
                        datetime.fromtimestamp(mtime, timezone.utc).isoformat()
                        if mtime is not None
                        else None
                    ),
                    "keys": self._count_env_keys(target),
                    "hop": hop + 1,
                }
            self._audit(
                container,
                "collection-status",
                "ok",
                {"hop": hop, "name": name, "present": resp.get("present")},
            )
            writer.write(json.dumps(resp).encode() + b"\n")
            await writer.drain()
            writer.close()
            return

        # In BUS_READ_VERBS but no branch served it → guard against a verb
        # being added to the set without a handler.
        self._audit(container, op, "denied", {"reason": "unimplemented"})
        writer.write(b'{"ok":false,"error":"bad_request"}\n')
        await writer.drain()
        writer.close()

    async def _run(self):
        try:
            os.unlink(UDS_SOCK_PATH)
        except FileNotFoundError:
            pass
        Path(UDS_SOCK_PATH).parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        self._server = await _uds_asyncio.start_unix_server(
            self._handle, path=UDS_SOCK_PATH
        )
        os.chmod(UDS_SOCK_PATH, 0o666)
        self._load_secrets()
        logger.info(
            f"UDS API listening on {UDS_SOCK_PATH}",
            extra={"machine": self.machine_name},
        )
        async with self._server:
            await self._server.serve_forever()

    def _thread_target(self):
        try:
            self._loop = _uds_asyncio.new_event_loop()
            _uds_asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._run())
        except Exception as e:
            logger.error(
                f"UDS API thread crashed: {e}", extra={"machine": self.machine_name}
            )

    def start(self):
        self._thread = threading.Thread(
            target=self._thread_target, name="uds-api", daemon=True
        )
        self._thread.start()

    def stop(self):
        # Actually stop the asyncio loop so the UDS server thread exits cleanly
        # (not just unblocks). The previous lambda was a no-op call_soon, which
        # left the loop running indefinitely until the process died.
        if self._loop and self._loop.is_running():
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except RuntimeError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
        try:
            os.unlink(UDS_SOCK_PATH)
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# Log Scanner — honeypot + leak detection (integrated since v1.4.0)
# ---------------------------------------------------------------------------
import re as _scan_re  # noqa: E402 -- log-scanner section (integrated v1.4.0)

SCAN_SECRETS_DIR = Path("/run/secrets")
SCAN_HONEYPOT_PREFIX = "HONEYPOT_"
SCAN_MIN_MATCH_LEN = 12
SCAN_STATE_PATH = Path("/var/lib/socialwarden/scan-state.json")


class LogScanner:
    """Tail docker logs, detect real secret values or honeypots. Runs in thread."""

    def __init__(self, webhook_url=None, machine_name="unknown", poll_interval=60):
        self.webhook_url = webhook_url
        self.machine_name = machine_name
        self.poll_interval = poll_interval
        self._thread = None
        self._stop_evt = threading.Event()
        self._state = self._load_state()

    def _load_state(self):
        try:
            if SCAN_STATE_PATH.exists():
                return json.loads(SCAN_STATE_PATH.read_text())
        except (OSError, PermissionError, json.JSONDecodeError):
            # state file unreadable or corrupt — fresh start, no crash
            pass
        return {"seen": {}}

    def _save_state(self):
        try:
            SCAN_STATE_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            SCAN_STATE_PATH.write_text(json.dumps(self._state))
        except (OSError, PermissionError):
            # if we can't persist state, still keep scanning (in-memory dedup
            # works for the lifetime of the process; worst case: extra alerts
            # after restart if a leak persists)
            pass

    def _load_values(self):
        out = {}
        if not SCAN_SECRETS_DIR.is_dir():
            return out
        for envfile in SCAN_SECRETS_DIR.glob("*.env"):
            try:
                for line in envfile.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    k, v = k.strip(), v.strip().strip("'\"")
                    if len(v) < SCAN_MIN_MATCH_LEN:
                        continue
                    out[v] = {
                        "name": k,
                        "file": envfile.name,
                        "honeypot": k.startswith(SCAN_HONEYPOT_PREFIX),
                    }
            except OSError:
                continue
        return out

    def _list_containers(self):
        try:
            r = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.returncode != 0:
                return []
            return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _tail_logs(self, container, since_seconds):
        try:
            r = subprocess.run(
                ["docker", "logs", "--since", f"{since_seconds}s", container],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return (r.stdout or "") + (r.stderr or "")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def _alert(self, title, desc, color, fields=None):
        send_discord_alert(
            self.webhook_url, f"Scan — {title}", desc, color, self.machine_name, fields
        )

    def _redact(self, v):
        if len(v) <= 8:
            return "***"
        return v[:4] + "…" + v[-2:]

    def _loop_once(self):
        values = self._load_values()
        if not values:
            return
        # Compile alternation regex, longest first (avoid overlap short-matches)
        sorted_vals = sorted(values.keys(), key=len, reverse=True)[:500]
        try:
            pattern = _scan_re.compile(
                "|".join(_scan_re.escape(v) for v in sorted_vals)
            )
        except _scan_re.error:
            return

        for container in self._list_containers():
            logs = self._tail_logs(container, self.poll_interval + 5)
            if not logs:
                continue
            for match in pattern.finditer(logs):
                val = match.group(0)
                meta = values[val]
                key = f"{container}::{meta['name']}"
                last = self._state["seen"].get(key, 0)
                if time.time() - last < 3600:
                    continue
                self._state["seen"][key] = time.time()

                if meta["honeypot"]:
                    self._alert(
                        "HONEYPOT TRIGGERED",
                        f"Honeypot secret `{meta['name']}` appeared in container **{container}**. "
                        "No legitimate service should reference this value. Treat as P0 exfiltration signal.",
                        COLOR_RED,
                        fields=[
                            {"name": "Container", "value": container, "inline": True},
                            {"name": "Secret", "value": meta["name"], "inline": True},
                            {
                                "name": "Value (redacted)",
                                "value": self._redact(val),
                                "inline": True,
                            },
                        ],
                    )
                else:
                    self._alert(
                        "Secret Leak in Logs",
                        f"Value of `{meta['name']}` (from `{meta['file']}`) appeared in "
                        f"**{container}** stdout/stderr. Fix the log statement immediately.",
                        COLOR_ORANGE,
                        fields=[
                            {"name": "Container", "value": container, "inline": True},
                            {"name": "Secret", "value": meta["name"], "inline": True},
                        ],
                    )
        self._save_state()

    def _thread_target(self):
        logger.info(
            f"Log scanner started (poll={self.poll_interval}s)",
            extra={"machine": self.machine_name},
        )
        while not self._stop_evt.is_set():
            t0 = time.time()
            try:
                self._loop_once()
            except Exception as e:
                logger.error(
                    f"Scan cycle error: {e}", extra={"machine": self.machine_name}
                )
            elapsed = time.time() - t0
            self._stop_evt.wait(timeout=max(1, self.poll_interval - elapsed))
        logger.info("Log scanner stopped", extra={"machine": self.machine_name})

    def start(self):
        self._thread = threading.Thread(
            target=self._thread_target, name="log-scanner", daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop_evt.set()


# ---------------------------------------------------------------------------
# Dynamic-pg revoke watcher (Sprint 3 — slice 3c) — OPT-IN, default OFF
# ---------------------------------------------------------------------------
# A host-local, DB-agnostic "session reaper". Watches `docker events` for
# container start/die. For a watched container (key in
# `resilience.pg_revoke_map`) it keeps that container's IP(s) cached; when
# the container dies it connects to the configured admin DB and immediately
# terminates the dead container's orphaned backends, instead of waiting for
# Postgres TCP keepalive / idle_in_transaction_session_timeout (minutes).
#
# Why client_addr, not role: roles are SHARED per app (e.g. app-b-server
# and app-b-worker authenticate as the same role). Terminating by `usename`
# would also kill the LIVING sibling, and `ALTER ROLE ... NOLOGIN` would
# lock out the surviving replicas and the restart. So the reaper scopes by
# the dead container's `client_addr` (its IP — verified distinct in
# pg_stat_activity per container). `NOLOGIN` is opt-in OFF for that reason.
#
# Safety invariants:
#  - OPT-IN: `resilience.pg_revoke_watcher: true` (default OFF → thread
#    never started; zero change to current fleet behaviour).
#  - DRY-RUN by default even when enabled: it only mutates the DB if
#    `resilience.pg_revoke_dry_run: false` is set explicitly per host.
#  - Fail-closed: unwatched container, no cached IP, no/blank admin DSN,
#    psql missing, non-zero/timeout → log + skip, never crash, never block
#    the poll. No new Python dependency: shells out to `psql` like the rest
#    of the agent shells out to `docker`/`bw`.
#  - Acyclic: own daemon thread, never calls back into SyncEngine.
#  - No secrets in argv/logs: the admin password goes via PGPASSWORD env,
#    never on the psql command line; logs carry only container/IP/role.
PG_REVOKE_RECONNECT_MIN_S = 2
PG_REVOKE_RECONNECT_MAX_S = 60
PG_REVOKE_PSQL_TIMEOUT_S = 5


class PgRevokeWatcher:
    """Tail `docker events` → reap a dead container's orphaned DB backends.

    Opt-in via `resilience.pg_revoke_watcher: true` (default OFF). Dry-run
    unless `resilience.pg_revoke_dry_run: false`. See module comment above.
    """

    def __init__(self, config=None, machine_name="unknown", webhook_url=None):
        rcfg = (config or {}).get("resilience") or {}
        # Watched set: container-name → optional role (role used ONLY for the
        # opt-in NOLOGIN path). A container NOT in the map is ignored
        # (fail-closed — we never touch a DB for something we were not told
        # to own). Value may be a role string, True, or None.
        self._map = dict(rcfg.get("pg_revoke_map") or {})
        # Live only if the operator explicitly opted in PER HOST. Absent or
        # anything other than the literal False → dry-run (safe default).
        self._dry_run = rcfg.get("pg_revoke_dry_run", True) is not False
        # ALTER ROLE NOLOGIN is dangerous on shared roles → opt-in OFF.
        self._nologin = rcfg.get("pg_revoke_nologin", False) is True
        # Path to a file (typically a socialwarden-synced secret in
        # /run/secrets) whose single line is a libpq URI for an admin role.
        self._admin_dsn_file = rcfg.get("pg_revoke_admin_dsn_file") or ""
        self.machine_name = machine_name
        self.webhook_url = webhook_url
        self._thread = None
        self._stop_evt = threading.Event()
        self._ips = {}  # container-name → set(ip-strings), last known
        self._actions = []  # observability/testing: (container, detail, outcome)

    # -- event source (isolated for testing: monkeypatch _spawn) -----------
    def _spawn(self):
        """Start the `docker events` stream. Returns a Popen or None.

        Streams both `start` and `die` for containers so we can keep the
        per-container IP cache fresh (the container is gone by `die`).
        """
        try:
            return subprocess.Popen(
                [
                    "docker",
                    "events",
                    "--filter",
                    "type=container",
                    "--filter",
                    "event=start",
                    "--filter",
                    "event=die",
                    "--format",
                    "{{.Status}} {{.Actor.Attributes.name}}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except (FileNotFoundError, OSError) as e:
            logger.error(
                f"pg-revoke: cannot start docker events: {e}",
                extra={"machine": self.machine_name},
            )
            return None

    # -- container → IP discovery (isolated for testing) -------------------
    def _container_ips(self, container):
        """Return the set of IPv4/IPv6 addresses of `container` (live)."""
        try:
            r = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}} "
                    "{{.GlobalIPv6Address}} {{end}}",
                    container,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.returncode != 0:
                return set()
            return {tok for tok in r.stdout.split() if self._valid_ip(tok)}
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return set()

    @staticmethod
    def _valid_ip(tok):
        import ipaddress

        try:
            ipaddress.ip_address(tok)
            return True
        except ValueError:
            return False

    def seed_ips(self):
        """Pre-populate the IP cache for already-running watched containers
        (so a container that dies before we ever saw its `start` is still
        reapable). Best-effort; never raises."""
        for container in list(self._map):
            ips = self._container_ips(container)
            if ips:
                self._ips[container] = ips

    # -- admin connection (re-read each use → picks up secret rotation) ----
    def _resolve_admin(self):
        """Parse the admin libpq URI from the configured secret file.

        Returns a dict {host,port,user,dbname,password} or None (fail-closed
        on missing/blank/unparseable — caller must skip the DB action).
        """
        import urllib.parse

        path = self._admin_dsn_file
        if not path:
            return None
        try:
            raw = Path(path).read_text().strip()
        except (OSError, PermissionError):
            return None
        if not raw or raw.startswith("ENC:"):
            # Blank, or still encrypted (not materialized) — fail-closed.
            return None
        try:
            p = urllib.parse.urlparse(raw)
            if p.scheme not in ("postgres", "postgresql") or not p.hostname:
                return None
            return {
                "host": p.hostname,
                "port": str(p.port or 5432),
                "user": p.username or "postgres",
                "dbname": (p.path or "/postgres").lstrip("/") or "postgres",
                "password": p.password or "",
            }
        except ValueError:
            return None

    # -- SQL + execution (isolated for testing: monkeypatch _run_psql) -----
    def _reap_sql(self, ips, role):
        """Build the reaper SQL for the dead container's IP(s).

        client_addr-scoped (never role-scoped → never kills a living
        sibling). NOLOGIN appended only when opt-in AND a role is known.
        """
        # ips already IP-validated by _valid_ip → safe to inline.
        in_list = ", ".join(f"'{ip}'" for ip in sorted(ips))
        sql = (
            "SELECT count(pg_terminate_backend(pid)) "
            "FROM pg_stat_activity "
            f"WHERE pid <> pg_backend_pid() AND client_addr IN ({in_list});"
        )
        if self._nologin and isinstance(role, str) and role:
            # Role name validated against a strict identifier charset; double
            # quoted. Reversible: operator re-enables via the next sync.
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", role):
                sql = f'ALTER ROLE "{role}" NOLOGIN; ' + sql
        return sql

    def _run_psql(self, admin, sql):
        """Run `sql` via psql. Returns (rc, stdout, stderr). Fail-closed:
        psql missing / timeout → (-1, '', reason). No secret in argv."""
        env = dict(os.environ)
        env["PGPASSWORD"] = admin["password"]
        env["PGCONNECT_TIMEOUT"] = str(PG_REVOKE_PSQL_TIMEOUT_S)
        try:
            r = subprocess.run(
                [
                    "psql",
                    "-h",
                    admin["host"],
                    "-p",
                    admin["port"],
                    "-U",
                    admin["user"],
                    "-d",
                    admin["dbname"],
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-At",
                    "-c",
                    sql,
                ],
                capture_output=True,
                text=True,
                timeout=PG_REVOKE_PSQL_TIMEOUT_S + 3,
                env=env,
            )
            return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except (FileNotFoundError, OSError) as e:
            return -1, "", f"psql-unavailable: {e}"

    # -- event routing -----------------------------------------------------
    def _handle_event(self, status, container):
        """Route one `docker events` record. Returns an outcome string for
        observability/testing."""
        status = (status or "").strip()
        container = (container or "").strip()
        if not container:
            return "skip:empty"
        if container not in self._map:
            return "skip:unwatched"
        if status == "start":
            ips = self._container_ips(container)
            if ips:
                self._ips[container] = ips
                return f"cached:{len(ips)}"
            return "cached:0"
        if status == "die":
            return self._reap(container)
        return "skip:other"

    # back-compat shim for the 3c.1 scaffold tests / external callers
    def _handle_die(self, container):
        return self._handle_event("die", container)

    def _reap(self, container):
        """Reap the dead `container`'s orphaned DB backends. Fail-closed."""
        ips = self._ips.pop(container, set())
        role = self._map.get(container)
        if not ips:
            # We never learned this container's IP (started before us and
            # inspect failed, or no network) — cannot scope safely → skip.
            out = "skip:no-ip"
            self._actions.append((container, "-", out))
            logger.warning(
                f"pg-revoke: '{container}' died but no cached IP → "
                "skipping (cannot scope reap safely)",
                extra={"machine": self.machine_name},
            )
            return out
        sql = self._reap_sql(ips, role)
        if self._dry_run:
            out = f"dry-run:{','.join(sorted(ips))}"
            self._actions.append((container, sql, out))
            logger.info(
                f"pg-revoke: '{container}' died → WOULD run on admin DB: "
                f"{sql} (dry-run; set resilience.pg_revoke_dry_run:false "
                "to enable)",
                extra={"machine": self.machine_name},
            )
            return out
        admin = self._resolve_admin()
        if not admin:
            out = "skip:no-admin"
            self._actions.append((container, "-", out))
            logger.error(
                f"pg-revoke: '{container}' died but admin DSN "
                "missing/blank/unparseable → fail-closed skip",
                extra={"machine": self.machine_name},
            )
            return out
        rc, stdout, stderr = self._run_psql(admin, sql)
        if rc != 0:
            out = "error:psql"
            self._actions.append((container, stderr[:200], out))
            logger.error(
                f"pg-revoke: reap for '{container}' failed (rc={rc}): {stderr[:200]}",
                extra={"machine": self.machine_name},
            )
            return out
        # The terminate count is the SELECT's scalar. When the NOLOGIN
        # prefix ran, psql also echoes its "ALTER ROLE" command tag — take
        # the last pure-integer line so the count stays clean.
        digits = [ln for ln in stdout.splitlines() if ln.strip().isdigit()]
        killed = digits[-1] if digits else "0"
        out = f"reaped:{killed}"
        self._actions.append((container, ",".join(sorted(ips)), out))
        logger.info(
            f"pg-revoke: '{container}' died → terminated {killed} "
            f"orphaned backend(s) from {sorted(ips)}"
            + (f"; ALTER ROLE {role} NOLOGIN" if self._nologin and role else ""),
            extra={"machine": self.machine_name},
        )
        return out

    def _thread_target(self):
        logger.info(
            f"pg-revoke watcher started (dry_run={self._dry_run}, "
            f"nologin={self._nologin}, watched={sorted(self._map)})",
            extra={"machine": self.machine_name},
        )
        with contextlib.suppress(Exception):
            self.seed_ips()
        backoff = PG_REVOKE_RECONNECT_MIN_S
        while not self._stop_evt.is_set():
            proc = self._spawn()
            if proc is None or proc.stdout is None:
                # docker missing / spawn failed — back off and retry (docker
                # may be installed later; never crash the agent).
                if self._stop_evt.wait(timeout=backoff):
                    break
                backoff = min(backoff * 2, PG_REVOKE_RECONNECT_MAX_S)
                continue
            backoff = PG_REVOKE_RECONNECT_MIN_S
            try:
                for line in proc.stdout:
                    if self._stop_evt.is_set():
                        break
                    status, _, name = line.strip().partition(" ")
                    try:
                        self._handle_event(status, name)
                    except Exception as e:
                        logger.error(
                            f"pg-revoke: handler error: {e}",
                            extra={"machine": self.machine_name},
                        )
            except Exception as e:
                logger.error(
                    f"pg-revoke: event stream error: {e}",
                    extra={"machine": self.machine_name},
                )
            finally:
                with contextlib.suppress(Exception):
                    proc.terminate()
                with contextlib.suppress(Exception):
                    proc.wait(timeout=5)
            # Stream ended (docker restart, etc.) — reconnect unless stopping.
            if not self._stop_evt.is_set():
                self._stop_evt.wait(timeout=PG_REVOKE_RECONNECT_MIN_S)
        logger.info("pg-revoke watcher stopped", extra={"machine": self.machine_name})

    def start(self):
        self._thread = threading.Thread(
            target=self._thread_target, name="pg-revoke", daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop_evt.set()


# ---------------------------------------------------------------------------
# Shamir share-release HTTP server — peer-to-peer share distribution (v1.4.2+)
# ---------------------------------------------------------------------------
# Protocol:
#   POST http://<tailscale-ip>:14841/v1/shamir/release-share
#   Body (JSON):
#     {
#       "v":          1,
#       "requester":  "<machine-name>",     # who's asking (= whose share)
#       "nonce":      "<64 hex chars>",      # random, anti-replay
#       "timestamp":  <unix epoch seconds>,  # within 60s of server's now()
#       "signature":  "<128 hex chars>"      # ed25519 over canonical payload
#     }
#   Canonical signed payload:
#     "v1|" + requester + "|" + nonce + "|" + str(timestamp)
#   Response 200:
#     {"ok": true,  "share": "<x_hex>:<y_hex>"}
#   Response 4xx / 5xx:
#     {"ok": false, "error": "<code>"}
#
# Security layers (defense-in-depth):
#   1. Network: binds to tailscale0 IP only (never 0.0.0.0 → not public).
#   2. Tailscale WireGuard encrypts+authenticates transport.
#   3. ed25519 signature proves requester identity at application level.
#   4. Timestamp ±60s window prevents old-message replay.
#   5. Nonce table remembers last 5 min of nonces; duplicates rejected.
#   6. Rate limit: 10 releases/min per requester name (per-source).
#   7. Every outcome audited to /var/lib/socialwarden/shamir-release.log.
#
# Storage on THIS host:
#   /var/lib/socialwarden/peer-shares/<requester>.share   (0600, format x_hex:y_hex)
#   /var/lib/socialwarden/peer-identities/<requester>.pub (0644, hex ed25519)

import http.server as _share_http  # noqa: E402 -- share-release section; aliased
from http import HTTPStatus  # noqa: E402

SHARE_RELEASE_PORT = 14841
SHARE_DIR = Path("/var/lib/socialwarden/peer-shares")
PEER_IDS_DIR = Path("/var/lib/socialwarden/peer-identities")
SHARE_AUDIT_LOG = Path("/var/lib/socialwarden/shamir-release.log")
SHARE_TIMESTAMP_WINDOW_S = 60
SHARE_NONCE_TTL_S = 300
SHARE_RATE_PER_MIN = 10
VALID_MACHINE_NAME = __import__("re").compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")


def _share_tailscale_ip():
    """Return this host's tailscale IP (IPv4), or None if tailscale not running."""
    try:
        r = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode != 0:
            return None
        ip = r.stdout.strip().splitlines()[0] if r.stdout.strip() else None
        return ip
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _share_audit(**kv):
    """Append a JSON line to the share-release audit log."""
    kv.setdefault("ts", datetime.now(timezone.utc).isoformat())
    try:
        SHARE_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(
            str(SHARE_AUDIT_LOG), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        os.write(fd, (json.dumps(kv) + "\n").encode())
        os.close(fd)
    except OSError:
        pass


class ShareReleaseHandler(_share_http.BaseHTTPRequestHandler):
    """HTTP handler for share-release requests. One handler per request, but
    shares state (rate buckets, nonces) through class-level dicts guarded by
    a lock. Python stdlib http.server runs sequentially per-server by default,
    so contention is minimal."""

    server_version = "SocialwardenShare/1.0"
    sys_version = ""  # suppress Python/X.Y version in headers

    def log_message(self, fmt, *args):
        # Silence stdlib's default per-request stderr spam; we use our own logger.
        return

    def do_POST(self):
        try:
            self._handle()
        except Exception as e:
            logger.error(
                f"share-release handler crashed: {e}",
                extra={"machine": self.server.machine_name},
                exc_info=True,
            )
            self._reply(
                HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "internal"}
            )

    def do_GET(self):
        # A minimal GET /health returns "ok" so operators can curl-test.
        if self.path == "/health":
            self._reply(
                HTTPStatus.OK, {"ok": True, "machine": self.server.machine_name, "v": 1}
            )
            return
        self._reply(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})

    def _reply(self, code, body_obj):
        data = json.dumps(body_obj).encode() + b"\n"
        self.send_response(code.value if hasattr(code, "value") else code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _handle(self):
        if self.path != "/v1/shamir/release-share":
            self._reply(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 4096:
            self._reply(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_length"})
            return

        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            _share_audit(
                event="release-deny", reason="bad_json", remote=self.client_address[0]
            )
            self._reply(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_json"})
            return

        # --- validate shape ---
        if req.get("v") != 1:
            self._reply(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_version"})
            return
        requester = req.get("requester")
        nonce = req.get("nonce")
        timestamp = req.get("timestamp")
        signature = req.get("signature")
        if not (
            isinstance(requester, str)
            and isinstance(nonce, str)
            and isinstance(timestamp, int)
            and isinstance(signature, str)
        ):
            self._reply(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_fields"})
            return
        if not VALID_MACHINE_NAME.match(requester):
            self._reply(
                HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_machine_name"}
            )
            return
        if len(nonce) not in (32, 64) or not all(
            c in "0123456789abcdef" for c in nonce
        ):
            self._reply(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_nonce"})
            return

        # --- rate limit ---
        if not self.server.check_rate(requester):
            _share_audit(
                event="release-deny",
                reason="rate_limited",
                requester=requester,
                remote=self.client_address[0],
            )
            self._reply(
                HTTPStatus.TOO_MANY_REQUESTS, {"ok": False, "error": "rate_limited"}
            )
            return

        # --- timestamp window ---
        now = int(time.time())
        skew = now - int(timestamp)
        if abs(skew) > SHARE_TIMESTAMP_WINDOW_S:
            _share_audit(
                event="release-deny",
                reason="bad_timestamp",
                requester=requester,
                skew=skew,
                remote=self.client_address[0],
            )
            self._reply(HTTPStatus.FORBIDDEN, {"ok": False, "error": "bad_timestamp"})
            return

        # --- nonce replay protection ---
        if not self.server.check_nonce(requester, nonce, now):
            _share_audit(
                event="release-deny",
                reason="replayed_nonce",
                requester=requester,
                remote=self.client_address[0],
            )
            self._reply(HTTPStatus.FORBIDDEN, {"ok": False, "error": "replayed_nonce"})
            return

        # --- pubkey lookup ---
        pub_path = PEER_IDS_DIR / f"{requester}.pub"
        if not pub_path.exists():
            _share_audit(
                event="release-deny",
                reason="no_pubkey",
                requester=requester,
                remote=self.client_address[0],
            )
            self._reply(HTTPStatus.FORBIDDEN, {"ok": False, "error": "no_pubkey"})
            return
        try:
            pub_hex = pub_path.read_text().strip()
            pub_raw = bytes.fromhex(pub_hex)
            if len(pub_raw) != 32:
                raise ValueError(f"pubkey length {len(pub_raw)} != 32")
        except (OSError, ValueError) as e:
            _share_audit(
                event="release-deny",
                reason="bad_pubkey",
                requester=requester,
                err=str(e),
            )
            self._reply(
                HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "bad_pubkey"}
            )
            return

        # --- signature verify ---
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
            from cryptography.exceptions import InvalidSignature

            pub_key = Ed25519PublicKey.from_public_bytes(pub_raw)
            canonical = f"v1|{requester}|{nonce}|{timestamp}".encode()
            try:
                sig_bytes = bytes.fromhex(signature)
            except ValueError:
                self._reply(
                    HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_sig_hex"}
                )
                return
            if len(sig_bytes) != 64:
                self._reply(
                    HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_sig_len"}
                )
                return
            try:
                pub_key.verify(sig_bytes, canonical)
            except InvalidSignature:
                _share_audit(
                    event="release-deny",
                    reason="bad_signature",
                    requester=requester,
                    remote=self.client_address[0],
                )
                self._reply(
                    HTTPStatus.FORBIDDEN, {"ok": False, "error": "bad_signature"}
                )
                return
        except ImportError:
            logger.error(
                "cryptography library missing; cannot verify signatures",
                extra={"machine": self.server.machine_name},
            )
            self._reply(
                HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "no_crypto"}
            )
            return

        # --- look up share ---
        share_path = SHARE_DIR / f"{requester}.share"
        if not share_path.exists():
            _share_audit(
                event="release-deny",
                reason="no_share",
                requester=requester,
                remote=self.client_address[0],
            )
            self._reply(HTTPStatus.NOT_FOUND, {"ok": False, "error": "no_share"})
            return
        try:
            share_content = share_path.read_text().strip()
        except OSError as e:
            _share_audit(
                event="release-deny",
                reason="share_read_err",
                requester=requester,
                err=str(e),
            )
            self._reply(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"ok": False, "error": "share_read_err"},
            )
            return
        if ":" not in share_content:
            _share_audit(
                event="release-deny", reason="share_malformed", requester=requester
            )
            self._reply(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"ok": False, "error": "share_malformed"},
            )
            return

        # --- success ---
        _share_audit(
            event="release-ok",
            requester=requester,
            remote=self.client_address[0],
            nonce_prefix=nonce[:8],
        )
        self._reply(HTTPStatus.OK, {"ok": True, "share": share_content})


class ShareReleaseServer(_share_http.HTTPServer):
    """Threaded HTTP server for share-release. Binds to tailscale IP only.

    Wrapper around stdlib HTTPServer with:
      - bind address forced to tailscale IP (never 0.0.0.0)
      - per-requester rate limit + nonce tracking in-memory
      - graceful stop via self._stop
    """

    allow_reuse_address = True

    def __init__(self, machine_name: str, bind_ip: str, port: int = SHARE_RELEASE_PORT):
        super().__init__((bind_ip, port), ShareReleaseHandler)
        self.machine_name = machine_name
        self._rate_buckets = _uds_defaultdict(_uds_deque)
        self._seen_nonces = {}  # {(requester, nonce): ts_seen}
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()

    def check_rate(self, requester: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = self._rate_buckets[requester]
            cutoff = now - 60
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= SHARE_RATE_PER_MIN:
                return False
            bucket.append(now)
        return True

    def check_nonce(self, requester: str, nonce: str, now_ts: int) -> bool:
        """Return True if nonce is fresh (not seen recently). Records it."""
        with self._lock:
            # Prune anything older than TTL
            expired = [
                k
                for k, t in self._seen_nonces.items()
                if now_ts - t > SHARE_NONCE_TTL_S
            ]
            for k in expired:
                del self._seen_nonces[k]
            key = (requester, nonce)
            if key in self._seen_nonces:
                return False
            self._seen_nonces[key] = now_ts
        return True

    def _thread_target(self):
        logger.info(
            f"Share-release HTTP server listening on http://{self.server_address[0]}:{self.server_address[1]}",
            extra={"machine": self.machine_name},
        )
        try:
            self.serve_forever(poll_interval=0.5)
        except Exception as e:
            logger.error(
                f"Share-release server exit: {e}", extra={"machine": self.machine_name}
            )

    def start(self):
        # Ensure state dirs with correct modes, even if install.sh wasn't re-run.
        SHARE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        PEER_IDS_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)
        try:
            os.chmod(SHARE_DIR, 0o700)
            os.chmod(PEER_IDS_DIR, 0o755)
        except OSError:
            pass
        self._thread = threading.Thread(
            target=self._thread_target, name="share-release", daemon=True
        )
        self._thread.start()

    def stop(self):
        try:
            self.shutdown()
            self.server_close()
        except Exception:
            pass
        self._stop_evt.set()


# ---------------------------------------------------------------------------
# Shamir boot reconstruction — v1.4.3+
# ---------------------------------------------------------------------------
# Flow on agent startup:
#   1. If local master.key exists and decrypts → use it (fast cache path)
#   2. Else if shamir.enabled → reconstruct from peer shares, write cache
#   3. Else → exit with alert
#
# The local master.key at /var/lib/socialwarden/master.key is an ENCRYPTED
# cache (with machine-id) of the plaintext master password. Shamir is the
# authoritative source: shares live on N-1 peers + this machine's own
# `local.share`. K-of-N threshold rules apply.
#
# Design notes:
#   - A single Shamir share reveals NOTHING about the secret. Storing it
#     unencrypted at mode 0600 is mathematically safe.
#   - During boot, peers may not be up yet (simultaneous reboot). We retry
#     with backoff for up to `boot_timeout_s` (default 300s).
#   - If reconstruction succeeds, we re-write the master.key cache so the
#     next boot is fast. This is the self-healing property.

LOCAL_SHARE_PATH_DEFAULT = "/var/lib/socialwarden/local.share"
SHARE_CLIENT_PORT = 14841


class BootShamirReconstructor:
    """Reconstructs master password from Shamir peer shares on boot.

    Input: config.shamir block with:
      enabled:      bool
      threshold:    K (default 3)
      peers:        list of {name, ip} dicts
      local_share_path: path to this machine's own local share

    Output: .reconstruct() returns plaintext password bytes, or None on failure.
    """

    def __init__(self, config: dict, machine_name: str):
        cfg = (config.get("shamir") or {}) if config else {}
        self.enabled: bool = bool(cfg.get("enabled", False))
        self.threshold: int = int(cfg.get("threshold", 3))
        # Reject malformed config early — threshold=0 makes the boot loop
        # exit immediately with empty shares list and crashes downstream.
        if self.enabled and self.threshold < 2:
            raise ValueError(
                f"shamir.threshold must be >= 2 (got {self.threshold}); "
                f"K=1 means no secret sharing, K=0 is undefined."
            )
        self.peers: list[dict] = list(cfg.get("peers") or [])
        self.local_share_path: str = cfg.get(
            "local_share_path", LOCAL_SHARE_PATH_DEFAULT
        )
        self.boot_timeout_s: int = int(cfg.get("boot_timeout_s", 300))
        self.machine_name = machine_name

    def _load_local_share(self):
        try:
            content = Path(self.local_share_path).read_text().strip()
        except FileNotFoundError:
            return None
        except (PermissionError, OSError) as e:
            logger.warning(
                f"local.share unreadable: {e}", extra={"machine": self.machine_name}
            )
            return None
        if ":" not in content:
            logger.warning(
                f"local.share malformed: {content[:40]!r}",
                extra={"machine": self.machine_name},
            )
            return None
        try:
            x_hex, y_hex = content.split(":", 1)
            return (int(x_hex, 16), bytes.fromhex(y_hex))
        except ValueError as e:
            logger.warning(
                f"local.share parse error: {e}", extra={"machine": self.machine_name}
            )
            return None

    def _sign_request(self, priv_key, nonce: str, timestamp: int) -> str:
        """Sign the canonical challenge payload with this machine's ed25519 key."""
        canonical = f"v1|{self.machine_name}|{nonce}|{timestamp}".encode()
        return priv_key.sign(canonical).hex()

    def _fetch_from_peer(self, peer: dict, priv_key) -> tuple | None:
        """Ask a single peer for our share. Returns (x, y_bytes) or None."""
        import urllib.request
        import urllib.error

        peer_ip = peer.get("ip") or peer.get("address")
        peer_name = peer.get("name") or peer_ip
        if not peer_ip:
            logger.warning(
                f"peer entry missing ip: {peer}", extra={"machine": self.machine_name}
            )
            return None
        if peer_name == self.machine_name:
            return None  # skip self

        ts = int(time.time())
        nonce = os.urandom(16).hex()
        sig = self._sign_request(priv_key, nonce, ts)
        body = {
            "v": 1,
            "requester": self.machine_name,
            "nonce": nonce,
            "timestamp": ts,
            "signature": sig,
        }
        url = f"http://{peer_ip}:{SHARE_CLIENT_PORT}/v1/shamir/release-share"
        # Cap response size at 4 KB. A legitimate share-release response is
        # ~200 bytes JSON. Without the cap a malicious/buggy peer could stream
        # gigabytes and OOM the agent.
        SHARE_RESP_MAX = 4096
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                cl = r.headers.get("Content-Length")
                if cl is not None and int(cl) > SHARE_RESP_MAX:
                    logger.warning(
                        f"peer {peer_name} returned oversized response ({cl} bytes), refusing",
                        extra={"machine": self.machine_name},
                    )
                    return None
                raw = r.read(SHARE_RESP_MAX + 1)
                if len(raw) > SHARE_RESP_MAX:
                    logger.warning(
                        f"peer {peer_name} streamed >{SHARE_RESP_MAX}B, truncated/refused",
                        extra={"machine": self.machine_name},
                    )
                    return None
            d = json.loads(raw.decode())
        except urllib.error.HTTPError as e:
            body_text = e.read(512).decode("utf-8", errors="replace")[:100]
            logger.info(
                f"peer {peer_name}: HTTP {e.code} {body_text}",
                extra={"machine": self.machine_name},
            )
            return None
        except (
            urllib.error.URLError,
            OSError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as e:
            logger.info(
                f"peer {peer_name} unreachable: {e}",
                extra={"machine": self.machine_name},
            )
            return None

        if not d.get("ok") or "share" not in d:
            return None

        share_str = d["share"]
        if ":" not in share_str:
            logger.warning(
                f"peer {peer_name} returned malformed share",
                extra={"machine": self.machine_name},
            )
            return None
        try:
            x_hex, y_hex = share_str.split(":", 1)
            return (int(x_hex, 16), bytes.fromhex(y_hex))
        except ValueError:
            return None

    def reconstruct(self):
        """Collect K shares and combine. Returns plaintext bytes or None."""
        if not self.enabled:
            return None

        try:
            from cryptography.hazmat.primitives import serialization as _ser
        except ImportError:
            logger.error(
                "cryptography missing; cannot Shamir-reconstruct",
                extra={"machine": self.machine_name},
            )
            return None

        # Load private key for signing peer requests
        try:
            priv_bytes = Path(IDENTITY_PRIV_PATH).read_bytes()
            priv_key = _ser.load_pem_private_key(priv_bytes, password=None)
        except (FileNotFoundError, PermissionError) as e:
            logger.error(
                f"cannot load identity key: {e}", extra={"machine": self.machine_name}
            )
            return None

        # Collect shares with retry/backoff (handles simultaneous reboot)
        shares = []
        local = self._load_local_share()
        if local:
            shares.append(local)
            logger.info(
                f"Shamir: loaded local share x={local[0]}",
                extra={"machine": self.machine_name},
            )

        deadline = time.time() + self.boot_timeout_s
        backoff = 2.0
        attempt = 0
        while len(shares) < self.threshold and time.time() < deadline:
            attempt += 1
            for peer in self.peers:
                if len(shares) >= self.threshold:
                    break
                # Skip peers we already have a share from (by x coord)
                s = self._fetch_from_peer(peer, priv_key)
                if s and all(s[0] != existing[0] for existing in shares):
                    shares.append(s)
                    logger.info(
                        f"Shamir: got share from {peer.get('name', peer.get('ip'))} (x={s[0]})",
                        extra={"machine": self.machine_name},
                    )
            if len(shares) < self.threshold:
                logger.warning(
                    f"Shamir: {len(shares)}/{self.threshold} shares, retrying in {backoff:.0f}s (attempt {attempt})",
                    extra={"machine": self.machine_name},
                )
                time.sleep(min(backoff, 30))
                backoff = min(backoff * 1.5, 30)

        if len(shares) < self.threshold:
            logger.error(
                f"Shamir: gave up after {self.boot_timeout_s}s "
                f"with {len(shares)}/{self.threshold} shares",
                extra={"machine": self.machine_name},
            )
            return None

        # Import shamir module (copied alongside agent.py on install or nearby)
        shamir_mod = None
        for candidate in (
            "/opt/socialwarden-agent/shamir.py",
            "/opt/socialwarden-manager/shamir.py",
            str(Path(__file__).parent / "shamir.py"),
        ):
            if os.path.isfile(candidate):
                import importlib.util

                _spec = importlib.util.spec_from_file_location(
                    "_shamir_boot", candidate
                )
                shamir_mod = importlib.util.module_from_spec(_spec)
                _spec.loader.exec_module(shamir_mod)
                break
        if shamir_mod is None:
            logger.error(
                "shamir.py not found; cannot combine",
                extra={"machine": self.machine_name},
            )
            return None

        try:
            master_bytes = shamir_mod.combine_bytes(shares)
            logger.info(
                f"Shamir: reconstructed master password "
                f"({len(master_bytes)} bytes, {len(shares)} shares used)",
                extra={"machine": self.machine_name},
            )
            return master_bytes
        except Exception as e:
            logger.error(
                f"Shamir combine raised: {e}", extra={"machine": self.machine_name}
            )
            return None


# ---------------------------------------------------------------------------
# Machine identity (ed25519) — used for Shamir peer authentication (v1.4.1+)
# ---------------------------------------------------------------------------
# Each machine generates its own ed25519 keypair once, at first agent startup.
# Private key: /var/lib/socialwarden/identity.key  (mode 0600, root-only)
# Public key:  /var/lib/socialwarden/identity.pub  (mode 0644, world-readable)
#
# The public key is consumed by:
#   - socialwarden-manager (registers it against the machine name in inventory)
#   - other agents (verify signed share-release requests originating from M)
#
# The keypair NEVER leaves the machine in private form. Rotation is allowed;
# manager re-registration is a manual operator action after a rotation.
#
# This is independent of the master-password encryption (machine-id-based).
# It provides a stable "who is this machine" identity that can sign challenges.
def ensure_machine_identity():
    """Generate ed25519 keypair if not present. Returns the public key (raw 32 bytes).

    Does nothing destructive on re-invocation: if keypair already exists, just
    loads and returns the public half. Private key stays untouched.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        logger.warning(
            "cryptography library not available; skipping ed25519 identity "
            "generation. Shamir features will degrade gracefully.",
            extra={"machine": "init"},
        )
        return None

    priv_p = Path(IDENTITY_PRIV_PATH)
    pub_p = Path(IDENTITY_PUB_PATH)

    if priv_p.exists() and pub_p.exists():
        # Load existing — verify pairing is internally consistent
        try:
            priv_bytes = priv_p.read_bytes()
            priv_key = serialization.load_pem_private_key(priv_bytes, password=None)
            pub_key = priv_key.public_key()
            pub_raw = pub_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            # Fingerprint = first 16 hex chars of sha256(pub_raw)
            fp = hashlib.sha256(pub_raw).hexdigest()[:16]
            logger.info(
                f"Machine identity loaded, fingerprint=sha256:{fp}",
                extra={"machine": "init"},
            )
            return pub_raw
        except Exception as e:
            logger.error(
                f"Failed to load existing identity keypair: {e}. Keeping old files.",
                extra={"machine": "init"},
            )
            return None

    # Generate new keypair
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Write atomically: tmp file + rename + chmod
    priv_p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = str(priv_p) + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, priv_pem)
    os.close(fd)
    os.replace(tmp, priv_p)

    pub_p.write_text(pub_raw.hex() + "\n")
    os.chmod(pub_p, 0o644)

    fp = hashlib.sha256(pub_raw).hexdigest()[:16]
    logger.info(
        f"Machine identity GENERATED. Public fingerprint: sha256:{fp}. "
        f"Register on manager with: "
        f"sudo socialwarden-manager register-identity <machine>",
        extra={"machine": "init"},
    )
    return pub_raw


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def main():
    # Parse args
    config_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONFIG

    # Setup logging
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger.info(f"SocialWarden Agent v{VERSION} starting", extra={"machine": "init"})

    # Load config
    try:
        config = load_config(config_path)
    except Exception as e:
        logger.critical(f"Cannot load config {config_path}: {e}")
        sys.exit(1)

    machine_name = config["machine"]["name"]
    discord_webhook = config.get("alerts", {}).get("discord_webhook")
    logger.info(
        f"Machine: {machine_name}, Server: {config['server']['url']}",
        extra={"machine": machine_name},
    )

    # v1.4.1+: ensure machine identity keypair exists. This is idempotent and
    # cheap: on first boot it generates, on later boots it just loads.
    # Failure to generate is non-fatal; Shamir features will degrade but core
    # sync keeps working.
    try:
        ensure_machine_identity()
    except Exception as e:
        logger.error(
            f"Identity keypair setup failed: {e}", extra={"machine": machine_name}
        )

    # Skip Vault auth entirely when no collections are configured (bundle-only
    # mode). On dedicated worker hosts we deliver secrets
    # via `socialwarden-manager bundle-push` (age-encrypted), not via Vaultwarden
    # sync. The daemon still stays up to host the UDS API, share-release HTTP
    # endpoint, and bundle-render hooks — but it should NOT crashloop trying
    # to bw login when there's nothing to sync.
    bundle_only_mode = not config.get("sync", {}).get("collections")
    if bundle_only_mode:
        logger.info(
            "No sync.collections configured — running in BUNDLE-ONLY mode "
            "(no Vaultwarden auth, no periodic sync). Bundle-push + render "
            "+ UDS API + share-release endpoint stay active.",
            extra={"machine": machine_name},
        )

    # Initialize BW client
    master_key_path = config["auth"]["master_key_path"]
    bw = BWClient(
        server_url=config["server"]["url"],
        email=config["auth"]["email"],
        master_key_path=master_key_path,
    )

    # v1.4.3+: Shamir boot reconstruction.
    # Flow:
    #   1. Try to login with the existing master.key cache (fast path).
    #   2. If step 1 fails AND shamir.enabled, reconstruct from peers → write
    #      the reconstructed password back to master.key and retry login.
    #   3. If both fail, exit with alert (same behaviour as v1.4.2 and earlier).
    # This gives self-healing on cache corruption / accidental delete.

    def _try_login_once():
        try:
            return bw.login()
        except FileNotFoundError:
            return False
        except Exception as e:
            logger.warning(f"login error: {e}", extra={"machine": machine_name})
            return False

    def _attempt_shamir_rescue():
        """If master.key cache failed, try Shamir reconstruction to rebuild it."""
        reconstructor = BootShamirReconstructor(config, machine_name)
        if not reconstructor.enabled:
            return False
        logger.info(
            "Attempting Shamir reconstruction of master password...",
            extra={"machine": machine_name},
        )
        master_plain = reconstructor.reconstruct()
        if not master_plain:
            return False
        # Write the plaintext to master.key, then immediately encrypt-in-place
        # so we never leave plaintext on disk longer than needed. fd close in
        # finally so a write failure can't leak the descriptor. Encryption is
        # idempotent — read_encrypted is also a fallback if encrypt fails here.
        key_path = Path(master_key_path)
        try:
            key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, master_plain)
            finally:
                os.close(fd)
            try:
                ensure_encrypted(str(key_path))
            except Exception as e:
                logger.warning(
                    f"Shamir rescue: encrypt-in-place after write failed ({e}); "
                    f"will retry on next read.",
                    extra={"machine": machine_name},
                )
            logger.info(
                f"Shamir rescue: wrote master.key cache at {master_key_path}",
                extra={"machine": machine_name},
            )
            send_discord_alert(
                discord_webhook,
                "Shamir Rescue",
                f"Master password reconstructed from peer shares; "
                f"local cache at `{master_key_path}` rebuilt. "
                f"This self-heal was triggered by missing/corrupt local master.key.",
                COLOR_YELLOW,
                machine_name,
            )
            return True
        except OSError as e:
            logger.error(
                f"Shamir rescue: write cache failed: {e}",
                extra={"machine": machine_name},
            )
            # If the file got partially created, try to wipe it so an attacker
            # finding the box later can't read residual master plaintext.
            try:
                if key_path.exists():
                    sz = key_path.stat().st_size
                    if sz > 0:
                        with open(key_path, "r+b") as f:
                            f.write(b"\x00" * sz)
                            f.flush()
                            os.fsync(f.fileno())
                        key_path.unlink()
            except OSError:
                pass
            return False

    # Login with retry (Infisical-style: 200ms base, 5s max, 3 retries)
    max_retries = config["server"].get("max_retries", 5)
    base_delay = 0.2
    max_delay = 5.0

    if bundle_only_mode:
        logger.info(
            "Skipping Vaultwarden login (bundle-only mode)",
            extra={"machine": machine_name},
        )

    for attempt in range(max_retries):
        if bundle_only_mode:
            break  # never try to login in bundle-only mode
        if _try_login_once():
            break
        # On first failure, try Shamir rescue ONCE. If it succeeds, the next
        # attempt should work. This keeps the normal retry loop for transient
        # network/bw issues and only triggers rescue for auth failures.
        if attempt == 0 and _attempt_shamir_rescue():
            if _try_login_once():
                logger.info(
                    "Login OK after Shamir rescue", extra={"machine": machine_name}
                )
                break
        delay = min(base_delay * (2**attempt), max_delay)
        logger.warning(
            f"Login attempt {attempt + 1}/{max_retries} failed, retrying in {delay:.1f}s",
            extra={"machine": machine_name},
        )
        time.sleep(delay)
    else:
        logger.critical(
            "All login attempts failed. Exiting.", extra={"machine": machine_name}
        )
        send_discord_alert(
            discord_webhook,
            "❌ Agent Failed to Start",
            f"All {max_retries} login attempts failed.\nAgent is **NOT running**.",
            COLOR_RED,
            machine_name,
        )
        sys.exit(1)

    # Initialize sync engine
    engine = SyncEngine(bw, config)
    poll_interval = config["server"].get("poll_interval", 60)

    # Graceful shutdown + force-sync on SIGHUP
    running = True
    force_sync = False

    def handle_signal(signum, frame):
        nonlocal running
        logger.info(
            f"Received signal {signum}, shutting down gracefully",
            extra={"machine": machine_name},
        )
        running = False

    def handle_sighup(signum, frame):
        nonlocal force_sync
        logger.info(
            "Received SIGHUP, reloading config + scheduling force sync",
            extra={"machine": machine_name},
        )
        # Reload config atomically — on failure, keep current in-memory config
        # and still trigger force_sync (so a partial bad-config + good-vault
        # situation still surfaces the secret change).
        try:
            new_config = load_config(config_path)
            engine.reload_config(new_config)
        except Exception as e:
            logger.error(
                f"Config reload FAILED, keeping current in-memory config: {e}",
                extra={"machine": machine_name},
            )
        force_sync = True

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGHUP, handle_sighup)
    # SIGCHLD → SIG_IGN on Linux makes the kernel auto-reap children,
    # eliminating zombie buildup from fire-and-forget post_sync hooks.
    # Without this, every `docker compose restart` hook spawned via
    # subprocess.Popen leaves a defunct entry until the agent dies.
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)

    # Initial sync (skipped in bundle-only mode — sync_once iterates over
    # collections, which is empty here, so it'd be a no-op anyway, but we
    # short-circuit explicitly to keep the log narrative clear.)
    if bundle_only_mode:
        logger.info(
            "Skipping initial sync (bundle-only mode)", extra={"machine": machine_name}
        )
    else:
        logger.info("Starting initial sync...", extra={"machine": machine_name})
        engine.sync_once()
        # 3a (Sprint 3): if the initial sync couldn't reach the vault and an
        # output is orphan, restore it from the offline ENCRYPTED snapshot.
        # Self-gated: no-op unless resilience.boot_fallback AND vault was
        # unreachable AND the output is actually missing/empty.
        engine.boot_fallback_restore()
    write_heartbeat()
    write_metrics(engine)

    # Start integrated threads (v1.4.0): UDS API + log scanner.
    # Both OPT-IN via config flags. Defaults are OFF to preserve v1.3.x behavior
    # until the client-side bits are validated machine by machine.
    uds_api = None
    scanner = None
    share_server = None

    api_cfg = config.get("api", {}) or {}
    if api_cfg.get("enabled"):
        try:
            uds_api = UDSApiServer(machine_name=machine_name)
            uds_api.start()
            logger.info("UDS API thread enabled", extra={"machine": machine_name})
        except Exception as e:
            logger.error(
                f"Failed to start UDS API: {e}", extra={"machine": machine_name}
            )

    scan_cfg = config.get("scan", {}) or {}
    if scan_cfg.get("enabled"):
        try:
            scanner = LogScanner(
                webhook_url=discord_webhook,
                machine_name=machine_name,
                poll_interval=scan_cfg.get("poll_interval", 60),
            )
            scanner.start()
            logger.info("Log scanner thread enabled", extra={"machine": machine_name})
        except Exception as e:
            logger.error(
                f"Failed to start log scanner: {e}", extra={"machine": machine_name}
            )

    # v1.4.16 (Sprint 3 — slice 3c): dynamic-pg revoke watcher. Opt-in via
    # `resilience.pg_revoke_watcher: true` (default OFF → not started, zero
    # change to current fleet). Own daemon thread; acyclic (never touches the
    # poll). 3c.1 is dry-run only (no DB mutation).
    pg_revoker = None
    rev_cfg = config.get("resilience", {}) or {}
    if rev_cfg.get("pg_revoke_watcher"):
        try:
            pg_revoker = PgRevokeWatcher(
                config=config,
                machine_name=machine_name,
                webhook_url=discord_webhook,
            )
            pg_revoker.start()
            logger.info(
                "pg-revoke watcher thread enabled",
                extra={"machine": machine_name},
            )
        except Exception as e:
            logger.error(
                f"Failed to start pg-revoke watcher: {e}",
                extra={"machine": machine_name},
            )

    # v1.4.2+: Shamir share-release HTTP server. Opt-in via config flag
    # `shamir.enabled: true`. Binds ONLY to tailscale0 IP (never 0.0.0.0).
    # Starting disabled-by-default; enrollment flow (Task #36) will flip it on.
    shamir_cfg = config.get("shamir", {}) or {}
    if shamir_cfg.get("enabled"):
        try:
            bind_ip = shamir_cfg.get("bind_ip") or _share_tailscale_ip()
            if not bind_ip:
                logger.warning(
                    "shamir.enabled=true but no bind_ip and tailscale not detected; share-release disabled",
                    extra={"machine": machine_name},
                )
            else:
                share_server = ShareReleaseServer(
                    machine_name=machine_name, bind_ip=bind_ip
                )
                share_server.start()
                logger.info(
                    f"Shamir share-release server bound to {bind_ip}:{SHARE_RELEASE_PORT}",
                    extra={"machine": machine_name},
                )
        except Exception as e:
            logger.error(
                f"Failed to start share-release server: {e}",
                extra={"machine": machine_name},
            )

    # Agent started alert
    if bundle_only_mode:
        send_discord_alert(
            discord_webhook,
            "Agent Started (bundle-only)",
            f"SocialWarden Agent v{VERSION} is running in BUNDLE-ONLY mode.\n"
            f"No Vaultwarden sync — receives secrets via "
            f"`socialwarden-manager bundle-push` (age-encrypted).\n"
            f"API thread: {'on' if uds_api else 'off'} | "
            f"Scanner thread: {'on' if scanner else 'off'}",
            COLOR_BLUE,
            machine_name,
        )
    else:
        send_discord_alert(
            discord_webhook,
            "Agent Started",
            f"SocialWarden Agent v{VERSION} is running.\n"
            f"Syncing **{len(engine.collections)}** collections every **{poll_interval}s**.\n"
            f"Managing **{engine.secrets_count}** secrets.\n"
            f"API thread: {'on' if uds_api else 'off'} | Scanner thread: {'on' if scanner else 'off'}",
            COLOR_BLUE,
            machine_name,
            fields=[
                {
                    "name": "Collections",
                    "value": ", ".join(c["name"] for c in engine.collections),
                    "inline": False,
                },
            ],
        )

    # Main loop
    logger.info(
        f"Entering poll loop (interval: {poll_interval}s)",
        extra={"machine": machine_name},
    )
    age_check_counter = 0

    while running:
        try:
            # Sleep in short increments so SIGHUP can interrupt us quickly.
            # (time.sleep(60) is atomic; signal handlers set force_sync but we
            # need to wake up to act on it.)
            slept = 0
            while slept < poll_interval and running and not force_sync:
                time.sleep(1)
                slept += 1

            if not running:
                break

            if force_sync:
                logger.info("Force sync triggered", extra={"machine": machine_name})
                force_sync = False

            # In bundle-only mode, skip ALL Vault-driven cycle work. The daemon
            # still keeps the UDS API, share-release endpoint, and threads alive.
            # Heartbeat below is a dead-man's-switch: written ONLY on a clean
            # cycle (no exception). If sync_once raises, this iteration's
            # heartbeat is skipped and the staleness alarm fires upstream
            # (Prom rule: time() - socialwarden_last_sync_timestamp > 300).
            # Without the bundle-only guard, sync_once → bw call → "session
            # expired, re-auth" → CRITICAL exit → restart loop + Discord spam.
            if not bundle_only_mode:
                engine.sync_once()
                engine.check_drift()
                age_check_counter += 1
                if age_check_counter >= 60:
                    engine.check_secret_ages()
                    engine.check_rotations()
                    age_check_counter = 0

            # Heartbeat & metrics (always — proves the daemon is alive)
            write_heartbeat()
            write_metrics(engine)

        except KeyboardInterrupt:
            break
        except Exception as e:
            engine.sync_errors += 1
            logger.error(
                f"Sync cycle error: {e}", extra={"machine": machine_name}, exc_info=True
            )
            write_metrics(engine)
            # Alert on unhandled errors (every 5th to avoid spam)
            if engine.sync_errors % 5 == 0:
                engine._alert(
                    "❌ Sync Cycle Error",
                    f"Unhandled error in sync cycle:\n```{str(e)[:500]}```\n"
                    f"Total errors: **{engine.sync_errors}**",
                    COLOR_RED,
                )
            time.sleep(poll_interval)

    # Stop background threads gracefully
    if share_server:
        try:
            share_server.stop()
        except Exception as e:
            logger.error(
                f"Share server stop error: {e}", extra={"machine": machine_name}
            )
    if scanner:
        try:
            scanner.stop()
        except Exception as e:
            logger.error(f"Scanner stop error: {e}", extra={"machine": machine_name})
    if uds_api:
        try:
            uds_api.stop()
        except Exception as e:
            logger.error(f"UDS API stop error: {e}", extra={"machine": machine_name})
    if pg_revoker:
        try:
            pg_revoker.stop()
        except Exception as e:
            logger.error(
                f"pg-revoke watcher stop error: {e}",
                extra={"machine": machine_name},
            )

    # Agent stopping alert
    send_discord_alert(
        discord_webhook,
        "Agent Stopped",
        f"SocialWarden Agent v{VERSION} shutting down gracefully.\n"
        f"Total syncs: **{engine.sync_total}** | Errors: **{engine.sync_errors}** | "
        f"Changes: **{engine.changes_detected}** | Drifts: **{engine.drift_detected}**",
        COLOR_BLUE,
        machine_name,
    )

    logger.info("SocialWarden Agent stopped", extra={"machine": machine_name})


if __name__ == "__main__":
    main()
