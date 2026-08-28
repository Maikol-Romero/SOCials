"""Centralized configuration: one socials.yml to rule all .env files."""

from __future__ import annotations

import os
from typing import Any

import yaml

from .utils import error, warn, info, project_root

CONFIG_NAME = "socials.yml"

_DEFAULTS: dict[str, Any] = {
    "monitor": {
        "ip": "127.0.0.1",
        "name": "socials-monitor",
    },
    "grafana": {
        "user": "admin",
        "password": "admin",
        "port": 3001,
        "root_url": "http://localhost:3001/",
    },
    "prometheus": {
        "port": 9090,
        "retention": "15d",
    },
    "loki": {
        "port": 3100,
        "retention": "168h",
    },
    "tempo": {
        "http_port": 3200,
        "grpc_port": 4317,
    },
    "dns": {
        "port": 53,
        "web_port": 2999,
    },
    "homepage": {
        "port": 8082,
        "allowed_hosts": "",
    },
    "wazuh": {
        "indexer_password": "",
        "indexer_java_opts": "-Xms512m -Xmx512m",
        "api_user": "wazuh-wui",
        "api_password": "",
        "dashboard_password": "",
        "dashboard_port": 5601,
    },
    "patroni": {
        "postgres_password": "",
        "replication_password": "",
        "node_name": "node-1",
        "s3_bucket": "",
    },
    "trivy": {
        "discord_webhook": "",
    },
    "betterstack": {
        "token": "",
        "status_page_id": "",
        "inbound_token": "",
        "resources": {},
    },
    "discord": {
        "webhook_url": "",
        "webhook_summary": "",
        "webhook_staging": "",
    },
    "agent_exporters": {
        "node_exporter_port": 9100,
        "cadvisor_port": 8080,
        "pg_exporter_port": 9187,
        "redis_exporter_port": 9121,
        "otel_metrics_port": 8889,
        "gpu_exporter_port": 9400,
    },
}

_REQUIRED_KEYS = [
    "monitor.ip",
]

_cached: dict[str, Any] | None = None


def config_path() -> str:
    return os.path.join(project_root(), CONFIG_NAME)


def load(path: str | None = None) -> dict[str, Any]:
    """Load socials.yml, merge with defaults, validate required keys."""
    global _cached
    if _cached is not None and path is None:
        return _cached

    p = path or config_path()
    user_cfg: dict[str, Any] = {}

    if os.path.exists(p):
        with open(p) as f:
            raw = yaml.safe_load(f)
            if isinstance(raw, dict):
                user_cfg = raw
    else:
        if path is None:
            warn(f"No {CONFIG_NAME} found — using defaults. Run: socials config init")

    merged = _deep_merge(_DEFAULTS, user_cfg)
    _apply_env_overrides(merged)

    missing = _check_required(merged)
    if missing:
        for key in missing:
            error(f"Missing required config: {key}")

    if path is None:
        _cached = merged
    return merged


def reload() -> dict[str, Any]:
    """Force reload from disk (clears cache)."""
    global _cached
    _cached = None
    return load()


def get(key: str, default: Any = None) -> Any:
    """Dot-notation access: get('grafana.port') → 3001."""
    cfg = load()
    parts = key.split(".")
    node: Any = cfg
    for part in parts:
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return default
    return node


def _deep_merge(defaults: dict, overrides: dict) -> dict:
    result = {}
    for key in set(list(defaults.keys()) + list(overrides.keys())):
        if key in overrides and key in defaults:
            if isinstance(defaults[key], dict) and isinstance(overrides[key], dict):
                result[key] = _deep_merge(defaults[key], overrides[key])
            else:
                result[key] = overrides[key]
        elif key in overrides:
            result[key] = overrides[key]
        else:
            result[key] = defaults[key]
    return result


def _apply_env_overrides(cfg: dict[str, Any]) -> None:
    """Allow SOCIALS_* env vars to override config values.

    SOCIALS_MONITOR_IP → cfg['monitor']['ip']
    SOCIALS_GRAFANA_PORT → cfg['grafana']['port']
    """
    prefix = "SOCIALS_"
    for env_key, env_val in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        parts = env_key[len(prefix):].lower().split("_", 1)
        if len(parts) != 2:
            continue
        section, key = parts
        if section in cfg and isinstance(cfg[section], dict):
            existing = cfg[section].get(key)
            if isinstance(existing, int):
                try:
                    cfg[section][key] = int(env_val)
                except ValueError:
                    cfg[section][key] = env_val
            elif isinstance(existing, bool):
                cfg[section][key] = env_val.lower() in ("1", "true", "yes")
            else:
                cfg[section][key] = env_val


def _check_required(cfg: dict[str, Any]) -> list[str]:
    missing = []
    for dotkey in _REQUIRED_KEYS:
        parts = dotkey.split(".")
        node: Any = cfg
        for part in parts:
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                missing.append(dotkey)
                break
        else:
            if not node:
                missing.append(dotkey)
    return missing


ENV_TEMPLATES: dict[str, list[tuple[str, str]]] = {
    "observability/.env": [
        ("MONITOR_IP", "monitor.ip"),
        ("GF_ADMIN_USER", "grafana.user"),
        ("GF_ADMIN_PASSWORD", "grafana.password"),
        ("GF_HTTP_PORT", "grafana.port"),
        ("GF_SERVER_ROOT_URL", "grafana.root_url"),
        ("PROMETHEUS_PORT", "prometheus.port"),
        ("PROMETHEUS_RETENTION", "prometheus.retention"),
        ("LOKI_PORT", "loki.port"),
        ("LOKI_RETENTION", "loki.retention"),
        ("TEMPO_HTTP_PORT", "tempo.http_port"),
        ("TEMPO_GRPC_PORT", "tempo.grpc_port"),
        ("DISCORD_WEBHOOK_URL", "discord.webhook_url"),
        ("DISCORD_WEBHOOK_SUMMARY", "discord.webhook_summary"),
        ("DISCORD_WEBHOOK_STAGING", "discord.webhook_staging"),
    ],
    "wazuh/.env": [
        ("MONITOR_IP", "monitor.ip"),
        ("INDEXER_PASSWORD", "wazuh.indexer_password"),
        ("INDEXER_JAVA_OPTS", "wazuh.indexer_java_opts"),
        ("WAZUH_API_USER", "wazuh.api_user"),
        ("WAZUH_API_PASSWORD", "wazuh.api_password"),
        ("DASHBOARD_PASSWORD", "wazuh.dashboard_password"),
    ],
    "dns/.env": [
        ("MONITOR_IP", "monitor.ip"),
        ("DNS_PORT", "dns.port"),
        ("DNS_WEB_PORT", "dns.web_port"),
    ],
    "homepage/.env": [
        ("MONITOR_IP", "monitor.ip"),
        ("HOMEPAGE_ALLOWED_HOSTS", "homepage.allowed_hosts"),
        ("HOMEPAGE_PORT", "homepage.port"),
        ("GF_ADMIN_PASSWORD", "grafana.password"),
        ("GF_HTTP_PORT", "grafana.port"),
        ("PROMETHEUS_PORT", "prometheus.port"),
        ("DNS_WEB_PORT", "dns.web_port"),
        ("WAZUH_DASHBOARD_PORT", "wazuh.dashboard_port"),
    ],
    "trivy/.env": [
        ("DISCORD_WEBHOOK_URL", "trivy.discord_webhook"),
        ("MONITOR_IP", "monitor.ip"),
    ],
    "patroni/.env": [
        ("POSTGRES_PASSWORD", "patroni.postgres_password"),
        ("REPLICATION_PASSWORD", "patroni.replication_password"),
        ("DISCORD_WEBHOOK", "discord.webhook_url"),
        ("S3_BUCKET", "patroni.s3_bucket"),
        ("PATRONI_NODE_NAME", "patroni.node_name"),
    ],
    "betterstack-bridge/.env": [
        ("BETTERSTACK_TOKEN", "betterstack.token"),
        ("BETTERSTACK_STATUS_PAGE_ID", "betterstack.status_page_id"),
        ("BS_INBOUND_TOKEN", "betterstack.inbound_token"),
    ],
}


def generate_env_files(cfg: dict[str, Any] | None = None, dry_run: bool = False) -> list[str]:
    """Generate component .env files from the central config. Returns list of paths written."""
    if cfg is None:
        cfg = load()

    root = project_root()
    written: list[str] = []

    for rel_path, mappings in ENV_TEMPLATES.items():
        lines: list[str] = []
        for env_key, config_key in mappings:
            val = get(config_key)
            if val is None:
                val = ""
            lines.append(f"{env_key}={val}")

        env_path = os.path.join(root, rel_path)

        if dry_run:
            info(f"Would write {rel_path} ({len(lines)} keys)")
            continue

        os.makedirs(os.path.dirname(env_path), exist_ok=True)

        if os.path.exists(env_path):
            with open(env_path) as f:
                existing = f.read()
            new_content = "\n".join(lines) + "\n"
            if existing == new_content:
                info(f"{rel_path}: unchanged")
                continue

        with open(env_path, "w") as f:
            f.write("\n".join(lines) + "\n")

        try:
            os.chmod(env_path, 0o600)
        except (PermissionError, OSError):
            pass

        written.append(rel_path)
        info(f"{rel_path}: written ({len(lines)} keys)")

    return written


def init_config() -> str:
    """Create a starter socials.yml from the example. Returns path."""
    p = config_path()
    if os.path.exists(p):
        warn(f"{CONFIG_NAME} already exists at {p}")
        return p

    example = os.path.join(project_root(), f"{CONFIG_NAME}.example")
    if os.path.exists(example):
        import shutil
        shutil.copy2(example, p)
        info(f"Created {CONFIG_NAME} from example")
    else:
        content = yaml.dump(_DEFAULTS, default_flow_style=False, sort_keys=False)
        with open(p, "w") as f:
            f.write(f"# SOCials configuration — edit values, then run: socials env-gen\n\n")
            f.write(content)
        info(f"Created {CONFIG_NAME} with defaults")

    return p
