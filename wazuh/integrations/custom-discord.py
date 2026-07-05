#!/usr/bin/env python3
"""custom-discord — Wazuh → Discord integration, standard-library only.

Why not slack.py / the bundled OSSEC integrations?
  * The bundled `slack.py` requires `requests`, which is not installed in
    the official Wazuh manager image. Result: every alert exited cleanly
    with rc=0 having sent nothing. Silent failure.
  * `requests` is overkill for a tiny POST. stdlib `urllib` + `ssl` do
    the job and we keep the integration trivially auditable.

Wiring (in /var/ossec/etc/ossec.conf):
    <integration>
      <name>custom-discord</name>
      <hook_url>https://discord.com/api/webhooks/.../.../slack</hook_url>
      <level>12</level>
      <alert_format>json</alert_format>
    </integration>

The wrapper `custom-discord` (shell) just execs this script with the
arguments Wazuh hands it: alert_file webhook ?? integration_name.

Friendly host names: many fleets number hosts as `host-N`. The
HOST_ALIASES map below turns those into the labels you want to see
in Discord (so an alert reads "Host: web-1" instead of "host-1").
Edit it to taste; remove the map to keep the raw label.
"""
from __future__ import annotations

import json
import ssl
import sys
import urllib.request
from datetime import datetime, timezone


HOST_ALIASES: dict[str, str] = {
    # "host-1": "web-1",
    # "host-2": "api-1",
    # …
}


def friendly_host(raw: str) -> str:
    return HOST_ALIASES.get(raw, raw or "(unknown host)")


def build_payload(alert: dict) -> dict:
    """Translate a Wazuh alert dict into a Slack-compatible JSON payload
    (Discord accepts Slack format via the /slack suffix on the webhook)."""
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    location = alert.get("location", "?")
    level = rule.get("level", "?")
    title = rule.get("description", "Wazuh alert")
    host = friendly_host(agent.get("name", ""))
    ts = alert.get("timestamp", datetime.now(timezone.utc).isoformat())

    full_log = (alert.get("full_log") or "").strip()
    if len(full_log) > 1500:
        full_log = full_log[:1500] + "…"

    text = (
        f"**[level {level}] {title}**\n"
        f"Host: `{host}`\n"
        f"Location: `{location}`\n"
        f"When: `{ts}`\n"
    )
    if full_log:
        text += f"```\n{full_log}\n```"

    return {"text": text}


def post(webhook: str, payload: dict, timeout: float = 5.0) -> int:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "custom-discord/1.0"},
        method="POST",
    )
    # Verify TLS — never disable it. The system trust store on Wazuh
    # images already has the right roots; if it doesn't, fix the image.
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status
    except Exception as e:  # noqa: BLE001
        # Fail-safe: never crash, never block the manager. Print to stderr
        # so the operator sees the issue in journalctl -u wazuh-manager.
        print(f"custom-discord: post failed: {e}", file=sys.stderr)
        return 0


def main() -> int:
    # Wazuh invokes integrations with: <alert.json> <webhook> '' <name>
    if len(sys.argv) < 3:
        print("usage: custom-discord <alert.json> <webhook> [api-key-unused] [name]", file=sys.stderr)
        return 2

    alert_path, webhook = sys.argv[1], sys.argv[2]
    try:
        with open(alert_path, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"custom-discord: cannot read alert {alert_path}: {e}", file=sys.stderr)
        return 0  # don't fail the manager

    status = post(webhook, build_payload(alert))
    # Discord returns 204 No Content on success
    return 0 if status in (200, 204) else 0  # fail-safe


if __name__ == "__main__":
    sys.exit(main())
