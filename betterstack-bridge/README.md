# SOCials-BetterStack-Bridge

Bridge between **Grafana / BetterStack alerts** and a **BetterStack public status page**, with auto-generated incident messages via Claude (with deterministic fallbacks). All routing maps and message templates live in a single JSON config — no service-specific names hardcoded in the script.

Two modes:

- **Interactive CLI** — full menu: create incident, update lifecycle, resolve, schedule maintenance, end maintenance, view active incidents, view history.
- **Webhook server** — receives outbound webhooks from Grafana and BetterStack, deduplicates, creates / resolves status-page incidents automatically.

## Why this exists

A status page should reflect reality without operator effort during an incident. Grafana already knows what's wrong; BetterStack already runs uptime probes. This bridge connects both signals to the public-facing status page so customers see "something's wrong" within seconds, not when someone notices and writes a manual update.

## Features

| Feature | Implementation |
|---|---|
| Config-driven service map | All service keys, display names, routing maps and message templates live in `services.json`. The Python script ships with no service-specific defaults. |
| AI-generated messages | Calls `claude` CLI with a configurable prompt + language; falls back to deterministic templates if Claude is unavailable |
| Multi-resource incidents | Single incident can affect any combination of services simultaneously (e.g. API + Database) |
| Lifecycle updates | Investigating → Identified → Fixing → Monitoring → Resolved (with auto-generated transition messages) |
| Maintenance windows | Schedule, update, extend, end. Auto-cleanup when end time passes |
| Inbound auth | `BS_INBOUND_TOKEN` required on `/betterstack` endpoint (header `X-Bridge-Token` or `?token=` query param) |
| Probe / smoke filtering | Configurable substrings (default: `test`, `smoke`, `probe`, `synthetic`, `dummy`, `ignore`) — names containing any are dropped |
| State persistence | `~/.betterstack-bridge/state.json` survives restarts; in-memory `active_reports` rebuilt on boot |

## Quick start

```bash
git clone https://github.com/Maikol-Romero/SOCials-BetterStack-Bridge.git
cd SOCials-BetterStack-Bridge

# 1. Copy and edit the service config (this is the file that defines what services exist)
cp services.example.json services.json
$EDITOR services.json
# - Edit "services": your service keys + display names
# - Edit "grafana_map": map your Grafana label substrings to service keys
# - Edit "betterstack_monitor_map": map BS monitor name substrings to service keys
# - Optionally translate "fallback_messages" / "titles" / "claude.prompt_template" to your language
# - Set "language" so Claude knows what language to write in
# - Set "timezone_offset_hours" for timestamps in the UI / history

# 2. Copy and fill the env file (secrets + BS resource IDs)
cp .env.example .env
$EDITOR .env

# 3. (Optional) install Claude CLI for AI messages — script falls back to templates if missing.

# Interactive mode
python3 betterstack-bridge.py

# Webhook server mode (default port 8085)
python3 betterstack-bridge.py serve
```

## Wiring

### Grafana → bridge (alert webhook)

In Grafana → Alerting → Contact points → Webhook:
- URL: `http://<bridge-host>:8085/`
- HTTP Method: `POST`
- Optional: bind-only-to-VPN by setting bridge `LISTEN_HOST` and only opening that port to the VPN.

The bridge looks at each alert's `labels.container` / `labels.instance` / `labels.job` and routes via `grafana_map` in `services.json`.

### BetterStack → bridge (incident webhook)

In BetterStack → your monitor / heartbeat → Notifications → Outbound Webhook:
- URL: `http://<bridge-host>:8085/betterstack`
- Header: `X-Bridge-Token: <BS_INBOUND_TOKEN>`
- Events: `incident_started`, `incident_resolved`

Names route to status-page resources via `betterstack_monitor_map` in `services.json` (substring match, case-insensitive).

## Configuring `services.json`

Everything domain-specific lives in this file:

```json
{
  "language": "english",
  "timezone_offset_hours": 0,
  "services": {
    "api": "API",
    "web": "Website"
  },
  "grafana_map": { "nginx": "web", "api": "api" },
  "betterstack_monitor_map": [["api", "api"], ["nginx", "web"]],
  "titles": { "downtime": "Outage in {s}" },
  "fallback_messages": { "downtime": "We are experiencing an outage in {s}." },
  "claude": {
    "model": "claude-haiku-4-5-20251001",
    "timeout_s": 20,
    "prompt_template": "Status page... in {language}..."
  }
}
```

The shipped `services.example.json` is a generic 5-category template (`api`, `web`, `worker`, `database`, `queue`) in English. Translate / replace as needed — the Python script reads everything from this file at startup.

For each service key in `services.json`, the script reads its BS resource ID from env var `BS_RESOURCE_<KEY_UPPER>`. Add matching entries to `.env`.

## Security notes

- **`BS_INBOUND_TOKEN` is required.** With it empty, every `/betterstack` POST returns 401. This is by design — leaking the URL of a status-page bridge without auth is a public-status-page DoS waiting to happen.
- Generate the token with: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`
- Bind `LISTEN_HOST` to your VPN IP (not `0.0.0.0`) when running in production.
- The `BETTERSTACK_TOKEN` (Status pages scope) lets the bridge create / update / resolve incidents on the public status page — treat it like any other production secret.

## License

MIT — see [LICENSE](./LICENSE).
