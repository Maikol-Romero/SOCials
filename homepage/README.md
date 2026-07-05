# SOCials-Homepage

[gethomepage/homepage](https://github.com/gethomepage/homepage) configured as the **single landing page** for a self-hosted observability + security stack. One tab to reach Grafana, Prometheus, Wazuh, AdGuard, Trivy, Loki, Tempo and your internal apps — with live status widgets pulling directly from each backend.

## What you get

- **Service tiles** with status indicators (Grafana ↔ Prometheus widgets show real metrics, not just links)
- **Bookmarks panel** with curated docs / external admin URLs
- **Single greeting + datetime** widget on the dashboard
- **Container telemetry** via Docker socket (`status: dot` shows up/down per service)
- All ports bind to `${MONITOR_IP}` so the homepage is only reachable through your VPN mesh

## Quick start

```bash
git clone https://github.com/Maikol-Romero/SOCials-Homepage.git
cd SOCials-Homepage

cp .env.example .env
# edit .env — MONITOR_IP, HOMEPAGE_ALLOWED_HOSTS, GF_ADMIN_PASSWORD (must match your Grafana stack)

# Edit config/services.yaml to point at YOUR domains. Example placeholder uses *.example.com.
$EDITOR config/services.yaml

docker compose up -d
```

Visit `http://${MONITOR_IP}:${HOMEPAGE_PORT}` (default port 8082).

## Customizing

The shipped configuration uses `*.example.com` placeholders. Edit:

| File | What to change |
|---|---|
| `config/services.yaml` | `href:` URLs for each tile, widget URLs (point at your stack's hostnames or container names if on the same network) |
| `config/bookmarks.yaml` | Replace / extend the documentation links |
| `config/widgets.yaml` | Greeting text |
| `config/settings.yaml` | Title, theme color, layout |

The homepage container expects `soc-monitor-net` to exist (created by your observability stack). If your stack uses a different network name, edit `docker-compose.yml`'s `networks:` block.

## Widgets that need credentials

- **Grafana widget** uses `HOMEPAGE_VAR_GRAFANA_PASS` (read from `.env` `GF_ADMIN_PASSWORD`). The widget calls Grafana's API to render dashboard counts — credentials never leave the bridge between containers.
- **Prometheus widget** is unauthenticated by design (assumes Prometheus is on a private network).

## Hardening notes

- Pin `image:` to a specific Homepage version in production, not `:latest` — the upstream image moves fast.
- Mount `/var/run/docker.sock:ro` so Homepage can read container statuses but not manipulate them.
- `HOMEPAGE_ALLOWED_HOSTS` is enforced by Homepage and rejects requests for any other Host header — keep this tight.

## License

MIT — see [LICENSE](./LICENSE).
