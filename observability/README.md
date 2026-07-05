# SOCials-Observability

Self-hosted **3-pillar observability stack** — Prometheus (metrics) + Loki (logs) + Tempo (traces) — wired into Grafana with cross-correlation and trace-to-logs / trace-to-metrics jumps. Promtail ships container logs from each fleet host.

## What's in the box

| Component | Image | Purpose |
|---|---|---|
| `prometheus` | `prom/prometheus:v3.11.1` | Metrics TSDB (15d retention, remote-write enabled for Tempo) |
| `loki` | `grafana/loki:3.6.10` | Log aggregation via OTLP, 7d retention, single-tenant |
| `tempo` | `grafana/tempo:2.10.3` | Distributed traces, OTLP gRPC ingestion, generates RED metrics from spans |
| `grafana` | `grafana/grafana:12.4.2` | Visualization with provisioned datasources + correlations |
| `blackbox-exporter` | `prom/blackbox-exporter:v0.28.0` | HTTP healthchecks (acts as a proxy for app liveness probes) |
| `node-exporter` | `prom/node-exporter:v1.11.0` | Host metrics from the monitor node itself |
| `cadvisor` | `gcr.io/cadvisor/cadvisor:v0.55.1` | Container metrics from the monitor node itself |
| `promtail` (separate compose) | `grafana/promtail:3.6.10` | Per-host log shipper — deploy on every fleet host |

## Quick start (monitor host)

```bash
git clone https://github.com/Maikol-Romero/SOCials-Observability.git
cd SOCials-Observability

cp .env.example .env
# edit .env — set MONITOR_IP (your VPN address), GF_ADMIN_PASSWORD, DISCORD webhooks

cp prometheus/prometheus.yml.example prometheus/prometheus.yml
# edit prometheus.yml — add per-host jobs pointing at your fleet's exporters

docker compose up -d
```

Grafana available at `http://<MONITOR_IP>:${GF_HTTP_PORT}/` (default 3001). The provisioned datasources (Prometheus, Loki, Tempo) are pre-wired with cross-correlations.

## Per-host log shipping

On every fleet host, deploy promtail:

```bash
cd SOCials-Observability/promtail
cp .env.example .env
# edit .env — set LOKI_HOST (monitor's VPN IP) and HOSTNAME (this host's label)

docker compose up -d
```

The compose file expects the network `soc-monitor-net` to already exist (created by the main stack). For hosts not on the same Docker network, swap to `network_mode: host` and update LOKI_HOST to use the monitor's IP.

## Provisioned dashboards

`grafana/dashboards/` ships 2 starter dashboards focused on infrastructure and app-error visibility. Domain-specific dashboards (call logs, ML pipelines, custom telemetry) belong in your private fork — this repo is intentionally generic.

| Dashboard | Purpose |
|---|---|
| `dashboard-container-logs.json` | App-error log volume per host, top error-producing containers, Promtail health |
| `dashboard-dffidv64tyltse.json` | Multi-host container health grid: CPU / RAM / disk / Redis / Postgres cache-hit + per-container resource breakdown |

Note: dashboards reference generic instance labels (`host-1`, `host-2`, …). To match your real fleet, either:
- Rename your prometheus instance labels to match, or
- Edit the queries in each dashboard JSON to your naming.

## Trace ↔ logs ↔ metrics correlation

The provisioned `datasources.yaml` wires:

- **Prometheus → Tempo**: exemplars carry trace IDs, click-through opens the trace
- **Tempo → Loki**: filter logs by trace/span ID and `service.name`
- **Tempo → Prometheus**: trace-derived RED metrics (rate, errors, duration) per span dimension
- **Loki → Tempo**: regex `traceID=(\\w+)` extracts trace IDs from log lines for one-click jump

All three are pre-configured — no manual click-through setup needed.

## Hardening notes

- **Never commit `.env` or `prometheus/prometheus.yml`** — both contain fleet topology and secrets (covered by `.gitignore`).
- All ports bind to `${MONITOR_IP}` — set this to your VPN address so dashboards are not exposed to the public internet.
- Loki ships with `auth_enabled: false` (single-tenant). Enable Loki's HTTP basic auth or fronted via nginx with auth if you go multi-tenant.
- Grafana ships with `GF_USERS_ALLOW_SIGN_UP=false` and `GF_AUTH_ANONYMOUS_ENABLED=false`. Add SSO / OAuth via env vars if needed.

## License

MIT — see [LICENSE](./LICENSE).
