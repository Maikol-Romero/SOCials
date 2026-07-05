# SOCials

Self-hosted **SOC + observability + DNS + secrets** stack — 8 components wired together, deployable as a unit or piecemeal. Built on Docker, designed for a small fleet of Linux hosts behind a VPN mesh (Tailscale, WireGuard, or any private network you trust).

Each component lives in its own subdirectory and can be deployed standalone — see the per-component READMEs for details. This top-level repo unifies them with a shared Docker network, shared `.env`, and a guided installer (`setup.sh`).

## Components

| Component | Subdir | What it does |
|---|---|---|
| **AdGuard DNS** | [`dns/`](./dns) | Internal DNS resolver — DoH upstream, ad/tracking blocklists, rewrites for VPN-mesh service hostnames |
| **Observability** | [`observability/`](./observability) | Prometheus + Loki + Tempo + Grafana with provisioned cross-correlation (trace ↔ logs ↔ metrics) |
| **Wazuh SIEM** | [`wazuh/`](./wazuh) | Manager + Indexer + Dashboard, with FIM, log analysis, vulnerability detection |
| **Trivy scanner** | [`trivy/`](./trivy) | Host vulnerability scanner — runs Trivy across the fleet via SSH, React dashboard with Claude-generated CVE explanations |
| **Warden secrets** | [`warden/`](./warden) | Bitwarden-backed secrets manager for fleets, with Shamir secret-share recovery and ed25519 peer auth |
| **Patroni HA** | [`patroni/`](./patroni) | Postgres High-Availability cluster (Patroni + pgbouncer + S3 backups + integrity checks + automatic switchback) |
| **Homepage** | [`homepage/`](./homepage) | Single landing page with status widgets pulling from Grafana / Prometheus and links to every internal admin URL |
| **BetterStack Bridge** | [`betterstack-bridge/`](./betterstack-bridge) | Bridges Grafana / BetterStack alerts to a public BetterStack status page, with config-driven service routing and AI-generated incident messages |

## Architecture at a glance

```
                        ┌─────────────────────────┐
                        │   VPN mesh (Tailscale,  │
                        │    WireGuard, ...)      │
                        └──────────┬──────────────┘
                                   │
   ┌───────────────┬───────────────┼───────────────┬──────────────┐
   │               │               │               │              │
┌──▼───┐    ┌──────▼──────┐  ┌─────▼─────┐  ┌──────▼──────┐  ┌────▼────┐
│ DNS  │    │   Wazuh     │  │  Trivy    │  │   Warden    │  │ Patroni │
│      │    │  SIEM       │  │ scanner   │  │  secrets    │  │  HA DB  │
└──┬───┘    └──────┬──────┘  └─────┬─────┘  └──────┬──────┘  └────┬────┘
   │               │               │               │              │
   └───────────────┴───────┬───────┴───────────────┴──────────────┘
                           │
                  ┌────────▼────────┐
                  │  Observability  │ ◄── shipped logs / metrics / traces
                  │   (Prom+Loki+   │     from every component
                  │    Tempo+Graf)  │
                  └────────┬────────┘
                           │
                  ┌────────▼────────┐         ┌─────────────────┐
                  │    Homepage     │         │   BetterStack   │
                  │  (landing UI)   │ ◄──────►│     Bridge      │
                  └─────────────────┘         │ (alerts → page) │
                                              └─────────────────┘
```

## Quick start

```bash
git clone https://github.com/Maikol-Romero/SOCials.git
cd SOCials

# Guided wizard — picks components, generates shared network, runs each subdir's deploy
./setup.sh
```

Or deploy individual components by `cd`-ing into the subdirectory and following the component-specific README.

## Top-level files

| File | Purpose |
|---|---|
| `setup.sh` | Interactive installer — picks components, creates the shared `soc-monitor-net` Docker network, delegates to each component's compose |
| `.env.example` | Consolidated env vars used across components (`MONITOR_IP`, ports, BetterStack token, Discord webhooks, etc.). Each component still has its own `.env.example` with component-specific vars. |
| `.gitignore` | Inherits each component's gitignore patterns + ignores top-level secrets |

## Networks

The Docker bridge network `soc-monitor-net` is the shared backplane — Homepage queries Grafana/Prometheus, Promtail ships to Loki, BetterStack Bridge reads Grafana alerts, etc. `setup.sh` creates it once before anything else. Each component's `docker-compose.yml` joins it with `external: true`.

## Recommended deploy order

If installing manually instead of via `setup.sh`:

1. **DNS** first — gives you `*.example.com` rewrites for everything else
2. **Observability** — most other components ship metrics/logs to it
3. **Wazuh** — independent SIEM, no dependencies
4. **Trivy** — independent scanner
5. **Warden** — secrets manager, used by everything that needs credentials
6. **Patroni** — Postgres HA, deploy alongside Warden if your apps need DB
7. **Homepage** — depends on Observability being up (widgets will show "down" until then)
8. **BetterStack Bridge** — needs your BetterStack account + Grafana alerts wired

## Hardening defaults

- Every component binds to `${MONITOR_IP}` (your VPN address) — nothing is exposed publicly
- All tokens, passwords, webhook URLs are placeholders in `.example` files; nothing real is committed
- Each component ships with `.gitignore` rules that exclude `*.env`, runtime state, and inventory
- Provisioning files (Grafana, Loki, etc.) use `service.account` env-var references, not literals

## License

MIT — see [LICENSE](./LICENSE). Each subdirectory also carries its own LICENSE for clarity if components are extracted.
