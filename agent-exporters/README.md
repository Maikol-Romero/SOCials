# SOCials-Agent-Exporters

Drop-in **observability + security agent** for a self-hosted SOC fleet. Installs on each production server and exposes metrics, logs and traces to a central monitor host over a VPN mesh — plus optionally enrolls a Wazuh agent for HIDS / FIM / CVE checks.

This is the *client* side of the SOCials SOC stack. The monitor side (Prometheus, Loki, Tempo, Grafana, Wazuh manager, Better Stack bridge) lives in its companion repos.

## What's in the box

| Component | Image | Purpose |
|---|---|---|
| `node-exporter` | `prom/node-exporter:v1.11.0` | Host CPU / memory / disk / systemd unit metrics |
| `cadvisor` | `gcr.io/cadvisor/cadvisor:v0.55.1` | Per-container CPU / memory / network metrics |
| `postgres-exporter` | `prometheuscommunity/postgres-exporter:v0.19.1` | PostgreSQL stats (only if a local DB is configured) |
| `redis-exporter` | `oliver006/redis_exporter:v1.82.0` | Redis stats (only if a local Redis is detected) |
| `otel-collector` | `otel/opentelemetry-collector-contrib:0.120.0` | Receives OTLP traces / logs / metrics from local apps and forwards to Tempo + Loki + Prometheus |
| `nvidia-dcgm-exporter` | `nvidia/dcgm-exporter:3.3.5-3.4.0-ubuntu22.04` | GPU utilisation, memory and SM clock metrics (auto-installed when `nvidia-smi` is present) |
| `wazuh-agent` | apt package, version 4.x | HIDS, FIM, rootcheck, CVE detection (optional, enrolled to manager via `WAZUH_MANAGER` env var) |

The installer **auto-detects** what to run on a given host: no DB → no postgres-exporter, no NVIDIA driver → no DCGM, OTEL collector already running → not duplicated.

## Quick start

```bash
git clone https://github.com/Maikol-Romero/SOCials-Agent-Exporters.git
cd SOCials-Agent-Exporters

# 1. VPN must already be up. Tailscale is the assumed mesh; swap for WireGuard/Nebula
#    by editing the `tailscale ip -4` block in install.sh.

# 2. Stage the install dir on the target host
mkdir -p ~/socials-monitoring
cp docker-compose.yml otel-collector-config.yaml ~/socials-monitoring/
cp .env.example                                  ~/socials-monitoring/.env
# edit ~/socials-monitoring/.env if you have a local PostgreSQL or non-default ports

# 3. Run the installer with the monitor host's VPN IP
./install.sh 100.64.0.1
```

The installer wires `${TAILSCALE_IP}` into every port binding, so exporters are **only** reachable from inside the VPN mesh — never on `0.0.0.0`.

## How it ports to your fleet

* **VPN mesh.** Tailscale by default. To use WireGuard / Nebula / ZeroTier, replace the `tailscale ip -4` line in `install.sh` with whatever resolves the local mesh IP for your tunnel.
* **Wazuh.** Drop the entire Wazuh block (steps 7 + 8 in `install.sh`) if you don't want HIDS — the exporters will still work standalone.
* **GPU.** The DCGM exporter only deploys when `nvidia-smi` is on `$PATH` and a Docker runtime with `--gpus all` is configured. CPU-only fleets simply skip it.
* **DB / Redis detection.** Postgres / Redis exporters spin up only when the installer finds matching env vars in `.env` or a running Redis container. To force-enable them, populate `DB_USER` / `DB_PASSWORD` / `DB_HOST` / `DB_NAME` in `.env`.
* **Inventory.** Use `inventory.json.example` as a template for the orchestrator on the monitor side — it tells the master `setup.sh` which hosts to SSH into and what role each one plays.

## OTEL Collector pipeline

`otel-collector-config.yaml` defines a single 3-pipeline collector:

```
  app (any language) ── OTLP ──┐
                              │
                            collector ── traces  ──> Tempo  (gRPC, monitor:4317)
                                       ── logs    ──> Loki   (HTTP, monitor:3100/otlp)
                                       ── metrics ──> Prometheus scrape (port 8889)
```

`PLACEHOLDER_HOSTNAME` and `PLACEHOLDER_MONITOR_IP` are rewritten in-place by `install.sh`. The collector batches every 5s, caps at 256 MiB heap, and tags every record with `host.name=<hostname>` and `deployment.environment=production`.

## Hardening notes

- **Bind to the VPN, not `0.0.0.0`.** Every published port in `docker-compose.yml` is prefixed with `${TAILSCALE_IP}:` so a mis-configured firewall won't expose your fleet metrics to the public internet. Audit this before changing the compose file.
- **`postgres-exporter` runs in `network_mode: host`** because the bridge network can't reach `localhost` on the host. The trade-off is that the exporter is bound to the host's loopback, not a Docker user-defined network — that's fine because access still goes through the VPN.
- **The Wazuh agent's manager IP is the only piece of trust placed on the network.** Verify `<address>` in `/var/ossec/etc/ossec.conf` matches your monitor before enrolling — a wrong IP plus an open 1514/1515 will silently send your HIDS events to whoever owns that address.
- **`.env` is `.gitignore`d.** Never commit the rendered file — only `*.env.example`.

## License

MIT — see [LICENSE](./LICENSE).
