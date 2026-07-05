# SOCials-DNS

[AdGuard Home](https://adguard.com/en/adguard-home/overview.html) configured as the **internal DNS resolver** for a self-hosted observability + security stack: blocks ads/tracking on every device on the VPN mesh and resolves the friendly hostnames (`grafana.example.com`, `wazuh.example.com`, `homepage.example.com`, …) that the rest of the stack uses.

## What you get

- **DoH upstream** (Quad9 `dns10.quad9.net`) — encrypted DNS to upstream resolvers, no plaintext leaks to your ISP
- **Local DNS rewrites** that map `*.example.com` to a single internal VPN IP — devices on the mesh can use real-looking hostnames instead of `100.x.y.z`
- **Filter list** (AdGuard's default) — drops ad/tracker domains at resolution time
- **Web UI** for query log + stats, bound to `${MONITOR_IP}:${DNS_WEB_PORT}` only

## Quick start

```bash
git clone https://github.com/Maikol-Romero/SOCials-DNS.git
cd SOCials-DNS

cp .env.example .env
# edit .env — set MONITOR_IP to your VPN mesh address

# Generate an admin password hash:
docker run --rm caddy caddy hash-password --plaintext 'YOUR_STRONG_PASSWORD'
# Paste the resulting bcrypt hash into conf/AdGuardHome.yaml under users.password

docker compose up -d
```

Web UI: `http://${MONITOR_IP}:${DNS_WEB_PORT}` (default port 2999).
DNS:   `${MONITOR_IP}:53` — point your devices' resolver here.

## Customizing the rewrites

`conf/AdGuardHome.yaml` ships with 11 example rewrites (`grafana.example.com`, `wazuh.example.com`, …) all pointing at `10.20.0.1`. Edit the `filtering.rewrites:` block to match your stack:

```yaml
filtering:
  rewrites:
    - domain: grafana.yourdomain.tld
      answer: 10.20.0.5     # the internal IP where Grafana runs
      enabled: true
```

You can also edit rewrites live from the web UI under **Filters → DNS rewrites** — changes are persisted to `AdGuardHome.yaml` automatically.

## Why bind to `${MONITOR_IP}` and not `0.0.0.0`?

Binding to `0.0.0.0` would expose port 53 on every interface — including any public one. An open recursive resolver is a [DNS amplification](https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/) liability. Binding to your VPN mesh IP only means the resolver is reachable exclusively to devices already authenticated into the mesh.

## Operational notes

- **`work/` is the AdGuard runtime state directory** — query log, stats DB, custom filters. It's `.gitignored` for a reason; do not commit it.
- **`conf/AdGuardHome.yaml` is the source of truth** for declarative config. The web UI writes back to this file, so if you bind-mount it (we do), changes from the UI survive container restarts.
- **DoH upstream**: `dns10.quad9.net` blocks malicious domains at the upstream level. Swap for `dns.cloudflare-dns.com` or `dns.google` in `conf/AdGuardHome.yaml` under `dns.upstream_dns:` if you prefer.
- **Filter updates** run every 24h (`filtering.filters_update_interval: 24`).

## Hardening notes

- The bcrypt hash in the shipped config is a **placeholder** (`REPLACE_WITH_BCRYPT_HASH`) and will not authenticate. Generate your own before bringing the container up — see Quick start.
- `serve_plain_dns: true` is on by default because the resolver is on a private network. If you expose it more widely, turn it off and use DoT/DoH.
- Pin `image:` to a specific AdGuard Home tag in production, not `:latest`.

## License

MIT — see [LICENSE](./LICENSE).
