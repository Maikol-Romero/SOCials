# SOCials-Trivy — Vulnerability Scanning Dashboard

Self-hosted Docker vulnerability scanner with a hardened Nginx-served dashboard.
Uses [Trivy](https://github.com/aquasecurity/trivy) under the hood, runs weekly
across your fleet via SSH, and produces a single-page React dashboard with:

- CVE classification by severity, fixability, conflict type, and internet exposure
- Optional AI enrichment (Claude CLI) — adds plain-language *what / why / howToFix*
- Reverse-dependency analysis: shows which packages depend on each vulnerable lib
- History view, resolved tracking, and weekly Discord summary

Designed to be **fully replicable**: clone, drop in your `inventory.json`, run.

---

## Quick start

```bash
git clone git@github.com:Maikol-Romero/SOCials-Trivy.git
cd SOCials-Trivy

# 1. Configure your fleet
cp inventory.json.example inventory.json
$EDITOR inventory.json   # add your machines (name, ssh, etc.)

# 2. Configure secrets (Discord webhook for alerts — optional)
cp .env.example .env
$EDITOR .env

# 3. Bring up Trivy
docker compose up -d

# 4. Run the first scan
bash scripts/trivy-scan.sh

# 5. Bring up the dashboard
htpasswd -c dashboard/.htpasswd <user>   # set basic-auth password
cd dashboard && docker compose up -d
# Open http://<host>:8086/
```

---

## Components

```
SOCials-Trivy/
├── docker-compose.yml          # Trivy scanner container
├── scripts/
│   ├── trivy-scan.sh           # Weekly orchestrator: scan all hosts → reports/
│   ├── trivy-enrich.py         # Claude-CLI AI enrichment (optional)
│   ├── trivy-deps.py           # Reverse-dependency mapping
│   └── trivy-summary.py        # Weekly summary banner
├── dashboard/
│   ├── docker-compose.yml      # Hardened nginx serving the dashboard
│   ├── nginx.conf              # OWASP Top 10 hardening (rate limit, CSP, …)
│   ├── index.html              # Production single-page React app
│   ├── trivy-security.jsx      # JSX source (with mock data for dev)
│   └── docs.html               # In-app documentation
└── reports/                    # Scan output lands here (gitignored)
```

---

## How it works

1. `trivy-scan.sh` reads `inventory.json` and SSHes to every host
2. Per host it scans **Docker images** (`trivy image`) and **OS packages** (`trivy rootfs`)
3. Output is parsed, conflict-classified, and saved to `reports/scan_<date>.json`
4. `latest.json` always points at the most recent scan
5. The dashboard reads `latest.json` directly via Nginx (`/api/latest.json`)

### Conflict classification

| Type | Risk | Action |
|------|------|--------|
| 🟢 Image library / TLS | Low | Rebuild your Docker image |
| 🟡 App runtime / dependency | Medium | Stage 72h, then promote |
| 🔴 Base system | High | Bump base image FROM only |

---

## Hardening (Nginx)

Mapped against OWASP Top 10 2021:

- A01 Access — basic-auth required, methods restricted to GET/HEAD/OPTIONS
- A02 Crypto — HSTS, secure headers
- A03 Injection — char filter on URLs
- A05 Misconfig — server tokens off, full security-header set, strict CSP
- A06 Components — `nginx:alpine` minimal surface, read-only root FS
- A09 Logging — combined access log + warn-level error log
- A10 SSRF — block requests to internal IP ranges

The dashboard container drops all caps except `NET_BIND_SERVICE`,
runs `read_only: true` with `tmpfs` mounts, and uses `no-new-privileges`.

---

## Customising the dashboard

Edit `dashboard/index.html` to set per-machine display options
(roles, colours, icons). Anything not in the map gets an auto-assigned colour:

```js
const MACHINE_DEFAULTS = {
  "your-host-1": { role: "Production", color: "#dc2645", icon: "🔴" },
  "your-host-2": { role: "Staging",    color: "#e05520", icon: "🟠" },
};
```

---

## Cron

```cron
# Weekly scan, Sunday 01:00
0 1 * * 0 /opt/SOCials-Trivy/scripts/trivy-scan.sh >> /tmp/trivy-scan.log 2>&1
```

The summary script (`trivy-summary.py`) is meant to run on Mondays for a weekly digest.

---

## Optional: AI enrichment

If you have the Claude CLI installed and authenticated:

```bash
python3 scripts/trivy-enrich.py
```

This adds a *what / why / howToFix* paragraph to each CVE in `latest.json`,
useful for stakeholders who can't read CVE summaries directly.

---

## License

MIT — see [LICENSE](LICENSE).
