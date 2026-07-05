# SOCials-Wazuh

Self-hosted **Wazuh 4.14 SOC stack** — Indexer + Manager + Dashboard — wired to push high-severity alerts to Discord. Designed to live on a single private *manager host* reachable through your VPN mesh, with lightweight agents enrolled across the rest of the fleet.

## What's in the box

| Component | Image | Purpose |
|---|---|---|
| `wazuh.indexer` | `wazuh/wazuh-indexer:4.14.4` | OpenSearch storage for alerts/events |
| `wazuh.manager` | `wazuh/wazuh-manager:4.14.4` | Receives agent events, runs FIM/rootcheck/CVE detection |
| `wazuh.dashboard` | `wazuh/wazuh-dashboard:4.14.4` | Web UI (port 5601) |

The **agent.conf** ships sane defaults for any Linux fleet: syslog/auth.log/dpkg/kern collection, docker-listener, FIM, rootkit and CVE scanning.

## Quick start

```bash
git clone https://github.com/Maikol-Romero/SOCials-Wazuh.git
cd SOCials-Wazuh

cp .env.example .env
# edit .env — strong passwords for INDEXER, WAZUH_API and DASHBOARD

./scripts/generate-certs.sh   # generates certs/*.pem from certs/config.yml

docker compose up -d
```

Dashboard available at `https://<MONITOR_IP>:5601` (login: `admin` / `$INDEXER_PASSWORD`).

## Discord alerting

`config/ossec.conf` ships an `<integration>` block that forwards alerts of level ≥ 12 to Discord. Replace the placeholders in the `<hook_url>` with your own webhook ID and token (Discord → server settings → integrations → webhooks → copy URL → append `/slack` for OSSEC's Slack-compatible payload).

## Adding agents

Each agent host needs the Wazuh agent installed and pointed at the manager (port 1514/1515). The included `config/agent.conf` is the canonical client-side configuration — drop it on each agent at `/var/ossec/etc/local_internal_options.conf`.

Inventory of fleet hosts goes in `inventory.json` (see `inventory.json.example`).

## Filesystem tripwire (auditd + Wazuh FIM)

Detect any **interactive** read of `/run/secrets` or any touch of the host's long-lived key material. The kernel filter `auid!=4294967295` means daemons running as root never trigger an event — only commands launched from a logged-in user session do. Zero false positives by construction.

### Manager side

`config/local_rules.xml` ships two custom rules (level 12) that fire on audit keys `secrets_read` and `keymat`. Drop the file at `/var/ossec/etc/rules/local_rules.xml` (or `shared/default/` for cluster).

`integrations/custom-discord` + `integrations/custom-discord.py` is a **standard-library-only** Wazuh → Discord forwarder. The bundled `slack.py` requires `requests`, which is not installed in the official image — silent failure waiting to happen. Wire it in `ossec.conf`:

```xml
<integration>
  <name>custom-discord</name>
  <hook_url>https://discord.com/api/webhooks/.../.../slack</hook_url>
  <level>12</level>
  <alert_format>json</alert_format>
</integration>
```

### Agent side (each host you want to watch)

Install `auditd` and drop `config/audit-rules/secrets-tripwire.rules.example` at `/etc/audit/rules.d/secrets-tripwire.rules` (edit the paths to match your secret-management layout), then `sudo augenrules --load`.

Verify with `sudo auditctl -l` and a smoke test:

```bash
sudo cat /var/lib/socialwarden/master.key  # should produce a Wazuh alert
```

## Hardening notes

- **Never commit `certs/*.pem` or `certs/*.key`** — they're regenerated on each host (covered by `.gitignore`).
- The Discord webhook in `ossec.conf` is itself a secret — do not paste real values into commits.
- All ports bind to `${MONITOR_IP}`, never `0.0.0.0`. Set `MONITOR_IP` to the host's VPN address so the dashboard is **only** reachable through the mesh.
- Rotate `kibanaserver` (the dashboard's internal user) for any production deployment — the upstream default is documented and well-known.

## License

MIT — see [LICENSE](./LICENSE).
