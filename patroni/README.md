# SOCials-Patroni

Self-hosted **Postgres HA** stack: Supabase-flavored Postgres + Patroni + pgbouncer + S3 backups + integrity verification + automatic switchback.

Built for the case where you need a HA Postgres cluster on commodity VMs without leaning on a managed service.

## What's in the box

| Component | Purpose |
|---|---|
| `supabase/postgres:15.14.1.095` | Postgres 15 with the Supabase extension set (pgaudit, pgsodium, timescaledb, pg_cron, …) |
| `patroni 4.0.4` (vendored in `Dockerfile`) | Leader election, automatic failover, replica streaming |
| `edoburu/pgbouncer:latest` | Connection pooler (transaction mode, 1000 max client conns) |
| `scripts/backup.sh` | Daily `pg_dumpall` → S3 with integrity gate |
| `scripts/integrity-check.sh` | Snapshot + compare table row counts; abort backup if a table dropped >50 % |
| `scripts/switchback.sh` | Cron-driven (every minute): hand leadership back to the preferred node + auto-reinitialize stuck replicas |
| `scripts/container-metrics.sh` | Tiny node-exporter textfile collector for `container_up` / `container_restarts` |

## Two deployment modes

This repo ships **two compose files** because real-world clusters typically start small:

- `docker-compose.yml` — single-node Postgres (no Patroni). Use this to bring up your first DB host.
- `docker-compose.patroni.yml` — Patroni-managed Postgres. Use this once you have ≥ 2 nodes and an etcd cluster.

The included `Dockerfile` builds a Postgres image with Patroni pre-installed, which `docker-compose.patroni.yml` uses.

## Quick start (single node)

```bash
git clone https://github.com/Maikol-Romero/SOCials-Patroni.git
cd SOCials-Patroni

cp .env.example .env
# edit .env — set strong POSTGRES_PASSWORD, DISCORD_WEBHOOK, S3_BUCKET

cp config/userlist.txt.example config/userlist.txt
# generate SCRAM hashes per the comments inside; the file stays untracked

docker compose up -d
```

## Switching to HA

1. Stand up an etcd cluster (single node fine for non-prod) and note its IP.
2. Provision your second host. Both hosts need fast disks at `/mnt/db/data` and a routable private network.
3. Copy `config/patroni.yml.example` to `config/patroni.yml` on each node and edit:
   - `name` (must be unique per node)
   - `restapi.connect_address` and `postgresql.connect_address` (this node's reachable IP)
   - `etcd3.host`
4. Build the patroni image once: `docker build -t patroni-postgres:15.14.1 .`
5. Bring up Patroni: `docker compose -f docker-compose.patroni.yml up -d`
6. Watch leader election: `curl -s localhost:8008/cluster | jq`

## Backups + integrity

`scripts/backup.sh` runs `scripts/integrity-check.sh` first. If the integrity check detects a table that dropped to zero or lost >50 % of its rows since yesterday, **the backup is aborted** — preserving the last known-good backup against accidental data loss propagating into S3.

Schedule via cron on the leader host:

```cron
# Integrity snapshot every morning
0 4 * * *   /opt/patroni/scripts/integrity-check.sh
# Backup right after
30 4 * * *  /opt/patroni/scripts/backup.sh
```

## Switchback strategy

Patroni elects whichever node has the lowest lag when the leader fails. After recovery, you usually want leadership back on the original "primary" host (better disks, closer to your app, etc). `switchback.sh` does that automatically when:

1. This node has been streaming with **0 lag for at least 5 minutes**, AND
2. It's currently a replica (so a switchover will return it to leader).

Drop the script in cron on the *preferred* leader, run every minute. The leader-side branch of the same script also auto-reinitializes any replica stuck in `running` state with >1 MB lag.

## Hardening notes

- **Never commit `.env`, `config/patroni.yml`, or `config/userlist.txt`** — `.gitignore` covers them.
- `patroni.yml`'s `pg_hba` block ships with `0.0.0.0/0 scram-sha-256` for external connections. Tighten that to your VPN/VPC CIDR if you don't need external access.
- The pgbouncer `auth_type = trust` in `config/pgbouncer.ini` works because pgbouncer has `userlist.txt` with hashed credentials. Postgres itself is still SCRAM-protected.

## License

MIT — see [LICENSE](./LICENSE).
