# SOCials-Warden — Self-hosted Secrets Manager

Production-grade secrets manager for small-to-medium fleets, built on top of
**Vaultwarden** with two delivery modes plus crypto-grade resilience.

- 🗄️ **Vault-sync mode** — agent logs into Vaultwarden, pulls collections,
  renders to `tmpfs` (`/run/secrets/<collection>.env`)
- 📦 **Bundle mode** — manager encrypts an env-file with the target's age
  pubkey, SCPs it, agent decrypts at boot. Plaintext **never persists on disk**.
- 🔐 **Shamir K-of-N** — master key split across fleet peers; cache loss
  recoverable from any K peers via ed25519-authenticated HTTP endpoint
- 🛟 **Break-glass ceremony** — paper share `x=N+1` + zero-knowledge canary
  verification (cron-friendly)

Inspired by SOC topology (one **manager** + lightweight **agents**),
similar to Wazuh's architecture.

---

## Features

| | Vault-sync | Bundle |
|--|--|--|
| Source of truth | Vaultwarden | Local env-file on the manager host |
| Encryption in transit | TLS to Vault | age (X25519) per machine |
| Storage on client | tmpfs only | tmpfs only |
| Use case | Shared secrets across the fleet | Per-machine bundles, dedicated workers |

Both modes coexist on the same agent — switch with `sync.collections`
in the config (`[]` = bundle-only mode).

---

## Architecture

```
                ┌────────────────┐
                │  Vaultwarden   │  (e.g. vault.example.com)
                └────────┬───────┘
                         │ bw login + sync (TLS)
                         ▼
              ┌────────────────────────┐
              │   socialwarden-manager │  ← runs on the manager host
              │                        │
              │ - inventory.json       │
              │ - shares/identities    │
              │ - bundle-push (age)    │
              │ - shamir enroll/recover│
              └─────┬──────────────────┘
                    │ SSH over private/VPN mesh (Tailscale, WireGuard, etc.)
        ┌───────────┼───────────────┬───────────────┐
        ▼           ▼               ▼               ▼
   ┌────────┐  ┌────────┐      ┌────────┐      ┌────────┐
   │ host-1 │  │ host-2 │ …    │ host-N │      │  ...   │
   │ agent  │  │ agent  │      │ agent  │      │ agent  │
   └────────┘  └────────┘      └────────┘      └────────┘
        ↕  ed25519 peer share-release HTTP (port 14841)
        Master key reconstructed at boot via K-of-N Shamir.
```

---

## Quick start

You'll need: a host that acts as **manager** (one machine), one or more
**agent hosts** (your fleet), an SSH path between them, and a running
Vaultwarden instance (only required if you want Vault-sync mode).

```bash
git clone git@github.com:Maikol-Romero/SOCials-Warden.git
cd SOCials-Warden

# 1. Install the manager on your manager host
sudo bash manager/install.sh

# 2. Configure inventory (edit to your fleet)
#    Default location: /opt/your-infra-ops/inventory.json
#    (override INVENTORY in manager/bin to point elsewhere)
cat > /opt/your-infra-ops/inventory.json <<'JSON'
[
  {"name": "manager-host", "role": "monitor",  "ip": "10.20.0.1",  "ssh": "ssh ubuntu@10.20.0.1"},
  {"name": "host-1",       "role": "worker",   "ip": "10.20.0.10", "ssh": "ssh ubuntu@10.20.0.10"},
  {"name": "host-2",       "role": "worker",   "ip": "10.20.0.11", "ssh": "ssh ubuntu@10.20.0.11"}
]
JSON

# 3. Install the agent on each fleet machine (manual, one-time)
scp -r agent/ host-1:/tmp/socialwarden-agent/
ssh host-1 'cd /tmp/socialwarden-agent && SOCIALWARDEN_MACHINE_NAME=host-1 sudo bash install.sh'

# 4. Edit /etc/socialwarden/config.yaml on each machine (server URL, email,
#    collections to sync, optional Discord webhook, etc.)

# 5. Set up Shamir resilience (optional but recommended)
sudo socialwarden-manager register-identity host-1
sudo socialwarden-manager distribute-pubkeys
echo -n '<your-master>' | sudo socialwarden-manager enroll-shamir host-1   # default K=3, N=5

# 6. Push your first age-encrypted bundle
sudo socialwarden-manager register-age-pubkey host-1
sudo socialwarden-manager bundle-push host-1 my-bundle \
     --env-file ./local.env --render
```

---

## Repository structure

```
SOCials-Warden/
├── agent/
│   ├── socialwarden-agent.py    # Main agent daemon
│   ├── socialwarden-agent.service
│   ├── shamir.py                # Polynomial split/reconstruction
│   ├── hot_env.py               # Drop-in helper: rotated secrets without restart
│   ├── bin                      # socialwarden-agent (operator CLI)
│   ├── install.sh               # Client installer (idempotent)
│   ├── install-agent-worker.sh  # Optional: docker-compose boot ordering
│   └── VERSION
├── manager/
│   ├── bin                      # socialwarden-manager (CLI)
│   ├── shamir.py                # Manager-side splitting
│   ├── install.sh               # Manager installer
│   └── VERSION
└── docs/
    ├── ARCHITECTURE.md          # Full operational manual (modes, config, recovery)
    └── BREAK-GLASS-RUNBOOK.md   # Paper share x=N+1 ceremony, canary, audit
```

---

## Resilience properties

- **Master key cache loss** (reboot, disk reformat, machine-id change):
  agent reconstructs from any K peers via Shamir, no human intervention.
- **Single peer compromise**: master remains unrecoverable from one share alone
  (K shares are needed to reconstruct).
- **Manager loss**: paper share `x=N+1` unlocks recovery (see runbook).
- **Bundle delivery**: per-machine age pubkey, plaintext never on agent disk.

---

## Hardening

The agent's systemd unit uses:

- `RuntimeDirectory=socialwarden` (auto-cleaned tmpfs)
- `ProtectSystem=strict`, `ProtectHome=no`, `RestrictSUIDSGID=yes`,
  `NoNewPrivileges=yes`, `ProtectKernelTunables`/`Modules`/`ControlGroups`
- `Before=docker.service` (guarantees secrets rendered before app starts)

Optional UDS API on the agent (`/run/socialwarden/api.sock`, opt-in via config)
is rate-limited (100 req/min) and policy-driven (`/etc/socialwarden/policy.yaml`).
Per-container access uses `SO_PEERCRED` + cgroup → container name resolution.

---

## Audit

Both manager and agent emit structured audit logs:

- Manager: `/var/lib/socialwarden-manager/audit.log` (rotated 50 MB × 5)
- Agent: `/var/lib/socialwarden/audit.log`
- Optional Discord webhook for alerts (configurable per machine)

Cron-friendly zero-knowledge canary verification (`verify-shamir`) confirms
peers still hold valid shares **without ever reconstructing the master key**.

---

## Status

`v0.1.0` — initial public release. APIs are subject to change while the
project is `< 1.0.0`.

---

## License

MIT — see [LICENSE](LICENSE).
