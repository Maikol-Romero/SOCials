# SocialWarden — Operator Manual

> Version: **0.2.0** · Last updated: 2026-05-20
>
> **Who reads this?** Anyone who has to add a secret, migrate a service, rotate a value, recover from drift, or understand why something isn't working. No prior code reading required.

---

## 1. What SocialWarden is, in 3 sentences

1. **Vaultwarden** (self-hosted at `vault.example.com`) stores the encrypted secrets.
2. **`socialwarden-agent`** runs on every fleet machine and, every 60 s, pulls the secrets from the vault and writes them to `/run/secrets/*.env` (tmpfs, RAM, wiped on reboot).
3. **`socialwarden-manager`** runs on the manager host, splits the vault master with Shamir's secret sharing, distributes shares to peers, and pushes age-encrypted bundles to bundle-only hosts.

Containers read `/run/secrets/*.env` via `env_file:` in their compose. No secrets in images, no secrets in repos.

---

## 2. Operation modes per host

| Mode               | Config                                  | Use when                                            |
|--------------------|-----------------------------------------|------------------------------------------------------|
| **Pull**           | `sync.collections: [...]`               | Host has `master.key` on disk and talks to vault     |
| **Bundle-only**    | `sync.collections: []` + `shamir.enabled: true` | Sensitive host with no master.key on disk; receives age-bundles via `bundle-push` |

The agent self-detects the mode at boot. Bundle-only mode logs `running in BUNDLE-ONLY mode (no Vaultwarden auth, no periodic sync)`.

---

## 3. The 6 things you'll do

### 3.1. Add a new secret to a managed app

1. Open `vault.example.com` with the operator account.
2. Pick the collection for the target app (e.g. `app-host-1`).
3. Create → Login → Name = `STRIPE_NEW_KEY`, Username = `STRIPE_NEW_KEY`, Password = `sk_test_xxxxxxx`. Assign to the collection. Save.
4. On the target host: `sudo /usr/local/bin/socialwarden-agent sync` (or wait 60 s).
5. The new value appears in `/run/secrets/<collection>.env` automatically.
6. To make the container see it: `cd /path/to/service && sudo docker compose up -d` (recreates the container with the new env).

**Special-character values** (`=`, `#`, `$`, quote, newline): the agent stores them with a `__SWB64__<base64>__` sentinel. The container receives the literal token unless the decode shim is wired as `entrypoint:`. The agent logs a WARNING when this happens — see §6.

### 3.2. Rotate an existing secret

Same as 3.1, but edit the vault item instead of creating it. The agent detects the change on the next poll, rewrites `/run/secrets/...`. Recreate the container.

### 3.3. Migrate a new service whose `.env` is still plaintext on disk

If a `git clone` left `/home/ubuntu/foo-service/.env` with secrets:

1. Add an entry to `/etc/socialwarden/config.yaml` under `sync.collections` pointing the merge `link:` at that path and `output:` at `/run/secrets/foo-service.env`.
2. Create the matching collection in the vault and assign Login items for each secret.
3. `sudo systemctl kill -s HUP socialwarden-agent` (reload config without restart).
4. The agent absorbs the existing values on the next sync, then writes the file back as a managed copy (with the SocialWarden sentinel header).
5. Update the compose `env_file:` to point at `/run/secrets/foo-service.env`. Recreate the container.

### 3.4. Recover from "drift reverted" alerts

Means: something overwrote the managed `.env` with plaintext (a `docker compose up`, a script, a manual edit).

Auto-recovery: the agent re-renders the path from the vault canonical on the next sync.

Operator action: investigate what overwrote it (`who edited it`, run `auditctl -l`, check `journalctl -u socialwarden-agent`). Usually a compose recreate without `pull`. Fix the root cause; the file will heal itself.

### 3.5. Recover from an orphan `.pre-socialwarden` file

A `*.env.pre-socialwarden` left in `/run/socialwarden-backups/` (tmpfs) is the pre-absorb backup that survives reboot loss. **Never copy it to non-tmpfs disk** — those are secrets in cleartext.

### 3.6. Push secrets to a bundle-only host

From the manager host:

```bash
sudo socialwarden-manager bundle-push <target-machine> <bundle-name> \
  --env-file /path/to/plaintext.env --render
```

- `<bundle-name>` = logical name (e.g. `agent`, `aws-creds`).
- The bundle travels age-encrypted with the target's public key.
- `--render` runs `socialwarden-agent render <bundle-name>` on the target → writes `/run/secrets/<bundle-name>.env`.
- **Do not persist the plaintext file on disk**. Use `/run/socialwarden-tmp-*.env` (tmpfs) or pipe stdin.

---

## 4. Quick diagnostics

| Symptom                                            | Command to run on the host                            |
|----------------------------------------------------|-------------------------------------------------------|
| Is the agent healthy?                              | `sudo systemctl status socialwarden-agent`            |
| Inventory of problems + recommendations            | `sudo /usr/local/bin/socialwarden-agent doctor`       |
| Force a sync now (don't wait for the poll)         | `sudo /usr/local/bin/socialwarden-agent sync`         |
| Reload `config.yaml` without restart               | `sudo systemctl kill -s HUP socialwarden-agent`       |
| Inspect recent agent activity                      | `sudo journalctl -u socialwarden-agent --since '5 minutes ago' --no-pager` |

### Real alarm signals (not false positives)

- `Collection Emptied: <name>` → the vault collection lost its items. Check it wasn't a `bw delete` accident.
- `DRIFT [reverted] /path/to/.env` **repeated every tick** → the managed sentinel is missing or a process is rewriting the file. See §3.4.

---

## 5. The "managed" sentinel

When the agent writes a merged `.env` (static config + vault secrets), it inserts a header line between the static block and the secrets block:

```
# === Secrets managed by SocialWarden (do not edit) ===
```

The 4 KiB prefix of any managed file should contain this line. Tools that detect drift look for it. **If you write a `render:` template, make sure your template includes this line on the first line**, or any tool watching the file will not recognise it as managed and will alert.

---

## 6. Special-character values (`__SWB64__` sentinel)

If a secret contains `=`, `#`, `$`, quote, space, or newline, the agent stores it in the merged file as:

```
KEY=__SWB64__<base64-of-original-value>__
```

…and emits a shim script `<path>.swb64-decode.sh` ready to wire as the container's `entrypoint:`:

```yaml
services:
  myapp:
    entrypoint: ["/path/to/.env.swb64-decode.sh"]
    env_file:
      - /run/secrets/myapp.env
```

If you don't wire the shim, the container sees the literal `__SWB64__...__` token (the agent will log a WARNING).

---

## 7. Things you must never do

1. **Edit `/run/secrets/*.env` by hand.** It's the agent's output — it gets rewritten on the next poll. Edit the vault item.
2. **Commit `.env` files with secrets to a repo.** The watcher (if running) absorbs them, but `ignore_paths` excludes `.git/` and certain test dirs — outside those, secrets get committed.
3. **`dockerd restart` on the manager host if it owns critical infra** (e.g. an etcd that other hosts depend on). Verify what the dockerd hosts before bouncing it.
4. **Run a vault audit (`bw audit`) while a live agent is polling on the same host.** It can invalidate the agent's session and trigger false "Collection Emptied" alerts.
5. **Put the manager's own bootstrap `.env` (the one with the vault credentials) under SocialWarden management.** Chicken-and-egg: the credentials to open the vault cannot live inside the vault. Keep it in `ignore_paths`.

---

## 8. How to verify everything is managed on a host

```bash
sudo find /home /etc /root -maxdepth 4 -name '.env' -type f | while read p; do
  if sudo grep -q 'managed by SocialWarden' "$p"; then
    echo "managed: $p"
  else
    n_sec=$(sudo grep -cE 'PASSWORD|SECRET|TOKEN|KEY=.{20,}|JWT|API_KEY' "$p")
    [ "$n_sec" -gt 0 ] && echo "ORPHAN: $p" || echo "config-only: $p"
  fi
done
```

Expected output: only `managed:` and `config-only:` lines. Any `ORPHAN:` line is a path you should migrate (§3.3).

---

## 9. References

- **Architecture deep-dive**: `docs/ARCHITECTURE.md`
- **Break-glass / recovery**: `docs/BREAK-GLASS-RUNBOOK.md`
- **Agent + manager CLI usage**: `socialwarden-agent --help`, `socialwarden-manager --help`

---

*This manual is meant to be readable without reading the code. If something is unclear or a case is missing, edit it — it should age well.*
