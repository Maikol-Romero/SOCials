# SocialWarden — Manual de Uso

Sistema de gestión de secrets para tu fleet, inspirado en la topología
SOC de Wazuh: **un manager** (head) + **agents ligeros** en cada máquina.

---

## 1. Visión general

```
                ┌─────────────────────────────┐
                │        Vaultwarden          │
                │   vault.example.com         │
                └──────────────┬──────────────┘
                               │  bw login + sync
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        │              ┌───────▼────────┐             │
        │              │  manager host  │             │
        │              │                │             │
        │              │  socialwarden- │             │
        │              │  manager       │             │
        │              └───────┬────────┘             │
        │                      │                      │
        │     SSH + VPN mesh   │   SSH + VPN mesh     │
        │                      │                      │
   ┌────▼─────┐  ┌──────▼──────┐  ┌──────▼──────┐  ┌──▼────────────┐
   │ host-1   │  │ host-2      │  │  host-3     │  │ host-4        │
   │ (agent)  │  │ (agent)     │  │  (agent)    │  │ (bundle-only) │
   └──────────┘  └─────────────┘  └─────────────┘  └───────────────┘
        ↕              ↕                ↕                  ↕
   peer share-release HTTP (port 14841) — boot-time Shamir reconstruction
```

**Principios:**

- **Vaultwarden** es el storage upstream. Cada máquina autentica con un usuario+master compartido (configurable en `/etc/socialwarden/config.yaml`).
- **Manager** orquesta toda operación de fleet (instalar, enrollar, distribuir, auditar). corre solo en el host del manager.
- **Agent** es un demonio Python ligero (~23 MB RAM) en cada host. Hace `bw login`, sincroniza colecciones, escribe `/run/secrets/*.env`.
- **VPN mesh** (Tailscale, WireGuard u otra red privada) es el control plane (todas las comunicaciones manager↔agent y agent↔agent).
- **Shamir K-of-N** protege el master password contra pérdida del cache (reboot duro, disk reformat, machine-id change).
- **age** se usa para entregar bundles cifrados de máquina a máquina sin pasar por Vault (uso: distribuir env-files que no están en Vault).
- **inventory.json** es la **única fuente de verdad** de la topología.

---

## 2. Modos de operación del agent

| Modo            | Trigger en config                | Qué hace                                                           |
|-----------------|----------------------------------|--------------------------------------------------------------------|
| **Vault-sync**  | `sync.collections: [...]` (≠ ∅)  | login en Vaultwarden, fetch colecciones, render `/run/secrets/*.env`, drift check periódico |
| **Bundle-only** | `sync.collections: []` (vacío)   | NO toca Vaultwarden. Sólo descifra bundles age que llegan vía `bundle-push`. Útil para máquinas dedicadas (ej: a dedicated agent host) |

Cambiar de uno a otro = editar `/etc/socialwarden/config.yaml` y `systemctl restart socialwarden-agent`.

---

## 3. Anatomía de archivos

### En cada host (`/var/lib/socialwarden/`, persistente, mode 700 root)

```
/etc/socialwarden/config.yaml         ← config principal (sync, auth, shamir, etc.)
/var/lib/socialwarden/
   master.key                       ← master de Vaultwarden, cifrado con machine-id
   identity.priv  identity.pub      ← ed25519 keypair de la máquina (firma share-release requests)
   age.key  age.pub                 ← age keypair (recipient para bundle-push)
   local.share                      ← su share Shamir (x=1 de N=5) — boot reconstruction primary source
   peer-shares/
      <peer-name>.share             ← shares que ESTA máquina mantiene de OTROS peers
   peer-identities/
      <peer-name>.pub               ← pubkeys de ed25519 de los peers (verifica share-release requests)
   bundles/
      <bundle-name>.age             ← bundles age-cifrados pendientes de render
/run/socialwarden/                    ← tmpfs, recreado en cada boot
   heartbeat                        ← timestamp del último poll loop tick
   api.sock                         ← UDS API (opt-in; off por defecto)
/run/secrets/                       ← tmpfs, donde el agent renderiza env files
   <bundle>.env                     ← output final, mode 600 root, listo para Docker bind-mount
/var/log/socialwarden/                ← persistente
   audit.log                        ← eventos del agent
   shamir-release.log               ← request log del endpoint share-release
/tmp/node-exporter-textfile/
   socialwarden.prom                  ← métricas Prometheus (scrape via node-exporter textfile)
```

### En el manager (manager host, `/var/lib/socialwarden-manager/`)

```
/etc/socialwarden/manager.yaml        ← config del manager (poco usado; defaults bastan)
/var/lib/socialwarden-manager/
   identities/
      <machine>.pub                 ← ed25519 pubkey de cada peer registrado
   age-pubkeys/
      <machine>.pub                 ← age pubkey de cada peer (para bundle-push)
   shares/
      <machine>.share               ← share Shamir x=N de cada machine (uso: recovery)
   bundles/
      <machine>-<bundle>.age        ← cache local de bundles cifrados
   audit.log                        ← eventos del manager
/opt/socialwarden-manager/            ← código instalado
/opt/socialwarden-agent/               ← código del agent (no, en clients)
inventory.json                      ← /opt/your-infra-ops/inventory.json — single source of truth
```

---

## 4. Cheat sheet — `socialwarden-manager` (en el manager host)

Todos los comandos requieren `sudo`. Resultado importante en `/var/lib/socialwarden-manager/audit.log`.

### Lectura / inspección

```bash
sudo socialwarden-manager status               # Estado del manager (paths, shares held, tailscale, audit)
sudo socialwarden-manager list                 # Tabla de todas las máquinas + estado socialwarden
sudo socialwarden-manager list-identities      # Lista de pubkeys ed25519 registradas
sudo socialwarden-manager audit-tail -n 40     # Últimos 40 eventos
```

### Registro de identidades (paso 1 tras enrolar el agent)

```bash
sudo socialwarden-manager register-identity <machine>          # Fetch ed25519 pub via SSH
sudo socialwarden-manager register-identity <machine> --force  # Sobreescribe si la pubkey cambió
sudo socialwarden-manager distribute-pubkeys                   # Push todas las pubkeys a cada peer (idempotente)
```

`register-identity` falla si la máquina no tiene `/var/lib/socialwarden/identity.pub` (= agent no ha arrancado).
`distribute-pubkeys` actualiza `/var/lib/socialwarden/peer-identities/*.pub` en cada host.

### age + bundles (env-files entregados fuera de Vault)

```bash
sudo socialwarden-manager register-age-pubkey <machine>                                # Fetch age.pub
sudo socialwarden-manager bundle-push <machine> <bundle-name> --env-file <local.env>   # Cifrar + SCP
sudo socialwarden-manager bundle-push <machine> <bundle> --env-file <f> --render       # Cifrar + SCP + render
```

**Flujo bundle-push:**

1. Manager lee `<local.env>` plaintext desde el filesystem del manager-host (the host running the manager).
2. Lo cifra con la age pubkey del target → `<machine>-<bundle>.age` (storage local en el manager host).
3. SCP atómico → `target:/var/lib/socialwarden/bundles/<bundle>.age`.
4. Con `--render`: ejecuta `socialwarden-agent render <bundle>` en target, que descifra con `age.key` y escribe `/run/secrets/<bundle>.env` (mode 600 root).

Ejemplo real (a dedicated agent host):

```bash
sudo socialwarden-manager bundle-push agent-host agent --env-file /tmp/agent-staging.env --render
```

### Shamir K-of-N

```bash
sudo socialwarden-manager enroll-shamir <machine>                              # Default: K=3, N=5
sudo socialwarden-manager enroll-shamir <machine> --k 3 --n 5                  # Explícito
sudo socialwarden-manager enroll-shamir <machine> --peers m1,m2,m3             # Override peer selection
sudo socialwarden-manager enroll-shamir <machine> --dry-run                    # Validar sin distribuir
sudo socialwarden-manager enroll-shamir <machine> --force                      # Re-enrolar (DESTRUCTIVO)

sudo socialwarden-manager recover <machine>                                    # Reconstruye master vía manager+peers, re-cifra master.key, restart agent
sudo socialwarden-manager revoke <machine> --confirm                           # Wipe shares + re-enroll con NEW master por stdin (DESTRUCTIVO)
sudo socialwarden-manager rotate-shares                                        # Misma master, polinomio fresco (cron mensual)
sudo socialwarden-manager rotate-shares --machine <m> --dry-run                # Reportar sin escribir
sudo socialwarden-manager verify-shamir                                        # Canary check: ¿reconstruye master? (cron horario)
sudo socialwarden-manager verify-shamir --machine <m>                          # Solo una máquina

# Break-glass (única vez por máquina, tras enroll-shamir, master por stdin)
echo -n '<master>' | sudo socialwarden-manager break-glass-emit <machine>      # Imprime share x=N+1 → papel → caja fuerte

# Primitivas crypto (uso debug / break-glass manual)
echo -n 'secret' | sudo socialwarden-manager shamir-split --k 2 --n 3          # Stdin → shares
sudo socialwarden-manager shamir-combine                                       # Shares por stdin → secret
```

Procedimiento break-glass completo (escenario 3+ peers caídos): ver
[`BREAK-GLASS-RUNBOOK.md`](BREAK-GLASS-RUNBOOK.md).

**`enroll-shamir` requiere master por stdin** (no se le pasa por argumento, no se prompted en TTY):

```bash
read -rsp 'master: ' MPW && echo
printf '%s' "$MPW" | sudo socialwarden-manager enroll-shamir host-1
unset MPW
```

Topología por defecto K=3/N=5: 1 share local en target + 3 peers (auto-seleccionados alfabéticos) + 1 share en manager.

### Side effects de `enroll-shamir`

1. Activa `shamir.enabled=true` en cada peer seleccionado (HTTP endpoint `:14841` arriba).
2. Restart de `socialwarden-agent` en cada peer + en el target.
3. Marca `socialwarden.shamir = {...}` en inventory.json.
4. Eventos `enroll-shamir-share` (uno por share) + `enroll-shamir-ok` en audit.

---

## 5. Cheat sheet — `socialwarden-agent` (en cada host)

```bash
sudo socialwarden-agent status                  # Daemon health, version, last sync, errors
sudo socialwarden-agent render <bundle>         # Descifra age bundle + escribe /run/secrets/<bundle>.env
sudo socialwarden-agent render-all              # Render de todos los bundles disponibles
sudo socialwarden-agent discover                # Scan de .env files no migrados (#23)
sudo socialwarden-agent migrate --apply         # Mover secrets a vault (#24, stub)
```

El agent normalmente corre como systemd service:

```bash
sudo systemctl status socialwarden-agent
sudo journalctl -u socialwarden-agent --since "1 hour ago" -f
sudo systemctl restart socialwarden-agent       # Tras editar /etc/socialwarden/config.yaml
sudo kill -HUP $(pgrep -f socialwarden-agent)   # Force re-sync sin restart
```

### Worker companion: `install-agent-worker.sh`

Para máquinas que *además* del agent corren un docker-compose de aplicación
(ej. `agent-host` con el container `agent-host`), hay un installer
companion que ata todo: docker engine, app dir, compose.yaml y un systemd
oneshot con el ordering `socialwarden-agent.service → agent-app.service →
docker compose up`.

```bash
# Primer run (con compose nuevo)
sudo bash /opt/socialwarden-agent/install-agent-worker.sh \
  --bundle agent \
  --compose /tmp/compose.yaml \
  --user ubuntu

# Re-run idempotente (preserva compose existente)
sudo bash /opt/socialwarden-agent/install-agent-worker.sh \
  --bundle agent --user ubuntu --keep-compose

# Dry-run
sudo bash /opt/socialwarden-agent/install-agent-worker.sh \
  --bundle agent --compose /tmp/compose.yaml --dry-run
```

Side effects: crea `/etc/systemd/system/agent-app.service` (override con
`--service-name`), añade el user al grupo `docker`, instala docker engine si
falta, valida compose con `docker compose config --quiet`.

Pre-requisitos:
- `socialwarden-agent` ya enrolado y service activo
- (Recomendado) bundle ya pusheado vía `socialwarden-manager bundle-push <m> <bundle> --env-file <path>` — si no, el oneshot reintentará render en cada boot

---

## 6. Enrolling a machine (manual)

SocialWarden no incluye un orchestrator de inventory propio — se asume que tienes un `inventory.json` (formato simple, ver más abajo) en el manager host. El proceso para enrolar una máquina nueva:

```bash
# 1. SCP del paquete agent/ al target
scp -r agent/ <target>:/tmp/socialwarden-agent/

# 2. Run installer en el target
ssh <target> 'cd /tmp/socialwarden-agent && SOCIALWARDEN_MACHINE_NAME=<name> sudo bash install.sh'

# 3. Edit /etc/socialwarden/config.yaml en target con server URL, email, collections, etc.

# 4. Restart agent
ssh <target> 'sudo systemctl restart socialwarden-agent'
```

Formato mínimo de `inventory.json` (en `/opt/your-infra-ops/inventory.json` o donde configures `INVENTORY` en `manager/bin`):

```json
[
  {"name": "manager-host", "role": "monitor", "ip": "10.20.0.1", "ssh": "ssh ubuntu@10.20.0.1"},
  {"name": "host-1", "role": "worker", "ip": "10.20.0.10", "ssh": "ssh ubuntu@10.20.0.10"},
  {"name": "host-2", "role": "worker", "ip": "10.20.0.11", "ssh": "ssh ubuntu@10.20.0.11"}
]
```

---

## 7. Ciclo de vida típico de una máquina

```
0. Provisión host + VPN (Tailscale/WireGuard) up                                                (operador)
1. Añadir entrada a inventory.json                                                              (operador)
2. SCP agent/ + run install.sh en target                                                        (operador)
3. Editar /etc/socialwarden/config.yaml (server, email, collections)                            (operador)
4. sudo socialwarden-manager register-identity <m>   → ed25519 pubkey registrada               (manager)
5. sudo socialwarden-manager distribute-pubkeys      → todos los peers conocen al nuevo nodo   (manager)
6. sudo socialwarden-manager register-age-pubkey <m> → age.pub registrada (para bundle-push)   (manager)

   ── EN ESTE PUNTO LA MÁQUINA YA ESTÁ FUNCIONAL ──

7. sudo socialwarden-manager enroll-shamir <m>       → resiliencia ante pérdida del master.key cache (manager, opcional pero recomendado)
8. sudo socialwarden-manager bundle-push <m> ...     → si la máquina necesita env-files fuera de Vault (manager)
```

---

## 8. Operaciones comunes

### Añadir un nuevo secret a Vault y propagarlo

1. Operator añade el secret a Vaultwarden (UI web o `bw create`).
2. Identifica la colección y `collection_name → file_path` en `/etc/socialwarden/config.yaml` del agent target.
3. `sudo systemctl reload-or-restart socialwarden-agent` (o esperar al próximo poll, default 60s).
4. Verifica: `sudo cat /run/secrets/<file>.env`.

### Cambiar un secret existente

Same as above — el agent detecta drift en cada poll y reescribe `/run/secrets/<file>.env`. Container que monte ese file via `env_file` recibirá el nuevo valor en su próximo restart.

### Pedir al agent que sincronice ahora (forzar)

```bash
sudo kill -HUP $(pgrep -f socialwarden-agent)        # SIGHUP → force_sync flag
```

### Cambiar la lista de colecciones que sincroniza una máquina

```bash
ssh <machine> sudo vi /etc/socialwarden/config.yaml
ssh <machine> sudo systemctl restart socialwarden-agent
```

### Recovery cuando el master.key se corrompe (auto-mático)

Si `/var/lib/socialwarden/master.key` se corrompe (machine-id cambió, disk corruption), el agent:

1. Detecta error en `read_encrypted()`.
2. Si `shamir.enabled=true`, dispara `BootShamirReconstructor.reconstruct()`.
3. Carga `local.share` + pide a peers via HTTP firmado (puerto 14841).
4. Combina K shares → master plaintext.
5. Reescribe `master.key` cache.
6. Continúa con `bw login` normal.

Tiempo típico de reconstrucción: ~100-200 ms (local share + 2 peers vía HTTP).

### Recovery operator-driven (cuando los peers no responden)

```bash
sudo socialwarden-manager recover <machine>
```

Lee la share del manager + lee K-1 peer shares por SSH, reconstruye master, lo cifra con la machine-id de la víctima (esquema ENC: AES-XOR+HMAC), instala como `master.key`, hace `systemctl restart socialwarden-agent` y comprueba "Vault unlocked successfully" en logs.

Si los peers tampoco son alcanzables y has perdido N-K+1 shares ≥ 3 → ejecuta el [BREAK-GLASS-RUNBOOK](BREAK-GLASS-RUNBOOK.md) usando la share x=N+1 del sobre lacrado.

---

## 9. Métricas y observabilidad

El agent escribe métricas Prometheus en `/tmp/node-exporter-textfile/socialwarden.prom` cada poll cycle. Las métricas se scrapean via `node-exporter` con `--collector.textfile.directory`.

Métricas expuestas:

```
socialwarden_sync_total{machine="..."}            # contador de sync cycles
socialwarden_sync_errors_total{machine="..."}     # contador de errores
socialwarden_secrets_count{machine="..."}         # gauge de secrets gestionados
socialwarden_changes_detected_total{machine="..."}# changes detected en upstream
socialwarden_drift_detected_total{machine="..."}  # drift detected en local files
socialwarden_last_sync_timestamp{machine="..."}   # gauge unix timestamp
socialwarden_info{machine="...", version="..."}   # info gauge (1)
```

Alerta recomendada: `time() - socialwarden_last_sync_timestamp > 300` → daemon stuck o crashed.

---

## 10. Modelo de seguridad

### Threat model

- **In-scope**: atacante con acceso a un host (lectura de disco), atacante de red local (Tailscale interceptado), pérdida de un master.key cache.
- **Out-of-scope**: atacante con root persistente en el manager host, compromiso de Vaultwarden cloud, exfiltración del master vía social engineering.

### Defensas por capa

| Capa                          | Defensa                                                                                  |
|-------------------------------|------------------------------------------------------------------------------------------|
| `master.key` en disco         | AES-XOR + HMAC con clave derivada de `/etc/machine-id` (atacante con disk image necesita tb el machine-id) |
| Comunicación peer↔peer        | Tailscale (mesh WireGuard) + ed25519 signed challenge-response en share-release          |
| Bundle-push                   | age (X25519 sealed-box, recipient = pubkey del target)                                   |
| Servicio systemd              | `NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths`, `RuntimeDirectory`          |
| Endpoint share-release        | Bind sólo a Tailscale IP (no `0.0.0.0`), rate limit 10/min/peer, nonce TTL 5min, replay protection |
| Shamir reconstruction         | Pérdida de 1 peer no compromete recovery; pérdida de N-K peers (= 2 en defaults) tampoco |

### Auditoría

- **manager host**: `/var/lib/socialwarden-manager/audit.log` (JSON Lines, mode 600 root)
- **client**: `/var/log/socialwarden/audit.log` y `shamir-release.log`
- Ambos ingestables a Wazuh / Loki vía Promtail.

---

## 11. Troubleshooting

### Agent no arranca: `bw CLI not found`

Causa: bw snap conflict con `NoNewPrivileges`. Fix: `install.sh` v1.4.4+ instala bw native (descarga desde GitHub releases). Si una máquina sigue con la version vieja:

```bash
sudo apt-get remove --purge -y bitwarden-cli  # o snap remove
ssh <m> 'cd /tmp && curl -L -o bw.zip https://github.com/bitwarden/clients/releases/download/cli-v2026.3.0/bw-oss-linux-2026.3.0.zip && unzip bw.zip && sudo install -m 755 bw /usr/local/bin/bw'
ssh <m> 'sudo systemctl restart socialwarden-agent'
```

### Agent crashloop: `Login failure: You are not logged in`

- **Causa A (esperada en bundle-only)**: `sync.collections=[]` pero el agent intenta login → bug pre-v1.4.4. Upgrade a v1.4.4.
- **Causa B**: el master en `master.key` es incorrecto. Validar con `socialwarden-manager shamir-split` (genera shares, reconstruye, compara). O simplemente reescribir `master.key`.

### Discord spam: alerta cada 3 min

Agent en restart loop. Buscar la causa raíz en `journalctl -u socialwarden-agent` (status=1 exit). Hasta v1.4.3 el bundle-only mode causaba esto; v1.4.4+ lo arregla.

### Share-release HTTP no responde

```bash
ssh <peer> 'sudo journalctl -u socialwarden-agent --since "5 min ago" | grep -i "share-release\|shamir"'
ssh <peer> 'sudo ss -tlnp | grep 14841'   # ¿está bind?
curl -s http://<tailscale-ip>:14841/health
```

Suele ser: `shamir.enabled=false` en config, o agent aún sync inicializando (initial sync gates endpoint start).

### Reconstrucción Shamir falla (`gave up after Ns with X/K shares`)

```bash
ssh <target> 'sudo journalctl -u socialwarden-agent | grep "Shamir"'
# Para cada peer listado:
ssh <peer> 'sudo ls /var/lib/socialwarden/peer-shares/<target>.share'  # ¿hold el share?
ssh <peer> 'sudo systemctl is-active socialwarden-agent'                # ¿endpoint up?
ssh <peer> 'sudo cat /var/lib/socialwarden/peer-identities/<target>.pub' # ¿conoce la pubkey del target?
```

Si falta pubkey del target en algún peer: `sudo socialwarden-manager distribute-pubkeys`.

### Inventory dice una versión, fleet tiene otra

```bash
for h in host-1 host-2 host-3 host-4 host-5; do
  V=$(ssh "$h" 'cat /opt/socialwarden-agent/VERSION 2>/dev/null')
  echo "$h: $V"
done
```

Inventory se actualiza solo en `socialwarden-enroll`. Si la versión local subió manualmente, el inventory queda stale. Re-enroll con `--force` para sincronizar.

### Stale heartbeat (alerta `time() - socialwarden_last_sync_timestamp > 300`)

```bash
ssh <m> 'sudo cat /run/socialwarden/heartbeat'                              # cuándo fue
ssh <m> 'sudo journalctl -u socialwarden-agent --since "10 min ago" -p err' # errores recientes
```

---

## 12. Versión actual

`0.1.0` — release inicial. Incluye:

- Sync Vaultwarden → `/run/secrets/*.env` (mode 600 root, tmpfs)
- Bundle-push (age-encrypted env-files entregados fuera de Vault)
- Shamir K-of-N para resiliencia ante pérdida del cache `master.key`
- Boot reconstruction vía peer share-release endpoint (HTTP firmado ed25519)
- Hardening systemd (RuntimeDirectory, NoNewPrivileges, ProtectSystem=strict)
- Identity ed25519 per-machine
- Discord webhook para alertas (cambios, drift, errores, secret age)
- UDS API opcional (JIT secret access per-container con SO_PEERCRED + cgroup)
- Log scanner (honeypot tripwire, leak detection en stdout/stderr de containers)

---

## 14. Referencias rápidas

- **Inventory**: `/opt/your-infra-ops/inventory.json` — única fuente de verdad
- **Manager code**: `/opt/socialwarden-manager/socialwarden-manager` (symlinked en `/usr/local/bin/`)
- **Agent code**: `/opt/socialwarden-agent/socialwarden-agent.py` en cada client
- **Source repo**: `/opt/your-infra-ops/`
- **Audit central**: `/var/lib/socialwarden-manager/audit.log` en el manager host

Para cualquier comando que no recuerdes:

```bash
sudo socialwarden-manager help
sudo socialwarden-agent help
python3 machines.py
```
