# Break-Glass Runbook — SocialWarden Master Recovery

**Cuándo usar este documento:** desastre total. La fleet no puede arrancar
porque ha perdido suficientes share holders para que el manager `recover`
funcione. Ejemplo: pérdida simultánea de 3+ máquinas en una región AWS.

**Quién:** sólo el responsable de seguridad / CTO / DPO con acceso físico al
sobre cerrado donde está la break-glass share.

**Frecuencia esperada:** nunca. Si tienes que usarlo, algo terriblemente
inusual ha pasado. Documenta el incidente.

---

## ¿Qué es la break-glass share?

Es la share x=N+1 (la sexta, fuera del Shamir K=3/N=5 normal). Generada por el
operator durante el enroll inicial, **impresa en papel** y guardada en una caja
fuerte / sobre lacrado / safe deposit box. Nunca tocada digitalmente después.

Combinada con la share del manager (en `/var/lib/socialwarden-manager/shares/<machine>.share`)
da K=2 shares — pero el master usa K=3, así que no basta sola. Necesitas también
**al menos una peer share**, leída de cualquier máquina de la fleet que aún
exista (incluso una offline si pudiste extraer su disco).

> **Sin la break-glass share PERO con 3 peer shares disponibles** → usa
> `socialwarden-manager recover <machine>` normal, no necesitas este runbook.

---

## Generación inicial de la break-glass share (UNA VEZ por máquina)

Esto se hace tras `enroll-shamir` exitoso, antes del primer release a prod:

```bash
# En el manager host, como root:
sudo socialwarden-manager break-glass-emit <machine>

# Output:
# x=06:abcd1234ef567890ab1234567890abcdef1234567890abcd...
#
# Imprime esto en papel, guárdalo en sobre lacrado con el nombre de la máquina,
# en caja fuerte. NO lo guardes digitalmente.
```

`break-glass-emit` genera un share adicional fuera del polynomial estándar (x=6)
que NUNCA se distribuye. Solo se imprime una vez. La share hace match con el
master vivo gracias a las propiedades de Shamir (cualquier K shares correctos
reconstruyen, sin importar de qué subset salieron).

---

## Procedimiento de break-glass (cuando todo lo demás falló)

### Pre-requisitos

1. ✅ El manager host está vivo y accesible
2. ✅ Tienes acceso al sobre con la break-glass share impresa
3. ✅ Conoces el nombre de la máquina a recuperar (`<machine>`)
4. ✅ Tienes acceso a al menos UNA peer share — bien sea:
   - SSH a un peer vivo (preferido)
   - Disco extraído de un peer y montado read-only en el manager host

### Pasos

#### 1. Sanidad: confirma manager share intacta

```bash
sudo cat /var/lib/socialwarden-manager/shares/<machine>.share
# Debe mostrar línea: 05:hexlongstring...
```

Si está vacía o corrupta → la situación es peor de lo que pensabas. Salta a
"Si todo lo demás falla" abajo.

#### 2. Lee una peer share

**Caso A: peer vivo accesible por SSH**
```bash
ssh <peer-name> 'sudo cat /var/lib/socialwarden/peer-shares/<machine>.share'
# Debe mostrar línea: 02:hex... (o 03, 04 según x)
```

**Caso B: disco de peer offline montado en el manager host**
```bash
sudo mount -o ro /dev/<device> /mnt/recovery
sudo cat /mnt/recovery/var/lib/socialwarden/peer-shares/<machine>.share
sudo umount /mnt/recovery
```

#### 3. Combina las 3 shares (manager + peer + break-glass)

```bash
sudo socialwarden-manager shamir-combine <<EOF
05:<contenido manager share>
02:<contenido peer share>
06:<contenido break-glass share del papel>
EOF
```

Output: el master plaintext en stdout.

#### 4. Re-enroll la fleet con el master recuperado (decisión)

Si la fleet entera está dañada y necesitas reconstruirla:

```bash
# Salva el master a archivo temporal mode 600
sudo bash -c 'umask 077 && cat > /tmp/.master.recovered'
# Pega el master, Ctrl-D

# Para cada máquina enrolled:
for m in host-1 host-2 host-3 host-4; do
  echo "Re-enrolling $m..."
  sudo bash -c "cat /tmp/.master.recovered | socialwarden-manager enroll-shamir $m --force"
done

# Borrar plaintext
sudo shred -u /tmp/.master.recovered
```

Si solo necesitas restaurar una máquina (las demás están bien):

```bash
sudo bash -c 'umask 077 && cat > /tmp/.master.recovered'
# pega master, Ctrl-D
sudo bash -c 'cat /tmp/.master.recovered | socialwarden-manager enroll-shamir <machine> --force'
sudo shred -u /tmp/.master.recovered
```

#### 5. Re-genera la break-glass share

La break-glass share del papel ya quedó "quemada" (digitalmente vista). Genera
una nueva, imprímela, guárdala, **destruye físicamente la antigua** (shredder).

```bash
sudo socialwarden-manager break-glass-emit <machine>
# Imprime la nueva, guarda en sobre lacrado, destruye papel viejo
```

#### 6. Documenta el incidente

```
INCIDENT REPORT — <fecha>
Trigger: <qué pasó>
Affected machines: <lista>
Recovery time: <duración>
Break-glass share consumed: yes
New break-glass share generated: yes / no
Operator: <nombre>
```

Email a CTO + DPO. Archivado en `/var/lib/socialwarden-manager/incident-log/`.

---

## Si todo lo demás falla

La manager share local TAMBIÉN está corrupta o perdida. Ya sólo tienes la
break-glass share + alguna peer share. Eso son 2 shares. K=3.

**Opciones:**

1. **Encontrar otra peer share** — busca en cualquier disco de la fleet,
   incluso una que pensabas perdida. Solo necesitas UNA más.
2. **Restaurar manager share desde backup** — el manager debería tener backup
   automático de `/var/lib/socialwarden-manager/shares/` (verifica con tu equipo
   de DevOps).
3. **Aceptar pérdida** — si realmente sólo tienes 2 shares, el master está
   irrecuperable matemáticamente. Hay que rotar el master en Vaultwarden con
   un master nuevo, re-enroll fleet desde cero (`enroll-shamir --force` con
   nuevo master en cada máquina).

---

## Detección preventiva

Para evitar llegar aquí: el cron `verify-shamir` corre cada hora y alerta
(Discord/Slack/etc.) si no puede reconstruir. Si recibes esa alerta,
escala inmediatamente — significa que la fleet está en estado degradado y
un incidente más te puede dejar sin recovery.

```bash
# Manualmente:
sudo socialwarden-manager verify-shamir
```

---

## Apéndice — Diagrama de los shares

Para K=3, N=5, máquina `<m>`:

```
┌──────────────────────────────────────────────────────────────────────┐
│ Master de Vaultwarden (in-memory only durante reconstruct)           │
└────────┬─────────────────────────────────────────────────────────────┘
         │ shamir.split_bytes(master, k=3, n=5)
         ▼
   ┌─────┴────┬─────┬─────┬─────┐    ┌─────┐
   │ x=1      │ x=2 │ x=3 │ x=4 │ x=5│ x=6 │ ← break-glass (extra fuera de N)
   ▼          ▼     ▼     ▼     ▼    ▼
   target    peerA peerB peerC mgr  PAPER (sobre lacrado, caja fuerte)
   /var/lib/...    .../peer-shares/<m>.share    /var/lib/socialwarden-manager/shares/<m>.share

Reconstrucción autónoma (boot):
   target's local x=1 + 2 peer responses via HTTP signed → K=3 → master

Recovery (operator):
   manager x=5 + 2 peer SSH reads → K=3 → master

Break-glass (este runbook):
   manager x=5 + 1 peer share + paper x=6 → K=3 → master
```
