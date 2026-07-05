#!/bin/bash
# Generate the Wazuh internal CA + node certificates using the official tool.
#
# Inputs:  certs/config.yml — node names + IPs (loopback by default)
# Outputs: certs/*.pem (root-ca, admin, manager, indexer, dashboard)
#
# Run once before first `docker compose up`. Re-run only when adding nodes.
# Generated keys must NEVER be committed (covered by .gitignore).
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f certs/config.yml ]; then
  echo "[!] certs/config.yml not found — copy from the template and edit IPs/names" >&2
  exit 1
fi

# Wazuh ships an official certificate-generation tool. Pull it once.
if [ ! -f certs/wazuh-certs-tool.sh ]; then
  echo "[*] Downloading wazuh-certs-tool…"
  curl -fsSL -o certs/wazuh-certs-tool.sh \
    https://packages.wazuh.com/4.14/wazuh-certs-tool.sh
  chmod +x certs/wazuh-certs-tool.sh
fi

cd certs
./wazuh-certs-tool.sh -A
# The tool emits ./wazuh-certificates/*.pem — flatten for compose volume mounts.
mv -f wazuh-certificates/* .
rmdir wazuh-certificates 2>/dev/null || true

echo "[OK] Certs generated in certs/"
ls -la *.pem
