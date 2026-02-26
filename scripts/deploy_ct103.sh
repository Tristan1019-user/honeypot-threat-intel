#!/usr/bin/env bash
set -euo pipefail

# Reproducible deploy to CT 103 threat-intel stack.
# Requires SSH key ~/.ssh/openclaw_proxmox_ro and access to root@192.168.1.13

PROXMOX_HOST="root@192.168.1.13"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/openclaw_proxmox_ro}"
STACK_DIR="/opt/stacks/threat-intel"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[1/3] Package app python sources"
TMP_TAR="/tmp/threat-intel-app-sync.tgz"
(
  cd "$ROOT_DIR"
  find app -type f -name '*.py' | sort | tar -czf "$TMP_TAR" -T -
)

scp -i "$SSH_KEY" "$TMP_TAR" "$PROXMOX_HOST:/tmp/threat-intel-app-sync.tgz"


echo "[2/3] Push files into CT103"
ssh -i "$SSH_KEY" "$PROXMOX_HOST" "
  set -e
  pct exec 103 -- mkdir -p $STACK_DIR
  pct push 103 /tmp/threat-intel-app-sync.tgz /tmp/threat-intel-app-sync.tgz
  pct exec 103 -- bash -lc 'cd $STACK_DIR && tar -xzf /tmp/threat-intel-app-sync.tgz && rm -f /tmp/threat-intel-app-sync.tgz'
"


echo "[3/3] Restart container and verify health"
ssh -i "$SSH_KEY" "$PROXMOX_HOST" "
  set -e
  pct exec 103 -- bash -lc 'docker compose -f $STACK_DIR/compose.yml restart threat-intel-api'
"

sleep 2
curl -fsS https://threat-intel.101904.xyz/api/v1/health >/dev/null
curl -fsS https://threat-intel.101904.xyz/api/v1/startup-check >/dev/null
echo "Deploy OK"
