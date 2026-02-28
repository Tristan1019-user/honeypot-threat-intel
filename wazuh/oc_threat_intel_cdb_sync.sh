#!/usr/bin/env bash
# oc_threat_intel_cdb_sync.sh
# Syncs honeypot threat intel into Wazuh's malicious-ioc CDB lists.
#
# Merges our high/critical IPs and malware hashes into the existing
# malicious-ip and malware-hashes CDB files on the Wazuh manager (CT 108).
# Existing third-party entries are preserved.
#
# Schedule: 0 * * * * (hourly)
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
set -euo pipefail

FEED_API="http://192.168.1.199:8099"    # CT 103, internal LAN direct
ADMIN_TOKEN="$(pct exec 103 -- bash -c "grep '^ADMIN_TOKEN=' /opt/stacks/threat-intel/.env | cut -d= -f2-" 2>/dev/null)"
if [ -z "${ADMIN_TOKEN:-}" ]; then
    echo "ERROR: could not read ADMIN_TOKEN from CT103 .env (CT down or token missing) — aborting" >&2
    exit 1
fi
WAZUH_CT=108
MALICIOUS_IP_PATH="/var/ossec/etc/lists/malicious-ioc/malicious-ip"
MALWARE_HASH_PATH="/var/ossec/etc/lists/malicious-ioc/malware-hashes"
LOCKFILE="/var/lock/oc_cdb_sync.lock"

exec 9>"$LOCKFILE"
flock -n 9 || { echo "already running"; exit 0; }

# ── 1. fetch new IPs from feed API (high + critical, min 2 sightings) ──────────
NEW_IPS=$(curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${FEED_API}/api/v1/feed/cdb?threat_level=high,critical&min_sightings=2" || true)
# ── 2. fetch new hashes ─────────────────────────────────────────────────────────
NEW_HASHES=$(curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${FEED_API}/api/v1/feed/hashes" || true)

# Nothing to do if the API returned empty
if [ -z "${NEW_IPS:-}" ] && [ -z "${NEW_HASHES:-}" ]; then
    echo "Feed returned empty — skipping sync"
    exit 0
fi

# ── 3. pull existing CDB files from Wazuh CT ───────────────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

pct pull "${WAZUH_CT}" "${MALICIOUS_IP_PATH}" "${TMPDIR}/malicious-ip" 2>/dev/null || touch "${TMPDIR}/malicious-ip"
pct pull "${WAZUH_CT}" "${MALWARE_HASH_PATH}" "${TMPDIR}/malware-hashes" 2>/dev/null || touch "${TMPDIR}/malware-hashes"

# ── 4. merge: add new entries that aren't already present ─────────────────────
python3 - <<'PY' "${TMPDIR}/malicious-ip" "${TMPDIR}/malware-hashes" "$NEW_IPS" "$NEW_HASHES"
import sys

def merge_cdb(existing_path: str, new_lines: str) -> tuple[str, int]:
    """Merge new_lines into existing CDB file. Returns (content, added_count)."""
    existing: dict[str, str] = {}
    try:
        with open(existing_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                key, _, val = line.partition(":")
                existing[key.strip()] = val.strip()
    except FileNotFoundError:
        pass

    added = 0
    for line in new_lines.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        if key not in existing:
            existing[key] = val.strip()
            added += 1

    content = "\n".join(f"{k}:{v}" for k, v in sorted(existing.items())) + "\n"
    with open(existing_path, "w") as f:
        f.write(content)
    return content, added

ip_file, hash_file, new_ips, new_hashes = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

_, ip_added = merge_cdb(ip_file, new_ips)
_, hash_added = merge_cdb(hash_file, new_hashes)
print(f"IPs added: {ip_added}, hashes added: {hash_added}")
PY

# ── 5. push merged files back to Wazuh ─────────────────────────────────────────
pct push "${WAZUH_CT}" "${TMPDIR}/malicious-ip"    "${MALICIOUS_IP_PATH}"
pct push "${WAZUH_CT}" "${TMPDIR}/malware-hashes"  "${MALWARE_HASH_PATH}"

# ── 6. trigger Wazuh to recompile CDB lists ────────────────────────────────────
# wazuh-logtest is an interactive testing tool — it does NOT compile CDB lists.
# The actual recompilation happens when wazuh-manager reloads.
pct exec "${WAZUH_CT}" -- bash -c \
  "systemctl reload-or-restart wazuh-manager 2>/dev/null || true"

echo "CDB sync complete"
