#!/bin/bash
set -e

# Phase 3: Start Besu with QBFT configuration. Token data persists from Phase 1
# via the mounted /var/lib/tokens volume.
#
# Runs as root (matching the base Besu image) and switches to the besu user
# after fixing token file permissions — mirroring the official besu-entry.sh
# pattern.
#
# Usage: entrypoint-besu.sh [besu-args...]

PIN=$(cat /etc/besu/config/pkcs11-hsm-password.txt | tr -d '[:space:]')
TOKEN_LABEL="testtoken"
KEY_LABEL="testkey"
MODULE="/usr/lib/softhsm/libsofthsm2.so"

# Verify the key exists on the token
if ! pkcs11-tool --module "${MODULE}" --login --pin "${PIN}" \
    --token-label "${TOKEN_LABEL}" --list-objects --type privkey 2>/dev/null | grep -q "${KEY_LABEL}"; then
    echo "ERROR: Private key '${KEY_LABEL}' not found on token '${TOKEN_LABEL}'."
    echo "Run entrypoint-setup.sh first to generate the key."
    exit 1
fi

# Fix ownership on bind-mounted volumes so the besu user can access them.
# Phase 1 and 2 run as root, creating files owned by root in these mounts.
chown -R besu:besu /var/lib/tokens /data

echo "Starting Besu ..."
exec su -s /bin/bash besu -- /opt/besu/bin/besu "$@"
