#!/bin/bash
set -e

# Phase 3: Start Besu with QBFT configuration. Token data persists from Phase 1
# via the mounted /var/lib/tokens volume.
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

echo "Starting Besu ..."
exec /opt/besu/bin/besu "$@"
