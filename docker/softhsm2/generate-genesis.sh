#!/bin/bash
set -e

# Phase 2: Read public keys from /data/node-*/pubkey.hex, generate QBFT genesis
# using `besu operator generate-blockchain-config`, and build static-nodes.json.
#
# Usage: generate-genesis.sh [node-count]
#   Default node-count is 4.

NODE_COUNT="${1:-4}"
DATA_DIR="/data"
OUTPUT_DIR="${DATA_DIR}/output"

# Ensure output directory is clean
rm -rf "${OUTPUT_DIR}"

# Read public keys
KEYS_JSON="["
for i in $(seq 0 $((NODE_COUNT - 1))); do
    PUBKEY_FILE="${DATA_DIR}/node-${i}/pubkey.hex"
    if [ ! -f "${PUBKEY_FILE}" ]; then
        echo "ERROR: Public key file not found: ${PUBKEY_FILE}"
        exit 1
    fi
    PUBKEY=$(cat "${PUBKEY_FILE}" | tr -d '[:space:]')
    if [ ${#PUBKEY} -ne 128 ]; then
        echo "ERROR: Invalid public key length in ${PUBKEY_FILE}: expected 128 hex chars, got ${#PUBKEY}"
        exit 1
    fi
    if [ $i -gt 0 ]; then
        KEYS_JSON="${KEYS_JSON},"
    fi
    KEYS_JSON="${KEYS_JSON}\"0x${PUBKEY}\""
    echo "Node ${i} public key: 0x${PUBKEY:0:16}..."
done
KEYS_JSON="${KEYS_JSON}]"

# Build the operator config file for besu generate-blockchain-config.
# "generate": false tells Besu to use supplied public keys instead of generating new ones.
# Pre-fund a known account for transaction testing.
TMPDIR=$(mktemp -d)
cat > "${TMPDIR}/qbftConfigFile.json" <<EOF
{
  "genesis": {
    "config": {
      "chainId": 1337,
      "berlinBlock": 0,
      "londonBlock": 0,
      "qbft": {
        "blockperiodseconds": 2,
        "epochlength": 30000,
        "requesttimeoutseconds": 4
      }
    },
    "nonce": "0x0",
    "timestamp": "0x0",
    "gasLimit": "0x1fffffffffffff",
    "difficulty": "0x1",
    "mixHash": "0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365",
    "coinbase": "0x0000000000000000000000000000000000000000",
    "alloc": {
      "fe3b557e8fb62b89f4916b721be55ceb828dbd73": {
        "balance": "0xad78ebc5ac6200000"
      }
    }
  },
  "blockchain": {
    "nodes": {
      "generate": false,
      "keys": ${KEYS_JSON}
    }
  }
}
EOF

echo "Generating QBFT genesis with besu operator generate-blockchain-config ..."
/opt/besu/bin/besu operator generate-blockchain-config \
    --config-file="${TMPDIR}/qbftConfigFile.json" \
    --to="${OUTPUT_DIR}"

# Copy genesis to a well-known location
cp "${OUTPUT_DIR}/genesis.json" "${DATA_DIR}/genesis.json"
echo "Genesis written to ${DATA_DIR}/genesis.json"

rm -rf "${TMPDIR}"
echo "Genesis generation complete."
