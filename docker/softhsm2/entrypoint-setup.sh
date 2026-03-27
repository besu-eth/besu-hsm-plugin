#!/bin/bash
set -e

# Phase 1: Generate EC key pair with OpenSSL, import into SoftHSM2 with a
# self-signed certificate, then export the uncompressed public key hex
# to /data/node-N/pubkey.hex.
#
# Usage: entrypoint-setup.sh <node-index>
#   e.g. entrypoint-setup.sh 0

cleanup_tmpdir() {
    if [ -n "${TMPDIR:-}" ] && [ -d "${TMPDIR}" ]; then
        rm -rf "${TMPDIR}"
    fi
}
trap cleanup_tmpdir EXIT

NODE_INDEX="${1:?Usage: entrypoint-setup.sh <node-index>}"

PIN=$(cat /etc/besu/config/pkcs11-hsm-password.txt | tr -d '[:space:]')
TOKEN_LABEL="testtoken"
KEY_LABEL="testkey"
EC_CURVE="${EC_CURVE:-secp256k1}"
MODULE="/usr/lib/softhsm/libsofthsm2.so"
OUTPUT_DIR="/data/node-${NODE_INDEX}"

mkdir -p "${OUTPUT_DIR}"

# Initialize SoftHSM2 token if not already present
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*${TOKEN_LABEL}"; then
    echo "[node-${NODE_INDEX}] Initializing SoftHSM2 token '${TOKEN_LABEL}' ..."
    softhsm2-util --init-token --slot 0 --label "${TOKEN_LABEL}" --pin "${PIN}" --so-pin "${PIN}"
fi

# Generate and import key if not already present
if ! pkcs11-tool --module "${MODULE}" --login --pin "${PIN}" \
    --token-label "${TOKEN_LABEL}" --list-objects --type privkey 2>/dev/null | grep -q "${KEY_LABEL}"; then

    echo "[node-${NODE_INDEX}] Generating EC key pair (curve: ${EC_CURVE}) ..."
    TMPDIR=$(mktemp -d)

    # Generate EC private key
    openssl ecparam -name "${EC_CURVE}" -genkey -noout -out "${TMPDIR}/ec-key.pem"

    # Extract public key
    openssl ec -in "${TMPDIR}/ec-key.pem" -pubout -out "${TMPDIR}/ec-pub.pem"

    # Generate self-signed certificate
    openssl req -new -x509 -key "${TMPDIR}/ec-key.pem" -out "${TMPDIR}/ec-cert.pem" \
        -days 365 -subj "/CN=besu-qbft-node-${NODE_INDEX}" -sha256

    # Convert to DER format for import
    openssl ec -in "${TMPDIR}/ec-key.pem" -outform DER -out "${TMPDIR}/ec-key.der"
    openssl ec -in "${TMPDIR}/ec-key.pem" -pubout -outform DER -out "${TMPDIR}/ec-pub.der"
    openssl x509 -in "${TMPDIR}/ec-cert.pem" -outform DER -out "${TMPDIR}/ec-cert.der"

    # Import private key
    pkcs11-tool --module "${MODULE}" --login --pin "${PIN}" \
        --token-label "${TOKEN_LABEL}" \
        --write-object "${TMPDIR}/ec-key.der" --type privkey \
        --label "${KEY_LABEL}" --id 01 --usage-derive

    # Import public key
    pkcs11-tool --module "${MODULE}" --login --pin "${PIN}" \
        --token-label "${TOKEN_LABEL}" \
        --write-object "${TMPDIR}/ec-pub.der" --type pubkey \
        --label "${KEY_LABEL}" --id 01 --usage-derive

    # Import certificate
    pkcs11-tool --module "${MODULE}" --login --pin "${PIN}" \
        --token-label "${TOKEN_LABEL}" \
        --write-object "${TMPDIR}/ec-cert.der" --type cert \
        --label "${KEY_LABEL}" --id 01

    # Export uncompressed public key hex (without 04 prefix) for genesis construction.
    # The public key in text form is: 04:xx:xx:..., we strip the 04 prefix and colons.
    PUBKEY_HEX=$(openssl ec -pubin -in "${TMPDIR}/ec-pub.pem" -text -noout 2>/dev/null \
        | sed -n '/pub:/,/ASN1/p' \
        | grep -v 'pub:' | grep -v 'ASN1' \
        | tr -d ' :\n' \
        | sed 's/^04//')

    if [ -z "${PUBKEY_HEX}" ] || [ ${#PUBKEY_HEX} -ne 128 ]; then
        echo "[node-${NODE_INDEX}] ERROR: Failed to extract public key hex (got '${PUBKEY_HEX}')"
        exit 1
    fi

    echo "${PUBKEY_HEX}" > "${OUTPUT_DIR}/pubkey.hex"

    echo "[node-${NODE_INDEX}] Key pair imported. Public key written to ${OUTPUT_DIR}/pubkey.hex"
else
    echo "[node-${NODE_INDEX}] Key already exists on token."
fi

echo "[node-${NODE_INDEX}] Setup complete."
