#!/bin/bash
set -e

cleanup_tmpdir() {
    if [ -n "${TMPDIR:-}" ] && [ -d "${TMPDIR}" ]; then
        rm -rf "${TMPDIR}"
    fi
}
trap cleanup_tmpdir EXIT

# Read PIN from password file
PIN=$(cat /etc/besu/config/pkcs11-hsm-password.txt | tr -d '[:space:]')
TOKEN_LABEL="testtoken"
KEY_LABEL="testkey"
EC_CURVE="${EC_CURVE:-secp256k1}"

# Initialize SoftHSM2 token if not already present
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*${TOKEN_LABEL}"; then
    echo "Initializing SoftHSM2 token '${TOKEN_LABEL}' ..."
    softhsm2-util --init-token --slot 0 --label "${TOKEN_LABEL}" --pin "${PIN}" --so-pin "${PIN}"
fi

# Generate and import key if not already present
if ! pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin "${PIN}" \
    --token-label "${TOKEN_LABEL}" --list-objects --type privkey 2>/dev/null | grep -q "${KEY_LABEL}"; then

    echo "Generating EC key pair (curve: ${EC_CURVE}) ..."
    TMPDIR=$(mktemp -d)

    # Generate EC private key
    openssl ecparam -name "${EC_CURVE}" -genkey -noout -out "${TMPDIR}/ec-key.pem"

    # Extract public key
    openssl ec -in "${TMPDIR}/ec-key.pem" -pubout -out "${TMPDIR}/ec-pub.pem"

    # Generate self-signed certificate
    openssl req -new -x509 -key "${TMPDIR}/ec-key.pem" -out "${TMPDIR}/ec-cert.pem" \
        -days 365 -subj "/CN=besu-hsm-test" -sha256

    # Convert to DER format for import
    openssl ec -in "${TMPDIR}/ec-key.pem" -outform DER -out "${TMPDIR}/ec-key.der"
    openssl ec -in "${TMPDIR}/ec-key.pem" -pubout -outform DER -out "${TMPDIR}/ec-pub.der"
    openssl x509 -in "${TMPDIR}/ec-cert.pem" -outform DER -out "${TMPDIR}/ec-cert.der"

    # Import private key
    pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin "${PIN}" \
        --token-label "${TOKEN_LABEL}" \
        --write-object "${TMPDIR}/ec-key.der" --type privkey \
        --label "${KEY_LABEL}" --id 01 --usage-derive

    # Import public key
    pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin "${PIN}" \
        --token-label "${TOKEN_LABEL}" \
        --write-object "${TMPDIR}/ec-pub.der" --type pubkey \
        --label "${KEY_LABEL}" --id 01 --usage-derive

    # Import certificate
    pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin "${PIN}" \
        --token-label "${TOKEN_LABEL}" \
        --write-object "${TMPDIR}/ec-cert.der" --type cert \
        --label "${KEY_LABEL}" --id 01

    echo "Key pair and certificate imported successfully."
fi

exec /opt/besu/bin/besu "$@"
