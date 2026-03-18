#!/bin/bash
set -e

# Read PIN from password file
PIN=$(cat /etc/besu/config/pkcs11-hsm-password.txt | tr -d '[:space:]')
TOKEN_LABEL="testtoken"
KEY_LABEL="testkey"
KEY_ID_HEX="01"
EC_CURVE="${EC_CURVE:-secp256k1}"
MODULE="/usr/lib/softhsm/libsofthsm2.so"

# Initialize SoftHSM2 token if not already present
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*${TOKEN_LABEL}"; then
    echo "Initializing SoftHSM2 token '${TOKEN_LABEL}' ..."
    softhsm2-util --init-token --slot 0 --label "${TOKEN_LABEL}" --pin "${PIN}" --so-pin "${PIN}"
fi

# Generate key pair and self-signed certificate if not already present
if ! pkcs11-tool --module "${MODULE}" --login --pin "${PIN}" \
    --token-label "${TOKEN_LABEL}" --list-objects --type privkey 2>/dev/null | grep -q "${KEY_LABEL}"; then

    echo "Generating EC key pair on HSM (curve: ${EC_CURVE}) ..."

    # 1. Generate key pair directly on the HSM
    pkcs11-tool --module "${MODULE}" --login --pin "${PIN}" \
        --token-label "${TOKEN_LABEL}" \
        --keypairgen --key-type "EC:${EC_CURVE}" \
        --label "${KEY_LABEL}" --id "${KEY_ID_HEX}" \
        --usage-sign --usage-derive

    # 2. Create self-signed certificate using OpenSSL PKCS#11 engine.
    #    This signs the certificate using the private key on the HSM.
    #    The key is referenced via a PKCS#11 URI (RFC 7512) which uses stable
    #    token/object labels instead of volatile slot numbers.
    ENGINE_PATH=$(find /usr/lib -name 'pkcs11.so' -path '*/engines-*' 2>/dev/null | head -1)
    TMPDIR=$(mktemp -d)

    cat > "${TMPDIR}/openssl-p11.cfg" <<SSLCFG
openssl_conf = openssl_def

[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = ${ENGINE_PATH}
MODULE_PATH = ${MODULE}
SSLCFG

    OPENSSL_CONF="${TMPDIR}/openssl-p11.cfg" openssl req -x509 -new \
        -engine pkcs11 \
        -keyform engine \
        -key "pkcs11:token=${TOKEN_LABEL};object=${KEY_LABEL};type=private" \
        -passin "pass:${PIN}" \
        -sha256 \
        -subj "/CN=besu-hsm-keypairgen" \
        -days 365 \
        -out "${TMPDIR}/cert.pem"

    # 3. Import certificate back to the token
    openssl x509 -in "${TMPDIR}/cert.pem" -outform DER -out "${TMPDIR}/cert.der"

    pkcs11-tool --module "${MODULE}" --login --pin "${PIN}" \
        --token-label "${TOKEN_LABEL}" \
        --write-object "${TMPDIR}/cert.der" --type cert \
        --label "${KEY_LABEL}" --id "${KEY_ID_HEX}"

    rm -rf "${TMPDIR}"
    echo "Key pair and self-signed certificate generated successfully."
fi

exec /opt/besu/bin/besu "$@"
