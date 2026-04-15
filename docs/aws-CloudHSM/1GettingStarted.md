# AWS CloudHSM — Getting Started

This guide walks through installing the AWS CloudHSM client SDKs, configuring your
environment, and generating secp256k1 validator keys on the HSM. By the end, you will
have five validator key pairs on the HSM and their raw public keys exported for use in
QBFT genesis configuration.

## Prerequisites

- **An initialized and activated CloudHSM cluster.** Follow the
  [AWS cluster initialization guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/initialize-cluster.html)
  if you have not done this yet. You will need:
  - The HSM IP address
  - The cluster certificate (`customerCA.crt`)
  - CryptoUser credentials (username and password)
- **An EC2 instance running Ubuntu 24.04 LTS** in the same VPC as the CloudHSM cluster.
- Copy the cluster certificate to `/opt/cloudhsm/etc/customerCA.crt` (the default
  location). If you place it elsewhere, specify the path explicitly when configuring
  each SDK.

## Install the CloudHSM CLI

The CloudHSM CLI is used to activate the cluster and manage HSM users. Install and
bootstrap it following the
[CloudHSM CLI installation guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/gs_cloudhsm_cli-install.html).

## Environment Variables

The following environment variables are required by the CloudHSM SDKs and the commands
in this guide. Add them to `~/.bashrc` or `~/.profile` for persistence, or export them
manually in each session:

```bash
export HSM_A_PRIVATE_IP=IP.ADDR.OF.HSM
export CLOUDHSM_PIN="CryptoUser:CryptoUserPassword"
export CLOUDHSM_ROLE=crypto-user
export PKCS11_MODULE_PATH=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so
export PATH=$PATH:/opt/cloudhsm/bin
export HSM_USER=CryptoUser
export HSM_PASSWORD=CryptoUserPassword
```

Replace `IP.ADDR.OF.HSM`, `CryptoUser`, and `CryptoUserPassword` with your actual values.

## Install the PKCS#11 Library

Install the CloudHSM PKCS#11 library following the
[PKCS#11 library installation guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html),
then bootstrap it using the instructions under the **PKCS#11 library** tab in the
[cluster connection guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/cluster-connect.html#connect-how-to).

## Install the JCE Provider

Install the CloudHSM JCE provider following the
[JCE provider installation guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html),
then bootstrap it using the instructions under the **JCE provider** tab in the
[cluster connection guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/cluster-connect.html#connect-how-to).

> **Important:** You must enable ECDH without a KDF. Besu uses raw ECDH key agreement for
> devp2p handshakes — if this flag is not set, CloudHSM applies a key derivation function to
> the ECDH output, which is incompatible with Besu's expectations.

```bash
sudo /opt/cloudhsm/bin/configure-jce -a $HSM_A_PRIVATE_IP \
  --hsm-ca-cert /opt/cloudhsm/etc/customerCA.crt --enable-ecdh-without-kdf
```

## Generating Validator Keys

The following commands create five secp256k1 key pairs on the HSM, one per validator
node. Each key pair consists of a public key (used for verification) and a private key
(used for signing and ECDH). These commands assume the environment variables above are
already exported.

```bash
for i in 1 2 3 4 5; do \
  cloudhsm-cli key generate-asymmetric-pair ec \
    --curve secp256k1 \
    --public-label "testValidator${i}:Public" \
    --private-label "testValidator${i}:Private" \
    --public-attributes verify=true id=$(printf "0x%02x" $i) \
    --private-attributes sign=true \
      sensitive=true \
      extractable=false \
      derive=true \
      id=$(printf "0x%02x" $i); \
done
```

Key attribute notes:
- `sensitive=true` — the private key value cannot be read off the HSM in plaintext
- `extractable=false` — the private key cannot be wrapped or exported
- `derive=true` — enables ECDH key agreement (required for Besu's devp2p handshakes)

### Extracting Public Keys

Extract the raw uncompressed public keys from the HSM and write them to `public_keys.json`.
This file is used when generating the QBFT genesis configuration.

```bash
for i in 1 2 3 4 5; do \
  cloudhsm-cli key list \
    --filter attr.label="testValidator${i}:Public" \
    --verbose \
    | jq -r '.data.matched_keys[0].attributes."ec-point"' \
    | sed 's/^0x044104/0x/'; \
done | jq -R . | jq -s . > public_keys.json
```

The `ec-point` attribute returned by CloudHSM is DER-encoded: `0x04` (ASN.1 OCTET STRING
tag) followed by `0x41` (65-byte length) followed by `0x04` (uncompressed point indicator)
and the 64-byte X/Y coordinates. The `sed` command strips this `044104` prefix to produce
the raw 64-byte public key that Besu expects.

## Next Steps

- [QBFT Setup — CloudHSM JCE Provider](2QBFTSetup-JCE.md)

