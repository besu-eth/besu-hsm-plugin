#!/usr/bin/env bash
# Phase 5: Create a secp256k1 key pair on the HSM.
# Runs on the EC2 instance after Phase 4 (hsm_b added via Terraform).
# The CloudHSM CLI requires an interactive terminal — paste the commands
# below into the shell after it starts.

# ── Fill in before running ────────────────────────────────────────────────────
HSM_USER=CryptoUser1
PRIVATE_LABEL=validatorPrivate
PUBLIC_LABEL=validatorPublic
KEY_ID=0x01                        # unique hex ID per key pair, e.g. 0x01, 0x02 …
# ─────────────────────────────────────────────────────────────────────────────

/opt/cloudhsm/bin/cloudhsm-cli interactive

# Inside the interactive shell:
#
#   login --username $HSM_USER --role crypto-user
#
#   key generate-asymmetric-pair ec \
#     --curve secp256k1 \
#     --private-label $PRIVATE_LABEL \
#     --public-label $PUBLIC_LABEL \
#     --public-attributes verify=true id=$KEY_ID \
#     --private-attributes sign=true sensitive=true extractable=false derive=true id=$KEY_ID
#
# Key attributes:
#   sensitive=true    — private key value cannot be read in plaintext from the HSM
#   extractable=false — private key cannot be exported or wrapped
#   derive=true       — enables ECDH key agreement (required for Besu's devp2p handshakes)
