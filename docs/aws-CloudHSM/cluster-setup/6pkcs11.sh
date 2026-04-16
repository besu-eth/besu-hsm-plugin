#!/usr/bin/env bash
# Phase 6: Verify PKCS#11 access to the HSM.
# Runs on the EC2 instance. Lists all objects (keys, certs) visible to the
# Crypto User. You should see the key pair created in Phase 5.

# ── Fill in before running ────────────────────────────────────────────────────
PKCS11_MODULE_PATH=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so
HSM_USER=CryptoUser1
HSM_PASSWORD=your-password
# ─────────────────────────────────────────────────────────────────────────────

pkcs11-tool \
  --module $PKCS11_MODULE_PATH \
  --login \
  --pin "${HSM_USER}:${HSM_PASSWORD}" \
  --list-objects
