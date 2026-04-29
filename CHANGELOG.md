# Changelog

## Unreleased

### Added
- PKCS#11 SecurityModule implementation via SunPKCS11/JCE (`Pkcs11SecurityModule`, `Pkcs11Provider`)
- Besu plugin (`HsmPlugin`) with CLI options: `--plugin-pkcs11-hsm-config-path`, `--plugin-pkcs11-hsm-password-path`, `--plugin-pkcs11-hsm-key-alias`
- `--plugin-pkcs11-hsm-ec-curve` CLI option for elliptic curve selection (secp256k1 default, secp256r1 experimental)
- Docker-based integration tests using Testcontainers and SoftHSM2 (`docker/softhsm2/`)
- QBFT 4-node integration test with HSM-backed block signing, including value transfer verification
- Curve-parameterized integration tests for both secp256k1 and secp256r1
- CI integration test job in GitHub Actions workflow
- DiscV5 (Discovery v5) support for HSM-backed secp256k1 keys via `calculateECDHKeyAgreementCompressed` (probe-point workaround for PKCS#11's x-only ECDH)

## 0.0.0

Initial project setup.
