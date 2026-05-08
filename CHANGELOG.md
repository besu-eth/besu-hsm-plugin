# Changelog

## Unreleased

### Added
- `native-pkcs11` provider for the PKCS#11 v2.40 HSM standard, using Java's Foreign Function & Memory API
- Docker-based integration tests using Testcontainers and SoftHSM2 (`docker/softhsm2/`)
- QBFT 4-node integration test with HSM-backed block signing, including value transfer verification
- Curve-parameterized integration tests for both secp256k1 and secp256r1
- CI integration test job in GitHub Actions workflow
- DiscV5 (Discovery v5) support for HSM-backed secp256k1 keys via `calculateECDHKeyAgreementCompressed` (probe-point workaround for PKCS#11's x-only ECDH)

## 0.0.0

Initial project setup.
