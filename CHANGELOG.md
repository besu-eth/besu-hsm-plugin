# Changelog

## Unreleased

### Added
- PKCS#11 SecurityModule implementation via SunPKCS11/JCE (`Pkcs11SecurityModule`, `Pkcs11Provider`)
- Besu plugin (`HsmPlugin`) with CLI options: `--plugin-pkcs11-hsm-config-path`, `--plugin-pkcs11-hsm-password-path`, `--plugin-pkcs11-hsm-key-alias`
- Docker-based integration tests using Testcontainers and SoftHSM2
- Docker image setup for SoftHSM2 (`docker/softhsm/`) with auto token initialization and EC key import
- Placeholder Docker setups for YubiHSM and AWS CloudHSM

## 0.0.0

Initial project setup.
