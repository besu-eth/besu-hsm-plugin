# Besu HSM Plugin
 [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/besu-eth/besu-hsm-plugin/blob/main/LICENSE)
 [![Discord](https://img.shields.io/discord/905194001349627914?logo=Hyperledger&style=plastic)](https://discord.com/invite/hyperledger)

A [PKCS#11](https://en.wikipedia.org/wiki/PKCS_11) based Hardware Security Module (HSM) plugin for [Hyperledger Besu](https://github.com/besu-eth/besu). This plugin enables Besu 
validators to delegate cryptographic signing operations to an HSM via the standard PKCS#11 interface, keeping private 
keys secure in dedicated hardware rather than in software.

## Architecture

![Besu HSM Plugin Architecture](docs/besu-hsm-plugin-architecture.png)

The plugin sits between the Besu client (validator) and HSM providers using the PKCS#11 interface. It supports:

- **Cloud HSM providers** — Connect to remote HSMs via vendor-specific PKCS#11 libraries (e.g. AWS CloudHSM, Azure 
Dedicated HSM, Google Cloud HSM)
- **Local HSMs** — Connect to on-premise HSM hardware via PKCS#11 libraries
- **Configuration** — Provider selection and authentication (secret/API key) are specified through plugin configuration

## HSM Key Setup

The plugin needs access to a private key and its corresponding public key on the PKCS#11 token. Java's SunPKCS11
`KeyStore` API requires a certificate to be associated with a private key — without one, the `KeyStore` will not
surface the private key entry at all. The certificate serves no cryptographic purpose; a self-signed certificate
is sufficient.

There are two approaches depending on where the key pair is generated:

### Option A: Generate Key Externally with OpenSSL

Generate the key pair and certificate with OpenSSL, then import everything into the HSM.

```shell
# Generate EC key pair and self-signed certificate
openssl ecparam -name secp256k1 -genkey -noout -out ec-key.pem
openssl req -new -x509 -key ec-key.pem -out ec-cert.pem -days 365 -subj "/CN=besu-hsm" -sha256

# Convert to DER format
openssl ec -in ec-key.pem -outform DER -out ec-key.der
openssl ec -in ec-key.pem -pubout -outform DER -out ec-pub.der
openssl x509 -in ec-cert.pem -outform DER -out ec-cert.der

# Import private key, public key, and certificate into HSM
pkcs11-tool --module <pkcs11-lib> --login --pin <pin> \
    --write-object ec-key.der --type privkey --label mykey --id 01 --usage-derive
pkcs11-tool --module <pkcs11-lib> --login --pin <pin> \
    --write-object ec-pub.der --type pubkey --label mykey --id 01 --usage-derive
pkcs11-tool --module <pkcs11-lib> --login --pin <pin> \
    --write-object ec-cert.der --type cert --label mykey --id 01
```

### Option B: Generate Key on the HSM with `pkcs11-tool`

Generate the key pair directly on the HSM, then create a self-signed certificate using OpenSSL's PKCS#11 engine 
(requires `libengine-pkcs11-openssl` / `libp11`). This keeps the private key on the HSM at all times.

```shell
# 1. Generate key pair on the HSM
pkcs11-tool --module <pkcs11-lib> --login --pin <pin> \
    --keypairgen --key-type EC:secp256k1 \
    --label mykey --id 01 --usage-sign --usage-derive

# 2. Create OpenSSL engine config (adjust paths for your platform)
cat > openssl-p11.cfg <<EOF
openssl_conf = openssl_def
[openssl_def]
engines = engine_section
[engine_section]
pkcs11 = pkcs11_section
[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so
MODULE_PATH = <pkcs11-lib>
EOF

# 3. Generate self-signed certificate (signed by the HSM private key)
#    The key is referenced via a PKCS#11 URI (RFC 7512) using stable
#    token/object labels rather than volatile slot numbers.
OPENSSL_CONF=openssl-p11.cfg openssl req -x509 -new \
    -engine pkcs11 -keyform engine \
    -key "pkcs11:token=<token-label>;object=mykey;type=private" \
    -passin "pass:<pin>" \
    -sha256 -subj "/CN=besu-hsm" -days 365 \
    -out cert.pem

# 4. Import certificate back to the HSM
openssl x509 -in cert.pem -outform DER -out cert.der
pkcs11-tool --module <pkcs11-lib> --login --pin <pin> \
    --write-object cert.der --type cert --label mykey --id 01
```

### Note on the Certificate Requirement

This is a limitation of Java's SunPKCS11 `KeyStore` implementation, not PKCS#11 itself. The PKCS#11 standard
does not require certificates for key access, but Java's `KeyStore` abstraction models private keys as
`PrivateKeyEntry` objects which always include a certificate chain. Without a certificate, `KeyStore.getKey()`
will not return the private key at all.

## Useful Links

* [Besu User Documentation](https://besu.hyperledger.org)
* [Besu HSM Plugin Issues]
* [Besu Wiki](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/)
* [How to Contribute to Besu](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22156850/How+to+Contribute)
* [Besu Maintainers](https://github.com/besu-eth/besu/blob/main/MAINTAINERS.md)

## Issues

Besu HSM Plugin issues are tracked [in the github issues tab][Besu HSM Plugin Issues].

If you have any questions, queries or comments, [Besu channel on Discord] is the place to find us.

## Besu HSM Plugin Developers

* [Contributing Guidelines]
* [Coding Conventions](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154259/Coding+Conventions)

### Development

Instructions for how to get started with developing on the Besu HSM Plugin codebase. Please also read the
[wiki](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154251/Pull+Requests) for more details on how to submit a pull request (PR).

### Prerequisites

* [Java 21+](https://adoptium.net/)
* [Gradle](https://gradle.org/) (or use the included Gradle wrapper)

### Building

```bash
./gradlew build
```

### Running Tests

```bash
./gradlew test
```

[Besu HSM Plugin Issues]: https://github.com/besu-eth/besu-hsm-plugin/issues
[Besu channel on Discord]: https://discord.com/invite/hyperledger
[Contributing Guidelines]: CONTRIBUTING.md
