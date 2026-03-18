# SoftHSM2 Docker Image for Besu HSM Plugin

Docker image based on `hyperledger/besu` with SoftHSM2 installed for testing the PKCS#11 HSM plugin.

## What it does

The entrypoint script (`entrypoint.sh`) automatically:
1. Initializes a SoftHSM2 token (`testtoken`) with PIN `1234`
2. Generates an EC key pair (default: `secp256k1`) via OpenSSL
3. Imports the private key, public key, and certificate into the token via `pkcs11-tool`
4. Starts Besu with any arguments passed to the container

## Build

```bash
# From the repository root
docker build -t besu-hsm-softhsm docker/softhsm/

# With a specific Besu version
docker build -t besu-hsm-softhsm --build-arg BESU_VERSION=26.2.0 docker/softhsm/
```

## Install the plugin

Build the plugin distribution first:

```bash
./gradlew distZip
```

Then copy the plugin jar into the container's `/opt/besu/plugins/` directory. For example, using a volume mount:

```bash
# Extract the jar from the distribution zip
unzip -o -j build/distributions/besu-hsm-plugin.zip -d /tmp/besu-hsm-plugin/
```

## Run

```bash
docker run --rm \
  -v /tmp/besu-hsm-plugin/besu-hsm-plugin.jar:/opt/besu/plugins/besu-hsm-plugin.jar \
  besu-hsm-softhsm \
  --network=dev \
  --discovery-enabled=false \
  --security-module=pkcs11-hsm \
  --plugin-pkcs11-hsm-config-path=/etc/besu/config/pkcs11-softhsm.cfg \
  --plugin-pkcs11-hsm-password-path=/etc/besu/config/pkcs11-hsm-password.txt \
  --plugin-pkcs11-hsm-key-alias=testkey
```

## Environment variables

| Variable   | Default     | Description                                          |
|------------|-------------|------------------------------------------------------|
| `EC_CURVE` | `secp256k1` | EC curve for key generation (`secp256k1`, `prime256v1`) |

Example with a different curve:

```bash
docker run --rm -e EC_CURVE=prime256v1 \
  -v /tmp/besu-hsm-plugin/besu-hsm-plugin.jar:/opt/besu/plugins/besu-hsm-plugin.jar \
  besu-hsm-softhsm \
  --network=dev \
  --discovery-enabled=false \
  --security-module=pkcs11-hsm \
  --plugin-pkcs11-hsm-config-path=/etc/besu/config/pkcs11-softhsm.cfg \
  --plugin-pkcs11-hsm-password-path=/etc/besu/config/pkcs11-hsm-password.txt \
  --plugin-pkcs11-hsm-key-alias=testkey
```

## Config files baked into the image

| File | Path in container | Description |
|------|-------------------|-------------|
| `config/pkcs11-softhsm.cfg` | `/etc/besu/config/pkcs11-softhsm.cfg` | SunPKCS11 provider configuration |
| `config/pkcs11-hsm-password.txt` | `/etc/besu/config/pkcs11-hsm-password.txt` | Token PIN (`1234`) |
| `config/softhsm2.conf` | `/etc/softhsm2.conf` | SoftHSM2 configuration (token dir: `/var/lib/tokens`) |

## Automated testing

The integration tests in `src/integrationTest/` use this Docker image via Testcontainers:

```bash
./gradlew integrationTest
```
