# QBFT 4-Node Network with SoftHSM2

Runs a 4-node QBFT network where each validator uses SoftHSM2 (via PKCS#11) for block signing.
This is the same setup used by `./gradlew integrationTest`, but can be run manually with Docker.

## Prerequisites

- Docker
- The plugin distribution zip: `./gradlew distZip` (produces `build/distributions/besu-hsm-plugin.zip`)

## Three-Phase Setup

All phases use the same Docker image. Build it once:

```bash
docker build -t besu-qbft-hsm-test docker/qbft-softhsm2/
```

Create shared volumes for data and per-node token storage:

```bash
mkdir -p /tmp/qbft-data
for i in 0 1 2 3; do mkdir -p /tmp/qbft-tokens-$i; done
```

### Phase 1: Generate Keys

Generate an EC key pair on each node's SoftHSM2 token and export the public key:

```bash
for i in 0 1 2 3; do
  docker run --rm \
    -v /tmp/qbft-data:/data \
    -v /tmp/qbft-tokens-$i:/var/lib/tokens \
    --entrypoint /entrypoint-setup.sh \
    besu-qbft-hsm-test $i
done
```

Each node gets a separate token directory. Public keys are written to `/tmp/qbft-data/node-N/pubkey.hex`.

### Phase 2: Generate Genesis

Generate QBFT genesis using the public keys from Phase 1:

```bash
docker run --rm \
  -v /tmp/qbft-data:/data \
  --entrypoint /generate-genesis.sh \
  besu-qbft-hsm-test 4
```

This produces `/tmp/qbft-data/genesis.json`.

### Phase 3: Start the Network

Create a Docker network:

```bash
docker network create qbft-net
```

Install the plugin and start the bootnode (node-0):

```bash
docker run -d --name besu-node-0 \
  --network qbft-net \
  -v /tmp/qbft-tokens-0:/var/lib/tokens \
  -v /tmp/qbft-data:/data \
  -v $(pwd)/build/distributions/besu-hsm-plugin.zip:/tmp/besu-hsm-plugin.zip \
  -p 8545:8545 \
  --entrypoint /bin/sh \
  besu-qbft-hsm-test -c \
  'unzip -o -j /tmp/besu-hsm-plugin.zip -d /opt/besu/plugins/ && /entrypoint-besu.sh \
    --genesis-file=/data/genesis.json \
    --security-module=pkcs11-hsm \
    --plugin-pkcs11-hsm-config-path=/etc/besu/config/pkcs11-softhsm.cfg \
    --plugin-pkcs11-hsm-password-path=/etc/besu/config/pkcs11-hsm-password.txt \
    --plugin-pkcs11-hsm-key-alias=testkey \
    --rpc-http-enabled \
    --rpc-http-api=ETH,NET,QBFT \
    --rpc-http-host=0.0.0.0 \
    --host-allowlist=* \
    --p2p-port=30303 \
    --min-gas-price=0 \
    --profile=ENTERPRISE'
```

Get node-0's IP and public key for the enode URL:

```bash
NODE0_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' besu-node-0)
NODE0_PUBKEY=$(cat /tmp/qbft-data/node-0/pubkey.hex)
BOOTNODE="enode://${NODE0_PUBKEY}@${NODE0_IP}:30303"
```

Start nodes 1-3 with `--bootnodes` pointing to node-0:

```bash
for i in 1 2 3; do
  docker run -d --name besu-node-$i \
    --network qbft-net \
    -v /tmp/qbft-tokens-$i:/var/lib/tokens \
    -v /tmp/qbft-data:/data \
    -v $(pwd)/build/distributions/besu-hsm-plugin.zip:/tmp/besu-hsm-plugin.zip \
    --entrypoint /bin/sh \
    besu-qbft-hsm-test -c \
    "unzip -o -j /tmp/besu-hsm-plugin.zip -d /opt/besu/plugins/ && /entrypoint-besu.sh \
      --genesis-file=/data/genesis.json \
      --security-module=pkcs11-hsm \
      --plugin-pkcs11-hsm-config-path=/etc/besu/config/pkcs11-softhsm.cfg \
      --plugin-pkcs11-hsm-password-path=/etc/besu/config/pkcs11-hsm-password.txt \
      --plugin-pkcs11-hsm-key-alias=testkey \
      --rpc-http-enabled \
      --rpc-http-api=ETH,NET,QBFT \
      --rpc-http-host=0.0.0.0 \
      --host-allowlist=* \
      --p2p-port=30303 \
      --min-gas-price=0 \
      --profile=ENTERPRISE \
      --bootnodes=${BOOTNODE}"
done
```

## Verify

Check block production:

```bash
curl -s -X POST http://localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

List QBFT validators:

```bash
curl -s -X POST http://localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"qbft_getValidatorsByBlockNumber","params":["latest"],"id":1}'
```

## Cleanup

```bash
for i in 0 1 2 3; do docker rm -f besu-node-$i; done
docker network rm qbft-net
rm -rf /tmp/qbft-data /tmp/qbft-tokens-*
```

## Notes

- The SoftHSM2 token PIN is `1234` (see `config/pkcs11-hsm-password.txt`).
- The entrypoint runs as root and switches to the `besu` user at runtime, mirroring the
  official Besu Docker entrypoint pattern.
- Peer discovery uses DiscV4 via `--bootnodes`. DiscV5 is not supported with HSM-backed
  signing — see the [project README](../../README.md#known-limitations) for details.
