# QBFT Setup — CloudHSM JCE Provider

This guide sets up a 5-node QBFT network on a single EC2 instance using the CloudHSM JCE
provider. Each validator runs as a separate Besu process with its own HSM-backed key pair.

> **Note:** This is a proof-of-concept setup for testing and validation. In production, each
> validator should run on its own EC2 instance.

All commands assume you have completed the [Getting Started](1GettingStarted.md) guide
(SDKs installed, environment variables exported, validator keys created) and that
`public_keys.json` is in the current directory.

## Download Besu and the HSM Plugin

```bash
BESU_VERSION="26.2.0"
HSM_PLUGIN_VERSION="0.0.2"

wget https://github.com/besu-eth/besu/releases/download/${BESU_VERSION}/besu-${BESU_VERSION}.tar.gz
wget https://github.com/besu-eth/besu-hsm-plugin/releases/download/${HSM_PLUGIN_VERSION}/besu-hsm-plugin-${HSM_PLUGIN_VERSION}.zip
```

## Create Validator Directories

Create a directory structure for each validator with dedicated `plugins`, `data`, and
`config` subdirectories:

```bash
for i in 1 2 3 4 5; do \
  mkdir -p validator${i}/plugins validator${i}/data validator${i}/config; \
done
```

Extract Besu and the HSM plugin into each validator directory:

```bash
for i in 1 2 3 4 5; do \
  tar xzf besu-${BESU_VERSION}.tar.gz --strip-components=1 -C validator${i}; \
  unzip -o -j besu-hsm-plugin-${HSM_PLUGIN_VERSION}.zip -d validator${i}/plugins; \
done
```

## Generate the QBFT Genesis

The genesis configuration requires the validator public keys extracted in the
[Getting Started](1GettingStarted.md#extracting-public-keys) guide. Read them into a
shell variable and inject them into the config file:

```bash
VALIDATOR_KEYS=$(cat public_keys.json)

cat > qbftConfigFile.json <<EOF
{
  "genesis": {
    "config": {
      "ecCurve": "secp256k1",
      "chainId": 1337,
      "berlinBlock": 0,
      "londonBlock": 0,
      "shanghaiTime": 0,
      "qbft": {
        "blockperiodseconds": 2,
        "epochlength": 30000,
        "requesttimeoutseconds": 4
      }
    },
    "nonce": "0x0",
    "timestamp": "0x0",
    "gasLimit": "0x1fffffffffffff",
    "difficulty": "0x1",
    "mixHash": "0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365",
    "coinbase": "0x0000000000000000000000000000000000000000",
    "alloc": {
      "fe3b557e8fb62b89f4916b721be55ceb828dbd73": {
        "balance": "0xad78ebc5ac6200000"
      }
    }
  },
  "blockchain": {
    "nodes": {
      "generate": false,
      "keys": ${VALIDATOR_KEYS}
    }
  }
}
EOF
```

Generate the genesis file using Besu's operator command and copy it to each validator:

```bash
./validator1/bin/besu operator generate-blockchain-config \
  --config-file=qbftConfigFile.json \
  --to=output

for i in 1 2 3 4 5; do \
  cp ./output/genesis.json ./validator${i}/data/; \
done
```

## Generate Besu Configuration Files

Each validator needs a TOML configuration file. Validator 1 acts as the bootnode; validators
2-5 connect to it via its enode URL.

Set up the working directory and enode address:

```bash
WORK_DIR=$(pwd)

# Extract validator 1's public key (strip 0x prefix) for the enode URL
VALIDATOR1_PUBKEY=$(jq -r '.[0]' public_keys.json | sed 's/^0x//')
VALIDATOR1_ENODE="enode://${VALIDATOR1_PUBKEY}@127.0.0.1:30301"
```

### Validator 1 (Bootnode)

```bash
cat > validator1/config/config.toml <<EOF
# Validator 1 — Bootnode
genesis-file="${WORK_DIR}/validator1/data/genesis.json"
data-path="${WORK_DIR}/validator1/data"

# HSM
security-module="hsm"
plugin-hsm-provider-type="cloudhsm-jce"
plugin-hsm-key-alias="testValidator1:Private"
plugin-hsm-public-key-alias="testValidator1:Public"
plugin-hsm-ec-curve="secp256k1"

# Network
p2p-port=30301
min-gas-price=0

# RPC
rpc-http-enabled=true
rpc-http-port=8541
rpc-http-api=["ETH","NET","QBFT"]
rpc-http-host="0.0.0.0"
host-allowlist=["*"]

# Profile
profile="ENTERPRISE"
EOF
```

### Validators 2-5

Each validator gets a unique p2p port (30300 + *i*), RPC port (8540 + *i*), and key alias.
All use validator 1 as their bootnode:

```bash
for i in 2 3 4 5; do
  P2P_PORT=$((30300 + i))
  RPC_PORT=$((8540 + i))
  cat > "validator${i}/config/config.toml" <<EOF
# Validator ${i}
genesis-file="${WORK_DIR}/validator${i}/data/genesis.json"
data-path="${WORK_DIR}/validator${i}/data"

# HSM
security-module="hsm"
plugin-hsm-provider-type="cloudhsm-jce"
plugin-hsm-key-alias="testValidator${i}:Private"
plugin-hsm-public-key-alias="testValidator${i}:Public"
plugin-hsm-ec-curve="secp256k1"

# Network
p2p-port=${P2P_PORT}
min-gas-price=0
bootnodes=["${VALIDATOR1_ENODE}"]

# RPC
rpc-http-enabled=true
rpc-http-port=${RPC_PORT}
rpc-http-api=["ETH","NET","QBFT"]
rpc-http-host="0.0.0.0"
host-allowlist=["*"]

# Profile
profile="ENTERPRISE"
EOF
done
```

## Start the Validators

Use `tmux` to run each validator in its own session. Start validator 1 first — the other
nodes need it running to connect via the bootnode enode URL.

Start validator 1 first:

```bash
tmux new -s validator1 ./validator1/bin/besu --config-file=validator1/config/config.toml
# Ctrl+b, d to detach
```

Then start validators 2-5 in detached tmux sessions:

```bash
for i in 2 3 4 5; do
  tmux new -d -s validator${i} ./validator${i}/bin/besu --config-file=validator${i}/config/config.toml
done
```

Re-attach to a session to monitor logs:

```bash
tmux attach -t validator1
```

> **Tip:** If you are already inside a tmux session on the host, use `Ctrl+b Ctrl+b d` to
> detach from the nested session instead of `Ctrl+b d`.

## Verify

Check that blocks are being produced:

```bash
curl -s -X POST http://localhost:8541 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

List the active QBFT validators:

```bash
curl -s -X POST http://localhost:8541 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"qbft_getValidatorsByBlockNumber","params":["latest"],"id":1}'
```

## Cleanup

Stop all validator sessions and remove the working directories:

```bash
for i in 1 2 3 4 5; do tmux kill-session -t "validator${i}" 2>/dev/null; done
rm -rf validator1 validator2 validator3 validator4 validator5 output qbftConfigFile.json
```
