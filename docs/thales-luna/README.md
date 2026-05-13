# Thales Luna HSM with Besu

End-to-end guide for running a Besu validator network with node-key
operations delegated to a Thales Luna HSM. Validated on a Luna K7 (PCIe)
with firmware `7.0.3` and client `10.9.0-65`, accessed from AlmaLinux
9.6. Both signing (QBFT consensus) and ECDH key agreement (devp2p peer
handshakes) run end-to-end on the HSM.

This guide uses the plugin's `native-pkcs11` provider, which is the
default. It talks to Luna's PKCS#11 library directly via a Java 25
Foreign Function &amp; Memory (FFM) binding, avoiding SunPKCS11 entirely
— necessary because Luna 7.x strictly enforces PKCS#11 v2.40 spec
compliance for `CKM_ECDH1_DERIVE` (the peer pubkey must be DER-wrapped),
which SunPKCS11 cannot produce. The provider also looks up keys
directly by `CKA_LABEL` so no per-key certificate is required.

## At a glance

The deployment has three phases:

1. **Partition setup.** Initialise the Luna user partition and set the
   Crypto Officer password (one-time per HSM partition).
2. **Generate keys on the HSM.** Five `secp256k1` keypairs (one per
   validator) generated *on* the HSM with `pkcs11-tool`. Private keys
   never exist in software. Their public points are extracted for the
   QBFT genesis.
3. **Run Besu.** Configure each validator with the plugin's HSM
   security module pointing at the partition; bring up the QBFT network.

## Prerequisites

You'll need:

- A Linux host with the Thales Luna client SDK installed (`lunacm`,
  `cmu`, `libCryptoki2_64.so` — verified in §1.1).
- Membership in the `hsmusers` group on the host (checked in §1.2).
- A Luna partition you have **Crypto Officer (CO)** credentials for, or
  the **Partition SO (PSO)** credentials needed to set CO up (see §2).
- The partition must allow the policies below — these are typically on
  by default on a Luna 7.x partition. Verification is part of §1.4
  after you have lunacm access and know the slot ID.

| Capability/Policy | Required | Used for |
|---|---|---|
| 5 — Enable secret key wrapping | `1` | Wrapping the derived ECDH shared secret with our session AES KEK |
| 11 — Enable changing key attributes | `1` | Standard PKCS#11 key generation |
| 28 — Enable Key Management Functions | `1` | Generating EC keys + AES KEKs |

Notably the provider does **not** require capability 1 (`Enable private
key wrapping`). The ECDH recipe keeps derived secrets HSM-resident
(`CKA_SENSITIVE=true`) and uses a session-scoped AES KEK as a wrap +
decryption oracle to recover the shared bytes — a standard PKCS#11
sequence that doesn't depend on cap 1. This makes the provider usable on
FIPS-conservative partitions without any policy relaxation.

---

## 1. Host Discovery

You need to know what state the HSM is in and what credentials you have
before you change anything. All commands in this section are read-only.

### 1.1 Verify the Luna client is installed

```bash
ls /usr/safenet/lunaclient/bin/lunacm \
   /usr/safenet/lunaclient/bin/cmu \
   /usr/safenet/lunaclient/lib/libCryptoki2_64.so
```

All three files should exist. If not, install the Luna Universal Client
RPM from your Thales support portal (out of scope for this guide).

### 1.2 Confirm `hsmusers` group membership

Luna restricts access to its libraries and config to users in the
`hsmusers` group. Without membership, `lunacm` will fail to read
`/etc/Chrystoki.conf`.

Check your current groups (no sudo needed):

```bash
id
```

Look for `hsmusers` in the `groups=...` list. Example:

```
uid=1000(besu) gid=1000(besu) groups=1000(besu),10(wheel),996(hsmusers)
```

If `hsmusers` is there, skip the rest of this section.

If not, either ask your HSM administrator to add you, or — if you have
sudo — add yourself:

```bash
sudo usermod -aG hsmusers $USER
```

You must **re-login** after the change for the new group to take effect:

```bash
exit
# ssh back in
id    # confirm 'hsmusers' is now in the groups list
```

### 1.3 Enumerate slots and partitions

```bash
/usr/safenet/lunaclient/bin/lunacm
```

At the lunacm prompt:

```
slot list
```

Expect output similar to:

```
Slot Id ->              3
Label ->                besu-validators
Model ->                Luna K7
Configuration ->        Luna User Partition With SO (PW) Signing With Cloning Mode

Slot Id ->              4
Label ->                besu
Configuration ->        Luna HSM Admin Partition (PW)
```

Note the user partition's slot ID — you will use it everywhere later
(referred to as `<user-slot>` in this guide).

The `(PW)` suffix indicates **password-based authentication** (no PED
keypad required). This guide assumes password-based auth throughout. If
your partition shows `(PED)` instead, login is interactive via a
hardware PED device — out of scope here.

### 1.4 Inspect the user partition

```
slot set slot <user-slot>
partition showinfo
role list
```

If `Partition Status` is `Zeroized`, the partition needs initialization
(section 2). Otherwise, you (or your HSM admin) have already initialized
it; go straight to section 3.

### 1.5 Confirm partition policies

While still in lunacm with the user partition selected:

```
partition showpolicies
```

In the `Partition Capabilities` table, confirm:

- `5: Enable secret key wrapping` is `1`
- `11: Enable changing key attributes` is `1`
- `28: Enable Key Management Functions` is `1`

If any of these are `0`, ask your HSM administrator — these are
typically on by default but can be locked off by partition policy. The
provider does **not** require capability 1, so don't worry if that one
is `0` (FIPS-conservative partitions often have it disabled).

Type `exit` to leave lunacm.

---

## 2. Initialize the User Partition

Skip this section if `partition showinfo` already shows
`CKF_TOKEN_INITIALIZED` and a non-empty Partition Label.

You need two passwords for partition setup. **Generate them with a
password manager and save each one as you create it**. Losing the
Partition SO password makes the partition irrecoverable without
zeroizing.

| Role | Used by | Lifetime |
|---|---|---|
| Partition SO (PSO) | Set up CO; rarely after | Setup only |
| Crypto Officer (CO) | **Besu reads this from a file** at runtime | Long-lived |

> **Why CO is the runtime password:** The PKCS#11 spec defines only
> `CKU_USER` and `CKU_SO` login types. Luna maps `CKU_USER` to **CO**.
> SunPKCS11 — and any standard PKCS#11 client, including the
> `native-pkcs11` provider — calls `C_Login(CKU_USER, ...)`, so the PIN
> file Besu reads must contain the CO password. Luna's optional CU role
> is only reachable via a vendor extension (`CKU_LIMITED_USER`) exposed
> only by Luna's own JCE provider, which the plugin does not use.

### 2.1 Initialize the partition (sets PSO)

In lunacm, with the user partition selected (`slot set slot <user-slot>`):

```
partition init -label besu-validators -auth
```

Prompts:
- `Enter password for Partition SO`: *(twice)*
- `Enter the domain name`: any string (e.g. `besu-validators-domain`);
  required for cloning, irrelevant otherwise.

The `-auth` flag leaves you logged in as PSO when init succeeds, saving
a separate `role login` step.

### 2.2 Set the Crypto Officer password

Still as PSO:

```
role init -name co
```

Prompts twice for the new CO password.

Luna sets the CO password to "expired-on-first-login". You must
explicitly change it before any other operation, otherwise the next op
fails with `CKR_PIN_EXPIRED`:

```
role logout
role login -name co
role changepw -name co
```

`changepw` prompts for the *initial* CO password, then twice for the
*new* CO password. **Save the new one to your password manager** — this
is the password Besu will use.

### 2.3 Verify

```
partition showinfo
```

Should show `CKF_TOKEN_INITIALIZED` and `CKF_USER_PIN_INITIALIZED` flags
set, and `Partition Label -> besu-validators`. Type `exit` to leave
lunacm.

---

## 3. Host Prerequisites

Install the OpenSC tools (`pkcs11-tool`), plus `jq`, `curl`, `unzip`,
and `tmux` (used in §§9–10 to run each validator in its own session):

**RHEL / AlmaLinux / Rocky / Fedora:**

```bash
sudo dnf install -y opensc jq curl unzip tmux
```

**Ubuntu / Debian:**

```bash
sudo apt-get update && sudo apt-get install -y opensc jq curl unzip tmux
```

> **`--module` flag is required.** `pkcs11-tool` doesn't auto-discover
> vendor PKCS#11 libraries, so every invocation in this guide passes
> `--module /usr/safenet/lunaclient/lib/libCryptoki2_64.so`. Set a
> shell variable if you want to keep the commands shorter:
>
> ```bash
> export PKCS11_MODULE=/usr/safenet/lunaclient/lib/libCryptoki2_64.so
> # then: pkcs11-tool --module "$PKCS11_MODULE" ...
> ```
>
> The commands in §4 onwards use the full path inline for copy-paste
> reliability; replace with `"$PKCS11_MODULE"` if you set the variable.

### 3.1 Java 25

This plugin requires Java 25, and upcoming releases of Besu will also
require Java 25. Eclipse Temurin works well; install it from your
distro's package manager or via Adoptium's repo. Adoptium's [official
Linux install guide](https://adoptium.net/installation/linux/) covers
both RPM-based and deb-based distros:

```bash
# After following Adoptium's guide for your distro:
# RHEL family:   sudo dnf install -y temurin-25-jdk
# Debian family: sudo apt-get install -y temurin-25-jdk
java --version
```

### 3.2 Working directory

```bash
mkdir -p ~/luna-validators
cd ~/luna-validators
```

This is where the plugin config, password file, public-key list, and
per-validator data directories will live. Subsequent sections assume
`~/luna-validators/` as the working directory.

---

## 4. Generate Validator Keys on the HSM

Five `secp256k1` keypairs, one per validator. Each is generated *on*
the HSM — the private key never exists in software.

> **Tooling note:** Luna's native `cmu generateKeyPair` only supports
> the NIST curves (`-curveType=1..5` mapping to NIST
> P-192/224/256/384/521). Ethereum's default `secp256k1` is not on that list, so
> `cmu` rejects it. We use OpenSC's `pkcs11-tool` instead, which talks
> to Luna's PKCS#11 library directly and accepts `secp256k1` via its
> OID.

Capture the CO password in a shell variable so it stays out of shell
history and `ps`:

```bash
read -s -p "CO password: " LUNA_CO_PIN; echo
```

Verify the partition is reachable through PKCS#11:

```bash
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2_64.so \
  --token-label besu-validators \
  --login --pin "$LUNA_CO_PIN" \
  --list-mechanisms | grep -Ei 'ecdsa|ec.*key.*pair|ecdh1-derive'
```

You should see `ECDSA-KEY-PAIR-GEN`, `ECDSA`, `ECDSA-SHA256`, and
`ECDH1-DERIVE` all flagged `hw, ...` — Luna advertises hardware support
for each.

Generate the keypairs:

```bash
for i in 1 2 3 4 5; do
  pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2_64.so \
    --token-label besu-validators \
    --login --pin "$LUNA_CO_PIN" \
    --keypairgen --key-type EC:secp256k1 \
    --label "testValidator${i}" --id "0${i}" \
    --usage-sign --usage-derive \
    --sensitive --private
done
```

Flag rationale:

- `--key-type EC:secp256k1` — Ethereum's curve (OID `1.3.132.0.10`)
- `--label`/`--id` — `CKA_LABEL` and `CKA_ID` on both keys; the plugin
  looks the private key up by label
- `--usage-sign` → `CKA_SIGN=true` on the private key (required for
  ECDSA signing) and `CKA_VERIFY=true` on the public key
- `--usage-derive` → `CKA_DERIVE=true` (required for ECDH peer
  handshakes)
- `--sensitive` → `CKA_SENSITIVE=true` (key value cannot be read in
  plaintext via `C_GetAttributeValue`)
- `--private` → `CKA_PRIVATE=true` (login required to access)

> **Testing secp256r1 instead?** Use `--key-type EC:secp256r1` here, and
> match it in `ecCurve` (§7 genesis) and `plugin-hsm-ec-curve` (§§8 and
> 10 TOMLs). The plugin's FFM recipe is curve-neutral; everything else
> in the walkthrough stays the same.

Verify all 10 objects (5 priv + 5 pub) are in place:

```bash
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2_64.so \
  --token-label besu-validators \
  --login --pin "$LUNA_CO_PIN" \
  --list-objects 2>/dev/null \
  | grep -E '^(Private Key|Public Key|  label:|  ID:)'
```

Expected: 5 `Private Key Object` and 5 `Public Key Object` blocks, each
with matching `label: testValidatorN` and `ID: 0N`.

---

## 5. Extract Public Keys for QBFT Genesis

QBFT's genesis configuration needs the validators' raw 64-byte
uncompressed public keys (X || Y, no `0x04` prefix). Read them from each
public-key object and strip pkcs11-tool's DER `OCTET STRING` wrapper:

```bash
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2_64.so \
  --token-label besu-validators \
  --login --pin "$LUNA_CO_PIN" \
  --list-objects --type pubkey 2>/dev/null \
  | awk '
      /^[[:space:]]*EC_POINT:/                              { ec=$2 }
      /^[[:space:]]*label:[[:space:]]*testValidator[0-9]+/ { keys[$2]=ec }
      END { for (i=1; i<=5; i++) print keys["testValidator" i] }
    ' \
  | sed 's/^044104/0x/' \
  | jq -R . | jq -s . > public_keys.json

cat public_keys.json
```

You should see five `0x`-prefixed 64-byte hex strings, in validator
order.

---

## 6. Download Besu and the HSM Plugin

```bash
BESU_VERSION="26.4.0"
HSM_PLUGIN_VERSION="0.0.2"

curl -L -O https://github.com/besu-eth/besu/releases/download/${BESU_VERSION}/besu-${BESU_VERSION}.tar.gz
curl -L -O https://github.com/besu-eth/besu-hsm-plugin/releases/download/${HSM_PLUGIN_VERSION}/besu-hsm-plugin-${HSM_PLUGIN_VERSION}.zip
```

Create per-validator working directories and unpack into each:

```bash
for i in 1 2 3 4 5; do
  mkdir -p validator${i}/plugins validator${i}/data validator${i}/config
  tar xzf besu-${BESU_VERSION}.tar.gz --strip-components=1 -C validator${i}
  unzip -o -j besu-hsm-plugin-${HSM_PLUGIN_VERSION}.zip -d validator${i}/plugins
done
```

Write the CO password to a file each Besu process can read:

```bash
echo -n "$LUNA_CO_PIN" > pkcs11-password.txt
chmod 600 pkcs11-password.txt
```

---

## 7. Generate the QBFT Genesis

Besu's `operator generate-blockchain-config` takes a config file
listing the validator public keys (`qbftConfigFile.json` below) and
emits a finalised `genesis.json` whose `extraData` field encodes the
initial QBFT validator set (RLP-encoded addresses derived from those
keys). Setting `"generate": false` under `blockchain.nodes` tells Besu
to use the public keys we supply rather than generating fresh ones —
the keys already live on the HSM, so we just want their addresses
baked into the genesis. The same `genesis.json` is then copied into
every validator's data directory so each node agrees on the chain's
starting state.

> **Testing secp256r1?** Change `ecCurve` below to `"secp256r1"` to
> match the curve you generated in §4.

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

./validator1/bin/besu operator generate-blockchain-config \
  --config-file=qbftConfigFile.json \
  --to=output

for i in 1 2 3 4 5; do
  cp ./output/genesis.json ./validator${i}/data/
done
```

---

## 8. Configure Validator 1 (Bootnode)

Validator 1 is started first and acts as the bootnode for the rest of
the network. Validators 2–5 can't be configured until validator 1 is
running, because they need its discovery URI (the `enode://` for
DiscV4, or the `enr:-...` for DiscV5) — and that URI is read out of
the running node's `admin_nodeInfo` RPC.

Create the PKCS#11 config file the plugin will read. The format is the
same as a SunPKCS11 config; only `library` and either `slot` or
`slotListIndex` are needed by the `native-pkcs11` provider:

```bash
cat > pkcs11-luna.cfg <<EOF
library = /usr/safenet/lunaclient/lib/libCryptoki2_64.so
slot = <user-slot>
EOF
```

> **Note:** `slotListIndex = N` — the SunPKCS11-style 0-based index
> into `C_GetSlotList(tokenPresent=TRUE)` — is also accepted if you
> prefer. For Luna, the direct `slot = N` form is more deterministic
> since admin and user partitions both register as token-present slots.

Write validator 1's TOML. Note that `ADMIN` is included in
`rpc-http-api` so we can call `admin_nodeInfo` in §9 to capture the
bootnode URI.

> **Testing secp256r1?** Change `plugin-hsm-ec-curve="secp256k1"` to
> `"secp256r1"` in every validator config to match the curve you
> generated in §4 and set in §7.

```bash
WORK_DIR=$(pwd)

cat > validator1/config/config.toml <<EOF
genesis-file="${WORK_DIR}/validator1/data/genesis.json"
data-path="${WORK_DIR}/validator1/data"

security-module="hsm"
plugin-hsm-config-path="${WORK_DIR}/pkcs11-luna.cfg"
plugin-hsm-password-path="${WORK_DIR}/pkcs11-password.txt"
plugin-hsm-key-alias="testValidator1"
plugin-hsm-ec-curve="secp256k1"

p2p-port=30301
min-gas-price=0

rpc-http-enabled=true
rpc-http-port=8541
rpc-http-api=["ETH","NET","QBFT","ADMIN"]
rpc-http-host="0.0.0.0"
host-allowlist=["*"]

profile="ENTERPRISE"
EOF
```

Notes on the HSM-plugin TOML:

- **No `plugin-hsm-provider-type`** — `native-pkcs11` is the default.
- `plugin-hsm-config-path` points at the SunPKCS11-format file written
  above. Only `library` and `slot`/`slotListIndex` are parsed; other
  directives (`name`, `attributes(...)`, `showInfo`, …) are ignored.
- `plugin-hsm-password-path` is the file with the **CO password** (the
  `CKU_USER` PIN per Luna's role mapping).
- `plugin-hsm-key-alias` matches the `CKA_LABEL` of the keypair on the
  HSM. No certificate is required for the key.
- No `plugin-hsm-public-key-alias` field — that's CloudHSM-JCE-only.

---

## 9. Start Validator 1 and Discover its Bootnode URI

Start validator 1 in a detached `tmux` session, wait for its RPC port
to come up, then ask it for its discovery URI via `admin_nodeInfo`.

> **Note:** keep the `./` prefix on `--config-file=./validator…/…toml`
> — Besu's launcher script needs an explicit relative path here.

```bash
tmux new -d -s validator1 ./validator1/bin/besu --config-file=./validator1/config/config.toml

# Wait for the RPC endpoint to start serving (first start can take ~20–30s)
for _ in {1..60}; do
  curl -s -o /dev/null -X POST http://localhost:8541 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}' && break
  sleep 1
done

# Capture the bootnode URI. For DiscV4, use .result.enode; for DiscV5,
# swap to .result.enr (an enr:-... string).
VALIDATOR1_BOOTNODE=$(curl -s -X POST http://localhost:8541 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"admin_nodeInfo","params":[],"id":1}' \
  | jq -r '.result.enode')

echo "$VALIDATOR1_BOOTNODE"
```

> **Tip:** attach to the tmux session at any time with `tmux attach -t
> validator1` (Ctrl+b, d to detach again). Watch the log for "Ethereum
> main loop is up" before moving on.

---

## 10. Configure and Start Validators 2–5

Write configs for validators 2–5, pointing each at the bootnode URI
captured in §9, then start them:

```bash
for i in 2 3 4 5; do
  P2P_PORT=$((30300 + i))
  RPC_PORT=$((8540 + i))
  cat > "validator${i}/config/config.toml" <<EOF
genesis-file="${WORK_DIR}/validator${i}/data/genesis.json"
data-path="${WORK_DIR}/validator${i}/data"

security-module="hsm"
plugin-hsm-config-path="${WORK_DIR}/pkcs11-luna.cfg"
plugin-hsm-password-path="${WORK_DIR}/pkcs11-password.txt"
plugin-hsm-key-alias="testValidator${i}"
plugin-hsm-ec-curve="secp256k1"

p2p-port=${P2P_PORT}
min-gas-price=0
bootnodes=["${VALIDATOR1_BOOTNODE}"]

rpc-http-enabled=true
rpc-http-port=${RPC_PORT}
rpc-http-api=["ETH","NET","QBFT"]
rpc-http-host="0.0.0.0"
host-allowlist=["*"]

profile="ENTERPRISE"
EOF
done

for i in 2 3 4 5; do
  tmux new -d -s validator${i} ./validator${i}/bin/besu --config-file=./validator${i}/config/config.toml
done
```

---

## 11. Verify the Network

```bash
for i in 1 2 3 4 5; do
  PORT=$((8540 + i))
  echo "=== validator${i} (port ${PORT}) ==="

  # Block height advancing
  curl -s -X POST http://localhost:${PORT} \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
  echo

  # All five validators visible to QBFT
  curl -s -X POST http://localhost:${PORT} \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"qbft_getValidatorsByBlockNumber","params":["latest"],"id":1}'
  echo
done
```

If `eth_blockNumber` advances and the validator list includes all five
addresses, the HSM-backed signing path is live and ECDH-backed peering
is working.

---

## Operations

### HA configuration

If your deployment uses Luna in an HA group (`hagroup`), Thales' HA
client library transparently virtualises the PKCS#11 session handle
across HA members and load-balances `C_Sign` / `C_DeriveKey` calls
under the hood. The plugin's "open one session for the lifetime of the
process" model is exactly the pattern Thales' SDK expects in HA mode —
do not introduce per-call session open/close, it fights the HA
library's design.

Recommendations:

- Set `HAOnly=1` in `Chrystoki.conf` (`[Misc]` section) so the
  application sees only the virtual HA slot, not the underlying
  per-member slots.
- Configure `hagroup` auto-recovery so transient member failures are
  rejoined transparently. The first PKCS#11 call after a failure pays
  the in-band recovery cost (Thales' recovery is piggy-backed on the
  next call, not a background thread).
- Multi-part operations don't fail over (per Thales' HA spec); a
  mid-flight call returns `CKR_DEVICE_ERROR` and the caller retries.
  Besu's sign and ECDH operations are single-part, so this isn't a
  concern in practice.

References: [Thales HA Implementations](https://thalesdocs.com/gphsm/luna/7/docs/usb/Content/sdk/design/ha.htm),
[Recovering From the Loss of All HA Members](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/java/ha_recover_all_members.htm).

### Session loss / partition events

The provider opens one PKCS#11 session at validator startup and reuses
it for the lifetime of the process. On session-invalidating events
(partition deactivation, total HA-group loss, firmware update, etc.)
the next sign or ECDH call throws `SecurityModuleException` with the
underlying PKCS#11 rv code in the message. The validator must be
restarted to recover.

The dead-session error codes from Luna are:

- `0xB3` `CKR_SESSION_HANDLE_INVALID`
- `0x30` `CKR_DEVICE_ERROR`
- `0xE0` `CKR_TOKEN_NOT_PRESENT`

Transparent re-init on these codes is intentionally not implemented in
v1: with a local PCIe HSM, session loss almost always indicates an
administratively significant event (partition touched, firmware update)
that an operator should see rather than have silently masked.

### FIPS compliance posture

The ECDH derive recipe is FIPS-conservative throughout:

- Derived secrets stay HSM-resident (`CKA_SENSITIVE=true`,
  `CKA_EXTRACTABLE=true`). The bytes are never readable via
  `C_GetAttributeValue`.
- Recovery of the shared secret uses a session-scoped AES-256 KEK on
  the HSM as a wrap + decryption oracle (`CKM_AES_CBC`). The ECDH
  secret is wrapped with the KEK, then decrypted with the same KEK to
  produce the plaintext. Both operations are standard PKCS#11 and run
  entirely on the HSM.
- The recipe does not depend on partition capability 1 (`Enable
  private key wrapping`), so locked-down partitions with cap 1 = 0 are
  fully supported.

---

## Cleanup

```bash
for i in 1 2 3 4 5; do tmux kill-session -t "validator${i}" 2>/dev/null; done
rm -rf validator1 validator2 validator3 validator4 validator5 output qbftConfigFile.json
rm -f pkcs11-luna.cfg pkcs11-password.txt public_keys.json
```

> **Note:** `pkcs11-password.txt` contains the CO password — make sure
> you don't have it copied elsewhere (shell history, scrollback,
> backup) before treating this cleanup as complete.

The HSM-resident keys persist through all of the above. To remove them,
delete by alias via `pkcs11-tool`:

```bash
for i in 1 2 3 4 5; do
  pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2_64.so \
    --token-label besu-validators --login --pin "$LUNA_CO_PIN" \
    --delete-object --type privkey --label "testValidator${i}"
  pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2_64.so \
    --token-label besu-validators --login --pin "$LUNA_CO_PIN" \
    --delete-object --type pubkey --label "testValidator${i}"
done
```

---

## Known Limitations

- **DiscV5 is only supported on the `secp256k1` curve.** The ENR v4
  identity scheme defined in EIP-778 mandates secp256k1, so DiscV5
  validators on `secp256r1` are not possible regardless of provider.
  DiscV4 and devp2p handshakes work on both curves.
- **Per-JVM serialisation of HSM operations.** Sign and ECDH calls are
  serialised at the Java level (one PKCS#11 session per process). For a
  QBFT validator this is fine — the consensus thread is single-flight.
  Multi-threaded signing workloads should size differently (currently
  out of scope for the plugin).
- **`pkcs11-tool` cannot generate `CKA_EXTRACTABLE=false` keys.** A
  `--no-extractable` flag does not exist; the keys take the partition
  default. They remain protected by `CKA_SENSITIVE=true`, which blocks
  plaintext readback. For maximum security, regenerate in production
  with a tool that allows full attribute control (small custom PKCS#11
  program, or `ckdemo` interactively).
- **`cmu generateKeyPair` rejects `secp256k1`** — only NIST curves are
  supported by Luna's cmu. Use `pkcs11-tool` (this guide) or a small
  custom PKCS#11 client.
- **JVM exits with `SIGSEGV` in `lnh_slots.plugin+...:plugin_finalize`**
  during shutdown of any Java process that loads Luna's lib. Cosmetic
  (results print before the crash) but means JVM exit isn't clean. Does
  not affect Besu correctness during runtime.

## Production Hardening

When this guide is the basis for a production deployment, also do:

1. Regenerate keys with `CKA_EXTRACTABLE=false` (see above).
2. Enable Luna's Secure Trusted Channel (STC) for client→HSM traffic if
   physical access to the HSM bus is not assumed safe.
3. Move the Besu PIN file to a tightly-scoped location with mode `0400`,
   readable only by the Besu service user.
4. Enable `partition activate` + `partition setActivationTimeout` so the
   CO role stays activated across Besu restarts without re-prompting
   for the PIN, while still timing out under attacker access.
5. Audit-log all `pkcs11-tool` and `cmu` activity via OS auditd rules
   covering `/usr/safenet/lunaclient/bin/*`.
6. For HA deployments, set `HAOnly=1` and configure `hagroup`
   auto-recovery (see [Operations](#operations)).

## See Also

- Plugin overview: [`../../README.md`](../../README.md)
- Architecture diagram:
  [`../besu-hsm-plugin-architecture.png`](../besu-hsm-plugin-architecture.png)
- AWS CloudHSM guide for comparison: [`../aws-CloudHSM/`](../aws-CloudHSM/)

## References

- [Thales Luna 7 PKCS#11 standard mechanisms](https://thalesdocs.com/gphsm/luna/7/docs/usb/Content/sdk/pkcs11/pkcs11_standard.htm)
  — which `CKM_*` mechanisms are supported by Luna firmware
- [Thales HA Implementations](https://thalesdocs.com/gphsm/luna/7/docs/usb/Content/sdk/design/ha.htm)
  — virtual session handle, transparent member failover
- [OASIS PKCS#11 v2.40 base specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
  — function-list layout, attribute and mechanism semantics, error
  codes
- [PKCS#11 v2.40 vendor return codes (Luna mapping)](https://www.thalesdocs.com/dpod/services/luna_cloud_hsm/extern/client_guides/Content/admin_hsm/monitor/vendor_return_codes.htm)
  — useful when a `0x8000xxxx` error appears: distinguishes vendor
  codes from standard PKCS#11 ones
