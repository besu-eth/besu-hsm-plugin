# Utimaco GP HSM with Besu

End-to-end guide for running a Besu validator network with node-key
operations delegated to an Utimaco GP HSM. Validated using the
**u.trust GP HSM Simulator v6.5.0.0** on Ubuntu 24.04 LTS (x86-64).
Both signing (QBFT consensus) and ECDH key agreement (devp2p peer
handshakes) are delegated to the HSM via the PKCS#11 R3 interface.

This guide uses the plugin's `native-pkcs11` provider, which is the
default. It calls the Utimaco PKCS#11 R3 library (`libcs_pkcs11_R3.so`)
directly via a Java 25 Foreign Function & Memory (FFM) binding. The
library in turn connects to the HSM (or simulator) over TCP.

> **Simulator note:** The u.trust GP HSM Simulator faithfully reproduces
> the PKCS#11 interface of real Utimaco hardware. Steps in this guide
> apply directly to physical Utimaco GP HSM hardware — replace the
> simulator address (`3001@127.0.0.1`) with your device's IP address.

## At a glance

The deployment has three phases:

1. **Simulator setup.** Install the SDK, start the `bl_sim5` simulator
   daemon, and initialise a PKCS#11 token with a user PIN (one-time).
2. **Generate keys on the HSM.** Five `secp256k1` keypairs (one per
   validator) generated *on* the simulator with `pkcs11-tool`. Private
   keys never exist in software. Their public points are extracted for
   the QBFT genesis.
3. **Run Besu.** Configure each validator with the plugin's HSM security
   module pointing at the initialised token; bring up the QBFT network.

## Prerequisites

- AWS Ubuntu 24.04 LTS instance (x86-64) with SSH access.
- `u.trust-GP-HSM-Simulator_v6.5.0.0.zip` already uploaded to the
  instance (e.g. at `~`).
- Besu and the HSM plugin are downloaded directly on the instance via
  `curl` in §8.

---

## 1. Extract the Utimaco SDK

Unzip the archive and set a convenience variable pointing at the Linux
software tree:

```bash
cd ~
unzip u.trust-GP-HSM-Simulator_v6.5.0.0.zip -d utimaco-sdk
```

Find the extracted Linux directory (the exact nesting depends on how the
archive was packaged):

```bash
ls ~/utimaco-sdk/
```

Set `SDK` to the `Software/Linux` path you see:

```bash
# Adjust to match your actual extraction — for example:
SDK="$HOME/utimaco-sdk/u.trust-GP-HSM-Simulator_v6.5.0.0/Software/Linux"
# or:
# SDK="$HOME/utimaco-sdk/Software/Linux"
echo "$SDK"   # should end in .../Software/Linux
```

Copy the files you need to `$HOME/utimaco/`:

```bash
mkdir -p $HOME/utimaco/key

cp -r  "$SDK/Simulator/sim5_linux"                                $HOME/utimaco/
cp     "$SDK/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so"       $HOME/utimaco/
cp     "$SDK/Crypto_APIs/PKCS11_R3/sample/cs_pkcs11_R3.cfg"      $HOME/utimaco/
cp     "$SDK/Administration/p11tool2"                             $HOME/utimaco/
cp     "$SDK/Administration/csadm"                                $HOME/utimaco/
cp     "$SDK/Administration/key/ADMIN_SIM.key"                    $HOME/utimaco/key/

chmod +x $HOME/utimaco/p11tool2 \
         $HOME/utimaco/csadm \
         $HOME/utimaco/sim5_linux/bin/bl_sim5
```

---

## 2. Install Prerequisites

### 2.1 32-bit runtime for the simulator

The simulator binary (`bl_sim5`) is a 32-bit ELF. Ubuntu 24.04 ships
only 64-bit libc by default, so you must enable the i386 architecture:

```bash
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install -y libc6:i386 libstdc++6:i386
```

Verify the binary runs:

```bash
$HOME/utimaco/sim5_linux/bin/bl_sim5 --help 2>&1 | head -5
```

Expected output:

```
unknown option '--help'
Boot Loader, version 5.02.5.0 (May  5 2026) started
syntax:
 bl_sim5                    start SDK in Bootloader mode
 bl_sim5 -o                 start SDK in SMOS mode
```

If you instead see `cannot execute binary file: Exec format error`, the
32-bit runtime packages were not installed correctly — re-run the
`dpkg --add-architecture` steps above.

### 2.2 General tools

```bash
sudo apt-get install -y opensc jq curl unzip tmux
```

### 2.3 Java 25

This plugin requires Java 25. Install Eclipse Temurin from Adoptium's
APT repository:

```bash
wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public \
  | sudo gpg --dearmor -o /etc/apt/keyrings/adoptium.gpg

echo "deb [signed-by=/etc/apt/keyrings/adoptium.gpg] \
  https://packages.adoptium.net/artifactory/deb \
  $(awk -F= '/^VERSION_CODENAME/{print $2}' /etc/os-release) main" \
  | sudo tee /etc/apt/sources.list.d/adoptium.list

sudo apt-get update && sudo apt-get install -y temurin-25-jdk

# If another JDK is already installed, activate Java 25 explicitly:
sudo update-alternatives --set java /usr/lib/jvm/temurin-25-jdk-amd64/bin/java
sudo update-alternatives --set javac /usr/lib/jvm/temurin-25-jdk-amd64/bin/javac

java --version
```

---

## 3. Configure and Start the Simulator

### 3.1 Configure the PKCS#11 R3 library

The library reads a config file at the path given by the environment
variable `CS_PKCS11_R3_CFG`. The sample `cs_pkcs11_R3.cfg` already has
`[HSMCluster]` with `Devices = 3001@127.0.0.1`, which is correct for
the local simulator. The only change needed is to enable logging so you
can see library activity during testing — set `Logging = 3` in the
`[Global]` section:

```ini
[Global]
Logging = 3    # change from 0 (NONE) to 3 (INFO)
```

Export the variable for the current session (optionally persist it in
`~/.bashrc` for interactive testing):

```bash
export CS_PKCS11_R3_CFG=$HOME/utimaco/cs_pkcs11_R3.cfg

# optional — only for interactive testing convenience:
echo 'export CS_PKCS11_R3_CFG=$HOME/utimaco/cs_pkcs11_R3.cfg' >> ~/.bashrc
```

> **Production note:** when Besu runs as a systemd service, environment
> variables set in `~/.bashrc` are not inherited. Set `CS_PKCS11_R3_CFG`
> in the systemd unit file instead:
>
> ```ini
> [Service]
> Environment="CS_PKCS11_R3_CFG=/path/to/cs_pkcs11_R3.cfg"
> ```

### 3.2 Start the simulator

Start `bl_sim5` in a detached tmux session so it keeps running when you
detach:

```bash
tmux new -d -s simulator $HOME/utimaco/sim5_linux/bin/bl_sim5 -h -o
sleep 2
```

Confirm it is listening on port 3001:

```bash
ss -tlnp | grep 3001
```

Expected output: a `LISTEN` entry on `0.0.0.0:3001` or `*:3001`.

### 3.3 Verify library connectivity

```bash
pkcs11-tool --module $HOME/utimaco/libcs_pkcs11_R3.so --list-slots
```

Expected output (abbreviated — logging lines are interleaved because
`Logging = 3`):

```
... | I: CryptoServer PKCS#11 Library R3 version 6.5.0.0 (May  5 2026)
... | I: Configfile: /home/<user>/utimaco/cs_pkcs11_R3.cfg
... | I: Device 3001@127.0.0.1
Available slots:
Slot 0 (0x0): ...
3001@127.0.0.1 - CLUSTER_0000 - SLOT_0000
  token state:   uninitialized
Slot 1 (0x1): ...
3001@127.0.0.1 - CLUSTER_0000 - SLOT_0001
  token state:   uninitialized
...
Slot 9 (0x9): ...
3001@127.0.0.1 - CLUSTER_0000 - SLOT_0009
  token state:   uninitialized
```

Ten slots (0–9) are shown, all `uninitialized` — this is correct before
token initialization. If the command hangs or returns a connection error,
confirm `CS_PKCS11_R3_CFG` is exported and the simulator is running
(`ss -tlnp | grep 3001`).

> **`--module` flag is required** for every `pkcs11-tool` call in this
> guide, and must be an absolute path (`~` is not expanded). Set a
> variable to avoid repetition:
>
> ```bash
> export PKCS11_MODULE=$HOME/utimaco/libcs_pkcs11_R3.so
> # then: pkcs11-tool --module "$PKCS11_MODULE" ...
> ```
>
> The commands below use `$HOME` inline for copy-paste clarity.

---

## 4. Initialize the Token

PKCS#11 tokens ship uninitialized. Initialization sets the token label,
a Security Officer (SO) PIN, and a normal User PIN. The User PIN is what
Besu reads at runtime.

> **Choose PINs now.** Generate both SO and User PINs with a password
> manager and save them before proceeding. The SO PIN is needed only for
> administrative operations. **The User PIN is the runtime credential
> Besu reads from a file.**

Unlike SoftHSM2 or Luna, Utimaco's `C_InitToken` requires a device
administrator to authenticate before the call is permitted. The standard
`pkcs11-tool --init-token` therefore fails with `CKR_USER_NOT_LOGGED_IN`.
Use Utimaco's own `p11tool2` instead — it accepts a `Login=` parameter
that passes the admin key alongside the `InitToken=` call.

> **Use `$HOME` inside parameter values.** The shell expands `~` when
> it appears at the start of a command argument (`~/utimaco/p11tool2`)
> but not inside a parameter value string (`Login=ADMIN,~/...`). Use
> `$HOME` or an absolute path for any path embedded in a parameter value.

### 4.1 Initialize the token (sets label and SO PIN)

```bash
~/utimaco/p11tool2 \
  Login=ADMIN,$HOME/utimaco/key/ADMIN_SIM.key \
  Label="besu-validators" \
  InitToken=ask
```

`Login=ADMIN,<keyfile>` authenticates as the device `ADMIN` user via
RSA signature using the simulator's pre-loaded admin key. `InitToken=`
then calls `C_InitToken` with the given SO PIN and sets the token label.
Using `ask` prompts for the PIN without it appearing in the shell or
command history, which is strongly recommended.

Alphanumeric characters and `-` are accepted. On success the command
returns to the shell after the ClusterSync log lines with no error
message — the absence of an error is the success indicator:

```
Enter SO PIN:
Repeat SO PIN:
... | I: [ClusterSync] State changing command started ...
... | I: [ClusterSync] The following devices are in sync:
... | I: Device 3001@127.0.0.1
... | I: [ClusterSync] The following devices are out of sync:
```

### 4.2 Change the SO PIN (mandatory before first use)

After `InitToken`, the `SO_0000` user is created with an `I[1]`
(initial credentials) flag set. Utimaco requires the SO to change this
initial PIN before it can perform any privileged operation such as
creating the normal user. Attempting `InitPIN` without doing this first
results in `CKR_PIN_TOO_WEAK`.

Change the SO PIN via `csadm`:

```bash
~/utimaco/csadm dev=3001@127.0.0.1 \
  "LogonPass=SO_0000,<so-pin-from-inittoken>" \
  "ChangeUser=SO_0000,<new-so-pin>"
```

Verify `I[1]` has cleared to `I[0]` before continuing:

```bash
~/utimaco/csadm dev=3001@127.0.0.1 \
  LogonSign=ADMIN,$HOME/utimaco/key/ADMIN_SIM.key \
  ListUser
```

`SO_0000` should now show `I[0]`. This is analogous to Luna's
`role changepw -name co` step.

### 4.3 Set the User PIN (initial)

Log in as SO with the **new** SO PIN and initialize the User PIN:

```bash
~/utimaco/p11tool2 Slot=0 LoginSO=ask InitPIN=<initial-user-pin>
```

- `LoginSO=ask` — prompts for the **new SO PIN** set in §4.2
- `InitPIN=<initial-user-pin>` — supply the initial User PIN as a plain
  value rather than `ask`; `csadm` has no hidden-entry equivalent and
  requires this PIN directly in the next command, so specifying it here
  avoids having to retype an invisible value. Minimum length is **8
  characters** (enforced by the token, confirmed by `pin min/max: 8/255`
  in §4.5)

This creates `USR_0000` with an `I[1]` (initial credentials) flag — the
same mandatory-change requirement as the SO.

### 4.4 Change the User PIN (mandatory before first use)

```bash
~/utimaco/csadm dev=3001@127.0.0.1 \
  "LogonPass=USR_0000,<initial-user-pin>" \
  "ChangeUser=USR_0000,<new-user-pin>"
```

Verify both SO and user show `I[0]`:

```bash
~/utimaco/csadm dev=3001@127.0.0.1 \
  LogonSign=ADMIN,$HOME/utimaco/key/ADMIN_SIM.key \
  ListUser
```

Expected output:

```
ADMIN      22000000    RSA sign       Z[0]I[0]
SO_0000    00000200    HMAC passwd    Z[0]I[0]A[CXI_GROUP=SLOT_0000]L[besu-validators]
USR_0000   00000002    HMAC passwd    I[0]A[CXI_GROUP=SLOT_0000]
```

> **The new User PIN (set in `ChangeUser`) is the runtime credential.**
> This is what Besu reads from `pkcs11-password.txt` — not the initial
> PIN set in §4.3.

### 4.5 Verify token

`p11tool2 ListSlots` only shows slot IDs. Use `pkcs11-tool` here for
the richer token detail:

```bash
pkcs11-tool --module $HOME/utimaco/libcs_pkcs11_R3.so --list-slots
```

Slot 0 should now show a fully initialized token (abbreviated — logging
lines omitted):

```
Slot 0 (0x0): 3001@127.0.0.1 - CLUSTER_0000 - SLOT_0000
  token label        : besu-validators
  token manufacturer : Utimaco IS GmbH
  token model        : CryptoServer
  token flags        : login required, rng, token initialized, PIN initialized, other flags=0x260
  hardware version   : 5.2
  firmware version   : 6.5
  serial num         : SI003001_0000
  pin min/max        : 8/255
```

`token initialized` and `PIN initialized` confirm SO and User are both
set up. Slots 1–9 remain uninitialized — that is expected.

---

## 5. Verify Mechanism Support

Before generating keys, confirm the simulator supports the mechanisms
Besu requires. Capture the User PIN in a shell variable so it stays out
of shell history:

```bash
read -s -p "User PIN: " UTIMACO_PIN; echo
```

List EC-related mechanisms:

```bash
pkcs11-tool --module $HOME/utimaco/libcs_pkcs11_R3.so \
  --token-label "besu-validators" \
  --login --pin "$UTIMACO_PIN" \
  --list-mechanisms | grep -Ei 'ecdsa|ec.*key.*pair|ecdh1-derive'
```

All three mechanisms required by the plugin are present and hardware-accelerated:

```
ECDSA, keySize={112,571}, hw, sign, verify, EC F_P, EC F_2M, EC parameters, EC OID, EC uncompressed, EC compressed
ECDSA-KEY-PAIR-GEN, keySize={112,521}, hw, generate_key_pair, EC F_P, EC F_2M, EC parameters, EC OID, EC uncompressed, EC compressed
ECDH1-DERIVE, keySize={112,571}, hw, derive
```

The key size range `{112,571}` covers secp256k1 (256-bit). `EC OID`
support means curves are specified by OID — secp256k1 uses OID
`1.3.132.0.10`, which falls within the supported range.

---

## 6. Generate Validator Keys on the HSM

Five `secp256k1` keypairs, one per validator. Each is generated *on*
the simulator — the private key never exists in software.

```bash
for i in 1 2 3 4 5; do
  pkcs11-tool --module $HOME/utimaco/libcs_pkcs11_R3.so \
    --token-label "besu-validators" \
    --login --pin "$UTIMACO_PIN" \
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

Verify all 10 objects (5 private + 5 public) are in place:

```bash
pkcs11-tool --module $HOME/utimaco/libcs_pkcs11_R3.so \
  --token-label "besu-validators" \
  --login --pin "$UTIMACO_PIN" \
  --list-objects 2>/dev/null \
  | grep -E '^(Private Key|Public Key|  label:|  ID:)'
```

Expected: 5 `Private Key Object` and 5 `Public Key Object` blocks, each
with matching `label: testValidatorN` and `ID: 0N`. Objects may appear
out of order — that is normal:

```
Private Key Object; EC
  label:      testValidator1
  ID:         01
Public Key Object; EC  EC_POINT 256 bits
  label:      testValidator1
  ID:         01
...
```

---

## 7. Extract Public Keys for QBFT Genesis

QBFT's genesis configuration needs the validators' raw 64-byte
uncompressed public keys (X ‖ Y, no `0x04` prefix). Read them from
the public-key objects and strip the DER `OCTET STRING` wrapper that
`pkcs11-tool` prints:

```bash
mkdir -p ~/utimaco-validators
cd ~/utimaco-validators

pkcs11-tool --module $HOME/utimaco/libcs_pkcs11_R3.so \
  --token-label "besu-validators" \
  --login --pin "$UTIMACO_PIN" \
  --list-objects --type pubkey 2>/dev/null \
  | awk '
      /^[[:space:]]*EC_POINT:/                               { ec=$2 }
      /^[[:space:]]*label:[[:space:]]*testValidator[0-9]+/  { keys[$2]=ec }
      END { for (i=1; i<=5; i++) print keys["testValidator" i] }
    ' \
  | sed 's/^044104/0x/' \
  | jq -R . | jq -s . > public_keys.json

cat public_keys.json
```

You should see five `0x`-prefixed 64-byte hex strings, in validator
order.

> **If the `sed` produces no output or wrong output:** The DER prefix
> on the EC_POINT attribute may differ from the expected `044104`. Run
> `pkcs11-tool ... --list-objects --type pubkey` and examine the raw
> `EC_POINT:` hex for the leading bytes. The uncompressed-point marker
> `04` and the 64-byte length `40` (hex) must appear after the OCTET
> STRING DER envelope. Adjust the `sed` expression to strip those
> leading bytes, and record the prefix in
> [Compatibility Findings](#compatibility-findings).

---

## 8. Download Besu and the HSM Plugin

```bash
BESU_VERSION="26.6.1"
HSM_PLUGIN_VERSION="26.6.1"
WORK_DIR=$(pwd)   # ~/utimaco-validators

curl -L -O https://github.com/besu-eth/besu/releases/download/${BESU_VERSION}/besu-${BESU_VERSION}.tar.gz
curl -L -O https://github.com/besu-eth/besu-hsm-plugin/releases/download/${HSM_PLUGIN_VERSION}/besu-hsm-plugin-${HSM_PLUGIN_VERSION}.zip
```

Create per-validator directories and unpack into each:

```bash
for i in 1 2 3 4 5; do
  mkdir -p validator${i}/plugins validator${i}/data validator${i}/config
  tar xzf besu-${BESU_VERSION}.tar.gz --strip-components=1 -C validator${i}
  unzip -o -j besu-hsm-plugin-${HSM_PLUGIN_VERSION}.zip -d validator${i}/plugins
done
```

Write the User PIN to a file each Besu process can read:

```bash
echo -n "$UTIMACO_PIN" > pkcs11-password.txt
chmod 600 pkcs11-password.txt
```

> **If code changes are needed:** Build a custom plugin distribution
> locally (`./gradlew clean build -x test`; output at
> `build/distributions/besu-hsm-plugin-<version>.zip`), upload it with
> `scp`, and use the uploaded zip in place of the `curl` download.

---

## 9. Create the Plugin PKCS#11 Config

The plugin reads a minimal config file that tells it which library to
load and which slot to use. This is **separate** from
`cs_pkcs11_R3.cfg` — the library reads that file independently via
`CS_PKCS11_R3_CFG`.

```bash
cat > pkcs11-utimaco.cfg <<EOF
library = ${HOME}/utimaco/libcs_pkcs11_R3.so
slotListIndex = 0
EOF
```

`slotListIndex = 0` selects the first token-present slot returned by
`C_GetSlotList`. If you initialised more than one token on the simulator,
use the exact slot number from `pkcs11-tool --list-slots` instead:
`slot = <N>`.

> **Prerequisite:** `CS_PKCS11_R3_CFG` must be set in any shell that
> starts Besu, otherwise the library cannot locate the simulator or HSM.
> Verify before continuing:
>
> ```bash
> echo "$CS_PKCS11_R3_CFG"
> # should print the path to cs_pkcs11_R3.cfg
> ```

---

## 10. Generate the QBFT Genesis

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

> **Testing secp256r1?** Change `"ecCurve": "secp256k1"` to
> `"secp256r1"` here, and match it in `plugin-hsm-ec-curve` in §§11–12.

---

## 11. Configure Validator 1 (Bootnode)

Validator 1 is started first so its discovery URI can be captured for
the other validators. `ADMIN` is included in `rpc-http-api` so
`admin_nodeInfo` is available.

```bash
cat > validator1/config/config.toml <<EOF
genesis-file="${WORK_DIR}/validator1/data/genesis.json"
data-path="${WORK_DIR}/validator1/data"

security-module="hsm"
plugin-hsm-config-path="${WORK_DIR}/pkcs11-utimaco.cfg"
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

Notes on the HSM-plugin TOML fields:

- **No `plugin-hsm-provider-type`** — `native-pkcs11` is the default.
- `plugin-hsm-config-path` — the minimal plugin config written in §9
  (`library` + `slotListIndex`).
- `plugin-hsm-password-path` — file containing the User PIN (`CKU_USER`
  credential in PKCS#11 terms).
- `plugin-hsm-key-alias` — matches `CKA_LABEL` of the keypair on the
  token. No certificate is required.
- No `plugin-hsm-public-key-alias` — that field is CloudHSM-JCE only.

Start validator 1 and wait for its RPC endpoint:

```bash
tmux new -d -s validator1 ./validator1/bin/besu --config-file=./validator1/config/config.toml

for _ in {1..60}; do
  curl -s -o /dev/null -X POST http://localhost:8541 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}' && break
  sleep 1
done
```

Capture the bootnode URI:

```bash
VALIDATOR1_BOOTNODE=$(curl -s -X POST http://localhost:8541 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"admin_nodeInfo","params":[],"id":1}' \
  | jq -r '.result.enode')

echo "$VALIDATOR1_BOOTNODE"
```

> **Tip:** attach to the tmux session with `tmux attach -t validator1`
> (Ctrl+b, d to detach). Watch for "Ethereum main loop is up" before
> moving on.

---

## 12. Configure and Start Validators 2–5

```bash
for i in 2 3 4 5; do
  P2P_PORT=$((30300 + i))
  RPC_PORT=$((8540 + i))
  cat > "validator${i}/config/config.toml" <<EOF
genesis-file="${WORK_DIR}/validator${i}/data/genesis.json"
data-path="${WORK_DIR}/validator${i}/data"

security-module="hsm"
plugin-hsm-config-path="${WORK_DIR}/pkcs11-utimaco.cfg"
plugin-hsm-password-path="${WORK_DIR}/pkcs11-password.txt"
plugin-hsm-key-alias="testValidator${i}"
plugin-hsm-ec-curve="secp256k1"

p2p-port=${P2P_PORT}
min-gas-price=0
bootnodes=["${VALIDATOR1_BOOTNODE}"]

rpc-http-enabled=true
rpc-http-port=${RPC_PORT}
rpc-http-api=["ETH","NET","QBFT","ADMIN"]
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

## 13. Verify the Network

```bash
for i in 1 2 3 4 5; do
  PORT=$((8540 + i))
  echo "=== validator${i} (port ${PORT}) ==="

  curl -s -X POST http://localhost:${PORT} \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
  echo

  curl -s -X POST http://localhost:${PORT} \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"qbft_getValidatorsByBlockNumber","params":["latest"],"id":1}'
  echo
done
```

Expected output — all five validators at the same (advancing) block
number, validator list identical across all nodes:

```
=== validator1 (port 8541) ===
{"jsonrpc":"2.0","id":1,"result":"0x5"}
{"jsonrpc":"2.0","id":1,"result":["0x1e9eb3...","0x6aebb8...","0xba76c7...","0xceff2a...","0xf06372..."]}
=== validator2 (port 8542) ===
{"jsonrpc":"2.0","id":1,"result":"0x5"}
...
```

If `eth_blockNumber` advances and the validator list includes all five
addresses, the HSM-backed signing path is live and ECDH-backed peering
is working.

---

## Operations

### Session management

The provider opens one PKCS#11 session at validator startup and reuses
it for the lifetime of the process. On session-invalidating events
(simulator restart, token re-initialisation, etc.) the next sign or
ECDH call throws `SecurityModuleException` with the underlying PKCS#11
return code in the message. Restart the validator to recover.

### Simulator restart

The simulator persists its token state in the `devices/` directory
inside `sim5_linux`. Restarting `bl_sim5` after a crash or host reboot
restores the token and all keys automatically:

```bash
tmux kill-session -t simulator 2>/dev/null
tmux new -d -s simulator $HOME/utimaco/sim5_linux/bin/bl_sim5 -h -o
sleep 2
ss -tlnp | grep 3001   # confirm it is listening again
```

Ensure `CS_PKCS11_R3_CFG` is set in any new shell before restarting
validators.

---

## Cleanup

**If you want to remove individual keys while keeping the token intact,**
do this *before* stopping the simulator:

```bash
for i in 1 2 3 4 5; do
  pkcs11-tool --module $HOME/utimaco/libcs_pkcs11_R3.so \
    --token-label "besu-validators" --login --pin "$UTIMACO_PIN" \
    --delete-object --type privkey --label "testValidator${i}"
  pkcs11-tool --module $HOME/utimaco/libcs_pkcs11_R3.so \
    --token-label "besu-validators" --login --pin "$UTIMACO_PIN" \
    --delete-object --type pubkey --label "testValidator${i}"
done
```

**For a full teardown**, stop all processes first, then remove directories.
The simulator's token state (keys, users, token label) lives entirely in
`sim5_linux/devices/` — deleting that directory is equivalent to wiping
the HSM, so there is no need to delete keys individually beforehand.

Stop all validators and the simulator:

```bash
for i in 1 2 3 4 5; do tmux kill-session -t "validator${i}" 2>/dev/null; done
tmux kill-session -t simulator 2>/dev/null
```

Remove working directories and the SDK (re-extractable from the zip):

```bash
rm -rf ~/utimaco-validators ~/utimaco ~/utimaco-sdk
```

> `pkcs11-password.txt` (inside `~/utimaco-validators`) contains the
> User PIN. Confirm it is not copied elsewhere (shell history, scrollback,
> tmux scrollback) before treating cleanup as complete.

---

## Known Limitations

- **DiscV5 is only supported on the `secp256k1` curve.** EIP-778
  mandates secp256k1 for ENR identity. DiscV4 and devp2p handshakes
  work on both curves.
- **Per-JVM serialisation of HSM operations.** Sign and ECDH calls are
  serialised at the Java level (one PKCS#11 session per process). For a
  QBFT validator this is fine.
- **`pkcs11-tool` cannot generate `CKA_EXTRACTABLE=false` keys.** Keys
  are protected by `CKA_SENSITIVE=true` which blocks plaintext readback.
  For maximum security in production, regenerate keys with a tool that
  permits full attribute control.

## Production Hardening

When adapting this guide for a real Utimaco GP HSM deployment:

1. Point `Devices` in `cs_pkcs11_R3.cfg` at the physical HSM's IP
   address instead of `3001@127.0.0.1`.
2. Regenerate keys with `CKA_EXTRACTABLE=false`.
3. Move `pkcs11-password.txt` to a tightly-scoped location with mode
   `0400`, readable only by the Besu service user.
4. Enable TLS for the Utimaco client-to-HSM channel (refer to the
   Utimaco administration guide for mutual-TLS configuration).
5. For HA deployments, configure multiple devices in `cs_pkcs11_R3.cfg`:
   ```ini
   [HSMCluster]
   Devices = { 192.168.0.1 192.168.0.2 }
   FallbackInterval = 30
   ```

---

## Compatibility Findings

Validated on Utimaco u.trust GP HSM Simulator v6.5.0.0, Ubuntu 24.04 LTS (x86-64), Besu 26.6.1, plugin 26.6.1.

| Check | Result | Notes |
|-------|--------|-------|
| `ECDSA-KEY-PAIR-GEN` mechanism present | ✅ | hw, keySize={112,521} |
| `ECDSA` mechanism present | ✅ | hw, sign/verify, keySize={112,571} |
| `ECDH1-DERIVE` mechanism present | ✅ | hw, derive, keySize={112,571} |
| `secp256k1` key generation | ✅ | 256-bit EC keypairs generated successfully |
| EC_POINT DER prefix | ✅ `044104` | Standard format; same as Luna; compatible with `NativePkcs11Provider` |
| `ECDSA` signing via `native-pkcs11` | ✅ | QBFT blocks produced; no errors |
| `CKM_ECDH1_DERIVE` ECDH via `native-pkcs11` | ✅ | All 5 validators peered via DiscV4; devp2p handshakes completed |
| Blocks produced (all 5 validators) | ✅ | All 5 validators at same block height; full validator set reported |
| DiscV4 peer discovery | ✅ | Validators discovered each other; consistent validator set across nodes |
| `sunpkcs11-jce` fallback (if needed) | N/A | `native-pkcs11` works without fallback |
| Code changes required | No | Plugin works as-is with the Utimaco PKCS#11 R3 library |

---

## See Also

- Plugin overview: [`../../README.md`](../../README.md)
- Architecture diagram:
  [`../besu-hsm-plugin-architecture.png`](../besu-hsm-plugin-architecture.png)
- Thales Luna guide for comparison: [`../thales-luna/`](../thales-luna/)
- AWS CloudHSM guide: [`../aws-CloudHSM/`](../aws-CloudHSM/)

## References

- [Utimaco u.trust GP HSM Simulator](https://utimaco.com/data-protection/simulators-and-trials/gp-hsm-simulator)
- [OASIS PKCS#11 v3.0 base specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
