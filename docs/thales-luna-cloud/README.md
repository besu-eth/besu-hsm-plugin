# Thales Luna Cloud HSM (DPoD) with Besu

Guide for pointing the plugin's `native-pkcs11` provider at a **Luna Cloud
HSM** service from Thales DPoD (Data Protection on Demand). It parallels the
[Luna K7 / network HSM guide](../thales-luna/README.md) and only covers what
differs for the cloud service. Read that guide first if you need the plugin
config reference, the QBFT genesis steps, or the Operations notes.

Validated on:

| Item | Value |
|---|---|
| Service | Luna Cloud HSM trial, region `eu.hsm.dpondemand.io` |
| Firmware / plugin | `7.3.0` (CV firmware `2.0.5`), `Cloud 2.7.0-1110` |
| Client | `lunacm v10.9.4-117` (DPoD "cvclient-min" bundle) |
| Host | Ubuntu 24.04 on WSL2, Temurin `25.0.4`, no root/sudo |
| Besu | `26.9.0`, plugin built from this repo |

## Summary of results

Two services were tested: the default one (**FIPS compliance enabled**) and a
second one created with the **"Disable FIPS compliance"** box ticked.

| Capability | FIPS service | Non-FIPS service |
|---|---|---|
| PKCS#11 login through the cloud client | Works (§§2-4) | Works |
| `secp256k1` / `secp256r1` key generation on the HSM | Works (§6) | Works |
| ECDSA signing / QBFT block production | **Works** — 58 blocks from one validator (§8) | Works (sign ~0.4 s) |
| `C_WrapKey` with `CKM_AES_CBC` | `0x70` — fixed by the probed mechanism (§10) | Works, probe keeps `CKM_AES_CBC` |
| Raw ECDH (`CKD_NULL` derive) | **Rejected, `0x71`** (§9) | **Works** (plugin `deriveEcdh` returns the secret, ~2.2 s) |
| Two-validator devp2p handshake | Cannot start (derive rejected) | Handshake **completes cryptographically** but takes ~12 s and misses Besu's 10 s limit from the test host (§9.1) |

The FIPS partition reports `*** The HSM is in FIPS approved operation mode.
***` and the operator cannot change that after creation (no partition policy
12/43 exists on this firmware, and HSM policy 12 is HSM-wide and
destructive). Under FIPS approved configuration Thales blocks two things this
plugin's ECDH recipe needs; both were reproduced (§9). A single validator
(or any setup where the node never has to do an RLPx/discv5 handshake) works
fully on either service.

---

## 1. What DPoD gave you

Creating a service (`besu-team-hsm`) and a service client (`besu-client`) in
the DPoD web UI produces `setup-besu-client.zip`. Contents (verified):

| File | Purpose |
|---|---|
| `Chrystoki.conf` | Client config for **Linux**: REST endpoint, OAuth client id/secret, partition data. Relative paths. |
| `cvclient-min.tar` / `cvclient-min.zip` | Minimal Luna client: `bin/64/{lunacm,cmu,ckdemo,...}`, `libs/64/libCryptoki2.so`, `plugins/libcloud.plugin`, `setenv`. The `.tar` is for Linux, the `.zip` for Windows. |
| `partition-ca-certificate.pem`, `partition-certificate.pem`, `server-certificate.pem` | XTC / TLS trust material for the service |
| `crystoki.ini`, `crystoki-template.ini` | Windows equivalents of `Chrystoki.conf` (ignore on Linux) |
| `lch-support-linux-64bit`, `lch-support-win-64bit.exe` | Thales support/diagnostic collector (not needed) |
| `EULA.zip` | License |

> **Treat the zip as a credential.** `Chrystoki.conf` contains
> `AuthTokenClientId` and `AuthTokenClientSecret`, which authenticate this
> client to the service. Never commit it or paste it into tickets. If it is
> exposed, regenerate the service client in the DPoD UI.

Unlike the on-prem client there is **no RPM install, no `/usr/safenet`, no
`hsmusers` group, and no root needed**: everything runs from the extracted
directory.

## 2. Install the client (no root)

```bash
mkdir -p ~/luna-cloud-client && cd ~/luna-cloud-client
unzip -o -q /path/to/setup-besu-client.zip \
  -x lch-support-win-64bit.exe cvclient-min.zip EULA.zip crystoki*.ini
tar xf cvclient-min.tar
chmod 700 . && chmod 600 Chrystoki.conf
```

Run `setenv` **sourced**, from inside that directory, in every shell (and
service unit) that will use the client:

```bash
cd ~/luna-cloud-client
source ./setenv          # prints "Configuring Chrystoki.conf for DPoD partition"
```

`setenv`:

- exports `ChrystokiConfigurationPath` pointing at this directory (the
  Luna library reads its config from there instead of `/etc/Chrystoki.conf`);
- rewrites `Chrystoki.conf` in place so `LibUNIX64`, `SSLConfigFile`,
  `PluginModuleDir` and `MutexFolder` are absolute paths, and removes the
  `SSLClientSideVerifyFile`, `PartitionCAPath` and `PartitionCertPath00` lines.

Quirks observed:

- **`setenv` parses its positional arguments.** Sourcing it from a script
  that was itself called with arguments (e.g. `-Dfoo=bar`) fails with
  `Error: Unknown command line argument` and silently skips the rest of an
  `&&` chain. Clear them first: `set --; source ./setenv`.
- It leaves a duplicate `PluginModuleDir = ./plugins;` and duplicate
  `ServerName`/`ServerPort` lines in `Chrystoki.conf`. They are harmless
  (the absolute-path entry is the one that works) but confusing.
- Because it rewrites `Chrystoki.conf`, keep an untouched copy of the zip.

> **The PKCS#11 library path differs from on-prem.** Here it is
> `~/luna-cloud-client/libs/64/libCryptoki2.so` — not
> `/usr/safenet/lunaclient/lib/libCryptoki2_64.so`.

## 3. Discover the slot and partition

```bash
cd ~/luna-cloud-client && source ./setenv
./bin/64/lunacm            # then: slot list
```

Observed:

```
Slot Id ->              3
Label ->                              (blank)
Serial Number ->        1771556813475
Model ->                Cryptovisor7
Firmware Version ->     7.3.0
Plugin Version ->       Cloud 2.7.0-1110
Configuration ->        Luna User Partition With SO (PW) Signing With Cloning Mode
Slot Description ->     Net Token Slot
```

The service shows up as one **Net Token Slot** (slot `3` here; use whatever
yours reports, referred to as `<user-slot>` below). A blank label plus
`partition showinfo` → `Partition Status -> L3 Device, Zeroized` means the
partition is **not initialized yet**. `pkcs11-tool -L` additionally lists
slots 0-2 as `Luna G7 Slot (empty)`; ignore them.

Every `lunacm` / `pkcs11-tool` invocation opens a fresh REST session to the
cloud and was observed to take **roughly 7 s to over 2 min** from the test
host. Batch commands into one `lunacm` session by piping them on stdin
(§4) instead of running one command per invocation.

Capabilities seen on the fresh partition (`partition showpolicies`), against
what this plugin needs:

| Capability | Value | Needed |
|---|---|---|
| 1: private key wrapping | `0` | not needed |
| 5: secret key wrapping | `1` | yes |
| 11: changing key attributes | `1` | yes |
| 28: Key Management Functions | `1` | yes |
| 12 / 43: allow non-FIPS algorithms | *not present* | cannot be changed (§9) |

## 4. Initialize the partition

The DPoD client bundle does not initialize the partition for you; the
`lunacm` commands are the same as for on-prem (see the
[K7 guide §2](../thales-luna/README.md#2-initialize-the-user-partition)):
`partition init` creates the Partition SO (PSO), `role init -name co`
creates the Crypto Officer (CO), and the CO must change its initial password
before first use. CO is what `C_Login(CKU_USER)` maps to, so **the CO
password is the plugin's PIN**.

Interactive form:

```
lunacm:> partition init -label besu-validators -auth
lunacm:> role init -name co
lunacm:> role logout
lunacm:> role login -name co
lunacm:> role changepw -name co
```

Non-interactive form used here (one `lunacm` session; all values generated
and kept in a `0600` file outside the repo):

```bash
cd ~/luna-cloud-client && source ./setenv
umask 077
gen() { openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 24; }
PSO=$(gen); CO0=$(gen); CO=$(gen); DOM=$(gen)
printf 'PARTITION_LABEL=besu-validators\nDOMAIN=%s\nPSO=%s\nCO_INITIAL=%s\nCO=%s\n' \
  "$DOM" "$PSO" "$CO0" "$CO" > .secrets

./bin/64/lunacm <<EOF
partition init -label besu-validators -domain $DOM -password $PSO -force -auth
role init -name co -password $CO0
role logout
role login -name co -password $CO0
role changepw -name co -oldpw $CO0 -newpw $CO
role logout
partition showinfo
exit
EOF
```

Notes:

- Passwords on the command line are visible in `ps` and can end up in shell
  history; for anything beyond a trial use the interactive form.
- Use only characters from `A-Za-z0-9` or the documented set
  (`!#$%'()*+,-./0123456789:=?@A-Z[]^_a-z{}~`); client 10.8+ enforces it.
- The **domain** is the cloning secret. Record it; it is needed to clone or
  back up the partition.
- Success is `Partition Label -> besu-validators`, flags
  `CKF_TOKEN_INITIALIZED` + `CKF_USER_PIN_INITIALIZED`, and
  `Extended Token Flags -> TOKEN_KCV_CREATED`. If `TOKEN_KCV_CREATED` is
  missing, do not use the partition (Thales guidance for `partition init`).

## 5. Host tools

`pkcs11-tool` (OpenSC) and `jq` are needed, as in the K7 guide:

```bash
sudo apt-get install -y opensc jq        # Ubuntu / Debian
```

Without sudo, unpack the packages into your home directory instead:

```bash
mkdir -p ~/luna-cloud-tools/debs && cd ~/luna-cloud-tools/debs
apt-get download opensc opensc-pkcs11 libeac3 jq libjq1 libonig5
mkdir -p ../root && for d in *.deb; do dpkg -x "$d" ../root; done
cat > ~/luna-cloud-tools/env.sh <<'EOF'
R=$HOME/luna-cloud-tools/root
export PATH=$R/usr/bin:$PATH
export LD_LIBRARY_PATH=$R/usr/lib/x86_64-linux-gnu:$R/usr/lib/x86_64-linux-gnu/pkcs11:${LD_LIBRARY_PATH:-}
EOF
source ~/luna-cloud-tools/env.sh
```

Java 25 (Temurin) is required as in the K7 guide.

## 6. Verify PKCS#11 access and generate keys

Everything from here uses these shell settings:

```bash
cd ~/luna-cloud-client && source ./setenv && source .secrets   # defines $CO
M=$PWD/libs/64/libCryptoki2.so
```

Check login and the mechanism table:

```bash
pkcs11-tool --module "$M" --token-label besu-validators \
  --login --pin "$CO" --list-mechanisms
```

Relevant lines observed (note what is **missing** from `AES-CBC`):

```
AES-CBC,             keySize={16,32}, hw, encrypt, decrypt, unwrap        <- no "wrap"
AES-GCM,             keySize={16,32}, hw, encrypt, decrypt, wrap, unwrap
mechtype-0x80000170, keySize={16,32}, hw, encrypt, decrypt, wrap, unwrap  <- Luna AES KW
mechtype-0x80000171, keySize={16,32}, hw, encrypt, decrypt, wrap, unwrap  <- Luna AES KWP
ECDSA-KEY-PAIR-GEN, ECDSA, ECDSA-SHA256, ECDH1-DERIVE ... hw
```

Generate the validator key exactly as in the K7 guide:

```bash
pkcs11-tool --module "$M" --token-label besu-validators --login --pin "$CO" \
  --keypairgen --key-type EC:secp256k1 \
  --label testValidator1 --id 01 \
  --usage-sign --usage-derive --sensitive --private
```

Observed differences from the K7 guide:

- `secp256k1` key generation is accepted by the cloud service.
- The private key comes back `sensitive, always sensitive, never extractable,
  local` — i.e. the production-hardening goal of the K7 guide
  (`CKA_EXTRACTABLE=false`) is the default here.
- `warning: PKCS11 function C_GetAttributeValue(ALWAYS_AUTHENTICATE) failed:
  rv = CKR_ATTRIBUTE_TYPE_INVALID (0x12)` appears on every `pkcs11-tool`
  object listing. It is cosmetic.

List the objects and extract the public key for the QBFT genesis (same
`EC_POINT` handling as K7 guide §5; strip the `044104` DER+uncompressed
prefix to get the 64-byte `X || Y`):

```bash
pkcs11-tool --module "$M" --token-label besu-validators --login --pin "$CO" \
  --list-objects --type pubkey 2>/dev/null | grep -E 'label|EC_POINT'
# EC_POINT: 044104233b26...b68d   ->   0x233b26...b68d
```

## 7. Plugin configuration

The plugin's PKCS#11 config differs from on-prem in two ways: the library
path, and the Luna client config must be discoverable by the JVM.

`pkcs11-luna.cfg`:

```
library = /home/<you>/luna-cloud-client/libs/64/libCryptoki2.so
slot = <user-slot>
```

Besu's TOML is the same as in the K7 guide §8 (`security-module="hsm"`,
`plugin-hsm-config-path`, `plugin-hsm-password-path` containing the **CO**
password, `plugin-hsm-key-alias="testValidator1"`,
`plugin-hsm-ec-curve="secp256k1"`).

**The Besu process must be started with `ChrystokiConfigurationPath` set**
(`setenv` does this for an interactive shell; a systemd unit or `tmux new -d`
launched from a clean environment must set it explicitly), otherwise the
Luna library looks for `/etc/Chrystoki.conf` and finds no cloud config:

```bash
ChrystokiConfigurationPath=$HOME/luna-cloud-client \
  ./validator1/bin/besu --config-file=./validator1/config.toml
```

No other JVM flags were needed.

## 8. Run a single-validator QBFT network (works)

Same genesis procedure as K7 guide §7, with one public key in
`blockchain.nodes.keys`. On start the log shows the provider choosing a wrap
mechanism for the Luna Cloud partition (this selection is described in §10):

```
NativePkcs11Provider | Initializing native-pkcs11 provider: lib=.../libs/64/libCryptoki2.so slot=3 ...
Pkcs11Ffm | Found PKCS#11 private key for alias 'testValidator1': handle=1
Pkcs11Ffm | Found PKCS#11 public key for alias 'testValidator1': handle=2
Pkcs11Ffm | Selected AES wrap mechanism for ECDH recipe: CKM_AES_KW (Luna vendor 0x80000170)
```

Startup took about 15-20 s (several cloud round trips). Verify:

```bash
curl -s -X POST http://localhost:8541 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
curl -s -X POST http://localhost:8541 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"qbft_getValidatorsByBlockNumber","params":["latest"],"id":1}'
```

Observed: blocks advanced continuously (`Produced #58` after about three
minutes at a 2 s block period, ~1.5 s per block including the HSM sign), and
the validator set was the single address derived from the HSM public key.
Block signing is performed by `C_Sign(CKM_ECDSA)` against the cloud HSM.

## 9. Multi-node networks: ECDH is rejected (FIPS approved mode)

Adding a second node (own HSM key `testValidator2`, `bootnodes` pointing at
validator 1) reproduces the failure seen in the field on **both** sides of
every connection:

```
WARN | ChannelInitializer | Failed to initialize a channel. Closing: [id: 0x...]
SecurityModuleException: C_DeriveKey failed: PKCS#11 rv=0x71
```

`net_peerCount` stays `0x0`. RLPx and discv5 both need the raw ECDH x
coordinate, which is what the plugin's recipe derives with `CKD_NULL`.

Root cause, established with the plugin's `Pkcs11Ffm` against the live
partition (throwaway harness, varying one parameter at a time):

| Experiment | Result |
|---|---|
| `CKM_ECDH1_DERIVE`, `CKD_NULL`, peer DER-wrapped, secp256k1 | `C_DeriveKey` → `0x71` `CKR_MECHANISM_PARAM_INVALID` |
| same, peer = secp256k1 generator `G` (known-valid point), DER **and** raw | `0x71` |
| same with a **secp256r1** key | `0x71` — not a curve problem |
| derived key type AES instead of generic secret | `0x71` |
| derived key `sensitive`/`extractable` = (true,false), (false,true), (false,false) | all `0x71` |
| `CKD_SHA256_KDF` instead of `CKD_NULL`, peer DER-wrapped | derive succeeds |
| `CKD_SHA256_KDF`, peer **raw** 65 bytes | `0x8000002f` (vendor error) — DER wrapping is still required, as on K7 |
| after a successful derive: `C_WrapKey` with `CKM_AES_CBC` | `0x70` `CKR_MECHANISM_INVALID` |
| after a successful derive: `C_WrapKey` + `C_Decrypt` with Luna AES KW `0x80000170` or KWP `0x80000171` | works, returns 32 bytes |
| `CKM_ECDH1_COFACTOR_DERIVE`, `CKD_NULL` | `0x71` |
| `CKD_NULL` with non-empty shared data | `0x71` (also `0x71` on the non-FIPS service — `CKD_NULL` takes no shared data) |
| `CKD_NULL` with `CKA_DERIVE=true` on the derived key | `0x71` |
| Luna `CA_DeriveKeyAndWrap` (derive + wrap in one call, no key object) with `CKD_NULL`, AES KW wrap | `0x71` |
| same, `CKM_AES_CBC` wrap | `0x70` |
| NIST concatenation KDFs: `CKD_SHA256_KDF_SP800` (`0x10`) and `CKD_SHA256_NIST_KDF` (`0x80000014`) | derive + AES KW wrap/decrypt succeed; both return identical 32 bytes (a hash of the secret) |
| Luna JCE (`LunaProvider`), `KeyAgreement` `ECDH` and `ECDHWithNistKdf256`, P-256 key | login and key lookup work; both fail `LunaException: Unable to derive secret key` |

This matches Thales' own
[Luna Compliance Guide](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/PDF_Network/Compliance%20Guide.pdf),
"FIPS Compliance" chapter:

- **Wrap**: `CKM_AES_CBC`, `CKM_AES_CBC_PAD`, `CKM_AES_CTR`, `CKM_AES_ECB`
  (and the 3DES / `RSA_PKCS` equivalents) are *not permitted to wrap* in
  FIPS approved configuration since firmware 7.7.0 (unwrap is allowed).
  This is the reported `C_WrapKey ... rv=0x70`; the plugin now works around
  it (§10).
- **Derive**: `secp256k1` "cannot be used for ECDH or ECIES derivation in
  FIPS 140 approved configuration" (documented for firmware 7.8.9 and
  newer; this service runs 7.3.0 and already rejects `CKD_NULL` for every
  curve tested, so treat the raw-`Z` derive as unavailable in FIPS mode).

A hashing KDF cannot substitute: it returns `KDF(Z)`, not `Z`, and RLPx /
discv5 require the raw coordinate for interoperability with other clients.

Why the hashed outputs cannot be used, checked against Besu's source
(`ethereum/p2p`, `crypto`, `services`): the HSM-backed `NodeKey` ECDH is
used in three places per handshake — `ECIESHandshaker` (initiator's static
secret), `ECIESEncryptionEngine.forDecryption` (decrypting the peer's
message) and `InitiatorHandshakeMessageV4.decode` (recipient's static
secret) — plus discv5 (`deriveECDHKeyAgreement`). The decode path computes
`staticSharedSecret.xor(nonce)` and feeds it to
`recoverPublicKeyFromSignature`, i.e. the raw secret is part of what the
peer signed on the wire. A Besu change that accepted an HSM-computed KDF
output would therefore break interoperability with any peer that does not
use the same substitute (including every software-key node) and still would
not cover discv5. Luna JCE also failed (`Unable to derive secret key`; the
underlying return code was not captured, so that it hits the same firmware
rule is an inference — it sits on the same Cryptoki library).

Conclusion: **on a FIPS-approved-configuration Luna partition the raw ECDH
secret Besu needs cannot be obtained from the HSM.** All tested routes
(`CKD_NULL` derive variants, cofactor derive, `CA_DeriveKeyAndWrap`, Luna
JCE) are rejected by the firmware; the allowed routes return a hash of the
secret.

**Possible future route (requires Besu changes, not implemented).** The
allowed NIST-KDF output is *exactly* the key block Besu's RLPx ECIES derives
in software: Besu's `ECIESHandshakeKDFFunction` is
`SHA256(00000001 || Z || iv)` (counter first, 32 bytes, empty `iv`), and the
HSM's `CKD_SHA256_KDF_SP800` (`0x10`) / `CKD_SHA256_NIST_KDF` (`0x80000014`)
returned precisely `SHA256(00000001 || Z)` — checked on the non-FIPS service
against the HSM's own raw `Z`, and on the FIPS service against a `Z` computed
in software from a known peer key (P-256). So decrypting the peer's handshake
message could be done with the HSM and stay wire-compatible, if Besu asked the
security module for the KDF output instead of `Z`. The static-secret step
(`staticSharedSecret XOR nonce`) is not compatible: it would need a
Besu-only protocol variant agreed by every node. discv5 would additionally
need changes in its external library. Both need new `SecurityModule` methods
and Besu core changes; the plugin interface alone cannot do this because the
RLPx handshaker is hard-wired in Besu.

### What to do

The wrap-mechanism fix in §10 is necessary but not sufficient on a partition
that also rejects `CKD_NULL`. Options, in order of preference:

1. **Use a non-FIPS Luna partition for validators that must peer** — an
   on-prem / network Luna HSM with HSM policy 12 allowing non-FIPS
   algorithms (the [K7 guide](../thales-luna/README.md) configuration), or
   a Luna Cloud service created with the **"Disable FIPS compliance"**
   checkbox ticked. It is left unticked by default, which is what the trial
   used here (FIPS on). The setting is fixed when the service is created, and
   a cloud user cannot flip an existing service (HSM policy 12 is HSM-wide
   and destructive), so the service must be re-created. Validated: a
   non-FIPS cloud service accepts `CKD_NULL` derive (§9.1).
2. **Single validator only** on the FIPS cloud service (§8). Useful for
   testing the PKCS#11 path and signing, not for a real network.
3. **Keep signing on the HSM, node key in software** is not supported by
   this plugin today: one HSM key serves both signing and ECDH.

If your own Luna Cloud service is **not** returning `0x71` on derive but
returns `C_WrapKey ... rv=0x70`, that is the case §10 fixes.

### 9.1 Non-FIPS service: ECDH works, but the handshake is too slow from a remote host

On the service created with "Disable FIPS compliance" ticked (partition
shows `*** The HSM is NOT in FIPS approved operation mode. ***`):

- `AES-CBC` advertises `wrap`; the probe keeps `CKM_AES_CBC`.
- `Pkcs11Ffm.deriveEcdh` succeeds. Measured from the test host (WSL2,
  Australia, to `eu.hsm.dpondemand.io`): **~2.2 s per derive**
  (`C_DeriveKey`, `C_WrapKey`, `C_DecryptInit`, `C_Decrypt`,
  `C_DestroyObject` = 5 cloud round trips) and **~0.4 s per sign**.

A two-validator QBFT network (validator 1 started first as the bootnode,
validator 2 with `bootnodes=[<enode of validator 1>]`, both started with
`--logging=DEBUG`) did **not** peer. The debug logs show:

```
PeerDiscoveryController | Starting ... bonding succeeds
NativePkcs11Provider | Calculating ECDH key agreement via native-pkcs11 provider ...   (x4 per node, 2.3-3 s apart)
RlpxAgent | Failed to connect to peer 0x...: java.util.concurrent.TimeoutException: Timed out waiting to establish connection with peer
PeerDiscoveryController | Handshake timed out with peer 0x...
AbstractPeerConnection | New PeerConnection (... inboundInitiated? true ...) established   <- ~20 ms AFTER the timeout
EthProtocolManager | Disconnect ... 0x01 TCP_SUBSYSTEM_ERROR
```

Reading: each node performs four sequential static-key ECDH derives during
one handshake and both nodes dial each other, so the plugin's single HSM
session serialises them. The handshake needs ~12 s against a hard 10 s
limit in Besu 26.9.0 (`RlpxAgent` future timeout; the 10000 ms constant in
`NettyConnectionInitializer`). The connection *is* established right after
the timeout (both inbound sides decrypt and authenticate successfully, which
proves the HSM-derived secrets are correct), then dropped.

So on the non-FIPS service the remaining problem is latency, not
correctness. It scales with the round-trip time to the HSM region and is not
expected with a host close to `eu.hsm.dpondemand.io` (not tested here).

## 10. Plugin change: probed wrap mechanism

`native-pkcs11` recovers the sensitive ECDH secret with a wrap + decrypt
"oracle" using an HSM-resident AES KEK. It previously always used
`CKM_AES_CBC`, which FIPS-mode Luna refuses to wrap with (`0x70`). Instead of
retrying on failure, `Pkcs11Ffm.open()` now probes `C_GetMechanismInfo` once
and picks the first mechanism whose flags contain **both** `CKF_WRAP` and
`CKF_DECRYPT` from, in order:

1. `CKM_AES_CBC` (zero IV) — unchanged behaviour for SoftHSM2, Utimaco,
   on-prem Luna and any token that advertises it;
2. Luna AES Key Wrap, vendor mechanism `0x80000170`, no parameter.

The choice is logged once (`Selected AES wrap mechanism ...`). If the token
advertises neither, the provider keeps the historical `CKM_AES_CBC` and logs a
warning, so tokens that support CBC wrap without advertising `CKF_WRAP` do
not regress. The selection logic is unit-tested in
`Pkcs11FfmWrapMechanismTest`.

Evidence on the live service: `C_GetMechanismInfo` reports `AES-CBC` without
`wrap`; the probe selects `CKM_AES_KW (0x80000170)`; with a derive that
succeeds, wrap + decrypt returns the 32-byte secret (§9 table). The
`0x80000170` / `0x80000171` ids are identified as AES KW / KWP from the
mechanism flags and Thales' `CKM_AES_KW` page (FIPS-approved, encrypt,
decrypt, wrap, unwrap); they were not cross-checked against a Luna
`cryptoki_v2.h`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `lunacm` shows no slots, or Besu cannot find the token | `ChrystokiConfigurationPath` not set for that process (§7), or `setenv` not sourced |
| Slot label blank, `Zeroized` | Partition not initialized (§4) |
| `CKR_PIN_EXPIRED` | CO initial password not changed yet (`role changepw`) |
| Very slow `lunacm` or `pkcs11-tool` | Each call opens a cloud REST session (7 s to minutes); batch commands |
| `SecurityModuleException: ... C_DeriveKey ... rv=0x71` | FIPS approved mode rejects raw ECDH (`CKD_NULL`); see §9 |
| `C_WrapKey ... rv=0x70` | CBC not permitted to wrap; fixed by the probed mechanism (§10) |
| `0x8000002f` from derive | Peer point not DER-wrapped (`04 41 04 \|\| X \|\| Y`) |
| `warning ... ALWAYS_AUTHENTICATE ... 0x12` | Cosmetic `pkcs11-tool` message |
| `SIGSEGV ... plugin_finalize` on JVM exit | Known Luna client issue on shutdown, cosmetic (see K7 guide) |
| `Error: Unknown command line argument` from `setenv` | Sourced from a script with arguments; run `set --` first (§2) |

## Cleanup

```bash
# Stop Besu, then remove test material
rm -rf ~/luna-cloud-besu-test
# Delete the HSM keys
for l in testValidator1 testValidator2; do
  for t in privkey pubkey; do
    pkcs11-tool --module "$M" --token-label besu-validators --login --pin "$CO" \
      --delete-object --type $t --label $l
  done
done
```

Remove `~/luna-cloud-client/.secrets` only after recording the PSO, CO and
domain values elsewhere; losing the PSO makes the partition unrecoverable
short of zeroizing it. To start over, zeroize/re-create the service in the
DPoD UI. Delete the service client in DPoD to revoke the credentials in
`Chrystoki.conf`.

## References

- [Thales `partition init`](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/lunacm/commands/partition/partition_init.htm)
  and [`role init`](https://thalesdocs.com/gphsm/luna/7/docs/pci/Content/lunacm/commands/role/role_init.htm)
- [Luna Network HSM 7 Compliance Guide (FIPS chapter)](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/PDF_Network/Compliance%20Guide.pdf)
- [`CKM_AES_KW`](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/mechanisms/CKM_AES_KW.htm)
- [Luna K7 guide in this repo](../thales-luna/README.md) and the
  [native-pkcs11 design notes](../native-pkcs11-design.md)
