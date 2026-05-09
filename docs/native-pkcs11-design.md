# native-pkcs11 design notes

Internal design reference for the FFM-based PKCS#11 provider (`native-pkcs11`).
Written for someone extending or porting this code who has not been part
of the original implementation. The user-facing operator guide lives at
[`docs/thales-luna/README.md`](thales-luna/README.md); this document
covers the *why* behind the implementation choices.

## 1. Why FFM (and not SunPKCS11)

`generic-pkcs11` drives PKCS#11 HSMs through SunPKCS11. That works
for permissive HSMs (SoftHSM2, YubiHSM2) but breaks against strict
v2.40 implementations such as Thales Luna 7.0.3, on two fronts:

- **Peer-point format.** SunPKCS11's `CKM_ECDH1_DERIVE` sends the
  peer's public point as a raw 65-byte buffer (`04 || X || Y`). Luna
  requires it DER-wrapped (`04 41 04 || X || Y`). SunPKCS11 has no
  way to change this encoding.
- **Sensitive-derive policy.** Luna's default policy (see §2) rejects
  non-sensitive derived secrets, but SunPKCS11's ECDH path then tries
  to read the secret's raw bytes via `C_GetAttributeValue`, which is
  blocked when the secret is sensitive.

`native-pkcs11` `dlopen`s the vendor library directly via Java 25's
Foreign Function & Memory API and issues PKCS#11 calls itself with
the exact byte layouts Luna requires. The same path also works
unmodified against permissive HSMs. FFM (vs JNI/JNA) gives us a
standard Java API with no native build step and explicit memory
lifecycle via `Arena`.

## 2. The ECDH derive recipe

This is the heart of the FFM path. Understanding it requires one
piece of Luna terminology first.

### Luna capabilities (a.k.a. policies)

A Luna partition is initialised with a numbered list of *capabilities*
(also called *policies*) that the Partition Security Officer toggles
between `0` and `1`. Each cap controls one partition-wide rule. The
two that matter here:

- **Cap 1: "Allow non-sensitive secret keys".** When `cap 1=0` (the
  strict / FIPS-mode default), the partition refuses any
  `C_DeriveKey` whose template sets `CKA_SENSITIVE=false` —
  `CKR_TEMPLATE_INCONSISTENT`. We design for `cap 1=0` so the recipe
  is portable to strict deployments.
- **Cap "Enable private key wrapping".** Permits wrapping
  *private* keys; we do NOT depend on this. The recipe wraps a
  *secret* (symmetric) key, which is allowed by default.

The rest of this document uses "cap 1=0" as shorthand for "the
partition forbids non-sensitive derived secrets."

### The constraint

Besu's devp2p / DiscV5 handshakes need the raw 32-byte ECDH shared
secret as input to HKDF. With `cap 1=0` we cannot derive a
non-sensitive secret, and a sensitive secret can't be read back via
`C_GetAttributeValue`. So we need a way to round-trip the secret out
of the HSM without ever asking for its plaintext attribute.

### The recipe

Each call to `Pkcs11Ffm.deriveEcdh(byte[] peerPointDer)` runs:

1. **`C_DeriveKey`** with template
   `(CKO_SECRET_KEY, CKK_GENERIC_SECRET, CKA_VALUE_LEN=32, CKA_TOKEN=false,
   CKA_SENSITIVE=true, CKA_EXTRACTABLE=true)`. Both `sensitive=true`
   and `extractable=true` are required:
   - `sensitive=true` satisfies cap 1=0 and prevents direct readback.
   - `extractable=true` is what `C_WrapKey` needs on its source key
     (a non-extractable key is `CKR_KEY_NOT_WRAPPABLE`).
2. **`C_WrapKey`** with mechanism `CKM_AES_CBC`, IV all-zeros, the
   long-lived KEK as wrapping key, the derived secret as source.
   Output is exactly 32 bytes (two AES blocks).
3. **`C_DecryptInit` + `C_Decrypt`** with the same KEK and same
   mechanism. The result is the original plaintext shared secret.
4. **`C_DestroyObject`** on the derived secret handle (in a `finally`
   block so error paths don't leak handles into the session table).

This is an *encrypt-decrypt-oracle* pattern: we use the HSM as both
encrypt and decrypt sides of the same operation, with a key the HSM
gave us. The plaintext never leaves the HSM in a non-cryptographic
form, so the recipe stays FIPS-conservative.

### Why `CKM_AES_CBC` (not `CKM_AES_CBC_PAD`) and a fixed-zero IV

SoftHSM2 returns `CKR_MECHANISM_INVALID` for `CKM_AES_CBC_PAD` as a
wrap mechanism. `CKM_AES_CBC` is universally supported, and the
32-byte secret is exactly two AES blocks — PKCS#7 padding isn't
needed.

The fixed all-zero IV would be a CBC anti-pattern *for
confidentiality*; it's not one here. The wrap-step ciphertext is
consumed by the very next decrypt call in the same method, in the
same arena — nothing outside `deriveEcdh` ever sees it. IV
uniqueness doesn't matter when the ciphertext is not a
confidentiality boundary.

## 3. Compressed ECDH for DiscV5

DiscV5 needs the SEC1-compressed encoding of the shared point
(33 bytes: `02|03 || X`), not just the X coordinate. PKCS#11's
`CKM_ECDH1_DERIVE` returns only X — which Y the underlying scalar
multiplication landed on is not exposed.

We recover Y-parity with a probe-point trick:

1. Run the standard derive against `Q` (the peer's point) → 32-byte X.
2. Decode the even-Y candidate from `02 || X` using BouncyCastle.
3. Compute `Q' = Q + G` in software (BouncyCastle, off-HSM).
4. Run a *second* derive against `Q'` → another 32-byte X (`xVerify`).
5. Pick the candidate whose sum with our public key has X equal to
   `xVerify`. The math:
   `d * Q' = d * (Q + G) = d*Q + d*G = sharedPoint + ourPubKey`.

So whichever Y candidate, when added to our public key, yields a
point with `xVerify` is the correct one. If neither matches, throw —
that indicates the HSM returned an inconsistent answer.

**Edge case:** If `Q == -G`, then `Q' = O` (the point at infinity),
and the second derive isn't well-defined. In that case
`d * Q = d * (-G) = -ourPubKey`, so the answer is the compressed
form of `-ourPubKey`. The implementation handles this branch
explicitly before the second derive call.

Cost: one extra HSM round-trip per peer handshake. For QBFT validators
this is negligible — handshakes happen once per peer, signing happens
per block.

## 4. `CK_FUNCTION_LIST` struct offsets

`C_GetFunctionList` returns a pointer to a struct of function
pointers; we use those pointers to bind `MethodHandle`s. FFM can't
read C headers at runtime, so the struct's field offsets are
hard-coded as `Pkcs11Ffm.java:OFF_C_*` constants.

The offsets assume 64-bit Linux/macOS SysV ABI: 8-byte function
pointers, `CK_VERSION` (2 bytes) padded to 8 at the start, then
`offset(N) = 8 + N * 8`. `Pkcs11Ffm.requireSupportedPlatform()` fails
fast on Windows or 32-bit JVMs rather than letting downcalls jump to
arbitrary addresses.

**Off-by-one trap.** The function indices around `C_Sign` are
adjacent:

| Index | Function | Offset |
|-------|----------|--------|
| 41 | `C_DigestFinal` | 336 |
| 42 | `C_SignInit` | **344** |
| 43 | `C_Sign` | **352** |

Using `336` for `C_SignInit` lands on `C_DigestFinal`, which (with
no active digest) returns `CKR_OPERATION_NOT_INITIALIZED` (`0x91`).
The error code is real but misleading — looks like a sign-init bug,
not an ABI bug. We hit this once during development; the constant
block carries an inline comment so the next developer doesn't.

## 5. Session and lifecycle model

`Pkcs11Ffm.open` runs once at provider construction. It holds one
PKCS#11 session and one long-lived AES-256 KEK for the lifetime of
the validator process — opening either per call would dominate hot-
path latency.

**Arena ownership.** `Arena.ofShared()` (held in a `final` field)
owns the library `SymbolLookup` and any segments that outlive a
single call. Shared (not confined) because public methods can be
invoked from different threads, serialized via the lock (§6).
`Arena.ofConfined()` is opened per `sign` / `deriveEcdh` call to
scope per-call temporaries deterministically.

**`close()` sequence.** `destroy KEK → C_Logout → C_CloseSession →
(if weInitialized) C_Finalize → arena.close`. Each step has its own
try/catch and logs at WARN on failure but doesn't abort. `C_Finalize`
is conditional because another component (e.g. SunPKCS11 in the same
JVM) may have initialized the library first.

**Idempotency and use-after-close.** A `volatile boolean closed` is
set inside `close()` under the lock; `sign` / `deriveEcdh` /
`getPublicEcPoint` check it and throw `IllegalStateException`. Without
this guard, a post-close call would invoke a `MethodHandle` whose
target is inside the now-unmapped library region — i.e., SIGSEGV.
The flag also makes double-close a silent no-op (avoiding the
`IllegalStateException` from a second `arena.close()`).

**Cleanup on init failure.** If `C_Initialize` succeeded but a later
step in `open()` throws, the catch block does best-effort
`C_Logout` / `C_CloseSession` / `C_Finalize` before `arena.close`,
so a half-initialized library doesn't linger.

**No transparent re-login.** Session-loss errors (`CKR_SESSION_HANDLE_INVALID`
0xB3, `CKR_DEVICE_ERROR` 0x30, `CKR_USER_NOT_LOGGED_IN` 0xE0) propagate
to the caller. With a local PCIe HSM, session loss is almost always
administratively significant (partition deactivated, firmware update);
operator visibility beats silent recovery. HA-group deployments may
want this changed — see §9.

## 6. Threading model

All public methods on `Pkcs11Ffm` are `synchronized` on a per-instance
`Object lock`. QBFT signing happens from the BFT processor thread;
ECDH can come from arbitrary peer threads, so cross-thread access is
real and we serialize at the Java level. PKCS#11's own OS-locking
(`CKF_OS_LOCKING_OK`) is not used — the Java lock is sufficient and
keeps the code simpler. Per-call `Arena.ofConfined` arenas are safe
inside the lock because only one thread holds it at a time and the
arena's lifetime is bounded by the synchronized block.

## 7. Memory and secret handling

PINs are kept off the `String` heap end-to-end so they can be
deterministically zeroed. `NativePkcs11Provider.readPin` decodes the
file via `CharsetDecoder` → `CharBuffer` → `char[]`, wiping the byte
and char buffers in `finally`. `Pkcs11Ffm.open` encodes the `char[]`
via `CharsetEncoder` → `ByteBuffer` → `byte[]` → arena segment →
`C_Login`, then wipes the byte buffers. The caller
(`NativePkcs11Provider.init`) zeroes the `char[] pin` it owns once
`open` returns. No `new String(...)` anywhere on the PIN path.

Logging policy: PINs, KEK material/handles, derived ECDH outputs,
and signatures are never logged. Slot IDs, key labels, and library
paths are logged at INFO. `getPublicEcPoint()` returns a defensive
clone so a caller mutating the result can't corrupt cached state.

## 8. Testing strategy

Three TestContainers-based integration tests in
`src/integrationTest/java/.../hsm/` boot a 4-node QBFT network with
every validator's keys in a SoftHSM2 token, exercising the full FFM
path on every sign and every handshake:

- `QbftSecp256k1NativePkcs11IntegrationTest` — DiscV4 + secp256k1.
- `QbftSecp256r1NativePkcs11IntegrationTest` — DiscV4 + secp256r1.
- `QbftSecp256k1NativePkcs11V5DiscoveryIntegrationTest` — DiscV5;
  exercises compressed-ECDH end-to-end.

`NativePkcs11ProviderTest` covers the static helpers (`parseConfig`,
`parseEcPoint`, `derWrapPoint`, `bigIntToFixedLength`), including
edge cases like the empty-array `parseEcPoint` path and negative
slot rejection. The FFM binding itself is not unit-tested (no mock
library); behaviour comes from the integration tests.

No Luna in CI — hardware HSMs can't run in GitHub Actions.
Production promotion gates on a manual soak run against the dev
Luna box; the operator guide describes the recipe.

## 9. Vendor compatibility — AWS CloudHSM is not supported

A POC against AWS CloudHSM revealed that the recipe in §2 cannot be
made to work on CloudHSM via standard PKCS#11. Documenting the
findings here so a future maintainer doesn't repeat the dead end.

**Root cause: AWS deliberately keeps the ECDH-derived secret
HSM-internal in SDK 5 for FIPS compliance.** From the [AWS
CloudHSM PKCS#11 known-issues page, ki-pkcs11-9](https://docs.aws.amazon.com/cloudhsm/latest/userguide/ki-pkcs11-sdk.html#ki-pkcs11-9):

> *"Elliptic-curve Diffie-Hellman (ECDH) key derivation is executed
> partially within the HSM. ... If your application requires your key
> to remain within an FIPS boundary at all times, consider using an
> alternative protocol that does not rely on ECDH key derivation.
> Resolution status: SDK 5.16 now supports ECDH with Key Derivation
> which is performed entirely within the HSM."*

In the older SDK 3 the derived bytes were briefly client-side; AWS
considered that a FIPS gap and closed it in SDK 5. Standard PKCS#11
gives no path to retrieve a fully-HSM-internal secret as plaintext.
The `cloudhsm-jce` provider works because it uses CloudHSM's
proprietary protocol (outside the PKCS#11 surface) to extract the
value.

CloudHSM rejected every standard path we tried:

- `CKM_AES_CBC` for `C_WrapKey` → `CKR_MECHANISM_INVALID (0x70)`.
  CBC isn't on CloudHSM's wrap whitelist.
- `CKA_SENSITIVE=false` on `C_DeriveKey` template →
  `CKR_ATTRIBUTE_VALUE_INVALID (0x13)`. The
  `--enable-ecdh-without-kdf` configure flag governs the KDF on the
  ECDH output, not the sensitive-attribute policy.
- `C_GetAttributeValue(CKA_VALUE)` on a `sensitive=true` derived
  secret → `CKR_ATTRIBUTE_SENSITIVE (0x11)`. No same-session
  exemption.
- `CKM_AES_GCM` for `C_WrapKey` (v2.40 params struct, 40 bytes) →
  `CKR_MECHANISM_PARAM_INVALID (0x71)`.
- `CKM_AES_GCM` for `C_WrapKey` (v3.0 params struct with `ulIvBits`,
  48 bytes) → `CKR_KEY_HANDLE_INVALID (0x60)`. Struct accepted, but
  CloudHSM refuses the source/wrapping key combination.
- `CKM_VENDOR_DEFINED | 0x1087` (CloudHSM's vendor GCM variant) →
  `CKR_MECHANISM_PARAM_INVALID (0x71)` again, with an undocumented
  params struct format.

Even if `C_WrapKey(GCM)` had been accepted, AWS issue
[ki-pkcs11-8](https://docs.aws.amazon.com/cloudhsm/latest/userguide/ki-pkcs11-sdk.html#ki-pkcs11-8)
notes that *"FIPS requires that the initialization vector (IV) for
`AES-GCM` be generated on the HSM"* — CloudHSM silently overwrites
caller-supplied IVs, which would break the deterministic
encrypt-decrypt-oracle assumption regardless. Likewise, AWS issue
[ki-pkcs11-13](https://docs.aws.amazon.com/cloudhsm/latest/userguide/ki-pkcs11-sdk.html#ki-pkcs11-13)
documents that SDK 5 does not support read-only `C_OpenSession`
calls; `Pkcs11Ffm.open` already passes `CKF_SERIAL_SESSION |
CKF_RW_SESSION` to satisfy that requirement on every HSM.

Reproducing `cloudhsm-jce`'s extraction path from a vendor-neutral
FFM binding would mean linking CloudHSM's private client SDK, which
defeats the "one FFM path drives any PKCS#11 v2.40 HSM" design and
turns this into a CloudHSM-specific provider — which is exactly
what `cloudhsm-jce` already is.

`native-pkcs11`'s sign path (`CKM_ECDSA`) does work on CloudHSM —
the failure is specific to ECDH derive. But a validator that can't
peer-handshake can't run, so practically `native-pkcs11` is unusable
on CloudHSM. Use `cloudhsm-jce` for that HSM.

## 10. Future work

- **Unit-testable `Pkcs11Ffm`.** A mock-library substitute would
  let us cover close-state semantics, the deriveEcdh error-path
  handle leak, and the sigLen sanity check without SoftHSM2.
  Substantial refactor; deferred.
- **Windows ABI support.** Windows uses a different struct alignment
  for `CK_FUNCTION_LIST`; the offsets in `Pkcs11Ffm` would need a
  parallel set, dispatched at runtime. Worth doing only when there's
  a concrete request.
- **Transparent session re-login** on `CKR_SESSION_HANDLE_INVALID`,
  `CKR_DEVICE_ERROR`, and `CKR_USER_NOT_LOGGED_IN` for HA-group
  deployments where session loss is more likely to be transient.
- **Provider rename.** `generic-pkcs11` → `sunpkcs11` (or similar)
  to match the implementation. Separate PR.

## 11. References

- [PKCS#11 v2.40 base spec](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
  — function-list layout, attribute and mechanism semantics, error
  codes.
- [Thales Luna 7 PKCS#11 mechanisms reference](https://thalesdocs.com/gphsm/luna/7/docs/usb/Content/sdk/pkcs11/pkcs11_standard.htm)
  — which `CKM_*` mechanisms are supported by Luna firmware, plus
  vendor-specific extensions.
- Java 25 [`java.lang.foreign` API docs](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/foreign/package-summary.html).
- Source: [`Pkcs11Ffm.java`](../src/main/java/org/hyperledger/besu/plugin/services/securitymodule/hsm/Pkcs11Ffm.java),
  [`NativePkcs11Provider.java`](../src/main/java/org/hyperledger/besu/plugin/services/securitymodule/hsm/NativePkcs11Provider.java),
  [`EcPointUtils.java`](../src/main/java/org/hyperledger/besu/plugin/services/securitymodule/hsm/EcPointUtils.java).
- Operator guide: [`docs/thales-luna/README.md`](thales-luna/README.md).
- Architecture diagram: [`docs/besu-hsm-plugin-architecture.png`](besu-hsm-plugin-architecture.png).
