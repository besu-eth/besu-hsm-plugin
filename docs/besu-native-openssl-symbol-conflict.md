# OpenSSL Symbol Conflict in besu-native-ec

## Summary

`libbesu_native_ec_crypto.so` (a renamed copy of OpenSSL's `libcrypto.so.3`) exports all OpenSSL symbols into the global symbol table of the JVM process. Any Besu plugin or JNI library that loads a shared library depending on the **system** OpenSSL (e.g. SoftHSM2, cloud HSM PKCS#11 clients) will have its OpenSSL calls silently redirected to Besu's bundled copy. This causes `SIGSEGV` crashes or cryptographic operation failures due to mismatched OpenSSL internal state.

## Affected Component

- **Repository**: [besu-native](https://github.com/hyperledger/besu-native)
- **Module**: `secp256r1/besu-native-ec`
- **Artifact**: `secp256r1-1.4.2.jar` (contains `libbesu_native_ec.so` and `libbesu_native_ec_crypto.so`)
- **Loaded by**: `org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.BesuNativeEC` via JNA

## How the Native Library is Built

In `secp256r1/besu-native-ec/Makefile`:

1. OpenSSL is built as a **shared library** (`libcrypto.so.3`) from the `openssl/` submodule
2. The shared library is **copied and renamed** to `libbesu_native_ec_crypto.so`:
   ```makefile
   $(COPY) $(OPENSSL_LIB_CRYPTO) $@
   patchelf --set-soname libbesu_native_ec_crypto.so $@
   ```
3. `libbesu_native_ec.so` is linked against it:
   ```makefile
   LINK_RELEASE=gcc -L$(PATHL) -Wl,-rpath ./
   $(LINK_RELEASE) -Wl,-rpath ./ $^ -l$(CRYPTO_LIB) -fPIC -shared -o libbesu_native_ec.so
   ```
4. Both `.so` files are packaged into `secp256r1-1.4.2.jar` and loaded at runtime via JNA into a temp directory

The problem: renaming `libcrypto.so.3` and patching its soname does **not** hide its exported symbols. All standard OpenSSL symbols (`EVP_DigestSign`, `EVP_EncryptUpdate`, `EC_KEY_set_private_key`, `ossl_namemap_empty`, etc.) remain globally visible.

## What Happens at Runtime

When Besu starts, the JNA library loader extracts and loads `libbesu_native_ec_crypto.so` into the JVM process with `dlopen()` using default flags (which includes `RTLD_GLOBAL` or equivalent). This makes all OpenSSL symbols from Besu's bundled copy available in the global symbol table.

Later, when a plugin loads a shared library that depends on system OpenSSL (e.g. `/usr/lib/softhsm/libsofthsm2.so` → `/lib/aarch64-linux-gnu/libcrypto.so.3`), the dynamic linker resolves some OpenSSL symbols to **Besu's bundled copy** instead of the system copy.

This was confirmed using `LD_DEBUG=bindings`:

```
# Expected (system OpenSSL):
binding file libsofthsm2.so to /lib/aarch64-linux-gnu/libcrypto.so.3: normal symbol `EVP_DigestSign'

# Actual (Besu's bundled copy):
binding file libsofthsm2.so to /tmp/besu_native_ec_crypto@.../libbesu_native_ec_crypto.so: normal symbol `EVP_DigestSign'
binding file libsofthsm2.so to /tmp/besu_native_ec_crypto@.../libbesu_native_ec_crypto.so: normal symbol `EVP_DecryptFinal'
binding file libsofthsm2.so to /tmp/besu_native_ec_crypto@.../libbesu_native_ec_crypto.so: normal symbol `EVP_EncryptUpdate'
binding file libsofthsm2.so to /tmp/besu_native_ec_crypto@.../libbesu_native_ec_crypto.so: normal symbol `EVP_PKEY_derive_set_peer'
...
```

## Impact

### SIGSEGV Crash

When the bundled OpenSSL's internal state is incompatible with what the calling library expects (e.g. different initialization, missing providers, stripped-down build), the process crashes:

```
# A fatal error has been detected by the Java Runtime Environment:
#
#  SIGSEGV (0xb) at pc=0x0000fffef6132828, pid=8, tid=70
#
# Problematic frame:
# C  [libbesu_native_ec_crypto.so+0x1a2828]  ossl_namemap_empty+0x8
```

### Silent Cryptographic Failures

Even when it doesn't crash, the mismatched OpenSSL state causes cryptographic operations to fail with opaque errors. For example, SoftHSM2's PKCS#11 `C_Sign` returns `CKR_GENERAL_ERROR` (0x00000005) because the `EVP_DigestSign` call goes to Besu's OpenSSL copy which was built with many features disabled:

```
./Configure ... no-stdio no-ocsp no-nextprotoneg no-module no-legacy no-gost
             no-engine no-dynamic-engine no-deprecated no-comp no-cmp
             no-capieng no-ui-console no-tls no-ssl no-dtls no-aria no-bf
             no-blake2 no-camellia no-cast no-chacha no-cmac no-des no-dh
             no-dsa no-ecdh no-idea no-md4 no-mdc2 no-ocb no-poly1305
             no-rc2 no-rc4 no-rmd160 no-scrypt no-seed no-siphash no-siv
             no-sm2 no-sm3 no-sm4 no-whirlpool
```

This stripped-down build is missing many algorithms and providers that system OpenSSL has, causing failures when SoftHSM2 (or any other library) tries to use them.

### Who is Affected

Any Besu plugin or component that loads a native shared library depending on the system OpenSSL, including but not limited to:

- **PKCS#11 HSM plugins** using SoftHSM2, AWS CloudHSM client, YubiHSM PKCS#11, or any other PKCS#11 provider backed by OpenSSL
- **TLS/SSL libraries** loaded via JNI/JNA plugins
- Any native library that links against the system `libcrypto.so.3` or `libssl.so.3`

## Other Native Libraries are Not Affected

This issue is unique to `secp256r1/besu-native-ec`. The other native modules in besu-native handle their dependencies correctly:

| Module | Dependency | Linking | Issue? |
|--------|-----------|---------|--------|
| **secp256r1** | OpenSSL `libcrypto` | **Shared** (copied + renamed) | **YES** — symbols leak globally |
| **boringssl** | BoringSSL `libcrypto` | **Static** (`libcrypto.a`) | No — symbols are hidden |
| **secp256k1** | Bitcoin libsecp256k1 | Shared, no OpenSSL | No — no OpenSSL symbols |
| **gnark** | gnark-crypto (Go) | Go c-shared | No — no OpenSSL symbols |
| **constantine** | constantine (Nim) | **Static** (`libconstantine.a`) | No — symbols are hidden |
| **arithmetic** | Rust eth_arithmetic | Rust cdylib | No — no OpenSSL symbols |

The `boringssl` module is a good reference for the correct approach — it statically links `libcrypto.a` into its shared library.

## Suggested Fix

### Option A: Static Linking with Symbol Hiding (Recommended)

Build OpenSSL as a **static library** (`libcrypto.a`) and link it into `libbesu_native_ec.so` with hidden visibility, so no OpenSSL symbols are exported:

```makefile
# In openssl Configure:
./Configure ... -fvisibility=hidden

# Build static library instead of shared:
make build_generated libcrypto.a

# Link statically into libbesu_native_ec.so with -Bsymbolic:
LINK_RELEASE=gcc -L$(PATHL) -Wl,-Bsymbolic -Wl,--exclude-libs,ALL
$(LINK_RELEASE) $^ $(PATH_OPENSSL)libcrypto.a -fPIC -shared -o libbesu_native_ec.so
```

This eliminates `libbesu_native_ec_crypto.so` entirely — only `libbesu_native_ec.so` is shipped, with all OpenSSL code statically linked and hidden.

### Option B: Use `-Bsymbolic` on the Shared Library

If keeping the shared `libbesu_native_ec_crypto.so`, add `-Wl,-Bsymbolic` when linking `libbesu_native_ec.so`:

```makefile
LINK_RELEASE=gcc -L$(PATHL) -Wl,-rpath ./ -Wl,-Bsymbolic
```

And also use a version script to limit exported symbols from `libbesu_native_ec_crypto.so` to only what `libbesu_native_ec.so` needs. However, this is more complex and may not fully prevent symbol leaking since `libbesu_native_ec_crypto.so` is loaded separately by the dynamic linker.

### Option C: Load with `RTLD_LOCAL`

Ensure JNA loads `libbesu_native_ec_crypto.so` with `RTLD_LOCAL` flag so its symbols are not added to the global scope. This requires changes in the Java loading code (`BesuNativeLibraryLoader` or JNA configuration).

## How to Reproduce

1. Build and run Besu with a PKCS#11 HSM plugin that uses SoftHSM2
2. Attempt any PKCS#11 signing operation (e.g. QBFT consensus, or a test sign in the plugin constructor)
3. Observe `CKR_GENERAL_ERROR` from `C_Sign` or `SIGSEGV` in `libbesu_native_ec_crypto.so`

To confirm the symbol conflict:

```bash
# Run Besu with LD_DEBUG to trace symbol bindings:
LD_DEBUG=bindings /opt/besu/bin/besu ... 2>&1 | grep "softhsm.*besu_native"
```

Expected output showing the conflict:
```
binding file libsofthsm2.so to /tmp/besu_native_ec_crypto@.../libbesu_native_ec_crypto.so: normal symbol `EVP_DigestSign'
```
