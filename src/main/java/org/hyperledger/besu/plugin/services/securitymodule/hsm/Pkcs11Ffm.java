/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.plugin.services.securitymodule.hsm;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Java 25 FFM binding to a PKCS#11 library, used by {@link NativePkcs11Provider} to drive Luna
 * directly without going through SunPKCS11. Owns a single PKCS#11 session for the lifetime of the
 * binding; {@link #close()} releases the session, AES wrap KEK, and library Arena.
 *
 * <p>This binding implements the FIPS-conservative ECDH derive recipe needed for HSMs that enforce
 * strict PKCS#11 v2.40 compliance and/or disallow non-sensitive derived secrets: peer pubkey
 * wrapped in a DER OCTET STRING (Luna 7.0.3 strictly requires this; SunPKCS11 sends raw 65 bytes),
 * derived secret marked sensitive (Luna HSM capability 1=0 forbids non-sensitive derived secrets),
 * then wrapped with an HSM-resident AES-256 KEK using CKM_AES_CBC and decrypted via the same HSM as
 * a decryption oracle to recover the raw 32-byte shared secret. The same path also works against
 * more permissive HSMs (e.g. SoftHSM2) without modification.
 *
 * <p>All public methods that talk to the HSM are synchronized on this instance; the underlying
 * PKCS#11 lib supports OS locking, but we serialize at the Java level for simplicity (one HSM
 * round-trip is on the order of 10-20 ms; per-provider serialization is acceptable).
 *
 * <p>References:
 *
 * <ul>
 *   <li><a
 *       href="https://thalesdocs.com/gphsm/luna/7/docs/usb/Content/sdk/pkcs11/pkcs11_standard.htm">Thales
 *       Luna 7 PKCS#11 standard mechanisms reference</a> — which standard mechanisms (CKM_*) are
 *       supported by Luna firmware, and any vendor-specific extensions
 *   <li><a href="http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html">OASIS
 *       PKCS#11 v2.40 base specification</a> — function-list layout, attribute and mechanism
 *       semantics, error codes
 * </ul>
 */
final class Pkcs11Ffm implements AutoCloseable {
  private static final Logger LOG = LoggerFactory.getLogger(Pkcs11Ffm.class);

  // -- PKCS#11 v2.40 standard constants (subset used here) --
  private static final long CKR_OK = 0x00000000L;
  private static final long CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191L;
  private static final long CKR_USER_ALREADY_LOGGED_IN = 0x00000100L;
  private static final long CKO_PRIVATE_KEY = 0x00000003L;
  private static final long CKO_PUBLIC_KEY = 0x00000002L;
  private static final long CKO_SECRET_KEY = 0x00000004L;
  private static final long CKK_GENERIC_SECRET = 0x00000010L;
  private static final long CKK_AES = 0x0000001FL;
  private static final long CKM_ECDSA = 0x00001041L;
  private static final long CKM_ECDH1_DERIVE = 0x00001050L;
  private static final long CKM_AES_KEY_GEN = 0x00001080L;
  // CKM_AES_CBC (no PKCS#7 padding) is used for both wrap and decrypt of the 32-byte derived
  // ECDH secret. The padded variant (CKM_AES_CBC_PAD = 0x1085) is rejected by SoftHSM2 as a
  // wrapping mechanism (returns CKR_MECHANISM_INVALID); CKM_AES_CBC is universally supported
  // and is sufficient since 32 bytes is already a multiple of the 16-byte AES block size.
  private static final long CKM_AES_CBC = 0x00001082L;
  private static final long CKD_NULL = 0x00000001L;
  private static final long CKU_USER = 0x00000001L;
  private static final long CKF_SERIAL_SESSION = 0x00000004L;
  private static final long CK_TRUE = 1L;
  private static final long CK_FALSE = 0L;
  private static final long CKA_CLASS = 0x00000000L;
  private static final long CKA_TOKEN = 0x00000001L;
  private static final long CKA_LABEL = 0x00000003L;
  private static final long CKA_KEY_TYPE = 0x00000100L;
  private static final long CKA_SENSITIVE = 0x00000103L;
  private static final long CKA_DECRYPT = 0x00000105L;
  private static final long CKA_WRAP = 0x00000106L;
  private static final long CKA_EC_POINT = 0x00000181L;
  private static final long CKA_VALUE_LEN = 0x00000161L;
  private static final long CKA_EXTRACTABLE = 0x00000162L;

  // -- CK_FUNCTION_LIST offsets on 64-bit Linux. CK_VERSION (2 bytes + 6 padding) at offset 0;
  //    each function pointer is 8 bytes. Offset = 8 + N * 8 where N is the v2.40 function index.
  private static final long OFF_C_INITIALIZE = 8;
  private static final long OFF_C_FINALIZE = 16;
  private static final long OFF_C_GET_SLOT_LIST = 40;
  private static final long OFF_C_OPEN_SESSION = 104;
  private static final long OFF_C_CLOSE_SESSION = 112;
  private static final long OFF_C_LOGIN = 152;
  private static final long OFF_C_LOGOUT = 160;
  private static final long OFF_C_DESTROY_OBJECT = 184;
  private static final long OFF_C_GET_ATTRIBUTE_VALUE = 200;
  private static final long OFF_C_FIND_OBJ_INIT = 216;
  private static final long OFF_C_FIND_OBJ = 224;
  private static final long OFF_C_FIND_OBJ_FINAL = 232;
  private static final long OFF_C_DECRYPT_INIT = 272;
  private static final long OFF_C_DECRYPT = 280;
  // Indices 42 and 43 in CK_FUNCTION_LIST. Note: index 41 is C_DigestFinal (offset 336),
  // not C_SignInit — getting these off by one yields CKR_OPERATION_NOT_INITIALIZED (0x91)
  // from the no-active-digest path of DigestFinal, which masquerades as a sign-init failure.
  private static final long OFF_C_SIGN_INIT = 344;
  private static final long OFF_C_SIGN = 352;
  private static final long OFF_C_GENERATE_KEY = 472;
  private static final long OFF_C_WRAP_KEY = 488;
  private static final long OFF_C_DERIVE_KEY = 504;

  // -- Memory layouts mirroring Luna's pkcs11t.h on 64-bit Linux. --
  // CK_ATTRIBUTE { CK_ULONG type; CK_VOID_PTR pValue; CK_ULONG ulValueLen; } -> 24 bytes
  private static final MemoryLayout CK_ATTRIBUTE =
      MemoryLayout.structLayout(
          JAVA_LONG.withName("type"), ADDRESS.withName("pValue"), JAVA_LONG.withName("ulValueLen"));
  private static final long CKA_SIZE = CK_ATTRIBUTE.byteSize();

  private static final MemoryLayout CK_MECHANISM =
      MemoryLayout.structLayout(
          JAVA_LONG.withName("mechanism"),
          ADDRESS.withName("pParameter"),
          JAVA_LONG.withName("ulParameterLen"));

  private static final MemoryLayout CK_ECDH1_DERIVE_PARAMS =
      MemoryLayout.structLayout(
          JAVA_LONG.withName("kdf"),
          JAVA_LONG.withName("ulSharedDataLen"),
          ADDRESS.withName("pSharedData"),
          JAVA_LONG.withName("ulPublicDataLen"),
          ADDRESS.withName("pPublicData"));

  private static final Linker LINKER = Linker.nativeLinker();

  // -- Per-instance state. The arena owns the loaded library and any long-lived allocations
  //    (session-only mechanism segments etc.). Method handles are bound once at construction. --
  private final Arena arena;
  private final long session;
  private final long privKeyHandle;
  private final long kekHandle;
  private final byte[] cachedEcPoint; // 65-byte uncompressed point, 04 || X || Y
  private final boolean weInitialized; // whether we called C_Initialize (vs. it was already done)
  private final Object lock = new Object();

  /**
   * Set inside {@link #close()} under {@link #lock}. Read inside the same lock by every public
   * method, which throws {@link IllegalStateException} if true. Volatile so any future
   * non-synchronized read still sees the latest value.
   */
  private volatile boolean closed = false;

  // Method handles bound at construction
  private final MethodHandle hFinalize;
  private final MethodHandle hCloseSession;
  private final MethodHandle hLogout;
  private final MethodHandle hSignInit;
  private final MethodHandle hSign;
  private final MethodHandle hDeriveKey;
  private final MethodHandle hWrapKey;
  private final MethodHandle hDecryptInit;
  private final MethodHandle hDecrypt;
  private final MethodHandle hDestroyObject;

  private Pkcs11Ffm(
      final Arena arena,
      final long session,
      final long privKeyHandle,
      final long kekHandle,
      final byte[] cachedEcPoint,
      final boolean weInitialized,
      final MethodHandle hFinalize,
      final MethodHandle hCloseSession,
      final MethodHandle hLogout,
      final MethodHandle hSignInit,
      final MethodHandle hSign,
      final MethodHandle hDeriveKey,
      final MethodHandle hWrapKey,
      final MethodHandle hDecryptInit,
      final MethodHandle hDecrypt,
      final MethodHandle hDestroyObject) {
    this.arena = arena;
    this.session = session;
    this.privKeyHandle = privKeyHandle;
    this.kekHandle = kekHandle;
    this.cachedEcPoint = cachedEcPoint;
    this.weInitialized = weInitialized;
    this.hFinalize = hFinalize;
    this.hCloseSession = hCloseSession;
    this.hLogout = hLogout;
    this.hSignInit = hSignInit;
    this.hSign = hSign;
    this.hDeriveKey = hDeriveKey;
    this.hWrapKey = hWrapKey;
    this.hDecryptInit = hDecryptInit;
    this.hDecrypt = hDecrypt;
    this.hDestroyObject = hDestroyObject;
  }

  /**
   * Loads the vendor PKCS#11 shared library, opens a session against the resolved slot, logs in
   * with {@code pin}, looks up the private key by {@code keyAlias} (i.e. {@code CKA_LABEL}), reads
   * the matching public-key {@code CKA_EC_POINT}, and generates a session-only AES-256 wrap KEK
   * that is reused across all subsequent {@link #deriveEcdh} calls.
   *
   * <p>Slot identification accepts either a direct PKCS#11 slot ID ({@code slot = N} in a
   * SunPKCS11-style config) or a slot-list index ({@code slotListIndex = N}); the latter is
   * resolved via {@code C_GetSlotList(tokenPresent=TRUE)} and is generally more portable since
   * vendors commonly assign random slot IDs to initialized tokens (e.g. SoftHSM2). Exactly one of
   * the two must be supplied.
   *
   * @param libPath path to the vendor PKCS#11 shared library
   * @param slotId direct PKCS#11 slot ID, or {@code null} if {@code slotListIndex} is used
   * @param slotListIndex 0-based index into {@code C_GetSlotList(tokenPresent=TRUE)}, or {@code
   *     null} if {@code slotId} is used
   * @param pin token PIN; the caller retains ownership and may zero it after this call returns
   * @param keyAlias {@code CKA_LABEL} of the private key on the token
   * @throws SecurityModuleException if any PKCS#11 call fails or both/neither slot params are set
   */
  static Pkcs11Ffm open(
      final Path libPath,
      final Long slotId,
      final Integer slotListIndex,
      final char[] pin,
      final String keyAlias) {
    requireSupportedPlatform();
    if ((slotId == null) == (slotListIndex == null)) {
      throw new SecurityModuleException(
          "Exactly one of slotId or slotListIndex must be supplied (slotId="
              + slotId
              + ", slotListIndex="
              + slotListIndex
              + ")");
    }
    LOG.info(
        "Opening PKCS#11 session via FFM: lib={} slot={} slotListIndex={} alias={}",
        libPath,
        slotId,
        slotListIndex,
        keyAlias);
    final Arena arena = Arena.ofShared();
    boolean weInitialized = false;
    boolean sessionOpened = false;
    long openedSession = 0L;
    // Hoisted out of the try so the catch blocks can call them for best-effort cleanup if init
    // fails partway through. They are reassigned to the bound handles inside the try.
    MethodHandle hLogoutForCleanup = null;
    MethodHandle hCloseSessionForCleanup = null;
    MethodHandle hFinalizeForCleanup = null;
    try {
      // Load the library and resolve C_GetFunctionList
      final SymbolLookup lib = SymbolLookup.libraryLookup(libPath, arena);
      final MethodHandle hGetFL =
          bind(
              lib.find("C_GetFunctionList")
                  .orElseThrow(
                      () ->
                          new SecurityModuleException("C_GetFunctionList not found in " + libPath)),
              JAVA_LONG,
              ADDRESS);
      final MemorySegment ppFL = arena.allocate(ADDRESS);
      check((long) hGetFL.invokeExact(ppFL), "C_GetFunctionList");
      // The function list pointer's address space size is unknown; reinterpret a 1024-byte window
      // (max pointer count we read from is < 100 entries × 8 bytes = 800).
      final MemorySegment fl = ppFL.get(ADDRESS, 0).reinterpret(1024);

      // Bind every method handle we need
      final MethodHandle hInitialize = bind(fl, OFF_C_INITIALIZE, ADDRESS);
      final MethodHandle hFinalize = bind(fl, OFF_C_FINALIZE, ADDRESS);
      hFinalizeForCleanup = hFinalize;
      final MethodHandle hGetSlotList = bind(fl, OFF_C_GET_SLOT_LIST, JAVA_BYTE, ADDRESS, ADDRESS);
      final MethodHandle hOpenSession =
          bind(fl, OFF_C_OPEN_SESSION, JAVA_LONG, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS);
      final MethodHandle hCloseSession = bind(fl, OFF_C_CLOSE_SESSION, JAVA_LONG);
      hCloseSessionForCleanup = hCloseSession;
      final MethodHandle hLogin = bind(fl, OFF_C_LOGIN, JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG);
      final MethodHandle hLogout = bind(fl, OFF_C_LOGOUT, JAVA_LONG);
      hLogoutForCleanup = hLogout;
      final MethodHandle hDestroyObject = bind(fl, OFF_C_DESTROY_OBJECT, JAVA_LONG, JAVA_LONG);
      final MethodHandle hGetAttr =
          bind(fl, OFF_C_GET_ATTRIBUTE_VALUE, JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG);
      final MethodHandle hFindObjInit =
          bind(fl, OFF_C_FIND_OBJ_INIT, JAVA_LONG, ADDRESS, JAVA_LONG);
      final MethodHandle hFindObj =
          bind(fl, OFF_C_FIND_OBJ, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS);
      final MethodHandle hFindObjFinal = bind(fl, OFF_C_FIND_OBJ_FINAL, JAVA_LONG);
      final MethodHandle hDecryptInit = bind(fl, OFF_C_DECRYPT_INIT, JAVA_LONG, ADDRESS, JAVA_LONG);
      final MethodHandle hDecrypt =
          bind(fl, OFF_C_DECRYPT, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS);
      final MethodHandle hSignInit = bind(fl, OFF_C_SIGN_INIT, JAVA_LONG, ADDRESS, JAVA_LONG);
      final MethodHandle hSign =
          bind(fl, OFF_C_SIGN, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS);
      final MethodHandle hGenerateKey =
          bind(fl, OFF_C_GENERATE_KEY, JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS);
      final MethodHandle hWrapKey =
          bind(fl, OFF_C_WRAP_KEY, JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG, ADDRESS, ADDRESS);
      final MethodHandle hDeriveKey =
          bind(fl, OFF_C_DERIVE_KEY, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS);

      // C_Initialize — handle "already initialized" gracefully (another lib loader, e.g. SunPKCS11
      // in the same JVM, may have done it first; we still consider ourselves the eventual finalizer
      // only if we initialized.)
      final long initRv = (long) hInitialize.invokeExact(MemorySegment.NULL);
      if (initRv == CKR_OK) {
        weInitialized = true;
      } else if (initRv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        check(initRv, "C_Initialize");
      }

      // Resolve slotListIndex → actual slot ID via C_GetSlotList(tokenPresent=TRUE) if needed.
      // Vendors like SoftHSM2 assign random slot IDs to tokens at init, so the list-index form
      // is what users typically configure.
      final long resolvedSlot =
          (slotId != null) ? slotId : resolveSlotByIndex(arena, hGetSlotList, slotListIndex);

      // Open session against the resolved slot, login
      final MemorySegment sessOut = arena.allocate(JAVA_LONG);
      check(
          (long)
              hOpenSession.invokeExact(
                  resolvedSlot,
                  CKF_SERIAL_SESSION,
                  MemorySegment.NULL,
                  MemorySegment.NULL,
                  sessOut),
          "C_OpenSession");
      final long session = sessOut.get(JAVA_LONG, 0);
      sessionOpened = true;
      openedSession = session;

      // Encode the char[] PIN to UTF-8 bytes without going through an immutable String, which
      // would otherwise pin the PIN in the heap until GC.
      final ByteBuffer pinEncoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(pin));
      final byte[] pinBytes = new byte[pinEncoded.remaining()];
      pinEncoded.get(pinBytes);
      if (pinEncoded.hasArray()) {
        Arrays.fill(pinEncoded.array(), (byte) 0);
      }
      final MemorySegment pinSeg = arena.allocateFrom(JAVA_BYTE, pinBytes);
      final long loginRv =
          (long) hLogin.invokeExact(session, CKU_USER, pinSeg, (long) pinBytes.length);
      Arrays.fill(pinBytes, (byte) 0);
      if (loginRv != CKR_OK && loginRv != CKR_USER_ALREADY_LOGGED_IN) {
        check(loginRv, "C_Login");
      }

      // Find private key by label
      final long privKey =
          findObjectByLabel(
              arena, hFindObjInit, hFindObj, hFindObjFinal, session, CKO_PRIVATE_KEY, keyAlias);
      LOG.info("Found PKCS#11 private key for alias '{}': handle={}", keyAlias, privKey);

      // Find public key by same label, read CKA_EC_POINT
      final long pubKey =
          findObjectByLabel(
              arena, hFindObjInit, hFindObj, hFindObjFinal, session, CKO_PUBLIC_KEY, keyAlias);
      final byte[] ecPoint = readEcPoint(arena, hGetAttr, session, pubKey);

      // Generate AES-256 KEK on HSM (sensitive by default; we never need its bytes)
      final long kek = generateAesKek(arena, hGenerateKey, session);
      LOG.info("Generated session AES KEK: handle={}", kek);

      return new Pkcs11Ffm(
          arena,
          session,
          privKey,
          kek,
          ecPoint,
          weInitialized,
          hFinalize,
          hCloseSession,
          hLogout,
          hSignInit,
          hSign,
          hDeriveKey,
          hWrapKey,
          hDecryptInit,
          hDecrypt,
          hDestroyObject);
    } catch (final Throwable t) {
      // Best-effort cleanup so a partial init does not leave the HSM session or the cryptoki
      // library state hanging around for the rest of the JVM's life.
      if (sessionOpened && hLogoutForCleanup != null && hCloseSessionForCleanup != null) {
        try {
          hLogoutForCleanup.invokeExact(openedSession);
        } catch (final Throwable ignored) {
          // best effort
        }
        try {
          hCloseSessionForCleanup.invokeExact(openedSession);
        } catch (final Throwable ignored) {
          // best effort
        }
      }
      if (weInitialized && hFinalizeForCleanup != null) {
        try {
          hFinalizeForCleanup.invokeExact(MemorySegment.NULL);
        } catch (final Throwable ignored) {
          // best effort
        }
      }
      arena.close();
      if (t instanceof SecurityModuleException sme) {
        throw sme;
      }
      throw new SecurityModuleException("Failed to initialize Pkcs11Ffm", t);
    }
  }

  /** Returns a defensive copy of the cached 65-byte uncompressed EC point (04 || X || Y). */
  byte[] getPublicEcPoint() {
    synchronized (lock) {
      requireOpen();
      return cachedEcPoint.clone();
    }
  }

  /**
   * Must be called holding {@link #lock}. Guards every FFM downcall against a use-after-close,
   * which would otherwise jump to addresses inside the closed Arena's now-unmapped library region
   * (SIGSEGV).
   */
  private void requireOpen() {
    if (closed) {
      throw new IllegalStateException("Pkcs11Ffm has been closed");
    }
  }

  /**
   * Sign a pre-computed 32-byte hash with the configured private key using {@code CKM_ECDSA}.
   * Returns r || s as a single 64-byte buffer (P1363 format). Caller is responsible for encoding
   * (DER or P1363) as needed.
   */
  byte[] sign(final byte[] dataHash) {
    if (dataHash.length != 32) {
      throw new SecurityModuleException(
          "Expected 32-byte hash for CKM_ECDSA; got " + dataHash.length);
    }
    synchronized (lock) {
      requireOpen();
      try (Arena scope = Arena.ofConfined()) {
        final MemorySegment mech = scope.allocate(CK_MECHANISM);
        mech.set(JAVA_LONG, 0, CKM_ECDSA);
        mech.set(ADDRESS, 8, MemorySegment.NULL);
        mech.set(JAVA_LONG, 16, 0L);
        check((long) hSignInit.invokeExact(session, mech, privKeyHandle), "C_SignInit");

        final MemorySegment in = scope.allocateFrom(JAVA_BYTE, dataHash);
        // For 256-bit curves r||s = 64 bytes; allocate generously to support 384/521 too
        final MemorySegment out = scope.allocate(JAVA_BYTE, 256);
        final MemorySegment outLen = scope.allocate(JAVA_LONG);
        outLen.set(JAVA_LONG, 0, 256L);
        check((long) hSign.invokeExact(session, in, (long) dataHash.length, out, outLen), "C_Sign");
        final long sigLen = outLen.get(JAVA_LONG, 0);
        if (sigLen <= 0 || sigLen > 256) {
          throw new SecurityModuleException(
              "C_Sign returned implausible signature length: " + sigLen);
        }
        final byte[] sig = new byte[(int) sigLen];
        MemorySegment.copy(out, JAVA_BYTE, 0, sig, 0, (int) sigLen);
        return sig;
      } catch (final SecurityModuleException e) {
        throw e;
      } catch (final Throwable t) {
        throw new SecurityModuleException("C_Sign failed", t);
      }
    }
  }

  /**
   * Compute ECDH shared secret using Luna's required recipe. {@code peerPointDer} is the peer's
   * uncompressed EC point wrapped in a DER OCTET STRING ({@code 04 41 04 || X || Y} for 256-bit
   * curves). Returns the raw 32-byte shared secret.
   */
  byte[] deriveEcdh(final byte[] peerPointDer) {
    synchronized (lock) {
      requireOpen();
      try (Arena scope = Arena.ofConfined()) {
        final MemorySegment peerSeg = scope.allocateFrom(JAVA_BYTE, peerPointDer);
        final MemorySegment params = scope.allocate(CK_ECDH1_DERIVE_PARAMS);
        params.set(JAVA_LONG, 0, CKD_NULL);
        params.set(JAVA_LONG, 8, 0L);
        params.set(ADDRESS, 16, MemorySegment.NULL);
        params.set(JAVA_LONG, 24, (long) peerPointDer.length);
        params.set(ADDRESS, 32, peerSeg);

        final MemorySegment ecdhMech = scope.allocate(CK_MECHANISM);
        ecdhMech.set(JAVA_LONG, 0, CKM_ECDH1_DERIVE);
        ecdhMech.set(ADDRESS, 8, params);
        ecdhMech.set(JAVA_LONG, 16, CK_ECDH1_DERIVE_PARAMS.byteSize());

        final MemorySegment scls = allocLong(scope, CKO_SECRET_KEY);
        final MemorySegment gtype = allocLong(scope, CKK_GENERIC_SECRET);
        final MemorySegment vl32 = allocLong(scope, 32L);
        final MemorySegment fseg = allocByte(scope, (byte) CK_FALSE);
        final MemorySegment tseg = allocByte(scope, (byte) CK_TRUE);

        // Template: sensitive=true + extractable=true. Both attributes are required together:
        // sensitive=true satisfies HSMs that forbid non-sensitive derived secrets (Luna cap 1=0)
        // and prevents direct readback via C_GetAttributeValue; extractable=true lets us run the
        // wrap step below — C_WrapKey requires CKA_EXTRACTABLE=true on the source key.
        final MemorySegment tmpl = scope.allocate(CK_ATTRIBUTE, 6);
        setAttr(tmpl, 0, CKA_CLASS, scls, 8L);
        setAttr(tmpl, 1, CKA_KEY_TYPE, gtype, 8L);
        setAttr(tmpl, 2, CKA_VALUE_LEN, vl32, 8L);
        setAttr(tmpl, 3, CKA_TOKEN, fseg, 1L);
        setAttr(tmpl, 4, CKA_SENSITIVE, tseg, 1L);
        setAttr(tmpl, 5, CKA_EXTRACTABLE, tseg, 1L);

        final MemorySegment hSecOut = scope.allocate(JAVA_LONG);
        check(
            (long) hDeriveKey.invokeExact(session, ecdhMech, privKeyHandle, tmpl, 6L, hSecOut),
            "C_DeriveKey");
        final long hSecret = hSecOut.get(JAVA_LONG, 0);

        try {
          // Wrap the derived secret with our long-lived KEK using AES-CBC. The 32-byte secret
          // is exactly 2 AES blocks, so no padding is needed; CKM_AES_CBC is supported by both
          // SoftHSM2 and Luna for wrap/decrypt. The IV is fixed all-zeros: this isn't a CBC
          // confidentiality use — the ciphertext never leaves this method. The wrap is just
          // half of an encrypt-decrypt-oracle pair that lets us round-trip the sensitive
          // derived secret out of the HSM (since CKA_SENSITIVE=true blocks direct readback).
          final MemorySegment iv = scope.allocate(JAVA_BYTE, 16); // zero-filled
          final MemorySegment cbcMech = scope.allocate(CK_MECHANISM);
          cbcMech.set(JAVA_LONG, 0, CKM_AES_CBC);
          cbcMech.set(ADDRESS, 8, iv);
          cbcMech.set(JAVA_LONG, 16, 16L);

          final MemorySegment ct = scope.allocate(JAVA_BYTE, 64);
          final MemorySegment ctLen = scope.allocate(JAVA_LONG);
          ctLen.set(JAVA_LONG, 0, 64L);
          check(
              (long) hWrapKey.invokeExact(session, cbcMech, kekHandle, hSecret, ct, ctLen),
              "C_WrapKey");
          final long wlen = ctLen.get(JAVA_LONG, 0);

          // Decrypt the wrapped ciphertext with the same KEK to recover the plaintext bytes
          check((long) hDecryptInit.invokeExact(session, cbcMech, kekHandle), "C_DecryptInit");
          final MemorySegment pt = scope.allocate(JAVA_BYTE, 64);
          final MemorySegment ptLen = scope.allocate(JAVA_LONG);
          ptLen.set(JAVA_LONG, 0, 64L);
          check((long) hDecrypt.invokeExact(session, ct, wlen, pt, ptLen), "C_Decrypt");
          final long plen = ptLen.get(JAVA_LONG, 0);

          if (plen != 32) {
            throw new SecurityModuleException("ECDH shared secret expected 32 bytes; got " + plen);
          }
          final byte[] shared = new byte[32];
          MemorySegment.copy(pt, JAVA_BYTE, 0, shared, 0, 32);
          return shared;
        } finally {
          // Always release the derived-secret handle so error paths don't leak object handles
          // into the HSM session table over time.
          try {
            @SuppressWarnings("unused")
            final long ignored = (long) hDestroyObject.invokeExact(session, hSecret);
          } catch (final Throwable ignore) {
            // best-effort cleanup; session close will release any leaked handles
          }
        }
      } catch (final SecurityModuleException e) {
        throw e;
      } catch (final Throwable t) {
        throw new SecurityModuleException("ECDH derive failed", t);
      }
    }
  }

  @Override
  public void close() {
    synchronized (lock) {
      if (closed) {
        return;
      }
      closed = true;
      // Destroy KEK first (best-effort)
      try {
        @SuppressWarnings("unused")
        final long ignored = (long) hDestroyObject.invokeExact(session, kekHandle);
      } catch (final Throwable t) {
        LOG.warn("C_DestroyObject(kek) failed during close: {}", t.getMessage());
      }
      try {
        @SuppressWarnings("unused")
        final long ignored = (long) hLogout.invokeExact(session);
      } catch (final Throwable t) {
        LOG.warn("C_Logout failed during close: {}", t.getMessage());
      }
      try {
        @SuppressWarnings("unused")
        final long ignored = (long) hCloseSession.invokeExact(session);
      } catch (final Throwable t) {
        LOG.warn("C_CloseSession failed during close: {}", t.getMessage());
      }
      // Only call C_Finalize if we initialized the lib; otherwise another component owns it
      if (weInitialized) {
        try {
          @SuppressWarnings("unused")
          final long ignored = (long) hFinalize.invokeExact(MemorySegment.NULL);
        } catch (final Throwable t) {
          LOG.warn("C_Finalize failed during close: {}", t.getMessage());
        }
      }
      arena.close();
    }
  }

  // ============== Helpers ==============

  private static MethodHandle bind(
      final MemorySegment fnPtr, final MemoryLayout ret, final MemoryLayout... args) {
    final FunctionDescriptor desc =
        (ret == null) ? FunctionDescriptor.ofVoid(args) : FunctionDescriptor.of(ret, args);
    return LINKER.downcallHandle(fnPtr, desc);
  }

  private static MethodHandle bind(
      final MemorySegment fl, final long off, final MemoryLayout... args) {
    return bind(fl.get(ADDRESS, off), JAVA_LONG, args);
  }

  private static void check(final long rv, final String what) {
    if (rv != CKR_OK) {
      throw new SecurityModuleException(what + " failed: PKCS#11 rv=0x" + Long.toHexString(rv));
    }
  }

  /**
   * The {@code CK_FUNCTION_LIST} field offsets used in this binding assume an 8-byte function
   * pointer and SysV struct layout (64-bit Linux/macOS). Other ABIs (Windows, 32-bit) would require
   * different offsets; fail fast rather than jump to garbage addresses at runtime.
   */
  private static void requireSupportedPlatform() {
    if (ValueLayout.ADDRESS.byteSize() != 8) {
      throw new SecurityModuleException(
          "native-pkcs11 requires a 64-bit JVM; pointer size is "
              + ValueLayout.ADDRESS.byteSize()
              + " bytes");
    }
    final String os = System.getProperty("os.name", "").toLowerCase();
    if (!(os.contains("linux") || os.contains("mac") || os.contains("darwin"))) {
      throw new SecurityModuleException(
          "native-pkcs11 currently supports 64-bit Linux and macOS only; got os.name='"
              + System.getProperty("os.name")
              + "'. Windows uses a different ABI and is not yet validated.");
    }
  }

  private static void setAttr(
      final MemorySegment tmpl,
      final int idx,
      final long type,
      final MemorySegment value,
      final long len) {
    final long base = idx * CKA_SIZE;
    tmpl.set(JAVA_LONG, base, type);
    tmpl.set(ADDRESS, base + 8, value);
    tmpl.set(JAVA_LONG, base + 16, len);
  }

  private static MemorySegment allocLong(final Arena arena, final long value) {
    final MemorySegment seg = arena.allocate(JAVA_LONG);
    seg.set(JAVA_LONG, 0, value);
    return seg;
  }

  private static MemorySegment allocByte(final Arena arena, final byte value) {
    final MemorySegment seg = arena.allocate(JAVA_BYTE, 1);
    seg.set(JAVA_BYTE, 0, value);
    return seg;
  }

  private static long resolveSlotByIndex(
      final Arena arena, final MethodHandle hGetSlotList, final int slotListIndex)
      throws Throwable {
    if (slotListIndex < 0) {
      throw new SecurityModuleException("slotListIndex must be >= 0; got " + slotListIndex);
    }
    // First call with pSlotList=NULL to discover count
    final MemorySegment count = arena.allocate(JAVA_LONG);
    count.set(JAVA_LONG, 0, 0L);
    check(
        (long) hGetSlotList.invokeExact((byte) CK_TRUE, MemorySegment.NULL, count),
        "C_GetSlotList(count)");
    final long n = count.get(JAVA_LONG, 0);
    if (slotListIndex >= n) {
      throw new SecurityModuleException(
          "slotListIndex=" + slotListIndex + " out of range; only " + n + " slot(s) with token");
    }
    final MemorySegment slots = arena.allocate(JAVA_LONG, n);
    count.set(JAVA_LONG, 0, n);
    check((long) hGetSlotList.invokeExact((byte) CK_TRUE, slots, count), "C_GetSlotList(values)");
    return slots.getAtIndex(JAVA_LONG, slotListIndex);
  }

  private static long findObjectByLabel(
      final Arena arena,
      final MethodHandle hFindObjInit,
      final MethodHandle hFindObj,
      final MethodHandle hFindObjFinal,
      final long session,
      final long objClass,
      final String label)
      throws Throwable {
    final byte[] labelBytes = label.getBytes(StandardCharsets.UTF_8);
    final MemorySegment classSeg = allocLong(arena, objClass);
    final MemorySegment labelSeg = arena.allocateFrom(JAVA_BYTE, labelBytes);
    final MemorySegment tmpl = arena.allocate(CK_ATTRIBUTE, 2);
    setAttr(tmpl, 0, CKA_CLASS, classSeg, 8L);
    setAttr(tmpl, 1, CKA_LABEL, labelSeg, labelBytes.length);
    check((long) hFindObjInit.invokeExact(session, tmpl, 2L), "C_FindObjectsInit");
    try {
      final MemorySegment hOut = arena.allocate(JAVA_LONG);
      final MemorySegment cnt = arena.allocate(JAVA_LONG);
      check((long) hFindObj.invokeExact(session, hOut, 1L, cnt), "C_FindObjects");
      final long count = cnt.get(JAVA_LONG, 0);
      if (count == 0) {
        throw new SecurityModuleException(
            "No PKCS#11 object with class=0x"
                + Long.toHexString(objClass)
                + " and label='"
                + label
                + "'");
      }
      return hOut.get(JAVA_LONG, 0);
    } finally {
      try {
        @SuppressWarnings("unused")
        final long ignored = (long) hFindObjFinal.invokeExact(session);
      } catch (final Throwable ignore) {
        // best-effort
      }
    }
  }

  private static byte[] readEcPoint(
      final Arena arena, final MethodHandle hGetAttr, final long session, final long pubKey)
      throws Throwable {
    // Two-phase read: first call with pValue=NULL to discover the size.
    final MemorySegment template = arena.allocate(CK_ATTRIBUTE, 1);
    template.set(JAVA_LONG, 0, CKA_EC_POINT);
    template.set(ADDRESS, 8, MemorySegment.NULL);
    template.set(JAVA_LONG, 16, 0L);
    check(
        (long) hGetAttr.invokeExact(session, pubKey, template, 1L),
        "C_GetAttributeValue(EC_POINT size)");
    final long len = template.get(JAVA_LONG, 16);
    if (len < 65 || len > 200) {
      throw new SecurityModuleException("Unexpected EC_POINT length: " + len);
    }
    final MemorySegment buf = arena.allocate(JAVA_BYTE, len);
    template.set(ADDRESS, 8, buf);
    template.set(JAVA_LONG, 16, len);
    check(
        (long) hGetAttr.invokeExact(session, pubKey, template, 1L),
        "C_GetAttributeValue(EC_POINT)");

    final byte[] full = new byte[(int) len];
    MemorySegment.copy(buf, JAVA_BYTE, 0, full, 0, (int) len);
    // Luna returns CKA_EC_POINT as a DER-wrapped OCTET STRING: 04 41 04 || X || Y for 256-bit
    // curves.
    // Strip the leading 04 41 to get the raw 65-byte uncompressed point.
    if (full[0] == 0x04 && full.length >= 67 && full[1] == 0x41) {
      return Arrays.copyOfRange(full, 2, full.length);
    }
    // Some PKCS#11 libs return the raw point directly without DER wrapping.
    if (full[0] == 0x04 && full.length == 65) {
      return full;
    }
    throw new SecurityModuleException(
        "Unrecognized CKA_EC_POINT encoding (first 4 bytes: "
            + String.format(
                "%02x %02x %02x %02x", full[0], full[1], full[2], full.length > 3 ? full[3] : 0)
            + ", len="
            + full.length
            + ")");
  }

  private static long generateAesKek(
      final Arena arena, final MethodHandle hGenerateKey, final long session) throws Throwable {
    final MemorySegment mech = arena.allocate(CK_MECHANISM);
    mech.set(JAVA_LONG, 0, CKM_AES_KEY_GEN);
    mech.set(ADDRESS, 8, MemorySegment.NULL);
    mech.set(JAVA_LONG, 16, 0L);

    final MemorySegment scls = allocLong(arena, CKO_SECRET_KEY);
    final MemorySegment akt = allocLong(arena, CKK_AES);
    final MemorySegment vl32 = allocLong(arena, 32L);
    final MemorySegment fseg = allocByte(arena, (byte) CK_FALSE);
    final MemorySegment tseg = allocByte(arena, (byte) CK_TRUE);
    // Set CKA_SENSITIVE=true and CKA_EXTRACTABLE=false explicitly rather than relying on
    // vendor defaults — Luna defaults are conservative but SoftHSM2 et al. may produce an
    // extractable, non-sensitive KEK otherwise.
    final MemorySegment tmpl = arena.allocate(CK_ATTRIBUTE, 8);
    setAttr(tmpl, 0, CKA_CLASS, scls, 8L);
    setAttr(tmpl, 1, CKA_KEY_TYPE, akt, 8L);
    setAttr(tmpl, 2, CKA_VALUE_LEN, vl32, 8L);
    setAttr(tmpl, 3, CKA_TOKEN, fseg, 1L);
    setAttr(tmpl, 4, CKA_WRAP, tseg, 1L);
    setAttr(tmpl, 5, CKA_DECRYPT, tseg, 1L);
    setAttr(tmpl, 6, CKA_SENSITIVE, tseg, 1L);
    setAttr(tmpl, 7, CKA_EXTRACTABLE, fseg, 1L);

    final MemorySegment hOut = arena.allocate(JAVA_LONG);
    check((long) hGenerateKey.invokeExact(session, mech, tmpl, 8L, hOut), "C_GenerateKey(AES)");
    return hOut.get(JAVA_LONG, 0);
  }
}
