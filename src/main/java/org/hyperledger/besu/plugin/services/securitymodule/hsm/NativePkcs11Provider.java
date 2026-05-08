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

import static org.hyperledger.besu.plugin.services.securitymodule.hsm.Validations.requireNonBlank;
import static org.hyperledger.besu.plugin.services.securitymodule.hsm.Validations.requireNonNull;

import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.spec.ECPoint;
import java.util.Arrays;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HSM provider that talks to any PKCS#11 HSM through a Java 25 FFM binding directly into the
 * vendor's PKCS#11 shared library (e.g. {@code libCryptoki2_64.so} on Thales Luna, {@code
 * libsofthsm2.so} on SoftHSM2). Bypasses SunPKCS11 entirely, which lets us drive HSMs whose strict
 * PKCS#11 v2.40 spec compliance is incompatible with SunPKCS11's hardcoded peer-point format (most
 * notably Thales Luna 7.0.3, which requires the DER OCTET STRING wrapped form for {@code
 * CKM_ECDH1_DERIVE}).
 *
 * <p>This provider uses the same {@code --plugin-hsm-config-path}, {@code -password-path}, {@code
 * -key-alias} CLI options as the {@code generic-pkcs11} provider; the config file is parsed for
 * {@code library = <path>} and either {@code slot = <int>} or {@code slotListIndex = <int>} (other
 * SunPKCS11 directives are ignored). The same config file therefore typically works unchanged for
 * both providers. Unlike the generic-pkcs11 path, this provider does NOT require a self-signed cert
 * to be associated with the private-key alias on the HSM — keys are looked up directly by {@code
 * CKA_LABEL}.
 *
 * <h2>Session management</h2>
 *
 * One PKCS#11 session is opened at construction time and reused for the lifetime of the provider (=
 * lifetime of the validator process). A long-lived AES-256 KEK is also generated once and reused
 * across all ECDH derives. This minimises HSM round-trips on the hot path (sign per QBFT block,
 * ECDH per peer handshake).
 *
 * <p>If the session is invalidated (e.g. partition deactivation, HA-group failover that doesn't
 * preserve the handle, idle disconnect), subsequent calls will throw {@link
 * SecurityModuleException} with the underlying PKCS#11 rv code in the message. The validator must
 * be restarted in this case. Transparent re-login on session-lost errors is intentionally NOT
 * implemented in v1: with a local PCIe HSM, session loss almost always indicates an
 * administratively significant event (partition touched, firmware update) that an operator should
 * see rather than have silently masked. See the README for guidance on running with HA-group client
 * configurations where automatic session-recovery would be more valuable.
 *
 * <p>For background on why the FFM path is needed (Luna's strict spec compliance, the
 * derive-then-wrap-then-decrypt-via-HSM-oracle recipe, and the documented HSM cap 1=0 sensitivity
 * constraint), see {@code docs/thales-luna/README.md}.
 */
class NativePkcs11Provider implements HsmProvider {
  private static final Logger LOG = LoggerFactory.getLogger(NativePkcs11Provider.class);

  private final Pkcs11Ffm nativeBinding;
  private final PublicKey publicKey;
  private final EcCurveParameters curveParams;
  private final SignatureUtil signatureUtil;
  private final int coordinateSize;

  /**
   * Bundles parsed PKCS#11 config (subset of SunPKCS11 cfg directives we care about). Exactly one
   * of {@code slotId} or {@code slotListIndex} must be non-null.
   *
   * @param libraryPath path to the vendor PKCS#11 shared library (e.g. {@code libCryptoki2_64.so},
   *     {@code libsofthsm2.so})
   * @param slotId direct PKCS#11 slot ID, from {@code slot = N} in the config; null if {@code
   *     slotListIndex} is used instead
   * @param slotListIndex 0-based index into the slot list (slots with tokens), from {@code
   *     slotListIndex = N} in the config; null if {@code slotId} is used instead
   */
  record Pkcs11FfmConfig(Path libraryPath, Long slotId, Integer slotListIndex) {}

  /**
   * Bundles all artifacts produced during init so they can be passed to the constructor.
   *
   * @param nativeBinding the open FFM session
   * @param publicPoint the validated public-key EC point for {@link #getPublicKey()}
   */
  private record InitResult(Pkcs11Ffm nativeBinding, ECPoint publicPoint) {}

  static NativePkcs11Provider create(
      final HsmCliOptions cliOptions, final EcCurveParameters curveParams) {
    requireNonNull(
        cliOptions.getPkcs11ConfigPath(),
        "PKCS#11 configuration file path is required for native-pkcs11");
    requireNonNull(
        cliOptions.getPkcs11PasswordPath(),
        "PKCS#11 password file path is required for native-pkcs11");
    requireNonBlank(
        cliOptions.getPrivateKeyAlias(), "Private key alias is required for native-pkcs11");
    return new NativePkcs11Provider(
        init(
            cliOptions.getPkcs11ConfigPath(),
            cliOptions.getPkcs11PasswordPath(),
            cliOptions.getPrivateKeyAlias(),
            curveParams),
        curveParams);
  }

  private NativePkcs11Provider(final InitResult result, final EcCurveParameters curveParams) {
    this.nativeBinding = result.nativeBinding();
    final ECPoint validatedPoint = result.publicPoint();
    this.publicKey = () -> validatedPoint;
    this.curveParams = curveParams;
    this.signatureUtil = new SignatureUtil(curveParams);
    this.coordinateSize = (curveParams.getCurveOrder().bitLength() + 7) / 8;
  }

  private static InitResult init(
      final Path configPath,
      final Path passwordPath,
      final String keyAlias,
      final EcCurveParameters curveParams) {
    final Pkcs11FfmConfig config = parseConfig(configPath);
    final char[] pin = readPin(passwordPath);
    try {
      LOG.info(
          "Initializing native-pkcs11 provider: lib={} slot={} slotListIndex={} alias={}",
          config.libraryPath(),
          config.slotId(),
          config.slotListIndex(),
          keyAlias);
      final Pkcs11Ffm nativeBinding =
          Pkcs11Ffm.open(
              config.libraryPath(), config.slotId(), config.slotListIndex(), pin, keyAlias);
      try {
        final byte[] ecPointBytes = nativeBinding.getPublicEcPoint();
        final ECPoint publicPoint = parseEcPoint(ecPointBytes, curveParams);
        return new InitResult(nativeBinding, publicPoint);
      } catch (final RuntimeException e) {
        nativeBinding.close();
        throw e;
      }
    } finally {
      Arrays.fill(pin, '\0');
    }
  }

  @Override
  public Signature sign(final Bytes32 dataHash) {
    try {
      final byte[] sigBytes = nativeBinding.sign(dataHash.toArray());
      // CKM_ECDSA returns r || s concatenated (P1363 format) — for 256-bit curves, 64 bytes.
      // SignatureUtil.extractRAndS handles canonicalization (low-S, EIP-2).
      return signatureUtil.extractRAndS(sigBytes, true);
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error signing via native-pkcs11 provider", e);
    }
  }

  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey) {
    LOG.debug("Calculating ECDH key agreement via native-pkcs11 provider ...");
    final ECPoint partyPoint = partyKey.getW();
    validatePointOnCurve(partyPoint);
    final byte[] derWrappedPeer = derWrapPoint(partyPoint, coordinateSize);
    final byte[] shared = nativeBinding.deriveEcdh(derWrappedPeer);
    return Bytes32.wrap(shared);
  }

  @Override
  public Bytes calculateECDHKeyAgreementCompressed(final PublicKey partyKey) {
    // DiscV5 support is intentionally deferred for v1. The pattern matches the existing
    // JcaHsmProvider.calculateECDHKeyAgreementCompressed: do TWO deriveEcdh calls (one with
    // partyKey, one with partyKey + G) and run the same y-parity probe-point logic. Tracked
    // as a follow-up task.
    throw new UnsupportedOperationException(
        "Compressed ECDH (DiscV5) is not yet implemented for the native-pkcs11 provider. "
            + "DiscV5 with HSM-backed keys is currently only supported via generic-pkcs11; "
            + "track plugin issue for native-pkcs11 DiscV5 support.");
  }

  @Override
  public void close() {
    nativeBinding.close();
  }

  // ============== Helpers (package-private for unit tests) ==============

  @VisibleForTesting
  static Pkcs11FfmConfig parseConfig(final Path configPath) {
    try {
      final String content = Files.readString(configPath, StandardCharsets.UTF_8);
      Path libraryPath = null;
      Long slotId = null;
      Integer slotListIndex = null;
      for (final String rawLine : (Iterable<String>) content.lines()::iterator) {
        final String line = stripComment(rawLine).trim();
        if (line.isEmpty()) {
          continue;
        }
        final int eq = line.indexOf('=');
        if (eq <= 0) {
          continue;
        }
        final String key = line.substring(0, eq).trim();
        final String value = line.substring(eq + 1).trim();
        switch (key) {
          case "library" -> libraryPath = Path.of(value);
          case "slot" -> slotId = Long.parseLong(value);
          case "slotListIndex" -> slotListIndex = Integer.parseInt(value);
          default -> {
            // ignore — name=, showInfo=, attributes(...) are SunPKCS11-only
          }
        }
      }
      if (libraryPath == null) {
        throw new SecurityModuleException(
            "native-pkcs11 config missing 'library = <path>' directive: " + configPath);
      }
      if (slotId != null && slotListIndex != null) {
        throw new SecurityModuleException(
            "native-pkcs11 config has both 'slot' and 'slotListIndex' set; pick one: "
                + configPath);
      }
      if (slotId == null && slotListIndex == null) {
        throw new SecurityModuleException(
            "native-pkcs11 config missing 'slot = <int>' or 'slotListIndex = <int>' directive: "
                + configPath);
      }
      return new Pkcs11FfmConfig(libraryPath, slotId, slotListIndex);
    } catch (final IOException e) {
      throw new SecurityModuleException(
          "Failed to read native-pkcs11 config from " + configPath, e);
    }
  }

  private static String stripComment(final String line) {
    final int hash = line.indexOf('#');
    return hash < 0 ? line : line.substring(0, hash);
  }

  private static char[] readPin(final Path passwordPath) {
    final byte[] bytes;
    try {
      bytes = Files.readAllBytes(passwordPath);
    } catch (final IOException e) {
      throw new SecurityModuleException("Failed to read PIN from " + passwordPath, e);
    }
    final char[] pin = new String(bytes, StandardCharsets.UTF_8).trim().toCharArray();
    Arrays.fill(bytes, (byte) 0);
    return pin;
  }

  @VisibleForTesting
  static ECPoint parseEcPoint(final byte[] ecPointBytes, final EcCurveParameters curveParams) {
    final int coordSize = (curveParams.getCurveOrder().bitLength() + 7) / 8;
    final int expected = 1 + 2 * coordSize;
    if (ecPointBytes.length != expected || ecPointBytes[0] != 0x04) {
      throw new SecurityModuleException(
          "Invalid HSM EC public point: expected "
              + expected
              + " bytes starting with 0x04, got length="
              + ecPointBytes.length
              + " prefix=0x"
              + String.format("%02x", ecPointBytes[0]));
    }
    final BigInteger x = new BigInteger(1, ecPointBytes, 1, coordSize);
    final BigInteger y = new BigInteger(1, ecPointBytes, 1 + coordSize, coordSize);
    return new ECPoint(x, y);
  }

  /**
   * Validates the peer's EC point lies on the configured curve. Mirrors the validation in {@link
   * JcaHsmProvider} so a malicious or misconfigured peer cannot smuggle an off-curve point through
   * to the HSM.
   */
  private void validatePointOnCurve(final ECPoint point) {
    try {
      curveParams.getBCCurve().validatePoint(point.getAffineX(), point.getAffineY());
    } catch (final IllegalArgumentException e) {
      throw new SecurityModuleException("Peer EC point is not on the configured curve", e);
    }
  }

  @VisibleForTesting
  static byte[] derWrapPoint(final ECPoint point, final int coordinateSize) {
    final byte[] x = bigIntToFixedLength(point.getAffineX(), coordinateSize);
    final byte[] y = bigIntToFixedLength(point.getAffineY(), coordinateSize);
    final int rawLen = 1 + 2 * coordinateSize; // 04 || X || Y
    if (rawLen > 127) {
      // Long-form DER length encoding only matters for very large curves (e.g. secp521r1 at 133B).
      // Out-of-scope for v1, which targets secp256k1/r1 (rawLen=65).
      throw new SecurityModuleException(
          "Curve coordinate size "
              + coordinateSize
              + " bytes exceeds short-form DER capacity; long-form encoding not yet supported");
    }
    final byte[] der = new byte[2 + rawLen];
    der[0] = 0x04; // ASN.1 OCTET STRING tag
    der[1] = (byte) rawLen;
    der[2] = 0x04; // SEC1 uncompressed point indicator
    System.arraycopy(x, 0, der, 3, coordinateSize);
    System.arraycopy(y, 0, der, 3 + coordinateSize, coordinateSize);
    return der;
  }

  @VisibleForTesting
  static byte[] bigIntToFixedLength(final BigInteger value, final int len) {
    final byte[] bytes = value.toByteArray();
    if (bytes.length == len) {
      return bytes;
    }
    if (bytes.length == len + 1 && bytes[0] == 0) {
      // Strip the sign byte added by BigInteger.toByteArray for positive values with high bit set.
      final byte[] out = new byte[len];
      System.arraycopy(bytes, 1, out, 0, len);
      return out;
    }
    if (bytes.length < len) {
      final byte[] out = new byte[len];
      System.arraycopy(bytes, 0, out, len - bytes.length, bytes.length);
      return out;
    }
    throw new SecurityModuleException(
        "BigInteger too large for fixed-length encoding: "
            + bytes.length
            + " bytes (max "
            + len
            + ")");
  }
}
