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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.spec.ECPoint;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for the static helpers in {@link NativePkcs11Provider}: config-file parsing, EC-point
 * encoding/decoding, and BigInteger fixed-length serialization. Does not exercise the FFM binding
 * (covered separately by integration tests against SoftHSM2 and manual tests against a real Luna
 * HSM).
 */
class NativePkcs11ProviderTest {

  private static final EcCurveParameters SECP256K1 = new EcCurveParameters("secp256k1");

  // ============== parseConfig ==============

  @Test
  void parseConfigReadsLibraryAndSlot(@TempDir final Path tmp) throws IOException {
    final Path cfg =
        write(
            tmp,
            "name = Luna",
            "library = /usr/safenet/lunaclient/lib/libCryptoki2_64.so",
            "slot = 3",
            "showInfo = false");

    final NativePkcs11Provider.Pkcs11FfmConfig parsed = NativePkcs11Provider.parseConfig(cfg);

    assertThat(parsed.libraryPath())
        .isEqualTo(Path.of("/usr/safenet/lunaclient/lib/libCryptoki2_64.so"));
    assertThat(parsed.slotId()).isEqualTo(3L);
    assertThat(parsed.slotListIndex()).isNull();
  }

  @Test
  void parseConfigReadsSlotListIndex(@TempDir final Path tmp) throws IOException {
    // SoftHSM2-style config: slotListIndex is the portable form since slot IDs are runtime-assigned
    final Path cfg = write(tmp, "library = /usr/lib/softhsm/libsofthsm2.so", "slotListIndex = 0");

    final NativePkcs11Provider.Pkcs11FfmConfig parsed = NativePkcs11Provider.parseConfig(cfg);

    assertThat(parsed.libraryPath()).isEqualTo(Path.of("/usr/lib/softhsm/libsofthsm2.so"));
    assertThat(parsed.slotId()).isNull();
    assertThat(parsed.slotListIndex()).isEqualTo(0);
  }

  @Test
  void parseConfigIgnoresAttributeBlocksAndComments(@TempDir final Path tmp) throws IOException {
    final Path cfg =
        write(
            tmp,
            "# Reuse of a SunPKCS11-style config file",
            "library = /custom/path/libsofthsm2.so",
            "slot = 7   # the user partition",
            "attributes(generate, CKO_SECRET_KEY, CKK_GENERIC_SECRET) = {",
            "  CKA_SENSITIVE = true",
            "}");

    final NativePkcs11Provider.Pkcs11FfmConfig parsed = NativePkcs11Provider.parseConfig(cfg);

    assertThat(parsed.libraryPath()).isEqualTo(Path.of("/custom/path/libsofthsm2.so"));
    assertThat(parsed.slotId()).isEqualTo(7L);
  }

  @Test
  void parseConfigThrowsWhenBothSlotAndSlotListIndexAreSet(@TempDir final Path tmp)
      throws IOException {
    final Path cfg = write(tmp, "library = /lib/libfoo.so", "slot = 3", "slotListIndex = 0");

    assertThatThrownBy(() -> NativePkcs11Provider.parseConfig(cfg))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("both 'slot' and 'slotListIndex'");
  }

  @Test
  void parseConfigThrowsWhenSlotAndSlotListIndexAreMissing(@TempDir final Path tmp)
      throws IOException {
    final Path cfg = write(tmp, "library = /usr/safenet/lunaclient/lib/libCryptoki2_64.so");

    assertThatThrownBy(() -> NativePkcs11Provider.parseConfig(cfg))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("missing 'slot");
  }

  @Test
  void parseConfigThrowsWhenLibraryIsMissing(@TempDir final Path tmp) throws IOException {
    final Path cfg = write(tmp, "slot = 3");

    assertThatThrownBy(() -> NativePkcs11Provider.parseConfig(cfg))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("missing 'library");
  }

  @Test
  void parseConfigThrowsForMissingFile(@TempDir final Path tmp) {
    final Path missing = tmp.resolve("does-not-exist.cfg");

    assertThatThrownBy(() -> NativePkcs11Provider.parseConfig(missing))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Failed to read");
  }

  // ============== bigIntToFixedLength ==============

  @Test
  void bigIntToFixedLengthExactSizeRoundtrips() {
    final byte[] in = new byte[32];
    for (int i = 0; i < 32; i++) {
      in[i] = (byte) (i + 1);
    }
    final BigInteger bi = new BigInteger(1, in);

    final byte[] out = NativePkcs11Provider.bigIntToFixedLength(bi, 32);

    assertThat(out).hasSize(32).isEqualTo(in);
  }

  @Test
  void bigIntToFixedLengthStripsLeadingZeroSignByte() {
    // BigInteger.toByteArray() prepends a 0x00 sign byte for positive values whose top bit is set.
    // A 32-byte buffer with the high bit set in byte 0 yields a 33-byte two's-complement.
    final byte[] in = new byte[32];
    in[0] = (byte) 0x80;
    final BigInteger bi = new BigInteger(1, in);

    assertThat(bi.toByteArray()).hasSize(33).startsWith((byte) 0x00, (byte) 0x80);

    final byte[] out = NativePkcs11Provider.bigIntToFixedLength(bi, 32);

    assertThat(out).hasSize(32).isEqualTo(in);
  }

  @Test
  void bigIntToFixedLengthLeftPadsShortValues() {
    final BigInteger bi = BigInteger.valueOf(0x1234L); // 2 bytes naturally

    final byte[] out = NativePkcs11Provider.bigIntToFixedLength(bi, 32);

    assertThat(out).hasSize(32);
    for (int i = 0; i < 30; i++) {
      assertThat(out[i]).isEqualTo((byte) 0);
    }
    assertThat(out[30]).isEqualTo((byte) 0x12);
    assertThat(out[31]).isEqualTo((byte) 0x34);
  }

  @Test
  void bigIntToFixedLengthThrowsWhenValueExceedsLength() {
    final BigInteger huge = BigInteger.ONE.shiftLeft(257); // requires 33 bytes

    assertThatThrownBy(() -> NativePkcs11Provider.bigIntToFixedLength(huge, 32))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("too large");
  }

  // ============== derWrapPoint ==============

  @Test
  void derWrapPointProducesSpecCompliant67ByteBufferForSecp256k1() {
    final BigInteger x =
        new BigInteger("a861ff0446859da20053e718f2c99dbb58438a01f3ce482681f8bf49f85bb76e", 16);
    final BigInteger y =
        new BigInteger("b0108129597292eb93df092ebc591ef2d55163f91a2b21d347026febb2de4c25", 16);
    final ECPoint point = new ECPoint(x, y);

    final byte[] der = NativePkcs11Provider.derWrapPoint(point, 32);

    assertThat(der).hasSize(67);
    // PKCS#11 v2.40 format: ASN.1 OCTET STRING tag (0x04), length 0x41 (=65), then SEC1
    // uncompressed indicator (0x04), then X || Y (32 bytes each).
    assertThat(der[0]).isEqualTo((byte) 0x04);
    assertThat(der[1]).isEqualTo((byte) 0x41);
    assertThat(der[2]).isEqualTo((byte) 0x04);
    assertThat(NativePkcs11Provider.bigIntToFixedLength(x, 32))
        .isEqualTo(java.util.Arrays.copyOfRange(der, 3, 35));
    assertThat(NativePkcs11Provider.bigIntToFixedLength(y, 32))
        .isEqualTo(java.util.Arrays.copyOfRange(der, 35, 67));
  }

  // ============== parseEcPoint ==============

  @Test
  void parseEcPointRoundtripsKnownSecp256k1Point() {
    // testValidator1's public point captured during the POC
    final BigInteger x =
        new BigInteger("a861ff0446859da20053e718f2c99dbb58438a01f3ce482681f8bf49f85bb76e", 16);
    final BigInteger y =
        new BigInteger("b0108129597292eb93df092ebc591ef2d55163f91a2b21d347026febb2de4c25", 16);
    final byte[] uncompressed = new byte[65];
    uncompressed[0] = 0x04;
    System.arraycopy(NativePkcs11Provider.bigIntToFixedLength(x, 32), 0, uncompressed, 1, 32);
    System.arraycopy(NativePkcs11Provider.bigIntToFixedLength(y, 32), 0, uncompressed, 33, 32);

    final ECPoint point = NativePkcs11Provider.parseEcPoint(uncompressed, SECP256K1);

    assertThat(point.getAffineX()).isEqualTo(x);
    assertThat(point.getAffineY()).isEqualTo(y);
  }

  @Test
  void parseEcPointRejectsMissingUncompressedPrefix() {
    final byte[] bad = new byte[65];
    bad[0] = 0x02; // compressed; we only handle uncompressed here

    assertThatThrownBy(() -> NativePkcs11Provider.parseEcPoint(bad, SECP256K1))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Invalid HSM EC public point");
  }

  @Test
  void parseEcPointRejectsWrongLength() {
    final byte[] bad = new byte[33]; // way too small for secp256k1 uncompressed (expects 65)
    bad[0] = 0x04;

    assertThatThrownBy(() -> NativePkcs11Provider.parseEcPoint(bad, SECP256K1))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Invalid HSM EC public point");
  }

  @Test
  void parseConfigRejectsNegativeSlot(@TempDir final Path tmp) throws IOException {
    final Path cfg = write(tmp, "library = /usr/lib/softhsm/libsofthsm2.so", "slot = -1");

    assertThatThrownBy(() -> NativePkcs11Provider.parseConfig(cfg))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("'slot' must be >= 0");
  }

  @Test
  void parseConfigRejectsNegativeSlotListIndex(@TempDir final Path tmp) throws IOException {
    final Path cfg = write(tmp, "library = /usr/lib/softhsm/libsofthsm2.so", "slotListIndex = -1");

    assertThatThrownBy(() -> NativePkcs11Provider.parseConfig(cfg))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("'slotListIndex' must be >= 0");
  }

  @Test
  void parseEcPointRejectsEmptyArrayWithoutAioobe() {
    final byte[] empty = new byte[0];

    // The error formatter must not index into an empty array; it should produce a clean
    // SecurityModuleException, not an ArrayIndexOutOfBoundsException.
    assertThatThrownBy(() -> NativePkcs11Provider.parseEcPoint(empty, SECP256K1))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("got length=0")
        .hasMessageNotContaining("prefix=0x");
  }

  // ============== Helper ==============

  private static Path write(final Path dir, final String... lines) throws IOException {
    final Path file = dir.resolve("pkcs11.cfg");
    Files.write(file, java.util.Arrays.asList(lines));
    return file;
  }
}
