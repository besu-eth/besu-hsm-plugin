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

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;
import org.junit.jupiter.api.Test;

class SignatureUtilTest {

  private static final BigInteger KNOWN_R =
      new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
  private static final BigInteger KNOWN_S =
      new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);

  @Test
  void extractRAndSFromDER() throws Exception {
    final byte[] der = buildDerSignature(KNOWN_R, KNOWN_S);
    final Signature sig = SignatureUtil.extractRAndS(der, false);
    assertThat(sig.getR()).isEqualTo(KNOWN_R);
    assertThat(sig.getS()).isEqualTo(KNOWN_S);
  }

  @Test
  void extractRAndSFromP1363() {
    final byte[] p1363 = new byte[64];
    final byte[] rBytes = KNOWN_R.toByteArray();
    final byte[] sBytes = KNOWN_S.toByteArray();
    // BigInteger may have leading zero byte; copy right-aligned into 32-byte slots
    System.arraycopy(
        rBytes,
        rBytes.length > 32 ? 1 : 0,
        p1363,
        32 - Math.min(rBytes.length, 32),
        Math.min(rBytes.length, 32));
    System.arraycopy(
        sBytes,
        sBytes.length > 32 ? 1 : 0,
        p1363,
        64 - Math.min(sBytes.length, 32),
        Math.min(sBytes.length, 32));

    final Signature sig = SignatureUtil.extractRAndS(p1363, true);
    assertThat(sig.getR()).isEqualTo(KNOWN_R);
    assertThat(sig.getS()).isEqualTo(KNOWN_S);
  }

  @Test
  void canonicalizesHighS() throws Exception {
    // Use an S value greater than HALF_CURVE_ORDER
    final BigInteger highS = Secp256k1Parameters.CURVE_ORDER.subtract(KNOWN_S);
    assertThat(highS).isGreaterThan(Secp256k1Parameters.HALF_CURVE_ORDER);

    final byte[] der = buildDerSignature(KNOWN_R, highS);
    final Signature sig = SignatureUtil.extractRAndS(der, false);
    assertThat(sig.getR()).isEqualTo(KNOWN_R);
    assertThat(sig.getS()).isEqualTo(KNOWN_S);
  }

  @Test
  void canonicalizesHighSInP1363() {
    final BigInteger highS = Secp256k1Parameters.CURVE_ORDER.subtract(KNOWN_S);
    final byte[] p1363 = new byte[64];
    final byte[] rBytes = KNOWN_R.toByteArray();
    final byte[] sBytes = highS.toByteArray();
    System.arraycopy(
        rBytes,
        rBytes.length > 32 ? 1 : 0,
        p1363,
        32 - Math.min(rBytes.length, 32),
        Math.min(rBytes.length, 32));
    System.arraycopy(
        sBytes,
        sBytes.length > 32 ? 1 : 0,
        p1363,
        64 - Math.min(sBytes.length, 32),
        Math.min(sBytes.length, 32));

    final Signature sig = SignatureUtil.extractRAndS(p1363, true);
    assertThat(sig.getR()).isEqualTo(KNOWN_R);
    assertThat(sig.getS()).isEqualTo(KNOWN_S);
  }

  @Test
  void rejectsInvalidP1363Length() {
    assertThatThrownBy(() -> SignatureUtil.extractRAndS(new byte[63], true))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Invalid P1363 signature length");
  }

  @Test
  void rejectsInvalidDER() {
    assertThatThrownBy(() -> SignatureUtil.extractRAndS(new byte[] {0x00, 0x01}, false))
        .isInstanceOf(SecurityModuleException.class);
  }

  @Test
  void rejectsZeroR() throws Exception {
    final byte[] der = buildDerSignature(BigInteger.ZERO, KNOWN_S);
    assertThatThrownBy(() -> SignatureUtil.extractRAndS(der, false))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("R is out of range");
  }

  @Test
  void rejectsRGreaterThanOrEqualToCurveOrder() throws Exception {
    final byte[] der = buildDerSignature(Secp256k1Parameters.CURVE_ORDER, KNOWN_S);
    assertThatThrownBy(() -> SignatureUtil.extractRAndS(der, false))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("R is out of range");
  }

  private static byte[] buildDerSignature(final BigInteger r, final BigInteger s) throws Exception {
    final ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1Integer(r));
    v.add(new ASN1Integer(s));
    return new DERSequence(v).getEncoded();
  }
}
