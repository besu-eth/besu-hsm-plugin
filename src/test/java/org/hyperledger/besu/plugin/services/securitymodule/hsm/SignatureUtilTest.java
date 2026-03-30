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

  private static final EcCurveParameters SECP256K1 = new EcCurveParameters("secp256k1");
  private static final EcCurveParameters SECP256R1 = new EcCurveParameters("secp256r1");
  private final SignatureUtil signatureUtil = new SignatureUtil(SECP256K1);

  private static final BigInteger KNOWN_R =
      new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
  private static final BigInteger KNOWN_S =
      new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);

  @Test
  void extractRAndSFromDER() throws Exception {
    final byte[] der = buildDerSignature(KNOWN_R, KNOWN_S);
    final Signature sig = signatureUtil.extractRAndS(der, false);
    assertThat(sig.getR()).isEqualTo(KNOWN_R);
    assertThat(sig.getS()).isEqualTo(KNOWN_S);
  }

  @Test
  void extractRAndSFromP1363() {
    final byte[] p1363 = toP1363(KNOWN_R, KNOWN_S);
    final Signature sig = signatureUtil.extractRAndS(p1363, true);
    assertThat(sig.getR()).isEqualTo(KNOWN_R);
    assertThat(sig.getS()).isEqualTo(KNOWN_S);
  }

  @Test
  void canonicalizesHighS() throws Exception {
    final BigInteger highS = SECP256K1.getCurveOrder().subtract(KNOWN_S);
    assertThat(highS).isGreaterThan(SECP256K1.getHalfCurveOrder());

    final byte[] der = buildDerSignature(KNOWN_R, highS);
    final Signature sig = signatureUtil.extractRAndS(der, false);
    assertThat(sig.getR()).isEqualTo(KNOWN_R);
    assertThat(sig.getS()).isEqualTo(KNOWN_S);
  }

  @Test
  void canonicalizesHighSInP1363() {
    final BigInteger highS = SECP256K1.getCurveOrder().subtract(KNOWN_S);
    final byte[] p1363 = toP1363(KNOWN_R, highS);

    final Signature sig = signatureUtil.extractRAndS(p1363, true);
    assertThat(sig.getR()).isEqualTo(KNOWN_R);
    assertThat(sig.getS()).isEqualTo(KNOWN_S);
  }

  @Test
  void canonicalizesHighSWithSecp256r1() throws Exception {
    final SignatureUtil r1Util = new SignatureUtil(SECP256R1);
    final BigInteger highS = SECP256R1.getCurveOrder().subtract(KNOWN_S);
    assertThat(highS).isGreaterThan(SECP256R1.getHalfCurveOrder());

    final byte[] der = buildDerSignature(KNOWN_R, highS);
    final Signature sig = r1Util.extractRAndS(der, false);
    assertThat(sig.getR()).isEqualTo(KNOWN_R);
    assertThat(sig.getS()).isEqualTo(KNOWN_S);
  }

  @Test
  void rejectsInvalidP1363Length() {
    assertThatThrownBy(() -> signatureUtil.extractRAndS(new byte[63], true))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Invalid P1363 signature length");
  }

  @Test
  void rejectsInvalidDER() {
    assertThatThrownBy(() -> signatureUtil.extractRAndS(new byte[] {0x00, 0x01}, false))
        .isInstanceOf(SecurityModuleException.class);
  }

  @Test
  void rejectsZeroR() throws Exception {
    final byte[] der = buildDerSignature(BigInteger.ZERO, KNOWN_S);
    assertThatThrownBy(() -> signatureUtil.extractRAndS(der, false))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("non-positive");
  }

  @Test
  void rejectsRGreaterThanOrEqualToCurveOrder() throws Exception {
    final byte[] der = buildDerSignature(SECP256K1.getCurveOrder(), KNOWN_S);
    assertThatThrownBy(() -> signatureUtil.extractRAndS(der, false))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("R is out of range");
  }

  private static byte[] buildDerSignature(final BigInteger r, final BigInteger s) throws Exception {
    final ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1Integer(r));
    v.add(new ASN1Integer(s));
    return new DERSequence(v).getEncoded();
  }

  private static byte[] toP1363(final BigInteger r, final BigInteger s) {
    final byte[] p1363 = new byte[64];
    final byte[] rBytes = r.toByteArray();
    final byte[] sBytes = s.toByteArray();
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
    return p1363;
  }
}
