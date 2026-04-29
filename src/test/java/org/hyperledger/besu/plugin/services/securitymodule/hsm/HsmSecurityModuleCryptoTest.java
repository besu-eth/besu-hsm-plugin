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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyAgreement;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class HsmSecurityModuleCryptoTest {

  private static final EcCurveParameters SECP256K1 = new EcCurveParameters("secp256k1");
  private static final EcCurveParameters SECP256R1 = new EcCurveParameters("secp256r1");

  private static Provider provider;
  private static PrivateKey k1PrivateKey;
  private static ECPublicKey k1PublicKey;
  private static PrivateKey r1PrivateKey;
  private static ECPublicKey r1PublicKey;

  @BeforeAll
  static void setUp() throws Exception {
    provider = new BouncyCastleProvider();

    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);

    kpg.initialize(new ECGenParameterSpec("secp256k1"));
    final KeyPair k1KeyPair = kpg.generateKeyPair();
    k1PrivateKey = k1KeyPair.getPrivate();
    k1PublicKey = (ECPublicKey) k1KeyPair.getPublic();

    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    final KeyPair r1KeyPair = kpg.generateKeyPair();
    r1PrivateKey = r1KeyPair.getPrivate();
    r1PublicKey = (ECPublicKey) r1KeyPair.getPublic();
  }

  private static JcaHsmProvider createTestProvider(
      final Provider provider,
      final PrivateKey privateKey,
      final ECPublicKey publicKey,
      final EcCurveParameters curveParams) {
    return new JcaHsmProvider(provider, privateKey, publicKey, curveParams) {
      @Override
      public void close() {
        // no-op for tests
      }
    };
  }

  // -- secp256k1 tests --

  @Test
  void secp256k1SignReturnsValidSignature() throws Exception {
    final JcaHsmProvider module =
        createTestProvider(provider, k1PrivateKey, k1PublicKey, SECP256K1);
    final Bytes32 dataHash = Bytes32.random();
    final Signature signature = module.sign(dataHash);

    assertThat(signature).isNotNull();
    assertThat(signature.getR().signum()).isPositive();
    assertThat(signature.getS().signum()).isPositive();
    assertThat(signature.getS()).isLessThanOrEqualTo(SECP256K1.getHalfCurveOrder());

    final java.security.Signature verifier =
        java.security.Signature.getInstance("NONEWithECDSA", provider);
    verifier.initVerify(k1PublicKey);
    verifier.update(dataHash.toArray());
    final byte[] derSig = SignatureUtil.toDer(signature.getR(), signature.getS());
    assertThat(verifier.verify(derSig)).isTrue();
  }

  @Test
  void secp256k1GetPublicKeyReturnsCorrectPoint() {
    final JcaHsmProvider module =
        createTestProvider(provider, k1PrivateKey, k1PublicKey, SECP256K1);
    final PublicKey publicKey = module.getPublicKey();
    assertThat(publicKey).isNotNull();
    assertThat(publicKey.getW()).isEqualTo(k1PublicKey.getW());
  }

  @Test
  void secp256k1CalculateECDHKeyAgreementReturnsSecret() throws Exception {
    final JcaHsmProvider module =
        createTestProvider(provider, k1PrivateKey, k1PublicKey, SECP256K1);
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
    kpg.initialize(new ECGenParameterSpec("secp256k1"));
    final KeyPair otherKeyPair = kpg.generateKeyPair();
    final ECPublicKey otherPublicKey = (ECPublicKey) otherKeyPair.getPublic();

    final PublicKey partyKey = otherPublicKey::getW;
    final Bytes32 secret = module.calculateECDHKeyAgreement(partyKey);

    assertThat(secret).isNotNull();
    assertThat(secret).isNotEqualTo(Bytes32.ZERO);

    final KeyAgreement otherAgreement = KeyAgreement.getInstance("ECDH", provider);
    otherAgreement.init(otherKeyPair.getPrivate());
    otherAgreement.doPhase(k1PublicKey, true);
    final Bytes32 expectedSecret = Bytes32.wrap(otherAgreement.generateSecret());
    assertThat(secret).isEqualTo(expectedSecret);
  }

  @Test
  void secp256k1MultipleSignaturesAreAllValidAndCanonical() throws Exception {
    final JcaHsmProvider module =
        createTestProvider(provider, k1PrivateKey, k1PublicKey, SECP256K1);
    final Bytes32 dataHash = Bytes32.random();
    final Signature sig1 = module.sign(dataHash);
    final Signature sig2 = module.sign(dataHash);

    assertThat(sig1.getS()).isLessThanOrEqualTo(SECP256K1.getHalfCurveOrder());
    assertThat(sig2.getS()).isLessThanOrEqualTo(SECP256K1.getHalfCurveOrder());

    final java.security.Signature verifier =
        java.security.Signature.getInstance("NONEWithECDSA", provider);
    verifier.initVerify(k1PublicKey);
    verifier.update(dataHash.toArray());
    assertThat(verifier.verify(SignatureUtil.toDer(sig1.getR(), sig1.getS()))).isTrue();

    verifier.initVerify(k1PublicKey);
    verifier.update(dataHash.toArray());
    assertThat(verifier.verify(SignatureUtil.toDer(sig2.getR(), sig2.getS()))).isTrue();
  }

  // -- secp256r1 tests --

  @Test
  void secp256r1SignReturnsValidSignature() throws Exception {
    final JcaHsmProvider module =
        createTestProvider(provider, r1PrivateKey, r1PublicKey, SECP256R1);
    final Bytes32 dataHash = Bytes32.random();
    final Signature signature = module.sign(dataHash);

    assertThat(signature).isNotNull();
    assertThat(signature.getR().signum()).isPositive();
    assertThat(signature.getS().signum()).isPositive();
    assertThat(signature.getS()).isLessThanOrEqualTo(SECP256R1.getHalfCurveOrder());

    final java.security.Signature verifier =
        java.security.Signature.getInstance("NONEWithECDSA", provider);
    verifier.initVerify(r1PublicKey);
    verifier.update(dataHash.toArray());
    final byte[] derSig = SignatureUtil.toDer(signature.getR(), signature.getS());
    assertThat(verifier.verify(derSig)).isTrue();
  }

  @Test
  void secp256r1CalculateECDHKeyAgreementReturnsSecret() throws Exception {
    final JcaHsmProvider module =
        createTestProvider(provider, r1PrivateKey, r1PublicKey, SECP256R1);
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    final KeyPair otherKeyPair = kpg.generateKeyPair();
    final ECPublicKey otherPublicKey = (ECPublicKey) otherKeyPair.getPublic();

    final PublicKey partyKey = otherPublicKey::getW;
    final Bytes32 secret = module.calculateECDHKeyAgreement(partyKey);

    assertThat(secret).isNotNull();
    assertThat(secret).isNotEqualTo(Bytes32.ZERO);

    final KeyAgreement otherAgreement = KeyAgreement.getInstance("ECDH", provider);
    otherAgreement.init(otherKeyPair.getPrivate());
    otherAgreement.doPhase(r1PublicKey, true);
    final Bytes32 expectedSecret = Bytes32.wrap(otherAgreement.generateSecret());
    assertThat(secret).isEqualTo(expectedSecret);
  }

  // -- compressed ECDH tests --

  @Test
  void secp256k1CalculateECDHKeyAgreementCompressedMatchesSoftwareOracle() throws Exception {
    final JcaHsmProvider module =
        createTestProvider(provider, k1PrivateKey, k1PublicKey, SECP256K1);
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
    kpg.initialize(new ECGenParameterSpec("secp256k1"));
    final KeyPair peerKeyPair = kpg.generateKeyPair();
    final ECPublicKey peerPublicKey = (ECPublicKey) peerKeyPair.getPublic();
    final PublicKey partyKey = peerPublicKey::getW;

    final Bytes compressed = module.calculateECDHKeyAgreementCompressed(partyKey);
    final Bytes oracle =
        softwareCompressedEcdh((ECPrivateKey) peerKeyPair.getPrivate(), k1PublicKey, SECP256K1);

    assertThat(compressed).isEqualTo(oracle);
    assertThat(compressed.size()).isEqualTo(33);
    assertThat(compressed.get(0)).isIn((byte) 0x02, (byte) 0x03);

    final Bytes32 plainEcdh = module.calculateECDHKeyAgreement(partyKey);
    assertThat(compressed.slice(1, 32)).isEqualTo(plainEcdh);
  }

  @Test
  void secp256r1CalculateECDHKeyAgreementCompressedMatchesSoftwareOracle() throws Exception {
    final JcaHsmProvider module =
        createTestProvider(provider, r1PrivateKey, r1PublicKey, SECP256R1);
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    final KeyPair peerKeyPair = kpg.generateKeyPair();
    final ECPublicKey peerPublicKey = (ECPublicKey) peerKeyPair.getPublic();
    final PublicKey partyKey = peerPublicKey::getW;

    final Bytes compressed = module.calculateECDHKeyAgreementCompressed(partyKey);
    final Bytes oracle =
        softwareCompressedEcdh((ECPrivateKey) peerKeyPair.getPrivate(), r1PublicKey, SECP256R1);

    assertThat(compressed).isEqualTo(oracle);
    assertThat(compressed.size()).isEqualTo(33);
    assertThat(compressed.get(0)).isIn((byte) 0x02, (byte) 0x03);

    final Bytes32 plainEcdh = module.calculateECDHKeyAgreement(partyKey);
    assertThat(compressed.slice(1, 32)).isEqualTo(plainEcdh);
  }

  @Test
  void secp256k1CompressedEcdhCoversBothYParities() throws Exception {
    assertCoversBothYParities("secp256k1", k1PrivateKey, k1PublicKey, SECP256K1);
  }

  @Test
  void secp256r1CompressedEcdhCoversBothYParities() throws Exception {
    assertCoversBothYParities("secp256r1", r1PrivateKey, r1PublicKey, SECP256R1);
  }

  @Test
  void compressedEcdhRejectsPartyKeyOffCurve() {
    final JcaHsmProvider module =
        createTestProvider(provider, k1PrivateKey, k1PublicKey, SECP256K1);
    final java.security.spec.ECPoint validPoint = k1PublicKey.getW();
    final java.security.spec.ECPoint offCurvePoint =
        new java.security.spec.ECPoint(
            validPoint.getAffineX(), validPoint.getAffineY().add(BigInteger.ONE));
    final PublicKey badParty = () -> offCurvePoint;

    assertThatThrownBy(() -> module.calculateECDHKeyAgreementCompressed(badParty))
        .isInstanceOf(SecurityModuleException.class)
        .hasStackTraceContaining("Point not on curve");
  }

  // -- curve mismatch test --

  @Test
  void rejectsCurveMismatchBetweenKeyAndConfig() {
    assertThatThrownBy(
            () ->
                createTestProvider(
                    provider, k1PrivateKey, k1PublicKey, new EcCurveParameters("secp256r1")))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("does not match configured curve");
  }

  private static void assertCoversBothYParities(
      final String curveName,
      final PrivateKey ourPrivateKey,
      final ECPublicKey ourPublicKey,
      final EcCurveParameters curveParams)
      throws Exception {
    final JcaHsmProvider module =
        createTestProvider(provider, ourPrivateKey, ourPublicKey, curveParams);
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
    kpg.initialize(new ECGenParameterSpec(curveName));

    boolean sawEven = false;
    boolean sawOdd = false;
    final int maxIterations = 30;
    for (int i = 0; i < maxIterations && !(sawEven && sawOdd); i++) {
      final KeyPair peerKeyPair = kpg.generateKeyPair();
      final ECPublicKey peerPublicKey = (ECPublicKey) peerKeyPair.getPublic();
      final PublicKey partyKey = peerPublicKey::getW;

      final Bytes compressed = module.calculateECDHKeyAgreementCompressed(partyKey);
      final Bytes oracle =
          softwareCompressedEcdh(
              (ECPrivateKey) peerKeyPair.getPrivate(), ourPublicKey, curveParams);
      assertThat(compressed).isEqualTo(oracle);

      final byte prefix = compressed.get(0);
      if (prefix == 0x02) {
        sawEven = true;
      } else if (prefix == 0x03) {
        sawOdd = true;
      }
    }
    assertThat(sawEven)
        .withFailMessage("Did not observe even-y parity (0x02) in %d trials", maxIterations)
        .isTrue();
    assertThat(sawOdd)
        .withFailMessage("Did not observe odd-y parity (0x03) in %d trials", maxIterations)
        .isTrue();
  }

  private static Bytes softwareCompressedEcdh(
      final ECPrivateKey peerPriv, final ECPublicKey ourPub, final EcCurveParameters curveParams) {
    final org.bouncycastle.math.ec.ECPoint ourBcPoint =
        curveParams
            .getBCCurve()
            .createPoint(ourPub.getW().getAffineX(), ourPub.getW().getAffineY());
    final org.bouncycastle.math.ec.ECPoint shared =
        ourBcPoint.multiply(peerPriv.getS()).normalize();
    return Bytes.wrap(shared.getEncoded(true));
  }
}
