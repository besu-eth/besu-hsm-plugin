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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.KeyAgreement;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class Pkcs11SecurityModuleTest {

  private static Provider provider;

  @BeforeAll
  static void setupProvider() {
    provider = new BouncyCastleProvider();
    Security.addProvider(provider);
  }

  @AfterAll
  static void removeProvider() {
    Security.removeProvider(provider.getName());
  }

  @Nested
  class Secp256k1Tests {
    private static final EcCurveParameters CURVE = new EcCurveParameters("secp256k1");
    private static PrivateKey privateKey;
    private static ECPublicKey ecPublicKey;
    private Pkcs11SecurityModule module;

    @BeforeAll
    static void generateKeyPair() throws Exception {
      final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
      kpg.initialize(new ECGenParameterSpec("secp256k1"));
      final KeyPair keyPair = kpg.generateKeyPair();
      privateKey = keyPair.getPrivate();
      ecPublicKey = (ECPublicKey) keyPair.getPublic();
    }

    @BeforeEach
    void setUp() {
      module =
          new Pkcs11SecurityModule(
              provider, privateKey, ecPublicKey, "NONEWithECDSA", false, CURVE);
    }

    @Test
    void signReturnsValidSignature() throws Exception {
      final Bytes32 dataHash = Bytes32.random();
      final Signature signature = module.sign(dataHash);

      assertThat(signature).isNotNull();
      assertThat(signature.getR().signum()).isPositive();
      assertThat(signature.getS().signum()).isPositive();
      assertThat(signature.getS()).isLessThanOrEqualTo(CURVE.getHalfCurveOrder());

      final java.security.Signature verifier =
          java.security.Signature.getInstance("NONEWithECDSA", provider);
      verifier.initVerify(ecPublicKey);
      verifier.update(dataHash.toArray());
      final byte[] derSig = SignatureUtil.toDer(signature.getR(), signature.getS());
      assertThat(verifier.verify(derSig)).isTrue();
    }

    @Test
    void getPublicKeyReturnsCorrectPoint() {
      final PublicKey publicKey = module.getPublicKey();
      assertThat(publicKey).isNotNull();
      assertThat(publicKey.getW()).isEqualTo(ecPublicKey.getW());
    }

    @Test
    void calculateECDHKeyAgreementReturnsSecret() throws Exception {
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
      otherAgreement.doPhase(ecPublicKey, true);
      final Bytes32 expectedSecret = Bytes32.wrap(otherAgreement.generateSecret());
      assertThat(secret).isEqualTo(expectedSecret);
    }

    @Test
    void compressedECDHReturnsOddYCompressedPoint() throws Exception {
      // DiscV5 community test vector — expected prefix 0x03 (odd y)
      final Pkcs11SecurityModule vectorModule =
          createModuleFromPrivateKey(
              "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736",
              "secp256k1",
              CURVE);

      final ECPoint peerPoint =
          uncompressedHexToECPoint(
              "049961e4c2356d61bedb83052c115d311acb3a96f5777296dcf29735113026623"
                  + "1503061ac4aaee666073d7e5bc2c80c3f5c5b500c1cb5fd0a76abbb6b675ad157");
      final PublicKey partyKey = () -> peerPoint;

      final Bytes result = vectorModule.calculateECDHKeyAgreementCompressed(partyKey);

      assertThat(result)
          .isEqualTo(
              Bytes.fromHexString(
                  "0x033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e"));
      // x-coordinate portion matches existing ECDH
      assertThat(result.slice(1)).isEqualTo(vectorModule.calculateECDHKeyAgreement(partyKey));
    }

    @Test
    void compressedECDHReturnsEvenYCompressedPoint() throws Exception {
      // Test vector with expected prefix 0x02 (even y)
      final Pkcs11SecurityModule vectorModule =
          createModuleFromPrivateKey(
              "0000000000000000000000000000000000000000000000000000000000000066",
              "secp256k1",
              CURVE);

      final ECPoint peerPoint =
          uncompressedHexToECPoint(
              "049961e4c2356d61bedb83052c115d311acb3a96f5777296dcf29735113026623"
                  + "1503061ac4aaee666073d7e5bc2c80c3f5c5b500c1cb5fd0a76abbb6b675ad157");
      final PublicKey partyKey = () -> peerPoint;

      final Bytes result = vectorModule.calculateECDHKeyAgreementCompressed(partyKey);

      assertThat(result)
          .isEqualTo(
              Bytes.fromHexString(
                  "0x0279ea6ca033f1c1155a7aaf67ae07c11aaf75aa61fe926025f78c1ea58a5ccbf5"));
      assertThat(result.slice(1)).isEqualTo(vectorModule.calculateECDHKeyAgreement(partyKey));
    }

    @Test
    void multipleSignaturesAreAllValidAndCanonical() throws Exception {
      final Bytes32 dataHash = Bytes32.random();
      final Signature sig1 = module.sign(dataHash);
      final Signature sig2 = module.sign(dataHash);

      assertThat(sig1.getS()).isLessThanOrEqualTo(CURVE.getHalfCurveOrder());
      assertThat(sig2.getS()).isLessThanOrEqualTo(CURVE.getHalfCurveOrder());

      final java.security.Signature verifier =
          java.security.Signature.getInstance("NONEWithECDSA", provider);
      verifier.initVerify(ecPublicKey);
      verifier.update(dataHash.toArray());
      assertThat(verifier.verify(SignatureUtil.toDer(sig1.getR(), sig1.getS()))).isTrue();

      verifier.initVerify(ecPublicKey);
      verifier.update(dataHash.toArray());
      assertThat(verifier.verify(SignatureUtil.toDer(sig2.getR(), sig2.getS()))).isTrue();
    }
  }

  @Nested
  class Secp256r1Tests {
    private static final EcCurveParameters CURVE = new EcCurveParameters("secp256r1");
    private static PrivateKey privateKey;
    private static ECPublicKey ecPublicKey;
    private Pkcs11SecurityModule module;

    @BeforeAll
    static void generateKeyPair() throws Exception {
      final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
      kpg.initialize(new ECGenParameterSpec("secp256r1"));
      final KeyPair keyPair = kpg.generateKeyPair();
      privateKey = keyPair.getPrivate();
      ecPublicKey = (ECPublicKey) keyPair.getPublic();
    }

    @BeforeEach
    void setUp() {
      module =
          new Pkcs11SecurityModule(
              provider, privateKey, ecPublicKey, "NONEWithECDSA", false, CURVE);
    }

    @Test
    void signReturnsValidSignature() throws Exception {
      final Bytes32 dataHash = Bytes32.random();
      final Signature signature = module.sign(dataHash);

      assertThat(signature).isNotNull();
      assertThat(signature.getR().signum()).isPositive();
      assertThat(signature.getS().signum()).isPositive();
      assertThat(signature.getS()).isLessThanOrEqualTo(CURVE.getHalfCurveOrder());

      final java.security.Signature verifier =
          java.security.Signature.getInstance("NONEWithECDSA", provider);
      verifier.initVerify(ecPublicKey);
      verifier.update(dataHash.toArray());
      final byte[] derSig = SignatureUtil.toDer(signature.getR(), signature.getS());
      assertThat(verifier.verify(derSig)).isTrue();
    }

    @Test
    void calculateECDHKeyAgreementReturnsSecret() throws Exception {
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
      otherAgreement.doPhase(ecPublicKey, true);
      final Bytes32 expectedSecret = Bytes32.wrap(otherAgreement.generateSecret());
      assertThat(secret).isEqualTo(expectedSecret);
    }

    @Test
    void compressedECDHReturnsEvenYCompressedPoint() throws Exception {
      final Pkcs11SecurityModule vectorModule =
          createModuleFromPrivateKey(
              "00000000000000000000000000000000000000000000000000000000000000c9",
              "secp256r1",
              CURVE);

      final ECPoint peerPoint =
          uncompressedHexToECPoint(
              "043ed7a28ec648edce5d5b7e252f6b2aafbb44835114a24b3caa8f710f64993bc"
                  + "25711a34cdc9229080b639f09977feb7ca91ecce1649bfea8ad85c72b206ade7e");
      final PublicKey partyKey = () -> peerPoint;

      final Bytes result = vectorModule.calculateECDHKeyAgreementCompressed(partyKey);

      assertThat(result)
          .isEqualTo(
              Bytes.fromHexString(
                  "0x024ecb31c5d3d0903b8b183eaaa14b02c3255f24547059222d6d568152a615e483"));
      assertThat(result.slice(1)).isEqualTo(vectorModule.calculateECDHKeyAgreement(partyKey));
    }

    @Test
    void compressedECDHReturnsOddYCompressedPoint() throws Exception {
      final Pkcs11SecurityModule vectorModule =
          createModuleFromPrivateKey(
              "00000000000000000000000000000000000000000000000000000000000000cf",
              "secp256r1",
              CURVE);

      final ECPoint peerPoint =
          uncompressedHexToECPoint(
              "043ed7a28ec648edce5d5b7e252f6b2aafbb44835114a24b3caa8f710f64993bc"
                  + "25711a34cdc9229080b639f09977feb7ca91ecce1649bfea8ad85c72b206ade7e");
      final PublicKey partyKey = () -> peerPoint;

      final Bytes result = vectorModule.calculateECDHKeyAgreementCompressed(partyKey);

      assertThat(result)
          .isEqualTo(
              Bytes.fromHexString(
                  "0x0309e80076f4629105093c0ede8f4355924e9f2133ef8be69995925aa12381c381"));
      assertThat(result.slice(1)).isEqualTo(vectorModule.calculateECDHKeyAgreement(partyKey));
    }
  }

  @Test
  void validateCliOptionsRejectsNullConfigPath() {
    final Pkcs11CliOptions options = mock(Pkcs11CliOptions.class);
    when(options.getPkcs11ConfigPath()).thenReturn(null);

    assertThatThrownBy(() -> new Pkcs11SecurityModule(options))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("configuration file path");
  }

  @Test
  void validateCliOptionsRejectsNullPasswordPath() {
    final Pkcs11CliOptions options = mock(Pkcs11CliOptions.class);
    when(options.getPkcs11ConfigPath()).thenReturn(Path.of("/tmp/config"));
    when(options.getPkcs11PasswordPath()).thenReturn(null);

    assertThatThrownBy(() -> new Pkcs11SecurityModule(options))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("password file path");
  }

  @Test
  void validateCliOptionsRejectsNullKeyAlias() {
    final Pkcs11CliOptions options = mock(Pkcs11CliOptions.class);
    when(options.getPkcs11ConfigPath()).thenReturn(Path.of("/tmp/config"));
    when(options.getPkcs11PasswordPath()).thenReturn(Path.of("/tmp/password"));
    when(options.getPrivateKeyAlias()).thenReturn(null);

    assertThatThrownBy(() -> new Pkcs11SecurityModule(options))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("key alias");
  }

  private static Pkcs11SecurityModule createModuleFromPrivateKey(
      final String privateKeyHex, final String curveName, final EcCurveParameters curveParams)
      throws Exception {
    final BigInteger privKeyScalar = new BigInteger(privateKeyHex, 16);
    final org.bouncycastle.math.ec.ECPoint bcPubPoint =
        curveParams.getGenerator().multiply(privKeyScalar).normalize();
    final ECPoint jcaPubPoint =
        new ECPoint(
            bcPubPoint.getAffineXCoord().toBigInteger(),
            bcPubPoint.getAffineYCoord().toBigInteger());

    final KeyFactory kf = KeyFactory.getInstance("EC", provider);
    final PrivateKey privKey =
        kf.generatePrivate(new ECPrivateKeySpec(privKeyScalar, curveParams.getParamSpec()));
    final ECPublicKey pubKey =
        (ECPublicKey)
            kf.generatePublic(new ECPublicKeySpec(jcaPubPoint, curveParams.getParamSpec()));

    return new Pkcs11SecurityModule(provider, privKey, pubKey, "NONEWithECDSA", false, curveParams);
  }

  private static ECPoint uncompressedHexToECPoint(final String hex) {
    final byte[] bytes = Bytes.fromHexString(hex).toArray();
    // Skip the 0x04 prefix
    final byte[] xBytes = new byte[32];
    final byte[] yBytes = new byte[32];
    System.arraycopy(bytes, 1, xBytes, 0, 32);
    System.arraycopy(bytes, 33, yBytes, 0, 32);
    return new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
  }

  @Test
  void rejectsCurveMismatchBetweenKeyAndConfig() throws Exception {
    // Generate a secp256k1 key but configure with secp256r1 curve params
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
    kpg.initialize(new ECGenParameterSpec("secp256k1"));
    final KeyPair keyPair = kpg.generateKeyPair();

    assertThatThrownBy(
            () ->
                new Pkcs11SecurityModule(
                    provider,
                    keyPair.getPrivate(),
                    (ECPublicKey) keyPair.getPublic(),
                    "NONEWithECDSA",
                    false,
                    new EcCurveParameters("secp256r1")))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("does not match configured curve");
  }
}
