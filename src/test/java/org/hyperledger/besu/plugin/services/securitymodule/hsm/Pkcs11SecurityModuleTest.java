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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Pkcs11SecurityModuleTest {

  private static PrivateKey privateKey;
  private static ECPublicKey ecPublicKey;
  private static Provider provider;

  private Pkcs11SecurityModule module;

  @BeforeAll
  static void generateKeyPair() throws Exception {
    provider = new BouncyCastleProvider();
    Security.addProvider(provider);
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
    kpg.initialize(new ECGenParameterSpec("secp256k1"));
    final KeyPair keyPair = kpg.generateKeyPair();
    privateKey = keyPair.getPrivate();
    ecPublicKey = (ECPublicKey) keyPair.getPublic();
  }

  @BeforeEach
  void setUp() {
    module = new Pkcs11SecurityModule(provider, privateKey, ecPublicKey);
  }

  @Test
  void signReturnsValidSignature() {
    final Bytes32 dataHash = Bytes32.random();
    final Signature signature = module.sign(dataHash);

    assertThat(signature).isNotNull();
    assertThat(signature.getR()).isNotNull();
    assertThat(signature.getS()).isNotNull();
    assertThat(signature.getR().signum()).isPositive();
    assertThat(signature.getS().signum()).isPositive();
    assertThat(signature.getS()).isLessThanOrEqualTo(Secp256k1Parameters.HALF_CURVE_ORDER);
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
  void signProducesConsistentResults() {
    final Bytes32 dataHash = Bytes32.random();
    final Signature sig1 = module.sign(dataHash);
    final Signature sig2 = module.sign(dataHash);

    assertThat(sig1.getR().signum()).isPositive();
    assertThat(sig2.getR().signum()).isPositive();
    assertThat(sig1.getS()).isLessThanOrEqualTo(Secp256k1Parameters.HALF_CURVE_ORDER);
    assertThat(sig2.getS()).isLessThanOrEqualTo(Secp256k1Parameters.HALF_CURVE_ORDER);
  }
}
