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

import java.math.BigInteger;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.web3j.crypto.RawTransaction;

/**
 * Runs the QBFT HSM integration tests against the secp256r1 curve, routed through the {@code
 * native-pkcs11} provider (Java 25 FFM binding into {@code libsofthsm2.so}). Confirms the FFM
 * recipe is curve-neutral.
 */
class QbftSecp256r1NativePkcs11IntegrationTest extends QbftHsmIntegrationTestBase {

  /**
   * Same private-key bytes as the secp256k1 sibling, but interpreted as a secp256r1 key. Genesis
   * pre-funds the resulting r1-derived address (0x91240f5b...) when EC_CURVE=secp256r1.
   */
  private static final BigInteger DEV_PRIVATE_KEY =
      new BigInteger("8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63", 16);

  @RegisterExtension
  static final QbftNetworkExtension NETWORK =
      new QbftNetworkExtension("secp256r1", false, "native-pkcs11");

  @Override
  QbftNetworkExtension network() {
    return NETWORK;
  }

  @Override
  protected String senderAddress() {
    return Secp256r1TransactionSigner.addressFromPrivateKey(DEV_PRIVATE_KEY);
  }

  @Override
  protected byte[] signRawTransaction(final RawTransaction tx, final long chainId) {
    return Secp256r1TransactionSigner.sign(tx, DEV_PRIVATE_KEY, chainId);
  }
}
