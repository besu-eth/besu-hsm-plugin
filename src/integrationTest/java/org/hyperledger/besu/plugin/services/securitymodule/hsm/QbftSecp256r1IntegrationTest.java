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

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/** Runs the QBFT HSM integration tests using the secp256r1 curve (experimental). */
class QbftSecp256r1IntegrationTest extends QbftHsmIntegrationTestBase {

  @RegisterExtension
  static final QbftNetworkExtension NETWORK = new QbftNetworkExtension("secp256r1");

  @Override
  QbftNetworkExtension network() {
    return NETWORK;
  }

  @Test
  @Disabled("web3j TransactionEncoder uses secp256k1 signing — needs secp256r1 dev key and signer")
  @Override
  void valueTransferProducesNonEmptyBlock() {}
}
