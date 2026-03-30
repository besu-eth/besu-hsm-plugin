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

import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * Runs the QBFT HSM integration tests using secp256k1 with DiscV5 discovery enabled. This exercises
 * the compressed ECDH key agreement required by the DiscV5 handshake protocol.
 */
class QbftSecp256k1DiscV5IntegrationTest extends QbftHsmIntegrationTestBase {

  @RegisterExtension
  static final QbftNetworkExtension NETWORK = new QbftNetworkExtension("secp256k1", true);

  @Override
  QbftNetworkExtension network() {
    return NETWORK;
  }
}
