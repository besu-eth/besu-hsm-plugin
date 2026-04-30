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

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * Runs the QBFT HSM integration tests with {@code --Xv5-discovery-enabled} on the secp256k1 curve.
 * Exercises {@link JcaHsmProvider#calculateECDHKeyAgreementCompressed} end-to-end via DiscV5
 * handshakes between SoftHSM2-backed validators. DiscV5 is only valid for secp256k1 (per the ENR v4
 * identity scheme), so no secp256r1 variant exists.
 */
class QbftSecp256k1V5DiscoveryIntegrationTest extends QbftHsmIntegrationTestBase {

  @RegisterExtension
  static final QbftNetworkExtension NETWORK = new QbftNetworkExtension("secp256k1", true);

  @Override
  QbftNetworkExtension network() {
    return NETWORK;
  }

  @Test
  void adminNodeInfoExposesEnr() throws Exception {
    final JsonNode result = rpcResult(network().getContainer(0), "admin_nodeInfo", "[]");
    assertThat(result.has("enr")).isTrue();
    assertThat(result.get("enr").asText()).startsWith("enr:");
  }
}
