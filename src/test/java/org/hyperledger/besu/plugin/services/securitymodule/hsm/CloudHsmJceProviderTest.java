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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.junit.jupiter.api.Test;

class CloudHsmJceProviderTest {

  @Test
  void rejectsNullPrivateKeyAlias() {
    assertThatThrownBy(() -> new CloudHsmJceProvider(null, "pubkey"))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Private key alias");
  }

  @Test
  void rejectsBlankPrivateKeyAlias() {
    assertThatThrownBy(() -> new CloudHsmJceProvider("  ", "pubkey"))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Private key alias");
  }

  @Test
  void rejectsNullPublicKeyAlias() {
    assertThatThrownBy(() -> new CloudHsmJceProvider("privkey", null))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Public key alias");
  }

  @Test
  void rejectsBlankPublicKeyAlias() {
    assertThatThrownBy(() -> new CloudHsmJceProvider("privkey", " "))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Public key alias");
  }

  @Test
  void throwsWhenCloudHsmJarNotOnClasspath() {
    assertThatThrownBy(() -> new CloudHsmJceProvider("privkey", "pubkey"))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("CloudHSM JCE provider jar not found");
  }
}
