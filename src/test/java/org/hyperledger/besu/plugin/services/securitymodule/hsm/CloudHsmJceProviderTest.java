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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.junit.jupiter.api.Test;

class CloudHsmJceProviderTest {

  private static final EcCurveParameters SECP256K1 = new EcCurveParameters("secp256k1");

  private static HsmCliOptions mockCloudHsmOptions(
      final String privateKeyAlias, final String publicKeyAlias) {
    final HsmCliOptions options = mock(HsmCliOptions.class);
    when(options.getProviderType()).thenReturn(HsmCliOptions.HsmProviderType.CLOUDHSM_JCE);
    when(options.getPrivateKeyAlias()).thenReturn(privateKeyAlias);
    when(options.getPublicKeyAlias()).thenReturn(publicKeyAlias);
    when(options.getCloudHsmJarPath()).thenReturn(Path.of("/nonexistent/path"));
    return options;
  }

  @Test
  void rejectsNullPrivateKeyAlias() {
    final HsmCliOptions options = mockCloudHsmOptions(null, "pubkey");
    assertThatThrownBy(() -> CloudHsmJceProvider.create(options, SECP256K1))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Private key alias");
  }

  @Test
  void rejectsBlankPrivateKeyAlias() {
    final HsmCliOptions options = mockCloudHsmOptions("  ", "pubkey");
    assertThatThrownBy(() -> CloudHsmJceProvider.create(options, SECP256K1))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Private key alias");
  }

  @Test
  void rejectsNullPublicKeyAlias() {
    final HsmCliOptions options = mockCloudHsmOptions("privkey", null);
    assertThatThrownBy(() -> CloudHsmJceProvider.create(options, SECP256K1))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Public key alias");
  }

  @Test
  void rejectsBlankPublicKeyAlias() {
    final HsmCliOptions options = mockCloudHsmOptions("privkey", " ");
    assertThatThrownBy(() -> CloudHsmJceProvider.create(options, SECP256K1))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Public key alias");
  }

  @Test
  void throwsWhenCloudHsmJarPathNotFound() {
    final HsmCliOptions options = mockCloudHsmOptions("privkey", "pubkey");
    assertThatThrownBy(() -> CloudHsmJceProvider.create(options, SECP256K1))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("CloudHSM JCE jar path not found");
  }

  @Test
  void throwsWhenCloudHsmJarFileNotFound() {
    final HsmCliOptions options = mockCloudHsmOptions("privkey", "pubkey");
    when(options.getCloudHsmJarPath()).thenReturn(Path.of("/nonexistent/cloudhsm-jce-5.0.jar"));
    assertThatThrownBy(() -> CloudHsmJceProvider.create(options, SECP256K1))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("CloudHSM JCE jar path not found");
  }
}
