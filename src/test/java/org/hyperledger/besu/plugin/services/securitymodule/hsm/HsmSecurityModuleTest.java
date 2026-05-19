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

class HsmSecurityModuleTest {

  private static HsmCliOptions mockOptions(final HsmCliOptions.HsmProviderType providerType) {
    final HsmCliOptions options = mock(HsmCliOptions.class);
    when(options.getProviderType()).thenReturn(providerType);
    when(options.getEcCurve()).thenReturn("secp256k1");
    return options;
  }

  // -- sunpkcs11-jce validation tests --

  @Test
  void sunPkcs11JceRejectsNullConfigPath() {
    final HsmCliOptions options = mockOptions(HsmCliOptions.HsmProviderType.SUNPKCS11_JCE);
    when(options.getPkcs11ConfigPath()).thenReturn(null);

    assertThatThrownBy(() -> new HsmSecurityModule(options))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("configuration file path");
  }

  @Test
  void sunPkcs11JceRejectsNullPasswordPath() {
    final HsmCliOptions options = mockOptions(HsmCliOptions.HsmProviderType.SUNPKCS11_JCE);
    when(options.getPkcs11ConfigPath()).thenReturn(Path.of("/tmp/config"));
    when(options.getPkcs11PasswordPath()).thenReturn(null);

    assertThatThrownBy(() -> new HsmSecurityModule(options))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("password file path");
  }

  @Test
  void sunPkcs11JceRejectsNullKeyAlias() {
    final HsmCliOptions options = mockOptions(HsmCliOptions.HsmProviderType.SUNPKCS11_JCE);
    when(options.getPkcs11ConfigPath()).thenReturn(Path.of("/tmp/config"));
    when(options.getPkcs11PasswordPath()).thenReturn(Path.of("/tmp/password"));
    when(options.getPrivateKeyAlias()).thenReturn(null);

    assertThatThrownBy(() -> new HsmSecurityModule(options))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("key alias");
  }

  // -- CloudHSM JCE validation tests --

  @Test
  void cloudHsmJceRejectsNullKeyAlias() {
    final HsmCliOptions options = mockOptions(HsmCliOptions.HsmProviderType.CLOUDHSM_JCE);
    when(options.getPrivateKeyAlias()).thenReturn(null);
    when(options.getCloudHsmJarPath()).thenReturn(Path.of("/nonexistent/path"));

    assertThatThrownBy(() -> new HsmSecurityModule(options))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("key alias");
  }

  @Test
  void cloudHsmJceRejectsNullPublicKeyAlias() {
    final HsmCliOptions options = mockOptions(HsmCliOptions.HsmProviderType.CLOUDHSM_JCE);
    when(options.getPrivateKeyAlias()).thenReturn("mykey");
    when(options.getPublicKeyAlias()).thenReturn(null);
    when(options.getCloudHsmJarPath()).thenReturn(Path.of("/nonexistent/path"));

    assertThatThrownBy(() -> new HsmSecurityModule(options))
        .isInstanceOf(SecurityModuleException.class)
        .hasMessageContaining("Public key alias");
  }
}
