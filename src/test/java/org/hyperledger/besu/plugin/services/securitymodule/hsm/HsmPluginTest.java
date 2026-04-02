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
import static org.assertj.core.api.Assertions.assertThatNoException;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import org.hyperledger.besu.plugin.ServiceManager;
import org.hyperledger.besu.plugin.services.PicoCLIOptions;
import org.hyperledger.besu.plugin.services.SecurityModuleService;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HsmPluginTest {

  private HsmPlugin hsmPlugin;
  private ServiceManager serviceManager;
  private final StubSecurityModuleService securityModuleService = new StubSecurityModuleService();

  @BeforeEach
  void setUp() {
    hsmPlugin = new HsmPlugin();
    serviceManager = new ServiceManager.SimpleServiceManager();
    serviceManager.addService(PicoCLIOptions.class, (namespace, optionObject) -> {});
    serviceManager.addService(SecurityModuleService.class, securityModuleService);
  }

  @Test
  void pluginCanBeInstantiated() {
    assertThat(hsmPlugin).isNotNull();
  }

  @Test
  void registerDoesNotThrow() {
    assertThatNoException().isThrownBy(() -> hsmPlugin.register(serviceManager));
  }

  @Test
  void registerRegistersSecurityModule() {
    hsmPlugin.register(serviceManager);
    assertThat(securityModuleService.getByName("hsm")).isPresent();
  }

  @Test
  void startDoesNotThrow() {
    assertThatNoException().isThrownBy(() -> hsmPlugin.start());
  }

  @Test
  void stopDoesNotThrow() {
    assertThatNoException().isThrownBy(() -> hsmPlugin.stop());
  }

  private static class StubSecurityModuleService implements SecurityModuleService {
    private final Map<String, Supplier<SecurityModule>> modules = new HashMap<>();

    @Override
    public void register(final String name, final Supplier<SecurityModule> securityModuleSupplier) {
      modules.put(name, securityModuleSupplier);
    }

    @Override
    public Optional<Supplier<SecurityModule>> getByName(final String name) {
      return Optional.ofNullable(modules.get(name));
    }
  }
}
