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

import com.google.auto.service.AutoService;
import org.hyperledger.besu.plugin.BesuPlugin;
import org.hyperledger.besu.plugin.ServiceManager;
import org.hyperledger.besu.plugin.services.PicoCLIOptions;
import org.hyperledger.besu.plugin.services.SecurityModuleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@AutoService(BesuPlugin.class)
public class HsmPlugin implements BesuPlugin {
  static final String SECURITY_MODULE_NAME = "hsm";
  private static final Logger LOG = LoggerFactory.getLogger(HsmPlugin.class);

  private final HsmCliOptions cliOptions = new HsmCliOptions();
  private volatile HsmSecurityModule module;

  @Override
  public void register(final ServiceManager serviceManager) {
    LOG.info("Registering HSM plugin ...");
    registerCliOptions(serviceManager);
    registerSecurityModule(serviceManager);
  }

  private void registerCliOptions(final ServiceManager serviceManager) {
    serviceManager
        .getService(PicoCLIOptions.class)
        .orElseThrow(() -> new IllegalStateException("PicoCLIOptions service not available"))
        .addPicoCLIOptions(SECURITY_MODULE_NAME, cliOptions);
  }

  private void registerSecurityModule(final ServiceManager serviceManager) {
    serviceManager
        .getService(SecurityModuleService.class)
        .orElseThrow(() -> new IllegalStateException("SecurityModuleService service not available"))
        .register(
            SECURITY_MODULE_NAME,
            () -> {
              this.module = new HsmSecurityModule(cliOptions);
              return this.module;
            });
  }

  @Override
  public void start() {
    LOG.debug("Starting HSM plugin ...");
  }

  @Override
  public void stop() {
    LOG.debug("Stopping HSM plugin ...");
    if (module != null) {
      module.removeProvider();
    }
  }
}
