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

import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModule;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Pkcs11SecurityModule implements SecurityModule {
  private static final Logger LOG = LoggerFactory.getLogger(Pkcs11SecurityModule.class);

  private final Pkcs11CliOptions cliOptions;

  public Pkcs11SecurityModule(final Pkcs11CliOptions cliOptions) {
    LOG.debug("Creating Pkcs11SecurityModule ...");
    this.cliOptions = cliOptions;
  }

  @Override
  public Signature sign(final Bytes32 dataHash) throws SecurityModuleException {
    throw new SecurityModuleException("Not yet implemented");
  }

  @Override
  public PublicKey getPublicKey() throws SecurityModuleException {
    throw new SecurityModuleException("Not yet implemented");
  }

  @Override
  public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey)
      throws SecurityModuleException {
    throw new SecurityModuleException("Not yet implemented");
  }
}
