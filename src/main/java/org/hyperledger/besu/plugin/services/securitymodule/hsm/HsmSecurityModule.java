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

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModule;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link SecurityModule} implementation that delegates cryptographic operations (signing, ECDH) to
 * a configured {@link HsmProvider}. Supports both generic PKCS#11 tokens and AWS CloudHSM JCE.
 */
public class HsmSecurityModule implements SecurityModule, AutoCloseable {
  private static final Logger LOG = LoggerFactory.getLogger(HsmSecurityModule.class);

  private final HsmProvider hsmProvider;

  /**
   * Creates an {@link HsmSecurityModule} from CLI options, initializing the appropriate HSM
   * provider.
   *
   * @param cliOptions the parsed CLI options specifying provider type, key aliases, and EC curve
   * @throws SecurityModuleException if validation fails or the provider cannot be initialized
   */
  public HsmSecurityModule(final HsmCliOptions cliOptions) {
    LOG.debug("Creating HsmSecurityModule ...");
    final EcCurveParameters curveParams;
    try {
      curveParams = new EcCurveParameters(cliOptions.getEcCurve());
    } catch (final IllegalArgumentException e) {
      throw new SecurityModuleException("Unsupported EC curve: " + cliOptions.getEcCurve(), e);
    }
    LOG.info("Using EC curve: {}", curveParams.getCurveName());
    this.hsmProvider = createHsmProvider(cliOptions, curveParams);
  }

  private static HsmProvider createHsmProvider(
      final HsmCliOptions cliOptions, final EcCurveParameters curveParams) {
    return switch (cliOptions.getProviderType()) {
      case GENERIC_PKCS11 -> Pkcs11Provider.create(cliOptions, curveParams);
      case CLOUDHSM_JCE -> CloudHsmJceProvider.create(cliOptions, curveParams);
    };
  }

  @Override
  public Signature sign(final Bytes32 dataHash) throws SecurityModuleException {
    return hsmProvider.sign(dataHash);
  }

  @Override
  public PublicKey getPublicKey() throws SecurityModuleException {
    return hsmProvider.getPublicKey();
  }

  @Override
  public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey)
      throws SecurityModuleException {
    return hsmProvider.calculateECDHKeyAgreement(partyKey);
  }

  @Override
  public Bytes calculateECDHKeyAgreementCompressed(final PublicKey partyKey)
      throws SecurityModuleException {
    return hsmProvider.calculateECDHKeyAgreementCompressed(partyKey);
  }

  @Override
  public void close() {
    hsmProvider.close();
  }
}
