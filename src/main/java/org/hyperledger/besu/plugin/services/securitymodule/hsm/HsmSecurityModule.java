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

import com.google.common.annotations.VisibleForTesting;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.ECPublicKey;
import javax.crypto.KeyAgreement;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModule;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link SecurityModule} implementation that delegates cryptographic operations (signing, ECDH) to
 * an HSM via a configured {@link HsmProvider}. Supports both generic PKCS#11 tokens and AWS
 * CloudHSM JCE.
 */
public class HsmSecurityModule implements SecurityModule {
  private static final Logger LOG = LoggerFactory.getLogger(HsmSecurityModule.class);
  private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";

  private final HsmProvider hsmProvider;
  private final Provider provider;
  private final PrivateKey privateKey;
  private final PublicKey publicKey;
  private final String signatureAlgorithm;
  private final boolean useP1363;
  private final SignatureUtil signatureUtil;

  /**
   * Creates an {@link HsmSecurityModule} from CLI options, initializing the appropriate HSM
   * provider.
   *
   * @param cliOptions the parsed CLI options specifying provider type, key aliases, and EC curve
   * @throws SecurityModuleException if validation fails or the provider cannot be initialized
   */
  public HsmSecurityModule(final HsmCliOptions cliOptions) {
    LOG.debug("Creating HsmSecurityModule ...");
    validateCliOptions(cliOptions);
    final EcCurveParameters curveParams;
    try {
      curveParams = new EcCurveParameters(cliOptions.getEcCurve());
    } catch (final IllegalArgumentException e) {
      throw new SecurityModuleException("Unsupported EC curve: " + cliOptions.getEcCurve(), e);
    }
    LOG.info("Using EC curve: {}", curveParams.getCurveName());
    this.signatureUtil = new SignatureUtil(curveParams);
    this.hsmProvider = createHsmProvider(cliOptions);
    this.provider = hsmProvider.getProvider();
    this.privateKey = hsmProvider.getPrivateKey();
    final ECPublicKey ecPublicKey = hsmProvider.getEcPublicKey();
    validatePublicKeyCurve(ecPublicKey, curveParams);
    this.publicKey = ecPublicKey::getW;
    this.useP1363 = probeP1363Support();
    this.signatureAlgorithm = useP1363 ? "NONEwithECDSAinP1363Format" : "NONEWithECDSA";
    LOG.info("Using signature algorithm: {}", signatureAlgorithm);
  }

  @VisibleForTesting
  HsmSecurityModule(
      final Provider provider,
      final PrivateKey privateKey,
      final ECPublicKey ecPublicKey,
      final String signatureAlgorithm,
      final boolean useP1363,
      final EcCurveParameters curveParams) {
    this.hsmProvider = null;
    this.provider = provider;
    this.privateKey = privateKey;
    validatePublicKeyCurve(ecPublicKey, curveParams);
    this.publicKey = ecPublicKey::getW;
    this.signatureAlgorithm = signatureAlgorithm;
    this.useP1363 = useP1363;
    this.signatureUtil = new SignatureUtil(curveParams);
  }

  private static void validateCliOptions(final HsmCliOptions cliOptions) {
    if (cliOptions.getProviderType() == HsmCliOptions.HsmProviderType.GENERIC_PKCS11) {
      if (cliOptions.getPkcs11ConfigPath() == null) {
        throw new SecurityModuleException("PKCS#11 configuration file path is not provided");
      }
      if (cliOptions.getPkcs11PasswordPath() == null) {
        throw new SecurityModuleException("PKCS#11 password file path is not provided");
      }
    }
    if (cliOptions.getPrivateKeyAlias() == null) {
      throw new SecurityModuleException("Private key alias is not provided");
    }
    if (cliOptions.getProviderType() == HsmCliOptions.HsmProviderType.CLOUDHSM_JCE) {
      if (cliOptions.getPublicKeyAlias() == null) {
        throw new SecurityModuleException(
            "Public key alias is required for cloudhsm-jce provider type");
      }
    }
  }

  private static HsmProvider createHsmProvider(final HsmCliOptions cliOptions) {
    return switch (cliOptions.getProviderType()) {
      case GENERIC_PKCS11 ->
          new Pkcs11Provider(
              cliOptions.getPkcs11ConfigPath(),
              cliOptions.getPkcs11PasswordPath(),
              cliOptions.getPrivateKeyAlias());
      case CLOUDHSM_JCE ->
          new CloudHsmJceProvider(cliOptions.getPrivateKeyAlias(), cliOptions.getPublicKeyAlias());
    };
  }

  private static void validatePublicKeyCurve(
      final ECPublicKey ecPublicKey, final EcCurveParameters expectedCurve) {
    final java.security.spec.ECParameterSpec keyParams = ecPublicKey.getParams();
    if (!keyParams.getOrder().equals(expectedCurve.getCurveOrder())) {
      throw new SecurityModuleException(
          "HSM public key curve does not match configured curve '"
              + expectedCurve.getCurveName()
              + "'. Check that the key on the HSM was generated with the correct curve.");
    }
  }

  private boolean probeP1363Support() {
    try {
      java.security.Signature.getInstance("NONEwithECDSAinP1363Format", provider);
      return true;
    } catch (final NoSuchAlgorithmException e) {
      LOG.info(
          "Provider does not support NONEwithECDSAinP1363Format, falling back to NONEWithECDSA");
      return false;
    }
  }

  @Override
  public Signature sign(final Bytes32 dataHash) throws SecurityModuleException {
    try {
      final java.security.Signature signature =
          java.security.Signature.getInstance(signatureAlgorithm, provider);
      signature.initSign(privateKey);
      signature.update(dataHash.toArray());
      final byte[] sigBytes = signature.sign();
      return signatureUtil.extractRAndS(sigBytes, useP1363);
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error signing data", e);
    }
  }

  @Override
  public PublicKey getPublicKey() throws SecurityModuleException {
    return publicKey;
  }

  @Override
  public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey)
      throws SecurityModuleException {
    LOG.debug("Calculating ECDH key agreement ...");
    final java.security.PublicKey theirPublicKey =
        signatureUtil.ecPointToJcePublicKey(partyKey.getW());
    try {
      final KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM, provider);
      keyAgreement.init(privateKey);
      keyAgreement.doPhase(theirPublicKey, true);
      return Bytes32.wrap(keyAgreement.generateSecret());
    } catch (final Exception e) {
      throw new SecurityModuleException("Error calculating ECDH key agreement", e);
    }
  }

  void removeProvider() {
    if (hsmProvider != null) {
      hsmProvider.removeProvider();
    }
  }
}
