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

public class Pkcs11SecurityModule implements SecurityModule {
  private static final Logger LOG = LoggerFactory.getLogger(Pkcs11SecurityModule.class);
  private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";

  private final Pkcs11Provider pkcs11Provider;
  private final Provider provider;
  private final PrivateKey privateKey;
  private final PublicKey publicKey;
  private final String signatureAlgorithm;
  private final boolean useP1363;
  private final SignatureUtil signatureUtil;

  public Pkcs11SecurityModule(final Pkcs11CliOptions cliOptions) {
    LOG.debug("Creating Pkcs11SecurityModule ...");
    validateCliOptions(cliOptions);
    final EcCurveParameters curveParams = new EcCurveParameters(cliOptions.getEcCurve());
    LOG.info("Using EC curve: {}", curveParams.getCurveName());
    this.signatureUtil = new SignatureUtil(curveParams);
    this.pkcs11Provider =
        new Pkcs11Provider(
            cliOptions.getPkcs11ConfigPath(),
            cliOptions.getPkcs11PasswordPath(),
            cliOptions.getPrivateKeyAlias());
    this.provider = pkcs11Provider.getProvider();
    this.privateKey = pkcs11Provider.getPrivateKey();
    final ECPublicKey ecPublicKey = pkcs11Provider.getEcPublicKey();
    validatePublicKeyCurve(ecPublicKey, curveParams);
    this.publicKey = ecPublicKey::getW;
    this.useP1363 = probeP1363Support();
    this.signatureAlgorithm = useP1363 ? "NONEwithECDSAinP1363Format" : "NONEWithECDSA";
    LOG.info("Using signature algorithm: {}", signatureAlgorithm);
  }

  @VisibleForTesting
  Pkcs11SecurityModule(
      final Provider provider,
      final PrivateKey privateKey,
      final ECPublicKey ecPublicKey,
      final String signatureAlgorithm,
      final boolean useP1363,
      final EcCurveParameters curveParams) {
    this.pkcs11Provider = null;
    this.provider = provider;
    this.privateKey = privateKey;
    validatePublicKeyCurve(ecPublicKey, curveParams);
    this.publicKey = ecPublicKey::getW;
    this.signatureAlgorithm = signatureAlgorithm;
    this.useP1363 = useP1363;
    this.signatureUtil = new SignatureUtil(curveParams);
  }

  private static void validateCliOptions(final Pkcs11CliOptions cliOptions) {
    if (cliOptions.getPkcs11ConfigPath() == null) {
      throw new SecurityModuleException("PKCS#11 configuration file path is not provided");
    }
    if (cliOptions.getPkcs11PasswordPath() == null) {
      throw new SecurityModuleException("PKCS#11 password file path is not provided");
    }
    if (cliOptions.getPrivateKeyAlias() == null) {
      throw new SecurityModuleException("PKCS#11 private key alias is not provided");
    }
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
        signatureUtil.ecPointToJcePublicKey(partyKey.getW(), provider);
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
    if (pkcs11Provider != null) {
      pkcs11Provider.removeProvider();
    }
  }
}
