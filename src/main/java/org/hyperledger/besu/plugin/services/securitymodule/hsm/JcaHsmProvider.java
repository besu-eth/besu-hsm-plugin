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

import static org.hyperledger.besu.plugin.services.securitymodule.hsm.Validations.requireNonNull;

import com.google.common.annotations.VisibleForTesting;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import javax.crypto.KeyAgreement;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract base class for {@link HsmProvider} implementations that use JCA (Java Cryptography
 * Architecture) for signing and ECDH operations. Subclasses are responsible for initializing the
 * JCA {@link Provider}, loading keys from the HSM, and resource cleanup.
 */
abstract class JcaHsmProvider implements HsmProvider {
  private static final Logger LOG = LoggerFactory.getLogger(JcaHsmProvider.class);
  private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";

  private final Provider provider;
  private final PrivateKey privateKey;
  private final PublicKey publicKey;
  private final String signatureAlgorithm;
  private final boolean useP1363;
  private final SignatureUtil signatureUtil;

  /**
   * Initializes the JCA-based provider with the given cryptographic components.
   *
   * @param provider the JCA {@link Provider} to use for cryptographic operations
   * @param privateKey the private key loaded from the HSM
   * @param ecPublicKey the EC public key loaded from the HSM
   * @param curveParams the EC curve parameters for signature handling
   * @throws SecurityModuleException if the public key curve does not match the configured curve
   */
  @VisibleForTesting
  JcaHsmProvider(
      final Provider provider,
      final PrivateKey privateKey,
      final ECPublicKey ecPublicKey,
      final EcCurveParameters curveParams) {
    this.provider = requireNonNull(provider, "provider must not be null");
    this.privateKey = requireNonNull(privateKey, "privateKey must not be null");
    final ECPublicKey validatedPublicKey =
        requireNonNull(ecPublicKey, "ecPublicKey must not be null");
    validatePublicKeyCurve(
        validatedPublicKey, requireNonNull(curveParams, "curveParams must not be null"));
    this.publicKey = validatedPublicKey::getW;
    this.signatureUtil = new SignatureUtil(curveParams);
    this.useP1363 = probeP1363Support();
    this.signatureAlgorithm = useP1363 ? "NONEwithECDSAinP1363Format" : "NONEWithECDSA";
    LOG.info("Using signature algorithm: {}", signatureAlgorithm);
  }

  private static void validatePublicKeyCurve(
      final ECPublicKey ecPublicKey, final EcCurveParameters expectedCurve) {
    final ECParameterSpec keyParams = ecPublicKey.getParams();
    if (!keyParams.getOrder().equals(expectedCurve.getCurveOrder())) {
      throw new SecurityModuleException(
          "HSM public key curve does not match configured curve '"
              + expectedCurve.getCurveName()
              + "'. Check that the key on the HSM was generated with the correct curve.");
    }
  }

  private boolean probeP1363Support() {
    try {
      Signature.getInstance("NONEwithECDSAinP1363Format", provider);
      return true;
    } catch (final NoSuchAlgorithmException e) {
      LOG.info(
          "Provider does not support NONEwithECDSAinP1363Format, falling back to NONEWithECDSA");
      return false;
    }
  }

  @Override
  public org.hyperledger.besu.plugin.services.securitymodule.data.Signature sign(
      final Bytes32 dataHash) {
    try {
      final Signature signature = Signature.getInstance(signatureAlgorithm, provider);
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
  public PublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey) {
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
}
