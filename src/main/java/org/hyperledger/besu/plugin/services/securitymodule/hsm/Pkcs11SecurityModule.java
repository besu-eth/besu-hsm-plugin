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
  private static final String SIGNATURE_ALGORITHM = "NONEWithECDSA";

  private final Provider provider;
  private final PrivateKey privateKey;
  private final ECPublicKey ecPublicKey;

  public Pkcs11SecurityModule(final Pkcs11CliOptions cliOptions) {
    LOG.debug("Creating Pkcs11SecurityModule ...");
    validateCliOptions(cliOptions);
    final Pkcs11Provider pkcs11Provider =
        new Pkcs11Provider(
            cliOptions.getPkcs11ConfigPath(),
            cliOptions.getPkcs11PasswordPath(),
            cliOptions.getPrivateKeyAlias());
    this.provider = pkcs11Provider.getProvider();
    this.privateKey = pkcs11Provider.getPrivateKey();
    this.ecPublicKey = pkcs11Provider.getEcPublicKey();
    LOG.info("Using signature algorithm: {}", SIGNATURE_ALGORITHM);

    LOG.info(
        "privateKey class={}, ecPublicKey class={}",
        privateKey.getClass().getName(),
        ecPublicKey.getClass().getName());

    // Test sign to verify PKCS#11 signing works — wrap each call separately
    try {
      LOG.info("Test sign: getting Signature instance ...");
      final java.security.Signature testSig =
          java.security.Signature.getInstance(SIGNATURE_ALGORITHM, provider);
      LOG.info("Test sign: Signature instance OK (provider={})", testSig.getProvider().getName());

      LOG.info("Test sign: calling initSign ...");
      testSig.initSign(privateKey);
      LOG.info("Test sign: initSign OK");

      LOG.info("Test sign: calling update with 32 bytes ...");
      testSig.update(new byte[32]);
      LOG.info("Test sign: update OK");

      LOG.info("Test sign: calling sign() ...");
      final byte[] testResult = testSig.sign();
      LOG.info("Test sign: SUCCESS sigLen={}", testResult.length);
    } catch (final Exception e) {
      LOG.error("Test sign: FAILED", e);
    }
  }

  Pkcs11SecurityModule(
      final Provider provider, final PrivateKey privateKey, final ECPublicKey ecPublicKey) {
    this.provider = provider;
    this.privateKey = privateKey;
    this.ecPublicKey = ecPublicKey;
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

  @Override
  public Signature sign(final Bytes32 dataHash) throws SecurityModuleException {
    try {
      final java.security.Signature signature =
          java.security.Signature.getInstance(SIGNATURE_ALGORITHM, provider);
      signature.initSign(privateKey);
      signature.update(dataHash.toArray());
      final byte[] sigBytes = signature.sign();
      return SignatureUtil.extractRAndS(sigBytes, false);
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error signing data", e);
    }
  }

  @Override
  public PublicKey getPublicKey() throws SecurityModuleException {
    return ecPublicKey::getW;
  }

  @Override
  public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey)
      throws SecurityModuleException {
    LOG.debug("Calculating ECDH key agreement ...");
    final java.security.PublicKey theirPublicKey =
        SignatureUtil.ecPointToJcePublicKey(partyKey.getW(), provider);
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
