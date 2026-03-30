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
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import javax.crypto.KeyAgreement;
import org.apache.tuweni.bytes.Bytes;
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
  private final EcCurveParameters curveParams;

  public Pkcs11SecurityModule(final Pkcs11CliOptions cliOptions) {
    LOG.debug("Creating Pkcs11SecurityModule ...");
    validateCliOptions(cliOptions);
    try {
      this.curveParams = new EcCurveParameters(cliOptions.getEcCurve());
    } catch (final IllegalArgumentException e) {
      throw new SecurityModuleException("Unsupported EC curve: " + cliOptions.getEcCurve(), e);
    }
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
    this.curveParams = curveParams;
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

  /**
   * Perform ECDH key agreement returning the compressed EC point.
   *
   * <p>Returns the full compressed EC point (SEC1 compressed format: prefix byte + x-coordinate)
   * from the ECDH scalar multiplication. This is required by protocols such as DiscV5 which use the
   * compressed point as input keying material for HKDF key derivation.
   *
   * <p>Since the HSM only exposes the x-coordinate of the ECDH shared point (via {@link
   * #calculateECDHKeyAgreement}), this method recovers the y-parity using a two-ECDH verification
   * technique: a second ECDH call with a probe point {@code Q + G} disambiguates the two candidate
   * y values derived from the curve equation.
   *
   * @param partyKey the key with which an agreement is to be created.
   * @return the compressed EC point in SEC1 format (33 bytes)
   * @throws SecurityModuleException if the operation is not supported or fails
   */
  @Override
  public Bytes calculateECDHKeyAgreementCompressed(final PublicKey partyKey)
      throws SecurityModuleException {
    LOG.debug("Calculating compressed ECDH key agreement ...");
    try {
      final org.bouncycastle.math.ec.ECCurve bcCurve = curveParams.getBcCurve();

      // Validate that the party key lies on the configured curve
      validatePartyKeyOnCurve(partyKey.getW(), bcCurve);

      // Step 1: Get x-coordinate from HSM ECDH
      final Bytes32 xCoord = calculateECDHKeyAgreement(partyKey);

      // Step 2: Recover the even-y candidate point from x using the curve equation
      final byte[] compressedEven = new byte[33];
      compressedEven[0] = 0x02;
      System.arraycopy(xCoord.toArray(), 0, compressedEven, 1, 32);
      final org.bouncycastle.math.ec.ECPoint candidateEven = bcCurve.decodePoint(compressedEven);

      // Step 3: Compute probe point Q' = Q + G (EC point addition in software)
      final org.bouncycastle.math.ec.ECPoint bcPartyPoint =
          signatureUtil.jcaPointToBcPoint(partyKey.getW());
      final org.bouncycastle.math.ec.ECPoint probePoint =
          bcPartyPoint.add(curveParams.getGenerator()).normalize();

      // Step 4: Second ECDH call with probe point through HSM
      final ECPoint probeJcaPoint =
          new ECPoint(
              probePoint.getAffineXCoord().toBigInteger(),
              probePoint.getAffineYCoord().toBigInteger());
      final Bytes32 xVerify = calculateECDHKeyAgreement(() -> probeJcaPoint);

      // Step 5: Determine correct y-parity
      // d*(Q+G) = d*Q + d*G = P + P_us, so check which candidate satisfies this
      final org.bouncycastle.math.ec.ECPoint ourPubKeyBc =
          signatureUtil.jcaPointToBcPoint(publicKey.getW());
      final org.bouncycastle.math.ec.ECPoint sumEven = candidateEven.add(ourPubKeyBc).normalize();
      final BigInteger sumEvenX = sumEven.getAffineXCoord().toBigInteger();

      if (toBytes32(sumEvenX).equals(xVerify)) {
        return Bytes.wrap(candidateEven.getEncoded(true));
      } else {
        return Bytes.wrap(candidateEven.negate().getEncoded(true));
      }
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException(
          "Unexpected error while calculating compressed ECDH key agreement", e);
    }
  }

  private static void validatePartyKeyOnCurve(
      final ECPoint point, final org.bouncycastle.math.ec.ECCurve bcCurve) {
    try {
      bcCurve.createPoint(point.getAffineX(), point.getAffineY()).normalize();
    } catch (final IllegalArgumentException e) {
      throw new SecurityModuleException(
          "Party key is not a valid point on the configured curve", e);
    }
  }

  private static Bytes32 toBytes32(final BigInteger value) {
    final byte[] bytes = value.toByteArray();
    if (bytes.length == 32) {
      return Bytes32.wrap(bytes);
    }
    final byte[] padded = new byte[32];
    if (bytes.length > 32) {
      // strip leading zero byte from unsigned BigInteger encoding
      System.arraycopy(bytes, bytes.length - 32, padded, 0, 32);
    } else {
      System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
    }
    return Bytes32.wrap(padded);
  }

  void removeProvider() {
    if (pkcs11Provider != null) {
      pkcs11Provider.removeProvider();
    }
  }
}
